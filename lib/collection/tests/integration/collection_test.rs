use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter};
use std::num::NonZeroU32;
use std::sync::Arc;

use ahash::AHashSet;
use api::rest::{LookupLocation, SearchRequestInternal};
use collection::collection::Collection;
use collection::collection::distance_matrix::CollectionSearchMatrixRequest;
use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams,
    CryptoMigrationCheckpoint, CryptoMigrationCheckpointStatus, CryptoMigrationPlan,
    CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, WalConfig,
};
use collection::discovery::{discover, discover_batch};
use collection::grouping::GroupBy;
use collection::grouping::group_by::{GroupRequest, SourceRequest};
use collection::lookup::types::PseudoId;
use collection::lookup::{WithLookup, lookup_ids};
use collection::operations::config_diff::CollectionParamsDiff;
use collection::operations::payload_ops::{DeletePayloadOp, PayloadOps, SetPayloadOp};
use collection::operations::point_ops::{
    BatchPersisted, BatchVectorStructPersisted, ConditionalInsertOperationInternal,
    PointInsertOperationsInternal, PointOperations, PointStructPersisted, PointSyncOperation,
    VectorStructPersisted, WriteOrdering,
};
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::{
    CollectionError, CollectionUpdateProvenance, ContextExamplePair, CountRequestInternal,
    DiscoverRequestInternal, PointRequestInternal, RecommendExample, RecommendRequestInternal,
    ScrollRequestInternal, UpdateStatus, ckks_vector_sidecar_delete_target,
};
use collection::operations::universal_query::collection_query::{
    CollectionPrefetch, CollectionQueryRequest, Query, VectorInputInternal, VectorQuery,
};
use collection::operations::universal_query::formula::{ExpressionInternal, FormulaInternal};
use collection::operations::universal_query::shard_query::{
    FusionInternal, SampleInternal, ScoringQuery, ShardQueryRequest,
};
use collection::operations::vector_ops::{
    PointVectorsPersisted, UpdateVectorsOp, VectorOperations,
};
use collection::operations::vector_params_builder::VectorParamsBuilder;
use collection::operations::{CollectionUpdateOperations, OperationWithClockTag};
use collection::recommendations::{recommend_batch_by, recommend_by};
use collection::shards::channel_service::ChannelService;
use collection::shards::replica_set::replica_set_state::{ReplicaSetState, ReplicaState};
use common::budget::ResourceBudget;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::types::{DetailsLevel, TelemetryDetail};
use data_encoding::BASE64URL_NOPAD;
use fs_err::{self as fs, File};
use itertools::Itertools;
use qdrant_sec::{
    CLIENT_ENCRYPTED_PAYLOAD_MARKER, CLIENT_PAYLOAD_ENVELOPE_BINDING, CkksEncryptionInput,
    CkksError, CkksParameters, CkksPublicMaterial, CkksVectorBackend, CkksVectorEncryptor,
    CkksVectorVerifiedSidecarKey, ClientPayloadSignatureVerification,
    ClientPayloadValidationContext, ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_PAYLOAD_MARKER,
    ENCRYPTED_VECTOR_SIDECAR_FIELD, ExistingPayloadMode, METADATA_EXACT_MATCH_TOKEN_BINDING,
    METADATA_VALUE_BINDING, PAYLOAD_TEXT_ENVELOPE_KIND, PRIVATE_HNSW_ORAM_BINDING,
    PayloadEncryptionPolicy, PayloadTextEncryptor, SecretKey, ServerPayloadValidationContext,
    VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, client_payload_signature_message,
    is_client_encrypted_payload_value, is_encrypted_payload_value,
    validate_client_payload_value_for_runtime, validate_server_payload_value_metadata,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use segment::data_types::facets::FacetParams;
use segment::data_types::order_by::{Direction, OrderBy, OrderByInterface};
use segment::data_types::vectors::{DEFAULT_VECTOR_NAME, VectorInternal, VectorStructInternal};
use segment::json_path::{JsonPath, JsonPathItem};
use segment::types::{
    Condition, Distance, EncryptedPayloadReadMode, ExtendedPointId, FieldCondition, Filter,
    HasIdCondition, HasVectorCondition, Payload, PayloadEncryptedReadPolicy, PayloadFieldSchema,
    PayloadSchemaType, PointIdType, WithPayloadInterface, WithVector,
};
use serde_json::{Map, json};
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
use shard::payload_index_schema::PayloadIndexSchema;
use shard::search::CoreSearchRequestBatch;
use tempfile::Builder;

use crate::common::{
    N_SHARDS, REST_PORT, TEST_OPTIMIZERS_CONFIG, dummy_abort_shard_transfer,
    dummy_on_replica_failure, dummy_request_shard_transfer, encrypted_collection_fixture,
    load_local_collection, new_local_collection, simple_collection_fixture,
};

fn canonical_collection_tempdir() -> tempfile::TempDir {
    Builder::new()
        .prefix("collection")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap()
}

fn runtime_verified_client_envelopes_for_operation(
    operation: &CollectionUpdateOperations,
    collection_crypto_id: &str,
    public_key: &[u8],
) -> CollectionUpdateProvenance {
    let mut verified_envelope_keys = Vec::new();
    let mut collect_payload = |point_id: &PointIdType, payload: &Payload| {
        let Some(value) = payload
            .0
            .get("document")
            .and_then(|document| document.get("body"))
        else {
            return;
        };
        let key = validate_client_payload_value_for_runtime(
            value,
            ClientPayloadValidationContext {
                collection_id: collection_crypto_id,
                point_id: &point_id.to_string(),
                field_path: "document.body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(3),
                max_rk_epoch: Some(3),
                key_id_required: true,
                signature_required: true,
                signature_verification: Some(ClientPayloadSignatureVerification {
                    expected_key_id: "tenant-a/client-signing-v1",
                    public_key,
                }),
            },
        )
        .unwrap();
        verified_envelope_keys.push(key);
    };

    match operation {
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(points),
        )) => {
            for point in points {
                if let Some(payload) = &point.payload {
                    collect_payload(&point.id, payload);
                }
            }
        }
        CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(operation)) => {
            for point in &operation.points {
                if let Some(payload) = &point.payload {
                    collect_payload(&point.id, payload);
                }
            }
        }
        _ => {}
    }

    CollectionUpdateProvenance::runtime_verified_client_envelopes(verified_envelope_keys)
}

fn sign_client_payload(payload: &mut Payload, key_pair: &Ed25519KeyPair) {
    let value = payload
        .0
        .get_mut("document")
        .and_then(|document| document.get_mut("body"))
        .expect("client payload fixture must contain document.body");
    let message = client_payload_signature_message(value, "document.body").unwrap();
    let signature = key_pair.sign(&message);
    value
        .as_object_mut()
        .unwrap()
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("signature")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "sig".to_string(),
            serde_json::Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
        );
}

fn payload_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a:docs".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 0,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "document_body".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["document.body".to_string()],
            },
            instance: "docs_payload_v1".to_string(),
            binding: Some("payload-field/v1".to_string()),
        }],
    }
}

fn payload_text_encryptor_from_resource_key(
    collection: &str,
    key_id: &str,
    resource_key: SecretKey,
    material_fingerprint_id: &str,
) -> PayloadTextEncryptor {
    PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        collection,
        key_id,
        &resource_key,
        material_fingerprint_id,
    )
    .unwrap()
}

fn payload_encryption_with_blind_index_config() -> CollectionEncryptionConfig {
    let mut config = payload_encryption_config();
    config.rules.push(EncryptionRuleRef {
        id: "document_body_blind_eq".to_string(),
        selector: EncryptionSelector::MetadataKeys {
            keys: vec!["document_body__blind_eq".to_string()],
        },
        instance: "docs_body_blind_v1".to_string(),
        binding: Some(METADATA_EXACT_MATCH_TOKEN_BINDING.to_string()),
    });
    config
}

fn client_payload_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a/client-rk-2026-04".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 3,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "document_body_client".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["document.body".to_string()],
            },
            instance: "docs_payload_client_v1".to_string(),
            binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
        }],
    }
}

fn client_payload_encryption_with_blind_index_config() -> CollectionEncryptionConfig {
    let mut config = client_payload_encryption_config();
    config.rules.push(EncryptionRuleRef {
        id: "document_body_blind_eq".to_string(),
        selector: EncryptionSelector::MetadataKeys {
            keys: vec!["document_body__blind_eq".to_string()],
        },
        instance: "docs_body_blind_v1".to_string(),
        binding: Some(METADATA_EXACT_MATCH_TOKEN_BINDING.to_string()),
    });
    config
}

fn vector_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a:docs".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 0,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "default_vector".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec![DEFAULT_VECTOR_NAME.to_string()],
            },
            instance: "docs_vector_v1".to_string(),
            binding: Some("vector-envelope/v1".to_string()),
        }],
    }
}

fn private_hnsw_vector_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a/vector-private-rk".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 7,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "default_private_hnsw".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec![DEFAULT_VECTOR_NAME.to_string()],
            },
            instance: "docs_text_private_hnsw".to_string(),
            binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
        }],
    }
}

fn private_result_oram_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a:result-private-rk".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 7,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "document_body_private_result".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["document.body".to_string()],
            },
            instance: "docs_private_result_oram_v1".to_string(),
            binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
        }],
    }
}

fn assert_private_hnsw_session_api_error(err: CollectionError) {
    assert_private_hnsw_session_api_error_without(err, &[]);
}

fn assert_private_hnsw_session_api_error_without(err: CollectionError, forbidden: &[&str]) {
    let CollectionError::BadInput { description } = err else {
        panic!("unexpected error: {err:?}");
    };
    assert!(
        description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
            && description.contains("client-led private ORAM sessions")
            && description.contains("/private-hnsw/")
            && description.contains("/session")
            && !description.contains("runtime CKKS"),
        "unexpected error: {description}",
    );
    for operation_label in [
        "retrieve",
        "scroll",
        "search",
        "query",
        "recommend",
        "discover",
        "delete points",
        "delete points by filter",
        "sync points",
        "upsert",
        "update vectors",
    ] {
        assert!(!description.contains(operation_label), "{description}");
    }
    for value in forbidden {
        assert!(!description.contains(value), "{description}");
    }
}

fn assert_private_result_oram_read_error_without(
    err: CollectionError,
    operation: &str,
    forbidden: &[&str],
) {
    let CollectionError::BadInput { description } = err else {
        panic!("unexpected error: {err:?}");
    };
    assert!(
        description.contains("cannot read private result ORAM payload field")
            && description.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
            && description.contains("/private-result-oram/session")
            && !description.contains("runtime payload encryption"),
        "unexpected error: {description}",
    );
    assert_private_result_oram_error_omits_operation_labels(&description);
    assert!(!description.contains(operation), "{description}");
    for value in forbidden {
        assert!(!description.contains(value), "{description}");
    }
}

fn assert_private_result_oram_write_error_without(
    err: CollectionError,
    operation: &str,
    forbidden: &[&str],
) {
    let CollectionError::BadInput { description } = err else {
        panic!("unexpected error: {err:?}");
    };
    assert!(
        description.contains("cannot modify private result ORAM payload field")
            && description.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
            && description.contains("/private-result-oram/session")
            && !description.contains("runtime payload encryption"),
        "unexpected error: {description}",
    );
    assert_private_result_oram_error_omits_operation_labels(&description);
    assert!(!description.contains(operation), "{description}");
    for value in forbidden {
        assert!(!description.contains(value), "{description}");
    }
}

fn assert_private_result_oram_selector_error_without(
    err: CollectionError,
    operation: &str,
    forbidden: &[&str],
) {
    let CollectionError::BadInput { description } = err else {
        panic!("unexpected error: {err:?}");
    };
    assert!(
        description.contains("cannot use private result ORAM payload field")
            && description.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
            && description.contains("/private-result-oram/session")
            && !description.contains("blind index")
            && !description.contains("runtime payload encryption"),
        "unexpected error: {description}",
    );
    assert_private_result_oram_error_omits_operation_labels(&description);
    if operation != "use" {
        assert!(!description.contains(operation), "{description}");
    }
    for value in forbidden {
        assert!(!description.contains(value), "{description}");
    }
}

fn assert_private_result_oram_error_omits_operation_labels(description: &str) {
    for operation_label in [
        "retrieve",
        "scroll",
        "search",
        "query",
        "recommend",
        "discover",
        "group lookup",
        "filter on",
        "order by",
        "facet on",
        "group by",
        "use formula condition on",
        "upsert",
        "conditional upsert",
        "delete points",
        "delete points by filter",
        "set payload",
        "overwrite payload",
        "delete payload",
        "delete payload by filter",
        "clear payload",
        "clear payload by filter",
    ] {
        assert!(!description.contains(operation_label), "{description}");
    }
}

#[derive(Clone, Copy)]
struct CollectionTestCkksBackend;

impl CkksVectorBackend for CollectionTestCkksBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        Ok(format!(
            "test-ciphertext:{}:{}:{}",
            input.collection, input.point_id, input.vector_name
        )
        .into_bytes())
    }
}

fn encrypted_payload_filter() -> Filter {
    Filter::new_must(Condition::Field(FieldCondition::new_match(
        "document.body".parse().unwrap(),
        serde_json::from_str(r#"{ "value": "secret body" }"#).unwrap(),
    )))
}

fn encrypted_vector_sidecar_filter() -> Filter {
    Filter::new_must(Condition::Field(FieldCondition::new_match(
        format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
            .parse()
            .unwrap(),
        serde_json::from_str(r#"{ "value": "opaque" }"#).unwrap(),
    )))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_updater() {
    test_collection_updater_with_shards(1).await;
    test_collection_updater_with_shards(N_SHARDS).await;
}

async fn test_collection_updater_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
            vec![1.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 0.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    let insert_result = collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await;

    match insert_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    let search_request = SearchRequestInternal {
        vector: vec![1.0, 1.0, 1.0, 1.0].into(),
        with_payload: None,
        with_vector: None,
        filter: None,
        params: None,
        limit: 3,
        offset: None,
        score_threshold: None,
    };

    let hw_acc = HwMeasurementAcc::new();
    let search_res = collection
        .search(
            search_request.into(),
            None,
            &ShardSelectorInternal::All,
            None,
            hw_acc,
        )
        .await;

    match search_res {
        Ok(res) => {
            assert_eq!(res.len(), 3);
            assert_eq!(res[0].id, 2.into());
            assert!(res[0].payload.is_none());
        }
        Err(err) => panic!("search failed: {err:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_search_with_payload_and_vector() {
    test_collection_search_with_payload_and_vector_with_shards(1).await;
    test_collection_search_with_payload_and_vector_with_shards(N_SHARDS).await;
}

async fn test_collection_search_with_payload_and_vector_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0.into(), 1.into()],
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
        ]),
        payloads: serde_json::from_str(
            r#"[{ "k": { "type": "keyword", "value": "v1" } }, { "k": "v2" , "v": "v3"}]"#,
        )
        .unwrap(),
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    let insert_result = collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await;

    match insert_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    let search_request = SearchRequestInternal {
        vector: vec![1.0, 0.0, 1.0, 1.0].into(),
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: Some(true.into()),
        filter: None,
        params: None,
        limit: 3,
        offset: None,
        score_threshold: None,
    };

    let hw_acc = HwMeasurementAcc::new();
    let search_res = collection
        .search(
            search_request.into(),
            None,
            &ShardSelectorInternal::All,
            None,
            hw_acc,
        )
        .await;

    match search_res {
        Ok(res) => {
            assert_eq!(res.len(), 2);
            assert_eq!(res[0].id, 0.into());
            assert_eq!(res[0].payload.as_ref().unwrap().len(), 1);
            let vec = vec![1.0, 0.0, 1.0, 1.0];
            match &res[0].vector {
                Some(VectorStructInternal::Single(v)) => assert_eq!(v.clone(), vec),
                _ => panic!("vector is not returned"),
            }
        }
        Err(err) => panic!("search failed: {err:?}"),
    }

    let count_request = CountRequestInternal {
        filter: Some(Filter::new_must(Condition::Field(
            FieldCondition::new_match(
                "k".parse().unwrap(),
                serde_json::from_str(r#"{ "value": "v2" }"#).unwrap(),
            ),
        ))),
        exact: true,
    };

    let hw_acc = HwMeasurementAcc::new();
    let count_res = collection
        .count(
            count_request,
            None,
            &ShardSelectorInternal::All,
            None,
            hw_acc,
        )
        .await
        .unwrap();
    assert_eq!(count_res.count, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_loading() {
    test_collection_loading_with_shards(1).await;
    test_collection_loading_with_shards(N_SHARDS).await;
}

async fn test_collection_loading_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    {
        let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

        let batch = BatchPersisted {
            ids: vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| x.into())
                .collect_vec(),
            vectors: BatchVectorStructPersisted::Single(vec![
                vec![1.0, 0.0, 1.0, 1.0],
                vec![1.0, 0.0, 1.0, 0.0],
                vec![1.0, 1.0, 1.0, 1.0],
                vec![1.0, 1.0, 0.0, 1.0],
                vec![1.0, 0.0, 0.0, 0.0],
            ]),
            payloads: None,
        };

        let insert_points = CollectionUpdateOperations::PointOperation(
            PointOperations::UpsertPoints(PointInsertOperationsInternal::from(batch)),
        );

        let hw_counter = HwMeasurementAcc::new();
        collection
            .update_from_client_simple(
                insert_points,
                true,
                None,
                WriteOrdering::default(),
                hw_counter,
            )
            .await
            .unwrap();

        let payload: Payload = serde_json::from_str(r#"{"color":"red"}"#).unwrap();

        let assign_payload =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload,
                points: Some(vec![2.into(), 3.into()]),
                filter: None,
                key: None,
            }));

        let hw_counter = HwMeasurementAcc::new();
        collection
            .update_from_client_simple(
                assign_payload,
                true,
                None,
                WriteOrdering::default(),
                hw_counter,
            )
            .await
            .unwrap();

        collection.stop_gracefully().await;
    }

    let collection_path = collection_dir.path();
    let loaded_collection = load_local_collection(
        "test".to_string(),
        collection_path,
        &collection_path.join("snapshots"),
    )
    .await;
    let request = PointRequestInternal {
        ids: vec![1.into(), 2.into()],
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: true.into(),
    };
    let retrieved = loaded_collection
        .retrieve(
            request,
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    assert_eq!(retrieved.len(), 2);

    for record in retrieved {
        if record.id == 2.into() {
            let non_empty_payload = record.payload.unwrap();

            assert_eq!(non_empty_payload.len(), 1)
        }
    }

    loaded_collection.stop_gracefully().await;
    println!("Function end");
}

#[test]
fn test_deserialization() {
    let batch = BatchPersisted {
        ids: vec![0.into(), 1.into()],
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));
    let json_str = serde_json::to_string_pretty(&insert_points).unwrap();

    let _read_obj: CollectionUpdateOperations = serde_json::from_str(&json_str).unwrap();

    let crob_bytes = rmp_serde::to_vec(&insert_points).unwrap();

    let _read_obj2: CollectionUpdateOperations = rmp_serde::from_slice(&crob_bytes).unwrap();
}

#[test]
fn test_deserialization2() {
    let points = vec![
        PointStructPersisted {
            id: 0.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 1.0, 1.0]),
            payload: None,
        },
        PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 1.0, 0.0]),
            payload: None,
        },
    ];

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(points),
    ));

    let json_str = serde_json::to_string_pretty(&insert_points).unwrap();

    let _read_obj: CollectionUpdateOperations = serde_json::from_str(&json_str).unwrap();

    let raw_bytes = rmp_serde::to_vec(&insert_points).unwrap();

    let _read_obj2: CollectionUpdateOperations = rmp_serde::from_slice(&raw_bytes).unwrap();
}

// Request to find points sent to all shards but they might not have a particular id, so they will return an error
#[tokio::test(flavor = "multi_thread")]
async fn test_recommendation_api() {
    test_recommendation_api_with_shards(1).await;
    test_recommendation_api_with_shards(N_SHARDS).await;
}

async fn test_recommendation_api_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 0.0, 0.0, 1.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_acc = HwMeasurementAcc::new();
    collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_acc.clone(),
        )
        .await
        .unwrap();
    let result = recommend_by(
        RecommendRequestInternal {
            positive: vec![0.into()],
            negative: vec![8.into()],
            limit: 5,
            ..Default::default()
        },
        &collection,
        |_name| async { unreachable!("Should not be called in this test") },
        None,
        ShardSelectorInternal::All,
        None,
        hw_acc,
    )
    .await
    .unwrap();
    assert!(!result.is_empty());
    let top1 = &result[0];

    assert!(top1.id == 5.into() || top1.id == 6.into());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_read_api() {
    test_read_api_with_shards(1).await;
    test_read_api_with_shards(N_SHARDS).await;
}

async fn test_read_api_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 0.0, 0.0, 1.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await
        .unwrap();

    let result = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(2),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.next_page_offset, Some(2.into()));
    assert_eq!(result.points.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ordered_read_api() {
    test_ordered_scroll_api_with_shards(1).await;
    test_ordered_scroll_api_with_shards(N_SHARDS).await;
}

async fn test_ordered_scroll_api_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    const PRICE_FLOAT_KEY: &str = "price_float";
    const PRICE_INT_KEY: &str = "price_int";
    const MULTI_VALUE_KEY: &str = "multi_value";

    let get_payload = |value: f64| -> Option<Payload> {
        let mut payload_map = Map::new();
        payload_map.insert(PRICE_FLOAT_KEY.to_string(), value.into());
        payload_map.insert(PRICE_INT_KEY.to_string(), (value as i64).into());
        payload_map.insert(
            MULTI_VALUE_KEY.to_string(),
            vec![value, value + 20.0].into(),
        );
        Some(Payload(payload_map))
    };

    let payloads: Vec<Option<Payload>> = vec![
        get_payload(11.0),
        get_payload(10.0),
        get_payload(9.0),
        get_payload(8.0),
        get_payload(7.0),
        get_payload(6.0),
        get_payload(5.0),
        get_payload(5.0),
        get_payload(5.0),
        get_payload(5.0),
        get_payload(4.0),
        get_payload(3.0),
        get_payload(2.0),
        get_payload(1.0),
    ];

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 1.0, 1.0],
        ]),
        payloads: Some(payloads),
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter.clone(),
        )
        .await
        .unwrap();

    collection
        .create_payload_index_with_wait(
            PRICE_FLOAT_KEY.parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Float),
            true,
            hw_counter.clone(),
        )
        .await
        .unwrap();

    collection
        .create_payload_index_with_wait(
            PRICE_INT_KEY.parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Integer),
            true,
            hw_counter.clone(),
        )
        .await
        .unwrap();

    collection
        .create_payload_index_with_wait(
            MULTI_VALUE_KEY.parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Float),
            true,
            hw_counter.clone(),
        )
        .await
        .unwrap();

    ///////// Test single-valued fields ///////////
    for key in [PRICE_FLOAT_KEY, PRICE_INT_KEY] {
        let result_asc = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(3),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Asc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        assert_eq!(result_asc.points.len(), 3);
        assert_eq!(result_asc.next_page_offset, None);
        assert!(result_asc.points.iter().tuple_windows().all(|(a, b)| {
            let a = a.payload.as_ref().unwrap();
            let b = b.payload.as_ref().unwrap();
            let a = a.0.get(key).unwrap().as_f64();
            let b = b.0.get(key).unwrap().as_f64();
            a <= b
        }));

        let result_desc = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(5),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Desc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        assert_eq!(result_desc.points.len(), 5);
        assert_eq!(result_desc.next_page_offset, None);
        assert!(
            result_desc.points.iter().tuple_windows().all(|(a, b)| {
                let a = a.payload.as_ref().unwrap();
                let b = b.payload.as_ref().unwrap();
                let a = a.0.get(key).unwrap().as_f64();
                let b = b.0.get(key).unwrap().as_f64();
                a >= b
            }),
            "Expected descending order when using {key} key, got: {:#?}",
            result_desc.points
        );

        let asc_already_seen: AHashSet<_> = result_asc.points.iter().map(|x| x.id).collect();

        dbg!(&asc_already_seen);
        let asc_second_page = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(5),
                    filter: Some(Filter::new_must_not(Condition::HasId(
                        HasIdCondition::from(asc_already_seen),
                    ))),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Asc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        let asc_second_page_points = asc_second_page
            .points
            .iter()
            .map(|x| x.id)
            .collect::<HashSet<_>>();
        let valid_asc_second_page_points = [10, 9, 8, 7, 6]
            .into_iter()
            .map(|x| x.into())
            .collect::<HashSet<ExtendedPointId>>();
        assert_eq!(asc_second_page.points.len(), 5);
        assert!(asc_second_page_points.is_subset(&valid_asc_second_page_points));

        let desc_already_seen: AHashSet<_> = result_desc.points.iter().map(|x| x.id).collect();

        dbg!(&desc_already_seen);

        let desc_second_page = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(4),
                    filter: Some(Filter::new_must_not(Condition::HasId(
                        HasIdCondition::from(desc_already_seen),
                    ))),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Desc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        let desc_second_page_points = desc_second_page
            .points
            .iter()
            .map(|x| x.id)
            .collect::<HashSet<_>>();

        let valid_desc_second_page_points = [5, 6, 7, 8, 9]
            .into_iter()
            .map(|x| x.into())
            .collect::<HashSet<ExtendedPointId>>();

        assert_eq!(desc_second_page.points.len(), 4);
        assert!(
            desc_second_page_points.is_subset(&valid_desc_second_page_points),
            "expected: {valid_desc_second_page_points:?}, got: {desc_second_page_points:?}"
        );
    }

    ///////// Test multi-valued field ///////////
    let result_multi = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(100),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Key(MULTI_VALUE_KEY.parse().unwrap())),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    assert!(
        result_multi
            .points
            .iter()
            .fold(HashMap::<PointIdType, usize, _>::new(), |mut acc, point| {
                acc.entry(point.id)
                    .and_modify(|x| {
                        *x += 1;
                    })
                    .or_insert(1);
                acc
            })
            .values()
            .all(|&x| x == 2),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_payload_index() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    for indexed_field in ["document.body", "document", "document.body.keyword"] {
        let err = collection
            .create_payload_index_with_wait(
                indexed_field.parse().unwrap(),
                PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
                true,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
                CollectionError::BadInput { description }
                if description.contains("encrypted payload field")
                    && !description.contains("document.body")
                    && description.contains("blind index")
        ));
    }

    collection
        .create_payload_index_with_wait(
            "document.summary".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            true,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_recovered_payload_index_schema() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let snapshot_dir = collection_dir.path().join("snapshots");

    let mut payload_schema = PayloadIndexSchema::default();
    payload_schema.schema.insert(
        "document.body".parse().unwrap(),
        PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
    );
    fs::write(
        collection_dir.path().join(PAYLOAD_INDEX_CONFIG_FILE),
        serde_json::to_vec(&payload_schema).unwrap(),
    )
    .unwrap();

    let collection_config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorParamsBuilder::new(4, Distance::Dot).build().into(),
            shard_number: NonZeroU32::new(1).unwrap(),
            encryption: Some(payload_encryption_config()),
            ..CollectionParams::empty()
        },
        optimizer_config: TEST_OPTIMIZERS_CONFIG.clone(),
        wal_config: WalConfig {
            wal_capacity_mb: 1,
            wal_segments_ahead: 0,
            wal_retain_closed: 1,
        },
        hnsw_config: Default::default(),
        quantization_config: Default::default(),
        strict_mode_config: Default::default(),
        uuid: None,
        metadata: None,
    };

    let err = match new_local_collection(
        "test".to_string(),
        collection_dir.path(),
        &snapshot_dir,
        &collection_config,
    )
    .await
    {
        Ok(_) => panic!("expected encrypted payload index schema recovery to fail"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
            CollectionError::BadInput { ref description }
            if description.contains("payload index schema")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_plan_updates_collection_config_through_admin_path() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: None,
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let start_rotation = CryptoMigrationPlan {
        from: CryptoMigrationState::Active,
        to: CryptoMigrationState::Rotating,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: true,
        checkpoints: Vec::new(),
    };

    collection
        .apply_crypto_migration_plan(&start_rotation)
        .await
        .unwrap();
    let dry_run_config = collection.config_snapshot().await;
    let dry_run_encryption = dry_run_config.params.encryption.unwrap();
    assert_eq!(
        dry_run_encryption.migration_state,
        CryptoMigrationState::Active
    );
    assert_eq!(dry_run_encryption.encryption_epoch, 0);

    let mut start_rotation = start_rotation;
    start_rotation.dry_run = false;
    collection
        .apply_crypto_migration_plan(&start_rotation)
        .await
        .unwrap();
    let rotating_config = collection.config_snapshot().await;
    let rotating_encryption = rotating_config.params.encryption.unwrap();
    assert_eq!(
        rotating_encryption.migration_state,
        CryptoMigrationState::Rotating
    );
    assert_eq!(rotating_encryption.encryption_epoch, 1);

    let regular_write_err = collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 99.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: None,
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        regular_write_err,
        CollectionError::BadInput { ref description }
            if description.contains("encryption migration")
                && description.contains("regular writes")
    ));

    let assert_migration_read_error = |err: CollectionError| {
        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("encryption migration")
                    && description.contains("regular reads")
        ));
    };

    assert_migration_read_error(
        collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: None,
                    with_vector: false.into(),
                    order_by: None,
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err(),
    );
    assert_migration_read_error(
        collection
            .count(
                CountRequestInternal {
                    filter: None,
                    exact: true,
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err(),
    );
    assert_migration_read_error(
        collection
            .retrieve(
                PointRequestInternal {
                    ids: vec![0.into()],
                    with_payload: None,
                    with_vector: WithVector::Bool(false),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err(),
    );
    assert_migration_read_error(
        collection
            .search(
                SearchRequestInternal {
                    vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                    with_payload: None,
                    with_vector: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err(),
    );
    assert_migration_read_error(
        collection
            .query(
                ShardQueryRequest {
                    prefetches: vec![],
                    query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                },
                None,
                ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err(),
    );

    let stale_start = CryptoMigrationPlan {
        from: CryptoMigrationState::Active,
        to: CryptoMigrationState::Rotating,
        target_epoch: 2,
        active_rk_id: Some("tenant-a/payload-rk-v3".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        dry_run: false,
        checkpoints: Vec::new(),
    };
    let err = collection
        .apply_crypto_migration_plan(&stale_start)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description == "invalid crypto migration plan"
                && !description.contains("crypto_migration_current_state_mismatch")
    ));

    let mismatched_checkpoint = CryptoMigrationPlan {
        from: CryptoMigrationState::Rotating,
        to: CryptoMigrationState::Active,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 0,
            processed_points: 0,
            rewritten_points: 0,
            changed_points: 0,
            status: CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    let err = collection
        .apply_crypto_migration_plan(&mismatched_checkpoint)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("completion checkpoint")
                && description.contains("local shard contains 1")
    ));

    let complete_rotation = CryptoMigrationPlan {
        from: CryptoMigrationState::Rotating,
        to: CryptoMigrationState::Active,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 1,
            processed_points: 1,
            rewritten_points: 1,
            changed_points: 0,
            status: CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    collection
        .apply_crypto_migration_plan(&complete_rotation)
        .await
        .unwrap();
    let active_config = collection.config_snapshot().await;
    let active_encryption = active_config.params.encryption.unwrap();
    assert_eq!(
        active_encryption.migration_state,
        CryptoMigrationState::Active
    );
    assert_eq!(active_encryption.encryption_epoch, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rewrites_stale_payload_envelopes_and_returns_checkpoints() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = Arc::new(
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await,
    );
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
    let old_resource_key = SecretKey::from_bytes([41u8; 32]);
    let new_resource_key = SecretKey::from_bytes([42u8; 32]);

    let old_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        &collection_crypto_id,
        "tenant-a:docs",
        &old_resource_key,
        "tenant-a/docs@v0",
        "tenant-a/docs-rk-v0",
        0,
    )
    .unwrap()
    .with_encryption_epoch(0);
    let mut stale_payload = Payload(
        serde_json::json!({ "document": { "body": "rotate me" } })
            .as_object()
            .unwrap()
            .clone(),
    );
    let (changed, verified_server_envelope_keys) = old_encryptor
        .encrypt_selected_fields_for_runtime(
            "1",
            &mut stale_payload.0,
            &policy,
            &collection_crypto_id,
        )
        .unwrap();
    assert_eq!(changed, 1);

    let stale_upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(stale_payload),
        }]),
    ));
    collection
        .update_from_client(
            stale_upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(verified_server_envelope_keys),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/docs-rk-v1".to_string()),
            retired_rk_id: Some("tenant-a/docs-rk-v0".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let rotating_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        &collection_crypto_id,
        "tenant-a:docs",
        &new_resource_key,
        "tenant-a/docs@v1",
        "tenant-a/docs-rk-v1",
        1,
    )
    .unwrap()
    .with_encryption_epoch(1)
    .with_retired_resource_key_metadata(
        "tenant-a:docs",
        &old_resource_key,
        "tenant-a/docs@v0",
        "tenant-a/docs-rk-v0",
        0,
    )
    .unwrap();

    let blocking_collection = Arc::clone(&collection);
    let blocking_collection_crypto_id = collection_crypto_id.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocking_migration = tokio::spawn(async move {
        blocking_collection
            .dry_run_payloads_for_crypto_migration(move |point_id, payload| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .map_err(|err| {
                        CollectionError::service_error(format!(
                            "timed out waiting to release blocking crypto migration test: {err}",
                        ))
                    })?;

                let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
                let old_resource_key = SecretKey::from_bytes([41u8; 32]);
                let new_resource_key = SecretKey::from_bytes([42u8; 32]);
                let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
                    &blocking_collection_crypto_id,
                    "tenant-a:docs",
                    &new_resource_key,
                    "tenant-a/docs@v1",
                    "tenant-a/docs-rk-v1",
                    1,
                )
                .unwrap()
                .with_encryption_epoch(1)
                .with_retired_resource_key_metadata(
                    "tenant-a:docs",
                    &old_resource_key,
                    "tenant-a/docs@v0",
                    "tenant-a/docs-rk-v0",
                    0,
                )
                .unwrap();

                encryptor
                    .encrypt_selected_fields_with_mode_for_runtime(
                        &point_id.to_string(),
                        &mut payload.0,
                        &policy,
                        &blocking_collection_crypto_id,
                        ExistingPayloadMode::ReencryptIfStale,
                    )
                    .map_err(|err| CollectionError::bad_input(err.to_string()))
            })
            .await
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let concurrent_err = collection
        .dry_run_payloads_for_crypto_migration(|_, _| Ok(0))
        .await
        .unwrap_err();
    assert!(
        matches!(concurrent_err, CollectionError::BadInput { ref description }
            if description.contains("already running")),
        "unexpected concurrent migration error: {concurrent_err:?}",
    );
    release_tx.send(()).unwrap();
    blocking_migration.await.unwrap().unwrap();

    let dry_run_checkpoints = collection
        .dry_run_payloads_for_crypto_migration(|point_id, payload| {
            rotating_encryptor
                .encrypt_selected_fields_with_mode_for_runtime(
                    &point_id.to_string(),
                    &mut payload.0,
                    &policy,
                    &collection_crypto_id,
                    ExistingPayloadMode::ReencryptIfStale,
                )
                .map_err(|err| CollectionError::bad_input(err.to_string()))
        })
        .await
        .unwrap();
    assert_eq!(dry_run_checkpoints.len(), 1);
    assert_eq!(dry_run_checkpoints[0].changed_points, 1);

    let checkpoints = collection
        .rewrite_payloads_for_crypto_migration(|point_id, payload| {
            rotating_encryptor
                .encrypt_selected_fields_with_mode_for_runtime(
                    &point_id.to_string(),
                    &mut payload.0,
                    &policy,
                    &collection_crypto_id,
                    ExistingPayloadMode::ReencryptIfStale,
                )
                .map_err(|err| CollectionError::bad_input(err.to_string()))
        })
        .await
        .unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].total_points, 1);
    assert_eq!(checkpoints[0].processed_points, 1);
    assert_eq!(checkpoints[0].rewritten_points, 1);
    assert_eq!(checkpoints[0].changed_points, 1);
    assert_eq!(
        checkpoints[0].status,
        CryptoMigrationCheckpointStatus::Verified
    );
    let checkpoints = collection
        .rewrite_payloads_for_crypto_migration(|point_id, payload| {
            rotating_encryptor
                .encrypt_selected_fields_with_mode_for_runtime(
                    &point_id.to_string(),
                    &mut payload.0,
                    &policy,
                    &collection_crypto_id,
                    ExistingPayloadMode::ReencryptIfStale,
                )
                .map_err(|err| CollectionError::bad_input(err.to_string()))
        })
        .await
        .unwrap();
    assert_eq!(
        checkpoints[0].rewritten_points, 1,
        "rerunning migration over already-current payloads must still produce a completion checkpoint",
    );
    assert_eq!(
        checkpoints[0].changed_points, 0,
        "rerunning migration over already-current payloads must report no byte changes",
    );

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Rotating,
            to: CryptoMigrationState::Active,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/docs-rk-v1".to_string()),
            retired_rk_id: Some("tenant-a/docs-rk-v0".to_string()),
            dry_run: false,
            checkpoints,
        })
        .await
        .unwrap();

    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let body = records[0]
        .payload
        .as_ref()
        .unwrap()
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    assert!(is_encrypted_payload_value(body));
    assert_ne!(body, &serde_json::json!("rotate me"));
    assert_eq!(
        body.get(ENCRYPTED_PAYLOAD_MARKER)
            .and_then(|marker| marker.get("encryption_epoch"))
            .and_then(|epoch| epoch.as_u64()),
        Some(1),
    );
    assert_eq!(
        body.get(ENCRYPTED_PAYLOAD_MARKER)
            .and_then(|marker| marker.get("envelope"))
            .and_then(|envelope| envelope.get("material_fingerprint"))
            .and_then(|fingerprint| fingerprint.as_str()),
        Some("tenant-a/docs@v1"),
    );
    assert_eq!(
        body.get(ENCRYPTED_PAYLOAD_MARKER)
            .and_then(|marker| marker.get("envelope"))
            .and_then(|envelope| envelope.get("rk_epoch"))
            .and_then(|epoch| epoch.as_u64()),
        Some(1),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_decrypts_payload_envelopes_and_returns_checkpoints() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let mut encryption_config = payload_encryption_config();
    encryption_config.encryption_epoch = 1;
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, encryption_config).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
    let resource_key = SecretKey::from_bytes([43u8; 32]);

    let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        &collection_crypto_id,
        "tenant-a:docs",
        &resource_key,
        "tenant-a/docs@v1",
        "tenant-a/docs-rk-v1",
        1,
    )
    .unwrap()
    .with_encryption_epoch(1);
    let mut encrypted_payload = Payload(
        serde_json::json!({ "document": { "body": "decrypt me" } })
            .as_object()
            .unwrap()
            .clone(),
    );
    let (_, verified_server_envelope_keys) = encryptor
        .encrypt_selected_fields_for_runtime(
            "1",
            &mut encrypted_payload.0,
            &policy,
            &collection_crypto_id,
        )
        .unwrap();

    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(encrypted_payload),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(verified_server_envelope_keys),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Decrypting,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/docs-rk-v1".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, _| Ok(0))
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must decrypt server-side encrypted field during decrypting migration")
                && !description.contains("document.body")),
        "unexpected error: {err:?}",
    );

    let checkpoints = collection
        .rewrite_payloads_for_crypto_migration(|point_id, payload| {
            encryptor
                .decrypt_selected_fields_if_encrypted(
                    &point_id.to_string(),
                    &mut payload.0,
                    &policy,
                )
                .map_err(|err| CollectionError::bad_input(err.to_string()))
        })
        .await
        .unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].total_points, 1);
    assert_eq!(checkpoints[0].processed_points, 1);
    assert_eq!(checkpoints[0].rewritten_points, 1);
    assert_eq!(checkpoints[0].changed_points, 1);

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Decrypting,
            to: CryptoMigrationState::Disabled,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/docs-rk-v1".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints,
        })
        .await
        .unwrap();

    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let body = records[0]
        .payload
        .as_ref()
        .unwrap()
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(body, &serde_json::json!("decrypt me"));
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_decrypt_completion_disables_effective_encryption() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();
    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Rotating,
            to: CryptoMigrationState::Active,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 0,
                processed_points: 0,
                rewritten_points: 0,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        })
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Decrypting,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let decrypting_config = collection.config_snapshot().await;
    assert!(decrypting_config.params.effective_encryption().is_some());

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Decrypting,
            to: CryptoMigrationState::Disabled,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: None,
            dry_run: false,
            checkpoints: vec![CryptoMigrationCheckpoint {
                shard_id: 0,
                total_points: 0,
                processed_points: 0,
                rewritten_points: 0,
                changed_points: 0,
                status: CryptoMigrationCheckpointStatus::Verified,
            }],
        })
        .await
        .unwrap();

    let disabled_config = collection.config_snapshot().await;
    assert!(
        disabled_config.params.effective_encryption().is_none(),
        "verified decrypt completion must stop enforcing encryption guards",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn plaintext_collection_load_ignores_malformed_client_nonce_cache() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let snapshots_path = collection_dir.path().join("snapshots");
    let collection = simple_collection_fixture(collection_dir.path(), 1).await;
    collection.stop_gracefully().await;

    fs::write(
        collection_dir
            .path()
            .join("client_payload_nonce_replay.cache"),
        "not-a-valid-cache-key\n",
    )
    .unwrap();

    let loaded =
        load_local_collection("test".to_string(), collection_dir.path(), &snapshots_path).await;
    loaded.stop_gracefully().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn server_encrypted_collection_load_ignores_malformed_client_nonce_cache() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let snapshots_path = collection_dir.path().join("snapshots");
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;
    collection.stop_gracefully().await;

    fs::write(
        collection_dir
            .path()
            .join("client_payload_nonce_replay.cache"),
        "not-a-valid-cache-key\n",
    )
    .unwrap();

    let loaded =
        load_local_collection("test".to_string(), collection_dir.path(), &snapshots_path).await;
    loaded.stop_gracefully().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_collection_load_rejects_malformed_client_nonce_cache() {
    let collection_dir = canonical_collection_tempdir();
    let snapshots_path = collection_dir.path().join("snapshots");
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, client_payload_encryption_config())
            .await;
    collection.stop_gracefully().await;

    let cache_path = collection_dir
        .path()
        .join("client_payload_nonce_replay.cache");
    fs::write(&cache_path, "not-a-valid-cache-key\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let err = match Collection::load(
        "test".to_string(),
        0,
        collection_dir.path(),
        &snapshots_path,
        Default::default(),
        ChannelService::new(REST_PORT, false, None, None),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    {
        Ok(collection) => {
            collection.stop_gracefully().await;
            panic!("client encrypted collection load must reject malformed nonce cache")
        }
        Err(err) => err,
    };
    assert!(format!("{err:?}").contains("client payload nonce replay cache"));
    assert!(format!("{err:?}").contains("malformed entry"));
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rewrites_payload_when_closure_underreports_change() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
    let resource_key = SecretKey::from_bytes([41u8; 32]);
    let new_resource_key = SecretKey::from_bytes([42u8; 32]);
    let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        &collection_crypto_id,
        "tenant-a:docs",
        &resource_key,
        "tenant-a/docs@v0",
        "tenant-a/payload-rk-v1",
        0,
    )
    .unwrap()
    .with_encryption_epoch(0);

    let mut encrypted_payload = Payload(
        serde_json::json!({ "document": { "body": "old" } })
            .as_object()
            .unwrap()
            .clone(),
    );
    let (_, verified_server_envelope_keys) = encryptor
        .encrypt_selected_fields_for_runtime(
            "1",
            &mut encrypted_payload.0,
            &policy,
            &collection_crypto_id,
        )
        .unwrap();
    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(encrypted_payload),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(verified_server_envelope_keys),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, _| Ok(0))
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must provide a runtime server-envelope proof for server-side encrypted field")
                && !description.contains("document.body")),
        "unexpected error: {err:?}",
    );

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            let body = payload
                .0
                .get_mut("document")
                .and_then(|document| document.get_mut("body"))
                .expect("test payload must contain document.body");
            *body = serde_json::json!("new");
            Ok(0)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must leave server-side encrypted field as an encrypted marker")
                && !description.contains("document.body")),
        "unexpected error: {err:?}",
    );

    let rotating_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        &collection_crypto_id,
        "tenant-a:docs",
        &new_resource_key,
        "tenant-a/docs@v1",
        "tenant-a/payload-rk-v2",
        1,
    )
    .unwrap()
    .with_encryption_epoch(1)
    .with_retired_resource_key_metadata(
        "tenant-a:docs",
        &resource_key,
        "tenant-a/docs@v0",
        "tenant-a/payload-rk-v1",
        0,
    )
    .unwrap();
    let checkpoints = collection
        .rewrite_payloads_for_crypto_migration(|point_id, payload| {
            rotating_encryptor
                .encrypt_selected_fields_with_mode_for_runtime(
                    &point_id.to_string(),
                    &mut payload.0,
                    &policy,
                    &collection_crypto_id,
                    ExistingPayloadMode::ReencryptIfStale,
                )
                .map(|(_, verified_envelope_keys)| (0, verified_envelope_keys))
                .map_err(|err| CollectionError::bad_input(err.to_string()))
        })
        .await
        .unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].rewritten_points, 1);
    assert_eq!(checkpoints[0].changed_points, 1);

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Rotating,
            to: CryptoMigrationState::Active,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints,
        })
        .await
        .unwrap();

    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let body = records[0]
        .payload
        .as_ref()
        .unwrap()
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    assert!(is_encrypted_payload_value(body));
    assert_eq!(
        body.get(ENCRYPTED_PAYLOAD_MARKER)
            .and_then(|marker| marker.get("encryption_epoch"))
            .and_then(|epoch| epoch.as_u64()),
        Some(1),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rejects_client_envelope_mutation() {
    let collection_dir = canonical_collection_tempdir();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, client_payload_encryption_config())
            .await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let mut client_payload = Payload(
        serde_json::json!({
            "document": {
                "body": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "version": 1,
                        "kind": "payload_text",
                        "algorithm": "AES-256-GCM",
                        "key_id": "tenant-a/client-rk-2026-04",
                        "rk_id": "tenant-a/client-rk-2026-04",
                        "rk_epoch": 3,
                        "kdf_domain": "qdrant-sec/client-payload-text/v1",
                        "aad": {
                            "collection_id": collection_crypto_id.clone(),
                            "point_id": "1",
                            "field_path": "document.body",
                            "schema_version": 1
                        },
                        "nonce": "AAAAAAAAAAAAAAAA",
                        "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                        "signature": {
                            "alg": "ed25519",
                            "key_id": "tenant-a/client-signing-v1",
                            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        }
                    }
                }
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    sign_client_payload(&mut client_payload, &key_pair);

    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload),
        }]),
    ));
    let provenance = runtime_verified_client_envelopes_for_operation(
        &upsert,
        &collection_crypto_id,
        &public_key,
    );
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            provenance,
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 4,
            active_rk_id: Some("tenant-a/client-rk-2026-05".to_string()),
            retired_rk_id: Some("tenant-a/client-rk-2026-04".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            payload
                .0
                .get_mut("document")
                .and_then(|document| document.get_mut("body"))
                .and_then(|body| body.get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER))
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert(
                    "ciphertext".to_string(),
                    serde_json::json!("BBBBBBBBBBBBBBBBBBBBBB"),
                );
            Ok(1)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must not add, remove, or mutate client-side encrypted payload envelopes")),
        "unexpected error: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rejects_vector_sidecar_mutation() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:docs",
        DEFAULT_VECTOR_NAME,
        CkksParameters::default(),
        &SecretKey::from_bytes([31u8; 32]),
        "tenant-a/vector@v1",
        "tenant-a/vector-rk@v1",
        1,
        CollectionTestCkksBackend,
    )
    .unwrap()
    .with_collection_identity(collection_crypto_id)
    .unwrap();
    let public_material =
        CkksPublicMaterial::new(b"openfhe context".to_vec(), b"openfhe public key".to_vec())
            .unwrap();
    let (envelope, verified_sidecar_key) = encryptor
        .encrypt_sidecar_payload_value("docs", "1", &public_material, &[1.0, 2.0])
        .unwrap();
    let mut sidecar = Map::new();
    sidecar.insert(DEFAULT_VECTOR_NAME.to_string(), envelope);
    let mut payload = Map::new();
    payload.insert(
        ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        serde_json::Value::Object(sidecar),
    );

    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::Named(HashMap::new()),
            payload: Some(Payload(payload)),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_vectors(vec![verified_sidecar_key]),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/vector-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/vector-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            payload
                .0
                .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
                .and_then(serde_json::Value::as_object_mut)
                .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
                .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
                .and_then(|marker| marker.get_mut("envelope"))
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert("ciphertext".to_string(), serde_json::json!("dGFtcGVyZWQ"));
            Ok(1)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must not add, remove, or mutate encrypted vector sidecar payloads")),
        "unexpected error: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rejects_blind_index_token_mutation() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        payload_encryption_with_blind_index_config(),
    )
    .await;

    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(Payload(
                serde_json::json!({
                    "document_body__blind_eq": BASE64URL_NOPAD.encode(&[7u8; 32])
                })
                .as_object()
                .unwrap()
                .clone(),
            )),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            payload.0.insert(
                "document_body__blind_eq".to_string(),
                serde_json::json!(BASE64URL_NOPAD.encode(&[8u8; 32])),
            );
            Ok(1)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must not add, remove, or mutate metadata blind-index token field")),
        "unexpected error: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rejects_non_migrated_payload_mutation() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(Payload(
                serde_json::json!({
                    "untouched": "keep this value"
                })
                .as_object()
                .unwrap()
                .clone(),
            )),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            payload
                .0
                .insert("untouched".to_string(), serde_json::json!("changed"));
            Ok(1)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must not mutate payload fields outside server-side encrypted migration selectors")),
        "unexpected error: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rejects_server_encrypted_field_add() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(Payload(
                serde_json::json!({
                    "untouched": "keep this value"
                })
                .as_object()
                .unwrap()
                .clone(),
            )),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            payload.0.insert(
                "document".to_string(),
                serde_json::json!({ "body": "new field" }),
            );
            Ok(1)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must not add or remove server-side encrypted field")),
        "unexpected add error: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_rejects_server_encrypted_field_removal() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
    let resource_key = SecretKey::from_bytes([42u8; 32]);
    let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
        &collection_crypto_id,
        "tenant-a:docs",
        &resource_key,
        "tenant-a/docs@v0",
        "tenant-a/docs-rk-v1",
        0,
    )
    .unwrap()
    .with_encryption_epoch(0);

    let mut encrypted_payload = Payload(
        serde_json::json!({ "document": { "body": "must remain present" } })
            .as_object()
            .unwrap()
            .clone(),
    );
    let (_, verified_server_envelope_keys) = encryptor
        .encrypt_selected_fields_for_runtime(
            "1",
            &mut encrypted_payload.0,
            &policy,
            &collection_crypto_id,
        )
        .unwrap();
    let upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(encrypted_payload),
        }]),
    ));
    collection
        .update_from_client(
            upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(verified_server_envelope_keys),
        )
        .await
        .unwrap();

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let err = collection
        .rewrite_payloads_for_crypto_migration(|_, payload| {
            payload.0.remove("document");
            Ok(1)
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, CollectionError::BadInput { ref description }
            if description.contains("must not add or remove server-side encrypted field")),
        "unexpected removal error: {err:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_completion_requires_all_collection_shards() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 2, payload_encryption_config()).await;

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let incomplete_completion = CryptoMigrationPlan {
        from: CryptoMigrationState::Rotating,
        to: CryptoMigrationState::Active,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 0,
            processed_points: 0,
            rewritten_points: 0,
            changed_points: 0,
            status: CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    let err = collection
        .apply_crypto_migration_plan(&incomplete_completion)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("must cover every collection shard")
    ));

    let mut complete = incomplete_completion;
    complete.checkpoints.push(CryptoMigrationCheckpoint {
        shard_id: 1,
        total_points: 0,
        processed_points: 0,
        rewritten_points: 0,
        changed_points: 0,
        status: CryptoMigrationCheckpointStatus::Verified,
    });
    collection
        .apply_crypto_migration_plan(&complete)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_filters() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let err = collection
        .ensure_filter_does_not_touch_encrypted_payload(Some(&encrypted_payload_filter()))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: Some(encrypted_payload_filter()),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .count(
            CountRequestInternal {
                filter: Some(encrypted_payload_filter()),
                exact: true,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: None,
                filter: Some(encrypted_payload_filter()),
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: Some(encrypted_payload_filter()),
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .query_batch_internal(
            vec![ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: Some(encrypted_payload_filter()),
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            }],
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .facet(
            FacetParams {
                key: "document.title".parse().unwrap(),
                limit: 10,
                filter: Some(encrypted_payload_filter()),
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn private_result_oram_payload_writes_require_session_api_in_collection_ops() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_result_oram_encryption_config(),
    )
    .await;
    let private_point_id = 987_654_321_u64;
    let public_point_id = 876_543_210_u64;
    let private_payload: Payload = serde_json::from_value(serde_json::json!({
        "document": {
            "body": "plaintext result payload",
            "title": "public",
        }
    }))
    .unwrap();
    let public_payload: Payload = serde_json::from_value(serde_json::json!({
        "summary": "public",
    }))
    .unwrap();
    let forbidden = [
        "987654321",
        "876543210",
        "plaintext result payload",
        "document.body",
        "document",
        "body",
        "12345.125",
        "-23456.25",
        "34567.5",
        "-45678.75",
    ];
    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: public_payload.clone(),
                points: None,
                filter: Some(Filter::new()),
                key: None,
            })),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .expect("public payload merge must stay on the ordinary update path");
    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: serde_json::from_value(serde_json::json!({
                    "value": "public title",
                }))
                .unwrap(),
                points: None,
                filter: Some(Filter::new()),
                key: Some("document.title".parse().unwrap()),
            })),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .expect("public sibling payload path must stay on the ordinary update path");

    let operations = [
        (
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: private_point_id.into(),
                    vector: VectorStructPersisted::from(vec![
                        12345.125, -23456.25, 34567.5, -45678.75,
                    ]),
                    payload: Some(private_payload.clone()),
                }]),
            )),
            "upsert points",
        ),
        (
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: public_point_id.into(),
                    vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                    payload: Some(public_payload.clone()),
                }]),
            )),
            "upsert points",
        ),
        (
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPointsConditional(
                ConditionalInsertOperationInternal {
                    points_op: PointInsertOperationsInternal::from(vec![PointStructPersisted {
                        id: private_point_id.into(),
                        vector: VectorStructPersisted::from(vec![
                            12345.125, -23456.25, 34567.5, -45678.75,
                        ]),
                        payload: Some(public_payload.clone()),
                    }]),
                    condition: Filter::new(),
                    update_mode: None,
                },
            )),
            "upsert points",
        ),
        (
            CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
                PointSyncOperation {
                    from_id: None,
                    to_id: None,
                    points: vec![PointStructPersisted {
                        id: private_point_id.into(),
                        vector: VectorStructPersisted::from(vec![
                            12345.125, -23456.25, 34567.5, -45678.75,
                        ]),
                        payload: Some(public_payload.clone()),
                    }],
                },
            )),
            "sync points",
        ),
        (
            CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints {
                ids: vec![private_point_id.into()],
            }),
            "delete points",
        ),
        (
            CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(
                Filter::new(),
            )),
            "delete points by filter",
        ),
        (
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: private_payload.clone(),
                points: Some(vec![private_point_id.into()]),
                filter: None,
                key: None,
            })),
            "set payload",
        ),
        (
            CollectionUpdateOperations::PayloadOperation(PayloadOps::OverwritePayload(
                SetPayloadOp {
                    payload: public_payload,
                    points: Some(vec![private_point_id.into()]),
                    filter: None,
                    key: None,
                },
            )),
            "overwrite payload",
        ),
        (
            CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                DeletePayloadOp {
                    keys: vec!["document.body".parse().unwrap()],
                    points: Some(vec![private_point_id.into()]),
                    filter: None,
                },
            )),
            "delete payload",
        ),
        (
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload {
                points: vec![private_point_id.into()],
            }),
            "clear payload",
        ),
        (
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                Filter::new(),
            )),
            "clear payload by filter",
        ),
    ];

    for (operation, expected_kind) in operations {
        let err = collection
            .update_from_client_simple(
                operation,
                true,
                None,
                WriteOrdering::default(),
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();
        assert_private_result_oram_write_error_without(err, expected_kind, &forbidden);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn private_result_oram_raw_payload_reads_require_session_api_in_collection_ops() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = Arc::new(
        encrypted_collection_fixture(
            collection_dir.path(),
            1,
            private_result_oram_encryption_config(),
        )
        .await,
    );
    let private_point_id = 987_654_321_u64;
    let raw_private_selector =
        || WithPayloadInterface::Fields(vec!["document.body.lang".parse().unwrap()]);
    let forbidden = [
        "document.body.lang",
        "document.body",
        "document",
        "body",
        "lang",
        "987654321",
    ];

    let err = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![private_point_id.into()],
                with_payload: Some(raw_private_selector()),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_read_error_without(err, "retrieve", &forbidden);

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(raw_private_selector()),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_read_error_without(err, "scroll", &forbidden);

    let err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(raw_private_selector()),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_read_error_without(err, "search", &forbidden);

    let err = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: raw_private_selector(),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_read_error_without(err, "query", &forbidden);

    let err = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
            negative: vec![],
            strategy: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(raw_private_selector()),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
            using: None,
            lookup_from: None,
        },
        collection.as_ref(),
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_result_oram_read_error_without(err, "recommend", &forbidden);

    let err = recommend_batch_by(
        vec![(
            RecommendRequestInternal {
                positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
                negative: vec![],
                strategy: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(raw_private_selector()),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        collection.as_ref(),
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_result_oram_read_error_without(err, "recommend", &forbidden);

    let err = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(raw_private_selector()),
            with_vector: Some(WithVector::Bool(false)),
            using: None,
            lookup_from: None,
        },
        collection.as_ref(),
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_result_oram_read_error_without(err, "discover", &forbidden);

    let err = discover_batch(
        vec![(
            DiscoverRequestInternal {
                target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
                context: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(raw_private_selector()),
                with_vector: Some(WithVector::Bool(false)),
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        collection.as_ref(),
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_result_oram_read_error_without(err, "discover", &forbidden);

    let lookup_collection = Arc::clone(&collection);
    let err = lookup_ids(
        WithLookup {
            collection_name: "test".to_string(),
            with_payload: Some(raw_private_selector()),
            with_vectors: Some(WithVector::Bool(false)),
        },
        Vec::<PseudoId>::new(),
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        None,
        &ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_result_oram_read_error_without(err, "group lookup", &forbidden);
}

#[tokio::test(flavor = "multi_thread")]
async fn private_result_oram_redacted_payload_reads_remain_allowed_in_collection_ops() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_result_oram_encryption_config(),
    )
    .await;
    let redacted_selector = || {
        WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
            encrypted_payload: EncryptedPayloadReadMode::Redacted,
        })
    };

    let retrieved = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![987_654_321_u64.into()],
                with_payload: Some(redacted_selector()),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert!(retrieved.is_empty());

    let scrolled = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(redacted_selector()),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert!(scrolled.points.is_empty());

    let searched = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(redacted_selector()),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert!(searched.is_empty());

    let queried = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: redacted_selector(),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert!(queried.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn private_result_oram_payload_selectors_require_session_api_in_collection_ops() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_result_oram_encryption_config(),
    )
    .await;
    let private_payload_value = "private result selector sentinel";
    let private_filter = || {
        Filter::new_must(Condition::Field(FieldCondition::new_match(
            "document.body.lang".parse().unwrap(),
            private_payload_value.to_string().into(),
        )))
    };
    let private_order_by = || OrderBy {
        key: "document.body.lang".parse().unwrap(),
        direction: Some(Direction::Asc),
        start_from: None,
    };
    let forbidden = [
        "document.body.lang",
        "document.body",
        "document",
        "body",
        "lang",
        private_payload_value,
    ];

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: Some(private_filter()),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "filter on", &forbidden);

    let err = collection
        .count(
            CountRequestInternal {
                filter: Some(private_filter()),
                exact: true,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "filter on", &forbidden);

    let err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: None,
                filter: Some(private_filter()),
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "filter on", &forbidden);

    let err = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: Some(private_filter()),
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "filter on", &forbidden);

    let err = collection
        .facet(
            FacetParams {
                key: "document.title".parse().unwrap(),
                limit: 10,
                filter: Some(private_filter()),
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "filter on", &forbidden);

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Struct(private_order_by())),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "order by", &forbidden);

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::OrderBy(private_order_by())),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "order by", &forbidden);

    let err = collection
        .facet(
            FacetParams {
                key: "document.body.lang".parse().unwrap(),
                limit: 10,
                filter: None,
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "facet on", &forbidden);

    let group_request = GroupRequest {
        source: SourceRequest::Search(SearchRequestInternal {
            vector: vec![0.0, 0.0, 0.0, 0.0].into(),
            filter: None,
            params: None,
            limit: 1,
            offset: Some(0),
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
        }),
        group_by: "document.body.lang".parse().unwrap(),
        group_size: 1,
        limit: 1,
        with_lookup: None,
    };
    let err = GroupBy::new(
        group_request,
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "group by", &forbidden);

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(FormulaInternal {
                        formula: ExpressionInternal::Variable("document.body.lang".to_string()),
                        defaults: HashMap::new(),
                    })),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "use", &forbidden);

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(FormulaInternal {
                        formula: ExpressionInternal::Condition(Box::new(
                            private_filter().must.unwrap().pop().unwrap(),
                        )),
                        defaults: HashMap::new(),
                    })),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_result_oram_selector_error_without(err, "use formula condition on", &forbidden);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_blind_index_token_filter_is_searchable() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        payload_encryption_with_blind_index_config(),
    )
    .await;
    let token = BASE64URL_NOPAD.encode(&[9_u8; 32]);
    let blind_filter = Filter::new_must(Condition::Field(FieldCondition::new_match(
        "document_body__blind_eq".parse().unwrap(),
        serde_json::from_value(serde_json::json!({ "value": token })).unwrap(),
    )));

    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: Some(
                        serde_json::from_value(serde_json::json!({
                            "document_body__blind_eq": BASE64URL_NOPAD.encode(&[9_u8; 32]),
                        }))
                        .unwrap(),
                    ),
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let err = collection
        .create_payload_index_with_wait(
            "document_body__blind_eq".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Text),
            true,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("metadata blind-index field")
                && description.contains("keyword schema")
                && !description.contains("document_body__blind_eq")
    ));

    let err = collection
        .create_payload_index_with_wait(
            "document_body__blind_eq.child".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            true,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("metadata blind-index field")
                && description.contains("exact token field")
                && !description.contains("document_body__blind_eq")
    ));

    collection
        .create_payload_index_with_wait(
            "document_body__blind_eq".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            true,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let records = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: Some(blind_filter.clone()),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(records.points.len(), 1);
    assert_eq!(records.points[0].id, 1.into());
    assert_eq!(
        records.points[0]
            .payload
            .as_ref()
            .and_then(|payload| payload.0.get("document_body__blind_eq"))
            .cloned(),
        Some(serde_json::json!({
            "$qdrant_sec_redacted": true,
            "reason": "encrypted_payload",
        })),
    );
    let serialized = serde_json::to_string(&records.points[0].payload).unwrap();
    assert!(!serialized.contains(&token));

    let redacted_records = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: Some(blind_filter.clone()),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    },
                )),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(redacted_records.points.len(), 1);
    assert_eq!(
        redacted_records.points[0]
            .payload
            .as_ref()
            .and_then(|payload| payload.0.get("document_body__blind_eq")),
        Some(&serde_json::json!({
            "$qdrant_sec_redacted": true,
            "reason": "encrypted_payload",
        })),
    );
    let redacted_serialized = serde_json::to_string(&redacted_records.points[0].payload).unwrap();
    assert!(!redacted_serialized.contains(&token));

    let count = collection
        .count(
            CountRequestInternal {
                filter: Some(blind_filter.clone()),
                exact: true,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(count.count, 1);

    let query_records = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: Some(blind_filter.clone()),
                score_threshold: None,
                limit: 10,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Redacted,
                }),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(query_records.len(), 1);
    assert_eq!(query_records[0].id, 1.into());
    assert_eq!(
        query_records[0]
            .payload
            .as_ref()
            .and_then(|payload| payload.0.get("document_body__blind_eq")),
        Some(&serde_json::json!({
            "$qdrant_sec_redacted": true,
            "reason": "encrypted_payload",
        })),
    );

    let invalid_blind_filter = Filter::new_must(Condition::Field(FieldCondition::new_match(
        "document_body__blind_eq".parse().unwrap(),
        serde_json::from_str(r#"{ "value": "client-token-v1" }"#).unwrap(),
    )));
    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: Some(invalid_blind_filter),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("metadata blind-index field")
                && description.contains("32 bytes")
                && !description.contains("document_body__blind_eq")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_blind_index_token_field_rejects_non_filter_read_modes() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        payload_encryption_with_blind_index_config(),
    )
    .await;
    let token_field = "document_body__blind_eq";
    let token_order_by = OrderBy {
        key: token_field.parse().unwrap(),
        direction: Some(Direction::Asc),
        start_from: None,
    };

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Struct(token_order_by.clone())),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot order by metadata blind-index field")
                && !description.contains(token_field)
                && description.contains("exact-match filters only")
    ));

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::OrderBy(token_order_by)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot order by metadata blind-index field")
                && !description.contains(token_field)
                && description.contains("exact-match filters only")
    ));

    let err = collection
        .facet(
            FacetParams {
                key: token_field.parse().unwrap(),
                limit: 10,
                filter: None,
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot facet on metadata blind-index field")
                && !description.contains(token_field)
                && description.contains("exact-match filters only")
    ));

    let group_request = GroupRequest {
        source: SourceRequest::Search(SearchRequestInternal {
            vector: vec![0.0, 0.0, 0.0, 0.0].into(),
            filter: None,
            params: None,
            limit: 1,
            offset: Some(0),
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
        }),
        group_by: token_field.parse().unwrap(),
        group_size: 1,
        limit: 1,
        with_lookup: None,
    };
    let err = GroupBy::new(
        group_request,
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot group by metadata blind-index field")
                && !description.contains(token_field)
                && description.contains("exact-match filters only")
    ));

    let token_formula = FormulaInternal {
        formula: ExpressionInternal::Variable(token_field.to_string()),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(token_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot use metadata blind-index field")
                && !description.contains(token_field)
                && description.contains("formula")
                && description.contains("exact-match filters only")
    ));

    let valid_token = BASE64URL_NOPAD.encode(&[9_u8; 32]);
    let token_filter = Filter::new_must(Condition::Field(FieldCondition::new_match(
        token_field.parse().unwrap(),
        serde_json::from_value(serde_json::json!({ "value": valid_token })).unwrap(),
    )));
    let token_condition_formula = FormulaInternal {
        formula: ExpressionInternal::Condition(Box::new(token_filter.must.unwrap().pop().unwrap())),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(token_condition_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot use formula condition on metadata blind-index field")
                && !description.contains(token_field)
                && description.contains("exact-match filters only")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_blind_index_writes_require_hmac_token_shape() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        payload_encryption_with_blind_index_config(),
    )
    .await;
    let valid_token = BASE64URL_NOPAD.encode(&[7_u8; 32]);

    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: Some(
                        serde_json::from_value(serde_json::json!({
                            "document_body__blind_eq": valid_token,
                        }))
                        .unwrap(),
                    ),
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let err = collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 2.into(),
                    vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                    payload: Some(
                        serde_json::from_value(serde_json::json!({
                            "document_body__blind_eq": "client-token-v1",
                        }))
                        .unwrap(),
                    ),
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("metadata blind-index field")
                    && description.contains("token must decode to 32 bytes")
                    && !description.contains("document_body__blind_eq")
        ),
        "unexpected error: {err:?}"
    );

    let err = collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: serde_json::from_value(serde_json::json!({
                    "token": BASE64URL_NOPAD.encode(&[8_u8; 32]),
                }))
                .unwrap(),
                points: Some(vec![1.into()]),
                filter: None,
                key: Some("document_body__blind_eq".parse().unwrap()),
            })),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("must be written as a full payload object")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_rejects_unbound_blind_index_token_writes() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        client_payload_encryption_with_blind_index_config(),
    )
    .await;

    let err = collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: Some(
                        serde_json::from_value(serde_json::json!({
                            "document_body__blind_eq": BASE64URL_NOPAD.encode(&[7_u8; 32]),
                        }))
                        .unwrap(),
                    ),
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("metadata blind-index field")
                && description.contains("client envelope signature binds the token manifest")
                && !description.contains("document_body__blind_eq")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_accepts_bound_blind_index_token_writes() {
    let collection_dir = canonical_collection_tempdir();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        client_payload_encryption_with_blind_index_config(),
    )
    .await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();
    let blind_token = BASE64URL_NOPAD.encode(&[7_u8; 32]);
    let mut payload = Payload(
        serde_json::json!({
            "document": {
                "body": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "version": 1,
                        "kind": "payload_text",
                        "algorithm": "AES-256-GCM",
                        "key_id": "tenant-a/client-rk-2026-04",
                        "rk_id": "tenant-a/client-rk-2026-04",
                        "rk_epoch": 3,
                        "kdf_domain": "qdrant-sec/client-payload-text/v1",
                        "aad": {
                            "collection_id": collection_crypto_id,
                            "point_id": "1",
                            "field_path": "document.body",
                            "schema_version": 1
                        },
                        "nonce": "AAAAAAAAAAAAAAAA",
                        "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                        "blind_indexes": [
                            {
                                "field_path": "document_body__blind_eq",
                                "token": blind_token,
                            }
                        ],
                        "signature": {
                            "alg": "ed25519",
                            "key_id": "tenant-a/client-signing-v1",
                            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        }
                    }
                }
            },
            "document_body__blind_eq": blind_token,
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    sign_client_payload(&mut payload, &key_pair);
    let operation = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(payload),
        }]),
    ));

    collection
        .update_from_client(
            operation.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &operation,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_update_filters() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let operations = vec![
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPointsConditional(
            ConditionalInsertOperationInternal {
                points_op: PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: Some(serde_json::from_str(r#"{"tag":"updated"}"#).unwrap()),
                }]),
                condition: encrypted_payload_filter(),
                update_mode: None,
            },
        )),
        CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(
            encrypted_payload_filter(),
        )),
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: serde_json::from_str(r#"{"tag":"updated"}"#).unwrap(),
            points: None,
            filter: Some(encrypted_payload_filter()),
            key: None,
        })),
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys: vec!["tag".parse().unwrap()],
            points: None,
            filter: Some(encrypted_payload_filter()),
        })),
        CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
            encrypted_payload_filter(),
        )),
        CollectionUpdateOperations::VectorOperation(VectorOperations::UpdateVectors(
            UpdateVectorsOp {
                points: vec![PointVectorsPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                }],
                update_filter: Some(encrypted_payload_filter()),
            },
        )),
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectorsByFilter(
            encrypted_payload_filter(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        )),
    ];

    for operation in operations {
        let err = collection
            .update_from_client_simple(
                operation,
                true,
                None,
                WriteOrdering::default(),
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("cannot filter on encrypted payload field")
                && !description.contains("document.body")
                    && description.contains("blind index")
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_payload_delete_and_clear() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    for key in ["document.body", "document", "document.body.marker"] {
        let err = collection
            .update_from_client_simple(
                CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                    DeletePayloadOp {
                        keys: vec![key.parse().unwrap()],
                        points: Some(vec![1.into()]),
                        filter: None,
                    },
                )),
                true,
                None,
                WriteOrdering::default(),
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("cannot delete encrypted payload field")
                    && !description.contains("document.body")
        ));
    }

    let err = collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload {
                points: vec![1.into()],
            }),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot clear payloads")
                && !description.contains("document.body")
    ));

    let err = collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                Filter::default(),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot clear payloads")
                && !description.contains("document.body")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_metadata_fields_reject_payload_delete_and_clear() {
    let blind_index_collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let blind_index_collection = encrypted_collection_fixture(
        blind_index_collection_dir.path(),
        1,
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "document_body_blind_eq".to_string(),
                selector: EncryptionSelector::MetadataKeys {
                    keys: vec!["document_body__blind_eq".to_string()],
                },
                instance: "docs_body_blind_v1".to_string(),
                binding: Some(METADATA_EXACT_MATCH_TOKEN_BINDING.to_string()),
            }],
        },
    )
    .await;

    for key in ["document_body__blind_eq", "document_body__blind_eq.child"] {
        let err = blind_index_collection
            .update_from_client_simple(
                CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                    DeletePayloadOp {
                        keys: vec![key.parse().unwrap()],
                        points: Some(vec![1.into()]),
                        filter: None,
                    },
                )),
                true,
                None,
                WriteOrdering::default(),
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("cannot delete metadata blind-index field")
                    && !description.contains("document_body__blind_eq")
        ));
    }

    let err = blind_index_collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload {
                points: vec![1.into()],
            }),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("cannot clear payloads")
                    && description.contains("metadata blind-index field")
                    && !description.contains("document_body__blind_eq")
        ),
        "unexpected error: {err:?}",
    );

    let err = blind_index_collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                Filter::default(),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot clear payloads")
                && description.contains("metadata blind-index field")
                && !description.contains("document_body__blind_eq")
    ));

    let metadata_value_collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let metadata_value_collection = encrypted_collection_fixture(
        metadata_value_collection_dir.path(),
        1,
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "tenant_metadata".to_string(),
                selector: EncryptionSelector::MetadataKeys {
                    keys: vec!["tenant.private".to_string()],
                },
                instance: "docs_metadata_value_v1".to_string(),
                binding: Some(METADATA_VALUE_BINDING.to_string()),
            }],
        },
    )
    .await;

    for key in ["tenant.private", "tenant", "tenant.private.child"] {
        let err = metadata_value_collection
            .update_from_client_simple(
                CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                    DeletePayloadOp {
                        keys: vec![key.parse().unwrap()],
                        points: Some(vec![1.into()]),
                        filter: None,
                    },
                )),
                true,
                None,
                WriteOrdering::default(),
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot delete encrypted metadata value field")
                    && !description.contains("tenant.private")
        ));
    }

    let err = metadata_value_collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload {
                points: vec![1.into()],
            }),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot clear payloads")
                && description.contains("encrypted metadata value field")
                && !description.contains("tenant.private")
    ));

    let err = metadata_value_collection
        .update_from_client_simple(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                Filter::default(),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot clear payloads")
                && description.contains("encrypted metadata value field")
                && !description.contains("tenant.private")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_order_by() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let encrypted_order_by = OrderBy {
        key: "document.body".parse().unwrap(),
        direction: Some(Direction::Asc),
        start_from: None,
    };
    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Struct(encrypted_order_by.clone())),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot order by encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::OrderBy(encrypted_order_by)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot order by encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_formula() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let encrypted_formula = FormulaInternal {
        formula: ExpressionInternal::Variable("document.body".to_string()),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(encrypted_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot use encrypted payload field")
                && !description.contains("document.body")
                && description.contains("formula")
                && description.contains("blind index")
    ));

    let condition_formula = FormulaInternal {
        formula: ExpressionInternal::Condition(Box::new(
            encrypted_payload_filter().must.unwrap().pop().unwrap(),
        )),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(condition_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot use formula condition")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_facet_key() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let err = collection
        .facet(
            FacetParams {
                key: "document.body".parse().unwrap(),
                limit: 10,
                filter: None,
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot facet on encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_group_by() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let group_request = GroupRequest {
        source: SourceRequest::Search(SearchRequestInternal {
            vector: vec![0.0, 0.0, 0.0, 0.0].into(),
            filter: None,
            params: None,
            limit: 1,
            offset: Some(0),
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
        }),
        group_by: "document.body".parse().unwrap(),
        group_size: 1,
        limit: 1,
        with_lookup: None,
    };
    let err = GroupBy::new(
        group_request,
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot group by encrypted payload field")
                && !description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_payload_writes() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();

    let plaintext_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(
                    serde_json::from_str(r#"{"document":{"body":"secret body"}}"#).unwrap(),
                ),
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            plaintext_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && !description.contains("document.body")
    ));

    let keyed_plaintext_payload =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: serde_json::from_str(r#"{"body":"secret body"}"#).unwrap(),
            points: Some(vec![1.into()]),
            filter: None,
            key: Some("document".parse().unwrap()),
        }));
    let err = collection
        .update_from_client_simple(
            keyed_plaintext_payload,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && !description.contains("document.body")
    ));

    let malformed_marker_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 3.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: Some(
                    serde_json::from_str(
                        r#"{"document":{"body":{"$qdrant_sec":{"kind":"payload_text"}}}}"#,
                    )
                    .unwrap(),
                ),
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            malformed_marker_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && !description.contains("document.body")
    ));

    let wrong_key_encryptor = payload_text_encryptor_from_resource_key(
        "docs",
        "tenant-a:other",
        SecretKey::from_bytes([7u8; 32]),
        "tenant-a/other@v1",
    );
    let mut wrong_key_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"wrong key marker"}}"#).unwrap();
    wrong_key_encryptor
        .encrypt_selected_fields(
            "4",
            &mut wrong_key_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
        )
        .unwrap();
    let wrong_key_marker_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 4.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 0.0, 1.0]),
                payload: Some(wrong_key_payload.clone()),
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            wrong_key_marker_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted payload marker")
                && !description.contains("document.body")
                && description.contains("requires runtime payload encryption")
    ));

    let wrong_key_value = wrong_key_payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    assert!(
        validate_server_payload_value_metadata(
            wrong_key_value,
            ServerPayloadValidationContext {
                field_path: "document.body",
                expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
                key_id: Some("tenant-a:docs"),
                crypto_schema_version: 1,
                encryption_epoch: 0,
            },
        )
        .unwrap_err()
        .to_string()
        .contains("key id does not match"),
    );

    let valid_key_encryptor = payload_text_encryptor_from_resource_key(
        &collection_crypto_id,
        "tenant-a:docs",
        SecretKey::from_bytes([8u8; 32]),
        "tenant-a/docs@v1",
    );
    let mut point_bound_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"point-bound marker"}}"#).unwrap();
    let (_changed, point_bound_proofs) = valid_key_encryptor
        .encrypt_selected_fields_for_runtime(
            "6",
            &mut point_bound_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
            &collection_crypto_id,
        )
        .unwrap();
    let point_bound_replay =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 7.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 1.0, 0.0]),
                payload: Some(point_bound_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            point_bound_replay,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(point_bound_proofs),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted payload marker")
                && !description.contains("document.body")
                && description.contains("requires runtime payload encryption")
    ));

    let mut malformed_header_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"bad nonce marker"}}"#).unwrap();
    valid_key_encryptor
        .encrypt_selected_fields(
            "5",
            &mut malformed_header_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
        )
        .unwrap();
    malformed_header_payload
        .0
        .get_mut("document")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("nonce".to_string(), serde_json::json!("AQID"));
    let malformed_header_value = malformed_header_payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    assert!(
        validate_server_payload_value_metadata(
            malformed_header_value,
            ServerPayloadValidationContext {
                field_path: "document.body",
                expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
                key_id: Some("tenant-a:docs"),
                crypto_schema_version: 1,
                encryption_epoch: 0,
            },
        )
        .unwrap_err()
        .to_string()
        .contains("nonce must decode to 96 bits"),
    );
    let malformed_header_marker_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 5.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 1.0, 0.0]),
                payload: Some(malformed_header_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            malformed_header_marker_upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted payload marker")
                && description.contains("invalid for this collection")
                && !description.contains("document.body")
                && !description.contains("nonce")
    ));

    let plaintext_sync = CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
        PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: 5.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 1.0]),
                payload: Some(
                    serde_json::from_str(r#"{"document":{"body":"sync plaintext"}}"#).unwrap(),
                ),
            }],
        },
    ));
    let err = collection
        .update_from_client_simple(
            plaintext_sync,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && !description.contains("document.body")
    ));

    let public_payload = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 2.into(),
            vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            payload: Some(serde_json::from_str(r#"{"document":{"summary":"public"}}"#).unwrap()),
        }]),
    ));

    collection
        .update_from_client_simple(
            public_payload,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_update_rechecks_encrypted_payload_invariants() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();

    let plaintext_peer_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 10.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(
                    serde_json::from_str(r#"{"document":{"body":"peer plaintext"}}"#).unwrap(),
                ),
            }]),
        ));
    let err = collection
        .update_from_peer(
            OperationWithClockTag::from(plaintext_peer_upsert),
            0,
            true.into(),
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("peer update")
                && description.contains("plaintext payload")
                && !description.contains("document.body")
    ));

    let valid_key_encryptor = payload_text_encryptor_from_resource_key(
        &collection_crypto_id,
        "tenant-a:docs",
        SecretKey::from_bytes([8u8; 32]),
        "tenant-a/docs@v1",
    );
    let mut encrypted_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"peer encrypted"}}"#).unwrap();
    valid_key_encryptor
        .encrypt_selected_fields(
            "11",
            &mut encrypted_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
        )
        .unwrap();
    let encrypted_peer_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 11.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                payload: Some(encrypted_payload),
            }]),
        ));
    collection
        .update_from_peer(
            OperationWithClockTag::from(encrypted_peer_upsert),
            0,
            true.into(),
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let mut malformed_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"peer malformed"}}"#).unwrap();
    valid_key_encryptor
        .encrypt_selected_fields(
            "12",
            &mut malformed_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
        )
        .unwrap();
    malformed_payload
        .0
        .get_mut("document")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("nonce".to_string(), serde_json::json!("AQID"));
    let malformed_peer_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 12.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: Some(malformed_payload),
            }]),
        ));
    let err = collection
        .update_from_peer(
            OperationWithClockTag::from(malformed_peer_upsert),
            0,
            true.into(),
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("peer encrypted payload marker")
                && description.contains("invalid for this collection")
                && !description.contains("document.body")
                && !description.contains("nonce")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_update_rejects_private_hnsw_point_and_vector_mutations() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_hnsw_vector_encryption_config(),
    )
    .await;

    let assert_private_hnsw_peer_error = |err: CollectionError| {
        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("peer update")
                    && description.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                    && description.contains("/private-hnsw/")
                    && !description.contains("runtime CKKS")
        ));
    };

    let plaintext_peer_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 10.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: None,
            }]),
        ));
    let err = collection
        .update_from_peer(
            OperationWithClockTag::from(plaintext_peer_upsert),
            0,
            true.into(),
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_peer_error(err);

    let peer_delete_points =
        CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints {
            ids: vec![10.into()],
        });
    let err = collection
        .update_from_peer(
            OperationWithClockTag::from(peer_delete_points),
            0,
            true.into(),
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_peer_error(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_update_rejects_client_envelope_replay_without_verifier_manifest() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, client_payload_encryption_config())
            .await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let nonce_sentinel = "AAAAAAAAAAAAAAAA";
    let ciphertext_sentinel = "AAAAAAAAAAAAAAAAAAAAAA";
    let mut payload = Payload(
        serde_json::json!({
            "document": {
                "body": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "version": 1,
                        "kind": "payload_text",
                        "algorithm": "AES-256-GCM",
                        "key_id": "tenant-a/client-rk-2026-04",
                        "rk_id": "tenant-a/client-rk-2026-04",
                        "rk_epoch": 3,
                        "kdf_domain": "qdrant-sec/client-payload-text/v1",
                        "aad": {
                            "collection_id": collection_crypto_id,
                            "point_id": "21",
                            "field_path": "document.body",
                            "schema_version": 1
                        },
                        "nonce": nonce_sentinel,
                        "ciphertext": ciphertext_sentinel,
                        "signature": {
                            "alg": "ed25519",
                            "key_id": "tenant-a/client-signing-v1",
                            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        }
                    }
                }
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    sign_client_payload(&mut payload, &key_pair);
    let signature_sentinel = payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .and_then(|body| body.get(CLIENT_ENCRYPTED_PAYLOAD_MARKER))
        .and_then(|marker| marker.get("signature"))
        .and_then(|signature| signature.get("sig"))
        .and_then(|sig| sig.as_str())
        .expect("signed fixture must contain client signature")
        .to_string();
    let peer_upsert = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 21.into(),
            vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
            payload: Some(payload),
        }]),
    ));

    let err = collection
        .update_from_peer(
            OperationWithClockTag::from(peer_upsert),
            0,
            true.into(),
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    let CollectionError::BadInput { description } = err else {
        panic!("unexpected peer replay error: {err:?}");
    };
    assert!(description.contains("peer client encrypted payload marker"));
    assert!(description.contains("runtime verifier manifest"));
    assert!(description.contains("cluster-wide nonce ledger"));
    assert!(!description.contains("document.body"));
    assert!(!description.contains(nonce_sentinel), "{description}");
    assert!(!description.contains(ciphertext_sentinel), "{description}");
    assert!(!description.contains(&signature_sentinel), "{description}");
    assert!(!description.contains("tenant-a/client-rk-2026-04"));
    assert!(!description.contains("tenant-a/client-signing-v1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_marker_must_match_collection_guard() {
    let collection_dir = canonical_collection_tempdir();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, client_payload_encryption_config())
            .await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let client_payload_with_epoch = |collection_id: &str, point_id: &str, rk_id: &str, rk_epoch| {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": {
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": rk_id,
                            "rk_epoch": rk_epoch,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_id,
                                "point_id": point_id,
                                "field_path": "document.body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        sign_client_payload(&mut payload, &key_pair);
        payload
    };
    let client_payload = |collection_id: &str, point_id: &str, rk_id: &str| {
        client_payload_with_epoch(collection_id, point_id, rk_id, 3)
    };

    let unverified_sync_marker = CollectionUpdateOperations::PointOperation(
        PointOperations::SyncPoints(PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }],
        }),
    );
    let err = collection
        .update_from_client_simple(
            unverified_sync_marker,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let empty_proof_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let empty_verified_provenance =
        CollectionUpdateProvenance::runtime_verified_client_envelopes(Vec::new());
    assert_eq!(
        empty_verified_provenance,
        CollectionUpdateProvenance::client_plaintext(),
    );
    let err = collection
        .update_from_client(
            empty_proof_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            empty_verified_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let point_specific_set_payload =
        client_payload(&collection_crypto_id, "1", "tenant-a/client-rk-2026-04");
    let point_specific_body = point_specific_set_payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    let point_specific_verified_key = validate_client_payload_value_for_runtime(
        point_specific_body,
        ClientPayloadValidationContext {
            collection_id: &collection_crypto_id,
            point_id: "1",
            field_path: "document.body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();
    let pointless_set_marker =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: point_specific_set_payload,
            points: None,
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            pointless_set_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_verified_client_envelopes(vec![
                point_specific_verified_key,
            ]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires point-specific runtime envelope verification")
                && !description.contains("document.body")
    ));

    let mismatched_point_payload =
        client_payload(&collection_crypto_id, "1", "tenant-a/client-rk-2026-04");
    let mismatched_point_body = mismatched_point_payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    let mismatched_point_verified_key = validate_client_payload_value_for_runtime(
        mismatched_point_body,
        ClientPayloadValidationContext {
            collection_id: &collection_crypto_id,
            point_id: "1",
            field_path: "document.body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();
    let mismatched_point_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 2.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                payload: Some(mismatched_point_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            mismatched_point_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_verified_client_envelopes(vec![
                mismatched_point_verified_key,
            ]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let mut wrong_collection_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let wrong_collection_provenance = runtime_verified_client_envelopes_for_operation(
        &wrong_collection_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut wrong_collection_marker
    {
        points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("aad")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "collection_id".to_string(),
                serde_json::Value::String("wrong-collection".to_string()),
            );
    }
    let err = collection
        .update_from_client(
            wrong_collection_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_collection_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let mut wrong_rk_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let wrong_rk_provenance = runtime_verified_client_envelopes_for_operation(
        &wrong_rk_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut wrong_rk_marker
    {
        points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "rk_id".to_string(),
                serde_json::Value::String("tenant-a/old-client-rk".to_string()),
            );
    }
    let err = collection
        .update_from_client(
            wrong_rk_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_rk_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let mut wrong_epoch_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload_with_epoch(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                    3,
                )),
            }]),
        ));
    let wrong_epoch_provenance = runtime_verified_client_envelopes_for_operation(
        &wrong_epoch_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut wrong_epoch_marker
    {
        points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "rk_epoch".to_string(),
                serde_json::Value::Number(serde_json::Number::from(2)),
            );
    }
    let err = collection
        .update_from_client(
            wrong_epoch_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_epoch_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let mut unsigned_payload =
        client_payload(&collection_crypto_id, "1", "tenant-a/client-rk-2026-04");
    let unsigned_marker_for_provenance =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(unsigned_payload.clone()),
            }]),
        ));
    let unsigned_provenance = runtime_verified_client_envelopes_for_operation(
        &unsigned_marker_for_provenance,
        &collection_crypto_id,
        &public_key,
    );
    unsigned_payload
        .0
        .get_mut("document")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("signature");
    let unsigned_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(unsigned_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            unsigned_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            unsigned_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
                && !description.contains("document.body")
    ));

    let mut signature_tamper_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let signature_tamper_provenance = runtime_verified_client_envelopes_for_operation(
        &signature_tamper_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut signature_tamper_marker
    {
        let signature_value = points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("signature")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("sig")
            .unwrap();
        let serde_json::Value::String(signature) = signature_value else {
            panic!("client signature fixture must contain string sig");
        };
        let replacement = if signature.starts_with('A') { "B" } else { "A" };
        signature.replace_range(0..1, replacement);
    }
    let err = collection
        .update_from_client(
            signature_tamper_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            signature_tamper_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let replay_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![
            PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            },
            PointStructPersisted {
                id: 2.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "2",
                    "tenant-a/client-rk-2026-04",
                )),
            },
        ]),
    ));
    let err = collection
        .update_from_client(
            replay_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("nonce was already used")
                && !description.contains("document.body")
    ));

    let valid_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload(
                &collection_crypto_id,
                "1",
                "tenant-a/client-rk-2026-04",
            )),
        }]),
    ));
    collection
        .update_from_client(
            valid_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &valid_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();

    let replay_after_valid =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 3.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "3",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let err = collection
        .update_from_client(
            replay_after_valid.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_after_valid,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("nonce was already used in this collection")
    ));

    let assert_raw_client_body = |payload: &Payload| {
        let body = payload
            .0
            .get("document")
            .and_then(|document| document.get("body"))
            .unwrap();
        assert!(is_client_encrypted_payload_value(body));
        assert!(!is_encrypted_payload_value(body));
    };

    let retrieved = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_raw_client_body(retrieved[0].payload.as_ref().unwrap());

    let scrolled = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(scrolled.points.len(), 1);
    assert_raw_client_body(scrolled.points[0].payload.as_ref().unwrap());

    let searched = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(searched.len(), 1);
    assert_raw_client_body(searched[0].payload.as_ref().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_nonce_replay_survives_collection_reload() {
    let collection_dir = canonical_collection_tempdir();
    let collection_path = collection_dir.path().to_path_buf();
    let snapshot_path = collection_path.join("snapshots");
    let collection =
        encrypted_collection_fixture(&collection_path, 1, client_payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let client_payload = |point_id: &str| {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": {
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": "tenant-a/client-rk-2026-04",
                            "rk_epoch": 3,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_crypto_id,
                                "point_id": point_id,
                                "field_path": "document.body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        sign_client_payload(&mut payload, &key_pair);
        payload
    };

    let valid_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload("1")),
        }]),
    ));
    collection
        .update_from_client(
            valid_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &valid_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();

    collection.stop_gracefully().await;
    drop(collection);

    let collection =
        load_local_collection("test".to_string(), &collection_path, &snapshot_path).await;
    let replay_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 2.into(),
            vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            payload: Some(client_payload("2")),
        }]),
    ));
    let err = collection
        .update_from_client(
            replay_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("nonce was already used in this collection")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_nonce_replay_cache_backfills_from_stored_payloads() {
    let collection_dir = canonical_collection_tempdir();
    let collection_path = collection_dir.path().to_path_buf();
    let snapshot_path = collection_path.join("snapshots");
    let collection =
        encrypted_collection_fixture(&collection_path, 1, client_payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let client_payload = |point_id: &str| {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": {
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": "tenant-a/client-rk-2026-04",
                            "rk_epoch": 3,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_crypto_id,
                                "point_id": point_id,
                                "field_path": "document.body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        sign_client_payload(&mut payload, &key_pair);
        payload
    };

    let valid_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload("1")),
        }]),
    ));
    collection
        .update_from_client(
            valid_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &valid_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();

    collection.stop_gracefully().await;
    drop(collection);
    fs::remove_file(collection_path.join("client_payload_nonce_replay.cache")).unwrap();

    let collection =
        load_local_collection("test".to_string(), &collection_path, &snapshot_path).await;
    let replay_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 2.into(),
            vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            payload: Some(client_payload("2")),
        }]),
    ));
    let err = collection
        .update_from_client(
            replay_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("nonce was already used in this collection")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_marker_upsert_does_not_leak_plaintext_to_collection_files() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let collection = Arc::new(
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await,
    );
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let sentinel = "qdrant-sec-plaintext-sentinel-9f74dcb5";
    let mut encrypted_payload = Payload(
        serde_json::json!({
            "document": { "body": sentinel },
            "group": 1,
            "notes": {
                ENCRYPTED_PAYLOAD_MARKER: {
                    "ordinary": "marker-shaped server note outside encrypted selector"
                },
                "nested": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "ordinary": "marker-shaped client note outside encrypted selector"
                    }
                }
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let encryptor = payload_text_encryptor_from_resource_key(
        &collection_crypto_id,
        "tenant-a:docs",
        SecretKey::from_bytes([31u8; 32]),
        "tenant-a/docs@v1",
    );
    let policy = PayloadEncryptionPolicy::new(vec!["document.body".to_string()]).unwrap();
    let (changed, verified_server_envelope_keys) = encryptor
        .encrypt_selected_fields_for_runtime(
            "1",
            &mut encrypted_payload.0,
            &policy,
            &collection_crypto_id,
        )
        .unwrap();
    assert_eq!(changed, 1);

    let encrypted_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(encrypted_payload),
            }]),
        ));
    collection
        .update_from_client(
            encrypted_upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(verified_server_envelope_keys),
        )
        .await
        .unwrap();

    let retrieved = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let retrieved_payload = retrieved[0].payload.as_ref().unwrap();
    let assert_raw_encrypted_body = |payload: &Payload| {
        let body = payload
            .0
            .get("document")
            .and_then(|document| document.get("body"))
            .unwrap();
        assert!(is_encrypted_payload_value(body));
        assert_ne!(body, &serde_json::json!(sentinel));
    };
    assert_raw_encrypted_body(retrieved_payload);

    let scrolled = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(scrolled.points.len(), 1);
    assert_raw_encrypted_body(scrolled.points[0].payload.as_ref().unwrap());

    let searched = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(searched.len(), 1);
    assert_raw_encrypted_body(searched[0].payload.as_ref().unwrap());

    let redacted_payload_selector = Some(WithPayloadInterface::Encrypted(
        PayloadEncryptedReadPolicy {
            encrypted_payload: EncryptedPayloadReadMode::Redacted,
        },
    ));
    let redacted = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: redacted_payload_selector.clone(),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let redacted_body = redacted[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(
        redacted_body,
        &serde_json::json!({
            "$qdrant_sec_redacted": true,
            "reason": "encrypted_payload",
        })
    );
    let assert_marker_shaped_notes_visible = |payload: &Payload| {
        let redacted_notes = payload.0.get("notes").unwrap();
        assert_eq!(
            redacted_notes
                .get(ENCRYPTED_PAYLOAD_MARKER)
                .and_then(|marker| marker.get("ordinary"))
                .and_then(|ordinary| ordinary.as_str()),
            Some("marker-shaped server note outside encrypted selector"),
        );
        assert_eq!(
            redacted_notes
                .get("nested")
                .and_then(|nested| nested.get(CLIENT_ENCRYPTED_PAYLOAD_MARKER))
                .and_then(|marker| marker.get("ordinary"))
                .and_then(|ordinary| ordinary.as_str()),
            Some("marker-shaped client note outside encrypted selector"),
        );
    };
    let redacted_body_serialized = serde_json::to_string(redacted_body).unwrap();
    assert!(!redacted_body_serialized.contains(&format!("\"{ENCRYPTED_PAYLOAD_MARKER}\"")));
    assert!(!redacted_body_serialized.contains(sentinel));
    assert_marker_shaped_notes_visible(redacted[0].payload.as_ref().unwrap());

    let redacted_scroll = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: redacted_payload_selector.clone(),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let redacted_scroll_body = redacted_scroll.points[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_scroll_body, redacted_body);
    assert_marker_shaped_notes_visible(redacted_scroll.points[0].payload.as_ref().unwrap());

    let redacted_search = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: redacted_payload_selector,
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let redacted_search_body = redacted_search[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_search_body, redacted_body);
    assert_marker_shaped_notes_visible(redacted_search[0].payload.as_ref().unwrap());

    let redacted_search_batch = collection
        .core_search_batch(
            CoreSearchRequestBatch {
                searches: vec![
                    SearchRequestInternal {
                        vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                        with_payload: Some(WithPayloadInterface::Encrypted(
                            PayloadEncryptedReadPolicy {
                                encrypted_payload: EncryptedPayloadReadMode::Redacted,
                            },
                        )),
                        with_vector: None,
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        score_threshold: None,
                    }
                    .into(),
                ],
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let redacted_search_batch_body = redacted_search_batch[0][0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_search_batch_body, redacted_body);

    let redacted_recommend = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
            negative: vec![],
            strategy: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(WithPayloadInterface::Encrypted(
                PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Redacted,
                },
            )),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap();
    let redacted_recommend_body = redacted_recommend[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_recommend_body, redacted_body);

    let redacted_recommend_batch = recommend_batch_by(
        vec![(
            RecommendRequestInternal {
                positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
                negative: vec![],
                strategy: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap();
    let redacted_recommend_batch_body = redacted_recommend_batch[0][0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_recommend_batch_body, redacted_body);

    let redacted_discover = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(WithPayloadInterface::Encrypted(
                PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Redacted,
                },
            )),
            with_vector: Some(WithVector::Bool(false)),
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap();
    let redacted_discover_body = redacted_discover[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_discover_body, redacted_body);

    let redacted_discover_batch = discover_batch(
        vec![(
            DiscoverRequestInternal {
                target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
                context: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap();
    let redacted_discover_batch_body = redacted_discover_batch[0][0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_discover_batch_body, redacted_body);

    let grouped = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap();
    assert_eq!(grouped.len(), 1);
    assert_raw_encrypted_body(grouped[0].hits[0].payload.as_ref().unwrap());

    let redacted_grouped = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap();
    let redacted_grouped_body = redacted_grouped[0].hits[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_grouped_body, redacted_body);

    let lookup_collection = Arc::clone(&collection);
    let inherited_redacted_lookup_grouped = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: Some(collection::lookup::WithLookup {
                collection_name: "test".to_string(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vectors: Some(WithVector::Bool(false)),
            }),
        },
        &collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap();
    let inherited_redacted_lookup_body = inherited_redacted_lookup_grouped[0]
        .lookup
        .as_ref()
        .and_then(|record| record.payload.as_ref())
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(inherited_redacted_lookup_body, redacted_body);

    let lookup_collection = Arc::clone(&collection);
    let redacted_lookup_grouped = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: Some(collection::lookup::WithLookup {
                collection_name: "test".to_string(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    },
                )),
                with_vectors: Some(WithVector::Bool(false)),
            }),
        },
        &collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap();
    let redacted_lookup_body = redacted_lookup_grouped[0]
        .lookup
        .as_ref()
        .and_then(|record| record.payload.as_ref())
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_lookup_body, redacted_body);

    let lookup_collection = Arc::clone(&collection);
    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: Some(collection::lookup::WithLookup {
                collection_name: "test".to_string(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vectors: Some(WithVector::Bool(false)),
            }),
        },
        &collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("collection-internal reads must use 'raw' or 'redacted'")
    ));

    let redacted_query = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Redacted,
                }),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let redacted_query_body = redacted_query[0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_query_body, redacted_body);

    let redacted_query_batch = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Redacted,
                    }),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let redacted_query_batch_body = redacted_query_batch[0][0]
        .payload
        .as_ref()
        .and_then(|payload| payload.0.get("document"))
        .and_then(|document| document.get("body"))
        .unwrap();
    assert_eq!(redacted_query_batch_body, redacted_body);

    let decrypt_err = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let scroll_decrypt_err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        scroll_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let query_decrypt_err = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                }),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        query_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let search_decrypt_err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        search_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let search_batch_decrypt_err = collection
        .core_search_batch(
            CoreSearchRequestBatch {
                searches: vec![
                    SearchRequestInternal {
                        vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                        with_payload: Some(WithPayloadInterface::Encrypted(
                            PayloadEncryptedReadPolicy {
                                encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                            },
                        )),
                        with_vector: None,
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        score_threshold: None,
                    }
                    .into(),
                ],
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        search_batch_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let recommend_decrypt_err = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
            negative: vec![],
            strategy: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(WithPayloadInterface::Encrypted(
                PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                },
            )),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        recommend_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let recommend_batch_decrypt_err = recommend_batch_by(
        vec![(
            RecommendRequestInternal {
                positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
                negative: vec![],
                strategy: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        recommend_batch_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let discover_decrypt_err = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(WithPayloadInterface::Encrypted(
                PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                },
            )),
            with_vector: Some(WithVector::Bool(false)),
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        discover_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let discover_batch_decrypt_err = discover_batch(
        vec![(
            DiscoverRequestInternal {
                target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
                context: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        discover_batch_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let query_batch_decrypt_err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    }),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        query_batch_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let group_decrypt_err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        group_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let lookup_collection = Arc::clone(&collection);
    let lookup_decrypt_err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: Some(collection::lookup::WithLookup {
                collection_name: "test".to_string(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vectors: Some(WithVector::Bool(false)),
            }),
        },
        &collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        lookup_decrypt_err,
        CollectionError::BadInput { description }
            if description.contains("API runtime layer")
    ));

    let telemetry = collection
        .get_telemetry_data(
            TelemetryDetail::new(DetailsLevel::Level4, true),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
    let telemetry_bytes = serde_json::to_vec(&telemetry).unwrap();
    assert!(
        !telemetry_bytes
            .windows(sentinel.as_bytes().len())
            .any(|window| window == sentinel.as_bytes()),
        "plaintext sentinel leaked into collection telemetry",
    );

    let snapshot_temp_dir = Builder::new().prefix("snapshot-temp").tempdir().unwrap();
    let snapshot = collection
        .create_snapshot(snapshot_temp_dir.path(), 0)
        .await
        .unwrap();
    let snapshot_path = collection_path.join("snapshots").join(&snapshot.name);
    assert!(snapshot_path.exists());

    collection.stop_gracefully().await;

    let sentinel = sentinel.as_bytes();
    let assert_path_has_no_sentinel = |root: &std::path::Path| {
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = fs::metadata(&path).unwrap();
            if metadata.is_dir() {
                for entry in fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
                continue;
            }
            if !metadata.is_file() {
                continue;
            }

            let bytes = fs::read(&path).unwrap();
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel),
                "plaintext sentinel leaked into {}",
                path.display(),
            );
        }
    };
    assert_path_has_no_sentinel(&collection_path);
    assert_path_has_no_sentinel(snapshot_temp_dir.path());
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_plaintext_vector_writes() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;
    let vector_sentinel = [12345.125_f32, -23456.25, 34567.5, -45678.75];
    let vector_sentinel_f32_bytes: Vec<u8> = vector_sentinel
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let vector_sentinel_f64_bytes: Vec<u8> = vector_sentinel
        .iter()
        .flat_map(|value| (*value as f64).to_le_bytes())
        .collect();

    let plaintext_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vector_sentinel.to_vec()),
                payload: None,
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            plaintext_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot write plaintext vector")
                && description.contains("runtime CKKS vector encryption")
    ));

    let plaintext_sync = CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
        PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: 2.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: None,
            }],
        },
    ));
    let err = collection
        .update_from_client_simple(
            plaintext_sync,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot write plaintext vector")
                && description.contains("runtime CKKS vector encryption")
    ));

    let plaintext_vector_update = CollectionUpdateOperations::VectorOperation(
        VectorOperations::UpdateVectors(UpdateVectorsOp {
            points: vec![PointVectorsPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            }],
            update_filter: None,
        }),
    );
    let err = collection
        .update_from_client_simple(
            plaintext_vector_update,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot write plaintext vector")
                && description.contains("runtime CKKS vector encryption")
    ));

    let delete_vector =
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectors(
            vec![1.into()].into(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        ));
    let err = collection
        .update_from_client_simple(
            delete_vector,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot write plaintext vector")
                && description.contains("runtime CKKS vector encryption")
    ));

    let delete_vector_by_filter =
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectorsByFilter(
            Filter::default(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        ));
    let err = collection
        .update_from_client_simple(
            delete_vector_by_filter,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot write plaintext vector")
                && description.contains("runtime CKKS vector encryption")
    ));

    let has_encrypted_vector_filter = Filter::new_must(Condition::HasVector(
        HasVectorCondition::from(DEFAULT_VECTOR_NAME.to_string()),
    ));
    let delete_points_by_filter = CollectionUpdateOperations::PointOperation(
        PointOperations::DeletePointsByFilter(has_encrypted_vector_filter),
    );
    let err = collection
        .update_from_client_simple(
            delete_points_by_filter,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted vector")
                && description.contains("use CKKS sidecar vector search APIs")
    ));

    collection.stop_gracefully().await;

    let mut pending = vec![collection_path];
    while let Some(path) = pending.pop() {
        let metadata = fs::metadata(&path).unwrap();
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        let bytes = fs::read(&path).unwrap();
        for pattern in [
            vector_sentinel_f32_bytes.as_slice(),
            vector_sentinel_f64_bytes.as_slice(),
        ] {
            assert!(
                !bytes.windows(pattern.len()).any(|window| window == pattern),
                "plaintext vector sentinel leaked into {}",
                path.display(),
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn private_hnsw_vector_rejects_plaintext_vector_writes_with_session_api_message() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_hnsw_vector_encryption_config(),
    )
    .await;

    let plaintext_point_id = 987_654_321_u64;
    let plaintext_vector_sentinel = vec![12345.125_f32, -23456.25, 34567.5, -45678.75];
    let plaintext_point =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                id: plaintext_point_id.into(),
                vector: VectorStructPersisted::from(plaintext_vector_sentinel.clone()),
                payload: None,
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            plaintext_point,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(
        err,
        &[
            "987654321",
            "12345.125",
            "-23456.25",
            "34567.5",
            "-45678.75",
        ],
    );

    let conditional_point_id = 765_432_111_u64;
    let conditional_vector_sentinel = vec![13579.125_f32, -24680.25, 35791.5, -46802.75];
    let conditional_plaintext_point = CollectionUpdateOperations::PointOperation(
        PointOperations::UpsertPointsConditional(ConditionalInsertOperationInternal {
            points_op: PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                id: conditional_point_id.into(),
                vector: VectorStructPersisted::from(conditional_vector_sentinel.clone()),
                payload: None,
            }]),
            condition: Filter::new(),
            update_mode: None,
        }),
    );
    let err = collection
        .update_from_client_simple(
            conditional_plaintext_point,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(
        err,
        &[
            "765432111",
            "13579.125",
            "-24680.25",
            "35791.5",
            "-46802.75",
        ],
    );

    let update_point_id = 876_543_210_u64;
    let update_vector_sentinel = vec![54321.5_f32, -65432.75, 76543.875, -87654.125];
    let plaintext_vector_update = CollectionUpdateOperations::VectorOperation(
        VectorOperations::UpdateVectors(UpdateVectorsOp {
            points: vec![PointVectorsPersisted {
                id: update_point_id.into(),
                vector: VectorStructPersisted::from(update_vector_sentinel.clone()),
            }],
            update_filter: None,
        }),
    );
    let err = collection
        .update_from_client_simple(
            plaintext_vector_update,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(
        err,
        &[
            "876543210",
            "54321.5",
            "-65432.75",
            "76543.875",
            "-87654.125",
        ],
    );

    let delete_vector_point_id = 765_432_109_u64;
    let delete_vector =
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectors(
            vec![delete_vector_point_id.into()].into(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        ));
    let err = collection
        .update_from_client_simple(
            delete_vector,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(err, &["765432109"]);

    let delete_vector_by_filter =
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectorsByFilter(
            Filter::default(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        ));
    let err = collection
        .update_from_client_simple(
            delete_vector_by_filter,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn private_hnsw_vector_rejects_point_delete_and_sync_with_session_api_message() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_hnsw_vector_encryption_config(),
    )
    .await;

    let delete_point_id = 654_321_098_u64;
    let delete_points = CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints {
        ids: vec![delete_point_id.into()],
    });
    let err = collection
        .update_from_client_simple(
            delete_points,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(err, &["654321098"]);

    let delete_points_by_filter = CollectionUpdateOperations::PointOperation(
        PointOperations::DeletePointsByFilter(Filter::default()),
    );
    let err = collection
        .update_from_client_simple(
            delete_points_by_filter,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let sync_point_id = 543_210_987_u64;
    let sync_vector_sentinel = vec![11111.125_f32, -22222.25, 33333.5, -44444.75];
    let sync_points = CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
        PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: sync_point_id.into(),
                vector: VectorStructPersisted::from(sync_vector_sentinel.clone()),
                payload: None,
            }],
        },
    ));
    let err = collection
        .update_from_client_simple(
            sync_points,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(
        err,
        &[
            "543210987",
            "11111.125",
            "-22222.25",
            "33333.5",
            "-44444.75",
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_sidecar_requires_matching_runtime_metadata() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();

    let vector_sidecar = |vector_name: &str,
                          key_id: &str|
     -> (Payload, CkksVectorVerifiedSidecarKey) {
        let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
            key_id,
            vector_name,
            CkksParameters::default(),
            &SecretKey::from_bytes([31u8; 32]),
            "tenant-a/vector@v1",
            "tenant-a/vector-rk@v1",
            1,
            CollectionTestCkksBackend,
        )
        .unwrap()
        .with_collection_identity(collection_crypto_id.clone())
        .unwrap();
        let public_material =
            CkksPublicMaterial::new(b"openfhe context".to_vec(), b"openfhe public key".to_vec())
                .unwrap();
        let (envelope, verified_sidecar_key) = encryptor
            .encrypt_sidecar_payload_value("docs", "1", &public_material, &[1.0, 2.0])
            .unwrap();
        let mut sidecar = Map::new();
        sidecar.insert(vector_name.to_string(), envelope);
        let mut payload = Map::new();
        payload.insert(
            ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
            serde_json::Value::Object(sidecar),
        );
        (Payload(payload), verified_sidecar_key)
    };
    let vector_sidecar_with_raw_parts =
        |vector_name: &str,
         key_id: &str,
         nonce: serde_json::Value,
         ciphertext: serde_json::Value| {
            let mut sidecar = Map::new();
            sidecar.insert(
                vector_name.to_string(),
                serde_json::json!({
                    ENCRYPTED_CKKS_VECTOR_MARKER: {
                        "version": 1,
                        "scheme": "openfhe-ckks",
                        "envelope": {
                            "version": 1,
                            "algorithm": "AES-256-GCM",
                            "key_id": key_id,
                            "material_fingerprint": "tenant-a/vector@v1",
                            "rk_id": "tenant-a/vector-rk@v1",
                            "rk_epoch": 1,
                            "nonce": nonce,
                            "ciphertext": ciphertext,
                        },
                    },
                }),
            );
            let mut payload = Map::new();
            payload.insert(
                ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
                serde_json::Value::Object(sidecar),
            );
            Payload(payload)
        };
    let valid_ciphertext = || serde_json::Value::String(BASE64URL_NOPAD.encode(&[2u8; 16]));
    let vector_sidecar_provenance = |verified_sidecar_key: CkksVectorVerifiedSidecarKey| {
        CollectionUpdateProvenance::runtime_encrypted_vectors(vec![verified_sidecar_key])
    };

    let (wrong_key_payload, wrong_key_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:wrong");
    let wrong_key_provenance = vector_sidecar_provenance(wrong_key_verified_sidecar_key);
    let wrong_key_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_key_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_key_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_key_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("key id does not match")
    ));

    let (unconfigured_payload, unconfigured_verified_sidecar_key) =
        vector_sidecar("other", "tenant-a:docs");
    let unconfigured_provenance = vector_sidecar_provenance(unconfigured_verified_sidecar_key);
    let unconfigured_vector_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: unconfigured_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            unconfigured_vector_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            unconfigured_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("not configured")
                && !description.contains("other")
    ));

    let (mut wrong_version_payload, wrong_version_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:docs");
    let wrong_version_provenance = vector_sidecar_provenance(wrong_version_verified_sidecar_key);
    let sidecar_marker = wrong_version_payload
        .0
        .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(|sidecar| sidecar.as_object_mut())
        .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
        .and_then(|entry| entry.as_object_mut())
        .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.as_object_mut())
        .unwrap();
    sidecar_marker.insert("version".to_string(), serde_json::json!(2));
    let wrong_version_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_version_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_version_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_version_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("unsupported version")
    ));

    let (mut wrong_scheme_payload, wrong_scheme_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:docs");
    let wrong_scheme_provenance = vector_sidecar_provenance(wrong_scheme_verified_sidecar_key);
    let sidecar_marker = wrong_scheme_payload
        .0
        .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(|sidecar| sidecar.as_object_mut())
        .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
        .and_then(|entry| entry.as_object_mut())
        .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.as_object_mut())
        .unwrap();
    sidecar_marker.insert("scheme".to_string(), serde_json::json!("other-scheme"));
    let wrong_scheme_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_scheme_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_scheme_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_scheme_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("unsupported scheme")
    ));

    let (mut wrong_algorithm_payload, wrong_algorithm_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:docs");
    let wrong_algorithm_provenance =
        vector_sidecar_provenance(wrong_algorithm_verified_sidecar_key);
    let sidecar_envelope = wrong_algorithm_payload
        .0
        .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(|sidecar| sidecar.as_object_mut())
        .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
        .and_then(|entry| entry.as_object_mut())
        .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.as_object_mut())
        .and_then(|marker| marker.get_mut("envelope"))
        .and_then(|envelope| envelope.as_object_mut())
        .unwrap();
    sidecar_envelope.insert("algorithm".to_string(), serde_json::json!("AES-128-GCM"));
    let wrong_algorithm_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_algorithm_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_algorithm_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_algorithm_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("unsupported envelope algorithm")
    ));

    let malformed_nonce_payload = vector_sidecar_with_raw_parts(
        DEFAULT_VECTOR_NAME,
        "tenant-a:docs",
        serde_json::Value::String("not-base64url".to_string()),
        valid_ciphertext(),
    );
    let malformed_nonce_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: malformed_nonce_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            malformed_nonce_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("nonce")
    ));

    let oversized_ciphertext_payload = vector_sidecar_with_raw_parts(
        DEFAULT_VECTOR_NAME,
        "tenant-a:docs",
        serde_json::Value::String("AAAAAAAAAAAAAAAA".to_string()),
        serde_json::Value::String("A".repeat(23 * 1024 * 1024)),
    );
    let oversized_ciphertext_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: oversized_ciphertext_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            oversized_ciphertext_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("maximum size")
    ));

    let (mut tampered_payload, tampered_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:docs");
    let tampered_provenance = vector_sidecar_provenance(tampered_verified_sidecar_key);
    let sidecar_entry = tampered_payload
        .0
        .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(|sidecar| sidecar.as_object_mut())
        .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
        .and_then(|entry| entry.as_object_mut())
        .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.as_object_mut())
        .and_then(|marker| marker.get_mut("envelope"))
        .and_then(|envelope| envelope.as_object_mut())
        .unwrap();
    sidecar_entry.insert(
        "ciphertext".to_string(),
        serde_json::Value::String(BASE64URL_NOPAD.encode(&[3u8; 16])),
    );
    let tampered_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: tampered_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            tampered_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            tampered_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("requires runtime vector encryption")
    ));

    let (mut tampered_fingerprint_payload, tampered_fingerprint_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:docs");
    let tampered_fingerprint_provenance =
        vector_sidecar_provenance(tampered_fingerprint_verified_sidecar_key);
    let sidecar_entry = tampered_fingerprint_payload
        .0
        .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(|sidecar| sidecar.as_object_mut())
        .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
        .and_then(|entry| entry.as_object_mut())
        .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.as_object_mut())
        .and_then(|marker| marker.get_mut("envelope"))
        .and_then(|envelope| envelope.as_object_mut())
        .unwrap();
    sidecar_entry.insert(
        "material_fingerprint".to_string(),
        serde_json::Value::String("tenant-a/vector@tampered".to_string()),
    );
    let tampered_fingerprint_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: tampered_fingerprint_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            tampered_fingerprint_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            tampered_fingerprint_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("requires runtime vector encryption")
    ));

    let (wrong_point_payload, wrong_point_verified_sidecar_key) =
        vector_sidecar(DEFAULT_VECTOR_NAME, "tenant-a:docs");
    let wrong_point_provenance = vector_sidecar_provenance(wrong_point_verified_sidecar_key);
    let wrong_point_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_point_payload,
            points: Some(vec![2.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_point_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_point_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("requires runtime vector encryption")
    ));

    let encrypted_sidecar_delete_key = JsonPath {
        first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        rest: vec![JsonPathItem::Key(DEFAULT_VECTOR_NAME.to_string())],
    };
    let delete_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys: vec![encrypted_sidecar_delete_key.clone()],
            points: Some(vec![1.into()]),
            filter: None,
        }));
    let err = collection
        .update_from_client(
            delete_sidecar.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("can only be removed by runtime delete_vectors")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
    let delete_points = vec![1.into()];
    let delete_target = ckks_vector_sidecar_delete_target(Some(&delete_points), None).unwrap();
    let wrong_collection_delete_provenance =
        CollectionUpdateProvenance::runtime_encrypted_vector_deletes_for_target(
            "other-collection",
            vec![DEFAULT_VECTOR_NAME.to_string()],
            delete_target.clone(),
        )
        .unwrap();
    let err = collection
        .update_from_client(
            delete_sidecar.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_collection_delete_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("can only be removed by runtime delete_vectors")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
    let verified_delete_provenance =
        CollectionUpdateProvenance::runtime_encrypted_vector_deletes_for_target(
            &collection_crypto_id,
            vec![DEFAULT_VECTOR_NAME.to_string()],
            delete_target.clone(),
        )
        .unwrap();
    let wrong_point_delete_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys: vec![encrypted_sidecar_delete_key.clone()],
            points: Some(vec![2.into()]),
            filter: None,
        }));
    let err = collection
        .update_from_client(
            wrong_point_delete_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            verified_delete_provenance.clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("can only be removed by runtime delete_vectors")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
    let filter_delete_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys: vec![encrypted_sidecar_delete_key.clone()],
            points: None,
            filter: Some(Filter::default()),
        }));
    let err = collection
        .update_from_client(
            filter_delete_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            verified_delete_provenance.clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("can only be removed by runtime delete_vectors")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
    let filter_delete_target = ckks_vector_sidecar_delete_target(None, Some(&Filter::default()))
        .expect("filter delete target");
    let filter_delete_provenance =
        CollectionUpdateProvenance::runtime_encrypted_vector_deletes_for_target(
            &collection_crypto_id,
            vec![DEFAULT_VECTOR_NAME.to_string()],
            filter_delete_target,
        )
        .unwrap();
    let different_filter_delete_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys: vec![encrypted_sidecar_delete_key.clone()],
            points: None,
            filter: Some(Filter::new_must(Condition::Field(
                FieldCondition::new_match(
                    "plain.field".parse().unwrap(),
                    serde_json::from_value(json!({
                        "value": "different-filter-target",
                    }))
                    .unwrap(),
                ),
            ))),
        }));
    let err = collection
        .update_from_client(
            different_filter_delete_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            filter_delete_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("can only be removed by runtime delete_vectors")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
    let err = collection
        .update_from_client(
            delete_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            verified_delete_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CollectionError::PointNotFound { .. }));

    let clear_payload = CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload {
        points: vec![1.into()],
    });
    let err = collection
        .update_from_client(
            clear_payload,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("clear_payload")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_segment_snapshot_reports_unindexed_sidecars_as_residual() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();

    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::Named(HashMap::new()),
                    payload: None,
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:docs",
        DEFAULT_VECTOR_NAME,
        CkksParameters::default(),
        &SecretKey::from_bytes([31u8; 32]),
        "tenant-a/vector@v1",
        "tenant-a/vector-rk@v1",
        1,
        CollectionTestCkksBackend,
    )
    .unwrap()
    .with_collection_identity(collection_crypto_id)
    .unwrap();
    let public_material =
        CkksPublicMaterial::new(b"openfhe context".to_vec(), b"openfhe public key".to_vec())
            .unwrap();
    let (envelope, verified_sidecar_key) = encryptor
        .encrypt_sidecar_payload_value("docs", "1", &public_material, &[1.0, 2.0])
        .unwrap();
    let expected_ciphertext = envelope
        .as_object()
        .and_then(|entry| entry.get(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.get("envelope"))
        .and_then(|envelope| envelope.get("ciphertext"))
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut sidecar = Map::new();
    sidecar.insert(DEFAULT_VECTOR_NAME.to_string(), envelope);
    let mut payload = Map::new();
    payload.insert(
        ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        serde_json::Value::Object(sidecar),
    );
    collection
        .update_from_client(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: Payload(payload),
                points: Some(vec![1.into()]),
                filter: None,
                key: None,
            })),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_vectors(vec![verified_sidecar_key]),
        )
        .await
        .unwrap();

    let snapshot = collection
        .ckks_ciphertext_segment_search_snapshot(DEFAULT_VECTOR_NAME, &ShardSelectorInternal::All)
        .await
        .unwrap();

    assert!(snapshot.complete);
    assert!(snapshot.indexed_segments.is_empty());
    assert_eq!(snapshot.residual_records.len(), 1);
    let residual = &snapshot.residual_records[0];
    assert_eq!(residual.id, PointIdType::NumId(1));
    assert_eq!(residual.point_id, "1");
    assert_eq!(residual.indexed_record.ciphertext, expected_ciphertext);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_segment_snapshot_recovers_unindexed_sidecars_after_reload() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let snapshots_path = collection_path.join("snapshots");
    let collection =
        encrypted_collection_fixture(&collection_path, 1, vector_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();

    collection
        .update_from_client_simple(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::Named(HashMap::new()),
                    payload: None,
                }]),
            )),
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:docs",
        DEFAULT_VECTOR_NAME,
        CkksParameters::default(),
        &SecretKey::from_bytes([31u8; 32]),
        "tenant-a/vector@v1",
        "tenant-a/vector-rk@v1",
        1,
        CollectionTestCkksBackend,
    )
    .unwrap()
    .with_collection_identity(collection_crypto_id)
    .unwrap();
    let public_material =
        CkksPublicMaterial::new(b"openfhe context".to_vec(), b"openfhe public key".to_vec())
            .unwrap();
    let (envelope, verified_sidecar_key) = encryptor
        .encrypt_sidecar_payload_value("docs", "1", &public_material, &[1.0, 2.0])
        .unwrap();
    let expected_ciphertext = envelope
        .as_object()
        .and_then(|entry| entry.get(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.get("envelope"))
        .and_then(|envelope| envelope.get("ciphertext"))
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut sidecar = Map::new();
    sidecar.insert(DEFAULT_VECTOR_NAME.to_string(), envelope);
    let mut payload = Map::new();
    payload.insert(
        ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        serde_json::Value::Object(sidecar),
    );
    collection
        .update_from_client(
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: Payload(payload),
                points: Some(vec![1.into()]),
                filter: None,
                key: None,
            })),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_vectors(vec![verified_sidecar_key]),
        )
        .await
        .unwrap();

    collection.stop_gracefully().await;
    drop(collection);

    let collection =
        load_local_collection("test".to_string(), &collection_path, &snapshots_path).await;
    let snapshot = collection
        .ckks_ciphertext_segment_search_snapshot(DEFAULT_VECTOR_NAME, &ShardSelectorInternal::All)
        .await
        .unwrap();

    assert!(snapshot.complete);
    assert!(snapshot.indexed_segments.is_empty());
    assert_eq!(snapshot.residual_records.len(), 1);
    let residual = &snapshot.residual_records[0];
    assert_eq!(residual.id, PointIdType::NumId(1));
    assert_eq!(residual.point_id, "1");
    assert_eq!(residual.indexed_record.ciphertext, expected_ciphertext);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_segment_snapshot_treats_optimizer_candidate_graph_as_residual() {
    let collection_dir = canonical_collection_tempdir();
    let collection_path = collection_dir.path().to_path_buf();
    let snapshot_path = collection_path.join("snapshots");
    let mut optimizer_config = TEST_OPTIMIZERS_CONFIG.clone();
    optimizer_config.default_segment_number = 1;
    optimizer_config.indexing_threshold = Some(1);
    optimizer_config.flush_interval_sec = 0;
    optimizer_config.max_optimization_threads = Some(1);
    let collection_config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorParamsBuilder::new(4, Distance::Dot).build().into(),
            shard_number: NonZeroU32::new(1).unwrap(),
            encryption: Some(vector_encryption_config()),
            ..CollectionParams::empty()
        },
        optimizer_config,
        wal_config: WalConfig {
            wal_capacity_mb: 1,
            wal_segments_ahead: 0,
            wal_retain_closed: 1,
        },
        hnsw_config: Default::default(),
        quantization_config: Default::default(),
        strict_mode_config: Default::default(),
        uuid: Some(uuid::Uuid::from_u128(0x22222222222222222222222222222222)),
        metadata: None,
    };
    let collection = new_local_collection(
        "test".to_string(),
        &collection_path,
        &snapshot_path,
        &collection_config,
    )
    .await
    .unwrap();
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:docs",
        DEFAULT_VECTOR_NAME,
        CkksParameters::default(),
        &SecretKey::from_bytes([31u8; 32]),
        "tenant-a/vector@v1",
        "tenant-a/vector-rk@v1",
        1,
        CollectionTestCkksBackend,
    )
    .unwrap()
    .with_collection_identity(collection_crypto_id)
    .unwrap();
    let public_material =
        CkksPublicMaterial::new(b"openfhe context".to_vec(), b"openfhe public key".to_vec())
            .unwrap();
    let mut verified_sidecar_keys = Vec::new();
    let points = (0..64_u64)
        .map(|point_id| {
            let (envelope, verified_sidecar_key) = encryptor
                .encrypt_sidecar_payload_value(
                    "docs",
                    &point_id.to_string(),
                    &public_material,
                    &[point_id as f64, 1.0],
                )
                .unwrap();
            verified_sidecar_keys.push(verified_sidecar_key);
            let mut sidecar = Map::new();
            sidecar.insert(DEFAULT_VECTOR_NAME.to_string(), envelope);
            let mut payload = Map::new();
            payload.insert(
                ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
                serde_json::Value::Object(sidecar),
            );
            PointStructPersisted {
                id: point_id.into(),
                vector: VectorStructPersisted::Named(HashMap::new()),
                payload: Some(Payload(payload)),
            }
        })
        .collect::<Vec<_>>();

    collection
        .update_from_client(
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::from(points),
            )),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_vectors(verified_sidecar_keys),
        )
        .await
        .unwrap();

    let mut complete_snapshot = None;
    for _ in 0..100 {
        collection.trigger_optimizers().await;
        let mut graph_artifact_exists = false;
        let mut pending = vec![collection_path.clone()];
        while let Some(path) = pending.pop() {
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            if metadata.is_dir() {
                // Optimizers can remove a temporary directory after the metadata check.
                let entries = match fs::read_dir(&path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    entries => entries.unwrap(),
                };
                for entry in entries {
                    pending.push(entry.unwrap().path());
                }
                continue;
            }
            if path
                .file_name()
                .is_some_and(|name| name == std::ffi::OsStr::new("ckks_ciphertext_hnsw_graph.json"))
            {
                graph_artifact_exists = true;
                break;
            }
        }
        if graph_artifact_exists {
            let snapshot = collection
                .ckks_ciphertext_segment_search_snapshot(
                    DEFAULT_VECTOR_NAME,
                    &ShardSelectorInternal::All,
                )
                .await
                .unwrap();
            if snapshot.complete {
                complete_snapshot = Some(snapshot);
                break;
            }
        }
        if complete_snapshot.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let snapshot = complete_snapshot.expect(
        "optimizer must produce a CKKS ciphertext candidate graph artifact and complete snapshot",
    );

    assert!(snapshot.complete);
    assert!(
        snapshot.indexed_segments.is_empty(),
        "optimizer-candidate graph artifacts must not be exposed as similarity HNSW indexes",
    );
    assert_eq!(snapshot.residual_records.len(), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_plaintext_vector_reads() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;

    let err = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: WithVector::Bool(true),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot return encrypted vector")
                && description.contains("ciphertext read path returns payload sidecar only")
    ));

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: WithVector::Selector(vec![DEFAULT_VECTOR_NAME.to_string()]),
                ..ScrollRequestInternal::default()
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot return encrypted vector")
                && description.contains("ciphertext read path returns payload sidecar only")
    ));

    let err = collection
        .core_search_batch(
            CoreSearchRequestBatch {
                searches: vec![
                    SearchRequestInternal {
                        vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                        with_payload: None,
                        with_vector: Some(WithVector::Bool(true)),
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        score_threshold: None,
                    }
                    .into(),
                ],
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot return encrypted vector")
                && description.contains("ciphertext read path returns payload sidecar only")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn private_hnsw_vector_rejects_plaintext_vector_reads_with_session_api_message() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_hnsw_vector_encryption_config(),
    )
    .await;

    let err = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: WithVector::Bool(true),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: WithVector::Selector(vec![DEFAULT_VECTOR_NAME.to_string()]),
                ..ScrollRequestInternal::default()
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn private_hnsw_vector_rejects_lookup_source_reference_reads_with_session_api_message() {
    let private_collection_dir = Builder::new()
        .prefix("private-hnsw-lookup-source")
        .tempdir()
        .unwrap();
    let private_collection = Arc::new(
        encrypted_collection_fixture(
            private_collection_dir.path(),
            1,
            private_hnsw_vector_encryption_config(),
        )
        .await,
    );
    let plain_collection_dir = Builder::new()
        .prefix("plain-lookup-target")
        .tempdir()
        .unwrap();
    let plain_collection = simple_collection_fixture(plain_collection_dir.path(), 1).await;
    let point_id_sentinel = 4_242_424_242_u64;
    let lookup_from_private_hnsw = || LookupLocation {
        collection: "private_docs".to_string(),
        vector: Some(DEFAULT_VECTOR_NAME.to_string()),
        shard_key: None,
    };

    let lookup_collection = Arc::clone(&private_collection);
    let err = plain_collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Id(point_id_sentinel.into()),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: Some(lookup_from_private_hnsw()),
                },
                ShardSelectorInternal::All,
            )],
            move |_name| {
                let lookup_collection = Arc::clone(&lookup_collection);
                async move { Some(lookup_collection) }
            },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(err, &["4242424242"]);

    let lookup_collection = Arc::clone(&private_collection);
    let err = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::PointId(point_id_sentinel.into())],
            negative: vec![],
            strategy: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
            using: None,
            lookup_from: Some(lookup_from_private_hnsw()),
        },
        &plain_collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error_without(err, &["4242424242"]);

    let lookup_collection = Arc::clone(&private_collection);
    let err = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::PointId(point_id_sentinel.into())),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: Some(WithVector::Bool(false)),
            using: None,
            lookup_from: Some(lookup_from_private_hnsw()),
        },
        &plain_collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error_without(err, &["4242424242"]);

    let lookup_collection = Arc::clone(&private_collection);
    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Query(CollectionQueryRequest {
                prefetch: vec![],
                query: Some(Query::Vector(VectorQuery::Nearest(
                    VectorInputInternal::Id(point_id_sentinel.into()),
                ))),
                using: DEFAULT_VECTOR_NAME.to_string(),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
                lookup_from: Some(lookup_from_private_hnsw()),
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &plain_collection,
        move |_name| {
            let lookup_collection = Arc::clone(&lookup_collection);
            async move { Some(lookup_collection) }
        },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error_without(err, &["4242424242"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_search_path() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;

    let err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: None,
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("encrypted vector")
                    && description.contains("runtime CKKS sidecar")
                    && description.contains("entrypoint")
        ),
        "unexpected error: {err:?}",
    );

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot query encrypted vector")
                && description.contains("runtime CKKS sidecar query entrypoint")
    ));

    let err = collection
        .query_batch_internal(
            vec![ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Vector(vec![1.0, 0.0, 0.0, 0.0].into())),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            }],
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot query encrypted vector")
                && description.contains("runtime CKKS sidecar query entrypoint")
    ));

    let err = collection
        .query_batch_internal(
            vec![ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(true),
                with_payload: WithPayloadInterface::Bool(false),
            }],
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot return encrypted vector")
                && description.contains("ciphertext read path returns payload sidecar only")
    ));

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: vec![CollectionPrefetch {
                            prefetch: vec![],
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::from(vec![
                                    1.0, 0.0, 0.0, 0.0,
                                ])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        }],
                        query: Some(Query::Sample(SampleInternal::Random)),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Fusion(FusionInternal::Dbsf)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot query encrypted vector")
                && description.contains("runtime CKKS sidecar query entrypoint")
    ));

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("encrypted vector")
                    && description.contains("runtime CKKS sidecar")
                    && description.contains("entrypoint")
        ),
        "unexpected error: {err:?}",
    );

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Query(CollectionQueryRequest {
                prefetch: vec![],
                query: Some(Query::Vector(VectorQuery::Nearest(
                    VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                ))),
                using: DEFAULT_VECTOR_NAME.to_string(),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
                lookup_from: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("encrypted vector")
                    && description.contains("runtime CKKS sidecar")
                    && description.contains("entrypoint")
        ),
        "unexpected error: {err:?}",
    );

    let err = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
            limit: 1,
            ..Default::default()
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("encrypted vector")
                    && description.contains("runtime CKKS sidecar")
                    && description.contains("entrypoint")
        ),
        "unexpected error: {err:?}",
    );

    let err = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: None,
            with_vector: None,
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            CollectionError::BadInput { ref description }
                if description.contains("encrypted vector")
                    && description.contains("runtime CKKS sidecar")
                    && description.contains("entrypoint")
        ),
        "unexpected error: {err:?}",
    );

    let err = collection
        .search_points_matrix(
            CollectionSearchMatrixRequest {
                sample_size: 2,
                limit_per_sample: 1,
                filter: None,
                using: DEFAULT_VECTOR_NAME.to_string(),
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && (description.contains("runtime CKKS sidecar matrix entrypoint")
                    || description.contains("use CKKS sidecar vector search APIs"))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn private_hnsw_vector_rejects_direct_search_paths_with_session_api_message() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = encrypted_collection_fixture(
        collection_dir.path(),
        1,
        private_hnsw_vector_encryption_config(),
    )
    .await;

    let query_vector_sentinel = vec![12345.125_f32, -23456.25, 34567.5, -45678.75];
    let err = collection
        .search(
            SearchRequestInternal {
                vector: query_vector_sentinel.clone().into(),
                with_payload: None,
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error_without(
        err,
        &["12345.125", "-23456.25", "34567.5", "-45678.75"],
    );

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = collection
        .query_batch_internal(
            vec![ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Vector(vec![1.0, 0.0, 0.0, 0.0].into())),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            }],
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: vec![CollectionPrefetch {
                            prefetch: vec![],
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::from(vec![
                                    1.0, 0.0, 0.0, 0.0,
                                ])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        }],
                        query: Some(Query::Sample(SampleInternal::Random)),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Fusion(FusionInternal::Dbsf)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
            limit: 1,
            ..Default::default()
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = recommend_batch_by(
        vec![(
            RecommendRequestInternal {
                positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
                limit: 1,
                ..Default::default()
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: None,
            with_vector: None,
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = discover_batch(
        vec![(
            DiscoverRequestInternal {
                target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
                context: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: None,
                with_vector: None,
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = discover(
        DiscoverRequestInternal {
            target: None,
            context: Some(vec![ContextExamplePair {
                positive: RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0]),
                negative: RecommendExample::Dense(vec![0.0, 1.0, 0.0, 0.0]),
            }]),
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: None,
            with_vector: None,
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = discover_batch(
        vec![(
            DiscoverRequestInternal {
                target: None,
                context: Some(vec![ContextExamplePair {
                    positive: RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0]),
                    negative: RecommendExample::Dense(vec![0.0, 1.0, 0.0, 0.0]),
                }]),
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                with_payload: None,
                with_vector: None,
                using: None,
                lookup_from: None,
            },
            ShardSelectorInternal::All,
        )],
        &collection,
        |_name| async { None },
        None,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Query(CollectionQueryRequest {
                prefetch: vec![],
                query: Some(Query::Vector(VectorQuery::Nearest(
                    VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                ))),
                using: DEFAULT_VECTOR_NAME.to_string(),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
                lookup_from: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Recommend(RecommendRequestInternal {
                positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
                limit: 1,
                ..Default::default()
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert_private_hnsw_session_api_error(err);

    let err = collection
        .search_points_matrix(
            CollectionSearchMatrixRequest {
                sample_size: 2,
                limit_per_sample: 1,
                filter: None,
                using: DEFAULT_VECTOR_NAME.to_string(),
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert_private_hnsw_session_api_error(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_sidecar_payload_query_surfaces() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;

    let err = collection
        .count(
            CountRequestInternal {
                filter: Some(encrypted_vector_sidecar_filter()),
                exact: true,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("cannot filter on encrypted vector sidecar field")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));

    let encrypted_sidecar_order_by = OrderBy {
        key: format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
            .parse()
            .unwrap(),
        direction: Some(Direction::Asc),
        start_from: None,
    };
    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Struct(encrypted_sidecar_order_by)),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("cannot order by encrypted vector sidecar field")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));

    let err = collection
        .facet(
            FacetParams {
                key: format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
                    .parse()
                    .unwrap(),
                limit: 10,
                filter: None,
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("cannot facet on encrypted vector sidecar field")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));

    let err = collection
        .create_payload_index_with_wait(
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
                .parse()
                .unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            true,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("cannot create payload index on encrypted vector sidecar field")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
            }),
            group_by: format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
                .parse()
                .unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("cannot group by encrypted vector sidecar field")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));

    let encrypted_sidecar_formula = FormulaInternal {
        formula: ExpressionInternal::Variable(format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(encrypted_sidecar_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { ref description }
            if description.contains("cannot use encrypted vector sidecar field")
                && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    ));
}

#[test]
fn collection_params_diff_rejects_crypto_mutation() {
    let generic_err = serde_json::from_value::<CollectionParamsDiff>(serde_json::json!({
        "encryption": {
            "version": 1,
            "key_id": "tenant-a:docs",
            "crypto_schema_version": 1,
            "encryption_epoch": 0,
            "migration_state": "active",
            "rules": []
        }
    }))
    .unwrap_err();
    assert!(
        generic_err.to_string().contains("unknown field"),
        "{generic_err}",
    );

    let legacy_err = serde_json::from_value::<CollectionParamsDiff>(serde_json::json!({
        "ckks": {
            "enabled": true,
            "payload_text_fields": ["body"]
        }
    }))
    .unwrap_err();
    assert!(
        legacy_err.to_string().contains("unknown field"),
        "{legacy_err}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_delete_points_by_filter() {
    test_collection_delete_points_by_filter_with_shards(1).await;
    test_collection_delete_points_by_filter_with_shards(N_SHARDS).await;
}

async fn test_collection_delete_points_by_filter_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
            vec![1.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 0.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    let insert_result = collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter.clone(),
        )
        .await;

    match insert_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    // delete points with id (0, 3)
    let to_be_deleted: AHashSet<PointIdType> = vec![0.into(), 3.into()].into_iter().collect();
    let delete_filter =
        segment::types::Filter::new_must(Condition::HasId(HasIdCondition::from(to_be_deleted)));

    let delete_points = CollectionUpdateOperations::PointOperation(
        PointOperations::DeletePointsByFilter(delete_filter),
    );

    let delete_result = collection
        .update_from_client_simple(
            delete_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await;

    match delete_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    let result = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    // check if we only have 3 out of 5 points left and that the point id were really deleted
    assert_eq!(result.points.len(), 3);
    assert_eq!(result.points.first().unwrap().id, 1.into());
    assert_eq!(result.points.get(1).unwrap().id, 2.into());
    assert_eq!(result.points.get(2).unwrap().id, 4.into());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_local_load_initializing_not_stuck() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    // Create and unload collection
    simple_collection_fixture(collection_dir.path(), 1)
        .await
        .stop_gracefully()
        .await;

    // Modify replica state file on disk, set state to Initializing
    // This is to simulate a situation where a collection was not fully created, we cannot create
    // this situation through our collection interface
    {
        let replica_state_path = collection_dir.path().join("0/replica_state.json");
        let replica_state_file = BufReader::new(File::open(&replica_state_path).unwrap());
        let mut replica_set_state: ReplicaSetState =
            serde_json::from_reader(replica_state_file).unwrap();

        for peer_id in replica_set_state.peers().clone().into_keys() {
            replica_set_state.set_peer_state(peer_id, ReplicaState::Initializing);
        }

        let replica_state_file = BufWriter::new(File::create(&replica_state_path).unwrap());
        serde_json::to_writer(replica_state_file, &replica_set_state).unwrap();
    }

    // Reload collection
    let collection_path = collection_dir.path();
    let loaded_collection = load_local_collection(
        "test".to_string(),
        collection_path,
        &collection_path.join("snapshots"),
    )
    .await;

    // Local replica must be in Active state after loading (all replicas are local)
    let loaded_state = loaded_collection.state().await;
    for shard_info in loaded_state.shards.values() {
        for replica_state in shard_info.replicas.values() {
            assert_eq!(replica_state, &ReplicaState::Active);
        }
    }
}
