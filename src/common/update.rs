use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use api::rest::models::InferenceUsage;
use api::rest::*;
use collection::collection::Collection;
use collection::collection::payload_index_schema::{
    validate_payload_index_entry_for_encryption, validate_payload_index_paths_for_encrypted_paths,
};
use collection::config::{
    CollectionParams, CryptoMigrationCheckpoint, CryptoMigrationState,
    encryption_rule_uses_private_result_oram, private_hnsw_oram_api_required_message,
    private_result_oram_api_required_message,
};
use collection::operations::conversions::write_ordering_from_proto;
use collection::operations::point_ops::*;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
#[cfg(test)]
use collection::operations::types::CountRequestInternal;
use collection::operations::types::{
    CollectionError, CollectionResult, CollectionUpdateProvenance, UpdateResult,
    ckks_vector_sidecar_delete_target,
};
#[cfg(test)]
use collection::operations::universal_query::formula::{ExpressionInternal, FormulaInternal};
use collection::operations::vector_ops::*;
use collection::operations::verification::*;
use collection::shards::shard::ShardId;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use qdrant_sec::{
    CLIENT_CKKS_VECTOR_MARKER, CkksVectorSidecarDeleteTarget, CkksVectorVerifiedSidecarKey,
    ClientCkksVectorVerifiedSidecarKey, ClientPayloadNonceReplayKey,
    ClientPayloadVerifiedEnvelopeKey, ENCRYPTED_VECTOR_SIDECAR_FIELD, METADATA_VALUE_BINDING,
    PRIVATE_HNSW_ORAM_BINDING, PayloadEncryptionError, ServerPayloadVerifiedEnvelopeKey,
};
use schemars::JsonSchema;
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use segment::json_path::{JsonPath, JsonPathItem};
use segment::types::{
    ExtendedPointId, Filter, Payload, PayloadFieldSchema, PayloadKeyType, StrictModeConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::DurationSeconds;
use shard::operations::payload_ops::*;
use shard::operations::*;
use storage::content_manager::collection_meta_ops::*;
use storage::content_manager::collection_verification::check_strict_mode;
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, AccessRequirements, Auth, CollectionMultipass};
use validator::Validate;

use crate::common::crypto::{
    PayloadWriteSetupError, payload_write_plan_for_collection_with_crypto_id,
    vector_write_plan_for_collection_with_crypto_id,
};
use crate::common::inference::params::InferenceParams;
use crate::common::inference::service::InferenceType;
use crate::common::inference::update_requests::*;
use crate::common::query::invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path;
use crate::common::strict_mode::*;
use crate::settings::Settings;

#[serde_with::serde_as]
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Validate)]
pub struct UpdateParams {
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub ordering: WriteOrdering,
    #[serde_as(as = "Option<DurationSeconds<String>>")]
    pub timeout: Option<Duration>,
}

impl UpdateParams {
    pub fn from_grpc(
        wait: Option<bool>,
        ordering: Option<api::grpc::qdrant::WriteOrdering>,
        timeout: Option<u64>,
    ) -> tonic::Result<Self> {
        let params = Self {
            wait: wait.unwrap_or(false),
            ordering: write_ordering_from_proto(ordering)?,
            timeout: timeout.map(Duration::from_secs),
        };

        Ok(params)
    }

    pub(crate) fn timeout_as_secs(&self) -> Option<usize> {
        self.timeout.map(|timeout| timeout.as_secs() as usize)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct InternalUpdateParams {
    pub shard_id: Option<ShardId>,
    pub clock_tag: Option<ClockTag>,
    /// When present, fully overrides the `wait` boolean from the public API message.
    /// When absent, falls back to the `wait` boolean (backward compatible with older nodes).
    pub wait_override: Option<collection::shards::shard_trait::WaitUntil>,
}

impl InternalUpdateParams {
    pub fn from_grpc(
        shard_id: Option<ShardId>,
        clock_tag: Option<api::grpc::qdrant::ClockTag>,
        wait_override: Option<i32>,
    ) -> Self {
        Self {
            shard_id,
            clock_tag: clock_tag.map(ClockTag::from),
            wait_override: wait_override
                .and_then(|v| api::grpc::qdrant::WaitUntil::try_from(v).ok())
                .map(collection::shards::shard_trait::WaitUntil::from),
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct UpdateOperations {
    #[validate(nested)]
    pub operations: Vec<UpdateOperation>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum UpdateOperation {
    Upsert(UpsertOperation),
    Delete(DeleteOperation),
    SetPayload(SetPayloadOperation),
    OverwritePayload(OverwritePayloadOperation),
    DeletePayload(DeletePayloadOperation),
    ClearPayload(ClearPayloadOperation),
    UpdateVectors(UpdateVectorsOperation),
    DeleteVectors(DeleteVectorsOperation),
}

impl Validate for UpdateOperation {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            UpdateOperation::Upsert(op) => op.validate(),
            UpdateOperation::Delete(op) => op.validate(),
            UpdateOperation::SetPayload(op) => op.validate(),
            UpdateOperation::OverwritePayload(op) => op.validate(),
            UpdateOperation::DeletePayload(op) => op.validate(),
            UpdateOperation::ClearPayload(op) => op.validate(),
            UpdateOperation::UpdateVectors(op) => op.validate(),
            UpdateOperation::DeleteVectors(op) => op.validate(),
        }
    }
}

impl StrictModeVerification for UpdateOperation {
    fn query_limit(&self) -> Option<usize> {
        None
    }

    fn indexed_filter_read(&self) -> Option<&segment::types::Filter> {
        None
    }

    fn indexed_filter_write(&self) -> Option<&segment::types::Filter> {
        None
    }

    fn request_exact(&self) -> Option<bool> {
        None
    }

    fn request_search_params(&self) -> Option<&segment::types::SearchParams> {
        None
    }

    async fn check_strict_mode(
        &self,
        collection: &Collection,
        strict_mode_config: &StrictModeConfig,
    ) -> CollectionResult<()> {
        match self {
            UpdateOperation::Upsert(op) => {
                op.upsert
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::Delete(op) => {
                op.delete
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::SetPayload(op) => {
                op.set_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::OverwritePayload(op) => {
                op.overwrite_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::DeletePayload(op) => {
                op.delete_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::ClearPayload(op) => {
                op.clear_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::UpdateVectors(op) => {
                op.update_vectors
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::DeleteVectors(op) => {
                op.delete_vectors
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
        }
    }
}

impl StrictModeVerification for CreateFieldIndex {
    async fn check_custom(
        &self,
        collection: &Collection,
        strict_mode_config: &StrictModeConfig,
    ) -> CollectionResult<()> {
        if let Some(max_payload_index_count) = strict_mode_config.max_payload_index_count {
            let collection_info = collection.info(&ShardSelectorInternal::All).await?;
            if collection_info.payload_schema.len() >= max_payload_index_count {
                return Err(CollectionError::strict_mode(
                    format!(
                        "Collection already has the maximum number of payload indices ({max_payload_index_count})"
                    ),
                    "Please delete an existing index before creating a new one.",
                ));
            }
        }
        Ok(())
    }

    fn indexed_filter_write(&self) -> Option<&Filter> {
        None
    }

    fn query_limit(&self) -> Option<usize> {
        None
    }

    fn indexed_filter_read(&self) -> Option<&Filter> {
        None
    }

    fn request_exact(&self) -> Option<bool> {
        None
    }

    fn request_search_params(&self) -> Option<&segment::types::SearchParams> {
        None
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct UpsertOperation {
    #[validate(nested)]
    upsert: PointInsertOperations,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct DeleteOperation {
    #[validate(nested)]
    delete: PointsSelector,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct SetPayloadOperation {
    #[validate(nested)]
    set_payload: SetPayload,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct OverwritePayloadOperation {
    #[validate(nested)]
    overwrite_payload: SetPayload,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct DeletePayloadOperation {
    #[validate(nested)]
    delete_payload: DeletePayload,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct ClearPayloadOperation {
    #[validate(nested)]
    clear_payload: PointsSelector,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct UpdateVectorsOperation {
    #[validate(nested)]
    update_vectors: UpdateVectors,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct DeleteVectorsOperation {
    #[validate(nested)]
    delete_vectors: DeleteVectors,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct CreateFieldIndex {
    pub field_name: PayloadKeyType,
    #[serde(alias = "field_type")]
    #[validate(nested)]
    pub field_schema: Option<PayloadFieldSchema>,
}

#[expect(clippy::too_many_arguments)]
pub async fn do_upsert_points(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: PointInsertOperations,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<(UpdateResult, Option<models::InferenceUsage>), StorageError> {
    do_upsert_points_with_replay_cache(
        toc_provider,
        collection_name,
        operation,
        internal_params,
        params,
        auth,
        inference_params,
        hw_measurement_acc,
        runtime_settings,
        None,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn do_upsert_points_with_replay_cache(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: PointInsertOperations,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<(UpdateResult, Option<models::InferenceUsage>), StorageError> {
    use point_ops::UpdateMode;
    use segment::types::Filter;

    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let (operation, mut update_provenance) = maybe_encrypt_upsert_payloads(
        toc,
        &collection_name,
        operation,
        &auth,
        runtime_settings,
        client_nonce_replay_cache,
    )
    .await?;

    ensure_upsert_inference_inputs_do_not_touch_encrypted_vectors(
        toc,
        &collection_name,
        &operation,
        &auth,
    )
    .await?;

    let (mut operation, shard_key, usage, update_filter, update_mode) = match operation {
        PointInsertOperations::PointsBatch(batch) => {
            let PointsBatch {
                batch,
                shard_key,
                update_filter,
                update_mode,
            } = batch;
            let (batch, usage) = convert_batch(batch, inference_params).await?;
            let operation = PointInsertOperationsInternal::PointsBatch(batch);
            let update_mode = update_mode.map(rest_update_mode_to_internal);
            (operation, shard_key, usage, update_filter, update_mode)
        }
        PointInsertOperations::PointsList(list) => {
            let PointsList {
                points,
                shard_key,
                update_filter,
                update_mode,
            } = list;
            let (list, usage) =
                convert_point_struct(points, InferenceType::Update, inference_params).await?;
            let operation = PointInsertOperationsInternal::PointsList(list);
            let update_mode = update_mode.map(rest_update_mode_to_internal);
            (operation, shard_key, usage, update_filter, update_mode)
        }
    };
    let vector_provenance = maybe_encrypt_upsert_vectors(
        toc,
        &collection_name,
        &mut operation,
        &auth,
        runtime_settings,
    )
    .await?;
    if vector_provenance.allows_vector_sidecars() {
        update_provenance =
            update_provenance.with_runtime_encrypted_vector_provenance(vector_provenance);
    }

    // Decide which operation to use based on update_filter and update_mode
    let operation = match (update_filter, update_mode) {
        // If update_filter is provided, always use conditional upsert
        (Some(condition), mode) => CollectionUpdateOperations::PointOperation(
            PointOperations::UpsertPointsConditional(ConditionalInsertOperationInternal {
                points_op: operation,
                condition,
                update_mode: mode,
            }),
        ),
        // If update_mode is InsertOnly or UpdateOnly, use conditional upsert with empty filter
        (None, Some(UpdateMode::InsertOnly)) | (None, Some(UpdateMode::UpdateOnly)) => {
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPointsConditional(
                ConditionalInsertOperationInternal {
                    points_op: operation,
                    condition: Filter::default(), // Empty filter matches all existing points
                    update_mode,
                },
            ))
        }
        // Default: regular upsert
        (None, None) | (None, Some(UpdateMode::Upsert)) => {
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(operation))
        }
    };

    let result = update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        update_provenance,
    )
    .await?;

    Ok((result, usage))
}

/// Convert REST UpdateMode to internal UpdateMode
fn rest_update_mode_to_internal(mode: api::rest::schema::UpdateMode) -> point_ops::UpdateMode {
    match mode {
        api::rest::schema::UpdateMode::Upsert => point_ops::UpdateMode::Upsert,
        api::rest::schema::UpdateMode::InsertOnly => point_ops::UpdateMode::InsertOnly,
        api::rest::schema::UpdateMode::UpdateOnly => point_ops::UpdateMode::UpdateOnly,
    }
}

pub async fn do_delete_points(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    points: PointsSelector,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(&points, &collection_name, params.timeout_as_secs(), &auth)
        .await?;

    fail_if_collection_has_private_hnsw_oram_vectors(toc, &collection_name, &auth).await?;

    let (operation, shard_key) = match points {
        PointsSelector::PointIdsSelector(PointIdsList { points, shard_key }) => {
            (PointOperations::DeletePoints { ids: points }, shard_key)
        }
        PointsSelector::FilterSelector(FilterSelector { filter, shard_key }) => {
            (PointOperations::DeletePointsByFilter(filter), shard_key)
        }
    };

    let operation = CollectionUpdateOperations::PointOperation(operation);

    update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

#[expect(clippy::too_many_arguments)]
pub async fn do_update_vectors(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: UpdateVectors,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<(UpdateResult, Option<models::InferenceUsage>), StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let UpdateVectors {
        points,
        shard_key,
        update_filter,
    } = operation;

    ensure_point_vectors_inference_inputs_do_not_touch_encrypted_vectors(
        toc,
        &collection_name,
        &points,
        &auth,
    )
    .await?;

    let (mut points, usage) =
        convert_point_vectors(points, InferenceType::Update, inference_params).await?;
    let (sidecar_payload_updates, vector_provenance) = maybe_encrypt_update_vectors(
        toc,
        &collection_name,
        &mut points,
        update_filter.as_ref(),
        &auth,
        runtime_settings,
    )
    .await?;

    let mut result = None;
    for payload in sidecar_payload_updates {
        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: payload.payload,
                points: payload.points,
                filter: payload.filter,
                key: payload.key,
            }));
        result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key.clone(),
                auth.clone(),
                hw_measurement_acc.clone(),
                vector_provenance.clone(),
            )
            .await?,
        );
    }

    if !points.is_empty() {
        let operation = CollectionUpdateOperations::VectorOperation(
            VectorOperations::UpdateVectors(UpdateVectorsOp {
                points,
                update_filter,
            }),
        );

        result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key,
                auth,
                hw_measurement_acc,
                vector_provenance,
            )
            .await?,
        );
    }

    let Some(result) = result else {
        return Err(StorageError::bad_request("No vectors provided"));
    };

    Ok((result, usage))
}

pub async fn do_delete_vectors(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: DeleteVectors,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    // TODO: Is this cancel safe!?

    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let DeleteVectors {
        vector,
        filter,
        points,
        shard_key,
    } = operation;

    let vector_names: Vec<_> = vector.into_iter().collect();
    let encrypted_sidecar_delete_target =
        ckks_vector_sidecar_delete_target(points.as_deref(), filter.as_ref());
    let (vector_names, encrypted_sidecar_keys, encrypted_sidecar_delete_provenance) =
        split_encrypted_vector_delete_names(
            toc,
            &collection_name,
            &auth,
            vector_names,
            encrypted_sidecar_delete_target.as_ref(),
        )
        .await?;
    ensure_not_mixed_encrypted_and_plaintext_vector_mutation(
        &collection_name,
        encrypted_sidecar_keys.len(),
        vector_names.len(),
        "delete_vectors",
    )?;

    let mut result = None;

    if let Some(filter) = filter.clone() {
        if !encrypted_sidecar_keys.is_empty() {
            let operation = CollectionUpdateOperations::PayloadOperation(
                PayloadOps::DeletePayload(DeletePayloadOp {
                    keys: encrypted_sidecar_keys.clone(),
                    points: None,
                    filter: Some(filter.clone()),
                }),
            );

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key.clone(),
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    encrypted_sidecar_delete_provenance.clone(),
                )
                .await?,
            );
        }
        if !vector_names.is_empty() {
            let vectors_operation =
                VectorOperations::DeleteVectorsByFilter(filter, vector_names.clone());

            let operation = CollectionUpdateOperations::VectorOperation(vectors_operation);

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key.clone(),
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    CollectionUpdateProvenance::client_plaintext(),
                )
                .await?,
            );
        }
    }

    if let Some(points) = points.clone() {
        if !encrypted_sidecar_keys.is_empty() {
            let operation = CollectionUpdateOperations::PayloadOperation(
                PayloadOps::DeletePayload(DeletePayloadOp {
                    keys: encrypted_sidecar_keys,
                    points: Some(points.clone()),
                    filter: None,
                }),
            );

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key.clone(),
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    encrypted_sidecar_delete_provenance.clone(),
                )
                .await?,
            );
        }
        if !vector_names.is_empty() {
            let vectors_operation = VectorOperations::DeleteVectors(points.into(), vector_names);
            let operation = CollectionUpdateOperations::VectorOperation(vectors_operation);

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key,
                    auth,
                    hw_measurement_acc,
                    CollectionUpdateProvenance::client_plaintext(),
                )
                .await?,
            );
        }
    }

    result.ok_or_else(|| StorageError::bad_request("No filter or points provided"))
}

pub async fn do_set_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<UpdateResult, StorageError> {
    do_set_payload_with_replay_cache(
        toc_provider,
        collection_name,
        operation,
        internal_params,
        params,
        auth,
        hw_measurement_acc,
        runtime_settings,
        None,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn do_set_payload_with_replay_cache(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let (operations, update_provenance) = maybe_encrypt_point_payload_update(
        toc,
        &collection_name,
        operation,
        &auth,
        runtime_settings,
        "set_payload",
        client_nonce_replay_cache,
    )
    .await?;

    let mut last_result = None;
    for operation in operations.into_operations() {
        let SetPayload {
            points,
            payload,
            filter,
            shard_key,
            key,
        } = operation;

        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload,
                points,
                filter,
                key,
            }));

        last_result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key,
                auth.clone(),
                hw_measurement_acc.clone(),
                update_provenance.clone(),
            )
            .await?,
        );
    }

    last_result.ok_or_else(|| StorageError::bad_request("No points provided"))
}

pub async fn do_overwrite_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<UpdateResult, StorageError> {
    do_overwrite_payload_with_replay_cache(
        toc_provider,
        collection_name,
        operation,
        internal_params,
        params,
        auth,
        hw_measurement_acc,
        runtime_settings,
        None,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn do_overwrite_payload_with_replay_cache(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;
    // Overwriting replaces the whole payload, which would silently discard the reserved
    // encrypted vector sidecar (the only copy of the point's encrypted vectors), exactly like
    // clear_payload would.
    ensure_payload_replacement_does_not_drop_encrypted_vector_sidecars(
        toc,
        &collection_name,
        "overwrite payloads",
    )
    .await?;

    let (operations, update_provenance) = maybe_encrypt_point_payload_update(
        toc,
        &collection_name,
        operation,
        &auth,
        runtime_settings,
        "overwrite_payload",
        client_nonce_replay_cache,
    )
    .await?;

    let mut last_result = None;
    for operation in operations.into_operations() {
        let SetPayload {
            points,
            payload,
            filter,
            shard_key,
            key: _,
        } = operation;

        let operation = CollectionUpdateOperations::PayloadOperation(PayloadOps::OverwritePayload(
            SetPayloadOp {
                payload,
                points,
                filter,
                // overwrite operation doesn't support payload selector
                key: None,
            },
        ));

        last_result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key,
                auth.clone(),
                hw_measurement_acc.clone(),
                update_provenance.clone(),
            )
            .await?,
        );
    }

    last_result.ok_or_else(|| StorageError::bad_request("No points provided"))
}

pub async fn do_delete_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: DeletePayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let DeletePayload {
        keys,
        points,
        filter,
        shard_key,
    } = operation;
    ensure_delete_payload_keys_do_not_touch_encrypted_vector_sidecar(&keys)?;

    let operation =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys,
            points,
            filter,
        }));

    update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

fn ensure_delete_payload_keys_do_not_touch_encrypted_vector_sidecar(
    keys: &[JsonPath],
) -> Result<(), StorageError> {
    let sidecar_path = JsonPath {
        first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
        rest: Vec::new(),
    };
    for key in keys {
        if key.compatible(&sidecar_path) {
            return Err(StorageError::bad_input(
                "cannot delete reserved encrypted vector sidecar payload field via delete_payload; use delete_vectors for encrypted vector names",
            ));
        }
    }
    Ok(())
}

pub async fn do_clear_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    points: PointsSelector,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(&points, &collection_name, params.timeout_as_secs(), &auth)
        .await?;
    ensure_payload_replacement_does_not_drop_encrypted_vector_sidecars(
        toc,
        &collection_name,
        "clear payloads",
    )
    .await?;

    let (point_operation, shard_key) = match points {
        PointsSelector::PointIdsSelector(PointIdsList { points, shard_key }) => {
            (PayloadOps::ClearPayload { points }, shard_key)
        }
        PointsSelector::FilterSelector(FilterSelector { filter, shard_key }) => {
            (PayloadOps::ClearPayloadByFilter(filter), shard_key)
        }
    };

    let operation = CollectionUpdateOperations::PayloadOperation(point_operation);

    update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

async fn ensure_payload_replacement_does_not_drop_encrypted_vector_sidecars(
    toc: &TableOfContent,
    collection_name: &str,
    operation_name: &str,
) -> Result<(), StorageError> {
    let multipass = CollectionMultipass;
    let collection_pass = multipass.issue_pass(collection_name);
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let has_encrypted_vector_rule =
        collection_config
            .params
            .effective_encryption()
            .is_some_and(|encryption| {
                encryption.rules.iter().any(|rule| {
                    matches!(
                        &rule.selector,
                        collection::config::EncryptionSelector::VectorNames { names }
                            if !names.is_empty()
                    )
                })
            });

    if has_encrypted_vector_rule {
        return Err(StorageError::bad_input(format!(
            "cannot {operation_name} because encrypted vector sidecars are stored in a reserved payload field; use set_payload/delete_payload for fields and delete_vectors for encrypted vector names",
        )));
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
pub async fn do_batch_update_points(
    toc_provider: impl CheckedTocProvider + Clone,
    collection_name: String,
    operations: Vec<UpdateOperation>,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<(Vec<UpdateResult>, Option<InferenceUsage>), StorageError> {
    // Check strict mode for all batch operations, *before applying* them
    let mut toc = None;

    for operation in &operations {
        toc = toc_provider
            .check_strict_mode(operation, &collection_name, params.timeout_as_secs(), &auth)
            .await?
            .into();
    }

    let Some(toc) = toc else {
        // Batch is empty, return empty result vector
        return Ok((Vec::new(), None));
    };

    // Pass unchecked ToC provider into `do_*` functions, because we already checked strict mode
    let toc_provider = UncheckedTocProvider::new_unchecked(toc);

    let mut results = Vec::with_capacity(operations.len());
    let mut inference_usage = InferenceUsage::default();
    let mut seen_client_nonces = std::collections::HashSet::new();

    for operation in operations {
        let current_update_result = match operation {
            UpdateOperation::Upsert(operation) => {
                let (result, usage) = do_upsert_points_with_replay_cache(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.upsert,
                    internal_params,
                    params,
                    auth.clone(),
                    inference_params.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                    Some(&mut seen_client_nonces),
                )
                .await?;

                inference_usage.merge_opt(usage);
                result
            }
            UpdateOperation::Delete(operation) => {
                do_delete_points(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.delete,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            UpdateOperation::SetPayload(operation) => {
                do_set_payload_with_replay_cache(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.set_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                    Some(&mut seen_client_nonces),
                )
                .await?
            }
            UpdateOperation::OverwritePayload(operation) => {
                do_overwrite_payload_with_replay_cache(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.overwrite_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                    Some(&mut seen_client_nonces),
                )
                .await?
            }
            UpdateOperation::DeletePayload(operation) => {
                do_delete_payload(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.delete_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            UpdateOperation::ClearPayload(operation) => {
                do_clear_payload(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.clear_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            UpdateOperation::UpdateVectors(operation) => {
                let (result, usage) = do_update_vectors(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.update_vectors,
                    internal_params,
                    params,
                    auth.clone(),
                    inference_params.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                )
                .await?;

                inference_usage.merge_opt(usage);
                result
            }
            UpdateOperation::DeleteVectors(operation) => {
                do_delete_vectors(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.delete_vectors,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
        };

        results.push(current_update_result);
    }

    Ok((results, inference_usage.into_non_empty()))
}

pub async fn do_create_index(
    dispatcher: Arc<Dispatcher>,
    collection_name: String,
    operation: CreateFieldIndex,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    // TODO: Is this cancel safe!?

    // Check strict mode before submitting consensus operation
    let pass = check_strict_mode(
        &operation,
        // Use per-request timeout from params if provided
        params.timeout_as_secs(),
        &collection_name,
        &dispatcher,
        &auth,
    )
    .await?;

    let Some(field_schema) = operation.field_schema else {
        return Err(StorageError::bad_request(
            "Can't auto-detect field type, please specify `field_schema` in the request",
        ));
    };

    auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().write().extras(),
        "create_payload_index",
    )?;

    let consensus_op = CollectionMetaOperations::CreatePayloadIndex(CreatePayloadIndex {
        collection_name: collection_name.clone(),
        field_name: operation.field_name.clone(),
        field_schema: field_schema.clone(),
    });

    let toc = dispatcher.toc(&auth, &pass).clone();

    ensure_payload_index_allowed_by_encryption(
        &toc,
        &collection_name,
        &operation.field_name,
        Some(&field_schema),
    )
    .await?;

    // TODO: Is `submit_collection_meta_op` cancel-safe!? Should be, I think?.. 🤔
    dispatcher
        .submit_collection_meta_op(consensus_op, auth, params.timeout)
        .await?;

    // This function is required as long as we want to maintain interface compatibility
    // for `wait` parameter and return type.
    // The idea is to migrate from the point-like interface to consensus-like interface in the next few versions

    do_create_index_internal(
        toc,
        collection_name,
        operation.field_name,
        Some(field_schema),
        internal_params,
        params,
        hw_measurement_acc,
    )
    .await
}

pub async fn do_create_index_internal(
    toc: Arc<TableOfContent>,
    collection_name: String,
    field_name: PayloadKeyType,
    field_schema: Option<PayloadFieldSchema>,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    ensure_payload_index_allowed_by_encryption(
        &toc,
        &collection_name,
        &field_name,
        field_schema.as_ref(),
    )
    .await?;

    let operation = CollectionUpdateOperations::FieldIndexOperation(
        FieldIndexOperations::CreateIndex(CreateIndex {
            field_name,
            field_schema,
        }),
    );

    update(
        &toc,
        &collection_name,
        operation,
        internal_params,
        params,
        None,
        Auth::new_internal(Access::full("Internal API")),
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

pub async fn do_delete_index(
    dispatcher: Arc<Dispatcher>,
    collection_name: String,
    index_name: JsonPath,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    // TODO: Is this cancel safe!?

    let consensus_op = CollectionMetaOperations::DropPayloadIndex(DropPayloadIndex {
        collection_name: collection_name.clone(),
        field_name: index_name.clone(),
    });

    auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().write().extras(),
        "delete_payload_index",
    )?;

    let pass = new_unchecked_verification_pass();

    let toc = dispatcher.toc(&auth, &pass).clone();

    ensure_payload_index_delete_allowed_by_encryption(&toc, &collection_name, &index_name).await?;

    // TODO: Is `submit_collection_meta_op` cancel-safe!? Should be, I think?.. 🤔
    dispatcher
        .submit_collection_meta_op(
            consensus_op,
            auth,
            // Use per-request timeout from params if provided
            params.timeout,
        )
        .await?;

    do_delete_index_internal(
        toc,
        collection_name,
        index_name,
        internal_params,
        params,
        hw_measurement_acc,
    )
    .await
}

pub async fn do_delete_index_internal(
    toc: Arc<TableOfContent>,
    collection_name: String,
    index_name: JsonPath,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    ensure_payload_index_delete_allowed_by_encryption(&toc, &collection_name, &index_name).await?;

    let operation = CollectionUpdateOperations::FieldIndexOperation(
        FieldIndexOperations::DeleteIndex(index_name),
    );

    update(
        &toc,
        &collection_name,
        operation,
        internal_params,
        params,
        None,
        Auth::new_internal(Access::full("Internal API")),
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

async fn ensure_payload_index_allowed_by_encryption(
    toc: &TableOfContent,
    collection_name: &str,
    field_name: &JsonPath,
    field_schema: Option<&PayloadFieldSchema>,
) -> Result<(), StorageError> {
    let multipass = CollectionMultipass;
    let collection_pass = multipass.issue_pass(collection_name);
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };

    validate_payload_index_paths_for_encrypted_paths(
        [field_name],
        &collection_config.params,
        "create",
    )
    .map_err(collection_error_to_storage_error)?;

    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::MetadataKeys { keys } = &rule.selector else {
            continue;
        };
        if rule.binding.as_deref() != Some(METADATA_VALUE_BINDING) {
            continue;
        }
        for metadata_key in keys {
            let metadata_path = metadata_key
                .parse::<JsonPath>()
                .map_err(|_| StorageError::bad_input("encrypted metadata field path is invalid"))?;
            if field_name.compatible(&metadata_path) {
                return Err(StorageError::bad_input(
                    "cannot create payload index on encrypted metadata value field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                ));
            }
        }
    }

    if let Some(field_schema) = field_schema {
        validate_payload_index_entry_for_encryption(
            field_name,
            field_schema,
            &collection_config.params,
            "create",
        )
        .map_err(collection_error_to_storage_error)?;
    } else {
        for rule in &encryption.rules {
            let collection::config::EncryptionSelector::MetadataKeys { keys } = &rule.selector
            else {
                continue;
            };
            if rule.binding.as_deref() != Some("metadata-exact-match-token/v1") {
                continue;
            }
            for metadata_key in keys {
                let metadata_path = metadata_key.parse::<JsonPath>().map_err(|_| {
                    StorageError::bad_input("metadata blind-index field path is invalid")
                })?;
                if field_name.compatible(&metadata_path) {
                    return Err(StorageError::bad_input(
                        "cannot create payload index schema on metadata blind-index field; blind-index token indexes must use keyword schema",
                    ));
                }
            }
        }
    }

    Ok(())
}

async fn ensure_payload_index_delete_allowed_by_encryption(
    toc: &TableOfContent,
    collection_name: &str,
    index_name: &JsonPath,
) -> Result<(), StorageError> {
    let multipass = CollectionMultipass;
    let collection_pass = multipass.issue_pass(collection_name);
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;

    validate_payload_index_paths_for_encrypted_paths(
        [index_name],
        &collection_config.params,
        "delete",
    )
    .map_err(collection_error_to_storage_error)
}

fn collection_error_to_storage_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::BadInput { description } => StorageError::bad_input(description),
        _err => {
            StorageError::service_error("collection encryption payload index validation failed")
        }
    }
}

fn stable_crypto_id_storage_error(_err: CollectionError) -> StorageError {
    StorageError::bad_input(
        "encrypted collection is missing a stable UUID; encrypted payload/vector AAD requires a stable collection identity",
    )
}

async fn ensure_sync_points_allowed_by_encryption(
    toc: &TableOfContent,
    collection_name: &str,
    operation: &PointSyncOperation,
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "sync_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;

    if let Some(vector_name) =
        sync_points_touch_private_hnsw_oram_config(operation, &collection_config.params)
    {
        return Err(private_hnsw_oram_api_required_error(&vector_name));
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
pub async fn update(
    toc: &TableOfContent,
    collection_name: &str,
    operation: CollectionUpdateOperations,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    shard_key: Option<ShardKeySelector>,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    update_provenance: CollectionUpdateProvenance,
) -> Result<UpdateResult, StorageError> {
    let InternalUpdateParams {
        shard_id,
        clock_tag,
        wait_override,
    } = internal_params;

    let UpdateParams {
        wait,
        ordering,
        timeout: _,
    } = params;

    if let CollectionUpdateOperations::PointOperation(point_ops::PointOperations::SyncPoints(
        sync_operation,
    )) = &operation
    {
        ensure_sync_points_allowed_by_encryption(toc, collection_name, sync_operation, &auth)
            .await?;
    }

    // Use wait_override if present, otherwise fall back to the wait boolean
    let wait =
        wait_override.unwrap_or_else(|| collection::shards::shard_trait::WaitUntil::from(wait));

    let shard_selector = match operation {
        CollectionUpdateOperations::PointOperation(point_ops::PointOperations::SyncPoints(_)) => {
            debug_assert_eq!(
                shard_key, None,
                "Sync points operations can't specify shard key"
            );

            match shard_id {
                Some(shard_id) => ShardSelectorInternal::ShardId(shard_id),
                None => {
                    debug_assert!(false, "Sync operation is supposed to select shard directly");
                    ShardSelectorInternal::Empty
                }
            }
        }

        CollectionUpdateOperations::FieldIndexOperation(_) => {
            debug_assert_eq!(
                shard_key, None,
                "Field index operations can't specify shard key"
            );

            match shard_id {
                Some(shard_id) => ShardSelectorInternal::ShardId(shard_id),
                None => ShardSelectorInternal::All,
            }
        }

        _ => get_shard_selector_for_update(shard_id, shard_key),
    };

    toc.update(
        collection_name,
        OperationWithClockTag::new(operation, clock_tag),
        wait,
        params.timeout,
        ordering,
        shard_selector,
        auth,
        hw_measurement_acc,
        update_provenance,
    )
    .await
}

/// Converts a pair of parameters into a shard selector
/// suitable for update operations.
///
/// The key difference from selector for search operations is that
/// empty shard selector in case of update means default shard,
/// while empty shard selector in case of search means all shards.
///
/// Parameters:
/// - shard_selection: selection of the exact shard ID, always have priority over shard_key
/// - shard_key: selection of the shard key, can be a single key or a list of keys
///
/// Returns:
/// - ShardSelectorInternal - resolved shard selector
fn get_shard_selector_for_update(
    shard_selection: Option<ShardId>,
    shard_key: Option<ShardKeySelector>,
) -> ShardSelectorInternal {
    match (shard_selection, shard_key) {
        (Some(shard_selection), None) => ShardSelectorInternal::ShardId(shard_selection),
        (Some(shard_selection), Some(_)) => {
            debug_assert!(
                false,
                "Shard selection and shard key are mutually exclusive"
            );
            ShardSelectorInternal::ShardId(shard_selection)
        }
        (None, Some(shard_key)) => ShardSelectorInternal::from(shard_key),
        (None, None) => ShardSelectorInternal::Empty,
    }
}

pub async fn do_reencrypt_stale_payloads_for_crypto_migration(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    runtime_settings: &Settings,
    auth: &Auth,
    dry_run: bool,
) -> Result<Vec<CryptoMigrationCheckpoint>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().manage(),
        "reencrypt_stale_payloads_for_crypto_migration",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Err(StorageError::bad_input(
            "payload crypto migration requires an encrypted collection",
        ));
    };
    if !matches!(
        encryption.migration_state,
        CryptoMigrationState::Encrypting | CryptoMigrationState::Rotating
    ) {
        return Err(StorageError::bad_input(format!(
            "payload re-encrypt migration requires migration_state=encrypting or rotating; current state is {:?}",
            encryption.migration_state,
        )));
    }

    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;
    let Some(plan) = payload_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(payload_runtime_invalid_storage_error)?
    else {
        return Err(StorageError::bad_input(
            "payload crypto migration requires a server-side payload encryption rule",
        ));
    };
    if !plan.has_server_encrypt_rules() {
        return Err(StorageError::bad_input(
            "payload crypto migration requires server-side payload encryption rules; client-side envelopes are store-only and cannot be re-encrypted by Qdrant",
        ));
    }

    let rewrite_payload = |point_id: &ExtendedPointId,
                           payload: &mut Payload|
     -> CollectionResult<(usize, Vec<ServerPayloadVerifiedEnvelopeKey>)> {
        plan.reencrypt_payload_if_stale_for_crypto_migration(&point_id.to_string(), payload)
            .map(|outcome| {
                (
                    outcome.changed,
                    outcome
                        .verified_server_envelope_keys
                        .into_iter()
                        .collect::<Vec<_>>(),
                )
            })
            .map_err(|_| CollectionError::bad_input("payload crypto migration rewrite failed"))
    };
    if dry_run {
        collection
            .dry_run_payloads_for_crypto_migration(rewrite_payload)
            .await
    } else {
        collection
            .rewrite_payloads_for_crypto_migration(rewrite_payload)
            .await
    }
    .map_err(StorageError::from)
}

pub async fn do_decrypt_payloads_for_crypto_migration(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    runtime_settings: &Settings,
    auth: &Auth,
    dry_run: bool,
) -> Result<Vec<CryptoMigrationCheckpoint>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().manage(),
        "decrypt_payloads_for_crypto_migration",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Err(StorageError::bad_input(
            "payload crypto decryption migration requires an encrypted collection",
        ));
    };
    if encryption.migration_state != CryptoMigrationState::Decrypting {
        return Err(StorageError::bad_input(format!(
            "payload decryption migration requires migration_state=decrypting; current state is {:?}",
            encryption.migration_state,
        )));
    }

    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;
    let Some(plan) = payload_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(payload_runtime_invalid_storage_error)?
    else {
        return Err(StorageError::bad_input(
            "payload crypto decryption migration requires server-side payload encryption rules",
        ));
    };
    if !plan.has_server_encrypt_rules() || plan.has_client_envelope_rules() {
        return Err(StorageError::bad_input(
            "payload crypto decryption migration requires only server-side payload encryption rules; client-side envelopes are store-only and cannot be decrypted by Qdrant",
        ));
    }

    let decrypt_payload =
        |point_id: &ExtendedPointId, payload: &mut Payload| -> CollectionResult<usize> {
            plan.decrypt_payload_for_crypto_migration(&point_id.to_string(), payload)
                .map_err(|_| CollectionError::bad_input("payload crypto migration decrypt failed"))
        };
    if dry_run {
        collection
            .dry_run_payloads_for_crypto_migration(decrypt_payload)
            .await
    } else {
        collection
            .rewrite_payloads_for_crypto_migration(decrypt_payload)
            .await
    }
    .map_err(StorageError::from)
}

async fn maybe_encrypt_upsert_payloads(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    mut operation: PointInsertOperations,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<(PointInsertOperations, CollectionUpdateProvenance), StorageError> {
    let Some(runtime_settings) = runtime_settings else {
        ensure_payload_runtime_available_for_upsert(toc, collection_name, &operation, auth).await?;
        return Ok((operation, CollectionUpdateProvenance::client_plaintext()));
    };

    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    if let Some(encryption) = collection_config.params.effective_encryption()
        && let Some(payload_path) =
            private_result_oram_payload_upsert_violation(&encryption, &operation)?
    {
        return Err(private_result_oram_payload_write_error(payload_path));
    }
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;
    let Some(plan) = payload_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(payload_runtime_invalid_storage_error)?
    else {
        return Ok((operation, CollectionUpdateProvenance::client_plaintext()));
    };
    ensure_client_envelope_cluster_nonce_ledger_available(
        runtime_settings,
        collection_name,
        plan.has_client_envelope_rules(),
    )?;
    let mut local_seen_client_nonces = std::collections::HashSet::new();
    let seen_client_nonces = client_nonce_replay_cache.unwrap_or(&mut local_seen_client_nonces);
    let seen_client_nonces_before = seen_client_nonces.clone();
    let mut verified_server_envelope_keys = std::collections::HashSet::new();
    let mut verified_client_envelope_keys = std::collections::HashSet::new();

    match &mut operation {
        PointInsertOperations::PointsList(list) => {
            for point in &mut list.points {
                if let Some(payload) = &mut point.payload {
                    let outcome = plan
                        .process_payload_with_replay_cache(
                            &point.id.to_string(),
                            payload,
                            &mut *seen_client_nonces,
                        )
                        .map_err(|err| {
                            payload_write_error_to_storage_error(collection_name, err)
                        })?;
                    verified_server_envelope_keys.extend(outcome.verified_server_envelope_keys);
                    verified_client_envelope_keys.extend(outcome.verified_client_envelope_keys);
                }
            }
        }
        PointInsertOperations::PointsBatch(batch) => {
            if let Some(payloads) = batch.batch.payloads.as_mut() {
                for (point_id, payload) in batch.batch.ids.iter().zip(payloads.iter_mut()) {
                    if let Some(payload) = payload {
                        let outcome = plan
                            .process_payload_with_replay_cache(
                                &point_id.to_string(),
                                payload,
                                &mut *seen_client_nonces,
                            )
                            .map_err(|err| {
                                payload_write_error_to_storage_error(collection_name, err)
                            })?;
                        verified_server_envelope_keys.extend(outcome.verified_server_envelope_keys);
                        verified_client_envelope_keys.extend(outcome.verified_client_envelope_keys);
                    }
                }
            }
        }
    }
    let update_provenance = payload_update_provenance(
        plan.has_server_encrypt_rules(),
        verified_server_envelope_keys,
        verified_client_envelope_keys,
    );
    record_process_client_nonce_replay_cache(
        toc,
        &collection_crypto_id,
        seen_client_nonces,
        &seen_client_nonces_before,
    )
    .await?;

    Ok((operation, update_provenance))
}

async fn maybe_encrypt_upsert_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &mut PointInsertOperationsInternal,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
) -> Result<CollectionUpdateProvenance, StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;

    let Some(runtime_settings) = runtime_settings else {
        if let Some(vector_name) =
            upsert_vectors_touch_private_hnsw_oram_config(operation, &collection_config.params)
        {
            return Err(private_hnsw_oram_api_required_error(&vector_name));
        }
        if upsert_vectors_touch_encrypted_config(operation, &collection_config.params)? {
            return Err(StorageError::bad_input(
                "CKKS vector encryption runtime is required before writing encrypted vectors",
            ));
        }
        return Ok(CollectionUpdateProvenance::client_plaintext());
    };

    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )?
    else {
        return Ok(CollectionUpdateProvenance::client_plaintext());
    };

    let mut verified_sidecar_keys = Vec::new();
    let mut verified_client_sidecar_keys = Vec::new();
    match operation {
        PointInsertOperationsInternal::PointsList(points) => {
            for point in points {
                verified_sidecar_keys.extend(encrypt_vectors_for_point(
                    &plan,
                    collection_name,
                    &point.id.to_string(),
                    &mut point.vector,
                    &mut point.payload,
                )?);
                verified_client_sidecar_keys.extend(verify_client_vector_sidecars_for_point(
                    &plan,
                    collection_name,
                    &point.id.to_string(),
                    point.payload.as_ref(),
                )?);
            }
        }
        PointInsertOperationsInternal::PointsBatch(batch) => {
            verified_sidecar_keys.extend(encrypt_vectors_for_batch(
                &plan,
                collection_name,
                &batch.ids,
                &mut batch.vectors,
                &mut batch.payloads,
            )?);
            if let Some(payloads) = batch.payloads.as_ref() {
                for (point_id, payload) in batch.ids.iter().zip(payloads) {
                    verified_client_sidecar_keys.extend(verify_client_vector_sidecars_for_point(
                        &plan,
                        collection_name,
                        &point_id.to_string(),
                        payload.as_ref(),
                    )?);
                }
            }
        }
    }

    Ok(
        CollectionUpdateProvenance::runtime_encrypted_vectors(verified_sidecar_keys)
            .with_runtime_encrypted_vector_provenance(
                CollectionUpdateProvenance::runtime_verified_client_vectors(
                    verified_client_sidecar_keys,
                ),
            ),
    )
}

async fn maybe_encrypt_update_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    points: &mut Vec<collection::operations::vector_ops::PointVectorsPersisted>,
    update_filter: Option<&Filter>,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
) -> Result<(Vec<SetPayload>, CollectionUpdateProvenance), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "update_vectors")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;

    let Some(runtime_settings) = runtime_settings else {
        if let Some(vector_name) =
            point_vectors_touch_private_hnsw_oram_config(points, &collection_config.params)
        {
            return Err(private_hnsw_oram_api_required_error(&vector_name));
        }
        if point_vectors_touch_encrypted_config(points, &collection_config.params)? {
            return Err(StorageError::bad_input(
                "CKKS vector encryption runtime is required before writing encrypted vectors",
            ));
        }
        return Ok((Vec::new(), CollectionUpdateProvenance::client_plaintext()));
    };

    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )?
    else {
        return Ok((Vec::new(), CollectionUpdateProvenance::client_plaintext()));
    };

    let mut sidecar_updates = Vec::new();
    let mut verified_sidecar_keys = Vec::new();
    let mut mutated_vector_names = Vec::new();
    for point in points.iter_mut() {
        let mut payload = None;
        let point_verified_sidecar_keys = encrypt_vectors_for_point(
            &plan,
            collection_name,
            &point.id.to_string(),
            &mut point.vector,
            &mut payload,
        )?;
        if !point_verified_sidecar_keys.is_empty() {
            verified_sidecar_keys.extend(point_verified_sidecar_keys);
            if let Some(sidecar) = payload
                .as_ref()
                .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                .and_then(Value::as_object)
            {
                mutated_vector_names.extend(sidecar.keys().cloned());
            }
            sidecar_updates.push(SetPayload {
                points: Some(vec![point.id]),
                payload: payload.unwrap_or_default(),
                filter: update_filter.cloned(),
                shard_key: None,
                key: None,
            });
        }
    }
    // The collection only accepts full runtime-generated sidecars, and the sidecar payload
    // write replaces the whole object, so the entries of the point's other encrypted vectors
    // must be re-verified and carried forward instead of being dropped by the shallow merge.
    let mut client_verified_sidecar_keys = Vec::new();
    if !sidecar_updates.is_empty() {
        let point_ids = sidecar_updates
            .iter()
            .filter_map(|update| {
                update
                    .points
                    .as_ref()
                    .and_then(|points| points.first().copied())
            })
            .collect::<Vec<_>>();
        let sidecar_field = format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
            .parse::<JsonPath>()
            .map_err(|_| {
                StorageError::service_error("encrypted vector sidecar field path is invalid")
            })?;
        let existing = crate::common::query::do_get_points(
            toc.as_ref(),
            collection_name,
            collection::operations::types::PointRequestInternal {
                ids: point_ids,
                with_payload: Some(segment::types::WithPayloadInterface::Fields(vec![
                    sidecar_field,
                ])),
                with_vector: segment::types::WithVector::Bool(false),
            },
            None,
            None,
            ShardSelectorInternal::All,
            auth.clone(),
            HwMeasurementAcc::disposable(),
            None,
        )
        .await?;
        let existing_sidecars = existing
            .into_iter()
            .filter_map(|record| {
                let sidecar = record
                    .payload
                    .as_ref()?
                    .0
                    .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)?
                    .as_object()?
                    .clone();
                Some((record.id, sidecar))
            })
            .collect::<HashMap<_, _>>();
        for update in &mut sidecar_updates {
            let Some(point_id) = update
                .points
                .as_ref()
                .and_then(|points| points.first().copied())
            else {
                continue;
            };
            let Some(existing_sidecar) = existing_sidecars.get(&point_id) else {
                continue;
            };
            let Some(Value::Object(new_sidecar)) =
                update.payload.0.get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            else {
                continue;
            };
            let point_id_string = point_id.to_string();
            for (vector_name, value) in existing_sidecar {
                if new_sidecar.contains_key(vector_name) {
                    continue;
                }
                if let Some(key) = plan.verify_stored_vector_sidecar_payload_value(
                    collection_name,
                    &point_id_string,
                    vector_name,
                    value,
                )? {
                    verified_sidecar_keys.push(key);
                } else if let Some(key) = plan.verify_client_vector_sidecar_payload_value(
                    collection_name,
                    &point_id_string,
                    vector_name,
                    value,
                )? {
                    client_verified_sidecar_keys.push(key);
                } else {
                    return Err(StorageError::bad_input(
                        "existing encrypted vector sidecar entry cannot be carried forward by update_vectors",
                    ));
                }
                new_sidecar.insert(vector_name.clone(), value.clone());
            }
        }
    }
    points.retain(|point| !point.vector.is_empty());
    ensure_not_mixed_encrypted_and_plaintext_vector_mutation(
        collection_name,
        sidecar_updates.len(),
        points.len(),
        "update_vectors",
    )?;
    ensure_encrypted_vector_update_sidecar_fanout_is_atomic(
        collection_name,
        sidecar_updates.len(),
    )?;
    mutated_vector_names.sort_unstable();
    mutated_vector_names.dedup();
    invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path(
        collection.path(),
        &collection_crypto_id,
        &mutated_vector_names,
    )?;

    let provenance = CollectionUpdateProvenance::runtime_encrypted_vectors(verified_sidecar_keys)
        .with_runtime_encrypted_vector_provenance(
            CollectionUpdateProvenance::runtime_verified_client_vectors(
                client_verified_sidecar_keys,
            ),
        );
    Ok((sidecar_updates, provenance))
}

async fn ensure_upsert_inference_inputs_do_not_touch_encrypted_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &PointInsertOperations,
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    if let Some(vector_name) =
        upsert_inference_inputs_touch_encrypted_config(operation, &collection_config.params)
    {
        return Err(encrypted_vector_inference_write_error(
            collection_name,
            &vector_name,
            &collection_config.params,
        ));
    }

    Ok(())
}

async fn ensure_point_vectors_inference_inputs_do_not_touch_encrypted_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    points: &[PointVectors],
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "update_vectors")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    if let Some(vector_name) =
        point_vectors_inference_inputs_touch_encrypted_config(points, &collection_config.params)
    {
        return Err(encrypted_vector_inference_write_error(
            collection_name,
            &vector_name,
            &collection_config.params,
        ));
    }

    Ok(())
}

fn encrypted_vector_inference_write_error(
    _collection_name: &str,
    vector_name: &str,
    params: &CollectionParams,
) -> StorageError {
    if private_hnsw_oram_vector_in_config(params, vector_name) {
        return private_hnsw_oram_api_required_error(vector_name);
    }

    StorageError::bad_input(
        "encrypted vectors do not allow inference-derived update vectors; provide precomputed \
         dense values or use an explicit client-side encrypted vector envelope path",
    )
}

fn upsert_inference_inputs_touch_encrypted_config(
    operation: &PointInsertOperations,
    params: &CollectionParams,
) -> Option<String> {
    match operation {
        PointInsertOperations::PointsList(list) => list.points.iter().find_map(|point| {
            vector_struct_inference_touches_encrypted_config(&point.vector, params)
        }),
        PointInsertOperations::PointsBatch(batch) => {
            batch_vector_struct_inference_touches_encrypted_config(&batch.batch.vectors, params)
        }
    }
}

fn point_vectors_inference_inputs_touch_encrypted_config(
    points: &[PointVectors],
    params: &CollectionParams,
) -> Option<String> {
    points
        .iter()
        .find_map(|point| vector_struct_inference_touches_encrypted_config(&point.vector, params))
}

fn vector_struct_inference_touches_encrypted_config(
    vector: &VectorStruct,
    params: &CollectionParams,
) -> Option<String> {
    let encryption = params.effective_encryption()?;
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for encrypted_name in names {
            let touches = match vector {
                VectorStruct::Document(_) | VectorStruct::Image(_) | VectorStruct::Object(_) => {
                    encrypted_name == DEFAULT_VECTOR_NAME
                }
                VectorStruct::Named(vectors) => vectors
                    .get(encrypted_name)
                    .is_some_and(rest_vector_requires_inference),
                VectorStruct::Single(_) | VectorStruct::MultiDense(_) => false,
            };
            if touches {
                return Some(encrypted_name.clone());
            }
        }
    }

    None
}

fn batch_vector_struct_inference_touches_encrypted_config(
    vectors: &BatchVectorStruct,
    params: &CollectionParams,
) -> Option<String> {
    let encryption = params.effective_encryption()?;
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for encrypted_name in names {
            let touches = match vectors {
                BatchVectorStruct::Document(_)
                | BatchVectorStruct::Image(_)
                | BatchVectorStruct::Object(_) => encrypted_name == DEFAULT_VECTOR_NAME,
                BatchVectorStruct::Named(named) => named
                    .get(encrypted_name)
                    .is_some_and(|vectors| vectors.iter().any(rest_vector_requires_inference)),
                BatchVectorStruct::Single(_) | BatchVectorStruct::MultiDense(_) => false,
            };
            if touches {
                return Some(encrypted_name.clone());
            }
        }
    }

    None
}

fn rest_vector_requires_inference(vector: &Vector) -> bool {
    matches!(
        vector,
        Vector::Document(_) | Vector::Image(_) | Vector::Object(_)
    )
}

fn ensure_not_mixed_encrypted_and_plaintext_vector_mutation(
    _collection_name: &str,
    encrypted_count: usize,
    plaintext_count: usize,
    operation: &str,
) -> Result<(), StorageError> {
    if encrypted_count > 0 && plaintext_count > 0 {
        return Err(StorageError::bad_input(format!(
            "cannot mix encrypted vector sidecar mutations and plaintext vector mutations in one {operation} request; split the request until atomic mixed vector updates are implemented",
        )));
    }
    Ok(())
}

fn ensure_encrypted_vector_update_sidecar_fanout_is_atomic(
    _collection_name: &str,
    encrypted_point_count: usize,
) -> Result<(), StorageError> {
    if encrypted_point_count > 1 {
        return Err(StorageError::bad_input(format!(
            "cannot update encrypted vectors for multiple points in one update_vectors request \
             until atomic encrypted vector sidecar fanout is implemented; split the request into \
             one point per update_vectors call",
        )));
    }
    Ok(())
}

fn upsert_vectors_touch_encrypted_config(
    operation: &PointInsertOperationsInternal,
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    match operation {
        PointInsertOperationsInternal::PointsList(points) => {
            points.iter().try_fold(false, |touches, point| {
                Ok(touches || vector_struct_touches_encrypted_config(&point.vector, params)?)
            })
        }
        PointInsertOperationsInternal::PointsBatch(batch) => {
            batch_vectors_touch_encrypted_config(&batch.vectors, params)
        }
    }
}

fn point_vectors_touch_encrypted_config(
    points: &[collection::operations::vector_ops::PointVectorsPersisted],
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    points.iter().try_fold(false, |touches, point| {
        Ok(touches || vector_struct_touches_encrypted_config(&point.vector, params)?)
    })
}

fn vector_struct_touches_encrypted_config(
    vector: &VectorStructPersisted,
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(false);
    };
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for encrypted_name in names {
            let touches = match vector {
                VectorStructPersisted::Single(_) | VectorStructPersisted::MultiDense(_) => {
                    encrypted_name == DEFAULT_VECTOR_NAME
                }
                VectorStructPersisted::Named(vectors) => vectors.contains_key(encrypted_name),
            };
            if touches {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn batch_vectors_touch_encrypted_config(
    vectors: &BatchVectorStructPersisted,
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(false);
    };
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for encrypted_name in names {
            let touches = match vectors {
                BatchVectorStructPersisted::Single(_)
                | BatchVectorStructPersisted::MultiDense(_) => {
                    encrypted_name == DEFAULT_VECTOR_NAME
                }
                BatchVectorStructPersisted::Named(vectors) => vectors.contains_key(encrypted_name),
            };
            if touches {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn private_hnsw_oram_api_required_error(vector_name: &str) -> StorageError {
    StorageError::bad_input(private_hnsw_oram_api_required_message(vector_name))
}

fn private_hnsw_oram_vector_in_config(params: &CollectionParams, vector_name: &str) -> bool {
    let Some(encryption) = params.effective_encryption() else {
        return false;
    };

    encryption.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING)
            && matches!(
                &rule.selector,
                collection::config::EncryptionSelector::VectorNames { names }
                    if names.iter().any(|name| name == vector_name)
            )
    })
}

async fn fail_if_collection_has_private_hnsw_oram_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "delete_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    if let Some(vector_name) = first_private_hnsw_oram_vector_in_config(&collection_config.params) {
        return Err(private_hnsw_oram_api_required_error(&vector_name));
    }
    Ok(())
}

fn first_private_hnsw_oram_vector_in_config(params: &CollectionParams) -> Option<String> {
    let encryption = params.effective_encryption()?;
    encryption.rules.iter().find_map(|rule| {
        if rule.binding.as_deref() != Some(PRIVATE_HNSW_ORAM_BINDING) {
            return None;
        }
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            return None;
        };
        names.first().cloned()
    })
}

fn upsert_vectors_touch_private_hnsw_oram_config(
    operation: &PointInsertOperationsInternal,
    params: &CollectionParams,
) -> Option<String> {
    match operation {
        PointInsertOperationsInternal::PointsList(points) => points.iter().find_map(|point| {
            vector_struct_touches_private_hnsw_oram_config(&point.vector, params)
        }),
        PointInsertOperationsInternal::PointsBatch(batch) => {
            batch_vectors_touch_private_hnsw_oram_config(&batch.vectors, params)
        }
    }
}

fn point_vectors_touch_private_hnsw_oram_config(
    points: &[collection::operations::vector_ops::PointVectorsPersisted],
    params: &CollectionParams,
) -> Option<String> {
    points
        .iter()
        .find_map(|point| vector_struct_touches_private_hnsw_oram_config(&point.vector, params))
}

fn sync_points_touch_private_hnsw_oram_config(
    operation: &PointSyncOperation,
    params: &CollectionParams,
) -> Option<String> {
    operation
        .points
        .iter()
        .find_map(|point| vector_struct_touches_private_hnsw_oram_config(&point.vector, params))
}

fn vector_struct_touches_private_hnsw_oram_config(
    vector: &VectorStructPersisted,
    params: &CollectionParams,
) -> Option<String> {
    let encryption = params.effective_encryption()?;
    for rule in &encryption.rules {
        if rule.binding.as_deref() != Some(PRIVATE_HNSW_ORAM_BINDING) {
            continue;
        }
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for private_name in names {
            let touches = match vector {
                VectorStructPersisted::Single(_) | VectorStructPersisted::MultiDense(_) => {
                    private_name == DEFAULT_VECTOR_NAME
                }
                VectorStructPersisted::Named(vectors) => vectors.contains_key(private_name),
            };
            if touches {
                return Some(private_name.clone());
            }
        }
    }

    None
}

fn batch_vectors_touch_private_hnsw_oram_config(
    vectors: &BatchVectorStructPersisted,
    params: &CollectionParams,
) -> Option<String> {
    let encryption = params.effective_encryption()?;
    for rule in &encryption.rules {
        if rule.binding.as_deref() != Some(PRIVATE_HNSW_ORAM_BINDING) {
            continue;
        }
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for private_name in names {
            let touches = match vectors {
                BatchVectorStructPersisted::Single(_)
                | BatchVectorStructPersisted::MultiDense(_) => private_name == DEFAULT_VECTOR_NAME,
                BatchVectorStructPersisted::Named(vectors) => vectors.contains_key(private_name),
            };
            if touches {
                return Some(private_name.clone());
            }
        }
    }

    None
}

fn encrypt_vectors_for_point(
    plan: &crate::common::crypto::VectorWritePlan,
    collection_name: &str,
    point_id: &str,
    vector: &mut VectorStructPersisted,
    payload: &mut Option<Payload>,
) -> Result<Vec<CkksVectorVerifiedSidecarKey>, StorageError> {
    match vector {
        VectorStructPersisted::Single(values) => {
            if !plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Ok(Vec::new());
            }
            let (envelope, verified_sidecar_key) = plan
                .encrypt_dense_vector_payload_value(
                    collection_name,
                    point_id,
                    DEFAULT_VECTOR_NAME,
                    values,
                )?
                .ok_or_else(|| {
                    StorageError::service_error(
                        "encrypted vector was selected but no sidecar was produced",
                    )
                })?;
            let mut staged_payload = payload.clone();
            insert_encrypted_vector_sidecar(&mut staged_payload, DEFAULT_VECTOR_NAME, envelope)?;
            *payload = staged_payload;
            *vector = VectorStructPersisted::Named(HashMap::new());
            Ok(vec![verified_sidecar_key])
        }
        VectorStructPersisted::MultiDense(_) => {
            if plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Err(StorageError::bad_input(
                    "encrypted vector only supports dense vectors; multi-dense vector encryption is not implemented",
                ));
            }
            Ok(Vec::new())
        }
        VectorStructPersisted::Named(vectors) => {
            let encrypted_names: Vec<_> = vectors
                .keys()
                .filter(|name| plan.contains_vector_name(name))
                .cloned()
                .collect();
            let mut staged_sidecars = Vec::new();
            for vector_name in &encrypted_names {
                let vector = vectors.get(vector_name).ok_or_else(|| {
                    StorageError::service_error(
                        "encrypted vector disappeared while staging point update",
                    )
                })?;
                let VectorPersisted::Dense(values) = vector else {
                    return Err(StorageError::bad_input(
                        "encrypted vector only supports dense vectors; sparse and multi-dense vector encryption is not implemented",
                    ));
                };
                let (envelope, verified_sidecar_key) = plan
                    .encrypt_dense_vector_payload_value(
                        collection_name,
                        point_id,
                        &vector_name,
                        &values,
                    )?
                    .ok_or_else(|| {
                        StorageError::service_error(
                            "encrypted vector was selected but no sidecar was produced",
                        )
                    })?;
                staged_sidecars.push((vector_name.clone(), envelope, verified_sidecar_key));
            }
            let mut staged_payload = payload.clone();
            let mut verified_sidecar_keys = Vec::with_capacity(staged_sidecars.len());
            for (vector_name, envelope, verified_sidecar_key) in staged_sidecars {
                insert_encrypted_vector_sidecar(&mut staged_payload, &vector_name, envelope)?;
                verified_sidecar_keys.push(verified_sidecar_key);
            }
            for vector_name in encrypted_names {
                vectors.remove(&vector_name);
            }
            *payload = staged_payload;
            Ok(verified_sidecar_keys)
        }
    }
}

fn encrypt_vectors_for_batch(
    plan: &crate::common::crypto::VectorWritePlan,
    collection_name: &str,
    ids: &[segment::types::PointIdType],
    vectors: &mut BatchVectorStructPersisted,
    payloads: &mut Option<Vec<Option<Payload>>>,
) -> Result<Vec<CkksVectorVerifiedSidecarKey>, StorageError> {
    match vectors {
        BatchVectorStructPersisted::Single(batch_values) => {
            if !plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Ok(Vec::new());
            }
            if batch_values.len() != ids.len() {
                return Err(StorageError::bad_input(
                    "batch vector count must match point id count",
                ));
            }
            let mut staged_payloads = payloads.clone();
            ensure_batch_payloads(&mut staged_payloads, ids.len())?;
            let staged_payloads_ref = staged_payloads.as_mut().ok_or_else(|| {
                StorageError::service_error(
                    "batch payload staging did not create payload slots for encrypted vectors",
                )
            })?;
            let mut staged_sidecars = Vec::with_capacity(ids.len());
            for (payload_index, (point_id, values)) in
                ids.iter().zip(batch_values.iter()).enumerate()
            {
                let (envelope, verified_sidecar_key) = plan
                    .encrypt_dense_vector_payload_value(
                        collection_name,
                        &point_id.to_string(),
                        DEFAULT_VECTOR_NAME,
                        values,
                    )?
                    .ok_or_else(|| {
                        StorageError::service_error(
                            "encrypted vector was selected but no sidecar was produced",
                        )
                    })?;
                staged_sidecars.push((payload_index, envelope, verified_sidecar_key));
            }
            let mut verified_sidecar_keys = Vec::with_capacity(staged_sidecars.len());
            for (payload_index, envelope, verified_sidecar_key) in staged_sidecars {
                insert_encrypted_vector_sidecar(
                    &mut staged_payloads_ref[payload_index],
                    DEFAULT_VECTOR_NAME,
                    envelope,
                )?;
                verified_sidecar_keys.push(verified_sidecar_key);
            }
            *payloads = staged_payloads;
            *vectors = BatchVectorStructPersisted::Named(HashMap::new());
            Ok(verified_sidecar_keys)
        }
        BatchVectorStructPersisted::MultiDense(_) => {
            if plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Err(StorageError::bad_input(
                    "encrypted vector only supports dense vectors; multi-dense vector encryption is not implemented",
                ));
            }
            Ok(Vec::new())
        }
        BatchVectorStructPersisted::Named(named) => {
            let encrypted_names: Vec<_> = named
                .keys()
                .filter(|name| plan.contains_vector_name(name))
                .cloned()
                .collect();
            if encrypted_names.is_empty() {
                return Ok(Vec::new());
            }
            let mut staged_sidecars = Vec::new();
            for vector_name in &encrypted_names {
                let values = named.get(vector_name).ok_or_else(|| {
                    StorageError::service_error(
                        "encrypted vector disappeared while staging batch update",
                    )
                })?;
                if values.len() != ids.len() {
                    return Err(StorageError::bad_input(
                        "batch vector count for encrypted vector must match point id count",
                    ));
                }
                for (payload_index, (point_id, value)) in ids.iter().zip(values).enumerate() {
                    let VectorPersisted::Dense(values) = value else {
                        return Err(StorageError::bad_input(
                            "encrypted vector only supports dense vectors; sparse and multi-dense vector encryption is not implemented",
                        ));
                    };
                    let (envelope, verified_sidecar_key) = plan
                        .encrypt_dense_vector_payload_value(
                            collection_name,
                            &point_id.to_string(),
                            &vector_name,
                            &values,
                        )?
                        .ok_or_else(|| {
                            StorageError::service_error(
                                "encrypted vector was selected but no sidecar was produced",
                            )
                        })?;
                    staged_sidecars.push((
                        payload_index,
                        vector_name.clone(),
                        envelope,
                        verified_sidecar_key,
                    ));
                }
            }
            let mut staged_payloads = payloads.clone();
            ensure_batch_payloads(&mut staged_payloads, ids.len())?;
            let staged_payloads_ref = staged_payloads.as_mut().ok_or_else(|| {
                StorageError::service_error(
                    "batch payload staging did not create payload slots for encrypted vectors",
                )
            })?;
            let mut verified_sidecar_keys = Vec::with_capacity(staged_sidecars.len());
            for (payload_index, vector_name, envelope, verified_sidecar_key) in staged_sidecars {
                insert_encrypted_vector_sidecar(
                    &mut staged_payloads_ref[payload_index],
                    &vector_name,
                    envelope,
                )?;
                verified_sidecar_keys.push(verified_sidecar_key);
            }
            for vector_name in encrypted_names {
                named.remove(&vector_name);
            }
            *payloads = staged_payloads;
            Ok(verified_sidecar_keys)
        }
    }
}

fn verify_client_vector_sidecars_for_point(
    plan: &crate::common::crypto::VectorWritePlan,
    collection_name: &str,
    point_id: &str,
    payload: Option<&Payload>,
) -> Result<Vec<ClientCkksVectorVerifiedSidecarKey>, StorageError> {
    let Some(sidecar) = payload
        .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
        .and_then(Value::as_object)
    else {
        return Ok(Vec::new());
    };

    let mut verified = Vec::new();
    for (vector_name, value) in sidecar {
        if !value
            .as_object()
            .is_some_and(|object| object.contains_key(CLIENT_CKKS_VECTOR_MARKER))
        {
            continue;
        }
        let Some(verified_key) = plan.verify_client_vector_sidecar_payload_value(
            collection_name,
            point_id,
            vector_name,
            value,
        )?
        else {
            return Err(StorageError::bad_input(
                "client CKKS vector sidecar entry is not configured as a server-blind encrypted vector",
            ));
        };
        verified.push(verified_key);
    }

    Ok(verified)
}

fn ensure_batch_payloads(
    payloads: &mut Option<Vec<Option<Payload>>>,
    len: usize,
) -> Result<(), StorageError> {
    match payloads {
        Some(payloads) if payloads.len() != len => Err(StorageError::bad_input(
            "batch payload count must match point id count",
        )),
        Some(_) => Ok(()),
        None => {
            *payloads = Some(vec![None; len]);
            Ok(())
        }
    }
}

fn insert_encrypted_vector_sidecar(
    payload: &mut Option<Payload>,
    vector_name: &str,
    envelope: Value,
) -> Result<(), StorageError> {
    let payload = payload.get_or_insert_with(Payload::default);
    let sidecar = payload
        .0
        .entry(ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(sidecar) = sidecar.as_object_mut() else {
        return Err(StorageError::bad_input(
            "reserved encrypted vector sidecar field is already set to a non-object value",
        ));
    };
    sidecar.insert(vector_name.to_string(), envelope);
    Ok(())
}

async fn split_encrypted_vector_delete_names(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    auth: &Auth,
    vector_names: Vec<String>,
    delete_target: Option<&CkksVectorSidecarDeleteTarget>,
) -> Result<(Vec<String>, Vec<JsonPath>, CollectionUpdateProvenance), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "delete_vectors")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok((
            vector_names,
            Vec::new(),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    let encrypted_names: std::collections::HashSet<_> = encryption
        .rules
        .iter()
        .filter_map(|rule| match &rule.selector {
            collection::config::EncryptionSelector::VectorNames { names } => Some(names),
            _ => None,
        })
        .flat_map(|names| names.iter().cloned())
        .collect();

    let mut plaintext_vector_names = Vec::new();
    let mut encrypted_sidecar_keys = Vec::new();
    let mut encrypted_sidecar_vector_names = Vec::new();
    for vector_name in vector_names {
        if private_hnsw_oram_vector_in_config(&collection_config.params, &vector_name) {
            return Err(private_hnsw_oram_api_required_error(&vector_name));
        }
        if encrypted_names.contains(&vector_name) {
            if delete_target.is_none() {
                return Err(StorageError::bad_request("No filter or points provided"));
            }
            encrypted_sidecar_keys.push(JsonPath {
                first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
                rest: vec![JsonPathItem::Key(vector_name.clone())],
            });
            encrypted_sidecar_vector_names.push(vector_name);
        } else {
            plaintext_vector_names.push(vector_name);
        }
    }
    let encrypted_sidecar_delete_provenance = if encrypted_sidecar_vector_names.is_empty() {
        CollectionUpdateProvenance::client_plaintext()
    } else {
        CollectionUpdateProvenance::runtime_encrypted_vector_deletes_for_target(
            &collection_crypto_id,
            encrypted_sidecar_vector_names.clone(),
            delete_target
                .ok_or_else(|| {
                    StorageError::service_error(
                        "encrypted sidecar vector delete provenance requires a delete target",
                    )
                })?
                .clone(),
        )
        .map_err(|_| {
            StorageError::bad_input("encrypted vector sidecar delete provenance is invalid")
        })?
    };
    invalidate_ckks_sidecar_hnsw_graph_cache_for_collection_path(
        collection.path(),
        &collection_crypto_id,
        &encrypted_sidecar_vector_names,
    )?;

    Ok((
        plaintext_vector_names,
        encrypted_sidecar_keys,
        encrypted_sidecar_delete_provenance,
    ))
}

enum PayloadUpdatePlan {
    Single(SetPayload),
    Fanout(Vec<SetPayload>),
}

impl PayloadUpdatePlan {
    fn into_operations(self) -> Vec<SetPayload> {
        match self {
            Self::Single(operation) => vec![operation],
            Self::Fanout(operations) => operations,
        }
    }
}

async fn maybe_encrypt_point_payload_update(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    mut operation: SetPayload,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
    operation_name: &str,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<(PayloadUpdatePlan, CollectionUpdateProvenance), StorageError> {
    let Some(runtime_settings) = runtime_settings else {
        ensure_payload_runtime_available_for_payload_update(
            toc,
            collection_name,
            &operation,
            auth,
            operation_name,
        )
        .await?;
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), operation_name)?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    if let Some(encryption) = collection_config.params.effective_encryption()
        && let Some(payload_path) =
            private_result_oram_payload_update_violation(&encryption, &operation)?
    {
        return Err(private_result_oram_payload_write_error(payload_path));
    }
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(stable_crypto_id_storage_error)?;
    let Some(plan) = payload_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(payload_runtime_invalid_storage_error)?
    else {
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };
    ensure_client_envelope_cluster_nonce_ledger_available(
        runtime_settings,
        collection_name,
        plan.has_client_envelope_rules(),
    )?;
    let mut local_seen_client_nonces = std::collections::HashSet::new();
    let seen_client_nonces = client_nonce_replay_cache.unwrap_or(&mut local_seen_client_nonces);
    let seen_client_nonces_before = seen_client_nonces.clone();

    let touches_encrypted_payload =
        plan.touches_selected_fields(&operation.payload, operation.key.as_ref());

    if operation.filter.is_some() {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} with a filter cannot update encrypted payload fields; use point-specific upsert/set_payload so encryption can bind AAD to each point id",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    }

    if operation.key.is_some() {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} with a key path cannot update encrypted payload fields; use a full point-specific payload update so the selected encrypted fields can be sealed with their canonical field paths",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    }

    let Some(points) = operation.points.as_ref() else {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} cannot update encrypted payload fields without point ids; send point-specific updates so encryption can bind AAD to each point id",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    if points.is_empty() {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} cannot update encrypted payload fields without point ids; send point-specific updates so encryption can bind AAD to each point id",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    }

    if points.len() > 1 && touches_encrypted_payload {
        if plan.has_client_envelope_rules() {
            return Err(StorageError::bad_input(format!(
                "{operation_name} cannot reuse client-side encrypted payload envelopes across multiple point ids; send one point-specific update per client envelope",
            )));
        }
        let mut encrypted_operations = Vec::with_capacity(points.len());
        let mut verified_server_envelope_keys = std::collections::HashSet::new();
        for point_id in points {
            let mut payload = operation.payload.clone();
            let outcome = plan
                .process_payload_with_replay_cache(
                    &point_id.to_string(),
                    &mut payload,
                    &mut *seen_client_nonces,
                )
                .map_err(|err| payload_write_error_to_storage_error(collection_name, err))?;
            verified_server_envelope_keys.extend(outcome.verified_server_envelope_keys);
            encrypted_operations.push(SetPayload {
                points: Some(vec![point_id.clone()]),
                payload,
                filter: None,
                shard_key: operation.shard_key.clone(),
                key: None,
            });
        }
        record_process_client_nonce_replay_cache(
            toc,
            &collection_crypto_id,
            seen_client_nonces,
            &seen_client_nonces_before,
        )
        .await?;
        return Ok((
            PayloadUpdatePlan::Fanout(encrypted_operations),
            payload_update_provenance(
                plan.has_server_encrypt_rules(),
                verified_server_envelope_keys,
                std::collections::HashSet::new(),
            ),
        ));
    }

    let Some(point_id) = points.first() else {
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    let outcome = plan
        .process_payload_with_replay_cache(
            &point_id.to_string(),
            &mut operation.payload,
            &mut *seen_client_nonces,
        )
        .map_err(|err| payload_write_error_to_storage_error(collection_name, err))?;
    let update_provenance = payload_update_provenance(
        plan.has_server_encrypt_rules(),
        outcome.verified_server_envelope_keys,
        outcome.verified_client_envelope_keys,
    );
    record_process_client_nonce_replay_cache(
        toc,
        &collection_crypto_id,
        seen_client_nonces,
        &seen_client_nonces_before,
    )
    .await?;

    Ok((PayloadUpdatePlan::Single(operation), update_provenance))
}

fn ensure_client_envelope_cluster_nonce_ledger_available(
    runtime_settings: &Settings,
    _collection_name: &str,
    has_client_envelope_rules: bool,
) -> Result<(), StorageError> {
    if runtime_settings.cluster.enabled && has_client_envelope_rules {
        return Err(StorageError::bad_input(
            "client-side encrypted payload writes in clustered mode require a cluster-wide nonce replay ledger; this build only provides request, process, and collection-local replay caches",
        ));
    }
    Ok(())
}

fn payload_update_provenance(
    has_server_encrypt_rules: bool,
    verified_server_envelope_keys: std::collections::HashSet<ServerPayloadVerifiedEnvelopeKey>,
    verified_client_envelope_keys: std::collections::HashSet<ClientPayloadVerifiedEnvelopeKey>,
) -> CollectionUpdateProvenance {
    match (
        has_server_encrypt_rules,
        verified_server_envelope_keys.is_empty(),
        verified_client_envelope_keys.is_empty(),
    ) {
        (true, false, false) => {
            CollectionUpdateProvenance::runtime_encrypted_payloads_and_verified_client_envelopes(
                verified_server_envelope_keys,
                verified_client_envelope_keys,
            )
        }
        (true, false, true) => {
            CollectionUpdateProvenance::runtime_encrypted_payloads(verified_server_envelope_keys)
        }
        (true, true, false) => CollectionUpdateProvenance::runtime_verified_client_envelopes(
            verified_client_envelope_keys,
        ),
        (true, true, true) | (false, _, true) => CollectionUpdateProvenance::client_plaintext(),
        (false, _, false) => CollectionUpdateProvenance::runtime_verified_client_envelopes(
            verified_client_envelope_keys,
        ),
    }
}

async fn record_process_client_nonce_replay_cache(
    toc: &Arc<TableOfContent>,
    collection_crypto_id: &str,
    seen_client_nonces: &std::collections::HashSet<ClientPayloadNonceReplayKey>,
    seen_client_nonces_before: &std::collections::HashSet<ClientPayloadNonceReplayKey>,
) -> Result<(), StorageError> {
    toc.record_client_payload_nonce_replay_keys(
        collection_crypto_id,
        seen_client_nonces
            .difference(seen_client_nonces_before)
            .map(client_nonce_replay_cache_key),
    )
    .await
}

fn client_nonce_replay_cache_key(key: &ClientPayloadNonceReplayKey) -> String {
    key.cache_key()
}

async fn ensure_payload_runtime_available_for_upsert(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &PointInsertOperations,
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };

    if let Some(payload_path) =
        private_result_oram_payload_upsert_violation(&encryption, operation)?
    {
        return Err(private_result_oram_payload_write_error(payload_path));
    }

    let mut touches_encrypted_payload = false;
    match operation {
        PointInsertOperations::PointsList(list) => {
            for point in &list.points {
                if let Some(payload) = &point.payload
                    && payload_touches_encrypted_config(&encryption, payload, None)?
                {
                    touches_encrypted_payload = true;
                    break;
                }
            }
        }
        PointInsertOperations::PointsBatch(batch) => {
            if let Some(payloads) = batch.batch.payloads.as_ref() {
                for payload in payloads.iter().flatten() {
                    if payload_touches_encrypted_config(&encryption, payload, None)? {
                        touches_encrypted_payload = true;
                        break;
                    }
                }
            }
        }
    }

    if touches_encrypted_payload {
        return Err(payload_runtime_required_storage_error());
    }

    Ok(())
}

async fn ensure_payload_runtime_available_for_payload_update(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &SetPayload,
    auth: &Auth,
    operation_name: &str,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), operation_name)?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };

    if let Some(payload_path) =
        private_result_oram_payload_update_violation(&encryption, operation)?
    {
        return Err(private_result_oram_payload_write_error(payload_path));
    }

    if payload_touches_encrypted_config(&encryption, &operation.payload, operation.key.as_ref())? {
        return Err(payload_runtime_required_storage_error());
    }

    Ok(())
}

fn private_result_oram_payload_upsert_violation<'a>(
    encryption: &'a collection::config::CollectionEncryptionConfig,
    operation: &PointInsertOperations,
) -> Result<Option<&'a str>, StorageError> {
    for rule in encryption
        .rules
        .iter()
        .filter(|rule| encryption_rule_uses_private_result_oram(rule))
    {
        let collection::config::EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for payload_path in paths {
            let protected_path = payload_path.parse::<JsonPath>().map_err(|_| {
                StorageError::bad_input("private result ORAM payload field path is invalid")
            })?;
            if upsert_touches_payload_path(operation, &protected_path) {
                return Ok(Some(payload_path.as_str()));
            }
        }
    }

    Ok(None)
}

fn private_result_oram_payload_update_violation<'a>(
    encryption: &'a collection::config::CollectionEncryptionConfig,
    operation: &SetPayload,
) -> Result<Option<&'a str>, StorageError> {
    for rule in encryption
        .rules
        .iter()
        .filter(|rule| encryption_rule_uses_private_result_oram(rule))
    {
        let collection::config::EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for payload_path in paths {
            let protected_path = payload_path.parse::<JsonPath>().map_err(|_| {
                StorageError::bad_input("private result ORAM payload field path is invalid")
            })?;
            if payload_touches_path(&operation.payload, operation.key.as_ref(), &protected_path) {
                return Ok(Some(payload_path.as_str()));
            }
        }
    }

    Ok(None)
}

fn upsert_touches_payload_path(
    operation: &PointInsertOperations,
    protected_path: &JsonPath,
) -> bool {
    match operation {
        PointInsertOperations::PointsList(list) => list.points.iter().any(|point| {
            point
                .payload
                .as_ref()
                .is_some_and(|payload| payload_touches_path(payload, None, protected_path))
        }),
        PointInsertOperations::PointsBatch(batch) => {
            batch.batch.payloads.as_ref().is_some_and(|payloads| {
                payloads
                    .iter()
                    .flatten()
                    .any(|payload| payload_touches_path(payload, None, protected_path))
            })
        }
    }
}

fn payload_touches_path(
    payload: &segment::types::Payload,
    key: Option<&JsonPath>,
    protected_path: &JsonPath,
) -> bool {
    if let Some(key) = key {
        return key.compatible(protected_path);
    }

    if payload.0.keys().any(|key| {
        key.parse::<JsonPath>()
            .is_ok_and(|payload_path| payload_path.compatible(protected_path))
    }) {
        return true;
    }

    !protected_path.value_get(&payload.0).is_empty()
}

fn private_result_oram_payload_write_error(payload_path: &str) -> StorageError {
    StorageError::bad_input(format!(
        "cannot modify private result ORAM payload field; {}",
        private_result_oram_api_required_message(payload_path),
    ))
}

fn payload_touches_encrypted_config(
    encryption: &collection::config::CollectionEncryptionConfig,
    payload: &segment::types::Payload,
    key: Option<&JsonPath>,
) -> Result<bool, StorageError> {
    for rule in &encryption.rules {
        let paths = match &rule.selector {
            collection::config::EncryptionSelector::PayloadPaths { paths } => paths.as_slice(),
            collection::config::EncryptionSelector::MetadataKeys { keys }
                if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) =>
            {
                keys.as_slice()
            }
            _ => continue,
        };
        for encrypted_path in paths {
            let encrypted_json_path = encrypted_path
                .parse::<JsonPath>()
                .map_err(|_| StorageError::bad_input("encrypted payload field path is invalid"))?;
            if payload_touches_path(payload, key, &encrypted_json_path) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn payload_write_error_to_storage_error(
    _collection_name: &str,
    err: PayloadWriteSetupError,
) -> StorageError {
    match err {
        PayloadWriteSetupError::Payload(PayloadEncryptionError::ClientNonceReplay) => {
            StorageError::bad_input(
                "failed to encrypt payload: client envelope nonce was already used; regenerate the client-side envelope with a fresh nonce before retrying",
            )
        }
        PayloadWriteSetupError::Payload(PayloadEncryptionError::AlreadyEncrypted(_)) => {
            StorageError::bad_input("failed to encrypt payload: payload field is already encrypted")
        }
        PayloadWriteSetupError::Payload(_) => StorageError::bad_input("failed to encrypt payload"),
        err => payload_runtime_invalid_storage_error(err),
    }
}

fn payload_runtime_invalid_storage_error(_err: PayloadWriteSetupError) -> StorageError {
    StorageError::service_error(
        "payload encryption runtime is invalid for encrypted payload fields",
    )
}

fn payload_runtime_required_storage_error() -> StorageError {
    StorageError::bad_input(
        "payload encryption runtime is required before writing encrypted payload fields",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};

    use api::rest::{BaseGroupRequest, SearchGroupsRequestInternal};
    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };
    use collection::operations::types::{
        ContextExamplePair, DiscoverRequestInternal, PointRequestInternal, RecommendExample,
        RecommendGroupsRequestInternal, RecommendRequestInternal,
    };
    use collection::operations::universal_query::collection_query::{
        CkksEncryptedQueryInput, CollectionPrefetch, CollectionQueryGroupsRequest,
        CollectionQueryRequest, Mmr, NearestWithMmr, Query, VectorInputInternal, VectorQuery,
    };
    use collection::operations::universal_query::shard_query::FusionInternal;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::shards::channel_service::ChannelService;
    use common::budget::ResourceBudget;
    use common::load_concurrency::LoadConcurrencyConfig;
    use common::mmap;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        CLIENT_CKKS_VECTOR_MARKER, CLIENT_ENCRYPTED_PAYLOAD_MARKER, ENCRYPTED_CKKS_VECTOR_MARKER,
        ENCRYPTED_VECTOR_SIDECAR_FIELD, METADATA_AES_GCM_PROVIDER, PRIVATE_HNSW_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_BINDING, VECTOR_CLIENT_CKKS_PROVIDER, VECTOR_ENVELOPE_BINDING,
        VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, ckks_vector_sidecar_envelope_key,
        client_ckks_vector_signature_message, client_payload_signature_message,
        is_client_encrypted_payload_value, is_encrypted_ckks_vector_payload_value,
        is_encrypted_payload_value, server_payload_envelope_key,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use segment::data_types::groups::GroupId;
    use segment::data_types::vectors::{DEFAULT_VECTOR_NAME, NamedQuery, VectorInternal};
    use segment::types::{
        Condition, Distance, EncryptedPayloadReadMode, FieldCondition, PayloadEncryptedReadPolicy,
        SearchParams, WithPayloadInterface, WithVector,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use shard::query::query_enum::QueryEnum;
    use shard::search::CoreSearchRequest;
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollectionOperation,
    };
    use storage::rbac::{CollectionAccess, CollectionAccessList, CollectionAccessMode};
    use storage::types::{PerformanceConfig, StorageConfig};
    use tempfile::Builder;
    use tokio::runtime::Runtime;
    use uuid::Uuid;

    use super::*;
    use crate::common::crypto::{
        PayloadWriteSetupError, payload_write_plan_for_collection_for_test,
    };
    use crate::settings::{
        CryptoBackendConfig, CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings, Settings,
    };

    const TEST_VECTOR_COLLECTION_CRYPTO_ID: &str = "32345678-90ab-cdef-1234-567890abcdef";

    fn update_test_storage_config(storage_path: &std::path::Path) -> StorageConfig {
        StorageConfig {
            storage_path: storage_path.to_path_buf(),
            snapshots_path: storage_path.join("snapshots"),
            snapshots_config: Default::default(),
            temp_path: None,
            on_disk_payload: false,
            optimizers: OptimizersConfig {
                deleted_threshold: 0.5,
                vacuum_min_vector_number: 100,
                default_segment_number: 1,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: Some(100),
                indexing_threshold: Some(100),
                flush_interval_sec: 2,
                max_optimization_threads: Some(1),
                prevent_unoptimized: None,
            },
            optimizers_overwrite: None,
            wal: Default::default(),
            performance: PerformanceConfig {
                max_search_threads: 1,
                max_optimization_runtime_threads: 1,
                optimizer_cpu_budget: 0,
                optimizer_io_budget: 0,
                update_rate_limit: None,
                search_timeout_sec: None,
                incoming_shard_transfers_limit: Some(1),
                outgoing_shard_transfers_limit: Some(1),
                async_scorer: None,
                load_concurrency: LoadConcurrencyConfig::default(),
            },
            hnsw_index: Default::default(),
            hnsw_global_config: Default::default(),
            mmap_advice: mmap::Advice::Random,
            node_type: Default::default(),
            update_queue_size: Default::default(),
            handle_collection_load_errors: false,
            recovery_mode: None,
            update_concurrency: Some(NonZeroUsize::new(1).unwrap()),
            shard_transfer_method: None,
            collection: None,
            max_collections: None,
        }
    }

    fn update_test_toc(storage_config: &StorageConfig) -> Arc<TableOfContent> {
        Arc::new(
            TableOfContent::new(
                storage_config,
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                ResourceBudget::default(),
                ChannelService::new(6333, false, None, None),
                0,
                None,
            )
            .unwrap(),
        )
    }

    fn fake_ckks_query_signing_key_pair() -> Ed25519KeyPair {
        static PKCS8: OnceLock<Vec<u8>> = OnceLock::new();
        let pkcs8 = PKCS8
            .get_or_init(|| {
                Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                    .unwrap()
                    .as_ref()
                    .to_vec()
            })
            .clone();
        Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap()
    }

    fn fake_ckks_query_nonce() -> String {
        static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);
        let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [7_u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        BASE64URL_NOPAD.encode(&nonce)
    }

    fn payload_runtime_settings() -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto.instances = HashMap::from([(
            "docs_payload_v1".to_string(),
            CryptoInstanceConfig {
                provider: "payload/aes-256-gcm@v1".to_string(),
                materials: HashMap::from([(
                    "sym_key".to_string(),
                    "tenant-a/payload-v1".to_string(),
                )]),
                backend_ref: None,
                options: json!({
                    "key_id": "tenant-a:docs",
                    "material_fingerprint_id": "tenant-a/payload@v1",
                }),
            },
        )]);
        settings.crypto.materials = HashMap::from([(
            "tenant-a/payload-v1".to_string(),
            crate::settings::CryptoMaterialConfig {
                kind: "symmetric_key_32".to_string(),
                source: Some("inline".to_string()),
                env: None,
                path: None,
                value_b64: Some(BASE64URL_NOPAD.encode(&[5u8; 32])),
                rk_epoch: Some(1),
                ..crate::settings::CryptoMaterialConfig::default()
            },
        )]);
        settings
    }

    fn metadata_value_runtime_settings() -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto.instances = HashMap::from([(
            "docs_metadata_v1".to_string(),
            CryptoInstanceConfig {
                provider: METADATA_AES_GCM_PROVIDER.to_string(),
                materials: HashMap::from([(
                    "sym_key".to_string(),
                    "tenant-a/metadata-v1".to_string(),
                )]),
                backend_ref: None,
                options: json!({
                    "key_id": "tenant-a:docs",
                    "material_fingerprint_id": "tenant-a/metadata@v1",
                }),
            },
        )]);
        settings.crypto.materials = HashMap::from([(
            "tenant-a/metadata-v1".to_string(),
            crate::settings::CryptoMaterialConfig {
                kind: "symmetric_key_32".to_string(),
                source: Some("inline".to_string()),
                env: None,
                path: None,
                value_b64: Some(BASE64URL_NOPAD.encode(&[17u8; 32])),
                rk_epoch: Some(3),
                ..crate::settings::CryptoMaterialConfig::default()
            },
        )]);
        settings
    }

    #[cfg(unix)]
    fn fake_openfhe_bridge() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let dir = Builder::new()
            .prefix("openfhe-sidecar")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let script_path = dir.path().join("openfhe-bridge");
        fs::write(
            &script_path,
            r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"operation":"encrypt_query"'*'"values":[1.0,1.0]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"ZmFrZS1ja2tzLXF1ZXJ5OjE"}\n'
    ;;
  *'"operation":"encrypt_query"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"ZmFrZS1ja2tzLXF1ZXJ5OjI"}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLXF1ZXJ5OjE"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"},{"point_id":"2","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[1.0,7.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLXF1ZXJ5OjE"'*'"items":[{"point_id":"2","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"},{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[7.0,1.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLXF1ZXJ5OjI"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLXF1ZXJ5Om5vLWZ1bGwtc2Nhbg"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"},{"point_id":"2","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.0,4.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLXF1ZXJ5Om5vLWZ1bGwtc2Nhbg"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[8.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"},{"point_id":"2","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[8.0,10.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"},{"point_id":"2","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[10.0,8.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"'*'"point_id":"1"'*'"point_id":"2"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[10.0,8.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"'*'"point_id":"2"'*'"point_id":"1"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[8.0,10.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"'*'"point_id":"1"'*'"point_id":"2"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[8.0,10.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"encrypted_query":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"'*'"point_id":"2"'*'"point_id":"1"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[10.0,8.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"items":[{"point_id":"1","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"},{"point_id":"2","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}]'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.0,4.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"point_id":"1"'*'"point_id":"2"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.0,4.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"point_id":"2"'*'"point_id":"1"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[4.0,9.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"point_id":"2"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[4.0]}\n'
    ;;
  *'"operation":"score_encrypted_query_batch"'*'"distance":"dot"'*'"point_id":"1"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","scores":[9.0]}\n'
    ;;
  *'"operation":"score_encrypted_query"'*'"distance":"dot"'*'"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":9.0}\n'
    ;;
  *'"operation":"score_encrypted_query"'*'"distance":"dot"'*'"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":4.0}\n'
    ;;
  *'"operation":"score_encrypted_query"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","score":1.0}\n'
    ;;
  *'"scheme":"openfhe-ckks"'*'"point_id":"1"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"}\n'
    ;;
  *'"scheme":"openfhe-ckks"'*'"point_id":"2"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}\n'
    ;;
  *'"scheme":"openfhe-ckks"'*)
    printf '{"version":1,"security_profile":"ckks-128-n16384-d4-scale50","ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ"}\n'
    ;;
  *) exit 7 ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&script_path, permissions).unwrap();
        dir
    }

    fn vector_runtime_settings(bridge_path: &std::path::Path) -> Settings {
        let bridge_digest: [u8; 32] = Sha256::digest(fs::read(bridge_path).unwrap()).into();
        let signing_key = fake_ckks_query_signing_key_pair();
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            zero_trust_profile: None,
            ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
            ckks_scoring_source_batch_max: crate::settings::default_ckks_scoring_source_batch_max(),
            ckks_query_nonce_replay_ttl_secs:
                crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
            ckks_query_nonce_replay_cache_max_entries:
                crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_vector_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "vector/openfhe-ckks@v1".to_string(),
                    materials: HashMap::from([(
                        "sym_key".to_string(),
                        "tenant-a/vector-v1".to_string(),
                    )]),
                    backend_ref: Some("openfhe_local".to_string()),
                    options: json!({
                        "key_id": "tenant-a:vector",
                        "material_fingerprint_id": "tenant-a/vector@v1",
                        "profile": qdrant_sec::CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                        "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                            "score_plaintext_output_tcb_ack": "qdrant-sec-ckks-score-output-tcb-v1",
                        "signature_public_keys": {
                            "tenant-a:query-signing-v1": BASE64URL_NOPAD.encode(signing_key.public_key().as_ref()),
                        },
                        "allow_plaintext_queries": true,
                        "plaintext_query_tcb_ack": "qdrant-sec-ckks-plaintext-query-tcb-v1",
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/vector-v1".to_string(),
                CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("inline".to_string()),
                    env: None,
                    path: None,
                    value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                    rk_epoch: Some(1),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::from([(
                "openfhe_local".to_string(),
                CryptoBackendConfig {
                    kind: "process".to_string(),
                    program: Some(bridge_path.display().to_string()),
                    sha256_b64: Some(BASE64URL_NOPAD.encode(&bridge_digest)),
                    signature_public_key_b64: None,
                    signature_b64: None,
                    size: None,
                    timeout_ms: Some(5_000),
                    max_output_bytes: None,
                    landlock_read_allow_roots: Vec::new(),
                },
            )]),
        };
        settings
    }

    fn client_vector_runtime_settings(signing_key: &Ed25519KeyPair) -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            zero_trust_profile: Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string()),
            ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
            ckks_scoring_source_batch_max: crate::settings::default_ckks_scoring_source_batch_max(),
            ckks_query_nonce_replay_ttl_secs:
                crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
            ckks_query_nonce_replay_cache_max_entries:
                crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
            allow_inline_key_material: false,
            instances: HashMap::from([(
                "docs_vector_v1".to_string(),
                CryptoInstanceConfig {
                    provider: VECTOR_CLIENT_CKKS_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({
                        "key_id": "tenant-a:vector",
                        "expected_rk_id": "tenant-a/client-vector-rk",
                        "min_rk_epoch": 3,
                        "max_rk_epoch": 3,
                        "search_mode": "opaque_storage_only",
                        "profile": qdrant_sec::CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                        "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                        "signature_public_keys": {
                            "tenant-a:vector-signing-v1": BASE64URL_NOPAD.encode(signing_key.public_key().as_ref()),
                        },
                    }),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };
        settings
    }

    fn private_hnsw_runtime_settings() -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto.zero_trust_profile =
            Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string());
        settings.crypto.allow_inline_key_material = false;
        settings.crypto.instances = HashMap::from([(
            "docs_private_hnsw_v1".to_string(),
            CryptoInstanceConfig {
                provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: json!({
                    "key_id": "tenant-a/vector-private-rk",
                    "expected_rk_id": "tenant-a/vector-private-rk",
                    "min_rk_epoch": 7,
                    "max_rk_epoch": 7,
                    "search_execution": "client_led",
                    "search_mode": "private_hnsw_oram",
                    "result_privacy": "ids_visible",
                    "distance": "dot",
                    "dim": 2,
                    "hnsw": {
                        "m": 2,
                        "ef_construction": 4,
                        "max_layers": 3,
                        "fixed_neighbor_slots": 4
                    },
                    "oram": {
                        "kind": "path_oram",
                        "bucket_size": 2,
                        "block_size_bytes": 4096,
                        "tree_height": 2,
                        "path_batch_size": 1
                    },
                    "fixed_budget": {
                        "enabled": true,
                        "upper_layer_steps": 1,
                        "base_layer_steps": 3,
                        "paths_per_round": 1,
                        "fixed_result_k": 1
                    },
                    "integrity": {
                        "manifest_signature_required": true,
                        "commit_signature_required": true,
                        "merkle_root_required": true
                    },
                    "signature_public_keys": {
                        "tenant-a/private-hnsw-signing-v1": BASE64URL_NOPAD.encode(&[11_u8; 32])
                    }
                }),
            },
        )]);
        settings
    }

    fn signed_client_ckks_vector_sidecar(signing_key: &Ed25519KeyPair) -> Value {
        let public_material =
            qdrant_sec::CkksPublicMaterial::new(b"openfhe context", b"openfhe public key").unwrap();
        let ciphertext = b"client-ckks-stored-ciphertext";
        let mut value = json!({
            CLIENT_CKKS_VECTOR_MARKER: {
                "version": 1,
                "scheme": qdrant_sec::CKKS_SCHEME,
                "security_profile": qdrant_sec::CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                "collection_id": TEST_VECTOR_COLLECTION_CRYPTO_ID,
                "point_id": "point-1",
                "vector_name": "embedding",
                "key_id": "tenant-a:vector",
                "rk_id": "tenant-a/client-vector-rk",
                "rk_epoch": 3,
                "context_digest": public_material.digest_for(&qdrant_sec::CkksParameters::openfhe_default_128_bit()),
                "slots": 2,
                "ciphertext_sha256": BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref()),
                "ciphertext": BASE64URL_NOPAD.encode(ciphertext),
                "signature": {
                    "alg": "ed25519",
                    "key_id": "tenant-a:vector-signing-v1",
                    "sig": "",
                },
            },
        });
        let signature_message = client_ckks_vector_signature_message(&value).unwrap();
        value[CLIENT_CKKS_VECTOR_MARKER]["signature"]["sig"] =
            json!(BASE64URL_NOPAD.encode(signing_key.sign(&signature_message).as_ref()));
        value
    }

    fn fake_ckks_client_query(ciphertext: &[u8], slots: usize) -> CkksEncryptedQueryInput {
        let public_material =
            qdrant_sec::CkksPublicMaterial::new(b"openfhe context", b"openfhe public key").unwrap();
        let context_digest =
            public_material.digest_for(&qdrant_sec::CkksParameters::openfhe_default_128_bit());
        let signing_key = fake_ckks_query_signing_key_pair();
        let signature_alg = "ed25519".to_string();
        let signature_key_id = "tenant-a:query-signing-v1".to_string();
        let query_nonce = fake_ckks_query_nonce();
        let signature_message = crate::common::crypto::ckks_client_query_signature_message(
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            DEFAULT_VECTOR_NAME,
            "tenant-a:vector",
            "tenant-a/vector-v1",
            1,
            &query_nonce,
            &context_digest,
            slots,
            ciphertext,
            &signature_alg,
            &signature_key_id,
        );
        CkksEncryptedQueryInput {
            version: 1,
            scheme: qdrant_sec::CKKS_SCHEME.to_string(),
            security_profile: qdrant_sec::CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50.to_string(),
            collection_id: TEST_VECTOR_COLLECTION_CRYPTO_ID.to_string(),
            vector_name: DEFAULT_VECTOR_NAME.to_string(),
            key_id: "tenant-a:vector".to_string(),
            rk_id: "tenant-a/vector-v1".to_string(),
            rk_epoch: 1,
            query_nonce,
            context_digest,
            slots,
            ciphertext_sha256: BASE64URL_NOPAD.encode(&Sha256::digest(ciphertext)),
            ciphertext: BASE64URL_NOPAD.encode(ciphertext),
            signature_alg,
            signature_key_id,
            signature_b64: BASE64URL_NOPAD.encode(signing_key.sign(&signature_message).as_ref()),
        }
    }

    fn fake_rest_named_ckks_client_query(
        ciphertext: &[u8],
        slots: usize,
    ) -> api::rest::NamedVectorStruct {
        let query = fake_ckks_client_query(ciphertext, slots);
        api::rest::NamedVectorStruct::CkksEncryptedQuery(api::rest::NamedCkksEncryptedQueryVector {
            name: Some(DEFAULT_VECTOR_NAME.to_string()),
            envelope: api::rest::CkksEncryptedQueryVectorEnvelope {
                version: query.version,
                scheme: query.scheme,
                security_profile: query.security_profile,
                collection_id: query.collection_id,
                vector_name: query.vector_name,
                key_id: query.key_id,
                rk_id: query.rk_id,
                rk_epoch: query.rk_epoch,
                query_nonce: query.query_nonce,
                context_digest: query.context_digest,
                slots: query.slots,
                ciphertext_sha256: query.ciphertext_sha256,
                ciphertext: query.ciphertext,
                signature: api::rest::CkksEncryptedQuerySignature {
                    alg: query.signature_alg,
                    key_id: query.signature_key_id,
                    sig: query.signature_b64,
                },
            },
        })
    }

    fn fake_grpc_ckks_client_query(
        ciphertext: &[u8],
        slots: usize,
    ) -> api::grpc::qdrant::CkksEncryptedQueryVector {
        let query = fake_ckks_client_query(ciphertext, slots);
        api::grpc::qdrant::CkksEncryptedQueryVector {
            version: query.version.into(),
            scheme: query.scheme,
            security_profile: query.security_profile,
            collection_id: query.collection_id,
            vector_name: query.vector_name,
            key_id: query.key_id,
            rk_id: query.rk_id,
            rk_epoch: query.rk_epoch,
            query_nonce: query.query_nonce,
            context_digest: query.context_digest,
            slots: query.slots as u64,
            ciphertext_sha256: query.ciphertext_sha256,
            ciphertext: query.ciphertext,
            signature_alg: query.signature_alg,
            signature_key_id: query.signature_key_id,
            signature_b64: query.signature_b64,
        }
    }

    fn encrypted_vector_params() -> CollectionParams {
        CollectionParams {
            vectors: collection::operations::types::VectorsConfig::Multi(BTreeMap::from([(
                "embedding".to_string(),
                VectorParamsBuilder::new(2, Distance::Dot).build(),
            )])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:vector".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "vector_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some(VECTOR_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    fn private_hnsw_vector_params() -> CollectionParams {
        let mut params = encrypted_vector_params();
        if let Some(encryption) = params.encryption.as_mut() {
            encryption.key_id = Some("tenant-a/vector-private-rk".to_string());
            encryption.encryption_epoch = 7;
            encryption.rules[0].id = "embedding_private_hnsw".to_string();
            encryption.rules[0].instance = "docs_private_hnsw_v1".to_string();
            encryption.rules[0].binding = Some(PRIVATE_HNSW_ORAM_BINDING.to_string());
        }
        params
    }

    fn private_result_oram_payload_params() -> CollectionParams {
        CollectionParams {
            vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_private_result_oram".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    #[test]
    fn private_result_oram_payload_writes_require_session_api_through_common_update() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("private-result-oram-write-guard")
            .tempdir()
            .unwrap();
        let storage_config = update_test_storage_config(storage_dir.path());
        let toc = update_test_toc(&storage_config);
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let params = private_result_oram_payload_params();

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "private_result_write_docs".to_string(),
                            CreateCollection {
                                vectors: params.vectors,
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: params.encryption,
                                strict_mode_config: None,
                                uuid: Some(
                                    Uuid::parse_str(TEST_VECTOR_COLLECTION_CRYPTO_ID).unwrap(),
                                ),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let assert_private_result_write_error =
                |err: StorageError, expected_operation: &str| {
                    let message = err.to_string();
                    assert!(message.contains(expected_operation), "{message}");
                    assert!(
                        message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                        "{message}"
                    );
                    assert!(
                        message.contains("/private-result-oram/session"),
                        "{message}"
                    );
                    assert!(!message.contains("payload encryption runtime"), "{message}");
                    assert!(!message.contains("ordinary"), "{message}");
                    assert!(!message.contains("body"), "{message}");
                    assert!(!message.contains("title"), "{message}");
                };
            let assert_private_result_grpc_write_error =
                |err: tonic::Status, expected_operation: &str| {
                    let message = err.message();
                    assert!(message.contains(expected_operation), "{message}");
                    assert!(
                        message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                        "{message}"
                    );
                    assert!(
                        message.contains("/private-result-oram/session"),
                        "{message}"
                    );
                    assert!(!message.contains("payload encryption runtime"), "{message}");
                    assert!(!message.contains("ordinary"), "{message}");
                    assert!(!message.contains("body"), "{message}");
                    assert!(!message.contains("title"), "{message}");
                };
            let request_hw_counter = || {
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                )
            };
            let private_result_create_index = || CreateFieldIndex {
                field_name: "body".parse().unwrap(),
                field_schema: Some(PayloadFieldSchema::FieldType(
                    segment::types::PayloadSchemaType::Keyword,
                )),
            };
            let grpc_private_result_create_index =
                || api::grpc::qdrant::CreateFieldIndexCollection {
                    collection_name: "private_result_write_docs".to_string(),
                    wait: Some(true),
                    field_name: "body".to_string(),
                    field_type: Some(api::grpc::qdrant::FieldType::Keyword as i32),
                    field_index_params: None,
                    ordering: None,
                    timeout: None,
                };
            let grpc_private_result_delete_index =
                || api::grpc::qdrant::DeleteFieldIndexCollection {
                    collection_name: "private_result_write_docs".to_string(),
                    wait: Some(true),
                    field_name: "body".to_string(),
                    ordering: None,
                    timeout: None,
                };
            let grpc_payload = |payload: Value| {
                api::conversions::json::payload_to_proto(segment::types::Payload(
                    payload.as_object().unwrap().clone(),
                ))
            };
            let grpc_result_vectors = || api::grpc::qdrant::Vectors {
                vectors_options: Some(api::grpc::qdrant::vectors::VectorsOptions::Vector(
                    api::grpc::qdrant::Vector {
                        vector: Some(api::grpc::qdrant::vector::Vector::Dense(
                            api::grpc::qdrant::DenseVector {
                                data: vec![0.1, 0.2],
                            },
                        )),
                        ..Default::default()
                    },
                )),
            };
            let grpc_result_point_struct = || api::grpc::qdrant::PointStruct {
                id: Some(segment::types::PointIdType::from(1).into()),
                payload: grpc_payload(json!({ "body": "grpc result secret" })),
                vectors: Some(grpc_result_vectors()),
            };
            let grpc_points_selector = || api::grpc::qdrant::PointsSelector {
                points_selector_one_of: Some(
                    api::grpc::qdrant::points_selector::PointsSelectorOneOf::Points(
                        api::grpc::qdrant::PointsIdsList {
                            ids: vec![segment::types::PointIdType::from(1).into()],
                        },
                    ),
                ),
            };
            let grpc_filter_selector = || api::grpc::qdrant::PointsSelector {
                points_selector_one_of: Some(
                    api::grpc::qdrant::points_selector::PointsSelectorOneOf::Filter(
                        api::grpc::qdrant::Filter {
                            should: Vec::new(),
                            must: Vec::new(),
                            must_not: Vec::new(),
                            min_should: None,
                        },
                    ),
                ),
            };
            let grpc_update_batch =
                |operation: api::grpc::qdrant::points_update_operation::Operation| {
                    api::grpc::qdrant::UpdateBatchPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        operations: vec![api::grpc::qdrant::PointsUpdateOperation {
                            operation: Some(operation),
                        }],
                        ordering: None,
                        timeout: None,
                    }
                };

            assert_private_result_write_error(
                do_create_index(
                    dispatcher.clone().into(),
                    "private_result_write_docs".to_string(),
                    private_result_create_index(),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM create payload index must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_create_index_internal(
                    toc.clone(),
                    "private_result_write_docs".to_string(),
                    "body".parse().unwrap(),
                    Some(PayloadFieldSchema::FieldType(
                        segment::types::PayloadSchemaType::Keyword,
                    )),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM internal create payload index must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::create_field_index(
                    dispatcher.clone().into(),
                    grpc_private_result_create_index(),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC create payload index must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::create_field_index_internal(
                    toc.clone(),
                    grpc_private_result_create_index(),
                    InternalUpdateParams::default(),
                )
                .await
                .expect_err(
                    "private result ORAM gRPC internal create payload index must fail closed",
                ),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_delete_index(
                    dispatcher.clone().into(),
                    "private_result_write_docs".to_string(),
                    "body".parse().unwrap(),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM delete payload index must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_delete_index_internal(
                    toc.clone(),
                    "private_result_write_docs".to_string(),
                    "body".parse().unwrap(),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM internal delete payload index must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::delete_field_index(
                    dispatcher.clone().into(),
                    grpc_private_result_delete_index(),
                    InternalUpdateParams::default(),
                    auth.clone(),
                )
                .await
                .expect_err("private result ORAM gRPC delete payload index must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::delete_field_index_internal(
                    toc.clone(),
                    grpc_private_result_delete_index(),
                    InternalUpdateParams::default(),
                )
                .await
                .expect_err(
                    "private result ORAM gRPC internal delete payload index must fail closed",
                ),
                "cannot use private result ORAM payload field",
            );

            let unauthorized_create_index = do_create_index(
                dispatcher.clone().into(),
                "private_result_write_docs".to_string(),
                private_result_create_index(),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                Auth::new_internal(Access::full_ro("For test")),
                HwMeasurementAcc::disposable(),
            )
            .await
            .expect_err("private result ORAM create payload index must check auth first");
            let unauthorized_create_index_message = unauthorized_create_index.to_string();
            assert!(
                matches!(unauthorized_create_index, StorageError::Forbidden { .. }),
                "{unauthorized_create_index_message}"
            );
            assert!(
                !unauthorized_create_index_message
                    .contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                "{unauthorized_create_index_message}"
            );
            assert!(
                !unauthorized_create_index_message.contains("/private-result-oram/session"),
                "{unauthorized_create_index_message}"
            );
            assert!(
                !unauthorized_create_index_message.contains("body"),
                "{unauthorized_create_index_message}"
            );

            let unauthorized_delete_index = do_delete_index(
                dispatcher.clone().into(),
                "private_result_write_docs".to_string(),
                "body".parse().unwrap(),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                Auth::new_internal(Access::full_ro("For test")),
                HwMeasurementAcc::disposable(),
            )
            .await
            .expect_err("private result ORAM delete payload index must check auth first");
            let unauthorized_delete_index_message = unauthorized_delete_index.to_string();
            assert!(
                matches!(unauthorized_delete_index, StorageError::Forbidden { .. }),
                "{unauthorized_delete_index_message}"
            );
            assert!(
                !unauthorized_delete_index_message
                    .contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                "{unauthorized_delete_index_message}"
            );
            assert!(
                !unauthorized_delete_index_message.contains("/private-result-oram/session"),
                "{unauthorized_delete_index_message}"
            );
            assert!(
                !unauthorized_delete_index_message.contains("body"),
                "{unauthorized_delete_index_message}"
            );

            assert_private_result_write_error(
                do_upsert_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointInsertOperations::PointsList(api::rest::schema::PointsList {
                        points: vec![api::rest::PointStruct {
                            id: 1.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                            payload: Some(segment::types::Payload(
                                json!({ "body": "ordinary write secret" })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        }],
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_upsert_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
                        batch: api::rest::schema::Batch {
                            ids: vec![2.into()],
                            vectors: api::rest::schema::BatchVectorStruct::Single(vec![vec![
                                0.3, 0.4,
                            ]]),
                            payloads: Some(vec![Some(segment::types::Payload(
                                json!({ "body": "ordinary batch secret" })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ))]),
                        },
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_upsert_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointInsertOperations::PointsList(api::rest::schema::PointsList {
                        points: vec![api::rest::PointStruct {
                            id: 3.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.5, 0.6]),
                            payload: Some(segment::types::Payload(
                                json!({ "title": "ordinary public-looking payload" })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        }],
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM public-looking upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_upsert_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointInsertOperations::PointsList(api::rest::schema::PointsList {
                        points: vec![api::rest::PointStruct {
                            id: 4.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.7, 0.8]),
                            payload: None,
                        }],
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM payload-less upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_upsert_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
                        batch: api::rest::schema::Batch {
                            ids: vec![5.into()],
                            vectors: api::rest::schema::BatchVectorStruct::Single(vec![vec![
                                0.9, 1.0,
                            ]]),
                            payloads: Some(vec![Some(segment::types::Payload(
                                json!({ "title": "ordinary public-looking batch payload" })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ))]),
                        },
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM public-looking batch upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_upsert_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
                        batch: api::rest::schema::Batch {
                            ids: vec![6.into()],
                            vectors: api::rest::schema::BatchVectorStruct::Single(vec![vec![
                                1.1, 1.2,
                            ]]),
                            payloads: None,
                        },
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM payload-less batch upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_set_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    SetPayload {
                        payload: segment::types::Payload(
                            json!({ "body": "ordinary set secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        points: Some(vec![1.into()]),
                        filter: None,
                        shard_key: None,
                        key: None,
                    },
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM set_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_overwrite_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    SetPayload {
                        payload: segment::types::Payload(
                            json!({ "body": "ordinary overwrite secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        points: Some(vec![1.into()]),
                        filter: None,
                        shard_key: None,
                        key: None,
                    },
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM overwrite_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_delete_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    DeletePayload {
                        keys: vec!["body".parse().unwrap()],
                        points: Some(vec![1.into()]),
                        filter: None,
                        shard_key: None,
                    },
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM delete_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_delete_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    DeletePayload {
                        keys: vec!["body".parse().unwrap()],
                        points: None,
                        filter: Some(Filter::new()),
                        shard_key: None,
                    },
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM delete_payload by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_clear_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointsSelector::PointIdsSelector(PointIdsList {
                        points: vec![1.into()],
                        shard_key: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM clear_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_clear_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointsSelector::FilterSelector(FilterSelector {
                        filter: Filter::new(),
                        shard_key: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM clear_payload by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_delete_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointsSelector::PointIdsSelector(PointIdsList {
                        points: vec![1.into()],
                        shard_key: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM delete_points must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_delete_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    PointsSelector::FilterSelector(FilterSelector {
                        filter: Filter::new(),
                        shard_key: None,
                    }),
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM delete_points by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::SetPayload(SetPayloadOperation {
                        set_payload: SetPayload {
                            payload: segment::types::Payload(
                                json!({ "body": "ordinary batch set secret" })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ),
                            points: Some(vec![1.into()]),
                            filter: None,
                            shard_key: None,
                            key: None,
                        },
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch update must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                            points: vec![api::rest::PointStruct {
                                id: 2.into(),
                                vector: api::rest::VectorStruct::Single(vec![0.5, 0.6]),
                                payload: Some(segment::types::Payload(
                                    json!({ "body": "ordinary batch upsert secret" })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                )),
                            }],
                            shard_key: None,
                            update_filter: None,
                            update_mode: None,
                        }),
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch upsert operation must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsBatch(
                            api::rest::schema::PointsBatch {
                                batch: api::rest::schema::Batch {
                                    ids: vec![3.into()],
                                    vectors: api::rest::schema::BatchVectorStruct::Single(vec![
                                        vec![0.7, 0.8],
                                    ]),
                                    payloads: Some(vec![Some(segment::types::Payload(
                                        json!({
                                            "title": "ordinary public-looking batch operation payload",
                                        })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                    ))]),
                                },
                                shard_key: None,
                                update_filter: None,
                                update_mode: None,
                            },
                        ),
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err(
                    "private result ORAM public-looking batch upsert operation must fail closed",
                ),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsBatch(
                            api::rest::schema::PointsBatch {
                                batch: api::rest::schema::Batch {
                                    ids: vec![4.into()],
                                    vectors: api::rest::schema::BatchVectorStruct::Single(vec![
                                        vec![0.9, 1.0],
                                    ]),
                                    payloads: None,
                                },
                                shard_key: None,
                                update_filter: None,
                                update_mode: None,
                            },
                        ),
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM payload-less batch upsert operation must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::OverwritePayload(
                        OverwritePayloadOperation {
                            overwrite_payload: SetPayload {
                                payload: segment::types::Payload(
                                    json!({ "body": "ordinary batch overwrite secret" })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                ),
                                points: Some(vec![1.into()]),
                                filter: None,
                                shard_key: None,
                                key: None,
                            },
                        },
                    )],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch overwrite must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::DeletePayload(DeletePayloadOperation {
                        delete_payload: DeletePayload {
                            keys: vec!["body".parse().unwrap()],
                            points: Some(vec![1.into()]),
                            filter: None,
                            shard_key: None,
                        },
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch delete_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::ClearPayload(ClearPayloadOperation {
                        clear_payload: PointsSelector::PointIdsSelector(PointIdsList {
                            points: vec![1.into()],
                            shard_key: None,
                        }),
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch clear_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_write_error(
                do_batch_update_points(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_write_docs".to_string(),
                    vec![UpdateOperation::Delete(DeleteOperation {
                        delete: PointsSelector::PointIdsSelector(PointIdsList {
                            points: vec![1.into()],
                            shard_key: None,
                        }),
                    })],
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    InferenceParams::default(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch delete points must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::upsert(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::UpsertPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        points: vec![grpc_result_point_struct()],
                        ordering: None,
                        shard_key_selector: None,
                        update_filter: None,
                        timeout: None,
                        update_mode: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::set_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SetPayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        payload: grpc_payload(json!({ "body": "grpc direct set secret" })),
                        points_selector: Some(grpc_points_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        key: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC set_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::set_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SetPayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        payload: grpc_payload(json!({ "body": "grpc direct filter set secret" })),
                        points_selector: Some(grpc_filter_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        key: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC set_payload by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::overwrite_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SetPayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        payload: grpc_payload(json!({ "body": "grpc direct overwrite secret" })),
                        points_selector: Some(grpc_points_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        key: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC overwrite_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::overwrite_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SetPayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        payload: grpc_payload(json!({
                            "body": "grpc direct filter overwrite secret",
                        })),
                        points_selector: Some(grpc_filter_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        key: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC overwrite_payload by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::delete_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        keys: vec!["body".to_string()],
                        points_selector: Some(grpc_points_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC delete_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::delete_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        keys: vec!["body".to_string()],
                        points_selector: Some(grpc_filter_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC delete_payload by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::clear_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::ClearPayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        points: Some(grpc_points_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC clear_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::clear_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::ClearPayloadPoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        points: Some(grpc_filter_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC clear_payload by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::delete(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        points: Some(grpc_points_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC delete points must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::delete(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePoints {
                        collection_name: "private_result_write_docs".to_string(),
                        wait: Some(true),
                        points: Some(grpc_filter_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC delete points by filter must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(api::grpc::qdrant::points_update_operation::Operation::Upsert(
                        api::grpc::qdrant::points_update_operation::PointStructList {
                            points: vec![grpc_result_point_struct()],
                            shard_key_selector: None,
                            update_filter: None,
                            update_mode: None,
                        },
                    )),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch upsert must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::SetPayload(
                            api::grpc::qdrant::points_update_operation::SetPayload {
                                payload: grpc_payload(json!({ "body": "grpc set secret" })),
                                points_selector: Some(grpc_points_selector()),
                                shard_key_selector: None,
                                key: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch set_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::OverwritePayload(
                            api::grpc::qdrant::points_update_operation::OverwritePayload {
                                payload: grpc_payload(json!({ "body": "grpc overwrite secret" })),
                                points_selector: Some(grpc_points_selector()),
                                shard_key_selector: None,
                                key: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch overwrite_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::DeletePayload(
                            api::grpc::qdrant::points_update_operation::DeletePayload {
                                keys: vec!["body".to_string()],
                                points_selector: Some(grpc_points_selector()),
                                shard_key_selector: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch delete_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::ClearPayload(
                            api::grpc::qdrant::points_update_operation::ClearPayload {
                                points: Some(grpc_points_selector()),
                                shard_key_selector: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch clear_payload must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::DeletePoints(
                            api::grpc::qdrant::points_update_operation::DeletePoints {
                                points: Some(grpc_points_selector()),
                                shard_key_selector: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch delete points must fail closed"),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::DeleteDeprecated(
                            grpc_points_selector(),
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err(
                    "private result ORAM gRPC batch deprecated delete must fail closed",
                ),
                "cannot modify private result ORAM payload field",
            );

            assert_private_result_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::ClearPayloadDeprecated(
                            grpc_points_selector(),
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err(
                    "private result ORAM gRPC batch deprecated clear_payload must fail closed",
                ),
                "cannot modify private result ORAM payload field",
            );
        });
    }

    fn default_private_hnsw_vector_params() -> CollectionParams {
        let mut params = private_hnsw_vector_params();
        params.vectors = collection::operations::types::VectorsConfig::Single(
            VectorParamsBuilder::new(2, Distance::Dot).build(),
        );
        if let Some(encryption) = params.encryption.as_mut() {
            encryption.rules[0].selector = EncryptionSelector::VectorNames {
                names: vec![DEFAULT_VECTOR_NAME.to_string()],
            };
        }
        params
    }

    fn test_document(text: &str) -> api::rest::Document {
        api::rest::Document {
            text: text.to_string(),
            model: "test-model".to_string(),
            options: None,
        }
    }

    #[test]
    fn mixed_encrypted_plaintext_vector_mutation_guard_rejects_mixed_requests() {
        let err = ensure_not_mixed_encrypted_and_plaintext_vector_mutation(
            "docs",
            1,
            1,
            "update_vectors",
        )
        .expect_err("mixed encrypted/plaintext vector mutation must be rejected");

        assert!(matches!(
            err,
                StorageError::BadInput { description }
                if description.contains("cannot mix encrypted vector sidecar mutations")
                    && description.contains("update_vectors")
                    && !description.contains("docs")
        ));

        ensure_not_mixed_encrypted_and_plaintext_vector_mutation("docs", 1, 0, "update_vectors")
            .unwrap();
        ensure_not_mixed_encrypted_and_plaintext_vector_mutation("docs", 0, 1, "update_vectors")
            .unwrap();
        ensure_not_mixed_encrypted_and_plaintext_vector_mutation("docs", 0, 0, "delete_vectors")
            .unwrap();
    }

    #[test]
    fn encrypted_vector_upsert_rejects_inference_inputs_before_conversion() {
        let params = encrypted_vector_params();
        let operation = PointInsertOperations::PointsList(api::rest::schema::PointsList {
            points: vec![api::rest::PointStruct {
                id: 1.into(),
                vector: api::rest::VectorStruct::Named(HashMap::from([
                    (
                        "embedding".to_string(),
                        api::rest::Vector::Document(test_document(
                            "encrypted-vector-inference-sentinel",
                        )),
                    ),
                    (
                        "plain".to_string(),
                        api::rest::Vector::Document(test_document("plain-vector-inference-ok")),
                    ),
                ])),
                payload: None,
            }],
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        assert_eq!(
            upsert_inference_inputs_touch_encrypted_config(&operation, &params),
            Some("embedding".to_string()),
        );
    }

    #[test]
    fn encrypted_vector_batch_upsert_rejects_inference_inputs_before_conversion() {
        let params = encrypted_vector_params();
        let operation = PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
            batch: api::rest::schema::Batch {
                ids: vec![1.into()],
                vectors: api::rest::schema::BatchVectorStruct::Named(HashMap::from([
                    (
                        "embedding".to_string(),
                        vec![api::rest::Vector::Document(test_document(
                            "encrypted-vector-batch-inference-sentinel",
                        ))],
                    ),
                    (
                        "plain".to_string(),
                        vec![api::rest::Vector::Document(test_document(
                            "plain-vector-batch-inference-ok",
                        ))],
                    ),
                ])),
                payloads: None,
            },
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        assert_eq!(
            upsert_inference_inputs_touch_encrypted_config(&operation, &params),
            Some("embedding".to_string()),
        );
    }

    #[test]
    fn encrypted_vector_update_rejects_inference_inputs_before_conversion() {
        let params = encrypted_vector_params();
        let points = vec![api::rest::PointVectors {
            id: 1.into(),
            vector: api::rest::VectorStruct::Named(HashMap::from([(
                "embedding".to_string(),
                api::rest::Vector::Document(test_document(
                    "encrypted-vector-update-inference-sentinel",
                )),
            )])),
        }];

        assert_eq!(
            point_vectors_inference_inputs_touch_encrypted_config(&points, &params),
            Some("embedding".to_string()),
        );
    }

    #[test]
    fn plaintext_vector_inference_inputs_remain_allowed() {
        let params = encrypted_vector_params();
        let operation = PointInsertOperations::PointsList(api::rest::schema::PointsList {
            points: vec![api::rest::PointStruct {
                id: 1.into(),
                vector: api::rest::VectorStruct::Named(HashMap::from([(
                    "plain".to_string(),
                    api::rest::Vector::Document(test_document("plain-vector-inference-ok")),
                )])),
                payload: None,
            }],
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        assert_eq!(
            upsert_inference_inputs_touch_encrypted_config(&operation, &params),
            None,
        );
    }

    #[test]
    fn private_hnsw_oram_inference_write_error_uses_session_api() {
        let params = private_hnsw_vector_params();
        let err = encrypted_vector_inference_write_error("docs", "embedding", &params);

        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                    && description.contains("/private-hnsw/{vector}/session")
                    && !description.contains("embedding")
                    && !description.contains("client-side encrypted vector envelope")
        ));
    }

    #[test]
    fn encrypted_vector_inference_write_error_redacts_collection_and_vector_names() {
        let collection_sentinel = "encrypted-vector-inference-secret-collection";
        let vector_sentinel = "encrypted_vector_inference_secret_embedding";
        let err = encrypted_vector_inference_write_error(
            collection_sentinel,
            vector_sentinel,
            &encrypted_vector_params(),
        );

        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("inference-derived update vectors")
                    && description.contains("client-side encrypted vector envelope")
                    && !description.contains(collection_sentinel)
                    && !description.contains(vector_sentinel)
        ));
    }

    #[test]
    fn private_hnsw_oram_vector_shape_guards_cover_batch_and_default_vectors() {
        let params = private_hnsw_vector_params();
        let named_batch = PointInsertOperationsInternal::PointsBatch(
            collection::operations::point_ops::BatchPersisted {
                ids: vec![1.into()],
                vectors: BatchVectorStructPersisted::Named(HashMap::from([(
                    "embedding".to_string(),
                    vec![VectorPersisted::Dense(vec![0.1, 0.2])],
                )])),
                payloads: None,
            },
        );
        assert_eq!(
            upsert_vectors_touch_private_hnsw_oram_config(&named_batch, &params),
            Some("embedding".to_string()),
        );

        let default_params = default_private_hnsw_vector_params();
        let default_batch = PointInsertOperationsInternal::PointsBatch(
            collection::operations::point_ops::BatchPersisted {
                ids: vec![1.into()],
                vectors: BatchVectorStructPersisted::Single(vec![vec![0.1, 0.2]]),
                payloads: None,
            },
        );
        assert_eq!(
            upsert_vectors_touch_private_hnsw_oram_config(&default_batch, &default_params),
            Some(DEFAULT_VECTOR_NAME.to_string()),
        );

        let default_point = vec![collection::operations::vector_ops::PointVectorsPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::Single(vec![0.1, 0.2]),
        }];
        assert_eq!(
            point_vectors_touch_private_hnsw_oram_config(&default_point, &default_params),
            Some(DEFAULT_VECTOR_NAME.to_string()),
        );

        for private_alias in [
            "clientStateCiphertextHash",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "client.state.snapshot.json",
            "client.state.snapshots.json",
            "encrypted.client.state.json",
            "encrypted_client_state_snapshot",
            "encrypted_client_state_snapshot.bin",
            "encrypted_client_state_snapshot.json",
            "encrypted.client.state.snapshot.json",
            "encrypted.client.state.snapshots.json",
            "encrypted_client_state_snapshots.json",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "oramPositionMapBackup",
            "token.map.backup.json",
            "token.position.map.backup.json",
            "token_position_map_backups",
        ] {
            let mut alias_params = private_hnsw_vector_params();
            if let Some(encryption) = alias_params.encryption.as_mut() {
                encryption.rules[0].selector = EncryptionSelector::VectorNames {
                    names: vec![private_alias.to_string()],
                };
            }

            let alias_batch = PointInsertOperationsInternal::PointsBatch(
                collection::operations::point_ops::BatchPersisted {
                    ids: vec![1.into()],
                    vectors: BatchVectorStructPersisted::Named(HashMap::from([(
                        private_alias.to_string(),
                        vec![VectorPersisted::Dense(vec![0.1, 0.2])],
                    )])),
                    payloads: None,
                },
            );
            let detected =
                upsert_vectors_touch_private_hnsw_oram_config(&alias_batch, &alias_params).unwrap();
            assert_eq!(detected, private_alias);

            let message = private_hnsw_oram_api_required_message(&detected);
            assert!(message.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
            assert!(message.contains("/private-hnsw/{vector}/session"));
            assert!(!message.contains(private_alias), "{message}");
        }
    }

    #[test]
    fn private_hnsw_oram_update_paths_reject_plaintext_dense_vectors() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("private-hnsw-update-guard")
            .tempdir()
            .unwrap();
        let storage_config = update_test_storage_config(storage_dir.path());
        let toc = update_test_toc(&storage_config);
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let settings = private_hnsw_runtime_settings();

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "private_hnsw_docs".to_string(),
                            CreateCollection {
                                vectors: collection::operations::types::VectorsConfig::Multi(
                                    BTreeMap::from([(
                                        "embedding".to_string(),
                                        VectorParamsBuilder::new(2, Distance::Dot).build(),
                                    )]),
                                ),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a/vector-private-rk".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 7,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "embedding_private_hnsw".to_string(),
                                        selector: EncryptionSelector::VectorNames {
                                            names: vec!["embedding".to_string()],
                                        },
                                        instance: "docs_private_hnsw_v1".to_string(),
                                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: Some(Uuid::from_u128(0x3234567890abcdef1234567890abcdef)),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let assert_private_hnsw_grpc_write_error = |err: tonic::Status| {
                let message = err.message();
                assert!(
                    message.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
                    "{message}"
                );
                assert!(
                    message.contains("/private-hnsw/{vector}/session"),
                    "{message}"
                );
                assert!(!message.contains("embedding"), "{message}");
                assert!(
                    !message.contains("CKKS vector encryption runtime"),
                    "{message}"
                );
                assert!(
                    !message.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD),
                    "{message}"
                );
            };
            let request_hw_counter = || {
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                )
            };
            let grpc_private_vectors = || api::grpc::qdrant::Vectors {
                vectors_options: Some(api::grpc::qdrant::vectors::VectorsOptions::Vectors(
                    api::grpc::qdrant::NamedVectors {
                        vectors: HashMap::from([(
                            "embedding".to_string(),
                            api::grpc::qdrant::Vector {
                                vector: Some(api::grpc::qdrant::vector::Vector::Dense(
                                    api::grpc::qdrant::DenseVector {
                                        data: vec![0.1, 0.2],
                                    },
                                )),
                                ..Default::default()
                            },
                        )]),
                    },
                )),
            };
            let grpc_point_struct = || api::grpc::qdrant::PointStruct {
                id: Some(segment::types::PointIdType::from(1).into()),
                payload: HashMap::new(),
                vectors: Some(grpc_private_vectors()),
            };
            let grpc_point_vectors = || api::grpc::qdrant::PointVectors {
                id: Some(segment::types::PointIdType::from(1).into()),
                vectors: Some(grpc_private_vectors()),
            };
            let grpc_points_selector = || api::grpc::qdrant::PointsSelector {
                points_selector_one_of: Some(
                    api::grpc::qdrant::points_selector::PointsSelectorOneOf::Points(
                        api::grpc::qdrant::PointsIdsList {
                            ids: vec![segment::types::PointIdType::from(1).into()],
                        },
                    ),
                ),
            };
            let grpc_filter_selector = || api::grpc::qdrant::PointsSelector {
                points_selector_one_of: Some(
                    api::grpc::qdrant::points_selector::PointsSelectorOneOf::Filter(
                        api::grpc::qdrant::Filter {
                            should: Vec::new(),
                            must: Vec::new(),
                            must_not: Vec::new(),
                            min_should: None,
                        },
                    ),
                ),
            };
            let grpc_vectors_selector = || api::grpc::qdrant::VectorsSelector {
                names: vec!["embedding".to_string()],
            };
            let grpc_sync_points = || api::grpc::qdrant::SyncPoints {
                collection_name: "private_hnsw_docs".to_string(),
                wait: Some(true),
                points: vec![grpc_point_struct()],
                from_id: None,
                to_id: None,
                ordering: None,
                timeout: None,
            };
            let grpc_sync_points_internal = || api::grpc::qdrant::SyncPointsInternal {
                sync_points: Some(grpc_sync_points()),
                shard_id: Some(0),
                clock_tag: None,
                wait_override: None,
            };
            let points_internal_service =
                crate::tonic::api::points_internal_api::PointsInternalService::new(
                    toc.clone(),
                    settings.service.clone(),
                );
            let grpc_update_batch =
                |operation: api::grpc::qdrant::points_update_operation::Operation| {
                    api::grpc::qdrant::UpdateBatchPoints {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        operations: vec![api::grpc::qdrant::PointsUpdateOperation {
                            operation: Some(operation),
                        }],
                        ordering: None,
                        timeout: None,
                    }
                };

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([(
                            "embedding".to_string(),
                            api::rest::Vector::Dense(vec![0.1, 0.2]),
                        )])),
                        payload: None,
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains("CKKS vector encryption runtime")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
                    batch: api::rest::schema::Batch {
                        ids: vec![2.into()],
                        vectors: api::rest::schema::BatchVectorStruct::Named(HashMap::from([(
                            "embedding".to_string(),
                            vec![api::rest::Vector::Dense(vec![0.3, 0.4])],
                        )])),
                        payloads: None,
                    },
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains("CKKS vector encryption runtime")
            ));

            let err = do_update_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                UpdateVectors {
                    points: vec![api::rest::PointVectors {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([(
                            "embedding".to_string(),
                            api::rest::Vector::Dense(vec![0.1, 0.2]),
                        )])),
                    }],
                    shard_key: None,
                    update_filter: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains("CKKS vector encryption runtime")
            ));

            let err = do_delete_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                DeleteVectors {
                    points: Some(vec![1.into()]),
                    filter: None,
                    vector: std::iter::once("embedding".to_string()).collect(),
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_delete_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                DeleteVectors {
                    points: None,
                    filter: Some(Filter::new()),
                    vector: std::iter::once("embedding".to_string()).collect(),
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_delete_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                PointsSelector::PointIdsSelector(PointIdsList {
                    points: vec![1.into()],
                    shard_key: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_delete_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                PointsSelector::FilterSelector(FilterSelector {
                    filter: Filter::new(),
                    shard_key: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([(
                            "embedding".to_string(),
                            api::rest::Vector::Dense(vec![0.1, 0.2]),
                        )])),
                        payload: None,
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
                    batch: api::rest::schema::Batch {
                        ids: vec![3.into()],
                        vectors: api::rest::schema::BatchVectorStruct::Named(HashMap::from([(
                            "embedding".to_string(),
                            vec![api::rest::Vector::Dense(vec![0.7, 0.8])],
                        )])),
                        payloads: None,
                    },
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
            ));

            let err = do_update_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                UpdateVectors {
                    points: vec![api::rest::PointVectors {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([(
                            "embedding".to_string(),
                            api::rest::Vector::Dense(vec![0.1, 0.2]),
                        )])),
                    }],
                    shard_key: None,
                    update_filter: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                vec![UpdateOperation::UpdateVectors(UpdateVectorsOperation {
                    update_vectors: UpdateVectors {
                        points: vec![api::rest::PointVectors {
                            id: 1.into(),
                            vector: api::rest::VectorStruct::Named(HashMap::from([(
                                "embedding".to_string(),
                                api::rest::Vector::Dense(vec![0.1, 0.2]),
                            )])),
                        }],
                        shard_key: None,
                        update_filter: None,
                    },
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains("CKKS vector encryption runtime")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                vec![UpdateOperation::DeleteVectors(DeleteVectorsOperation {
                    delete_vectors: DeleteVectors {
                        points: Some(vec![1.into()]),
                        filter: None,
                        vector: std::iter::once("embedding".to_string()).collect(),
                        shard_key: None,
                    },
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                vec![UpdateOperation::Upsert(UpsertOperation {
                    upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                        points: vec![api::rest::PointStruct {
                            id: 2.into(),
                            vector: api::rest::VectorStruct::Named(HashMap::from([(
                                "embedding".to_string(),
                                api::rest::Vector::Dense(vec![0.5, 0.6]),
                            )])),
                            payload: None,
                        }],
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains("CKKS vector encryption runtime")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                vec![UpdateOperation::Delete(DeleteOperation {
                    delete: PointsSelector::FilterSelector(FilterSelector {
                        filter: Filter::new(),
                        shard_key: None,
                    }),
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "private_hnsw_docs".to_string(),
                vec![UpdateOperation::DeleteVectors(DeleteVectorsOperation {
                    delete_vectors: DeleteVectors {
                        points: None,
                        filter: Some(Filter::new()),
                        vector: std::iter::once("embedding".to_string()).collect(),
                        shard_key: None,
                    },
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
                        && description.contains("/private-hnsw/{vector}/session")
                        && !description.contains("embedding")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::upsert(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::UpsertPoints {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        points: vec![grpc_point_struct()],
                        ordering: None,
                        shard_key_selector: None,
                        update_filter: None,
                        timeout: None,
                        update_mode: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::update_vectors(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::UpdatePointVectors {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        points: vec![grpc_point_vectors()],
                        ordering: None,
                        shard_key_selector: None,
                        update_filter: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::delete_vectors(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePointVectors {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        points_selector: Some(grpc_points_selector()),
                        vectors: Some(grpc_vectors_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::delete_vectors(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePointVectors {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        points_selector: Some(grpc_filter_selector()),
                        vectors: Some(grpc_vectors_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::delete(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePoints {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        points: Some(grpc_points_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::delete(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DeletePoints {
                        collection_name: "private_hnsw_docs".to_string(),
                        wait: Some(true),
                        points: Some(grpc_filter_selector()),
                        ordering: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    InternalUpdateParams::default(),
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                api::grpc::qdrant::points_internal_server::PointsInternal::sync(
                    &points_internal_service,
                    tonic::Request::new(grpc_sync_points_internal()),
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                api::grpc::qdrant::points_internal_server::PointsInternal::update_batch(
                    &points_internal_service,
                    tonic::Request::new(api::grpc::qdrant::UpdateBatchInternal {
                        operations: vec![api::grpc::qdrant::UpdateOperation {
                            update: Some(api::grpc::qdrant::update_operation::Update::Sync(
                                grpc_sync_points_internal(),
                            )),
                        }],
                        wait_override: None,
                    }),
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::UpdateVectors(
                            api::grpc::qdrant::points_update_operation::UpdateVectors {
                                points: vec![grpc_point_vectors()],
                                shard_key_selector: None,
                                update_filter: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::Upsert(
                            api::grpc::qdrant::points_update_operation::PointStructList {
                                points: vec![grpc_point_struct()],
                                shard_key_selector: None,
                                update_filter: None,
                                update_mode: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::DeleteVectors(
                            api::grpc::qdrant::points_update_operation::DeleteVectors {
                                points_selector: Some(grpc_points_selector()),
                                vectors: Some(grpc_vectors_selector()),
                                shard_key_selector: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::DeletePoints(
                            api::grpc::qdrant::points_update_operation::DeletePoints {
                                points: Some(grpc_points_selector()),
                                shard_key_selector: None,
                            },
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_write_error(
                crate::tonic::api::update_common::update_batch(
                    &dispatcher,
                    grpc_update_batch(
                        api::grpc::qdrant::points_update_operation::Operation::DeleteDeprecated(
                            grpc_points_selector(),
                        ),
                    ),
                    InternalUpdateParams::default(),
                    auth.clone(),
                    InferenceParams::default(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );
        });
    }

    #[test]
    fn private_hnsw_oram_ordinary_reads_and_queries_require_session_api() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("private-hnsw-ordinary-read-guard")
            .tempdir()
            .unwrap();
        let storage_config = update_test_storage_config(storage_dir.path());
        let toc = update_test_toc(&storage_config);
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let collection_name = "private_hnsw_read_docs";
        let private_vector_name = "embedding";

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            collection_name.to_string(),
                            CreateCollection {
                                vectors: collection::operations::types::VectorsConfig::Multi(
                                    BTreeMap::from([(
                                        private_vector_name.to_string(),
                                        VectorParamsBuilder::new(2, Distance::Dot).build(),
                                    )]),
                                ),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a/vector-private-rk".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 7,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "embedding_private_hnsw".to_string(),
                                        selector: EncryptionSelector::VectorNames {
                                            names: vec![private_vector_name.to_string()],
                                        },
                                        instance: "docs_private_hnsw_v1".to_string(),
                                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: Some(Uuid::from_u128(0x4234567890abcdef1234567890abcdef)),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let assert_private_hnsw_read_error = |err: StorageError| {
                let message = err.to_string();
                assert!(
                    message.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
                    "{message}"
                );
                assert!(
                    message.contains("/private-hnsw/{vector}/session"),
                    "{message}"
                );
                assert!(!message.contains(private_vector_name), "{message}");
                assert!(!message.contains(collection_name), "{message}");
                assert!(!message.contains("runtime CKKS sidecar"), "{message}");
                assert!(!message.contains("payload sidecar only"), "{message}");
            };
            let assert_private_hnsw_grpc_read_error = |err: tonic::Status| {
                let message = err.message();
                assert!(
                    message.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
                    "{message}"
                );
                assert!(
                    message.contains("/private-hnsw/{vector}/session"),
                    "{message}"
                );
                assert!(!message.contains(private_vector_name), "{message}");
                assert!(!message.contains(collection_name), "{message}");
                assert!(!message.contains("runtime CKKS sidecar"), "{message}");
                assert!(!message.contains("payload sidecar only"), "{message}");
            };
            let request_hw_counter = || {
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                )
            };
            let rest_named_dense_vector = || {
                api::rest::NamedVectorStruct::Dense(segment::data_types::vectors::NamedVector {
                    name: private_vector_name.parse().unwrap(),
                    vector: vec![0.0, 0.0],
                })
            };
            let grpc_dense_vector = || api::grpc::qdrant::Vector {
                vector: Some(api::grpc::qdrant::vector::Vector::Dense(
                    api::grpc::qdrant::DenseVector {
                        data: vec![0.0, 0.0],
                    },
                )),
                ..Default::default()
            };
            let grpc_dense_input = || api::grpc::qdrant::VectorInput {
                variant: Some(api::grpc::qdrant::vector_input::Variant::Dense(
                    api::grpc::qdrant::DenseVector {
                        data: vec![0.0, 0.0],
                    },
                )),
            };
            let grpc_nearest_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Nearest(
                    grpc_dense_input(),
                )),
            };
            let grpc_context_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Context(
                    api::grpc::qdrant::ContextInput {
                        pairs: vec![api::grpc::qdrant::ContextInputPair {
                            positive: Some(grpc_dense_input()),
                            negative: Some(grpc_dense_input()),
                        }],
                    },
                )),
            };
            let grpc_fusion_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Fusion(
                    api::grpc::qdrant::Fusion::Rrf as i32,
                )),
            };

            let no_vector_records = crate::common::query::do_get_points(
                &toc,
                collection_name,
                PointRequestInternal {
                    ids: Vec::new(),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .expect("private HNSW ORAM retrieve without vectors must remain ordinary");
            assert!(no_vector_records.is_empty());

            let no_vector_scroll = crate::common::query::do_scroll_points(
                &toc,
                collection_name,
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .expect("private HNSW ORAM scroll without vectors must remain ordinary");
            assert!(no_vector_scroll.points.is_empty());

            let grpc_no_vector_records = crate::tonic::api::query_common::get(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::GetPoints {
                    collection_name: collection_name.to_string(),
                    ids: Vec::new(),
                    with_payload: None,
                    with_vectors: None,
                    read_consistency: None,
                    shard_key_selector: None,
                    timeout: None,
                },
                None,
                auth.clone(),
                request_hw_counter(),
                None,
            )
            .await
            .expect("private HNSW ORAM gRPC retrieve without vectors must remain ordinary")
            .into_inner();
            assert!(grpc_no_vector_records.result.is_empty());

            let grpc_no_vector_scroll = crate::tonic::api::query_common::scroll(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::ScrollPoints {
                    collection_name: collection_name.to_string(),
                    filter: None,
                    offset: None,
                    limit: Some(1),
                    with_payload: None,
                    with_vectors: None,
                    read_consistency: None,
                    shard_key_selector: None,
                    order_by: None,
                    timeout: None,
                },
                None,
                auth.clone(),
                request_hw_counter(),
                None,
            )
            .await
            .expect("private HNSW ORAM gRPC scroll without vectors must remain ordinary")
            .into_inner();
            assert!(grpc_no_vector_scroll.result.is_empty());

            assert_private_hnsw_read_error(
                crate::common::query::do_get_points(
                    &toc,
                    collection_name,
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: WithVector::Bool(true),
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_get_points(
                    &toc,
                    collection_name,
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: WithVector::Selector(vec![private_vector_name.to_string()]),
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_scroll_points(
                    &toc,
                    collection_name,
                    shard::scroll::ScrollRequestInternal {
                        offset: None,
                        limit: Some(1),
                        filter: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: WithVector::Bool(true),
                        order_by: None,
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::get(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::GetPoints {
                        collection_name: collection_name.to_string(),
                        ids: vec![segment::types::PointIdType::from(1).into()],
                        with_payload: None,
                        with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                            selector_options: Some(
                                api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                    api::grpc::qdrant::VectorsSelector {
                                        names: vec![private_vector_name.to_string()],
                                    },
                                ),
                            ),
                        }),
                        read_consistency: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::scroll(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::ScrollPoints {
                        collection_name: collection_name.to_string(),
                        filter: None,
                        offset: None,
                        limit: Some(1),
                        with_payload: None,
                        with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                            selector_options: Some(
                                api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                    api::grpc::qdrant::VectorsSelector {
                                        names: vec![private_vector_name.to_string()],
                                    },
                                ),
                            ),
                        }),
                        read_consistency: None,
                        shard_key_selector: None,
                        order_by: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_core_search_points(
                    &toc,
                    collection_name,
                    CoreSearchRequest {
                        query: QueryEnum::Nearest(NamedQuery::new(
                            VectorInternal::Dense(vec![0.0, 0.0]),
                            private_vector_name,
                        )),
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: 0,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_search_batch_points(
                    &toc,
                    collection_name,
                    vec![(
                        CoreSearchRequest {
                            query: QueryEnum::Nearest(NamedQuery::new(
                                VectorInternal::Dense(vec![0.0, 0.0]),
                                private_vector_name,
                            )),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: 0,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_search_batch_points_from_rest(
                    &toc,
                    collection_name,
                    vec![(
                        SearchRequestInternal {
                            vector: rest_named_dense_vector(),
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            score_threshold: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_search_point_groups(
                    &toc,
                    collection_name,
                    SearchGroupsRequestInternal {
                        vector: rest_named_dense_vector(),
                        filter: None,
                        params: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: None,
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::search(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPoints {
                        collection_name: collection_name.to_string(),
                        vector: vec![0.0, 0.0],
                        limit: 1,
                        vector_name: Some(private_vector_name.to_string()),
                        ..Default::default()
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: collection_name.to_string(),
                        vector: vec![0.0, 0.0],
                        filter: None,
                        limit: 1,
                        with_payload: None,
                        params: None,
                        score_threshold: None,
                        vector_name: Some(private_vector_name.to_string()),
                        with_vectors: None,
                        group_by: "group".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: None,
                        timeout: None,
                        shard_key_selector: None,
                        sparse_indices: None,
                        ckks_encrypted_query: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::search_batch_from_grpc(
                    UncheckedTocProvider::new_unchecked(&toc),
                    collection_name,
                    vec![(
                        api::rest::SearchRequestInternal::try_from(
                            api::grpc::qdrant::SearchPoints {
                                collection_name: collection_name.to_string(),
                                vector: vec![0.0, 0.0],
                                limit: 1,
                                vector_name: Some(private_vector_name.to_string()),
                                ..Default::default()
                            },
                        )
                        .unwrap(),
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_query_point_groups(
                    &toc,
                    collection_name,
                    CollectionQueryGroupsRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        ))),
                        using: private_vector_name.to_string(),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::query_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPointGroups {
                        collection_name: collection_name.to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(private_vector_name.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_payload: None,
                        with_vectors: None,
                        lookup_from: None,
                        limit: Some(1),
                        group_size: Some(1),
                        group_by: "group".to_string(),
                        read_consistency: None,
                        with_lookup: None,
                        timeout: None,
                        shard_key_selector: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_query_points(
                    &toc,
                    collection_name,
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        ))),
                        using: private_vector_name.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_query_points(
                    &toc,
                    collection_name,
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Context(
                            segment::vector_storage::query::ContextQuery::new(vec![
                                segment::vector_storage::query::ContextPair {
                                    positive: VectorInputInternal::Vector(VectorInternal::Dense(
                                        vec![0.0, 0.0],
                                    )),
                                    negative: VectorInputInternal::Vector(VectorInternal::Dense(
                                        vec![1.0, 0.0],
                                    )),
                                },
                            ]),
                        ))),
                        using: private_vector_name.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_query_points(
                    &toc,
                    collection_name,
                    CollectionQueryRequest {
                        prefetch: vec![CollectionPrefetch {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: private_vector_name.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        }],
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        ))),
                        using: private_vector_name.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_query_points(
                    &toc,
                    collection_name,
                    CollectionQueryRequest {
                        prefetch: vec![CollectionPrefetch {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: private_vector_name.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        }],
                        query: Some(Query::Fusion(FusionInternal::Rrf {
                            k: 2,
                            weights: None,
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
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_query_batch_points(
                    &toc,
                    collection_name,
                    vec![(
                        CollectionQueryRequest {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: private_vector_name.to_string(),
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
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::query_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    collection_name,
                    vec![api::grpc::qdrant::QueryPoints {
                        collection_name: collection_name.to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_context_query()),
                        using: Some(private_vector_name.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::query_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    collection_name,
                    vec![api::grpc::qdrant::QueryPoints {
                        collection_name: collection_name.to_string(),
                        prefetch: vec![api::grpc::qdrant::PrefetchQuery {
                            prefetch: Vec::new(),
                            query: Some(grpc_nearest_query()),
                            using: Some(private_vector_name.to_string()),
                            filter: None,
                            params: None,
                            score_threshold: None,
                            limit: Some(1),
                            lookup_from: None,
                        }],
                        query: Some(grpc_fusion_query()),
                        using: None,
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::query_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    collection_name,
                    vec![api::grpc::qdrant::QueryPoints {
                        collection_name: collection_name.to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(private_vector_name.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_recommend_points(
                    &toc,
                    collection_name,
                    RecommendRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        using: Some(collection::operations::types::UsingVector::Name(
                            private_vector_name.to_string(),
                        )),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_recommend_batch_points(
                    &toc,
                    collection_name,
                    vec![(
                        RecommendRequestInternal {
                            positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                            negative: Vec::new(),
                            strategy: Some(api::rest::RecommendStrategy::AverageVector),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                            using: Some(collection::operations::types::UsingVector::Name(
                                private_vector_name.to_string(),
                            )),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::recommend(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::RecommendPoints {
                        collection_name: collection_name.to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: None,
                        params: None,
                        score_threshold: None,
                        offset: None,
                        using: Some(private_vector_name.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::recommend_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    collection_name,
                    vec![api::grpc::qdrant::RecommendPoints {
                        collection_name: collection_name.to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: None,
                        params: None,
                        score_threshold: None,
                        offset: None,
                        using: Some(private_vector_name.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_recommend_point_groups(
                    &toc,
                    collection_name,
                    RecommendGroupsRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        using: Some(collection::operations::types::UsingVector::Name(
                            private_vector_name.to_string(),
                        )),
                        lookup_from: None,
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: None,
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::recommend_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::RecommendPointGroups {
                        collection_name: collection_name.to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: None,
                        params: None,
                        score_threshold: None,
                        using: Some(private_vector_name.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        group_by: "group".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: None,
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_discover_points(
                    &toc,
                    collection_name,
                    DiscoverRequestInternal {
                        target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                        context: None,
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        using: Some(collection::operations::types::UsingVector::Name(
                            private_vector_name.to_string(),
                        )),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_discover_batch_points(
                    &toc,
                    collection_name,
                    vec![(
                        DiscoverRequestInternal {
                            target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                            context: None,
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            using: Some(collection::operations::types::UsingVector::Name(
                                private_vector_name.to_string(),
                            )),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::discover(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DiscoverPoints {
                        collection_name: collection_name.to_string(),
                        target: Some(api::grpc::qdrant::TargetVector {
                            target: Some(api::grpc::qdrant::target_vector::Target::Single(
                                api::grpc::qdrant::VectorExample {
                                    example: Some(
                                        api::grpc::qdrant::vector_example::Example::Vector(
                                            grpc_dense_vector(),
                                        ),
                                    ),
                                },
                            )),
                        }),
                        context: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: None,
                        params: None,
                        offset: None,
                        using: Some(private_vector_name.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::discover_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    collection_name,
                    vec![api::grpc::qdrant::DiscoverPoints {
                        collection_name: collection_name.to_string(),
                        target: Some(api::grpc::qdrant::TargetVector {
                            target: Some(api::grpc::qdrant::target_vector::Target::Single(
                                api::grpc::qdrant::VectorExample {
                                    example: Some(
                                        api::grpc::qdrant::vector_example::Example::Vector(
                                            grpc_dense_vector(),
                                        ),
                                    ),
                                },
                            )),
                        }),
                        context: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: None,
                        params: None,
                        offset: None,
                        using: Some(private_vector_name.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        timeout: None,
                        shard_key_selector: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_grpc_read_error(
                crate::tonic::api::query_common::search_points_matrix(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchMatrixPoints {
                        collection_name: collection_name.to_string(),
                        filter: None,
                        sample: Some(2),
                        limit: Some(1),
                        using: Some(private_vector_name.to_string()),
                        read_consistency: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );

            assert_private_hnsw_read_error(
                crate::common::query::do_search_points_matrix(
                    &toc,
                    collection_name,
                    collection::collection::distance_matrix::CollectionSearchMatrixRequest {
                        filter: None,
                        sample_size: 2,
                        limit_per_sample: 1,
                        using: private_vector_name.to_string(),
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .unwrap_err(),
            );
        });
    }

    #[test]
    fn encrypted_vector_update_rejects_multi_point_sidecar_fanout() {
        let err = ensure_encrypted_vector_update_sidecar_fanout_is_atomic("docs", 2)
            .expect_err("multi-point encrypted vector sidecar fanout must be rejected");

        assert!(matches!(
            err,
                StorageError::BadInput { description }
                if description.contains("cannot update encrypted vectors for multiple points")
                    && description.contains("atomic encrypted vector sidecar fanout")
                    && !description.contains("docs")
        ));

        ensure_encrypted_vector_update_sidecar_fanout_is_atomic("docs", 1).unwrap();
        ensure_encrypted_vector_update_sidecar_fanout_is_atomic("docs", 0).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_moves_dense_vector_into_encrypted_sidecar() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let mut vector = VectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            VectorPersisted::Dense(vec![0.125, -42.5]),
        )]));
        let mut payload = None;

        let encrypted =
            encrypt_vectors_for_point(&plan, "docs", "point-1", &mut vector, &mut payload).unwrap();

        assert_eq!(encrypted.len(), 1);
        assert!(matches!(vector, VectorStructPersisted::Named(ref vectors) if vectors.is_empty()));
        let payload = payload.unwrap();
        let sidecar = payload
            .0
            .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            .and_then(Value::as_object)
            .unwrap();
        let encrypted_embedding = sidecar.get("embedding").unwrap();
        assert!(is_encrypted_ckks_vector_payload_value(encrypted_embedding));
        assert!(
            encrypted_embedding
                .get(ENCRYPTED_CKKS_VECTOR_MARKER)
                .is_some()
        );
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(!serialized.contains("0.125"));
        assert!(!serialized.contains("-42.5"));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_rejects_plaintext_query_without_opt_in() {
        let bridge = fake_openfhe_bridge();
        let mut settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        settings
            .crypto
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove("allow_plaintext_queries");
        settings
            .crypto
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove("plaintext_query_tcb_ack");
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();

        let err = plan
            .score_encrypted_query_batch("docs", "embedding", &[], &[0.125, -42.5])
            .expect_err("raw dense CKKS query must require explicit plaintext-query opt-in");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("does not allow plaintext query vectors")
                    && description.contains("client-encrypted CKKS query")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_preflights_client_encrypted_query_metadata() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let mut query = fake_ckks_client_query(b"fake-ckks-query:2", 2);
        query.vector_name = "embedding".to_string();
        query.signature_b64 = BASE64URL_NOPAD.encode(
            fake_ckks_query_signing_key_pair()
                .sign(&crate::common::crypto::ckks_client_query_signature_message(
                    &query.collection_id,
                    &query.vector_name,
                    &query.key_id,
                    &query.rk_id,
                    query.rk_epoch,
                    &query.query_nonce,
                    &query.context_digest,
                    query.slots,
                    b"fake-ckks-query:2",
                    &query.signature_alg,
                    &query.signature_key_id,
                ))
                .as_ref(),
        );

        plan.validate_client_encrypted_query(
            "docs",
            "embedding",
            &query.collection_id,
            &query.vector_name,
            &query.key_id,
            &query.rk_id,
            query.rk_epoch,
            &query.query_nonce,
            &query.context_digest,
            query.slots,
            b"fake-ckks-query:2",
            &query.signature_alg,
            &query.signature_key_id,
            &query.signature_b64,
        )
        .unwrap()
        .unwrap();

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                "tenant-a:unknown-query-signing-key",
                &query.signature_b64,
            )
            .expect_err("client encrypted query must use a trusted signature key");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("signature key_id is not trusted")
        ));

        let bad_signature = BASE64URL_NOPAD.encode(&[5_u8; 64]);
        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &bad_signature,
            )
            .expect_err("client encrypted query must verify the Ed25519 signature");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("signature verification failed")
        ));

        let tampered_nonce = BASE64URL_NOPAD.encode(&[8_u8; 12]);
        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &tampered_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("client encrypted query signature must bind query nonce");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("signature verification failed")
        ));

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                "other-collection",
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("client encrypted query must bind to collection crypto identity");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("collection_id does not match")
        ));

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                "other-vector",
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("client encrypted query must bind to vector name");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("vector_name does not match")
        ));

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                "other-key",
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("client encrypted query must bind to active key id");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("key_id does not match")
        ));

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                "other-rk",
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("client encrypted query must bind to active RK id");
        assert!(matches!(
            err,
            StorageError::BadInput { description } if description.contains("rk_id does not match")
        ));

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch + 1,
                &query.query_nonce,
                &query.context_digest,
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("client encrypted query must bind to active RK epoch");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("rk_epoch does not match")
        ));

        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &BASE64URL_NOPAD.encode(&[9u8; 32]),
                query.slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("wrong client encrypted query context must fail before scoring");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("context digest does not match")
        ));

        let too_many_slots =
            qdrant_sec::CkksParameters::openfhe_default_128_bit().batch_size as usize + 1;
        let err = plan
            .validate_client_encrypted_query(
                "docs",
                "embedding",
                &query.collection_id,
                &query.vector_name,
                &query.key_id,
                &query.rk_id,
                query.rk_epoch,
                &query.query_nonce,
                &query.context_digest,
                too_many_slots,
                b"fake-ckks-query:2",
                &query.signature_alg,
                &query.signature_key_id,
                &query.signature_b64,
            )
            .expect_err("oversized client encrypted query slot count must fail before scoring");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("client CKKS query is incompatible with active CKKS parameters")
                    && !description.contains("batch size")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_rejects_sparse_encrypted_vector() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let mut vector = VectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            VectorPersisted::empty_sparse(),
        )]));
        let mut payload = None;

        let err = encrypt_vectors_for_point(&plan, "docs", "point-1", &mut vector, &mut payload)
            .unwrap_err();

        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("only supports dense vectors")
                    && !description.contains("embedding")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_rejects_reserved_sidecar_collision() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let mut vector = VectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            VectorPersisted::Dense(vec![0.125, -42.5]),
        )]));
        let mut payload = Some(segment::types::Payload(
            json!({ ENCRYPTED_VECTOR_SIDECAR_FIELD: "client-controlled sidecar" })
                .as_object()
                .unwrap()
                .clone(),
        ));

        let err = encrypt_vectors_for_point(&plan, "docs", "point-1", &mut vector, &mut payload)
            .unwrap_err();

        assert!(matches!(
            err,
            StorageError::BadInput { ref description }
                if description.contains("reserved encrypted vector sidecar field")
                    && description.contains("already set to a non-object value")
                    && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        ));
    }

    #[test]
    fn vector_write_plan_verifies_client_ckks_vector_sidecar() {
        let signing_key = fake_ckks_query_signing_key_pair();
        let settings = client_vector_runtime_settings(&signing_key);
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let payload = segment::types::Payload(
            json!({
                ENCRYPTED_VECTOR_SIDECAR_FIELD: {
                    "embedding": signed_client_ckks_vector_sidecar(&signing_key),
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        let verified =
            verify_client_vector_sidecars_for_point(&plan, "docs", "point-1", Some(&payload))
                .unwrap();

        assert_eq!(verified.len(), 1);
        let provenance = CollectionUpdateProvenance::runtime_verified_client_vectors(verified);
        let sidecar_value = payload.0[ENCRYPTED_VECTOR_SIDECAR_FIELD]
            .as_object()
            .unwrap()
            .get("embedding")
            .unwrap();
        let sidecar_key =
            qdrant_sec::client_ckks_vector_sidecar_envelope_key(sidecar_value, "embedding")
                .unwrap()
                .unwrap();
        assert!(
            provenance
                .verified_client_vector_sidecar_key_for_binding(
                    &sidecar_key,
                    TEST_VECTOR_COLLECTION_CRYPTO_ID,
                    "point-1",
                    "embedding",
                )
                .is_some()
        );

        let collection_sentinel = "client-ckks-sidecar-secret-collection";
        let point_sentinel = "client-ckks-sidecar-secret-point";
        let vector_sentinel = "client_ckks_sidecar_secret_unconfigured_vector";
        let mut sidecar = serde_json::Map::new();
        sidecar.insert(
            vector_sentinel.to_string(),
            signed_client_ckks_vector_sidecar(&signing_key),
        );
        let payload = segment::types::Payload(
            json!({
                ENCRYPTED_VECTOR_SIDECAR_FIELD: Value::Object(sidecar),
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let err = verify_client_vector_sidecars_for_point(
            &plan,
            collection_sentinel,
            point_sentinel,
            Some(&payload),
        )
        .expect_err("unconfigured client CKKS vector sidecar must fail closed");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("server-blind encrypted vector")
                    && !description.contains(collection_sentinel)
                    && !description.contains(point_sentinel)
                    && !description.contains(vector_sentinel)
        ));
    }

    #[test]
    fn vector_write_plan_rejects_server_blind_client_vector_scoring() {
        let signing_key = fake_ckks_query_signing_key_pair();
        let settings = client_vector_runtime_settings(&signing_key);
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();

        let plaintext_score_err = plan
            .score_encrypted_query_batch("docs", "embedding", &[], &[0.1, 0.2])
            .unwrap_err();
        assert!(matches!(
            plaintext_score_err,
            StorageError::BadInput { description }
                if description.contains("server-blind client CKKS envelopes")
                    && description.contains("cannot be scored by Qdrant")
        ));

        let encrypted_query_err = plan
            .score_client_encrypted_query_batch(
                "docs",
                "embedding",
                &[],
                TEST_VECTOR_COLLECTION_CRYPTO_ID,
                "embedding",
                "tenant-a:vector",
                "tenant-a/client-vector-rk",
                3,
                "AAAAAAAAAAAAAAAA",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                2,
                b"encrypted-query",
                "ed25519",
                "tenant-a:vector-signing-v1",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .unwrap_err();
        assert!(matches!(
            encrypted_query_err,
            StorageError::BadInput { description }
                if description.contains("server-blind client CKKS envelopes")
                    && description.contains("cannot be scored by Qdrant")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_moves_batch_vectors_into_encrypted_sidecars() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let ids = vec![1.into(), 2.into()];
        let mut vectors = BatchVectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            vec![
                VectorPersisted::Dense(vec![0.125, -42.5]),
                VectorPersisted::Dense(vec![0.25, -84.0]),
            ],
        )]));
        let mut payloads = None;

        let encrypted =
            encrypt_vectors_for_batch(&plan, "docs", &ids, &mut vectors, &mut payloads).unwrap();

        assert_eq!(encrypted.len(), 2);
        assert!(
            matches!(vectors, BatchVectorStructPersisted::Named(ref vectors) if vectors.is_empty())
        );
        let payloads = payloads.unwrap();
        assert_eq!(payloads.len(), 2);
        for payload in payloads {
            let payload = payload.unwrap();
            let sidecar = payload
                .0
                .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
                .and_then(Value::as_object)
                .unwrap();
            assert!(is_encrypted_ckks_vector_payload_value(
                sidecar.get("embedding").unwrap()
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_rejects_batch_vector_count_mismatch() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let ids = vec![1.into(), 2.into()];
        let mut vectors = BatchVectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            vec![VectorPersisted::Dense(vec![0.125, -42.5])],
        )]));
        let mut payloads = None;

        let err = encrypt_vectors_for_batch(&plan, "docs", &ids, &mut vectors, &mut payloads)
            .unwrap_err();

        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("batch vector count for encrypted vector")
                    && !description.contains("embedding")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_keeps_point_input_on_encryption_failure() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let too_wide =
            vec![
                1.0;
                qdrant_sec::CkksParameters::openfhe_default_128_bit().batch_size as usize + 1
            ];
        let mut vector = VectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            VectorPersisted::Dense(too_wide.clone()),
        )]));
        let original_payload = Some(segment::types::Payload(
            json!({ "public": "keep" }).as_object().unwrap().clone(),
        ));
        let mut payload = original_payload.clone();

        let err = encrypt_vectors_for_point(&plan, "docs", "point-1", &mut vector, &mut payload)
            .expect_err("oversized vector encryption must fail");

        assert!(matches!(
            err,
            StorageError::ServiceError { description, .. }
                if description.contains("CKKS vector encryption failed")
        ));
        assert!(matches!(vector, VectorStructPersisted::Named(ref vectors)
                if matches!(vectors.get("embedding"), Some(VectorPersisted::Dense(values)) if values == &too_wide)));
        assert_eq!(payload, original_payload);
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_keeps_batch_input_on_partial_encryption_failure() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            TEST_VECTOR_COLLECTION_CRYPTO_ID,
            &params,
        )
        .unwrap()
        .unwrap();
        let ids = vec![1.into(), 2.into()];
        let valid = vec![0.125, -42.5];
        let too_wide =
            vec![
                1.0;
                qdrant_sec::CkksParameters::openfhe_default_128_bit().batch_size as usize + 1
            ];
        let mut vectors = BatchVectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            vec![
                VectorPersisted::Dense(valid.clone()),
                VectorPersisted::Dense(too_wide.clone()),
            ],
        )]));
        let original_payloads = Some(vec![
            Some(segment::types::Payload(
                json!({ "public": "keep" }).as_object().unwrap().clone(),
            )),
            None,
        ]);
        let mut payloads = original_payloads.clone();

        let err = encrypt_vectors_for_batch(&plan, "docs", &ids, &mut vectors, &mut payloads)
            .expect_err("second oversized vector must fail the whole batch transform");

        assert!(matches!(
            err,
            StorageError::ServiceError { description, .. }
                if description.contains("CKKS vector encryption failed")
        ));
        assert!(
            matches!(vectors, BatchVectorStructPersisted::Named(ref named)
                if matches!(named.get("embedding"), Some(values)
                    if matches!(&values[..], [VectorPersisted::Dense(first), VectorPersisted::Dense(second)]
                        if first == &valid && second == &too_wide)))
        );
        assert_eq!(payloads, original_payloads);
    }

    #[cfg(unix)]
    #[test]
    fn combined_payload_and_vector_write_provenance_keeps_both_proofs() {
        let bridge = fake_openfhe_bridge();
        let vector_settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let mut settings = payload_runtime_settings();
        settings
            .crypto
            .instances
            .extend(vector_settings.crypto.instances.clone());
        settings
            .crypto
            .materials
            .extend(vector_settings.crypto.materials.clone());
        settings
            .crypto
            .backends
            .extend(vector_settings.crypto.backends.clone());
        let params = CollectionParams {
            vectors: collection::operations::types::VectorsConfig::Multi(BTreeMap::from([
                (
                    DEFAULT_VECTOR_NAME.to_string(),
                    VectorParamsBuilder::new(2, Distance::Dot).build(),
                ),
                (
                    "plain".to_string(),
                    VectorParamsBuilder::new(2, Distance::Dot).build(),
                ),
            ])),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: None,
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "body_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    },
                    EncryptionRuleRef {
                        id: "vector_conf".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                        },
                        instance: "docs_vector_v1".to_string(),
                        binding: Some(VECTOR_ENVELOPE_BINDING.to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };
        let payload_plan = payload_write_plan_for_collection_with_crypto_id(
            &settings,
            "mixed_docs",
            "mixed-crypto-id",
            &params,
        )
        .unwrap()
        .unwrap();
        let vector_plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "mixed_docs",
            "mixed-crypto-id",
            &params,
        )
        .unwrap()
        .unwrap();
        let mut payload = Some(segment::types::Payload(
            json!({ "body": "mixed secret body", "group": "mixed" })
                .as_object()
                .unwrap()
                .clone(),
        ));
        let mut seen_client_nonces = std::collections::HashSet::new();
        let payload_outcome = payload_plan
            .process_payload_with_replay_cache(
                "1",
                payload.as_mut().unwrap(),
                &mut seen_client_nonces,
            )
            .unwrap();
        assert_eq!(payload_outcome.changed, 1);

        let mut vector = VectorStructPersisted::Named(HashMap::from([
            (
                DEFAULT_VECTOR_NAME.to_string(),
                VectorPersisted::Dense(vec![0.9, -0.125]),
            ),
            ("plain".to_string(), VectorPersisted::Dense(vec![0.2, 0.8])),
        ]));
        let vector_sidecar_keys =
            encrypt_vectors_for_point(&vector_plan, "mixed_docs", "1", &mut vector, &mut payload)
                .unwrap();
        assert_eq!(vector_sidecar_keys.len(), 1);
        assert!(matches!(vector, VectorStructPersisted::Named(ref vectors)
                if !vectors.contains_key(DEFAULT_VECTOR_NAME) && vectors.contains_key("plain")));

        let mut provenance = payload_update_provenance(
            payload_plan.has_server_encrypt_rules(),
            payload_outcome.verified_server_envelope_keys,
            payload_outcome.verified_client_envelope_keys,
        );
        let vector_provenance =
            CollectionUpdateProvenance::runtime_encrypted_vectors(vector_sidecar_keys);
        provenance = provenance.with_runtime_encrypted_vector_provenance(vector_provenance);

        let payload = payload.unwrap();
        let body = payload.0.get("body").unwrap();
        assert!(is_encrypted_payload_value(body));
        let body_key = server_payload_envelope_key(body, "mixed-crypto-id", "1", "body")
            .unwrap()
            .unwrap();
        assert!(
            provenance
                .verified_server_envelope_key_for_binding(
                    &body_key,
                    "mixed-crypto-id",
                    "1",
                    "body",
                )
                .is_some()
        );

        let encrypted_vector = payload
            .0
            .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            .and_then(Value::as_object)
            .and_then(|sidecar| sidecar.get(DEFAULT_VECTOR_NAME))
            .unwrap();
        assert!(is_encrypted_ckks_vector_payload_value(encrypted_vector));
        let sidecar_key = ckks_vector_sidecar_envelope_key(
            encrypted_vector,
            "mixed-crypto-id",
            "1",
            DEFAULT_VECTOR_NAME,
        )
        .unwrap()
        .unwrap();
        assert!(
            provenance
                .verified_vector_sidecar_key_for_binding(
                    &sidecar_key,
                    "mixed-crypto-id",
                    "1",
                    DEFAULT_VECTOR_NAME,
                )
                .is_some()
        );

        let serialized_payload = serde_json::to_string(&payload).unwrap();
        assert!(!serialized_payload.contains("mixed secret body"));
        assert!(!serialized_payload.contains("0.9"));
        assert!(!serialized_payload.contains("-0.125"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_vector_search_groups_uses_sidecar_scores() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new().prefix("vector-groups").tempdir().unwrap();
        let storage_config = StorageConfig {
            storage_path: storage_dir.path().to_path_buf(),
            snapshots_path: storage_dir.path().join("snapshots"),
            snapshots_config: Default::default(),
            temp_path: None,
            on_disk_payload: false,
            optimizers: OptimizersConfig {
                deleted_threshold: 0.5,
                vacuum_min_vector_number: 100,
                default_segment_number: 1,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: Some(100),
                indexing_threshold: Some(100),
                flush_interval_sec: 2,
                max_optimization_threads: Some(1),
                prevent_unoptimized: None,
            },
            optimizers_overwrite: None,
            wal: Default::default(),
            performance: PerformanceConfig {
                max_search_threads: 1,
                max_optimization_runtime_threads: 1,
                optimizer_cpu_budget: 0,
                optimizer_io_budget: 0,
                update_rate_limit: None,
                search_timeout_sec: None,
                incoming_shard_transfers_limit: Some(1),
                outgoing_shard_transfers_limit: Some(1),
                async_scorer: None,
                load_concurrency: LoadConcurrencyConfig::default(),
            },
            hnsw_index: Default::default(),
            hnsw_global_config: Default::default(),
            mmap_advice: mmap::Advice::Random,
            node_type: Default::default(),
            update_queue_size: Default::default(),
            handle_collection_load_errors: false,
            recovery_mode: None,
            update_concurrency: Some(NonZeroUsize::new(1).unwrap()),
            shard_transfer_method: None,
            collection: None,
            max_collections: None,
        };
        let toc = Arc::new(
            TableOfContent::new(
                &storage_config,
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                ResourceBudget::default(),
                ChannelService::new(6333, false, None, None),
                0,
                None,
            )
            .unwrap(),
        );
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "vector_groups".to_string(),
                            CreateCollection {
                                vectors: collection::operations::types::VectorsConfig::Multi(
                                    BTreeMap::from([
                                        (
                                            DEFAULT_VECTOR_NAME.to_string(),
                                            VectorParamsBuilder::new(2, Distance::Dot).build(),
                                        ),
                                        (
                                            "plain".to_string(),
                                            VectorParamsBuilder::new(2, Distance::Dot).build(),
                                        ),
                                    ]),
                                ),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a:vector".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 0,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "vector_conf".to_string(),
                                        selector: EncryptionSelector::VectorNames {
                                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                        },
                                        instance: "docs_vector_v1".to_string(),
                                        binding: Some("vector-envelope/v1".to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let bridge = fake_openfhe_bridge();
            let vector_settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "vector_small_better".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Euclid)
                                    .build()
                                    .into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a:vector".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 0,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "vector_conf".to_string(),
                                        selector: EncryptionSelector::VectorNames {
                                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                        },
                                        instance: "docs_vector_v1".to_string(),
                                        binding: Some("vector-envelope/v1".to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "vector_group_lookup".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: None,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_group_lookup".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![
                        api::rest::PointStruct {
                            id: 1.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.0, 0.0]),
                            payload: Some(segment::types::Payload(
                                json!({ "label": "lookup-a" }).as_object().unwrap().clone(),
                            )),
                        },
                        api::rest::PointStruct {
                            id: 2.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.0, 0.0]),
                            payload: Some(segment::types::Payload(
                                json!({ "label": "lookup-b" }).as_object().unwrap().clone(),
                            )),
                        },
                    ],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap();

            let small_better_recommend_err = crate::common::query::do_query_points(
                &toc,
                "vector_small_better",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendBestScore(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 0.0,
                            ]))],
                            Vec::new(),
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                small_better_recommend_err,
                StorageError::BadInput { ref description }
                    if description.contains("large-better metric")
                        && !description.contains("encrypted vector '")
            ));

            let small_better_discover_err = crate::common::query::do_query_points(
                &toc,
                "vector_small_better",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Discover(
                        segment::vector_storage::query::DiscoverQuery::new(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            Vec::new(),
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                small_better_discover_err,
                StorageError::BadInput { ref description }
                    if description.contains("large-better metric")
                        && !description.contains("encrypted vector '")
            ));

            let small_better_context_err = crate::common::query::do_query_points(
                &toc,
                "vector_small_better",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Context(
                        segment::vector_storage::query::ContextQuery::new(vec![
                            segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    1.0, 1.0,
                                ])),
                            },
                        ]),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                small_better_context_err,
                StorageError::BadInput { ref description }
                    if description.contains("large-better metric")
                        && !description.contains("encrypted vector '")
            ));

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_groups".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![
                        api::rest::PointStruct {
                            id: 1.into(),
                            vector: api::rest::VectorStruct::Named(HashMap::from([
                                (
                                    DEFAULT_VECTOR_NAME.to_string(),
                                    api::rest::Vector::Dense(vec![0.7, -0.25]),
                                ),
                                (
                                    "plain".to_string(),
                                    api::rest::Vector::Dense(vec![0.3, 0.4]),
                                ),
                            ])),
                            payload: Some(segment::types::Payload(
                                json!({ "group": "a", "group_id": 1 })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        },
                        api::rest::PointStruct {
                            id: 2.into(),
                            vector: api::rest::VectorStruct::Named(HashMap::from([
                                (
                                    DEFAULT_VECTOR_NAME.to_string(),
                                    api::rest::Vector::Dense(vec![0.1, 0.2]),
                                ),
                                (
                                    "plain".to_string(),
                                    api::rest::Vector::Dense(vec![0.5, 0.6]),
                                ),
                            ])),
                            payload: Some(segment::types::Payload(
                                json!({ "group": "b", "group_id": 2 })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        },
                    ],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();

            let groups = crate::common::query::do_search_point_groups(
                &toc,
                "vector_groups",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();

            assert_eq!(groups.groups.len(), 2);
            assert_eq!(groups.groups[0].id, GroupId::from("a"));
            assert_eq!(groups.groups[0].hits[0].id, 1.into());
            assert_eq!(groups.groups[0].hits[0].score, 9.0);
            assert!(groups.groups[0].hits[0].payload.is_none());
            assert!(groups.groups[0].hits[0].vector.is_none());
            assert_eq!(groups.groups[1].id, GroupId::from("b"));
            assert_eq!(groups.groups[1].hits[0].id, 2.into());
            assert_eq!(groups.groups[1].hits[0].score, 4.0);

            let groups_with_lookup = crate::common::query::do_search_point_groups(
                &toc,
                "vector_groups",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group_id".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: Some(api::rest::WithLookupInterface::Collection(
                            "vector_group_lookup".to_string(),
                        )),
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(groups_with_lookup.groups.len(), 2);
            assert_eq!(groups_with_lookup.groups[0].id, GroupId::from(1_u64));
            assert_eq!(
                groups_with_lookup.groups[0]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.payload.as_ref())
                    .and_then(|payload| payload.0.get("label"))
                    .and_then(Value::as_str),
                Some("lookup-a")
            );
            assert_eq!(groups_with_lookup.groups[1].id, GroupId::from(2_u64));
            assert_eq!(
                groups_with_lookup.groups[1]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.payload.as_ref())
                    .and_then(|payload| payload.0.get("label"))
                    .and_then(Value::as_str),
                Some("lookup-b")
            );

            let groups_with_plain_lookup_vector = crate::common::query::do_search_point_groups(
                &toc,
                "vector_groups",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group_id".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: Some(api::rest::WithLookupInterface::WithLookup(
                            api::rest::WithLookup {
                                collection_name: "vector_group_lookup".to_string(),
                                with_payload: Some(WithPayloadInterface::Bool(false)),
                                with_vectors: Some(WithVector::Bool(true)),
                            },
                        )),
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(groups_with_plain_lookup_vector.groups.len(), 2);
            assert!(
                groups_with_plain_lookup_vector.groups[0]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.vector.as_ref())
                    .is_some()
            );
            assert!(
                groups_with_plain_lookup_vector.groups[1]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.vector.as_ref())
                    .is_some()
            );

            let encrypted_lookup_vector_err = crate::common::query::do_search_point_groups(
                &toc,
                "vector_groups",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group_id".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: Some(api::rest::WithLookupInterface::WithLookup(
                            api::rest::WithLookup {
                                collection_name: "vector_groups".to_string(),
                                with_payload: Some(WithPayloadInterface::Bool(true)),
                                with_vectors: Some(WithVector::Selector(vec![
                                    DEFAULT_VECTOR_NAME.to_string(),
                                ])),
                            },
                        )),
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                encrypted_lookup_vector_err,
                StorageError::BadInput { description }
                    if description.contains("cannot group lookup encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let query_groups_with_lookup = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group_id".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: Some(api::rest::WithLookupInterface::Collection(
                        "vector_group_lookup".to_string(),
                    ).into()),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(query_groups_with_lookup.groups.len(), 2);
            assert_eq!(
                query_groups_with_lookup.groups[0].id,
                GroupId::from(1_u64)
            );
            assert_eq!(
                query_groups_with_lookup.groups[0]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.payload.as_ref())
                    .and_then(|payload| payload.0.get("label"))
                    .and_then(Value::as_str),
                Some("lookup-a")
            );
            assert_eq!(
                query_groups_with_lookup.groups[1].id,
                GroupId::from(2_u64)
            );
            assert_eq!(
                query_groups_with_lookup.groups[1]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.payload.as_ref())
                    .and_then(|payload| payload.0.get("label"))
                    .and_then(Value::as_str),
                Some("lookup-b")
            );

            let query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();

            assert_eq!(query_groups.groups.len(), 2);
            assert_eq!(query_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(query_groups.groups[0].hits[0].id, 1.into());
            assert_eq!(query_groups.groups[1].id, GroupId::from("b"));
            assert_eq!(query_groups.groups[1].hits[0].id, 2.into());

            let fusion_query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: vec![
                        CollectionPrefetch {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 2,
                            params: None,
                            lookup_from: None,
                        },
                        CollectionPrefetch {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                            ))),
                            using: "plain".to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        },
                    ],
                    query: Some(Query::Fusion(FusionInternal::Rrf {
                        k: 2,
                        weights: None,
                    })),
                    using: String::new(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(fusion_query_groups.groups.len(), 2);
            assert_eq!(fusion_query_groups.groups[0].id, GroupId::from("b"));
            assert_eq!(fusion_query_groups.groups[0].hits[0].id, 2.into());
            assert_eq!(fusion_query_groups.groups[1].id, GroupId::from("a"));
            assert_eq!(fusion_query_groups.groups[1].hits[0].id, 1.into());

            let prefetched_query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(prefetched_query_groups.groups.len(), 1);
            assert_eq!(prefetched_query_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(prefetched_query_groups.groups[0].hits[0].id, 1.into());
            assert_eq!(prefetched_query_groups.groups[0].hits[0].score, 9.0);

            let mmr_query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::NearestWithMmr(NearestWithMmr {
                        nearest: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        mmr: Mmr {
                            diversity: Some(0.5),
                            candidates_limit: Some(2),
                        },
                    }))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mmr_query_groups.groups.len(), 2);
            assert_eq!(mmr_query_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(mmr_query_groups.groups[0].hits[0].score, 9.0);
            assert_eq!(mmr_query_groups.groups[1].id, GroupId::from("b"));
            assert_eq!(mmr_query_groups.groups[1].hits[0].score, 4.0);

            let query_best_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendBestScore(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 0.0,
                            ]))],
                            Vec::new(),
                        ),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(query_best_groups.groups.len(), 2);
            assert_eq!(query_best_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(query_best_groups.groups[0].hits[0].id, 1.into());
            assert_eq!(query_best_groups.groups[1].id, GroupId::from("b"));
            assert_eq!(query_best_groups.groups[1].hits[0].id, 2.into());

            let point_id_average_query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendAverageVector(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![
                                VectorInputInternal::Id(1.into()),
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ],
                            Vec::new(),
                        ),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_average_query_groups.groups.len(), 2);
            assert_eq!(
                point_id_average_query_groups.groups[0].id,
                GroupId::from("a")
            );
            assert_eq!(
                point_id_average_query_groups.groups[0].hits[0].score,
                9.5
            );
            assert_eq!(
                point_id_average_query_groups.groups[1].id,
                GroupId::from("b")
            );
            assert_eq!(
                point_id_average_query_groups.groups[1].hits[0].score,
                6.0
            );

            let recommend_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendAverageVector(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 0.0,
                            ]))],
                            Vec::new(),
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_query[0].id, 1.into());
            assert_eq!(recommend_query[0].score, 9.0);

            let point_id_average_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendAverageVector(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![
                                VectorInputInternal::Id(1.into()),
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ],
                            Vec::new(),
                        ),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 2,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_average_query.len(), 2);
            assert_eq!(point_id_average_query[0].id, 1.into());
            assert_eq!(point_id_average_query[0].score, 9.5);
            assert_eq!(point_id_average_query[1].id, 2.into());
            assert_eq!(point_id_average_query[1].score, 6.0);

            let mmr_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::NearestWithMmr(NearestWithMmr {
                        nearest: VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        mmr: Mmr {
                            diversity: Some(0.5),
                            candidates_limit: Some(2),
                        },
                    }))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 2,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mmr_query.len(), 2);
            assert_eq!(mmr_query[0].id, 1.into());
            assert_eq!(mmr_query[0].score, 9.0);
            assert_eq!(mmr_query[1].id, 2.into());
            assert_eq!(mmr_query[1].score, 4.0);

            let recommend_best_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendBestScore(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 0.0,
                            ]))],
                            Vec::new(),
                        ),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: Some(0.93),
                    limit: 2,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_best_query.len(), 1);
            assert_eq!(recommend_best_query[0].id, 1.into());
            assert_eq!(
                recommend_best_query[0].score,
                common::math::scaled_fast_sigmoid(9.0)
            );

            let recommend_best_point_id_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendBestScore(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Id(2.into())],
                            Vec::new(),
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_best_point_id_query[0].id, 2.into());
            assert_eq!(
                recommend_best_point_id_query[0].score,
                common::math::scaled_fast_sigmoid(10.0)
            );

            let recommend_sum_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendSumScores(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 0.0,
                            ]))],
                            Vec::new(),
                        ),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: Some(5.0),
                    limit: 2,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_sum_query.len(), 1);
            assert_eq!(recommend_sum_query[0].id, 1.into());
            assert_eq!(recommend_sum_query[0].score, 9.0);

            let recommend_sum_point_id_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::RecommendSumScores(
                        segment::vector_storage::query::RecoQuery::new(
                            vec![VectorInputInternal::Id(2.into())],
                            vec![VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                0.0, 0.0,
                            ]))],
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_sum_point_id_query[0].id, 2.into());
            assert_eq!(recommend_sum_point_id_query[0].score, 6.0);

            let discover_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Discover(
                        segment::vector_storage::query::DiscoverQuery::new(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            Vec::new(),
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover_query[0].id, 1.into());
            assert_eq!(
                discover_query[0].score,
                common::math::scaled_fast_sigmoid(9.0)
            );

            let discover_context_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Discover(
                        segment::vector_storage::query::DiscoverQuery::new(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            vec![segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    1.0, 1.0,
                                ])),
                            }],
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover_context_query[0].id, 1.into());
            assert_eq!(
                discover_context_query[0].score,
                1.0 + common::math::scaled_fast_sigmoid(9.0)
            );

            let discover_point_id_context_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Discover(
                        segment::vector_storage::query::DiscoverQuery::new(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            vec![segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Id(2.into()),
                            }],
                        ),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover_point_id_context_query[0].id, 1.into());
            assert_eq!(
                discover_point_id_context_query[0].score,
                1.0 + common::math::scaled_fast_sigmoid(9.0)
            );

            let context_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Context(
                        segment::vector_storage::query::ContextQuery::new(vec![
                            segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    1.0, 1.0,
                                ])),
                            },
                        ]),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: Some(0.0),
                    limit: 2,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(context_query.len(), 1);
            assert_eq!(context_query[0].id, 1.into());
            assert_eq!(context_query[0].score, 1.0);

            let context_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Context(
                        segment::vector_storage::query::ContextQuery::new(vec![
                            segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    1.0, 1.0,
                                ])),
                            },
                        ]),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(context_groups.groups.len(), 2);
            assert_eq!(context_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(context_groups.groups[0].hits[0].score, 1.0);
            assert_eq!(context_groups.groups[1].id, GroupId::from("b"));
            assert_eq!(context_groups.groups[1].hits[0].score, -1.0);

            let context_point_id_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Context(
                        segment::vector_storage::query::ContextQuery::new(vec![
                            segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Id(2.into()),
                            },
                        ]),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(context_point_id_groups.groups.len(), 2);
            assert_eq!(context_point_id_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(context_point_id_groups.groups[0].hits[0].score, 1.0);
            assert_eq!(context_point_id_groups.groups[1].id, GroupId::from("b"));
            assert_eq!(context_point_id_groups.groups[1].hits[0].score, -1.0);

            let discover_point_id_context_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Discover(
                        segment::vector_storage::query::DiscoverQuery::new(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            vec![segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Id(2.into()),
                            }],
                        ),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover_point_id_context_groups.groups.len(), 2);
            assert_eq!(
                discover_point_id_context_groups.groups[0].id,
                GroupId::from("a")
            );
            assert_eq!(
                discover_point_id_context_groups.groups[0].hits[0].score,
                1.0 + common::math::scaled_fast_sigmoid(9.0)
            );
            assert_eq!(
                discover_point_id_context_groups.groups[1].id,
                GroupId::from("b")
            );
            assert_eq!(
                discover_point_id_context_groups.groups[1].hits[0].score,
                -1.0 + common::math::scaled_fast_sigmoid(4.0)
            );

            let context_point_id_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Context(
                        segment::vector_storage::query::ContextQuery::new(vec![
                            segment::vector_storage::query::ContextPair {
                                positive: VectorInputInternal::Vector(VectorInternal::Dense(vec![
                                    0.0, 0.0,
                                ])),
                                negative: VectorInputInternal::Id(2.into()),
                            },
                        ]),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(context_point_id_query.len(), 1);
            assert_eq!(context_point_id_query[0].id, 1.into());
            assert_eq!(context_point_id_query[0].score, 1.0);

            let point_id_nearest_query = crate::common::query::do_query_points(
                &toc,
                "vector_groups",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(
                        2.into(),
                    )))),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_nearest_query.len(), 1);
            assert_eq!(point_id_nearest_query[0].id, 2.into());
            assert_eq!(point_id_nearest_query[0].score, 10.0);

            let point_id_nearest_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_groups",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(
                        2.into(),
                    )))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 2,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_nearest_groups.groups.len(), 2);
            assert_eq!(point_id_nearest_groups.groups[0].id, GroupId::from("b"));
            assert_eq!(point_id_nearest_groups.groups[0].hits[0].score, 10.0);
            assert_eq!(point_id_nearest_groups.groups[1].id, GroupId::from("a"));
            assert_eq!(point_id_nearest_groups.groups[1].hits[0].score, 8.0);

            let recommend = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend[0].id, 1.into());
            assert_eq!(recommend[0].score, 9.0);

            let recommend_best = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::BestScore),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_best[0].id, 1.into());
            assert_eq!(
                recommend_best[0].score,
                common::math::scaled_fast_sigmoid(9.0)
            );

            let recommend_best_point_id = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::PointId(2.into())],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::BestScore),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_best_point_id[0].id, 2.into());
            assert_eq!(
                recommend_best_point_id[0].score,
                common::math::scaled_fast_sigmoid(10.0)
            );

            let recommend_sum = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::SumScores),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_sum[0].id, 1.into());
            assert_eq!(recommend_sum[0].score, 9.0);

            let recommend_sum_point_id = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::PointId(2.into())],
                    negative: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    strategy: Some(api::rest::RecommendStrategy::SumScores),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_sum_point_id[0].id, 2.into());
            assert_eq!(recommend_sum_point_id[0].score, 6.0);

            let discover = crate::common::query::do_discover_points(
                &toc,
                "vector_groups",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover[0].id, 1.into());
            assert_eq!(
                discover[0].score,
                common::math::scaled_fast_sigmoid(9.0)
            );

            let recommend_batch = crate::common::query::do_recommend_batch_points(
                &toc,
                "vector_groups",
                vec![
                    (
                        RecommendRequestInternal {
                            positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                            negative: Vec::new(),
                            strategy: Some(api::rest::RecommendStrategy::AverageVector),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                    (
                        RecommendRequestInternal {
                            positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                            negative: Vec::new(),
                            strategy: Some(api::rest::RecommendStrategy::AverageVector),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_batch.len(), 2);
            assert_eq!(recommend_batch[0][0].id, 1.into());
            assert_eq!(recommend_batch[1][0].id, 1.into());

            let mixed_recommend_batch = crate::common::query::do_recommend_batch_points(
                &toc,
                "vector_groups",
                vec![
                    (
                        RecommendRequestInternal {
                            positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                            negative: Vec::new(),
                            strategy: Some(api::rest::RecommendStrategy::AverageVector),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                    (
                        RecommendRequestInternal {
                            positive: vec![RecommendExample::Dense(vec![1.0, 0.0])],
                            negative: Vec::new(),
                            strategy: Some(api::rest::RecommendStrategy::AverageVector),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                            using: Some("plain".to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mixed_recommend_batch.len(), 2);
            assert_eq!(mixed_recommend_batch[0][0].id, 1.into());
            assert_eq!(mixed_recommend_batch[0][0].score, 9.0);
            assert_eq!(mixed_recommend_batch[1][0].id, 2.into());
            assert_eq!(mixed_recommend_batch[1][0].score, 0.5);

            let recommend_groups = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_groups",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_groups.groups.len(), 2);
            assert_eq!(recommend_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(recommend_groups.groups[1].id, GroupId::from("b"));

            let recommend_groups_with_lookup = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_groups",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group_id".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: Some(api::rest::WithLookupInterface::Collection(
                            "vector_group_lookup".to_string(),
                        )),
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_groups_with_lookup.groups.len(), 2);
            assert_eq!(
                recommend_groups_with_lookup.groups[0].id,
                GroupId::from(1_u64)
            );
            assert_eq!(
                recommend_groups_with_lookup.groups[0]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.payload.as_ref())
                    .and_then(|payload| payload.0.get("label"))
                    .and_then(Value::as_str),
                Some("lookup-a")
            );
            assert_eq!(
                recommend_groups_with_lookup.groups[1].id,
                GroupId::from(2_u64)
            );
            assert_eq!(
                recommend_groups_with_lookup.groups[1]
                    .lookup
                    .as_ref()
                    .and_then(|lookup| lookup.payload.as_ref())
                    .and_then(|payload| payload.0.get("label"))
                    .and_then(Value::as_str),
                Some("lookup-b")
            );

            let point_id_recommend_groups = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_groups",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::PointId(2.into())],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_recommend_groups.groups.len(), 2);
            assert_eq!(point_id_recommend_groups.groups[0].id, GroupId::from("b"));
            assert_eq!(point_id_recommend_groups.groups[0].hits[0].score, 10.0);
            assert_eq!(point_id_recommend_groups.groups[1].id, GroupId::from("a"));
            assert_eq!(point_id_recommend_groups.groups[1].hits[0].score, 8.0);

            let mixed_point_id_recommend_groups =
                crate::common::query::do_recommend_point_groups(
                    &toc,
                    "vector_groups",
                    RecommendGroupsRequestInternal {
                        positive: vec![
                            RecommendExample::PointId(1.into()),
                            RecommendExample::Dense(vec![0.0, 0.0]),
                        ],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 2,
                            with_lookup: None,
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    Some(&vector_settings),
                )
                .await
                .unwrap();
            assert_eq!(mixed_point_id_recommend_groups.groups.len(), 2);
            assert_eq!(
                mixed_point_id_recommend_groups.groups[0].id,
                GroupId::from("a")
            );
            assert_eq!(
                mixed_point_id_recommend_groups.groups[0].hits[0].score,
                9.5
            );
            assert_eq!(
                mixed_point_id_recommend_groups.groups[1].id,
                GroupId::from("b")
            );
            assert_eq!(
                mixed_point_id_recommend_groups.groups[1].hits[0].score,
                6.0
            );

            let recommend_best_groups = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_groups",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::BestScore),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_best_groups.groups.len(), 2);
            assert_eq!(recommend_best_groups.groups[0].id, GroupId::from("a"));
            assert_eq!(recommend_best_groups.groups[1].id, GroupId::from("b"));

            let recommend_best_point_id_groups = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_groups",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::PointId(2.into())],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::BestScore),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 2,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(recommend_best_point_id_groups.groups.len(), 2);
            assert_eq!(
                recommend_best_point_id_groups.groups[0].id,
                GroupId::from("b")
            );
            assert_eq!(
                recommend_best_point_id_groups.groups[0].hits[0].score,
                common::math::scaled_fast_sigmoid(10.0)
            );
            assert_eq!(
                recommend_best_point_id_groups.groups[1].id,
                GroupId::from("a")
            );
            assert_eq!(
                recommend_best_point_id_groups.groups[1].hits[0].score,
                common::math::scaled_fast_sigmoid(8.0)
            );

            let discover_batch = crate::common::query::do_discover_batch_points(
                &toc,
                "vector_groups",
                vec![
                    (
                        DiscoverRequestInternal {
                            target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                            context: None,
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                    (
                        DiscoverRequestInternal {
                            target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                            context: None,
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover_batch.len(), 2);
            assert_eq!(discover_batch[0][0].id, 1.into());
            assert_eq!(discover_batch[1][0].id, 1.into());

            let mixed_discover = crate::common::query::do_discover_batch_points(
                &toc,
                "vector_groups",
                vec![
                    (
                        DiscoverRequestInternal {
                            target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                            context: None,
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                    (
                        DiscoverRequestInternal {
                            target: Some(RecommendExample::Dense(vec![1.0, 0.0])),
                            context: None,
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(false)),
                            with_vector: Some(WithVector::Bool(false)),
                            using: Some("plain".to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mixed_discover.len(), 2);
            assert_eq!(mixed_discover[0][0].id, 1.into());
            assert_eq!(
                mixed_discover[0][0].score,
                common::math::scaled_fast_sigmoid(9.0)
            );
            assert_eq!(mixed_discover[1][0].id, 2.into());
            assert_eq!(
                mixed_discover[1][0].score,
                common::math::scaled_fast_sigmoid(0.5)
            );

            let point_id_recommend = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::PointId(1.into())],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_recommend.len(), 1);
            assert_eq!(point_id_recommend[0].id, 1.into());
            assert_eq!(point_id_recommend[0].score, 10.0);

            let mixed_point_id_recommend = crate::common::query::do_recommend_points(
                &toc,
                "vector_groups",
                RecommendRequestInternal {
                    positive: vec![
                        RecommendExample::PointId(1.into()),
                        RecommendExample::Dense(vec![0.0, 0.0]),
                    ],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 2,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mixed_point_id_recommend.len(), 2);
            assert_eq!(mixed_point_id_recommend[0].id, 1.into());
            assert_eq!(mixed_point_id_recommend[0].score, 9.5);
            assert_eq!(mixed_point_id_recommend[1].id, 2.into());
            assert_eq!(mixed_point_id_recommend[1].score, 6.0);

            let point_id_discover = crate::common::query::do_discover_points(
                &toc,
                "vector_groups",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::PointId(1.into())),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_discover.len(), 1);
            assert_eq!(point_id_discover[0].id, 1.into());
            assert_eq!(
                point_id_discover[0].score,
                common::math::scaled_fast_sigmoid(10.0)
            );

            let point_id_context_discover = crate::common::query::do_discover_points(
                &toc,
                "vector_groups",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                    context: Some(vec![ContextExamplePair {
                        positive: RecommendExample::Dense(vec![0.0, 0.0]),
                        negative: RecommendExample::PointId(2.into()),
                    }]),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_context_discover[0].id, 1.into());
            assert_eq!(
                point_id_context_discover[0].score,
                1.0 + common::math::scaled_fast_sigmoid(9.0)
            );

            let discover_context = crate::common::query::do_discover_points(
                &toc,
                "vector_groups",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                    context: Some(vec![ContextExamplePair {
                        positive: RecommendExample::Dense(vec![0.0, 0.0]),
                        negative: RecommendExample::Dense(vec![1.0, 1.0]),
                    }]),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(discover_context[0].id, 1.into());
            assert_eq!(
                discover_context[0].score,
                1.0 + common::math::scaled_fast_sigmoid(9.0)
            );
        });
    }

    #[test]
    fn client_nonce_replay_error_tells_clients_to_regenerate_envelope() {
        let err = payload_write_error_to_storage_error(
            "docs",
            PayloadWriteSetupError::Payload(PayloadEncryptionError::ClientNonceReplay),
        );

        let message = err.to_string();
        assert!(message.contains("client envelope nonce was already used"));
        assert!(message.contains("regenerate the client-side envelope"));
        assert!(message.contains("fresh nonce before retrying"));
        assert!(!message.contains("docs"));
    }

    fn encrypted_params() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    fn metadata_value_params() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "tenant_conf".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["tenant_id".to_string()],
                    },
                    instance: "docs_metadata_v1".to_string(),
                    binding: Some(METADATA_VALUE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    #[test]
    fn metadata_value_rules_require_runtime_for_plaintext_writes() {
        let params = metadata_value_params();
        let encryption = params.encryption.as_ref().unwrap();
        let payload = segment::types::Payload(
            json!({
                "tenant_id": "acme",
                "body": "public",
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        assert!(payload_touches_encrypted_config(encryption, &payload, None).unwrap());
        assert!(
            payload_touches_encrypted_config(
                encryption,
                &payload,
                Some(&"tenant_id.child".parse().unwrap()),
            )
            .unwrap()
        );
        assert!(
            !payload_touches_encrypted_config(encryption, &payload, Some(&"body".parse().unwrap()))
                .unwrap()
        );
    }

    #[test]
    fn payload_touches_encrypted_config_matches_literal_json_path_keys() {
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "body_conf".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["document.body".to_string()],
                },
                instance: "docs_payload_v1".to_string(),
                binding: Some("payload-field/v1".to_string()),
            }],
        };

        for payload in [
            segment::types::Payload(
                json!({ "document.body": "literal protected path" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            segment::types::Payload(
                json!({ "document.body.lang": "literal protected child path" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            segment::types::Payload(
                json!({ "document": { "title": "parent update can replace protected child" } })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        ] {
            assert!(payload_touches_encrypted_config(&encryption, &payload, None).unwrap());
        }

        let public_literal_sibling = segment::types::Payload(
            json!({ "document.title": "literal public sibling" })
                .as_object()
                .unwrap()
                .clone(),
        );
        assert!(
            !payload_touches_encrypted_config(&encryption, &public_literal_sibling, None).unwrap()
        );

        assert!(
            payload_touches_encrypted_config(
                &encryption,
                &public_literal_sibling,
                Some(&"document".parse().unwrap())
            )
            .unwrap()
        );
        assert!(
            payload_touches_encrypted_config(
                &encryption,
                &public_literal_sibling,
                Some(&"document.body.lang".parse().unwrap())
            )
            .unwrap()
        );
        assert!(
            !payload_touches_encrypted_config(
                &encryption,
                &public_literal_sibling,
                Some(&"document.title".parse().unwrap())
            )
            .unwrap()
        );
    }

    #[test]
    fn private_result_oram_payload_update_invalid_path_error_is_sanitized() {
        let secret_path = "document.body[private-result-update-secret";
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:result-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private_result_payload".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec![secret_path.to_string()],
                },
                instance: "docs_private_result_oram_v1".to_string(),
                binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
            }],
        };
        let operation = SetPayload {
            payload: segment::types::Payload(
                json!({ "document": { "body": "ordinary write secret" } })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            points: Some(vec![1.into()]),
            filter: None,
            shard_key: None,
            key: None,
        };

        let err = private_result_oram_payload_update_violation(&encryption, &operation)
            .unwrap_err()
            .to_string();

        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-update-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");

        let upsert = PointInsertOperations::PointsList(api::rest::schema::PointsList {
            points: Vec::new(),
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });
        let err = private_result_oram_payload_upsert_violation(&encryption, &upsert)
            .unwrap_err()
            .to_string();
        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-update-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }

    const PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS: &[&str] = &[
        "clientState",
        "clientStates",
        "client_state",
        "client_states",
        "clientStateBackup",
        "clientStateBackups",
        "client_state_backup",
        "client_state_backups",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client.state.snapshot",
        "client.state.snapshot.json",
        "client.state.snapshots.json",
        "client_state_snapshot",
        "client_state_snapshots",
        "clientStateCiphertext",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
        "client_state_ciphertext",
        "client_state_ciphertext_hash",
        "client_state_ciphertext_hash.bin",
        "client_state_ciphertext_hash.json",
        "client_state_ciphertext_hashes",
        "client_state_ciphertext_hashes.bin",
        "client_state_ciphertext_hashes.json",
        "client_state_ciphertext_sha256",
        "client_state_ciphertext_sha256.bin",
        "client_state_ciphertext_sha256.json",
        "client_state_ciphertexts_sha256",
        "client_state_ciphertexts_sha256.bin",
        "client_state_ciphertexts_sha256.json",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encryptedClientState",
        "encryptedClientStates",
        "encrypted.client.state",
        "encrypted.client.state.json",
        "encrypted.client.state.snapshot",
        "encrypted.client.state.snapshot.json",
        "encrypted.client.state.snapshots.json",
        "encrypted_client_states",
        "encrypted_client_state_backups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshot.json",
        "encrypted_client_state_snapshots",
        "encrypted_client_state_snapshots.json",
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state",
        "encrypted_client_state_backup",
        "encrypted_client_state_ciphertext",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state_ciphertext_hash.bin",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes",
        "encrypted_client_state_ciphertext_hashes.bin",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256",
        "encrypted_client_state_ciphertext_sha256.bin",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256",
        "encrypted_client_state_ciphertexts_sha256.bin",
        "encrypted_client_state_ciphertexts_sha256.json",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "oram_position_map_backup",
        "oram_position_map_backups",
        "positionMapBackup",
        "positionMapBackups",
        "position_map_backup",
        "position_map_backups",
        "stashBackup",
        "stashBackups",
        "stateCiphertext",
        "stateCiphertextHash",
        "stateCiphertextHashes",
        "stateCiphertextSha256",
        "stateCiphertextsSha256",
        "state_ciphertext",
        "state_ciphertext_hash",
        "state_ciphertext_hash.bin",
        "state_ciphertext_hash.json",
        "state_ciphertext_hashes",
        "state_ciphertext_hashes.bin",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256",
        "state_ciphertext_sha256.bin",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256",
        "state_ciphertexts_sha256.bin",
        "state_ciphertexts_sha256.json",
        "tokenMapBackup",
        "tokenMapBackups",
        "token.map.backup",
        "token.map.backup.json",
        "token.map.backups",
        "token.map.backups.json",
        "token_map_backup",
        "token_map_backups",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map.backup",
        "token.position.map.backup.json",
        "token.position.map.backups",
        "token.position.map.backups.json",
        "token_position_map_backup",
        "token_position_map_backups",
    ];

    #[test]
    fn private_result_oram_payload_write_error_redacts_payload_path() {
        for payload_path in std::iter::once("document.private-result-payload-path-sentinel")
            .chain(PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS.iter().copied())
        {
            for operation_kind in [
                "upsert points",
                "set payload",
                "overwrite payload",
                "delete payload",
                "clear payload",
                "clear payload by filter",
                "delete points",
                "delete points by filter",
                "payload update",
                "private-result-write-operation-sentinel",
            ] {
                let err = private_result_oram_payload_write_error(payload_path).to_string();

                assert!(err.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
                assert!(err.contains("/private-result-oram/session"));
                assert!(err.contains("cannot modify private result ORAM payload field"));
                assert!(!err.contains(operation_kind), "{err}");
                assert!(!err.contains(payload_path), "{err}");
                assert!(
                    !err.contains("private-result-payload-path-sentinel"),
                    "{err}"
                );
                for &sentinel in PRIVATE_RESULT_ORAM_PAYLOAD_ALIAS_SENTINELS {
                    assert!(!err.contains(sentinel), "{err}");
                }
            }
        }
    }

    #[test]
    fn stable_crypto_id_storage_error_redacts_source_error_details() {
        let sentinel = "stable-crypto-id-source-error-sentinel";
        let err = stable_crypto_id_storage_error(CollectionError::bad_input(format!(
            "collection docs leaked {sentinel}"
        )));
        let rendered = err.to_string();

        assert!(rendered.contains("encrypted collection is missing a stable UUID"));
        assert!(!rendered.contains("docs"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
    }

    #[test]
    fn encrypts_points_list_payloads_before_upsert() {
        let settings = payload_runtime_settings();
        let plan =
            payload_write_plan_for_collection_for_test(&settings, "docs", &encrypted_params())
                .unwrap()
                .unwrap();
        let mut operation = PointInsertOperations::PointsList(api::rest::schema::PointsList {
            points: vec![api::rest::PointStruct {
                id: 1.into(),
                vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                payload: Some(segment::types::Payload(
                    json!({ "body": "secret body" })
                        .as_object()
                        .unwrap()
                        .clone(),
                )),
            }],
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        match &mut operation {
            PointInsertOperations::PointsList(list) => {
                for point in &mut list.points {
                    if let Some(payload) = &mut point.payload {
                        plan.encrypt_payload(&point.id.to_string(), payload)
                            .unwrap();
                    }
                }
            }
            PointInsertOperations::PointsBatch(_) => unreachable!(),
        }

        match operation {
            PointInsertOperations::PointsList(list) => {
                let body = list.points.into_iter().next().unwrap().payload.unwrap();
                assert!(is_encrypted_payload_value(body.0.get("body").unwrap()));
            }
            PointInsertOperations::PointsBatch(_) => unreachable!(),
        }
    }

    #[test]
    fn encrypts_batch_payloads_before_upsert() {
        let settings = payload_runtime_settings();
        let plan =
            payload_write_plan_for_collection_for_test(&settings, "docs", &encrypted_params())
                .unwrap()
                .unwrap();
        let mut operation = PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
            batch: api::rest::schema::Batch {
                ids: vec![1.into()],
                vectors: api::rest::schema::BatchVectorStruct::Single(vec![vec![0.1, 0.2]]),
                payloads: Some(vec![Some(segment::types::Payload(
                    json!({ "body": "batch secret" })
                        .as_object()
                        .unwrap()
                        .clone(),
                ))]),
            },
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        match &mut operation {
            PointInsertOperations::PointsBatch(batch) => {
                for (point_id, payload) in batch
                    .batch
                    .ids
                    .iter()
                    .zip(batch.batch.payloads.as_mut().unwrap().iter_mut())
                {
                    if let Some(payload) = payload {
                        plan.encrypt_payload(&point_id.to_string(), payload)
                            .unwrap();
                    }
                }
            }
            PointInsertOperations::PointsList(_) => unreachable!(),
        }

        match operation {
            PointInsertOperations::PointsBatch(batch) => {
                let payload = batch
                    .batch
                    .payloads
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap();
                assert!(is_encrypted_payload_value(payload.0.get("body").unwrap()));
            }
            PointInsertOperations::PointsList(_) => unreachable!(),
        }
    }

    #[test]
    fn payload_write_plan_rejects_client_supplied_envelope() {
        let settings = payload_runtime_settings();
        let plan =
            payload_write_plan_for_collection_for_test(&settings, "docs", &encrypted_params())
                .unwrap()
                .unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "client supplied secret" })
                .as_object()
                .unwrap()
                .clone(),
        );

        plan.encrypt_payload("1", &mut payload).unwrap();

        assert!(matches!(
            plan.encrypt_payload("1", &mut payload),
            Err(PayloadWriteSetupError::Payload(
                qdrant_sec::PayloadEncryptionError::AlreadyEncrypted(field)
            )) if field == "body"
        ));
    }

    #[test]
    fn payload_write_plan_decrypts_server_envelopes_for_crypto_migration() {
        let settings = payload_runtime_settings();
        let plan =
            payload_write_plan_for_collection_for_test(&settings, "docs", &encrypted_params())
                .unwrap()
                .unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "server-side secret" })
                .as_object()
                .unwrap()
                .clone(),
        );

        assert_eq!(plan.encrypt_payload("1", &mut payload).unwrap(), 1);
        assert!(is_encrypted_payload_value(payload.0.get("body").unwrap()));
        assert_eq!(
            plan.decrypt_payload_for_crypto_migration("1", &mut payload)
                .unwrap(),
            1,
        );
        assert_eq!(
            payload.0.get("body"),
            Some(&json!("server-side secret")),
            "decrypt migration must restore plaintext for server-side payload AEAD",
        );
        assert_eq!(
            plan.decrypt_payload_for_crypto_migration("1", &mut payload)
                .unwrap(),
            0,
            "decrypt migration must be idempotent over already-plaintext payloads",
        );
    }

    #[test]
    fn server_side_encrypted_payload_read_mode_decrypts_get_and_scroll() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("payload-decrypted-read")
            .tempdir()
            .unwrap();
        let temp_dir = Builder::new()
            .prefix("payload-decrypted-read-temp")
            .tempdir()
            .unwrap();
        let storage_config = StorageConfig {
            storage_path: storage_dir.path().to_path_buf(),
            snapshots_path: storage_dir.path().join("snapshots"),
            snapshots_config: Default::default(),
            temp_path: Some(temp_dir.path().to_path_buf()),
            on_disk_payload: false,
            optimizers: OptimizersConfig {
                deleted_threshold: 0.5,
                vacuum_min_vector_number: 100,
                default_segment_number: 1,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: Some(100),
                indexing_threshold: Some(100),
                flush_interval_sec: 2,
                max_optimization_threads: Some(1),
                prevent_unoptimized: None,
            },
            optimizers_overwrite: None,
            wal: Default::default(),
            performance: PerformanceConfig {
                max_search_threads: 1,
                max_optimization_runtime_threads: 1,
                optimizer_cpu_budget: 0,
                optimizer_io_budget: 0,
                update_rate_limit: None,
                search_timeout_sec: None,
                incoming_shard_transfers_limit: Some(1),
                outgoing_shard_transfers_limit: Some(1),
                async_scorer: None,
                load_concurrency: LoadConcurrencyConfig::default(),
            },
            hnsw_index: Default::default(),
            hnsw_global_config: Default::default(),
            mmap_advice: mmap::Advice::Random,
            node_type: Default::default(),
            update_queue_size: Default::default(),
            handle_collection_load_errors: false,
            recovery_mode: None,
            update_concurrency: Some(NonZeroUsize::new(1).unwrap()),
            shard_transfer_method: None,
            collection: None,
            max_collections: None,
        };
        let toc = Arc::new(
            TableOfContent::new(
                &storage_config,
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                ResourceBudget::default(),
                ChannelService::new(6333, false, None, None),
                0,
                None,
            )
            .unwrap(),
        );
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let settings = payload_runtime_settings();

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: encrypted_params().encryption,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": "server secret", "title": "public", "lookup_id": 1 })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();

            let raw_records = crate::common::query::do_get_points(
                &toc,
                "docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap();
            assert!(is_encrypted_payload_value(
                raw_records[0]
                    .payload
                    .as_ref()
                    .unwrap()
                    .0
                    .get("body")
                    .unwrap()
            ));

            let read_only_auth = Auth::new_internal(Access::full_ro("For test"));
            let err = crate::common::query::do_get_points(
                &toc,
                "docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                read_only_auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let payload_decrypt_auth =
                Auth::new_internal(Access::Collection(CollectionAccessList(vec![
                    CollectionAccess {
                        collection: "docs".to_string(),
                        access: CollectionAccessMode::Read,
                        payload_decrypt: true,
                        snapshot_export: false,
                        #[expect(deprecated)]
                        payload: None,
                    },
                ])));
            let mut strict_settings = settings.clone();
            strict_settings.crypto.zero_trust_profile =
                Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string());
            strict_settings.crypto.allow_inline_key_material = false;
            let err = crate::common::query::do_get_points(
                &toc,
                "docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                payload_decrypt_auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&strict_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("strict zero-trust profile")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            let decrypted_records = crate::common::query::do_get_points(
                &toc,
                "docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                payload_decrypt_auth,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_records[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(serde_json::Value::as_str),
                Some("server secret"),
            );

            let err = crate::common::query::do_search_points(
                &toc,
                "docs",
                SearchRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                read_only_auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let batch_search_request: CoreSearchRequest = SearchRequestInternal {
                vector: vec![0.1, 0.2].into(),
                with_payload: Some(WithPayloadInterface::Encrypted(
                    PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    },
                )),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into();
            let err = crate::common::query::do_search_batch_points(
                &toc,
                "docs",
                vec![(batch_search_request, ShardSelectorInternal::All)],
                None,
                read_only_auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let err = crate::common::query::do_query_batch_points(
                &toc,
                "docs",
                vec![(
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
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
                None,
                read_only_auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let err = crate::common::query::do_recommend_batch_points(
                &toc,
                "docs",
                vec![(
                    RecommendRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
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
                None,
                read_only_auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let err = crate::common::query::do_discover_batch_points(
                &toc,
                "docs",
                vec![(
                    DiscoverRequestInternal {
                        target: Some(RecommendExample::Dense(vec![0.1, 0.2])),
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
                None,
                read_only_auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let decrypted_records = crate::common::query::do_get_points(
                &toc,
                "docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_records[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );
            assert_eq!(
                decrypted_records[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("title"))
                    .and_then(Value::as_str),
                Some("public"),
            );

            let err = crate::common::query::do_get_points(
                &toc,
                "docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("requires runtime crypto settings")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            let err = crate::common::query::do_scroll_points(
                &toc,
                "docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("requires runtime crypto settings")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            let decrypted_scroll = crate::common::query::do_scroll_points(
                &toc,
                "docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_scroll.points[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let decrypted_search = crate::common::query::do_search_points(
                &toc,
                "docs",
                SearchRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_search[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let decrypted_query = crate::common::query::do_query_points(
                &toc,
                "docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_query[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let decrypted_recommend = crate::common::query::do_recommend_points(
                &toc,
                "docs",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_recommend[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let decrypted_discover = crate::common::query::do_discover_points(
                &toc,
                "docs",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.1, 0.2])),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_discover[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let decrypted_search_groups = crate::common::query::do_search_point_groups(
                &toc,
                "docs",
                SearchGroupsRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "title".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_search_groups.groups[0].hits[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let decrypted_search_groups_with_lookup = crate::common::query::do_search_point_groups(
                &toc,
                "docs",
                SearchGroupsRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "lookup_id".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: Some(api::rest::WithLookupInterface::Collection(
                            "docs".to_string(),
                        )),
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_search_groups_with_lookup.groups[0]
                    .lookup
                    .as_ref()
                    .and_then(|record| record.payload.as_ref())
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );

            let err = crate::common::query::do_search_point_groups(
                &toc,
                "docs",
                SearchGroupsRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "lookup_id".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: Some(api::rest::WithLookupInterface::WithLookup(
                            api::rest::WithLookup {
                                collection_name: "docs".to_string(),
                                with_payload: Some(WithPayloadInterface::Encrypted(
                                    PayloadEncryptedReadPolicy {
                                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                                    },
                                )),
                                with_vectors: Some(WithVector::Bool(false)),
                            },
                        )),
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("collection-internal reads must use 'raw' or 'redacted'")
            ));

            let decrypted_query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "docs",
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                        encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                    }),
                    lookup_from: None,
                    group_by: "title".parse().unwrap(),
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_query_groups.groups[0].hits[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("body"))
                    .and_then(Value::as_str),
                Some("server secret"),
            );
        });
    }

    #[test]
    fn private_result_oram_ordinary_payload_reads_require_session_api() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("private-result-oram-read-guard")
            .tempdir()
            .unwrap();
        let storage_config = update_test_storage_config(storage_dir.path());
        let toc = update_test_toc(&storage_config);
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let params = private_result_oram_payload_params();

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "private_result_docs".to_string(),
                            CreateCollection {
                                vectors: params.vectors,
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: params.encryption,
                                strict_mode_config: None,
                                uuid: Some(
                                    Uuid::parse_str(TEST_VECTOR_COLLECTION_CRYPTO_ID).unwrap(),
                                ),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let assert_private_result_session_error = |err: StorageError| {
                let message = err.to_string();
                assert!(
                    message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                    "{message}"
                );
                assert!(
                    message.contains("/private-result-oram/session"),
                    "{message}"
                );
                assert!(
                    message.contains("ordinary collection payload reads"),
                    "{message}"
                );
            };
            let assert_private_result_grpc_session_error = |err: tonic::Status| {
                let message = err.message();
                assert!(
                    message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                    "{message}"
                );
                assert!(
                    message.contains("/private-result-oram/session"),
                    "{message}"
                );
                assert!(
                    message.contains("ordinary collection payload reads"),
                    "{message}"
                );
            };
            let request_hw_counter = || {
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                )
            };
            let grpc_payload_enabled = || api::grpc::qdrant::WithPayloadSelector {
                selector_options: Some(
                    api::grpc::qdrant::with_payload_selector::SelectorOptions::Enable(true),
                ),
            };
            let grpc_payload_disabled = || api::grpc::qdrant::WithPayloadSelector {
                selector_options: Some(
                    api::grpc::qdrant::with_payload_selector::SelectorOptions::Enable(false),
                ),
            };
            let grpc_payload_decrypted = || api::grpc::qdrant::WithPayloadSelector {
                selector_options: Some(
                    api::grpc::qdrant::with_payload_selector::SelectorOptions::Encrypted(
                        api::grpc::qdrant::PayloadEncryptedSelector {
                            mode: api::grpc::qdrant::payload_encrypted_selector::EncryptedPayloadReadMode::EncryptedPayloadDecrypted as i32,
                        },
                    ),
                ),
            };
            let grpc_dense_vector = || api::grpc::qdrant::Vector {
                vector: Some(api::grpc::qdrant::vector::Vector::Dense(
                    api::grpc::qdrant::DenseVector {
                        data: vec![0.1, 0.2],
                    },
                )),
                ..Default::default()
            };
            let grpc_dense_input = || api::grpc::qdrant::VectorInput {
                variant: Some(api::grpc::qdrant::vector_input::Variant::Dense(
                    api::grpc::qdrant::DenseVector {
                        data: vec![0.1, 0.2],
                    },
                )),
            };
            let grpc_nearest_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Nearest(
                    grpc_dense_input(),
                )),
            };
            let grpc_search_points = || api::grpc::qdrant::SearchPoints {
                collection_name: "private_result_docs".to_string(),
                vector: vec![0.1, 0.2],
                filter: None,
                limit: 1,
                with_payload: Some(grpc_payload_enabled()),
                params: None,
                score_threshold: None,
                offset: None,
                vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                with_vectors: None,
                read_consistency: None,
                timeout: None,
                shard_key_selector: None,
                sparse_indices: None,
                ckks_encrypted_query: None,
            };
            let collection_pass = auth
                .check_collection_access("private_result_docs", AccessRequirements::new(), "test")
                .unwrap();
            let private_result_collection = toc.get_collection(&collection_pass).await.unwrap();

            let no_payload_records = crate::common::query::do_get_points(
                &toc,
                "private_result_docs",
                PointRequestInternal {
                    ids: Vec::new(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .expect("private result ORAM retrieve without payload must remain ordinary");
            assert!(no_payload_records.is_empty());

            let grpc_no_payload_records = crate::tonic::api::query_common::get(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::GetPoints {
                    collection_name: "private_result_docs".to_string(),
                    ids: Vec::new(),
                    with_payload: Some(grpc_payload_disabled()),
                    with_vectors: None,
                    read_consistency: None,
                    shard_key_selector: None,
                    timeout: None,
                },
                None,
                auth.clone(),
                request_hw_counter(),
                None,
            )
            .await
            .expect("private result ORAM gRPC retrieve without payload must remain ordinary")
            .into_inner();
            assert!(grpc_no_payload_records.result.is_empty());

            let no_payload_scroll = crate::common::query::do_scroll_points(
                &toc,
                "private_result_docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .expect("private result ORAM scroll without payload must remain ordinary");
            assert!(no_payload_scroll.points.is_empty());

            let no_payload_search = crate::common::query::do_search_points(
                &toc,
                "private_result_docs",
                SearchRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .expect("private result ORAM search without payload must remain ordinary");
            assert!(no_payload_search.is_empty());

            let grpc_no_payload_search = crate::tonic::api::query_common::search(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::SearchPoints {
                    collection_name: "private_result_docs".to_string(),
                    vector: vec![0.1, 0.2],
                    filter: None,
                    limit: 1,
                    with_payload: Some(grpc_payload_disabled()),
                    params: None,
                    score_threshold: None,
                    offset: None,
                    vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: None,
                    read_consistency: None,
                    timeout: None,
                    shard_key_selector: None,
                    sparse_indices: None,
                    ckks_encrypted_query: None,
                },
                None,
                auth.clone(),
                request_hw_counter(),
                None,
            )
            .await
            .expect("private result ORAM gRPC search without payload must remain ordinary")
            .into_inner();
            assert!(grpc_no_payload_search.result.is_empty());

            assert_private_result_session_error(
                crate::common::query::do_get_points(
                    &toc,
                    "private_result_docs",
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: WithVector::Bool(false),
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM retrieve must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_get_points(
                    &toc,
                    "private_result_docs",
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Encrypted(
                            PayloadEncryptedReadPolicy {
                                encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                            },
                        )),
                        with_vector: WithVector::Bool(false),
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM decrypted retrieve must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_get_points(
                    &toc,
                    "private_result_docs",
                    PointRequestInternal {
                        ids: Vec::new(),
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: WithVector::Bool(false),
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM empty retrieve must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::get(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::GetPoints {
                        collection_name: "private_result_docs".to_string(),
                        ids: vec![segment::types::PointIdType::from(1).into()],
                        with_payload: Some(grpc_payload_enabled()),
                        with_vectors: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC retrieve must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::get(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::GetPoints {
                        collection_name: "private_result_docs".to_string(),
                        ids: vec![segment::types::PointIdType::from(1).into()],
                        with_payload: Some(grpc_payload_decrypted()),
                        with_vectors: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC decrypted retrieve must fail closed"),
            );

            assert_private_result_session_error(
                private_result_collection
                    .retrieve(
                        PointRequestInternal {
                            ids: Vec::new(),
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: WithVector::Bool(false),
                        },
                        None,
                        &ShardSelectorInternal::All,
                        None,
                        HwMeasurementAcc::disposable(),
                    )
                    .await
                    .map_err(StorageError::from)
                    .expect_err("private result ORAM collection empty retrieve must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_scroll_points(
                    &toc,
                    "private_result_docs",
                    shard::scroll::ScrollRequestInternal {
                        offset: None,
                        limit: Some(1),
                        filter: None,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: WithVector::Bool(false),
                        order_by: None,
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM scroll must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_scroll_points(
                    &toc,
                    "private_result_docs",
                    shard::scroll::ScrollRequestInternal {
                        offset: None,
                        limit: Some(0),
                        filter: None,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: WithVector::Bool(false),
                        order_by: None,
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM zero-limit scroll must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::scroll(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::ScrollPoints {
                        collection_name: "private_result_docs".to_string(),
                        filter: None,
                        offset: None,
                        limit: Some(1),
                        with_payload: Some(grpc_payload_enabled()),
                        with_vectors: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        order_by: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC scroll must fail closed"),
            );

            assert_private_result_session_error(
                private_result_collection
                    .scroll_by(
                        shard::scroll::ScrollRequestInternal {
                            offset: None,
                            limit: Some(0),
                            filter: None,
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: WithVector::Bool(false),
                            order_by: None,
                        },
                        None,
                        &ShardSelectorInternal::All,
                        None,
                        HwMeasurementAcc::disposable(),
                    )
                    .await
                    .map_err(StorageError::from)
                    .expect_err(
                        "private result ORAM collection zero-limit scroll must fail closed",
                    ),
            );

            assert_private_result_session_error(
                crate::common::query::do_search_points(
                    &toc,
                    "private_result_docs",
                    SearchRequestInternal {
                        vector: vec![0.1, 0.2].into(),
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: Some(WithVector::Bool(false)),
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        score_threshold: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM search must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::search(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPoints {
                        collection_name: "private_result_docs".to_string(),
                        vector: vec![0.1, 0.2],
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        score_threshold: None,
                        offset: None,
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        read_consistency: None,
                        timeout: None,
                        shard_key_selector: None,
                        sparse_indices: None,
                        ckks_encrypted_query: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC search must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_search_batch_points(
                    &toc,
                    "private_result_docs",
                    vec![(
                        CoreSearchRequest {
                            query: QueryEnum::Nearest(NamedQuery::new(
                                VectorInternal::Dense(vec![0.1, 0.2]),
                                DEFAULT_VECTOR_NAME,
                            )),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: 0,
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch search must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_core_search_points(
                    &toc,
                    "private_result_docs",
                    CoreSearchRequest {
                        query: QueryEnum::Nearest(NamedQuery::new(
                            VectorInternal::Dense(vec![0.1, 0.2]),
                            DEFAULT_VECTOR_NAME,
                        )),
                        filter: None,
                        params: None,
                        limit: 0,
                        offset: 0,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM zero-limit core search must fail closed"),
            );

            assert_private_result_session_error(
                private_result_collection
                    .core_search_batch(
                        shard::search::CoreSearchRequestBatch {
                            searches: vec![CoreSearchRequest {
                                query: QueryEnum::Nearest(NamedQuery::new(
                                    VectorInternal::Dense(vec![0.1, 0.2]),
                                    DEFAULT_VECTOR_NAME,
                                )),
                                filter: None,
                                params: None,
                                limit: 0,
                                offset: 0,
                                with_payload: Some(WithPayloadInterface::Bool(true)),
                                with_vector: Some(WithVector::Bool(false)),
                                score_threshold: None,
                            }],
                        },
                        None,
                        ShardSelectorInternal::All,
                        None,
                        HwMeasurementAcc::disposable(),
                    )
                    .await
                    .map_err(StorageError::from)
                    .expect_err(
                        "private result ORAM collection zero-limit search must fail closed",
                    ),
            );

            assert_private_result_session_error(
                crate::common::query::do_search_batch_points_from_rest(
                    &toc,
                    "private_result_docs",
                    vec![(
                        SearchRequestInternal {
                            vector: vec![0.1, 0.2].into(),
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: Some(WithVector::Bool(false)),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            score_threshold: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM REST batch search must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::search_batch_from_grpc(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_docs",
                    vec![(
                        api::rest::SearchRequestInternal::try_from(grpc_search_points()).unwrap(),
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch search must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_search_point_groups(
                    &toc,
                    "private_result_docs",
                    SearchGroupsRequestInternal {
                        vector: vec![0.1, 0.2].into(),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: Some(WithVector::Bool(false)),
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: None,
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM grouped search must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: "private_result_docs".to_string(),
                        vector: vec![0.1, 0.2],
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        score_threshold: None,
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        group_by: "group".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: None,
                        timeout: None,
                        shard_key_selector: None,
                        sparse_indices: None,
                        ckks_encrypted_query: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC grouped search must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_search_point_groups(
                    &toc,
                    "private_result_docs",
                    SearchGroupsRequestInternal {
                        vector: vec![0.1, 0.2].into(),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: Some(WithVector::Bool(false)),
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: Some(api::rest::WithLookupInterface::Collection(
                                "private_result_docs".to_string(),
                            )),
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM grouped search lookup must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: "private_result_docs".to_string(),
                        vector: vec![0.1, 0.2],
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_disabled()),
                        params: None,
                        score_threshold: None,
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        group_by: "group".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: Some(api::grpc::qdrant::WithLookup {
                            collection: "private_result_docs".to_string(),
                            with_payload: Some(grpc_payload_enabled()),
                            with_vectors: None,
                        }),
                        timeout: None,
                        shard_key_selector: None,
                        sparse_indices: None,
                        ckks_encrypted_query: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC grouped search lookup must fail closed"),
            );

            let lookup_collection = private_result_collection.clone();
            assert_private_result_session_error(
                collection::lookup::lookup_ids(
                    collection::lookup::WithLookup {
                        collection_name: "private_result_docs".to_string(),
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vectors: Some(WithVector::Bool(false)),
                    },
                    Vec::<collection::lookup::types::PseudoId>::new(),
                    |_| async move { Some(lookup_collection) },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .map_err(StorageError::from)
                .expect_err("private result ORAM empty group lookup must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_query_point_groups(
                    &toc,
                    "private_result_docs",
                    CollectionQueryGroupsRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(true),
                        lookup_from: None,
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM grouped universal query must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::query_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPointGroups {
                        collection_name: "private_result_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_payload: Some(grpc_payload_enabled()),
                        with_vectors: None,
                        lookup_from: None,
                        limit: Some(1),
                        group_size: Some(1),
                        group_by: "group".to_string(),
                        read_consistency: None,
                        with_lookup: None,
                        timeout: None,
                        shard_key_selector: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC grouped query must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_query_point_groups(
                    &toc,
                    "private_result_docs",
                    CollectionQueryGroupsRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: Some(collection::lookup::WithLookup {
                            collection_name: "private_result_docs".to_string(),
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vectors: Some(WithVector::Bool(false)),
                        }),
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM grouped universal query lookup must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::query_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPointGroups {
                        collection_name: "private_result_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_payload: Some(grpc_payload_disabled()),
                        with_vectors: None,
                        lookup_from: None,
                        limit: Some(1),
                        group_size: Some(1),
                        group_by: "group".to_string(),
                        read_consistency: None,
                        with_lookup: Some(api::grpc::qdrant::WithLookup {
                            collection: "private_result_docs".to_string(),
                            with_payload: Some(grpc_payload_enabled()),
                            with_vectors: None,
                        }),
                        timeout: None,
                        shard_key_selector: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC grouped query lookup must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_recommend_points(
                    &toc,
                    "private_result_docs",
                    RecommendRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM recommend must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::recommend(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::RecommendPoints {
                        collection_name: "private_result_docs".to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        score_threshold: None,
                        offset: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC recommend must fail closed"),
            );

            assert_private_result_session_error(
                collection::recommendations::recommend_by(
                    RecommendRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        limit: 0,
                        offset: None,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                    },
                    private_result_collection.as_ref(),
                    |_| async { None },
                    None,
                    ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .map_err(StorageError::from)
                .expect_err("private result ORAM zero-limit collection recommend must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_recommend_batch_points(
                    &toc,
                    "private_result_docs",
                    vec![(
                        RecommendRequestInternal {
                            positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                            negative: Vec::new(),
                            strategy: Some(api::rest::RecommendStrategy::AverageVector),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: Some(WithVector::Bool(false)),
                            score_threshold: None,
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch recommend must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::recommend_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_docs",
                    vec![api::grpc::qdrant::RecommendPoints {
                        collection_name: "private_result_docs".to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        score_threshold: None,
                        offset: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch recommend must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_recommend_point_groups(
                    &toc,
                    "private_result_docs",
                    RecommendGroupsRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: Some(WithVector::Bool(false)),
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: None,
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM grouped recommend must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::recommend_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::RecommendPointGroups {
                        collection_name: "private_result_docs".to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        score_threshold: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        group_by: "group".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: None,
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC grouped recommend must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_recommend_point_groups(
                    &toc,
                    "private_result_docs",
                    RecommendGroupsRequestInternal {
                        positive: vec![RecommendExample::Dense(vec![0.1, 0.2])],
                        negative: Vec::new(),
                        strategy: Some(api::rest::RecommendStrategy::AverageVector),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: Some(WithVector::Bool(false)),
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                        group_request: BaseGroupRequest {
                            group_by: "group".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: Some(api::rest::WithLookupInterface::Collection(
                                "private_result_docs".to_string(),
                            )),
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM grouped recommend lookup must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::recommend_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::RecommendPointGroups {
                        collection_name: "private_result_docs".to_string(),
                        positive: Vec::new(),
                        negative: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_disabled()),
                        params: None,
                        score_threshold: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        group_by: "group".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: Some(api::grpc::qdrant::WithLookup {
                            collection: "private_result_docs".to_string(),
                            with_payload: Some(grpc_payload_enabled()),
                            with_vectors: None,
                        }),
                        strategy: None,
                        positive_vectors: vec![grpc_dense_vector()],
                        negative_vectors: Vec::new(),
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC grouped recommend lookup must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_discover_points(
                    &toc,
                    "private_result_docs",
                    DiscoverRequestInternal {
                        target: Some(RecommendExample::Dense(vec![0.1, 0.2])),
                        context: None,
                        filter: None,
                        params: None,
                        limit: 1,
                        offset: None,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: Some(WithVector::Bool(false)),
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM discover must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::discover(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::DiscoverPoints {
                        collection_name: "private_result_docs".to_string(),
                        target: Some(api::grpc::qdrant::TargetVector {
                            target: Some(api::grpc::qdrant::target_vector::Target::Single(
                                api::grpc::qdrant::VectorExample {
                                    example: Some(
                                        api::grpc::qdrant::vector_example::Example::Vector(
                                            grpc_dense_vector(),
                                        ),
                                    ),
                                },
                            )),
                        }),
                        context: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        offset: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        timeout: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC discover must fail closed"),
            );

            assert_private_result_session_error(
                collection::discovery::discover(
                    DiscoverRequestInternal {
                        target: Some(RecommendExample::Dense(vec![0.1, 0.2])),
                        context: None,
                        filter: None,
                        params: None,
                        limit: 0,
                        offset: None,
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: Some(WithVector::Bool(false)),
                        using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                        lookup_from: None,
                    },
                    private_result_collection.as_ref(),
                    |_| async { None },
                    None,
                    ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .map_err(StorageError::from)
                .expect_err("private result ORAM zero-limit collection discover must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_discover_batch_points(
                    &toc,
                    "private_result_docs",
                    vec![(
                        DiscoverRequestInternal {
                            target: Some(RecommendExample::Dense(vec![0.1, 0.2])),
                            context: None,
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: Some(WithVector::Bool(false)),
                            using: Some(DEFAULT_VECTOR_NAME.to_string().into()),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch discover must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::discover_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_docs",
                    vec![api::grpc::qdrant::DiscoverPoints {
                        collection_name: "private_result_docs".to_string(),
                        target: Some(api::grpc::qdrant::TargetVector {
                            target: Some(api::grpc::qdrant::target_vector::Target::Single(
                                api::grpc::qdrant::VectorExample {
                                    example: Some(
                                        api::grpc::qdrant::vector_example::Example::Vector(
                                            grpc_dense_vector(),
                                        ),
                                    ),
                                },
                            )),
                        }),
                        context: Vec::new(),
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_enabled()),
                        params: None,
                        offset: None,
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        lookup_from: None,
                        read_consistency: None,
                        timeout: None,
                        shard_key_selector: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch discover must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_query_points(
                    &toc,
                    "private_result_docs",
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(true),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM universal query must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::query(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPoints {
                        collection_name: "private_result_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: Some(grpc_payload_enabled()),
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC query must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_query_points(
                    &toc,
                    "private_result_docs",
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Encrypted(
                            PayloadEncryptedReadPolicy {
                                encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                            },
                        ),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM decrypted universal query must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::query(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPoints {
                        collection_name: "private_result_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: Some(grpc_payload_decrypted()),
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC decrypted query must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_query_points(
                    &toc,
                    "private_result_docs",
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 0,
                        offset: 0,
                        params: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(true),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM zero-limit universal query must fail closed"),
            );

            assert_private_result_session_error(
                private_result_collection
                    .query(
                        collection::operations::universal_query::shard_query::ShardQueryRequest {
                            prefetches: Vec::new(),
                            query: None,
                            filter: None,
                            score_threshold: None,
                            limit: 0,
                            offset: 0,
                            params: None,
                            with_vector: WithVector::Bool(false),
                            with_payload: WithPayloadInterface::Bool(true),
                        },
                        None,
                        ShardSelectorInternal::All,
                        None,
                        HwMeasurementAcc::disposable(),
                    )
                    .await
                    .map_err(StorageError::from)
                    .expect_err("private result ORAM collection zero-limit query must fail closed"),
            );

            assert_private_result_session_error(
                crate::common::query::do_query_batch_points(
                    &toc,
                    "private_result_docs",
                    vec![(
                        CollectionQueryRequest {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            offset: 0,
                            params: None,
                            with_vector: WithVector::Bool(false),
                            with_payload: WithPayloadInterface::Bool(true),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    )],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM batch universal query must fail closed"),
            );

            assert_private_result_grpc_session_error(
                crate::tonic::api::query_common::query_batch(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "private_result_docs",
                    vec![api::grpc::qdrant::QueryPoints {
                        collection_name: "private_result_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: Some(grpc_payload_enabled()),
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    }],
                    None,
                    auth.clone(),
                    None,
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC batch query must fail closed"),
            );
        });
    }

    #[test]
    fn private_result_oram_predicate_paths_require_session_api() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("private-result-oram-predicate-guard")
            .tempdir()
            .unwrap();
        let storage_config = update_test_storage_config(storage_dir.path());
        let toc = update_test_toc(&storage_config);
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let params = private_result_oram_payload_params();

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "private_result_predicate_docs".to_string(),
                            CreateCollection {
                                vectors: params.vectors,
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: params.encryption,
                                strict_mode_config: None,
                                uuid: Some(
                                    Uuid::parse_str(TEST_VECTOR_COLLECTION_CRYPTO_ID).unwrap(),
                                ),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let private_body_filter = || {
                Filter::new_must(Condition::Field(FieldCondition::new_match(
                    "body".parse().unwrap(),
                    "secret".to_string().into(),
                )))
            };
            let private_body_grpc_filter =
                || api::grpc::qdrant::Filter::from(private_body_filter());
            let private_body_grpc_condition = || {
                private_body_grpc_filter()
                    .must
                    .pop()
                    .expect("private body filter must contain a condition")
            };
            let assert_private_result_predicate_error =
                |err: StorageError, expected_operation: &str| {
                    let message = err.to_string();
                    assert!(message.contains(expected_operation), "{message}");
                    assert!(
                        message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                        "{message}"
                    );
                    assert!(
                        message.contains("/private-result-oram/session"),
                        "{message}"
                    );
                };
            let assert_private_result_grpc_predicate_error =
                |err: tonic::Status, expected_operation: &str| {
                    let message = err.message();
                    assert!(message.contains(expected_operation), "{message}");
                    assert!(
                        message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                        "{message}"
                    );
                    assert!(
                        message.contains("/private-result-oram/session"),
                        "{message}"
                    );
                };
            let request_hw_counter = || {
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                )
            };
            let grpc_payload_disabled = || api::grpc::qdrant::WithPayloadSelector {
                selector_options: Some(
                    api::grpc::qdrant::with_payload_selector::SelectorOptions::Enable(false),
                ),
            };
            let grpc_dense_input = || api::grpc::qdrant::VectorInput {
                variant: Some(api::grpc::qdrant::vector_input::Variant::Dense(
                    api::grpc::qdrant::DenseVector {
                        data: vec![0.1, 0.2],
                    },
                )),
            };
            let grpc_nearest_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Nearest(
                    grpc_dense_input(),
                )),
            };
            let grpc_formula_variable_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Formula(
                    api::grpc::qdrant::Formula {
                        expression: Some(api::grpc::qdrant::Expression {
                            variant: Some(api::grpc::qdrant::expression::Variant::Variable(
                                "body".to_string(),
                            )),
                        }),
                        defaults: Default::default(),
                    },
                )),
            };
            let grpc_formula_condition_query = || api::grpc::qdrant::Query {
                variant: Some(api::grpc::qdrant::query::Variant::Formula(
                    api::grpc::qdrant::Formula {
                        expression: Some(api::grpc::qdrant::Expression {
                            variant: Some(api::grpc::qdrant::expression::Variant::Condition(
                                private_body_grpc_condition(),
                            )),
                        }),
                        defaults: Default::default(),
                    },
                )),
            };

            assert_private_result_predicate_error(
                toc.facet(
                    "private_result_predicate_docs",
                    segment::data_types::facets::FacetParams {
                        key: "body".parse().unwrap(),
                        limit: 0,
                        filter: None,
                        exact: false,
                    },
                    ShardSelectorInternal::All,
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM zero-limit facet must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::facet(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::FacetCounts {
                        collection_name: "private_result_predicate_docs".to_string(),
                        key: "body".to_string(),
                        filter: None,
                        limit: Some(1),
                        exact: Some(false),
                        timeout: None,
                        read_consistency: None,
                        shard_key_selector: None,
                    },
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC facet must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_scroll_points(
                    &toc,
                    "private_result_predicate_docs",
                    shard::scroll::ScrollRequestInternal {
                        offset: None,
                        limit: Some(1),
                        filter: Some(private_body_filter()),
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: WithVector::Bool(false),
                        order_by: None,
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM filter must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::scroll(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::ScrollPoints {
                        collection_name: "private_result_predicate_docs".to_string(),
                        filter: Some(private_body_grpc_filter()),
                        offset: None,
                        limit: Some(1),
                        with_payload: Some(grpc_payload_disabled()),
                        with_vectors: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        order_by: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC filter must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_count_points(
                    &toc,
                    "private_result_predicate_docs",
                    CountRequestInternal {
                        filter: Some(private_body_filter()),
                        exact: true,
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .expect_err("private result ORAM count filter must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::count(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::CountPoints {
                        collection_name: "private_result_predicate_docs".to_string(),
                        filter: Some(private_body_grpc_filter()),
                        exact: Some(true),
                        read_consistency: None,
                        shard_key_selector: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                )
                .await
                .expect_err("private result ORAM gRPC count filter must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_query_points(
                    &toc,
                    "private_result_predicate_docs",
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Formula(FormulaInternal {
                            formula: ExpressionInternal::Variable("body".to_string()),
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
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM formula must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::query(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPoints {
                        collection_name: "private_result_predicate_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_formula_variable_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: Some(grpc_payload_disabled()),
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC formula must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_query_points(
                    &toc,
                    "private_result_predicate_docs",
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Formula(FormulaInternal {
                            formula: ExpressionInternal::Condition(Box::new(
                                private_body_filter().must.unwrap().pop().unwrap(),
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
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM formula condition must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::query(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPoints {
                        collection_name: "private_result_predicate_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_formula_condition_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        limit: Some(1),
                        offset: None,
                        with_vectors: None,
                        with_payload: Some(grpc_payload_disabled()),
                        read_consistency: None,
                        shard_key_selector: None,
                        lookup_from: None,
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC formula condition must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_scroll_points(
                    &toc,
                    "private_result_predicate_docs",
                    shard::scroll::ScrollRequestInternal {
                        offset: None,
                        limit: Some(1),
                        filter: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: WithVector::Bool(false),
                        order_by: Some(segment::data_types::order_by::OrderByInterface::Key(
                            "body".parse().unwrap(),
                        )),
                    },
                    None,
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM order_by must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::scroll(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::ScrollPoints {
                        collection_name: "private_result_predicate_docs".to_string(),
                        filter: None,
                        offset: None,
                        limit: Some(1),
                        with_payload: Some(grpc_payload_disabled()),
                        with_vectors: None,
                        read_consistency: None,
                        shard_key_selector: None,
                        order_by: Some(api::grpc::qdrant::OrderBy {
                            key: "body".to_string(),
                            direction: None,
                            start_from: None,
                        }),
                        timeout: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC order_by must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_search_point_groups(
                    &toc,
                    "private_result_predicate_docs",
                    SearchGroupsRequestInternal {
                        vector: vec![0.1, 0.2].into(),
                        filter: None,
                        params: None,
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        score_threshold: None,
                        group_request: BaseGroupRequest {
                            group_by: "body".parse().unwrap(),
                            group_size: 1,
                            limit: 1,
                            with_lookup: None,
                        },
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM search group_by must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: "private_result_predicate_docs".to_string(),
                        vector: vec![0.1, 0.2],
                        filter: None,
                        limit: 1,
                        with_payload: Some(grpc_payload_disabled()),
                        params: None,
                        score_threshold: None,
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: None,
                        group_by: "body".to_string(),
                        group_size: 1,
                        read_consistency: None,
                        with_lookup: None,
                        timeout: None,
                        shard_key_selector: None,
                        sparse_indices: None,
                        ckks_encrypted_query: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC search group_by must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_predicate_error(
                crate::common::query::do_query_point_groups(
                    &toc,
                    "private_result_predicate_docs",
                    CollectionQueryGroupsRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.1, 0.2])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                        group_by: "body".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    None,
                )
                .await
                .expect_err("private result ORAM query group_by must fail closed"),
                "cannot use private result ORAM payload field",
            );

            assert_private_result_grpc_predicate_error(
                crate::tonic::api::query_common::query_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::QueryPointGroups {
                        collection_name: "private_result_predicate_docs".to_string(),
                        prefetch: Vec::new(),
                        query: Some(grpc_nearest_query()),
                        using: Some(DEFAULT_VECTOR_NAME.to_string()),
                        filter: None,
                        params: None,
                        score_threshold: None,
                        with_payload: Some(grpc_payload_disabled()),
                        with_vectors: None,
                        lookup_from: None,
                        limit: Some(1),
                        group_size: Some(1),
                        group_by: "body".to_string(),
                        read_consistency: None,
                        with_lookup: None,
                        timeout: None,
                        shard_key_selector: None,
                    },
                    None,
                    auth.clone(),
                    request_hw_counter(),
                    InferenceParams::default(),
                    None,
                )
                .await
                .expect_err("private result ORAM gRPC query group_by must fail closed"),
                "cannot use private result ORAM payload field",
            );
        });
    }

    #[test]
    fn metadata_value_encrypted_read_mode_decrypts_with_payload_decrypt_access() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new()
            .prefix("metadata-decrypted-read")
            .tempdir()
            .unwrap();
        let temp_dir = Builder::new()
            .prefix("metadata-decrypted-read-temp")
            .tempdir()
            .unwrap();
        let storage_config = StorageConfig {
            storage_path: storage_dir.path().to_path_buf(),
            snapshots_path: storage_dir.path().join("snapshots"),
            snapshots_config: Default::default(),
            temp_path: Some(temp_dir.path().to_path_buf()),
            on_disk_payload: false,
            optimizers: OptimizersConfig {
                deleted_threshold: 0.5,
                vacuum_min_vector_number: 100,
                default_segment_number: 1,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: Some(100),
                indexing_threshold: Some(100),
                flush_interval_sec: 2,
                max_optimization_threads: Some(1),
                prevent_unoptimized: None,
            },
            optimizers_overwrite: None,
            wal: Default::default(),
            performance: PerformanceConfig {
                max_search_threads: 1,
                max_optimization_runtime_threads: 1,
                optimizer_cpu_budget: 0,
                optimizer_io_budget: 0,
                update_rate_limit: None,
                search_timeout_sec: None,
                incoming_shard_transfers_limit: Some(1),
                outgoing_shard_transfers_limit: Some(1),
                async_scorer: None,
                load_concurrency: LoadConcurrencyConfig::default(),
            },
            hnsw_index: Default::default(),
            hnsw_global_config: Default::default(),
            mmap_advice: mmap::Advice::Random,
            node_type: Default::default(),
            update_queue_size: Default::default(),
            handle_collection_load_errors: false,
            recovery_mode: None,
            update_concurrency: Some(NonZeroUsize::new(1).unwrap()),
            shard_transfer_method: None,
            collection: None,
            max_collections: None,
        };
        let toc = Arc::new(
            TableOfContent::new(
                &storage_config,
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                Runtime::new().unwrap(),
                ResourceBudget::default(),
                ChannelService::new(6333, false, None, None),
                0,
                None,
            )
            .unwrap(),
        );
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));
        let settings = metadata_value_runtime_settings();
        let metadata_sentinel = "qdrant-sec-metadata-value-sentinel-6f2c9a31";

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "metadata_docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: metadata_value_params().encryption,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "metadata_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                        payload: Some(segment::types::Payload(
                            json!({ "tenant_id": metadata_sentinel, "title": "public" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();

            let raw_records = crate::common::query::do_get_points(
                &toc,
                "metadata_docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap();
            let raw_payload = raw_records[0].payload.as_ref().unwrap();
            assert!(is_encrypted_payload_value(
                raw_payload.0.get("tenant_id").unwrap()
            ));
            assert_eq!(
                raw_payload.0.get("title").and_then(Value::as_str),
                Some("public"),
            );

            let read_only_auth = Auth::new_internal(Access::full_ro("For test"));
            let err = crate::common::query::do_get_points(
                &toc,
                "metadata_docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                read_only_auth,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::Forbidden { description }
                    if description.contains("payload decrypt")
            ));

            let payload_decrypt_auth =
                Auth::new_internal(Access::Collection(CollectionAccessList(vec![
                    CollectionAccess {
                        collection: "metadata_docs".to_string(),
                        access: CollectionAccessMode::Read,
                        payload_decrypt: true,
                        snapshot_export: false,
                        #[expect(deprecated)]
                        payload: None,
                    },
                ])));
            let decrypted_records = crate::common::query::do_get_points(
                &toc,
                "metadata_docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                payload_decrypt_auth,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            let decrypted_payload = decrypted_records[0].payload.as_ref().unwrap();
            assert_eq!(
                decrypted_payload.0.get("tenant_id").and_then(Value::as_str),
                Some(metadata_sentinel),
            );
            assert_eq!(
                decrypted_payload.0.get("title").and_then(Value::as_str),
                Some("public"),
            );

            let decrypted_scroll = crate::common::query::do_scroll_points(
                &toc,
                "metadata_docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_scroll.points[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("tenant_id"))
                    .and_then(Value::as_str),
                Some(metadata_sentinel),
            );

            let decrypted_search = crate::common::query::do_search_points(
                &toc,
                "metadata_docs",
                SearchRequestInternal {
                    vector: vec![0.1, 0.2].into(),
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth,
                None,
                HwMeasurementAcc::disposable(),
                Some(&settings),
            )
            .await
            .unwrap();
            assert_eq!(
                decrypted_search[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get("tenant_id"))
                    .and_then(Value::as_str),
                Some(metadata_sentinel),
            );
        });

        let sentinel = metadata_sentinel.as_bytes();
        for root in [storage_dir.path(), temp_dir.path()] {
            let mut pending = vec![root.to_path_buf()];
            while let Some(path) = pending.pop() {
                let metadata = std::fs::metadata(&path).unwrap();
                if metadata.is_dir() {
                    for entry in std::fs::read_dir(&path).unwrap() {
                        pending.push(entry.unwrap().path());
                    }
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }

                let bytes = std::fs::read(&path).unwrap();
                assert!(
                    !bytes
                        .windows(sentinel.len())
                        .any(|window| window == sentinel),
                    "metadata value plaintext sentinel leaked into {}",
                    path.display(),
                );
            }
        }
    }

    #[test]
    fn payload_write_plan_detects_key_path_overlap_with_encrypted_fields() {
        let settings = payload_runtime_settings();
        let plan =
            payload_write_plan_for_collection_for_test(&settings, "docs", &encrypted_params())
                .unwrap()
                .unwrap();
        let payload =
            segment::types::Payload(json!({ "title": "public" }).as_object().unwrap().clone());
        let encrypted_key = "body".parse::<JsonPath>().unwrap();
        let encrypted_child_key = "body.text".parse::<JsonPath>().unwrap();
        let public_key = "title".parse::<JsonPath>().unwrap();

        assert!(plan.touches_selected_fields(&payload, Some(&encrypted_key)));
        assert!(plan.touches_selected_fields(&payload, Some(&encrypted_child_key)));
        assert!(!plan.touches_selected_fields(&payload, Some(&public_key)));
    }

    #[test]
    fn delete_payload_rejects_encrypted_vector_sidecar_paths() {
        for key in [
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\""),
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\".embedding"),
        ] {
            let key = key.parse::<JsonPath>().unwrap();
            let err = ensure_delete_payload_keys_do_not_touch_encrypted_vector_sidecar(&[key])
                .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { ref description }
                    if description.contains("reserved encrypted vector sidecar payload field")
                        && description.contains("delete_vectors")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));
        }

        ensure_delete_payload_keys_do_not_touch_encrypted_vector_sidecar(&["public"
            .parse::<JsonPath>()
            .unwrap()])
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn do_upsert_points_encrypts_payload_before_storage() {
        if std::env::var_os("QDRANT_SEC_LONG_UPDATE_TEST_STACK").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("common::update::tests::do_upsert_points_encrypts_payload_before_storage")
                .arg("--exact")
                .env("QDRANT_SEC_LONG_UPDATE_TEST_STACK", "1")
                .env("RUST_MIN_STACK", "33554432")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new().prefix("storage").tempdir().unwrap();
        let temp_dir = Builder::new().prefix("storage-temp").tempdir().unwrap();
        let storage_config = StorageConfig {
            storage_path: storage_dir.path().to_path_buf(),
            snapshots_path: storage_dir.path().join("snapshots"),
            snapshots_config: Default::default(),
            temp_path: Some(temp_dir.path().to_path_buf()),
            on_disk_payload: false,
            optimizers: OptimizersConfig {
                deleted_threshold: 0.5,
                vacuum_min_vector_number: 100,
                default_segment_number: 2,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: Some(100),
                indexing_threshold: Some(100),
                flush_interval_sec: 2,
                max_optimization_threads: Some(2),
                prevent_unoptimized: None,
            },
            optimizers_overwrite: None,
            wal: Default::default(),
            performance: PerformanceConfig {
                max_search_threads: 1,
                max_optimization_runtime_threads: 1,
                optimizer_cpu_budget: 0,
                optimizer_io_budget: 0,
                update_rate_limit: None,
                search_timeout_sec: None,
                incoming_shard_transfers_limit: Some(1),
                outgoing_shard_transfers_limit: Some(1),
                async_scorer: None,
                load_concurrency: LoadConcurrencyConfig::default(),
            },
            hnsw_index: Default::default(),
            hnsw_global_config: Default::default(),
            mmap_advice: mmap::Advice::Random,
            node_type: Default::default(),
            update_queue_size: Default::default(),
            handle_collection_load_errors: false,
            recovery_mode: None,
            update_concurrency: Some(NonZeroUsize::new(2).unwrap()),
            shard_transfer_method: None,
            collection: None,
            max_collections: None,
        };
        let search_runtime = Runtime::new().unwrap();
        let update_runtime = Runtime::new().unwrap();
        let general_runtime = Runtime::new().unwrap();
        let toc = Arc::new(
            TableOfContent::new(
                &storage_config,
                search_runtime,
                update_runtime,
                general_runtime,
                ResourceBudget::default(),
                ChannelService::new(6333, false, None, None),
                0,
                None,
            )
            .unwrap(),
        );
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: encrypted_params().encryption,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "vector_docs".to_string(),
                            CreateCollection {
                                vectors: collection::operations::types::VectorsConfig::Multi(
                                    BTreeMap::from([
                                        (
                                            DEFAULT_VECTOR_NAME.to_string(),
                                            VectorParamsBuilder::new(2, Distance::Dot).build(),
                                        ),
                                        (
                                            "plain".to_string(),
                                            VectorParamsBuilder::new(2, Distance::Dot).build(),
                                        ),
                                    ]),
                                ),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a:vector".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 0,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "vector_conf".to_string(),
                                        selector: EncryptionSelector::VectorNames {
                                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                        },
                                        instance: "docs_vector_v1".to_string(),
                                        binding: Some("vector-envelope/v1".to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: Some(Uuid::parse_str(TEST_VECTOR_COLLECTION_CRYPTO_ID).unwrap()),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let bridge = fake_openfhe_bridge();
            let vector_settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([
                            (
                                DEFAULT_VECTOR_NAME.to_string(),
                                api::rest::Vector::Dense(vec![0.7, -0.25]),
                            ),
                            (
                                "plain".to_string(),
                                api::rest::Vector::Dense(vec![0.3, 0.4]),
                            ),
                        ])),
                        payload: Some(segment::types::Payload(
                            json!({ "group": "a" }).as_object().unwrap().clone(),
                        )),
                    }, api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([
                            (
                                DEFAULT_VECTOR_NAME.to_string(),
                                api::rest::Vector::Dense(vec![0.1, 0.2]),
                            ),
                            (
                                "plain".to_string(),
                                api::rest::Vector::Dense(vec![0.5, 0.6]),
                            ),
                        ])),
                        payload: Some(segment::types::Payload(
                            json!({ "group": "b" }).as_object().unwrap().clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Named(HashMap::from([
                            (
                                DEFAULT_VECTOR_NAME.to_string(),
                                api::rest::Vector::Dense(vec![0.7, -0.25]),
                            ),
                            (
                                "plain".to_string(),
                                api::rest::Vector::Dense(vec![0.3, 0.4]),
                            ),
                        ])),
                        payload: Some(segment::types::Payload(
                            json!({ "group": "a" }).as_object().unwrap().clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();

            let vector_collection_pass = auth
                .check_collection_access("vector_docs", AccessRequirements::new(), "test")
                .unwrap();
            let vector_collection = toc.get_collection(&vector_collection_pass).await.unwrap();
            let retrieved = vector_collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let sidecar = retrieved[0]
                .payload
                .as_ref()
                .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                .and_then(Value::as_object)
                .unwrap();
            let encrypted_default_vector = sidecar.get(DEFAULT_VECTOR_NAME).unwrap();
            assert!(is_encrypted_ckks_vector_payload_value(encrypted_default_vector));
            let serialized_vector_payload = serde_json::to_string(&retrieved[0].payload).unwrap();
            assert!(!serialized_vector_payload.contains("0.7"));
            assert!(!serialized_vector_payload.contains("-0.25"));

            let err = do_delete_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                DeletePayload {
                    keys: vec![format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
                        .parse()
                        .unwrap()],
                    points: Some(vec![1.into()]),
                    filter: None,
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { ref description }
                    if description.contains("reserved encrypted vector sidecar payload field")
                        && description.contains("delete_vectors")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let err = do_clear_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                PointsSelector::PointIdsSelector(PointIdsList {
                    points: vec![1.into()],
                    shard_key: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { ref description }
                    if description.contains("cannot clear payloads")
                        && description.contains("delete_vectors")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
                        && !description.contains("vector_docs")
            ));

            let plaintext_vector_patterns = [
                vec![0.7_f32, -0.25]
                    .into_iter()
                    .flat_map(f32::to_le_bytes)
                    .collect::<Vec<_>>(),
                vec![0.1_f32, 0.2]
                    .into_iter()
                    .flat_map(f32::to_le_bytes)
                    .collect::<Vec<_>>(),
                vec![0.7_f64, -0.25]
                    .into_iter()
                    .flat_map(f64::to_le_bytes)
                    .collect::<Vec<_>>(),
                vec![0.1_f64, 0.2]
                    .into_iter()
                    .flat_map(f64::to_le_bytes)
                    .collect::<Vec<_>>(),
            ];
            for (root_label, root_path) in [
                ("storage", storage_dir.path()),
                ("temp", temp_dir.path()),
            ] {
                let mut files = vec![root_path.to_path_buf()];
                while let Some(path) = files.pop() {
                    if path.is_dir() {
                        for entry in fs::read_dir(&path).unwrap() {
                            files.push(entry.unwrap().path());
                        }
                        continue;
                    }
                    let bytes = fs::read(&path).unwrap_or_default();
                    for pattern in &plaintext_vector_patterns {
                        assert!(
                            !bytes.windows(pattern.len()).any(|window| window == pattern),
                            "plaintext vector byte pattern leaked into {root_label} path {}",
                            path.display(),
                        );
                    }
                }
            }

            let err = crate::common::query::do_get_points(
                &toc,
                "vector_docs",
                PointRequestInternal {
                    ids: vec![1.into()],
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Selector(vec![DEFAULT_VECTOR_NAME.to_string()]),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot retrieve encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::tonic::api::query_common::get(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::GetPoints {
                    collection_name: "vector_docs".to_string(),
                    ids: vec![segment::types::PointIdType::from(1).into()],
                    with_payload: None,
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    read_consistency: None,
                    shard_key_selector: None,
                    timeout: None,
                },
                None,
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                None,
            )
            .await
            .unwrap_err();
            assert!(
                err.message()
                    .contains("cannot retrieve encrypted vector")
            );

            let err = crate::common::query::do_scroll_points(
                &toc,
                "vector_docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(true),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot scroll encrypted vectors")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::tonic::api::query_common::scroll(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::ScrollPoints {
                    collection_name: "vector_docs".to_string(),
                    filter: None,
                    offset: None,
                    limit: Some(1),
                    with_payload: None,
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    read_consistency: None,
                    shard_key_selector: None,
                    order_by: None,
                    timeout: None,
                },
                None,
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                None,
            )
            .await
            .unwrap_err();
            assert!(err.message().contains("cannot scroll encrypted vector"));

            let err = crate::tonic::api::query_common::recommend(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::RecommendPoints {
                    collection_name: "vector_docs".to_string(),
                    positive: vec![segment::types::PointIdType::from(1).into()],
                    negative: Vec::new(),
                    filter: None,
                    limit: 1,
                    with_payload: None,
                    params: None,
                    score_threshold: None,
                    offset: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    lookup_from: None,
                    read_consistency: None,
                    strategy: None,
                    positive_vectors: Vec::new(),
                    negative_vectors: Vec::new(),
                    timeout: None,
                    shard_key_selector: None,
                },
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(
                err.message().contains("cannot return encrypted vector")
                    && err.message().contains("payload sidecar only")
            );

            let err = crate::tonic::api::query_common::recommend_groups(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::RecommendPointGroups {
                    collection_name: "vector_docs".to_string(),
                    positive: vec![segment::types::PointIdType::from(1).into()],
                    negative: Vec::new(),
                    filter: None,
                    limit: 1,
                    with_payload: None,
                    params: None,
                    score_threshold: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    lookup_from: None,
                    group_by: "group".to_string(),
                    group_size: 1,
                    read_consistency: None,
                    with_lookup: None,
                    strategy: None,
                    positive_vectors: Vec::new(),
                    negative_vectors: Vec::new(),
                    timeout: None,
                    shard_key_selector: None,
                },
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(
                err.message().contains("cannot return encrypted vector")
                    && err.message().contains("payload sidecar only")
            );

            let err = crate::tonic::api::query_common::discover(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::DiscoverPoints {
                    collection_name: "vector_docs".to_string(),
                    target: Some(api::grpc::qdrant::TargetVector {
                        target: Some(api::grpc::qdrant::target_vector::Target::Single(
                            api::grpc::qdrant::VectorExample {
                                example: Some(
                                    api::grpc::qdrant::vector_example::Example::Id(
                                        segment::types::PointIdType::from(1).into(),
                                    ),
                                ),
                            },
                        )),
                    }),
                    context: Vec::new(),
                    filter: None,
                    limit: 1,
                    with_payload: None,
                    params: None,
                    offset: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    lookup_from: None,
                    read_consistency: None,
                    timeout: None,
                    shard_key_selector: None,
                },
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(
                err.message().contains("cannot return encrypted vector")
                    && err.message().contains("payload sidecar only")
            );

            let err = crate::tonic::api::query_common::recommend_batch(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs",
                vec![api::grpc::qdrant::RecommendPoints {
                    collection_name: "vector_docs".to_string(),
                    positive: vec![segment::types::PointIdType::from(1).into()],
                    negative: Vec::new(),
                    filter: None,
                    limit: 1,
                    with_payload: None,
                    params: None,
                    score_threshold: None,
                    offset: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    lookup_from: None,
                    read_consistency: None,
                    strategy: None,
                    positive_vectors: Vec::new(),
                    negative_vectors: Vec::new(),
                    timeout: None,
                    shard_key_selector: None,
                }],
                None,
                auth.clone(),
                None,
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(
                err.message().contains("cannot return encrypted vector")
                    && err.message().contains("payload sidecar only")
            );

            let err = crate::tonic::api::query_common::discover_batch(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs",
                vec![api::grpc::qdrant::DiscoverPoints {
                    collection_name: "vector_docs".to_string(),
                    target: Some(api::grpc::qdrant::TargetVector {
                        target: Some(api::grpc::qdrant::target_vector::Target::Single(
                            api::grpc::qdrant::VectorExample {
                                example: Some(
                                    api::grpc::qdrant::vector_example::Example::Id(
                                        segment::types::PointIdType::from(1).into(),
                                    ),
                                ),
                            },
                        )),
                    }),
                    context: Vec::new(),
                    filter: None,
                    limit: 1,
                    with_payload: None,
                    params: None,
                    offset: None,
                    using: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    lookup_from: None,
                    read_consistency: None,
                    timeout: None,
                    shard_key_selector: None,
                }],
                None,
                auth.clone(),
                None,
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(
                err.message().contains("cannot return encrypted vector")
                    && err.message().contains("payload sidecar only")
            );

            let err = crate::common::query::do_search_points_matrix(
                &toc,
                "vector_docs",
                collection::collection::distance_matrix::CollectionSearchMatrixRequest {
                    filter: None,
                    sample_size: 2,
                    limit_per_sample: 2,
                    using: DEFAULT_VECTOR_NAME.to_string(),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot search matrix using encrypted vector")
                        && description.contains("runtime OpenFHE settings are required")
            ));

            let sidecar_filter = Filter::new_must(Condition::Field(FieldCondition::new_match(
                format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
                    .parse()
                    .unwrap(),
                serde_json::from_str(r#"{ "value": "client-controlled sidecar" }"#).unwrap(),
            )));
            let err = crate::common::query::do_search_points_matrix(
                &toc,
                "vector_docs",
                collection::collection::distance_matrix::CollectionSearchMatrixRequest {
                    filter: Some(sidecar_filter),
                    sample_size: 2,
                    limit_per_sample: 1,
                    using: DEFAULT_VECTOR_NAME.to_string(),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { ref description }
                    if description.contains("cannot filter on encrypted vector sidecar field")
                        && !description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));

            let matrix = crate::common::query::do_search_points_matrix(
                &toc,
                "vector_docs",
                collection::collection::distance_matrix::CollectionSearchMatrixRequest {
                    filter: None,
                    sample_size: 2,
                    limit_per_sample: 1,
                    using: DEFAULT_VECTOR_NAME.to_string(),
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(matrix.sample_ids, vec![1.into(), 2.into()]);
            assert_eq!(matrix.nearests.len(), 2);
            assert_eq!(matrix.nearests[0][0].id, 2.into());
            assert!(
                matrix.nearests[0][0].version > 0,
                "CKKS matrix search must preserve nearest point versions"
            );
            assert_eq!(matrix.nearests[0][0].score, 8.0);
            assert_eq!(matrix.nearests[1][0].id, 1.into());
            assert!(
                matrix.nearests[1][0].version > 0,
                "CKKS matrix search must preserve nearest point versions"
            );
            assert_eq!(matrix.nearests[1][0].score, 8.0);

            let grpc_matrix = crate::tonic::api::query_common::search_points_matrix(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::SearchMatrixPoints {
                    collection_name: "vector_docs".to_string(),
                    filter: None,
                    sample: Some(2),
                    limit: Some(2),
                    using: Some(DEFAULT_VECTOR_NAME.to_string()),
                    read_consistency: None,
                    shard_key_selector: None,
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(grpc_matrix.sample_ids, vec![1.into(), 2.into()]);
            assert_eq!(grpc_matrix.nearests.len(), 2);

            let err = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(true)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot search encrypted vectors")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(true),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot query encrypted vectors")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_recommend_points(
                &toc,
                "vector_docs",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(true)),
                    score_threshold: None,
                    using: None,
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot recommend encrypted vectors")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_recommend_points(
                &toc,
                "vector_docs",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Selector(vec![
                        DEFAULT_VECTOR_NAME.to_string(),
                    ])),
                    score_threshold: None,
                    using: None,
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot recommend encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_discover_points(
                &toc,
                "vector_docs",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(true)),
                    using: None,
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot discover encrypted vectors")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_discover_points(
                &toc,
                "vector_docs",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Selector(vec![
                        DEFAULT_VECTOR_NAME.to_string(),
                    ])),
                    using: None,
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot discover encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_search_point_groups(
                &toc,
                "vector_docs",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(true)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot search groups encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_search_point_groups(
                &toc,
                "vector_docs",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Selector(vec![
                        DEFAULT_VECTOR_NAME.to_string(),
                    ])),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot search groups encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_query_point_groups(
                &toc,
                "vector_docs",
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(true),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot query groups encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_query_point_groups(
                &toc,
                "vector_docs",
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Selector(vec![DEFAULT_VECTOR_NAME.to_string()]),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot query groups encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_docs",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(true)),
                    score_threshold: None,
                    using: None,
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot recommend groups encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let err = crate::common::query::do_recommend_point_groups(
                &toc,
                "vector_docs",
                RecommendGroupsRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Selector(vec![
                        DEFAULT_VECTOR_NAME.to_string(),
                    ])),
                    score_threshold: None,
                    using: None,
                    lookup_from: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot recommend groups encrypted vector")
                        && description.contains("payload sidecar only")
            ));

            let search_result = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(search_result.len(), 1);
            assert_eq!(search_result[0].id, 1.into());
            assert!(
                search_result[0].version > 0,
                "CKKS sidecar search must preserve the updated point version"
            );
            assert_eq!(search_result[0].score, 9.0);

            let hnsw_search_result = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![1.0, 1.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: Some(SearchParams {
                        hnsw_ef: Some(128),
                        ..SearchParams::default()
                    }),
                    limit: 2,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(hnsw_search_result.len(), 2);
            assert_eq!(hnsw_search_result[0].id, 2.into());
            assert_eq!(hnsw_search_result[0].score, 7.0);
            assert_eq!(hnsw_search_result[1].id, 1.into());
            assert_eq!(hnsw_search_result[1].score, 1.0);

            let hnsw_graph_search_result = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: Some(SearchParams {
                        hnsw_ef: Some(1),
                        ..SearchParams::default()
                    }),
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(hnsw_graph_search_result.len(), 1);
            let hnsw_graph_candidate = &hnsw_graph_search_result[0];
            assert!(
                (hnsw_graph_candidate.id == 1.into() && hnsw_graph_candidate.score == 9.0)
                    || (hnsw_graph_candidate.id == 2.into() && hnsw_graph_candidate.score == 4.0),
                "CKKS HNSW search is approximate with ef=1 and should only score the selected graph candidate"
            );
            assert!(
                hnsw_graph_candidate.version > 0,
                "CKKS HNSW sidecar search must preserve the updated point version"
            );

            let mut zero_trust_vector_settings = vector_settings.clone();
            let zero_trust_options = zero_trust_vector_settings
                .crypto
                .instances
                .get_mut("docs_vector_v1")
                .unwrap()
                .options
                .as_object_mut()
                .unwrap();
            zero_trust_options.remove("allow_plaintext_queries");
            zero_trust_options.remove("plaintext_query_tcb_ack");

            let err = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&zero_trust_vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("does not allow plaintext query vectors")
            ));

            let err = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&zero_trust_vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("does not allow plaintext query vectors")
            ));

            let err = crate::common::query::do_recommend_points(
                &toc,
                "vector_docs",
                RecommendRequestInternal {
                    positive: vec![RecommendExample::Dense(vec![0.0, 0.0])],
                    negative: Vec::new(),
                    strategy: Some(api::rest::RecommendStrategy::AverageVector),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    using: None,
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&zero_trust_vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("does not allow plaintext query vectors")
            ));

            let err = crate::common::query::do_discover_points(
                &toc,
                "vector_docs",
                DiscoverRequestInternal {
                    target: Some(RecommendExample::Dense(vec![0.0, 0.0])),
                    context: None,
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    using: None,
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&zero_trust_vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("does not allow plaintext query vectors")
            ));

            for params in [
                SearchParams {
                    indexed_only: true,
                    ..SearchParams::default()
                },
                SearchParams {
                    quantization: Some(segment::types::QuantizationSearchParams::default()),
                    ..SearchParams::default()
                },
                SearchParams {
                    acorn: Some(segment::types::AcornSearchParams::default()),
                    ..SearchParams::default()
                },
            ] {
                let err = crate::common::query::do_core_search_points(
                    &toc,
                    "vector_docs",
                    SearchRequestInternal {
                        vector: vec![0.0, 0.0].into(),
                        with_payload: Some(WithPayloadInterface::Bool(false)),
                        with_vector: Some(WithVector::Bool(false)),
                        filter: None,
                        params: Some(params),
                        limit: 1,
                        offset: None,
                        score_threshold: None,
                    }
                    .into(),
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    Some(&vector_settings),
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::BadInput { ref description }
                        if description.contains(
                            "does not support quantization, indexed_only, or ACORN search params"
                        )
                        && !description.contains("encrypted vector '")
                ));
            }

            let point_id_hnsw_query_result = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(
                        2.into(),
                    )))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: Some(SearchParams {
                        hnsw_ef: Some(128),
                        ..SearchParams::default()
                    }),
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(point_id_hnsw_query_result.len(), 1);
            assert_eq!(point_id_hnsw_query_result[0].id, 2.into());
            assert_eq!(point_id_hnsw_query_result[0].score, 10.0);

            let vector_cache_dir = vector_collection.path().join("ckks_sidecar_hnsw_graphs");
            if vector_cache_dir.exists() {
                assert!(
                    fs::read_dir(&vector_cache_dir)
                        .unwrap()
                        .any(|entry| entry
                            .unwrap()
                            .path()
                            .extension()
                            .and_then(|extension| extension.to_str())
                            .is_some_and(|extension| extension == "json")),
                    "CKKS sidecar HNSW graph cache directory exists without a graph cache file",
                );
            }

            let search_with_payload = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(search_with_payload.len(), 1);
            let returned_sidecar = search_with_payload[0]
                .payload
                .as_ref()
                .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                .and_then(Value::as_object)
                .unwrap()
                .get(DEFAULT_VECTOR_NAME)
                .unwrap();
            assert!(is_encrypted_ckks_vector_payload_value(returned_sidecar));
            assert!(search_with_payload[0].vector.is_none());

            let threshold_result = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 2,
                    offset: None,
                    score_threshold: Some(5.0),
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(threshold_result.len(), 1);
            assert_eq!(threshold_result[0].id, 1.into());
            assert_eq!(threshold_result[0].score, 9.0);

            let batch_with_payload = crate::common::query::do_search_batch_points(
                &toc,
                "vector_docs",
                vec![
                    (
                        SearchRequestInternal {
                            vector: vec![0.0, 0.0].into(),
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: Some(WithVector::Bool(false)),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            score_threshold: None,
                        }
                        .into(),
                        ShardSelectorInternal::All,
                    ),
                    (
                        SearchRequestInternal {
                            vector: vec![0.0, 0.0].into(),
                            with_payload: Some(WithPayloadInterface::Bool(true)),
                            with_vector: Some(WithVector::Bool(false)),
                            filter: None,
                            params: None,
                            limit: 1,
                            offset: None,
                            score_threshold: Some(5.0),
                        }
                        .into(),
                        ShardSelectorInternal::All,
                    ),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(batch_with_payload.len(), 2);
            for batch_result in &batch_with_payload {
                assert_eq!(batch_result.len(), 1);
                assert_eq!(batch_result[0].id, 1.into());
                let returned_sidecar = batch_result[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                    .and_then(Value::as_object)
                    .unwrap()
                    .get(DEFAULT_VECTOR_NAME)
                    .unwrap();
                assert!(is_encrypted_ckks_vector_payload_value(returned_sidecar));
                assert!(batch_result[0].vector.is_none());
            }

            let query_result = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(query_result.len(), 1);
            assert_eq!(query_result[0].id, 1.into());
            assert_eq!(query_result[0].score, 9.0);

            let client_encrypted_query = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(fake_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(client_encrypted_query.len(), 1);
            assert_eq!(client_encrypted_query[0].id, 1.into());
            assert_eq!(client_encrypted_query[0].score, 9.0);

            let client_encrypted_hnsw_query = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(fake_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: Some(SearchParams {
                        hnsw_ef: Some(1),
                        ..SearchParams::default()
                    }),
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(client_encrypted_hnsw_query.len(), 1);
            let client_hnsw_candidate = &client_encrypted_hnsw_query[0];
            assert!(
                (client_hnsw_candidate.id == 1.into() && client_hnsw_candidate.score == 9.0)
                    || (client_hnsw_candidate.id == 2.into()
                        && client_hnsw_candidate.score == 4.0),
                "CKKS HNSW search is approximate with ef=1 and should only score the selected graph candidate"
            );

            for params in [
                SearchParams {
                    indexed_only: true,
                    ..SearchParams::default()
                },
                SearchParams {
                    quantization: Some(segment::types::QuantizationSearchParams::default()),
                    ..SearchParams::default()
                },
                SearchParams {
                    acorn: Some(segment::types::AcornSearchParams::default()),
                    ..SearchParams::default()
                },
            ] {
                let err = crate::common::query::do_query_points(
                    &toc,
                    "vector_docs",
                    CollectionQueryRequest {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::CkksEncryptedQuery(fake_ckks_client_query(
                                b"fake-ckks-query:2",
                                2,
                            )),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        offset: 0,
                        params: Some(params),
                        with_vector: WithVector::Bool(false),
                        with_payload: WithPayloadInterface::Bool(false),
                        lookup_from: None,
                    },
                    None,
                    ShardSelectorInternal::All,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    Some(&vector_settings),
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::BadInput { ref description }
                        if description.contains(
                            "does not support quantization, indexed_only, or ACORN search params"
                        )
                        && !description.contains("encrypted vector '")
                ));
            }

            let legacy_client_encrypted_search = crate::common::query::do_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: fake_rest_named_ckks_client_query(b"fake-ckks-query:2", 2),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(legacy_client_encrypted_search.len(), 1);
            assert_eq!(legacy_client_encrypted_search[0].id, 1.into());
            assert_eq!(legacy_client_encrypted_search[0].score, 9.0);

            let legacy_client_encrypted_hnsw_search = crate::common::query::do_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: fake_rest_named_ckks_client_query(b"fake-ckks-query:2", 2),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: Some(SearchParams {
                        hnsw_ef: Some(1),
                        ..SearchParams::default()
                    }),
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(legacy_client_encrypted_hnsw_search.len(), 1);
            let legacy_hnsw_candidate = &legacy_client_encrypted_hnsw_search[0];
            assert!(
                (legacy_hnsw_candidate.id == 1.into() && legacy_hnsw_candidate.score == 9.0)
                    || (legacy_hnsw_candidate.id == 2.into() && legacy_hnsw_candidate.score == 4.0),
                "CKKS HNSW search is approximate with ef=1 and should only score the selected graph candidate"
            );

            let hnsw_no_full_scan_query = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(fake_ckks_client_query(
                            b"fake-ckks-query:no-full-scan",
                            2,
                        )),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: Some(SearchParams {
                        hnsw_ef: Some(1),
                        ..SearchParams::default()
                    }),
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(hnsw_no_full_scan_query.len(), 1);
            let hnsw_candidate = &hnsw_no_full_scan_query[0];
            assert!(
                (hnsw_candidate.id == 1.into() && hnsw_candidate.score == 9.0)
                    || (hnsw_candidate.id == 2.into() && hnsw_candidate.score == 4.0),
                "CKKS HNSW search should score only the approximate candidate set, not full-scan all sidecars"
            );

            let legacy_client_encrypted_batch =
                crate::common::query::do_search_batch_points_from_rest(
                    &toc,
                    "vector_docs",
                    vec![
                        (
                            SearchRequestInternal {
                                vector: fake_rest_named_ckks_client_query(
                                    b"fake-ckks-query:2",
                                    2,
                                ),
                                with_payload: Some(WithPayloadInterface::Bool(false)),
                                with_vector: Some(WithVector::Bool(false)),
                                filter: None,
                                params: None,
                                limit: 1,
                                offset: None,
                                score_threshold: None,
                            },
                            ShardSelectorInternal::All,
                        ),
                        (
                            SearchRequestInternal {
                                vector: vec![0.0, 0.0].into(),
                                with_payload: Some(WithPayloadInterface::Bool(false)),
                                with_vector: Some(WithVector::Bool(false)),
                                filter: None,
                                params: None,
                                limit: 1,
                                offset: None,
                                score_threshold: Some(5.0),
                            },
                            ShardSelectorInternal::All,
                        ),
                    ],
                    None,
                    auth.clone(),
                    None,
                    HwMeasurementAcc::disposable(),
                    Some(&vector_settings),
                )
                .await
                .unwrap();
            assert_eq!(legacy_client_encrypted_batch.len(), 2);
            for batch_result in &legacy_client_encrypted_batch {
                assert_eq!(batch_result.len(), 1);
                assert_eq!(batch_result[0].id, 1.into());
                assert_eq!(batch_result[0].score, 9.0);
            }

            let client_encrypted_query_groups = crate::common::query::do_query_point_groups(
                &toc,
                "vector_docs",
                CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(fake_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(client_encrypted_query_groups.groups.len(), 1);
            assert_eq!(
                client_encrypted_query_groups.groups[0].hits[0].id,
                1.into()
            );
            assert_eq!(client_encrypted_query_groups.groups[0].hits[0].score, 9.0);

            let legacy_client_encrypted_groups = crate::common::query::do_search_point_groups(
                &toc,
                "vector_docs",
                SearchGroupsRequestInternal {
                    vector: fake_rest_named_ckks_client_query(b"fake-ckks-query:2", 2),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: Some(WithVector::Bool(false)),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    group_request: api::rest::BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(legacy_client_encrypted_groups.groups.len(), 1);
            assert_eq!(
                legacy_client_encrypted_groups.groups[0].hits[0].id,
                1.into()
            );
            assert_eq!(legacy_client_encrypted_groups.groups[0].hits[0].score, 9.0);

            let grpc_client_encrypted_search = crate::tonic::api::query_common::search(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::SearchPoints {
                    collection_name: "vector_docs".to_string(),
                    limit: 1,
                    vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                    ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                        b"fake-ckks-query:2",
                        2,
                    )),
                    ..Default::default()
                },
                None,
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(grpc_client_encrypted_search.result.len(), 1);
            assert_eq!(
                grpc_client_encrypted_search.result[0].id,
                Some(segment::types::PointIdType::from(1).into())
            );
            assert_eq!(grpc_client_encrypted_search.result[0].score, 9.0);

            let grpc_with_vector_selector_err = crate::tonic::api::query_common::search(
                UncheckedTocProvider::new_unchecked(&toc),
                api::grpc::qdrant::SearchPoints {
                    collection_name: "vector_docs".to_string(),
                    limit: 1,
                    vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                    with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                        selector_options: Some(
                            api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                api::grpc::qdrant::VectorsSelector {
                                    names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                },
                            ),
                        ),
                    }),
                    ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                        b"fake-ckks-query:2",
                        2,
                    )),
                    ..Default::default()
                },
                None,
                auth.clone(),
                storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                    HwMeasurementAcc::disposable(),
                    false,
                ),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(
                grpc_with_vector_selector_err
                    .message()
                    .contains("cannot return encrypted vector")
            );

            for params in [
                api::grpc::qdrant::SearchParams {
                    indexed_only: Some(true),
                    ..Default::default()
                },
                api::grpc::qdrant::SearchParams {
                    quantization: Some(api::grpc::qdrant::QuantizationSearchParams::default()),
                    ..Default::default()
                },
                api::grpc::qdrant::SearchParams {
                    acorn: Some(api::grpc::qdrant::AcornSearchParams::default()),
                    ..Default::default()
                },
            ] {
                let err = crate::tonic::api::query_common::search(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPoints {
                        collection_name: "vector_docs".to_string(),
                        limit: 1,
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        params: Some(params),
                        ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
                        ..Default::default()
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    Some(&vector_settings),
                )
                .await
                .unwrap_err();
                assert!(
                    err.message()
                        .contains("does not support quantization, indexed_only, or ACORN")
                );
                assert!(!err.message().contains("encrypted vector '"));
            }

            let grpc_conflicting_query = api::rest::SearchRequestInternal::try_from(
                api::grpc::qdrant::SearchPoints {
                    collection_name: "vector_docs".to_string(),
                    vector: vec![0.0, 0.0],
                    limit: 1,
                    vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                    ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                        b"fake-ckks-query:2",
                        2,
                    )),
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert!(
                grpc_conflicting_query
                    .message()
                    .contains("cannot be combined with raw vector")
            );

            let grpc_client_encrypted_batch =
                crate::tonic::api::query_common::search_batch_from_grpc(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "vector_docs",
                    vec![
                        (
                            api::rest::SearchRequestInternal::try_from(
                                api::grpc::qdrant::SearchPoints {
                                    collection_name: "vector_docs".to_string(),
                                    limit: 1,
                                    vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                                    ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                                        b"fake-ckks-query:2",
                                        2,
                                    )),
                                    ..Default::default()
                                },
                            )
                            .unwrap(),
                            ShardSelectorInternal::All,
                        ),
                        (
                            api::rest::SearchRequestInternal::try_from(
                                api::grpc::qdrant::SearchPoints {
                                    collection_name: "vector_docs".to_string(),
                                    vector: vec![0.0, 0.0],
                                    limit: 1,
                                    score_threshold: Some(5.0),
                                    vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                                    ..Default::default()
                                },
                            )
                            .unwrap(),
                            ShardSelectorInternal::All,
                        ),
                    ],
                    None,
                    auth.clone(),
                    None,
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    Some(&vector_settings),
                )
                .await
                .unwrap()
                .into_inner();
            assert_eq!(grpc_client_encrypted_batch.result.len(), 2);
            for batch_result in &grpc_client_encrypted_batch.result {
                assert_eq!(batch_result.result.len(), 1);
                assert_eq!(
                    batch_result.result[0].id,
                    Some(segment::types::PointIdType::from(1).into())
                );
                assert_eq!(batch_result.result[0].score, 9.0);
            }

            let grpc_client_encrypted_groups =
                crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: "vector_docs".to_string(),
                        limit: 1,
                        group_size: 1,
                        group_by: "group".to_string(),
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
                        ..Default::default()
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    Some(&vector_settings),
                )
                .await
                .unwrap()
                .into_inner();
            let grpc_groups = grpc_client_encrypted_groups.result.unwrap().groups;
            assert_eq!(grpc_groups.len(), 1);
            assert_eq!(
                grpc_groups[0].hits[0].id,
                Some(segment::types::PointIdType::from(1).into())
            );
            assert_eq!(grpc_groups[0].hits[0].score, 9.0);

            let grpc_group_with_vector_selector_err =
                crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: "vector_docs".to_string(),
                        limit: 1,
                        group_size: 1,
                        group_by: "group".to_string(),
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        with_vectors: Some(api::grpc::qdrant::WithVectorsSelector {
                            selector_options: Some(
                                api::grpc::qdrant::with_vectors_selector::SelectorOptions::Include(
                                    api::grpc::qdrant::VectorsSelector {
                                        names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                    },
                                ),
                            ),
                        }),
                        ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
                        ..Default::default()
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    Some(&vector_settings),
                )
                .await
                .unwrap_err();
            assert!(
                grpc_group_with_vector_selector_err
                    .message()
                    .contains("cannot return encrypted vector")
            );

            for params in [
                api::grpc::qdrant::SearchParams {
                    indexed_only: Some(true),
                    ..Default::default()
                },
                api::grpc::qdrant::SearchParams {
                    quantization: Some(api::grpc::qdrant::QuantizationSearchParams::default()),
                    ..Default::default()
                },
                api::grpc::qdrant::SearchParams {
                    acorn: Some(api::grpc::qdrant::AcornSearchParams::default()),
                    ..Default::default()
                },
            ] {
                let err = crate::tonic::api::query_common::search_groups(
                    UncheckedTocProvider::new_unchecked(&toc),
                    api::grpc::qdrant::SearchPointGroups {
                        collection_name: "vector_docs".to_string(),
                        limit: 1,
                        group_size: 1,
                        group_by: "group".to_string(),
                        vector_name: Some(DEFAULT_VECTOR_NAME.to_string()),
                        params: Some(params),
                        ckks_encrypted_query: Some(fake_grpc_ckks_client_query(
                            b"fake-ckks-query:2",
                            2,
                        )),
                        ..Default::default()
                    },
                    None,
                    auth.clone(),
                    storage::content_manager::toc::request_hw_counter::RequestHwCounter::new(
                        HwMeasurementAcc::disposable(),
                        false,
                    ),
                    Some(&vector_settings),
                )
                .await
                .unwrap_err();
                assert!(
                    err.message()
                        .contains("does not support quantization, indexed_only, or ACORN")
                );
                assert!(!err.message().contains("encrypted vector '"));
            }

            let mut wrong_context_query = fake_ckks_client_query(b"fake-ckks-query:2", 2);
            wrong_context_query.context_digest = BASE64URL_NOPAD.encode(&[9u8; 32]);
            let err = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(wrong_context_query),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted query context digest does not match")
            ));

            let query_with_payload = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(true),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(query_with_payload.len(), 1);
            let returned_sidecar = query_with_payload[0]
                .payload
                .as_ref()
                .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                .and_then(Value::as_object)
                .unwrap()
                .get(DEFAULT_VECTOR_NAME)
                .unwrap();
            assert!(is_encrypted_ckks_vector_payload_value(returned_sidecar));
            assert!(query_with_payload[0].vector.is_none());

            let batch_query_with_payload = crate::common::query::do_query_batch_points(
                &toc,
                "vector_docs",
                vec![
                    (
                        CollectionQueryRequest {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            offset: 0,
                            params: None,
                            with_vector: WithVector::Bool(false),
                            with_payload: WithPayloadInterface::Bool(true),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                    (
                        CollectionQueryRequest {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: Some(5.0),
                            limit: 1,
                            offset: 0,
                            params: None,
                            with_vector: WithVector::Bool(false),
                            with_payload: WithPayloadInterface::Bool(true),
                            lookup_from: None,
                        },
                        ShardSelectorInternal::All,
                    ),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(batch_query_with_payload.len(), 2);
            for batch_result in &batch_query_with_payload {
                assert_eq!(batch_result.len(), 1);
                assert_eq!(batch_result[0].id, 1.into());
                let returned_sidecar = batch_result[0]
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                    .and_then(Value::as_object)
                    .unwrap()
                    .get(DEFAULT_VECTOR_NAME)
                    .unwrap();
                assert!(is_encrypted_ckks_vector_payload_value(returned_sidecar));
                assert!(batch_result[0].vector.is_none());
            }

            let mut wrong_context_settings =
                vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
            wrong_context_settings
                .crypto
                .instances
                .get_mut("docs_vector_v1")
                .unwrap()
                .options["crypto_context_b64"] =
                json!(BASE64URL_NOPAD.encode(b"different openfhe context"));
            let err = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&wrong_context_settings),
            )
            .await
            .unwrap_err();
            let description = match &err {
                StorageError::BadInput { description }
                | StorageError::ServiceError { description, .. } => description,
                _ => panic!("unexpected error: {err:?}"),
            };
            assert!(
                description.contains("context digest does not match")
                    || description.contains("encrypted-query batch scoring failed"),
                "unexpected error: {err:?}",
            );

            let mut wrong_public_key_settings =
                vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
            wrong_public_key_settings
                .crypto
                .instances
                .get_mut("docs_vector_v1")
                .unwrap()
                .options["public_key_b64"] =
                json!(BASE64URL_NOPAD.encode(b"different openfhe public key"));
            let err = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&wrong_public_key_settings),
            )
            .await
            .unwrap_err();
            let description = match &err {
                StorageError::BadInput { description }
                | StorageError::ServiceError { description, .. } => description,
                _ => panic!("unexpected error: {err:?}"),
            };
            assert!(
                description.contains("context digest does not match")
                    || description.contains("encrypted-query batch scoring failed"),
                "unexpected error: {err:?}",
            );

            let err = crate::common::query::do_search_point_groups(
                &toc,
                "vector_docs",
                SearchGroupsRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    filter: None,
                    params: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    score_threshold: None,
                    group_request: BaseGroupRequest {
                        group_by: "group".parse().unwrap(),
                        group_size: 1,
                        limit: 1,
                        with_lookup: None,
                    },
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted vector")
                        && description.contains("runtime OpenFHE settings are required")
            ));

            let err = crate::common::query::do_query_point_groups(
                &toc,
                "vector_docs",
                collection::operations::universal_query::collection_query::CollectionQueryGroupsRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    params: None,
                    score_threshold: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                    group_by: "group".parse().unwrap(),
                    group_size: 1,
                    limit: 1,
                    with_lookup: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted vector")
                        && description.contains("runtime OpenFHE settings are required")
            ));

            let err = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(true),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot return encrypted vector")
            ));

            let err = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: Vec::new(),
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Selector(vec![DEFAULT_VECTOR_NAME.to_string()]),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot return encrypted vector")
            ));

            let encrypted_query = CollectionQueryRequest {
                prefetch: Vec::new(),
                query: Some(Query::Vector(VectorQuery::Nearest(
                    VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
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
            };
            let plaintext_query = CollectionQueryRequest {
                prefetch: Vec::new(),
                query: Some(Query::Vector(VectorQuery::Nearest(
                    VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                ))),
                using: "plain".to_string(),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
                lookup_from: None,
            };
            let mixed_query = crate::common::query::do_query_batch_points(
                &toc,
                "vector_docs",
                vec![
                    (encrypted_query, ShardSelectorInternal::All),
                    (plaintext_query, ShardSelectorInternal::All),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mixed_query.len(), 2);
            assert_eq!(mixed_query[0][0].id, 1.into());
            assert_eq!(mixed_query[0][0].score, 9.0);
            assert_eq!(mixed_query[1][0].id, 2.into());
            assert_eq!(mixed_query[1][0].score, 0.5);

            let fusion_query = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: vec![
                        CollectionPrefetch {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 2,
                            params: None,
                            lookup_from: None,
                        },
                        CollectionPrefetch {
                            prefetch: Vec::new(),
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                            ))),
                            using: "plain".to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        },
                    ],
                    query: Some(Query::Fusion(FusionInternal::Rrf {
                        k: 2,
                        weights: None,
                    })),
                    using: String::new(),
                    filter: None,
                    score_threshold: None,
                    limit: 2,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(fusion_query.len(), 2);
            assert_eq!(fusion_query[0].id, 2.into());
            assert!(fusion_query[0].score > fusion_query[1].score);
            assert_eq!(fusion_query[1].id, 1.into());

            let prefetched_query = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
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
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(prefetched_query.len(), 1);
            assert_eq!(prefetched_query[0].id, 1.into());
            assert_eq!(prefetched_query[0].score, 9.0);

            let plaintext_root_prefetched_query = crate::common::query::do_query_points(
                &toc,
                "vector_docs",
                CollectionQueryRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: Vec::new(),
                        query: Some(Query::Vector(VectorQuery::Nearest(
                            VectorInputInternal::Vector(VectorInternal::Dense(vec![0.0, 0.0])),
                        ))),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::Dense(vec![1.0, 0.0])),
                    ))),
                    using: "plain".to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(plaintext_root_prefetched_query.len(), 1);
            assert_eq!(plaintext_root_prefetched_query[0].id, 1.into());
            assert_eq!(plaintext_root_prefetched_query[0].score, 0.3);

            let err = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(true)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot return encrypted vector")
            ));

            let err = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Selector(vec![
                        DEFAULT_VECTOR_NAME.to_string(),
                    ])),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot return encrypted vector")
            ));

            let encrypted_search = SearchRequestInternal {
                vector: vec![0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into();
            let plaintext_search = CoreSearchRequest {
                query: QueryEnum::Nearest(NamedQuery::new(
                    VectorInternal::Dense(vec![1.0, 0.0]),
                    "plain",
                )),
                filter: None,
                params: None,
                limit: 1,
                offset: 0,
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
            };
            let mixed_search = crate::common::query::do_search_batch_points(
                &toc,
                "vector_docs",
                vec![
                    (encrypted_search, ShardSelectorInternal::All),
                    (plaintext_search, ShardSelectorInternal::All),
                ],
                None,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(mixed_search.len(), 2);
            assert_eq!(mixed_search[0][0].id, 1.into());
            assert_eq!(mixed_search[0][0].score, 9.0);
            assert_eq!(mixed_search[1][0].id, 2.into());
            assert_eq!(mixed_search[1][0].score, 0.5);

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                        payload: None,
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted vector")
                        && description.contains("runtime")
            ));

            let err = do_update_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                UpdateVectors {
                    points: vec![PointVectors {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                    }],
                    shard_key: None,
                    update_filter: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted vector")
                        && description.contains("runtime")
            ));

            do_delete_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                DeleteVectors {
                    points: Some(vec![1.into()]),
                    filter: None,
                    vector: std::iter::once(DEFAULT_VECTOR_NAME.to_string()).collect(),
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap();

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 99.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.9, 0.9]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": "missing runtime secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            let err = do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    payload: segment::types::Payload(
                        json!({ "body": "missing runtime set secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    points: Some(vec![99.into()]),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            let err = do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    payload: segment::types::Payload(
                        json!({ "body": "missing runtime overwrite secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    points: Some(vec![99.into()]),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            let operation = PointInsertOperations::PointsList(api::rest::schema::PointsList {
                points: vec![api::rest::PointStruct {
                    id: 1.into(),
                    vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                    payload: Some(segment::types::Payload(
                        json!({ "body": "public ingress secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    )),
                }],
                shard_key: None,
                update_filter: None,
                update_mode: None,
            });

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                operation,
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let collection_pass = auth
                .check_collection_access("docs", AccessRequirements::new(), "test")
                .unwrap();
            let collection = toc.get_collection(&collection_pass).await.unwrap();
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
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let payload = retrieved[0].payload.as_ref().unwrap();
            let body = payload.0.get("body").unwrap();
            assert!(is_encrypted_payload_value(body));
            assert_ne!(body, &json!("public ingress secret"));
            let upsert_body = body.clone();

            let scroll_with_payload = crate::common::query::do_scroll_points(
                &toc,
                "docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap()
            .points;
            assert_eq!(scroll_with_payload.len(), 1);
            let scroll_body = scroll_with_payload[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_encrypted_payload_value(scroll_body));
            let serialized_scroll_payload =
                serde_json::to_string(&scroll_with_payload[0].payload).unwrap();
            assert!(!serialized_scroll_payload.contains("public ingress secret"));

            let scroll_without_payload = crate::common::query::do_scroll_points(
                &toc,
                "docs",
                shard::scroll::ScrollRequestInternal {
                    offset: None,
                    limit: Some(1),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap()
            .points;
            assert_eq!(scroll_without_payload.len(), 1);
            assert!(scroll_without_payload[0].payload.is_none());

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.3, 0.4]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": upsert_body.clone() })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("failed to encrypt payload")
                        && description.contains("already encrypted")
                        && !description.contains("docs")
                        && !description.contains("body")
            ));

            do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "public set payload secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
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
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let body = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_encrypted_payload_value(body));
            assert_ne!(body, &json!("public set payload secret"));
            assert_ne!(body, &upsert_body);

            do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "public overwrite payload secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
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
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let body = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_encrypted_payload_value(body));
            assert_ne!(body, &json!("public overwrite payload secret"));

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.5, 0.6]),
                        payload: Some(segment::types::Payload(
                            json!({ "title": "point 2 public" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into(), 2.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "multi point secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into(), 2.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let multi_point_body_1 = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            let multi_point_body_2 = retrieved[1]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            assert!(is_encrypted_payload_value(&multi_point_body_1));
            assert!(is_encrypted_payload_value(&multi_point_body_2));
            assert_ne!(multi_point_body_1, json!("multi point secret"));
            assert_ne!(multi_point_body_2, json!("multi point secret"));
            assert_ne!(multi_point_body_1, multi_point_body_2);

            do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into(), 2.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "multi point overwrite secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into(), 2.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let multi_point_overwrite_body_1 = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            let multi_point_overwrite_body_2 = retrieved[1]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            assert!(is_encrypted_payload_value(&multi_point_overwrite_body_1));
            assert!(is_encrypted_payload_value(&multi_point_overwrite_body_2));
            assert_ne!(
                multi_point_overwrite_body_1,
                json!("multi point overwrite secret")
            );
            assert_ne!(
                multi_point_overwrite_body_2,
                json!("multi point overwrite secret")
            );
            assert_ne!(multi_point_overwrite_body_1, multi_point_overwrite_body_2);

            let unsupported_updates = [
                (
                    SetPayload {
                        points: None,
                        payload: segment::types::Payload(
                            json!({ "body": "missing point id secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: None,
                        shard_key: None,
                        key: None,
                    },
                    "without point ids",
                ),
                (
                    SetPayload {
                        points: Some(vec![1.into()]),
                        payload: segment::types::Payload(
                            json!({ "body": "filter secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: Some(Filter::default()),
                        shard_key: None,
                        key: None,
                    },
                    "with a filter cannot update encrypted payload fields",
                ),
                (
                    SetPayload {
                        points: Some(vec![1.into()]),
                        payload: segment::types::Payload(
                            json!({ "value": "key path secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: None,
                        shard_key: None,
                        key: Some("body".parse().unwrap()),
                    },
                    "with a key path cannot update encrypted payload fields",
                ),
            ];
            for (operation, expected_error) in unsupported_updates {
                let err = do_set_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "docs".to_string(),
                    operation,
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    Some(&payload_runtime_settings()),
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::BadInput { description }
                        if description.contains(expected_error)
                            && !description.contains("docs")
                            && !description.contains("body")
                ));
            }

            let signing_rng = SystemRandom::new();
            let signing_pkcs8 = Ed25519KeyPair::generate_pkcs8(&signing_rng).unwrap();
            let signing_key = Ed25519KeyPair::from_pkcs8(signing_pkcs8.as_ref()).unwrap();
            let signed_client_body = |collection_id: &str, point_id: &str| {
                let client_ciphertext = BASE64URL_NOPAD.encode(&[42u8; 16]);
                let mut body = {
                    let mut marker = serde_json::Map::new();
                    marker.insert(
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER.to_string(),
                        json!({
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": "tenant-a/client-rk-2026-04",
                            "rk_epoch": 3,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_id,
                                "point_id": point_id,
                                "field_path": "body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": client_ciphertext,
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": ""
                            }
                        }),
                    );
                    serde_json::Value::Object(marker)
                };
                let message = client_payload_signature_message(&body, "body").unwrap();
                let signature = signing_key.sign(&message);
                body.get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
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
                body
            };
            let mut client_settings = Settings::new(None).unwrap();
            client_settings.crypto.instances = HashMap::from([(
                "docs_payload_client_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload/client-aead@v1".to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({
                        "key_id": "tenant-a/client-rk-2026-04",
                        "expected_rk_id": "tenant-a/client-rk-2026-04",
                        "min_rk_epoch": 3,
                        "max_rk_epoch": 3,
                        "signature_public_keys": {
                            "tenant-a/client-signing-v1": BASE64URL_NOPAD
                                .encode(signing_key.public_key().as_ref()),
                        },
                    }),
                },
            )]);
            let client_docs_uuid = Uuid::from_u128(0x2234567890abcdef1234567890abcdef);
            let client_docs_uuid_string = client_docs_uuid.to_string();
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "client_docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 3,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "body_client_conf".to_string(),
                                        selector: EncryptionSelector::PayloadPaths {
                                            paths: vec!["body".to_string()],
                                        },
                                        instance: "docs_payload_client_v1".to_string(),
                                        binding: Some("client-payload-envelope/v1".to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: Some(client_docs_uuid),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();
            let client_uuid = Uuid::from_u128(0x1234567890abcdef1234567890abcdef);
            let client_uuid_string = client_uuid.to_string();
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "client_uuid_docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
                                sparse_vectors: None,
                                hnsw_config: None,
                                wal_config: None,
                                optimizers_config: None,
                                shard_number: Some(1),
                                on_disk_payload: None,
                                replication_factor: None,
                                write_consistency_factor: None,
                                quantization_config: None,
                                sharding_method: None,
                                encryption: Some(CollectionEncryptionConfig {
                                    version: 1,
                                    key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 3,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "body_client_conf".to_string(),
                                        selector: EncryptionSelector::PayloadPaths {
                                            paths: vec!["body".to_string()],
                                        },
                                        instance: "docs_payload_client_v1".to_string(),
                                        binding: Some("client-payload-envelope/v1".to_string()),
                                    }],
                                }),
                                strict_mode_config: None,
                                uuid: Some(client_uuid),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();
            let mut clustered_client_settings = client_settings.clone();
            clustered_client_settings.cluster.enabled = true;
            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 11.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.7, 0.8]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&clustered_client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cluster-wide nonce replay ledger")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));
            let err = do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                SetPayload {
                    points: Some(vec![12.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": signed_client_body(&client_docs_uuid_string, "12") })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&clustered_client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cluster-wide nonce replay ledger")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));
            let err = do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                SetPayload {
                    points: Some(vec![14.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": signed_client_body(&client_docs_uuid_string, "14") })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&clustered_client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cluster-wide nonce replay ledger")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));
            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![UpdateOperation::Upsert(UpsertOperation {
                    upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                        points: vec![api::rest::PointStruct {
                            id: 15.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.5, 0.6]),
                            payload: Some(segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "15") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        }],
                        shard_key: None,
                        update_filter: None,
                        update_mode: None,
                    }),
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&clustered_client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cluster-wide nonce replay ledger")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));
            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![UpdateOperation::SetPayload(SetPayloadOperation {
                    set_payload: SetPayload {
                        points: Some(vec![16.into()]),
                        payload: segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "16") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: None,
                        shard_key: None,
                        key: None,
                    },
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&clustered_client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cluster-wide nonce replay ledger")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));
            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![UpdateOperation::OverwritePayload(OverwritePayloadOperation {
                    overwrite_payload: SetPayload {
                        points: Some(vec![17.into()]),
                        payload: segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "17") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: None,
                        shard_key: None,
                        key: None,
                    },
                })],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&clustered_client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cluster-wide nonce replay ledger")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 10.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.7, 0.8]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap();
            let client_collection_pass = auth
                .check_collection_access("client_docs", AccessRequirements::new(), "test")
                .unwrap();
            let client_collection = toc.get_collection(&client_collection_pass).await.unwrap();
            let retrieved = client_collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![10.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let body = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_client_encrypted_payload_value(body));

            let err = crate::common::query::do_get_points(
                &toc,
                "client_docs",
                PointRequestInternal {
                    ids: vec![10.into()],
                    with_payload: Some(WithPayloadInterface::Encrypted(
                        PayloadEncryptedReadPolicy {
                            encrypted_payload: EncryptedPayloadReadMode::Decrypted,
                        },
                    )),
                    with_vector: WithVector::Bool(false),
                },
                None,
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("client-side envelopes are opaque")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 13.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.4, 0.4]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "13") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used in this collection")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_uuid_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 20.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.2, 0.1]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body("client_uuid_docs", "20") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("failed to encrypt payload")
                        && !description.contains("collection_id")
                        && !description.contains("client_uuid_docs")
                        && !description.contains("body")
            ));

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_uuid_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 20.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.2, 0.1]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_uuid_string, "20") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap();
            let client_uuid_collection_pass = auth
                .check_collection_access("client_uuid_docs", AccessRequirements::new(), "test")
                .unwrap();
            let client_uuid_collection = toc
                .get_collection(&client_uuid_collection_pass)
                .await
                .unwrap();

            let err = do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                SetPayload {
                    points: Some(vec![10.into(), 11.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot reuse client-side encrypted payload envelopes")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![
                        api::rest::PointStruct {
                            id: 11.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.8, 0.9]),
                            payload: Some(segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        },
                        api::rest::PointStruct {
                            id: 12.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.9, 1.0]),
                            payload: Some(segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "12") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        },
                    ],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![
                    UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                            points: vec![api::rest::PointStruct {
                                id: 11.into(),
                                vector: api::rest::VectorStruct::Single(vec![0.8, 0.9]),
                                payload: Some(segment::types::Payload(
                                    json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                )),
                            }],
                            shard_key: None,
                            update_filter: None,
                            update_mode: None,
                        }),
                    }),
                    UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                            points: vec![api::rest::PointStruct {
                                id: 12.into(),
                                vector: api::rest::VectorStruct::Single(vec![0.9, 1.0]),
                                payload: Some(segment::types::Payload(
                                    json!({ "body": signed_client_body(&client_docs_uuid_string, "12") })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                )),
                            }],
                            shard_key: None,
                            update_filter: None,
                            update_mode: None,
                        }),
                    }),
                ],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![
                    UpdateOperation::SetPayload(SetPayloadOperation {
                        set_payload: SetPayload {
                            points: Some(vec![10.into()]),
                            payload: segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ),
                            filter: None,
                            shard_key: None,
                            key: None,
                        },
                    }),
                    UpdateOperation::SetPayload(SetPayloadOperation {
                        set_payload: SetPayload {
                            points: Some(vec![10.into()]),
                            payload: segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ),
                            filter: None,
                            shard_key: None,
                            key: None,
                        },
                    }),
                ],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 11.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.8, 0.9]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
                        && !description.contains("client_docs")
                        && !description.contains("body")
            ));

            let encrypted_filter = || {
                Filter::new_must(Condition::Field(FieldCondition::new_match(
                    "body".parse().unwrap(),
                    serde_json::from_str(r#"{ "value": "secret body" }"#).unwrap(),
                )))
            };
            let err = do_delete_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                DeletePayload {
                    keys: vec!["tag".parse().unwrap()],
                    points: None,
                    filter: Some(encrypted_filter()),
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot filter on encrypted payload field")
                        && !description.contains("body")
            ));

            let err = do_delete_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                DeletePayload {
                    keys: vec!["body".parse().unwrap()],
                    points: Some(vec![1.into()]),
                    filter: None,
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot delete encrypted payload field")
                        && !description.contains("body")
            ));

            let err = do_clear_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointsSelector::PointIdsSelector(PointIdsList {
                    points: vec![1.into()],
                    shard_key: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot clear payloads")
                        && !description.contains("body")
            ));

            let err = do_clear_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointsSelector::FilterSelector(FilterSelector {
                    filter: encrypted_filter(),
                    shard_key: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot filter on encrypted payload field")
                        && !description.contains("body")
            ));

            for indexed_field in ["body", "body.keyword"] {
                let err = do_create_index(
                    dispatcher.clone().into(),
                    "docs".to_string(),
                    CreateFieldIndex {
                        field_name: indexed_field.parse().unwrap(),
                        field_schema: Some(PayloadFieldSchema::FieldType(
                            segment::types::PayloadSchemaType::Keyword,
                        )),
                    },
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::BadInput { description }
                        if (description.contains("encrypted payload field")
                            && !description.contains("body")
                            && description.contains("blind index"))
                ));
            }

            let snapshot_temp_dir = Builder::new().prefix("snapshot-temp").tempdir().unwrap();
            let snapshot = collection
                .create_snapshot(snapshot_temp_dir.path(), 0)
                .await
                .unwrap();
            assert!(collection.snapshots_path().join(&snapshot.name).exists());

            let client_snapshot_temp_dir = Builder::new()
                .prefix("client-snapshot-temp")
                .tempdir()
                .unwrap();
            let client_snapshot = client_collection
                .create_snapshot(client_snapshot_temp_dir.path(), 0)
                .await
                .unwrap();
            assert!(
                client_collection
                    .snapshots_path()
                    .join(&client_snapshot.name)
                    .exists()
            );

            fs::create_dir_all(&vector_cache_dir).unwrap();
            fs::write(
                vector_cache_dir.join("should-not-be-snapshotted.json"),
                b"ckks sidecar graph cache snapshot sentinel",
            )
            .unwrap();
            let vector_snapshot_temp_dir = Builder::new()
                .prefix("vector-snapshot-temp")
                .tempdir()
                .unwrap();
            let vector_snapshot = vector_collection
                .create_snapshot(vector_snapshot_temp_dir.path(), 0)
                .await
                .unwrap();
            let vector_snapshot_path = vector_collection
                .snapshots_path()
                .join(&vector_snapshot.name);
            assert!(vector_snapshot_path.exists());
            let vector_snapshot_bytes = fs::read(&vector_snapshot_path).unwrap();
            for forbidden in [
                b"ckks_sidecar_hnsw_graphs".as_slice(),
                b"should-not-be-snapshotted.json".as_slice(),
                b"ckks sidecar graph cache snapshot sentinel".as_slice(),
            ] {
                assert!(
                    !vector_snapshot_bytes
                        .windows(forbidden.len())
                        .any(|window| window == forbidden),
                    "CKKS sidecar HNSW cache data leaked into vector collection snapshot",
                );
            }
            let mut vector_snapshot_plaintext_f32_pair = Vec::new();
            vector_snapshot_plaintext_f32_pair.extend_from_slice(&0.7_f32.to_le_bytes());
            vector_snapshot_plaintext_f32_pair.extend_from_slice(&(-0.25_f32).to_le_bytes());
            let mut vector_snapshot_plaintext_f64_pair = Vec::new();
            vector_snapshot_plaintext_f64_pair.extend_from_slice(&0.7_f64.to_le_bytes());
            vector_snapshot_plaintext_f64_pair.extend_from_slice(&(-0.25_f64).to_le_bytes());
            for (label, sentinel) in [
                (
                    "CKKS sidecar HNSW cache directory",
                    b"ckks_sidecar_hnsw_graphs".to_vec(),
                ),
                (
                    "CKKS sidecar HNSW cache filename",
                    b"should-not-be-snapshotted.json".to_vec(),
                ),
                (
                    "CKKS sidecar HNSW cache sentinel",
                    b"ckks sidecar graph cache snapshot sentinel".to_vec(),
                ),
                (
                    "CKKS vector plaintext f32 pair",
                    vector_snapshot_plaintext_f32_pair,
                ),
                (
                    "CKKS vector plaintext f64 pair",
                    vector_snapshot_plaintext_f64_pair,
                ),
            ] {
                let mut pending = vec![vector_snapshot_temp_dir.path().to_path_buf()];
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
                        !bytes.windows(sentinel.len()).any(|window| window == sentinel),
                        "plaintext/cache sentinel '{label}' leaked into vector snapshot temp file {}",
                        path.display(),
                    );
                }
            }

            client_collection.stop_gracefully().await;
            client_uuid_collection.stop_gracefully().await;
            vector_collection.stop_gracefully().await;
            collection.stop_gracefully().await;
        });

        let mut vector_plaintext_f32_pair = Vec::new();
        vector_plaintext_f32_pair.extend_from_slice(&0.7_f32.to_le_bytes());
        vector_plaintext_f32_pair.extend_from_slice(&(-0.25_f32).to_le_bytes());
        let mut vector_plaintext_f64_pair = Vec::new();
        vector_plaintext_f64_pair.extend_from_slice(&0.7_f64.to_le_bytes());
        vector_plaintext_f64_pair.extend_from_slice(&(-0.25_f64).to_le_bytes());

        let mut sentinels = vec![
            (
                "payload public ingress secret",
                b"public ingress secret".to_vec(),
            ),
            (
                "payload public set secret",
                b"public set payload secret".to_vec(),
            ),
            (
                "payload public overwrite secret",
                b"public overwrite payload secret".to_vec(),
            ),
            ("payload multi point secret", b"multi point secret".to_vec()),
            (
                "payload multi point overwrite secret",
                b"multi point overwrite secret".to_vec(),
            ),
            ("CKKS vector plaintext ascii x", b"0.7".to_vec()),
            ("CKKS vector plaintext ascii y", b"-0.25".to_vec()),
        ];
        sentinels.push(("CKKS vector plaintext f32 pair", vector_plaintext_f32_pair));
        sentinels.push(("CKKS vector plaintext f64 pair", vector_plaintext_f64_pair));

        for (label, sentinel) in sentinels {
            for (root_label, root_path) in
                [("storage", storage_dir.path()), ("temp", temp_dir.path())]
            {
                let mut pending = vec![root_path.to_path_buf()];
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
                            .any(|window| window == sentinel.as_slice()),
                        "plaintext sentinel '{label}' leaked into {root_label} path {}",
                        path.display(),
                    );
                }
            }
        }
    }
}
