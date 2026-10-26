use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU32;
use std::sync::Arc;

use ahash::AHashMap;
use common::budget::ResourceBudget;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING, PrivateHnswBucketAeadBaseContext,
    PrivateHnswOramBucket, PrivateHnswOramManifest, PrivateHnswOramSignature, PrivateHnswParams,
    PrivateResultOramBucket, PrivateResultOramBucketCommitmentContext, PrivateResultOramManifest,
    PrivateResultOramSignature, ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
    private_hnsw_bucket_commitment, private_hnsw_oram_bucket_ciphertext_bytes,
    private_result_oram_bucket_ciphertext_bytes, private_result_oram_bucket_commitment,
};
use segment::types::Distance;
use sha2::{Digest, Sha256};
use shard::snapshots::snapshot_data::SnapshotData;
use tempfile::Builder;
use uuid::Uuid;

use crate::collection::{Collection, RequestShardTransfer};
use crate::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, CryptoMigrationState,
    EncryptionRuleRef, EncryptionSelector, WalConfig,
};
use crate::operations::shared_storage_config::SharedStorageConfig;
use crate::operations::types::{NodeType, VectorsConfig};
use crate::operations::vector_params_builder::VectorParamsBuilder;
use crate::private_hnsw_oram_store::{
    PRIVATE_HNSW_ORAM_DIR, PrivateHnswOramEpochState, PrivateHnswOramStore,
};
use crate::private_result_oram_store::{
    PRIVATE_RESULT_ORAM_DIR, PrivateResultOramEpochState, PrivateResultOramStore,
};
use crate::shards::channel_service::ChannelService;
use crate::shards::collection_shard_distribution::CollectionShardDistribution;
use crate::shards::replica_set::{AbortShardTransfer, ChangePeerFromState};
use crate::tests::fixtures::TEST_OPTIMIZERS_CONFIG;

pub fn dummy_on_replica_failure() -> ChangePeerFromState {
    Arc::new(move |_peer_id, _shard_id, _from_state| {})
}

pub fn dummy_request_shard_transfer() -> RequestShardTransfer {
    Arc::new(move |_transfer| {})
}

pub fn dummy_abort_shard_transfer() -> AbortShardTransfer {
    Arc::new(|_transfer, _reason| {})
}

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

async fn _test_snapshot_collection(node_type: NodeType) {
    let wal_config = WalConfig {
        wal_capacity_mb: 1,
        wal_segments_ahead: 0,
        wal_retain_closed: 1,
    };

    let collection_params = CollectionParams {
        vectors: VectorsConfig::Single(VectorParamsBuilder::new(4, Distance::Dot).build()),
        shard_number: NonZeroU32::new(4).unwrap(),
        replication_factor: NonZeroU32::new(3).unwrap(),
        write_consistency_factor: NonZeroU32::new(2).unwrap(),
        ..CollectionParams::empty()
    };

    let config = CollectionConfigInternal {
        params: collection_params,
        optimizer_config: TEST_OPTIMIZERS_CONFIG.clone(),
        wal_config,
        hnsw_config: Default::default(),
        quantization_config: Default::default(),
        strict_mode_config: Default::default(),
        uuid: None,
        metadata: None,
    };

    let snapshots_path = Builder::new().prefix("test_snapshots").tempdir().unwrap();
    let collection_dir = Builder::new().prefix("test_collection").tempdir().unwrap();

    let collection_name = "test".to_string();
    let collection_name_rec = "test_rec".to_string();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));
    shards.insert(1, HashSet::from([1]));
    shards.insert(2, HashSet::from([10_000])); // remote shard
    shards.insert(3, HashSet::from([1, 20_000, 30_000]));

    let storage_config: SharedStorageConfig = SharedStorageConfig {
        node_type,
        ..Default::default()
    };

    let collection = Collection::new(
        collection_name,
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(storage_config),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let prepared_snapshot = collection
        .prepare_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap();
    let prepared_archive_path = prepared_snapshot.archive_path().to_path_buf();
    let prepared_public_path = snapshots_path.path().join(prepared_snapshot.name());
    let (prepared_size, prepared_checksum) = prepared_snapshot.size_and_checksum().await.unwrap();
    assert!(prepared_size > 0);
    assert_eq!(prepared_checksum.len(), 64);
    assert!(prepared_archive_path.is_file());
    assert!(!prepared_public_path.exists());
    assert!(
        std::fs::read_dir(snapshots_path.path())
            .unwrap()
            .next()
            .is_none()
    );
    drop(prepared_snapshot);
    assert!(!prepared_archive_path.exists());

    let snapshot_description = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap();

    assert_eq!(snapshot_description.checksum.unwrap().len(), 64);
    let snapshot_path = snapshots_path.path().join(&snapshot_description.name);

    {
        let recover_dir = Builder::new()
            .prefix("test_collection_rec")
            .tempdir()
            .unwrap();
        let snapshot_data = SnapshotData::new_packed_persistent(snapshot_path.clone());

        // Do not recover in local mode if some shards are remote
        assert!(
            Collection::restore_snapshot(snapshot_data, recover_dir.path(), 0, false,).is_err(),
        );
    }

    let recover_dir = Builder::new()
        .prefix("test_collection_rec")
        .tempdir()
        .unwrap();
    let snapshot_data = SnapshotData::new_packed_persistent(snapshot_path);
    if let Err(err) = Collection::restore_snapshot(snapshot_data, recover_dir.path(), 0, true) {
        panic!("Failed to restore snapshot: {err}")
    }
    let recovered_collection = Collection::load(
        collection_name_rec,
        1,
        recover_dir.path(),
        snapshots_path.path(),
        Default::default(),
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    {
        let shards_holder = &recovered_collection.shards_holder.read().await;

        let replica_ser_0 = shards_holder.get_shard(0).unwrap();
        assert!(replica_ser_0.is_local().await);
        let replica_ser_1 = shards_holder.get_shard(1).unwrap();
        assert!(replica_ser_1.is_local().await);
        let replica_ser_2 = shards_holder.get_shard(2).unwrap();
        assert!(!replica_ser_2.is_local().await);
        assert_eq!(replica_ser_2.peers().len(), 1);

        let replica_ser_3 = shards_holder.get_shard(3).unwrap();

        assert!(replica_ser_3.is_local().await);
        assert_eq!(replica_ser_3.peers().len(), 3); // 2 remotes + 1 local
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_result_oram_unconfigured_store_fails_before_archive() {
    init_logger();

    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Single(VectorParamsBuilder::new(4, Distance::Dot).build()),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
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

    let snapshots_path = Builder::new()
        .prefix("test_result_oram_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_result_oram_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));

    let collection = Collection::new(
        "test_result_oram".to_string(),
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    let result_bucket_path = collection_dir
        .path()
        .join(PRIVATE_RESULT_ORAM_DIR)
        .join("buckets")
        .join("00000000.bucket");
    std::fs::create_dir_all(result_bucket_path.parent().unwrap()).unwrap();
    let ciphertext = BASE64URL_NOPAD.encode(b"encrypted result bucket 0");
    let ciphertext_sha256 =
        BASE64URL_NOPAD.encode(Sha256::digest(b"encrypted result bucket 0").as_ref());
    let bucket_json = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "bucket_id": 0,
        "index_epoch": 42,
        "ciphertext": ciphertext,
        "ciphertext_sha256": ciphertext_sha256,
        "bucket_commitment": BASE64URL_NOPAD.encode(&[7; 32]),
    }))
    .unwrap();
    std::fs::write(&result_bucket_path, &bucket_json).unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let err = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap_err();
    let err = err.to_string();
    assert!(
        err.contains("private result ORAM snapshot store is present without a matching collection encryption rule")
    );
    assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    assert!(!err.contains(&ciphertext));
    assert!(!err.contains("00000000.bucket"));
    assert!(
        std::fs::read_dir(snapshots_path.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_hnsw_unconfigured_store_fails_before_archive() {
    init_logger();

    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Single(VectorParamsBuilder::new(4, Distance::Dot).build()),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
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

    let snapshots_path = Builder::new()
        .prefix("test_hnsw_oram_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_hnsw_oram_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));

    let collection = Collection::new(
        "test_hnsw_oram".to_string(),
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    let bucket_path = collection_dir
        .path()
        .join(PRIVATE_HNSW_ORAM_DIR)
        .join("text")
        .join("buckets")
        .join("00000000.bucket");
    std::fs::create_dir_all(bucket_path.parent().unwrap()).unwrap();
    let ciphertext = BASE64URL_NOPAD.encode(b"encrypted hnsw bucket 0");
    let ciphertext_sha256 =
        BASE64URL_NOPAD.encode(Sha256::digest(b"encrypted hnsw bucket 0").as_ref());
    let bucket_json = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "bucket_id": 0,
        "index_epoch": 42,
        "ciphertext": ciphertext,
        "ciphertext_sha256": ciphertext_sha256,
        "bucket_commitment": BASE64URL_NOPAD.encode(&[7; 32]),
    }))
    .unwrap();
    std::fs::write(&bucket_path, &bucket_json).unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let err = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap_err();
    let err = err.to_string();
    assert!(
        err.contains(
            "private HNSW ORAM snapshot store is present without a matching collection encryption rule"
        ),
        "{err}"
    );
    assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
    assert!(!err.contains(&ciphertext));
    assert!(!err.contains("00000000.bucket"));
    assert!(
        std::fs::read_dir(snapshots_path.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_result_oram_missing_bucket_fails_before_archive() {
    init_logger();

    let collection_uuid = Uuid::from_u128(11);
    let collection_name = "test_private_result_oram_snapshot".to_string();
    let key_id = "tenant-a/result-private-rk".to_string();
    let signing_key_id = "tenant-a/private-result-signing-v1".to_string();
    let leaf_commitments = vec![
        BASE64URL_NOPAD.encode(&[17; 32]),
        BASE64URL_NOPAD.encode(&[18; 32]),
        BASE64URL_NOPAD.encode(&[19; 32]),
    ];
    let root_hash = PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Single(VectorParamsBuilder::new(2, Distance::Euclid).build()),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some(key_id.clone()),
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
        uuid: Some(collection_uuid),
        metadata: None,
    };
    let snapshots_path = Builder::new()
        .prefix("test_private_result_missing_bucket_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_private_result_missing_bucket_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));
    let collection = Collection::new(
        collection_name,
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();
    let store = PrivateResultOramStore::new(collection_dir.path());
    let manifest = PrivateResultOramManifest {
        version: 1,
        provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
        collection_id: collection_uuid.to_string(),
        key_id: key_id.clone(),
        rk_id: key_id,
        rk_epoch: 7,
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 128,
            tree_height: 1,
            path_batch_size: 1,
        },
        index_epoch: 42,
        root_hash: root_hash.clone(),
        bucket_count: 3,
        logical_result_count: 1,
        dummy_result_count: 2,
        owner_signing_key_id: signing_key_id.clone(),
        created_at_unix: 1,
    };
    store
        .write_manifest(
            &manifest,
            &PrivateResultOramSignature {
                alg: "ed25519".to_string(),
                key_id: signing_key_id,
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            },
        )
        .unwrap();
    store
        .write_initial_epoch(&PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash,
        })
        .unwrap();
    store
        .write_merkle_tree_from_commitments(42, manifest.root_hash.clone(), leaf_commitments)
        .unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let err = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("private result ORAM file not found"), "{err}");
    assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    assert!(!err.contains("00000000.bucket"));
    assert!(!err.contains(&manifest.root_hash));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_hnsw_missing_bucket_fails_before_archive() {
    init_logger();

    let collection_uuid = Uuid::from_u128(7);
    let collection_name = "test_private_hnsw_snapshot".to_string();
    let vector_name = "text".to_string();
    let key_id = "tenant-a/vector-private-rk".to_string();
    let signing_key_id = "tenant-a/private-hnsw-signing-v1".to_string();
    let leaf_commitments = vec![
        BASE64URL_NOPAD.encode(&[7; 32]),
        BASE64URL_NOPAD.encode(&[8; 32]),
        BASE64URL_NOPAD.encode(&[9; 32]),
    ];
    let root_hash = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                vector_name.clone(),
                VectorParamsBuilder::new(2, Distance::Euclid).build(),
            )])),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some(key_id.clone()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec![vector_name.clone()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
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
        uuid: Some(collection_uuid),
        metadata: None,
    };
    let snapshots_path = Builder::new()
        .prefix("test_private_hnsw_missing_bucket_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_private_hnsw_missing_bucket_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));
    let collection = Collection::new(
        collection_name,
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();
    let store = PrivateHnswOramStore::new(collection_dir.path(), &vector_name).unwrap();
    let manifest = PrivateHnswOramManifest {
        version: 1,
        provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
        collection_id: collection_uuid.to_string(),
        vector_name: vector_name.clone(),
        key_id: key_id.clone(),
        rk_id: key_id,
        rk_epoch: 7,
        dim: 2,
        distance: DistanceKind::Euclid,
        hnsw: PrivateHnswParams {
            m: 2,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 4,
        },
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 1,
        },
        fixed_budget: FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 1,
            base_layer_steps: 1,
            paths_per_round: 1,
            fixed_result_k: 1,
        },
        index_epoch: 42,
        root_hash: root_hash.clone(),
        bucket_count: 3,
        logical_node_count: 1,
        dummy_node_count: 2,
        result_privacy: ResultPrivacyMode::IdsVisible,
        owner_signing_key_id: signing_key_id.clone(),
        created_at_unix: 1,
    };
    store
        .write_manifest(
            &manifest,
            &PrivateHnswOramSignature {
                alg: "ed25519".to_string(),
                key_id: signing_key_id,
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            },
        )
        .unwrap();
    store
        .write_initial_epoch(&PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash,
        })
        .unwrap();
    store
        .write_merkle_tree_from_commitments(42, manifest.root_hash.clone(), leaf_commitments)
        .unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let err = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("private HNSW ORAM file not found"), "{err}");
    assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
    assert!(!err.contains("00000000.bucket"));
    assert!(!err.contains(&manifest.root_hash));
}

fn snapshot_private_hnsw_bucket(
    manifest: &PrivateHnswOramManifest,
    bucket_id: u64,
) -> PrivateHnswOramBucket {
    let ciphertext_bytes = vec![
        0x40u8.wrapping_add(bucket_id as u8);
        private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap()
    ];
    let ciphertext = BASE64URL_NOPAD.encode(&ciphertext_bytes);
    let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext_bytes).as_ref());
    let bucket_commitment = private_hnsw_bucket_commitment(
        PrivateHnswBucketAeadBaseContext {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
        }
        .for_bucket(bucket_id, manifest.index_epoch),
        &ciphertext_sha256,
    )
    .unwrap();

    PrivateHnswOramBucket {
        version: 1,
        bucket_id,
        index_epoch: manifest.index_epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

fn snapshot_private_hnsw_leaf_commitments(manifest: &PrivateHnswOramManifest) -> Vec<String> {
    (0..manifest.bucket_count)
        .map(|bucket_id| {
            let leaf_commitment =
                snapshot_private_hnsw_bucket(manifest, bucket_id).bucket_commitment;
            leaf_commitment
        })
        .collect()
}

fn snapshot_private_hnsw_manifest(
    collection_id: String,
    vector_name: String,
    key_id: String,
) -> PrivateHnswOramManifest {
    let mut manifest = PrivateHnswOramManifest {
        version: 1,
        provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
        collection_id,
        vector_name,
        key_id: key_id.clone(),
        rk_id: key_id,
        rk_epoch: 7,
        dim: 2,
        distance: DistanceKind::Euclid,
        hnsw: PrivateHnswParams {
            m: 2,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 4,
        },
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 1,
        },
        fixed_budget: FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 1,
            base_layer_steps: 1,
            paths_per_round: 1,
            fixed_result_k: 1,
        },
        index_epoch: 42,
        root_hash: String::new(),
        bucket_count: 3,
        logical_node_count: 1,
        dummy_node_count: 2,
        result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
        owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
        created_at_unix: 1,
    };
    let leaf_commitments = snapshot_private_hnsw_leaf_commitments(&manifest);
    manifest.root_hash =
        PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
    manifest
}

fn write_snapshot_private_hnsw_store(
    collection_dir: &std::path::Path,
    manifest: &PrivateHnswOramManifest,
) {
    let store = PrivateHnswOramStore::new(collection_dir, &manifest.vector_name).unwrap();
    let signature = PrivateHnswOramSignature {
        alg: "ed25519".to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(&[7; 64]),
    };
    store.write_manifest(manifest, &signature).unwrap();
    store
        .write_initial_epoch(&PrivateHnswOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        })
        .unwrap();

    let leaf_commitments = snapshot_private_hnsw_leaf_commitments(manifest);
    let expected_ciphertext_bytes =
        private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
    for bucket_id in 0..manifest.bucket_count {
        let bucket = snapshot_private_hnsw_bucket(manifest, bucket_id);
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                expected_ciphertext_bytes,
            )
            .unwrap();
    }
    store
        .write_merkle_tree_from_commitments(
            manifest.index_epoch,
            manifest.root_hash.clone(),
            leaf_commitments,
        )
        .unwrap();
}

fn snapshot_private_result_bucket(
    manifest: &PrivateResultOramManifest,
    bucket_id: u64,
) -> PrivateResultOramBucket {
    let ciphertext_bytes = vec![
        0x60u8.wrapping_add(bucket_id as u8);
        private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap()
    ];
    let ciphertext = BASE64URL_NOPAD.encode(&ciphertext_bytes);
    let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext_bytes).as_ref());
    let bucket_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: manifest.index_epoch,
        },
        &ciphertext_sha256,
    )
    .unwrap();

    PrivateResultOramBucket {
        version: 1,
        bucket_id,
        index_epoch: manifest.index_epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

fn snapshot_private_result_leaf_commitments(manifest: &PrivateResultOramManifest) -> Vec<String> {
    (0..manifest.bucket_count)
        .map(|bucket_id| {
            let leaf_commitment =
                snapshot_private_result_bucket(manifest, bucket_id).bucket_commitment;
            leaf_commitment
        })
        .collect()
}

fn snapshot_private_result_manifest(
    collection_id: String,
    key_id: String,
) -> PrivateResultOramManifest {
    let mut manifest = PrivateResultOramManifest {
        version: 1,
        provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
        collection_id,
        key_id: key_id.clone(),
        rk_id: key_id,
        rk_epoch: 7,
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 128,
            tree_height: 1,
            path_batch_size: 1,
        },
        index_epoch: 42,
        root_hash: String::new(),
        bucket_count: 3,
        logical_result_count: 1,
        dummy_result_count: 2,
        owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
        created_at_unix: 1,
    };
    let leaf_commitments = snapshot_private_result_leaf_commitments(&manifest);
    manifest.root_hash =
        PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
    manifest
}

fn write_snapshot_private_result_store(
    collection_dir: &std::path::Path,
    manifest: &PrivateResultOramManifest,
) {
    let store = PrivateResultOramStore::new(collection_dir);
    let signature = PrivateResultOramSignature {
        alg: "ed25519".to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(&[9; 64]),
    };
    store.write_manifest(manifest, &signature).unwrap();
    store
        .write_initial_epoch(&PrivateResultOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        })
        .unwrap();

    let leaf_commitments = snapshot_private_result_leaf_commitments(manifest);
    let expected_ciphertext_bytes =
        private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
    for bucket_id in 0..manifest.bucket_count {
        let bucket = snapshot_private_result_bucket(manifest, bucket_id);
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                expected_ciphertext_bytes,
            )
            .unwrap();
    }
    store
        .write_merkle_tree_from_commitments(
            manifest.index_epoch,
            manifest.root_hash.clone(),
            leaf_commitments,
        )
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_oram_store_files_are_archived() {
    init_logger();

    let collection_uuid = Uuid::from_u128(71);
    let vector_name = "text".to_string();
    let key_id = "tenant-a/private-oram-rk".to_string();
    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                vector_name.clone(),
                VectorParamsBuilder::new(2, Distance::Euclid).build(),
            )])),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some(key_id.clone()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "body_private_result_oram".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_private_result_oram_v1".to_string(),
                        binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    },
                    EncryptionRuleRef {
                        id: "text_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![vector_name.clone()],
                        },
                        instance: "docs_private_hnsw_v1".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    },
                ],
            }),
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
        uuid: Some(collection_uuid),
        metadata: None,
    };
    let snapshots_path = Builder::new()
        .prefix("test_private_oram_archive_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_private_oram_archive_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));
    let collection = Collection::new(
        "test_private_oram_archive".to_string(),
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    let result_manifest =
        snapshot_private_result_manifest(collection_uuid.to_string(), key_id.clone());
    write_snapshot_private_result_store(collection_dir.path(), &result_manifest);
    let hnsw_manifest =
        snapshot_private_hnsw_manifest(collection_uuid.to_string(), vector_name.clone(), key_id);
    write_snapshot_private_hnsw_store(collection_dir.path(), &hnsw_manifest);

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let snapshot_description = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap();
    let snapshot_path = snapshots_path.path().join(&snapshot_description.name);
    let snapshot_file = std::fs::File::open(&snapshot_path).unwrap();
    let mut archive = tar::Archive::new(snapshot_file);
    let mut archive_paths = HashSet::new();
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        archive_paths.insert(entry.path().unwrap().to_string_lossy().replace('\\', "/"));
    }

    let expected_paths = [
        format!("{PRIVATE_RESULT_ORAM_DIR}/manifest.json"),
        format!("{PRIVATE_RESULT_ORAM_DIR}/manifest.sig"),
        format!("{PRIVATE_RESULT_ORAM_DIR}/epochs/current.json"),
        format!("{PRIVATE_RESULT_ORAM_DIR}/buckets/00000000.bucket"),
        format!("{PRIVATE_RESULT_ORAM_DIR}/buckets/00000002.bucket"),
        format!("{PRIVATE_RESULT_ORAM_DIR}/merkle/nodes.dat"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/manifest.json"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/manifest.sig"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/epochs/current.json"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/buckets/00000000.bucket"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/buckets/00000002.bucket"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/merkle/nodes.dat"),
    ];
    for expected_path in expected_paths {
        assert!(
            archive_paths.contains(&expected_path),
            "snapshot archive is missing {expected_path}; archived paths: {archive_paths:?}",
        );
    }
    for forbidden in [
        "client_state",
        "client_states",
        "clientState",
        "clientStates",
        "clientStateBackup",
        "clientStateBackups",
        "client_state_backup",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client.state.snapshot",
        "client_state_snapshot",
        "client_state_snapshots",
        "client.state.snapshots",
        "clientStateCiphertext",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "client_state_ciphertext_hashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
        "client_state_ciphertext_sha256",
        "client_state_ciphertexts_sha256",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted.client.state",
        "encrypted.client.state.snapshot",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshots",
        "encrypted.client.state.snapshots",
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state_ciphertext_hashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state_ciphertext_sha256",
        "encrypted_client_state_ciphertexts_sha256",
        "position_map",
        "positionMap",
        "positionMapBackup",
        "positionMapBackups",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "stateCiphertext",
        "stateCiphertextHash",
        "stateCiphertextHashes",
        "state_ciphertext_hash",
        "state_ciphertext_hashes",
        "stateCiphertextSha256",
        "stateCiphertextsSha256",
        "state_ciphertext_sha256",
        "state_ciphertexts_sha256",
        "stash",
        "stashBackup",
        "stashBackups",
        "tokenMap",
        "tokenMapBackup",
        "tokenMapBackups",
        "token.map.backup",
        "token.map.backups",
        "token_map",
        "token_map_backup",
        "token_map_backups",
        "tokenPositionMap",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map.backup",
        "token.position.map.backups",
        "token_position_map",
        "token_position_map_backup",
        "token_position_map_backups",
    ] {
        assert!(
            !archive_paths.iter().any(|path| path.contains(forbidden)),
            "snapshot archive contains client-owned private ORAM state marker {forbidden}: {archive_paths:?}",
        );
    }
    let forbidden_temp_prefixes = [
        format!("{PRIVATE_RESULT_ORAM_DIR}/temp"),
        format!("{PRIVATE_HNSW_ORAM_DIR}/{vector_name}/temp"),
    ];
    for forbidden_temp_prefix in forbidden_temp_prefixes {
        assert!(
            !archive_paths
                .iter()
                .any(|path| path == &forbidden_temp_prefix
                    || path.starts_with(&format!("{forbidden_temp_prefix}/"))),
            "snapshot archive contains private ORAM temp subtree {forbidden_temp_prefix}: {archive_paths:?}",
        );
    }

    let recover_dir = Builder::new()
        .prefix("test_private_oram_archive_recover")
        .tempdir()
        .unwrap();
    let snapshot_data = SnapshotData::new_packed_persistent(snapshot_path);
    Collection::restore_snapshot(snapshot_data, recover_dir.path(), 0, false).unwrap();
    assert!(
        recover_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("manifest.json")
            .exists()
    );
    assert!(
        recover_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join(vector_name)
            .join("manifest.json")
            .exists()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_collection_normal() {
    init_logger();
    _test_snapshot_collection(NodeType::Normal).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_collection_listener() {
    init_logger();
    _test_snapshot_collection(NodeType::Listener).await;
}
