use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use api::grpc::private_oram_chunking::PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES;
use common::fs::read_json;
use common::storage_version::StorageVersion as _;
use common::tar_ext::BuilderExt;
use common::tar_unpack::tar_unpack_file;
use data_encoding::BASE64URL_NOPAD;
use fs_err::File;
use qdrant_sec::{
    DistanceKind, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_HNSW_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_BINDING, PrivateHnswBucketAeadBaseContext, PrivateHnswOramBucket,
    PrivateHnswOramManifest, PrivateHnswOramSignature, PrivateResultOramBucket,
    PrivateResultOramBucketCommitmentContext, PrivateResultOramManifest,
    PrivateResultOramSignature, ResultPrivacyMode, private_hnsw_bucket_commitment,
    private_hnsw_oram_bucket_ciphertext_bytes, private_result_oram_bucket_ciphertext_bytes,
    private_result_oram_bucket_commitment, validate_private_hnsw_oram_manifest_shape,
    validate_private_hnsw_oram_manifest_signature_shape,
    validate_private_result_oram_manifest_shape,
    validate_private_result_oram_manifest_signature_shape,
};
use segment::types::{ShardKey, SnapshotFormat};
use segment::utils::fs::move_all;
use serde::Deserialize;
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
use shard::snapshots::snapshot_data::SnapshotData;
use shard::snapshots::snapshot_manifest::{RecoveryType, SnapshotManifest};
use tempfile::TempPath;
use tokio::sync::OwnedRwLockReadGuard;

use super::Collection;
use crate::collection::CollectionVersion;
use crate::common::snapshot_stream::SnapshotStream;
use crate::common::snapshots_manager::SnapshotStorageManager;
use crate::config::{
    COLLECTION_CONFIG_FILE, CollectionConfigInternal, CollectionParams, CryptoMigrationState,
    EncryptionSelector, ShardingMethod,
};
use crate::operations::snapshot_ops::SnapshotDescription;
use crate::operations::types::{CollectionError, CollectionResult, NodeType};
use crate::private_hnsw_oram_store::{
    PRIVATE_HNSW_ORAM_DIR, PrivateHnswOramStore,
    private_hnsw_oram_vector_name_is_safe_store_component,
    private_oram_path_component_is_client_owned_state_alias,
};
use crate::private_oram_owner_journal::{
    PRIVATE_ORAM_OWNER_JOURNAL_DIR, PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
    PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1, PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2,
    PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2, PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2,
};
use crate::private_result_oram_store::{PRIVATE_RESULT_ORAM_DIR, PrivateResultOramStore};
use crate::shards::local_shard::LocalShard;
use crate::shards::remote_shard::RemoteShard;
use crate::shards::replica_set::replica_set_state::{ReplicaSetState, ReplicaState};
use crate::shards::replica_set::{REPLICA_STATE_FILE, ShardReplicaSet};
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::shard_config::{self, ShardConfig};
use crate::shards::shard_holder::shard_mapping::ShardKeyMapping;
use crate::shards::shard_holder::{SHARD_KEY_MAPPING_FILE, ShardHolder, shard_not_found_error};
use crate::shards::{shard_initializing_flag_path, shard_path};

const PRIVATE_ORAM_SNAPSHOT_MAX_EPOCH_BYTES: u64 = 16 * 1024;
#[cfg(feature = "staging")]
const PRIVATE_ORAM_EXTERNAL_RECOVERY_UNPACK_ERROR_KIND_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_UNPACK_ERROR_KIND_FILE";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateOramRecoveryShardTopology {
    pub shard_id: ShardId,
    pub shard_key: Option<ShardKey>,
    pub owner_peer_ids: Vec<PeerId>,
    pub is_local: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PrivateOramRecoveryCandidateInspection {
    pub config: CollectionConfigInternal,
    pub local_shard_ids: Vec<ShardId>,
    pub shards: Vec<PrivateOramRecoveryShardTopology>,
}

#[derive(Clone, Copy)]
enum SnapshotReplicaIdentityMode {
    Rewrite,
    Preserve,
}

pub struct PreparedCollectionSnapshot {
    name: String,
    archive: TempPath,
}

impl PreparedCollectionSnapshot {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn archive_path(&self) -> &Path {
        &self.archive
    }

    pub async fn size_and_checksum(&self) -> CollectionResult<(u64, String)> {
        let size = tokio::fs::metadata(self.archive_path()).await?.len();
        let checksum = crate::common::sha_256::hash_file(self.archive_path()).await?;
        Ok((size, checksum))
    }
}

#[cfg(feature = "staging")]
fn record_private_oram_external_recovery_unpack_error_kind(
    replica_identity_mode: SnapshotReplicaIdentityMode,
    error: &std::io::Error,
) {
    if !matches!(replica_identity_mode, SnapshotReplicaIdentityMode::Preserve)
        || error.kind() != ErrorKind::StorageFull
    {
        return;
    }
    let Some(marker_path) =
        std::env::var_os(PRIVATE_ORAM_EXTERNAL_RECOVERY_UNPACK_ERROR_KIND_FILE_ENV)
    else {
        return;
    };
    if marker_path.is_empty() {
        return;
    }
    let _ = std::fs::write(marker_path, b"storage_full\n");
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramSnapshotEpochFile {
    index_epoch: u64,
    root_hash: String,
    #[serde(default)]
    writeback_digest: Option<String>,
}

impl Collection {
    pub fn get_snapshots_storage_manager(&self) -> CollectionResult<SnapshotStorageManager> {
        SnapshotStorageManager::new(&self.shared_storage_config.snapshots_config)
    }

    pub async fn list_snapshots(&self) -> CollectionResult<Vec<SnapshotDescription>> {
        let snapshot_manager = self.get_snapshots_storage_manager()?;
        snapshot_manager.list_snapshots(&self.snapshots_path).await
    }

    /// Creates a snapshot of the collection.
    ///
    /// The snapshot is created in three steps:
    /// 1. Create a temporary directory and create a snapshot of each shard in it.
    /// 2. Archive the temporary directory into a single file.
    /// 3. Move the archive to the final location.
    ///
    /// # Arguments
    ///
    /// * `global_temp_dir`: directory used to host snapshots while they are being created
    /// * `this_peer_id`: current peer id
    ///
    /// returns: Result<SnapshotDescription, CollectionError>
    pub async fn create_snapshot(
        &self,
        global_temp_dir: &Path,
        this_peer_id: PeerId,
    ) -> CollectionResult<SnapshotDescription> {
        let prepared = self.prepare_snapshot(global_temp_dir, this_peer_id).await?;
        let snapshot_path = self.snapshots_path.join(prepared.name());
        let snapshot_manager = self.get_snapshots_storage_manager()?;
        snapshot_manager
            .store_file(prepared.archive_path(), snapshot_path.as_path())
            .await
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to store snapshot archive to {}: {err}",
                    prepared.archive_path().display()
                ))
            })
    }

    /// Builds a collection snapshot archive without publishing it to snapshot storage.
    pub async fn prepare_snapshot(
        &self,
        global_temp_dir: &Path,
        this_peer_id: PeerId,
    ) -> CollectionResult<PreparedCollectionSnapshot> {
        let collection_config = {
            let collection_config = self.collection_config.read().await;
            ensure_snapshot_crypto_migration_state_allows_snapshot(
                self.name(),
                &collection_config.params,
            )?;
            let collection_config = collection_config.clone();
            Self::validate_private_hnsw_oram_snapshot_restore_layout(
                self.name(),
                &collection_config,
                &self.path,
            )
            .map_err(|err| sanitize_private_hnsw_snapshot_layout_error(&self.path, err))?;
            Self::validate_private_result_oram_snapshot_restore_layout(
                self.name(),
                &collection_config,
                &self.path,
            )
            .map_err(|err| sanitize_private_result_oram_snapshot_layout_error(&self.path, err))?;
            collection_config
        };

        let snapshot_name = format!(
            "{}-{this_peer_id}-{}.snapshot",
            self.name(),
            chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S"),
        );

        log::info!("Preparing collection snapshot {snapshot_name}");

        // Dedicated temporary file for archiving this snapshot (deleted on drop)
        let snapshot_temp_arc_file = tempfile::Builder::new()
            .prefix(&format!("{snapshot_name}-arc-"))
            .tempfile_in(global_temp_dir)
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to create temporary snapshot directory {}/{snapshot_name}-arc-XXXX: \
                     {err}",
                    global_temp_dir.display(),
                ))
            })?;

        let tar = BuilderExt::new_seekable_owned(File::create(snapshot_temp_arc_file.path())?);

        // Create snapshot of each shard
        {
            let snapshot_temp_temp_dir = tempfile::Builder::new()
                .prefix(&format!("{snapshot_name}-temp-"))
                .tempdir_in(global_temp_dir)
                .map_err(|err| {
                    CollectionError::service_error(format!(
                        "failed to create temporary snapshot directory {}/{snapshot_name}-temp-XXXX: \
                         {err}",
                        global_temp_dir.display(),
                    ))
                })?;

            let mut futures = Vec::new();
            {
                let shards_holder = self.shards_holder.read().await;

                // Create snapshot of each shard
                for (shard_id, replica_set) in shards_holder.get_shards() {
                    let shard_snapshot_path = shard_path(Path::new(""), shard_id);

                    // If node is listener, we can save whatever currently is in the storage
                    let save_wal = self.shared_storage_config.node_type != NodeType::Listener;
                    let future = replica_set
                        .create_snapshot(
                            snapshot_temp_temp_dir.path(),
                            tar.descend(&shard_snapshot_path)?,
                            SnapshotFormat::Regular,
                            None,
                            save_wal,
                        )
                        .await?;
                    futures.push(future);
                }
            }

            for future in futures {
                future.await.map_err(|err| {
                    CollectionError::service_error(format!("failed to create snapshot: {err}"))
                })?;
            }
        }

        // Save collection config and version
        tar.append_data(
            CollectionVersion::current_raw().as_bytes().to_vec(),
            Path::new(common::storage_version::VERSION_FILE),
        )
        .await?;

        tar.append_data(
            collection_config.to_bytes()?,
            Path::new(COLLECTION_CONFIG_FILE),
        )
        .await?;

        self.shards_holder
            .read()
            .await
            .save_key_mapping_to_tar(&tar)
            .await?;

        self.payload_index_schema
            .save_to_tar(&tar, Path::new(PAYLOAD_INDEX_CONFIG_FILE))
            .await?;

        if let Some(private_hnsw_oram_path) =
            private_oram_snapshot_source_dir(&self.path, PRIVATE_HNSW_ORAM_DIR)?
        {
            let tar = tar.clone();
            tokio::task::spawn_blocking(move || {
                blocking_append_private_oram_snapshot_dir(
                    &tar,
                    &private_hnsw_oram_path,
                    Path::new(PRIVATE_HNSW_ORAM_DIR),
                    PRIVATE_HNSW_ORAM_DIR,
                )
            })
            .await
            .map_err(CollectionError::from)??;
        }

        if let Some(private_oram_parent_path) =
            private_oram_snapshot_source_dir(&self.path, PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2)?
        {
            let tar = tar.clone();
            tokio::task::spawn_blocking(move || {
                blocking_append_private_oram_snapshot_dir(
                    &tar,
                    &private_oram_parent_path,
                    Path::new(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2),
                    PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2,
                )
            })
            .await
            .map_err(CollectionError::from)??;
        }

        if let Some(private_result_oram_path) =
            private_oram_snapshot_source_dir(&self.path, PRIVATE_RESULT_ORAM_DIR)?
        {
            let tar = tar.clone();
            tokio::task::spawn_blocking(move || {
                blocking_append_private_oram_snapshot_dir(
                    &tar,
                    &private_result_oram_path,
                    Path::new(PRIVATE_RESULT_ORAM_DIR),
                    PRIVATE_RESULT_ORAM_DIR,
                )
            })
            .await
            .map_err(CollectionError::from)??;
        }

        tar.finish().await.map_err(|err| {
            CollectionError::service_error(format!("failed to create snapshot archive: {err}"))
        })?;

        Ok(PreparedCollectionSnapshot {
            name: snapshot_name,
            archive: snapshot_temp_arc_file.into_temp_path(),
        })
    }

    /// Restore collection from snapshot
    ///
    /// This method performs blocking IO.
    pub fn restore_snapshot(
        snapshot_data: SnapshotData,
        target_dir: &Path,
        this_peer_id: PeerId,
        is_distributed: bool,
    ) -> CollectionResult<()> {
        Self::restore_snapshot_with_replica_identity(
            snapshot_data,
            target_dir,
            this_peer_id,
            is_distributed,
            SnapshotReplicaIdentityMode::Rewrite,
        )
    }

    pub fn restore_private_oram_external_recovery_snapshot(
        snapshot_data: SnapshotData,
        target_dir: &Path,
        this_peer_id: PeerId,
    ) -> CollectionResult<()> {
        Self::restore_snapshot_with_replica_identity(
            snapshot_data,
            target_dir,
            this_peer_id,
            true,
            SnapshotReplicaIdentityMode::Preserve,
        )
    }

    fn restore_snapshot_with_replica_identity(
        snapshot_data: SnapshotData,
        target_dir: &Path,
        this_peer_id: PeerId,
        is_distributed: bool,
        replica_identity_mode: SnapshotReplicaIdentityMode,
    ) -> CollectionResult<()> {
        match snapshot_data {
            SnapshotData::Packed(snapshot_path) => {
                let unpack_result = tar_unpack_file(&snapshot_path, target_dir);
                #[cfg(feature = "staging")]
                if let Err(error) = &unpack_result {
                    record_private_oram_external_recovery_unpack_error_kind(
                        replica_identity_mode,
                        error,
                    );
                }
                unpack_result?;
                snapshot_path.close()?;
            }
            SnapshotData::Unpacked(snapshot_dir) => {
                // already unpacked snapshot, validate files and move to target dir
                let snapshot_dir_path = snapshot_dir.path();
                move_all(snapshot_dir_path, target_dir)?;
            }
        }

        let config = CollectionConfigInternal::load(target_dir)?;
        config.validate_and_warn();
        let restore_collection_name = target_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("restored_collection");
        Self::validate_private_result_oram_snapshot_restore_layout(
            restore_collection_name,
            &config,
            target_dir,
        )
        .map_err(|err| sanitize_private_result_oram_snapshot_layout_error(target_dir, err))?;
        Self::validate_private_hnsw_oram_snapshot_restore_layout(
            restore_collection_name,
            &config,
            target_dir,
        )
        .map_err(|err| sanitize_private_hnsw_snapshot_layout_error(target_dir, err))?;
        Self::validate_private_oram_mutation_journal_snapshot_restore_layout(target_dir)?;
        let shard_ids_list = snapshot_shard_ids(&config, target_dir)?;

        for shard_id in shard_ids_list {
            let shard_path = shard_path(target_dir, shard_id);
            let shard_config_opt = ShardConfig::load(&shard_path)?;
            if let Some(shard_config) = shard_config_opt {
                match shard_config.r#type {
                    shard_config::ShardType::Local => LocalShard::restore_snapshot(&shard_path)?,
                    shard_config::ShardType::Remote { .. } => {
                        RemoteShard::restore_snapshot(&shard_path)
                    }
                    shard_config::ShardType::Temporary => {}
                    shard_config::ShardType::ReplicaSet => match replica_identity_mode {
                        SnapshotReplicaIdentityMode::Rewrite => ShardReplicaSet::restore_snapshot(
                            &shard_path,
                            this_peer_id,
                            is_distributed,
                        )?,
                        SnapshotReplicaIdentityMode::Preserve => {
                            ShardReplicaSet::restore_snapshot_preserving_peer_identity(
                                &shard_path,
                                this_peer_id,
                                is_distributed,
                            )?
                        }
                    },
                }
            } else {
                return Err(CollectionError::service_error(format!(
                    "Can't read shard config at {}",
                    shard_path.display()
                )));
            }
        }

        Ok(())
    }

    pub fn private_oram_restored_snapshot_local_shard_ids(
        config: &CollectionConfigInternal,
        collection_dir: &Path,
        this_peer_id: PeerId,
    ) -> CollectionResult<Vec<ShardId>> {
        let mut local_shard_ids = Vec::new();
        for shard_id in snapshot_shard_ids(config, collection_dir)? {
            let shard_dir = shard_path(collection_dir, shard_id);
            let Some(shard_config) = ShardConfig::load(&shard_dir)? else {
                return Err(CollectionError::service_error(
                    "private ORAM recovery snapshot shard configuration is missing",
                ));
            };
            if shard_config.r#type != shard_config::ShardType::ReplicaSet {
                return Err(CollectionError::service_error(
                    "private ORAM recovery snapshot requires replica-set shards",
                ));
            }
            let replica_state: ReplicaSetState = read_json(&shard_dir.join(REPLICA_STATE_FILE))?;
            if replica_state.this_peer_id != this_peer_id
                || replica_state.is_local && replica_state.get_peer_state(this_peer_id).is_none()
            {
                return Err(CollectionError::service_error(
                    "private ORAM recovery snapshot replica ownership is invalid",
                ));
            }
            if replica_state.is_local {
                local_shard_ids.push(shard_id);
            }
        }
        local_shard_ids.sort_unstable();
        Ok(local_shard_ids)
    }

    pub fn validate_private_hnsw_oram_snapshot_restore_layout(
        collection_name: &str,
        config: &CollectionConfigInternal,
        collection_dir: &Path,
    ) -> CollectionResult<()> {
        let configured_vectors = private_hnsw_oram_configured_vectors(&config.params)?;

        validate_private_hnsw_oram_snapshot_store_matches_config(
            collection_dir,
            &configured_vectors,
        )?;

        if configured_vectors.is_empty() {
            return Ok(());
        }

        let stable_crypto_id = config.stable_crypto_id(collection_name)?;
        for vector_name in configured_vectors {
            validate_private_hnsw_oram_vector_snapshot(
                collection_dir,
                &stable_crypto_id,
                &config.params,
                &vector_name,
            )?;
        }

        Ok(())
    }

    pub fn validate_private_hnsw_oram_live_replica_layout(
        collection_name: &str,
        config: &CollectionConfigInternal,
        collection_dir: &Path,
    ) -> CollectionResult<()> {
        let configured_vectors = private_hnsw_oram_configured_vectors(&config.params)?;
        validate_private_hnsw_oram_snapshot_store_matches_config(
            collection_dir,
            &configured_vectors,
        )?;
        if configured_vectors.is_empty() {
            return Ok(());
        }

        let stable_crypto_id = config.stable_crypto_id(collection_name)?;
        for vector_name in configured_vectors {
            let vector_params =
                config
                    .params
                    .vectors
                    .get_params(&vector_name)
                    .ok_or_else(|| {
                        CollectionError::bad_request(
                            "private HNSW ORAM live replica vector is not configured",
                        )
                    })?;
            let expected_dim = u32::try_from(vector_params.size.get()).map_err(|_| {
                CollectionError::bad_request(
                    "private HNSW ORAM live replica vector dimension exceeds u32",
                )
            })?;
            let expected_distance = private_hnsw_distance_kind(vector_params.distance);
            let store = PrivateHnswOramStore::new(collection_dir, &vector_name)?;
            let (manifest, signature) = store.read_manifest()?;
            let private_result_oram_path_batch_size =
                private_result_oram_snapshot_path_batch_size_for_hnsw_restore(
                    collection_dir,
                    &stable_crypto_id,
                    &config.params,
                    manifest.result_privacy,
                )?;
            validate_private_hnsw_oram_restore_manifest(
                &manifest,
                &signature,
                &stable_crypto_id,
                &config.params,
                &vector_name,
                expected_dim,
                expected_distance,
                private_result_oram_path_batch_size,
            )?;
            validate_private_oram_snapshot_store_layout(
                store.root_path(),
                manifest.bucket_count,
                "private HNSW ORAM",
            )?;
            let bundle = store.read_live_replication_bundle(
                private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest)?,
                PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES,
            )?;
            if bundle.manifest != manifest || bundle.manifest_signature != signature {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM live replica bundle does not match validated manifest",
                ));
            }
        }

        Ok(())
    }

    pub fn validate_private_result_oram_snapshot_restore_layout(
        collection_name: &str,
        config: &CollectionConfigInternal,
        collection_dir: &Path,
    ) -> CollectionResult<()> {
        let configured = private_result_oram_configured(&config.params)?;
        validate_private_result_oram_snapshot_store_matches_config(collection_dir, configured)?;

        if !configured {
            return Ok(());
        }

        let stable_crypto_id = config.stable_crypto_id(collection_name)?;
        validate_private_result_oram_snapshot(collection_dir, &stable_crypto_id, &config.params)
    }

    pub fn validate_private_result_oram_live_replica_layout(
        collection_name: &str,
        config: &CollectionConfigInternal,
        collection_dir: &Path,
    ) -> CollectionResult<()> {
        let configured = private_result_oram_configured(&config.params)?;
        validate_private_result_oram_snapshot_store_matches_config(collection_dir, configured)?;
        if !configured {
            return Ok(());
        }

        let stable_crypto_id = config.stable_crypto_id(collection_name)?;
        let store = PrivateResultOramStore::new(collection_dir);
        let (manifest, signature) = store.read_manifest()?;
        validate_private_result_oram_restore_manifest(
            &manifest,
            &signature,
            &stable_crypto_id,
            &config.params,
        )?;
        validate_private_oram_snapshot_store_layout(
            store.root_path(),
            manifest.bucket_count,
            "private result ORAM",
        )?;
        let bundle = store.read_live_replication_bundle(
            private_result_restore_max_bucket_ciphertext_bytes(&manifest)?,
            PRIVATE_ORAM_INSTALL_MAX_ENCODED_BYTES,
        )?;
        if bundle.manifest != manifest || bundle.manifest_signature != signature {
            return Err(CollectionError::bad_request(
                "private result ORAM live replica bundle does not match validated manifest",
            ));
        }

        Ok(())
    }

    #[doc(hidden)]
    pub fn validate_private_oram_mutation_journal_snapshot_restore_layout(
        collection_dir: &Path,
    ) -> CollectionResult<()> {
        private_oram_snapshot_source_dir(collection_dir, PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2)
            .map(|_| ())
    }

    /// # Cancel safety
    ///
    /// This method is *not* cancel safe.
    pub async fn recover_local_shard_from(
        &self,
        snapshot_shard_path: &Path,
        recovery_type: RecoveryType,
        shard_id: ShardId,
        cancel: cancel::CancellationToken,
    ) -> CollectionResult<bool> {
        self.validate_private_oram_shard_snapshot_allowed(if recovery_type.is_partial() {
            "partial shard snapshot recovery"
        } else {
            "shard snapshot recovery"
        })
        .await?;

        // TODO:
        //   Check that shard snapshot is compatible with the collection
        //   (see `VectorsConfig::check_compatible_with_segment_config`)

        // `ShardHolder::recover_local_shard_from` is *not* cancel safe
        // (see `ShardReplicaSet::restore_local_replica_from`)
        let res = self
            .shards_holder
            .read()
            .await
            .recover_local_shard_from(
                snapshot_shard_path,
                recovery_type,
                &self.path,
                shard_id,
                cancel,
            )
            .await?;

        Ok(res)
    }

    pub async fn list_shard_snapshots(
        &self,
        shard_id: ShardId,
    ) -> CollectionResult<Vec<SnapshotDescription>> {
        self.validate_private_oram_shard_snapshot_allowed("shard snapshot listing")
            .await?;

        self.shards_holder
            .read()
            .await
            .list_shard_snapshots(&self.snapshots_path, shard_id)
            .await
    }

    pub async fn create_shard_snapshot(
        &self,
        shard_id: ShardId,
        temp_dir: &Path,
    ) -> CollectionResult<SnapshotDescription> {
        self.validate_private_oram_shard_snapshot_allowed("shard snapshot creation")
            .await?;

        let snapshot_creator = self
            .shards_holder
            .read()
            .await
            .create_shard_snapshot(&self.snapshots_path, self.name(), shard_id, temp_dir)
            .await?;
        // We don't hold shards_holder lock here on purpose,
        // because snapshot creation may take a long time,
        // and we don't want to block other operations on the collection.
        let (snapshot_description, _) = snapshot_creator.await?;
        Ok(snapshot_description)
    }

    pub async fn stream_shard_snapshot(
        &self,
        shard_id: ShardId,
        manifest: Option<SnapshotManifest>,
        temp_dir: &Path,
    ) -> CollectionResult<SnapshotStream> {
        self.validate_private_oram_shard_snapshot_allowed("shard snapshot streaming")
            .await?;

        let shard = OwnedRwLockReadGuard::try_map(
            self.shards_holder.clone().read_owned().await,
            |shard_holder| shard_holder.get_shard(shard_id),
        )
        .map_err(|_| shard_not_found_error(shard_id))?;

        ShardHolder::stream_shard_snapshot(shard, self.name(), shard_id, manifest, temp_dir).await
    }

    /// # Cancel safety
    ///
    /// This method is cancel safe.
    #[expect(clippy::too_many_arguments)]
    pub async fn restore_shard_snapshot(
        &self,
        shard_id: ShardId,
        snapshot_data: SnapshotData,
        recovery_type: RecoveryType,
        this_peer_id: PeerId,
        is_distributed: bool,
        temp_dir: &Path,
        cancel: cancel::CancellationToken,
    ) -> CollectionResult<impl Future<Output = CollectionResult<()>> + 'static> {
        // `ShardHolder::validate_shard_snapshot` is cancel safe, so we explicitly cancel it
        // when token is triggered
        let shard_holder = self.shards_holder.clone().read_owned().await;

        let collection_path = self.path.clone();
        let collection_name = self.name().to_string();
        let collection_params = self.collection_config.read().await.params.clone();
        validate_private_oram_shard_snapshot_operation(
            &collection_name,
            &collection_params,
            "shard snapshot recovery",
        )?;

        let temp_dir = temp_dir.to_path_buf();

        // `ShardHolder::restore_shard_snapshot` is *not* cancel safe, so we spawn it onto runtime,
        // so that it won't be cancelled if current future is dropped
        let restore = self.update_runtime.spawn(async move {
            shard_holder
                .restore_shard_snapshot(
                    snapshot_data,
                    recovery_type,
                    &collection_path,
                    collection_params,
                    &collection_name,
                    shard_id,
                    this_peer_id,
                    is_distributed,
                    &temp_dir,
                    cancel,
                )
                .await?;

            CollectionResult::Ok(())
        });

        // Flatten nested `Result<Result<()>>` into `Result<()>`
        let restore = async move {
            restore.await.map_err(CollectionError::from)??;
            Ok(())
        };

        Ok(restore)
    }

    pub async fn assert_shard_exists(&self, shard_id: ShardId) -> CollectionResult<()> {
        self.shards_holder
            .read()
            .await
            .assert_shard_exists(shard_id)
    }

    pub async fn try_take_partial_snapshot_recovery_lock(
        &self,
        shard_id: ShardId,
        recovery_type: RecoveryType,
    ) -> CollectionResult<Option<tokio::sync::OwnedRwLockWriteGuard<()>>> {
        self.validate_private_oram_shard_snapshot_allowed("partial shard snapshot recovery")
            .await?;

        self.shards_holder
            .read()
            .await
            .try_take_partial_snapshot_recovery_lock(shard_id, recovery_type)
    }

    pub async fn get_partial_snapshot_manifest(
        &self,
        shard_id: ShardId,
    ) -> CollectionResult<SnapshotManifest> {
        self.validate_private_oram_shard_snapshot_allowed("partial shard snapshot manifest")
            .await?;

        self.shards_holder
            .read()
            .await
            .get_shard(shard_id)
            .ok_or_else(|| shard_not_found_error(shard_id))?
            .get_partial_snapshot_manifest()
            .await
    }

    pub async fn validate_private_oram_shard_snapshot_allowed(
        &self,
        operation_name: &str,
    ) -> CollectionResult<()> {
        let params = self.collection_config.read().await.params.clone();
        validate_private_oram_shard_snapshot_operation(self.name(), &params, operation_name)
    }
}

/// Inspects an external private ORAM recovery candidate without activating or modifying it.
///
/// This intentionally uses only read-only filesystem operations. In particular, it must not call
/// collection/shard load paths, which can migrate files, repair segments, replay WAL entries, or
/// start background workers.
impl Collection {
    pub fn inspect_private_oram_recovery_candidate_read_only(
        collection_name: &str,
        collection_path: &Path,
        this_peer_id: PeerId,
        recovery_mode: Option<&str>,
    ) -> CollectionResult<PrivateOramRecoveryCandidateInspection> {
        if collection_name.is_empty() {
            return Err(private_oram_candidate_inspection_error(
                "collection identity is invalid",
            ));
        }
        if recovery_mode.is_some() {
            return Err(private_oram_candidate_inspection_error(
                "runtime recovery mode is active",
            ));
        }

        require_private_oram_candidate_regular_file(
            &collection_path.join(common::storage_version::VERSION_FILE),
            "collection version",
        )?;
        let version =
            std::fs::read_to_string(collection_path.join(common::storage_version::VERSION_FILE))
                .map_err(|_| {
                    private_oram_candidate_inspection_error("collection version cannot be read")
                })?;
        if version != CollectionVersion::current_raw() {
            return Err(private_oram_candidate_inspection_error(
                "collection version is not current",
            ));
        }

        require_private_oram_candidate_regular_file(
            &collection_path.join(COLLECTION_CONFIG_FILE),
            "collection configuration",
        )?;
        let config = CollectionConfigInternal::load(collection_path).map_err(|_| {
            private_oram_candidate_inspection_error("collection configuration cannot be read")
        })?;

        let expected_shard_ids = snapshot_shard_ids(&config, collection_path)?;
        let expected_shard_set: HashSet<_> = expected_shard_ids.iter().copied().collect();
        let actual_shard_set = private_oram_candidate_actual_shard_ids(collection_path)?;
        if actual_shard_set != expected_shard_set {
            return Err(private_oram_candidate_inspection_error(
                "actual shard directories do not match collection configuration",
            ));
        }

        let shard_key_mapping = match config.params.sharding_method.unwrap_or_default() {
            ShardingMethod::Auto => None,
            ShardingMethod::Custom => {
                let mapping_path = collection_path.join(SHARD_KEY_MAPPING_FILE);
                require_private_oram_candidate_regular_file(&mapping_path, "shard key mapping")?;
                Some(read_json::<ShardKeyMapping>(&mapping_path).map_err(|_| {
                    private_oram_candidate_inspection_error("shard key mapping cannot be read")
                })?)
            }
        };

        let mut shards = Vec::with_capacity(expected_shard_ids.len());
        let mut local_shard_ids = Vec::new();
        for shard_id in expected_shard_ids {
            let initializing_flag = shard_initializing_flag_path(collection_path, shard_id);
            if std::fs::symlink_metadata(&initializing_flag).is_ok() {
                return Err(private_oram_candidate_inspection_error(
                    "shard initializing marker is present",
                ));
            }

            let shard_dir = shard_path(collection_path, shard_id);
            require_private_oram_candidate_directory(&shard_dir, "shard")?;
            require_private_oram_candidate_regular_file(
                &ShardConfig::get_config_path(&shard_dir),
                "shard configuration",
            )?;
            let shard_config: ShardConfig = read_json(&ShardConfig::get_config_path(&shard_dir))
                .map_err(|_| {
                    private_oram_candidate_inspection_error("shard configuration cannot be read")
                })?;
            if shard_config.r#type != shard_config::ShardType::ReplicaSet {
                return Err(private_oram_candidate_inspection_error(
                    "shard is not a replica set",
                ));
            }

            let replica_state_path = shard_dir.join(REPLICA_STATE_FILE);
            require_private_oram_candidate_regular_file(&replica_state_path, "replica state")?;
            let replica_state: ReplicaSetState = read_json(&replica_state_path).map_err(|_| {
                private_oram_candidate_inspection_error("replica state cannot be read")
            })?;
            if replica_state.this_peer_id != this_peer_id {
                return Err(private_oram_candidate_inspection_error(
                    "replica state peer identity is invalid",
                ));
            }
            if replica_state.peers().is_empty()
                || replica_state
                    .peers()
                    .values()
                    .any(|state| *state != ReplicaState::Active)
            {
                return Err(private_oram_candidate_inspection_error(
                    "replica state is not fully active",
                ));
            }
            let local_peer_is_owner = replica_state.peers().contains_key(&this_peer_id);
            if replica_state.is_local != local_peer_is_owner {
                return Err(private_oram_candidate_inspection_error(
                    "replica ownership is inconsistent",
                ));
            }

            if replica_state.is_local {
                require_private_oram_candidate_directory(
                    &LocalShard::wal_path(&shard_dir),
                    "local shard WAL",
                )?;
                require_private_oram_candidate_directory(
                    &LocalShard::segments_path(&shard_dir),
                    "local shard segments",
                )?;
                local_shard_ids.push(shard_id);
            }

            let mut owner_peer_ids: Vec<_> = replica_state.peers().keys().copied().collect();
            owner_peer_ids.sort_unstable();
            shards.push(PrivateOramRecoveryShardTopology {
                shard_id,
                shard_key: shard_key_mapping
                    .as_ref()
                    .and_then(|mapping| mapping.shard_key(shard_id)),
                owner_peer_ids,
                is_local: replica_state.is_local,
            });
        }

        shards.sort_by_key(|shard| shard.shard_id);
        local_shard_ids.sort_unstable();
        Ok(PrivateOramRecoveryCandidateInspection {
            config,
            local_shard_ids,
            shards,
        })
    }
}

fn private_oram_candidate_actual_shard_ids(
    collection_path: &Path,
) -> CollectionResult<HashSet<ShardId>> {
    let entries = std::fs::read_dir(collection_path).map_err(|_| {
        private_oram_candidate_inspection_error("collection directory cannot be read")
    })?;
    let mut shard_ids = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| {
            private_oram_candidate_inspection_error("collection directory cannot be read")
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name.starts_with("shard_") && file_name.ends_with(".initializing") {
            return Err(private_oram_candidate_inspection_error(
                "shard initializing marker is present",
            ));
        }
        if !file_name.bytes().all(|byte| byte.is_ascii_digit()) || file_name.is_empty() {
            continue;
        }
        let shard_id: ShardId = file_name.parse().map_err(|_| {
            private_oram_candidate_inspection_error("shard directory name is invalid")
        })?;
        if file_name != shard_id.to_string() {
            return Err(private_oram_candidate_inspection_error(
                "shard directory name is not canonical",
            ));
        }
        let file_type = entry.file_type().map_err(|_| {
            private_oram_candidate_inspection_error("shard directory cannot be inspected")
        })?;
        if file_type.is_symlink() || !file_type.is_dir() || !shard_ids.insert(shard_id) {
            return Err(private_oram_candidate_inspection_error(
                "shard directory is invalid",
            ));
        }
    }
    Ok(shard_ids)
}

fn require_private_oram_candidate_directory(path: &Path, label: &str) -> CollectionResult<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        private_oram_candidate_inspection_error(&format!("{label} directory is missing"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(private_oram_candidate_inspection_error(&format!(
            "{label} must be a non-symlink directory"
        )));
    }
    Ok(())
}

fn require_private_oram_candidate_regular_file(path: &Path, label: &str) -> CollectionResult<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        private_oram_candidate_inspection_error(&format!("{label} file is missing"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(private_oram_candidate_inspection_error(&format!(
            "{label} must be a non-symlink regular file"
        )));
    }
    Ok(())
}

fn private_oram_candidate_inspection_error(reason: &str) -> CollectionError {
    CollectionError::service_error(format!(
        "private ORAM recovery candidate inspection failed: {reason}"
    ))
}

fn snapshot_shard_ids(
    config: &CollectionConfigInternal,
    collection_dir: &Path,
) -> CollectionResult<Vec<ShardId>> {
    let shard_ids: Vec<_> = match config.params.sharding_method.unwrap_or_default() {
        ShardingMethod::Auto => (0..config.params.shard_number.get()).collect(),
        ShardingMethod::Custom => {
            let mapping_path = collection_dir.join(SHARD_KEY_MAPPING_FILE);
            if !mapping_path.is_file() {
                return Err(CollectionError::service_error(
                    "custom-sharded snapshot is missing its shard mapping",
                ));
            }
            let shard_key_mapping: ShardKeyMapping = read_json(&mapping_path)?;
            shard_key_mapping.shard_ids()
        }
    };
    if shard_ids.len() != shard_ids.iter().collect::<HashSet<_>>().len() {
        return Err(CollectionError::service_error(
            "snapshot shard mapping contains duplicate shard ids",
        ));
    }
    Ok(shard_ids)
}

fn private_oram_snapshot_source_dir(
    collection_dir: &Path,
    dir_name: &str,
) -> CollectionResult<Option<PathBuf>> {
    let label = private_oram_label(dir_name);
    let source_dir = collection_dir.join(dir_name);
    match std::fs::symlink_metadata(&source_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            Err(CollectionError::service_error(format!(
                "{label} snapshot source must be a non-symlink directory",
            )))
        }
        Ok(_) => {
            validate_private_oram_snapshot_source_tree(
                &source_dir,
                Path::new(dir_name),
                label,
                dir_name,
                0,
            )?;
            Ok(Some(source_dir))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(CollectionError::service_error(format!(
            "{label} snapshot source cannot be inspected"
        ))),
    }
}

fn blocking_append_private_oram_snapshot_dir(
    tar: &BuilderExt,
    source_dir: &Path,
    archive_dir: &Path,
    dir_name: &str,
) -> CollectionResult<()> {
    let label = private_oram_label(dir_name);
    blocking_append_private_oram_snapshot_tree(tar, source_dir, archive_dir, dir_name, 0, label)
}

fn blocking_append_private_oram_snapshot_tree(
    tar: &BuilderExt,
    source_dir: &Path,
    archive_dir: &Path,
    dir_name: &str,
    depth: usize,
    label: &str,
) -> CollectionResult<()> {
    tar.blocking_append_dir(source_dir, archive_dir)
        .map_err(|_| {
            CollectionError::service_error(format!("{label} snapshot source cannot be archived"))
        })?;
    let entries = std::fs::read_dir(source_dir).map_err(|_| {
        CollectionError::service_error(format!("{label} snapshot source cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::service_error(format!("{label} snapshot source cannot be read"))
        })?;
        let file_name = entry.file_name();
        if private_oram_snapshot_source_entry_is_client_owned_state(&file_name) {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains client-owned ORAM state",
            )));
        }
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::service_error(format!("{label} snapshot source cannot be inspected"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains a symlink",
            )));
        }

        let archive_path = archive_dir.join(Path::new(&file_name));
        if !metadata.file_type().is_dir() && !metadata.file_type().is_file() {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains an unsupported file type",
            )));
        }
        if private_oram_snapshot_entry_is_unrecognized_retained_temp_state(
            dir_name,
            &archive_path,
            &metadata.file_type(),
        ) {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains incomplete private ORAM write state",
            )));
        }
        validate_private_oram_snapshot_archive_entry_layout(
            label,
            dir_name,
            &archive_path,
            &metadata.file_type(),
        )?;
        validate_private_oram_snapshot_source_epoch_file(
            &entry.path(),
            label,
            dir_name,
            &archive_path,
        )?;
        if metadata.file_type().is_dir() {
            if private_oram_snapshot_entry_is_temp_dir(dir_name, depth, &file_name)
                && !private_oram_snapshot_temp_dir_retains_owner_state(dir_name, &archive_path)
            {
                if private_oram_snapshot_dir_has_entries(&entry.path()).map_err(|_| {
                    CollectionError::service_error(format!(
                        "{label} snapshot source cannot be inspected"
                    ))
                })? {
                    return Err(CollectionError::service_error(format!(
                        "{label} snapshot source contains incomplete private ORAM write state",
                    )));
                }
                continue;
            }
            blocking_append_private_oram_snapshot_tree(
                tar,
                &entry.path(),
                &archive_path,
                dir_name,
                depth + 1,
                label,
            )?;
            continue;
        }
        tar.blocking_append_file(&entry.path(), &archive_path)
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "{label} snapshot source cannot be archived"
                ))
            })?;
    }

    Ok(())
}

fn private_oram_label(dir_name: &str) -> &'static str {
    match dir_name {
        PRIVATE_HNSW_ORAM_DIR => "private HNSW ORAM",
        PRIVATE_RESULT_ORAM_DIR => "private result ORAM",
        PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2 => "private ORAM mutation journal",
        _ => "private ORAM",
    }
}

fn validate_private_oram_snapshot_source_tree(
    source_dir: &Path,
    archive_dir: &Path,
    label: &str,
    dir_name: &str,
    depth: usize,
) -> CollectionResult<()> {
    let entries = std::fs::read_dir(source_dir).map_err(|_| {
        CollectionError::service_error(format!("{label} snapshot source cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::service_error(format!("{label} snapshot source cannot be read"))
        })?;
        if private_oram_snapshot_source_entry_is_client_owned_state(&entry.file_name()) {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains client-owned ORAM state",
            )));
        }
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::service_error(format!("{label} snapshot source cannot be inspected"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains a symlink",
            )));
        }
        if !metadata.file_type().is_dir() && !metadata.file_type().is_file() {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains an unsupported file type",
            )));
        }
        let archive_path = archive_dir.join(entry.file_name());
        if private_oram_snapshot_entry_is_unrecognized_retained_temp_state(
            dir_name,
            &archive_path,
            &metadata.file_type(),
        ) {
            return Err(CollectionError::service_error(format!(
                "{label} snapshot source contains incomplete private ORAM write state",
            )));
        }
        validate_private_oram_snapshot_archive_entry_layout(
            label,
            dir_name,
            &archive_path,
            &metadata.file_type(),
        )?;
        validate_private_oram_snapshot_source_epoch_file(
            &entry.path(),
            label,
            dir_name,
            &archive_path,
        )?;
        if metadata.file_type().is_dir() {
            if private_oram_snapshot_entry_is_temp_dir(dir_name, depth, &entry.file_name())
                && !private_oram_snapshot_temp_dir_retains_owner_state(dir_name, &archive_path)
                && private_oram_snapshot_dir_has_entries(&entry.path()).map_err(|_| {
                    CollectionError::service_error(format!(
                        "{label} snapshot source cannot be inspected"
                    ))
                })?
            {
                return Err(CollectionError::service_error(format!(
                    "{label} snapshot source contains incomplete private ORAM write state",
                )));
            }
            validate_private_oram_snapshot_source_tree(
                &entry.path(),
                &archive_path,
                label,
                dir_name,
                depth + 1,
            )?;
        }
    }
    Ok(())
}

fn validate_private_oram_snapshot_archive_entry_layout(
    label: &str,
    dir_name: &str,
    archive_path: &Path,
    file_type: &std::fs::FileType,
) -> CollectionResult<()> {
    let allowed =
        private_oram_snapshot_archive_entry_matches_layout(dir_name, archive_path, file_type)
            .unwrap_or(false);
    if allowed {
        return Ok(());
    }

    Err(CollectionError::service_error(format!(
        "{label} snapshot source contains an unexpected file",
    )))
}

fn private_oram_snapshot_archive_entry_matches_layout(
    dir_name: &str,
    archive_path: &Path,
    file_type: &std::fs::FileType,
) -> Option<bool> {
    let relative = archive_path.strip_prefix(Path::new(dir_name)).ok()?;
    let components = private_oram_snapshot_archive_components(relative)?;
    match dir_name {
        PRIVATE_RESULT_ORAM_DIR => Some(private_oram_snapshot_result_entry_matches_layout(
            &components,
            file_type,
        )),
        PRIVATE_HNSW_ORAM_DIR => Some(private_oram_snapshot_hnsw_entry_matches_layout(
            &components,
            file_type,
        )),
        PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2 => Some(
            private_oram_snapshot_parent_journal_entry_matches_layout(&components, file_type),
        ),
        _ => Some(true),
    }
}

fn private_oram_snapshot_archive_components(path: &Path) -> Option<Vec<&str>> {
    path.components()
        .map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect()
}

fn private_oram_snapshot_result_entry_matches_layout(
    components: &[&str],
    file_type: &std::fs::FileType,
) -> bool {
    match components {
        ["manifest.json"] | ["manifest.sig"] => file_type.is_file(),
        ["buckets"] | ["epochs"] | ["merkle"] | ["temp"] => file_type.is_dir(),
        ["buckets", file_name] => {
            file_type.is_file() && private_oram_snapshot_bucket_file_is_canonical(file_name)
        }
        ["epochs", "current.json"] => file_type.is_file(),
        ["epochs", file_name] => {
            file_type.is_file() && private_oram_snapshot_commit_file_is_canonical(file_name)
        }
        ["merkle", "nodes.dat"] => file_type.is_file(),
        _ => false,
    }
}

fn private_oram_snapshot_hnsw_entry_matches_layout(
    components: &[&str],
    file_type: &std::fs::FileType,
) -> bool {
    let Some(vector_name) = components.first() else {
        return false;
    };
    if !private_hnsw_oram_vector_name_is_safe_store_component(vector_name) {
        return false;
    }
    match components {
        [_vector_name] => file_type.is_dir(),
        [_vector_name, "manifest.json"] | [_vector_name, "manifest.sig"] => file_type.is_file(),
        [_vector_name, "buckets"]
        | [_vector_name, "epochs"]
        | [_vector_name, "merkle"]
        | [_vector_name, "temp"] => file_type.is_dir(),
        [_vector_name, "buckets", file_name] => {
            file_type.is_file() && private_oram_snapshot_bucket_file_is_canonical(file_name)
        }
        [_vector_name, "epochs", "current.json"] => file_type.is_file(),
        [_vector_name, "epochs", file_name] => {
            file_type.is_file() && private_oram_snapshot_commit_file_is_canonical(file_name)
        }
        [_vector_name, "merkle", "nodes.dat"] => file_type.is_file(),
        [_vector_name, "temp", owner_root] if private_oram_snapshot_owner_root_name(owner_root) => {
            file_type.is_dir()
        }
        [
            _vector_name,
            "temp",
            PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
            tail @ ..,
        ] => private_oram_snapshot_prestage_owner_entry_matches_layout(tail, file_type),
        [
            _vector_name,
            "temp",
            PRIVATE_ORAM_OWNER_JOURNAL_DIR,
            tail @ ..,
        ] => private_oram_snapshot_canonical_owner_entry_matches_layout(tail, file_type),
        _ => false,
    }
}

fn private_oram_snapshot_owner_root_name(name: &str) -> bool {
    matches!(
        name,
        PRIVATE_ORAM_OWNER_JOURNAL_DIR | PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2
    )
}

fn private_oram_snapshot_digest_component_is_canonical(name: &str) -> bool {
    BASE64URL_NOPAD
        .decode(name.as_bytes())
        .is_ok_and(|bytes| bytes.len() == 32 && BASE64URL_NOPAD.encode(&bytes) == name)
}

fn private_oram_snapshot_prestage_owner_entry_matches_layout(
    components: &[&str],
    file_type: &std::fs::FileType,
) -> bool {
    match components {
        ["intents"]
        | ["temp"]
        | ["terminals"]
        | ["retired"]
        | ["quarantine"]
        | ["reservation-fence"] => file_type.is_dir(),
        ["superblock.json"] => file_type.is_file(),
        [parent, intent]
            if matches!(*parent, "intents" | "retired" | "quarantine")
                && private_oram_snapshot_digest_component_is_canonical(intent) =>
        {
            file_type.is_dir()
        }
        [parent, intent, file_name]
            if matches!(*parent, "intents" | "retired" | "quarantine")
                && private_oram_snapshot_digest_component_is_canonical(intent) =>
        {
            file_type.is_file()
                && matches!(
                    *file_name,
                    "package.json"
                        | "receipt.json"
                        | "intent.json"
                        | "adoption-pending.json"
                        | "adopted.json"
                        | "descriptor.bin"
                        | "final-buckets.bin"
                        | "state.bin"
                )
        }
        ["terminals", intent] if private_oram_snapshot_digest_component_is_canonical(intent) => {
            file_type.is_dir()
        }
        ["terminals", intent, "record.json"]
            if private_oram_snapshot_digest_component_is_canonical(intent) =>
        {
            file_type.is_file()
        }
        ["reservation-fence", file_name] => {
            file_type.is_file()
                && matches!(
                    *file_name,
                    "fence.json" | "resolution.json" | "abort-release.json"
                )
        }
        _ => false,
    }
}

fn private_oram_snapshot_canonical_owner_entry_matches_layout(
    components: &[&str],
    file_type: &std::fs::FileType,
) -> bool {
    match components {
        [completed] => {
            file_type.is_dir() && private_oram_snapshot_parent_completed_dir_is_canonical(completed)
        }
        [completed, "temp"] | [completed, "terminal"] => {
            file_type.is_dir() && private_oram_snapshot_parent_completed_dir_is_canonical(completed)
        }
        [completed, file_name] => {
            private_oram_snapshot_parent_completed_dir_is_canonical(completed)
                && file_type.is_file()
                && matches!(
                    *file_name,
                    "descriptor.bin"
                        | "final-buckets.bin"
                        | "state.bin"
                        | "owner-terminal-archive-v1.json"
                )
        }
        [completed, "terminal", "record.bin"] => {
            file_type.is_file()
                && private_oram_snapshot_parent_completed_dir_is_canonical(completed)
        }
        _ => false,
    }
}

fn private_oram_snapshot_parent_journal_entry_matches_layout(
    components: &[&str],
    file_type: &std::fs::FileType,
) -> bool {
    match components {
        [PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2] => file_type.is_file(),
        ["temp"] => file_type.is_dir(),
        [completed] => {
            file_type.is_dir() && private_oram_snapshot_parent_completed_dir_is_canonical(completed)
        }
        [completed, "temp"] => {
            file_type.is_dir() && private_oram_snapshot_parent_completed_dir_is_canonical(completed)
        }
        [completed, "state_records"] => {
            file_type.is_dir() && private_oram_snapshot_parent_completed_dir_is_canonical(completed)
        }
        [completed, file_name] => {
            private_oram_snapshot_parent_completed_dir_is_canonical(completed)
                && file_type.is_file()
                && matches!(
                    *file_name,
                    "descriptor.json"
                        | "immutable_manifest.json"
                        | "state.json"
                        | "format.json"
                        | "cleanup_complete_v2.json"
                        | PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2
                        | PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1
                )
        }
        [completed, "state_records", record] => {
            private_oram_snapshot_parent_completed_dir_is_canonical(completed)
                && file_type.is_file()
                && private_oram_snapshot_parent_state_record_is_canonical(record)
        }
        _ => false,
    }
}

fn private_oram_snapshot_parent_completed_dir_is_canonical(name: &str) -> bool {
    let Some(generation) = name.strip_prefix("completed-v2-") else {
        return false;
    };
    generation.len() == 20
        && generation.bytes().all(|byte| byte.is_ascii_digit())
        && generation
            .parse::<u64>()
            .is_ok_and(|generation| generation > 0)
}

fn private_oram_snapshot_parent_state_record_is_canonical(name: &str) -> bool {
    let Some(sequence) = name.strip_suffix(".json") else {
        return false;
    };
    sequence.len() == 20
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && sequence
            .parse::<u64>()
            .is_ok_and(|sequence| (1..=7).contains(&sequence))
}

fn validate_private_oram_snapshot_source_epoch_file(
    source_path: &Path,
    label: &str,
    dir_name: &str,
    archive_path: &Path,
) -> CollectionResult<()> {
    let Some(expected_epoch) = private_oram_snapshot_archive_epoch_file(dir_name, archive_path)
    else {
        return Ok(());
    };
    validate_private_oram_snapshot_epoch_file(source_path, expected_epoch, label).map_err(|_| {
        CollectionError::service_error(format!(
            "{label} snapshot source contains an unexpected file",
        ))
    })
}

fn private_oram_snapshot_archive_epoch_file(
    dir_name: &str,
    archive_path: &Path,
) -> Option<Option<u64>> {
    let relative = archive_path.strip_prefix(Path::new(dir_name)).ok()?;
    let components = private_oram_snapshot_archive_components(relative)?;
    let file_name = match (dir_name, components.as_slice()) {
        (PRIVATE_RESULT_ORAM_DIR, ["epochs", file_name]) => *file_name,
        (PRIVATE_HNSW_ORAM_DIR, [_vector_name, "epochs", file_name]) => *file_name,
        _ => return None,
    };
    if file_name == "current.json" {
        return Some(None);
    }
    private_oram_snapshot_commit_file_epoch(file_name).map(Some)
}

fn private_oram_snapshot_source_entry_is_client_owned_state(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    private_oram_path_component_is_client_owned_state_alias(name)
}

fn private_oram_snapshot_entry_is_temp_dir(
    dir_name: &str,
    depth: usize,
    name: &std::ffi::OsStr,
) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    match dir_name {
        PRIVATE_RESULT_ORAM_DIR => depth == 0 && name == "temp",
        PRIVATE_HNSW_ORAM_DIR => (depth == 1 || depth >= 3) && name == "temp",
        PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2 => name == "temp",
        _ => false,
    }
}

fn private_oram_snapshot_temp_dir_retains_owner_state(dir_name: &str, archive_path: &Path) -> bool {
    let Ok(relative) = archive_path.strip_prefix(Path::new(dir_name)) else {
        return false;
    };
    private_oram_snapshot_archive_components(relative).is_some_and(|components| {
        match (dir_name, components.as_slice()) {
            (PRIVATE_HNSW_ORAM_DIR, [_vector_name, "temp"]) => true,
            (
                PRIVATE_HNSW_ORAM_DIR,
                [
                    _vector_name,
                    "temp",
                    PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
                    "temp",
                ],
            ) => true,
            (PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2, ["temp"]) => true,
            (
                PRIVATE_HNSW_ORAM_DIR,
                [
                    _vector_name,
                    "temp",
                    PRIVATE_ORAM_OWNER_JOURNAL_DIR,
                    completed,
                    "temp",
                ],
            ) => private_oram_snapshot_parent_completed_dir_is_canonical(completed),
            (PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2, [completed, "temp"]) => {
                private_oram_snapshot_parent_completed_dir_is_canonical(completed)
            }
            _ => false,
        }
    })
}

fn private_oram_snapshot_entry_is_unrecognized_retained_temp_state(
    dir_name: &str,
    archive_path: &Path,
    file_type: &std::fs::FileType,
) -> bool {
    archive_path.parent().is_some_and(|parent| {
        private_oram_snapshot_temp_dir_retains_owner_state(dir_name, parent)
            && !private_oram_snapshot_archive_entry_matches_layout(
                dir_name,
                archive_path,
                file_type,
            )
            .unwrap_or(false)
    })
}

fn private_oram_snapshot_dir_has_entries(path: &Path) -> std::io::Result<bool> {
    Ok(std::fs::read_dir(path)?.next().is_some())
}

fn ensure_snapshot_crypto_migration_state_allows_snapshot(
    collection_name: &str,
    params: &CollectionParams,
) -> CollectionResult<()> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(());
    };
    if encryption.migration_state != CryptoMigrationState::Active {
        return Err(CollectionError::bad_request(format!(
            "encrypted collection {collection_name} snapshot creation requires \
             migration_state=active; current state is {:?}. Finish or roll back the crypto \
             migration before creating a snapshot because in-flight migration snapshots are not \
             recovery-supported.",
            encryption.migration_state,
        )));
    }

    Ok(())
}

fn validate_private_result_oram_snapshot_store_matches_config(
    collection_dir: &Path,
    configured: bool,
) -> CollectionResult<()> {
    let private_result_oram_path = collection_dir.join(PRIVATE_RESULT_ORAM_DIR);
    let metadata = match std::fs::symlink_metadata(&private_result_oram_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound && !configured => return Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(CollectionError::bad_request(
                "private result ORAM snapshot store is missing for configured binding",
            ));
        }
        Err(_) => {
            return Err(CollectionError::bad_request(
                "private result ORAM snapshot store root cannot be inspected",
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot store root must be a non-symlink directory",
        ));
    }

    if !configured {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot store is present without a matching collection encryption rule",
        ));
    }
    validate_private_oram_snapshot_restore_tree_has_no_client_owned_state(
        &private_result_oram_path,
        Path::new(PRIVATE_RESULT_ORAM_DIR),
        "private result ORAM",
        PRIVATE_RESULT_ORAM_DIR,
        0,
    )?;

    Ok(())
}

fn validate_private_oram_shard_snapshot_operation(
    _collection_name: &str,
    params: &CollectionParams,
    _operation_name: &str,
) -> CollectionResult<()> {
    if private_hnsw_oram_configured_vectors(params)?.is_empty()
        && !private_result_oram_configured(params)?
    {
        return Ok(());
    }

    Err(CollectionError::bad_request(
        "shard snapshot operations for private ORAM collections are disabled until shard snapshots include \
         collection-local encrypted ORAM buckets with epoch/root parity; \
         use collection snapshot/restore preflight",
    ))
}

fn validate_private_hnsw_oram_vector_snapshot(
    collection_dir: &Path,
    stable_crypto_id: &str,
    params: &CollectionParams,
    vector_name: &str,
) -> CollectionResult<()> {
    let vector_params = params.vectors.get_params(vector_name).ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM snapshot vector is not configured")
    })?;
    let expected_dim = u32::try_from(vector_params.size.get()).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM snapshot vector dimension exceeds u32")
    })?;
    let expected_distance = private_hnsw_distance_kind(vector_params.distance);

    let store = PrivateHnswOramStore::new(collection_dir, vector_name)?;
    let (manifest, signature) = store.read_manifest()?;
    let private_result_oram_path_batch_size =
        private_result_oram_snapshot_path_batch_size_for_hnsw_restore(
            collection_dir,
            stable_crypto_id,
            params,
            manifest.result_privacy,
        )?;
    validate_private_hnsw_oram_restore_manifest(
        &manifest,
        &signature,
        stable_crypto_id,
        params,
        vector_name,
        expected_dim,
        expected_distance,
        private_result_oram_path_batch_size,
    )?;
    validate_private_oram_snapshot_store_layout(
        store.root_path(),
        manifest.bucket_count,
        "private HNSW ORAM",
    )?;

    let current_epoch = store.read_current_epoch()?;
    if current_epoch.index_epoch != manifest.index_epoch
        || current_epoch.root_hash != manifest.root_hash
    {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot current epoch/root does not match manifest",
        ));
    }

    let expected_bucket_ciphertext_bytes =
        private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest)?;
    let mut bucket_commitments = Vec::new();
    for bucket_id in 0..manifest.bucket_count {
        let bucket = store.read_bucket(
            bucket_id,
            manifest.index_epoch,
            manifest.bucket_count,
            expected_bucket_ciphertext_bytes,
        )?;
        validate_private_hnsw_restore_bucket_contract(
            &manifest,
            &bucket,
            expected_bucket_ciphertext_bytes,
        )?;
        bucket_commitments.push(bucket.bucket_commitment);
    }
    let bucket_root = PrivateHnswOramStore::merkle_root_for_commitments(&bucket_commitments)?;
    if bucket_root != manifest.root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot bucket commitments do not match manifest root_hash",
        ));
    }
    let last_bucket_id = manifest.bucket_count.saturating_sub(1);
    let bucket_ids = if last_bucket_id == 0 {
        vec![0]
    } else {
        vec![0, last_bucket_id]
    };
    store.read_merkle_path_batch(
        &bucket_ids,
        manifest.index_epoch,
        &manifest.root_hash,
        manifest.bucket_count,
    )?;

    Ok(())
}

fn validate_private_result_oram_snapshot(
    collection_dir: &Path,
    stable_crypto_id: &str,
    params: &CollectionParams,
) -> CollectionResult<()> {
    let store = PrivateResultOramStore::new(collection_dir);
    let (manifest, signature) = store.read_manifest()?;
    validate_private_result_oram_restore_manifest(&manifest, &signature, stable_crypto_id, params)?;
    validate_private_oram_snapshot_store_layout(
        store.root_path(),
        manifest.bucket_count,
        "private result ORAM",
    )?;

    let current_epoch = store.read_current_epoch()?;
    if current_epoch.index_epoch != manifest.index_epoch
        || current_epoch.root_hash != manifest.root_hash
    {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot current epoch/root does not match manifest",
        ));
    }

    let max_ciphertext_bytes = private_result_restore_max_bucket_ciphertext_bytes(&manifest)?;
    let expected_ciphertext_bytes =
        private_result_restore_expected_bucket_ciphertext_bytes(&manifest)?;
    let mut bucket_commitments = Vec::new();
    for bucket_id in 0..manifest.bucket_count {
        let bucket = store.read_bucket(
            bucket_id,
            manifest.index_epoch,
            manifest.bucket_count,
            max_ciphertext_bytes,
        )?;
        validate_private_result_restore_bucket_contract(
            &manifest,
            &bucket,
            expected_ciphertext_bytes,
        )?;
        bucket_commitments.push(bucket.bucket_commitment);
    }
    let bucket_root = PrivateResultOramStore::merkle_root_for_commitments(&bucket_commitments)?;
    if bucket_root != manifest.root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot bucket commitments do not match manifest root_hash",
        ));
    }
    let last_bucket_id = manifest.bucket_count.saturating_sub(1);
    let bucket_ids = if last_bucket_id == 0 {
        vec![0]
    } else {
        vec![0, last_bucket_id]
    };
    store.read_merkle_path_batch(
        &bucket_ids,
        manifest.index_epoch,
        &manifest.root_hash,
        manifest.bucket_count,
    )?;

    Ok(())
}

fn validate_private_oram_snapshot_store_layout(
    store_root: &Path,
    bucket_count: u64,
    label: &str,
) -> CollectionResult<()> {
    validate_private_oram_snapshot_store_root_entries(store_root, label)?;
    validate_private_oram_snapshot_merkle_dir(store_root, label)?;
    validate_private_oram_snapshot_epochs_dir(store_root, label)?;
    validate_private_oram_snapshot_bucket_dir_matches_manifest(
        &store_root.join("buckets"),
        bucket_count,
        label,
    )
}

fn validate_private_oram_snapshot_store_root_entries(
    store_root: &Path,
    label: &str,
) -> CollectionResult<()> {
    let entries = std::fs::read_dir(store_root).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot store cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot store cannot be read"))
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Err(private_oram_snapshot_unexpected_store_file_error(label));
        };
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot store cannot be inspected"))
        })?;
        let file_type = metadata.file_type();
        match file_name {
            "manifest.json" | "manifest.sig" if file_type.is_file() => {}
            "buckets" | "epochs" | "merkle" | "temp" if file_type.is_dir() => {}
            _ => return Err(private_oram_snapshot_unexpected_store_file_error(label)),
        }
    }

    Ok(())
}

fn validate_private_oram_snapshot_merkle_dir(
    store_root: &Path,
    label: &str,
) -> CollectionResult<()> {
    let merkle_dir = store_root.join("merkle");
    let entries = std::fs::read_dir(&merkle_dir).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot Merkle store cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot Merkle store cannot be read"))
        })?;
        let file_name = entry.file_name();
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(format!(
                "{label} snapshot Merkle store cannot be inspected"
            ))
        })?;
        if file_name.to_str() != Some("nodes.dat") || !metadata.file_type().is_file() {
            return Err(private_oram_snapshot_unexpected_store_file_error(label));
        }
    }

    Ok(())
}

fn validate_private_oram_snapshot_epochs_dir(
    store_root: &Path,
    label: &str,
) -> CollectionResult<()> {
    let epochs_dir = store_root.join("epochs");
    let entries = std::fs::read_dir(&epochs_dir).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot epoch store cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot epoch store cannot be read"))
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Err(private_oram_snapshot_unexpected_store_file_error(label));
        };
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(format!(
                "{label} snapshot epoch store cannot be inspected"
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(private_oram_snapshot_unexpected_store_file_error(label));
        }
        if file_name == "current.json" {
            continue;
        }
        let Some(epoch) = private_oram_snapshot_commit_file_epoch(file_name) else {
            return Err(private_oram_snapshot_unexpected_store_file_error(label));
        };
        if file_name != format!("{epoch:08}.commit") {
            return Err(private_oram_snapshot_unexpected_store_file_error(label));
        }
        validate_private_oram_snapshot_epoch_file(&entry.path(), Some(epoch), label)?;
    }

    Ok(())
}

fn validate_private_oram_snapshot_epoch_file(
    path: &Path,
    expected_epoch: Option<u64>,
    label: &str,
) -> CollectionResult<()> {
    let metadata = std::fs::metadata(path).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot epoch store cannot be inspected"))
    })?;
    if metadata.len() > PRIVATE_ORAM_SNAPSHOT_MAX_EPOCH_BYTES {
        return Err(private_oram_snapshot_unexpected_store_file_error(label));
    }
    let bytes = std::fs::read(path).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot epoch store cannot be read"))
    })?;
    if bytes.len() as u64 > PRIVATE_ORAM_SNAPSHOT_MAX_EPOCH_BYTES {
        return Err(private_oram_snapshot_unexpected_store_file_error(label));
    }
    let epoch: PrivateOramSnapshotEpochFile = serde_json::from_slice(&bytes)
        .map_err(|_| private_oram_snapshot_unexpected_store_file_error(label))?;
    if expected_epoch.is_some_and(|expected_epoch| epoch.index_epoch != expected_epoch)
        || !private_oram_snapshot_root_hash_is_canonical(&epoch.root_hash)
        || expected_epoch.is_none() && epoch.writeback_digest.is_some()
        || epoch
            .writeback_digest
            .as_deref()
            .is_some_and(|digest| !private_oram_snapshot_root_hash_is_canonical(digest))
    {
        return Err(private_oram_snapshot_unexpected_store_file_error(label));
    }

    Ok(())
}

fn validate_private_oram_snapshot_bucket_dir_matches_manifest(
    buckets_dir: &Path,
    bucket_count: u64,
    label: &str,
) -> CollectionResult<()> {
    let entries = std::fs::read_dir(buckets_dir).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot bucket store cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot bucket store cannot be read"))
        })?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(format!(
                "{label} snapshot bucket store cannot be inspected"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot bucket store contains an unexpected file",
            )));
        }

        let file_name = entry.file_name().into_string().map_err(|_| {
            CollectionError::bad_request(format!(
                "{label} snapshot bucket store contains an unexpected file",
            ))
        })?;
        let Some(bucket_id) = private_oram_snapshot_bucket_file_id(&file_name) else {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot bucket store contains an unexpected file",
            )));
        };
        if bucket_id >= bucket_count || file_name != format!("{bucket_id:08}.bucket") {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot bucket store contains an unexpected file",
            )));
        }
    }

    Ok(())
}

fn private_oram_snapshot_unexpected_store_file_error(label: &str) -> CollectionError {
    CollectionError::bad_request(format!(
        "{label} snapshot store contains an unexpected file"
    ))
}

fn private_oram_snapshot_bucket_file_id(file_name: &str) -> Option<u64> {
    let bucket_id = file_name.strip_suffix(".bucket")?;
    if bucket_id.is_empty() || !bucket_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    bucket_id.parse().ok()
}

fn private_oram_snapshot_bucket_file_is_canonical(file_name: &str) -> bool {
    private_oram_snapshot_bucket_file_id(file_name)
        .is_some_and(|bucket_id| file_name == format!("{bucket_id:08}.bucket"))
}

fn private_oram_snapshot_commit_file_epoch(file_name: &str) -> Option<u64> {
    let epoch = file_name.strip_suffix(".commit")?;
    if epoch.is_empty() || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    epoch.parse().ok()
}

fn private_oram_snapshot_commit_file_is_canonical(file_name: &str) -> bool {
    private_oram_snapshot_commit_file_epoch(file_name)
        .is_some_and(|epoch| file_name == format!("{epoch:08}.commit"))
}

fn private_oram_snapshot_root_hash_is_canonical(root_hash: &str) -> bool {
    BASE64URL_NOPAD
        .decode(root_hash.as_bytes())
        .is_ok_and(|bytes| bytes.len() == 32)
}

fn private_result_oram_configured(params: &CollectionParams) -> CollectionResult<bool> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(false);
    };

    let mut configured = false;
    for rule in encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING))
    {
        if !matches!(rule.selector, EncryptionSelector::PayloadPaths { .. }) {
            return Err(CollectionError::bad_request(
                "private result ORAM snapshot rules must use payload_paths selector",
            ));
        }
        if configured {
            return Err(CollectionError::bad_request(
                "private result ORAM snapshot supports one configured binding in v1",
            ));
        }
        configured = true;
    }

    Ok(configured)
}

fn private_result_oram_snapshot_path_batch_size_for_hnsw_restore(
    collection_dir: &Path,
    stable_crypto_id: &str,
    params: &CollectionParams,
    result_privacy: ResultPrivacyMode,
) -> CollectionResult<Option<u32>> {
    if result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired {
        return Ok(None);
    }
    if !private_result_oram_configured(params)? {
        return Ok(None);
    }

    validate_private_result_oram_snapshot_store_matches_config(collection_dir, true)?;
    let store = PrivateResultOramStore::new(collection_dir);
    let (manifest, signature) = store.read_manifest().map_err(|_| {
        CollectionError::bad_request(
            "private HNSW ORAM snapshot restore result_privacy=private_payload_oram_required \
             requires a readable private result ORAM snapshot manifest",
        )
    })?;
    validate_private_result_oram_restore_manifest(&manifest, &signature, stable_crypto_id, params)?;
    Ok(Some(manifest.oram.path_batch_size))
}

fn private_hnsw_oram_configured_vectors(
    params: &CollectionParams,
) -> CollectionResult<HashSet<String>> {
    let mut configured_vectors = HashSet::new();
    let Some(encryption) = params.effective_encryption() else {
        return Ok(configured_vectors);
    };

    for rule in encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING))
    {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot rules must use vector_names selector",
            ));
        };
        if names.len() != 1 {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot rules must select exactly one vector in v1",
            ));
        }
        for name in names {
            if !private_hnsw_oram_vector_name_is_safe_store_component(name) {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM snapshot configured vector name must be a safe store path component",
                ));
            }
            if !configured_vectors.insert(name.clone()) {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM snapshot supports one configured binding per vector in v1",
                ));
            }
        }
    }

    Ok(configured_vectors)
}

fn validate_private_hnsw_oram_snapshot_store_matches_config(
    collection_dir: &Path,
    configured_vectors: &HashSet<String>,
) -> CollectionResult<()> {
    let private_hnsw_root = collection_dir.join(PRIVATE_HNSW_ORAM_DIR);
    let metadata = match std::fs::symlink_metadata(&private_hnsw_root) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound && configured_vectors.is_empty() => {
            return Ok(());
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot store is missing for configured vector rules",
            ));
        }
        Err(_) => {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot store root cannot be inspected",
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot store root must be a non-symlink directory",
        ));
    }

    if configured_vectors.is_empty() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot store is present without a matching collection encryption rule",
        ));
    }
    validate_private_oram_snapshot_restore_tree_has_no_client_owned_state(
        &private_hnsw_root,
        Path::new(PRIVATE_HNSW_ORAM_DIR),
        "private HNSW ORAM",
        PRIVATE_HNSW_ORAM_DIR,
        0,
    )?;

    let entries = std::fs::read_dir(&private_hnsw_root).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM snapshot store root cannot be read")
    })?;
    let mut stored_vectors = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM snapshot store entry cannot be read")
        })?;
        let file_name = entry.file_name().into_string().map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM snapshot contains a non-UTF-8 vector store",
            )
        })?;
        let entry_metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM snapshot vector store cannot be inspected",
            )
        })?;
        if entry_metadata.file_type().is_symlink() || !entry_metadata.file_type().is_dir() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot vector store must be a non-symlink directory",
            ));
        }
        if !configured_vectors.contains(&file_name) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot contains an unconfigured vector store",
            ));
        }
        stored_vectors.insert(file_name);
    }

    if stored_vectors.len() != configured_vectors.len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot is missing a configured vector store",
        ));
    }

    Ok(())
}

fn validate_private_oram_snapshot_restore_tree_has_no_client_owned_state(
    root: &Path,
    archive_dir: &Path,
    label: &str,
    dir_name: &str,
    depth: usize,
) -> CollectionResult<()> {
    let entries = std::fs::read_dir(root).map_err(|_| {
        CollectionError::bad_request(format!("{label} snapshot store cannot be read"))
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot store cannot be read"))
        })?;
        if private_oram_snapshot_source_entry_is_client_owned_state(&entry.file_name()) {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot store contains client-owned ORAM state",
            )));
        }
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(format!("{label} snapshot store cannot be inspected"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot store contains a symlink",
            )));
        }
        let archive_path = archive_dir.join(entry.file_name());
        if private_oram_snapshot_entry_is_unrecognized_retained_temp_state(
            dir_name,
            &archive_path,
            &metadata.file_type(),
        ) {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot store contains incomplete private ORAM write state",
            )));
        }
        validate_private_oram_snapshot_archive_entry_layout(
            label,
            dir_name,
            &archive_path,
            &metadata.file_type(),
        )?;
        if metadata.file_type().is_dir() {
            if private_oram_snapshot_entry_is_temp_dir(dir_name, depth, &entry.file_name())
                && !private_oram_snapshot_temp_dir_retains_owner_state(dir_name, &archive_path)
                && private_oram_snapshot_dir_has_entries(&entry.path()).map_err(|_| {
                    CollectionError::bad_request(format!(
                        "{label} snapshot store cannot be inspected"
                    ))
                })?
            {
                return Err(CollectionError::bad_request(format!(
                    "{label} snapshot store contains incomplete private ORAM write state",
                )));
            }
            validate_private_oram_snapshot_restore_tree_has_no_client_owned_state(
                &entry.path(),
                &archive_path,
                label,
                dir_name,
                depth + 1,
            )?;
        } else if !metadata.file_type().is_file() {
            return Err(CollectionError::bad_request(format!(
                "{label} snapshot store contains an unsupported file type",
            )));
        }
    }

    Ok(())
}

fn sanitize_private_hnsw_snapshot_layout_error(
    collection_dir: &Path,
    err: CollectionError,
) -> CollectionError {
    let rendered = err.to_string();
    if private_oram_snapshot_layout_error_contains_sensitive_detail(
        &rendered,
        collection_dir,
        PRIVATE_HNSW_ORAM_DIR,
    ) {
        return CollectionError::bad_request("private HNSW ORAM snapshot layout validation failed");
    }
    err
}

fn sanitize_private_result_oram_snapshot_layout_error(
    collection_dir: &Path,
    err: CollectionError,
) -> CollectionError {
    let rendered = err.to_string();
    if private_oram_snapshot_layout_error_contains_sensitive_detail(
        &rendered,
        collection_dir,
        PRIVATE_RESULT_ORAM_DIR,
    ) {
        return CollectionError::bad_request(
            "private result ORAM snapshot layout validation failed",
        );
    }
    err
}

fn private_oram_snapshot_layout_error_contains_sensitive_detail(
    rendered: &str,
    collection_dir: &Path,
    private_oram_dir: &str,
) -> bool {
    let collection_dir = collection_dir.to_string_lossy();
    rendered.contains(collection_dir.as_ref())
        || rendered.contains(private_oram_dir)
        || private_oram_snapshot_layout_error_contains_sensitive_marker(rendered)
        || rendered
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')))
            .any(|token| {
                token.ends_with(".bucket") || looks_like_base64url_private_oram_token(token)
            })
}

fn private_oram_snapshot_layout_error_contains_sensitive_marker(rendered: &str) -> bool {
    const SENSITIVE_MARKERS: &[&str] = &[
        "accessed_leaf_labels",
        "bucket id",
        "bucket_id",
        "bucket_ids",
        "ciphertext",
        "client_signature",
        "commit_signature",
        "entry_node_id",
        "leaf hash",
        "leaf_hash",
        "leaf_label",
        "manifest_signature",
        "new_root_hash",
        "node_id",
        "old_root_hash",
        "path_label",
        "payload.fetch.token",
        "payload_fetch_token",
        "payload_fetch_tokens",
        "point_token",
        "proof",
        "read_bucket_id",
        "read_bucket_ids",
        "read_signature",
        "root_hash",
        "sibling hash",
        "sibling_hash",
        "signature",
        "visited_node_id",
        "visited_node_ids",
    ];
    const COMPACT_SENSITIVE_MARKERS: &[&str] = &[
        "accessvolume",
        "accessvolumecount",
        "accessvolumecounts",
        "accessvolumelen",
        "accessvolumelength",
        "accessvolumelengths",
        "accessedleaflabels",
        "bucketid",
        "bucketids",
        "clientsignature",
        "commitsignature",
        "entrynodeid",
        "leafhash",
        "leaflabel",
        "manifestsignature",
        "newroothash",
        "nodeid",
        "oldroothash",
        "pathlabel",
        "payloadfetchtoken",
        "payloadfetchtokens",
        "pointtoken",
        "proofvalue",
        "proofvalues",
        "readbucketid",
        "readbucketids",
        "readsignature",
        "resultid",
        "resultids",
        "roothash",
        "siblinghash",
        "visitednodeid",
        "visitednodeids",
    ];

    let rendered = rendered.to_ascii_lowercase();
    if SENSITIVE_MARKERS
        .iter()
        .any(|marker| rendered.contains(marker))
    {
        return true;
    }

    let compact_rendered = rendered.replace(['_', '-', '.', ' '], "");
    COMPACT_SENSITIVE_MARKERS
        .iter()
        .any(|marker| compact_rendered.contains(marker))
}

fn looks_like_base64url_private_oram_token(token: &str) -> bool {
    token.len() >= 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn validate_private_hnsw_oram_restore_manifest(
    manifest: &PrivateHnswOramManifest,
    signature: &PrivateHnswOramSignature,
    stable_crypto_id: &str,
    params: &CollectionParams,
    vector_name: &str,
    expected_dim: u32,
    expected_distance: DistanceKind,
    private_result_oram_path_batch_size: Option<u32>,
) -> CollectionResult<()> {
    validate_private_hnsw_oram_manifest_shape(manifest).map_err(private_hnsw_restore_error)?;
    validate_private_hnsw_oram_manifest_signature_shape(signature)
        .map_err(private_hnsw_restore_error)?;
    if manifest.result_privacy == ResultPrivacyMode::PrivatePayloadOramRequired {
        let Some(result_path_batch_size) = private_result_oram_path_batch_size else {
            return Err(CollectionError::bad_request(format!(
                "private HNSW ORAM snapshot restore result_privacy=private_payload_oram_required \
                 requires a {PRIVATE_RESULT_ORAM_BINDING} payload rule backed by \
                 {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}"
            )));
        };
        if result_path_batch_size == 0
            || manifest.fixed_budget.fixed_result_k % result_path_batch_size != 0
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot restore result_privacy=private_payload_oram_required \
                 requires result ORAM oram.path_batch_size to divide private HNSW \
                 fixed_budget.fixed_result_k for fixed-size read_buckets batches",
            ));
        }
    }
    if signature.key_id != manifest.owner_signing_key_id {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot manifest signature key_id does not match owner_signing_key_id",
        ));
    }
    if manifest.collection_id != stable_crypto_id {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot manifest collection_id mismatch",
        ));
    }
    if let Some(encryption) = params.effective_encryption() {
        if let Some(collection_key_id) = encryption.key_id.as_deref() {
            if manifest.key_id != collection_key_id {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM snapshot manifest key_id mismatch",
                ));
            }
            if manifest.rk_id != collection_key_id {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM snapshot manifest rk_id mismatch",
                ));
            }
        }
        if manifest.rk_epoch != encryption.encryption_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot manifest rk_epoch mismatch",
            ));
        }
    }
    if manifest.vector_name != vector_name {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot manifest vector_name mismatch",
        ));
    }
    if manifest.dim != expected_dim {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot manifest dim mismatch",
        ));
    }
    if manifest.distance != expected_distance {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot manifest distance mismatch",
        ));
    }
    Ok(())
}

fn validate_private_result_oram_restore_manifest(
    manifest: &PrivateResultOramManifest,
    signature: &PrivateResultOramSignature,
    stable_crypto_id: &str,
    params: &CollectionParams,
) -> CollectionResult<()> {
    validate_private_result_oram_manifest_shape(manifest).map_err(private_result_restore_error)?;
    validate_private_result_oram_manifest_signature_shape(signature)
        .map_err(private_result_restore_error)?;
    if signature.key_id != manifest.owner_signing_key_id {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot manifest signature key_id does not match owner_signing_key_id",
        ));
    }
    if manifest.collection_id != stable_crypto_id {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot manifest collection_id mismatch",
        ));
    }
    if let Some(encryption) = params.effective_encryption()
        && let Some(collection_key_id) = encryption.key_id.as_deref()
    {
        if manifest.key_id != collection_key_id {
            return Err(CollectionError::bad_request(
                "private result ORAM snapshot manifest key_id mismatch",
            ));
        }
        if manifest.rk_id != collection_key_id {
            return Err(CollectionError::bad_request(
                "private result ORAM snapshot manifest rk_id mismatch",
            ));
        }
    }
    if let Some(encryption) = params.effective_encryption()
        && manifest.rk_epoch != encryption.encryption_epoch
    {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot manifest rk_epoch mismatch",
        ));
    }
    Ok(())
}

fn private_hnsw_restore_expected_bucket_ciphertext_bytes(
    manifest: &PrivateHnswOramManifest,
) -> CollectionResult<usize> {
    private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_hnsw_restore_bucket_ciphertext_size_error)
}

fn private_hnsw_restore_bucket_ciphertext_size_error(
    _err: qdrant_sec::PrivateHnswOramError,
) -> CollectionError {
    CollectionError::bad_request("private HNSW ORAM snapshot bucket ciphertext size is invalid")
}

fn validate_private_hnsw_restore_bucket_contract(
    manifest: &PrivateHnswOramManifest,
    bucket: &PrivateHnswOramBucket,
    expected_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    let expected_ciphertext_b64_len =
        private_oram_snapshot_base64url_nopad_encoded_len(expected_ciphertext_bytes)?;
    if bucket.ciphertext.len() != expected_ciphertext_b64_len {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM snapshot bucket ciphertext is not base64url",
            )
        })?;
    if ciphertext.len() != expected_ciphertext_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot bucket ciphertext must match fixed ciphertext size",
        ));
    }

    let expected_commitment = private_hnsw_bucket_commitment(
        PrivateHnswBucketAeadBaseContext {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
        }
        .for_bucket(bucket.bucket_id, bucket.index_epoch),
        &bucket.ciphertext_sha256,
    )
    .map_err(|_| {
        CollectionError::bad_request(
            "private HNSW ORAM snapshot bucket commitment context mismatch",
        )
    })?;
    if expected_commitment != bucket.bucket_commitment {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot bucket commitment context mismatch",
        ));
    }
    Ok(())
}

fn private_result_restore_max_bucket_ciphertext_bytes(
    manifest: &PrivateResultOramManifest,
) -> CollectionResult<usize> {
    let block_size = usize::try_from(manifest.oram.block_size_bytes).map_err(|_| {
        CollectionError::bad_request("private result ORAM snapshot block_size_bytes is invalid")
    })?;
    let bucket_size = usize::try_from(manifest.oram.bucket_size).map_err(|_| {
        CollectionError::bad_request("private result ORAM snapshot bucket_size is invalid")
    })?;
    block_size
        .checked_mul(bucket_size)
        .and_then(|size| size.checked_add(4096))
        .ok_or_else(|| {
            CollectionError::bad_request("private result ORAM snapshot bucket size is invalid")
        })
}

fn private_result_restore_expected_bucket_ciphertext_bytes(
    manifest: &PrivateResultOramManifest,
) -> CollectionResult<usize> {
    private_result_oram_bucket_ciphertext_bytes(&manifest.oram).map_err(|_| {
        CollectionError::bad_request("private result ORAM snapshot bucket size is invalid")
    })
}

fn validate_private_result_restore_bucket_contract(
    manifest: &PrivateResultOramManifest,
    bucket: &PrivateResultOramBucket,
    expected_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    // A write-back rewrites only the buckets on the paths it read; every other bucket keeps the
    // epoch it was sealed (and committed) at, as the store's reads allow.
    if bucket.index_epoch > manifest.index_epoch {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot bucket is newer than its manifest",
        ));
    }
    let expected_ciphertext_b64_len =
        private_oram_snapshot_base64url_nopad_encoded_len(expected_ciphertext_bytes)?;
    if bucket.ciphertext.len() != expected_ciphertext_b64_len {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request(
                "private result ORAM snapshot bucket ciphertext is not base64url",
            )
        })?;
    if ciphertext.len() != expected_ciphertext_bytes {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let expected_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id: bucket.bucket_id,
            index_epoch: bucket.index_epoch,
        },
        &bucket.ciphertext_sha256,
    )
    .map_err(|_| {
        CollectionError::bad_request(
            "private result ORAM snapshot bucket commitment context mismatch",
        )
    })?;
    if expected_commitment != bucket.bucket_commitment {
        return Err(CollectionError::bad_request(
            "private result ORAM snapshot bucket commitment context mismatch",
        ));
    }
    Ok(())
}

fn private_oram_snapshot_base64url_nopad_encoded_len(byte_len: usize) -> CollectionResult<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => {
            return Err(CollectionError::bad_request(
                "private ORAM snapshot bucket ciphertext size is invalid",
            ));
        }
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
        .ok_or_else(|| {
            CollectionError::bad_request("private ORAM snapshot bucket ciphertext size is invalid")
        })
}

fn private_hnsw_restore_error(_err: qdrant_sec::PrivateHnswOramError) -> CollectionError {
    CollectionError::bad_request("private HNSW ORAM snapshot manifest or signature is invalid")
}

fn private_result_restore_error(_err: qdrant_sec::PrivateResultOramError) -> CollectionError {
    CollectionError::bad_request("private result ORAM snapshot manifest or signature is invalid")
}

fn private_hnsw_distance_kind(distance: segment::types::Distance) -> DistanceKind {
    match distance {
        segment::types::Distance::Cosine => DistanceKind::Cosine,
        segment::types::Distance::Euclid => DistanceKind::Euclid,
        segment::types::Distance::Dot => DistanceKind::Dot,
        segment::types::Distance::Manhattan => DistanceKind::Manhattan,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::num::NonZeroU32;

    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        FixedBudgetParams, OramKind, OramParams, PrivateHnswOramBucket, PrivateHnswParams,
        ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
    };
    use segment::types::{Distance, HnswConfig};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::config::{
        CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, EncryptionRuleRef,
        WalConfig,
    };
    use crate::operations::types::VectorsConfig;
    use crate::operations::vector_params_builder::VectorParamsBuilder;
    use crate::optimizers_builder::OptimizersConfig;

    fn params_with_migration_state(migration_state: CryptoMigrationState) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state,
                rules: Vec::new(),
            }),
            ..CollectionParams::empty()
        }
    }

    fn private_hnsw_config(uuid: Uuid) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    "text".into(),
                    VectorParamsBuilder::new(1536, Distance::Cosine).build(),
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/vector-private-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "docs_text_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec!["text".to_string()],
                        },
                        instance: "docs_text_private_hnsw".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig::fixture(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(uuid),
            metadata: None,
        }
    }

    fn private_result_config(uuid: Uuid) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/result-private-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "docs_body_private_result".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_private_result_oram".to_string(),
                        binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig::fixture(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(uuid),
            metadata: None,
        }
    }

    #[test]
    fn restored_private_oram_snapshot_reports_exact_local_replica_shards() {
        use crate::shards::replica_set::replica_set_state::{ReplicaSetState, ReplicaState};

        let temp = tempfile::tempdir().unwrap();
        let config = private_hnsw_config(Uuid::from_u128(7));
        let shard_dir = shard_path(temp.path(), 0);
        fs::create_dir_all(&shard_dir).unwrap();
        ShardConfig::new_replica_set().save(&shard_dir).unwrap();

        let mut replica_state = ReplicaSetState::default();
        replica_state.is_local = true;
        replica_state.this_peer_id = 11;
        replica_state.set_peer_state(11, ReplicaState::Active);
        fs::write(
            shard_dir.join(REPLICA_STATE_FILE),
            serde_json::to_vec(&replica_state).unwrap(),
        )
        .unwrap();

        assert_eq!(
            Collection::private_oram_restored_snapshot_local_shard_ids(&config, temp.path(), 11,)
                .unwrap(),
            vec![0]
        );

        replica_state.is_local = false;
        fs::write(
            shard_dir.join(REPLICA_STATE_FILE),
            serde_json::to_vec(&replica_state).unwrap(),
        )
        .unwrap();
        assert!(
            Collection::private_oram_restored_snapshot_local_shard_ids(&config, temp.path(), 11,)
                .unwrap()
                .is_empty()
        );

        replica_state.this_peer_id = 12;
        fs::write(
            shard_dir.join(REPLICA_STATE_FILE),
            serde_json::to_vec(&replica_state).unwrap(),
        )
        .unwrap();
        assert!(
            Collection::private_oram_restored_snapshot_local_shard_ids(&config, temp.path(), 11,)
                .is_err()
        );
    }

    fn write_private_oram_recovery_candidate_root(
        collection_dir: &Path,
        config: &CollectionConfigInternal,
    ) {
        config.save(collection_dir).unwrap();
        fs::write(
            collection_dir.join(common::storage_version::VERSION_FILE),
            CollectionVersion::current_raw(),
        )
        .unwrap();
    }

    fn write_private_oram_recovery_candidate_shard(
        collection_dir: &Path,
        shard_id: ShardId,
        this_peer_id: PeerId,
        is_local: bool,
        peers: &[(PeerId, ReplicaState)],
    ) {
        let shard_dir = shard_path(collection_dir, shard_id);
        fs::create_dir_all(&shard_dir).unwrap();
        ShardConfig::new_replica_set().save(&shard_dir).unwrap();

        let mut replica_state = ReplicaSetState::default();
        replica_state.is_local = is_local;
        replica_state.this_peer_id = this_peer_id;
        for (peer_id, state) in peers {
            replica_state.set_peer_state(*peer_id, *state);
        }
        fs::write(
            shard_dir.join(REPLICA_STATE_FILE),
            serde_json::to_vec(&replica_state).unwrap(),
        )
        .unwrap();
        if is_local {
            fs::create_dir_all(LocalShard::wal_path(&shard_dir)).unwrap();
            fs::create_dir_all(LocalShard::segments_path(&shard_dir)).unwrap();
        }
    }

    fn write_private_oram_recovery_auto_candidate(
        collection_dir: &Path,
    ) -> CollectionConfigInternal {
        let config = private_hnsw_config(Uuid::from_u128(701));
        write_private_oram_recovery_candidate_root(collection_dir, &config);
        write_private_oram_recovery_candidate_shard(
            collection_dir,
            0,
            11,
            true,
            &[(11, ReplicaState::Active)],
        );
        config
    }

    fn private_oram_recovery_candidate_tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            let mut children: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect();
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let child_path = child.path();
                let relative = child_path.strip_prefix(root).unwrap().to_path_buf();
                if child.file_type().unwrap().is_dir() {
                    entries.insert(relative, None);
                    visit(root, &child_path, entries);
                } else {
                    entries.insert(relative, Some(fs::read(&child_path).unwrap()));
                }
            }
        }

        let mut entries = BTreeMap::new();
        visit(root, root, &mut entries);
        entries
    }

    #[test]
    fn private_oram_recovery_candidate_inspector_returns_sorted_read_only_topology() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = private_hnsw_config(Uuid::from_u128(702));
        config.params.sharding_method = Some(ShardingMethod::Custom);
        config.params.shard_number = NonZeroU32::new(2).unwrap();
        write_private_oram_recovery_candidate_root(temp.path(), &config);

        let mut shard_key_mapping = ShardKeyMapping::default();
        shard_key_mapping
            .entry(ShardKey::from("archive"))
            .or_default()
            .insert(2);
        shard_key_mapping
            .entry(ShardKey::from("current"))
            .or_default()
            .insert(0);
        fs::write(
            temp.path().join(SHARD_KEY_MAPPING_FILE),
            serde_json::to_vec(&shard_key_mapping).unwrap(),
        )
        .unwrap();
        write_private_oram_recovery_candidate_shard(
            temp.path(),
            2,
            11,
            true,
            &[(29, ReplicaState::Active), (11, ReplicaState::Active)],
        );
        write_private_oram_recovery_candidate_shard(
            temp.path(),
            0,
            11,
            false,
            &[(29, ReplicaState::Active)],
        );

        let before = private_oram_recovery_candidate_tree(temp.path());
        let inspection = Collection::inspect_private_oram_recovery_candidate_read_only(
            "docs",
            temp.path(),
            11,
            None,
        )
        .unwrap();
        let after = private_oram_recovery_candidate_tree(temp.path());

        assert_eq!(before, after);
        assert_eq!(inspection.config, config);
        assert_eq!(inspection.local_shard_ids, vec![2]);
        assert_eq!(
            inspection.shards,
            vec![
                PrivateOramRecoveryShardTopology {
                    shard_id: 0,
                    shard_key: Some(ShardKey::from("current")),
                    owner_peer_ids: vec![29],
                    is_local: false,
                },
                PrivateOramRecoveryShardTopology {
                    shard_id: 2,
                    shard_key: Some(ShardKey::from("archive")),
                    owner_peer_ids: vec![11, 29],
                    is_local: true,
                },
            ]
        );
    }

    #[test]
    fn private_oram_recovery_candidate_inspector_requires_exact_version_and_normal_runtime() {
        let stale = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(stale.path());
        fs::write(
            stale.path().join(common::storage_version::VERSION_FILE),
            "0.0.0",
        )
        .unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                stale.path(),
                11,
                None,
            )
            .is_err()
        );

        let recovery = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(recovery.path());
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                recovery.path(),
                11,
                Some("operator recovery"),
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_recovery_candidate_inspector_requires_exact_shard_directory_set() {
        let unexpected = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(unexpected.path());
        fs::create_dir(unexpected.path().join("7")).unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                unexpected.path(),
                11,
                None,
            )
            .is_err()
        );

        let missing = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(missing.path());
        fs::remove_dir_all(missing.path().join("0")).unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                missing.path(),
                11,
                None,
            )
            .is_err()
        );

        let initializing = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(initializing.path());
        fs::write(initializing.path().join("shard_0.initializing"), b"").unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                initializing.path(),
                11,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_recovery_candidate_inspector_rejects_non_replica_and_recovery_states() {
        let legacy = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(legacy.path());
        fs::write(
            ShardConfig::get_config_path(&legacy.path().join("0")),
            serde_json::to_vec(&ShardConfig {
                r#type: shard_config::ShardType::Local,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                legacy.path(),
                11,
                None,
            )
            .is_err()
        );

        let recovering = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(recovering.path());
        let mut replica_state = ReplicaSetState::default();
        replica_state.is_local = true;
        replica_state.this_peer_id = 11;
        replica_state.set_peer_state(11, ReplicaState::Recovery);
        fs::write(
            recovering.path().join("0").join(REPLICA_STATE_FILE),
            serde_json::to_vec(&replica_state).unwrap(),
        )
        .unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                recovering.path(),
                11,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_recovery_candidate_inspector_requires_replica_state_and_local_storage() {
        let missing_state = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(missing_state.path());
        fs::remove_file(missing_state.path().join("0").join(REPLICA_STATE_FILE)).unwrap();
        let before = private_oram_recovery_candidate_tree(missing_state.path());
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                missing_state.path(),
                11,
                None,
            )
            .is_err()
        );
        assert_eq!(
            before,
            private_oram_recovery_candidate_tree(missing_state.path())
        );
        assert!(
            !missing_state
                .path()
                .join("0")
                .join(REPLICA_STATE_FILE)
                .exists()
        );

        let missing_wal = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(missing_wal.path());
        fs::remove_dir_all(LocalShard::wal_path(&missing_wal.path().join("0"))).unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                missing_wal.path(),
                11,
                None,
            )
            .is_err()
        );

        let missing_segments = tempfile::tempdir().unwrap();
        write_private_oram_recovery_auto_candidate(missing_segments.path());
        fs::remove_dir_all(LocalShard::segments_path(
            &missing_segments.path().join("0"),
        ))
        .unwrap();
        assert!(
            Collection::inspect_private_oram_recovery_candidate_read_only(
                "docs",
                missing_segments.path(),
                11,
                None,
            )
            .is_err()
        );
    }

    fn private_hnsw_with_result_config(uuid: Uuid) -> CollectionConfigInternal {
        let mut config = private_hnsw_config(uuid);
        let result_config = private_result_config(uuid);
        let result_rule = result_config
            .params
            .encryption
            .unwrap()
            .rules
            .into_iter()
            .next()
            .unwrap();
        config
            .params
            .encryption
            .as_mut()
            .unwrap()
            .rules
            .push(result_rule);
        config
    }

    fn private_hnsw_manifest(collection_id: String) -> PrivateHnswOramManifest {
        let bucket_count = 3;
        let mut manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id,
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 1536,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 32,
                ef_construction: 128,
                max_layers: 16,
                fixed_neighbor_slots: 64,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 16384,
                tree_height: 1,
                path_batch_size: 2,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 32,
                base_layer_steps: 256,
                paths_per_round: 2,
                fixed_result_k: 10,
            },
            index_epoch: 42,
            root_hash: String::new(),
            bucket_count,
            logical_node_count: 3,
            dummy_node_count: 1,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1,
        };
        refresh_private_hnsw_snapshot_manifest_root(&mut manifest);
        manifest
    }

    fn refresh_private_hnsw_snapshot_manifest_root(manifest: &mut PrivateHnswOramManifest) {
        let commitments = private_hnsw_snapshot_leaf_commitments(manifest);
        manifest.root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&commitments).unwrap();
    }

    fn private_hnsw_snapshot_leaf_commitments(manifest: &PrivateHnswOramManifest) -> Vec<String> {
        (0..manifest.bucket_count)
            .map(|bucket_id| private_hnsw_snapshot_bucket(manifest, bucket_id).bucket_commitment)
            .collect()
    }

    fn private_hnsw_snapshot_bucket(
        manifest: &PrivateHnswOramManifest,
        bucket_id: u64,
    ) -> PrivateHnswOramBucket {
        let expected_bytes =
            private_hnsw_restore_expected_bucket_ciphertext_bytes(manifest).unwrap();
        let ciphertext_bytes = vec![9 + bucket_id as u8; expected_bytes];
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

    fn write_private_hnsw_snapshot_fixture(
        collection_dir: &Path,
        manifest: &PrivateHnswOramManifest,
    ) {
        let store = PrivateHnswOramStore::new(collection_dir, "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();

        let commitments = private_hnsw_snapshot_leaf_commitments(manifest);
        for bucket_id in 0..manifest.bucket_count {
            let bucket = private_hnsw_snapshot_bucket(manifest, bucket_id);
            store
                .write_bucket(
                    &bucket,
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_hnsw_restore_expected_bucket_ciphertext_bytes(manifest).unwrap(),
                )
                .unwrap();
        }
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                commitments,
            )
            .unwrap();
    }

    fn private_result_manifest(collection_id: String) -> PrivateResultOramManifest {
        let bucket_count = 3;
        let mut manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id,
            key_id: "tenant-a/result-private-rk".to_string(),
            rk_id: "tenant-a/result-private-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 1024,
                tree_height: 1,
                path_batch_size: 2,
            },
            index_epoch: 42,
            root_hash: String::new(),
            bucket_count,
            logical_result_count: 2,
            dummy_result_count: 1,
            owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
            created_at_unix: 1,
        };
        refresh_private_result_snapshot_manifest_root(&mut manifest);
        manifest
    }

    fn refresh_private_result_snapshot_manifest_root(manifest: &mut PrivateResultOramManifest) {
        let commitments = private_result_snapshot_leaf_commitments(manifest);
        manifest.root_hash =
            PrivateResultOramStore::merkle_root_for_commitments(&commitments).unwrap();
    }

    fn private_result_snapshot_leaf_commitments(
        manifest: &PrivateResultOramManifest,
    ) -> Vec<String> {
        (0..manifest.bucket_count)
            .map(|bucket_id| private_result_snapshot_bucket(manifest, bucket_id).bucket_commitment)
            .collect()
    }

    fn private_result_snapshot_bucket(
        manifest: &PrivateResultOramManifest,
        bucket_id: u64,
    ) -> PrivateResultOramBucket {
        let ciphertext_bytes =
            vec![
                19 + bucket_id as u8;
                private_result_restore_expected_bucket_ciphertext_bytes(manifest).unwrap()
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

    fn rebind_private_result_snapshot_bucket_epoch(
        manifest: &PrivateResultOramManifest,
        bucket: &mut PrivateResultOramBucket,
        index_epoch: u64,
    ) {
        bucket.index_epoch = index_epoch;
        bucket.bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch,
            },
            &bucket.ciphertext_sha256,
        )
        .unwrap();
    }

    fn private_result_mixed_epoch_snapshot_fixture(
        collection_id: String,
    ) -> (PrivateResultOramManifest, Vec<PrivateResultOramBucket>) {
        let previous = private_result_manifest(collection_id);
        let mut current = previous.clone();
        current.index_epoch += 1;
        let mut buckets = (0..current.bucket_count)
            .map(|bucket_id| private_result_snapshot_bucket(&current, bucket_id))
            .collect::<Vec<_>>();
        buckets[0] = private_result_snapshot_bucket(&previous, 0);
        current.root_hash = PrivateResultOramStore::merkle_root_for_commitments(
            &buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        (current, buckets)
    }

    fn write_private_result_snapshot_fixture(
        collection_dir: &Path,
        manifest: &PrivateResultOramManifest,
    ) {
        let buckets = (0..manifest.bucket_count)
            .map(|bucket_id| private_result_snapshot_bucket(manifest, bucket_id))
            .collect::<Vec<_>>();
        write_private_result_snapshot_fixture_with_buckets(collection_dir, manifest, &buckets);
    }

    fn write_private_result_snapshot_fixture_with_buckets(
        collection_dir: &Path,
        manifest: &PrivateResultOramManifest,
        buckets: &[PrivateResultOramBucket],
    ) {
        assert_eq!(buckets.len(), manifest.bucket_count as usize);
        let store = PrivateResultOramStore::new(collection_dir);
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[9; 64]),
        };
        store.write_manifest(manifest, &signature).unwrap();
        store
            .write_initial_epoch(
                &crate::private_result_oram_store::PrivateResultOramEpochState {
                    index_epoch: manifest.index_epoch,
                    root_hash: manifest.root_hash.clone(),
                },
            )
            .unwrap();

        for bucket_id in 0..manifest.bucket_count {
            let current_bucket = private_result_snapshot_bucket(manifest, bucket_id);
            store
                .write_bucket(
                    &current_bucket,
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_result_restore_max_bucket_ciphertext_bytes(manifest).unwrap(),
                )
                .unwrap();
        }
        for bucket in buckets {
            assert!(bucket.bucket_id < manifest.bucket_count);
            std::fs::write(
                private_result_snapshot_bucket_path(collection_dir, bucket.bucket_id),
                serde_json::to_vec(bucket).unwrap(),
            )
            .unwrap();
        }
        let commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                commitments,
            )
            .unwrap();
    }

    fn private_hnsw_snapshot_bucket_path(collection_dir: &Path, bucket_id: u64) -> PathBuf {
        collection_dir
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("buckets")
            .join(format!("{bucket_id:08}.bucket"))
    }

    fn private_result_snapshot_bucket_path(collection_dir: &Path, bucket_id: u64) -> PathBuf {
        collection_dir
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("buckets")
            .join(format!("{bucket_id:08}.bucket"))
    }

    fn assert_private_hnsw_restore_error_redacts_common(rendered: &str) {
        for forbidden in [
            PRIVATE_HNSW_ORAM_DIR,
            PRIVATE_RESULT_ORAM_DIR,
            VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
            PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            PRIVATE_HNSW_ORAM_BINDING,
            PRIVATE_RESULT_ORAM_BINDING,
            "docs_text_private_hnsw",
            "docs_private_hnsw",
            "tenant-a/vector-private-rk",
            "tenant-a/private-hnsw-signing-v1",
            "tenant-a/private-result-signing-v1",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "private HNSW restore preflight leaked `{forbidden}`: {rendered}",
            );
        }
    }

    fn assert_private_result_restore_error_redacts_common(rendered: &str) {
        for forbidden in [
            PRIVATE_RESULT_ORAM_DIR,
            PRIVATE_HNSW_ORAM_DIR,
            PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
            VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
            PRIVATE_RESULT_ORAM_BINDING,
            PRIVATE_HNSW_ORAM_BINDING,
            "docs_body_private_result",
            "docs_private_result_oram",
            "tenant-a/result-private-rk",
            "tenant-a/private-result-signing-v1",
            "tenant-a/private-hnsw-signing-v1",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "private result ORAM restore preflight leaked `{forbidden}`: {rendered}",
            );
        }
    }

    #[test]
    fn private_oram_snapshot_restore_error_mapping_redacts_qdrant_sec_fields() {
        let hnsw = private_hnsw_restore_error(
            qdrant_sec::PrivateHnswOramError::InvalidManifestField("secret_hnsw_field"),
        )
        .to_string();
        assert!(hnsw.contains("private HNSW ORAM snapshot manifest or signature is invalid"));
        assert!(!hnsw.contains("secret_hnsw_field"), "{hnsw}");

        let result = private_result_restore_error(
            qdrant_sec::PrivateResultOramError::InvalidManifestField("secret_result_field"),
        )
        .to_string();
        assert!(result.contains("private result ORAM snapshot manifest or signature is invalid"));
        assert!(!result.contains("secret_result_field"), "{result}");
    }

    #[test]
    fn private_hnsw_restore_bucket_shape_errors_are_sanitized() {
        let rendered = private_hnsw_restore_bucket_ciphertext_size_error(
            qdrant_sec::PrivateHnswOramError::InvalidManifestField("oram.bucket_size"),
        )
        .to_string();

        assert!(rendered.contains("snapshot bucket ciphertext size is invalid"));
        assert!(!rendered.contains("oram.bucket_size"), "{rendered}");
    }

    #[test]
    fn private_oram_snapshot_layout_sanitizer_redacts_bucket_and_base64url_tokens() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-token-redact")
            .tempdir()
            .unwrap();

        let leaked_signature = BASE64URL_NOPAD.encode(&[5; 64]);
        let hnsw = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private HNSW ORAM manifest signature {leaked_signature}",
            )),
        )
        .to_string();
        assert!(hnsw.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!hnsw.contains(&leaked_signature), "{hnsw}");

        let hnsw_bucket = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::not_found("private HNSW ORAM bucket 00000002.bucket"),
        )
        .to_string();
        assert!(hnsw_bucket.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!hnsw_bucket.contains("00000002.bucket"), "{hnsw_bucket}");

        let hnsw_short_markers = [
            "hnsw-short-bucket-id",
            "hnsw-short-path-label",
            "hnsw-short-node-id",
            "hnsw-short-point-token",
        ];
        let hnsw_short = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private HNSW ORAM bucket_id {} path_label {} node_id {} point_token {}",
                hnsw_short_markers[0],
                hnsw_short_markers[1],
                hnsw_short_markers[2],
                hnsw_short_markers[3],
            )),
        )
        .to_string();
        assert!(hnsw_short.contains("private HNSW ORAM snapshot layout validation failed"));
        for marker in hnsw_short_markers {
            assert!(!hnsw_short.contains(marker), "{hnsw_short}");
        }

        let leaked_ciphertext = BASE64URL_NOPAD.encode(&[7; 96]);
        let result = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM bucket ciphertext {leaked_ciphertext}",
            )),
        )
        .to_string();
        assert!(result.contains("private result ORAM snapshot layout validation failed"));
        assert!(!result.contains(&leaked_ciphertext), "{result}");

        let result_short_markers = [
            "result-short-read-bucket-id",
            "result-short-proof-leaf",
            "result-short-read-signature",
            "result-short-commit-signature",
        ];
        let result_short = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM read_bucket_id {} proof leaf_hash {} \
                 read_signature {} commit_signature {}",
                result_short_markers[0],
                result_short_markers[1],
                result_short_markers[2],
                result_short_markers[3],
            )),
        )
        .to_string();
        assert!(result_short.contains("private result ORAM snapshot layout validation failed"));
        for marker in result_short_markers {
            assert!(!result_short.contains(marker), "{result_short}");
        }

        let result_camel_markers = [
            "result-camel-read-bucket-id",
            "result-camel-payload-token",
            "result-dot-payload-token",
            "result-camel-sibling-hash",
            "result-camel-proof-value",
            "result-camel-access-volume-length",
            "result-camel-result-id",
            "result-camel-visited-node",
        ];
        let result_camel = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM readBucketIds {} payloadFetchTokens {} \
                 payload.fetch.token {} siblingHash {} proofValue {} accessVolumeLength {} \
                 resultIds {} visitedNodeIds {}",
                result_camel_markers[0],
                result_camel_markers[1],
                result_camel_markers[2],
                result_camel_markers[3],
                result_camel_markers[4],
                result_camel_markers[5],
                result_camel_markers[6],
                result_camel_markers[7],
            )),
        )
        .to_string();
        assert!(result_camel.contains("private result ORAM snapshot layout validation failed"));
        for marker in result_camel_markers {
            assert!(!result_camel.contains(marker), "{result_camel}");
        }

        let safe = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(
                "private HNSW ORAM snapshot contains an unconfigured vector store",
            ),
        )
        .to_string();
        assert!(safe.contains("unconfigured vector store"), "{safe}");
    }

    #[test]
    fn snapshot_crypto_migration_state_guard_rejects_in_flight_states() {
        ensure_snapshot_crypto_migration_state_allows_snapshot(
            "docs",
            &params_with_migration_state(CryptoMigrationState::Active),
        )
        .unwrap();
        ensure_snapshot_crypto_migration_state_allows_snapshot(
            "docs",
            &params_with_migration_state(CryptoMigrationState::Disabled),
        )
        .unwrap();

        for migration_state in [
            CryptoMigrationState::Encrypting,
            CryptoMigrationState::Rotating,
            CryptoMigrationState::Decrypting,
        ] {
            let err = ensure_snapshot_crypto_migration_state_allows_snapshot(
                "docs",
                &params_with_migration_state(migration_state),
            )
            .expect_err("in-flight crypto migration snapshots must fail closed");
            assert!(
                err.to_string().contains("migration_state=active"),
                "unexpected error for {migration_state:?}: {err}",
            );
        }
    }

    #[test]
    fn private_oram_snapshot_source_dir_accepts_only_present_directories() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source")
            .tempdir()
            .unwrap();

        assert!(
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR)
                .unwrap()
                .is_none()
        );

        fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();
        assert!(
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn private_oram_snapshot_source_dir_rejects_regular_file_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-file")
            .tempdir()
            .unwrap();

        fs::write(
            temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            b"not-a-directory",
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private HNSW ORAM snapshot source"));
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn private_oram_snapshot_source_dir_rejects_unexpected_layout_file_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-extra-layout")
            .tempdir()
            .unwrap();

        let hnsw_extra = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("epochs")
            .join("latest.json");
        fs::create_dir_all(hnsw_extra.parent().unwrap()).unwrap();
        fs::write(&hnsw_extra, b"private HNSW source layout sentinel").unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("latest.json"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));

        fs::remove_dir_all(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();
        let result_extra = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("epochs")
            .join("latest.json");
        fs::create_dir_all(result_extra.parent().unwrap()).unwrap();
        fs::write(&result_extra, b"private result source layout sentinel").unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("latest.json"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn private_hnsw_snapshot_source_dir_rejects_unsafe_vector_store_name_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-snapshot-source-unsafe-vector")
            .tempdir()
            .unwrap();

        let unsafe_manifest = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("private vector secret")
            .join("manifest.json");
        fs::create_dir_all(unsafe_manifest.parent().unwrap()).unwrap();
        fs::write(&unsafe_manifest, b"private HNSW unsafe vector sentinel").unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("private vector secret"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn private_oram_snapshot_source_dir_rejects_malformed_epoch_commit_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-bad-commit")
            .tempdir()
            .unwrap();

        let hnsw_commit = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("epochs")
            .join("00000042.commit");
        fs::create_dir_all(hnsw_commit.parent().unwrap()).unwrap();
        fs::write(
            &hnsw_commit,
            r#"{"index_epoch":43,"root_hash":"private-hnsw-source-commit-sentinel"}"#,
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("00000042.commit"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));

        fs::remove_dir_all(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();
        let result_commit = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("epochs")
            .join("00000042.commit");
        fs::create_dir_all(result_commit.parent().unwrap()).unwrap();
        fs::write(
            &result_commit,
            r#"{"index_epoch":43,"root_hash":"private-result-source-commit-sentinel"}"#,
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("00000042.commit"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn private_oram_snapshot_source_dir_rejects_malformed_current_epoch_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-bad-current")
            .tempdir()
            .unwrap();

        let hnsw_current = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("epochs")
            .join("current.json");
        fs::create_dir_all(hnsw_current.parent().unwrap()).unwrap();
        fs::write(
            &hnsw_current,
            r#"{"index_epoch":42,"root_hash":"private-hnsw-current-sentinel"}"#,
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("current.json"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));

        fs::remove_dir_all(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();
        let result_current = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("epochs")
            .join("current.json");
        fs::create_dir_all(result_current.parent().unwrap()).unwrap();
        fs::write(
            &result_current,
            r#"{"index_epoch":42,"root_hash":"private-result-current-sentinel"}"#,
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("unexpected file"), "{rendered}");
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("current.json"));
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn private_oram_snapshot_source_dir_accepts_valid_epoch_files() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-valid-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);

        let hnsw_manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &hnsw_manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("epochs")
                .join("00000042.commit"),
            format!(
                r#"{{"index_epoch":{},"root_hash":"{}","writeback_digest":"{}"}}"#,
                hnsw_manifest.index_epoch, hnsw_manifest.root_hash, hnsw_manifest.root_hash,
            ),
        )
        .unwrap();
        private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap();

        fs::remove_dir_all(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();

        let result_manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &result_manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("epochs")
                .join("00000042.commit"),
            format!(
                r#"{{"index_epoch":{},"root_hash":"{}","writeback_digest":"{}"}}"#,
                result_manifest.index_epoch, result_manifest.root_hash, result_manifest.root_hash,
            ),
        )
        .unwrap();
        private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap();
    }

    #[test]
    fn private_oram_snapshot_epoch_digest_is_commit_only_and_canonical() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-epoch-digest")
            .tempdir()
            .unwrap();
        let root_hash = data_encoding::BASE64URL_NOPAD.encode(&[7; 32]);
        let current = temp_dir.path().join("current.json");
        fs::write(
            &current,
            format!(
                r#"{{"index_epoch":42,"root_hash":"{root_hash}","writeback_digest":"{root_hash}"}}"#
            ),
        )
        .unwrap();
        let current_error =
            validate_private_oram_snapshot_epoch_file(&current, None, "private ORAM")
                .unwrap_err()
                .to_string();
        assert!(current_error.contains("unexpected file"));
        assert!(!current_error.contains(&root_hash));

        let commit = temp_dir.path().join("00000042.commit");
        fs::write(
            &commit,
            format!(
                r#"{{"index_epoch":42,"root_hash":"{root_hash}","writeback_digest":"malformed-digest-sentinel"}}"#
            ),
        )
        .unwrap();
        let commit_error =
            validate_private_oram_snapshot_epoch_file(&commit, Some(42), "private ORAM")
                .unwrap_err()
                .to_string();
        assert!(commit_error.contains("unexpected file"));
        assert!(!commit_error.contains("sentinel"));
        assert!(!commit_error.contains(&root_hash));
    }

    #[test]
    fn private_oram_snapshot_source_dir_sanitizes_inspection_errors() {
        let collection_path = std::path::Path::new("private-oram-source-inspect\0sentinel");

        for (dir_name, label) in [
            (PRIVATE_HNSW_ORAM_DIR, "private HNSW ORAM snapshot source"),
            (
                PRIVATE_RESULT_ORAM_DIR,
                "private result ORAM snapshot source",
            ),
        ] {
            let err = private_oram_snapshot_source_dir(collection_path, dir_name).unwrap_err();
            let rendered = err.to_string();

            assert!(rendered.contains(label), "{rendered}");
            assert!(rendered.contains("cannot be inspected"), "{rendered}");
            assert!(
                !rendered.contains("private-oram-source-inspect"),
                "{rendered}"
            );
            assert!(!rendered.contains("sentinel"), "{rendered}");
            assert!(!rendered.contains("NUL"), "{rendered}");
            assert!(!rendered.contains("nul"), "{rendered}");
            assert!(!rendered.contains(dir_name), "{rendered}");
        }
    }

    #[test]
    fn private_oram_snapshot_client_owned_state_detection_covers_aliases() {
        for protected_name in [
            "client_state.json",
            "client_states.json",
            "clientState.json",
            "clientStates.json",
            "client-state.json",
            "client.state",
            "client.state.json",
            "client_state_backup.bin",
            "client_state_backups.bin",
            "clientStateBackup.json",
            "clientStateBackups.json",
            "client_state_snapshot.bin",
            "client_state_snapshot.json",
            "client_state_snapshots.bin",
            "client_state_snapshots.json",
            "client.state.snapshots.json",
            "client.state.snapshot",
            "client.state.snapshot.bin",
            "client.state.snapshot.json",
            "clientStateSnapshot.json",
            "clientStateSnapshots.json",
            "client_state_ciphertext.bin",
            "clientStateCiphertext.json",
            "client.state.ciphertext",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "clientStateCiphertextHash.json",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "clientStateCiphertextHashes.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "clientStateCiphertextSha256.json",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "clientStateCiphertextsSha256.json",
            "encrypted_client_state.bin",
            "encrypted.client.state",
            "encrypted.client.state.bin",
            "encrypted.client.state.json",
            "encryptedClientStates.json",
            "encrypted_client_state_backup.bin",
            "encrypted_client_state_backups.bin",
            "encryptedClientStateBackup.json",
            "encryptedClientStateBackups.json",
            "encrypted_client_state_snapshot.bin",
            "encrypted_client_state_snapshot.json",
            "encrypted_client_state_snapshots.bin",
            "encrypted_client_state_snapshots.json",
            "encrypted.client.state.snapshots.json",
            "encrypted.client.state.snapshot",
            "encrypted.client.state.snapshot.bin",
            "encrypted.client.state.snapshot.json",
            "encryptedClientStateSnapshot.json",
            "encryptedClientStateSnapshots.json",
            "encrypted_client_state_ciphertext.bin",
            "encryptedClientStateCiphertext.json",
            "encrypted.client.state.ciphertext",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encryptedClientStateCiphertextHash.json",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encryptedClientStateCiphertextHashes.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encryptedClientStateCiphertextSha256.json",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "encryptedClientStateCiphertextsSha256.json",
            "state_ciphertext.bin",
            "stateCiphertext.json",
            "state.ciphertext",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "stateCiphertextHash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "stateCiphertextHashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "stateCiphertextSha256.json",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "stateCiphertextsSha256.json",
            "payload_fetch_token.bin",
            "payload_fetch_token.json",
            "payload_fetch_tokens.bin",
            "payload_fetch_tokens.json",
            "payloadFetchToken.json",
            "payloadFetchTokens.json",
            "payload.fetch.token",
            "position_map.bin",
            "positionMap.json",
            "position.map",
            "position.map.json",
            "position_map_backup.bin",
            "positionMapBackup.json",
            "positionMapBackups.json",
            "position-maps.json",
            "position_map_snapshot.bin",
            "position_map_snapshots.bin",
            "position.map.snapshot",
            "position.map.snapshot.bin",
            "positionMapSnapshots.json",
            "oram_position_map.bin",
            "oram.position.map",
            "oram.position.map.bin",
            "oram_position_map_backup.bin",
            "oram_position_map_backups.bin",
            "oramPositionMapBackup.json",
            "oramPositionMapBackups.json",
            "oramPositionMapSnapshot.json",
            "token_map.bin",
            "token.map",
            "tokenMaps.json",
            "token_map_backup.bin",
            "token.map.backup",
            "token.map.backup.bin",
            "token.map.backup.json",
            "token.map.backups",
            "token.map.backups.bin",
            "token.map.backups.json",
            "token_map_backups.bin",
            "tokenMapBackup.json",
            "tokenMapBackups.json",
            "token_map_snapshot.bin",
            "token_map_snapshots.bin",
            "token.map.snapshot",
            "token.map.snapshot.bin",
            "tokenMapSnapshot.json",
            "tokenMapSnapshots.json",
            "token_position_map.bin",
            "token.position.map",
            "tokenPositionMaps.json",
            "token_position_map_backup.bin",
            "token.position.map.backup",
            "token.position.map.backup.bin",
            "token.position.map.backup.json",
            "token.position.map.backups",
            "token.position.map.backups.bin",
            "token.position.map.backups.json",
            "token_position_map_backups.bin",
            "tokenPositionMapBackup.json",
            "tokenPositionMapBackups.json",
            "token_position_map_snapshot.bin",
            "token_position_map_snapshots.bin",
            "token.position.map.snapshot",
            "token.position.map.snapshot.bin",
            "tokenPositionMapSnapshot.json",
            "tokenPositionMapSnapshots.json",
            "stash",
            "stash_backup.bin",
            "stash_backups.bin",
            "stashBackup.json",
            "stashBackups.json",
            "stash.snapshot",
            "stash_snapshot.bin",
            "stash_snapshots.bin",
            "stash.snapshot.bin",
            "stashSnapshots.json",
        ] {
            assert!(
                private_oram_snapshot_source_entry_is_client_owned_state(std::ffi::OsStr::new(
                    protected_name
                )),
                "{protected_name} must be treated as client-owned ORAM state",
            );
        }

        for allowed_name in [
            "manifest.json",
            "manifest.sig",
            "buckets",
            "epochs",
            "current.json",
            "nodes.dat",
            "bucket_commitments.json",
            "position_metadata.json",
        ] {
            assert!(
                !private_oram_snapshot_source_entry_is_client_owned_state(std::ffi::OsStr::new(
                    allowed_name
                )),
                "{allowed_name} must remain valid server-owned snapshot metadata",
            );
        }
    }

    #[test]
    fn private_oram_snapshot_source_dir_rejects_client_owned_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-client-state")
            .tempdir()
            .unwrap();

        let hnsw_client_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("clientStateCiphertext.json");
        fs::create_dir_all(hnsw_client_state.parent().unwrap()).unwrap();
        fs::write(&hnsw_client_state, b"client state sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("text"));
        assert!(!rendered.contains("clientStateCiphertext"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(&hnsw_client_state).unwrap();
        let hnsw_encrypted_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("encrypted_client_state_ciphertext_hashes.bin");
        fs::write(&hnsw_encrypted_state, b"encrypted state hashes sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("encrypted_client_state_ciphertext_hashes"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_encrypted_state).unwrap();

        let hnsw_camel_hashes = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("encryptedClientStateCiphertextHashes.json");
        fs::write(&hnsw_camel_hashes, b"encrypted camel state hashes sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("encryptedClientStateCiphertextHashes"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_camel_hashes).unwrap();

        let hnsw_sha256_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("encrypted_client_state_ciphertexts_sha256.bin");
        fs::write(&hnsw_sha256_state, b"encrypted state sha256 sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("encrypted_client_state_ciphertexts_sha256"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_sha256_state).unwrap();

        let result_position_map = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("stateCiphertextHash.json");
        fs::create_dir_all(result_position_map.parent().unwrap()).unwrap();
        fs::write(&result_position_map, b"position map sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("stateCiphertextHash"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(&result_position_map).unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("state_ciphertext_hashes.bin"),
            b"result state hashes sentinel",
        )
        .unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("state_ciphertext_hashes"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("state_ciphertext_hashes.bin"),
        )
        .unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("stateCiphertextsSha256.json"),
            b"result state sha256 sentinel",
        )
        .unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("stateCiphertextsSha256"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("stateCiphertextsSha256.json"),
        )
        .unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("payloadFetchTokens.json"),
            b"payload fetch token sentinel",
        )
        .unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("payloadFetchTokens"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("payloadFetchTokens.json"),
        )
        .unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("payload.fetch.token"),
            b"payload fetch token dot sentinel",
        )
        .unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("payload.fetch.token"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("payload.fetch.token"),
        )
        .unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("token_position_map_backups.bin"),
            b"token map backups sentinel",
        )
        .unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("token_position_map_backups"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("token_position_map_backups.bin"),
        )
        .unwrap();
        fs::write(
            temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR).join("stash"),
            b"stash sentinel",
        )
        .unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("stash"));
        assert!(!rendered.contains("sentinel"));
    }

    #[test]
    fn private_oram_snapshot_archive_append_rejects_client_owned_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-append-client-state")
            .tempdir()
            .unwrap();

        let hnsw_client_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("encryptedClientStateCiphertextHash.json");
        fs::create_dir_all(hnsw_client_state.parent().unwrap()).unwrap();
        fs::write(&hnsw_client_state, b"append HNSW client state sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("text"));
        assert!(!rendered.contains("encryptedClientStateCiphertextHash"));
        assert!(!rendered.contains("sentinel"));

        let hnsw_snake_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("client_state_ciphertext_hash.bin");
        fs::remove_file(&hnsw_client_state).unwrap();
        fs::write(&hnsw_snake_state, b"append HNSW snake state sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("client_state_ciphertext_hash"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_snake_state).unwrap();

        let hnsw_snake_json_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("client_state_ciphertext_hash.json");
        fs::write(
            &hnsw_snake_json_state,
            b"append HNSW snake json state sentinel",
        )
        .unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("client_state_ciphertext_hash"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_snake_json_state).unwrap();

        let hnsw_camel_hashes = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("clientStateCiphertextHashes.json");
        fs::write(&hnsw_camel_hashes, b"append HNSW camel hashes sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("clientStateCiphertextHashes"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_camel_hashes).unwrap();

        let hnsw_sha256_state = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("client_state_ciphertexts_sha256.bin");
        fs::write(&hnsw_sha256_state, b"append HNSW sha256 state sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("client_state_ciphertexts_sha256"));
        assert!(!rendered.contains("sentinel"));
        fs::remove_file(&hnsw_sha256_state).unwrap();

        let result_position_map = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("state_ciphertext_hash.bin");
        fs::create_dir_all(result_position_map.parent().unwrap()).unwrap();
        fs::write(&result_position_map, b"append result position map sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
            Path::new(PRIVATE_RESULT_ORAM_DIR),
            PRIVATE_RESULT_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("state_ciphertext_hash"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(&result_position_map).unwrap();
        let result_json_position_map = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("state_ciphertext_hash.json");
        fs::write(
            &result_json_position_map,
            b"append result json position map sentinel",
        )
        .unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
            Path::new(PRIVATE_RESULT_ORAM_DIR),
            PRIVATE_RESULT_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("state_ciphertext_hash"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(&result_json_position_map).unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("stateCiphertextHashes.json"),
            b"append result camel hashes sentinel",
        )
        .unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
            Path::new(PRIVATE_RESULT_ORAM_DIR),
            PRIVATE_RESULT_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("stateCiphertextHashes"));
        assert!(!rendered.contains("sentinel"));

        fs::remove_file(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("stateCiphertextHashes.json"),
        )
        .unwrap();
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("state_ciphertexts_sha256.bin"),
            b"append result sha256 state sentinel",
        )
        .unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
            Path::new(PRIVATE_RESULT_ORAM_DIR),
            PRIVATE_RESULT_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered
                .contains("private result ORAM snapshot source contains client-owned ORAM state")
        );
        assert!(!rendered.contains("state_ciphertexts_sha256"));
        assert!(!rendered.contains("sentinel"));
    }

    #[test]
    fn private_oram_snapshot_archive_append_rejects_non_empty_temp_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-append-non-empty-temp")
            .tempdir()
            .unwrap();

        let hnsw_temp_file = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("temp")
            .join("stale-write.tmp");
        fs::create_dir_all(hnsw_temp_file.parent().unwrap()).unwrap();
        fs::write(&hnsw_temp_file, b"append HNSW temp sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains(
                "private HNSW ORAM snapshot source contains incomplete private ORAM write state"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("text"));
        assert!(!rendered.contains("stale-write"));
        assert!(!rendered.contains("sentinel"));

        let result_temp_file = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("temp")
            .join("stale-write.tmp");
        fs::create_dir_all(result_temp_file.parent().unwrap()).unwrap();
        fs::write(&result_temp_file, b"append result temp sentinel").unwrap();

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        let err = blocking_append_private_oram_snapshot_dir(
            &tar,
            &temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
            Path::new(PRIVATE_RESULT_ORAM_DIR),
            PRIVATE_RESULT_ORAM_DIR,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains(
                "private result ORAM snapshot source contains incomplete private ORAM write state"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("stale-write"));
        assert!(!rendered.contains("sentinel"));
    }

    #[test]
    fn private_oram_snapshot_archive_preserves_empty_parent_state_directories() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-parent-empty-directories")
            .tempdir()
            .unwrap();
        let parent_root = temp_dir.path().join(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2);
        let completed = parent_root.join("completed-v2-00000000000000000001");
        fs::create_dir_all(parent_root.join("temp")).unwrap();
        fs::create_dir_all(completed.join("temp")).unwrap();
        fs::create_dir_all(completed.join("state_records")).unwrap();
        fs::write(
            parent_root.join(PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2),
            b"",
        )
        .unwrap();

        let archive_path = temp_dir.path().join("snapshot.tar");
        let tar = BuilderExt::new_seekable_owned(std::fs::File::create(&archive_path).unwrap());
        blocking_append_private_oram_snapshot_dir(
            &tar,
            &parent_root,
            Path::new(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2),
            PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2,
        )
        .unwrap();
        tar.blocking_finish().unwrap();

        let mut archive = tar::Archive::new(std::fs::File::open(&archive_path).unwrap());
        let archived_paths = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .collect::<Vec<_>>();
        assert!(archived_paths.contains(&PathBuf::from(format!(
            "{PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2}/temp"
        ))));
        assert!(archived_paths.contains(&PathBuf::from(format!(
            "{PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2}/completed-v2-00000000000000000001/temp"
        ))));
    }

    #[test]
    fn private_oram_snapshot_source_dir_rejects_non_empty_temp_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-non-empty-temp")
            .tempdir()
            .unwrap();

        let hnsw_temp_file = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("temp")
            .join("stale-write.tmp");
        fs::create_dir_all(hnsw_temp_file.parent().unwrap()).unwrap();
        fs::write(&hnsw_temp_file, b"stale HNSW temp sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains(
                "private HNSW ORAM snapshot source contains incomplete private ORAM write state"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("text"));
        assert!(!rendered.contains("stale-write"));
        assert!(!rendered.contains("sentinel"));

        let result_temp_file = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("temp")
            .join("stale-result-write.tmp");
        fs::create_dir_all(result_temp_file.parent().unwrap()).unwrap();
        fs::write(&result_temp_file, b"stale result temp sentinel").unwrap();
        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains(
                "private result ORAM snapshot source contains incomplete private ORAM write state"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("stale-result-write"));
        assert!(!rendered.contains("sentinel"));
    }

    #[test]
    fn private_oram_snapshot_source_dir_allows_canonical_owner_archive_in_temp() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-owner-archive")
            .tempdir()
            .unwrap();
        let completed = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("temp")
            .join(PRIVATE_ORAM_OWNER_JOURNAL_DIR)
            .join("completed-v2-00000000000000000001");
        fs::create_dir_all(completed.join("temp")).unwrap();
        fs::create_dir_all(completed.join("terminal")).unwrap();
        for file_name in [
            "descriptor.bin",
            "final-buckets.bin",
            "state.bin",
            "owner-terminal-archive-v1.json",
        ] {
            fs::write(
                completed.join(file_name),
                b"canonical owner archive fixture",
            )
            .unwrap();
        }
        fs::write(
            completed.join("terminal").join("record.bin"),
            b"canonical owner terminal fixture",
        )
        .unwrap();

        let source = private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR)
            .unwrap()
            .unwrap();
        assert_eq!(source, temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR));

        let archive = tempfile::NamedTempFile::new().unwrap();
        let tar = BuilderExt::new_seekable_owned(File::create(archive.path()).unwrap());
        blocking_append_private_oram_snapshot_dir(
            &tar,
            &source,
            Path::new(PRIVATE_HNSW_ORAM_DIR),
            PRIVATE_HNSW_ORAM_DIR,
        )
        .unwrap();
        tar.blocking_finish().unwrap();
    }

    #[test]
    fn private_hnsw_oram_shard_snapshot_operations_fail_closed_until_bucket_parity_supported() {
        let empty_params = CollectionParams::empty();
        validate_private_oram_shard_snapshot_operation(
            "docs",
            &empty_params,
            "shard snapshot creation",
        )
        .unwrap();

        let configs = [
            private_hnsw_config(Uuid::from_u128(7)),
            private_result_config(Uuid::from_u128(8)),
        ];
        let collection_name = "private-oram-shard-snapshot-secret-collection";
        for operation_name in [
            "shard snapshot creation",
            "shard snapshot listing",
            "shard snapshot deletion",
            "shard snapshot streaming",
            "shard snapshot download",
            "shard snapshot recovery",
            "shard snapshot upload recovery",
            "partial shard snapshot recovery",
            "partial shard snapshot manifest",
            "private-shard-snapshot-operation-sentinel",
        ] {
            for config in &configs {
                let err = validate_private_oram_shard_snapshot_operation(
                    collection_name,
                    &config.params,
                    operation_name,
                )
                .expect_err("private ORAM shard snapshots must fail closed");
                let rendered = err.to_string();
                assert!(
                    rendered.contains(
                        "shard snapshot operations for private ORAM collections are disabled"
                    ),
                    "unexpected error: {rendered}",
                );
                assert!(
                    rendered.contains("collection-local encrypted ORAM buckets"),
                    "unexpected error: {rendered}",
                );
                assert!(
                    rendered.contains("collection snapshot/restore preflight"),
                    "unexpected error: {rendered}",
                );
                assert!(!rendered.contains(operation_name));
                assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
                assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
                for sentinel in [
                    "tenant-a/vector-private-rk",
                    "docs_text_private_hnsw",
                    PRIVATE_HNSW_ORAM_BINDING,
                    "tenant-a/result-private-rk",
                    "docs_body_private_result",
                    "docs_private_result_oram",
                    PRIVATE_RESULT_ORAM_BINDING,
                    collection_name,
                ] {
                    assert!(
                        !rendered.contains(sentinel),
                        "private ORAM shard snapshot guard must not expose config sentinel `{sentinel}`: {rendered}",
                    );
                }
            }
        }
    }

    #[test]
    fn private_result_oram_shard_snapshot_guard_redacts_client_state_aliases() {
        let mut config = private_result_config(Uuid::from_u128(80));
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.key_id = Some("clientStateCiphertextHash.json".to_string());
        let rule = encryption.rules.first_mut().unwrap();
        rule.id = "encryptedClientStateCiphertext.json".to_string();
        rule.instance = "stateCiphertextHash.json".to_string();
        if let EncryptionSelector::PayloadPaths { paths } = &mut rule.selector {
            *paths = vec![
                "tokenPositionMapBackup.json".to_string(),
                "tokenPositionMapBackups.json".to_string(),
                "tokenMapBackup.json".to_string(),
                "tokenMapBackups.json".to_string(),
                "token_map_backup.json".to_string(),
                "token_position_map_backup.json".to_string(),
                "token.map.backup.json".to_string(),
                "token.position.map.backup.json".to_string(),
                "clientState.json".to_string(),
                "clientStates.json".to_string(),
                "client_state.json".to_string(),
                "client_states.json".to_string(),
                "clientStateBackup.json".to_string(),
                "clientStateSnapshot.json".to_string(),
                "clientStateSnapshots.json".to_string(),
                "client_state_backup.json".to_string(),
                "client.state.snapshot.json".to_string(),
                "client_state_snapshot.json".to_string(),
                "client_state_snapshots.json".to_string(),
                "client.state.snapshots.json".to_string(),
                "clientStateCiphertext.json".to_string(),
                "clientStateCiphertextHashes.json".to_string(),
                "clientStateCiphertextSha256.json".to_string(),
                "clientStateCiphertextsSha256.json".to_string(),
                "client_state_ciphertext.json".to_string(),
                "client_state_ciphertext_hash.bin".to_string(),
                "client_state_ciphertext_hash.json".to_string(),
                "client_state_ciphertext_hashes.bin".to_string(),
                "client_state_ciphertext_hashes.json".to_string(),
                "client_state_ciphertext_sha256.bin".to_string(),
                "client_state_ciphertext_sha256.json".to_string(),
                "client_state_ciphertexts_sha256.bin".to_string(),
                "client_state_ciphertexts_sha256.json".to_string(),
                "encryptedClientState.json".to_string(),
                "encryptedClientStates.json".to_string(),
                "encrypted.client.state.json".to_string(),
                "encrypted_client_state.json".to_string(),
                "encrypted_client_states.json".to_string(),
                "encrypted_client_state_backup.json".to_string(),
                "encrypted_client_state_backups.json".to_string(),
                "encryptedClientStateBackup.json".to_string(),
                "encryptedClientStateSnapshot.json".to_string(),
                "encryptedClientStateSnapshots.json".to_string(),
                "encrypted.client.state.snapshot.json".to_string(),
                "encrypted_client_state_snapshot.json".to_string(),
                "encrypted_client_state_snapshots.json".to_string(),
                "encrypted.client.state.snapshots.json".to_string(),
                "encrypted_client_state_ciphertext.json".to_string(),
                "encryptedClientStateCiphertextHash.json".to_string(),
                "encryptedClientStateCiphertextHashes.json".to_string(),
                "encryptedClientStateCiphertextSha256.json".to_string(),
                "encryptedClientStateCiphertextsSha256.json".to_string(),
                "encrypted_client_state_ciphertext_hash.bin".to_string(),
                "encrypted_client_state_ciphertext_hash.json".to_string(),
                "encrypted_client_state_ciphertext_hashes.bin".to_string(),
                "encrypted_client_state_ciphertext_hashes.json".to_string(),
                "encrypted_client_state_ciphertext_sha256.bin".to_string(),
                "encrypted_client_state_ciphertext_sha256.json".to_string(),
                "encrypted_client_state_ciphertexts_sha256.bin".to_string(),
                "encrypted_client_state_ciphertexts_sha256.json".to_string(),
                "stateCiphertext.json".to_string(),
                "stateCiphertextHashes.json".to_string(),
                "stateCiphertextSha256.json".to_string(),
                "stateCiphertextsSha256.json".to_string(),
                "state_ciphertext.json".to_string(),
                "state_ciphertext_hash.bin".to_string(),
                "state_ciphertext_hash.json".to_string(),
                "state_ciphertext_hashes.bin".to_string(),
                "state_ciphertext_hashes.json".to_string(),
                "state_ciphertext_sha256.bin".to_string(),
                "state_ciphertext_sha256.json".to_string(),
                "state_ciphertexts_sha256.bin".to_string(),
                "state_ciphertexts_sha256.json".to_string(),
                "payload_fetch_token.json".to_string(),
                "payload_fetch_tokens.json".to_string(),
                "payloadFetchToken.json".to_string(),
                "payloadFetchTokens.json".to_string(),
                "payload.fetch.token".to_string(),
                "token_map_backups.json".to_string(),
                "token_position_map_backups.json".to_string(),
            ];
        }

        let err = validate_private_oram_shard_snapshot_operation(
            "stashBackup.json",
            &config.params,
            "private-shard-snapshot-operation-sentinel",
        )
        .expect_err("private result ORAM shard snapshots must fail closed without alias leaks");
        let rendered = err.to_string();

        assert!(rendered.contains("shard snapshot operations for private ORAM collections"));
        assert!(rendered.contains("collection snapshot/restore preflight"));
        for sentinel in [
            "clientState",
            "clientStates",
            "client_state",
            "client_states",
            "clientStateCiphertext",
            "clientStateBackup",
            "clientStateSnapshot",
            "clientStateSnapshots",
            "client.state.snapshot",
            "client_state_backup",
            "client_state_snapshot",
            "client_state_snapshots",
            "clientStateCiphertextHash",
            "clientStateCiphertextHashes",
            "clientStateCiphertextSha256",
            "clientStateCiphertextsSha256",
            "client_state_ciphertext",
            "client_state_ciphertext_hash",
            "client_state_ciphertext_hashes",
            "client_state_ciphertext_sha256",
            "client_state_ciphertexts_sha256",
            "encryptedClientState",
            "encryptedClientStates",
            "encrypted.client.state",
            "encrypted_client_state",
            "encrypted_client_states",
            "encrypted_client_state_backup",
            "encrypted_client_state_backups",
            "encryptedClientStateBackup",
            "encryptedClientStateSnapshot",
            "encryptedClientStateSnapshots",
            "encrypted.client.state.snapshot",
            "encrypted_client_state_snapshot",
            "encrypted_client_state_snapshots",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertext",
            "encryptedClientStateCiphertextHash",
            "encryptedClientStateCiphertextHashes",
            "encryptedClientStateCiphertextSha256",
            "encryptedClientStateCiphertextsSha256",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hashes",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertexts_sha256",
            "stateCiphertext",
            "stateCiphertextHash",
            "stateCiphertextHashes",
            "stateCiphertextSha256",
            "stateCiphertextsSha256",
            "state_ciphertext",
            "state_ciphertext_hash",
            "state_ciphertext_hashes",
            "state_ciphertext_sha256",
            "state_ciphertexts_sha256",
            "payload_fetch_token",
            "payload_fetch_tokens",
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload.fetch.token",
            "tokenMapBackup",
            "tokenMapBackups",
            "token.map.backup",
            "token.map.backups",
            "token_map_backup",
            "token_map_backups",
            "tokenPositionMapBackup",
            "tokenPositionMapBackups",
            "token.position.map.backup",
            "token.position.map.backups",
            "token_position_map_backup",
            "token_position_map_backups",
            "stashBackup",
            "stashBackups",
            "private-shard-snapshot-operation-sentinel",
            PRIVATE_RESULT_ORAM_BINDING,
            PRIVATE_RESULT_ORAM_DIR,
        ] {
            assert!(
                !rendered.contains(sentinel),
                "private ORAM shard snapshot guard leaked client-state alias `{sentinel}`: {rendered}",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_oram_snapshot_source_dir_rejects_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-symlink")
            .tempdir()
            .unwrap();

        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-hnsw-oram"),
            temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private HNSW ORAM snapshot source"));
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains("outside-private-hnsw-oram"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_snapshot_source_dir_rejects_nested_symlink_without_target_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-snapshot-source-nested-symlink")
            .tempdir()
            .unwrap();
        let buckets_dir = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("buckets");
        fs::create_dir_all(&buckets_dir).unwrap();
        fs::write(temp_dir.path().join("outside-hnsw-bucket"), b"outside").unwrap();
        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-hnsw-bucket"),
            buckets_dir.join("00000000.bucket"),
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private HNSW ORAM snapshot source contains a symlink"));
        assert!(!rendered.contains("outside-hnsw-bucket"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("00000000.bucket"));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_snapshot_source_dir_rejects_fifo_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-snapshot-source-fifo")
            .tempdir()
            .unwrap();
        let buckets_dir = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("buckets");
        fs::create_dir_all(&buckets_dir).unwrap();
        nix::unistd::mkfifo(
            &buckets_dir.join("fifo-sentinel"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(
            rendered
                .contains("private HNSW ORAM snapshot source contains an unsupported file type")
        );
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("text"));
        assert!(!rendered.contains("buckets"));
        assert!(!rendered.contains("fifo-sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_snapshot_source_dir_rejects_symlink_without_target_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-snapshot-source-symlink")
            .tempdir()
            .unwrap();

        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-result-oram"),
            temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private result ORAM snapshot source"));
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains("outside-private-result-oram"));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_snapshot_source_dir_rejects_nested_symlink_without_target_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-snapshot-source-nested-symlink")
            .tempdir()
            .unwrap();
        let buckets_dir = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("buckets");
        fs::create_dir_all(&buckets_dir).unwrap();
        fs::write(temp_dir.path().join("outside-result-bucket"), b"outside").unwrap();
        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-result-bucket"),
            buckets_dir.join("00000000.bucket"),
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private result ORAM snapshot source contains a symlink"));
        assert!(!rendered.contains("outside-result-bucket"));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("00000000.bucket"));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_snapshot_source_dir_rejects_fifo_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-snapshot-source-fifo")
            .tempdir()
            .unwrap();
        let buckets_dir = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("buckets");
        fs::create_dir_all(&buckets_dir).unwrap();
        nix::unistd::mkfifo(
            &buckets_dir.join("fifo-sentinel"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();
        let rendered = err.to_string();

        assert!(
            rendered
                .contains("private result ORAM snapshot source contains an unsupported file type")
        );
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("buckets"));
        assert!(!rendered.contains("fifo-sentinel"));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_store_without_binding() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-orphan-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_result_config(uuid);
        config.params.encryption.as_mut().unwrap().rules.clear();

        Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();

        fs::create_dir(temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();
        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("without a matching collection encryption rule"));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_client_owned_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-client-state")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("buckets")
                .join("position_map.bin"),
            b"position map sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("client-owned ORAM state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("position_map"));
        assert!(!err.contains("sentinel"));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_json_hash_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-json-hash-state")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("state_ciphertext_hash.json"),
            b"result json hash state sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("client-owned ORAM state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("state_ciphertext_hash"));
        assert!(!err.contains("sentinel"));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_json_hashes_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-json-hashes-state")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("state_ciphertext_hashes.json"),
            b"result json hashes state sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("client-owned ORAM state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("state_ciphertext_hashes"));
        assert!(!err.contains("sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_restore_preflight_rejects_nested_symlink_without_target_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-nested-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        let outside = temp_dir.path().join("outside-private-result-target");
        fs::write(&outside, b"private result symlink target sentinel").unwrap();
        std::os::unix::fs::symlink(
            &outside,
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("buckets")
                .join("extra-link"),
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private result ORAM snapshot store contains a symlink"));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("extra-link"));
        assert!(!err.contains("outside-private-result-target"));
        assert!(!err.contains("sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_restore_preflight_rejects_fifo_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-fifo")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        let fifo_path = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("buckets")
            .join("fifo-sentinel");
        nix::unistd::mkfifo(
            &fifo_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("private result ORAM snapshot store contains an unsupported file type")
        );
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("fifo-sentinel"));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_extra_bucket_file_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-extra-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("buckets")
                .join("00000003.bucket"),
            b"extra result bucket sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("00000003.bucket"));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash), "{err}");
    }

    fn assert_private_result_oram_restore_preflight_rejects_extra_layout_file(relative_path: &str) {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-extra-layout")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join(relative_path),
            b"extra result layout sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();
        let file_name = Path::new(relative_path)
            .file_name()
            .unwrap()
            .to_string_lossy();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains(file_name.as_ref()));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash), "{err}");
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_extra_layout_files_without_path_leak() {
        for relative_path in [
            "unexpected-layout.bin",
            "merkle/extra.nodes",
            "epochs/latest.json",
        ] {
            assert_private_result_oram_restore_preflight_rejects_extra_layout_file(relative_path);
        }
    }

    #[test]
    fn private_result_oram_restore_preflight_accepts_canonical_epoch_commit_file() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-commit-file")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        let commit_path = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("epochs")
            .join("00000042.commit");
        fs::write(
            &commit_path,
            format!(
                r#"{{"index_epoch":{},"root_hash":"{}","writeback_digest":"{}"}}"#,
                manifest.index_epoch, manifest.root_hash, manifest.root_hash
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&commit_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
        Collection::validate_private_hnsw_oram_live_replica_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
        Collection::validate_private_result_oram_live_replica_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_malformed_epoch_commit_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-commit-file")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("epochs")
                .join("00000042.commit"),
            r#"{"index_epoch":43,"root_hash":"malformed-result-epoch-sentinel"}"#,
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("00000042.commit"));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash), "{err}");
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_non_empty_temp_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-non-empty-temp")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("temp")
                .join("stale-result-write.tmp"),
            b"stale result temp sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("incomplete private ORAM write state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("stale-result-write"));
        assert!(!err.contains("sentinel"));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_wrong_selector_without_rule_id() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-wrong-selector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_result_config(uuid);
        let rule = &mut config.params.encryption.as_mut().unwrap().rules[0];
        rule.id = "private-result-secret-rule-id".to_string();
        rule.selector = EncryptionSelector::VectorNames {
            names: vec!["secret-result-vector".to_string()],
        };

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("must use payload_paths selector"));
        assert!(
            !rendered.contains("private-result-secret-rule-id"),
            "{rendered}"
        );
        assert!(!rendered.contains("secret-result-vector"), "{rendered}");
        assert!(!rendered.contains("missing for configured binding"));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_duplicate_binding_before_store_read() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-duplicate-binding")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_result_config(uuid);
        let encryption = config.params.encryption.as_mut().unwrap();
        let mut duplicate_rule = encryption.rules[0].clone();
        duplicate_rule.id = "docs_body_private_result_duplicate_secret".to_string();
        duplicate_rule.selector = EncryptionSelector::PayloadPaths {
            paths: vec!["body.duplicate.secret".to_string()],
        };
        encryption.rules.push(duplicate_rule);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("one configured binding in v1"));
        assert!(
            !rendered.contains("docs_body_private_result_duplicate_secret"),
            "{rendered}"
        );
        assert!(!rendered.contains("body.duplicate.secret"), "{rendered}");
        assert!(!rendered.contains("missing for configured binding"));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_restore_preflight_rejects_root_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);

        std::os::unix::fs::symlink(
            temp_dir.path().join("missing-result-oram-target"),
            temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        assert!(!err.to_string().contains("missing-result-oram-target"));
        assert!(!err.to_string().contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[test]
    fn private_result_oram_restore_preflight_sanitizes_inspection_errors() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-inspect-error")
            .tempdir()
            .unwrap();
        let collection_path = temp_dir.path().join("collection-file");
        fs::write(&collection_path, b"not-a-directory").unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_result_config(uuid);
        config.params.encryption.as_mut().unwrap().rules.clear();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            &collection_path,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("snapshot store root cannot be inspected"));
        assert!(!err.contains(collection_path.to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("os error"));
        assert!(!err.contains("Not a directory"));
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_missing_store_for_configured_rule() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-missing-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing for configured binding"));
        assert!(!err.to_string().contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_restore_preflight_rejects_bucket_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bucket-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        let bucket_path = private_result_snapshot_bucket_path(temp_dir.path(), 0);
        fs::remove_file(&bucket_path).unwrap();
        std::os::unix::fs::symlink(temp_dir.path().join("outside-result.bucket"), &bucket_path)
            .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("contains a symlink"));
        assert!(!rendered.contains("outside-result.bucket"));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("00000000.bucket"));
        assert!(!rendered.contains(&manifest.root_hash));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_restore_preflight_rejects_world_readable_bucket_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-world-readable-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        let bucket_path = private_result_snapshot_bucket_path(temp_dir.path(), 0);
        fs::set_permissions(&bucket_path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("must not be group/world accessible"));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains("00000000.bucket"));
        assert!(!rendered.contains(&manifest.root_hash));
    }

    #[test]
    fn private_result_oram_restore_preflight_accepts_manifest_epoch_and_buckets() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-ok")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_result_oram_restore_preflight_accepts_signed_mixed_epoch_buckets() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-mixed-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let (manifest, buckets) = private_result_mixed_epoch_snapshot_fixture(uuid.to_string());
        assert!(buckets[0].index_epoch < manifest.index_epoch);
        write_private_result_snapshot_fixture_with_buckets(temp_dir.path(), &manifest, &buckets);

        Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_future_epoch_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-future-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let (mut manifest, mut buckets) =
            private_result_mixed_epoch_snapshot_fixture(uuid.to_string());
        let future_epoch = manifest.index_epoch + 1;
        rebind_private_result_snapshot_bucket_epoch(&manifest, &mut buckets[1], future_epoch);
        manifest.root_hash = PrivateResultOramStore::merkle_root_for_commitments(
            &buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        write_private_result_snapshot_fixture_with_buckets(temp_dir.path(), &manifest, &buckets);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_rebound_stale_bucket_epoch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-rebound-stale-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let (manifest, mut buckets) = private_result_mixed_epoch_snapshot_fixture(uuid.to_string());
        write_private_result_snapshot_fixture_with_buckets(temp_dir.path(), &manifest, &buckets);
        let stale_epoch = buckets[0].index_epoch - 1;
        rebind_private_result_snapshot_bucket_epoch(&manifest, &mut buckets[0], stale_epoch);
        std::fs::write(
            private_result_snapshot_bucket_path(temp_dir.path(), 0),
            serde_json::to_vec(&buckets[0]).unwrap(),
        )
        .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket commitments"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert!(
            !rendered.contains(&buckets[0].bucket_commitment),
            "{rendered}"
        );
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_mixed_epoch_merkle_leaf_tamper() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-mixed-merkle-tamper")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let (manifest, buckets) = private_result_mixed_epoch_snapshot_fixture(uuid.to_string());
        write_private_result_snapshot_fixture_with_buckets(temp_dir.path(), &manifest, &buckets);
        let merkle_path = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("merkle")
            .join("nodes.dat");
        let mut tree: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&merkle_path).unwrap()).unwrap();
        tree["leaf_hashes"][0] = serde_json::Value::String(BASE64URL_NOPAD.encode(&[88; 32]));
        std::fs::write(&merkle_path, serde_json::to_vec(&tree).unwrap()).unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("Merkle tree root_hash mismatch"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_accepts_missing_temp_dir() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-missing-temp")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        fs::remove_dir(temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR).join("temp")).unwrap();

        Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_context_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-context")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(Uuid::from_u128(8).to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("collection_id mismatch"));
        assert!(!rendered.contains(&manifest.collection_id), "{rendered}");
        assert!(!rendered.contains(&uuid.to_string()), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_signature_key_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-signature-key")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateResultOramStore::new(temp_dir.path());
        store
            .write_manifest(
                &manifest,
                &PrivateResultOramSignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a/private-result-signing-v2".to_string(),
                    sig: BASE64URL_NOPAD.encode(&[7; 64]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key_id"));
        assert!(
            !rendered.contains("tenant-a/private-result-signing-v2"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&manifest.owner_signing_key_id),
            "{rendered}"
        );
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_manifest_key_id_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-key-id")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let mut manifest = private_result_manifest(uuid.to_string());
        manifest.key_id = "tenant-a/result-private-rk-v2".to_string();
        refresh_private_result_snapshot_manifest_root(&mut manifest);
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("manifest key_id mismatch"));
        assert!(!rendered.contains(&manifest.key_id), "{rendered}");
        assert!(
            !rendered.contains("tenant-a/result-private-rk"),
            "{rendered}"
        );
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_manifest_rk_id_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-rk-id")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let mut manifest = private_result_manifest(uuid.to_string());
        manifest.rk_id = "tenant-a/result-private-rk-v2".to_string();
        refresh_private_result_snapshot_manifest_root(&mut manifest);
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("manifest rk_id mismatch"));
        assert!(!rendered.contains(&manifest.rk_id), "{rendered}");
        assert!(
            !rendered.contains("tenant-a/result-private-rk"),
            "{rendered}"
        );
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_manifest_rk_epoch_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-rk-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let mut manifest = private_result_manifest(uuid.to_string());
        manifest.rk_epoch = 8;
        refresh_private_result_snapshot_manifest_root(&mut manifest);
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("manifest rk_epoch mismatch"));
        assert!(!rendered.contains("8"), "{rendered}");
        assert!(!rendered.contains("7"), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_current_epoch_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-current-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateResultOramStore::new(temp_dir.path());
        store
            .compare_and_swap_epoch(
                &crate::private_result_oram_store::PrivateResultOramEpochState {
                    index_epoch: manifest.index_epoch,
                    root_hash: manifest.root_hash.clone(),
                },
                &crate::private_result_oram_store::PrivateResultOramEpochState {
                    index_epoch: manifest.index_epoch + 1,
                    root_hash: BASE64URL_NOPAD.encode(&[8; 32]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("current epoch/root"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_bucket_commitment_root_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-bucket-commitment")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateResultOramStore::new(temp_dir.path());
        let max_ciphertext_bytes =
            private_result_restore_max_bucket_ciphertext_bytes(&manifest).unwrap();
        let mut bucket = store
            .read_bucket(
                1,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();
        let replacement_bytes =
            vec![77; private_result_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap()];
        bucket.ciphertext = BASE64URL_NOPAD.encode(&replacement_bytes);
        bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&replacement_bytes).as_ref());
        bucket.bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: bucket.index_epoch,
            },
            &bucket.ciphertext_sha256,
        )
        .unwrap();
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket commitments"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_bucket_fixed_size_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-bucket-size")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateResultOramStore::new(temp_dir.path());
        let max_ciphertext_bytes =
            private_result_restore_max_bucket_ciphertext_bytes(&manifest).unwrap();
        let mut bucket = store
            .read_bucket(
                0,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();
        let mut ciphertext_bytes = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .unwrap();
        ciphertext_bytes.pop();
        bucket.ciphertext = BASE64URL_NOPAD.encode(&ciphertext_bytes);
        bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext_bytes).as_ref());
        bucket.bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: bucket.index_epoch,
            },
            &bucket.ciphertext_sha256,
        )
        .unwrap();
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_restore_bucket_contract_accepts_older_buckets_and_rejects_newer_ones() {
        let uuid = Uuid::from_u128(7);
        let manifest = private_result_manifest(uuid.to_string());
        let expected_bytes =
            private_result_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap();
        let mut next_manifest = manifest.clone();
        next_manifest.index_epoch += 1;

        // After a write-back that did not touch it, a bucket keeps its older epoch and the
        // commitment it was sealed with.
        let untouched = private_result_snapshot_bucket(&manifest, 0);
        validate_private_result_restore_bucket_contract(&next_manifest, &untouched, expected_bytes)
            .unwrap();

        let newer = private_result_snapshot_bucket(&next_manifest, 0);
        let rendered =
            validate_private_result_restore_bucket_contract(&manifest, &newer, expected_bytes)
                .unwrap_err()
                .to_string();
        assert!(rendered.contains("newer than its manifest"), "{rendered}");

        // The commitment is bound to the bucket's own epoch.
        let mut relabeled = untouched;
        relabeled.index_epoch = next_manifest.index_epoch;
        let rendered = validate_private_result_restore_bucket_contract(
            &next_manifest,
            &relabeled,
            expected_bytes,
        )
        .unwrap_err()
        .to_string();
        assert!(
            rendered.contains("commitment context mismatch"),
            "{rendered}"
        );
    }

    #[test]
    fn private_result_restore_bucket_contract_rejects_oversized_encoded_bucket_before_decode() {
        let uuid = Uuid::from_u128(7);
        let manifest = private_result_manifest(uuid.to_string());
        let mut bucket = private_result_snapshot_bucket(&manifest, 0);
        bucket
            .ciphertext
            .push_str("private-result-restore-oversized-ciphertext-sentinel");
        let err = validate_private_result_restore_bucket_contract(
            &manifest,
            &bucket,
            private_result_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(
            !rendered.contains("private-result-restore-oversized-ciphertext-sentinel"),
            "{rendered}"
        );
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_bucket_commitment_context_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-bad-bucket-context")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateResultOramStore::new(temp_dir.path());
        let max_ciphertext_bytes =
            private_result_restore_max_bucket_ciphertext_bytes(&manifest).unwrap();
        let mut bucket = store
            .read_bucket(
                0,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();
        bucket.bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket commitment context"));
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    fn assert_private_result_oram_restore_preflight_rejects_missing_bucket(missing_bucket_id: u64) {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-missing-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        write_private_result_snapshot_fixture(temp_dir.path(), &manifest);
        let missing_bucket_path =
            private_result_snapshot_bucket_path(temp_dir.path(), missing_bucket_id);
        fs::remove_file(&missing_bucket_path).unwrap();

        let err = Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("private result ORAM file"), "{rendered}");
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR), "{rendered}");
        assert!(!rendered.contains("buckets"), "{rendered}");
        assert!(
            !rendered.contains(&format!("{missing_bucket_id:08}.bucket")),
            "{rendered}"
        );
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_result_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_missing_bucket_zero() {
        assert_private_result_oram_restore_preflight_rejects_missing_bucket(0);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_missing_last_bucket() {
        assert_private_result_oram_restore_preflight_rejects_missing_bucket(2);
    }

    #[test]
    fn private_result_oram_restore_preflight_rejects_missing_middle_bucket() {
        assert_private_result_oram_restore_preflight_rejects_missing_bucket(1);
    }

    #[test]
    fn private_result_oram_storage_restore_runs_sanitized_layout_preflight() {
        let snapshot_dir = tempfile::Builder::new()
            .prefix("private-result-storage-restore-source")
            .tempdir()
            .unwrap();
        let target_dir = tempfile::Builder::new()
            .prefix("private-result-storage-restore-target")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        fs::write(
            snapshot_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        write_private_result_snapshot_fixture(snapshot_dir.path(), &manifest);
        fs::remove_file(private_result_snapshot_bucket_path(snapshot_dir.path(), 0)).unwrap();
        let snapshot_path = snapshot_dir.path().to_string_lossy().into_owned();

        let err = Collection::restore_snapshot(
            SnapshotData::Unpacked(snapshot_dir),
            target_dir.path(),
            0,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private result ORAM file not found"), "{err}");
        assert!(!err.contains(&snapshot_path), "{err}");
        assert!(!err.contains(target_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("00000000.bucket"));
        assert!(!err.contains(&manifest.root_hash));
        assert_private_result_restore_error_redacts_common(&err);
    }

    #[test]
    fn private_result_oram_storage_restore_sanitizes_unexpected_layout_file() {
        let snapshot_dir = tempfile::Builder::new()
            .prefix("private-result-storage-restore-extra-layout")
            .tempdir()
            .unwrap();
        let target_dir = tempfile::Builder::new()
            .prefix("private-result-storage-restore-target")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_result_config(uuid);
        let manifest = private_result_manifest(uuid.to_string());
        fs::write(
            snapshot_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        write_private_result_snapshot_fixture(snapshot_dir.path(), &manifest);
        fs::write(
            snapshot_dir
                .path()
                .join(PRIVATE_RESULT_ORAM_DIR)
                .join("epochs")
                .join("latest.json"),
            b"private result storage restore layout sentinel",
        )
        .unwrap();
        let snapshot_path = snapshot_dir.path().to_string_lossy().into_owned();

        let err = Collection::restore_snapshot(
            SnapshotData::Unpacked(snapshot_dir),
            target_dir.path(),
            0,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(&snapshot_path), "{err}");
        assert!(!err.contains(target_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!err.contains("latest.json"));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash));
        assert_private_result_restore_error_redacts_common(&err);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_accepts_manifest_epoch_and_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-ok")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_accepts_missing_temp_dir() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-temp")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::remove_dir(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("temp"),
        )
        .unwrap();

        Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_manifest_key_id_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-key-id")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.key_id = "tenant-a/vector-private-rk-v2".to_string();
        refresh_private_hnsw_snapshot_manifest_root(&mut manifest);
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("manifest key_id mismatch"));
        assert!(!rendered.contains(&manifest.key_id), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_manifest_rk_id_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-rk-id")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.rk_id = "tenant-a/vector-private-rk-v2".to_string();
        refresh_private_hnsw_snapshot_manifest_root(&mut manifest);
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("manifest rk_id mismatch"));
        assert!(!rendered.contains(&manifest.rk_id), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_manifest_rk_epoch_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-rk-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.rk_epoch = 8;
        refresh_private_hnsw_snapshot_manifest_root(&mut manifest);
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("manifest rk_epoch mismatch"));
        assert!(!rendered.contains("8"), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_store_for_configured_rule() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("missing for configured vector rules")
        );
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_wrong_selector_without_rule_id() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-wrong-selector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_hnsw_config(uuid);
        let rule = &mut config.params.encryption.as_mut().unwrap().rules[0];
        rule.id = "private-hnsw-secret-rule-id".to_string();
        rule.selector = EncryptionSelector::PayloadPaths {
            paths: vec!["secret.payload".to_string()],
        };

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("must use vector_names selector"));
        assert!(
            !rendered.contains("private-hnsw-secret-rule-id"),
            "{rendered}"
        );
        assert!(!rendered.contains("secret.payload"), "{rendered}");
        assert!(!rendered.contains("missing for configured vector rules"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_multi_vector_rule_before_store_read() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-multi-vector-rule")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_hnsw_config(uuid);
        let encryption = config.params.encryption.as_mut().unwrap();
        let EncryptionSelector::VectorNames { names } = &mut encryption.rules[0].selector else {
            panic!("fixture must use vector_names selector");
        };
        names.push("body-secret".to_string());

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("exactly one vector"));
        assert!(!rendered.contains("body-secret"), "{rendered}");
        assert!(!rendered.contains("missing for configured vector rules"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_duplicate_vector_rule_before_store_read() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-duplicate-vector-rule")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_hnsw_config(uuid);
        let encryption = config.params.encryption.as_mut().unwrap();
        let mut duplicate_rule = encryption.rules[0].clone();
        duplicate_rule.id = "docs_text_private_hnsw_duplicate".to_string();
        encryption.rules.push(duplicate_rule);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("one configured binding per vector"));
        assert!(!rendered.contains("text"), "{rendered}");
        assert!(!rendered.contains("duplicate"), "{rendered}");
        assert!(!rendered.contains("missing for configured vector rules"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_unsafe_vector_name_before_store_read() {
        for unsafe_vector_name in [
            "private vector secret",
            "client.state",
            "position.map",
            "stashBackup.json",
            "stashBackups.json",
        ] {
            let temp_dir = tempfile::Builder::new()
                .prefix("private-hnsw-restore-unsafe-vector-rule")
                .tempdir()
                .unwrap();
            let uuid = Uuid::from_u128(7);
            let mut config = private_hnsw_config(uuid);
            let vector_params = config
                .params
                .vectors
                .get_params("text")
                .expect("fixture must have text vector")
                .clone();
            config.params.vectors = VectorsConfig::Multi(BTreeMap::from([(
                unsafe_vector_name.to_string(),
                vector_params,
            )]));
            let EncryptionSelector::VectorNames { names } =
                &mut config.params.encryption.as_mut().unwrap().rules[0].selector
            else {
                panic!("fixture must use vector_names selector");
            };
            names[0] = unsafe_vector_name.to_string();

            let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
                "docs",
                &config,
                temp_dir.path(),
            )
            .unwrap_err();
            let rendered = err.to_string();

            assert!(rendered.contains("safe store path component"), "{rendered}");
            assert!(!rendered.contains(unsafe_vector_name), "{rendered}");
            assert!(!rendered.contains("missing for configured vector rules"));
            assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        }
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_configured_vector_store() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-vector-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("missing a configured vector store")
        );
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_store_without_binding() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-orphan-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_hnsw_config(uuid);
        config.params.encryption.as_mut().unwrap().rules.clear();
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("without a matching collection encryption rule")
        );
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_unconfigured_vector_store() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-unconfigured-vector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR).join("title")).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("unconfigured vector store"));
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_client_owned_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-client-state")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("stash.bin"),
            b"stash sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("client-owned ORAM state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("text"));
        assert!(!err.contains("stash"));
        assert!(!err.contains("sentinel"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_json_hash_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-json-hash-state")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("client_state_ciphertext_hash.json"),
            b"hnsw json hash state sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("client-owned ORAM state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("text"));
        assert!(!err.contains("client_state_ciphertext_hash"));
        assert!(!err.contains("sentinel"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_json_hashes_state_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-json-hashes-state")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("client_state_ciphertext_hashes.json"),
            b"hnsw json hashes state sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("client-owned ORAM state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("text"));
        assert!(!err.contains("client_state_ciphertext_hashes"));
        assert!(!err.contains("sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_nested_symlink_without_target_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-nested-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let outside = temp_dir.path().join("outside-private-hnsw-target");
        fs::write(&outside, b"private HNSW symlink target sentinel").unwrap();
        std::os::unix::fs::symlink(
            &outside,
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("buckets")
                .join("extra-link"),
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private HNSW ORAM snapshot store contains a symlink"));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("text"));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("extra-link"));
        assert!(!err.contains("outside-private-hnsw-target"));
        assert!(!err.contains("sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_fifo_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-fifo")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let fifo_path = temp_dir
            .path()
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("buckets")
            .join("fifo-sentinel");
        nix::unistd::mkfifo(
            &fifo_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private HNSW ORAM snapshot store contains an unsupported file type"));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("text"));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("fifo-sentinel"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_non_empty_temp_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-non-empty-temp")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("temp")
                .join("stale-hnsw-write.tmp"),
            b"stale HNSW temp sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("incomplete private ORAM write state"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("text"));
        assert!(!err.contains("stale-hnsw-write"));
        assert!(!err.contains("sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_root_dir_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-root-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-hnsw-root"),
            temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        assert!(!err.to_string().contains("outside-private-hnsw-root"));
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_bucket_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bucket-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let bucket_path = private_hnsw_snapshot_bucket_path(temp_dir.path(), 0);
        fs::remove_file(&bucket_path).unwrap();
        std::os::unix::fs::symlink(temp_dir.path().join("outside.bucket"), &bucket_path).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("contains a symlink"));
        assert!(!rendered.contains("outside.bucket"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("00000000.bucket"));
        assert!(!rendered.contains(&manifest.root_hash));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_world_readable_bucket_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-world-readable-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let bucket_path = private_hnsw_snapshot_bucket_path(temp_dir.path(), 0);
        fs::set_permissions(&bucket_path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("must not be group/world accessible"));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("00000000.bucket"));
        assert!(!rendered.contains(&manifest.root_hash));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_result_private_manifest() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-result-private")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("requires a private-result-oram/v1 payload rule")
        );
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_accepts_result_private_with_result_oram_binding() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-result-private-allowed")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_with_result_config(uuid);
        let mut hnsw_manifest = private_hnsw_manifest(uuid.to_string());
        hnsw_manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &hnsw_manifest);
        let mut result_manifest = private_result_manifest(uuid.to_string());
        result_manifest.key_id = "tenant-a/vector-private-rk".to_string();
        result_manifest.rk_id = "tenant-a/vector-private-rk".to_string();
        refresh_private_result_snapshot_manifest_root(&mut result_manifest);
        write_private_result_snapshot_fixture(temp_dir.path(), &result_manifest);

        Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
        Collection::validate_private_result_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_result_oram_signature_key_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-result-private-bad-signature")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_with_result_config(uuid);
        let mut hnsw_manifest = private_hnsw_manifest(uuid.to_string());
        hnsw_manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &hnsw_manifest);
        let mut result_manifest = private_result_manifest(uuid.to_string());
        result_manifest.key_id = "tenant-a/vector-private-rk".to_string();
        result_manifest.rk_id = "tenant-a/vector-private-rk".to_string();
        refresh_private_result_snapshot_manifest_root(&mut result_manifest);
        write_private_result_snapshot_fixture(temp_dir.path(), &result_manifest);

        let result_store = PrivateResultOramStore::new(temp_dir.path());
        result_store
            .write_manifest(
                &result_manifest,
                &PrivateResultOramSignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a/private-result-signing-v2".to_string(),
                    sig: BASE64URL_NOPAD.encode(&[7; 64]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private result ORAM snapshot manifest signature key_id"));
        assert!(!rendered.contains("tenant-a/private-result-signing-v2"));
        assert!(!rendered.contains(&result_manifest.owner_signing_key_id));
        assert!(!rendered.contains(&result_manifest.root_hash));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_result_oram_batch_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-result-private-batch-mismatch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_with_result_config(uuid);
        let mut hnsw_manifest = private_hnsw_manifest(uuid.to_string());
        hnsw_manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        hnsw_manifest.fixed_budget.fixed_result_k = 3;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &hnsw_manifest);
        let mut result_manifest = private_result_manifest(uuid.to_string());
        result_manifest.key_id = "tenant-a/vector-private-rk".to_string();
        result_manifest.rk_id = "tenant-a/vector-private-rk".to_string();
        refresh_private_result_snapshot_manifest_root(&mut result_manifest);
        write_private_result_snapshot_fixture(temp_dir.path(), &result_manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed_budget.fixed_result_k"));
        assert!(rendered.contains("oram.path_batch_size"));
        assert!(rendered.contains("fixed-size read_buckets"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("3"));
        assert!(!rendered.contains("2"));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_symlinked_result_oram_store() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-result-private-symlink")
            .tempdir()
            .unwrap();
        let outside_dir = tempfile::Builder::new()
            .prefix("private-hnsw-result-outside")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_with_result_config(uuid);
        let mut hnsw_manifest = private_hnsw_manifest(uuid.to_string());
        hnsw_manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &hnsw_manifest);
        let mut result_manifest = private_result_manifest(uuid.to_string());
        result_manifest.key_id = "tenant-a/vector-private-rk".to_string();
        result_manifest.rk_id = "tenant-a/vector-private-rk".to_string();
        refresh_private_result_snapshot_manifest_root(&mut result_manifest);
        write_private_result_snapshot_fixture(outside_dir.path(), &result_manifest);
        std::os::unix::fs::symlink(
            outside_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
            temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("private result ORAM snapshot store root"));
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains(outside_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));
        assert!(!rendered.contains(&result_manifest.root_hash));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_vector_dir_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-vector-dir-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let private_hnsw_root = temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_hnsw_root).unwrap();
        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-hnsw-vector"),
            private_hnsw_root.join("text"),
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("contains a symlink"));
        assert!(!err.to_string().contains("outside-private-hnsw-vector"));
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_signature_key_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-signature-key")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        store
            .write_manifest(
                &manifest,
                &PrivateHnswOramSignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a/private-hnsw-signing-v2".to_string(),
                    sig: BASE64URL_NOPAD.encode(&[7; 64]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key_id"));
        assert!(
            !rendered.contains("tenant-a/private-hnsw-signing-v2"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&manifest.owner_signing_key_id),
            "{rendered}"
        );
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_context_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-context")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(Uuid::from_u128(8).to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("collection_id mismatch"));
        assert!(!rendered.contains(&manifest.collection_id), "{rendered}");
        assert!(!rendered.contains(&uuid.to_string()), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_vector_metadata_mismatch() {
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-vector-name")
            .tempdir()
            .unwrap();
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.vector_name = "title".to_string();
        refresh_private_hnsw_snapshot_manifest_root(&mut manifest);
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("vector_name mismatch"));
        assert!(!rendered.contains("title"), "{rendered}");
        assert!(!rendered.contains("text"), "{rendered}");

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-dim")
            .tempdir()
            .unwrap();
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.dim = 768;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("dim mismatch"));
        assert!(!rendered.contains("768"), "{rendered}");
        assert!(!rendered.contains("1536"), "{rendered}");

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-distance")
            .tempdir()
            .unwrap();
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.distance = DistanceKind::Dot;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("distance mismatch"));
        assert!(!rendered.contains("Dot"), "{rendered}");
        assert!(!rendered.contains("Cosine"), "{rendered}");
        assert!(!rendered.contains("cosine"), "{rendered}");
        assert!(!rendered.contains("text"), "{rendered}");
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_current_epoch_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-current-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        store
            .compare_and_swap_epoch(
                &crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                    index_epoch: manifest.index_epoch,
                    root_hash: manifest.root_hash.clone(),
                },
                &crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                    index_epoch: manifest.index_epoch + 1,
                    root_hash: BASE64URL_NOPAD.encode(&[8; 32]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("current epoch/root"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert!(!rendered.contains("text"), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_bucket_commitment_root_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-bucket-commitment")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let mut bucket = store
            .read_bucket(
                1,
                manifest.index_epoch,
                manifest.bucket_count,
                private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap(),
            )
            .unwrap();
        let replacement_bytes =
            vec![77; private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap()];
        bucket.ciphertext = BASE64URL_NOPAD.encode(&replacement_bytes);
        bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&replacement_bytes).as_ref());
        bucket.bucket_commitment = private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadBaseContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
            }
            .for_bucket(bucket.bucket_id, bucket.index_epoch),
            &bucket.ciphertext_sha256,
        )
        .unwrap();
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap(),
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket commitments"));
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
        assert!(!rendered.contains("text"), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_bucket_fixed_size_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-bucket-size")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let expected_ciphertext_bytes =
            private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap();
        let mut bucket = store
            .read_bucket(
                0,
                manifest.index_epoch,
                manifest.bucket_count,
                expected_ciphertext_bytes,
            )
            .unwrap();
        let mut ciphertext_bytes = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .unwrap();
        ciphertext_bytes.pop();
        bucket.ciphertext = BASE64URL_NOPAD.encode(&ciphertext_bytes);
        bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext_bytes).as_ref());
        bucket.bucket_commitment = private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadBaseContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
            }
            .for_bucket(bucket.bucket_id, bucket.index_epoch),
            &bucket.ciphertext_sha256,
        )
        .unwrap();
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                expected_ciphertext_bytes,
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_restore_bucket_contract_rejects_oversized_encoded_bucket_before_decode() {
        let uuid = Uuid::from_u128(7);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let mut bucket = private_hnsw_snapshot_bucket(&manifest, 0);
        bucket
            .ciphertext
            .push_str("private-hnsw-restore-oversized-ciphertext-sentinel");
        let err = validate_private_hnsw_restore_bucket_contract(
            &manifest,
            &bucket,
            private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(
            !rendered.contains("private-hnsw-restore-oversized-ciphertext-sentinel"),
            "{rendered}"
        );
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_bucket_commitment_context_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-bucket-context")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let expected_ciphertext_bytes =
            private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap();
        let mut bucket = store
            .read_bucket(
                0,
                manifest.index_epoch,
                manifest.bucket_count,
                expected_ciphertext_bytes,
            )
            .unwrap();
        bucket.bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                expected_ciphertext_bytes,
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("commitment context mismatch"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_extra_bucket_file_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-extra-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("buckets")
                .join("00000003.bucket"),
            b"extra HNSW bucket sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("00000003.bucket"));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash), "{err}");
    }

    fn assert_private_hnsw_oram_restore_preflight_rejects_extra_layout_file(relative_path: &str) {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-extra-layout")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join(relative_path),
            b"extra HNSW layout sentinel",
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();
        let file_name = Path::new(relative_path)
            .file_name()
            .unwrap()
            .to_string_lossy();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains(file_name.as_ref()));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash), "{err}");
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_extra_layout_files_without_path_leak() {
        for relative_path in [
            "unexpected-layout.bin",
            "merkle/extra.nodes",
            "epochs/latest.json",
        ] {
            assert_private_hnsw_oram_restore_preflight_rejects_extra_layout_file(relative_path);
        }
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_accepts_canonical_epoch_commit_file() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-commit-file")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("epochs")
                .join("00000042.commit"),
            format!(
                r#"{{"index_epoch":{},"root_hash":"{}","writeback_digest":"{}"}}"#,
                manifest.index_epoch, manifest.root_hash, manifest.root_hash
            ),
        )
        .unwrap();

        Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_malformed_epoch_commit_without_path_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-commit-file")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::write(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("epochs")
                .join("00000042.commit"),
            r#"{"index_epoch":43,"root_hash":"malformed-hnsw-epoch-sentinel"}"#,
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("00000042.commit"));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash), "{err}");
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_bucket_zero() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(&manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                private_hnsw_snapshot_leaf_commitments(&manifest),
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM file"));
        assert!(!rendered.contains("00000000.bucket"), "{rendered}");
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("buckets"), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_storage_restore_runs_sanitized_layout_preflight() {
        let snapshot_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-restore-source")
            .tempdir()
            .unwrap();
        let target_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-restore-target")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        fs::write(
            snapshot_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        let store = PrivateHnswOramStore::new(snapshot_dir.path(), "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(&manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                private_hnsw_snapshot_leaf_commitments(&manifest),
            )
            .unwrap();
        let snapshot_path = snapshot_dir.path().to_string_lossy().into_owned();

        let err = Collection::restore_snapshot(
            SnapshotData::Unpacked(snapshot_dir),
            target_dir.path(),
            0,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private HNSW ORAM file not found"), "{err}");
        assert!(!err.contains(&snapshot_path));
        assert!(!err.contains(target_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("buckets"));
        assert!(!err.contains("00000000.bucket"));
        assert!(!err.contains(&manifest.root_hash));
        assert_private_hnsw_restore_error_redacts_common(&err);
    }

    #[test]
    fn private_hnsw_oram_storage_restore_sanitizes_unexpected_layout_file() {
        let snapshot_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-restore-extra-layout")
            .tempdir()
            .unwrap();
        let target_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-restore-target")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        fs::write(
            snapshot_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        write_private_hnsw_snapshot_fixture(snapshot_dir.path(), &manifest);
        fs::write(
            snapshot_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("epochs")
                .join("latest.json"),
            b"private HNSW storage restore layout sentinel",
        )
        .unwrap();
        let snapshot_path = snapshot_dir.path().to_string_lossy().into_owned();

        let err = Collection::restore_snapshot(
            SnapshotData::Unpacked(snapshot_dir),
            target_dir.path(),
            0,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unexpected file"), "{err}");
        assert!(!err.contains(&snapshot_path));
        assert!(!err.contains(target_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("latest.json"));
        assert!(!err.contains("sentinel"));
        assert!(!err.contains(&manifest.root_hash));
        assert_private_hnsw_restore_error_redacts_common(&err);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_last_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-last-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let commitments = private_hnsw_snapshot_leaf_commitments(&manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(&manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();

        for bucket_id in [0, 1] {
            let bucket = private_hnsw_snapshot_bucket(&manifest, bucket_id);
            store
                .write_bucket(
                    &bucket,
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap(),
                )
                .unwrap();
        }
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                commitments,
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM file"));
        assert!(!rendered.contains("00000002.bucket"), "{rendered}");
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("buckets"), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_middle_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-middle-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let commitments = private_hnsw_snapshot_leaf_commitments(&manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(&manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();

        for bucket_id in [0, 2] {
            let bucket = private_hnsw_snapshot_bucket(&manifest, bucket_id);
            store
                .write_bucket(
                    &bucket,
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_hnsw_restore_expected_bucket_ciphertext_bytes(&manifest).unwrap(),
                )
                .unwrap();
        }
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                commitments,
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM file"));
        assert!(!rendered.contains("00000001.bucket"), "{rendered}");
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!rendered.contains("buckets"), "{rendered}");
        assert!(!rendered.contains(&manifest.root_hash), "{rendered}");
        assert_private_hnsw_restore_error_redacts_common(&rendered);
    }
}
