use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api::grpc::{PrivateOramActiveTransferResumeContext, RequestPrivateOramShardRecoveryRequest};
use collection::collection::Collection;
use collection::collection_state;
use collection::config::{CollectionParams, ShardingMethod};
use collection::operations::cluster_ops::ReshardingDirection;
use collection::private_hnsw_oram_store::PrivateHnswOramStore;
use collection::private_result_oram_store::PrivateResultOramStore;
use collection::shards::CollectionId;
use collection::shards::collection_shard_distribution::CollectionShardDistribution;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::resharding::{ReshardKey, ReshardState, ReshardingStage};
use collection::shards::shard::PeerId;
use collection::shards::transfer::ShardTransfer;
use fs_err::OpenOptions;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLockWriteGuard;

use super::TableOfContent;
use crate::content_manager::collection_meta_ops::*;
use crate::content_manager::collections_ops::{Checker as _, Collections};
use crate::content_manager::consensus::operation_sender::OperationSender;
use crate::content_manager::consensus::persistent::{
    private_oram_epoch_snapshot_value, private_oram_layout_snapshot_value,
};
use crate::content_manager::consensus_ops::{
    ConsensusOperations, PrivateOramCollectionLayoutTransition, PrivateOramConsensusLayout,
    PrivateOramIndexKind, PrivateOramLayoutTransitionState, PrivateOramReshardingOperation,
    PrivateOramShardKeyLayoutChange, PrivateOramShardKeyLayoutChangeKind,
    PrivateOramShardLayoutEntry, PrivateOramShardTransferFinish, PrivateOramShardTransferStart,
    canonical_private_oram_index_state_digest, canonical_private_oram_shard_layout_digest,
    classify_private_oram_replica_removal_layout_transition,
    classify_private_oram_resharding_layout_transition,
    classify_private_oram_shard_key_layout_transition,
    classify_private_oram_shard_transfer_layout_transition, private_oram_index_keys_for_config,
    private_oram_transfer_consensus_layouts, private_oram_transfer_consensus_states,
};
use crate::content_manager::errors::StorageError;
use crate::content_manager::{CollectionContainer, consensus_manager};

const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_FILE: &str = "private_oram_snapshot_recovery.json";
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION: u16 = 3;
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_ABORT_VERSION: u16 = 2;
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_LEGACY_VERSION: u16 = 1;
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES: u64 = 16 * 1024;
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_ABORT_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramSnapshotRecoveryMarker {
    version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action: Option<PrivateOramSnapshotRecoveryAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resharding_key: Option<ReshardKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shard_transfer: Option<ShardTransfer>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PrivateOramSnapshotRecoveryAction {
    Abort,
    Resume,
}

#[derive(Clone, Eq, PartialEq)]
enum PrivateOramSnapshotRecoveryOperation {
    Resharding(ReshardKey),
    ShardTransferAbort(ShardTransfer),
    ShardTransferResume(ShardTransfer),
}

impl PrivateOramSnapshotRecoveryMarker {
    fn operation(&self) -> Result<PrivateOramSnapshotRecoveryOperation, StorageError> {
        match (
            self.version,
            self.action,
            self.resharding_key.as_ref(),
            self.shard_transfer.as_ref(),
        ) {
            (
                PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_LEGACY_VERSION
                | PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_ABORT_VERSION,
                None,
                Some(resharding_key),
                None,
            ) => Ok(PrivateOramSnapshotRecoveryOperation::Resharding(
                resharding_key.clone(),
            )),
            (
                PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_ABORT_VERSION,
                None,
                None,
                Some(shard_transfer),
            ) => Ok(PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(
                shard_transfer.clone(),
            )),
            (
                PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION,
                Some(PrivateOramSnapshotRecoveryAction::Abort),
                Some(resharding_key),
                None,
            ) => Ok(PrivateOramSnapshotRecoveryOperation::Resharding(
                resharding_key.clone(),
            )),
            (
                PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION,
                Some(PrivateOramSnapshotRecoveryAction::Abort),
                None,
                Some(shard_transfer),
            ) => Ok(PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(
                shard_transfer.clone(),
            )),
            (
                PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION,
                Some(PrivateOramSnapshotRecoveryAction::Resume),
                None,
                Some(shard_transfer),
            ) => Ok(PrivateOramSnapshotRecoveryOperation::ShardTransferResume(
                shard_transfer.clone(),
            )),
            _ => Err(invalid_private_oram_snapshot_recovery_marker()),
        }
    }
}

fn invalid_private_oram_snapshot_recovery_marker() -> StorageError {
    StorageError::service_error("private ORAM snapshot recovery marker is invalid")
}

fn private_oram_snapshot_recovery_marker_path(collection_path: &Path) -> PathBuf {
    collection_path.join(PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_FILE)
}

fn validate_private_oram_missing_collection_path(
    collection_path: &Path,
) -> Result<(), StorageError> {
    match fs_err::symlink_metadata(collection_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(invalid_private_oram_active_transfer_snapshot()),
    }
}

fn read_private_oram_snapshot_recovery_marker(
    collection_path: &Path,
) -> Result<Option<PrivateOramSnapshotRecoveryMarker>, StorageError> {
    let marker_path = private_oram_snapshot_recovery_marker_path(collection_path);
    let metadata = match fs_err::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_private_oram_snapshot_recovery_marker()),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES
    {
        return Err(invalid_private_oram_snapshot_recovery_marker());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid_private_oram_snapshot_recovery_marker());
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid_private_oram_snapshot_recovery_marker());
    }
    let marker: PrivateOramSnapshotRecoveryMarker = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    marker.operation()?;
    Ok(Some(marker))
}

fn write_private_oram_snapshot_recovery_operation(
    collection_path: &Path,
    operation: PrivateOramSnapshotRecoveryOperation,
) -> Result<(), StorageError> {
    let (action, resharding_key, shard_transfer) = match &operation {
        PrivateOramSnapshotRecoveryOperation::Resharding(key) => (
            PrivateOramSnapshotRecoveryAction::Abort,
            Some(key.clone()),
            None,
        ),
        PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(transfer) => (
            PrivateOramSnapshotRecoveryAction::Abort,
            None,
            Some(transfer.clone()),
        ),
        PrivateOramSnapshotRecoveryOperation::ShardTransferResume(transfer) => (
            PrivateOramSnapshotRecoveryAction::Resume,
            None,
            Some(transfer.clone()),
        ),
    };
    let marker = PrivateOramSnapshotRecoveryMarker {
        version: PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION,
        action: Some(action),
        resharding_key,
        shard_transfer,
    };
    let marker_bytes =
        serde_json::to_vec(&marker).map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    if marker_bytes.is_empty()
        || marker_bytes.len() as u64 > PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES
    {
        return Err(invalid_private_oram_snapshot_recovery_marker());
    }
    if let Some(existing) = read_private_oram_snapshot_recovery_marker(collection_path)? {
        return if existing.operation()? == operation {
            Ok(())
        } else {
            Err(invalid_private_oram_snapshot_recovery_marker())
        };
    }

    let marker_path = private_oram_snapshot_recovery_marker_path(collection_path);
    common::fs::atomic_save(&marker_path, |writer| writer.write_all(&marker_bytes))
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs_err::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    }
    OpenOptions::new()
        .read(true)
        .write(cfg!(windows))
        .open(&marker_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    common::fs::sync_parent_dir(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    Ok(())
}

fn write_private_oram_snapshot_recovery_marker(
    collection_path: &Path,
    resharding_key: &ReshardKey,
) -> Result<(), StorageError> {
    write_private_oram_snapshot_recovery_operation(
        collection_path,
        PrivateOramSnapshotRecoveryOperation::Resharding(resharding_key.clone()),
    )
}

fn write_private_oram_transfer_snapshot_recovery_marker(
    collection_path: &Path,
    shard_transfer: &ShardTransfer,
) -> Result<(), StorageError> {
    write_private_oram_snapshot_recovery_operation(
        collection_path,
        PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(shard_transfer.clone()),
    )
}

fn write_private_oram_transfer_snapshot_resume_marker(
    collection_path: &Path,
    shard_transfer: &ShardTransfer,
) -> Result<(), StorageError> {
    write_private_oram_snapshot_recovery_operation(
        collection_path,
        PrivateOramSnapshotRecoveryOperation::ShardTransferResume(shard_transfer.clone()),
    )
}

fn remove_private_oram_snapshot_recovery_marker(
    collection_path: &Path,
) -> Result<(), StorageError> {
    if read_private_oram_snapshot_recovery_marker(collection_path)?.is_none() {
        return Ok(());
    }
    let marker_path = private_oram_snapshot_recovery_marker_path(collection_path);
    fs_err::remove_file(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    common::fs::sync_parent_dir(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())
}

fn validate_private_oram_snapshot_recovery_complete(
    collection_path: &Path,
) -> Result<(), StorageError> {
    if read_private_oram_snapshot_recovery_marker(collection_path)?.is_some() {
        return Err(StorageError::bad_request(
            "private ORAM sessions are blocked while snapshot recovery is pending",
        ));
    }
    Ok(())
}

impl TableOfContent {
    pub fn require_private_oram_snapshot_recovery_complete(
        &self,
        collection: &Collection,
    ) -> Result<(), StorageError> {
        validate_private_oram_snapshot_recovery_complete(collection.path())
    }

    pub(super) async fn validate_private_oram_transfer_snapshot_resume(
        &self,
        collection: &Collection,
    ) -> Result<bool, StorageError> {
        self.validate_or_complete_private_oram_transfer_snapshot_resume(collection, false)
            .await
    }

    pub(super) async fn complete_private_oram_transfer_snapshot_resume(
        &self,
        collection: &Collection,
    ) -> Result<bool, StorageError> {
        self.validate_or_complete_private_oram_transfer_snapshot_resume(collection, true)
            .await
    }

    async fn validate_or_complete_private_oram_transfer_snapshot_resume(
        &self,
        collection: &Collection,
        complete: bool,
    ) -> Result<bool, StorageError> {
        let Some(marker) = read_private_oram_snapshot_recovery_marker(collection.path())? else {
            return Ok(false);
        };
        let PrivateOramSnapshotRecoveryOperation::ShardTransferResume(expected_transfer) =
            marker.operation()?
        else {
            return Ok(false);
        };
        let transition = expected_transfer
            .private_oram_layout_transition
            .as_ref()
            .ok_or_else(invalid_private_oram_snapshot_recovery_marker)?;
        if expected_transfer.to != self.this_peer_id
            || !expected_transfer.is_private_oram_preinstalled_transfer_for(None)
        {
            return Err(invalid_private_oram_snapshot_recovery_marker());
        }

        let state = collection.state().await;
        if state.resharding.is_some() || state.transfers.len() > 1 {
            return Err(invalid_private_oram_snapshot_recovery_marker());
        }
        let shard = state
            .shards
            .get(&expected_transfer.shard_id)
            .ok_or_else(invalid_private_oram_snapshot_recovery_marker)?;
        if let Some(active_transfer) = state.transfers.iter().next() {
            if active_transfer != &expected_transfer
                || shard.replicas.get(&expected_transfer.from) != Some(&ReplicaState::Active)
                || shard.replicas.get(&expected_transfer.to) != Some(&ReplicaState::Partial)
            {
                return Err(invalid_private_oram_snapshot_recovery_marker());
            }
        } else {
            match shard.replicas.get(&expected_transfer.to) {
                Some(ReplicaState::Active) => {}
                Some(ReplicaState::Partial) => return Ok(false),
                Some(ReplicaState::Dead) => {
                    // The resumed transfer was aborted and this replica demoted. Regular
                    // dead-replica recovery (with a fresh preinstall) takes over from here; the
                    // resume marker would otherwise fence this replica out of it forever.
                    if complete {
                        log::warn!(
                            "Releasing the private ORAM transfer resume marker of collection {}: \
                             the resumed transfer was aborted and the replica is dead",
                            collection.name(),
                        );
                        remove_private_oram_snapshot_recovery_marker(collection.path())?;
                        self.private_oram_snapshot_recovery_resume_requests
                            .lock()
                            .await
                            .remove(collection.name());
                    }
                    return Ok(complete);
                }
                _ => return Err(invalid_private_oram_snapshot_recovery_marker()),
            }
        }

        Collection::validate_private_hnsw_oram_live_replica_layout(
            collection.name(),
            &state.config,
            collection.path(),
        )
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
        Collection::validate_private_result_oram_live_replica_layout(
            collection.name(),
            &state.config,
            collection.path(),
        )
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
        let configured_keys = private_oram_index_keys_for_config(&state.config, collection.name())?;
        let transition_states = private_oram_transfer_consensus_states(transition);
        if transition_states.len() != configured_keys.len()
            || !transition_states
                .iter()
                .map(|(key, _)| key)
                .eq(configured_keys.iter())
        {
            return Err(invalid_private_oram_snapshot_recovery_marker());
        }
        for (key, expected) in &transition_states {
            validate_private_oram_active_transfer_local_store(collection.path(), key, expected)
                .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
        }

        if complete && !state.transfers.is_empty() {
            return Ok(false);
        }
        if complete {
            remove_private_oram_snapshot_recovery_marker(collection.path())?;
            self.private_oram_snapshot_recovery_abort_requests
                .lock()
                .await
                .remove(collection.name());
            self.private_oram_snapshot_recovery_resume_requests
                .lock()
                .await
                .remove(collection.name());
        }
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOramActiveReshardSnapshotAction {
    Apply,
    AbortForReplicaRecovery,
}

#[derive(Clone, Eq, PartialEq)]
enum PrivateOramActiveTransferSnapshotAction {
    Apply,
    AbortForReplicaRecovery(ShardTransfer),
    ResumeForTargetRecovery(ShardTransfer),
}

impl CollectionContainer for TableOfContent {
    fn perform_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError> {
        self.perform_collection_meta_op_sync(operation)
    }

    fn perform_private_oram_resharding_meta_op(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        self.general_runtime
            .block_on(self.perform_private_oram_resharding_meta_op(operation))
    }

    fn perform_private_oram_collection_layout_meta_op(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<bool, StorageError> {
        self.general_runtime
            .block_on(self.perform_private_oram_collection_layout_meta_op(transition))
    }

    fn private_oram_layout_transition_state(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_layout_transition_state_async(transition))
    }

    fn private_oram_shard_transfer_start_state(
        &self,
        operation: &PrivateOramShardTransferStart,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_shard_transfer_state_async(
                &operation.collection_meta,
                PrivateOramShardTransferPhase::Start,
            ))
    }

    fn private_oram_shard_transfer_finish_state(
        &self,
        operation: &PrivateOramShardTransferFinish,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_shard_transfer_state_async(
                &operation.collection_meta,
                PrivateOramShardTransferPhase::Finish,
            ))
    }

    fn private_oram_resharding_state(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_resharding_state_async(operation))
    }

    fn collections_snapshot(&self) -> consensus_manager::CollectionsSnapshot {
        self.collections_snapshot_sync()
    }

    fn apply_collections_snapshot(
        &self,
        data: consensus_manager::CollectionsSnapshot,
    ) -> Result<(), StorageError> {
        self.apply_collections_snapshot_inner(data, None)
            .map_err(consensus_manager::CollectionsSnapshotApplyError::into_storage_error)
    }

    fn apply_collections_snapshot_with_private_oram_state(
        &self,
        data: consensus_manager::CollectionsSnapshot,
        private_oram: consensus_manager::PrivateOramSnapshotState<'_>,
    ) -> Result<(), consensus_manager::CollectionsSnapshotApplyError> {
        self.apply_collections_snapshot_inner(data, Some(private_oram))
    }

    fn private_oram_index_keys_for_collection(
        &self,
        collection_name: &str,
    ) -> Result<Vec<crate::content_manager::consensus_ops::PrivateOramEpochKey>, StorageError> {
        self.general_runtime.block_on(async {
            let collection = self.collections.read().await.get(collection_name).cloned();
            let Some(collection) = collection else {
                return Ok(Vec::new());
            };
            let config = collection.config_snapshot().await;
            private_oram_index_keys_for_config(&config, collection_name)
        })
    }

    fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError> {
        self.general_runtime.block_on(async {
            // Validation:
            // 1. Check that we are not removing some unique shards (removed)

            // Validation passed

            self.remove_shards_at_peer(peer_id).await?;

            if self.this_peer_id == peer_id {
                // We are detaching the current peer, so we need to remove all connections
                // Remove all peers from the channel service

                let ids_to_drop: Vec<_> = self
                    .channel_service
                    .id_to_address
                    .read()
                    .keys()
                    .filter(|id| **id != self.this_peer_id)
                    .copied()
                    .collect();
                for id in ids_to_drop {
                    self.channel_service.remove_peer(id).await;
                }
            } else {
                self.channel_service.remove_peer(peer_id).await;
            }
            Ok(())
        })
    }

    fn sync_local_state(&self) -> Result<(), StorageError> {
        self.general_runtime.block_on(async {
            let collections = self.collections.read().await;
            let transfer_failure_callback =
                Self::on_transfer_failure_callback(self.consensus_proposal_sender.clone());
            let transfer_success_callback =
                Self::on_transfer_success_callback(self.consensus_proposal_sender.clone());

            for collection in collections.values() {
                match self
                    .reconcile_private_oram_snapshot_recovery_marker(collection)
                    .await
                {
                    Ok(false) => {}
                    Ok(true) => continue,
                    Err(error) => {
                        // A marker the local state cannot be reconciled with fences this
                        // collection until an operator intervenes; it must not stop the Raft
                        // loop or the sync of every other collection.
                        log::warn!(
                            "Skipping local state sync for collection {} until its private ORAM \
                             snapshot recovery marker can be reconciled: {error}",
                            collection.name(),
                        );
                        continue;
                    }
                }
                let finish_shard_initialize = Self::change_peer_state_callback(
                    self.consensus_proposal_sender.clone(),
                    collection.name().to_string(),
                    ReplicaState::Active,
                    Some(ReplicaState::Initializing),
                );
                let convert_to_listener_callback = Self::change_peer_state_callback(
                    self.consensus_proposal_sender.clone(),
                    collection.name().to_string(),
                    ReplicaState::Listener,
                    Some(ReplicaState::Active),
                );
                let convert_from_listener_to_active_callback = Self::change_peer_state_callback(
                    self.consensus_proposal_sender.clone(),
                    collection.name().to_string(),
                    ReplicaState::Active,
                    Some(ReplicaState::Listener),
                );

                collection
                    .sync_local_state(
                        transfer_failure_callback.clone(),
                        transfer_success_callback.clone(),
                        finish_shard_initialize,
                        convert_to_listener_callback,
                        convert_from_listener_to_active_callback,
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

impl TableOfContent {
    /// Reconciles a private ORAM snapshot recovery marker with the collection's consensus
    /// state. Returns `Ok(true)` when the collection must skip its regular local state sync
    /// this round (recovery is still in flight), `Ok(false)` when the sync may proceed.
    async fn reconcile_private_oram_snapshot_recovery_marker(
        &self,
        collection: &Arc<Collection>,
    ) -> Result<bool, StorageError> {
        if let Some(marker) = read_private_oram_snapshot_recovery_marker(collection.path())? {
            match marker.operation()? {
                PrivateOramSnapshotRecoveryOperation::Resharding(resharding_key) => {
                    match collection.resharding_state().await {
                        Some(state)
                            if state.key() == resharding_key
                                && state.stage == ReshardingStage::MigratingPoints =>
                        {
                            let should_request_abort = {
                                let mut requests = self
                                    .private_oram_snapshot_recovery_abort_requests
                                    .lock()
                                    .await;
                                let now = Instant::now();
                                match requests.get(collection.name()) {
                                            Some(last_request)
                                                if now.duration_since(*last_request)
                                                    < PRIVATE_ORAM_SNAPSHOT_RECOVERY_ABORT_RETRY_INTERVAL =>
                                            {
                                                false
                                            }
                                            _ => {
                                                requests
                                                    .insert(collection.name().to_string(), now);
                                                true
                                            }
                                        }
                            };
                            if should_request_abort {
                                log::warn!(
                                    "Requesting private ORAM active reshard rollback for snapshot replica recovery",
                                );
                                let Some(proposal_sender) = &self.consensus_proposal_sender else {
                                    return Err(invalid_private_oram_snapshot_recovery_marker());
                                };
                                if proposal_sender
                                    .send(ConsensusOperations::abort_resharding(
                                        collection.name().to_string(),
                                        resharding_key,
                                    ))
                                    .is_err()
                                {
                                    self.private_oram_snapshot_recovery_abort_requests
                                        .lock()
                                        .await
                                        .remove(collection.name());
                                    return Err(StorageError::service_error(
                                        "private ORAM snapshot recovery abort could not be scheduled",
                                    ));
                                }
                            }
                            return Ok(true);
                        }
                        Some(_) => {
                            return Err(invalid_private_oram_snapshot_recovery_marker());
                        }
                        None => {
                            remove_private_oram_snapshot_recovery_marker(collection.path())?;
                            self.private_oram_snapshot_recovery_abort_requests
                                .lock()
                                .await
                                .remove(collection.name());
                        }
                    }
                }
                operation @ (PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(_)
                | PrivateOramSnapshotRecoveryOperation::ShardTransferResume(_)) => {
                    let (expected_transfer, resume_target) = match operation {
                        PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(transfer) => {
                            (transfer, false)
                        }
                        PrivateOramSnapshotRecoveryOperation::ShardTransferResume(transfer) => {
                            (transfer, true)
                        }
                        PrivateOramSnapshotRecoveryOperation::Resharding(_) => {
                            unreachable!("matched a shard transfer recovery operation")
                        }
                    };
                    if resume_target != (expected_transfer.to == self.this_peer_id) {
                        return Err(invalid_private_oram_snapshot_recovery_marker());
                    }
                    let resume_transition = if resume_target {
                        Some(
                            expected_transfer
                                .private_oram_layout_transition
                                .as_ref()
                                .ok_or_else(invalid_private_oram_snapshot_recovery_marker)?,
                        )
                    } else {
                        None
                    };
                    let state = collection.state().await;
                    if state.resharding.is_some()
                        || state.transfers.len() > 1
                        || state
                            .transfers
                            .iter()
                            .next()
                            .is_some_and(|transfer| transfer != &expected_transfer)
                    {
                        return Err(invalid_private_oram_snapshot_recovery_marker());
                    }
                    if state.transfers.is_empty() {
                        if resume_target {
                            if !self
                                .complete_private_oram_transfer_snapshot_resume(collection)
                                .await?
                            {
                                return Ok(true);
                            }
                        } else {
                            remove_private_oram_snapshot_recovery_marker(collection.path())?;
                            self.private_oram_snapshot_recovery_abort_requests
                                .lock()
                                .await
                                .remove(collection.name());
                        }
                    } else if resume_target {
                        let shard = state
                            .shards
                            .get(&expected_transfer.shard_id)
                            .ok_or_else(invalid_private_oram_snapshot_recovery_marker)?;
                        let transition =
                            resume_transition.expect("validated resume recovery transition");
                        if !expected_transfer.is_private_oram_preinstalled_transfer_for(None)
                            || shard.replicas.get(&expected_transfer.from)
                                != Some(&ReplicaState::Active)
                            || shard.replicas.get(&expected_transfer.to)
                                != Some(&ReplicaState::Partial)
                        {
                            return Err(invalid_private_oram_snapshot_recovery_marker());
                        }

                        let configured_keys =
                            private_oram_index_keys_for_config(&state.config, collection.name())?;
                        if private_oram_stores_present(collection.path(), &configured_keys)? {
                            // The fresh preinstall landed; the source streams and
                            // finishes the transfer. Asking again would make the source
                            // restart it, so only a store lost again re-requests.
                            return Ok(true);
                        }

                        let collection_name = collection.name().to_string();
                        let should_request_resume = self
                            .private_oram_snapshot_recovery_resume_requests
                            .lock()
                            .await
                            .insert(collection_name.clone());
                        if should_request_resume {
                            log::warn!(
                                "Requesting fresh-preinstall resume for a private ORAM active fixed-layout transfer after snapshot target recovery",
                            );
                            let source_peer_id = expected_transfer.from;
                            let request = RequestPrivateOramShardRecoveryRequest {
                                collection_name: collection_name.clone(),
                                shard_id: expected_transfer.shard_id,
                                source_peer_id,
                                target_peer_id: expected_transfer.to,
                                active_transfer_resume: Some(
                                    PrivateOramActiveTransferResumeContext {
                                        sync: expected_transfer.sync,
                                        expected_layout_generation: transition.expected.generation,
                                        expected_layout_digest: transition
                                            .expected
                                            .layout_digest
                                            .clone(),
                                        new_layout_generation: transition.new.generation,
                                        new_layout_digest: transition.new.layout_digest.clone(),
                                        index_state_digest: transition
                                            .expected
                                            .index_state_digest
                                            .clone(),
                                    },
                                ),
                                resume_if_task_missing: false,
                            };
                            let channel_service = self.channel_service.clone();
                            let pending =
                                self.private_oram_snapshot_recovery_resume_requests.clone();
                            self.general_runtime.spawn(async move {
                                        match channel_service
                                            .request_private_oram_shard_recovery(
                                                source_peer_id,
                                                request,
                                            )
                                            .await
                                        {
                                            Ok(response) if response.accepted => {}
                                            Ok(_) => log::warn!(
                                                "Private ORAM active fixed-layout transfer resume was not accepted by the source peer",
                                            ),
                                            Err(error) => log::warn!(
                                                "Failed to request private ORAM active fixed-layout transfer resume: {error}",
                                            ),
                                        }
                                        tokio::time::sleep(
                                            PRIVATE_ORAM_SNAPSHOT_RECOVERY_ABORT_RETRY_INTERVAL,
                                        )
                                        .await;
                                        pending.lock().await.remove(&collection_name);
                                    });
                        }
                        return Ok(true);
                    } else {
                        let should_request_abort = {
                            let mut requests = self
                                .private_oram_snapshot_recovery_abort_requests
                                .lock()
                                .await;
                            let now = Instant::now();
                            match requests.get(collection.name()) {
                                Some(last_request)
                                    if now.duration_since(*last_request)
                                        < PRIVATE_ORAM_SNAPSHOT_RECOVERY_ABORT_RETRY_INTERVAL =>
                                {
                                    false
                                }
                                _ => {
                                    requests.insert(collection.name().to_string(), now);
                                    true
                                }
                            }
                        };
                        if should_request_abort {
                            log::warn!(
                                "Requesting private ORAM active shard transfer rollback for snapshot replica recovery",
                            );
                            let Some(proposal_sender) = &self.consensus_proposal_sender else {
                                return Err(invalid_private_oram_snapshot_recovery_marker());
                            };
                            if proposal_sender
                                .send(ConsensusOperations::abort_transfer(
                                    collection.name().to_string(),
                                    expected_transfer,
                                    "private ORAM snapshot replica recovery",
                                ))
                                .is_err()
                            {
                                self.private_oram_snapshot_recovery_abort_requests
                                    .lock()
                                    .await
                                    .remove(collection.name());
                                return Err(StorageError::service_error(
                                    "private ORAM snapshot recovery abort could not be scheduled",
                                ));
                            }
                        }
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    async fn private_oram_resharding_state_async(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (collection_name, phase, resharding_key) = match operation.collection_meta.as_ref() {
            CollectionMetaOperations::Resharding(
                collection_name,
                ReshardingOperation::Start(key),
            ) => (collection_name, PrivateOramReshardingPhase::Start, key),
            CollectionMetaOperations::Resharding(
                collection_name,
                ReshardingOperation::Finish(key),
            ) => (collection_name, PrivateOramReshardingPhase::Finish, key),
            _ => return Err(invalid_private_oram_resharding_layout_transition()),
        };
        if resharding_key != &operation.transition.resharding_key {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let collection = self.get_collection_unchecked(collection_name).await?;
        let config = collection.config_snapshot().await;
        let collection_id = config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        let configured_keys = private_oram_index_keys_for_config(&config, collection_name)?;
        let transition_keys = operation
            .transition
            .index_states
            .iter()
            .map(|binding| binding.key.clone())
            .collect::<Vec<_>>();
        if collection_id != operation.transition.layout.key.collection_id
            || configured_keys.is_empty()
            || configured_keys != transition_keys
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if !shard_holder.get_transfers(|_| true).is_empty() {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let resharding_state = shard_holder.resharding_state();
        let resharding_is_active = match resharding_state.as_ref() {
            Some(state) if state.matches(resharding_key) => true,
            Some(_) => return Err(invalid_private_oram_resharding_layout_transition()),
            None => false,
        };
        if matches!(phase, PrivateOramReshardingPhase::Finish)
            && resharding_state
                .as_ref()
                .is_some_and(|state| state.stage != ReshardingStage::WriteHashRingCommitted)
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            let is_scale_up_target = resharding_is_active
                && matches!(phase, PrivateOramReshardingPhase::Start)
                && resharding_key.direction == ReshardingDirection::Up
                && shard_id == resharding_key.shard_id;
            if is_scale_up_target {
                let mut target_owners = peers.keys().copied().collect::<Vec<_>>();
                target_owners.sort_unstable();
                if replica_set.shard_key() != resharding_key.shard_key.as_ref()
                    || target_owners != operation.transition.target_shard_owner_peer_ids
                    || peers.values().any(|state| {
                        !matches!(state, ReplicaState::Resharding | ReplicaState::Active)
                    })
                {
                    return Err(invalid_private_oram_resharding_layout_transition());
                }
                continue;
            }

            let allows_scale_down_transition = resharding_is_active
                && matches!(phase, PrivateOramReshardingPhase::Start)
                && resharding_key.direction == ReshardingDirection::Down;
            if peers.is_empty()
                || peers.values().any(|state| {
                    *state != ReplicaState::Active
                        && !(allows_scale_down_transition
                            && *state == ReplicaState::ReshardingScaleDown)
                })
            {
                return Err(invalid_private_oram_resharding_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }

        let layout_state = classify_private_oram_resharding_layout_transition(
            &collection_id,
            shard_holder.get_sharding_method(),
            &entries,
            &operation.transition,
        )?;
        match (
            phase,
            resharding_is_active,
            resharding_key.direction,
            layout_state,
        ) {
            (
                PrivateOramReshardingPhase::Start,
                false,
                _,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramReshardingPhase::Finish,
                true,
                ReshardingDirection::Up,
                PrivateOramLayoutTransitionState::Applied,
            )
            | (
                PrivateOramReshardingPhase::Finish,
                true,
                ReshardingDirection::Down,
                PrivateOramLayoutTransitionState::Pending,
            ) => Ok(PrivateOramLayoutTransitionState::Pending),
            (
                PrivateOramReshardingPhase::Start,
                true,
                _,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramReshardingPhase::Finish,
                false,
                _,
                PrivateOramLayoutTransitionState::Applied,
            ) => Ok(PrivateOramLayoutTransitionState::Applied),
            _ => Err(invalid_private_oram_resharding_layout_transition()),
        }
    }

    async fn private_oram_layout_transition_state_async(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (collection_name, replica_removal) = match (
            transition.collection_meta.as_ref(),
            transition.shard_key_change.as_ref(),
        ) {
            (CollectionMetaOperations::UpdateCollection(update), None) => {
                let removal = update
                    .private_oram_replica_removal_only()
                    .ok_or_else(invalid_private_oram_layout_transition)?;
                (&update.collection_name, Some(removal))
            }
            (CollectionMetaOperations::CreateShardKey(operation), Some(change))
                if private_oram_shard_key_change_matches_create(operation, change) =>
            {
                (&operation.collection_name, None)
            }
            (CollectionMetaOperations::DropShardKey(operation), Some(change))
                if change.kind == PrivateOramShardKeyLayoutChangeKind::Drop
                    && change.shard_key == operation.shard_key =>
            {
                (&operation.collection_name, None)
            }
            _ => return Err(invalid_private_oram_layout_transition()),
        };
        let Some(expected_layout) = transition.layout.expected.as_ref() else {
            return Err(invalid_private_oram_layout_transition());
        };

        let collection = self.get_collection_unchecked(collection_name).await?;
        let config = collection.config_snapshot().await;
        let collection_id = config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_layout_transition())?;
        let configured_keys = private_oram_index_keys_for_config(&config, collection_name)?;
        let transition_keys = transition
            .leases
            .iter()
            .map(|binding| binding.key.clone())
            .collect::<Vec<_>>();
        if collection_id != transition.layout.key.collection_id
            || configured_keys.is_empty()
            || configured_keys != transition_keys
        {
            return Err(invalid_private_oram_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some()
            || !shard_holder.get_transfers(|_| true).is_empty()
        {
            return Err(invalid_private_oram_layout_transition());
        }
        let mut entries = Vec::new();
        for (current_shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            if peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active) {
                return Err(invalid_private_oram_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id: current_shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }
        match (replica_removal, transition.shard_key_change.as_ref()) {
            (Some((shard_id, peer_id)), None) => {
                classify_private_oram_replica_removal_layout_transition(
                    &collection_id,
                    shard_holder.get_sharding_method(),
                    &entries,
                    shard_id,
                    peer_id,
                    expected_layout,
                    &transition.layout.new,
                )
            }
            (None, Some(change)) => classify_private_oram_shard_key_layout_transition(
                &collection_id,
                shard_holder.get_sharding_method(),
                &entries,
                change,
                expected_layout,
                &transition.layout.new,
            ),
            _ => Err(invalid_private_oram_layout_transition()),
        }
    }

    async fn private_oram_shard_transfer_state_async(
        &self,
        collection_meta: &CollectionMetaOperations,
        phase: PrivateOramShardTransferPhase,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let CollectionMetaOperations::TransferShard(collection_name, operation) = collection_meta
        else {
            return Err(invalid_private_oram_transfer_layout_transition());
        };
        let transfer = match (phase, operation) {
            (PrivateOramShardTransferPhase::Start, ShardTransferOperations::Start(transfer))
            | (PrivateOramShardTransferPhase::Finish, ShardTransferOperations::Finish(transfer)) => {
                transfer
            }
            _ => return Err(invalid_private_oram_transfer_layout_transition()),
        };
        let transition = transfer
            .private_oram_layout_transition
            .as_ref()
            .ok_or_else(invalid_private_oram_transfer_layout_transition)?;
        let (layout_key, expected_layout, new_layout) =
            private_oram_transfer_consensus_layouts(transition);
        let transition_keys = private_oram_transfer_consensus_states(transition)
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>();

        let collection = self.get_collection_unchecked(collection_name).await?;
        let config = collection.config_snapshot().await;
        let collection_id = config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_transfer_layout_transition())?;
        if collection_id != layout_key.collection_id
            || private_oram_index_keys_for_config(&config, collection_name)? != transition_keys
        {
            return Err(invalid_private_oram_transfer_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some() {
            return Err(invalid_private_oram_transfer_layout_transition());
        }
        let transfers = shard_holder.get_transfers(|_| true);
        let transfer_is_active = match transfers.as_slice() {
            [] => false,
            [active] if active == transfer => true,
            _ => return Err(invalid_private_oram_transfer_layout_transition()),
        };
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            let mut owner_peer_ids = Vec::new();
            for (peer_id, state) in peers {
                let is_transfer_target = shard_id == transfer.shard_id && peer_id == transfer.to;
                if transfer_is_active && is_transfer_target {
                    if state == ReplicaState::Active {
                        return Err(invalid_private_oram_transfer_layout_transition());
                    }
                    continue;
                }
                if state == ReplicaState::Dead {
                    if peer_id == transfer.to && shard_id != transfer.shard_id {
                        owner_peer_ids.push(peer_id);
                    }
                    continue;
                }
                if state != ReplicaState::Active {
                    return Err(invalid_private_oram_transfer_layout_transition());
                }
                owner_peer_ids.push(peer_id);
            }
            if owner_peer_ids.is_empty() {
                return Err(invalid_private_oram_transfer_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids,
            });
        }
        let layout_state = classify_private_oram_shard_transfer_layout_transition(
            &collection_id,
            shard_holder.get_sharding_method(),
            &entries,
            transfer,
            &expected_layout,
            &new_layout,
        )?;
        match (phase, transfer_is_active, layout_state) {
            (
                PrivateOramShardTransferPhase::Start,
                false,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramShardTransferPhase::Finish,
                true,
                PrivateOramLayoutTransitionState::Pending,
            ) => Ok(PrivateOramLayoutTransitionState::Pending),
            (
                PrivateOramShardTransferPhase::Start,
                true,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramShardTransferPhase::Finish,
                false,
                PrivateOramLayoutTransitionState::Applied,
            ) => Ok(PrivateOramLayoutTransitionState::Applied),
            _ => Err(invalid_private_oram_transfer_layout_transition()),
        }
    }
}

#[derive(Clone, Copy)]
enum PrivateOramShardTransferPhase {
    Start,
    Finish,
}

#[derive(Clone, Copy)]
enum PrivateOramReshardingPhase {
    Start,
    Finish,
}

fn private_oram_shard_key_change_matches_create(
    operation: &CreateShardKey,
    change: &PrivateOramShardKeyLayoutChange,
) -> bool {
    if change.kind != PrivateOramShardKeyLayoutChangeKind::Create
        || change.shard_key != operation.shard_key
        || operation.initial_state != Some(ReplicaState::Active)
        || change.entries.len() != operation.placement.len()
    {
        return false;
    }
    let mut entries = change.entries.clone();
    entries.sort_by_key(|entry| entry.shard_id);
    entries
        .iter()
        .zip(&operation.placement)
        .all(|(entry, placement)| {
            let mut owners = entry.owner_peer_ids.clone();
            let mut placement = placement.clone();
            owners.sort_unstable();
            placement.sort_unstable();
            owners == placement
        })
}

fn invalid_private_oram_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM collection layout transition is invalid")
}

fn invalid_private_oram_transfer_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM shard transfer layout transition is invalid")
}

fn invalid_private_oram_resharding_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM resharding layout transition is invalid")
}

fn collection_params_bind_crypto_identity(params: &CollectionParams) -> bool {
    params.effective_encryption().is_some()
}

fn encrypted_uuid_mismatch_requires_fail_closed(
    existing_params: &CollectionParams,
    snapshot_params: &CollectionParams,
) -> bool {
    collection_params_bind_crypto_identity(existing_params)
        || collection_params_bind_crypto_identity(snapshot_params)
}

fn invalid_private_oram_resharding_snapshot() -> StorageError {
    StorageError::bad_request("private ORAM active reshard Raft snapshot state is invalid")
}

/// Outcome of the side-effect-free validation pass over a collections snapshot.
struct PreparedCollectionsSnapshot {
    recovery_fenced: HashMap<CollectionId, collection_state::State>,
    validated_private_oram_resharding: HashSet<CollectionId>,
    private_oram_snapshot_recovery_aborts: HashMap<CollectionId, ReshardKey>,
    private_oram_transfer_snapshot_recovery_aborts: HashMap<CollectionId, ShardTransfer>,
    private_oram_transfer_snapshot_recovery_resumes: HashMap<CollectionId, ShardTransfer>,
}

/// Whether every configured private ORAM store root of the collection exists on disk.
fn private_oram_stores_present(
    collection_path: &Path,
    index_keys: &[crate::content_manager::consensus_ops::PrivateOramEpochKey],
) -> Result<bool, StorageError> {
    for key in index_keys {
        let store_path = match key.index_kind {
            PrivateOramIndexKind::Hnsw => {
                PrivateHnswOramStore::new(collection_path, &key.index_name)?
                    .root_path()
                    .to_path_buf()
            }
            PrivateOramIndexKind::ResultPayload => PrivateResultOramStore::new(collection_path)
                .root_path()
                .to_path_buf(),
        };
        match fs_err::symlink_metadata(&store_path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(StorageError::service_error(format!(
                    "failed to inspect private ORAM store {}: {error}",
                    store_path.display()
                )));
            }
        }
    }
    Ok(!index_keys.is_empty())
}

fn invalid_private_oram_active_transfer_snapshot() -> StorageError {
    StorageError::bad_request("private ORAM active shard transfer Raft snapshot state is invalid")
}

fn private_oram_snapshot_shard_key(
    state: &collection_state::State,
    shard_id: collection::shards::shard::ShardId,
    sharding_method: ShardingMethod,
) -> Result<Option<segment::types::ShardKey>, StorageError> {
    let shard_key = state.shards_key_mapping.shard_key(shard_id);
    if matches!(
        (sharding_method, shard_key.as_ref()),
        (ShardingMethod::Auto, None) | (ShardingMethod::Custom, Some(_))
    ) {
        Ok(shard_key)
    } else {
        Err(invalid_private_oram_resharding_snapshot())
    }
}

fn validate_private_oram_snapshot_shard_mapping(
    state: &collection_state::State,
    sharding_method: ShardingMethod,
) -> Result<(), StorageError> {
    let shard_ids = state.shards.keys().copied().collect::<HashSet<_>>();
    let mapped = state
        .shards_key_mapping
        .iter_shard_ids()
        .collect::<Vec<_>>();
    let mapped_ids = mapped.iter().copied().collect::<HashSet<_>>();
    let valid = match sharding_method {
        ShardingMethod::Auto => mapped.is_empty(),
        ShardingMethod::Custom => mapped.len() == mapped_ids.len() && mapped_ids == shard_ids,
    };
    if !valid
        || matches!(sharding_method, ShardingMethod::Auto)
            && state.config.params.shard_number.get() as usize != shard_ids.len()
    {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    Ok(())
}

fn private_oram_stable_snapshot_layout_entries(
    state: &collection_state::State,
) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
    if state.shards.is_empty() || state.resharding.is_some() || !state.transfers.is_empty() {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    let sharding_method = state.config.params.sharding_method.unwrap_or_default();
    validate_private_oram_snapshot_shard_mapping(state, sharding_method)?;
    let mut entries = Vec::with_capacity(state.shards.len());
    for (shard_id, shard) in &state.shards {
        if shard.replicas.is_empty()
            || shard
                .replicas
                .values()
                .any(|replica_state| *replica_state != ReplicaState::Active)
        {
            return Err(invalid_private_oram_resharding_snapshot());
        }
        entries.push(PrivateOramShardLayoutEntry {
            shard_id: *shard_id,
            shard_key: private_oram_snapshot_shard_key(state, *shard_id, sharding_method)?,
            owner_peer_ids: shard.replicas.keys().copied().collect(),
        });
    }
    Ok(entries)
}

fn private_oram_active_transfer_snapshot_layout_entries(
    state: &collection_state::State,
) -> Result<
    (
        &collection::shards::transfer::ShardTransfer,
        Vec<PrivateOramShardLayoutEntry>,
    ),
    StorageError,
> {
    if state.resharding.is_some() || state.transfers.len() != 1 {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }
    let transfer = state
        .transfers
        .iter()
        .next()
        .expect("validated one private ORAM shard transfer");
    if !transfer.is_private_oram_preinstalled_transfer_for(None) {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }

    let sharding_method = state.config.params.sharding_method.unwrap_or_default();
    validate_private_oram_snapshot_shard_mapping(state, sharding_method)
        .map_err(|_| invalid_private_oram_active_transfer_snapshot())?;
    let mut transfer_shard_seen = false;
    let mut entries = Vec::with_capacity(state.shards.len());
    for (shard_id, shard) in &state.shards {
        if shard.replicas.is_empty() {
            return Err(invalid_private_oram_active_transfer_snapshot());
        }
        let is_transfer_shard = *shard_id == transfer.shard_id;
        if is_transfer_shard {
            transfer_shard_seen = true;
            if shard.replicas.get(&transfer.from) != Some(&ReplicaState::Active)
                || shard.replicas.get(&transfer.to) != Some(&ReplicaState::Partial)
            {
                return Err(invalid_private_oram_active_transfer_snapshot());
            }
        }
        if shard.replicas.iter().any(|(peer_id, state)| {
            is_transfer_shard && *peer_id == transfer.to && *state != ReplicaState::Partial
                || (!is_transfer_shard || *peer_id != transfer.to) && *state != ReplicaState::Active
        }) {
            return Err(invalid_private_oram_active_transfer_snapshot());
        }

        entries.push(PrivateOramShardLayoutEntry {
            shard_id: *shard_id,
            shard_key: private_oram_snapshot_shard_key(state, *shard_id, sharding_method)
                .map_err(|_| invalid_private_oram_active_transfer_snapshot())?,
            owner_peer_ids: shard
                .replicas
                .iter()
                .filter_map(|(peer_id, replica_state)| {
                    (*replica_state == ReplicaState::Active).then_some(*peer_id)
                })
                .collect(),
        });
    }
    if !transfer_shard_seen {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }
    Ok((transfer, entries))
}

fn validate_private_oram_active_transfer_local_store(
    collection_path: &Path,
    key: &crate::content_manager::consensus_ops::PrivateOramEpochKey,
    expected: &crate::content_manager::consensus_ops::PrivateOramConsensusEpoch,
) -> Result<(), StorageError> {
    let matches = match key.index_kind {
        PrivateOramIndexKind::Hnsw => {
            let current = PrivateHnswOramStore::new(collection_path, &key.index_name)
                .and_then(|store| store.read_current_epoch())
                .map_err(|_| invalid_private_oram_active_transfer_snapshot())?;
            current.index_epoch == expected.index_epoch && current.root_hash == expected.root_hash
        }
        PrivateOramIndexKind::ResultPayload => {
            let current = PrivateResultOramStore::new(collection_path)
                .read_current_epoch()
                .map_err(|_| invalid_private_oram_active_transfer_snapshot())?;
            current.index_epoch == expected.index_epoch && current.root_hash == expected.root_hash
        }
    };
    if !matches {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }
    Ok(())
}

fn private_oram_active_transfer_snapshot_can_rollback_redundant_owner(
    incoming: &collection_state::State,
    transfer: &ShardTransfer,
    expected_layout: &PrivateOramConsensusLayout,
    entries: &[PrivateOramShardLayoutEntry],
    this_peer_id: PeerId,
) -> bool {
    if transfer.to == this_peer_id || !expected_layout.owner_peer_ids.contains(&this_peer_id) {
        return false;
    }
    let local_entries = entries
        .iter()
        .filter(|entry| entry.owner_peer_ids.contains(&this_peer_id))
        .collect::<Vec<_>>();
    !local_entries.is_empty()
        && local_entries.iter().all(|entry| {
            incoming.shards.get(&entry.shard_id).is_some_and(|shard| {
                shard.replicas.get(&this_peer_id) == Some(&ReplicaState::Active)
                    && shard.replicas.iter().any(|(peer_id, state)| {
                        *peer_id != this_peer_id && *state == ReplicaState::Active
                    })
            })
        })
}

fn validate_private_oram_active_transfer_snapshot(
    collection_name: &str,
    current: Option<&collection_state::State>,
    current_collection_path: Option<&Path>,
    incoming: &collection_state::State,
    snapshot: consensus_manager::PrivateOramSnapshotState<'_>,
    this_peer_id: PeerId,
) -> Result<Option<PrivateOramActiveTransferSnapshotAction>, StorageError> {
    if incoming.resharding.is_some() || incoming.transfers.is_empty() {
        return Ok(None);
    }
    let incoming_keys = private_oram_index_keys_for_config(&incoming.config, collection_name)?;
    if incoming_keys.is_empty() {
        return Ok(None);
    }

    let collection_id = incoming
        .config
        .stable_crypto_id(collection_name)
        .map_err(|_| invalid_private_oram_active_transfer_snapshot())?;
    if let Some(current) = current {
        let current_keys = private_oram_index_keys_for_config(&current.config, collection_name)?;
        if incoming_keys != current_keys
            || current
                .config
                .stable_crypto_id(collection_name)
                .map_err(|_| invalid_private_oram_active_transfer_snapshot())?
                != collection_id
            || current.config.params.sharding_method != incoming.config.params.sharding_method
            || current.config.params.replication_factor != incoming.config.params.replication_factor
        {
            return Err(invalid_private_oram_active_transfer_snapshot());
        }
    }

    let (transfer, entries) = private_oram_active_transfer_snapshot_layout_entries(incoming)?;
    let transition = transfer
        .private_oram_layout_transition
        .as_ref()
        .ok_or_else(invalid_private_oram_active_transfer_snapshot)?;
    let transition_states = private_oram_transfer_consensus_states(transition);
    if transition_states.len() != incoming_keys.len()
        || !transition_states
            .iter()
            .map(|(key, _)| key)
            .eq(incoming_keys.iter())
    {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }
    let mut index_states = Vec::with_capacity(incoming_keys.len());
    for (key, (_, transition_state)) in incoming_keys.iter().zip(&transition_states) {
        let incoming_epoch = private_oram_epoch_snapshot_value(snapshot.incoming_epochs, key)
            .ok_or_else(invalid_private_oram_active_transfer_snapshot)?;
        let current_epoch = private_oram_epoch_snapshot_value(snapshot.current_epochs, key);
        let current_epoch_matches = match current {
            Some(_) => current_epoch == Some(incoming_epoch),
            None => current_epoch.is_none() || current_epoch == Some(incoming_epoch),
        };
        if !current_epoch_matches || transition_state != incoming_epoch {
            return Err(invalid_private_oram_active_transfer_snapshot());
        }
        index_states.push((key.clone(), incoming_epoch.clone()));
    }
    let index_state_digest =
        canonical_private_oram_index_state_digest(&collection_id, &index_states)
            .map_err(|_| invalid_private_oram_active_transfer_snapshot())?;
    let (layout_key, expected_layout, new_layout) =
        private_oram_transfer_consensus_layouts(transition);
    if layout_key.collection_id != collection_id
        || expected_layout.index_state_digest != index_state_digest
        || new_layout.index_state_digest != index_state_digest
        || expected_layout
            .generation
            .checked_add(1)
            .is_none_or(|generation| generation != new_layout.generation)
    {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }
    let incoming_layout =
        private_oram_layout_snapshot_value(snapshot.incoming_layouts, &layout_key)
            .ok_or_else(invalid_private_oram_active_transfer_snapshot)?;
    let current_layout = private_oram_layout_snapshot_value(snapshot.current_layouts, &layout_key);
    if incoming_layout != &expected_layout
        || current_layout.is_some_and(|layout| layout != incoming_layout)
        || classify_private_oram_shard_transfer_layout_transition(
            &collection_id,
            incoming.config.params.sharding_method.unwrap_or_default(),
            &entries,
            transfer,
            &expected_layout,
            &new_layout,
        )
        .map_err(|_| invalid_private_oram_active_transfer_snapshot())?
            != PrivateOramLayoutTransitionState::Pending
    {
        return Err(invalid_private_oram_active_transfer_snapshot());
    }

    let topology_only_non_owner = !incoming_layout.owner_peer_ids.contains(&this_peer_id)
        && !incoming
            .shards
            .values()
            .any(|shard| shard.replicas.contains_key(&this_peer_id))
        && transfer.from != this_peer_id
        && transfer.to != this_peer_id;
    let fresh_transfer_target = transfer.to == this_peer_id
        && !expected_layout.owner_peer_ids.contains(&this_peer_id)
        && entries
            .iter()
            .all(|entry| !entry.owner_peer_ids.contains(&this_peer_id));
    if current.is_none() {
        if topology_only_non_owner {
            return Ok(Some(PrivateOramActiveTransferSnapshotAction::Apply));
        }
        if fresh_transfer_target {
            return Ok(Some(
                PrivateOramActiveTransferSnapshotAction::ResumeForTargetRecovery(transfer.clone()),
            ));
        }
        if private_oram_active_transfer_snapshot_can_rollback_redundant_owner(
            incoming,
            transfer,
            &expected_layout,
            &entries,
            this_peer_id,
        ) {
            return Ok(Some(
                PrivateOramActiveTransferSnapshotAction::AbortForReplicaRecovery(transfer.clone()),
            ));
        }
        return Err(invalid_private_oram_active_transfer_snapshot());
    }
    if !topology_only_non_owner {
        let collection_path =
            current_collection_path.ok_or_else(invalid_private_oram_active_transfer_snapshot)?;
        if fresh_transfer_target {
            let current = current.expect("validated existing private ORAM collection state");
            let current_shard = current
                .shards
                .get(&transfer.shard_id)
                .ok_or_else(invalid_private_oram_active_transfer_snapshot)?;
            if current.resharding.is_some()
                || current.transfers.len() != 1
                || !current.transfers.contains(transfer)
                || current_shard.replicas.get(&transfer.from) != Some(&ReplicaState::Active)
                || current_shard.replicas.get(&transfer.to) != Some(&ReplicaState::Partial)
            {
                return Err(invalid_private_oram_active_transfer_snapshot());
            }
            let mut absent_store_count = 0;
            for (key, _) in &index_states {
                let store_path = match key.index_kind {
                    PrivateOramIndexKind::Hnsw => {
                        PrivateHnswOramStore::new(collection_path, &key.index_name)
                            .map_err(|_| invalid_private_oram_active_transfer_snapshot())?
                            .root_path()
                            .to_path_buf()
                    }
                    PrivateOramIndexKind::ResultPayload => {
                        PrivateResultOramStore::new(collection_path)
                            .root_path()
                            .to_path_buf()
                    }
                };
                match fs_err::symlink_metadata(&store_path) {
                    Ok(metadata) if metadata.file_type().is_dir() => {}
                    Ok(_) => return Err(invalid_private_oram_active_transfer_snapshot()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        absent_store_count += 1;
                    }
                    Err(_) => return Err(invalid_private_oram_active_transfer_snapshot()),
                }
            }
            if absent_store_count == index_states.len() {
                return Ok(Some(
                    PrivateOramActiveTransferSnapshotAction::ResumeForTargetRecovery(
                        transfer.clone(),
                    ),
                ));
            }
            if absent_store_count != 0 {
                return Err(invalid_private_oram_active_transfer_snapshot());
            }
        }
        for (key, state) in &index_states {
            validate_private_oram_active_transfer_local_store(collection_path, key, state)?;
        }
    }

    Ok(Some(PrivateOramActiveTransferSnapshotAction::Apply))
}

fn private_oram_active_reshard_snapshot_layout_entries(
    state: &collection_state::State,
    resharding: &ReshardState,
) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
    if state.shards.is_empty()
        || state
            .transfers
            .iter()
            .any(|transfer| !transfer.is_private_oram_preinstalled_transfer_for(Some(resharding)))
        || resharding.stage != ReshardingStage::MigratingPoints && !state.transfers.is_empty()
    {
        return Err(invalid_private_oram_resharding_snapshot());
    }

    let sharding_method = state.config.params.sharding_method.unwrap_or_default();
    validate_private_oram_snapshot_shard_mapping(state, sharding_method)?;
    let mut target_seen = false;
    let mut entries = Vec::with_capacity(state.shards.len());
    for (shard_id, shard) in &state.shards {
        let shard_key = private_oram_snapshot_shard_key(state, *shard_id, sharding_method)?;
        if shard.replicas.is_empty() {
            return Err(invalid_private_oram_resharding_snapshot());
        }

        let is_target = *shard_id == resharding.shard_id;
        if is_target {
            target_seen = true;
            if shard_key.as_ref() != resharding.shard_key.as_ref()
                || !shard.replicas.contains_key(&resharding.peer_id)
            {
                return Err(invalid_private_oram_resharding_snapshot());
            }
        }

        if resharding.direction == ReshardingDirection::Up && is_target {
            if shard.replicas.len() != 1
                || shard.replicas.values().any(|replica_state| {
                    !matches!(
                        replica_state,
                        ReplicaState::Resharding | ReplicaState::Active
                    ) || resharding.stage != ReshardingStage::MigratingPoints
                        && *replica_state != ReplicaState::Active
                })
            {
                return Err(invalid_private_oram_resharding_snapshot());
            }
            continue;
        }

        let valid_replica_states = shard.replicas.values().all(|replica_state| {
            *replica_state == ReplicaState::Active
                || resharding.direction == ReshardingDirection::Down
                    && resharding.stage == ReshardingStage::MigratingPoints
                    && !is_target
                    && *replica_state == ReplicaState::ReshardingScaleDown
        });
        if !valid_replica_states {
            return Err(invalid_private_oram_resharding_snapshot());
        }
        entries.push(PrivateOramShardLayoutEntry {
            shard_id: *shard_id,
            shard_key,
            owner_peer_ids: shard.replicas.keys().copied().collect(),
        });
    }
    if !target_seen || entries.is_empty() {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    Ok(entries)
}

fn private_oram_snapshot_layout_matches(
    collection_id: &str,
    state: &collection_state::State,
    entries: &[PrivateOramShardLayoutEntry],
    layout: &PrivateOramConsensusLayout,
) -> Result<(), StorageError> {
    let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
        collection_id,
        state.config.params.sharding_method.unwrap_or_default(),
        entries,
    )
    .map_err(|_| invalid_private_oram_resharding_snapshot())?;
    if owner_peer_ids != layout.owner_peer_ids || layout_digest != layout.layout_digest {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    Ok(())
}

fn private_oram_snapshot_can_bootstrap_new_scale_up_target(
    incoming: &collection_state::State,
    resharding: &ReshardState,
    layout: &PrivateOramConsensusLayout,
    this_peer_id: PeerId,
) -> bool {
    if resharding.direction != ReshardingDirection::Up
        || resharding.stage != ReshardingStage::MigratingPoints
        || resharding.peer_id != this_peer_id
        || layout.owner_peer_ids.contains(&this_peer_id)
        || incoming.transfers.len() != 1
    {
        return false;
    }

    let Some(target_shard) = incoming.shards.get(&resharding.shard_id) else {
        return false;
    };
    if target_shard.replicas.len() != 1
        || target_shard.replicas.get(&this_peer_id) != Some(&ReplicaState::Resharding)
        || incoming.shards.iter().any(|(shard_id, shard)| {
            *shard_id != resharding.shard_id && shard.replicas.contains_key(&this_peer_id)
        })
    {
        return false;
    }

    let transfer = incoming
        .transfers
        .iter()
        .next()
        .expect("validated one private ORAM resharding transfer");
    transfer.to == this_peer_id
        && transfer.from != this_peer_id
        && transfer.to_shard_id == Some(resharding.shard_id)
        && transfer.is_private_oram_preinstalled_transfer_for(Some(resharding))
        && incoming
            .shards
            .get(&transfer.shard_id)
            .and_then(|shard| shard.replicas.get(&transfer.from))
            == Some(&ReplicaState::Active)
}

fn private_oram_snapshot_can_rollback_redundant_pre_layout_owner(
    incoming: &collection_state::State,
    resharding: &ReshardState,
    layout: &PrivateOramConsensusLayout,
    pre_layout_entries: &[PrivateOramShardLayoutEntry],
    this_peer_id: PeerId,
) -> bool {
    let is_scale_down_endpoint = resharding.peer_id == this_peer_id;
    if resharding.stage != ReshardingStage::MigratingPoints
        || !layout.owner_peer_ids.contains(&this_peer_id)
        || incoming
            .transfers
            .iter()
            .any(|transfer| transfer.from == this_peer_id || transfer.to == this_peer_id)
    {
        return false;
    }
    if is_scale_down_endpoint
        && (resharding.direction != ReshardingDirection::Down
            || !incoming.transfers.is_empty()
            || incoming.shards.values().any(|shard| {
                shard
                    .replicas
                    .values()
                    .any(|state| *state != ReplicaState::Active)
            }))
    {
        return false;
    }

    let local_pre_layout_entries = pre_layout_entries
        .iter()
        .filter(|entry| entry.owner_peer_ids.contains(&this_peer_id))
        .collect::<Vec<_>>();
    if is_scale_down_endpoint
        && !local_pre_layout_entries
            .iter()
            .any(|entry| entry.shard_id == resharding.shard_id)
    {
        return false;
    }
    !local_pre_layout_entries.is_empty()
        && local_pre_layout_entries.iter().all(|entry| {
            incoming.shards.get(&entry.shard_id).is_some_and(|shard| {
                matches!(
                    shard.replicas.get(&this_peer_id),
                    Some(ReplicaState::Active | ReplicaState::ReshardingScaleDown)
                ) && shard.replicas.iter().any(|(peer_id, state)| {
                    *peer_id != this_peer_id && *state == ReplicaState::Active
                })
            })
        })
}

fn classify_private_oram_active_reshard_snapshot(
    collection_name: &str,
    current: Option<&collection_state::State>,
    incoming: &collection_state::State,
    snapshot: consensus_manager::PrivateOramSnapshotState<'_>,
    this_peer_id: PeerId,
) -> Result<Option<PrivateOramActiveReshardSnapshotAction>, StorageError> {
    let Some(incoming_resharding) = incoming.resharding.as_ref() else {
        return Ok(None);
    };
    let incoming_keys = private_oram_index_keys_for_config(&incoming.config, collection_name)?;
    if incoming_keys.is_empty() {
        return Ok(None);
    }
    let collection_id = incoming
        .config
        .stable_crypto_id(collection_name)
        .map_err(|_| invalid_private_oram_resharding_snapshot())?;
    if let Some(current) = current {
        let current_keys = private_oram_index_keys_for_config(&current.config, collection_name)?;
        if incoming_keys != current_keys
            || current
                .config
                .stable_crypto_id(collection_name)
                .map_err(|_| invalid_private_oram_resharding_snapshot())?
                != collection_id
            || current.config.params.sharding_method != incoming.config.params.sharding_method
            || current.config.params.replication_factor != incoming.config.params.replication_factor
        {
            return Err(invalid_private_oram_resharding_snapshot());
        }
    }

    let mut index_states = Vec::with_capacity(incoming_keys.len());
    for key in &incoming_keys {
        let incoming_epoch = private_oram_epoch_snapshot_value(snapshot.incoming_epochs, key)
            .ok_or_else(invalid_private_oram_resharding_snapshot)?;
        let current_epoch = private_oram_epoch_snapshot_value(snapshot.current_epochs, key);
        let current_epoch_matches = match current {
            Some(_) => current_epoch == Some(incoming_epoch),
            None => current_epoch.is_none() || current_epoch == Some(incoming_epoch),
        };
        if !current_epoch_matches {
            return Err(invalid_private_oram_resharding_snapshot());
        }
        index_states.push((key.clone(), incoming_epoch.clone()));
    }
    let index_state_digest =
        canonical_private_oram_index_state_digest(&collection_id, &index_states)
            .map_err(|_| invalid_private_oram_resharding_snapshot())?;
    let layout_key = crate::content_manager::consensus_ops::PrivateOramLayoutKey {
        collection_id: collection_id.clone(),
    };
    let incoming_layout =
        private_oram_layout_snapshot_value(snapshot.incoming_layouts, &layout_key)
            .ok_or_else(invalid_private_oram_resharding_snapshot)?;
    let current_layout = private_oram_layout_snapshot_value(snapshot.current_layouts, &layout_key);
    if current_layout.is_some_and(|current_layout| current_layout != incoming_layout)
        || current.is_some() && current_layout.is_none() && incoming_layout.generation != 1
        || incoming_layout.index_state_digest != index_state_digest
    {
        return Err(invalid_private_oram_resharding_snapshot());
    }

    let incoming_entries =
        private_oram_active_reshard_snapshot_layout_entries(incoming, incoming_resharding)?;
    private_oram_snapshot_layout_matches(
        &collection_id,
        incoming,
        &incoming_entries,
        incoming_layout,
    )?;

    let Some(current) = current else {
        let topology_only_non_owner = !incoming_layout.owner_peer_ids.contains(&this_peer_id)
            && !incoming
                .shards
                .values()
                .any(|shard| shard.replicas.contains_key(&this_peer_id))
            && !incoming
                .transfers
                .iter()
                .any(|transfer| transfer.from == this_peer_id || transfer.to == this_peer_id);
        let action = if topology_only_non_owner
            || private_oram_snapshot_can_bootstrap_new_scale_up_target(
                incoming,
                incoming_resharding,
                incoming_layout,
                this_peer_id,
            ) {
            PrivateOramActiveReshardSnapshotAction::Apply
        } else if private_oram_snapshot_can_rollback_redundant_pre_layout_owner(
            incoming,
            incoming_resharding,
            incoming_layout,
            &incoming_entries,
            this_peer_id,
        ) {
            PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery
        } else {
            return Err(invalid_private_oram_resharding_snapshot());
        };
        return Ok(Some(action));
    };

    match current.resharding.as_ref() {
        None => {
            let current_entries = private_oram_stable_snapshot_layout_entries(current)?;
            private_oram_snapshot_layout_matches(
                &collection_id,
                current,
                &current_entries,
                incoming_layout,
            )?;
            let config_transition_matches = match incoming_resharding.direction {
                ReshardingDirection::Up => current
                    .config
                    .params
                    .shard_number
                    .checked_add(1)
                    .is_some_and(|count| count == incoming.config.params.shard_number),
                ReshardingDirection::Down => {
                    current.config.params.shard_number == incoming.config.params.shard_number
                }
            };
            if !config_transition_matches {
                return Err(invalid_private_oram_resharding_snapshot());
            }
        }
        Some(current_resharding) => {
            if current_resharding.key() != incoming_resharding.key()
                || current_resharding.stage > incoming_resharding.stage
                || current.config.params.shard_number != incoming.config.params.shard_number
                || current.shards.keys().collect::<HashSet<_>>()
                    != incoming.shards.keys().collect::<HashSet<_>>()
            {
                return Err(invalid_private_oram_resharding_snapshot());
            }
            let current_entries =
                private_oram_active_reshard_snapshot_layout_entries(current, current_resharding)?;
            private_oram_snapshot_layout_matches(
                &collection_id,
                current,
                &current_entries,
                incoming_layout,
            )?;
            for (shard_id, current_shard) in &current.shards {
                let incoming_shard = incoming
                    .shards
                    .get(shard_id)
                    .ok_or_else(invalid_private_oram_resharding_snapshot)?;
                if current_shard.replicas.keys().collect::<HashSet<_>>()
                    != incoming_shard.replicas.keys().collect::<HashSet<_>>()
                    || current_shard
                        .replicas
                        .iter()
                        .any(|(peer_id, replica_state)| {
                            *replica_state == ReplicaState::Active
                                && incoming_shard.replicas.get(peer_id)
                                    != Some(&ReplicaState::Active)
                        })
                {
                    return Err(invalid_private_oram_resharding_snapshot());
                }
            }
        }
    }

    Ok(Some(PrivateOramActiveReshardSnapshotAction::Apply))
}

#[cfg(test)]
fn validate_private_oram_active_reshard_snapshot(
    collection_name: &str,
    current: Option<&collection_state::State>,
    incoming: &collection_state::State,
    snapshot: consensus_manager::PrivateOramSnapshotState<'_>,
    this_peer_id: PeerId,
) -> Result<bool, StorageError> {
    Ok(classify_private_oram_active_reshard_snapshot(
        collection_name,
        current,
        incoming,
        snapshot,
        this_peer_id,
    )?
    .is_some())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::num::NonZeroU32;

    use ahash::AHashMap;
    use collection::collection::payload_index_schema::PayloadIndexSchema;
    use collection::collection_state::{ShardInfo, State};
    use collection::config::{
        CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams,
        CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, ShardingMethod, WalConfig,
    };
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::resharding::{ReshardState, ReshardingStage};
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferIndexState,
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition, ShardTransfer,
        ShardTransferMethod,
    };
    use data_encoding::BASE64URL_NOPAD;
    use fs_err as fs;
    use segment::types::HnswConfig;
    use uuid::Uuid;

    use super::{
        PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_ABORT_VERSION,
        PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_LEGACY_VERSION,
        PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES, PrivateOramActiveReshardSnapshotAction,
        PrivateOramActiveTransferSnapshotAction, PrivateOramSnapshotRecoveryOperation,
        classify_private_oram_active_reshard_snapshot, collection_params_bind_crypto_identity,
        encrypted_uuid_mismatch_requires_fail_closed, private_oram_snapshot_recovery_marker_path,
        read_private_oram_snapshot_recovery_marker, remove_private_oram_snapshot_recovery_marker,
        validate_private_oram_active_reshard_snapshot,
        validate_private_oram_active_transfer_snapshot,
        validate_private_oram_missing_collection_path,
        validate_private_oram_snapshot_recovery_complete,
        write_private_oram_snapshot_recovery_marker,
        write_private_oram_transfer_snapshot_recovery_marker,
        write_private_oram_transfer_snapshot_resume_marker,
    };
    use crate::content_manager::consensus::persistent::{
        private_oram_epoch_key_digest, private_oram_layout_key_digest,
    };
    use crate::content_manager::consensus_manager::PrivateOramSnapshotState;
    use crate::content_manager::consensus_ops::{
        PrivateOramConsensusEpoch, PrivateOramConsensusLayout, PrivateOramIndexKind,
        PrivateOramLayoutKey, PrivateOramShardLayoutEntry,
        canonical_private_oram_index_state_digest, canonical_private_oram_shard_layout_digest,
        private_oram_index_keys_for_config,
    };

    fn encrypted_params() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/payload".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body".to_string(),
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

    fn test_optimizers_config() -> OptimizersConfig {
        OptimizersConfig {
            deleted_threshold: 0.1,
            vacuum_min_vector_number: 1000,
            default_segment_number: 0,
            max_segment_size: None,
            #[expect(deprecated)]
            memmap_threshold: None,
            indexing_threshold: Some(100_000),
            flush_interval_sec: 60,
            max_optimization_threads: Some(0),
            prevent_unoptimized: None,
        }
    }

    fn private_oram_snapshot_config(shard_number: u32) -> CollectionConfigInternal {
        let mut params = CollectionParams::empty();
        params.shard_number = NonZeroU32::new(shard_number).unwrap();
        params.encryption = Some(CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a/private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private-result".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs-private-result".to_string(),
                binding: Some("private-result-oram/v1".to_string()),
            }],
        });
        CollectionConfigInternal {
            params,
            hnsw_config: HnswConfig::default(),
            optimizer_config: test_optimizers_config(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(0x1234567890abcdef1234567890abcdef)),
            metadata: None,
        }
    }

    fn private_oram_active_snapshot_fixture() -> (
        State,
        State,
        HashMap<String, PrivateOramConsensusEpoch>,
        HashMap<String, PrivateOramConsensusLayout>,
    ) {
        let current = State {
            config: private_oram_snapshot_config(1),
            shards: AHashMap::from([(
                0,
                ShardInfo {
                    replicas: HashMap::from([(11, ReplicaState::Active)]),
                },
            )]),
            resharding: None,
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let resharding = ReshardState::new(Uuid::nil(), ReshardingDirection::Up, 22, 1, None);
        let incoming = State {
            config: private_oram_snapshot_config(2),
            shards: AHashMap::from([
                (
                    0,
                    ShardInfo {
                        replicas: HashMap::from([(11, ReplicaState::Active)]),
                    },
                ),
                (
                    1,
                    ShardInfo {
                        replicas: HashMap::from([(22, ReplicaState::Resharding)]),
                    },
                ),
            ]),
            resharding: Some(resharding),
            transfers: HashSet::from([ShardTransfer {
                shard_id: 0,
                to_shard_id: Some(1),
                from: 11,
                to: 22,
                sync: true,
                method: Some(ShardTransferMethod::ReshardingStreamRecords),
                private_oram_preinstalled: true,
                private_oram_layout_transition: None,
                filter: None,
            }]),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };

        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[3; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[4; 32])),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch.clone())]);
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &[PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![11],
            }],
        )
        .unwrap();
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids,
            layout_digest,
            index_state_digest,
        };
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(private_oram_layout_key_digest(&layout_key), layout)]);
        (current, incoming, epochs, layouts)
    }

    fn private_oram_active_transfer_snapshot_fixture(
        pre_owner_peer_ids: &[u64],
    ) -> (
        State,
        HashMap<String, PrivateOramConsensusEpoch>,
        HashMap<String, PrivateOramConsensusLayout>,
    ) {
        let mut config = private_oram_snapshot_config(1);
        config.params.replication_factor =
            NonZeroU32::new(pre_owner_peer_ids.len() as u32).unwrap();
        let collection_id = config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[7; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[8; 32])),
        };
        let index_state_digest = canonical_private_oram_index_state_digest(
            &collection_id,
            &[(keys[0].clone(), epoch.clone())],
        )
        .unwrap();
        let pre_entries = vec![PrivateOramShardLayoutEntry {
            shard_id: 0,
            shard_key: None,
            owner_peer_ids: pre_owner_peer_ids.to_vec(),
        }];
        let mut post_owner_peer_ids = pre_owner_peer_ids.to_vec();
        post_owner_peer_ids.push(22);
        post_owner_peer_ids.sort_unstable();
        let post_entries = vec![PrivateOramShardLayoutEntry {
            shard_id: 0,
            shard_key: None,
            owner_peer_ids: post_owner_peer_ids,
        }];
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &post_entries,
        )
        .unwrap();
        let expected = PrivateOramTransferLayoutState {
            generation: 1,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: index_state_digest.clone(),
        };
        let new = PrivateOramTransferLayoutState {
            generation: 2,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest,
        };
        let transfer = ShardTransfer {
            shard_id: 0,
            to_shard_id: None,
            from: 11,
            to: 22,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: collection_id.clone(),
                expected: expected.clone(),
                new,
                index_states: vec![PrivateOramTransferIndexState {
                    index_kind: match keys[0].index_kind {
                        PrivateOramIndexKind::Hnsw => PrivateOramTransferIndexKind::Hnsw,
                        PrivateOramIndexKind::ResultPayload => {
                            PrivateOramTransferIndexKind::ResultPayload
                        }
                    },
                    index_name: keys[0].index_name.clone(),
                    index_epoch: epoch.index_epoch,
                    root_hash: epoch.root_hash.clone(),
                    writeback_digest: epoch.writeback_digest.clone(),
                }],
            }),
            filter: None,
        };
        let mut replicas = pre_owner_peer_ids
            .iter()
            .map(|peer_id| (*peer_id, ReplicaState::Active))
            .collect::<HashMap<_, _>>();
        replicas.insert(22, ReplicaState::Partial);
        let incoming = State {
            config,
            shards: AHashMap::from([(0, ShardInfo { replicas })]),
            resharding: None,
            transfers: HashSet::from([transfer]),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch)]);
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: expected.generation,
                owner_peer_ids: expected.owner_peer_ids,
                layout_digest: expected.layout_digest,
                index_state_digest: expected.index_state_digest,
            },
        )]);
        (incoming, epochs, layouts)
    }

    #[test]
    fn collection_params_bind_crypto_identity_for_encrypted_configs() {
        assert!(!collection_params_bind_crypto_identity(
            &CollectionParams::empty()
        ));

        let encrypted = encrypted_params();

        assert!(collection_params_bind_crypto_identity(&encrypted));
    }

    #[test]
    fn encrypted_uuid_mismatch_requires_fail_closed_for_encrypted_configs() {
        let plaintext = CollectionParams::empty();
        let encrypted = encrypted_params();

        assert!(!encrypted_uuid_mismatch_requires_fail_closed(
            &plaintext, &plaintext,
        ));
        assert!(encrypted_uuid_mismatch_requires_fail_closed(
            &encrypted, &plaintext,
        ));
        assert!(encrypted_uuid_mismatch_requires_fail_closed(
            &plaintext, &encrypted,
        ));
    }

    #[test]
    fn active_private_oram_transfer_snapshot_recovers_redundant_owners_and_fresh_target() {
        let (incoming, epochs, layouts) = private_oram_active_transfer_snapshot_fixture(&[11, 12]);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert!(matches!(
            validate_private_oram_active_transfer_snapshot(
                "docs", None, None, &incoming, snapshot, 11,
            )
            .unwrap(),
            Some(PrivateOramActiveTransferSnapshotAction::AbortForReplicaRecovery(_))
        ));
        assert!(matches!(
            validate_private_oram_active_transfer_snapshot(
                "docs", None, None, &incoming, snapshot, 22,
            )
            .unwrap(),
            Some(PrivateOramActiveTransferSnapshotAction::ResumeForTargetRecovery(_))
        ));
        assert!(matches!(
            validate_private_oram_active_transfer_snapshot(
                "docs", None, None, &incoming, snapshot, 12,
            )
            .unwrap(),
            Some(PrivateOramActiveTransferSnapshotAction::AbortForReplicaRecovery(_))
        ));
        assert!(matches!(
            validate_private_oram_active_transfer_snapshot(
                "docs", None, None, &incoming, snapshot, 33,
            )
            .unwrap(),
            Some(PrivateOramActiveTransferSnapshotAction::Apply)
        ));

        let temp = tempfile::tempdir().unwrap();
        let snapshot_with_current = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };
        assert!(matches!(
            validate_private_oram_active_transfer_snapshot(
                "docs",
                Some(&incoming),
                Some(temp.path()),
                &incoming,
                snapshot_with_current,
                22,
            )
            .unwrap(),
            Some(PrivateOramActiveTransferSnapshotAction::ResumeForTargetRecovery(_))
        ));

        let mut completed_target = incoming.clone();
        completed_target.transfers.clear();
        completed_target
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_transfer_snapshot(
                "docs",
                Some(&completed_target),
                Some(temp.path()),
                &incoming,
                snapshot_with_current,
                22,
            )
            .is_err()
        );
    }

    #[test]
    fn active_private_oram_transfer_snapshot_rejects_wiped_sole_source() {
        let (incoming, epochs, layouts) = private_oram_active_transfer_snapshot_fixture(&[11]);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert!(
            validate_private_oram_active_transfer_snapshot(
                "docs", None, None, &incoming, snapshot, 11,
            )
            .is_err()
        );
    }

    #[test]
    fn active_private_oram_transfer_snapshot_rejects_missing_current_owner_store() {
        let (incoming, epochs, layouts) = private_oram_active_transfer_snapshot_fixture(&[11, 12]);
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };
        let temp = tempfile::tempdir().unwrap();

        assert!(
            validate_private_oram_active_transfer_snapshot(
                "docs",
                Some(&incoming),
                Some(temp.path()),
                &incoming,
                snapshot,
                11,
            )
            .is_err()
        );
        assert!(matches!(
            validate_private_oram_active_transfer_snapshot(
                "docs",
                Some(&incoming),
                Some(temp.path()),
                &incoming,
                snapshot,
                33,
            )
            .unwrap(),
            Some(PrivateOramActiveTransferSnapshotAction::Apply)
        ));
    }

    #[test]
    fn active_private_oram_transfer_snapshot_rejects_generation_skip() {
        let (mut incoming, epochs, layouts) =
            private_oram_active_transfer_snapshot_fixture(&[11, 12]);
        let mut transfer = incoming.transfers.iter().next().unwrap().clone();
        transfer
            .private_oram_layout_transition
            .as_mut()
            .unwrap()
            .new
            .generation += 1;
        incoming.transfers.clear();
        incoming.transfers.insert(transfer);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert!(
            validate_private_oram_active_transfer_snapshot(
                "docs", None, None, &incoming, snapshot, 33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_active_reshard_snapshot_requires_exact_consensus_bound_pre_layout() {
        let (current, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&incoming),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );

        let mut wrong_layouts = layouts.clone();
        wrong_layouts.values_mut().next().unwrap().layout_digest = BASE64URL_NOPAD.encode(&[9; 32]);
        let err = validate_private_oram_active_reshard_snapshot(
            "docs",
            Some(&current),
            &incoming,
            PrivateOramSnapshotState {
                incoming_epochs: &epochs,
                current_epochs: &epochs,
                incoming_layouts: &wrong_layouts,
                current_layouts: &layouts,
            },
            33,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("private ORAM active reshard Raft snapshot state is invalid")
        );

        let mut wrong_epochs = epochs.clone();
        wrong_epochs.values_mut().next().unwrap().index_epoch += 1;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &wrong_epochs,
                    current_epochs: &epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &layouts,
                },
                33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_active_reshard_snapshot_allows_only_first_layout_initialization() {
        let (current, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let empty_layouts = HashMap::new();
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&incoming),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );

        let mut later_layouts = layouts.clone();
        later_layouts.values_mut().next().unwrap().generation = 2;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &epochs,
                    incoming_layouts: &later_layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_new_peer_active_reshard_snapshot_allows_only_recoverable_roles() {
        let (_, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();

        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &empty_epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .unwrap()
        );

        let mut later_layouts = layouts.clone();
        later_layouts.values_mut().next().unwrap().generation = 7;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &empty_epochs,
                    incoming_layouts: &later_layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .unwrap()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &epochs,
                    incoming_layouts: &later_layouts,
                    current_layouts: &later_layouts,
                },
                33,
            )
            .unwrap()
        );

        let mut wrong_epochs = epochs.clone();
        wrong_epochs.values_mut().next().unwrap().index_epoch += 1;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &wrong_epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .is_err()
        );

        let mut wrong_layouts = layouts.clone();
        wrong_layouts.values_mut().next().unwrap().generation += 1;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &empty_epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &wrong_layouts,
                },
                33,
            )
            .is_err()
        );

        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };
        assert!(
            validate_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 11,)
                .is_err()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .unwrap()
        );

        let mut missing_transfer = incoming.clone();
        missing_transfer.transfers.clear();
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &missing_transfer,
                snapshot,
                22,
            )
            .is_err()
        );

        let mut active_target = incoming.clone();
        *active_target
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .get_mut(&22)
            .unwrap() = ReplicaState::Active;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &active_target,
                snapshot,
                22,
            )
            .is_err()
        );

        let mut target_is_existing_owner = incoming;
        target_is_existing_owner
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &target_is_existing_owner,
                snapshot,
                22,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_new_redundant_owner_snapshot_requires_exact_reshard_rollback() {
        let (_, mut incoming, epochs, _) = private_oram_active_snapshot_fixture();
        incoming
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(12, ReplicaState::Active);

        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = epochs.values().next().unwrap().clone();
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &[PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![11, 12],
            }],
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids,
                layout_digest,
                index_state_digest,
            },
        )]);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert_eq!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 12,)
                .unwrap(),
            Some(PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery),
        );
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 11,)
                .is_err(),
            "the active transfer source must not bootstrap through non-endpoint rollback",
        );

        let mut committed = incoming;
        committed.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        committed.transfers.clear();
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &committed, snapshot, 12,)
                .is_err(),
            "snapshot rollback must close after the read hash ring is committed",
        );
    }

    #[test]
    fn private_oram_wiped_redundant_scale_down_endpoint_requires_exact_rollback() {
        let mut incoming = State {
            config: private_oram_snapshot_config(2),
            shards: AHashMap::from([
                (
                    0,
                    ShardInfo {
                        replicas: HashMap::from([
                            (11, ReplicaState::Active),
                            (22, ReplicaState::Active),
                            (44, ReplicaState::Active),
                        ]),
                    },
                ),
                (
                    1,
                    ShardInfo {
                        replicas: HashMap::from([
                            (22, ReplicaState::Active),
                            (33, ReplicaState::Active),
                        ]),
                    },
                ),
            ]),
            resharding: Some(ReshardState::new(
                Uuid::nil(),
                ReshardingDirection::Down,
                22,
                1,
                None,
            )),
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[23; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[24; 32])),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch.clone())]);
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &[
                PrivateOramShardLayoutEntry {
                    shard_id: 0,
                    shard_key: None,
                    owner_peer_ids: vec![11, 22, 44],
                },
                PrivateOramShardLayoutEntry {
                    shard_id: 1,
                    shard_key: None,
                    owner_peer_ids: vec![22, 33],
                },
            ],
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids,
                layout_digest,
                index_state_digest,
            },
        )]);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert_eq!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .unwrap(),
            Some(PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery),
        );

        let mut nonredundant_local_shard = incoming.clone();
        nonredundant_local_shard
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .retain(|peer_id, _| *peer_id == 22);
        assert!(
            classify_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &nonredundant_local_shard,
                snapshot,
                22,
            )
            .is_err(),
            "every local pre-layout shard must retain another active replica",
        );

        incoming.transfers.insert(ShardTransfer {
            shard_id: 1,
            to_shard_id: Some(0),
            from: 22,
            to: 11,
            sync: true,
            method: Some(ShardTransferMethod::ReshardingStreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        });
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .is_err(),
            "an in-flight scale-down transfer source must remain fail closed",
        );

        incoming.transfers.clear();
        incoming.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .is_err(),
            "a committed scale-down endpoint must remain fail closed",
        );
    }

    #[test]
    fn private_oram_snapshot_recovery_marker_is_durable_exact_and_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let key = ReshardState::new(Uuid::new_v4(), ReshardingDirection::Up, 22, 1, None).key();
        write_private_oram_snapshot_recovery_marker(temp.path(), &key).unwrap();
        write_private_oram_snapshot_recovery_marker(temp.path(), &key).unwrap();

        let marker = read_private_oram_snapshot_recovery_marker(temp.path())
            .unwrap()
            .unwrap();
        assert!(matches!(
            marker.operation().unwrap(),
            PrivateOramSnapshotRecoveryOperation::Resharding(actual) if actual == key
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs::metadata(private_oram_snapshot_recovery_marker_path(temp.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }

        let other = ReshardState::new(Uuid::new_v4(), ReshardingDirection::Up, 22, 1, None).key();
        assert!(write_private_oram_snapshot_recovery_marker(temp.path(), &other).is_err());
        remove_private_oram_snapshot_recovery_marker(temp.path()).unwrap();
        assert!(
            read_private_oram_snapshot_recovery_marker(temp.path())
                .unwrap()
                .is_none()
        );

        let (incoming, _, _) = private_oram_active_transfer_snapshot_fixture(&[11, 12]);
        let transfer = incoming.transfers.iter().next().unwrap().clone();
        write_private_oram_transfer_snapshot_recovery_marker(temp.path(), &transfer).unwrap();
        write_private_oram_transfer_snapshot_recovery_marker(temp.path(), &transfer).unwrap();
        assert!(write_private_oram_snapshot_recovery_marker(temp.path(), &key).is_err());
        let marker = read_private_oram_snapshot_recovery_marker(temp.path())
            .unwrap()
            .unwrap();
        assert!(matches!(
            marker.operation().unwrap(),
            PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(actual) if actual == transfer
        ));
        remove_private_oram_snapshot_recovery_marker(temp.path()).unwrap();

        write_private_oram_transfer_snapshot_resume_marker(temp.path(), &transfer).unwrap();
        write_private_oram_transfer_snapshot_resume_marker(temp.path(), &transfer).unwrap();
        assert!(
            write_private_oram_transfer_snapshot_recovery_marker(temp.path(), &transfer).is_err()
        );
        let marker = read_private_oram_snapshot_recovery_marker(temp.path())
            .unwrap()
            .unwrap();
        assert!(matches!(
            marker.operation().unwrap(),
            PrivateOramSnapshotRecoveryOperation::ShardTransferResume(actual) if actual == transfer
        ));
        let blocked = validate_private_oram_snapshot_recovery_complete(temp.path())
            .unwrap_err()
            .to_string();
        assert!(blocked.contains("snapshot recovery is pending"));
        assert!(!blocked.contains("docs-id"));
        remove_private_oram_snapshot_recovery_marker(temp.path()).unwrap();

        let marker_path = private_oram_snapshot_recovery_marker_path(temp.path());
        let write_legacy_marker = |value: serde_json::Value| {
            fs::write(&marker_path, serde_json::to_vec(&value).unwrap()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        };
        write_legacy_marker(serde_json::json!({
            "version": PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_LEGACY_VERSION,
            "resharding_key": key,
        }));
        let marker = read_private_oram_snapshot_recovery_marker(temp.path())
            .unwrap()
            .unwrap();
        assert!(matches!(
            marker.operation().unwrap(),
            PrivateOramSnapshotRecoveryOperation::Resharding(actual) if actual == key
        ));
        remove_private_oram_snapshot_recovery_marker(temp.path()).unwrap();

        write_legacy_marker(serde_json::json!({
            "version": PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_ABORT_VERSION,
            "shard_transfer": transfer,
        }));
        let marker = read_private_oram_snapshot_recovery_marker(temp.path())
            .unwrap()
            .unwrap();
        assert!(matches!(
            marker.operation().unwrap(),
            PrivateOramSnapshotRecoveryOperation::ShardTransferAbort(actual) if actual == transfer
        ));
        remove_private_oram_snapshot_recovery_marker(temp.path()).unwrap();

        let mut oversized = transfer;
        oversized
            .private_oram_layout_transition
            .as_mut()
            .unwrap()
            .expected
            .layout_digest = "x".repeat(PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES as usize);
        assert!(
            write_private_oram_transfer_snapshot_resume_marker(temp.path(), &oversized).is_err()
        );
        assert!(!marker_path.exists());

        fs::write(&marker_path, b"recovery-marker-secret-sentinel").unwrap();
        let rendered = match read_private_oram_snapshot_recovery_marker(temp.path()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("malformed private ORAM recovery marker must fail closed"),
        };
        assert!(!rendered.contains("recovery-marker-secret-sentinel"));
    }

    #[test]
    fn private_oram_missing_collection_path_rejects_orphan_disk_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("orphan-collection");
        validate_private_oram_missing_collection_path(&path).unwrap();

        fs::create_dir(&path).unwrap();
        assert!(validate_private_oram_missing_collection_path(&path).is_err());
        fs::remove_dir(&path).unwrap();

        fs::write(&path, b"orphan").unwrap();
        assert!(validate_private_oram_missing_collection_path(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_oram_snapshot_recovery_marker_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"{}").unwrap();
        symlink(
            &outside,
            private_oram_snapshot_recovery_marker_path(temp.path()),
        )
        .unwrap();
        assert!(read_private_oram_snapshot_recovery_marker(temp.path()).is_err());
    }

    #[test]
    fn private_oram_active_reshard_snapshot_rejects_unmarked_or_regressing_state() {
        let (current, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };

        let mut unmarked = incoming.clone();
        unmarked.transfers = unmarked
            .transfers
            .into_iter()
            .map(|transfer| ShardTransfer {
                private_oram_preinstalled: false,
                ..transfer
            })
            .collect();
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &unmarked,
                context,
                33,
            )
            .is_err()
        );

        let mut advanced = incoming.clone();
        advanced.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        advanced.transfers.clear();
        advanced
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&advanced),
                &incoming,
                context,
                33,
            )
            .is_err()
        );

        let mut active_current = incoming.clone();
        active_current
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&active_current),
                &incoming,
                context,
                33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_scale_down_snapshot_accepts_only_receiver_resharding_state() {
        let current = State {
            config: private_oram_snapshot_config(2),
            shards: AHashMap::from([
                (
                    0,
                    ShardInfo {
                        replicas: HashMap::from([(11, ReplicaState::Active)]),
                    },
                ),
                (
                    1,
                    ShardInfo {
                        replicas: HashMap::from([(22, ReplicaState::Active)]),
                    },
                ),
            ]),
            resharding: None,
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let mut incoming = current.clone();
        incoming.resharding = Some(ReshardState::new(
            Uuid::nil(),
            ReshardingDirection::Down,
            22,
            1,
            None,
        ));
        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[13; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[14; 32])),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch.clone())]);
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let entries = [
            PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![11],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![22],
            },
        ];
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &entries,
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids,
                layout_digest,
                index_state_digest,
            },
        )]);
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };

        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );
        let mut committed = incoming.clone();
        committed.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&incoming),
                &committed,
                context,
                33,
            )
            .unwrap()
        );

        let mut receiver_transition = incoming.clone();
        receiver_transition
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(11, ReplicaState::ReshardingScaleDown);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &receiver_transition,
                context,
                33,
            )
            .unwrap()
        );

        let mut wrong_target = incoming.clone();
        wrong_target
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::ReshardingScaleDown);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &wrong_target,
                context,
                33,
            )
            .is_err()
        );
    }
}

impl TableOfContent {
    fn collections_snapshot_sync(&self) -> consensus_manager::CollectionsSnapshot {
        self.general_runtime.block_on(self.collections_snapshot())
    }

    async fn collections_snapshot(&self) -> consensus_manager::CollectionsSnapshot {
        let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        let mut collections: HashMap<CollectionId, collection_state::State> = HashMap::new();
        let live_collections: Vec<_> = self
            .collections
            .read()
            .await
            .iter()
            .map(|(id, collection)| (id.clone(), collection.clone()))
            .collect();
        for (id, collection) in live_collections {
            collections.insert(id.clone(), collection.state().await);
        }
        for detached in &self.private_oram_external_recovery_detached {
            collections
                .entry(detached.key().clone())
                .or_insert_with(|| detached.state.clone());
        }
        consensus_manager::CollectionsSnapshot {
            collections,
            aliases: self.alias_persistence.read().await.state().clone(),
        }
    }

    fn apply_collections_snapshot_inner(
        &self,
        data: consensus_manager::CollectionsSnapshot,
        private_oram_snapshot: Option<consensus_manager::PrivateOramSnapshotState<'_>>,
    ) -> Result<(), consensus_manager::CollectionsSnapshotApplyError> {
        self.general_runtime.block_on(async {
            let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
            // Validate first: nothing local changes until `prepared` exists, so a rejection here
            // leaves the node consistent and must not arm the indeterminate fence.
            let (collections, prepared) = self
                .validate_collections_snapshot(&data, private_oram_snapshot)
                .await
                .map_err(consensus_manager::CollectionsSnapshotApplyError::Rejected)?;
            self.apply_validated_collections_snapshot(data, prepared, collections)
                .await
                .map_err(consensus_manager::CollectionsSnapshotApplyError::Indeterminate)
        })
    }

    /// Read-only classification of a collections snapshot against local state. Holds the
    /// collections write lock so the classification stays valid for the apply that follows.
    async fn validate_collections_snapshot(
        &self,
        data: &consensus_manager::CollectionsSnapshot,
        private_oram_snapshot: Option<consensus_manager::PrivateOramSnapshotState<'_>>,
    ) -> Result<
        (
            RwLockWriteGuard<'_, Collections>,
            PreparedCollectionsSnapshot,
        ),
        StorageError,
    > {
        let mut recovery_fenced: HashMap<_, _> = self
            .private_oram_external_recovery_detached
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().state.clone()))
            .collect();
        let live_collections: Vec<_> = self
            .collections
            .read()
            .await
            .iter()
            .map(|(id, collection)| (id.clone(), collection.clone()))
            .collect();
        for (collection_name, collection) in live_collections {
            if self
                .private_oram_external_recovery_fence(&collection)
                .await?
                .is_some()
            {
                recovery_fenced
                    .entry(collection_name)
                    .or_insert(collection.state().await);
            }
        }
        if !recovery_fenced.is_empty() {
            let aliases = self.alias_persistence.read().await;
            if aliases.state() != &data.aliases
                || recovery_fenced.iter().any(|(collection_name, state)| {
                    data.collections.get(collection_name) != Some(state)
                })
            {
                return Err(StorageError::Locked {
                    description: "Raft snapshot conflicts with private ORAM recovery installation"
                        .to_string(),
                });
            }
        }
        let collections = self.collections.write().await;
        let mut validated_private_oram_resharding = HashSet::new();
        let mut private_oram_snapshot_recovery_aborts = HashMap::new();
        let mut private_oram_transfer_snapshot_recovery_aborts = HashMap::new();
        let mut private_oram_transfer_snapshot_recovery_resumes = HashMap::new();
        for (id, state) in &data.collections {
            if recovery_fenced.contains_key(id) {
                continue;
            }
            if private_oram_index_keys_for_config(&state.config, id)?.is_empty()
                || state.resharding.is_none() && state.transfers.is_empty()
            {
                continue;
            }
            let private_oram_snapshot =
                private_oram_snapshot.ok_or_else(invalid_private_oram_resharding_snapshot)?;
            let (current, current_collection_path) = match collections.get(id) {
                Some(collection) => (
                    Some(collection.state().await),
                    Some(collection.path().to_path_buf()),
                ),
                None => {
                    let collection_path = self.get_collection_path(id);
                    validate_private_oram_missing_collection_path(&collection_path)?;
                    (None, None)
                }
            };
            if let Some(action) = validate_private_oram_active_transfer_snapshot(
                id,
                current.as_ref(),
                current_collection_path.as_deref(),
                state,
                private_oram_snapshot,
                self.this_peer_id,
            )? {
                match action {
                    PrivateOramActiveTransferSnapshotAction::Apply => {}
                    PrivateOramActiveTransferSnapshotAction::AbortForReplicaRecovery(transfer) => {
                        private_oram_transfer_snapshot_recovery_aborts.insert(id.clone(), transfer);
                    }
                    PrivateOramActiveTransferSnapshotAction::ResumeForTargetRecovery(transfer) => {
                        private_oram_transfer_snapshot_recovery_resumes
                            .insert(id.clone(), transfer);
                    }
                }
                continue;
            }
            if state.resharding.is_none() {
                continue;
            }
            if let Some(action) = classify_private_oram_active_reshard_snapshot(
                id,
                current.as_ref(),
                state,
                private_oram_snapshot,
                self.this_peer_id,
            )? {
                validated_private_oram_resharding.insert(id.clone());
                if action == PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery {
                    private_oram_snapshot_recovery_aborts.insert(
                        id.clone(),
                        state
                            .resharding
                            .as_ref()
                            .expect("validated active private ORAM reshard")
                            .key(),
                    );
                }
            }
        }

        Ok((
            collections,
            PreparedCollectionsSnapshot {
                recovery_fenced,
                validated_private_oram_resharding,
                private_oram_snapshot_recovery_aborts,
                private_oram_transfer_snapshot_recovery_aborts,
                private_oram_transfer_snapshot_recovery_resumes,
            },
        ))
    }

    /// Applies a snapshot that `validate_collections_snapshot` accepted. Every error from here
    /// on may leave local collections partially updated.
    async fn apply_validated_collections_snapshot(
        &self,
        data: consensus_manager::CollectionsSnapshot,
        prepared: PreparedCollectionsSnapshot,
        mut collections: RwLockWriteGuard<'_, Collections>,
    ) -> Result<(), StorageError> {
        let PreparedCollectionsSnapshot {
            recovery_fenced,
            validated_private_oram_resharding,
            private_oram_snapshot_recovery_aborts,
            private_oram_transfer_snapshot_recovery_aborts,
            private_oram_transfer_snapshot_recovery_resumes,
        } = prepared;
        for (id, state) in &data.collections {
            if recovery_fenced.contains_key(id) {
                continue;
            }
            if let Some(collection) = collections.get(id) {
                let collection_config = collection.config_snapshot().await;
                let collection_uuid = collection_config.uuid;

                let recreate_collection = if collection_uuid != state.config.uuid {
                    if encrypted_uuid_mismatch_requires_fail_closed(
                        &collection_config.params,
                        &state.config.params,
                    ) {
                        return Err(StorageError::service_error(format!(
                            "encrypted collection {id} UUID mismatch while applying Raft snapshot: \
                                 existing collection UUID: {collection_uuid:?}, \
                                 Raft snapshot collection UUID: {:?}; refusing encrypted collection rebind",
                            state.config.uuid,
                        )));
                    }

                    log::warn!(
                        "Recreating collection {id}, because collection UUID is different: \
                             existing collection UUID: {collection_uuid:?}, \
                             Raft snapshot collection UUID: {:?}",
                        state.config.uuid,
                    );

                    true
                } else if let Err(err) = collection.check_config_compatible(&state.config).await {
                    log::warn!(
                        "Recreating collection {id}, because collection config is incompatible: \
                             {err}",
                    );

                    true
                } else {
                    false
                };

                if recreate_collection {
                    // Drop `collections` lock
                    drop(collections);

                    // Delete collection
                    self.delete_collection_locked(id).await?;

                    // Re-acquire `collections` lock 🙄
                    collections = self.collections.write().await;
                }
            }

            let collection_exists = collections.contains_key(id);

            if collection_exists
                && let Some(transfer) = private_oram_transfer_snapshot_recovery_resumes.get(id)
            {
                let collection = collections
                    .get(id)
                    .expect("checked existing collection during snapshot recovery");
                write_private_oram_transfer_snapshot_resume_marker(collection.path(), transfer)?;
            }

            // Create collection if not present locally
            if !collection_exists {
                let collection_path = self.create_collection_path(id).await?;
                let snapshots_path = self.create_snapshots_path(id).await?;
                if let Some(resharding_key) = private_oram_snapshot_recovery_aborts.get(id) {
                    write_private_oram_snapshot_recovery_marker(&collection_path, resharding_key)?;
                } else if let Some(transfer) =
                    private_oram_transfer_snapshot_recovery_aborts.get(id)
                {
                    write_private_oram_transfer_snapshot_recovery_marker(
                        &collection_path,
                        transfer,
                    )?;
                } else if let Some(transfer) =
                    private_oram_transfer_snapshot_recovery_resumes.get(id)
                {
                    write_private_oram_transfer_snapshot_resume_marker(&collection_path, transfer)?;
                }
                let shard_distribution =
                    CollectionShardDistribution::from_shards_info(state.shards.clone());
                let collection = Collection::new(
                    id.clone(),
                    self.this_peer_id,
                    &collection_path,
                    &snapshots_path,
                    &state.config,
                    self.storage_config
                        .to_shared_storage_config(self.is_distributed())
                        .into(),
                    shard_distribution,
                    Some(state.shards_key_mapping.clone()),
                    self.channel_service.clone(),
                    Self::change_peer_from_state_callback(
                        self.consensus_proposal_sender.clone(),
                        id.clone(),
                        ReplicaState::Dead,
                    ),
                    Self::request_shard_transfer_callback(
                        self.consensus_proposal_sender.clone(),
                        id.clone(),
                    ),
                    Self::abort_shard_transfer_callback(
                        self.consensus_proposal_sender.clone(),
                        id.clone(),
                    ),
                    Some(self.search_runtime.handle().clone()),
                    Some(self.update_runtime.handle().clone()),
                    self.optimizer_resource_budget.clone(),
                    self.storage_config.optimizers_overwrite.clone(),
                )
                .await?;
                collections.validate_collection_not_exists(id)?;
                collections.insert(id.clone(), Arc::new(collection));
            }

            let Some(collection) = collections.get(id) else {
                return Err(StorageError::service_error(format!(
                    "collection {id} is missing after snapshot apply",
                )));
            };

            // Update collection state
            if &collection.state().await != state {
                if let Some(proposal_sender) = self.consensus_proposal_sender.clone() {
                    // In some cases on state application it might be needed to abort the transfer
                    let abort_transfer = |transfer| {
                        if let Err(error) =
                            proposal_sender.send(ConsensusOperations::abort_transfer(
                                id.clone(),
                                transfer,
                                "sender was not up to date",
                            ))
                        {
                            log::error!("Can't report transfer progress to consensus: {error}")
                        };
                    };
                    if private_oram_transfer_snapshot_recovery_aborts.contains_key(id)
                        || private_oram_transfer_snapshot_recovery_resumes.contains_key(id)
                    {
                        collection
                            .apply_validated_private_oram_transfer_snapshot_recovery_state(
                                state.clone(),
                                self.this_peer_id(),
                                abort_transfer,
                            )
                            .await?;
                    } else if validated_private_oram_resharding.contains(id) {
                        collection
                            .apply_validated_private_oram_resharding_snapshot_state(
                                state.clone(),
                                self.this_peer_id(),
                                abort_transfer,
                            )
                            .await?;
                    } else {
                        collection
                            .apply_state(state.clone(), self.this_peer_id(), abort_transfer)
                            .await?;
                    }
                } else {
                    log::error!("Can't apply state: single node mode");
                }
            }

            // Mark local shards as dead (to initiate shard transfer),
            // if collection has been created during snapshot application
            if !collection_exists
                && !private_oram_transfer_snapshot_recovery_resumes.contains_key(id)
            {
                for shard_id in collection.get_local_shards().await {
                    let shard_holder = collection.shards_holder().read_owned().await;

                    let Some(replica_set) = shard_holder.get_shard(shard_id) else {
                        continue;
                    };

                    if replica_set.is_local().await {
                        replica_set.add_locally_disabled(None, self.this_peer_id, None);
                    }
                }
            }
        }

        // Collect names of collections that are present locally
        let collection_names: Vec<_> = collections.keys().cloned().collect();

        // Drop `collections` lock
        drop(collections);

        // Remove collections that are present locally, but are not in the snapshot state
        for collection_name in &collection_names {
            if !data.collections.contains_key(collection_name) {
                log::debug!(
                    "Deleting collection {collection_name} \
                         because it is not part of the consensus snapshot",
                );

                self.delete_collection_locked(collection_name).await?;
            }
        }

        // Apply alias mapping
        self.alias_persistence
            .write()
            .await
            .apply_state(data.aliases)?;

        Ok(())
    }

    async fn remove_shards_at_peer(&self, peer_id: PeerId) -> Result<(), StorageError> {
        let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        if !self.private_oram_external_recovery_detached.is_empty() {
            return Err(StorageError::Locked {
                description: "peer shard changes are locked by private ORAM recovery installation"
                    .to_string(),
            });
        }
        let collections: Vec<_> = self.collections.read().await.values().cloned().collect();
        for collection in &collections {
            if self
                .private_oram_external_recovery_fence(collection)
                .await?
                .is_some()
            {
                return Err(StorageError::Locked {
                    description:
                        "peer shard changes are locked by private ORAM recovery installation"
                            .to_string(),
                });
            }
        }
        for collection in collections {
            collection.remove_shards_at_peer(peer_id).await?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_shards_at_peer_sync(&self, peer_id: PeerId) -> Result<(), StorageError> {
        self.general_runtime
            .block_on(self.remove_shards_at_peer(peer_id))
    }

    fn on_transfer_failure_callback(
        proposal_sender: Option<OperationSender>,
    ) -> collection::collection::OnTransferFailure {
        Arc::new(move |transfer, collection_name, reason| {
            if let Some(proposal_sender) = &proposal_sender {
                let operation = ConsensusOperations::abort_transfer(
                    collection_name.clone(),
                    transfer.clone(),
                    reason,
                );
                if let Err(send_error) = proposal_sender.send(operation) {
                    log::error!(
                        "Can't send proposal to abort transfer of shard {} of collection {collection_name}. Error: {send_error}",
                        transfer.shard_id,
                    );
                }
            }
        })
    }

    fn on_transfer_success_callback(
        proposal_sender: Option<OperationSender>,
    ) -> collection::collection::OnTransferSuccess {
        Arc::new(move |transfer, collection_name| {
            if let Some(proposal_sender) = &proposal_sender {
                let operation =
                    ConsensusOperations::finish_transfer(collection_name.clone(), transfer.clone());
                if let Err(send_error) = proposal_sender.send(operation) {
                    log::error!(
                        "Can't send proposal to complete transfer of shard {} of collection {collection_name}. Error: {send_error}",
                        transfer.shard_id,
                    );
                }
            }
        })
    }
}
