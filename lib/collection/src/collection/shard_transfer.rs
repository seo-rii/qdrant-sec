use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::defaults;
use data_encoding::BASE64URL_NOPAD;
use fs_err::{OpenOptions, tokio as tokio_fs};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::task::AbortOnDropHandle;

use super::{Collection, collection_encryption_uses_private_oram_bucket_store};
use crate::operations::cluster_ops::ReshardingDirection;
use crate::operations::types::{CollectionError, CollectionResult};
use crate::shards::local_shard::LocalShard;
use crate::shards::replica_set::replica_set_state::ReplicaState;
use crate::shards::resharding::ReshardState;
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::shard_holder::ShardHolder;
use crate::shards::transfer::transfer_tasks_pool::{
    TaskResult, TransferTaskItem, TransferTaskProgress,
};
use crate::shards::transfer::{
    ShardTransfer, ShardTransferConsensus, ShardTransferKey, ShardTransferMethod,
};
use crate::shards::{shard_initializing_flag_path, transfer};

const PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_FILE: &str =
    "private_oram_source_preinstall.json";
const PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_VERSION: u16 = 1;
const PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_MAX_BYTES: u64 = 16 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramFixedTransferPreinstallIntent {
    version: u16,
    transfer: ShardTransfer,
    reservation_lease_id_hash: String,
}

fn invalid_private_oram_fixed_transfer_preinstall_intent() -> CollectionError {
    CollectionError::service_error("private ORAM source preinstall intent is invalid")
}

fn private_oram_fixed_transfer_preinstall_intent_path(collection_path: &Path) -> PathBuf {
    collection_path.join(PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_FILE)
}

fn validate_private_oram_fixed_transfer_preinstall_intent(
    intent: &PrivateOramFixedTransferPreinstallIntent,
) -> CollectionResult<()> {
    if intent.version != PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_VERSION
        || !intent
            .transfer
            .is_private_oram_preinstalled_transfer_for(None)
        || intent.transfer.private_oram_layout_transition.is_none()
    {
        return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
    }
    let reservation_lease_id_hash = BASE64URL_NOPAD
        .decode(intent.reservation_lease_id_hash.as_bytes())
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    if reservation_lease_id_hash.len() != 32
        || BASE64URL_NOPAD.encode(&reservation_lease_id_hash) != intent.reservation_lease_id_hash
    {
        return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
    }
    Ok(())
}

fn read_private_oram_fixed_transfer_preinstall_intent(
    collection_path: &Path,
) -> CollectionResult<Option<PrivateOramFixedTransferPreinstallIntent>> {
    let intent_path = private_oram_fixed_transfer_preinstall_intent_path(collection_path);
    let metadata = match fs_err::symlink_metadata(&intent_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_private_oram_fixed_transfer_preinstall_intent()),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_MAX_BYTES
    {
        return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let file = options
        .open(&intent_path)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    if !opened_metadata.file_type().is_file()
        || opened_metadata.len() != metadata.len()
        || opened_metadata.len() == 0
        || opened_metadata.len() > PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_MAX_BYTES
    {
        return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if opened_metadata.dev() != metadata.dev()
            || opened_metadata.ino() != metadata.ino()
            || opened_metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || opened_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
        }
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    if bytes.len() as u64 != opened_metadata.len()
        || bytes.len() as u64 > PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_MAX_BYTES
    {
        return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
    }
    let intent = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    validate_private_oram_fixed_transfer_preinstall_intent(&intent)?;
    Ok(Some(intent))
}

/// Reads the intent for the paths that only need to know whether one exists (local sync,
/// finish, abort, a new preinstall). An unreadable or invalid file is moved aside and treated
/// as "no intent": the file is only meaningful on the source of one transfer, and a damaged
/// copy must not turn every finish, abort or local sync of the collection into a
/// consensus-stopping error. Callers that consume the reservation lease hash keep the strict
/// reader.
fn read_private_oram_fixed_transfer_preinstall_intent_or_quarantine(
    collection_path: &Path,
) -> Option<PrivateOramFixedTransferPreinstallIntent> {
    match read_private_oram_fixed_transfer_preinstall_intent(collection_path) {
        Ok(intent) => intent,
        Err(error) => {
            let intent_path = private_oram_fixed_transfer_preinstall_intent_path(collection_path);
            let unix_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or_default();
            let quarantine_path = intent_path.with_extension(format!("json.invalid-{unix_secs}"));
            match fs_err::rename(&intent_path, &quarantine_path) {
                Ok(()) => log::warn!(
                    "Quarantined an invalid private ORAM source preinstall intent as {}: {error}",
                    quarantine_path.display(),
                ),
                Err(rename_error) => log::warn!(
                    "Ignoring an invalid private ORAM source preinstall intent that could not be \
                     quarantined ({rename_error}): {error}",
                ),
            }
            None
        }
    }
}

fn write_private_oram_fixed_transfer_preinstall_intent(
    collection_path: &Path,
    transfer: &ShardTransfer,
    reservation_lease_id_hash: &str,
) -> CollectionResult<()> {
    let intent = PrivateOramFixedTransferPreinstallIntent {
        version: PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_VERSION,
        transfer: transfer.clone(),
        reservation_lease_id_hash: reservation_lease_id_hash.to_string(),
    };
    validate_private_oram_fixed_transfer_preinstall_intent(&intent)?;
    if let Some(existing) =
        read_private_oram_fixed_transfer_preinstall_intent_or_quarantine(collection_path)
    {
        if existing.transfer != *transfer {
            return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
        }
        if existing.reservation_lease_id_hash == intent.reservation_lease_id_hash {
            let intent_path = private_oram_fixed_transfer_preinstall_intent_path(collection_path);
            // Windows FlushFileBuffers, used by sync_all, requires write access.
            OpenOptions::new()
                .read(true)
                .write(cfg!(windows))
                .open(&intent_path)
                .and_then(|file| file.sync_all())
                .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
            return common::fs::sync_parent_dir(&intent_path)
                .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent());
        }
    }
    let bytes = serde_json::to_vec(&intent)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    if bytes.is_empty()
        || bytes.len() as u64 > PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_MAX_BYTES
    {
        return Err(invalid_private_oram_fixed_transfer_preinstall_intent());
    }

    let intent_path = private_oram_fixed_transfer_preinstall_intent_path(collection_path);
    common::fs::atomic_save(&intent_path, |writer| writer.write_all(&bytes))
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs_err::set_permissions(&intent_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    }
    // Windows FlushFileBuffers, used by sync_all, requires write access.
    OpenOptions::new()
        .read(true)
        .write(cfg!(windows))
        .open(&intent_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    common::fs::sync_parent_dir(&intent_path)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())
}

fn remove_private_oram_fixed_transfer_preinstall_intent(
    collection_path: &Path,
    transfer: &ShardTransfer,
) -> CollectionResult<()> {
    let Some(existing) =
        read_private_oram_fixed_transfer_preinstall_intent_or_quarantine(collection_path)
    else {
        let intent_path = private_oram_fixed_transfer_preinstall_intent_path(collection_path);
        return common::fs::sync_parent_dir(&intent_path)
            .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent());
    };
    if existing.transfer != *transfer {
        // Another transfer's intent: leave it for the sync that reconciles it with the active
        // transfers instead of failing this transfer's finish or abort.
        log::warn!(
            "Leaving a private ORAM source preinstall intent of a different transfer in place"
        );
        return Ok(());
    }
    let intent_path = private_oram_fixed_transfer_preinstall_intent_path(collection_path);
    fs_err::remove_file(&intent_path)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())?;
    common::fs::sync_parent_dir(&intent_path)
        .map_err(|_| invalid_private_oram_fixed_transfer_preinstall_intent())
}

fn validate_private_oram_transfer_task_start_until_supported(
    _collection_name: &str,
    private_oram_bucket_store_collection: bool,
    transfer: &ShardTransfer,
    resharding: Option<&ReshardState>,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection
        || transfer.is_private_oram_preinstalled_transfer_for(resharding)
    {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot start shard transfer task for private ORAM collections without a verified \
         encrypted ORAM preinstall and consensus-backed epoch/root ownership",
    ))
}

fn validate_private_oram_receiving_preinstall_until_supported(
    _collection_name: &str,
    private_oram_bucket_store_collection: bool,
    private_oram_preinstalled: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection || private_oram_preinstalled {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot start shard transfer task for private ORAM collections without a verified \
         encrypted ORAM preinstall and consensus-backed epoch/root ownership",
    ))
}

impl Collection {
    pub async fn get_related_transfers(&self, current_peer_id: PeerId) -> Vec<ShardTransfer> {
        self.shards_holder.read().await.get_transfers(|transfer| {
            transfer.from == current_peer_id || transfer.to == current_peer_id
        })
    }

    pub async fn check_transfer_exists(&self, transfer_key: &ShardTransferKey) -> bool {
        self.shards_holder
            .read()
            .await
            .check_transfer_exists(transfer_key)
    }

    pub async fn shard_transfer_task_is_missing(&self, transfer_key: &ShardTransferKey) -> bool {
        self.transfer_tasks
            .lock()
            .await
            .get_task_status(transfer_key)
            .is_none()
    }

    pub async fn shard_transfer_task_requires_restart(
        &self,
        transfer_key: &ShardTransferKey,
    ) -> bool {
        self.transfer_tasks
            .lock()
            .await
            .get_task_status(transfer_key)
            .is_none_or(|status| status.result == TaskResult::Failed)
    }

    pub async fn mark_private_oram_fixed_transfer_resume(&self, transfer: &ShardTransfer) -> bool {
        self.private_oram_fixed_transfer_resume_intents
            .lock()
            .await
            .insert(transfer.clone())
    }

    pub async fn clear_private_oram_fixed_transfer_resume(&self, transfer: &ShardTransfer) {
        self.private_oram_fixed_transfer_resume_intents
            .lock()
            .await
            .remove(transfer);
    }

    pub fn private_oram_fixed_transfer_preinstall_intent(
        &self,
    ) -> CollectionResult<Option<ShardTransfer>> {
        Ok(
            read_private_oram_fixed_transfer_preinstall_intent_or_quarantine(&self.path)
                .map(|intent| intent.transfer),
        )
    }

    pub fn persist_private_oram_fixed_transfer_preinstall_intent(
        &self,
        transfer: &ShardTransfer,
        reservation_lease_id_hash: &str,
    ) -> CollectionResult<()> {
        write_private_oram_fixed_transfer_preinstall_intent(
            &self.path,
            transfer,
            reservation_lease_id_hash,
        )
    }

    pub fn clear_private_oram_fixed_transfer_preinstall_intent(
        &self,
        transfer: &ShardTransfer,
    ) -> CollectionResult<()> {
        remove_private_oram_fixed_transfer_preinstall_intent(&self.path, transfer)
    }

    pub fn private_oram_fixed_transfer_preinstall_intent_matches(
        &self,
        transfer: &ShardTransfer,
    ) -> CollectionResult<bool> {
        match self.private_oram_fixed_transfer_preinstall_intent()? {
            None => Ok(false),
            Some(existing) if existing == *transfer => Ok(true),
            Some(_) => Err(invalid_private_oram_fixed_transfer_preinstall_intent()),
        }
    }

    pub fn private_oram_fixed_transfer_preinstall_reservation_lease_id_hash(
        &self,
        transfer: &ShardTransfer,
    ) -> CollectionResult<Option<String>> {
        match read_private_oram_fixed_transfer_preinstall_intent(&self.path)? {
            None => Ok(None),
            Some(intent) if intent.transfer == *transfer => {
                Ok(Some(intent.reservation_lease_id_hash))
            }
            Some(_) => Err(invalid_private_oram_fixed_transfer_preinstall_intent()),
        }
    }

    async fn clear_terminal_private_oram_fixed_transfer_resume(
        &self,
        transfer: &ShardTransfer,
    ) -> CollectionResult<()> {
        if !transfer.is_private_oram_preinstalled_transfer_for(None)
            || transfer.private_oram_layout_transition.is_none()
        {
            return Ok(());
        }
        self.clear_private_oram_fixed_transfer_preinstall_intent(transfer)?;
        self.clear_private_oram_fixed_transfer_resume(transfer)
            .await;
        Ok(())
    }

    pub async fn stop_shard_transfer_task_for_restart(
        &self,
        transfer: &ShardTransfer,
    ) -> CollectionResult<()> {
        self.transfer_tasks
            .lock()
            .await
            .stop_task_if_exact(transfer)
            .await
            .map_err(|()| {
                CollectionError::bad_input(
                    "private ORAM restart transfer task identity changed before fencing",
                )
            })?;
        Ok(())
    }

    async fn is_prevent_unoptimized(&self) -> bool {
        self.effective_optimizers_config()
            .await
            .map(|config| config.prevent_unoptimized.unwrap_or(false))
            .unwrap_or(false)
    }

    pub async fn default_shard_transfer_method(&self) -> ShardTransferMethod {
        if self.is_prevent_unoptimized().await {
            // With prevent_unoptimized, use snapshot as the default method.
            // For automatic transfers, mod.rs prefers WalDelta when all peers
            // support it and falls back to this default otherwise.
            log::info!("Using snapshot transfer method because prevent_unoptimized is enabled");
            ShardTransferMethod::Snapshot
        } else {
            self.shared_storage_config
                .default_shard_transfer_method
                .unwrap_or(ShardTransferMethod::StreamRecords)
        }
    }

    pub async fn start_shard_transfer<T, F>(
        &self,
        mut shard_transfer: ShardTransfer,
        consensus: Box<dyn ShardTransferConsensus>,
        temp_dir: PathBuf,
        on_finish: T,
        on_error: F,
    ) -> CollectionResult<bool>
    where
        T: Future<Output = ()> + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        // Select transfer method
        let default_method = self.default_shard_transfer_method().await;
        if shard_transfer.method.is_none() {
            log::warn!("No shard transfer method selected, defaulting to {default_method:?}");
            shard_transfer.method.replace(default_method);
        }
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        let resharding = self.resharding_state().await;
        validate_private_oram_transfer_task_start_until_supported(
            self.name(),
            private_oram_bucket_store_collection,
            &shard_transfer,
            resharding.as_ref(),
        )?;

        let do_transfer = {
            let this_peer_id = consensus.this_peer_id();
            let is_receiver = this_peer_id == shard_transfer.to;
            let is_sender = this_peer_id == shard_transfer.from;

            // Get the source and target shards, in case of resharding the target shard is different
            let from_shard_id = shard_transfer.shard_id;
            let to_shard_id = shard_transfer
                .to_shard_id
                .unwrap_or(shard_transfer.shard_id);

            let shards_holder = self.shards_holder.read().await;
            let from_replica_set = shards_holder.get_shard(from_shard_id).ok_or_else(|| {
                CollectionError::service_error(format!("Shard {from_shard_id} doesn't exist"))
            })?;
            let to_replica_set = shards_holder.get_shard(to_shard_id).ok_or_else(|| {
                CollectionError::service_error(format!("Shard {to_shard_id} doesn't exist"))
            })?;
            let _was_not_transferred =
                shards_holder.register_start_shard_transfer(shard_transfer.clone())?;

            let from_is_local = from_replica_set.is_local().await;
            let to_is_local = to_replica_set.is_local().await;

            let transfer_method = shard_transfer.method.unwrap_or(default_method);
            let initial_state = match transfer_method {
                ShardTransferMethod::StreamRecords => ReplicaState::Partial,

                ShardTransferMethod::Snapshot | ShardTransferMethod::WalDelta => {
                    ReplicaState::Recovery
                }

                ShardTransferMethod::ReshardingStreamRecords => {
                    let resharding_direction =
                        self.resharding_state().await.map(|state| state.direction);

                    match resharding_direction {
                        Some(ReshardingDirection::Up) => ReplicaState::Resharding,
                        Some(ReshardingDirection::Down) => ReplicaState::ReshardingScaleDown,
                        None => {
                            return Err(CollectionError::bad_input(
                                "can't start resharding transfer, because resharding is not in progress",
                            ));
                        }
                    }
                }
            };

            // Create local shard if it does not exist on receiver, or simply set replica state otherwise
            // (on all peers, regardless if shard is local or remote on that peer).
            //
            // This should disable queries to receiver replica even if it was active before.
            if !to_is_local && is_receiver {
                let effective_optimizers_config = self.effective_optimizers_config().await?;

                let shard = LocalShard::build(
                    to_shard_id,
                    self.name().to_string(),
                    &to_replica_set.shard_path,
                    self.collection_config.clone(),
                    self.shared_storage_config.clone(),
                    self.payload_index_schema.clone(),
                    self.update_runtime.clone(),
                    self.search_runtime.clone(),
                    self.optimizer_resource_budget.clone(),
                    effective_optimizers_config,
                )
                .await?;

                let old_shard = to_replica_set.set_local(shard, Some(initial_state)).await?;
                if let Some(old_shard) = old_shard {
                    debug_assert!(false, "We should not have a local shard yet");
                    old_shard.stop_gracefully().await;
                }
            } else {
                to_replica_set
                    .ensure_replica_with_state(shard_transfer.to, initial_state)
                    .await?;
            }

            from_is_local && is_sender
        };
        if do_transfer {
            self.send_shard(
                shard_transfer,
                consensus,
                temp_dir,
                on_finish,
                on_error,
                false,
            )
            .await?;
        }
        Ok(do_transfer)
    }

    /// Replaces only the source task for an exact fixed-layout private ORAM transfer.
    ///
    /// The registered transfer and the target's `Partial` replica state remain unchanged. This
    /// avoids an abort/start metadata gap while a freshly restored target resumes an active
    /// transfer whose original source task no longer exists.
    pub async fn restart_private_oram_fixed_shard_transfer_task<T, F>(
        &self,
        shard_transfer: ShardTransfer,
        consensus: Box<dyn ShardTransferConsensus>,
        temp_dir: PathBuf,
        on_finish: T,
        on_error: F,
    ) -> CollectionResult<bool>
    where
        T: Future<Output = ()> + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        let resharding = self.resharding_state().await;
        if !private_oram_bucket_store_collection
            || resharding.is_some()
            || !shard_transfer.is_private_oram_preinstalled_transfer_for(None)
        {
            return Err(CollectionError::bad_input(
                "can only replace the source task for an exact preinstalled fixed-layout private ORAM transfer",
            ));
        }

        let do_transfer = {
            let shards_holder = self.shards_holder.read().await;
            let active_transfers = shards_holder.get_transfers(|_| true);
            if active_transfers.as_slice() != [shard_transfer.clone()] {
                return Err(CollectionError::bad_input(
                    "private ORAM source task replacement requires the exact sole active transfer",
                ));
            }

            let source_replica_set = shards_holder
                .get_shard(shard_transfer.shard_id)
                .ok_or_else(|| {
                    CollectionError::service_error(format!(
                        "Shard {} doesn't exist",
                        shard_transfer.shard_id,
                    ))
                })?;
            // An active source is already proxified by the original transfer. It still owns the
            // local shard and must be eligible to spawn the replacement task.
            consensus.this_peer_id() == shard_transfer.from
                && source_replica_set.has_local_shard().await
        };
        if do_transfer {
            self.send_shard(
                shard_transfer,
                consensus,
                temp_dir,
                on_finish,
                on_error,
                true,
            )
            .await?;
        }
        Ok(do_transfer)
    }

    async fn send_shard<OF, OE>(
        &self,
        transfer: ShardTransfer,
        consensus: Box<dyn ShardTransferConsensus>,
        temp_dir: PathBuf,
        on_finish: OF,
        on_error: OE,
        replace_existing: bool,
    ) -> CollectionResult<()>
    where
        OF: Future<Output = ()> + Send + 'static,
        OE: Future<Output = ()> + Send + 'static,
    {
        let mut active_transfer_tasks = self.transfer_tasks.lock().await;
        let task_result = if replace_existing {
            active_transfer_tasks
                .stop_task_if_exact(&transfer)
                .await
                .map_err(|()| {
                    CollectionError::bad_input(
                        "private ORAM replacement transfer task identity changed before apply",
                    )
                })?
        } else {
            active_transfer_tasks.stop_task(&transfer.key()).await
        };

        if !replace_existing {
            debug_assert!(task_result.is_none(), "Transfer task already exists");
        }
        debug_assert!(
            transfer.method.is_some(),
            "When sending shard, a transfer method must have been selected",
        );

        let shard_holder = self.shards_holder.clone();
        let collection_id = self.id.clone();
        let channel_service = self.channel_service.clone();

        let progress = Arc::new(Mutex::new(TransferTaskProgress::new()));

        // With prevent_unoptimized, fall back to snapshot which preserves deferred
        // point state exactly (raw segment copy). stream_records sends deferred
        // points but they won't be deferred on the target.
        let fallback_method = if self.is_prevent_unoptimized().await {
            ShardTransferMethod::Snapshot
        } else {
            ShardTransferMethod::StreamRecords
        };
        let transfer_task = transfer::driver::spawn_transfer_task(
            shard_holder,
            progress.clone(),
            transfer.clone(),
            consensus,
            collection_id,
            channel_service,
            self.snapshots_path.clone(),
            temp_dir,
            fallback_method,
            on_finish,
            on_error,
        );

        active_transfer_tasks.add_task(
            &transfer,
            TransferTaskItem {
                transfer: transfer.clone(),
                task: transfer_task,
                started_at: chrono::Utc::now(),
                progress,
            },
        );
        Ok(())
    }

    /// Handles finishing of the shard transfer.
    ///
    /// Returns true if state was changed, false otherwise.
    pub async fn finish_shard_transfer(
        &self,
        transfer: ShardTransfer,
        shard_holder: Option<&ShardHolder>,
    ) -> CollectionResult<()> {
        let transfer_result = self
            .transfer_tasks
            .lock()
            .await
            .stop_task(&transfer.key())
            .await;

        log::debug!("Transfer result: {transfer_result:?}");

        let mut shard_holder_guard = None;

        let shard_holder = match shard_holder {
            Some(shard_holder) => shard_holder,
            None => shard_holder_guard.insert(self.shards_holder.read().await),
        };

        let is_resharding_transfer = transfer.method.is_some_and(|method| method.is_resharding());

        // Handle *destination* replica
        let mut is_dest_replica_active = false;

        let dest_replica_set =
            shard_holder.get_shard(transfer.to_shard_id.unwrap_or(transfer.shard_id));

        if let Some(replica_set) = dest_replica_set
            && replica_set.peer_state(transfer.to).is_some()
        {
            // Promote *destination* replica/shard to `Active` if:
            //
            // - replica *exists*
            //   - replica should be created when shard transfer (or resharding) is started
            //   - replica might *not* exist, if it (or the whole *peer*) was removed right
            //     before transfer is finished
            // - transfer is *not* resharding
            //   - resharding requires multiple transfers, so destination shard is promoted
            //     *explicitly* when all transfers are finished

            // TODO(resharding): Do not change replica state at all, when finishing resharding transfer?
            //
            // We switch replica into correct state when *starting* resharding transfer, and
            // we want to *keep* it in the same state *after* resharding transfer is finished...
            let state = if is_resharding_transfer {
                let resharding_direction =
                    self.resharding_state().await.map(|state| state.direction);

                match resharding_direction {
                    Some(ReshardingDirection::Up) => ReplicaState::Resharding,
                    Some(ReshardingDirection::Down) => ReplicaState::ReshardingScaleDown,
                    None => {
                        log::error!(
                            "Can't finish resharding shard transfer correctly, \
                                 because resharding is not in progress anymore!",
                        );

                        ReplicaState::Dead
                    }
                }
            } else {
                ReplicaState::Active
            };

            if transfer.to == self.this_peer_id {
                replica_set.set_replica_state(transfer.to, state).await?;
            } else {
                replica_set.add_remote(transfer.to, state).await?;
            }

            is_dest_replica_active = state == ReplicaState::Active;
        }

        // Handle *source* replica
        let src_replica_set = shard_holder.get_shard(transfer.shard_id);

        if let Some(replica_set) = src_replica_set {
            if transfer.sync || is_resharding_transfer {
                // If transfer is *sync* (or *resharding*), we *keep* source replica

                if transfer.from == self.this_peer_id {
                    // If current peer is *transfer-sender*, we need to unproxify local shard

                    replica_set.un_proxify_local().await?;
                }
            } else if is_dest_replica_active {
                // If transfer is *not* sync (and *not* resharding) and *destination* replica is `Active`,
                // we *remove* source replica

                if transfer.from == self.this_peer_id {
                    self.invalidate_clean_local_shards([transfer.shard_id])
                        .await;
                    replica_set.remove_local().await?;
                } else {
                    replica_set.remove_remote(transfer.from).await?;
                }
            }
        }

        let is_finish_registered = shard_holder.register_finish_transfer(&transfer.key())?;
        log::debug!("Transfer finish registered: {is_finish_registered}");
        self.clear_terminal_private_oram_fixed_transfer_resume(&transfer)
            .await?;

        Ok(())
    }

    /// Return if it was a resharding transfer so it can be handled correctly (aborted or ignored)
    pub async fn abort_shard_transfer(
        &self,
        transfer: ShardTransfer,
        shard_holder: &ShardHolder,
    ) -> CollectionResult<()> {
        // TODO: Ensure cancel safety!
        let transfer_key = transfer.key();
        log::debug!("Aborting shard transfer {transfer:?}");

        let _transfer_result = self
            .transfer_tasks
            .lock()
            .await
            .stop_task(&transfer_key)
            .await;

        let is_resharding_transfer = transfer.is_resharding();

        let shard_id = transfer_key.to_shard_id.unwrap_or(transfer_key.shard_id);

        if let Some(replica_set) = shard_holder.get_shard(shard_id) {
            if replica_set.peer_state(transfer.to).is_some() {
                if is_resharding_transfer {
                    // If *resharding* shard transfer failed, we don't need/want to change replica state:
                    // - on transfer failure, the whole resharding would be aborted (see below),
                    //   and so all changes to replicas would be discarded/rolled-back anyway
                    // - during resharding *up*, we transfer points to a single new shard replica;
                    //   it is expected that this node is initially empty/incomplete, and so failed
                    //   transfer should not strictly introduce inconsistency (it just means the node
                    //   is *still* empty/incomplete); marking this new replica as `Dead` would only
                    //   make requests to return explicit errors
                    // - during resharding *down*, we transfer points from shard-to-be-removed
                    //   to all other shards; all other shards are expected to be `Active`,
                    //   and so failed transfer does not introduce any inconsistencies to points
                    //   that are not affected by resharding in all other shards
                } else if transfer.sync {
                    replica_set
                        .set_replica_state(transfer.to, ReplicaState::Dead)
                        .await?;
                } else {
                    self.invalidate_clean_local_shards([transfer
                        .to_shard_id
                        .unwrap_or(transfer.shard_id)])
                        .await;
                    replica_set.remove_peer(transfer.to).await?;
                }
            }
        } else {
            log::warn!(
                "Aborting shard transfer {transfer_key:?}, but shard {shard_id} does not exist"
            );
        }

        if transfer.from == self.this_peer_id {
            transfer::driver::revert_proxy_shard_to_local(shard_holder, transfer.shard_id).await?;
        }

        shard_holder.register_abort_transfer(&transfer_key)?;

        Ok(())
    }

    /// Stops and unregisters a transfer while preserving its active resharding operation.
    ///
    /// Callers must validate that the transfer is immediately replaced by the same exact
    /// resharding transfer. Normal aborts must use `abort_shard_transfer_and_resharding`.
    pub async fn abort_shard_transfer_for_restart(
        &self,
        transfer: ShardTransfer,
    ) -> CollectionResult<()> {
        let shard_holder = self.shards_holder.read().await;
        self.abort_shard_transfer(transfer, &shard_holder).await
    }

    /// Handles abort of the transfer and also aborts resharding if the transfer was related to resharding
    ///
    /// 1. Unregister the transfer
    /// 2. Stop transfer task
    /// 3. Unwrap the proxy
    /// 4. Remove temp shard, or mark it as dead
    pub async fn abort_shard_transfer_and_resharding(
        &self,
        transfer_key: ShardTransferKey,
        shard_holder: Option<&ShardHolder>,
    ) -> CollectionResult<()> {
        let mut shard_holder_guard = None;

        let shard_holder = match shard_holder {
            Some(shard_holder) => shard_holder,
            None => shard_holder_guard.insert(self.shards_holder.read().await),
        };

        let Some(transfer) = shard_holder.get_transfer(&transfer_key) else {
            if let Some(intent_transfer) = self.private_oram_fixed_transfer_preinstall_intent()?
                && intent_transfer.key() == transfer_key
            {
                self.clear_terminal_private_oram_fixed_transfer_resume(&intent_transfer)
                    .await?;
            }
            return Ok(());
        };

        let is_resharding_transfer = transfer.is_resharding();
        self.abort_shard_transfer(transfer.clone(), shard_holder)
            .await?;
        self.clear_terminal_private_oram_fixed_transfer_resume(&transfer)
            .await?;

        if is_resharding_transfer {
            let resharding_state = shard_holder.resharding_state.read().clone();

            // `abort_resharding` locks `shard_holder`!
            drop(shard_holder_guard);

            if let Some(state) = resharding_state {
                self.abort_resharding(state.key(), false).await?;
            }
        }

        Ok(())
    }

    /// Initiate local partial shard
    pub fn initiate_shard_transfer(
        &self,
        shard_id: ShardId,
        private_oram_preinstalled: bool,
    ) -> impl Future<Output = CollectionResult<()>> + 'static {
        // TODO: Ensure cancel safety!

        let shards_holder = self.shards_holder.clone();
        let collection_config = self.collection_config.clone();
        let collection_name = self.name().to_string();

        let collection_path = self.path.clone();

        async move {
            let private_oram_bucket_store_collection = {
                let config = collection_config.read().await;
                config
                    .params
                    .effective_encryption()
                    .as_ref()
                    .is_some_and(collection_encryption_uses_private_oram_bucket_store)
            };
            validate_private_oram_receiving_preinstall_until_supported(
                &collection_name,
                private_oram_bucket_store_collection,
                private_oram_preinstalled,
            )?;

            let shards_holder_guard = shards_holder.clone().read_owned().await;

            let Some(replica_set) = shards_holder_guard.get_shard(shard_id) else {
                return Err(CollectionError::service_error(format!(
                    "Shard {shard_id} doesn't exist, repartition is not supported yet"
                )));
            };

            // Wait for the replica set to have the local shard initialized
            // This can take some time as this is arranged through consensus
            replica_set
                .wait_for_local(defaults::CONSENSUS_META_OP_WAIT)
                .await?;

            let this_peer_id = replica_set.this_peer_id();

            let shard_transfer_requested = tokio::task::spawn_blocking(move || {
                // We can guarantee that replica_set is not None, cause we checked it before
                // and `shards_holder` is holding the lock.
                // This is a workaround for lifetime checker.
                let Some(replica_set) = shards_holder_guard.get_shard(shard_id) else {
                    log::error!("Shard {shard_id} disappeared while waiting for shard transfer");
                    return false;
                };
                let shard_transfer_registered = shards_holder_guard.shard_transfers.wait_for(
                    |shard_transfers| {
                        shard_transfers
                            .iter()
                            .any(|shard_transfer| shard_transfer.is_target(this_peer_id, shard_id))
                    },
                    Duration::from_secs(60),
                );

                // It is not enough to check for shard_transfer_registered,
                // because it is registered before the state of the shard is changed.
                shard_transfer_registered
                    && replica_set.wait_for_state_condition_sync(
                        |state| {
                            state
                                .get_peer_state(this_peer_id)
                                .is_some_and(|peer_state| peer_state.is_partial_or_recovery())
                        },
                        defaults::CONSENSUS_META_OP_WAIT,
                    )
            });

            match AbortOnDropHandle::new(shard_transfer_requested).await {
                Ok(true) => Ok(()),

                Ok(false) => {
                    let description = "\
                        Failed to initiate shard transfer: \
                        Didn't receive shard transfer notification from consensus in 60 seconds";

                    Err(CollectionError::Timeout {
                        description: description.into(),
                    })
                }

                Err(err) => Err(CollectionError::service_error(format!(
                    "Failed to initiate shard transfer: \
                     Failed to execute wait-for-consensus-notification task: \
                     {err}"
                ))),
            }?;

            // At this point we made sure that receiver replica is synced and expecting incoming
            // shard transfer.
            // Further checks are an extra safety net, in normal situation they should not fail.

            let shards_holder_guard = shards_holder.read_owned().await;

            let Some(replica_set) = shards_holder_guard.get_shard(shard_id) else {
                return Err(CollectionError::service_error(format!(
                    "Shard {shard_id} doesn't exist, repartition is not supported yet"
                )));
            };

            if replica_set.is_proxy().await {
                debug_assert!(false, "We should not have proxy shard here");
                // We have proxy or something, we need to unwrap it
                log::error!("Unwrapping proxy shard {shard_id}");
                replica_set.un_proxify_local().await?;
            }

            if replica_set.is_dummy().await {
                // We can reach here because of either of these:
                // 1. Qdrant is in recovery mode, and user intentionally triggered a transfer
                // 2. Shard is dirty (shard initializing flag), and Qdrant triggered a transfer to recover from Dead state after an update fails
                //
                // In both cases, it's safe to drop existing local shard data
                log::debug!(
                    "Initiating transfer to dummy shard {}. Initializing empty local shard first",
                    replica_set.shard_id,
                );
                replica_set.init_empty_local_shard().await?;

                let shard_flag = shard_initializing_flag_path(&collection_path, shard_id);

                if tokio_fs::try_exists(&shard_flag).await.is_ok() {
                    // We can delete initializing flag without waiting for transfer to finish
                    // because if transfer fails in between, Qdrant will retry it.
                    tokio_fs::remove_file(&shard_flag).await?;
                    log::debug!("Removed shard initializing flag {shard_flag:?}");
                }
            }

            Ok(())
        }
    }

    /// Whether we have reached the automatic shard transfer limit based on the given incoming and
    /// outgoing transfers.
    pub(super) fn check_auto_shard_transfer_limit(&self, incoming: usize, outgoing: usize) -> bool {
        let incoming_shard_transfer_limit_reached = self
            .shared_storage_config
            .incoming_shard_transfers_limit
            .is_some_and(|limit| incoming >= limit);

        let outgoing_shard_transfer_limit_reached = self
            .shared_storage_config
            .outgoing_shard_transfers_limit
            .is_some_and(|limit| outgoing >= limit);

        incoming_shard_transfer_limit_reached || outgoing_shard_transfer_limit_reached
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shards::transfer::{
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition,
    };

    fn private_oram_fixed_transfer() -> ShardTransfer {
        ShardTransfer {
            shard_id: 7,
            to_shard_id: None,
            from: 11,
            to: 22,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: "private-source-intent-collection".to_string(),
                expected: PrivateOramTransferLayoutState {
                    generation: 7,
                    owner_peer_ids: vec![11],
                    layout_digest: "private-source-intent-old-layout".to_string(),
                    index_state_digest: "private-source-intent-index-state".to_string(),
                },
                new: PrivateOramTransferLayoutState {
                    generation: 8,
                    owner_peer_ids: vec![11, 22],
                    layout_digest: "private-source-intent-new-layout".to_string(),
                    index_state_digest: "private-source-intent-index-state".to_string(),
                },
                index_states: Vec::new(),
            }),
            filter: None,
        }
    }

    #[test]
    fn private_oram_fixed_transfer_preinstall_intent_is_exact_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let transfer = private_oram_fixed_transfer();
        let first_lease_id_hash = BASE64URL_NOPAD.encode(&[23; 32]);
        let second_lease_id_hash = BASE64URL_NOPAD.encode(&[24; 32]);
        write_private_oram_fixed_transfer_preinstall_intent(
            dir.path(),
            &transfer,
            &first_lease_id_hash,
        )
        .unwrap();
        write_private_oram_fixed_transfer_preinstall_intent(
            dir.path(),
            &transfer,
            &first_lease_id_hash,
        )
        .unwrap();
        let intent = read_private_oram_fixed_transfer_preinstall_intent(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(intent.transfer, transfer);
        assert_eq!(intent.reservation_lease_id_hash, first_lease_id_hash);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs_err::metadata(private_oram_fixed_transfer_preinstall_intent_path(
                dir.path(),
            ))
            .unwrap()
            .permissions()
            .mode();
            assert_eq!(mode & 0o077, 0);
        }

        let different_target = ShardTransfer {
            to: 33,
            ..transfer.clone()
        };
        let mut different_generation = transfer.clone();
        let transition = different_generation
            .private_oram_layout_transition
            .as_mut()
            .unwrap();
        transition.expected.generation += 1;
        transition.new.generation += 1;
        assert_eq!(different_generation.key(), transfer.key());

        for different in [different_target, different_generation] {
            // Each candidate is valid on its own, but cannot replace this exact intent.
            validate_private_oram_fixed_transfer_preinstall_intent(
                &PrivateOramFixedTransferPreinstallIntent {
                    version: PRIVATE_ORAM_FIXED_TRANSFER_PREINSTALL_INTENT_VERSION,
                    transfer: different.clone(),
                    reservation_lease_id_hash: second_lease_id_hash.clone(),
                },
            )
            .unwrap();
            let error = write_private_oram_fixed_transfer_preinstall_intent(
                dir.path(),
                &different,
                &second_lease_id_hash,
            )
            .unwrap_err();
            let rendered = format!("{error:?}");
            assert!(rendered.contains("source preinstall intent is invalid"));
            assert!(!rendered.contains("private-source-intent"));

            // A stale finish or abort must not fail consensus or remove another intent.
            remove_private_oram_fixed_transfer_preinstall_intent(dir.path(), &different).unwrap();
            let intent = read_private_oram_fixed_transfer_preinstall_intent(dir.path())
                .unwrap()
                .unwrap();
            assert_eq!(intent.transfer, transfer);
            assert_eq!(intent.reservation_lease_id_hash, first_lease_id_hash);
        }

        write_private_oram_fixed_transfer_preinstall_intent(
            dir.path(),
            &transfer,
            &second_lease_id_hash,
        )
        .unwrap();
        let intent = read_private_oram_fixed_transfer_preinstall_intent(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(intent.transfer, transfer);
        assert_eq!(intent.reservation_lease_id_hash, second_lease_id_hash);

        remove_private_oram_fixed_transfer_preinstall_intent(dir.path(), &transfer).unwrap();
        assert!(
            read_private_oram_fixed_transfer_preinstall_intent(dir.path())
                .unwrap()
                .is_none()
        );
        remove_private_oram_fixed_transfer_preinstall_intent(dir.path(), &transfer).unwrap();
    }

    #[test]
    fn private_oram_fixed_transfer_preinstall_intent_rejects_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        let intent_path = private_oram_fixed_transfer_preinstall_intent_path(dir.path());
        fs_err::write(
            &intent_path,
            br#"{"version":1,"transfer":{},"unexpected":true}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs_err::set_permissions(&intent_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = read_private_oram_fixed_transfer_preinstall_intent(dir.path()).unwrap_err();
        let rendered = format!("{error:?}");
        assert!(rendered.contains("source preinstall intent is invalid"));
        assert!(!rendered.contains(dir.path().to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn private_oram_fixed_transfer_preinstall_intent_rejects_unsafe_file() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::tempdir().unwrap();
        let transfer = private_oram_fixed_transfer();
        let intent_path = private_oram_fixed_transfer_preinstall_intent_path(dir.path());
        write_private_oram_fixed_transfer_preinstall_intent(
            dir.path(),
            &transfer,
            &BASE64URL_NOPAD.encode(&[23; 32]),
        )
        .unwrap();
        fs_err::set_permissions(&intent_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        read_private_oram_fixed_transfer_preinstall_intent(dir.path()).unwrap_err();

        fs_err::remove_file(&intent_path).unwrap();
        let outside = dir.path().join("outside-private-intent-sentinel");
        fs_err::write(&outside, b"private intent sentinel").unwrap();
        symlink(&outside, &intent_path).unwrap();
        let error = read_private_oram_fixed_transfer_preinstall_intent(dir.path()).unwrap_err();
        let rendered = format!("{error:?}");
        assert!(rendered.contains("source preinstall intent is invalid"));
        assert!(!rendered.contains("outside-private-intent-sentinel"));
    }

    #[test]
    fn private_oram_fixed_transfer_preinstall_intent_rejects_invalid_lease_hash() {
        let dir = tempfile::tempdir().unwrap();
        let error = write_private_oram_fixed_transfer_preinstall_intent(
            dir.path(),
            &private_oram_fixed_transfer(),
            "not-a-private-oram-lease-hash",
        )
        .unwrap_err();
        assert!(format!("{error:?}").contains("source preinstall intent is invalid"));
        assert!(
            read_private_oram_fixed_transfer_preinstall_intent(dir.path())
                .unwrap()
                .is_none()
        );
    }

    const PRIVATE_ORAM_TRANSFER_COLLECTION_NAMES: &[&str] = &[
        "clientStateCiphertext.json",
        "clientStateSnapshot.json",
        "clientStateSnapshots.json",
        "client_state_snapshot.bin",
        "client_state_snapshots.bin",
        "client.state.snapshots.bin",
        "clientStateCiphertextHash.json",
        "clientStateCiphertextHashes.json",
        "clientStateCiphertextSha256.json",
        "clientStateCiphertextsSha256.json",
        "client_state_ciphertext_hash.bin",
        "client_state_ciphertext_hash.json",
        "client_state_ciphertext_hashes.bin",
        "client_state_ciphertext_hashes.json",
        "client_state_ciphertext_sha256.bin",
        "client_state_ciphertext_sha256.json",
        "client_state_ciphertexts_sha256.bin",
        "client_state_ciphertexts_sha256.json",
        "encryptedClientStateCiphertext.json",
        "encryptedClientStateCiphertextHash.json",
        "encryptedClientStateCiphertextHashes.json",
        "encryptedClientStateCiphertextSha256.json",
        "encryptedClientStateCiphertextsSha256.json",
        "encrypted_client_state_ciphertext_hash.bin",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes.bin",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256.bin",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256.bin",
        "encrypted_client_state_ciphertexts_sha256.json",
        "encrypted_client_state.bin",
        "encrypted_client_state_backup.bin",
        "encrypted_client_state_backups.bin",
        "encrypted.client.state",
        "encrypted.client.state.bin",
        "encrypted.client.state.snapshot",
        "encrypted.client.state.snapshot.bin",
        "encryptedClientStateSnapshot.json",
        "encryptedClientStateSnapshots.json",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshots.bin",
        "encrypted.client.state.snapshots.bin",
        "stateCiphertext.json",
        "stateCiphertextHash.json",
        "stateCiphertextHashes.json",
        "stateCiphertextSha256.json",
        "stateCiphertextsSha256.json",
        "state_ciphertext_hash.bin",
        "state_ciphertext_hash.json",
        "state_ciphertext_hashes.bin",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256.bin",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256.bin",
        "state_ciphertexts_sha256.json",
        "ciphertextSha256.json",
        "ciphertextsSha256.json",
        "ciphertext_sha256.bin",
        "ciphertexts_sha256.bin",
        "bucketCommitment.json",
        "bucketCommitments.json",
        "bucket_commitment.bin",
        "bucket_commitments.bin",
        "updatedBucketCommitment.json",
        "updatedBucketCommitments.json",
        "updated_bucket_commitment.bin",
        "updated_bucket_commitments.bin",
        "state_ciphertext.bin",
        "clientState.json",
        "clientStates.json",
        "client_state.bin",
        "client_states.bin",
        "clientStateBackup.json",
        "clientStateBackups.json",
        "client_state_backup.bin",
        "client_state_backups.bin",
        "encryptedClientState.json",
        "encryptedClientStates.json",
        "encrypted_client_states.bin",
        "encryptedClientStateBackup.json",
        "encryptedClientStateBackups.json",
        "tokenMapBackup.json",
        "tokenMapBackups.json",
        "token_map_backup.json",
        "token_map_backups.json",
        "token.map.backup",
        "token.map.backup.json",
        "token.map.backups",
        "token.map.backups.json",
        "tokenPositionMapBackup.json",
        "tokenPositionMapBackups.json",
        "token_position_map_backup.json",
        "token.position.map.backup",
        "token.position.map.backup.json",
        "token.position.map.backups",
        "token.position.map.backups.json",
        "accessVolume.json",
        "accessVolumes.json",
        "access_volume.json",
        "access_volumes.json",
        "oramPositionMapBackup.json",
        "oramPositionMapBackups.json",
        "oram_position_map_backup.json",
        "positionMapBackup.json",
        "positionMapBackups.json",
        "position_map_backup.json",
        "stashBackup.json",
        "stashBackups.json",
        "stash_backup.json",
    ];

    const PRIVATE_ORAM_TRANSFER_REDACTION_STEMS: &[&str] = &[
        "clientState",
        "clientStates",
        "client_state",
        "client_states",
        "clientStateBackup",
        "clientStateBackups",
        "client_state_backup",
        "client_state_backups",
        "clientStateCiphertext",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client_state_snapshot",
        "client_state_snapshots",
        "client.state.snapshots",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
        "client_state_ciphertext_hashes",
        "client_state_ciphertext_sha256",
        "client_state_ciphertexts_sha256",
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state",
        "encrypted_client_states",
        "encryptedClientState",
        "encryptedClientStates",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encrypted_client_state_backup",
        "encrypted_client_state_backups",
        "encrypted.client.state",
        "encrypted.client.state.snapshot",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshots",
        "encrypted.client.state.snapshots",
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
        "ciphertextSha256",
        "ciphertextsSha256",
        "ciphertext_sha256",
        "ciphertexts_sha256",
        "bucketCommitment",
        "bucketCommitments",
        "bucket_commitment",
        "bucket_commitments",
        "updatedBucketCommitment",
        "updatedBucketCommitments",
        "updated_bucket_commitment",
        "updated_bucket_commitments",
        "tokenMapBackup",
        "tokenMapBackups",
        "token_map_backup",
        "token_map_backups",
        "token.map.backup",
        "token.map.backups",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token_position_map_backup",
        "token.position.map.backup",
        "token.position.map.backups",
        "accessVolume",
        "accessVolumes",
        "access_volume",
        "access_volumes",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "oram_position_map_backup",
        "positionMapBackup",
        "positionMapBackups",
        "position_map_backup",
        "stashBackup",
        "stashBackups",
        "stash_backup",
    ];

    #[test]
    fn private_oram_transfer_task_start_fails_closed_until_bucket_transfer_supported() {
        let mut transfer = ShardTransfer {
            shard_id: 7,
            to_shard_id: None,
            from: 11,
            to: 22,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: false,
            private_oram_layout_transition: None,
            filter: None,
        };
        for collection_name in PRIVATE_ORAM_TRANSFER_COLLECTION_NAMES {
            validate_private_oram_transfer_task_start_until_supported(
                collection_name,
                false,
                &transfer,
                None,
            )
            .unwrap();

            let err = validate_private_oram_transfer_task_start_until_supported(
                collection_name,
                true,
                &transfer,
                None,
            )
            .unwrap_err();
            let rendered = format!("{err:?}");
            assert!(rendered.contains("private ORAM collections"));
            assert!(rendered.contains("encrypted ORAM preinstall"));
            assert!(rendered.contains("consensus-backed epoch/root"));
            assert!(!rendered.contains(collection_name));
            for &leaked_alias in PRIVATE_ORAM_TRANSFER_REDACTION_STEMS {
                assert!(!rendered.contains(leaked_alias), "{rendered}");
            }
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));

            transfer.private_oram_preinstalled = true;
            validate_private_oram_transfer_task_start_until_supported(
                collection_name,
                true,
                &transfer,
                None,
            )
            .expect("verified private ORAM preinstall must allow transfer task startup");
            validate_private_oram_receiving_preinstall_until_supported(collection_name, true, true)
                .expect("verified private ORAM preinstall must allow receiver initialization");
            transfer.private_oram_preinstalled = false;
        }

        let resharding = ReshardState::new(uuid::Uuid::nil(), ReshardingDirection::Up, 22, 9, None);
        let resharding_transfer = ShardTransfer {
            shard_id: 7,
            to_shard_id: Some(9),
            from: 11,
            to: 22,
            sync: true,
            method: Some(ShardTransferMethod::ReshardingStreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        };
        validate_private_oram_transfer_task_start_until_supported(
            "docs",
            true,
            &resharding_transfer,
            Some(&resharding),
        )
        .expect("exact marked private ORAM resharding transfer must start");
        validate_private_oram_transfer_task_start_until_supported(
            "docs",
            true,
            &resharding_transfer,
            None,
        )
        .expect_err("private ORAM resharding transfer requires active matching state");
    }
}
