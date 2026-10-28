pub mod ckks_search;
mod clean;
mod collection_ops;
pub mod distance_matrix;
mod facet;
pub mod mmr;
pub mod payload_index_schema;
mod point_ops;
pub mod query;
mod resharding;
mod search;
mod shard_transfer;
mod sharding_keys;
mod snapshots;
mod state_management;
mod telemetry;

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use api::grpc::qdrant::{
    PrivateOramActiveTransferResumeContext, RequestPrivateOramReshardingResumeRequest,
    RequestPrivateOramShardRecoveryRequest,
};
use clean::ShardCleanTasks;
use common::budget::ResourceBudget;
use common::save_on_disk::SaveOnDisk;
use common::storage_version::StorageVersion;
use segment::types::{SeqNumberType, ShardKey};
use semver::Version;
use shard::operations::optimization::{OptimizationsRequestOptions, OptimizationsResponse};
pub use snapshots::PreparedCollectionSnapshot;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, RwLock};

use crate::collection::collection_ops::ABORT_TRANSFERS_ON_SHARD_DROP_FIX_FROM_VERSION;
use crate::collection::payload_index_schema::PayloadIndexSchema;
use crate::collection_state::{ShardInfo, State};
use crate::common::collection_size_stats::{
    CollectionSizeAtomicStats, CollectionSizeStats, CollectionSizeStatsCache,
};
use crate::common::is_ready::IsReady;
use crate::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, EncryptionSelector, ShardingMethod,
};
use crate::operations::OperationWithClockTag;
use crate::operations::cluster_ops::ReshardingDirection;
use crate::operations::config_diff::{DiffConfig, OptimizersConfigDiff};
use crate::operations::shared_storage_config::SharedStorageConfig;
use crate::operations::types::{
    CollectionError, CollectionResult, NodeType, OptimizersStatus, PeerMetadata,
};
use crate::optimizers_builder::OptimizersConfig;
use crate::shards::channel_service::ChannelService;
use crate::shards::collection_shard_distribution::CollectionShardDistribution;
use crate::shards::local_shard::clock_map::RecoveryPoint;
use crate::shards::replica_set::replica_set_state::ReplicaState;
use crate::shards::replica_set::replica_set_state::ReplicaState::{
    Active, Dead, Initializing, Listener,
};
use crate::shards::replica_set::{ChangePeerFromState, ChangePeerState, ShardReplicaSet};
use crate::shards::resharding::{ReshardState, ReshardingStage};
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::shard_holder::shard_mapping::ShardKeyMapping;
use crate::shards::shard_holder::{ShardHolder, SharedShardHolder, shard_not_found_error};
use crate::shards::transfer::helpers::check_transfer_conflicts_strict;
use crate::shards::transfer::transfer_tasks_pool::{TaskResult, TransferTasksPool};
use crate::shards::transfer::{ShardTransfer, ShardTransferKey, ShardTransferMethod};
use crate::shards::{CollectionId, replica_set};
use crate::telemetry::CollectionsAggregatedTelemetry;

const CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_CAPACITY: usize = 1_000_000;
const CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE: &str = "client_payload_nonce_replay.cache";
const CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_ENTRY_MAX_BYTES: usize = 512;
const CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_MAX_BYTES: u64 = CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_CAPACITY
    as u64
    * (CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_ENTRY_MAX_BYTES as u64 + 1);
const PRIVATE_ORAM_RESHARDING_RESUME_REQUEST_INTERVAL: Duration = Duration::from_secs(5);
const PRIVATE_ORAM_SOURCE_RESUME_REQUEST_INTERVAL: Duration = Duration::from_secs(5);

/// Collection's data is split into several shards.
pub struct Collection {
    pub(crate) id: CollectionId,
    pub(crate) shards_holder: SharedShardHolder,
    pub(crate) collection_config: Arc<RwLock<CollectionConfigInternal>>,
    pub(crate) shared_storage_config: Arc<SharedStorageConfig>,
    payload_index_schema: Arc<SaveOnDisk<PayloadIndexSchema>>,
    optimizers_overwrite: Option<OptimizersConfigDiff>,
    this_peer_id: PeerId,
    path: PathBuf,
    snapshots_path: PathBuf,
    channel_service: ChannelService,
    transfer_tasks: Mutex<TransferTasksPool>,
    request_shard_transfer_cb: RequestShardTransfer,
    notify_peer_failure_cb: ChangePeerFromState,
    abort_shard_transfer_cb: replica_set::AbortShardTransfer,
    init_time: Duration,
    // One-way boolean flag that is set to true when the collection is fully initialized
    // i.e. all shards are activated for the first time.
    is_initialized: Arc<IsReady>,
    // Update runtime handle.
    update_runtime: Handle,
    // Search runtime handle.
    search_runtime: Handle,
    optimizer_resource_budget: ResourceBudget,
    // Cached statistics of collection size, may be outdated.
    collection_stats_cache: CollectionSizeStatsCache,
    client_payload_nonce_replay_cache: Mutex<ClientPayloadNonceReplayCache>,
    crypto_payload_migration_lock: Mutex<()>,
    private_oram_automatic_recovery_tasks: Arc<Mutex<HashSet<ShardId>>>,
    private_oram_resharding_resume_requests: Arc<Mutex<HashSet<ShardTransferKey>>>,
    private_oram_fixed_transfer_resume_intents: Arc<Mutex<HashSet<ShardTransfer>>>,
    private_oram_source_resume_requests: Arc<Mutex<HashSet<ShardTransferKey>>>,
    // Background tasks to clean shards
    shard_clean_tasks: ShardCleanTasks,
}

#[derive(Debug)]
struct ClientPayloadNonceReplayCache {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl Default for ClientPayloadNonceReplayCache {
    fn default() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_CAPACITY,
        }
    }
}

impl ClientPayloadNonceReplayCache {
    fn load(path: &Path) -> CollectionResult<Self> {
        let cache_path = path.join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        validate_client_payload_nonce_replay_cache_parent(&cache_path)?;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut options = OpenOptions::new();
            options.read(true);
            options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
            match options.open(&cache_path) {
                Ok(file) => {
                    let metadata = file.metadata().map_err(|err| {
                        CollectionError::service_error(format!(
                            "failed to inspect client payload nonce replay cache: {err}",
                        ))
                    })?;
                    if !metadata.is_file() {
                        return Err(CollectionError::service_error(
                            "client payload nonce replay cache must be a regular file",
                        ));
                    }
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err(CollectionError::service_error(
                            "client payload nonce replay cache must not be group/world accessible",
                        ));
                    }
                    if metadata.len() > CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_MAX_BYTES {
                        return Err(CollectionError::service_error(
                            "client payload nonce replay cache exceeds maximum size",
                        ));
                    }
                    file
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Self::default());
                }
                Err(err) => {
                    return Err(CollectionError::service_error(format!(
                        "failed to open client payload nonce replay cache: {err}",
                    )));
                }
            }
        };
        #[cfg(not(unix))]
        let file = match std::fs::File::open(&cache_path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(CollectionError::service_error(format!(
                    "failed to open client payload nonce replay cache: {err}",
                )));
            }
        };
        #[cfg(not(unix))]
        {
            let metadata = file.metadata().map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to inspect client payload nonce replay cache: {err}",
                ))
            })?;
            if metadata.len() > CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_MAX_BYTES {
                return Err(CollectionError::service_error(
                    "client payload nonce replay cache exceeds maximum size",
                ));
            }
        }

        let mut cache = Self::default();
        for line in BufReader::new(file).lines() {
            let key = line.map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to read client payload nonce replay cache: {err}",
                ))
            })?;
            if !key.is_empty() {
                if key.len() > CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_ENTRY_MAX_BYTES {
                    return Err(CollectionError::service_error(
                        "client payload nonce replay cache contains oversized entry",
                    ));
                }
                qdrant_sec::ClientPayloadNonceReplayKey::validate_cache_key_for_collection(&key)
                    .map_err(|err| {
                        CollectionError::service_error(format!(
                            "client payload nonce replay cache contains malformed entry: {err}",
                        ))
                    })?;
                cache.insert_loaded(key);
            }
        }

        Ok(cache)
    }

    fn pending_keys(
        &self,
        keys: impl IntoIterator<Item = String>,
    ) -> CollectionResult<Option<Vec<String>>> {
        let mut batch_seen = HashSet::new();
        let mut pending = Vec::new();

        for key in keys {
            qdrant_sec::ClientPayloadNonceReplayKey::validate_cache_key_for_collection(&key)
                .map_err(|_| {
                    CollectionError::bad_input(
                        "client encrypted payload nonce replay cache key is invalid",
                    )
                })?;
            if self.seen.contains(&key) || !batch_seen.insert(key.clone()) {
                return Ok(None);
            }
            pending.push(key);
        }

        Ok(Some(pending))
    }

    fn insert_pending(&mut self, pending: Vec<String>) -> bool {
        for key in pending {
            if self.seen.insert(key.clone()) {
                self.order.push_back(key);
            }
        }

        self.evict_oldest()
    }

    fn insert_loaded(&mut self, key: String) {
        if self.seen.insert(key.clone()) {
            self.order.push_back(key);
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let mut evicted = false;
        while self.seen.len() > self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.seen.remove(&oldest);
            evicted = true;
        }

        evicted
    }
}

pub type RequestShardTransfer = Arc<dyn Fn(ShardTransfer) + Send + Sync>;

pub type OnTransferFailure = Arc<dyn Fn(ShardTransfer, CollectionId, &str) + Send + Sync>;
pub type OnTransferSuccess = Arc<dyn Fn(ShardTransfer, CollectionId) + Send + Sync>;

impl Collection {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        name: CollectionId,
        this_peer_id: PeerId,
        path: &Path,
        snapshots_path: &Path,
        collection_config: &CollectionConfigInternal,
        shared_storage_config: Arc<SharedStorageConfig>,
        shard_distribution: CollectionShardDistribution,
        shard_key_mapping: Option<ShardKeyMapping>,
        channel_service: ChannelService,
        on_replica_failure: ChangePeerFromState,
        request_shard_transfer: RequestShardTransfer,
        abort_shard_transfer: replica_set::AbortShardTransfer,
        search_runtime: Option<Handle>,
        update_runtime: Option<Handle>,
        optimizer_resource_budget: ResourceBudget,
        optimizers_overwrite: Option<OptimizersConfigDiff>,
    ) -> CollectionResult<Self> {
        let start_time = std::time::Instant::now();

        let sharding_method = collection_config.params.sharding_method.unwrap_or_default();
        let mut shard_holder = ShardHolder::new(path, sharding_method)?;
        shard_holder.set_shard_key_mappings(shard_key_mapping.clone().unwrap_or_default())?;

        let payload_index_schema = Arc::new(Self::load_payload_index_schema(
            path,
            &collection_config.params,
        )?);

        let shared_collection_config = Arc::new(RwLock::new(collection_config.clone()));
        for (shard_id, mut peers) in shard_distribution.shards {
            let is_local = peers.remove(&this_peer_id);

            let mut effective_optimizers_config = collection_config.optimizer_config.clone();
            if let Some(optimizers_overwrite) = optimizers_overwrite.clone() {
                effective_optimizers_config =
                    effective_optimizers_config.update(&optimizers_overwrite);
            }

            let shard_key = shard_key_mapping
                .as_ref()
                .and_then(|mapping| mapping.shard_key(shard_id));
            let replica_set = ShardReplicaSet::build(
                shard_id,
                shard_key.clone(),
                name.clone(),
                this_peer_id,
                is_local,
                peers,
                on_replica_failure.clone(),
                abort_shard_transfer.clone(),
                path,
                shared_collection_config.clone(),
                effective_optimizers_config,
                shared_storage_config.clone(),
                payload_index_schema.clone(),
                channel_service.clone(),
                update_runtime.clone().unwrap_or_else(Handle::current),
                search_runtime.clone().unwrap_or_else(Handle::current),
                optimizer_resource_budget.clone(),
                None,
            )
            .await?;

            shard_holder
                .add_shard(shard_id, replica_set, shard_key)
                .await?;
        }

        let shared_shard_holder = SharedShardHolder::new(shard_holder);

        let collection_stats_cache = CollectionSizeStatsCache::new_with_values(
            Self::estimate_collection_size_stats(&shared_shard_holder).await?,
        );

        // Once the config is persisted - the collection is considered to be successfully created.
        CollectionVersion::save(path)?;
        collection_config.save(path)?;

        Ok(Self {
            id: name.clone(),
            shards_holder: shared_shard_holder,
            collection_config: shared_collection_config,
            optimizers_overwrite,
            payload_index_schema,
            shared_storage_config,
            this_peer_id,
            path: path.to_owned(),
            snapshots_path: snapshots_path.to_owned(),
            channel_service,
            transfer_tasks: Mutex::new(TransferTasksPool::new(name.clone())),
            request_shard_transfer_cb: request_shard_transfer.clone(),
            notify_peer_failure_cb: on_replica_failure.clone(),
            abort_shard_transfer_cb: abort_shard_transfer,
            init_time: start_time.elapsed(),
            is_initialized: Default::default(),
            update_runtime: update_runtime.unwrap_or_else(Handle::current),
            search_runtime: search_runtime.unwrap_or_else(Handle::current),
            optimizer_resource_budget,
            collection_stats_cache,
            client_payload_nonce_replay_cache: Mutex::new(ClientPayloadNonceReplayCache::default()),
            crypto_payload_migration_lock: Mutex::new(()),
            private_oram_automatic_recovery_tasks: Default::default(),
            private_oram_resharding_resume_requests: Default::default(),
            private_oram_fixed_transfer_resume_intents: Default::default(),
            private_oram_source_resume_requests: Default::default(),
            shard_clean_tasks: Default::default(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn load(
        collection_id: CollectionId,
        this_peer_id: PeerId,
        path: &Path,
        snapshots_path: &Path,
        shared_storage_config: Arc<SharedStorageConfig>,
        channel_service: ChannelService,
        on_replica_failure: replica_set::ChangePeerFromState,
        request_shard_transfer: RequestShardTransfer,
        abort_shard_transfer: replica_set::AbortShardTransfer,
        search_runtime: Option<Handle>,
        update_runtime: Option<Handle>,
        optimizer_resource_budget: ResourceBudget,
        optimizers_overwrite: Option<OptimizersConfigDiff>,
    ) -> CollectionResult<Self> {
        let start_time = std::time::Instant::now();
        let stored_version = CollectionVersion::load(path)?.ok_or_else(|| {
            CollectionError::service_error(format!(
                "Collection version is not found at {}",
                path.display()
            ))
        })?;

        let app_version = CollectionVersion::current();

        if stored_version > app_version {
            return Err(CollectionError::service_error(format!(
                "Collection version {stored_version} is greater than application version {app_version}",
            )));
        }

        if stored_version != app_version {
            if Self::can_upgrade_storage(&stored_version, &app_version) {
                log::info!("Migrating collection {stored_version} -> {app_version}");
                CollectionVersion::save(path)?;
            } else {
                log::error!("Cannot upgrade version {stored_version} to {app_version}.");
                return Err(CollectionError::service_error(format!(
                    "Cannot upgrade version {stored_version} to {app_version}. Try to use older version of Qdrant first.",
                )));
            }
        }

        let collection_config = CollectionConfigInternal::load(path)?;
        collection_config.validate_and_warn();
        collection_config.validate_startup_crypto_state()?;

        let sharding_method = collection_config.params.sharding_method.unwrap_or_default();
        let mut shard_holder = ShardHolder::new(path, sharding_method)?;

        let mut effective_optimizers_config = collection_config.optimizer_config.clone();

        if let Some(optimizers_overwrite) = optimizers_overwrite.clone() {
            effective_optimizers_config = effective_optimizers_config.update(&optimizers_overwrite);
        }

        let has_client_envelope_rules = collection_config
            .params
            .effective_encryption()
            .is_some_and(|encryption| {
                encryption.rules.iter().any(|rule| {
                    matches!(&rule.selector, EncryptionSelector::PayloadPaths { .. })
                        && rule.binding.as_deref()
                            == Some(qdrant_sec::CLIENT_PAYLOAD_ENVELOPE_BINDING)
                })
            });
        let shared_collection_config = Arc::new(RwLock::new(collection_config.clone()));

        let payload_index_schema = Arc::new(Self::load_payload_index_schema(
            path,
            &collection_config.params,
        )?);

        shard_holder
            .load_shards(
                path,
                &collection_id,
                shared_collection_config.clone(),
                effective_optimizers_config,
                shared_storage_config.clone(),
                payload_index_schema.clone(),
                channel_service.clone(),
                on_replica_failure.clone(),
                abort_shard_transfer.clone(),
                this_peer_id,
                update_runtime.clone().unwrap_or_else(Handle::current),
                search_runtime.clone().unwrap_or_else(Handle::current),
                optimizer_resource_budget.clone(),
            )
            .await?;

        let shared_shard_holder = SharedShardHolder::new(shard_holder);

        let collection_stats_cache = CollectionSizeStatsCache::new_with_values(
            Self::estimate_collection_size_stats(&shared_shard_holder).await?,
        );

        let collection = Self {
            id: collection_id.clone(),
            shards_holder: shared_shard_holder,
            collection_config: shared_collection_config,
            optimizers_overwrite,
            payload_index_schema,
            shared_storage_config,
            this_peer_id,
            path: path.to_owned(),
            snapshots_path: snapshots_path.to_owned(),
            channel_service,
            transfer_tasks: Mutex::new(TransferTasksPool::new(collection_id.clone())),
            request_shard_transfer_cb: request_shard_transfer.clone(),
            notify_peer_failure_cb: on_replica_failure,
            abort_shard_transfer_cb: abort_shard_transfer,
            init_time: start_time.elapsed(),
            is_initialized: Default::default(),
            update_runtime: update_runtime.unwrap_or_else(Handle::current),
            search_runtime: search_runtime.unwrap_or_else(Handle::current),
            optimizer_resource_budget,
            collection_stats_cache,
            client_payload_nonce_replay_cache: Mutex::new(if has_client_envelope_rules {
                ClientPayloadNonceReplayCache::load(path)?
            } else {
                ClientPayloadNonceReplayCache::default()
            }),
            crypto_payload_migration_lock: Mutex::new(()),
            private_oram_automatic_recovery_tasks: Default::default(),
            private_oram_resharding_resume_requests: Default::default(),
            private_oram_fixed_transfer_resume_intents: Default::default(),
            private_oram_source_resume_requests: Default::default(),
            shard_clean_tasks: Default::default(),
        };

        if has_client_envelope_rules {
            collection
                .backfill_client_payload_nonce_replay_cache_from_storage()
                .await?;
        }

        Ok(collection)
    }

    pub async fn stop_gracefully(&self) {
        let mut owned_holder = self.shards_holder.write().await;
        owned_holder.stop_gracefully().await;
    }

    /// Check if stored version have consequent version.
    /// If major version is different, then it is not compatible.
    /// If the difference in consecutive versions is greater than 1 in patch,
    /// then the collection is not compatible with the current version.
    ///
    /// Example:
    ///   0.4.0 -> 0.4.1 = true
    ///   0.4.0 -> 0.4.2 = false
    ///   0.4.0 -> 0.5.0 = false
    ///   0.4.0 -> 0.5.1 = false
    pub fn can_upgrade_storage(stored: &Version, app: &Version) -> bool {
        if stored.major != app.major {
            return false;
        }
        if stored.minor != app.minor {
            return false;
        }
        if stored.patch + 1 < app.patch {
            return false;
        }
        true
    }

    pub fn name(&self) -> &str {
        &self.id
    }

    pub async fn uuid(&self) -> Option<uuid::Uuid> {
        self.collection_config.read().await.uuid
    }

    pub(crate) async fn record_client_payload_nonce_replay_keys(
        &self,
        keys: impl IntoIterator<Item = String>,
    ) -> CollectionResult<()> {
        let keys = keys.into_iter().collect::<Vec<_>>();
        if keys.is_empty() {
            return Ok(());
        }

        let mut cache = self.client_payload_nonce_replay_cache.lock().await;
        let Some(pending) = cache.pending_keys(keys)? else {
            return Err(CollectionError::bad_input(
                "client encrypted payload nonce was already used in this collection; regenerate the client-side envelope with a fresh nonce before retrying".to_string(),
            ));
        };

        let cache_path = self.path.join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        append_client_payload_nonce_replay_cache(&cache_path, &pending)?;
        if cache.insert_pending(pending) {
            rewrite_client_payload_nonce_replay_cache(&cache_path, &cache.order)?;
        }

        Ok(())
    }

    pub(crate) async fn backfill_client_payload_nonce_replay_keys(
        &self,
        keys: impl IntoIterator<Item = String>,
    ) -> CollectionResult<usize> {
        let keys = keys.into_iter().collect::<Vec<_>>();
        if keys.is_empty() {
            return Ok(0);
        }

        let mut loaded_keys = HashSet::new();
        for key in &keys {
            qdrant_sec::ClientPayloadNonceReplayKey::validate_cache_key_for_collection(key)
                .map_err(|_| {
                    CollectionError::service_error(
                        "stored client encrypted payload nonce replay cache key is invalid",
                    )
                })?;
            if !loaded_keys.insert(key) {
                return Err(CollectionError::service_error(
                    "stored client encrypted payload nonce was reused in this collection; refuse to load replay cache backfill".to_string(),
                ));
            }
        }

        let mut cache = self.client_payload_nonce_replay_cache.lock().await;
        let missing = keys
            .into_iter()
            .filter(|key| !cache.seen.contains(key))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(0);
        }

        let missing_count = missing.len();
        let cache_path = self.path.join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        append_client_payload_nonce_replay_cache(&cache_path, &missing)?;
        if cache.insert_pending(missing) {
            rewrite_client_payload_nonce_replay_cache(&cache_path, &cache.order)?;
        }

        Ok(missing_count)
    }

    pub async fn get_sharding_method_and_keys(&self) -> (ShardingMethod, Vec<ShardKey>) {
        let shards_holder = self.shards_holder.read().await;

        let sharding_method = shards_holder.get_sharding_method();
        let shard_keys = shards_holder
            .get_shard_key_to_ids_mapping()
            .keys()
            .cloned()
            .collect();

        (sharding_method, shard_keys)
    }

    /// Return a list of local shards, present on this peer
    pub async fn get_local_shards(&self) -> Vec<ShardId> {
        self.shards_holder.read().await.get_local_shards().await
    }

    pub async fn contains_shard(&self, shard_id: ShardId) -> bool {
        self.shards_holder.read().await.contains_shard(shard_id)
    }

    pub async fn wait_local_shard_replica_state(
        &self,
        shard_id: ShardId,
        state: ReplicaState,
        timeout: Duration,
    ) -> CollectionResult<()> {
        let shard_holder_read = self.shards_holder.read().await;

        let shard = shard_holder_read.get_shard(shard_id);
        let replica_set = shard.ok_or_else(|| CollectionError::NotFound {
            what: format!("Shard {shard_id}"),
        })?;

        replica_set.wait_for_local_state(state, timeout).await
    }

    pub async fn set_shard_replica_state(
        &self,
        shard_id: ShardId,
        peer_id: PeerId,
        new_state: ReplicaState,
        from_state: Option<ReplicaState>,
    ) -> CollectionResult<()> {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };

        let shard_holder = self.shards_holder.read().await;
        let replica_set = shard_holder
            .get_shard(shard_id)
            .ok_or_else(|| shard_not_found_error(shard_id))?;

        log::debug!(
            "Changing shard {}:{shard_id} replica state from {:?} to {new_state:?}",
            self.id,
            replica_set.peer_state(peer_id),
        );

        let current_state = replica_set.peer_state(peer_id);
        let resharding_state = shard_holder.resharding_state();

        validate_private_oram_resharding_replica_state_until_supported(
            shard_id,
            peer_id,
            replica_set.shard_key(),
            new_state,
            from_state,
            current_state,
            resharding_state.as_ref(),
            private_oram_bucket_store_collection,
        )?;

        // Validation:
        //
        // 1. Check that peer exists in the cluster (peer might *not* exist, if it was removed from
        //    the cluster right before `SetShardReplicaSet` was proposed)
        let peer_exists = self
            .channel_service
            .id_to_address
            .read()
            .contains_key(&peer_id);

        let replica_exists = replica_set.peer_state(peer_id).is_some();

        if !peer_exists && !replica_exists {
            return Err(CollectionError::bad_input(format!(
                "Can't set replica {peer_id}:{shard_id} state to {new_state:?}, \
                 because replica {peer_id}:{shard_id} does not exist \
                 and peer {peer_id} is not part of the cluster"
            )));
        }

        // 2. Check that `from_state` matches current state
        if from_state.is_some() && current_state != from_state {
            return Err(CollectionError::bad_input(format!(
                "Replica {peer_id} of shard {shard_id} has state {current_state:?}, but expected {from_state:?}"
            )));
        }

        // 3. Do not deactivate the last active replica
        //
        // `is_last_active_replica` counts both `Active` and `ReshardingScaleDown` replicas!
        if replica_set.is_last_source_of_truth_replica(peer_id) && !new_state.is_active() {
            return Err(CollectionError::bad_input(format!(
                "Cannot deactivate the last active replica {peer_id} of shard {shard_id}"
            )));
        }

        // Update replica status
        replica_set
            .ensure_replica_with_state(peer_id, new_state)
            .await?;

        if new_state == ReplicaState::Dead {
            let resharding_state = shard_holder.resharding_state.read().clone();

            let all_nodes_fixed_cancellation = self
                .channel_service
                .all_peers_at_version(&ABORT_TRANSFERS_ON_SHARD_DROP_FIX_FROM_VERSION);
            let related_transfers = if all_nodes_fixed_cancellation {
                shard_holder.get_related_transfers(peer_id, shard_id)
            } else {
                // This is the old buggy logic, but we have to keep it
                // for maintaining consistency in a cluster with mixed versions.
                shard_holder.get_transfers(|transfer| {
                    transfer.shard_id == shard_id
                        && (transfer.from == peer_id || transfer.to == peer_id)
                })
            };

            // Functions below lock `shard_holder`!
            drop(shard_holder);

            let mut abort_resharding_result = CollectionResult::Ok(());

            // Abort resharding, if resharding shard is marked as `Dead`.
            //
            // This branch should only be triggered, if resharding is currently at `MigratingPoints`
            // stage, because target shard should be marked as `Active`, when all resharding transfers
            // are successfully completed, and so the check *right above* this one would be triggered.
            //
            // So, if resharding reached `ReadHashRingCommitted`, this branch *won't* be triggered,
            // and resharding *won't* be cancelled. The update request should *fail* with "failed to
            // update all replicas of a shard" error.
            //
            // If resharding reached `ReadHashRingCommitted`, and this branch is triggered *somehow*,
            // then `Collection::abort_resharding` call should return an error, so no special handling
            // is needed.
            let is_resharding = current_state
                .as_ref()
                .is_some_and(ReplicaState::is_resharding);
            if is_resharding && let Some(state) = resharding_state {
                abort_resharding_result = self.abort_resharding(state.key(), false).await;
            }

            // Terminate transfer if source or target replicas are now dead
            for transfer in related_transfers {
                self.abort_shard_transfer_and_resharding(transfer.key(), None)
                    .await?;
            }

            // Propagate resharding errors now
            abort_resharding_result?;
        }

        // If not initialized yet, we need to check if it was initialized by this call
        if !self.is_initialized.check_ready() {
            let state = self.state().await;

            let mut is_ready = true;

            for (_shard_id, shard_info) in state.shards {
                let all_replicas_active = shard_info.replicas.into_iter().all(|(_, state)| {
                    matches!(
                        state,
                        ReplicaState::Active | ReplicaState::ReshardingScaleDown
                    )
                });

                if !all_replicas_active {
                    is_ready = false;
                    break;
                }
            }

            if is_ready {
                self.is_initialized.make_ready();
            }
        }

        Ok(())
    }

    pub async fn shard_recovery_point(&self, shard_id: ShardId) -> CollectionResult<RecoveryPoint> {
        let shard_holder_read = self.shards_holder.read().await;

        let shard = shard_holder_read.get_shard(shard_id);
        let replica_set = shard.ok_or_else(|| CollectionError::NotFound {
            what: format!("Shard {shard_id}"),
        })?;

        replica_set.shard_recovery_point().await
    }

    pub async fn update_shard_cutoff_point(
        &self,
        shard_id: ShardId,
        cutoff: &RecoveryPoint,
    ) -> CollectionResult<()> {
        let shard_holder_read = self.shards_holder.read().await;

        let shard = shard_holder_read.get_shard(shard_id);
        let replica_set = shard.ok_or_else(|| CollectionError::NotFound {
            what: format!("Shard {shard_id}"),
        })?;

        replica_set.update_shard_cutoff_point(cutoff).await
    }

    pub async fn get_shard_wal_entries(
        &self,
        shard_id: ShardId,
        count: u64,
    ) -> CollectionResult<Vec<(SeqNumberType, OperationWithClockTag)>> {
        let shard_holder = self.shards_holder.read().await;

        let Some(replica_set) = shard_holder.get_shard(shard_id) else {
            return Err(CollectionError::NotFound {
                what: format!("Shard {shard_id}"),
            });
        };

        replica_set.get_wal_entries(count).await
    }

    /// Get optimizations info from the local shard only.
    ///
    /// Used by the internal gRPC handler to serve requests from remote peers.
    pub async fn local_shard_optimizations(
        &self,
        shard_id: ShardId,
        options: OptimizationsRequestOptions,
    ) -> CollectionResult<OptimizationsResponse> {
        let shard_holder_read = self.shards_holder.read().await;

        let shard = shard_holder_read.get_shard(shard_id);
        let replica_set = shard.ok_or_else(|| CollectionError::NotFound {
            what: format!("Shard {shard_id}"),
        })?;

        replica_set.local_optimizations(options).await
    }

    pub async fn state(&self) -> State {
        let shards_holder = self.shards_holder.read().await;
        let transfers = shards_holder.shard_transfers.read().clone();
        let resharding = shards_holder.resharding_state.read().clone();
        State {
            config: self.collection_config.read().await.clone(),
            shards: shards_holder
                .get_shards()
                .map(|(shard_id, replicas)| {
                    let shard_info = ShardInfo {
                        replicas: replicas.peers(),
                    };
                    (shard_id, shard_info)
                })
                .collect(),
            resharding,
            transfers,
            shards_key_mapping: shards_holder.get_shard_key_to_ids_mapping(),
            payload_index_schema: self.payload_index_schema.read().clone(),
        }
    }

    pub async fn remove_shards_at_peer(&self, peer_id: PeerId) -> CollectionResult<()> {
        // Abort resharding, if shards are removed from peer driving resharding
        // (which *usually* means the *peer* is being removed from consensus)
        let resharding_state = self
            .resharding_state()
            .await
            .filter(|state| state.peer_id == peer_id);

        if let Some(state) = resharding_state
            && let Err(err) = self.abort_resharding(state.key(), true).await
        {
            log::error!(
                "Failed to abort resharding {} while removing peer {peer_id}: {err}",
                state.key(),
            );
        }

        for transfer in self.get_related_transfers(peer_id).await {
            self.abort_shard_transfer_and_resharding(transfer.key(), None)
                .await?;
        }

        self.shards_holder
            .read()
            .await
            .remove_shards_at_peer(peer_id)
            .await
    }

    pub async fn sync_local_state(
        &self,
        on_transfer_failure: OnTransferFailure,
        on_transfer_success: OnTransferSuccess,
        on_finish_init: ChangePeerState,
        on_convert_to_listener: ChangePeerState,
        on_convert_from_listener: ChangePeerState,
    ) -> CollectionResult<()> {
        let (
            encrypted_collection,
            private_oram_bucket_store_collection,
            configured_shard_count,
            sharding_method,
        ) = {
            let config = self.collection_config.read().await;
            let encryption = config.params.effective_encryption();
            (
                encryption.is_some(),
                encryption
                    .as_ref()
                    .is_some_and(collection_encryption_uses_private_oram_bucket_store),
                config.params.shard_number.get() as usize,
                config.params.sharding_method.unwrap_or_default(),
            )
        };

        // Check for disabled replicas
        let shard_holder = self.shards_holder.read().await;
        let private_oram_recovery_layout_is_stable = {
            let shard_ids = shard_holder
                .all_shards()
                .map(|replica_set| replica_set.shard_id)
                .collect::<BTreeSet<_>>();
            let mapped_shard_ids = shard_holder
                .get_shard_key_to_ids_mapping()
                .iter_shard_ids()
                .collect::<Vec<_>>();
            private_oram_shard_layout_is_stable(
                sharding_method,
                configured_shard_count,
                &shard_ids,
                &mapped_shard_ids,
            )
        };

        let get_shard_transfers = |shard_id, from| {
            shard_holder.get_transfers(|transfer| transfer.is_source(from, shard_id))
        };

        for replica_set in shard_holder.all_shards() {
            replica_set.sync_local_state(get_shard_transfers)?;
        }

        // Check for un-reported finished transfers
        let outgoing_transfers = shard_holder.get_outgoing_transfers(self.this_peer_id);
        let active_transfers = shard_holder
            .get_transfers(|_| true)
            .into_iter()
            .collect::<HashSet<_>>();
        let active_transfer_count = active_transfers.len();
        let mut durable_fixed_transfer_resume_intent =
            self.private_oram_fixed_transfer_preinstall_intent()?;
        if let Some(transfer) = durable_fixed_transfer_resume_intent.as_ref() {
            if !active_transfers.contains(transfer) {
                self.clear_private_oram_fixed_transfer_preinstall_intent(transfer)?;
                durable_fixed_transfer_resume_intent = None;
            } else if transfer.from != self.this_peer_id
                || !shard_holder
                    .get_shard(transfer.shard_id)
                    .is_some_and(|replica_set| {
                        private_oram_fixed_transfer_requires_exact_restart(
                            private_oram_bucket_store_collection,
                            transfer,
                            shard_holder.resharding_state().as_ref(),
                            transfer.to,
                            active_transfer_count,
                            replica_set.peer_state(transfer.from),
                            replica_set.peer_state(transfer.to),
                        )
                    })
            {
                // The intent only drives an automatic exact restart; one that does not fit the
                // active transfer is ignored (not deleted: replica states may still be moving)
                // instead of failing every local sync of the collection.
                log::warn!(
                    "Ignoring a private ORAM source preinstall intent that does not match the \
                     active transfer of collection {}",
                    self.name(),
                );
                durable_fixed_transfer_resume_intent = None;
            }
        }
        let fixed_transfer_resume_intents = {
            let mut intents = self.private_oram_fixed_transfer_resume_intents.lock().await;
            intents.retain(|transfer| active_transfers.contains(transfer));
            if let Some(transfer) = durable_fixed_transfer_resume_intent.as_ref() {
                intents.insert(transfer.clone());
            }
            intents.clone()
        };
        let resharding_state = shard_holder.resharding_state();
        let incoming_private_oram_resharding_resume_requests = shard_holder
            .get_transfers(|transfer| transfer.to == self.this_peer_id)
            .into_iter()
            .filter_map(|transfer| {
                private_oram_resharding_resume_request(
                    self.name(),
                    self.this_peer_id,
                    private_oram_bucket_store_collection,
                    &transfer,
                    resharding_state.as_ref(),
                )
                .map(|request| (transfer.key(), request))
            })
            .collect::<Vec<_>>();
        let resume_requests = {
            let mut pending = self.private_oram_resharding_resume_requests.lock().await;
            incoming_private_oram_resharding_resume_requests
                .into_iter()
                .filter(|(key, _)| pending.insert((*key).clone()))
                .collect::<Vec<_>>()
        };
        for (transfer_key, request) in resume_requests {
            let channel_service = self.channel_service.clone();
            let pending = self.private_oram_resharding_resume_requests.clone();
            self.update_runtime.spawn(async move {
                let source_peer_id = request.source_peer_id;
                let response = channel_service
                    .request_private_oram_resharding_resume(source_peer_id, request)
                    .await;
                match response {
                    Ok(response) if response.accepted => {}
                    Ok(_) => log::warn!(
                        "Private ORAM resharding resume was not accepted by source peer {source_peer_id}"
                    ),
                    Err(error) => log::warn!(
                        "Failed to request private ORAM resharding resume from source peer {source_peer_id}: {error}"
                    ),
                }
                tokio::time::sleep(PRIVATE_ORAM_RESHARDING_RESUME_REQUEST_INTERVAL).await;
                pending.lock().await.remove(&transfer_key);
            });
        }
        let tasks_lock = self.transfer_tasks.lock().await;
        for transfer in outgoing_transfers {
            let fixed_transfer_requires_exact_restart = shard_holder
                .get_shard(transfer.shard_id)
                .is_some_and(|replica_set| {
                    fixed_transfer_resume_intents.contains(&transfer)
                        && private_oram_fixed_transfer_requires_exact_restart(
                            private_oram_bucket_store_collection,
                            &transfer,
                            resharding_state.as_ref(),
                            transfer.to,
                            active_transfer_count,
                            replica_set.peer_state(transfer.from),
                            replica_set.peer_state(transfer.to),
                        )
                });
            let resharding_transfer_requires_exact_restart =
                private_oram_resharding_transfer_requires_exact_restart(
                    private_oram_bucket_store_collection,
                    &transfer,
                    resharding_state.as_ref(),
                    self.this_peer_id,
                );
            let task_result = tasks_lock
                .get_task_status(&transfer.key())
                .map(|s| s.result);
            if fixed_transfer_requires_exact_restart
                && durable_fixed_transfer_resume_intent.as_ref() == Some(&transfer)
                && task_result
                    .as_ref()
                    .is_none_or(|result| *result == TaskResult::Failed)
            {
                // Once both stores are installed the target stops requesting preinstall.
                // A source crash can still lose the streaming task, so its durable intent
                // must drive recovery too. The RPC rechecks task state under its lock to
                // avoid a delayed retry replacing a task another request already started.
                let transfer_key = transfer.key();
                let should_request_resume = self
                    .private_oram_source_resume_requests
                    .lock()
                    .await
                    .insert(transfer_key.clone());
                if should_request_resume {
                    let transition = transfer
                        .private_oram_layout_transition
                        .as_ref()
                        .expect("exact fixed transfer resume requires a layout transition");
                    let request = RequestPrivateOramShardRecoveryRequest {
                        collection_name: self.name().to_string(),
                        shard_id: transfer.shard_id,
                        source_peer_id: transfer.from,
                        target_peer_id: transfer.to,
                        active_transfer_resume: Some(PrivateOramActiveTransferResumeContext {
                            sync: transfer.sync,
                            expected_layout_generation: transition.expected.generation,
                            expected_layout_digest: transition.expected.layout_digest.clone(),
                            new_layout_generation: transition.new.generation,
                            new_layout_digest: transition.new.layout_digest.clone(),
                            index_state_digest: transition.expected.index_state_digest.clone(),
                        }),
                        resume_if_task_missing: true,
                    };
                    let channel_service = self.channel_service.clone();
                    let pending = self.private_oram_source_resume_requests.clone();
                    self.update_runtime.spawn(async move {
                        log::info!(
                            "Resuming a private ORAM source transfer from its durable preinstall intent"
                        );
                        match channel_service
                            .request_private_oram_shard_recovery(request.source_peer_id, request)
                            .await
                        {
                            Ok(response) if response.accepted => {}
                            Ok(_) => log::warn!(
                                "Private ORAM source transfer resume was not accepted"
                            ),
                            Err(error) => log::warn!(
                                "Failed to resume private ORAM source transfer: {error}"
                            ),
                        }
                        tokio::time::sleep(PRIVATE_ORAM_SOURCE_RESUME_REQUEST_INTERVAL).await;
                        pending.lock().await.remove(&transfer_key);
                    });
                }
                continue;
            }
            match task_result {
                None => {
                    if fixed_transfer_requires_exact_restart
                        || resharding_transfer_requires_exact_restart
                    {
                        log::warn!(
                            "Private ORAM transfer task is missing; preserving the active transfer while the target requests an exact automatic restart",
                        );
                        continue;
                    }
                    log::debug!(
                        "Transfer {:?} does not exist, but not reported as cancelled. Reporting now.",
                        transfer.key(),
                    );
                    on_transfer_failure(
                        transfer,
                        self.name().to_string(),
                        "transfer task does not exist",
                    );
                }
                Some(TaskResult::Running) => (),
                Some(TaskResult::Finished) => {
                    log::debug!(
                        "Transfer {:?} is finished successfully, but not reported. Reporting now.",
                        transfer.key(),
                    );
                    on_transfer_success(transfer, self.name().to_string());
                }
                Some(TaskResult::Failed) => {
                    if fixed_transfer_requires_exact_restart {
                        log::warn!(
                            "Private ORAM fixed-layout transfer task failed during target recovery; preserving the active transfer for an exact automatic restart",
                        );
                        continue;
                    }
                    log::debug!(
                        "Transfer {:?} is failed, but not reported as failed. Reporting now.",
                        transfer.key(),
                    );
                    on_transfer_failure(transfer, self.name().to_string(), "transfer failed");
                }
            }
        }

        // Count how many transfers we are now proposing
        // We must track this here so we can reference it when checking for tranfser limits,
        // because transfers we propose now will not be in the consensus state within the lifetime
        // of this function
        let mut proposed = HashMap::<PeerId, usize>::new();

        // Check for proper replica states
        for replica_set in shard_holder.all_shards() {
            let this_peer_id = replica_set.this_peer_id();
            let shard_id = replica_set.shard_id;

            let peers = replica_set.peers();
            let this_peer_state = peers.get(&this_peer_id).copied();

            if this_peer_state == Some(Initializing) {
                // It is possible, that collection creation didn't report
                // Try to activate shard, as the collection clearly exists
                on_finish_init(this_peer_id, shard_id);
                continue;
            }

            if self.shared_storage_config.node_type == NodeType::Listener {
                // We probably should not switch node type during resharding, so we only check for `Active`,
                // but not `ReshardingScaleDown` replica state here...
                let is_last_active = peers.values().filter(|&&state| state == Active).count() == 1;

                if this_peer_state == Some(Active) && !is_last_active {
                    // Convert active node from active to listener
                    on_convert_to_listener(this_peer_id, shard_id);
                    continue;
                }
            } else if this_peer_state == Some(Listener) {
                // Convert listener node to active
                on_convert_from_listener(this_peer_id, shard_id);
                continue;
            }

            // Don't automatically recover replicas if started in recovery mode
            if self.shared_storage_config.recovery_mode.is_some() {
                continue;
            }

            // Don't recover replicas if not dead
            let is_dead = this_peer_state == Some(Dead);
            if !is_dead {
                continue;
            }
            if let Err(err) = validate_private_oram_automatic_transfer_recovery_layout(
                self.name(),
                shard_id,
                private_oram_bucket_store_collection,
                private_oram_recovery_layout_is_stable,
            ) {
                log::warn!("{err}");
                continue;
            }

            // Try to find dead replicas with no active transfers
            let transfers = shard_holder.get_transfers(|_| true);

            // Respect shard transfer limit, consider already proposed transfers in our counts
            let (mut incoming, outgoing) = shard_holder.count_shard_transfer_io(this_peer_id);
            incoming += proposed.get(&this_peer_id).copied().unwrap_or(0);
            if self.check_auto_shard_transfer_limit(incoming, outgoing) {
                log::trace!(
                    "Postponing automatic shard {shard_id} transfer to stay below limit on this node (incoming: {incoming}, outgoing: {outgoing})",
                );
                continue;
            }

            // Select shard transfer method, prefer user configured method or choose one now
            // If all peers are 1.8+, we try WAL delta transfer, otherwise we use the default method
            let shard_transfer_method = if private_oram_bucket_store_collection {
                ShardTransferMethod::StreamRecords
            } else {
                let default_method = self.default_shard_transfer_method().await;
                self.shared_storage_config
                    .default_shard_transfer_method
                    .unwrap_or_else(|| {
                        let all_support_wal_delta = self
                            .channel_service
                            .all_peers_at_version(&Version::new(1, 8, 0));
                        if all_support_wal_delta {
                            ShardTransferMethod::WalDelta
                        } else {
                            default_method
                        }
                    })
            };

            // Try to find a replica to transfer from
            //
            // `active_shards` includes `Active` and `ReshardingScaleDown` replicas!
            for replica_id in replica_set.active_shards(true) {
                if encrypted_collection {
                    let parity_result = {
                        let peer_metadata_by_id = self.channel_service.id_to_metadata.read();
                        validate_encrypted_automatic_transfer_crypto_runtime_parity(
                            self.name(),
                            shard_id,
                            replica_id,
                            this_peer_id,
                            &peer_metadata_by_id,
                        )
                    };
                    if let Err(err) = parity_result {
                        log::warn!(
                            "Skipping automatic shard transfer recovery for encrypted collection {} shard {shard_id} \
                             from peer {replica_id} to peer {this_peer_id}: {err}",
                            self.name(),
                        );
                        continue;
                    }
                }

                let transfer = ShardTransfer {
                    from: replica_id,
                    to: this_peer_id,
                    shard_id,
                    to_shard_id: None,
                    sync: true,
                    // For automatic shard transfers, always select some default method from this point on
                    method: Some(shard_transfer_method),
                    private_oram_preinstalled: false,
                    private_oram_layout_transition: None,
                    filter: None,
                };

                if check_transfer_conflicts_strict(&transfer, transfers.iter()).is_some() {
                    continue; // this transfer won't work
                }

                // Respect shard transfer limit, consider already proposed transfers in our counts
                let (incoming, mut outgoing) = shard_holder.count_shard_transfer_io(replica_id);
                outgoing += proposed.get(&replica_id).copied().unwrap_or(0);
                if self.check_auto_shard_transfer_limit(incoming, outgoing) {
                    log::trace!(
                        "Postponing automatic shard {shard_id} transfer to stay below limit on peer {replica_id} (incoming: {incoming}, outgoing: {outgoing})",
                    );
                    continue;
                }

                // TODO: Should we, maybe, throttle/backoff this requests a bit?
                if let Err(err) = replica_set.health_check(replica_id).await {
                    // TODO: This is rather verbose, not sure if we want to log this at all... :/
                    log::trace!(
                        "Replica {replica_id}/{}:{} is not available \
                         to request shard transfer from: \
                         {err}",
                        self.id,
                        replica_set.shard_id,
                    );
                    continue;
                }

                log::debug!(
                    "Recovering shard {}:{shard_id} on peer {this_peer_id} by requesting it from {replica_id}",
                    self.name(),
                );

                if private_oram_bucket_store_collection {
                    let mut recovery_tasks =
                        self.private_oram_automatic_recovery_tasks.lock().await;
                    if !recovery_tasks.insert(shard_id) {
                        break;
                    }
                    drop(recovery_tasks);

                    let channel_service = self.channel_service.clone();
                    let collection_name = self.name().to_string();
                    let recovery_tasks = self.private_oram_automatic_recovery_tasks.clone();
                    self.update_runtime.spawn(async move {
                        let response = channel_service
                            .request_private_oram_shard_recovery(
                                replica_id,
                                RequestPrivateOramShardRecoveryRequest {
                                    collection_name,
                                    shard_id,
                                    source_peer_id: replica_id,
                                    target_peer_id: this_peer_id,
                                    active_transfer_resume: None,
                                    resume_if_task_missing: false,
                                },
                            )
                            .await;
                        match response {
                            Ok(response) if response.accepted => {}
                            Ok(_) => log::warn!(
                                "Private ORAM automatic shard recovery was not accepted by source peer {replica_id}"
                            ),
                            Err(error) => log::warn!(
                                "Failed to request private ORAM automatic shard recovery from peer {replica_id}: {error}"
                            ),
                        }
                        recovery_tasks.lock().await.remove(&shard_id);
                    });
                }

                // Update our counters for proposed transfers, then request (propose) shard transfer
                *proposed.entry(transfer.from).or_default() += 1;
                *proposed.entry(transfer.to).or_default() += 1;
                if !private_oram_bucket_store_collection {
                    self.request_shard_transfer(transfer);
                }
                break;
            }
        }

        Ok(())
    }

    /// Whether a peer restart must preserve an active private ORAM transfer until the target
    /// requests the exact automatic restart that re-preinstalls the encrypted stores. A fixed
    /// transfer source is preserved only while an exact durable or in-process resume intent
    /// exists.
    pub async fn should_preserve_private_oram_transfer_on_peer_restart(
        &self,
        transfer: &ShardTransfer,
        restarted_peer_id: PeerId,
    ) -> CollectionResult<bool> {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        let state = self.state().await;
        if private_oram_resharding_transfer_requires_exact_restart(
            private_oram_bucket_store_collection,
            transfer,
            state.resharding.as_ref(),
            restarted_peer_id,
        ) {
            return Ok(true);
        }

        let Some(shard) = state.shards.get(&transfer.shard_id) else {
            return Ok(false);
        };
        let fixed_transfer_requires_exact_restart = state.transfers.contains(transfer)
            && private_oram_fixed_transfer_requires_exact_restart(
                private_oram_bucket_store_collection,
                transfer,
                state.resharding.as_ref(),
                transfer.to,
                state.transfers.len(),
                shard.replicas.get(&transfer.from).copied(),
                shard.replicas.get(&transfer.to).copied(),
            );
        if !fixed_transfer_requires_exact_restart {
            return Ok(false);
        }
        if restarted_peer_id == transfer.to {
            return Ok(true);
        }
        if restarted_peer_id == transfer.from {
            return Ok(
                self.private_oram_fixed_transfer_preinstall_intent_matches(transfer)?
                    || self
                        .private_oram_fixed_transfer_resume_intents
                        .lock()
                        .await
                        .contains(transfer),
            );
        }
        Ok(false)
    }

    pub async fn get_aggregated_telemetry_data(
        &self,
        timeout: Duration,
    ) -> CollectionResult<CollectionsAggregatedTelemetry> {
        let start = std::time::Instant::now();
        let shards_holder = self.shards_holder.read().await;

        let mut shard_optimization_statuses = Vec::new();
        let mut vectors = 0;

        for shard in shards_holder.all_shards() {
            let shard_optimization_status = match shard
                .get_optimization_status(timeout.saturating_sub(start.elapsed()))
                .await
            {
                None => OptimizersStatus::Ok,
                Some(status) => status?,
            };

            shard_optimization_statuses.push(shard_optimization_status);
            let size_stats = shard
                .get_size_stats(timeout.saturating_sub(start.elapsed()))
                .await?;
            vectors += size_stats.num_vectors;
        }

        let optimizers_status = shard_optimization_statuses
            .into_iter()
            .max()
            .unwrap_or(OptimizersStatus::Ok);

        Ok(CollectionsAggregatedTelemetry {
            vectors,
            optimizers_status,
            params: self.collection_config.read().await.params.clone(),
        })
    }

    pub async fn effective_optimizers_config(&self) -> CollectionResult<OptimizersConfig> {
        let config = self.collection_config.read().await;

        if let Some(optimizers_overwrite) = self.optimizers_overwrite.clone() {
            Ok(config.optimizer_config.update(&optimizers_overwrite))
        } else {
            Ok(config.optimizer_config.clone())
        }
    }

    pub fn request_shard_transfer(&self, shard_transfer: ShardTransfer) {
        self.request_shard_transfer_cb.deref()(shard_transfer)
    }

    pub fn snapshots_path(&self) -> &Path {
        &self.snapshots_path
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn shards_holder(&self) -> SharedShardHolder {
        self.shards_holder.clone()
    }

    pub async fn trigger_optimizers(&self) {
        self.shards_holder.read().await.trigger_optimizers().await;
    }

    async fn estimate_collection_size_stats(
        shards_holder: &SharedShardHolder,
    ) -> CollectionResult<Option<CollectionSizeStats>> {
        let shard_lock = shards_holder.read().await;
        shard_lock.estimate_collection_size_stats().await
    }

    /// Returns estimations of collection sizes. This values are cached and might be not 100% up to date.
    /// The cache gets updated every 32 calls.
    pub(crate) async fn estimated_collection_stats(
        &self,
    ) -> CollectionResult<Option<&CollectionSizeAtomicStats>> {
        self.collection_stats_cache
            .get_or_update_cache(|| Self::estimate_collection_size_stats(&self.shards_holder))
            .await
    }
}

fn append_client_payload_nonce_replay_cache(path: &Path, keys: &[String]) -> CollectionResult<()> {
    validate_client_payload_nonce_replay_cache_parent(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to open client payload nonce replay cache: {err}",
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = file.metadata().map_err(|err| {
            CollectionError::service_error(format!(
                "failed to inspect client payload nonce replay cache: {err}",
            ))
        })?;
        if permissions.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "client payload nonce replay cache must not be group/world accessible",
            ));
        }
    }

    for key in keys {
        writeln!(file, "{key}").map_err(|err| {
            CollectionError::service_error(format!(
                "failed to write client payload nonce replay cache: {err}",
            ))
        })?;
    }

    file.flush().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to flush client payload nonce replay cache: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync client payload nonce replay cache: {err}",
        ))
    })?;
    sync_client_payload_nonce_replay_cache_parent(path)
}

fn rewrite_client_payload_nonce_replay_cache(
    path: &Path,
    keys: &VecDeque<String>,
) -> CollectionResult<()> {
    validate_client_payload_nonce_replay_cache_parent(path)?;
    let temp_path = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp_path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to create client payload nonce replay cache temp file: {err}",
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = file.metadata().map_err(|err| {
            CollectionError::service_error(format!(
                "failed to inspect client payload nonce replay cache temp file: {err}",
            ))
        })?;
        if permissions.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "client payload nonce replay cache temp file must not be group/world accessible",
            ));
        }
    }

    for key in keys {
        writeln!(file, "{key}").map_err(|err| {
            CollectionError::service_error(format!(
                "failed to write client payload nonce replay cache temp file: {err}",
            ))
        })?;
    }

    file.flush().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to flush client payload nonce replay cache temp file: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync client payload nonce replay cache temp file: {err}",
        ))
    })?;

    std::fs::rename(&temp_path, path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to replace client payload nonce replay cache: {err}",
        ))
    })?;
    sync_client_payload_nonce_replay_cache_parent(path)
}

#[cfg(unix)]
fn validate_client_payload_nonce_replay_cache_parent(path: &Path) -> CollectionResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let direct_parent = Some(parent);
    let mut current = direct_parent;
    while let Some(directory) = current {
        let metadata = std::fs::symlink_metadata(directory).map_err(|err| {
            CollectionError::service_error(format!(
                "failed to inspect client payload nonce replay cache directory: {err}",
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CollectionError::service_error(
                "client payload nonce replay cache directory must be a regular directory",
            ));
        }
        let owner = metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CollectionError::service_error(
                "client payload nonce replay cache directory must be owned by root or the Qdrant process user",
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            let sticky_ancestor = Some(directory) != direct_parent && mode & 0o1000 != 0;
            if sticky_ancestor {
                current = directory.parent();
                continue;
            }
            return Err(CollectionError::service_error(
                "client payload nonce replay cache directory must not be group/world writable",
            ));
        }
        current = directory.parent();
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_client_payload_nonce_replay_cache_parent(_path: &Path) -> CollectionResult<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_client_payload_nonce_replay_cache_parent(path: &Path) -> CollectionResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|err| {
            CollectionError::service_error(format!(
                "failed to open client payload nonce replay cache directory: {err}",
            ))
        })?;
    directory.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync client payload nonce replay cache directory: {err}",
        ))
    })
}

#[cfg(not(unix))]
fn sync_client_payload_nonce_replay_cache_parent(_path: &Path) -> CollectionResult<()> {
    Ok(())
}

fn validate_encrypted_automatic_transfer_crypto_runtime_parity(
    collection_name: &str,
    shard_id: ShardId,
    from_peer_id: PeerId,
    to_peer_id: PeerId,
    peer_metadata_by_id: &HashMap<PeerId, PeerMetadata>,
) -> CollectionResult<()> {
    let from_fingerprint = peer_metadata_by_id
        .get(&from_peer_id)
        .and_then(PeerMetadata::crypto_runtime_capability_fingerprint)
        .ok_or_else(|| {
            CollectionError::bad_input(format!(
                "automatic shard transfer recovery for encrypted collection {collection_name} shard {shard_id} \
                 requires crypto runtime capability metadata for source peer {from_peer_id}",
            ))
        })?;
    let to_fingerprint = peer_metadata_by_id
        .get(&to_peer_id)
        .and_then(PeerMetadata::crypto_runtime_capability_fingerprint)
        .ok_or_else(|| {
            CollectionError::bad_input(format!(
                "automatic shard transfer recovery for encrypted collection {collection_name} shard {shard_id} \
                 requires crypto runtime capability metadata for target peer {to_peer_id}",
            ))
        })?;

    if from_fingerprint != to_fingerprint {
        return Err(CollectionError::bad_input(format!(
            "automatic shard transfer recovery for encrypted collection {collection_name} shard {shard_id} \
             requires matching crypto runtime capability fingerprints for source peer {from_peer_id} \
             and target peer {to_peer_id}",
        )));
    }

    Ok(())
}

fn collection_encryption_uses_private_oram_bucket_store(
    encryption: &CollectionEncryptionConfig,
) -> bool {
    encryption.rules.iter().any(|rule| {
        matches!(
            rule.binding.as_deref(),
            Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING)
                | Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING)
        )
    })
}

/// Whether the shard layout is the configured stable one that private ORAM automatic recovery
/// can reason about: auto sharding needs exactly `shard_number` shards and no key mapping,
/// custom sharding needs every shard to be reachable through the shard key mapping (the shard
/// count is `shard_number` per key there, so a raw count comparison rejected every collection
/// with more than one shard key).
pub(crate) fn private_oram_shard_layout_is_stable(
    sharding_method: ShardingMethod,
    configured_shard_number: usize,
    shard_ids: &BTreeSet<ShardId>,
    mapped_shard_ids: &[ShardId],
) -> bool {
    match sharding_method {
        ShardingMethod::Auto => {
            mapped_shard_ids.is_empty() && configured_shard_number == shard_ids.len()
        }
        ShardingMethod::Custom => {
            !shard_ids.is_empty()
                && mapped_shard_ids.len() == shard_ids.len()
                && mapped_shard_ids.iter().copied().collect::<BTreeSet<_>>() == *shard_ids
        }
    }
}

fn validate_private_oram_automatic_transfer_recovery_layout(
    _collection_name: &str,
    _shard_id: ShardId,
    private_oram_bucket_store_collection: bool,
    layout_is_stable: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection || layout_is_stable {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "automatic shard transfer recovery for private ORAM collections requires the configured \
         stable shard layout",
    ))
}

fn private_oram_resharding_transfer_requires_exact_restart(
    private_oram_bucket_store_collection: bool,
    transfer: &ShardTransfer,
    resharding_state: Option<&ReshardState>,
    restarted_peer_id: PeerId,
) -> bool {
    private_oram_bucket_store_collection
        && transfer.from == restarted_peer_id
        && transfer.is_resharding()
        && transfer.is_private_oram_preinstalled_transfer_for(resharding_state)
}

fn private_oram_fixed_transfer_requires_exact_restart(
    private_oram_bucket_store_collection: bool,
    transfer: &ShardTransfer,
    resharding_state: Option<&ReshardState>,
    restarted_peer_id: PeerId,
    active_transfer_count: usize,
    source_state: Option<ReplicaState>,
    target_state: Option<ReplicaState>,
) -> bool {
    private_oram_bucket_store_collection
        && resharding_state.is_none()
        && active_transfer_count == 1
        && transfer.to == restarted_peer_id
        && transfer.is_private_oram_preinstalled_transfer_for(None)
        && transfer.private_oram_layout_transition.is_some()
        && source_state == Some(ReplicaState::Active)
        && target_state == Some(ReplicaState::Partial)
}

fn private_oram_resharding_resume_request(
    collection_name: &str,
    this_peer_id: PeerId,
    private_oram_bucket_store_collection: bool,
    transfer: &ShardTransfer,
    resharding_state: Option<&ReshardState>,
) -> Option<RequestPrivateOramReshardingResumeRequest> {
    if !private_oram_bucket_store_collection
        || transfer.to != this_peer_id
        || !transfer.is_private_oram_preinstalled_transfer_for(resharding_state)
    {
        return None;
    }
    Some(RequestPrivateOramReshardingResumeRequest {
        collection_name: collection_name.to_string(),
        shard_id: transfer.shard_id,
        to_shard_id: transfer.to_shard_id?,
        source_peer_id: transfer.from,
        target_peer_id: transfer.to,
    })
}

fn validate_private_oram_resharding_replica_state_until_supported(
    shard_id: ShardId,
    peer_id: PeerId,
    shard_key: Option<&ShardKey>,
    new_state: ReplicaState,
    from_state: Option<ReplicaState>,
    current_state: Option<ReplicaState>,
    resharding_state: Option<&ReshardState>,
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection
        || !replica_state_transition_touches_resharding_state(new_state, from_state, current_state)
    {
        return Ok(());
    }

    let exact_promotion = new_state == ReplicaState::Active
        && current_state == from_state
        && resharding_state.is_some_and(|state| {
            state.stage == ReshardingStage::MigratingPoints
                && state.shard_key.as_ref() == shard_key
                && match state.direction {
                    ReshardingDirection::Up => {
                        from_state == Some(ReplicaState::Resharding)
                            && shard_id == state.shard_id
                            && peer_id == state.peer_id
                    }
                    ReshardingDirection::Down => {
                        from_state == Some(ReplicaState::ReshardingScaleDown)
                            && shard_id != state.shard_id
                    }
                }
        });
    if exact_promotion {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot change resharding replica state for private ORAM collections: only the exact \
         active resharding promotion from its transitional state is allowed",
    ))
}

fn replica_state_transition_touches_resharding_state(
    new_state: ReplicaState,
    from_state: Option<ReplicaState>,
    current_state: Option<ReplicaState>,
) -> bool {
    new_state.is_resharding()
        || from_state.is_some_and(|state| state.is_resharding())
        || current_state.is_some_and(|state| state.is_resharding())
}

struct CollectionVersion;

impl StorageVersion for CollectionVersion {
    fn current_raw() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_payload_nonce_replay_cache_rejects_oversized_entries() {
        let dir = tempfile::Builder::new()
            .prefix("nonce-replay-path-sentinel-")
            .tempdir()
            .unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        std::fs::write(
            &cache_path,
            format!(
                "{}\n",
                "x".repeat(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_ENTRY_MAX_BYTES + 1)
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = ClientPayloadNonceReplayCache::load(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("oversized entry"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
    }

    #[test]
    fn client_payload_nonce_replay_cache_rejects_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let file = options.open(&cache_path).unwrap();
        file.set_len(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_MAX_BYTES + 1)
            .unwrap();

        let err = ClientPayloadNonceReplayCache::load(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("exceeds maximum size"));
    }

    #[test]
    fn client_payload_nonce_replay_cache_rejects_malformed_entries() {
        let dir = tempfile::Builder::new()
            .prefix("nonce-replay-path-sentinel-")
            .tempdir()
            .unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        std::fs::write(&cache_path, "not-a-valid-cache-key\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let err = ClientPayloadNonceReplayCache::load(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("malformed entry"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
    }

    #[test]
    fn client_payload_nonce_replay_cache_rejects_malformed_pending_keys() {
        let cache = ClientPayloadNonceReplayCache::default();
        let malformed_key = "not-a-valid-cache-key";
        let err = cache.pending_keys([malformed_key.to_string()]).unwrap_err();
        let rendered = format!("{err:?}");
        assert!(rendered.contains("nonce replay cache key is invalid"));
        assert!(!rendered.contains(malformed_key), "{rendered}");
    }

    #[test]
    fn client_payload_nonce_replay_cache_rejects_duplicate_pending_keys_in_same_batch() {
        let cache = ClientPayloadNonceReplayCache::default();
        let key =
            "collection-uuid\x1ftenant-a-key\x1ftenant-a-rk\x1f1\x1fAAAAAAAAAAAAAAAA".to_string();

        assert!(
            cache
                .pending_keys([key.clone(), key.clone()])
                .unwrap()
                .is_none()
        );
        let pending = cache
            .pending_keys([key.clone()])
            .unwrap()
            .expect("rejected duplicate batches must not partially record nonce keys");
        assert_eq!(pending, vec![key]);
    }

    #[test]
    fn encrypted_automatic_transfer_requires_matching_crypto_runtime_peer_metadata() {
        let mut metadata = HashMap::<PeerId, PeerMetadata>::new();
        let err =
            validate_encrypted_automatic_transfer_crypto_runtime_parity("docs", 0, 1, 2, &metadata)
                .unwrap_err();
        assert!(format!("{err:?}").contains("source peer 1"));

        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-b".to_string(),
            )),
        );
        let err =
            validate_encrypted_automatic_transfer_crypto_runtime_parity("docs", 0, 1, 2, &metadata)
                .unwrap_err();
        assert!(format!("{err:?}").contains("matching crypto runtime"));

        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        validate_encrypted_automatic_transfer_crypto_runtime_parity("docs", 0, 1, 2, &metadata)
            .unwrap();
    }

    #[test]
    fn encrypted_automatic_transfer_rejects_empty_crypto_runtime_peer_metadata() {
        let mut metadata = HashMap::<PeerId, PeerMetadata>::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new())),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );

        let err =
            validate_encrypted_automatic_transfer_crypto_runtime_parity("docs", 0, 1, 2, &metadata)
                .unwrap_err();
        assert!(format!("{err:?}").contains("source peer 1"));

        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new())),
        );

        let err =
            validate_encrypted_automatic_transfer_crypto_runtime_parity("docs", 0, 1, 2, &metadata)
                .unwrap_err();
        assert!(format!("{err:?}").contains("target peer 2"));
    }

    #[test]
    fn collection_encryption_detects_private_hnsw_oram_binding() {
        let mut encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a/vector-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: crate::config::CryptoMigrationState::Active,
            rules: vec![crate::config::EncryptionRuleRef {
                id: "docs_text_private_hnsw".to_string(),
                selector: EncryptionSelector::VectorNames {
                    names: vec!["text".to_string()],
                },
                instance: "docs_text_private_hnsw".to_string(),
                binding: Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string()),
            }],
        };

        assert!(collection_encryption_uses_private_oram_bucket_store(
            &encryption
        ));

        encryption.rules[0].binding = Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string());
        assert!(collection_encryption_uses_private_oram_bucket_store(
            &encryption
        ));

        encryption.rules[0].binding = None;
        assert!(!collection_encryption_uses_private_oram_bucket_store(
            &encryption
        ));
    }

    const PRIVATE_ORAM_CLIENT_STATE_COLLECTION_NAMES: &[&str] = &[
        "stashBackup.json",
        "stashBackups.json",
        "stash_backup.json",
        "tokenMapBackup.json",
        "tokenMapBackups.json",
        "token.map.backup",
        "token.map.backup.json",
        "token.map.backups",
        "token.map.backups.json",
        "token_map_backup.json",
        "tokenPositionMapBackup.json",
        "tokenPositionMapBackups.json",
        "token.position.map.backup",
        "token.position.map.backup.json",
        "token.position.map.backups",
        "token.position.map.backups.json",
        "token_position_map_backup.json",
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
        "clientState.json",
        "clientStates.json",
        "client_state.bin",
        "client_states.bin",
        "clientStateBackup.json",
        "clientStateBackups.json",
        "client_state_backup.bin",
        "client_state_backups.bin",
        "clientStateCiphertext.json",
        "client_state_ciphertext.json",
        "client_state_ciphertext.bin",
        "clientStateSnapshot.json",
        "clientStateSnapshots.json",
        "client.state.snapshot",
        "client.state.snapshot.bin",
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
        "encrypted_client_state_ciphertext.json",
        "encrypted_client_state_ciphertext.bin",
        "encrypted_client_state_ciphertext_hash.bin",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes.bin",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256.bin",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256.bin",
        "encrypted_client_state_ciphertexts_sha256.json",
        "encryptedClientState.json",
        "encryptedClientStates.json",
        "encrypted.client.state",
        "encrypted.client.state.bin",
        "encrypted.client.state.snapshot",
        "encrypted.client.state.snapshot.bin",
        "encrypted_client_state.bin",
        "encrypted_client_states.bin",
        "encryptedClientStateBackup.json",
        "encryptedClientStateBackups.json",
        "encrypted_client_state_backup.bin",
        "encrypted_client_state_backups.bin",
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
        "state_ciphertext.json",
        "state_ciphertext_hash.json",
        "state_ciphertext_hashes.bin",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256.bin",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256.bin",
        "state_ciphertexts_sha256.json",
        "state_ciphertext.bin",
        "state_ciphertext_hash.bin",
    ];

    const PRIVATE_ORAM_CLIENT_STATE_REDACTION_STEMS: &[&str] = &[
        "stashBackup",
        "stashBackups",
        "stash_backup",
        "tokenMapBackup",
        "tokenMapBackups",
        "token.map.backup",
        "token.map.backups",
        "token_map_backup",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map.backup",
        "token.position.map.backups",
        "token_position_map_backup",
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
        "clientState",
        "clientStates",
        "client_state",
        "client_states",
        "clientStateBackup",
        "clientStateBackups",
        "client_state_backup",
        "client_state_backups",
        "clientStateCiphertext",
        "client_state_ciphertext",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client.state.snapshot",
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
        "encrypted_client_state_ciphertext",
        "encrypted_client_state",
        "encrypted.client.state",
        "encrypted.client.state.snapshot",
        "encrypted_client_states",
        "encryptedClientState",
        "encryptedClientStates",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encrypted_client_state_backup",
        "encrypted_client_state_backups",
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
    ];

    #[test]
    fn private_oram_automatic_transfer_recovery_requires_configured_stable_layout() {
        for &collection_name in PRIVATE_ORAM_CLIENT_STATE_COLLECTION_NAMES {
            validate_private_oram_automatic_transfer_recovery_layout(
                collection_name,
                3,
                false,
                false,
            )
            .unwrap();
            validate_private_oram_automatic_transfer_recovery_layout(
                collection_name,
                3,
                true,
                true,
            )
            .unwrap();

            let err = validate_private_oram_automatic_transfer_recovery_layout(
                collection_name,
                3,
                true,
                false,
            )
            .unwrap_err();
            let rendered = format!("{err:?}");
            assert!(rendered.contains("private ORAM collections"));
            assert!(rendered.contains("configured stable shard layout"));
            assert!(!rendered.contains(collection_name));
            for &leaked_alias in PRIVATE_ORAM_CLIENT_STATE_REDACTION_STEMS {
                assert!(!rendered.contains(leaked_alias), "{rendered}");
            }
            assert!(!rendered.contains("shard 3"));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
        }
    }

    #[test]
    fn private_oram_shard_layout_stability_accounts_for_custom_shard_keys() {
        let shard_ids = [0, 1, 2, 3].into_iter().collect::<BTreeSet<ShardId>>();
        assert!(private_oram_shard_layout_is_stable(
            ShardingMethod::Auto,
            4,
            &shard_ids,
            &[]
        ));
        assert!(!private_oram_shard_layout_is_stable(
            ShardingMethod::Auto,
            2,
            &shard_ids,
            &[]
        ));
        assert!(!private_oram_shard_layout_is_stable(
            ShardingMethod::Auto,
            4,
            &shard_ids,
            &[0]
        ));
        // Two shard keys with two shards each: every shard is reachable through the mapping,
        // even though the shard count is twice the configured shard number.
        assert!(private_oram_shard_layout_is_stable(
            ShardingMethod::Custom,
            2,
            &shard_ids,
            &[0, 1, 2, 3]
        ));
        assert!(!private_oram_shard_layout_is_stable(
            ShardingMethod::Custom,
            2,
            &shard_ids,
            &[0, 1]
        ));
        assert!(!private_oram_shard_layout_is_stable(
            ShardingMethod::Custom,
            2,
            &shard_ids,
            &[0, 1, 2, 9]
        ));
        assert!(!private_oram_shard_layout_is_stable(
            ShardingMethod::Custom,
            2,
            &BTreeSet::new(),
            &[]
        ));
    }

    #[test]
    fn private_oram_resharding_transfer_restart_preservation_is_source_and_marker_bounded() {
        let state = ReshardState::new(uuid::Uuid::nil(), ReshardingDirection::Up, 22, 9, None);
        let transfer = ShardTransfer {
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

        assert!(private_oram_resharding_transfer_requires_exact_restart(
            true,
            &transfer,
            Some(&state),
            transfer.from,
        ));
        assert!(!private_oram_resharding_transfer_requires_exact_restart(
            false,
            &transfer,
            Some(&state),
            transfer.from,
        ));
        assert!(!private_oram_resharding_transfer_requires_exact_restart(
            true,
            &transfer,
            Some(&state),
            transfer.to,
        ));
        assert!(!private_oram_resharding_transfer_requires_exact_restart(
            true,
            &ShardTransfer {
                private_oram_preinstalled: false,
                ..transfer.clone()
            },
            Some(&state),
            transfer.from,
        ));

        let mut advanced_state = state;
        advanced_state.stage = ReshardingStage::ReadHashRingCommitted;
        assert!(!private_oram_resharding_transfer_requires_exact_restart(
            true,
            &transfer,
            Some(&advanced_state),
            transfer.from,
        ));
    }

    #[test]
    fn private_oram_fixed_transfer_restart_preservation_is_target_and_state_bounded() {
        use crate::shards::transfer::{
            PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition,
        };

        let transfer = ShardTransfer {
            shard_id: 7,
            to_shard_id: None,
            from: 11,
            to: 22,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: "docs-id".to_string(),
                expected: PrivateOramTransferLayoutState {
                    generation: 7,
                    owner_peer_ids: vec![11],
                    layout_digest: "old-layout".to_string(),
                    index_state_digest: "index-state".to_string(),
                },
                new: PrivateOramTransferLayoutState {
                    generation: 8,
                    owner_peer_ids: vec![11, 22],
                    layout_digest: "new-layout".to_string(),
                    index_state_digest: "index-state".to_string(),
                },
                index_states: Vec::new(),
            }),
            filter: None,
        };

        assert!(private_oram_fixed_transfer_requires_exact_restart(
            true,
            &transfer,
            None,
            transfer.to,
            1,
            Some(ReplicaState::Active),
            Some(ReplicaState::Partial),
        ));
        for rejected in [
            private_oram_fixed_transfer_requires_exact_restart(
                false,
                &transfer,
                None,
                transfer.to,
                1,
                Some(ReplicaState::Active),
                Some(ReplicaState::Partial),
            ),
            private_oram_fixed_transfer_requires_exact_restart(
                true,
                &transfer,
                None,
                transfer.from,
                1,
                Some(ReplicaState::Active),
                Some(ReplicaState::Partial),
            ),
            private_oram_fixed_transfer_requires_exact_restart(
                true,
                &transfer,
                None,
                transfer.to,
                2,
                Some(ReplicaState::Active),
                Some(ReplicaState::Partial),
            ),
            private_oram_fixed_transfer_requires_exact_restart(
                true,
                &transfer,
                None,
                transfer.to,
                1,
                Some(ReplicaState::Active),
                Some(ReplicaState::Dead),
            ),
            private_oram_fixed_transfer_requires_exact_restart(
                true,
                &ShardTransfer {
                    private_oram_layout_transition: None,
                    ..transfer.clone()
                },
                None,
                transfer.to,
                1,
                Some(ReplicaState::Active),
                Some(ReplicaState::Partial),
            ),
        ] {
            assert!(!rejected);
        }
    }

    #[test]
    fn private_oram_resharding_resume_request_is_target_and_active_transfer_bounded() {
        let up = ReshardState::new(uuid::Uuid::nil(), ReshardingDirection::Up, 22, 9, None);
        let transfer = ShardTransfer {
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

        let request =
            private_oram_resharding_resume_request("docs", transfer.to, true, &transfer, Some(&up))
                .unwrap();
        assert_eq!(request.collection_name, "docs");
        assert_eq!(request.shard_id, transfer.shard_id);
        assert_eq!(request.to_shard_id, transfer.to_shard_id.unwrap());
        assert_eq!(request.source_peer_id, transfer.from);
        assert_eq!(request.target_peer_id, transfer.to);

        assert!(
            private_oram_resharding_resume_request(
                "docs",
                transfer.from,
                true,
                &transfer,
                Some(&up),
            )
            .is_none()
        );
        assert!(
            private_oram_resharding_resume_request(
                "docs",
                transfer.to,
                false,
                &transfer,
                Some(&up),
            )
            .is_none()
        );
        let unmarked = ShardTransfer {
            private_oram_preinstalled: false,
            ..transfer.clone()
        };
        assert!(
            private_oram_resharding_resume_request(
                "docs",
                transfer.to,
                true,
                &unmarked,
                Some(&up),
            )
            .is_none()
        );

        let down = ReshardState::new(
            uuid::Uuid::nil(),
            ReshardingDirection::Down,
            transfer.from,
            transfer.shard_id,
            None,
        );
        assert!(
            private_oram_resharding_resume_request(
                "docs",
                transfer.to,
                true,
                &transfer,
                Some(&down),
            )
            .is_some()
        );
    }

    #[test]
    fn private_oram_resharding_replica_state_guard_redacts_collection_details() {
        let up = ReshardState::new(
            uuid::Uuid::from_u128(42),
            ReshardingDirection::Up,
            7,
            3,
            None,
        );
        let down = ReshardState::new(
            uuid::Uuid::from_u128(43),
            ReshardingDirection::Down,
            7,
            3,
            None,
        );
        validate_private_oram_resharding_replica_state_until_supported(
            3,
            7,
            None,
            ReplicaState::Active,
            Some(ReplicaState::Partial),
            Some(ReplicaState::Partial),
            None,
            true,
        )
        .unwrap();
        validate_private_oram_resharding_replica_state_until_supported(
            3,
            7,
            None,
            ReplicaState::Active,
            Some(ReplicaState::Resharding),
            Some(ReplicaState::Resharding),
            None,
            false,
        )
        .unwrap();
        validate_private_oram_resharding_replica_state_until_supported(
            3,
            7,
            None,
            ReplicaState::Active,
            Some(ReplicaState::Resharding),
            Some(ReplicaState::Resharding),
            Some(&up),
            true,
        )
        .expect("exact scale-up target promotion must be allowed");
        validate_private_oram_resharding_replica_state_until_supported(
            2,
            9,
            None,
            ReplicaState::Active,
            Some(ReplicaState::ReshardingScaleDown),
            Some(ReplicaState::ReshardingScaleDown),
            Some(&down),
            true,
        )
        .expect("exact scale-down receiver promotion must be allowed");

        for state in [
            ReplicaState::Active,
            ReplicaState::Dead,
            ReplicaState::Partial,
            ReplicaState::Initializing,
            ReplicaState::Listener,
            ReplicaState::PartialSnapshot,
            ReplicaState::Recovery,
            ReplicaState::ActiveRead,
            ReplicaState::ManualRecovery,
        ] {
            validate_private_oram_resharding_replica_state_until_supported(
                3,
                7,
                None,
                state,
                Some(state),
                Some(state),
                None,
                true,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "private ORAM resharding replica-state guard must allow non-resharding state-only transition for {state:?}: {err}"
                )
            });
        }

        let mut committed_up = up.clone();
        committed_up.stage = ReshardingStage::ReadHashRingCommitted;
        for (shard_id, peer_id, new_state, from_state, current_state, state) in [
            (3, 7, ReplicaState::Resharding, None, None, Some(&up)),
            (
                3,
                7,
                ReplicaState::Active,
                Some(ReplicaState::Resharding),
                None,
                Some(&up),
            ),
            (
                3,
                9,
                ReplicaState::Active,
                Some(ReplicaState::Resharding),
                Some(ReplicaState::Resharding),
                Some(&up),
            ),
            (
                3,
                7,
                ReplicaState::Active,
                Some(ReplicaState::Resharding),
                Some(ReplicaState::Resharding),
                Some(&committed_up),
            ),
            (
                2,
                9,
                ReplicaState::Dead,
                None,
                Some(ReplicaState::ReshardingScaleDown),
                Some(&down),
            ),
        ] {
            let err = validate_private_oram_resharding_replica_state_until_supported(
                shard_id,
                peer_id,
                None,
                new_state,
                from_state,
                current_state,
                state,
                true,
            )
            .unwrap_err();
            let rendered = format!("{err:?}");

            assert!(rendered.contains("cannot change resharding replica state"));
            assert!(rendered.contains("exact active resharding promotion"));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            for &leaked_alias in PRIVATE_ORAM_CLIENT_STATE_REDACTION_STEMS {
                assert!(!rendered.contains(leaked_alias), "{rendered}");
            }
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
        }
    }

    #[cfg(unix)]
    #[test]
    fn client_payload_nonce_replay_cache_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);

        append_client_payload_nonce_replay_cache(&cache_path, &["nonce-a".to_string()]).unwrap();
        assert_eq!(
            std::fs::metadata(&cache_path).unwrap().permissions().mode() & 0o077,
            0,
        );

        let mut keys = VecDeque::new();
        keys.push_back("nonce-b".to_string());
        rewrite_client_payload_nonce_replay_cache(&cache_path, &keys).unwrap();
        assert_eq!(
            std::fs::metadata(&cache_path).unwrap().permissions().mode() & 0o077,
            0,
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_payload_nonce_replay_cache_load_rejects_group_world_accessible_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("nonce-replay-path-sentinel-")
            .tempdir()
            .unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        std::fs::write(
            &cache_path,
            "collection-uuid\x1ftenant-a/key\x1ftenant-a/rk\x1f1\x1fAAAAAAAAAAAAAAAA\n",
        )
        .unwrap();
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = ClientPayloadNonceReplayCache::load(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world accessible"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
    }

    #[cfg(unix)]
    #[test]
    fn client_payload_nonce_replay_cache_rejects_group_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("nonce-replay-path-sentinel-")
            .tempdir()
            .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);

        let err = ClientPayloadNonceReplayCache::load(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world writable"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);

        let err = append_client_payload_nonce_replay_cache(&cache_path, &["nonce-a".to_string()])
            .unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world writable"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);

        let mut keys = VecDeque::new();
        keys.push_back("nonce-b".to_string());
        let err = rewrite_client_payload_nonce_replay_cache(&cache_path, &keys).unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world writable"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
    }

    #[cfg(unix)]
    #[test]
    fn client_payload_nonce_replay_cache_rejects_group_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let writable_ancestor = dir.path().join("writable-ancestor");
        let collection_dir = writable_ancestor.join("collection");
        std::fs::create_dir(&writable_ancestor).unwrap();
        std::fs::create_dir(&collection_dir).unwrap();
        std::fs::set_permissions(&writable_ancestor, std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let cache_path = collection_dir.join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);

        let err = ClientPayloadNonceReplayCache::load(&collection_dir).unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world writable"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);

        let err = append_client_payload_nonce_replay_cache(&cache_path, &["nonce-a".to_string()])
            .unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world writable"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);

        let mut keys = VecDeque::new();
        keys.push_back("nonce-b".to_string());
        let err = rewrite_client_payload_nonce_replay_cache(&cache_path, &keys).unwrap_err();
        assert!(format!("{err:?}").contains("must not be group/world writable"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
    }

    #[cfg(unix)]
    #[test]
    fn client_payload_nonce_replay_cache_rejects_symlink_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);
        let target_path = dir.path().join("target");
        std::fs::write(&target_path, "target-before\n").unwrap();
        symlink(&target_path, &cache_path).unwrap();

        let err = ClientPayloadNonceReplayCache::load(dir.path()).unwrap_err();
        assert!(format!("{err:?}").contains("failed to open"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
        assert_eq!(
            std::fs::read_to_string(&target_path).unwrap(),
            "target-before\n"
        );

        let err = append_client_payload_nonce_replay_cache(&cache_path, &["nonce-a".to_string()])
            .unwrap_err();
        assert!(format!("{err:?}").contains("failed to open"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
        assert_eq!(
            std::fs::read_to_string(&target_path).unwrap(),
            "target-before\n"
        );

        std::fs::remove_file(&cache_path).unwrap();
        let temp_path = cache_path.with_extension("tmp");
        symlink(&target_path, &temp_path).unwrap();
        let mut keys = VecDeque::new();
        keys.push_back("nonce-b".to_string());
        let err = rewrite_client_payload_nonce_replay_cache(&cache_path, &keys).unwrap_err();
        assert!(format!("{err:?}").contains("failed to create"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
        assert_eq!(
            std::fs::read_to_string(&target_path).unwrap(),
            "target-before\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_payload_nonce_replay_cache_rejects_symlink_parent_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real-parent");
        let symlink_parent = dir.path().join("symlink-parent");
        std::fs::create_dir(&real_parent).unwrap();
        symlink(&real_parent, &symlink_parent).unwrap();
        let cache_path = symlink_parent.join(CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE);

        let err = ClientPayloadNonceReplayCache::load(&symlink_parent).unwrap_err();
        assert!(format!("{err:?}").contains("must be a regular directory"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);

        let err = append_client_payload_nonce_replay_cache(&cache_path, &["nonce-a".to_string()])
            .unwrap_err();
        assert!(format!("{err:?}").contains("must be a regular directory"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);

        let mut keys = VecDeque::new();
        keys.push_back("nonce-b".to_string());
        let err = rewrite_client_payload_nonce_replay_cache(&cache_path, &keys).unwrap_err();
        assert!(format!("{err:?}").contains("must be a regular directory"));
        assert_client_payload_nonce_replay_cache_error_redacts_paths(&err);
    }

    fn assert_client_payload_nonce_replay_cache_error_redacts_paths(err: &CollectionError) {
        let rendered = format!("{err:?}");
        for leaked in [
            "nonce-replay-path-sentinel",
            "writable-ancestor",
            "real-parent",
            "symlink-parent",
            "target",
            CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_FILE,
        ] {
            assert!(
                !rendered.contains(leaked),
                "client payload nonce replay cache error leaked path component {leaked}: {rendered}",
            );
        }
    }
}
