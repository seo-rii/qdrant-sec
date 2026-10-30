mod collection_container;
mod collection_meta_ops;
mod create_collection;
pub mod dispatcher;
mod point_ops;
mod point_ops_internal;
pub mod request_hw_counter;
mod snapshots;
mod telemetry;
mod temp_directories;
pub mod transfer;

use std::cmp::max;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use api::rest::models::HardwareUsage;
use collection::collection::{Collection, RequestShardTransfer};
use collection::collection_state;
use collection::config::{
    CollectionConfigInternal, default_replication_factor, default_shard_number,
};
use collection::operations::types::*;
use collection::shards::channel_service::ChannelService;
use collection::shards::replica_set::AbortShardTransfer;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::{PeerId, ShardId};
use collection::shards::{CollectionId, replica_set};
use common::budget::ResourceBudget;
use common::counter::hardware_accumulator::HwSharedDrain;
use common::cpu::get_num_cpus;
use common::fs::safe_delete_in_tmp;
use dashmap::DashMap;
use fs_err as fs;
use fs_err::tokio as tokio_fs;
use futures::{StreamExt, stream};
use parking_lot::Mutex as ParkingMutex;
use segment::data_types::collection_defaults::CollectionConfigDefaults;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};

use self::collection_meta_ops::collection_params_use_private_oram_bucket_store;
use self::dispatcher::TocDispatcher;
use crate::ConsensusOperations;
use crate::common::utils::try_unwrap_with_timeout_async;
use crate::content_manager::alias_mapping::AliasPersistence;
use crate::content_manager::collection_meta_ops::CreateCollectionOperation;
use crate::content_manager::collections_ops::{Checker, Collections};
use crate::content_manager::consensus::operation_sender::OperationSender;
use crate::content_manager::consensus_ops::{
    PrivateOramExternalRecoveryKey, PrivateOramExternalRecoveryLeasePhase,
    PrivateOramExternalRecoveryState, PrivateOramShardLayoutEntry,
    canonical_private_oram_shard_layout_digest, private_oram_index_keys_for_config,
};
use crate::content_manager::errors::StorageError;
use crate::content_manager::shard_distribution::ShardDistributionProposal;
use crate::content_manager::snapshots::private_oram_external_recovery::{
    PrivateOramExternalRecoveryArchiveResources, load_private_oram_external_recovery_reservations,
    private_oram_external_recovery_reservation_bytes,
};
use crate::content_manager::toc::telemetry::TocTelemetryCollector;
use crate::rbac::{Access, AccessRequirements, CollectionMultipass, CollectionPass};
use crate::types::{PrivateOramExternalRecoveryConfig, StorageConfig};

pub const ALIASES_PATH: &str = "aliases";
pub const COLLECTIONS_DIR: &str = "collections";
pub const FULL_SNAPSHOT_FILE_NAME: &str = "full-snapshot";
const CLIENT_PAYLOAD_NONCE_REPLAY_CACHE_CAPACITY: usize = 1_000_000;
const CLIENT_PAYLOAD_NONCE_REPLAY_ERROR: &str = "client encrypted payload nonce was already used in this collection; regenerate the client-side envelope with a fresh nonce before retrying";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_WRITE_FENCE_ERROR: &str =
    "collection writes are locked by private ORAM external recovery";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_FENCE_ERROR: &str =
    "collection is locked by private ORAM external recovery installation";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
const PRIVATE_ORAM_EXTERNAL_RECOVERY_DRAIN_INTERVAL: Duration = Duration::from_millis(50);

/// How long to wait till deleted collection is released from previous operations
pub const COLLECTION_DELETE_WAIT_TIMEOUT: Duration = Duration::from_secs(60 * 10); // 10 mins
pub const COLLECTION_DELETE_SPIN_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOramExternalRecoveryFence {
    Writes,
    All,
}

pub struct PrivateOramExternalRecoveryCollectionInstallGuard<'a> {
    toc: &'a TableOfContent,
    collection_name: String,
    collection_id: String,
    operation_id_hash: String,
    consensus_binding: PrivateOramExternalRecoveryInstallGuardConsensusBinding,
}

enum PrivateOramExternalRecoveryInstallGuardConsensusBinding {
    Active,
    Committed {
        backup_generation: u64,
        checkpoint_digest: String,
        install_intent_digest: String,
    },
}

#[derive(Clone)]
struct PrivateOramExternalRecoveryDetachedCollection {
    collection_id: String,
    operation_id_hash: String,
    state: collection_state::State,
}

struct PrivateOramExternalRecoveryResourceState {
    reservations: HashMap<String, u64>,
    reserved_bytes: u64,
}

struct PrivateOramExternalRecoveryResources {
    limits: PrivateOramExternalRecoveryConfig,
    state: ParkingMutex<PrivateOramExternalRecoveryResourceState>,
    workers: Arc<Semaphore>,
    preflight_scanned_logical_bytes: AtomicU64,
    preflight_scanned_entries: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateOramExternalRecoveryResourceSnapshot {
    pub reserved_bytes: u64,
    pub staging_reservations: u64,
    pub worker_limit: u64,
    pub workers_in_use: u64,
    pub preflight_scanned_logical_bytes: u64,
    pub preflight_scanned_entries: u64,
}

pub struct PrivateOramExternalRecoveryReservation {
    resources: Arc<PrivateOramExternalRecoveryResources>,
    operation_id_hash: String,
    persistent: bool,
}

impl PrivateOramExternalRecoveryReservation {
    pub fn persist(mut self) {
        self.persistent = true;
    }
}

impl Drop for PrivateOramExternalRecoveryReservation {
    fn drop(&mut self) {
        if !self.persistent {
            self.resources.release(&self.operation_id_hash);
        }
    }
}

impl PrivateOramExternalRecoveryResources {
    fn new(
        limits: PrivateOramExternalRecoveryConfig,
        reservations: HashMap<String, u64>,
    ) -> Result<Self, StorageError> {
        let reserved_bytes = reservations.values().try_fold(0_u64, |total, reserved| {
            total
                .checked_add(*reserved)
                .ok_or_else(invalid_private_oram_external_recovery_resource_state)
        })?;
        Ok(Self {
            workers: Arc::new(Semaphore::new(limits.max_concurrent_verify_prepare.get())),
            limits,
            state: ParkingMutex::new(PrivateOramExternalRecoveryResourceState {
                reservations,
                reserved_bytes,
            }),
            preflight_scanned_logical_bytes: AtomicU64::new(0),
            preflight_scanned_entries: AtomicU64::new(0),
        })
    }

    fn reserve(
        self: &Arc<Self>,
        operation_id_hash: &str,
        snapshot_size_bytes: u64,
    ) -> Result<PrivateOramExternalRecoveryReservation, StorageError> {
        let reserved =
            private_oram_external_recovery_reservation_bytes(snapshot_size_bytes, &self.limits)?;
        let mut state = self.state.lock();
        if state.reservations.contains_key(operation_id_hash) {
            return Err(invalid_private_oram_external_recovery_resource_state());
        }
        let next_total = state
            .reserved_bytes
            .checked_add(reserved)
            .ok_or_else(invalid_private_oram_external_recovery_resource_state)?;
        if next_total > self.limits.max_total_staged_bytes {
            return Err(StorageError::bad_request(
                "private ORAM external recovery staging quota exceeded",
            ));
        }
        state
            .reservations
            .insert(operation_id_hash.to_string(), reserved);
        state.reserved_bytes = next_total;
        Ok(PrivateOramExternalRecoveryReservation {
            resources: Arc::clone(self),
            operation_id_hash: operation_id_hash.to_string(),
            persistent: false,
        })
    }

    fn release(&self, operation_id_hash: &str) {
        let mut state = self.state.lock();
        if let Some(reserved) = state.reservations.remove(operation_id_hash) {
            state.reserved_bytes = state.reserved_bytes.saturating_sub(reserved);
        }
    }

    fn record_archive_scan(&self, resources: PrivateOramExternalRecoveryArchiveResources) {
        saturating_atomic_add(
            &self.preflight_scanned_logical_bytes,
            resources.logical_bytes,
        );
        saturating_atomic_add(&self.preflight_scanned_entries, resources.entry_count);
    }

    fn snapshot(&self) -> PrivateOramExternalRecoveryResourceSnapshot {
        let state = self.state.lock();
        let worker_limit = self.limits.max_concurrent_verify_prepare.get();
        PrivateOramExternalRecoveryResourceSnapshot {
            reserved_bytes: state.reserved_bytes,
            staging_reservations: state.reservations.len() as u64,
            worker_limit: worker_limit as u64,
            workers_in_use: worker_limit.saturating_sub(self.workers.available_permits()) as u64,
            preflight_scanned_logical_bytes: self
                .preflight_scanned_logical_bytes
                .load(Ordering::Relaxed),
            preflight_scanned_entries: self.preflight_scanned_entries.load(Ordering::Relaxed),
        }
    }
}

fn saturating_atomic_add(target: &AtomicU64, value: u64) {
    let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

impl fmt::Debug for PrivateOramExternalRecoveryDetachedCollection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryDetachedCollection")
            .field("collection_id", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .field("state", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for PrivateOramExternalRecoveryCollectionInstallGuard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryCollectionInstallGuard")
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .finish()
    }
}

/// The main object of the service. It holds all objects, required for proper functioning.
///
/// In most cases only one `TableOfContent` is enough for service. It is created only once during
/// the launch of the service.
pub struct TableOfContent {
    collections: Arc<RwLock<Collections>>,
    pub(crate) storage_config: Arc<StorageConfig>,
    search_runtime: Runtime,
    update_runtime: Runtime,
    general_runtime: Runtime,
    /// Global CPU budget in number of cores for all optimization tasks.
    /// Assigns CPU permits to tasks to limit overall resource utilization.
    optimizer_resource_budget: ResourceBudget,
    alias_persistence: RwLock<AliasPersistence>,
    pub this_peer_id: PeerId,
    channel_service: ChannelService,
    /// Backlink to the consensus, if none - single node mode
    consensus_proposal_sender: Option<OperationSender>,
    /// Dispatcher for access to table of contents and consensus, if none - single node mode
    toc_dispatcher: parking_lot::Mutex<Option<TocDispatcher>>,
    /// Prevent DDoS of too many concurrent updates in distributed mode.
    /// One external update usually triggers multiple internal updates, which breaks internal
    /// timings. For example, the health check timing and consensus timing.
    ///
    /// If not defined - no rate limiting is applied.
    update_rate_limiter: Option<Semaphore>,
    /// Serializes collection registry, path, and alias lifecycle changes.
    collection_lifecycle_lock: Arc<Mutex<()>>,
    private_oram_external_recovery_detached:
        DashMap<CollectionId, PrivateOramExternalRecoveryDetachedCollection>,
    private_oram_external_recovery_resources: Arc<PrivateOramExternalRecoveryResources>,
    /// Aggregation of all hardware measurements for each alias or collection config.
    collection_hw_metrics: DashMap<CollectionId, Arc<HwSharedDrain>>,
    client_payload_nonce_replay_cache: Mutex<ClientPayloadNonceReplayCache>,
    private_oram_snapshot_recovery_abort_requests: Mutex<HashMap<CollectionId, Instant>>,
    private_oram_snapshot_recovery_resume_requests: Arc<Mutex<HashSet<CollectionId>>>,
    /// Collector for various telemetry/metrics.
    telemetry: TocTelemetryCollector,
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
    fn record(&mut self, keys: impl IntoIterator<Item = String>) -> Result<bool, StorageError> {
        let mut batch_seen = HashSet::new();
        let mut pending = Vec::new();

        for key in keys {
            let mut parts = key.split('\x1f');
            let collection_crypto_id = parts.next();
            let key_id = parts.next();
            let rk_id = parts.next();
            let rk_epoch = parts.next();
            let nonce = parts.next();
            let valid_nonce = nonce.is_some_and(|nonce| {
                nonce.len() == 16
                    && nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            });
            if parts.next().is_some()
                || collection_crypto_id.is_none_or(str::is_empty)
                || key_id.is_none_or(str::is_empty)
                || rk_id.is_none_or(str::is_empty)
                || rk_epoch.is_none_or(str::is_empty)
                || rk_epoch.is_some_and(|epoch| epoch.parse::<u64>().is_err())
                || !valid_nonce
            {
                return Err(StorageError::bad_input(
                    "client encrypted payload nonce replay cache key is invalid".to_string(),
                ));
            }
            if self.seen.contains(&key) || !batch_seen.insert(key.clone()) {
                return Ok(false);
            }
            pending.push(key);
        }

        for key in pending {
            if self.seen.insert(key.clone()) {
                self.order.push_back(key);
            }
        }

        while self.seen.len() > self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.seen.remove(&oldest);
        }

        Ok(true)
    }
}

impl TableOfContent {
    /// PeerId does not change during execution so it is ok to copy it here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage_config: &StorageConfig,
        search_runtime: Runtime,
        update_runtime: Runtime,
        general_runtime: Runtime,
        optimizer_resource_budget: ResourceBudget,
        channel_service: ChannelService,
        this_peer_id: PeerId,
        consensus_proposal_sender: Option<OperationSender>,
    ) -> Result<Self, StorageError> {
        let collections_path = storage_config.storage_path.join(COLLECTIONS_DIR);
        fs::create_dir_all(&collections_path)?;
        if let Some(path) = storage_config.temp_path.as_deref() {
            fs::create_dir_all(path)?;
        }
        let collection_paths = fs::read_dir(&collections_path)?;
        let is_distributed = consensus_proposal_sender.is_some();

        // Collect valid collection paths for loading
        let mut collection_load_tasks = Vec::new();
        for entry in collection_paths {
            let collection_path = entry?.path();

            if !CollectionConfigInternal::check(&collection_path) {
                log::warn!(
                    "Collection config is not found in the collection directory: {}, skipping",
                    collection_path.display(),
                );
                continue;
            }

            let collection_name = collection_path
                .file_name()
                .ok_or_else(|| {
                    StorageError::service_error(format!(
                        "Can't resolve collection directory filename: {}",
                        collection_path.display(),
                    ))
                })?
                .to_str()
                .ok_or_else(|| {
                    StorageError::service_error(format!(
                        "Collection directory filename is not valid UTF-8: {}",
                        collection_path.display(),
                    ))
                })?
                .to_string();

            let collection_snapshots_path =
                Self::collection_snapshots_path(&storage_config.snapshots_path, &collection_name);

            let consensus_proposal_sender = consensus_proposal_sender.clone();
            let channel_service = channel_service.clone();
            let storage_config = storage_config.clone();
            let search_runtime_handle = search_runtime.handle().clone();
            let update_runtime_handle = update_runtime.handle().clone();
            let optimizer_resource_budget = optimizer_resource_budget.clone();

            collection_load_tasks.push(async move {
                log::info!("Loading collection: {collection_name}");
                let collection = Collection::load(
                    collection_name.clone(),
                    this_peer_id,
                    &collection_path,
                    &collection_snapshots_path,
                    storage_config
                        .to_shared_storage_config(is_distributed)
                        .into(),
                    channel_service,
                    Self::change_peer_from_state_callback(
                        consensus_proposal_sender.clone(),
                        collection_name.clone(),
                        ReplicaState::Dead,
                    ),
                    Self::request_shard_transfer_callback(
                        consensus_proposal_sender.clone(),
                        collection_name.clone(),
                    ),
                    Self::abort_shard_transfer_callback(
                        consensus_proposal_sender.clone(),
                        collection_name.clone(),
                    ),
                    Some(search_runtime_handle),
                    Some(update_runtime_handle),
                    optimizer_resource_budget,
                    storage_config.optimizers_overwrite.clone(),
                )
                .await;
                (collection_name.clone(), collection)
            });
        }

        // Load collections with specified concurrency
        let mut collection_stream = stream::iter(collection_load_tasks).buffer_unordered(
            storage_config
                .performance
                .load_concurrency
                .get_concurrent_collections()
                .get(),
        );

        let mut collections: HashMap<String, Arc<Collection>> = Default::default();
        general_runtime.block_on(async {
            while let Some((collection_name, collection)) = collection_stream.next().await {
                match collection {
                    Ok(collection) => {
                        collections.insert(collection_name, Arc::new(collection));
                    }
                    Err(err) => {
                        log::error!("Failed to load collection {collection_name}: {err}");
                    }
                }
            }
        });

        // Initialize snapshot telemetry for all loaded collections.
        let telemetry = TocTelemetryCollector::default();
        for collection_name in collections.keys() {
            telemetry.init_snapshot_telemetry(collection_name);
        }

        let alias_path = storage_config.storage_path.join(ALIASES_PATH);
        let alias_persistence = AliasPersistence::open(&alias_path)?;

        let private_oram_external_recovery_reservations =
            load_private_oram_external_recovery_reservations(
                &storage_config.storage_path,
                &storage_config.private_oram_external_recovery,
            )?;
        let private_oram_external_recovery_resources =
            Arc::new(PrivateOramExternalRecoveryResources::new(
                storage_config.private_oram_external_recovery.clone(),
                private_oram_external_recovery_reservations,
            )?);

        let rate_limiter = match storage_config.performance.update_rate_limit {
            Some(limit) => Some(Semaphore::new(limit)),
            None => {
                if consensus_proposal_sender.is_some() {
                    // Auto adjust the rate limit in distributed mode.
                    // Select number of working threads as a guess.
                    let limit = max(get_num_cpus(), 2);
                    log::debug!(
                        "Auto adjusting update rate limit to {limit} parallel update requests"
                    );
                    Some(Semaphore::new(limit))
                } else {
                    None
                }
            }
        };

        Ok(TableOfContent {
            collections: Arc::new(RwLock::new(collections)),
            storage_config: Arc::new(storage_config.clone()),
            search_runtime,
            update_runtime,
            general_runtime,
            optimizer_resource_budget,
            alias_persistence: RwLock::new(alias_persistence),
            this_peer_id,
            channel_service,
            consensus_proposal_sender,
            toc_dispatcher: Default::default(),
            update_rate_limiter: rate_limiter,
            collection_lifecycle_lock: Default::default(),
            private_oram_external_recovery_detached: Default::default(),
            private_oram_external_recovery_resources,
            collection_hw_metrics: DashMap::new(),
            client_payload_nonce_replay_cache: Mutex::new(ClientPayloadNonceReplayCache::default()),
            private_oram_snapshot_recovery_abort_requests: Default::default(),
            private_oram_snapshot_recovery_resume_requests: Default::default(),
            telemetry,
        })
    }

    pub async fn record_client_payload_nonce_replay_keys(
        &self,
        collection_crypto_scope: &str,
        keys: impl IntoIterator<Item = String>,
    ) -> Result<(), StorageError> {
        let scoped_keys = keys
            .into_iter()
            .map(|key| format!("{collection_crypto_scope}\x1f{key}"))
            .collect::<Vec<_>>();
        if scoped_keys.is_empty() {
            return Ok(());
        }

        let mut cache = self.client_payload_nonce_replay_cache.lock().await;
        if !cache.record(scoped_keys)? {
            return Err(StorageError::bad_input(
                CLIENT_PAYLOAD_NONCE_REPLAY_ERROR.to_string(),
            ));
        }

        Ok(())
    }

    /// Return `true` if service is working in distributed mode.
    pub fn is_distributed(&self) -> bool {
        self.consensus_proposal_sender.is_some()
    }

    pub fn storage_path(&self) -> &Path {
        &self.storage_config.storage_path
    }

    pub fn private_oram_external_recovery_limits(&self) -> &PrivateOramExternalRecoveryConfig {
        &self.private_oram_external_recovery_resources.limits
    }

    pub fn reserve_private_oram_external_recovery(
        &self,
        operation_id_hash: &str,
        snapshot_size_bytes: u64,
    ) -> Result<PrivateOramExternalRecoveryReservation, StorageError> {
        self.private_oram_external_recovery_resources
            .reserve(operation_id_hash, snapshot_size_bytes)
    }

    pub fn release_private_oram_external_recovery(&self, operation_id_hash: &str) {
        self.private_oram_external_recovery_resources
            .release(operation_id_hash);
    }

    pub fn try_acquire_private_oram_external_recovery_worker(
        &self,
    ) -> Result<OwnedSemaphorePermit, StorageError> {
        Arc::clone(&self.private_oram_external_recovery_resources.workers)
            .try_acquire_owned()
            .map_err(|_| {
                StorageError::rate_limit_exceeded(
                    "private ORAM external recovery verify/install worker limit reached",
                    Some(Duration::from_secs(1)),
                )
            })
    }

    pub fn record_private_oram_external_recovery_archive_scan(
        &self,
        resources: PrivateOramExternalRecoveryArchiveResources,
    ) {
        self.private_oram_external_recovery_resources
            .record_archive_scan(resources);
    }

    pub fn private_oram_external_recovery_resource_snapshot(
        &self,
    ) -> PrivateOramExternalRecoveryResourceSnapshot {
        self.private_oram_external_recovery_resources.snapshot()
    }

    /// List of all collections to which the user has access
    pub async fn all_collections(&self, access: &Access) -> Vec<CollectionPass<'static>> {
        self.all_collections_with_access_requirements(access, AccessRequirements::new())
            .await
    }

    pub async fn all_collections_access(&self, access: &Access) -> Vec<CollectionPass<'static>> {
        self.all_collections_with_access_requirements(access, AccessRequirements::new())
            .await
    }

    pub async fn multipass_into_collections(
        &self,
        multipass: &CollectionMultipass,
    ) -> Vec<CollectionPass<'static>> {
        self.collection_names_including_detached()
            .await
            .into_iter()
            .map(|name| multipass.issue_pass(&name).into_static())
            .collect()
    }

    async fn all_collections_with_access_requirements(
        &self,
        access: &Access,
        access_requirements: AccessRequirements,
    ) -> Vec<CollectionPass<'static>> {
        self.collection_names_including_detached()
            .await
            .into_iter()
            .filter_map(|name| {
                access
                    .check_collection_access(&name, access_requirements)
                    .ok()
                    .map(|pass| pass.into_static())
            })
            .collect()
    }

    /// List of all collections
    pub fn all_collections_sync(&self) -> Vec<String> {
        self.general_runtime
            .block_on(self.collection_names_including_detached())
    }

    pub fn private_oram_external_recovery_collection_is_loaded(
        &self,
        collection_name: &str,
        collection_id: &str,
        expected_layout_digest: &str,
    ) -> Result<bool, StorageError> {
        self.general_runtime.block_on(async {
            let collection = self.collections.read().await.get(collection_name).cloned();
            let Some(collection) = collection else {
                return Ok(false);
            };
            let config = collection.config_snapshot().await;
            if collection.name() != collection_name
                || config.stable_crypto_id(collection_name)? != collection_id
                || private_oram_index_keys_for_config(&config, collection_name)?.is_empty()
            {
                return Ok(false);
            }
            let state = collection.state().await;
            if state.resharding.is_some() || !state.transfers.is_empty() || state.shards.is_empty()
            {
                return Ok(false);
            }
            let mut entries = Vec::with_capacity(state.shards.len());
            for (shard_id, shard) in &state.shards {
                if shard.replicas.is_empty()
                    || shard
                        .replicas
                        .values()
                        .any(|replica_state| *replica_state != ReplicaState::Active)
                {
                    return Ok(false);
                }
                entries.push(PrivateOramShardLayoutEntry {
                    shard_id: *shard_id,
                    shard_key: state.shards_key_mapping.shard_key(*shard_id),
                    owner_peer_ids: shard.replicas.keys().copied().collect(),
                });
            }
            let (_, layout_digest) = canonical_private_oram_shard_layout_digest(
                collection_id,
                config.params.sharding_method.unwrap_or_default(),
                &entries,
            )?;
            Ok(layout_digest == expected_layout_digest)
        })
    }

    async fn collection_names_including_detached(&self) -> Vec<String> {
        let collections = self.collections.read().await;
        let mut names: Vec<_> = collections.keys().cloned().collect();
        for detached in &self.private_oram_external_recovery_detached {
            if !collections.contains_key(detached.key()) {
                names.push(detached.key().clone());
            }
        }
        names.sort();
        names.dedup();
        names
    }

    pub(crate) fn private_oram_external_recovery_collection_is_detached(
        &self,
        collection_name: &str,
    ) -> bool {
        self.private_oram_external_recovery_detached
            .contains_key(collection_name)
    }

    async fn require_no_private_oram_external_recovery_lookup_fence(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, StorageError> {
        let lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        if !self.private_oram_external_recovery_detached.is_empty() {
            return Err(StorageError::Locked {
                description: PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_FENCE_ERROR.to_string(),
            });
        }
        let collections: Vec<_> = self.collections.read().await.values().cloned().collect();
        for collection in collections {
            if self
                .private_oram_external_recovery_fence(&collection)
                .await?
                == Some(PrivateOramExternalRecoveryFence::All)
            {
                return Err(StorageError::Locked {
                    description: PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_FENCE_ERROR.to_string(),
                });
            }
        }
        Ok(lifecycle_guard)
    }

    pub fn private_oram_external_recovery_detached_state(
        &self,
        collection_name: &str,
        operation_id_hash: &str,
    ) -> Option<(String, collection_state::State)> {
        self.private_oram_external_recovery_detached
            .get(collection_name)
            .filter(|detached| detached.operation_id_hash == operation_id_hash)
            .map(|detached| (detached.collection_id.clone(), detached.state.clone()))
    }

    /// Same as `get_collection`, but does not check access rights.
    /// Intended for internal use only.
    ///
    /// **Do no make public**
    async fn get_collection_unchecked(
        &self,
        collection_name: &str,
    ) -> Result<Arc<Collection>, StorageError> {
        let (_, collection) = self.get_collection_unfenced(collection_name).await?;
        self.require_private_oram_external_recovery_read_allowed(&collection)
            .await?;
        Ok(collection)
    }

    async fn get_collection_unfenced(
        &self,
        collection_name: &str,
    ) -> Result<(String, Arc<Collection>), StorageError> {
        let read_collection = self.collections.read().await;

        let real_collection_name = {
            let alias_persistence = self.alias_persistence.read().await;
            Self::resolve_name(collection_name, &alias_persistence)
        };

        if let Some(collection) = read_collection.get(&real_collection_name).cloned() {
            return Ok((real_collection_name, collection));
        }
        if self
            .private_oram_external_recovery_detached
            .contains_key(&real_collection_name)
        {
            return Err(StorageError::Locked {
                description: PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_FENCE_ERROR.to_string(),
            });
        }
        Err(StorageError::NotFound {
            description: format!("Collection `{collection_name}` doesn't exist!"),
        })
    }

    async fn private_oram_external_recovery_fence(
        &self,
        collection: &Collection,
    ) -> Result<Option<PrivateOramExternalRecoveryFence>, StorageError> {
        let Some(dispatcher) = self.toc_dispatcher.lock().clone() else {
            return Ok(None);
        };
        let config = collection.config_snapshot().await;
        if private_oram_index_keys_for_config(&config, collection.name())?.is_empty() {
            return Ok(None);
        }
        let key = PrivateOramExternalRecoveryKey {
            collection_id: config.stable_crypto_id(collection.name())?,
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default();
        Ok(private_oram_external_recovery_fence(
            dispatcher
                .consensus_state()
                .private_oram_external_recovery(&key)
                .as_ref(),
            now_unix,
        ))
    }

    async fn require_private_oram_external_recovery_read_allowed(
        &self,
        collection: &Collection,
    ) -> Result<(), StorageError> {
        if self
            .private_oram_external_recovery_fence(collection)
            .await?
            == Some(PrivateOramExternalRecoveryFence::All)
        {
            return Err(StorageError::Locked {
                description: PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_FENCE_ERROR.to_string(),
            });
        }
        Ok(())
    }

    pub async fn require_private_oram_external_recovery_write_allowed(
        &self,
        collection: &Collection,
    ) -> Result<(), StorageError> {
        match self
            .private_oram_external_recovery_fence(collection)
            .await?
        {
            Some(PrivateOramExternalRecoveryFence::Writes) => Err(StorageError::Locked {
                description: PRIVATE_ORAM_EXTERNAL_RECOVERY_WRITE_FENCE_ERROR.to_string(),
            }),
            Some(PrivateOramExternalRecoveryFence::All) => Err(StorageError::Locked {
                description: PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_FENCE_ERROR.to_string(),
            }),
            None => Ok(()),
        }
    }

    pub async fn acquire_private_oram_external_recovery_install_guard(
        &self,
        collection_name: &str,
        collection_id: &str,
        operation_id_hash: &str,
    ) -> Result<PrivateOramExternalRecoveryCollectionInstallGuard<'_>, StorageError> {
        let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        if self
            .private_oram_external_recovery_detached
            .get(collection_name)
            .is_some_and(|detached| {
                detached.collection_id == collection_id
                    && detached.operation_id_hash == operation_id_hash
            })
        {
            self.validate_private_oram_external_recovery_consensus_binding(
                collection_id,
                operation_id_hash,
            )?;
            return Ok(PrivateOramExternalRecoveryCollectionInstallGuard {
                toc: self,
                collection_name: collection_name.to_string(),
                collection_id: collection_id.to_string(),
                operation_id_hash: operation_id_hash.to_string(),
                consensus_binding: PrivateOramExternalRecoveryInstallGuardConsensusBinding::Active,
            });
        }
        let (resolved_name, collection) = self.get_collection_unfenced(collection_name).await?;
        if resolved_name != collection_name || collection.name() != collection_name {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        self.validate_private_oram_external_recovery_active_binding(
            &collection,
            collection_id,
            operation_id_hash,
        )
        .await?;
        drop(collection);

        Ok(PrivateOramExternalRecoveryCollectionInstallGuard {
            toc: self,
            collection_name: collection_name.to_string(),
            collection_id: collection_id.to_string(),
            operation_id_hash: operation_id_hash.to_string(),
            consensus_binding: PrivateOramExternalRecoveryInstallGuardConsensusBinding::Active,
        })
    }

    pub async fn acquire_committed_private_oram_external_recovery_install_guard(
        &self,
        collection_name: &str,
        collection_id: &str,
        operation_id_hash: &str,
        backup_generation: u64,
        checkpoint_digest: &str,
        install_intent_digest: &str,
    ) -> Result<PrivateOramExternalRecoveryCollectionInstallGuard<'_>, StorageError> {
        let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        let matching_tombstone = self
            .private_oram_external_recovery_detached
            .get(collection_name)
            .is_some_and(|detached| {
                detached.collection_id == collection_id
                    && detached.operation_id_hash == operation_id_hash
            });
        if !matching_tombstone {
            let (resolved_name, collection) = self.get_collection_unfenced(collection_name).await?;
            if resolved_name != collection_name || collection.name() != collection_name {
                return Err(invalid_private_oram_external_recovery_collection_state());
            }
            let config = collection.config_snapshot().await;
            if config.stable_crypto_id(collection_name)? != collection_id
                || private_oram_index_keys_for_config(&config, collection_name)?.is_empty()
            {
                return Err(invalid_private_oram_external_recovery_collection_state());
            }
        }
        self.validate_private_oram_external_recovery_committed_binding(
            collection_id,
            backup_generation,
            checkpoint_digest,
            install_intent_digest,
        )?;
        Ok(PrivateOramExternalRecoveryCollectionInstallGuard {
            toc: self,
            collection_name: collection_name.to_string(),
            collection_id: collection_id.to_string(),
            operation_id_hash: operation_id_hash.to_string(),
            consensus_binding: PrivateOramExternalRecoveryInstallGuardConsensusBinding::Committed {
                backup_generation,
                checkpoint_digest: checkpoint_digest.to_string(),
                install_intent_digest: install_intent_digest.to_string(),
            },
        })
    }

    async fn validate_private_oram_external_recovery_active_binding(
        &self,
        collection: &Collection,
        collection_id: &str,
        operation_id_hash: &str,
    ) -> Result<PrivateOramExternalRecoveryState, StorageError> {
        let config = collection.config_snapshot().await;
        if collection.name().is_empty()
            || config.stable_crypto_id(collection.name())? != collection_id
            || private_oram_index_keys_for_config(&config, collection.name())?.is_empty()
        {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        self.validate_private_oram_external_recovery_consensus_binding(
            collection_id,
            operation_id_hash,
        )
    }

    fn validate_private_oram_external_recovery_consensus_binding(
        &self,
        collection_id: &str,
        operation_id_hash: &str,
    ) -> Result<PrivateOramExternalRecoveryState, StorageError> {
        let dispatcher = self
            .toc_dispatcher
            .lock()
            .clone()
            .ok_or_else(invalid_private_oram_external_recovery_collection_state)?;
        let state = dispatcher
            .consensus_state()
            .private_oram_external_recovery(&PrivateOramExternalRecoveryKey {
                collection_id: collection_id.to_string(),
            })
            .ok_or_else(invalid_private_oram_external_recovery_collection_state)?;
        let lease = state
            .active_lease
            .as_ref()
            .ok_or_else(invalid_private_oram_external_recovery_collection_state)?;
        if lease.owner_peer_id != self.this_peer_id
            || lease.operation_id_hash != operation_id_hash
            || !matches!(
                lease.phase,
                PrivateOramExternalRecoveryLeasePhase::Staging
                    | PrivateOramExternalRecoveryLeasePhase::Installing
            )
        {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        Ok(state)
    }

    fn validate_private_oram_external_recovery_committed_binding(
        &self,
        collection_id: &str,
        backup_generation: u64,
        checkpoint_digest: &str,
        install_intent_digest: &str,
    ) -> Result<PrivateOramExternalRecoveryState, StorageError> {
        let dispatcher = self
            .toc_dispatcher
            .lock()
            .clone()
            .ok_or_else(invalid_private_oram_external_recovery_collection_state)?;
        let state = dispatcher
            .consensus_state()
            .private_oram_external_recovery(&PrivateOramExternalRecoveryKey {
                collection_id: collection_id.to_string(),
            })
            .ok_or_else(invalid_private_oram_external_recovery_collection_state)?;
        if state.committed_backup_generation != backup_generation
            || state.committed_checkpoint_digest.as_deref() != Some(checkpoint_digest)
            || state.committed_install_intent_digest.as_deref() != Some(install_intent_digest)
            || state.active_lease.is_some()
        {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        Ok(state)
    }

    pub async fn get_collection(
        &self,
        collection: &CollectionPass<'_>,
    ) -> Result<Arc<Collection>, StorageError> {
        self.get_collection_unchecked(collection.name()).await
    }

    pub async fn get_collection_for_private_oram_external_recovery(
        &self,
        collection: &CollectionPass<'_>,
        operation_id_hash: &str,
    ) -> Result<Arc<Collection>, StorageError> {
        let (resolved_name, resolved_collection) =
            self.get_collection_unfenced(collection.name()).await?;
        if resolved_name != collection.name() || resolved_collection.name() != collection.name() {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        let config = resolved_collection.config_snapshot().await;
        let collection_id = config.stable_crypto_id(collection.name())?;
        self.validate_private_oram_external_recovery_active_binding(
            &resolved_collection,
            &collection_id,
            operation_id_hash,
        )
        .await?;
        Ok(resolved_collection)
    }

    async fn get_collection_opt(&self, collection_name: String) -> Option<Arc<Collection>> {
        self.get_collection_unchecked(&collection_name).await.ok()
    }

    /// Finds the original name of the collection
    ///
    /// # Arguments
    ///
    /// * `collection_name` - Name of the collection or alias to resolve
    /// * `aliases` - A reference to the aliases storage
    ///
    /// # Result
    ///
    /// If the collection exists - return its name
    /// If alias exists - returns the original collection name
    /// If neither exists - returns [`StorageError`]
    fn resolve_name(collection_name: &str, aliases: &AliasPersistence) -> String {
        let alias_collection_name = aliases.get(collection_name);

        match alias_collection_name {
            None => collection_name.to_string(),
            Some(resolved_alias) => resolved_alias,
        }
    }

    pub async fn all_collection_aliases(
        &self,
        collection_name: &str,
        _multipass: &CollectionMultipass,
    ) -> Vec<String> {
        self.alias_persistence
            .read()
            .await
            .collection_aliases(collection_name)
    }

    /// List of all aliases for a given collection
    pub async fn collection_aliases(
        &self,
        collection_pass: &CollectionPass<'_>,
        access: &Access,
    ) -> Result<Vec<String>, StorageError> {
        let mut result = self
            .alias_persistence
            .read()
            .await
            .collection_aliases(collection_pass.name());
        result.retain(|alias| {
            access
                .check_collection_access(alias, AccessRequirements::new())
                .is_ok()
        });
        Ok(result)
    }

    /// List of all aliases across all collections
    pub async fn list_aliases(
        &self,
        access: &Access,
    ) -> Result<Vec<AliasDescription>, StorageError> {
        let all_collections = self.all_collections(access).await;
        let mut aliases: Vec<AliasDescription> = Default::default();
        for collection_pass in &all_collections {
            for alias in self.collection_aliases(collection_pass, access).await? {
                aliases.push(AliasDescription {
                    alias_name: alias.clone(),
                    collection_name: collection_pass.to_string(),
                });
            }
        }

        Ok(aliases)
    }

    pub fn suggest_shard_distribution(
        &self,
        op: &CreateCollectionOperation,
        collection_defaults: Option<&CollectionConfigDefaults>,
        number_of_peers: usize,
    ) -> ShardDistributionProposal {
        let number_of_peers = u32::try_from(number_of_peers).unwrap_or(u32::MAX);
        let non_zero_number_of_peers = NonZeroU32::new(number_of_peers).unwrap_or(NonZeroU32::MIN);

        let suggested_shard_number = collection_defaults
            .map(|cd| cd.get_shard_number(number_of_peers))
            .map(|x| NonZeroU32::new(x).unwrap_or_else(default_shard_number))
            .unwrap_or_else(|| default_shard_number().saturating_mul(non_zero_number_of_peers));

        let shard_number = op
            .create_collection
            .shard_number
            .and_then(NonZeroU32::new)
            .unwrap_or(suggested_shard_number);

        let mut known_peers_set: HashSet<_> = self
            .channel_service
            .id_to_address
            .read()
            .keys()
            .copied()
            .collect();
        known_peers_set.insert(self.this_peer_id());
        let known_peers: Vec<_> = known_peers_set.into_iter().collect();

        let suggested_replication_factor = collection_defaults
            .and_then(|cd| cd.replication_factor)
            .and_then(NonZeroU32::new)
            .unwrap_or_else(default_replication_factor);

        let replication_factor = op
            .create_collection
            .replication_factor
            .and_then(NonZeroU32::new)
            .unwrap_or(suggested_replication_factor);

        let shard_distribution =
            ShardDistributionProposal::new(shard_number, replication_factor, &known_peers);

        log::debug!(
            "Suggesting distribution for {} shards for collection '{}' among {} peers {:?}",
            shard_number,
            op.collection_name,
            known_peers.len(),
            shard_distribution.distribution
        );
        shard_distribution
    }

    /// Initiate receiving shard.
    ///
    /// Fails if the collection does not exist
    pub async fn initiate_receiving_shard(
        &self,
        collection_name: String,
        shard_id: ShardId,
        private_oram_preinstalled: bool,
    ) -> Result<(), StorageError> {
        // TODO: Ensure cancel safety!

        log::info!("Initiating receiving shard {collection_name}:{shard_id}");

        // TODO: Ensure cancel safety!
        let collection = self.get_collection_unchecked(&collection_name).await?;
        let config = collection.config_snapshot().await;
        let private_oram_bucket_store_collection =
            collection_params_use_private_oram_bucket_store(&config.params);
        let state = collection.state().await;
        let consensus_authorized_preinstall =
            if private_oram_bucket_store_collection && private_oram_preinstalled {
                state.transfers.iter().any(|transfer| {
                    transfer.is_private_oram_preinstalled_transfer_for(state.resharding.as_ref())
                        && transfer.is_target(self.this_peer_id, shard_id)
                })
            } else {
                false
            };
        reject_private_oram_receiving_shard_until_supported(
            &collection_name,
            private_oram_bucket_store_collection,
            consensus_authorized_preinstall,
        )?;
        if consensus_authorized_preinstall {
            self.validate_private_oram_transfer_snapshot_resume(&collection)
                .await?;
        }
        let initiate_shard_transfer_future =
            collection.initiate_shard_transfer(shard_id, consensus_authorized_preinstall);
        initiate_shard_transfer_future.await?;
        Ok(())
    }

    pub fn request_snapshot(&self) -> Result<(), StorageError> {
        self.get_consensus_proposal_sender()?
            .send(ConsensusOperations::request_snapshot())?;

        Ok(())
    }

    pub async fn update_cluster_metadata(
        &self,
        key: String,
        value: serde_json::Value,
        wait: bool,
    ) -> Result<(), StorageError> {
        let operation = ConsensusOperations::UpdateClusterMetadata { key, value };

        if wait {
            let dispatcher = self.toc_dispatcher.lock().clone().ok_or_else(|| {
                StorageError::service_error("Qdrant is running in standalone mode")
            })?;
            dispatcher
                .consensus_state()
                .propose_consensus_op_with_await(operation, None)
                .await
                .map_err(|err| {
                    StorageError::service_error(format!("Failed to propose and confirm metadata update operation through consensus: {err}"))
                })?;
        } else {
            self.get_consensus_proposal_sender()?.send(operation)?;
        }

        Ok(())
    }

    pub async fn peer_has_shards(&self, peer_id: PeerId) -> bool {
        for collection in self.collections.read().await.values() {
            let state = collection.state().await;
            if state
                .shards
                .into_values()
                .flat_map(|shard_info| shard_info.replicas.into_keys())
                .any(|x| x == peer_id)
            {
                return true;
            }
        }
        false
    }

    /// Cancels all transfers related to the current peer.
    ///
    /// Transfers whehre this peer is the source or the target will be cancelled.
    pub async fn cancel_related_transfers(&self, reason: &str) -> Result<(), StorageError> {
        let collections = self.collections.read().await;
        if let Some(proposal_sender) = &self.consensus_proposal_sender {
            for collection in collections.values() {
                for transfer in collection.get_related_transfers(self.this_peer_id).await {
                    if collection
                        .should_preserve_private_oram_transfer_on_peer_restart(
                            &transfer,
                            self.this_peer_id,
                        )
                        .await?
                    {
                        log::warn!(
                            "Preserving an active private ORAM transfer after a peer restarted; the target will request an exact automatic restart",
                        );
                        continue;
                    }
                    let cancel_transfer = ConsensusOperations::abort_transfer(
                        collection.name().to_string(),
                        transfer,
                        reason,
                    );
                    proposal_sender.send(cancel_transfer)?;
                }
            }
        } else {
            log::error!(
                "Can't cancel transfers related to this node, this is a single node deployment"
            );
        }
        Ok(())
    }

    fn change_peer_state_callback(
        proposal_sender: Option<OperationSender>,
        collection_name: String,
        state: ReplicaState,
        from_state: Option<ReplicaState>,
    ) -> replica_set::ChangePeerState {
        let callback =
            Self::change_peer_from_state_callback(proposal_sender, collection_name, state);
        Arc::new(move |peer_id, shard_id| callback(peer_id, shard_id, from_state))
    }

    fn change_peer_from_state_callback(
        proposal_sender: Option<OperationSender>,
        collection_name: String,
        state: ReplicaState,
    ) -> replica_set::ChangePeerFromState {
        Arc::new(move |peer_id, shard_id, from_state| {
            if let Some(proposal_sender) = &proposal_sender {
                if let Err(send_error) = Self::send_set_replica_state_proposal_op(
                    proposal_sender,
                    collection_name.clone(),
                    peer_id,
                    shard_id,
                    state,
                    from_state,
                ) {
                    log::error!(
                        "Can't send proposal to deactivate replica on peer {peer_id} of shard {shard_id} of collection {collection_name}. Error: {send_error}",
                    );
                }
            } else {
                log::error!(
                    "Can't send proposal to deactivate replica. Error: this is a single node deployment",
                );
            }
        })
    }

    fn send_set_replica_state_proposal_op(
        proposal_sender: &OperationSender,
        collection_name: String,
        peer_id: PeerId,
        shard_id: ShardId,
        state: ReplicaState,
        from_state: Option<ReplicaState>,
    ) -> Result<(), StorageError> {
        let operation = ConsensusOperations::set_replica_state(
            collection_name,
            shard_id,
            peer_id,
            state,
            from_state,
        );
        proposal_sender.send(operation)
    }

    fn request_shard_transfer_callback(
        proposal_sender: Option<OperationSender>,
        collection_name: String,
    ) -> RequestShardTransfer {
        Arc::new(move |shard_transfer| {
            if let Some(proposal_sender) = &proposal_sender {
                let collection_name = collection_name.clone();
                let to_peer = shard_transfer.to;
                let operation =
                    ConsensusOperations::start_transfer(collection_name.clone(), shard_transfer);
                if let Err(send_error) = proposal_sender.send(operation) {
                    log::error!(
                        "Can't send proposal to request shard transfer to peer {to_peer} of collection {collection_name}. Error: {send_error}"
                    );
                }
            } else {
                log::error!(
                    "Can't send proposal to request shard transfer. Error: this is a single node deployment",
                );
            }
        })
    }

    fn abort_shard_transfer_callback(
        proposal_sender: Option<OperationSender>,
        collection_name: String,
    ) -> AbortShardTransfer {
        Arc::new(move |shard_transfer, reason| {
            if let Some(proposal_sender) = &proposal_sender {
                let shard_id = shard_transfer.shard_id;
                let from = shard_transfer.from;
                let to = shard_transfer.to;

                let operation = ConsensusOperations::abort_transfer(
                    collection_name.clone(),
                    shard_transfer,
                    reason,
                );

                if let Err(send_error) = proposal_sender.send(operation) {
                    log::error!(
                        "Can't send proposal to abort \
                         {collection_name}:{shard_id} / {from} -> {to} shard transfer: \
                         {send_error}",
                    );
                }
            } else {
                log::error!(
                    "Can't send proposal to abort shard transfer: \
                     this is a single node deployment",
                );
            }
        })
    }

    fn this_peer_id(&self) -> PeerId {
        self.this_peer_id
    }

    async fn create_collection_path(&self, collection_name: &str) -> Result<PathBuf, StorageError> {
        let path = self.get_collection_path(collection_name);

        if path.exists() {
            if CollectionConfigInternal::check(&path) {
                return Err(StorageError::bad_input(format!(
                    "Can't create collection with name {collection_name}. Collection data already exists at {path}",
                    collection_name = collection_name,
                    path = path.display(),
                )));
            } else {
                // Collection doesn't have a valid config, remove it
                log::debug!(
                    "Removing invalid collection path {path} from storage",
                    path = path.display(),
                );

                let path = path.clone();
                let deleted_dir = self.storage_config.storage_path.join(".deleted");
                tokio::task::spawn_blocking(move || {
                    safe_delete_in_tmp(&path, &deleted_dir)?.close()
                })
                .await??;
            }
        }

        tokio_fs::create_dir_all(&path).await.map_err(|err| {
            StorageError::service_error(format!(
                "Can't create directory for collection {collection_name}. Error: {err}"
            ))
        })?;

        Ok(path)
    }

    fn get_collection_path(&self, collection_name: &str) -> PathBuf {
        self.storage_config
            .storage_path
            .join(COLLECTIONS_DIR)
            .join(collection_name)
    }

    fn get_consensus_proposal_sender(&self) -> Result<&OperationSender, StorageError> {
        self.consensus_proposal_sender
            .as_ref()
            .ok_or_else(|| StorageError::service_error("Qdrant is running in standalone mode"))
    }

    /// Insert dispatcher for access to table of contents and consensus.
    pub fn with_toc_dispatcher(&self, dispatcher: TocDispatcher) {
        self.toc_dispatcher.lock().replace(dispatcher);
    }

    pub fn get_channel_service(&self) -> &ChannelService {
        &self.channel_service
    }

    /// Gets a copy of hardware metrics for all collections that have been collected from operations on this node.
    /// This copy is intentional to prevent 'uncontrolled' modifications of the DashMap, which doesn't need to be mutable for modifications.
    pub fn all_hw_metrics(&self) -> HashMap<String, HardwareUsage> {
        self.collection_hw_metrics
            .iter()
            .map(|i| {
                let key = i.key().clone();
                let hw_usage = HardwareUsage {
                    cpu: i.get_cpu(),
                    payload_io_read: i.get_payload_io_read(),
                    payload_io_write: i.get_payload_io_write(),
                    payload_index_io_read: i.get_payload_index_io_read(),
                    payload_index_io_write: i.get_payload_index_io_write(),
                    vector_io_read: i.get_vector_io_read(),
                    vector_io_write: i.get_vector_io_write(),
                };
                (key, hw_usage)
            })
            .collect()
    }

    pub fn general_runtime_handle(&self) -> &Handle {
        self.general_runtime.handle()
    }
}

impl PrivateOramExternalRecoveryCollectionInstallGuard<'_> {
    pub async fn unload_current_collection(&self) -> Result<(), StorageError> {
        {
            let _collection_lifecycle_guard = self.toc.collection_lifecycle_lock.lock().await;
            if self.require_matching_tombstone().is_ok() {
                if self
                    .toc
                    .collections
                    .read()
                    .await
                    .contains_key(&self.collection_name)
                {
                    return Err(invalid_private_oram_external_recovery_collection_state());
                }
                self.validate_consensus_binding()?;
                return Ok(());
            }
        }
        let removed = {
            let _collection_lifecycle_guard = self.toc.collection_lifecycle_lock.lock().await;
            let (resolved_name, current) = self
                .toc
                .get_collection_unfenced(&self.collection_name)
                .await?;
            if resolved_name != self.collection_name {
                return Err(invalid_private_oram_external_recovery_collection_state());
            }
            self.validate_loaded_collection_identity(&current).await?;
            self.validate_consensus_binding()?;
            let state = current.state().await;
            let mut collections = self.toc.collections.write().await;
            if !collections
                .get(&self.collection_name)
                .is_some_and(|registered| Arc::ptr_eq(registered, &current))
                || self
                    .toc
                    .private_oram_external_recovery_detached
                    .contains_key(&self.collection_name)
            {
                return Err(invalid_private_oram_external_recovery_collection_state());
            }
            self.toc.private_oram_external_recovery_detached.insert(
                self.collection_name.clone(),
                PrivateOramExternalRecoveryDetachedCollection {
                    collection_id: self.collection_id.clone(),
                    operation_id_hash: self.operation_id_hash.clone(),
                    state,
                },
            );
            let removed = collections
                .remove(&self.collection_name)
                .ok_or_else(invalid_private_oram_external_recovery_collection_state)?;
            drop(current);
            removed
        };
        let collection = match try_unwrap_with_timeout_async(
            removed,
            PRIVATE_ORAM_EXTERNAL_RECOVERY_DRAIN_INTERVAL,
            PRIVATE_ORAM_EXTERNAL_RECOVERY_DRAIN_TIMEOUT,
        )
        .await
        {
            Ok(collection) => collection,
            Err(collection) => {
                self.restore_detached_collection(collection).await?;
                return Err(StorageError::Locked {
                    description:
                        "collection is busy and cannot enter private ORAM recovery installation"
                            .to_string(),
                });
            }
        };

        if let Err(error) = self
            .validate_loaded_collection_identity(&collection)
            .await
            .and_then(|()| self.validate_consensus_binding())
        {
            self.restore_detached_collection(Arc::new(collection))
                .await?;
            return Err(error);
        }
        collection.stop_gracefully().await;
        drop(collection);
        Ok(())
    }

    fn validate_consensus_binding(&self) -> Result<(), StorageError> {
        match &self.consensus_binding {
            PrivateOramExternalRecoveryInstallGuardConsensusBinding::Active => self
                .toc
                .validate_private_oram_external_recovery_consensus_binding(
                    &self.collection_id,
                    &self.operation_id_hash,
                )
                .map(|_| ()),
            PrivateOramExternalRecoveryInstallGuardConsensusBinding::Committed {
                backup_generation,
                checkpoint_digest,
                install_intent_digest,
            } => self
                .toc
                .validate_private_oram_external_recovery_committed_binding(
                    &self.collection_id,
                    *backup_generation,
                    checkpoint_digest,
                    install_intent_digest,
                )
                .map(|_| ()),
        }
    }

    pub async fn load_live_collection_strict(&self) -> Result<Collection, StorageError> {
        if self
            .toc
            .collections
            .read()
            .await
            .contains_key(&self.collection_name)
        {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        self.require_matching_tombstone()?;
        let collection_path = self.toc.get_collection_path(&self.collection_name);
        let snapshots_path = TableOfContent::collection_snapshots_path(
            &self.toc.storage_config.snapshots_path,
            &self.collection_name,
        );
        let mut shared_storage_config = self
            .toc
            .storage_config
            .to_shared_storage_config(self.toc.is_distributed());
        shared_storage_config.handle_collection_load_errors = false;
        let collection_name = self.collection_name.clone();
        let this_peer_id = self.toc.this_peer_id;
        let channel_service = self.toc.channel_service.clone();
        let consensus_proposal_sender = self.toc.consensus_proposal_sender.clone();
        let search_runtime = self.toc.search_runtime.handle().clone();
        let update_runtime = self.toc.update_runtime.handle().clone();
        let optimizer_resource_budget = self.toc.optimizer_resource_budget.clone();
        let optimizers_overwrite = self.toc.storage_config.optimizers_overwrite.clone();
        let collection = self
            .toc
            .general_runtime_handle()
            .spawn(async move {
                Collection::load(
                    collection_name.clone(),
                    this_peer_id,
                    &collection_path,
                    &snapshots_path,
                    Arc::new(shared_storage_config),
                    channel_service,
                    TableOfContent::change_peer_from_state_callback(
                        consensus_proposal_sender.clone(),
                        collection_name.clone(),
                        ReplicaState::Dead,
                    ),
                    TableOfContent::request_shard_transfer_callback(
                        consensus_proposal_sender.clone(),
                        collection_name.clone(),
                    ),
                    TableOfContent::abort_shard_transfer_callback(
                        consensus_proposal_sender,
                        collection_name,
                    ),
                    Some(search_runtime),
                    Some(update_runtime),
                    optimizer_resource_budget,
                    optimizers_overwrite,
                )
                .await
            })
            .await??;
        if let Err(error) = self.validate_loaded_collection_identity(&collection).await {
            collection.stop_gracefully().await;
            return Err(error);
        }
        Ok(collection)
    }

    pub async fn publish_fenced_collection(
        &self,
        collection: Collection,
    ) -> Result<(), StorageError> {
        if let Err(error) = self
            .toc
            .validate_private_oram_external_recovery_active_binding(
                &collection,
                &self.collection_id,
                &self.operation_id_hash,
            )
            .await
        {
            collection.stop_gracefully().await;
            return Err(error);
        }
        self.insert_collection(collection).await
    }

    pub async fn publish_committed_collection(
        &self,
        collection: Collection,
        backup_generation: u64,
        checkpoint_digest: &str,
        install_intent_digest: &str,
    ) -> Result<(), StorageError> {
        if let Err(error) = self.validate_loaded_collection_identity(&collection).await {
            collection.stop_gracefully().await;
            return Err(error);
        }
        let Some(dispatcher) = self.toc.toc_dispatcher.lock().clone() else {
            collection.stop_gracefully().await;
            return Err(invalid_private_oram_external_recovery_collection_state());
        };
        let Some(state) = dispatcher.consensus_state().private_oram_external_recovery(
            &PrivateOramExternalRecoveryKey {
                collection_id: self.collection_id.clone(),
            },
        ) else {
            collection.stop_gracefully().await;
            return Err(invalid_private_oram_external_recovery_collection_state());
        };
        if state.committed_backup_generation != backup_generation
            || state.committed_checkpoint_digest.as_deref() != Some(checkpoint_digest)
            || state.committed_install_intent_digest.as_deref() != Some(install_intent_digest)
            || state.active_lease.is_some()
        {
            collection.stop_gracefully().await;
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        self.insert_collection(collection).await
    }

    async fn validate_loaded_collection_identity(
        &self,
        collection: &Collection,
    ) -> Result<(), StorageError> {
        if collection.name() != self.collection_name
            || collection.path() != self.toc.get_collection_path(&self.collection_name)
        {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        let config = collection.config_snapshot().await;
        if config.stable_crypto_id(&self.collection_name)? != self.collection_id
            || private_oram_index_keys_for_config(&config, &self.collection_name)?.is_empty()
        {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        Ok(())
    }

    async fn insert_collection(&self, collection: Collection) -> Result<(), StorageError> {
        let _collection_lifecycle_guard = self.toc.collection_lifecycle_lock.lock().await;
        let mut collections = self.toc.collections.write().await;
        if let Err(error) = collections
            .validate_collection_not_exists(&self.collection_name)
            .and_then(|()| self.require_matching_tombstone())
        {
            drop(collections);
            drop(_collection_lifecycle_guard);
            collection.stop_gracefully().await;
            return Err(error);
        }
        collections.insert(self.collection_name.clone(), Arc::new(collection));
        self.toc
            .private_oram_external_recovery_detached
            .remove(&self.collection_name);
        Ok(())
    }

    async fn restore_detached_collection(
        &self,
        collection: Arc<Collection>,
    ) -> Result<(), StorageError> {
        let _collection_lifecycle_guard = self.toc.collection_lifecycle_lock.lock().await;
        let mut collections = self.toc.collections.write().await;
        collections.validate_collection_not_exists(&self.collection_name)?;
        self.require_matching_tombstone()?;
        collections.insert(self.collection_name.clone(), collection);
        self.toc
            .private_oram_external_recovery_detached
            .remove(&self.collection_name);
        Ok(())
    }

    fn require_matching_tombstone(&self) -> Result<(), StorageError> {
        let matches = self
            .toc
            .private_oram_external_recovery_detached
            .get(&self.collection_name)
            .is_some_and(|detached| {
                detached.collection_id == self.collection_id
                    && detached.operation_id_hash == self.operation_id_hash
            });
        if !matches {
            return Err(invalid_private_oram_external_recovery_collection_state());
        }
        Ok(())
    }
}

fn private_oram_external_recovery_fence(
    state: Option<&PrivateOramExternalRecoveryState>,
    now_unix: u64,
) -> Option<PrivateOramExternalRecoveryFence> {
    match state.and_then(|state| state.active_lease.as_ref()) {
        // An expired staging lease can already be superseded by another peer's `begin`; it must
        // not keep fencing writes until someone remembers to abort it. Installing leases still
        // fence unconditionally because the live tree may be mid-replacement.
        Some(lease)
            if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                && lease.expires_at_unix > now_unix =>
        {
            Some(PrivateOramExternalRecoveryFence::Writes)
        }
        Some(lease) if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging => None,
        Some(lease) if lease.phase == PrivateOramExternalRecoveryLeasePhase::Installing => {
            Some(PrivateOramExternalRecoveryFence::All)
        }
        Some(_) | None => None,
    }
}

fn invalid_private_oram_external_recovery_collection_state() -> StorageError {
    StorageError::bad_request("private ORAM external recovery collection state is invalid")
}

fn invalid_private_oram_external_recovery_resource_state() -> StorageError {
    StorageError::service_error("private ORAM external recovery resource state is invalid")
}

fn reject_private_oram_receiving_shard_until_supported(
    _collection_name: &str,
    private_oram_bucket_store_collection: bool,
    consensus_authorized_preinstall: bool,
) -> Result<(), StorageError> {
    if !private_oram_bucket_store_collection || consensus_authorized_preinstall {
        return Ok(());
    }

    Err(StorageError::bad_request(format!(
        "cannot initiate receiving shard for private ORAM collections: \
         encrypted ORAM bucket preinstall and consensus-backed epoch/root ownership must be \
         verified before shard transfer",
    )))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector, PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING,
    };

    use super::*;

    #[test]
    fn private_oram_external_recovery_resources_enforce_quota_and_worker_limit() {
        let limits = PrivateOramExternalRecoveryConfig {
            max_snapshot_bytes: 10,
            max_total_staged_bytes: 20,
            max_unpacked_bytes: 10,
            min_free_space_bytes: 0,
            max_concurrent_verify_prepare: NonZeroUsize::new(1).unwrap(),
        };
        let resources =
            Arc::new(PrivateOramExternalRecoveryResources::new(limits, HashMap::new()).unwrap());

        let reservation = resources.reserve("operation-a", 6).unwrap();
        reservation.persist();
        assert_eq!(
            resources.snapshot(),
            PrivateOramExternalRecoveryResourceSnapshot {
                reserved_bytes: 16,
                staging_reservations: 1,
                worker_limit: 1,
                workers_in_use: 0,
                preflight_scanned_logical_bytes: 0,
                preflight_scanned_entries: 0,
            }
        );
        assert!(resources.reserve("operation-b", 5).is_err());
        resources.release("operation-a");
        let reservation = resources.reserve("operation-b", 5).unwrap();
        resources.record_archive_scan(PrivateOramExternalRecoveryArchiveResources {
            entry_count: 5,
            logical_bytes: 17,
        });

        let worker = Arc::clone(&resources.workers).try_acquire_owned().unwrap();
        assert_eq!(resources.snapshot().workers_in_use, 1);
        assert_eq!(resources.snapshot().preflight_scanned_entries, 5);
        assert_eq!(resources.snapshot().preflight_scanned_logical_bytes, 17);
        assert!(Arc::clone(&resources.workers).try_acquire_owned().is_err());
        drop(worker);
        assert!(Arc::clone(&resources.workers).try_acquire_owned().is_ok());
        drop(reservation);
        assert_eq!(resources.snapshot().staging_reservations, 0);
        assert_eq!(resources.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn private_oram_external_recovery_fence_tracks_install_phase() {
        let state = |phase| {
            PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(
                crate::content_manager::consensus_ops::PrivateOramExternalRecoveryLease {
                    owner_peer_id: 7,
                    operation_id_hash: "A".repeat(43),
                    checkpoint_digest: "B".repeat(43),
                    backup_generation: 1,
                    issued_at_unix: 100,
                    expires_at_unix: 160,
                    authority: crate::content_manager::consensus_ops::PrivateOramExternalRecoveryAuthority::LegacyV1,
                    install_intent_digest: (phase
                        == PrivateOramExternalRecoveryLeasePhase::Installing)
                        .then(|| "C".repeat(43)),
                    phase,
                },
            ),
        }
        };

        assert_eq!(private_oram_external_recovery_fence(None, 150), None);
        assert_eq!(
            private_oram_external_recovery_fence(
                Some(&state(PrivateOramExternalRecoveryLeasePhase::Staging)),
                150,
            ),
            Some(PrivateOramExternalRecoveryFence::Writes),
        );
        // An expired staging lease no longer fences writes; it is already supersedable.
        assert_eq!(
            private_oram_external_recovery_fence(
                Some(&state(PrivateOramExternalRecoveryLeasePhase::Staging)),
                160,
            ),
            None,
        );
        // Installing leases fence regardless of expiry: the live tree may be mid-replacement.
        for now_unix in [150, 1_000] {
            assert_eq!(
                private_oram_external_recovery_fence(
                    Some(&state(PrivateOramExternalRecoveryLeasePhase::Installing)),
                    now_unix,
                ),
                Some(PrivateOramExternalRecoveryFence::All),
            );
        }
    }

    const PRIVATE_ORAM_RECEIVING_SHARD_COLLECTION_NAMES: &[&str] = &[
        "clientState.json",
        "clientStates.json",
        "client_state.json",
        "client_state.bin",
        "client_states.bin",
        "clientStateBackup.json",
        "clientStateBackups.json",
        "client_state_backup.bin",
        "client_state_backups.bin",
        "clientStateCiphertext.json",
        "clientStateSnapshot.json",
        "clientStateSnapshots.json",
        "client.state.snapshot.json",
        "client_state_snapshot.bin",
        "client_state_snapshots.bin",
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
        "encrypted_client_state_ciphertext.json",
        "encrypted_client_state_ciphertexts.json",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes.bin",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256.bin",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256.bin",
        "encrypted_client_state_ciphertexts_sha256.json",
        "encryptedClientState.json",
        "encryptedClientStates.json",
        "encrypted_client_state.json",
        "encrypted_client_state.bin",
        "encrypted_client_states.json",
        "encrypted_client_states.bin",
        "encryptedClientStateBackup.json",
        "encryptedClientStateBackups.json",
        "encrypted_client_state_backup.json",
        "encrypted_client_state_backup.bin",
        "encrypted_client_state_backups.json",
        "encrypted_client_state_backups.bin",
        "encryptedClientStateSnapshot.json",
        "encryptedClientStateSnapshots.json",
        "encrypted.client.state.json",
        "encrypted.client.state.snapshot.json",
        "encrypted_client_state_snapshot.json",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshots.json",
        "encrypted.client.state.snapshots.json",
        "encrypted_client_state_snapshots.bin",
        "stateCiphertext.json",
        "stateCiphertextHash.json",
        "stateCiphertextHashes.json",
        "stateCiphertextSha256.json",
        "stateCiphertextsSha256.json",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256.bin",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256.bin",
        "state_ciphertexts_sha256.json",
        "state_ciphertext.bin",
        "state_ciphertext_hash.bin",
        "state_ciphertext_hash.json",
        "state_ciphertext_hashes.bin",
        "token_position_map_backup.json",
        "token_position_map_backups.json",
        "token.map.backup.json",
        "token.map.backups.json",
        "token.position.map.backup.json",
        "token.position.map.backups.json",
        "tokenPositionMapBackup.json",
        "tokenPositionMapBackups.json",
        "oramPositionMapBackup.json",
        "oramPositionMapBackups.json",
        "positionMapBackup.json",
        "positionMapBackups.json",
        "stashBackup.json",
        "stashBackups.json",
    ];

    const PRIVATE_ORAM_RECEIVING_SHARD_REDACTION_STEMS: &[&str] = &[
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
        "client.state.snapshot",
        "client_state_snapshot",
        "client_state_snapshots",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
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
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state",
        "encrypted_client_states",
        "encryptedClientState",
        "encryptedClientStates",
        "encryptedClientStateBackup",
        "encryptedClientStateBackups",
        "encrypted_client_state_backup",
        "encrypted_client_state_backups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted.client.state",
        "encrypted.client.state.snapshot",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshots",
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
        "token.map.backups",
        "token_map_backup",
        "token_map_backups",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token.position.map.backup",
        "token.position.map.backups",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "positionMapBackup",
        "positionMapBackups",
        "stashBackup",
        "stashBackups",
    ];

    #[test]
    fn client_payload_nonce_replay_cache_rejects_malformed_scoped_keys() {
        let mut cache = ClientPayloadNonceReplayCache::default();
        let err = cache
            .record(["not-a-valid-cache-key".to_string()])
            .unwrap_err();
        assert!(format!("{err:?}").contains("nonce replay cache key is invalid"));
    }

    #[test]
    fn client_payload_nonce_replay_cache_rejects_duplicate_scoped_keys() {
        let mut cache = ClientPayloadNonceReplayCache::default();
        let key =
            "collection-uuid\x1ftenant-a-key\x1ftenant-a-rk\x1f1\x1fAAAAAAAAAAAAAAAA".to_string();

        assert!(cache.record([key.clone()]).unwrap());
        assert!(!cache.record([key]).unwrap());
    }

    #[test]
    fn client_payload_nonce_replay_cache_rejects_duplicate_scoped_keys_in_same_batch() {
        let mut cache = ClientPayloadNonceReplayCache::default();
        let key =
            "collection-uuid\x1ftenant-a-key\x1ftenant-a-rk\x1f1\x1fAAAAAAAAAAAAAAAA".to_string();

        assert!(!cache.record([key.clone(), key.clone()]).unwrap());
        assert!(
            cache.record([key]).unwrap(),
            "rejected duplicate batches must not partially record nonce keys"
        );
    }

    #[test]
    fn client_payload_nonce_replay_error_tells_clients_to_regenerate_envelopes() {
        assert!(CLIENT_PAYLOAD_NONCE_REPLAY_ERROR.contains("nonce was already used"));
        assert!(CLIENT_PAYLOAD_NONCE_REPLAY_ERROR.contains("regenerate the client-side envelope"));
        assert!(CLIENT_PAYLOAD_NONCE_REPLAY_ERROR.contains("fresh nonce before retrying"));
    }

    #[test]
    fn receiving_shard_rejects_private_oram_collection_until_bucket_transfer_exists() {
        for collection_name in PRIVATE_ORAM_RECEIVING_SHARD_COLLECTION_NAMES {
            reject_private_oram_receiving_shard_until_supported(collection_name, false, false)
                .unwrap();

            let err =
                reject_private_oram_receiving_shard_until_supported(collection_name, true, false)
                    .unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("private ORAM collections"));
            assert!(rendered.contains("encrypted ORAM bucket preinstall"));
            assert!(rendered.contains("consensus-backed epoch/root"));
            assert!(!rendered.contains(collection_name));
            for &leaked_alias in PRIVATE_ORAM_RECEIVING_SHARD_REDACTION_STEMS {
                assert!(!rendered.contains(leaked_alias), "{rendered}");
            }
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            assert!(!rendered.contains(PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(PRIVATE_RESULT_ORAM_BINDING));

            reject_private_oram_receiving_shard_until_supported(collection_name, true, true)
                .expect("consensus-authorized private ORAM preinstall must allow receive setup");
        }
    }

    #[test]
    fn receiving_shard_guard_uses_private_oram_binding_detection() {
        for binding in [PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING] {
            let params = CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/private-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "private_oram_rule".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["document.body".to_string()],
                        },
                        instance: "docs_private_oram_v1".to_string(),
                        binding: Some(binding.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            };

            assert!(collection_params_use_private_oram_bucket_store(&params));
            assert!(
                reject_private_oram_receiving_shard_until_supported(
                    "docs",
                    collection_params_use_private_oram_bucket_store(&params),
                    false,
                )
                .is_err()
            );
        }
    }
}
