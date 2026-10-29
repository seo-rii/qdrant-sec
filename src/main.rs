mod actix;
mod common;
mod consensus;
mod greeting;
mod issues_setup;
mod migrations;
mod settings;
mod snapshots;
mod startup;
mod tonic;
mod tracing;

use std::io::{Error, Read};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use ::common::budget::{ResourceBudget, get_io_budget};
use ::common::cpu::get_cpu_budget;
use ::common::flags::{feature_flags, init_feature_flags};
use ::common::fs::{FsCheckResult, check_fs_info, check_mmap_functionality};
use ::common::mmap::MULTI_MMAP_SUPPORT_CHECK_RESULT;
use ::common::mmap::advice::set_global;
use ::tonic::transport::Uri;
use api::grpc::transport_channel_pool::TransportChannelPool;
use clap::Parser;
use collection::profiling::interface::init_requests_profile_collector;
use collection::shards::channel_service::ChannelService;
use consensus::Consensus;
use fs_err as fs;
use qdrant_sec::{
    PrivateOramActivationAuthorityBundleV1, PrivateOramActivationAuthorityTrustAnchorV1,
    PrivateOramPeerRecoveryPublicKeyV1,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use slog::Drain;
use startup::setup_panic_hook;
use storage::content_manager::consensus::operation_sender::OperationSender;
use storage::content_manager::consensus::persistent::Persistent;
use storage::content_manager::consensus_manager::{ConsensusManager, ConsensusStateRef};
use storage::content_manager::snapshots::private_oram_external_recovery::{
    finalize_committed_private_oram_external_recovery_installs,
    private_oram_external_recovery_install_is_pending,
    reconcile_private_oram_external_recovery_installs,
};
use storage::content_manager::toc::TableOfContent;
use storage::content_manager::toc::dispatcher::TocDispatcher;
use storage::dispatcher::Dispatcher;
use storage::rbac::Access;
#[cfg(all(
    not(target_env = "msvc"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use tikv_jemallocator::Jemalloc;

use crate::common::helpers::{
    create_general_purpose_runtime, create_search_runtime, create_update_runtime,
    load_tls_client_config,
};
use crate::common::inference::service::InferenceService;
use crate::common::private_oram_mutation_supervisor::{
    initialize_private_oram_mutation_supervisor_v2, supervise_private_oram_mutations_v2,
};
use crate::common::private_oram_peer_identity::{
    PrivateOramPeerIdentityOpenPolicy, PrivateOramPeerRecoveryIdentity,
};
use crate::common::telemetry::TelemetryCollector;
use crate::common::telemetry_reporting::TelemetryReporter;
use crate::greeting::welcome;
use crate::migrations::single_to_cluster::handle_existing_collections;
use crate::settings::Settings;
use crate::snapshots::{recover_full_snapshot, recover_snapshots};
use crate::startup::{remove_started_file_indicator, touch_started_file_indicator};

#[cfg(all(
    not(target_env = "msvc"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

const FULL_ACCESS: Access = Access::full("For main");

/// Qdrant (read: quadrant ) is a vector similarity search engine.
/// It provides a production-ready service with a convenient API to store, search, and manage points - vectors with an additional payload.
///
/// This CLI starts a Qdrant peer/server.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Uri of the peer to bootstrap from in case of multi-peer deployment.
    /// If not specified - this peer will be considered as a first in a new deployment.
    #[arg(long, value_parser, value_name = "URI", env = "QDRANT_BOOTSTRAP")]
    bootstrap: Option<Uri>,
    /// Uri of this peer.
    /// Other peers should be able to reach it by this uri.
    ///
    /// This value has to be supplied if this is the first peer in a new deployment.
    ///
    /// In case this is not the first peer and it bootstraps the value is optional.
    /// If not supplied then qdrant will take internal grpc port from config and derive the IP address of this peer on bootstrap peer (receiving side)
    #[arg(long, value_parser, value_name = "URI", env = "QDRANT_URI")]
    uri: Option<Uri>,

    /// Force snapshot re-creation
    /// If provided - existing collections will be replaced with snapshots.
    /// Default is to not recreate from snapshots.
    #[arg(short, long, action, default_value_t = false)]
    force_snapshot: bool,

    /// List of paths to snapshot files.
    /// Format: <snapshot_file_path>:<target_collection_name>
    ///
    /// WARN: Do not use this option if you are recovering collection in existing distributed cluster.
    /// Use `/collections/<collection-name>/snapshots/recover` API instead.
    #[arg(long, value_name = "PATH:NAME", alias = "collection-snapshot")]
    snapshot: Option<Vec<String>>,

    /// Path to snapshot of multiple collections.
    /// Format: <snapshot_file_path>
    ///
    /// WARN: Do not use this option if you are recovering collection in existing distributed cluster.
    /// Use `/collections/<collection-name>/snapshots/recover` API instead.
    #[arg(long, value_name = "PATH")]
    storage_snapshot: Option<String>,

    /// Path to an alternative configuration file.
    /// Format: <config_file_path>
    ///
    /// Default path: config/config.yaml
    #[arg(long, value_name = "PATH")]
    config_path: Option<String>,

    /// Disable telemetry sending to developers
    /// If provided - telemetry collection will be disabled.
    /// Read more: <https://qdrant.tech/documentation/guides/telemetry>
    #[arg(long, action, default_value_t = false)]
    disable_telemetry: bool,

    /// Run stacktrace collector. Used for debugging.
    #[arg(long, action, default_value_t = false)]
    stacktrace: bool,

    /// Reinit consensus state.
    /// When enabled, the service will assume the consensus should be reinitialized.
    /// The exact behavior depends on if this current node has bootstrap URI or not.
    /// If it has - it'll remove current consensus state and consensus WAL (while keeping peer ID)
    ///             and will try to receive state from the bootstrap peer.
    /// If it doesn't have - it'll remove other peers from voters promote
    ///             the current peer to the leader and the single member of the cluster.
    ///             It'll also compact consensus WAL to force snapshot
    #[arg(long, action, default_value_t = false)]
    reinit: bool,

    /// Create or inspect this peer's private ORAM signing identity and exit.
    #[arg(long, action, default_value_t = false)]
    bootstrap_private_oram_peer_identity: bool,
}

const PRIVATE_ORAM_ACTIVATION_BUNDLE_MAX_BYTES: u64 = 1024 * 1024;

struct PrivateOramMutationV2Startup {
    trust_anchor: PrivateOramActivationAuthorityTrustAnchorV1,
    authority_bundle: PrivateOramActivationAuthorityBundleV1,
}

#[derive(Serialize)]
struct PrivateOramPeerIdentityBootstrapOutput<'a> {
    peer_id: u64,
    public_key: &'a PrivateOramPeerRecoveryPublicKeyV1,
    binary_capability_digest: String,
    runtime_capability_fingerprint: String,
}

fn read_bounded_canonical_json<T>(path: &Path, max_bytes: u64) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        anyhow::bail!("private ORAM activation authority bundle file is invalid");
    }
    let capacity = usize::try_from(metadata.len())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| anyhow::anyhow!("private ORAM activation authority bundle is oversized"))?;
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() != capacity || bytes.len() as u64 > max_bytes {
        anyhow::bail!("private ORAM activation authority bundle file changed while reading");
    }
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("private ORAM activation authority bundle is invalid"))?;
    if serde_json::to_vec(&value)? != bytes {
        anyhow::bail!("private ORAM activation authority bundle is not canonical JSON");
    }
    Ok(value)
}

fn private_oram_mutation_v2_startup(
    settings: &Settings,
) -> anyhow::Result<Option<PrivateOramMutationV2Startup>> {
    let Some(config) = settings
        .cluster
        .consensus
        .private_oram_mutation_v2_activation
        .as_ref()
    else {
        return Ok(None);
    };
    if !settings.cluster.enabled {
        anyhow::bail!("private ORAM mutation V2 activation requires cluster mode");
    }
    let trust_anchor = PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
        config.authority.clone(),
        config.cluster_identity_digest.clone(),
        config.cluster_first_voter_peer_id,
    )
    .map_err(|_| anyhow::anyhow!("private ORAM activation trust anchor is invalid"))?;
    let authority_bundle: PrivateOramActivationAuthorityBundleV1 = read_bounded_canonical_json(
        &config.authority_bundle_path,
        PRIVATE_ORAM_ACTIVATION_BUNDLE_MAX_BYTES,
    )?;
    let required_binary_capability_digest =
        &authority_bundle.manifest.required_binary_capability_digest;
    if required_binary_capability_digest
        != &crate::common::crypto::private_oram_mutation_v2_binary_capability_digest()
        && required_binary_capability_digest
            != &crate::common::crypto::private_oram_mutation_v3_binary_capability_digest()
    {
        anyhow::bail!("private ORAM activation authority requires a different binary capability");
    }
    Ok(Some(PrivateOramMutationV2Startup {
        trust_anchor,
        authority_bundle,
    }))
}

fn main() -> anyhow::Result<()> {
    // Install ring as the default rustls CryptoProvider.
    // reqwest 0.13 "rustls" feature pulls in aws-lc-rs; we install ring
    // explicitly to use the same provider as before.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install default CryptoProvider"))?;

    let args = Args::parse();

    // Run backtrace collector, expected to used by `rstack` crate
    if args.stacktrace {
        #[cfg(all(target_os = "linux", feature = "stacktrace"))]
        {
            let _ = rstack_self::child();
        }
        return Ok(());
    }

    let mut settings = Settings::new(args.config_path)?;

    // Set global feature flags, sourced from configuration
    init_feature_flags(settings.feature_flags);

    let reporting_enabled = !settings.telemetry_disabled && !args.disable_telemetry;

    let reporting_id = TelemetryCollector::generate_id();

    // Setup logging (no logging before this point)
    let logger_handle = tracing::setup(
        settings
            .logger
            .with_top_level_directive(settings.log_level.clone()),
    )?;

    remove_started_file_indicator();

    setup_panic_hook(reporting_enabled, reporting_id.to_string());

    set_global(settings.storage.mmap_advice);
    segment::vector_storage::common::set_async_scorer(
        settings
            .storage
            .performance
            .async_scorer
            .unwrap_or_default(),
    );
    welcome(&settings);

    // If audit logging is enabled, but failed to initialize,
    // we should stop the service, as it may cause unlogged access to the data.
    // The guard must be held alive until shutdown to flush remaining audit events.
    let _audit_guard =
        common::audit::init_audit_logger(settings.audit.as_ref()).map_err(|err| {
            anyhow::anyhow!("Audit logger must be initialized if audit logging is enabled: {err}")
        })?;

    #[cfg(feature = "gpu")]
    if let Some(settings_gpu) = &settings.gpu {
        use segment::index::hnsw_index::gpu::*;

        // initialize GPU devices manager.
        if settings_gpu.indexing {
            set_gpu_force_half_precision(settings_gpu.force_half_precision);
            set_gpu_groups_count(settings_gpu.groups_count);

            let mut gpu_device_manager = GPU_DEVICES_MANAGER.write();
            *gpu_device_manager = match gpu_devices_manager::GpuDevicesMaganer::new(
                &settings_gpu.device_filter,
                settings_gpu.devices.as_deref(),
                settings_gpu.allow_integrated,
                settings_gpu.allow_emulated,
                true, // Currently we always wait for the free gpu device.
                settings_gpu.parallel_indexes.unwrap_or(1),
            ) {
                Ok(gpu_device_manager) => Some(gpu_device_manager),
                Err(err) => {
                    log::error!("Can't initialize GPU devices manager: {err}");
                    None
                }
            }
        }
    }

    if let Some(recovery_warning) = &settings.storage.recovery_mode {
        log::warn!("Qdrant is loaded in recovery mode: {recovery_warning}");
        log::warn!(
            "Read more: https://qdrant.tech/documentation/guides/administration/#recovery-mode"
        );
    }

    // Validate as soon as possible, but we must initialize logging first
    settings.validate_and_warn();
    crate::common::crypto::validate_runtime_config(&settings)?;
    let _effective_crypto = crate::common::crypto::effective_settings(&settings);

    fs::create_dir_all(&settings.storage.storage_path)?;

    if args.bootstrap_private_oram_peer_identity {
        let peer_id = settings.cluster.peer_id.ok_or_else(|| {
            anyhow::anyhow!(
                "--bootstrap-private-oram-peer-identity requires cluster.peer_id to be configured"
            )
        })?;
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            &settings.storage.storage_path,
            peer_id,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let output = PrivateOramPeerIdentityBootstrapOutput {
            peer_id,
            public_key: identity.public_key(),
            binary_capability_digest:
                crate::common::crypto::private_oram_mutation_v3_binary_capability_digest(),
            runtime_capability_fingerprint:
                crate::common::crypto::crypto_runtime_capability_fingerprint(&settings),
        };
        println!("{}", serde_json::to_string(&output)?);
        return Ok(());
    }

    // Check if the filesystem is compatible with Qdrant
    let mmaps_working;
    match check_fs_info(&settings.storage.storage_path) {
        FsCheckResult::Good => {
            mmaps_working = true;
        }
        FsCheckResult::Unknown(details) => {
            match check_mmap_functionality(&settings.storage.storage_path) {
                Ok(true) => {
                    log::warn!(
                        "There is a potential issue with the filesystem for storage path {}. Details: {details}",
                        settings.storage.storage_path.display(),
                    );
                    mmaps_working = true;
                }
                Ok(false) => {
                    log::error!(
                        "Filesystem check failed for storage path {}. Details: {details}",
                        settings.storage.storage_path.display(),
                    );
                    mmaps_working = false;
                }
                Err(e) => {
                    log::error!(
                        "Unable to check mmap functionality for storage path {}. Details: {details}, error: {e}",
                        settings.storage.storage_path.display(),
                    );
                    mmaps_working = false;
                }
            }
        }
        FsCheckResult::Bad(details) => {
            log::error!(
                "Filesystem check failed for storage path {}. Details: {details}",
                settings.storage.storage_path.display(),
            );
            mmaps_working = false;
        }
    }
    let _ = MULTI_MMAP_SUPPORT_CHECK_RESULT.set(mmaps_working);

    // Report feature flags that are enabled for easier debugging
    let flags = feature_flags();
    if !flags.is_default() {
        log::debug!("Feature flags: {flags:?}");
    }

    let bootstrap = if args.bootstrap == args.uri {
        if args.bootstrap.is_some() {
            log::warn!(
                "Bootstrap URI is the same as this peer URI. Consider this peer as a first in a new deployment.",
            );
        }
        None
    } else {
        args.bootstrap
    };

    let private_oram_mutation_v2_startup = private_oram_mutation_v2_startup(&settings)?;

    // Saved state of the consensus.
    let persistent_consensus_state = match private_oram_mutation_v2_startup.as_ref() {
        Some(activation) => Persistent::load_or_init_with_private_oram_mutation_v2_activation(
            &settings.storage.storage_path,
            bootstrap.is_none(),
            args.reinit,
            settings.cluster.peer_id,
            &activation.trust_anchor,
            &activation.authority_bundle,
        )?,
        None => Persistent::load_or_init(
            &settings.storage.storage_path,
            bootstrap.is_none(),
            args.reinit,
            settings.cluster.peer_id,
        )?,
    };
    let is_distributed_deployment = settings.cluster.enabled;
    let private_oram_mutation_unsettled = persistent_consensus_state
        .has_unsettled_private_oram_mutation()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if !is_distributed_deployment && private_oram_mutation_unsettled {
        anyhow::bail!(
            "Standalone startup is blocked by an unsettled private ORAM cluster mutation"
        );
    }
    let private_oram_peer_identity = private_oram_mutation_v2_startup
        .as_ref()
        .map(|activation| {
            let peer_id = persistent_consensus_state.this_peer_id();
            let signer = activation
                .authority_bundle
                .manifest
                .peers
                .iter()
                .find(|peer| peer.peer_id == peer_id)
                .map(|peer| &peer.signer)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "private ORAM activation authority does not pin this peer identity"
                    )
                })?;
            PrivateOramPeerRecoveryIdentity::open_or_create(
                &settings.storage.storage_path,
                peer_id,
                PrivateOramPeerIdentityOpenPolicy::RequirePinned(signer),
            )
            .map(Arc::new)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
        })
        .transpose()?;
    reconcile_private_oram_external_recovery_installs(&settings.storage.storage_path, |key| {
        persistent_consensus_state.private_oram_external_recovery(key)
    })
    .map_err(|err| {
        anyhow::anyhow!("Failed to reconcile private ORAM recovery installation: {err}")
    })?;
    let private_oram_recovery_install_pending =
        private_oram_external_recovery_install_is_pending(&settings.storage.storage_path)?;
    let private_oram_external_recovery_active =
        persistent_consensus_state.has_active_private_oram_external_recovery();
    if (args.storage_snapshot.is_some() || args.snapshot.is_some())
        && (private_oram_recovery_install_pending || private_oram_external_recovery_active)
    {
        anyhow::bail!("Snapshot recovery is blocked by an active private ORAM external recovery");
    }
    if (args.storage_snapshot.is_some() || args.snapshot.is_some())
        && private_oram_mutation_unsettled
    {
        anyhow::bail!("Snapshot recovery is blocked by an unsettled private ORAM mutation");
    }
    if private_oram_recovery_install_pending
        || private_oram_external_recovery_active
        || private_oram_mutation_unsettled
    {
        settings.storage.handle_collection_load_errors = false;
    }

    let temp_path = settings.storage.temp_path.as_deref();

    let restored_collections = if let Some(full_snapshot) = args.storage_snapshot {
        recover_full_snapshot(
            temp_path,
            &full_snapshot,
            &settings.storage.storage_path,
            args.force_snapshot,
            persistent_consensus_state.this_peer_id(),
            is_distributed_deployment,
            &settings,
        )
        .map_err(|err| anyhow::anyhow!("{err}"))?
    } else if let Some(snapshots) = args.snapshot {
        // recover from snapshots
        recover_snapshots(
            &snapshots,
            args.force_snapshot,
            temp_path,
            &settings.storage.storage_path,
            persistent_consensus_state.this_peer_id(),
            is_distributed_deployment,
            &settings,
        )
        .map_err(|err| anyhow::anyhow!("{err}"))?
    } else {
        vec![]
    };
    reconcile_private_oram_external_recovery_installs(&settings.storage.storage_path, |key| {
        persistent_consensus_state.private_oram_external_recovery(key)
    })
    .map_err(|err| {
        anyhow::anyhow!("Failed to reconcile private ORAM recovery installation: {err}")
    })?;

    // Create and own search runtime out of the scope of async context to ensure correct
    // destruction of it
    let search_runtime = create_search_runtime(settings.storage.performance.max_search_threads)
        .map_err(|err| anyhow::anyhow!("Can't create search runtime: {err}"))?;

    let update_runtime = create_update_runtime(
        settings
            .storage
            .performance
            .max_optimization_runtime_threads,
    )
    .map_err(|err| anyhow::anyhow!("Can't create optimizer runtime: {err}"))?;

    let general_runtime = create_general_purpose_runtime()
        .map_err(|err| anyhow::anyhow!("Can't create general purpose runtime: {err}"))?;
    let runtime_handle = general_runtime.handle().clone();

    // Use global CPU budget for optimizations based on settings
    let cpu_budget = get_cpu_budget(settings.storage.performance.optimizer_cpu_budget);
    let io_budget = get_io_budget(settings.storage.performance.optimizer_io_budget, cpu_budget);
    let optimizer_resource_budget = ResourceBudget::new(cpu_budget, io_budget);

    // Create a signal sender and receiver. It is used to communicate with the consensus thread.
    let (propose_sender, propose_receiver) = std::sync::mpsc::channel();

    let propose_operation_sender = if settings.cluster.enabled {
        // High-level channel which could be used to send User-space consensus operations
        Some(OperationSender::new(propose_sender))
    } else {
        // We don't need sender for the single-node mode
        None
    };

    // Channel service is used to manage connections between peers.
    // It allocates required number of channels and manages proper reconnection handling
    let mut channel_service = ChannelService::new(
        settings.service.http_port,
        settings.service.enable_tls,
        settings.service.api_key.clone(),
        settings.service.alt_api_key.clone(),
    );

    if is_distributed_deployment {
        // We only need channel_service in case if cluster is enabled.
        // So we initialize it with real values here
        let p2p_grpc_timeout = Duration::from_millis(settings.cluster.grpc_timeout_ms);
        let connection_timeout = Duration::from_millis(settings.cluster.connection_timeout_ms);

        let tls_config = load_tls_client_config(&settings)?;

        channel_service.channel_pool = Arc::new(TransportChannelPool::new(
            p2p_grpc_timeout,
            connection_timeout,
            settings.cluster.p2p.connection_pool_size,
            tls_config,
        ));
        channel_service.id_to_address = persistent_consensus_state.peer_address_by_id.clone();
        channel_service.id_to_metadata = persistent_consensus_state.peer_metadata_by_id.clone();
    }

    // Table of content manages the list of collections.
    // It is a main entry point for the storage.
    let toc = TableOfContent::new(
        &settings.storage,
        search_runtime,
        update_runtime,
        general_runtime,
        optimizer_resource_budget,
        channel_service.clone(),
        persistent_consensus_state.this_peer_id(),
        propose_operation_sender.clone(),
    )?;

    finalize_committed_private_oram_external_recovery_installs(
        &settings.storage.storage_path,
        |key| persistent_consensus_state.private_oram_external_recovery(key),
        |collection_name, collection_id, layout_digest| {
            toc.private_oram_external_recovery_collection_is_loaded(
                collection_name,
                collection_id,
                layout_digest,
            )
        },
    )
    .map_err(|err| {
        anyhow::anyhow!("Failed to finalize private ORAM recovery installation: {err}")
    })?;

    toc.clear_all_tmp_directories()?;

    // Here we load all stored collections.
    runtime_handle.block_on(async {
        for collection in toc.all_collections(&FULL_ACCESS).await {
            log::debug!("Loaded collection: {collection}");
        }
    });

    let toc_arc = Arc::new(toc);
    let storage_path = toc_arc.storage_path();

    // Holder for all actively running threads of the service: web, gPRC, consensus, etc.
    let mut handles: Vec<JoinHandle<Result<(), Error>>> = vec![];

    // Router for external queries.
    // It decides if query should go directly to the ToC or through the consensus.
    let mut dispatcher = Dispatcher::new(toc_arc.clone());

    let (telemetry_collector, tonic_telemetry_collector, dispatcher_arc, health_checker);
    if is_distributed_deployment {
        let consensus_state: ConsensusStateRef = ConsensusManager::new(
            persistent_consensus_state,
            toc_arc.clone(),
            propose_operation_sender.ok_or_else(|| {
                anyhow::anyhow!("Distributed deployment requires a consensus proposal sender")
            })?,
            storage_path,
            collection::operations::types::PeerMetadata::current_with_crypto_runtime_capability_fingerprint(
                Some(crate::common::crypto::crypto_runtime_capability_fingerprint(&settings)),
            ),
        )
        .map_err(|err| anyhow::anyhow!("initialize consensus manager: {err}"))?
        .into();
        let is_new_deployment = consensus_state.is_new_deployment();

        dispatcher =
            dispatcher.with_consensus(consensus_state.clone(), settings.cluster.resharding_enabled);

        let toc_dispatcher = TocDispatcher::new(Arc::downgrade(&toc_arc), consensus_state.clone());
        toc_arc.with_toc_dispatcher(toc_dispatcher);

        dispatcher_arc = Arc::new(dispatcher);

        // Monitoring and telemetry.
        let telemetry =
            TelemetryCollector::new(settings.clone(), dispatcher_arc.clone(), reporting_id);
        tonic_telemetry_collector = telemetry.tonic_telemetry_collector.clone();

        telemetry_collector = Arc::new(tokio::sync::Mutex::new(telemetry));

        // `raft` crate uses `slog` crate so it is needed to use `slog_stdlog::StdLog` to forward
        // logs from it to `log` crate
        let slog_logger = slog::Logger::root(slog_stdlog::StdLog.fuse(), slog::o!());

        // Runs raft consensus in a separate thread.
        // Create a pipe `message_sender` to communicate with the consensus
        health_checker = Some(Arc::new(common::health::HealthChecker::spawn(
            toc_arc.clone(),
            consensus_state.clone(),
            &runtime_handle,
            // NOTE: `wait_for_bootstrap` should be calculated *before* starting `Consensus` thread
            consensus_state.is_new_deployment() && bootstrap.is_some(),
        )));

        let handle = Consensus::run(
            &slog_logger,
            consensus_state.clone(),
            bootstrap,
            args.uri.map(|uri| uri.to_string()),
            settings.clone(),
            channel_service,
            propose_receiver,
            telemetry_collector.clone(),
            tonic_telemetry_collector.clone(),
            toc_arc.clone(),
            private_oram_peer_identity.clone(),
            runtime_handle.clone(),
            args.reinit,
        )
        .map_err(|err| anyhow::anyhow!("Can't initialize consensus: {err}"))?;

        handles.push(handle);

        if let Some(identity) = private_oram_peer_identity.clone() {
            initialize_private_oram_mutation_supervisor_v2();
            let supervisor_consensus = consensus_state.clone();
            let supervisor_dispatcher = dispatcher_arc.clone();
            let supervisor_settings = Arc::new(settings.clone());
            let _private_oram_mutation_supervisor = runtime_handle.spawn(async move {
                supervisor_consensus.is_leader_established.await_ready();
                supervise_private_oram_mutations_v2(
                    supervisor_dispatcher,
                    supervisor_settings,
                    identity,
                )
                .await;
            });
        }

        let toc_arc_clone = toc_arc.clone();
        let consensus_state_clone = consensus_state.clone();
        let _cancel_transfer_handle = runtime_handle.spawn(async move {
            consensus_state_clone.is_leader_established.await_ready();
            match toc_arc_clone
                .cancel_related_transfers("Source or target peer restarted")
                .await
            {
                Ok(_) => {
                    log::debug!("All transfers if any cancelled");
                }
                Err(err) => {
                    log::error!("Can't cancel related transfers: {err}");
                }
            }
        });

        // TODO(resharding): Remove resharding driver?
        //
        // runtime_handle.block_on(async {
        //     toc_arc.resume_resharding_tasks().await;
        // });

        // Reinitialized followers start with an empty Raft state, but their collections
        // already belong to the cluster and are restored by the bootstrap peer's snapshot.
        // Re-proposing them as standalone migrations would create duplicates and abort startup.
        let collections_to_recover_in_consensus = if is_new_deployment && !args.reinit {
            let existing_collections =
                runtime_handle.block_on(toc_arc.all_collections(&FULL_ACCESS));
            existing_collections
                .into_iter()
                .map(|pass| pass.name().to_string())
                .collect()
        } else {
            restored_collections
        };

        if !collections_to_recover_in_consensus.is_empty() {
            runtime_handle.block_on(handle_existing_collections(
                toc_arc.clone(),
                consensus_state.clone(),
                dispatcher_arc.clone(),
                consensus_state.this_peer_id(),
                collections_to_recover_in_consensus,
            ))?;
        }
    } else {
        log::info!("Distributed mode disabled");
        dispatcher_arc = Arc::new(dispatcher);

        // Monitoring and telemetry.
        let telemetry =
            TelemetryCollector::new(settings.clone(), dispatcher_arc.clone(), reporting_id);

        tonic_telemetry_collector = telemetry.tonic_telemetry_collector.clone();
        telemetry_collector = Arc::new(tokio::sync::Mutex::new(telemetry));
        health_checker = None;
    };

    //
    // Telemetry reporting
    //

    if reporting_enabled {
        log::info!("Telemetry reporting enabled, id: {reporting_id}");

        runtime_handle.spawn(TelemetryReporter::run(telemetry_collector.clone()));
    } else {
        log::info!("Telemetry reporting disabled");
    }

    if settings.service.hardware_reporting == Some(true) {
        log::info!("Hardware reporting enabled");
    }

    // Setup subscribers to listen for issue-able events
    issues_setup::setup_subscribers(&settings);
    init_requests_profile_collector(runtime_handle.clone());

    // Helper to better log start errors
    let log_err_if_any = |server_name, result| match result {
        Err(err) => {
            log::error!("Error while starting {server_name} server: {err}");
            Err(err)
        }
        ok => ok,
    };

    //
    // Inference Service
    //
    if let Err(err) = InferenceService::init_global(settings.inference.clone()) {
        log::error!("Inference service init failed: {err}");
    }

    //
    // REST API server
    //

    {
        let dispatcher_arc = dispatcher_arc.clone();
        let telemetry_collector = telemetry_collector.clone();
        let settings = settings.clone();
        let private_oram_peer_identity = private_oram_peer_identity.clone();
        let handle = thread::Builder::new()
            .name("web".to_string())
            .spawn(move || {
                log_err_if_any(
                    "REST",
                    actix::init(
                        dispatcher_arc.clone(),
                        telemetry_collector,
                        health_checker,
                        settings,
                        logger_handle,
                        private_oram_peer_identity,
                    ),
                )
            })
            .map_err(|err| anyhow::anyhow!("Can't spawn REST thread: {err}"))?;
        handles.push(handle);
    }

    //
    // Extra `/metrics` server
    //

    if let Some(metrics_port) = settings.service.metrics_port {
        let telemetry_collector = telemetry_collector.clone();
        let settings = settings.clone();
        let handle = thread::Builder::new()
            .name("metrics".to_string())
            .spawn(move || {
                log_err_if_any(
                    "Metrics",
                    actix::metrics_service::init_metrics(
                        metrics_port,
                        telemetry_collector,
                        settings,
                    ),
                )
            })
            .map_err(|err| anyhow::anyhow!("Can't spawn metrics thread: {err}"))?;
        handles.push(handle);
    }

    //
    // gRPC server
    //

    if let Some(grpc_port) = settings.service.grpc_port {
        let settings = settings.clone();
        let handle = thread::Builder::new()
            .name("grpc".to_string())
            .spawn(move || {
                log_err_if_any(
                    "gRPC",
                    tonic::init(
                        dispatcher_arc,
                        tonic_telemetry_collector,
                        settings,
                        grpc_port,
                        runtime_handle,
                    ),
                )
            })
            .map_err(|err| anyhow::anyhow!("Can't spawn gRPC thread: {err}"))?;
        handles.push(handle);
    } else {
        log::info!("gRPC endpoint disabled");
    }

    #[cfg(feature = "service_debug")]
    {
        use std::fmt::Write;

        use parking_lot::deadlock;

        const DEADLOCK_CHECK_PERIOD: Duration = Duration::from_secs(10);

        thread::Builder::new()
            .name("deadlock_checker".to_string())
            .spawn(move || {
                loop {
                    thread::sleep(DEADLOCK_CHECK_PERIOD);
                    let deadlocks = deadlock::check_deadlock();
                    if deadlocks.is_empty() {
                        continue;
                    }

                    let mut error = format!("{} deadlocks detected\n", deadlocks.len());
                    for (i, threads) in deadlocks.iter().enumerate() {
                        let _ = writeln!(error, "Deadlock #{i}");
                        for t in threads {
                            let _ = writeln!(
                                error,
                                "Thread Id {:#?}\n{:#?}",
                                t.thread_id(),
                                t.backtrace(),
                            );
                        }
                    }
                    log::error!("{error}");
                }
            })
            .map_err(|err| anyhow::anyhow!("Can't spawn deadlock checker thread: {err}"))?;
    }

    touch_started_file_indicator();

    for handle in handles {
        let thread_name = handle.thread().name().unwrap_or("<unnamed>").to_string();
        log::debug!("Waiting for thread {thread_name} to finish");
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err(anyhow::anyhow!("Thread {thread_name} panicked")),
        }
    }
    drop(toc_arc);
    drop(settings);
    Ok(())
}
