use std::net::IpAddr;
use std::sync::Arc;

use collection::collection::Collection;
use collection::common::sha_256;
use collection::common::snapshot_stream::SnapshotStream;
use collection::config::CollectionConfigInternal;
use collection::operations::snapshot_ops::{
    ShardSnapshotLocation, SnapshotDescription, SnapshotPriority,
};
use collection::operations::verification::{VerificationPass, new_unchecked_verification_pass};
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::ShardId;
use collection::shards::transfer::RecoveryStage;
use reqwest::Url;
use shard::snapshots::snapshot_data::SnapshotData;
use shard::snapshots::snapshot_manifest::{RecoveryType, SnapshotManifest};
use storage::content_manager::errors::StorageError;
use storage::content_manager::snapshots;
use storage::content_manager::snapshots::download_result::DownloadResult;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use tokio::sync::OwnedRwLockWriteGuard;

use super::auth::Auth;
use super::crypto::validate_recovered_collection_crypto_config;
use super::http_client::HttpClient;
use super::private_hnsw::{
    PrivateHnswCollectionSnapshotGuard, begin_private_hnsw_collection_lifecycle,
    begin_private_hnsw_collection_snapshot,
};
use super::private_result_oram::{
    PrivateResultOramCollectionSnapshotGuard, begin_private_result_oram_collection_lifecycle,
    begin_private_result_oram_collection_snapshot,
};
use crate::settings::Settings;

pub fn validate_snapshot_url_api_key_policy(
    url: &Url,
    api_key: Option<&str>,
    operation: &str,
) -> Result<(), StorageError> {
    if matches!(url.scheme(), "http" | "https")
        && (!url.username().is_empty() || url.password().is_some())
    {
        return Err(StorageError::bad_input(format!(
            "{operation} does not allow credentials embedded in caller-provided snapshot URL {}; use configured peer credentials instead",
            redacted_snapshot_url_for_message(url),
        )));
    }

    if api_key.is_some() && matches!(url.scheme(), "http" | "https") {
        return Err(StorageError::bad_input(format!(
            "{operation} does not allow api_key with caller-provided snapshot URL {}; configure a trusted peer transfer or host allowlist before forwarding credentials",
            redacted_snapshot_url_for_message(url),
        )));
    }

    Ok(())
}

pub fn validate_snapshot_peer_base_url_policy(
    url: &Url,
    operation: &str,
) -> Result<(), StorageError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(StorageError::bad_input(format!(
            "{operation} peer URL {} must use http or https",
            redacted_snapshot_url_for_message(url),
        )));
    }
    if url.scheme() == "http" {
        let loopback_http = url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost") || {
                host.parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
            }
        });
        if !loopback_http {
            return Err(StorageError::bad_input(format!(
                "{operation} peer URL {} must use https unless the host is loopback",
                redacted_snapshot_url_for_message(url),
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(StorageError::bad_input(format!(
            "{operation} does not allow credentials embedded in peer URL {}; use configured peer credentials instead",
            redacted_snapshot_url_for_message(url),
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(StorageError::bad_input(format!(
            "{operation} peer URL {} must not contain query parameters or fragments",
            redacted_snapshot_url_for_message(url),
        )));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(StorageError::bad_input(format!(
            "{operation} peer URL {} must be an origin-only URL without a path",
            redacted_snapshot_url_for_message(url),
        )));
    }

    Ok(())
}

pub(crate) fn redacted_snapshot_url_for_message(url: &Url) -> String {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_query(url.query().map(|_| "[redacted]"));
    redacted.set_fragment(url.fragment().map(|_| "[redacted]"));
    redacted.to_string()
}

#[derive(Default)]
pub(crate) struct PrivateOramCollectionLifecycleGuard {
    _private_hnsw_snapshot_guard: Option<PrivateHnswCollectionSnapshotGuard>,
    _private_result_snapshot_guard: Option<PrivateResultOramCollectionSnapshotGuard>,
}

pub(crate) async fn begin_private_oram_collection_lifecycle_guard(
    dispatcher: &Dispatcher,
    auth: &Auth,
    collection_name: &str,
) -> Result<PrivateOramCollectionLifecycleGuard, StorageError> {
    let collection_pass = auth
        .check_global_access(
            AccessRequirements::new().manage(),
            "private_oram_collection_lifecycle",
        )?
        .issue_pass(collection_name)
        .into_static();
    let pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &pass);
    let collection = match toc.get_collection(&collection_pass).await {
        Ok(collection) => collection,
        Err(StorageError::NotFound { .. }) => {
            return Ok(PrivateOramCollectionLifecycleGuard::default());
        }
        Err(err) => return Err(err),
    };
    toc.require_private_oram_external_recovery_write_allowed(&collection)
        .await?;
    let config = collection.config_snapshot().await;
    Ok(PrivateOramCollectionLifecycleGuard {
        _private_hnsw_snapshot_guard: begin_private_hnsw_collection_lifecycle(
            collection.name(),
            &config,
        )?,
        _private_result_snapshot_guard: begin_private_result_oram_collection_lifecycle(
            collection.name(),
            &config,
        )?,
    })
}

pub(crate) async fn begin_private_oram_collection_recovery(
    dispatcher: &Dispatcher,
    auth: &Auth,
    collection_name: &str,
) -> Result<PrivateOramCollectionLifecycleGuard, StorageError> {
    begin_private_oram_collection_lifecycle_guard(dispatcher, auth, collection_name).await
}

pub async fn do_create_full_snapshot(
    dispatcher: &Dispatcher,
    auth: Auth,
) -> Result<SnapshotDescription, StorageError> {
    let collections_pass =
        auth.check_global_access(AccessRequirements::new().manage(), "create_full_snapshot")?;
    let pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &pass).clone();

    let mut private_hnsw_snapshot_guards = Vec::new();
    let mut private_result_snapshot_guards = Vec::new();
    for collection_pass in toc.multipass_into_collections(&collections_pass).await {
        let collection = toc.get_collection(&collection_pass).await?;
        let config = collection.config_snapshot().await;
        if let Some(snapshot_guard) =
            begin_private_hnsw_collection_snapshot(collection.name(), &config)?
        {
            private_hnsw_snapshot_guards.push(snapshot_guard);
        }
        if let Some(snapshot_guard) =
            begin_private_result_oram_collection_snapshot(collection.name(), &config)?
        {
            private_result_snapshot_guards.push(snapshot_guard);
        }
    }

    let snapshot = snapshots::do_create_full_snapshot(dispatcher, auth).await;
    drop(private_result_snapshot_guards);
    drop(private_hnsw_snapshot_guards);
    snapshot
}

/// # Cancel safety
///
/// This function is cancel safe.
pub async fn create_shard_snapshot(
    toc: Arc<TableOfContent>,
    auth: &Auth,
    collection_name: String,
    shard_id: ShardId,
) -> Result<SnapshotDescription, StorageError> {
    let collection_pass = auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().write().extras(),
        "create_shard_snapshot",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    collection
        .validate_private_oram_shard_snapshot_allowed("shard snapshot creation")
        .await?;

    let _telemetry_scope_guard = toc
        .snapshot_telemetry_collector(&collection_name)
        .running_snapshots
        .measure_scope();

    let snapshot = collection
        .create_shard_snapshot(shard_id, &toc.optional_temp_or_snapshot_temp_path()?)
        .await?;

    Ok(snapshot)
}

/// # Cancel safety
///
/// This function is cancel safe.
pub async fn stream_shard_snapshot(
    toc: Arc<TableOfContent>,
    auth: &Auth,
    collection_name: String,
    shard_id: ShardId,
    manifest: Option<SnapshotManifest>,
) -> Result<SnapshotStream, StorageError> {
    let collection_pass = auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().write().extras(),
        "stream_shard_snapshot",
    )?;

    let collection = toc.get_collection(&collection_pass).await?;
    collection
        .validate_private_oram_shard_snapshot_allowed("shard snapshot streaming")
        .await?;

    let _telemetry_scope_guard = toc
        .snapshot_telemetry_collector(&collection_name)
        .running_snapshots
        .measure_scope();

    if let Some(old_manifest) = &manifest {
        let current_manifest = collection.get_partial_snapshot_manifest(shard_id).await?;

        // If `old_manifest` is *exactly* the same, as `current_manifest`, return specialized error
        // instead of creating partial snapshot.
        //
        // Snapshot manifest format is flexible, so it *might* be possible that manifests are *not*
        // exactly the same, but resulting partial snapshot will still be "empty", but:
        // - it should *not* happen in practice currently
        // - we intentionally use exact equality as the most "conservative" comparison, just in case
        if old_manifest == &current_manifest {
            return Err(StorageError::EmptyPartialSnapshot { shard_id });
        }
    }

    let snapshot_stream = toc
        .get_collection(&collection_pass)
        .await?
        .stream_shard_snapshot(
            shard_id,
            manifest,
            &toc.optional_temp_or_snapshot_temp_path()?,
        )
        .await?;

    Ok(snapshot_stream)
}

/// # Cancel safety
///
/// This function is cancel safe.
pub async fn list_shard_snapshots(
    toc: Arc<TableOfContent>,
    auth: &Auth,
    collection_name: String,
    shard_id: ShardId,
) -> Result<Vec<SnapshotDescription>, StorageError> {
    let collection_pass = auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().extras(),
        "list_shard_snapshots",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    collection
        .validate_private_oram_shard_snapshot_allowed("shard snapshot listing")
        .await?;
    let snapshots = collection.list_shard_snapshots(shard_id).await?;
    Ok(snapshots)
}

/// # Cancel safety
///
/// This function is cancel safe.
pub async fn delete_shard_snapshot(
    toc: Arc<TableOfContent>,
    auth: &Auth,
    collection_name: String,
    shard_id: ShardId,
    snapshot_name: String,
) -> Result<(), StorageError> {
    let collection_pass = auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().write().extras(),
        "delete_shard_snapshot",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    collection
        .validate_private_oram_shard_snapshot_allowed("shard snapshot deletion")
        .await?;
    let snapshot_manager = collection.get_snapshots_storage_manager()?;

    let snapshot_path = collection
        .shards_holder()
        .read()
        .await
        .get_shard_snapshot_path(collection.snapshots_path(), shard_id, &snapshot_name)
        .await?;

    tokio::spawn(async move { snapshot_manager.delete_snapshot(&snapshot_path).await }).await??;

    Ok(())
}

/// # Cancel safety
///
/// This function is cancel safe.
#[allow(clippy::too_many_arguments)]
pub async fn recover_shard_snapshot(
    toc: Arc<TableOfContent>,
    auth: &Auth,
    collection_name: String,
    shard_id: ShardId,
    snapshot_location: ShardSnapshotLocation,
    snapshot_priority: SnapshotPriority,
    checksum: Option<String>,
    client: HttpClient,
    api_key: Option<String>,
    runtime_settings: Option<Settings>,
) -> Result<(), StorageError> {
    let collection_pass = auth
        .check_global_access(AccessRequirements::new().manage(), "recover_shard_snapshot")?
        .issue_pass(&collection_name)
        .into_static();

    // - `recover_shard_snapshot_impl` is *not* cancel safe
    //   - but the task is *spawned* on the runtime and won't be cancelled, if request is cancelled

    cancel::future::spawn_cancel_on_drop(async move |cancel| {
        let pre_recovery_task = async {
            let collection = toc.get_collection(&collection_pass).await?;
            collection.assert_shard_exists(shard_id).await?;
            collection
                .validate_private_oram_shard_snapshot_allowed("shard snapshot recovery")
                .await?;

            // Default temporary path to storage dir, to allow faster recovery within the same volume
            let download_dir = toc.optional_temp_or_storage_temp_path()?;
            Result::<_, StorageError>::Ok((collection, download_dir))
        };

        let (collection, download_dir) =
            cancel::future::cancel_on_token(cancel.clone(), pre_recovery_task).await??;

        // Once recovery tracking starts, `finish_shard_recovery` must run on all paths
        let recovery_progress = collection
            .shards_holder()
            .read()
            .await
            .start_shard_recovery(shard_id);

        let download_task = async {
            let DownloadResult {
                snapshot,
                hash
            } = match snapshot_location {
                ShardSnapshotLocation::Url(url) => {
                    if !matches!(url.scheme(), "http" | "https") {
                        let description = format!(
                            "Invalid snapshot URL {}: URLs with {} scheme are not supported",
                            redacted_snapshot_url_for_message(&url),
                            url.scheme(),
                        );

                        return Err(StorageError::bad_input(description));
                    }
                    validate_snapshot_url_api_key_policy(
                        &url,
                        api_key.as_deref(),
                        "shard snapshot recovery",
                    )?;

                    recovery_progress
                        .lock()
                        .set_stage(RecoveryStage::Downloading);

                    let client = client.client(api_key.as_deref())?;
                    snapshots::download::download_snapshot(
                        &client,
                        url,
                        &download_dir,
                        collection.snapshots_path(),
                        checksum.is_some(),
                    )
                    .await?
                }

                ShardSnapshotLocation::Path(snapshot_file_name) => {
                    let snapshot_path = collection
                        .shards_holder()
                        .read()
                        .await
                        .get_shard_snapshot_path(
                            collection.snapshots_path(),
                            shard_id,
                            &snapshot_file_name,
                        )
                        .await?;

                    let snapshot_file = collection
                        .get_snapshots_storage_manager()?
                        .get_snapshot_file(&snapshot_path, &download_dir)
                        .await?;

                    let hash = if checksum.is_some() {
                        Some(sha_256::hash_file(&snapshot_path).await?)
                    } else {
                        None
                    };

                    DownloadResult {
                        snapshot: SnapshotData::Packed(snapshot_file),
                        hash,
                    }
                }
            };

            if let Some(checksum) = checksum {
                if let Some(snapshot_checksum) = hash {
                    if !sha_256::hashes_equal(&snapshot_checksum, &checksum) {
                        return Err(StorageError::bad_input(format!(
                            "Snapshot checksum mismatch: expected {checksum}, got {snapshot_checksum}"
                        )));
                    }
                } else {
                    return Err(StorageError::service_error(
                        "Snapshot checksum could not be verified".to_string(),
                    ));
                }
            }

            Ok(snapshot)
        };

        let snapshot_data =
            cancel::future::cancel_on_token(cancel.clone(), download_task).await??;

        // `recover_shard_snapshot_impl` is *not* cancel safe
        let result = recover_shard_snapshot_impl(
            &toc,
            &collection,
            shard_id,
            snapshot_data,
            snapshot_priority,
            RecoveryType::Full,
            cancel,
            runtime_settings.as_ref(),
        )
        .await;

        // Finish tracking recovery progress
        collection
            .shards_holder()
            .read()
            .await
            .finish_shard_recovery(shard_id);

        result
    })
    .await??;

    Ok(())
}

/// # Cancel safety
///
/// This function is *not* cancel safe.
pub async fn recover_shard_snapshot_impl(
    toc: &TableOfContent,
    collection: &Collection,
    shard: ShardId,
    snapshot_data: SnapshotData,
    priority: SnapshotPriority,
    recovery_type: RecoveryType,
    cancel: cancel::CancellationToken,
    runtime_settings: Option<&Settings>,
) -> Result<(), StorageError> {
    let _recover_tracker_guard = toc
        .snapshot_telemetry_collector(collection.name())
        .running_snapshot_recovery
        .measure_scope();

    let config = collection.config_snapshot().await;
    collection
        .validate_private_oram_shard_snapshot_allowed(if recovery_type.is_partial() {
            "partial shard snapshot recovery"
        } else {
            "shard snapshot recovery"
        })
        .await?;
    validate_shard_snapshot_recovery_crypto_runtime(runtime_settings, collection.name(), &config)?;

    // `Collection::restore_shard_snapshot` and `activate_shard` calls *have to* be executed as a
    // single transaction
    //
    // It is *possible* to make this function to be cancel safe, but it is *extremely tedious* to do so

    // TODO: `Collection::restore_shard_snapshot` *is* cancel-safe, but `recover_shard_snapshot_impl` is *not* cancel-safe (yet)
    collection
        .restore_shard_snapshot(
            shard,
            snapshot_data,
            recovery_type,
            toc.this_peer_id,
            toc.is_distributed(),
            // Default temporary path to storage dir, to allow faster recovery within the same volume
            &toc.optional_temp_or_storage_temp_path()?,
            cancel,
        )
        .await?
        .await?;

    let state = collection.state().await;
    let shard_info = state.shards.get(&shard).ok_or_else(|| {
        StorageError::service_error(format!(
            "shard snapshot recovery for collection {} restored shard {shard}, but the shard \
             metadata is missing after restore",
            collection.name(),
        ))
    })?;

    // TODO: Unify (and de-duplicate) "recovered shard state notification" logic in `_do_recover_from_snapshot` with this one!

    let other_active_replicas: Vec<_> = shard_info
        .replicas
        .iter()
        .map(|(&peer, &state)| (peer, state))
        .filter(|&(peer, state)| {
            // Check if there are *other* active replicas, after recovering shard snapshot.
            // This should include `ReshardingScaleDown` replicas.

            let is_active = matches!(
                state,
                ReplicaState::Active | ReplicaState::ReshardingScaleDown
            );

            peer != toc.this_peer_id && is_active
        })
        .collect();

    if other_active_replicas.is_empty() || recovery_type.is_partial() {
        snapshots::recover::activate_shard(toc, collection, toc.this_peer_id, &shard).await?;
    } else {
        match priority {
            SnapshotPriority::NoSync => {
                snapshots::recover::activate_shard(toc, collection, toc.this_peer_id, &shard)
                    .await?;
            }

            SnapshotPriority::Snapshot => {
                snapshots::recover::activate_shard(toc, collection, toc.this_peer_id, &shard)
                    .await?;

                for &(peer, _) in other_active_replicas.iter() {
                    toc.send_set_replica_state_proposal(
                        collection.name().to_string(),
                        peer,
                        shard,
                        ReplicaState::Dead,
                        None,
                    )?;
                }
            }

            SnapshotPriority::Replica => {
                toc.send_set_replica_state_proposal(
                    collection.name().to_string(),
                    toc.this_peer_id,
                    shard,
                    ReplicaState::Dead,
                    None,
                )?;
            }

            // `ShardTransfer` is only used during snapshot *shard transfer*.
            // State transitions are performed as part of shard transfer *later*, so this simply does *nothing*.
            SnapshotPriority::ShardTransfer => (),
        }
    }

    Ok(())
}

fn validate_shard_snapshot_recovery_crypto_runtime(
    runtime_settings: Option<&Settings>,
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> Result<(), StorageError> {
    if config.params.effective_encryption().is_none() {
        return Ok(());
    }

    let Some(settings) = runtime_settings else {
        return Err(StorageError::bad_input(format!(
            "encrypted shard snapshot recovery for collection {collection_name} requires runtime \
             crypto settings so key, context, and provider availability are validated before \
             restore",
        )));
    };

    validate_recovered_collection_crypto_config(settings, collection_name, config)
}

pub async fn try_take_partial_snapshot_recovery_lock(
    dispatcher: &Dispatcher,
    collection_name: &str,
    shard_id: ShardId,
    auth: &Auth,
    pass: &VerificationPass,
) -> Result<Option<OwnedRwLockWriteGuard<()>>, StorageError> {
    let collection_pass = auth
        .check_global_access(
            AccessRequirements::new().manage(),
            "partial_snapshot_recovery_lock",
        )?
        .issue_pass(collection_name);

    let collection = dispatcher
        .toc(auth, pass)
        .get_collection(&collection_pass)
        .await?;
    collection
        .validate_private_oram_shard_snapshot_allowed("partial shard snapshot recovery")
        .await?;

    let recovery_lock = collection
        .try_take_partial_snapshot_recovery_lock(shard_id, RecoveryType::Partial)
        .await?;

    Ok(recovery_lock)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector, WalConfig,
    };
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, VECTOR_ENVELOPE_BINDING,
        VECTOR_OPENFHE_CKKS_PROVIDER,
    };
    use segment::types::{Distance, HnswConfig};
    use storage::rbac::{Access, Auth};
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw::do_upload_private_hnsw_manifest;
    use crate::common::private_hnsw_wire_fixture::{
        COLLECTION_NAME, PrivateHnswRouteWireFixture, PrivateResultOramRouteFixture, VECTOR_NAME,
        create_private_hnsw_collection, create_private_hnsw_collection_with_private_result_oram,
        route_e2e_guard, test_dispatcher,
    };
    use crate::common::private_result_oram::do_upload_private_result_oram_manifest;

    fn config_with_params(params: CollectionParams) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params,
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig {
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
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(42)),
            metadata: None,
        }
    }

    fn encrypted_config() -> CollectionConfigInternal {
        config_with_params(CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
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
        })
    }

    #[test]
    fn shard_snapshot_recovery_allows_missing_runtime_for_plaintext_collection() {
        validate_shard_snapshot_recovery_crypto_runtime(
            None,
            "docs",
            &config_with_params(CollectionParams::empty()),
        )
        .expect("plaintext recovery should not require crypto runtime settings");
    }

    #[test]
    fn snapshot_url_recovery_rejects_api_key_for_caller_provided_http_urls() {
        let http_url = Url::parse("http://example.test/snapshots/docs.snapshot").unwrap();
        let err =
            validate_snapshot_url_api_key_policy(&http_url, Some("secret"), "snapshot recovery")
                .expect_err("api_key must not be forwarded to caller-provided HTTP URLs");
        assert!(err.to_string().contains("does not allow api_key"));

        let https_url = Url::parse("https://example.test/snapshots/docs.snapshot").unwrap();
        let err =
            validate_snapshot_url_api_key_policy(&https_url, Some("secret"), "snapshot recovery")
                .expect_err("api_key must not be forwarded to caller-provided HTTPS URLs");
        assert!(err.to_string().contains("does not allow api_key"));

        validate_snapshot_url_api_key_policy(&http_url, None, "snapshot recovery")
            .expect("URL recovery without forwarded credentials is allowed");

        let file_url = Url::parse("file:///tmp/docs.snapshot").unwrap();
        validate_snapshot_url_api_key_policy(&file_url, Some("secret"), "snapshot recovery")
            .expect("non-network snapshot locations do not forward HTTP credentials");
    }

    #[test]
    fn snapshot_url_policy_rejects_and_redacts_embedded_credentials() {
        let url = Url::parse(
            "https://user:password@example.test/snapshots/docs.snapshot?token=secret#fragment",
        )
        .unwrap();
        let err = validate_snapshot_url_api_key_policy(&url, None, "snapshot recovery")
            .expect_err("embedded snapshot URL credentials must fail closed");
        let message = err.to_string();

        assert!(message.contains("does not allow credentials embedded"));
        assert!(
            message.contains("https://example.test/snapshots/docs.snapshot?[redacted]#[redacted]")
        );
        assert!(!message.contains("user"));
        assert!(!message.contains("password"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("fragment"));
    }

    #[test]
    fn snapshot_url_api_key_error_redacts_query_tokens() {
        let url = Url::parse("https://example.test/snapshots/docs.snapshot?token=secret").unwrap();
        let err = validate_snapshot_url_api_key_policy(&url, Some("api-key"), "snapshot recovery")
            .expect_err("snapshot api_key with caller URL must fail closed");
        let message = err.to_string();

        assert!(message.contains("does not allow api_key"));
        assert!(message.contains("https://example.test/snapshots/docs.snapshot?[redacted]"));
        assert!(!message.contains("secret"));
        assert!(!message.contains("api-key"));
    }

    #[test]
    fn private_oram_collection_lifecycle_guard_blocks_private_hnsw_upload() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let auth = Auth::new_internal(Access::full("private ORAM lifecycle guard test"));
            let recovery_guard =
                begin_private_oram_collection_lifecycle_guard(&dispatcher, &auth, COLLECTION_NAME)
                    .await
                    .expect("private ORAM lifecycle guard should open");
            let pass = new_unchecked_verification_pass();

            let err = do_upload_private_hnsw_manifest(
                dispatcher.toc(&auth, &pass),
                &auth,
                &settings,
                COLLECTION_NAME,
                VECTOR_NAME,
                fixture.manifest.clone(),
                fixture.manifest_signature.clone(),
            )
            .await
            .expect_err("active collection recovery must block private HNSW upload");
            let rendered = err.to_string();
            assert!(
                rendered.contains("upload requires no active collection lifecycle operation"),
                "{rendered}",
            );
            assert!(
                !rendered.contains(&fixture.manifest.root_hash),
                "{rendered}"
            );
            assert!(
                !rendered.contains(&fixture.manifest_signature.sig),
                "{rendered}"
            );
            assert!(
                !rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING),
                "{rendered}"
            );

            drop(recovery_guard);
        });
    }

    #[test]
    fn private_oram_collection_lifecycle_guard_blocks_private_result_oram_upload() {
        let _guard = route_e2e_guard();
        let hnsw_fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let result_fixture = PrivateResultOramRouteFixture::build();
        let settings = result_fixture.route_settings_with_private_hnsw(&hnsw_fixture);
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(&dispatcher).await;
            let auth = Auth::new_internal(Access::full("private result ORAM lifecycle guard test"));
            let recovery_guard =
                begin_private_oram_collection_lifecycle_guard(&dispatcher, &auth, COLLECTION_NAME)
                    .await
                    .expect("private ORAM lifecycle guard should open");
            let pass = new_unchecked_verification_pass();

            let err = do_upload_private_result_oram_manifest(
                dispatcher.toc(&auth, &pass),
                &auth,
                &settings,
                COLLECTION_NAME,
                result_fixture.manifest.clone(),
                result_fixture.signature.clone(),
            )
            .await
            .expect_err("active collection recovery must block private result ORAM upload");
            let rendered = err.to_string();
            assert!(
                rendered.contains("upload requires no active collection lifecycle operation"),
                "{rendered}",
            );
            assert!(
                !rendered.contains(&result_fixture.manifest.root_hash),
                "{rendered}"
            );
            assert!(
                !rendered.contains(&result_fixture.signature.sig),
                "{rendered}"
            );
            assert!(
                !rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING),
                "{rendered}"
            );

            drop(recovery_guard);
        });
    }

    #[test]
    fn snapshot_peer_base_url_policy_requires_origin_only_http_urls() {
        validate_snapshot_peer_base_url_policy(
            &Url::parse("https://peer.example.test").unwrap(),
            "partial snapshot recover_from",
        )
        .expect("origin-only HTTPS peer URL should be allowed");
        validate_snapshot_peer_base_url_policy(
            &Url::parse("http://127.0.0.1:6333/").unwrap(),
            "partial snapshot recover_from",
        )
        .expect("origin-only loopback HTTP peer URL should be allowed for local development");

        for (url, expected) in [
            ("file:///tmp/snapshot", "must use http or https"),
            (
                "http://peer.example.test:6333/",
                "must use https unless the host is loopback",
            ),
            (
                "https://peer.example.test/collections/docs",
                "without a path",
            ),
            (
                "https://peer.example.test?token=secret#fragment",
                "must not contain query parameters or fragments",
            ),
            (
                "https://user:password@peer.example.test",
                "does not allow credentials embedded",
            ),
        ] {
            let err = validate_snapshot_peer_base_url_policy(
                &Url::parse(url).unwrap(),
                "partial snapshot recover_from",
            )
            .expect_err("non-origin or credential-bearing peer URL must fail closed");
            let message = err.to_string();
            assert!(
                message.contains(expected),
                "expected {message:?} to contain {expected:?}",
            );
            assert!(!message.contains("password"));
            assert!(!message.contains("secret"));
            assert!(!message.contains("#fragment"));
        }
    }

    #[test]
    fn shard_snapshot_recovery_requires_runtime_for_encrypted_collection() {
        let err =
            validate_shard_snapshot_recovery_crypto_runtime(None, "docs", &encrypted_config())
                .expect_err("encrypted recovery without runtime settings must fail closed");

        assert!(err.to_string().contains("requires runtime crypto settings"));
    }

    #[test]
    fn shard_snapshot_recovery_requires_stable_uuid_for_encrypted_collection() {
        let settings = Settings::new(None).unwrap();
        let mut config = encrypted_config();
        config.uuid = None;

        let err = validate_shard_snapshot_recovery_crypto_runtime(Some(&settings), "docs", &config)
            .expect_err("encrypted shard recovery without stable UUID must fail closed");

        assert!(err.to_string().contains("missing a stable UUID"));
    }

    #[test]
    fn shard_snapshot_recovery_validates_encrypted_runtime_when_present() {
        let settings = Settings::new(None).unwrap();
        let err = validate_shard_snapshot_recovery_crypto_runtime(
            Some(&settings),
            "docs",
            &encrypted_config(),
        )
        .expect_err("missing runtime instance must fail encrypted recovery preflight");

        let rendered = err.to_string();
        assert!(
            rendered.contains("payload crypto runtime validation failed"),
            "{rendered}",
        );
        assert!(!rendered.contains("unknown payload crypto instance"));
        assert!(!rendered.contains("docs_payload_v1"));
    }

    #[test]
    fn shard_snapshot_recovery_rejects_client_envelopes_in_clustered_mode() {
        let mut settings = Settings::new(None).unwrap();
        settings.cluster.enabled = true;
        settings.crypto.instances.insert(
            "docs_payload_client_v1".to_string(),
            crate::settings::CryptoInstanceConfig {
                provider: "payload/client-aead@v1".to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: serde_json::json!({}),
            },
        );
        let config = config_with_params(CollectionParams {
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
            ..CollectionParams::empty()
        });

        let err = validate_shard_snapshot_recovery_crypto_runtime(Some(&settings), "docs", &config)
            .expect_err("clustered client envelope recovery must fail closed");

        assert!(
            err.to_string().contains("cluster-wide nonce replay ledger"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn shard_snapshot_recovery_validates_ckks_vector_public_material() {
        let settings = Settings {
            crypto: crate::settings::CryptoSettings {
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    crate::settings::CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/vector-v1".to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: serde_json::json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector@v1",
                            "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                            "score_plaintext_output_tcb_ack": "qdrant-sec-ckks-score-output-tcb-v1",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/vector-v1".to_string(),
                    crate::settings::CryptoMaterialConfig {
                        kind: "symmetric_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                        rk_epoch: Some(3),
                        ..crate::settings::CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    crate::settings::CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: Some(BASE64URL_NOPAD.encode(&[17_u8; 32])),
                        signature_public_key_b64: None,
                        signature_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                        max_output_bytes: None,
                        landlock_read_allow_roots: Vec::new(),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let mut params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some(VECTOR_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        params.vectors = VectorsConfig::Multi(BTreeMap::from([(
            "embedding".to_string(),
            VectorParamsBuilder::new(2, Distance::Dot).build(),
        )]));
        let config = config_with_params(params);

        validate_shard_snapshot_recovery_crypto_runtime(Some(&settings), "docs", &config)
            .expect("valid CKKS vector runtime must pass snapshot recovery preflight");

        let mut invalid_public_material = settings.clone();
        invalid_public_material
            .crypto
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                "crypto_context_b64".to_string(),
                serde_json::json!(BASE64URL_NOPAD.encode(&[])),
            );
        let err = validate_shard_snapshot_recovery_crypto_runtime(
            Some(&invalid_public_material),
            "docs",
            &config,
        )
        .expect_err("invalid CKKS public material must fail snapshot recovery preflight");

        assert!(
            err.to_string().contains("public material is invalid"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn shard_snapshot_recovery_rejects_missing_ckks_vector_metadata_material() {
        let settings = Settings {
            crypto: crate::settings::CryptoSettings {
                zero_trust_profile: None,
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    crate::settings::CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/missing-vector-v1".to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: serde_json::json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector@v1",
                            "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                            "score_plaintext_output_tcb_ack": "qdrant-sec-ckks-score-output-tcb-v1",
                        }),
                    },
                )]),
                materials: HashMap::new(),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    crate::settings::CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: Some(BASE64URL_NOPAD.encode(&[17_u8; 32])),
                        signature_public_key_b64: None,
                        signature_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                        max_output_bytes: None,
                        landlock_read_allow_roots: Vec::new(),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let mut params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some(VECTOR_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        params.vectors = VectorsConfig::Multi(BTreeMap::from([(
            "embedding".to_string(),
            VectorParamsBuilder::new(2, Distance::Dot).build(),
        )]));
        let config = config_with_params(params);

        let err = validate_shard_snapshot_recovery_crypto_runtime(Some(&settings), "docs", &config)
            .expect_err("missing vector metadata material must fail shard recovery preflight");

        assert!(
            err.to_string()
                .contains("references unknown metadata key material tenant-a/missing-vector-v1"),
            "unexpected error: {err:?}",
        );
    }
}
