use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use collection::collection::Collection;
use collection::collection::payload_index_schema::{
    PayloadIndexSchema, validate_payload_index_paths_for_encrypted_paths,
};
use collection::common::sha_256::hashes_equal;
use collection::config::{
    CollectionConfigInternal, CollectionParams, PRIVATE_HNSW_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_BINDING,
};
use collection::operations::snapshot_ops::{SnapshotPriority, SnapshotRecover};
use collection::operations::types::CollectionError;
use collection::operations::verification::new_unchecked_verification_pass;
use collection::private_hnsw_oram_store::PRIVATE_HNSW_ORAM_DIR;
use collection::private_oram_owner_journal::{
    PRIVATE_ORAM_OWNER_JOURNAL_DIR, PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
    PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2,
};
use collection::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR;
use collection::shards::check_shard_path;
use collection::shards::replica_set::replica_set_state::{
    MANUAL_RECOVERY_SHARD_STATE_VERSION, ReplicaState,
};
use collection::shards::shard::{PeerId, ShardId};
use common::save_on_disk::SaveOnDisk;
use fs_err::tokio as tokio_fs;
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
use shard::snapshots::snapshot_data::SnapshotData;
use shard::snapshots::snapshot_manifest::RecoveryType;

use crate::content_manager::collection_meta_ops::{
    CollectionMetaOperations, CreateCollectionOperation, CreatePayloadIndex,
};
use crate::content_manager::consensus_ops::{
    PrivateOramShardLayoutEntry, canonical_private_oram_shard_layout_digest,
};
use crate::content_manager::snapshots::download::download_snapshot;
use crate::content_manager::snapshots::download_result::DownloadResult;
use crate::content_manager::snapshots::private_oram_external_recovery::PrivateOramExternalRecoveryVerification;
use crate::dispatcher::Dispatcher;
use crate::rbac::{AccessRequirements, Auth, CollectionPass};
use crate::{StorageError, TableOfContent};

pub type SnapshotConfigValidator =
    Arc<dyn Fn(&str, &CollectionConfigInternal, &Path) -> Result<(), StorageError> + Send + Sync>;

pub fn verify_private_oram_external_recovery_snapshot(
    collection_name: &str,
    verification: &PrivateOramExternalRecoveryVerification,
    this_peer_id: PeerId,
    existing_config: &CollectionConfigInternal,
    recovery_mode: Option<&str>,
    snapshot_config_validator: Option<&SnapshotConfigValidator>,
) -> Result<(), StorageError> {
    let checkpoint = &verification.checkpoint_bundle().checkpoint;
    if checkpoint.source_peer_id != this_peer_id {
        return Err(invalid_private_oram_external_recovery_snapshot());
    }

    verification.reset_verification_output()?;
    Collection::restore_private_oram_external_recovery_snapshot(
        SnapshotData::new_packed_persistent(verification.snapshot_path()),
        verification.verify_temp_collection_path(),
        this_peer_id,
    )
    .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;

    let restored_path = verification.verify_temp_collection_path();
    let snapshot_config = CollectionConfigInternal::load(restored_path)
        .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    snapshot_config.validate_and_warn();
    let snapshot_collection_id = snapshot_config
        .stable_crypto_id(collection_name)
        .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    let existing_collection_id = existing_config
        .stable_crypto_id(collection_name)
        .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    if snapshot_collection_id != checkpoint.collection_id
        || existing_collection_id != checkpoint.collection_id
        || snapshot_config != *existing_config
    {
        return Err(invalid_private_oram_external_recovery_snapshot());
    }

    validate_private_oram_snapshot_restore_layouts(
        collection_name,
        &snapshot_config,
        restored_path,
    )
    .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    if let Some(validate_snapshot_config) = snapshot_config_validator {
        validate_snapshot_config(collection_name, &snapshot_config, restored_path)
            .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    }

    let payload_index_file = restored_path.join(PAYLOAD_INDEX_CONFIG_FILE);
    if !payload_index_file.is_file() {
        return Err(invalid_private_oram_external_recovery_snapshot());
    }
    let payload_schema: SaveOnDisk<PayloadIndexSchema> =
        SaveOnDisk::load_or_init_default(&payload_index_file)
            .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    validate_payload_index_paths_for_encrypted_paths(
        payload_schema.read().schema.keys(),
        &snapshot_config.params,
        "private ORAM external recovery",
    )
    .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;

    let inspection = Collection::inspect_private_oram_recovery_candidate_read_only(
        collection_name,
        restored_path,
        this_peer_id,
        recovery_mode,
    )
    .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    let layout_entries: Vec<_> = inspection
        .shards
        .iter()
        .map(|shard| PrivateOramShardLayoutEntry {
            shard_id: shard.shard_id,
            shard_key: shard.shard_key.clone(),
            owner_peer_ids: shard.owner_peer_ids.clone(),
        })
        .collect();
    let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
        &checkpoint.collection_id,
        inspection.config.params.sharding_method.unwrap_or_default(),
        &layout_entries,
    )
    .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    if inspection.config != snapshot_config
        || inspection.local_shard_ids != checkpoint.source_shard_ids
        || owner_peer_ids != checkpoint.owner_peer_ids
        || layout_digest != checkpoint.layout_digest
    {
        return Err(invalid_private_oram_external_recovery_snapshot());
    }

    common::fs::bulk_sync_dir(restored_path)
        .map_err(|_| invalid_private_oram_external_recovery_snapshot())?;
    verification.promote_verification_output()?;
    Ok(())
}

fn invalid_private_oram_external_recovery_snapshot() -> StorageError {
    StorageError::bad_input("private ORAM external recovery snapshot preflight failed")
}

const ORDINARY_PRIVATE_ORAM_V2_RECOVERY_REJECTION: &str = "snapshot contains distributed private ORAM V2 owner/parent state; ordinary snapshot recovery is forbidden; use consensus-qualified private ORAM external recovery";

/// Rejects V2 owner/parent state on recovery paths that cannot bind it to consensus authority.
///
/// This must run after unpacking into an isolated temporary directory and before any collection,
/// replica, or persisted startup state is replaced. External recovery intentionally does not call
/// this boundary because it verifies the consensus-qualified checkpoint and owner authority.
pub fn reject_ordinary_private_oram_v2_snapshot_recovery(
    collection_path: &Path,
) -> Result<(), StorageError> {
    if snapshot_entry_exists(&collection_path.join(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2))? {
        return Err(StorageError::bad_input(
            ORDINARY_PRIVATE_ORAM_V2_RECOVERY_REJECTION,
        ));
    }

    let hnsw_root = collection_path.join(PRIVATE_HNSW_ORAM_DIR);
    let hnsw_root_metadata = match std::fs::symlink_metadata(&hnsw_root) {
        Ok(metadata) if metadata.file_type().is_dir() => metadata,
        Ok(_) => return Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(private_oram_v2_boundary_inspection_failed()),
    };
    debug_assert!(hnsw_root_metadata.file_type().is_dir());

    let vector_entries =
        std::fs::read_dir(&hnsw_root).map_err(|_| private_oram_v2_boundary_inspection_failed())?;
    for vector_entry in vector_entries {
        let vector_entry =
            vector_entry.map_err(|_| private_oram_v2_boundary_inspection_failed())?;
        let file_type = vector_entry
            .file_type()
            .map_err(|_| private_oram_v2_boundary_inspection_failed())?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }

        let owner_temp = vector_entry.path().join("temp");
        for owner_root in [
            PRIVATE_ORAM_OWNER_JOURNAL_DIR,
            PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
        ] {
            if snapshot_entry_exists(&owner_temp.join(owner_root))? {
                return Err(StorageError::bad_input(
                    ORDINARY_PRIVATE_ORAM_V2_RECOVERY_REJECTION,
                ));
            }
        }
    }

    Ok(())
}

fn snapshot_entry_exists(path: &Path) -> Result<bool, StorageError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(private_oram_v2_boundary_inspection_failed()),
    }
}

fn private_oram_v2_boundary_inspection_failed() -> StorageError {
    StorageError::bad_input(
        "ordinary snapshot recovery could not verify absence of distributed private ORAM V2 owner/parent state",
    )
}

pub async fn activate_shard(
    toc: &TableOfContent,
    collection: &Collection,
    peer_id: PeerId,
    shard_id: &ShardId,
) -> Result<(), StorageError> {
    if toc.is_distributed() {
        log::debug!(
            "Activating shard {} of collection {} with consensus",
            shard_id,
            &collection.name()
        );
        toc.send_set_replica_state_proposal(
            collection.name().to_string(),
            peer_id,
            *shard_id,
            ReplicaState::Active,
            None,
        )?;
    } else {
        log::debug!(
            "Activating shard {} of collection {} locally",
            shard_id,
            &collection.name()
        );
        collection
            .set_shard_replica_state(*shard_id, peer_id, ReplicaState::Active, None)
            .await?;
    }
    Ok(())
}

/// # Cancel safety
///
/// This method is cancel safe.
pub async fn do_recover_from_snapshot(
    dispatcher: &Dispatcher,
    collection_name: &str,
    source: SnapshotRecover,
    auth: Auth,
    client: reqwest::Client,
    snapshot_config_validator: Option<SnapshotConfigValidator>,
) -> Result<bool, StorageError> {
    let multipass =
        auth.check_global_access(AccessRequirements::new().manage(), "recover_from_snapshot")?;

    let dispatcher = dispatcher.clone();
    let collection_pass = multipass.issue_pass(collection_name).into_static();

    let toc = dispatcher
        .toc(&auth, &new_unchecked_verification_pass())
        .clone();

    let res = toc
        .general_runtime_handle()
        .spawn(async move {
            _do_recover_from_snapshot(
                dispatcher,
                auth,
                collection_pass,
                source,
                &client,
                snapshot_config_validator,
            )
            .await
        })
        .await??;

    Ok(res)
}

/// # Cancel safety
///
/// This method is *not* cancel safe.
async fn _do_recover_from_snapshot(
    dispatcher: Dispatcher,
    auth: Auth,
    collection_pass: CollectionPass<'static>,
    source: SnapshotRecover,
    client: &reqwest::Client,
    snapshot_config_validator: Option<SnapshotConfigValidator>,
) -> Result<bool, StorageError> {
    let SnapshotRecover {
        location,
        priority,
        checksum,
        api_key: _,
    } = source;

    // All checks should've been done at this point.
    let pass = new_unchecked_verification_pass();

    let toc = dispatcher.toc(&auth, &pass);

    // Measure this scope for metrics/telemetry.
    // (This must be a named variable so it doesn't get dropped prematurely!)
    let _measure_guard = toc
        .snapshot_telemetry_collector(collection_pass.name())
        .running_snapshot_recovery
        .measure_scope();

    let this_peer_id = toc.this_peer_id;

    let is_distributed = toc.is_distributed();

    let DownloadResult {
        snapshot: snapshot_data,
        hash: snapshot_hash,
    } = download_snapshot(
        client,
        location,
        // Default temporary path to storage dir, to allow faster recovery within the same volume
        &toc.optional_temp_or_storage_temp_path()?,
        toc.snapshots_path(),
        checksum.is_some(),
    )
    .await?;

    if let Some(checksum) = checksum {
        let Some(snapshot_checksum) = snapshot_hash else {
            return Err(StorageError::service_error(
                "Snapshot checksum was not computed during download",
            ));
        };
        if !hashes_equal(&snapshot_checksum, &checksum) {
            return Err(StorageError::bad_input(format!(
                "Snapshot checksum mismatch: expected {checksum}, got {snapshot_checksum}"
            )));
        }
    }

    let temp_storage_path = toc.optional_temp_or_storage_temp_path()?;

    let tmp_collection_dir = tempfile::Builder::new()
        .prefix(&format!("col-{collection_pass}-recovery-"))
        .tempdir_in(temp_storage_path)?;

    let tmp_collection_dir_clone = tmp_collection_dir.path().to_path_buf();

    let restoring = tokio::task::spawn_blocking(move || {
        Collection::restore_snapshot(
            snapshot_data,
            &tmp_collection_dir_clone,
            this_peer_id,
            is_distributed,
        )?;
        common::fs::bulk_sync_dir(&tmp_collection_dir_clone)?;
        Ok::<(), StorageError>(())
    });
    restoring.await??;

    let snapshot_config = CollectionConfigInternal::load(tmp_collection_dir.path())?;
    snapshot_config.validate_and_warn();
    reject_ordinary_private_oram_v2_snapshot_recovery(tmp_collection_dir.path())?;
    validate_private_oram_snapshot_restore_layouts(
        collection_pass.name(),
        &snapshot_config,
        tmp_collection_dir.path(),
    )?;
    if let Some(validate_snapshot_config) = &snapshot_config_validator {
        validate_snapshot_config(
            collection_pass.name(),
            &snapshot_config,
            tmp_collection_dir.path(),
        )?;
    }

    let payload_index_file = tmp_collection_dir.path().join(PAYLOAD_INDEX_CONFIG_FILE);

    let payload_schema: SaveOnDisk<PayloadIndexSchema> =
        SaveOnDisk::load_or_init_default(&payload_index_file).map_err(|err| {
            StorageError::service_error(format!(
                "Failed to load payload index schema from {payload_index_file:?}: {err}"
            ))
        })?;

    let schema = payload_schema.read().schema.clone();
    validate_payload_index_paths_for_encrypted_paths(
        schema.keys(),
        &snapshot_config.params,
        "recover snapshot",
    )?;

    let collection = match toc.get_collection(&collection_pass).await {
        Ok(collection) => collection,
        Err(StorageError::NotFound { .. }) => {
            log::debug!("Collection {collection_pass} does not exist, creating it");
            let operation =
                CollectionMetaOperations::CreateCollection(CreateCollectionOperation::new(
                    collection_pass.to_string(),
                    snapshot_config.clone().into(),
                )?);
            dispatcher
                .submit_collection_meta_op(operation, auth.clone(), None)
                .await?;

            // Since we not just copy files into a collection dir,
            // but create collection in consensus and then copy data into recreated collection,
            // we also need to register all associated payload indexes in consensus.
            for (field_name, field_schema) in schema.iter() {
                let consensus_op =
                    CollectionMetaOperations::CreatePayloadIndex(CreatePayloadIndex {
                        collection_name: collection_pass.to_string(),
                        field_name: field_name.clone(),
                        field_schema: field_schema.clone(),
                    });

                dispatcher
                    .submit_collection_meta_op(consensus_op, auth.clone(), None)
                    .await?;
            }

            toc.get_collection(&collection_pass).await?
        }
        Err(error) => return Err(error),
    };
    toc.require_private_oram_external_recovery_write_allowed(&collection)
        .await?;
    // Fail before any replica is demoted through consensus: the per-shard recovery below would
    // otherwise reject a private ORAM collection only after every local replica was already
    // proposed into the recovery state.
    collection
        .validate_private_oram_shard_snapshot_allowed("collection snapshot recovery")
        .await?;

    let state = collection.state().await;
    validate_existing_collection_crypto_identity(
        collection_pass.name(),
        state.config.uuid,
        &state.config.params,
        snapshot_config.uuid,
        &snapshot_config.params,
    )?;

    // Check config compatibility
    // Check vectors config
    if snapshot_config.params.vectors != state.config.params.vectors {
        return Err(StorageError::bad_input(format!(
            "Snapshot is not compatible with existing collection: Collection vectors: {:?} Snapshot Vectors: {:?}",
            state.config.params.vectors, snapshot_config.params.vectors
        )));
    }
    // Check shard number
    if snapshot_config.params.shard_number != state.config.params.shard_number {
        return Err(StorageError::bad_input(format!(
            "Snapshot is not compatible with existing collection: Collection shard number: {:?} Snapshot shard number: {:?}",
            state.config.params.shard_number, snapshot_config.params.shard_number
        )));
    }
    state
        .config
        .params
        .check_compatible(&snapshot_config.params)?;

    let is_manual_recovery_state_supported = toc
        .get_channel_service()
        .all_peers_at_version(&MANUAL_RECOVERY_SHARD_STATE_VERSION);

    let recovery_state = if is_manual_recovery_state_supported {
        ReplicaState::ManualRecovery
    } else {
        ReplicaState::Partial
    };

    let local_states_before_recovery: HashMap<_, _> = state
        .shards
        .iter()
        .filter_map(|(&shard_id, shard_info)| {
            shard_info
                .replicas
                .get(&this_peer_id)
                .copied()
                .map(|replica_state| (shard_id, replica_state))
        })
        .collect();

    // Deactivate collection local shards during recovery
    for (shard_id, shard_info) in &state.shards {
        let local_shard_state = shard_info.replicas.get(&this_peer_id);
        match local_shard_state {
            None => {} // Shard is not on this node, skip
            Some(state) => {
                if state != &recovery_state {
                    toc.send_set_replica_state_proposal(
                        collection_pass.to_string(),
                        this_peer_id,
                        *shard_id,
                        recovery_state,
                        None,
                    )?;
                }
            }
        }
    }

    let priority = priority.unwrap_or_default();

    // Recover shards from the snapshot
    for (shard_id, shard_info) in &state.shards {
        let snapshot_shard_path = check_shard_path(tmp_collection_dir.path(), *shard_id).await?;
        log::debug!(
            "Recovering shard {} from {}",
            shard_id,
            snapshot_shard_path.display(),
        );

        // TODO:
        //   `_do_recover_from_snapshot` is not *yet* analyzed/organized for cancel safety,
        //   but `recover_local_shard_from` requires `cancel::CanellationToken` argument *now*,
        //   so we provide a token that is never triggered (in this case `recover_local_shard_from`
        //   works *exactly* as before the `cancel::CancellationToken` parameter was added to it)
        let recovered = collection
            .recover_local_shard_from(
                &snapshot_shard_path,
                RecoveryType::Full,
                *shard_id,
                cancel::CancellationToken::new(),
            )
            .await?;

        if !recovered {
            log::debug!("Shard {shard_id} is not in snapshot");

            // This peer may have been switched into recovery state before restore. If the snapshot
            // does not contain local data for this shard, revert to previous state so the replica
            // is not left stuck in `Partial`/`ManualRecovery`.
            if let Some(previous_state) = local_states_before_recovery.get(shard_id).copied()
                && previous_state != recovery_state
            {
                if toc.is_distributed() {
                    toc.send_set_replica_state_proposal(
                        collection_pass.to_string(),
                        this_peer_id,
                        *shard_id,
                        previous_state,
                        Some(recovery_state),
                    )?;
                } else {
                    collection
                        .set_shard_replica_state(
                            *shard_id,
                            this_peer_id,
                            previous_state,
                            Some(recovery_state),
                        )
                        .await?;
                }
            }

            continue;
        }

        // Staging delay: Allow observing Partial state before activation
        #[cfg(feature = "staging")]
        {
            let delay_secs: f64 = std::env::var("QDRANT_STAGING_SNAPSHOT_RECOVERY_DELAY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            if delay_secs > 0.0 {
                log::debug!(
                    "Staging: Delaying shard {shard_id} activation for {delay_secs}s (shard is in Partial state)"
                );
                tokio::time::sleep(std::time::Duration::from_secs_f64(delay_secs)).await;
                log::debug!("Staging: Delay complete, proceeding with activation");
            }
        }

        // If this is the only replica, we can activate it
        // If not - de-sync is possible, so we need to run synchronization
        let other_active_replicas: Vec<_> = shard_info
            .replicas
            .iter()
            .filter(|&(&peer_id, &state)| {
                // Check if there are *other* active replicas, after recovering collection snapshot.
                // This should include `ReshardingScaleDown` replicas.

                let is_active = matches!(
                    state,
                    ReplicaState::Active | ReplicaState::ReshardingScaleDown
                );

                peer_id != this_peer_id && is_active
            })
            .collect();

        if other_active_replicas.is_empty() {
            // No other active replicas, we can activate this shard
            // as there is no de-sync possible
            activate_shard(toc, &collection, this_peer_id, shard_id).await?;
        } else {
            match priority {
                SnapshotPriority::NoSync => {
                    activate_shard(toc, &collection, this_peer_id, shard_id).await?;
                }

                SnapshotPriority::Snapshot => {
                    // Snapshot is the source of truth, we need to remove all other replicas
                    activate_shard(toc, &collection, this_peer_id, shard_id).await?;

                    let replicas_to_keep = state.config.params.replication_factor.get() - 1;
                    let mut replicas_to_remove = other_active_replicas
                        .len()
                        .saturating_sub(replicas_to_keep as usize);

                    for (peer_id, _) in other_active_replicas {
                        if replicas_to_remove > 0 {
                            // Keep this replica
                            replicas_to_remove -= 1;

                            // Don't need more replicas, remove this one
                            toc.request_remove_replica(
                                collection_pass.to_string(),
                                *shard_id,
                                *peer_id,
                            )?;
                        } else {
                            toc.send_set_replica_state_proposal(
                                collection_pass.to_string(),
                                *peer_id,
                                *shard_id,
                                ReplicaState::Dead,
                                None,
                            )?;
                        }
                    }
                }

                SnapshotPriority::Replica => {
                    reject_private_oram_replica_priority_snapshot_recovery_until_supported(
                        collection_pass.name(),
                        &state.config.params,
                    )?;
                    // Replica is the source of truth, we need to sync recovered data with this replica
                    let Some((replica_peer_id, _state)) = other_active_replicas.into_iter().next()
                    else {
                        return Err(StorageError::service_error(
                            "snapshot recovery with replica priority requires another active replica",
                        ));
                    };
                    log::debug!(
                        "Running synchronization for shard {shard_id} of collection {collection_pass} from {replica_peer_id}",
                    );

                    // assume that if there is another peers, the server is distributed
                    toc.request_shard_transfer(
                        collection_pass.to_string(),
                        *shard_id,
                        *replica_peer_id,
                        this_peer_id,
                        true,
                        None,
                    )?;
                }

                // `ShardTransfer` is only used during snapshot *shard transfer*.
                // It is only exposed in internal gRPC API and only used for *shard* snapshot recovery.
                SnapshotPriority::ShardTransfer => {
                    return Err(StorageError::bad_request(
                        "shard-transfer snapshot priority is not valid for collection snapshot recovery",
                    ));
                }
            }
        }
    }

    // Explicitly trigger optimizers for the collection we have recovered. This prevents them from
    // remaining in grey state if the snapshot is not optimized.
    // See: <https://github.com/qdrant/qdrant/issues/5139>
    collection.trigger_optimizers().await;

    // Remove tmp collection dir
    tokio_fs::remove_dir_all(&tmp_collection_dir).await?;

    Ok(true)
}

fn validate_private_oram_snapshot_restore_layouts(
    collection_name: &str,
    snapshot_config: &CollectionConfigInternal,
    collection_path: &std::path::Path,
) -> Result<(), StorageError> {
    Collection::validate_private_oram_mutation_journal_snapshot_restore_layout(collection_path)
        .map_err(StorageError::from)?;
    Collection::validate_private_hnsw_oram_snapshot_restore_layout(
        collection_name,
        snapshot_config,
        collection_path,
    )
    .map_err(|err| sanitize_private_hnsw_snapshot_layout_error(collection_path, err))?;
    Collection::validate_private_result_oram_snapshot_restore_layout(
        collection_name,
        snapshot_config,
        collection_path,
    )
    .map_err(|err| sanitize_private_result_oram_snapshot_layout_error(collection_path, err))?;
    Ok(())
}

fn reject_private_oram_replica_priority_snapshot_recovery_until_supported(
    _collection_name: &str,
    params: &CollectionParams,
) -> Result<(), StorageError> {
    if !collection_params_use_private_oram_bucket_store(params) {
        return Ok(());
    }

    Err(StorageError::bad_request(format!(
        "replica-priority snapshot recovery for private ORAM collections \
         is disabled until encrypted ORAM bucket transfer and consensus-backed epoch/root \
         ownership are implemented; use snapshot priority or no-sync recovery with collection \
         snapshot restore preflight",
    )))
}

fn collection_params_use_private_oram_bucket_store(params: &CollectionParams) -> bool {
    params.encryption.as_ref().is_some_and(|encryption| {
        encryption.rules.iter().any(|rule| {
            matches!(
                rule.binding.as_deref(),
                Some(PRIVATE_HNSW_ORAM_BINDING) | Some(PRIVATE_RESULT_ORAM_BINDING)
            )
        })
    })
}

fn sanitize_private_hnsw_snapshot_layout_error(
    collection_path: &std::path::Path,
    err: CollectionError,
) -> StorageError {
    let rendered = err.to_string();
    if private_oram_layout_error_contains_sensitive_detail(
        &rendered,
        collection_path,
        PRIVATE_HNSW_ORAM_DIR,
    ) {
        return StorageError::bad_input("private HNSW ORAM snapshot layout validation failed");
    }
    StorageError::from(err)
}

fn sanitize_private_result_oram_snapshot_layout_error(
    collection_path: &std::path::Path,
    err: CollectionError,
) -> StorageError {
    let rendered = err.to_string();
    if private_oram_layout_error_contains_sensitive_detail(
        &rendered,
        collection_path,
        PRIVATE_RESULT_ORAM_DIR,
    ) {
        return StorageError::bad_input("private result ORAM snapshot layout validation failed");
    }
    StorageError::from(err)
}

fn private_oram_layout_error_contains_sensitive_detail(
    rendered: &str,
    collection_path: &std::path::Path,
    private_oram_dir: &str,
) -> bool {
    let collection_path = collection_path.to_string_lossy();
    rendered.contains(collection_path.as_ref())
        || rendered.contains(private_oram_dir)
        || private_oram_layout_error_contains_sensitive_marker(rendered)
        || rendered
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')))
            .any(|token| {
                token.ends_with(".bucket") || looks_like_base64url_private_oram_token(token)
            })
}

fn private_oram_layout_error_contains_sensitive_marker(rendered: &str) -> bool {
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

fn validate_existing_collection_crypto_identity(
    collection_name: &str,
    existing_uuid: Option<uuid::Uuid>,
    existing_params: &CollectionParams,
    snapshot_uuid: Option<uuid::Uuid>,
    snapshot_params: &CollectionParams,
) -> Result<(), StorageError> {
    let crypto_identity_bound = existing_params.effective_encryption().is_some()
        || snapshot_params.effective_encryption().is_some();
    if !crypto_identity_bound {
        return Ok(());
    }

    match (existing_uuid, snapshot_uuid) {
        (Some(existing_uuid), Some(snapshot_uuid)) if existing_uuid == snapshot_uuid => {}
        (Some(existing_uuid), Some(snapshot_uuid)) => {
            return Err(StorageError::bad_input(format!(
                "Snapshot is not compatible with existing encrypted collection {collection_name}: \
                 collection UUID {existing_uuid} does not match snapshot UUID {snapshot_uuid}; \
                 encrypted payload/vector AAD is bound to the stable collection identity",
            )));
        }
        (None, Some(snapshot_uuid)) => {
            return Err(StorageError::bad_input(format!(
                "Snapshot is not compatible with existing encrypted collection {collection_name}: \
                 existing collection is missing a stable UUID while snapshot UUID is {snapshot_uuid}; \
                 encrypted payload/vector AAD requires an explicit stable collection identity",
            )));
        }
        (Some(existing_uuid), None) => {
            return Err(StorageError::bad_input(format!(
                "Snapshot is not compatible with existing encrypted collection {collection_name}: \
                 snapshot is missing a stable UUID while existing collection UUID is {existing_uuid}; \
                 encrypted payload/vector AAD requires an explicit stable collection identity",
            )));
        }
        (None, None) => {
            return Err(StorageError::bad_input(format!(
                "Snapshot is not compatible with existing encrypted collection {collection_name}: \
                 both existing collection and snapshot are missing stable UUIDs; \
                 encrypted payload/vector AAD requires an explicit stable collection identity",
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use collection::config::{
        CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams,
        CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, PRIVATE_HNSW_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_BINDING, WalConfig,
    };
    use collection::operations::types::CollectionError;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::private_hnsw_oram_store::PRIVATE_HNSW_ORAM_DIR;
    use collection::private_oram_owner_journal::{
        PRIVATE_ORAM_OWNER_JOURNAL_DIR, PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
        PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2,
    };
    use collection::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR;
    use segment::types::HnswConfig;
    use uuid::Uuid;

    use super::{
        reject_ordinary_private_oram_v2_snapshot_recovery,
        reject_private_oram_replica_priority_snapshot_recovery_until_supported,
        sanitize_private_hnsw_snapshot_layout_error,
        sanitize_private_result_oram_snapshot_layout_error,
        validate_existing_collection_crypto_identity,
        validate_private_oram_snapshot_restore_layouts,
    };

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

    #[test]
    fn ordinary_collection_snapshot_recovery_rejects_private_oram_v2_parent_state() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-v2-parent-ordinary-recovery")
            .tempdir()
            .unwrap();
        std::fs::create_dir(temp_dir.path().join(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2)).unwrap();

        let err = reject_ordinary_private_oram_v2_snapshot_recovery(temp_dir.path())
            .expect_err("ordinary recovery must reject V2 parent state");
        let rendered = err.to_string();

        assert!(rendered.contains("ordinary snapshot recovery is forbidden"));
        assert!(rendered.contains("consensus-qualified private ORAM external recovery"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2));
    }

    #[test]
    fn ordinary_collection_snapshot_recovery_rejects_private_oram_v2_owner_state() {
        for owner_root in [
            PRIVATE_ORAM_OWNER_JOURNAL_DIR,
            PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2,
        ] {
            let temp_dir = tempfile::Builder::new()
                .prefix("private-oram-v2-owner-ordinary-recovery")
                .tempdir()
                .unwrap();
            std::fs::create_dir_all(
                temp_dir
                    .path()
                    .join(PRIVATE_HNSW_ORAM_DIR)
                    .join("text")
                    .join("temp")
                    .join(owner_root),
            )
            .unwrap();

            let err = reject_ordinary_private_oram_v2_snapshot_recovery(temp_dir.path())
                .expect_err("ordinary recovery must reject V2 owner state");
            let rendered = err.to_string();

            assert!(rendered.contains("ordinary snapshot recovery is forbidden"));
            assert!(rendered.contains("consensus-qualified private ORAM external recovery"));
            assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
            assert!(!rendered.contains(owner_root));
        }
    }

    #[test]
    fn ordinary_collection_snapshot_recovery_allows_private_oram_without_v2_state() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-no-v2-ordinary-recovery")
            .tempdir()
            .unwrap();
        std::fs::create_dir_all(
            temp_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("temp"),
        )
        .unwrap();

        reject_ordinary_private_oram_v2_snapshot_recovery(temp_dir.path())
            .expect("ordinary recovery boundary must allow snapshots without V2 state");
    }

    #[test]
    fn private_hnsw_snapshot_recovery_layout_error_is_sanitized() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-recover-sanitize")
            .tempdir()
            .unwrap();
        let leaked_path = temp_dir
            .path()
            .join("private_hnsw_oram")
            .join("text")
            .join("buckets")
            .join("00000000.bucket");
        let err = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::not_found(format!("private HNSW ORAM bucket {leaked_path:?}")),
        );

        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains("private_hnsw_oram"));

        let leaked_bucket = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::not_found("private HNSW ORAM bucket 00000000.bucket"),
        );
        let rendered = leaked_bucket.to_string();
        assert!(rendered.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!rendered.contains("00000000.bucket"));

        let leaked_root = "A".repeat(43);
        let err = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!("private HNSW ORAM root mismatch {leaked_root}")),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!rendered.contains(&leaked_root));

        let leaked_signature = "B".repeat(86);
        let err = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private HNSW ORAM manifest signature {leaked_signature}",
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!rendered.contains(&leaked_signature));

        let leaked_short_values = [
            "hnsw-short-bucket-id",
            "hnsw-short-path-label",
            "hnsw-short-leaf-label",
            "hnsw-short-node-id",
            "hnsw-short-entry-node-id",
            "hnsw-short-point-token",
            "hnsw-short-payload-token",
            "hnsw-short-proof-leaf",
            "hnsw-short-proof-sibling",
        ];
        let err = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private HNSW ORAM bucket_id {} path_label {} leaf_label {} node_id {} \
                 entry_node_id {} point_token {} payload_fetch_token {} proof leaf_hash {} \
                 sibling_hash {}",
                leaked_short_values[0],
                leaked_short_values[1],
                leaked_short_values[2],
                leaked_short_values[3],
                leaked_short_values[4],
                leaked_short_values[5],
                leaked_short_values[6],
                leaked_short_values[7],
                leaked_short_values[8],
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM snapshot layout validation failed"));
        for leaked in leaked_short_values {
            assert!(!rendered.contains(leaked));
        }

        let leaked_camel_values = [
            "hnsw-camel-bucket-id",
            "hnsw-camel-path-label",
            "hnsw-camel-leaf-label",
            "hnsw-camel-node-id",
            "hnsw-camel-entry-node-id",
            "hnsw-camel-point-token",
            "hnsw-camel-payload-token",
            "hnsw-camel-proof-value",
            "hnsw-camel-sibling-hash",
            "hnsw-camel-visited-node",
        ];
        let err = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private HNSW ORAM bucketIds {} pathLabel {} leafLabel {} nodeId {} \
                 entryNodeId {} pointToken {} payloadFetchToken {} proofValue {} \
                 siblingHash {} visitedNodeIds {}",
                leaked_camel_values[0],
                leaked_camel_values[1],
                leaked_camel_values[2],
                leaked_camel_values[3],
                leaked_camel_values[4],
                leaked_camel_values[5],
                leaked_camel_values[6],
                leaked_camel_values[7],
                leaked_camel_values[8],
                leaked_camel_values[9],
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM snapshot layout validation failed"));
        for leaked in leaked_camel_values {
            assert!(!rendered.contains(leaked));
        }

        let safe = sanitize_private_hnsw_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(
                "private HNSW ORAM snapshot contains an unconfigured vector store",
            ),
        );
        assert!(safe.to_string().contains("unconfigured vector store"));
    }

    #[test]
    fn private_result_oram_snapshot_recovery_layout_error_is_sanitized() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-storage-recover-sanitize")
            .tempdir()
            .unwrap();
        let leaked_path = temp_dir
            .path()
            .join(PRIVATE_RESULT_ORAM_DIR)
            .join("buckets")
            .join("00000000.bucket");
        let err = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::not_found(format!("private result ORAM bucket {leaked_path:?}")),
        );

        let rendered = err.to_string();
        assert!(rendered.contains("private result ORAM snapshot layout validation failed"));
        assert!(!rendered.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_DIR));

        let leaked_bucket = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::not_found("private result ORAM bucket 00000000.bucket"),
        );
        let rendered = leaked_bucket.to_string();
        assert!(rendered.contains("private result ORAM snapshot layout validation failed"));
        assert!(!rendered.contains("00000000.bucket"));

        let leaked_root = "A".repeat(43);
        let err = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM root mismatch {leaked_root}"
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private result ORAM snapshot layout validation failed"));
        assert!(!rendered.contains(&leaked_root));

        let leaked_ciphertext = "C".repeat(128);
        let err = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM bucket ciphertext {leaked_ciphertext}",
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private result ORAM snapshot layout validation failed"));
        assert!(!rendered.contains(&leaked_ciphertext));

        let leaked_short_values = [
            "result-short-read-bucket-id",
            "result-short-bucket-id",
            "result-short-proof-leaf",
            "result-short-proof-sibling",
            "result-short-payload-token",
            "result-short-read-signature",
            "result-short-commit-signature",
        ];
        let err = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM read_bucket_id {} bucket_ids [{}] proof leaf_hash {} \
                 sibling_hash {} payload_fetch_tokens {} read_signature {} commit_signature {}",
                leaked_short_values[0],
                leaked_short_values[1],
                leaked_short_values[2],
                leaked_short_values[3],
                leaked_short_values[4],
                leaked_short_values[5],
                leaked_short_values[6],
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private result ORAM snapshot layout validation failed"));
        for leaked in leaked_short_values {
            assert!(!rendered.contains(leaked));
        }

        let leaked_camel_values = [
            "result-camel-read-bucket-id",
            "result-camel-bucket-id",
            "result-camel-proof-leaf",
            "result-camel-proof-sibling",
            "result-camel-payload-token",
            "result-camel-read-signature",
            "result-camel-commit-signature",
            "result-camel-access-volume-length",
            "result-camel-result-id",
            "result-camel-visited-node",
        ];
        let err = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(format!(
                "private result ORAM readBucketIds {} bucketIds [{}] proofValue {} \
                 siblingHash {} payloadFetchTokens {} readSignature {} commitSignature {} \
                 accessVolumeLength {} resultIds {} visitedNodeIds {}",
                leaked_camel_values[0],
                leaked_camel_values[1],
                leaked_camel_values[2],
                leaked_camel_values[3],
                leaked_camel_values[4],
                leaked_camel_values[5],
                leaked_camel_values[6],
                leaked_camel_values[7],
                leaked_camel_values[8],
                leaked_camel_values[9],
            )),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("private result ORAM snapshot layout validation failed"));
        for leaked in leaked_camel_values {
            assert!(!rendered.contains(leaked));
        }

        let safe = sanitize_private_result_oram_snapshot_layout_error(
            temp_dir.path(),
            CollectionError::bad_request(
                "private result ORAM snapshot store is present without a matching collection encryption rule",
            ),
        );
        assert!(
            safe.to_string()
                .contains("without a matching collection encryption rule")
        );
    }

    #[test]
    fn private_oram_snapshot_recovery_layouts_reject_hnsw_store_without_binding() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-recover-layout")
            .tempdir()
            .unwrap();
        std::fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();
        let config = CollectionConfigInternal {
            params: CollectionParams::empty(),
            hnsw_config: HnswConfig::default(),
            optimizer_config: test_optimizers_config(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: None,
            metadata: None,
        };

        let err = validate_private_oram_snapshot_restore_layouts("docs", &config, temp_dir.path())
            .expect_err("orphan private HNSW ORAM snapshot store must fail closed")
            .to_string();

        assert!(err.contains("without a matching collection encryption rule"));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_oram_snapshot_recovery_layouts_reject_result_store_without_binding() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-storage-recover-layout")
            .tempdir()
            .unwrap();
        std::fs::create_dir(temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();
        let config = CollectionConfigInternal {
            params: CollectionParams::empty(),
            hnsw_config: HnswConfig::default(),
            optimizer_config: test_optimizers_config(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: None,
            metadata: None,
        };

        let err = validate_private_oram_snapshot_restore_layouts("docs", &config, temp_dir.path())
            .expect_err("orphan private result ORAM snapshot store must fail closed")
            .to_string();

        assert!(err.contains("without a matching collection encryption rule"));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[test]
    fn private_oram_replica_priority_snapshot_recovery_fails_closed_until_transfer_exists() {
        reject_private_oram_replica_priority_snapshot_recovery_until_supported(
            "docs",
            &encrypted_params(),
        )
        .unwrap();

        for (binding, selector) in [
            (
                PRIVATE_HNSW_ORAM_BINDING,
                EncryptionSelector::VectorNames {
                    names: vec!["text".to_string()],
                },
            ),
            (
                PRIVATE_RESULT_ORAM_BINDING,
                EncryptionSelector::PayloadPaths {
                    paths: vec!["document.body".to_string()],
                },
            ),
        ] {
            let params = CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/private-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "private_oram_rule".to_string(),
                        selector,
                        instance: "docs_private_oram_v1".to_string(),
                        binding: Some(binding.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            };

            let err = reject_private_oram_replica_priority_snapshot_recovery_until_supported(
                "docs", &params,
            )
            .expect_err("private ORAM replica-priority recovery must fail closed")
            .to_string();

            assert!(err.contains("private ORAM collections"));
            assert!(err.contains("encrypted ORAM bucket transfer"));
            assert!(!err.contains("docs"));
            assert!(!err.contains(PRIVATE_HNSW_ORAM_BINDING));
            assert!(!err.contains(PRIVATE_RESULT_ORAM_BINDING));
        }
    }

    #[test]
    fn private_oram_replica_priority_recovery_redacts_client_state_aliases() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("clientStateCiphertextHash.json".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "encryptedClientStateCiphertext.json".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec![
                            "clientState.json".to_string(),
                            "clientStates.json".to_string(),
                            "client_state.json".to_string(),
                            "client_states.json".to_string(),
                            "clientStateBackup.json".to_string(),
                            "clientStateBackups.json".to_string(),
                            "client_state_backup.json".to_string(),
                            "client_state_backups.json".to_string(),
                            "tokenMapBackup.json".to_string(),
                            "tokenMapBackups.json".to_string(),
                            "token_map_backup.json".to_string(),
                            "token_map_backups.json".to_string(),
                            "tokenPositionMapBackup.json".to_string(),
                            "tokenPositionMapBackups.json".to_string(),
                            "token_position_map_backup.json".to_string(),
                            "clientStateSnapshot.json".to_string(),
                            "clientStateSnapshots.json".to_string(),
                            "client.state.snapshot.json".to_string(),
                            "client_state_snapshot.json".to_string(),
                            "client_state_snapshots.json".to_string(),
                            "client.state.snapshots.json".to_string(),
                            "clientStateCiphertext.json".to_string(),
                            "clientStateCiphertextHashes.json".to_string(),
                            "clientStateCiphertextSha256.json".to_string(),
                            "clientStateCiphertextsSha256.json".to_string(),
                            "client_state_ciphertext.json".to_string(),
                            "client_state_ciphertext_hash.json".to_string(),
                            "client_state_ciphertext_hash.bin".to_string(),
                            "client_state_ciphertext_hashes.json".to_string(),
                            "client_state_ciphertext_hashes.bin".to_string(),
                            "client_state_ciphertext_sha256.json".to_string(),
                            "client_state_ciphertext_sha256.bin".to_string(),
                            "client_state_ciphertexts_sha256.bin".to_string(),
                            "client_state_ciphertexts_sha256.json".to_string(),
                            "encryptedClientStateCiphertextHash.json".to_string(),
                            "encryptedClientStateCiphertextHashes.json".to_string(),
                            "encryptedClientStateCiphertextSha256.json".to_string(),
                            "encryptedClientStateCiphertextsSha256.json".to_string(),
                            "encryptedClientState.json".to_string(),
                            "encryptedClientStates.json".to_string(),
                            "encrypted_client_state.json".to_string(),
                            "encrypted_client_states.json".to_string(),
                            "encryptedClientStateBackup.json".to_string(),
                            "encryptedClientStateBackups.json".to_string(),
                            "encrypted_client_state_backup.json".to_string(),
                            "encrypted_client_state_backups.json".to_string(),
                            "encryptedClientStateSnapshot.json".to_string(),
                            "encryptedClientStateSnapshots.json".to_string(),
                            "encrypted.client.state.json".to_string(),
                            "encrypted.client.state.snapshot.json".to_string(),
                            "encrypted_client_state_snapshot.json".to_string(),
                            "encrypted_client_state_snapshots.json".to_string(),
                            "encrypted.client.state.snapshots.json".to_string(),
                            "encrypted_client_state_ciphertext.json".to_string(),
                            "encrypted_client_state_ciphertexts.json".to_string(),
                            "encrypted_client_state_ciphertext_hash.json".to_string(),
                            "encrypted_client_state_ciphertext_hash.bin".to_string(),
                            "encrypted_client_state_ciphertext_hashes.json".to_string(),
                            "encrypted_client_state_ciphertext_hashes.bin".to_string(),
                            "encrypted_client_state_ciphertext_sha256.json".to_string(),
                            "encrypted_client_state_ciphertext_sha256.bin".to_string(),
                            "encrypted_client_state_ciphertexts_sha256.bin".to_string(),
                            "encrypted_client_state_ciphertexts_sha256.json".to_string(),
                            "stateCiphertext.json".to_string(),
                            "stateCiphertextHashes.json".to_string(),
                            "stateCiphertextSha256.json".to_string(),
                            "stateCiphertextsSha256.json".to_string(),
                            "state_ciphertext.json".to_string(),
                            "state_ciphertext_hash.json".to_string(),
                            "state_ciphertext_hash.bin".to_string(),
                            "state_ciphertext_hashes.json".to_string(),
                            "state_ciphertext_hashes.bin".to_string(),
                            "state_ciphertext_sha256.json".to_string(),
                            "state_ciphertexts_sha256.bin".to_string(),
                            "state_ciphertexts_sha256.json".to_string(),
                            "payload_fetch_token.json".to_string(),
                            "payload_fetch_tokens.json".to_string(),
                            "payloadFetchToken.json".to_string(),
                            "payloadFetchTokens.json".to_string(),
                            "payload.fetch.token".to_string(),
                            "token.map.backup.json".to_string(),
                            "token.map.backups.json".to_string(),
                            "token.position.map.backup.json".to_string(),
                            "token.position.map.backups.json".to_string(),
                            "token_position_map_backup.json".to_string(),
                            "token_position_map_backups.json".to_string(),
                        ],
                    },
                    instance: "stateCiphertextHash.json".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = reject_private_oram_replica_priority_snapshot_recovery_until_supported(
            "stashBackup.json",
            &params,
        )
            .expect_err(
                "private ORAM replica-priority recovery must fail closed without client-state alias leaks",
            )
        .to_string();

        assert!(err.contains("private ORAM collections"));
        assert!(err.contains("encrypted ORAM bucket transfer"));
        for sentinel in [
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
            "encryptedClientStateSnapshot",
            "encryptedClientStateSnapshots",
            "encrypted.client.state",
            "encrypted.client.state.snapshot",
            "encrypted_client_state_snapshot",
            "encrypted_client_state_snapshots",
            "encrypted_client_state_ciphertext",
            "encrypted_client_state_ciphertexts",
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
            "payload_fetch_token",
            "payload_fetch_tokens",
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload.fetch.token",
            "stashBackup",
            "stashBackups",
            PRIVATE_RESULT_ORAM_BINDING,
            PRIVATE_RESULT_ORAM_DIR,
        ] {
            assert!(
                !err.contains(sentinel),
                "private ORAM replica-priority recovery leaked client-state alias `{sentinel}`: {err}",
            );
        }
    }

    #[test]
    fn encrypted_snapshot_recovery_rejects_collection_uuid_mismatch() {
        let existing_uuid = Uuid::from_u128(1);
        let snapshot_uuid = Uuid::from_u128(2);
        let err = validate_existing_collection_crypto_identity(
            "docs",
            Some(existing_uuid),
            &encrypted_params(),
            Some(snapshot_uuid),
            &encrypted_params(),
        )
        .expect_err("encrypted restore must reject mismatched stable identity");

        assert!(err.to_string().contains("encrypted collection docs"));
        assert!(err.to_string().contains(&existing_uuid.to_string()));
        assert!(err.to_string().contains(&snapshot_uuid.to_string()));
    }

    #[test]
    fn encrypted_snapshot_recovery_requires_collection_uuids() {
        let err = validate_existing_collection_crypto_identity(
            "docs",
            None,
            &encrypted_params(),
            Some(Uuid::from_u128(2)),
            &encrypted_params(),
        )
        .expect_err("encrypted restore must reject missing existing stable identity");
        assert!(err.to_string().contains("missing a stable UUID"));
        assert!(err.to_string().contains("snapshot UUID"));

        let err = validate_existing_collection_crypto_identity(
            "docs",
            Some(Uuid::from_u128(1)),
            &encrypted_params(),
            None,
            &encrypted_params(),
        )
        .expect_err("encrypted restore must reject missing snapshot stable identity");
        assert!(
            err.to_string()
                .contains("snapshot is missing a stable UUID")
        );

        let err = validate_existing_collection_crypto_identity(
            "docs",
            None,
            &encrypted_params(),
            None,
            &encrypted_params(),
        )
        .expect_err("encrypted restore must reject missing stable identities");
        assert!(
            err.to_string()
                .contains("both existing collection and snapshot")
        );
    }

    #[test]
    fn encrypted_snapshot_recovery_accepts_matching_collection_uuid() {
        let uuid = Uuid::from_u128(7);
        validate_existing_collection_crypto_identity(
            "docs",
            Some(uuid),
            &encrypted_params(),
            Some(uuid),
            &encrypted_params(),
        )
        .unwrap();
    }

    #[test]
    fn plaintext_snapshot_recovery_keeps_existing_uuid_behavior() {
        validate_existing_collection_crypto_identity(
            "docs",
            Some(Uuid::from_u128(1)),
            &CollectionParams::empty(),
            Some(Uuid::from_u128(2)),
            &CollectionParams::empty(),
        )
        .unwrap();
    }
}
