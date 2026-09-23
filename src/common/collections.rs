use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use api::grpc::qdrant::CollectionExists;
use api::rest::models::{
    CollectionDescription, CollectionsResponse, ShardKeyDescription, ShardKeysResponse,
};
use collection::collection::Collection;
use collection::config::{CollectionConfigInternal, ShardingMethod};
#[cfg(feature = "staging")]
use collection::operations::cluster_ops::TestSlowDownOperation;
use collection::operations::cluster_ops::{
    AbortTransferOperation, ClusterOperations, DropReplicaOperation, MoveShardOperation, Replica,
    ReplicatePoints, ReplicatePointsOperation, ReplicateShardOperation, ReshardingDirection,
    RestartTransfer, RestartTransferOperation, StartResharding,
};
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::snapshot_ops::SnapshotDescription;
use collection::operations::types::{
    AliasDescription, CollectionClusterInfo, CollectionInfo, CollectionsAliasesResponse,
    PeerMetadata,
};
use collection::operations::verification::new_unchecked_verification_pass;
use collection::shards::replica_set;
use collection::shards::replica_set::replica_set_state;
use collection::shards::resharding::{ReshardKey, ReshardState};
use collection::shards::shard::{PeerId, ShardId, ShardsPlacement};
use collection::shards::transfer::{
    ShardTransfer, ShardTransferKey, ShardTransferMethod, ShardTransferRestart,
};
use itertools::Itertools;
use qdrant_sec::{PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING};
use rand::prelude::SliceRandom;
use rand::seq::IteratorRandom;
use storage::content_manager::collection_meta_ops::ShardTransferOperations::{Abort, Start};
#[cfg(feature = "staging")]
use storage::content_manager::collection_meta_ops::TestSlowDown;
use storage::content_manager::collection_meta_ops::{
    CollectionMetaOperations, CreateShardKey, DropShardKey, ReshardingOperation,
    SetShardReplicaState, ShardTransferOperations, UpdateCollectionOperation,
};
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use uuid::Uuid;

use super::auth::Auth;
use super::private_hnsw::begin_private_hnsw_collection_snapshot;
use super::private_result_oram::begin_private_result_oram_collection_snapshot;
use crate::settings::Settings;
#[cfg(feature = "staging")]
use crate::tonic::api::qdrant_internal_api::apply_private_oram_preinstall_restart_pause;
use crate::tonic::api::qdrant_internal_api::{
    prepare_private_oram_replica_removal, prepare_private_oram_resharding_finish,
    prepare_private_oram_shard_key_layout_change, prepare_private_oram_shard_transfer,
    private_oram_replica_removal_layout_transition, private_oram_resharding_finish_operation,
    private_oram_resharding_start_operation, private_oram_session_lease_hash,
    private_oram_shard_transfer_start_operation, release_private_oram_transfer_reservation,
};
pub async fn do_collection_exists(
    toc: &TableOfContent,
    auth: &Auth,
    name: &str,
) -> Result<CollectionExists, StorageError> {
    let collection_pass =
        auth.check_collection_access(name, AccessRequirements::new(), "collection_exists")?;

    // if this returns Ok, it means the collection exists.
    // if not, we check that the error is NotFound
    let Err(error) = toc.get_collection(&collection_pass).await else {
        return Ok(CollectionExists { exists: true });
    };
    match error {
        StorageError::NotFound { .. } => Ok(CollectionExists { exists: false }),
        e => Err(e),
    }
}

pub async fn do_get_collection(
    toc: &TableOfContent,
    auth: &Auth,
    name: &str,
    shard_selection: Option<ShardId>,
) -> Result<CollectionInfo, StorageError> {
    let collection_pass =
        auth.check_collection_access(name, AccessRequirements::new(), "get_collection")?;

    let collection = toc.get_collection(&collection_pass).await?;

    let shard_selection = match shard_selection {
        None => ShardSelectorInternal::All,
        Some(shard_id) => ShardSelectorInternal::ShardId(shard_id),
    };

    Ok(collection.info(&shard_selection).await?)
}

pub async fn do_list_collections(
    toc: &TableOfContent,
    auth: &Auth,
) -> Result<CollectionsResponse, StorageError> {
    let collections = toc
        .all_collections(auth.access("list_collections"))
        .await
        .into_iter()
        .map(|pass| CollectionDescription {
            name: pass.name().to_string(),
        })
        .collect_vec();

    Ok(CollectionsResponse { collections })
}

pub async fn do_get_collection_shard_keys(
    toc: &TableOfContent,
    auth: &Auth,
    name: &str,
) -> Result<ShardKeysResponse, StorageError> {
    let collection_pass =
        auth.check_collection_access(name, AccessRequirements::new(), "get_collection_shard_keys")?;

    let collection = toc.get_collection(&collection_pass).await?;

    let state = collection.state().await;
    let shard_keys = match state.config.params.sharding_method.unwrap_or_default() {
        ShardingMethod::Auto => None,
        ShardingMethod::Custom => Some(
            state
                .shards_key_mapping
                .iter_shard_keys()
                .map(|k| ShardKeyDescription { key: k.clone() })
                .collect(),
        ),
    };

    Ok(ShardKeysResponse { shard_keys })
}

/// Construct shards-replicas layout for the shard from the given scope of peers
/// Example:
///   Shards: 3
///   Replicas: 2
///   Peers: [A, B, C]
///
/// Placement:
/// [
///         [A, B]
///         [B, C]
///         [A, C]
/// ]
fn generate_even_placement(
    mut pool: Vec<PeerId>,
    shard_number: usize,
    replication_factor: usize,
) -> ShardsPlacement {
    let mut exact_placement = Vec::new();
    let mut rng = rand::rng();
    pool.shuffle(&mut rng);
    let mut loop_iter = pool.iter().cycle();

    // pool: [1,2,3,4]
    // shuf_pool: [2,3,4,1]
    //
    // loop_iter:       [2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,...]
    // shard_placement: [2, 3, 4][1, 2, 3][4, 1, 2][3, 4, 1][2, 3, 4]

    let max_replication_factor = std::cmp::min(replication_factor, pool.len());
    for _shard in 0..shard_number {
        let mut shard_placement = Vec::new();
        for _replica in 0..max_replication_factor {
            if let Some(peer_id) = loop_iter.next() {
                shard_placement.push(*peer_id);
            }
        }
        exact_placement.push(shard_placement);
    }
    exact_placement
}

pub async fn do_list_collection_aliases(
    toc: &TableOfContent,
    auth: &Auth,
    collection_name: &str,
) -> Result<CollectionsAliasesResponse, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "list_collection_aliases",
    )?;
    let access = auth.unlogged_access(); // Do not log as it is just logger above
    let aliases: Vec<AliasDescription> = toc
        .collection_aliases(&collection_pass, access)
        .await?
        .into_iter()
        .map(|alias| AliasDescription {
            alias_name: alias,
            collection_name: collection_name.to_string(),
        })
        .collect();
    Ok(CollectionsAliasesResponse { aliases })
}

pub async fn do_list_aliases(
    toc: &TableOfContent,
    auth: &Auth,
) -> Result<CollectionsAliasesResponse, StorageError> {
    let aliases = toc.list_aliases(auth.access("list_aliases")).await?;
    Ok(CollectionsAliasesResponse { aliases })
}

pub async fn do_list_snapshots(
    toc: &TableOfContent,
    auth: &Auth,
    collection_name: &str,
) -> Result<Vec<SnapshotDescription>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().extras().snapshot_export(),
        "list_snapshots",
    )?;
    Ok(toc
        .get_collection(&collection_pass)
        .await?
        .list_snapshots()
        .await?)
}

pub async fn do_create_snapshot(
    toc: Arc<TableOfContent>,
    auth: &Auth,
    collection_name: &str,
) -> Result<SnapshotDescription, StorageError> {
    let collection_pass = auth
        .check_collection_access(
            collection_name,
            AccessRequirements::new().write().extras(),
            "create_snapshot",
        )?
        .into_static();

    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let private_hnsw_snapshot_guard =
        begin_private_hnsw_collection_snapshot(collection.name(), &config)?;
    let private_result_snapshot_guard =
        begin_private_result_oram_collection_snapshot(collection.name(), &config)?;

    let result = tokio::spawn(async move {
        let _private_hnsw_snapshot_guard = private_hnsw_snapshot_guard;
        let _private_result_snapshot_guard = private_result_snapshot_guard;
        toc.create_snapshot(&collection_pass).await
    })
    .await??;

    Ok(result)
}

pub async fn do_get_collection_cluster(
    toc: &TableOfContent,
    auth: &Auth,
    name: &str,
) -> Result<CollectionClusterInfo, StorageError> {
    let collection_pass = auth.check_collection_access(
        name,
        AccessRequirements::new().extras(),
        "get_collection_cluster",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    Ok(collection.cluster_info(toc.this_peer_id).await?)
}

pub async fn do_update_collection_cluster(
    dispatcher: &Dispatcher,
    settings: &Settings,
    collection_name: String,
    operation: ClusterOperations,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    let collection_pass = auth.check_collection_access(
        &collection_name,
        AccessRequirements::new().write().manage().extras(),
        "update_collection_cluster",
    )?;

    let Some(consensus_state) = dispatcher.consensus_state() else {
        return Err(StorageError::BadRequest {
            description: "Distributed mode disabled".to_string(),
        });
    };

    let get_all_peer_ids = || {
        consensus_state
            .persistent
            .read()
            .peer_address_by_id
            .read()
            .keys()
            .cloned()
            .collect_vec()
    };

    let validate_peer_exists = |peer_id| {
        let target_peer_exist = consensus_state
            .persistent
            .read()
            .peer_address_by_id
            .read()
            .contains_key(&peer_id);
        if !target_peer_exist {
            return Err(StorageError::BadRequest {
                description: format!("Peer {peer_id} does not exist"),
            });
        }
        Ok(())
    };

    // All checks should've been done at this point.
    let pass = new_unchecked_verification_pass();

    let collection = dispatcher
        .toc(&auth, &pass)
        .get_collection(&collection_pass)
        .await?;

    let collection_state = collection.state().await;
    let private_oram_transfer_route =
        validate_private_oram_cluster_transfer(&collection_name, &collection_state, &operation)?;
    let private_oram_transfer =
        private_oram_transfer_route != PrivateOramClusterTransferRoute::Ordinary;
    let private_oram_restart =
        private_oram_transfer && matches!(&operation, ClusterOperations::RestartTransfer(_));
    if private_oram_transfer && !private_oram_restart && !collection_state.transfers.is_empty() {
        return Err(StorageError::bad_request(
            "cannot start private ORAM shard transfer while another shard transfer is active",
        ));
    }
    let private_oram_resharding = classify_private_oram_cluster_resharding_route(
        &collection_name,
        &collection_state.config,
        &operation,
    );
    let private_oram_shard_key_change =
        classify_private_oram_cluster_shard_key_change(&collection_state.config, &operation);
    let private_oram_initial_shard_key_bootstrap = private_oram_shard_key_change
        && collection_state.shards.is_empty()
        && matches!(&operation, ClusterOperations::CreateShardingKey(_));
    let private_oram_replica_removal = validate_private_oram_cluster_replica_removal(
        &collection_name,
        &collection_state,
        &operation,
        dispatcher.this_peer_id(),
    )?;
    let peer_metadata_by_id = consensus_state.persistent.read().peer_metadata_by_id();
    validate_encrypted_cluster_data_movement_parity(
        &collection_name,
        collection_state
            .config
            .params
            .effective_encryption()
            .is_some(),
        &operation,
        consensus_state.persistent.read().this_peer_id(),
        &get_all_peer_ids(),
        &peer_metadata_by_id,
    )?;

    match operation {
        ClusterOperations::MoveShard(MoveShardOperation { move_shard }) => {
            // validate shard to move
            if !collection.contains_shard(move_shard.shard_id).await {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Shard {} of {} does not exist",
                        move_shard.shard_id, collection_name
                    ),
                });
            };

            // validate target and source peer exists
            validate_peer_exists(move_shard.to_peer_id)?;
            validate_peer_exists(move_shard.from_peer_id)?;

            submit_shard_transfer_with_private_oram_preinstall(
                dispatcher,
                settings,
                &collection_state.config,
                collection_name,
                ShardTransfer {
                    shard_id: move_shard.shard_id,
                    to_shard_id: move_shard.to_shard_id,
                    to: move_shard.to_peer_id,
                    from: move_shard.from_peer_id,
                    sync: false,
                    method: move_shard.method,
                    private_oram_preinstalled: false,
                    private_oram_layout_transition: None,
                    filter: None,
                },
                private_oram_transfer_route,
                collection_state.resharding.as_ref(),
                auth,
                wait_timeout,
            )
            .await
        }
        ClusterOperations::ReplicateShard(ReplicateShardOperation { replicate_shard }) => {
            // validate shard to move
            if !collection.contains_shard(replicate_shard.shard_id).await {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Shard {} of {} does not exist",
                        replicate_shard.shard_id, collection_name
                    ),
                });
            };

            // validate target peer exists
            validate_peer_exists(replicate_shard.to_peer_id)?;

            // validate source peer exists
            validate_peer_exists(replicate_shard.from_peer_id)?;

            submit_shard_transfer_with_private_oram_preinstall(
                dispatcher,
                settings,
                &collection_state.config,
                collection_name,
                ShardTransfer {
                    shard_id: replicate_shard.shard_id,
                    to_shard_id: replicate_shard.to_shard_id,
                    to: replicate_shard.to_peer_id,
                    from: replicate_shard.from_peer_id,
                    sync: true,
                    method: replicate_shard.method,
                    private_oram_preinstalled: false,
                    private_oram_layout_transition: None,
                    filter: None,
                },
                private_oram_transfer_route,
                collection_state.resharding.as_ref(),
                auth,
                wait_timeout,
            )
            .await
        }
        ClusterOperations::ReplicatePoints(ReplicatePointsOperation { replicate_points }) => {
            let ReplicatePoints {
                filter,
                from_shard_key,
                to_shard_key,
            } = replicate_points;

            let from_shard_ids = collection.get_shard_ids(&from_shard_key).await?;

            // Temporary, before we support multi-source transfers
            if from_shard_ids.len() != 1 {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Only replicating from shard keys with exactly one shard is supported. Shard key {from_shard_key} has {} shards",
                        from_shard_ids.len()
                    ),
                });
            }

            // validate shard key exists
            let from_replicas = collection.get_replicas(&from_shard_key).await?;
            let to_replicas = collection.get_replicas(&to_shard_key).await?;

            debug_assert!(!from_replicas.is_empty());

            if to_replicas.len() != 1 {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Only replicating to shard keys with exactly one replica is supported. Shard key {to_shard_key} has {} replicas",
                        to_replicas.len()
                    ),
                });
            }

            let (from_shard_id, from_peer_id) = from_replicas[0];
            let (to_shard_id, to_peer_id) = to_replicas[0];

            // validate source & target peers exist
            validate_peer_exists(to_peer_id)?;
            validate_peer_exists(from_peer_id)?;

            // Decide on a transfer-method and check its validity in combination with filters.
            let method = collection.default_shard_transfer_method().await;
            if !method.is_streaming() && filter.is_some() {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Can't do shard transfer using method {method:?} in combination with a filter",
                    ),
                });
            }
            collection
                .ensure_filter_does_not_touch_encrypted_payload(filter.as_ref())
                .await
                .map_err(StorageError::from)?;

            // submit operation to consensus
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::TransferShard(
                        collection_name,
                        Start(ShardTransfer {
                            shard_id: from_shard_id,
                            to_shard_id: Some(to_shard_id),
                            from: from_peer_id,
                            to: to_peer_id,
                            sync: true,
                            method: Some(method),
                            private_oram_preinstalled: false,
                            private_oram_layout_transition: None,
                            filter,
                        }),
                    ),
                    auth,
                    wait_timeout,
                )
                .await
        }
        ClusterOperations::AbortTransfer(AbortTransferOperation { abort_transfer }) => {
            let transfer = ShardTransferKey {
                shard_id: abort_transfer.shard_id,
                to_shard_id: abort_transfer.to_shard_id,
                to: abort_transfer.to_peer_id,
                from: abort_transfer.from_peer_id,
            };

            if !collection.check_transfer_exists(&transfer).await {
                return Err(StorageError::NotFound {
                    description: format!(
                        "Shard transfer {} -> {} for collection {}:{} does not exist",
                        transfer.from, transfer.to, collection_name, transfer.shard_id
                    ),
                });
            }

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::TransferShard(
                        collection_name,
                        Abort {
                            transfer,
                            reason: "user request".to_string(),
                        },
                    ),
                    auth,
                    wait_timeout,
                )
                .await
        }
        ClusterOperations::DropReplica(DropReplicaOperation { drop_replica }) => {
            if !collection.contains_shard(drop_replica.shard_id).await {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Shard {} of {} does not exist",
                        drop_replica.shard_id, collection_name
                    ),
                });
            };

            validate_peer_exists(drop_replica.peer_id)?;

            submit_replica_removal_with_private_oram_reservation(
                dispatcher,
                settings,
                &collection,
                &collection_state.config,
                collection_name,
                drop_replica,
                private_oram_replica_removal,
                auth,
                wait_timeout,
            )
            .await
        }
        ClusterOperations::CreateShardingKey(create_sharding_key_op) => {
            let create_sharding_key = create_sharding_key_op.create_sharding_key;

            // Validate that:
            // - proper sharding method is used
            // - key does not exist yet
            //
            // If placement suggested:
            // - Peers exist

            let state = collection_state;

            match state.config.params.sharding_method.unwrap_or_default() {
                ShardingMethod::Auto => {
                    return Err(StorageError::bad_request(
                        "Shard Key cannot be created with Auto sharding method",
                    ));
                }
                ShardingMethod::Custom => {}
            }

            let shard_number = create_sharding_key
                .shards_number
                .unwrap_or(state.config.params.shard_number)
                .get() as usize;

            let default_replication_factor = if create_sharding_key.initial_state.is_some() {
                // When initial_state is set (e.g. Partial), create a single replica per shard.
                // Data must be transferred into the shard first before it can be replicated.
                1
            } else {
                state.config.params.replication_factor.get()
            };

            let replication_factor = create_sharding_key
                .replication_factor
                .map(NonZeroU32::get)
                .unwrap_or(default_replication_factor)
                as usize;

            if let Some(initial_state) = create_sharding_key.initial_state {
                match initial_state {
                    replica_set_state::ReplicaState::Active
                    | replica_set_state::ReplicaState::Partial => {}
                    _ => {
                        return Err(StorageError::bad_request(format!(
                            "Initial state cannot be {initial_state:?}, only Active or Partial are allowed",
                        )));
                    }
                }
            }
            if private_oram_shard_key_change
                && create_sharding_key
                    .initial_state
                    .is_some_and(|state| state != replica_set_state::ReplicaState::Active)
            {
                return Err(StorageError::bad_request(
                    "private ORAM shard-key creation requires Active replicas",
                ));
            }

            let shard_keys_mapping = state.shards_key_mapping;
            if shard_keys_mapping.contains_key(&create_sharding_key.shard_key) {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Sharding key {} already exists for collection {}",
                        create_sharding_key.shard_key, collection_name
                    ),
                });
            }

            let peers_pool: Vec<_> = if let Some(placement) = create_sharding_key.placement {
                if placement.is_empty() {
                    return Err(StorageError::BadRequest {
                        description: format!(
                            "Sharding key {} placement cannot be empty. If you want to use random placement, do not specify placement",
                            create_sharding_key.shard_key
                        ),
                    });
                }

                for peer_id in placement.iter().copied() {
                    validate_peer_exists(peer_id)?;
                }
                placement
            } else {
                get_all_peer_ids()
            };

            let exact_placement =
                generate_even_placement(peers_pool, shard_number, replication_factor);

            let operation = CollectionMetaOperations::CreateShardKey(CreateShardKey {
                collection_name: collection_name.clone(),
                shard_key: create_sharding_key.shard_key,
                placement: exact_placement,
                initial_state: if private_oram_shard_key_change {
                    Some(replica_set_state::ReplicaState::Active)
                } else {
                    create_sharding_key.initial_state
                },
            });
            if private_oram_shard_key_change && !private_oram_initial_shard_key_bootstrap {
                submit_shard_key_change_with_private_oram_reservation(
                    dispatcher,
                    settings,
                    &state.config,
                    collection_name,
                    operation,
                    auth,
                    wait_timeout,
                )
                .await
            } else {
                dispatcher
                    .submit_collection_meta_op(operation, auth, wait_timeout)
                    .await
            }
        }
        ClusterOperations::DropShardingKey(drop_sharding_key_op) => {
            let drop_sharding_key = drop_sharding_key_op.drop_sharding_key;
            // Validate that:
            // - proper sharding method is used
            // - key does exist

            let state = collection.state().await;

            match state.config.params.sharding_method.unwrap_or_default() {
                ShardingMethod::Auto => {
                    return Err(StorageError::bad_request(
                        "Shard Key cannot be created with Auto sharding method",
                    ));
                }
                ShardingMethod::Custom => {}
            }

            let shard_keys_mapping = state.shards_key_mapping;
            if !shard_keys_mapping.contains_key(&drop_sharding_key.shard_key) {
                return Err(StorageError::BadRequest {
                    description: format!(
                        "Sharding key {} does not exist for collection {collection_name}",
                        drop_sharding_key.shard_key,
                    ),
                });
            }

            let operation = CollectionMetaOperations::DropShardKey(DropShardKey {
                collection_name: collection_name.clone(),
                shard_key: drop_sharding_key.shard_key,
            });
            if private_oram_shard_key_change {
                submit_shard_key_change_with_private_oram_reservation(
                    dispatcher,
                    settings,
                    &state.config,
                    collection_name,
                    operation,
                    auth,
                    wait_timeout,
                )
                .await
            } else {
                dispatcher
                    .submit_collection_meta_op(operation, auth, wait_timeout)
                    .await
            }
        }
        ClusterOperations::RestartTransfer(RestartTransferOperation { restart_transfer }) => {
            // TODO(reshading): Deduplicate resharding operations handling?

            if private_oram_transfer {
                validate_private_oram_restart_transfer(
                    &restart_transfer,
                    &collection_state.transfers,
                    collection_state.resharding.as_ref(),
                    dispatcher.this_peer_id(),
                )?;
            }

            let RestartTransfer {
                shard_id,
                to_shard_id,
                from_peer_id,
                to_peer_id,
                method,
            } = restart_transfer;

            let transfer_key = ShardTransferKey {
                shard_id,
                to_shard_id,
                to: to_peer_id,
                from: from_peer_id,
            };

            if !collection.check_transfer_exists(&transfer_key).await {
                return Err(StorageError::NotFound {
                    description: format!(
                        "Shard transfer {} -> {} for collection {}:{} does not exist",
                        transfer_key.from, transfer_key.to, collection_name, transfer_key.shard_id
                    ),
                });
            }

            submit_restart_transfer_with_private_oram_preinstall(
                dispatcher,
                settings,
                &collection,
                &collection_state.config,
                collection_name,
                ShardTransferRestart {
                    shard_id,
                    to_shard_id,
                    to: to_peer_id,
                    from: from_peer_id,
                    method,
                    expected_private_oram_transfer: None,
                },
                private_oram_transfer,
                None,
                auth,
                wait_timeout,
            )
            .await
        }
        ClusterOperations::StartResharding(op) => {
            let StartResharding {
                uuid,
                direction,
                peer_id,
                shard_key,
            } = op.start_resharding;

            if !dispatcher.is_resharding_enabled() {
                return Err(StorageError::bad_request(
                    "resharding is only supported in Qdrant Cloud",
                ));
            }

            // Assign random UUID if not specified by user before processing operation on all peers
            let uuid = uuid.unwrap_or_else(Uuid::new_v4);

            if let Some(shard_key) = &shard_key
                && !collection_state.shards_key_mapping.contains_key(shard_key)
            {
                return Err(StorageError::bad_request(format!(
                    "sharding key {shard_key} does not exist for collection {collection_name}",
                )));
            }

            let shard_id = match (direction, shard_key.as_ref()) {
                // When scaling up, just pick the next shard ID
                (ReshardingDirection::Up, _) => {
                    let max_shard_id = collection_state
                        .shards
                        .keys()
                        .copied()
                        .max()
                        .ok_or_else(|| {
                            StorageError::service_error(format!(
                                "cannot reshard collection {collection_name}: collection has no shards",
                            ))
                        })?;
                    max_shard_id.checked_add(1).ok_or_else(|| {
                        StorageError::service_error(format!(
                            "cannot reshard collection {collection_name}: next shard id overflows",
                        ))
                    })?
                }
                // When scaling down without shard keys, pick the last shard ID
                (ReshardingDirection::Down, None) => collection_state
                    .shards
                    .keys()
                    .copied()
                    .max()
                    .ok_or_else(|| {
                        StorageError::service_error(format!(
                            "cannot reshard collection {collection_name}: collection has no shards",
                        ))
                    })?,
                // When scaling down with shard keys, pick the last shard ID of that key
                (ReshardingDirection::Down, Some(shard_key)) => {
                    let shard_ids = collection_state
                        .shards_key_mapping
                        .get(shard_key)
                        .ok_or_else(|| {
                            StorageError::bad_request(format!(
                                "sharding key {shard_key} does not exist for collection {collection_name}",
                            ))
                        })?;
                    shard_ids.iter().copied().max().ok_or_else(|| {
                        StorageError::service_error(format!(
                            "cannot reshard collection {collection_name}: sharding key {shard_key} has no shards",
                        ))
                    })?
                }
            };

            let peer_id = match (peer_id, direction) {
                // Select user specified peer, but make sure it exists
                (Some(peer_id), _) => {
                    validate_peer_exists(peer_id)?;
                    peer_id
                }

                // When scaling up, select peer with least number of shards for this collection
                (None, ReshardingDirection::Up) => {
                    let mut shards_on_peers = collection_state
                        .shards
                        .values()
                        .flat_map(|shard_info| shard_info.replicas.keys())
                        .fold(HashMap::new(), |mut counts, peer_id| {
                            *counts.entry(*peer_id).or_insert(0) += 1;
                            counts
                        });
                    for peer_id in get_all_peer_ids() {
                        // Add registered peers not holding any shard yet
                        shards_on_peers.entry(peer_id).or_insert(0);
                    }
                    shards_on_peers
                        .into_iter()
                        .min_by_key(|(_, count)| *count)
                        .map(|(peer_id, _)| peer_id)
                        .ok_or_else(|| {
                            StorageError::service_error(format!(
                                "cannot reshard collection {collection_name}: no peers are available",
                            ))
                        })?
                }

                // When scaling down, select random peer that contains the shard we're dropping
                // Other peers work, but are less efficient due to remote operations
                (None, ReshardingDirection::Down) => {
                    let shard_info = collection_state.shards.get(&shard_id).ok_or_else(|| {
                        StorageError::service_error(format!(
                            "cannot reshard collection {collection_name}: selected shard {shard_id} is missing",
                        ))
                    })?;
                    shard_info
                        .replicas
                        .keys()
                        .choose(&mut rand::rng())
                        .copied()
                        .ok_or_else(|| {
                            StorageError::service_error(format!(
                                "cannot reshard collection {collection_name}: selected shard {shard_id} has no replicas",
                            ))
                        })?
                }
            };

            if let Some(resharding) = &collection_state.resharding {
                return Err(StorageError::bad_request(format!(
                    "resharding {resharding:?} is already in progress \
                     for collection {collection_name}"
                )));
            }

            let resharding_key = ReshardKey {
                uuid,
                direction,
                peer_id,
                shard_id,
                shard_key,
            };
            if private_oram_resharding {
                submit_private_oram_resharding_start_with_preinstall(
                    dispatcher,
                    settings,
                    &collection_state.config,
                    collection_name,
                    resharding_key,
                    auth,
                    wait_timeout,
                )
                .await
            } else {
                dispatcher
                    .submit_collection_meta_op(
                        CollectionMetaOperations::Resharding(
                            collection_name,
                            ReshardingOperation::Start(resharding_key),
                        ),
                        auth,
                        wait_timeout,
                    )
                    .await
            }
        }
        ClusterOperations::AbortResharding(_) => {
            // TODO(reshading): Deduplicate resharding operations handling?

            let Some(state) = collection.resharding_state().await else {
                return Err(StorageError::bad_request(format!(
                    "resharding is not in progress for collection {collection_name}"
                )));
            };

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::Resharding(
                        collection_name.clone(),
                        ReshardingOperation::Abort(ReshardKey {
                            uuid: state.uuid,
                            direction: state.direction,
                            peer_id: state.peer_id,
                            shard_id: state.shard_id,
                            shard_key: state.shard_key.clone(),
                        }),
                    ),
                    auth,
                    wait_timeout,
                )
                .await
        }
        ClusterOperations::FinishResharding(_) => {
            // TODO(resharding): Deduplicate resharding operations handling?

            let Some(state) = collection.resharding_state().await else {
                return Err(StorageError::bad_request(format!(
                    "resharding is not in progress for collection {collection_name}"
                )));
            };

            let resharding_key = state.key();
            if private_oram_resharding {
                submit_private_oram_resharding_finish_with_reservation(
                    dispatcher,
                    settings,
                    &collection_state.config,
                    collection_name,
                    resharding_key,
                    auth,
                    wait_timeout,
                )
                .await
            } else {
                dispatcher
                    .submit_collection_meta_op(
                        CollectionMetaOperations::Resharding(
                            collection_name,
                            ReshardingOperation::Finish(resharding_key),
                        ),
                        auth,
                        wait_timeout,
                    )
                    .await
            }
        }

        ClusterOperations::FinishMigratingPoints(op) => {
            // TODO(resharding): Deduplicate resharding operations handling?

            let Some(state) = collection.resharding_state().await else {
                return Err(StorageError::bad_request(format!(
                    "resharding is not in progress for collection {collection_name}"
                )));
            };

            let op = op.finish_migrating_points;

            let shard_id = match (op.shard_id, state.direction) {
                (Some(shard_id), _) => shard_id,
                (None, ReshardingDirection::Up) => state.shard_id,
                (None, ReshardingDirection::Down) => {
                    return Err(StorageError::bad_request(
                        "shard ID must be specified when resharding down",
                    ));
                }
            };

            let peer_id = match (op.peer_id, state.direction) {
                (Some(peer_id), _) => peer_id,
                (None, ReshardingDirection::Up) => state.peer_id,
                (None, ReshardingDirection::Down) => {
                    return Err(StorageError::bad_request(
                        "peer ID must be specified when resharding down",
                    ));
                }
            };

            let from_state = match state.direction {
                ReshardingDirection::Up => replica_set_state::ReplicaState::Resharding,
                ReshardingDirection::Down => replica_set_state::ReplicaState::ReshardingScaleDown,
            };

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::SetShardReplicaState(SetShardReplicaState {
                        collection_name: collection_name.clone(),
                        shard_id,
                        peer_id,
                        state: replica_set_state::ReplicaState::Active,
                        from_state: Some(from_state),
                    }),
                    auth,
                    wait_timeout,
                )
                .await
        }

        ClusterOperations::CommitReadHashRing(_) => {
            // TODO(reshading): Deduplicate resharding operations handling?

            let Some(state) = collection.resharding_state().await else {
                return Err(StorageError::bad_request(format!(
                    "resharding is not in progress for collection {collection_name}"
                )));
            };

            // TODO(resharding): Add precondition checks?

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::Resharding(
                        collection_name.clone(),
                        ReshardingOperation::CommitRead(ReshardKey {
                            uuid: state.uuid,
                            direction: state.direction,
                            peer_id: state.peer_id,
                            shard_id: state.shard_id,
                            shard_key: state.shard_key.clone(),
                        }),
                    ),
                    auth,
                    wait_timeout,
                )
                .await
        }

        ClusterOperations::CommitWriteHashRing(_) => {
            // TODO(reshading): Deduplicate resharding operations handling?

            let Some(state) = collection.resharding_state().await else {
                return Err(StorageError::bad_request(format!(
                    "resharding is not in progress for collection {collection_name}"
                )));
            };

            // TODO(resharding): Add precondition checks?

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::Resharding(
                        collection_name.clone(),
                        ReshardingOperation::CommitWrite(ReshardKey {
                            uuid: state.uuid,
                            direction: state.direction,
                            peer_id: state.peer_id,
                            shard_id: state.shard_id,
                            shard_key: state.shard_key.clone(),
                        }),
                    ),
                    auth,
                    wait_timeout,
                )
                .await
        }

        #[cfg(feature = "staging")]
        ClusterOperations::TestSlowDown(TestSlowDownOperation { test_slow_down }) => {
            if let Some(peer_id) = test_slow_down.peer_id {
                validate_peer_exists(peer_id)?;
            }

            // Convert seconds (f64) to milliseconds (u64)
            let duration_ms = (test_slow_down.duration * 1000.0) as u64;

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::TestSlowDown(TestSlowDown {
                        peer_id: test_slow_down.peer_id,
                        duration_ms,
                    }),
                    auth,
                    wait_timeout,
                )
                .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn submit_shard_transfer_with_private_oram_preinstall(
    dispatcher: &Dispatcher,
    settings: &Settings,
    config: &CollectionConfigInternal,
    collection_name: String,
    mut transfer: ShardTransfer,
    private_oram_transfer_route: PrivateOramClusterTransferRoute,
    resharding: Option<&ReshardState>,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    if private_oram_transfer_route == PrivateOramClusterTransferRoute::Ordinary {
        return dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::TransferShard(collection_name, Start(transfer)),
                auth,
                wait_timeout,
            )
            .await;
    }
    if transfer.from != dispatcher.this_peer_id() {
        return Err(StorageError::bad_request(
            "private ORAM shard transfer must be coordinated by its current source peer",
        ));
    }
    if private_oram_transfer_route == PrivateOramClusterTransferRoute::Resharding
        && !resharding.is_some_and(|state| transfer.is_exact_resharding_transfer_for(state))
    {
        return Err(StorageError::bad_request(
            "private ORAM resharding transfer does not match the active point-migration state",
        ));
    }
    let reservation = prepare_private_oram_shard_transfer(
        dispatcher,
        &auth,
        settings,
        &collection_name,
        config,
        transfer.to,
        None,
        false,
    )
    .await?;
    transfer.private_oram_preinstalled = true;
    if private_oram_transfer_route == PrivateOramClusterTransferRoute::Resharding {
        let result = dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::TransferShard(collection_name, Start(transfer)),
                auth,
                wait_timeout,
            )
            .await;
        if result.is_ok() {
            if release_private_oram_transfer_reservation(dispatcher, &reservation)
                .await
                .is_err()
            {
                log::warn!("failed to release private ORAM resharding transfer reservation");
            }
        } else {
            log::warn!(
                "retaining private ORAM resharding transfer reservation after uncertain consensus submission"
            );
        }
        return result;
    }
    let start_operation = private_oram_shard_transfer_start_operation(
        dispatcher,
        &collection_name,
        config,
        &reservation,
        transfer,
    )
    .await;
    let start_operation = match start_operation {
        Ok(operation) => operation,
        Err(error) => {
            if release_private_oram_transfer_reservation(dispatcher, &reservation)
                .await
                .is_err()
            {
                log::warn!(
                    "failed to release private ORAM shard transfer reservation after layout transition preparation failure"
                );
            }
            return Err(error);
        }
    };
    let result = dispatcher
        .submit_private_oram_shard_transfer_start(start_operation, auth, wait_timeout)
        .await;
    if result.is_ok() {
        if release_private_oram_transfer_reservation(dispatcher, &reservation)
            .await
            .is_err()
        {
            log::warn!("failed to release private ORAM shard transfer reservation");
        }
    } else {
        log::warn!(
            "retaining private ORAM shard transfer reservation after uncertain consensus submission"
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn submit_private_oram_resharding_start_with_preinstall(
    dispatcher: &Dispatcher,
    settings: &Settings,
    config: &CollectionConfigInternal,
    collection_name: String,
    resharding_key: ReshardKey,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    let reservation = match resharding_key.direction {
        ReshardingDirection::Up => {
            prepare_private_oram_shard_transfer(
                dispatcher,
                &auth,
                settings,
                &collection_name,
                config,
                resharding_key.peer_id,
                None,
                false,
            )
            .await?
        }
        ReshardingDirection::Down => {
            prepare_private_oram_replica_removal(
                dispatcher,
                &auth,
                settings,
                &collection_name,
                config,
            )
            .await?
        }
    };
    let operation = private_oram_resharding_start_operation(
        dispatcher,
        &collection_name,
        config,
        &reservation,
        resharding_key,
    )
    .await;
    let operation = match operation {
        Ok(operation) => operation,
        Err(error) => {
            if release_private_oram_transfer_reservation(dispatcher, &reservation)
                .await
                .is_err()
            {
                log::warn!(
                    "failed to release private ORAM resharding reservation after layout transition preparation failure"
                );
            }
            return Err(error);
        }
    };
    let result = dispatcher
        .submit_private_oram_resharding_start(operation, auth, wait_timeout)
        .await;
    if result.is_ok() {
        if release_private_oram_transfer_reservation(dispatcher, &reservation)
            .await
            .is_err()
        {
            log::warn!("failed to release private ORAM resharding start reservation");
        }
    } else {
        log::warn!(
            "retaining private ORAM resharding start reservation after uncertain consensus submission"
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn submit_private_oram_resharding_finish_with_reservation(
    dispatcher: &Dispatcher,
    settings: &Settings,
    config: &CollectionConfigInternal,
    collection_name: String,
    resharding_key: ReshardKey,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    let reservation = prepare_private_oram_resharding_finish(
        dispatcher,
        &auth,
        settings,
        &collection_name,
        config,
        &resharding_key,
    )
    .await?;
    let operation = private_oram_resharding_finish_operation(
        dispatcher,
        &collection_name,
        config,
        &reservation,
        resharding_key,
    )
    .await;
    let operation = match operation {
        Ok(operation) => operation,
        Err(error) => {
            if release_private_oram_transfer_reservation(dispatcher, &reservation)
                .await
                .is_err()
            {
                log::warn!(
                    "failed to release private ORAM resharding finish reservation after layout transition preparation failure"
                );
            }
            return Err(error);
        }
    };
    let result = dispatcher
        .submit_private_oram_resharding_finish(operation, auth, wait_timeout)
        .await;
    if result.is_ok() {
        if release_private_oram_transfer_reservation(dispatcher, &reservation)
            .await
            .is_err()
        {
            log::warn!("failed to release private ORAM resharding finish reservation");
        }
    } else {
        log::warn!(
            "retaining private ORAM resharding finish reservation after uncertain consensus submission"
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_restart_transfer_with_private_oram_preinstall(
    dispatcher: &Dispatcher,
    settings: &Settings,
    collection: &Collection,
    config: &CollectionConfigInternal,
    collection_name: String,
    mut transfer_restart: ShardTransferRestart,
    private_oram_transfer: bool,
    expected_private_oram_transfer: Option<ShardTransfer>,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    if !private_oram_transfer {
        return dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::TransferShard(
                    collection_name,
                    ShardTransferOperations::Restart(transfer_restart),
                ),
                auth,
                wait_timeout,
            )
            .await;
    }
    if transfer_restart.from != dispatcher.this_peer_id() {
        return Err(StorageError::bad_request(
            "private ORAM restart transfer must be coordinated by its current source peer",
        ));
    }
    let automatic_fixed_resume = expected_private_oram_transfer.is_some();
    let transfer_key = transfer_restart.key();
    let active_transfers = collection.state().await.transfers;
    let active_transfer = match expected_private_oram_transfer {
        Some(expected) if active_transfers.len() == 1 && active_transfers.contains(&expected) => {
            expected
        }
        Some(_) => {
            return Err(StorageError::bad_request(
                "private ORAM restart requires the exact expected active transfer",
            ));
        }
        None => active_transfers
            .into_iter()
            .find(|transfer| transfer.key() == transfer_key)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM restart requires the exact active transfer task",
                )
            })?,
    };
    transfer_restart.expected_private_oram_transfer = Some(Box::new(active_transfer.clone()));
    let reservation_session_id = automatic_fixed_resume.then(|| Uuid::new_v4().to_string());
    let reservation_lease_id_hash = reservation_session_id
        .as_deref()
        .map(private_oram_session_lease_hash)
        .transpose()?;
    let owns_fixed_restart_intent = !active_transfer.is_resharding()
        && collection
            .mark_private_oram_fixed_transfer_resume(&active_transfer)
            .await;
    if automatic_fixed_resume {
        if active_transfer.is_resharding() {
            if owns_fixed_restart_intent {
                collection
                    .clear_private_oram_fixed_transfer_resume(&active_transfer)
                    .await;
            }
            return Err(StorageError::bad_request(
                "private ORAM fixed-layout resume cannot target a resharding transfer",
            ));
        }
        let reservation_lease_id_hash = reservation_lease_id_hash.as_deref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM fixed-layout resume reservation identity is missing",
            )
        })?;
        if let Err(error) = collection.persist_private_oram_fixed_transfer_preinstall_intent(
            &active_transfer,
            reservation_lease_id_hash,
        ) {
            if owns_fixed_restart_intent {
                collection
                    .clear_private_oram_fixed_transfer_resume(&active_transfer)
                    .await;
            }
            return Err(error.into());
        }
    }
    if let Err(error) = collection
        .stop_shard_transfer_task_for_restart(&active_transfer)
        .await
    {
        if automatic_fixed_resume
            && let Err(cleanup_error) =
                collection.clear_private_oram_fixed_transfer_preinstall_intent(&active_transfer)
        {
            if owns_fixed_restart_intent {
                collection
                    .clear_private_oram_fixed_transfer_resume(&active_transfer)
                    .await;
            }
            return Err(cleanup_error.into());
        }
        if owns_fixed_restart_intent {
            collection
                .clear_private_oram_fixed_transfer_resume(&active_transfer)
                .await;
        }
        return Err(error.into());
    }

    let reservation = match prepare_private_oram_shard_transfer(
        dispatcher,
        &auth,
        settings,
        &collection_name,
        config,
        transfer_restart.to,
        reservation_session_id,
        automatic_fixed_resume,
    )
    .await
    {
        Ok(reservation) => reservation,
        Err(error) => {
            if owns_fixed_restart_intent {
                collection
                    .clear_private_oram_fixed_transfer_resume(&active_transfer)
                    .await;
            }
            return Err(error);
        }
    };
    let result = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::TransferShard(
                collection_name,
                ShardTransferOperations::Restart(transfer_restart),
            ),
            auth,
            wait_timeout,
        )
        .await;
    #[cfg(feature = "staging")]
    if automatic_fixed_resume && matches!(&result, Ok(true)) {
        apply_private_oram_preinstall_restart_pause().await;
    }
    if result.is_ok() {
        if let Err(error) =
            release_private_oram_transfer_reservation(dispatcher, &reservation).await
        {
            log::warn!("failed to release private ORAM restart transfer reservation");
            if automatic_fixed_resume {
                return Err(error);
            }
        }
    } else {
        log::warn!(
            "retaining private ORAM restart transfer reservation after uncertain consensus submission"
        );
    }
    if !matches!(result, Ok(true)) && owns_fixed_restart_intent {
        collection
            .clear_private_oram_fixed_transfer_resume(&active_transfer)
            .await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn submit_shard_key_change_with_private_oram_reservation(
    dispatcher: &Dispatcher,
    settings: &Settings,
    config: &CollectionConfigInternal,
    collection_name: String,
    operation: CollectionMetaOperations,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    let (reservation, transition) = prepare_private_oram_shard_key_layout_change(
        dispatcher,
        &auth,
        settings,
        &collection_name,
        config,
        operation,
    )
    .await?;
    let result = dispatcher
        .submit_private_oram_collection_layout_transition(transition, auth, wait_timeout)
        .await;
    if result.is_ok() {
        if release_private_oram_transfer_reservation(dispatcher, &reservation)
            .await
            .is_err()
        {
            log::warn!("failed to release private ORAM shard-key reservation");
        }
    } else {
        log::warn!(
            "retaining private ORAM shard-key reservation after uncertain consensus submission"
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn submit_replica_removal_with_private_oram_reservation(
    dispatcher: &Dispatcher,
    settings: &Settings,
    collection: &collection::collection::Collection,
    config: &CollectionConfigInternal,
    collection_name: String,
    drop_replica: Replica,
    private_oram_replica_removal: bool,
    auth: Auth,
    wait_timeout: Option<Duration>,
) -> Result<bool, StorageError> {
    let build_update = |reserved: bool| {
        let mut update = UpdateCollectionOperation::new_empty(collection_name.clone());
        update.set_shard_replica_changes(vec![replica_set::Change::Remove(
            drop_replica.shard_id,
            drop_replica.peer_id,
        )]);
        if reserved {
            update.mark_private_oram_replica_removal_reserved();
        }
        update
    };
    if !private_oram_replica_removal {
        return dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::UpdateCollection(build_update(false)),
                auth,
                wait_timeout,
            )
            .await;
    }

    let reservation =
        prepare_private_oram_replica_removal(dispatcher, &auth, settings, &collection_name, config)
            .await?;
    let revalidation = validate_private_oram_cluster_replica_removal(
        &collection_name,
        &collection.state().await,
        &ClusterOperations::DropReplica(DropReplicaOperation {
            drop_replica: drop_replica.clone(),
        }),
        dispatcher.this_peer_id(),
    );
    let revalidation_error = match revalidation {
        Ok(true) => None,
        Ok(false) => Some(StorageError::bad_request(
            "private ORAM replica removal reservation is no longer valid",
        )),
        Err(error) => Some(error),
    };
    if let Some(error) = revalidation_error {
        if release_private_oram_transfer_reservation(dispatcher, &reservation)
            .await
            .is_err()
        {
            log::warn!(
                "failed to release private ORAM replica removal reservation after revalidation failure"
            );
        }
        return Err(error);
    }

    let transition = private_oram_replica_removal_layout_transition(
        dispatcher,
        &collection_name,
        config,
        &reservation,
        drop_replica.shard_id,
        drop_replica.peer_id,
        CollectionMetaOperations::UpdateCollection(build_update(true)),
    )
    .await;
    let transition = match transition {
        Ok(transition) => transition,
        Err(error) => {
            if release_private_oram_transfer_reservation(dispatcher, &reservation)
                .await
                .is_err()
            {
                log::warn!(
                    "failed to release private ORAM replica removal reservation after layout transition preparation failure"
                );
            }
            return Err(error);
        }
    };
    let result = dispatcher
        .submit_private_oram_collection_layout_transition(transition, auth, wait_timeout)
        .await;
    if result.is_ok() {
        if release_private_oram_transfer_reservation(dispatcher, &reservation)
            .await
            .is_err()
        {
            log::warn!("failed to release private ORAM replica removal reservation");
        }
    } else {
        log::warn!(
            "retaining private ORAM replica removal reservation after uncertain consensus submission"
        );
    }
    result
}

fn validate_encrypted_cluster_data_movement_parity(
    collection_name: &str,
    encrypted_collection: bool,
    operation: &ClusterOperations,
    local_peer_id: PeerId,
    all_peer_ids: &[PeerId],
    peer_metadata_by_id: &HashMap<PeerId, PeerMetadata>,
) -> Result<(), StorageError> {
    if !encrypted_collection {
        return Ok(());
    }

    let (operation_name, peer_ids): (&str, Vec<PeerId>) = match operation {
        ClusterOperations::MoveShard(op) => (
            "move_shard",
            vec![op.move_shard.from_peer_id, op.move_shard.to_peer_id],
        ),
        ClusterOperations::ReplicateShard(op) => (
            "replicate_shard",
            vec![
                op.replicate_shard.from_peer_id,
                op.replicate_shard.to_peer_id,
            ],
        ),
        ClusterOperations::CreateShardingKey(op) => (
            "create_sharding_key",
            op.create_sharding_key
                .placement
                .clone()
                .unwrap_or_else(|| all_peer_ids.to_vec()),
        ),
        ClusterOperations::ReplicatePoints(_) => ("replicate_points", all_peer_ids.to_vec()),
        ClusterOperations::RestartTransfer(op) => (
            "restart_transfer",
            vec![
                op.restart_transfer.from_peer_id,
                op.restart_transfer.to_peer_id,
            ],
        ),
        ClusterOperations::StartResharding(op) => (
            "start_resharding",
            op.start_resharding
                .peer_id
                .map_or_else(|| all_peer_ids.to_vec(), |peer_id| vec![peer_id]),
        ),
        ClusterOperations::FinishMigratingPoints(_) => {
            ("finish_migrating_points", all_peer_ids.to_vec())
        }
        ClusterOperations::CommitReadHashRing(_) => {
            ("commit_read_hash_ring", all_peer_ids.to_vec())
        }
        ClusterOperations::CommitWriteHashRing(_) => {
            ("commit_write_hash_ring", all_peer_ids.to_vec())
        }
        ClusterOperations::FinishResharding(_) => ("finish_resharding", all_peer_ids.to_vec()),
        _ => return Ok(()),
    };

    let Some(local_fingerprint) = peer_metadata_by_id
        .get(&local_peer_id)
        .and_then(PeerMetadata::crypto_runtime_capability_fingerprint)
    else {
        return Err(StorageError::BadRequest {
            description: format!(
                "cannot run {operation_name} on encrypted collection {collection_name}: \
                     local peer {local_peer_id} has not published crypto runtime capability metadata",
            ),
        });
    };

    for peer_id in peer_ids.into_iter().chain(std::iter::once(local_peer_id)) {
        let Some(peer_fingerprint) = peer_metadata_by_id
            .get(&peer_id)
            .and_then(PeerMetadata::crypto_runtime_capability_fingerprint)
        else {
            return Err(StorageError::BadRequest {
                description: format!(
                    "cannot run {operation_name} on encrypted collection {collection_name}: \
                     peer {peer_id} has not published crypto runtime capability metadata",
                ),
            });
        };

        if peer_fingerprint != local_fingerprint {
            return Err(StorageError::BadRequest {
                description: format!(
                    "cannot run {operation_name} on encrypted collection {collection_name}: \
                     crypto runtime parity mismatch for peer {peer_id}",
                ),
            });
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOramClusterTransferRoute {
    Ordinary,
    StableLayout,
    Resharding,
}

fn validate_private_oram_cluster_transfer(
    _collection_name: &str,
    state: &collection::collection_state::State,
    operation: &ClusterOperations,
) -> Result<PrivateOramClusterTransferRoute, StorageError> {
    if !cluster_operation_starts_shard_transfer(operation)
        || !collection_uses_private_oram_bucket_store(&state.config)
    {
        return Ok(PrivateOramClusterTransferRoute::Ordinary);
    }

    let stable_layout_shape = match operation {
        ClusterOperations::MoveShard(MoveShardOperation { move_shard }) => {
            move_shard.to_shard_id.is_none()
                && move_shard.method == Some(ShardTransferMethod::StreamRecords)
        }
        ClusterOperations::ReplicateShard(ReplicateShardOperation { replicate_shard }) => {
            replicate_shard.to_shard_id.is_none()
                && replicate_shard.method == Some(ShardTransferMethod::StreamRecords)
        }
        ClusterOperations::RestartTransfer(RestartTransferOperation { restart_transfer }) => {
            restart_transfer.to_shard_id.is_none()
                && restart_transfer.method == ShardTransferMethod::StreamRecords
        }
        _ => false,
    };
    if stable_layout_shape && state.resharding.is_none() {
        return Ok(PrivateOramClusterTransferRoute::StableLayout);
    }

    if let ClusterOperations::RestartTransfer(RestartTransferOperation { restart_transfer }) =
        operation
        && state.resharding.is_some()
        && private_oram_restart_matches_exact_active_transfer(
            restart_transfer,
            &state.transfers,
            state.resharding.as_ref(),
        )
    {
        return Ok(PrivateOramClusterTransferRoute::Resharding);
    }

    if let ClusterOperations::ReplicateShard(ReplicateShardOperation { replicate_shard }) =
        operation
        && let Some(resharding) = state.resharding.as_ref()
    {
        let transfer = ShardTransfer {
            shard_id: replicate_shard.shard_id,
            to_shard_id: replicate_shard.to_shard_id,
            from: replicate_shard.from_peer_id,
            to: replicate_shard.to_peer_id,
            sync: true,
            method: replicate_shard.method,
            private_oram_preinstalled: false,
            private_oram_layout_transition: None,
            filter: None,
        };
        let shards_exist = state.shards.contains_key(&transfer.shard_id)
            && transfer
                .to_shard_id
                .is_some_and(|shard_id| state.shards.contains_key(&shard_id));
        let source_state = state
            .shards
            .get(&transfer.shard_id)
            .and_then(|shard| shard.replicas.get(&transfer.from));
        let destination_state = transfer.to_shard_id.and_then(|shard_id| {
            state
                .shards
                .get(&shard_id)
                .and_then(|shard| shard.replicas.get(&transfer.to))
        });
        let endpoints_match = match resharding.direction {
            ReshardingDirection::Up => {
                source_state == Some(&replica_set_state::ReplicaState::Active)
                    && destination_state == Some(&replica_set_state::ReplicaState::Resharding)
            }
            ReshardingDirection::Down => {
                matches!(
                    source_state,
                    Some(
                        replica_set_state::ReplicaState::Active
                            | replica_set_state::ReplicaState::ReshardingScaleDown
                    )
                ) && matches!(
                    destination_state,
                    Some(
                        replica_set_state::ReplicaState::Active
                            | replica_set_state::ReplicaState::ReshardingScaleDown
                    )
                )
            }
        };
        let source_key = state.shards_key_mapping.shard_key(transfer.shard_id);
        let target_key = transfer
            .to_shard_id
            .and_then(|shard_id| state.shards_key_mapping.shard_key(shard_id));
        if shards_exist
            && endpoints_match
            && source_key == resharding.shard_key
            && target_key == resharding.shard_key
            && transfer.is_exact_resharding_transfer_for(resharding)
        {
            return Ok(PrivateOramClusterTransferRoute::Resharding);
        }
    }

    Err(StorageError::BadRequest {
        description: "private ORAM collections support shard transfer only for MoveShard, \
                      ReplicateShard, or exact active RestartTransfer requests with explicit \
                      stream_records and no temporary shard id, plus exact active ReplicateShard \
                      point migration with resharding_stream_records; point replication, snapshot, \
                      WAL, and unrelated resharding transfers remain unsupported"
            .to_string(),
    })
}

fn validate_private_oram_restart_transfer(
    restart: &RestartTransfer,
    active_transfers: &HashSet<ShardTransfer>,
    resharding: Option<&ReshardState>,
    local_peer_id: PeerId,
) -> Result<(), StorageError> {
    let valid = restart.from_peer_id == local_peer_id
        && private_oram_restart_matches_exact_active_transfer(
            restart,
            active_transfers,
            resharding,
        );
    if valid {
        return Ok(());
    }

    Err(StorageError::bad_request(
        "private ORAM restart transfer requires the exact active marked transfer with an \
         unchanged method on its current source peer",
    ))
}

fn private_oram_restart_matches_exact_active_transfer(
    restart: &RestartTransfer,
    active_transfers: &HashSet<ShardTransfer>,
    resharding: Option<&ReshardState>,
) -> bool {
    let transfer_key = ShardTransferKey {
        shard_id: restart.shard_id,
        to_shard_id: restart.to_shard_id,
        to: restart.to_peer_id,
        from: restart.from_peer_id,
    };
    active_transfers.len() == 1
        && active_transfers.iter().next().is_some_and(|transfer| {
            transfer.key() == transfer_key
                && transfer.method == Some(restart.method)
                && transfer.is_private_oram_preinstalled_transfer_for(resharding)
        })
}

fn classify_private_oram_cluster_resharding_route(
    _collection_name: &str,
    config: &CollectionConfigInternal,
    operation: &ClusterOperations,
) -> bool {
    cluster_operation_progresses_resharding(operation)
        && collection_uses_private_oram_bucket_store(config)
}

fn cluster_operation_progresses_resharding(operation: &ClusterOperations) -> bool {
    matches!(
        operation,
        ClusterOperations::StartResharding(_)
            | ClusterOperations::FinishMigratingPoints(_)
            | ClusterOperations::CommitReadHashRing(_)
            | ClusterOperations::CommitWriteHashRing(_)
            | ClusterOperations::FinishResharding(_)
    )
}

fn classify_private_oram_cluster_shard_key_change(
    config: &CollectionConfigInternal,
    operation: &ClusterOperations,
) -> bool {
    cluster_operation_changes_shard_keys(operation)
        && collection_uses_private_oram_bucket_store(config)
}

fn cluster_operation_changes_shard_keys(operation: &ClusterOperations) -> bool {
    matches!(
        operation,
        ClusterOperations::CreateShardingKey(_) | ClusterOperations::DropShardingKey(_)
    )
}

fn validate_private_oram_cluster_replica_removal(
    _collection_name: &str,
    state: &collection::collection_state::State,
    operation: &ClusterOperations,
    local_peer_id: PeerId,
) -> Result<bool, StorageError> {
    let ClusterOperations::DropReplica(DropReplicaOperation { drop_replica }) = operation else {
        return Ok(false);
    };
    if !collection_uses_private_oram_bucket_store(&state.config) {
        return Ok(false);
    }
    if state.private_oram_replica_removal_preserves_fully_active_layout(
        drop_replica.shard_id,
        drop_replica.peer_id,
        Some(local_peer_id),
    ) {
        return Ok(true);
    }

    Err(StorageError::BadRequest {
        description: "private ORAM collections require replica removal to retain a coordinator \
                      owner, have no active transfer or resharding, and preserve a fully-active \
                      fixed shard layout with at least one replica per shard under \
                      consensus-backed epoch/root ownership"
            .to_string(),
    })
}

fn cluster_operation_starts_shard_transfer(operation: &ClusterOperations) -> bool {
    matches!(
        operation,
        ClusterOperations::MoveShard(_)
            | ClusterOperations::ReplicateShard(_)
            | ClusterOperations::ReplicatePoints(_)
            | ClusterOperations::RestartTransfer(_)
    )
}

fn collection_uses_private_oram_bucket_store(config: &CollectionConfigInternal) -> bool {
    config
        .params
        .effective_encryption()
        .is_some_and(|encryption| {
            encryption.rules.iter().any(|rule| {
                matches!(
                    rule.binding.as_deref(),
                    Some(PRIVATE_HNSW_ORAM_BINDING) | Some(PRIVATE_RESULT_ORAM_BINDING)
                )
            })
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use collection::operations::cluster_ops::{
        CreateShardingKey, CreateShardingKeyOperation, DropShardingKey, DropShardingKeyOperation,
        Replica,
    };
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, VECTOR_OPENFHE_CKKS_PROVIDER};

    use super::*;

    fn assert_no_cluster_fingerprint_leak(rendered: &str, sentinels: &[&str]) {
        for sentinel in sentinels {
            assert!(
                !rendered.contains(sentinel),
                "cluster crypto parity errors must not expose fingerprint `{sentinel}`: {rendered}",
            );
        }
    }

    #[test]
    fn test_generate_even_placement() {
        let pool = vec![1, 2, 3];
        let placement = generate_even_placement(pool, 3, 2);

        assert_eq!(placement.len(), 3);
        for shard_placement in placement {
            assert_eq!(shard_placement.len(), 2);
            assert_ne!(shard_placement[0], shard_placement[1]);
        }

        let pool = vec![1, 2, 3];
        let placement = generate_even_placement(pool, 3, 3);

        assert_eq!(placement.len(), 3);
        for shard_placement in placement {
            assert_eq!(shard_placement.len(), 3);
            let set: HashSet<_> = shard_placement.into_iter().collect();
            assert_eq!(set.len(), 3);
        }

        let pool = vec![1, 2, 3, 4, 5, 6];
        let placement = generate_even_placement(pool, 3, 2);

        assert_eq!(placement.len(), 3);
        let flat_placement: Vec<_> = placement.into_iter().flatten().collect();
        let set: HashSet<_> = flat_placement.into_iter().collect();
        assert_eq!(set.len(), 6);

        let pool = vec![1, 2, 3, 4, 5];
        let placement = generate_even_placement(pool, 3, 10);

        assert_eq!(placement.len(), 3);
        for shard_placement in placement {
            assert_eq!(shard_placement.len(), 5);
        }
    }

    #[test]
    fn encrypted_cluster_data_movement_requires_crypto_runtime_parity() {
        let operation = ClusterOperations::ReplicateShard(ReplicateShardOperation {
            replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                shard_id: 1,
                from_peer_id: 1,
                to_peer_id: 2,
                method: None,
                to_shard_id: None,
            },
        });

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "different-fingerprint".to_string(),
            )),
        );

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect_err("encrypted shard replication must fail closed on mismatched parity");

        assert!(matches!(err, StorageError::BadRequest { .. }));
        assert!(err.to_string().contains("crypto runtime parity"));
        assert!(err.to_string().contains("mismatch"));

        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect("matching crypto runtime parity should allow encrypted movement");
    }

    #[test]
    fn encrypted_cluster_data_movement_parity_errors_redact_fingerprints() {
        let operation = ClusterOperations::MoveShard(MoveShardOperation {
            move_shard: collection::operations::cluster_ops::MoveShard {
                shard_id: 1,
                to_shard_id: None,
                from_peer_id: 1,
                to_peer_id: 2,
                method: None,
            },
        });
        let local_sentinel = "local-fingerprint-redaction-sentinel";
        let peer_sentinel = "peer-fingerprint-redaction-sentinel";
        let metadata = HashMap::from([
            (
                1,
                PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                    local_sentinel.to_string(),
                )),
            ),
            (
                2,
                PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                    peer_sentinel.to_string(),
                )),
            ),
        ]);

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect_err("encrypted shard movement must fail closed on mismatched parity");
        let rendered = err.to_string();
        assert!(rendered.contains("crypto runtime parity mismatch"));
        assert!(rendered.contains("peer 2"));
        assert_no_cluster_fingerprint_leak(&rendered, &[local_sentinel, peer_sentinel]);

        let metadata = HashMap::from([(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                peer_sentinel.to_string(),
            )),
        )]);
        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect_err("encrypted shard movement must fail closed when local metadata is missing");
        let rendered = err.to_string();
        assert!(rendered.contains("local peer 1 has not published"));
        assert_no_cluster_fingerprint_leak(&rendered, &[peer_sentinel]);
    }

    #[test]
    fn encrypted_cluster_transfer_variants_require_endpoint_crypto_runtime_parity() {
        let operations = [
            ClusterOperations::MoveShard(MoveShardOperation {
                move_shard: collection::operations::cluster_ops::MoveShard {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: None,
                },
            }),
            ClusterOperations::RestartTransfer(RestartTransferOperation {
                restart_transfer: RestartTransfer {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: collection::shards::transfer::ShardTransferMethod::StreamRecords,
                },
            }),
        ];

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "different-fingerprint".to_string(),
            )),
        );

        for operation in operations {
            let err = validate_encrypted_cluster_data_movement_parity(
                "docs",
                true,
                &operation,
                1,
                &[1, 2],
                &metadata,
            )
            .expect_err("encrypted shard transfer variants must fail closed on endpoint mismatch");
            assert!(
                err.to_string().contains("crypto runtime parity"),
                "unexpected error for {operation:?}: {err}",
            );
        }
    }

    #[test]
    fn private_hnsw_transfer_guard_classifies_transfer_start_operations() {
        let abort_transfer = ClusterOperations::AbortTransfer(AbortTransferOperation {
            abort_transfer: collection::operations::cluster_ops::AbortShardTransfer {
                shard_id: 1,
                to_shard_id: None,
                from_peer_id: 1,
                to_peer_id: 2,
            },
        });

        for operation in private_hnsw_transfer_start_operations()
            .into_iter()
            .chain(supported_private_oram_transfer_operations())
        {
            assert!(
                cluster_operation_starts_shard_transfer(&operation),
                "expected private HNSW ORAM transfer guard to classify {operation:?}",
            );
        }
        assert!(!cluster_operation_starts_shard_transfer(&abort_transfer));
    }

    fn private_hnsw_transfer_start_operations() -> Vec<ClusterOperations> {
        vec![
            ClusterOperations::MoveShard(MoveShardOperation {
                move_shard: collection::operations::cluster_ops::MoveShard {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: None,
                },
            }),
            ClusterOperations::ReplicateShard(ReplicateShardOperation {
                replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                    shard_id: 1,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: None,
                    to_shard_id: None,
                },
            }),
            ClusterOperations::ReplicatePoints(ReplicatePointsOperation {
                replicate_points: ReplicatePoints {
                    filter: None,
                    from_shard_key: "source".into(),
                    to_shard_key: "target".into(),
                },
            }),
            ClusterOperations::MoveShard(MoveShardOperation {
                move_shard: collection::operations::cluster_ops::MoveShard {
                    shard_id: 1,
                    to_shard_id: Some(2),
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: Some(ShardTransferMethod::StreamRecords),
                },
            }),
            ClusterOperations::MoveShard(MoveShardOperation {
                move_shard: collection::operations::cluster_ops::MoveShard {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: Some(ShardTransferMethod::Snapshot),
                },
            }),
        ]
    }

    fn supported_private_oram_transfer_operations() -> Vec<ClusterOperations> {
        vec![
            ClusterOperations::MoveShard(MoveShardOperation {
                move_shard: collection::operations::cluster_ops::MoveShard {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: Some(ShardTransferMethod::StreamRecords),
                },
            }),
            ClusterOperations::ReplicateShard(ReplicateShardOperation {
                replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: Some(ShardTransferMethod::StreamRecords),
                },
            }),
            ClusterOperations::RestartTransfer(RestartTransferOperation {
                restart_transfer: RestartTransfer {
                    shard_id: 1,
                    to_shard_id: None,
                    from_peer_id: 1,
                    to_peer_id: 2,
                    method: ShardTransferMethod::StreamRecords,
                },
            }),
        ]
    }

    fn private_oram_resharding_progress_operations() -> Vec<ClusterOperations> {
        vec![
            ClusterOperations::StartResharding(
                collection::operations::cluster_ops::StartReshardingOperation {
                    start_resharding: StartResharding {
                        uuid: Some(Uuid::from_u128(99)),
                        direction: ReshardingDirection::Up,
                        peer_id: Some(2),
                        shard_key: None,
                    },
                },
            ),
            ClusterOperations::FinishMigratingPoints(
                collection::operations::cluster_ops::FinishMigratingPointsOperation {
                    finish_migrating_points:
                        collection::operations::cluster_ops::FinishMigratingPoints {
                            shard_id: Some(1),
                            peer_id: Some(2),
                        },
                },
            ),
            ClusterOperations::CommitReadHashRing(
                collection::operations::cluster_ops::CommitReadHashRingOperation {
                    commit_read_hash_ring:
                        collection::operations::cluster_ops::CommitReadHashRing {},
                },
            ),
            ClusterOperations::CommitWriteHashRing(
                collection::operations::cluster_ops::CommitWriteHashRingOperation {
                    commit_write_hash_ring:
                        collection::operations::cluster_ops::CommitWriteHashRing {},
                },
            ),
            ClusterOperations::FinishResharding(
                collection::operations::cluster_ops::FinishReshardingOperation {
                    finish_resharding: collection::operations::cluster_ops::FinishResharding {},
                },
            ),
        ]
    }

    fn private_oram_abort_resharding_operation() -> ClusterOperations {
        ClusterOperations::AbortResharding(
            collection::operations::cluster_ops::AbortReshardingOperation {
                abort_resharding: collection::operations::cluster_ops::AbortResharding {},
            },
        )
    }

    fn private_oram_shard_key_change_operations() -> Vec<ClusterOperations> {
        vec![
            ClusterOperations::CreateShardingKey(CreateShardingKeyOperation {
                create_sharding_key: CreateShardingKey {
                    shard_key: "tenant-a".into(),
                    shards_number: None,
                    replication_factor: None,
                    placement: Some(vec![1, 2]),
                    initial_state: None,
                },
            }),
            ClusterOperations::DropShardingKey(DropShardingKeyOperation {
                drop_sharding_key: DropShardingKey {
                    shard_key: "tenant-a".into(),
                },
            }),
        ]
    }

    fn private_oram_drop_replica_operation() -> ClusterOperations {
        ClusterOperations::DropReplica(DropReplicaOperation {
            drop_replica: Replica {
                shard_id: 1,
                peer_id: 2,
            },
        })
    }

    fn replica_removal_state(
        config: CollectionConfigInternal,
    ) -> collection::collection_state::State {
        collection::collection_state::State {
            config,
            shards: [(
                1,
                collection::collection_state::ShardInfo {
                    replicas: HashMap::from([
                        (1, replica_set_state::ReplicaState::Active),
                        (2, replica_set_state::ReplicaState::Active),
                    ]),
                },
            )]
            .into_iter()
            .collect(),
            resharding: None,
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: Default::default(),
        }
    }

    fn private_oram_resharding_transfer_state(
        direction: ReshardingDirection,
    ) -> (collection::collection_state::State, ClusterOperations) {
        let mut config = private_hnsw_collection_config();
        config.params.shard_number = NonZeroU32::new(2).unwrap();
        let (source_shard, target_shard, source_peer, target_peer, shards) = match direction {
            ReshardingDirection::Up => (
                1,
                2,
                1,
                2,
                [
                    (
                        1,
                        collection::collection_state::ShardInfo {
                            replicas: HashMap::from([(1, replica_set_state::ReplicaState::Active)]),
                        },
                    ),
                    (
                        2,
                        collection::collection_state::ShardInfo {
                            replicas: HashMap::from([(
                                2,
                                replica_set_state::ReplicaState::Resharding,
                            )]),
                        },
                    ),
                ],
            ),
            ReshardingDirection::Down => (
                2,
                1,
                2,
                1,
                [
                    (
                        1,
                        collection::collection_state::ShardInfo {
                            replicas: HashMap::from([(1, replica_set_state::ReplicaState::Active)]),
                        },
                    ),
                    (
                        2,
                        collection::collection_state::ShardInfo {
                            replicas: HashMap::from([(2, replica_set_state::ReplicaState::Active)]),
                        },
                    ),
                ],
            ),
        };
        let state = collection::collection_state::State {
            config,
            shards: shards.into_iter().collect(),
            resharding: Some(ReshardState::new(
                Uuid::from_u128(77),
                direction,
                2,
                2,
                None,
            )),
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: Default::default(),
        };
        let operation = ClusterOperations::ReplicateShard(ReplicateShardOperation {
            replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                shard_id: source_shard,
                to_shard_id: Some(target_shard),
                from_peer_id: source_peer,
                to_peer_id: target_peer,
                method: Some(ShardTransferMethod::ReshardingStreamRecords),
            },
        });
        (state, operation)
    }

    fn private_hnsw_collection_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: collection::config::CollectionParams {
                encryption: Some(collection::config::CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/vector-private-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: collection::config::CryptoMigrationState::Active,
                    rules: vec![collection::config::EncryptionRuleRef {
                        id: "docs_text_private_hnsw".to_string(),
                        selector: collection::config::EncryptionSelector::VectorNames {
                            names: vec!["text".to_string()],
                        },
                        instance: "docs_text_private_hnsw".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
                ..collection::config::CollectionParams::empty()
            },
            hnsw_config: Default::default(),
            optimizer_config: collection::optimizers_builder::OptimizersConfig {
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
            wal_config: collection::config::WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(11)),
            metadata: None,
        }
    }

    fn private_result_oram_collection_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: collection::config::CollectionParams {
                encryption: Some(collection::config::CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/result-private-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: collection::config::CryptoMigrationState::Active,
                    rules: vec![collection::config::EncryptionRuleRef {
                        id: "body_private_result_oram".to_string(),
                        selector: collection::config::EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_private_result_oram".to_string(),
                        binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    }],
                }),
                ..collection::config::CollectionParams::empty()
            },
            hnsw_config: Default::default(),
            optimizer_config: collection::optimizers_builder::OptimizersConfig {
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
            wal_config: collection::config::WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(12)),
            metadata: None,
        }
    }

    fn ordinary_collection_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: collection::config::CollectionParams::empty(),
            hnsw_config: Default::default(),
            optimizer_config: collection::optimizers_builder::OptimizersConfig {
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
            wal_config: collection::config::WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(13)),
            metadata: None,
        }
    }

    #[test]
    fn private_hnsw_transfer_guard_allows_only_preinstall_supported_shape() {
        let config = private_hnsw_collection_config();
        let state = replica_removal_state(config.clone());
        let collection_name = "private-oram-transfer-secret-collection";
        let keys = crate::tonic::api::qdrant_internal_api::private_oram_transfer_index_keys(
            &config,
            collection_name,
        )
        .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].index_kind,
            storage::content_manager::consensus_ops::PrivateOramIndexKind::Hnsw
        );
        assert_eq!(keys[0].index_name, "text");
        for operation in supported_private_oram_transfer_operations() {
            assert_eq!(
                validate_private_oram_cluster_transfer(collection_name, &state, &operation)
                    .unwrap(),
                PrivateOramClusterTransferRoute::StableLayout,
            );
        }
        for operation in private_hnsw_transfer_start_operations() {
            let err = validate_private_oram_cluster_transfer(collection_name, &state, &operation)
                .expect_err("unsupported private HNSW ORAM transfer must fail closed");
            assert!(
                err.to_string().contains("explicit stream_records"),
                "unexpected error for {operation:?}: {err}",
            );
            assert_no_private_oram_config_leak(
                &err.to_string(),
                &[
                    "tenant-a/vector-private-rk",
                    "docs_text_private_hnsw",
                    PRIVATE_HNSW_ORAM_BINDING,
                    "private_hnsw_oram",
                    collection_name,
                ],
            );
        }
    }

    #[test]
    fn private_result_oram_transfer_guard_allows_only_preinstall_supported_shape() {
        let config = private_result_oram_collection_config();
        let state = replica_removal_state(config.clone());
        let collection_name = "private-result-oram-transfer-secret-collection";
        let keys = crate::tonic::api::qdrant_internal_api::private_oram_transfer_index_keys(
            &config,
            collection_name,
        )
        .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].index_kind,
            storage::content_manager::consensus_ops::PrivateOramIndexKind::ResultPayload
        );
        assert!(keys[0].index_name.is_empty());
        for operation in supported_private_oram_transfer_operations() {
            assert_eq!(
                validate_private_oram_cluster_transfer(collection_name, &state, &operation)
                    .unwrap(),
                PrivateOramClusterTransferRoute::StableLayout,
            );
        }
        for operation in private_hnsw_transfer_start_operations() {
            let err = validate_private_oram_cluster_transfer(collection_name, &state, &operation)
                .expect_err("unsupported private result ORAM transfer must fail closed");
            assert!(
                err.to_string().contains("explicit stream_records"),
                "unexpected error for {operation:?}: {err}",
            );
            assert_no_private_oram_config_leak(
                &err.to_string(),
                &[
                    "tenant-a/result-private-rk",
                    "body_private_result_oram",
                    PRIVATE_RESULT_ORAM_BINDING,
                    "private_result_oram",
                    collection_name,
                ],
            );
        }
    }

    #[test]
    fn private_oram_transfer_guard_supports_fixed_multi_shard_collection() {
        let mut config = private_hnsw_collection_config();
        config.params.shard_number = NonZeroU32::new(2).unwrap();
        let state = replica_removal_state(config);
        for operation in supported_private_oram_transfer_operations() {
            assert_eq!(
                validate_private_oram_cluster_transfer("docs", &state, &operation).unwrap(),
                PrivateOramClusterTransferRoute::StableLayout,
            );
        }

        let ordinary_state = replica_removal_state(ordinary_collection_config());
        for operation in supported_private_oram_transfer_operations() {
            assert_eq!(
                validate_private_oram_cluster_transfer("docs", &ordinary_state, &operation)
                    .unwrap(),
                PrivateOramClusterTransferRoute::Ordinary,
            );
        }
    }

    #[test]
    fn private_oram_transfer_guard_allows_only_exact_active_resharding_migration() {
        for direction in [ReshardingDirection::Up, ReshardingDirection::Down] {
            let (state, operation) = private_oram_resharding_transfer_state(direction);
            assert_eq!(
                validate_private_oram_cluster_transfer("docs", &state, &operation).unwrap(),
                PrivateOramClusterTransferRoute::Resharding,
            );
            let ClusterOperations::ReplicateShard(ReplicateShardOperation { replicate_shard }) =
                &operation
            else {
                unreachable!();
            };

            let mut committed_state = state.clone();
            committed_state.resharding.as_mut().unwrap().stage =
                collection::shards::resharding::ReshardingStage::ReadHashRingCommitted;
            validate_private_oram_cluster_transfer("docs", &committed_state, &operation)
                .expect_err("resharding transfer must be limited to point migration");

            let mut wrong_shard_key_state = state.clone();
            wrong_shard_key_state
                .shards_key_mapping
                .insert("tenant-a".into(), HashSet::from([replicate_shard.shard_id]));
            validate_private_oram_cluster_transfer("docs", &wrong_shard_key_state, &operation)
                .expect_err("resharding transfer must remain within the active shard key");

            if direction == ReshardingDirection::Up {
                let mut transitional_source_state = state.clone();
                transitional_source_state
                    .shards
                    .get_mut(&replicate_shard.shard_id)
                    .unwrap()
                    .replicas
                    .insert(
                        replicate_shard.from_peer_id,
                        replica_set_state::ReplicaState::ReshardingScaleDown,
                    );
                validate_private_oram_cluster_transfer(
                    "docs",
                    &transitional_source_state,
                    &operation,
                )
                .expect_err("scale-up source must be fully active");
            }

            for invalid in [
                ClusterOperations::ReplicateShard(ReplicateShardOperation {
                    replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                        to_peer_id: 99,
                        ..replicate_shard.clone()
                    },
                }),
                ClusterOperations::ReplicateShard(ReplicateShardOperation {
                    replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                        to_shard_id: None,
                        ..replicate_shard.clone()
                    },
                }),
                ClusterOperations::ReplicateShard(ReplicateShardOperation {
                    replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                        method: Some(ShardTransferMethod::StreamRecords),
                        ..replicate_shard.clone()
                    },
                }),
            ] {
                validate_private_oram_cluster_transfer("docs", &state, &invalid)
                    .expect_err("unrelated private ORAM resharding transfer must fail closed");
            }
        }
    }

    #[test]
    fn private_oram_restart_requires_exact_active_marked_transfer_on_source() {
        let restart = RestartTransfer {
            shard_id: 1,
            to_shard_id: None,
            from_peer_id: 7,
            to_peer_id: 9,
            method: ShardTransferMethod::StreamRecords,
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 7,
            to: 9,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        };
        validate_private_oram_restart_transfer(
            &restart,
            &HashSet::from([transfer.clone()]),
            None,
            7,
        )
        .unwrap();

        let mut unmarked = transfer.clone();
        unmarked.private_oram_preinstalled = false;
        let mut wrong_method = restart.clone();
        wrong_method.method = ShardTransferMethod::Snapshot;
        let mut temporary = restart.clone();
        temporary.to_shard_id = Some(2);
        for (request, transfers, local_peer) in [
            (restart.clone(), HashSet::from([unmarked]), 7),
            (
                restart.clone(),
                HashSet::from([
                    transfer.clone(),
                    ShardTransfer {
                        shard_id: 2,
                        ..transfer.clone()
                    },
                ]),
                7,
            ),
            (restart.clone(), HashSet::from([transfer.clone()]), 11),
            (wrong_method, HashSet::from([transfer.clone()]), 7),
            (temporary, HashSet::from([transfer]), 7),
        ] {
            let rendered =
                validate_private_oram_restart_transfer(&request, &transfers, None, local_peer)
                    .unwrap_err()
                    .to_string();
            assert!(rendered.contains("exact active marked transfer"));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
        }
    }

    #[test]
    fn private_oram_resharding_restart_requires_exact_active_marked_transfer() {
        for direction in [ReshardingDirection::Up, ReshardingDirection::Down] {
            let (mut state, operation) = private_oram_resharding_transfer_state(direction);
            let ClusterOperations::ReplicateShard(ReplicateShardOperation { replicate_shard }) =
                operation
            else {
                unreachable!();
            };
            let transfer = ShardTransfer {
                shard_id: replicate_shard.shard_id,
                to_shard_id: replicate_shard.to_shard_id,
                from: replicate_shard.from_peer_id,
                to: replicate_shard.to_peer_id,
                sync: true,
                method: replicate_shard.method,
                private_oram_preinstalled: true,
                private_oram_layout_transition: None,
                filter: None,
            };
            state.transfers.insert(transfer.clone());
            let restart = RestartTransfer {
                shard_id: transfer.shard_id,
                to_shard_id: transfer.to_shard_id,
                from_peer_id: transfer.from,
                to_peer_id: transfer.to,
                method: ShardTransferMethod::ReshardingStreamRecords,
            };
            let restart_operation = ClusterOperations::RestartTransfer(RestartTransferOperation {
                restart_transfer: restart.clone(),
            });

            assert_eq!(
                validate_private_oram_cluster_transfer("docs", &state, &restart_operation).unwrap(),
                PrivateOramClusterTransferRoute::Resharding,
            );
            validate_private_oram_restart_transfer(
                &restart,
                &state.transfers,
                state.resharding.as_ref(),
                transfer.from,
            )
            .unwrap();

            let mut wrong_method = restart.clone();
            wrong_method.method = ShardTransferMethod::StreamRecords;
            validate_private_oram_restart_transfer(
                &wrong_method,
                &state.transfers,
                state.resharding.as_ref(),
                transfer.from,
            )
            .expect_err("resharding restart must preserve its transfer method");

            state.resharding.as_mut().unwrap().stage =
                collection::shards::resharding::ReshardingStage::ReadHashRingCommitted;
            validate_private_oram_restart_transfer(
                &restart,
                &state.transfers,
                state.resharding.as_ref(),
                transfer.from,
            )
            .expect_err("resharding restart must remain in point migration");
        }
    }

    #[test]
    fn private_oram_transfer_index_keys_are_deterministic() {
        let mut config = private_hnsw_collection_config();
        let mut result_encryption = private_result_oram_collection_config()
            .params
            .encryption
            .unwrap();
        let result_rule = result_encryption.rules.remove(0);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption
            .rules
            .push(collection::config::EncryptionRuleRef {
                id: "docs_alpha_private_hnsw".to_string(),
                selector: collection::config::EncryptionSelector::VectorNames {
                    names: vec!["alpha".to_string()],
                },
                instance: "docs_alpha_private_hnsw".to_string(),
                binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
            });
        encryption.rules.push(result_rule);

        let keys = crate::tonic::api::qdrant_internal_api::private_oram_transfer_index_keys(
            &config, "docs",
        )
        .unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].index_name, "alpha");
        assert_eq!(keys[1].index_name, "text");
        assert_eq!(
            keys[2].index_kind,
            storage::content_manager::consensus_ops::PrivateOramIndexKind::ResultPayload
        );
        assert!(keys[2].index_name.is_empty());
    }

    #[test]
    fn private_oram_resharding_route_selects_typed_coordinator() {
        let collection_name = "private-oram-resharding-secret-collection";
        for (label, config) in [
            ("private HNSW ORAM", private_hnsw_collection_config()),
            (
                "private result ORAM",
                private_result_oram_collection_config(),
            ),
        ] {
            for operation in private_oram_resharding_progress_operations() {
                assert!(
                    classify_private_oram_cluster_resharding_route(
                        collection_name,
                        &config,
                        &operation,
                    ),
                    "{label} resharding operation did not select the private coordinator: {operation:?}",
                );
            }
        }
        for operation in private_oram_resharding_progress_operations() {
            assert!(!classify_private_oram_cluster_resharding_route(
                collection_name,
                &ordinary_collection_config(),
                &operation,
            ));
        }
    }

    fn assert_no_private_oram_config_leak(rendered: &str, sentinels: &[&str]) {
        for sentinel in sentinels {
            assert!(
                !rendered.contains(sentinel),
                "private ORAM cluster guard must not expose config sentinel `{sentinel}`: {rendered}",
            );
        }
    }

    #[test]
    fn private_oram_cluster_guards_redact_client_state_aliases() {
        let mut config = private_result_oram_collection_config();
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.key_id = Some("clientStateCiphertextSha256.json".to_string());
        let rule = encryption.rules.first_mut().unwrap();
        rule.id = "encryptedClientStateCiphertextSha256.json".to_string();
        rule.instance = "stateCiphertextSha256.json".to_string();
        if let collection::config::EncryptionSelector::PayloadPaths { paths } = &mut rule.selector {
            *paths = vec![
                "clientState.json".to_string(),
                "clientStates.json".to_string(),
                "client_state.json".to_string(),
                "client_states.json".to_string(),
                "clientStateBackup.json".to_string(),
                "clientStateBackups.json".to_string(),
                "client_state_backup.json".to_string(),
                "client_state_backups.json".to_string(),
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
                "client_state_ciphertext_hash.bin".to_string(),
                "client_state_ciphertext_hash.json".to_string(),
                "client_state_ciphertext_hashes.bin".to_string(),
                "client_state_ciphertext_hashes.json".to_string(),
                "client_state_ciphertext_sha256.bin".to_string(),
                "client_state_ciphertext_sha256.json".to_string(),
                "client_state_ciphertexts_sha256.json".to_string(),
                "client_state_ciphertexts_sha256.bin".to_string(),
                "encryptedClientStateBackup.json".to_string(),
                "encryptedClientStateBackups.json".to_string(),
                "encryptedClientState.json".to_string(),
                "encryptedClientStates.json".to_string(),
                "encrypted.client.state.json".to_string(),
                "encrypted_client_states.json".to_string(),
                "encryptedClientStateSnapshot.json".to_string(),
                "encryptedClientStateSnapshots.json".to_string(),
                "encrypted_client_state_backups.json".to_string(),
                "encrypted_client_state.json".to_string(),
                "encrypted_client_state_backup.json".to_string(),
                "encrypted_client_state_snapshot.bin".to_string(),
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
                "encrypted_client_state_ciphertexts_sha256.json".to_string(),
                "encrypted_client_state_ciphertexts_sha256.bin".to_string(),
                "tokenMapBackup.json".to_string(),
                "tokenMapBackups.json".to_string(),
                "token.map.backup.json".to_string(),
                "token.map.backups.json".to_string(),
                "token_map_backup.json".to_string(),
                "token_map_backups.json".to_string(),
                "tokenPositionMapBackup.json".to_string(),
                "tokenPositionMapBackups.json".to_string(),
                "token.position.map.backup.json".to_string(),
                "token.position.map.backups.json".to_string(),
                "token_position_map_backup.json".to_string(),
                "token_position_map_backups.json".to_string(),
                "accessVolume.json".to_string(),
                "accessVolumes.json".to_string(),
                "access_volume.json".to_string(),
                "access.volume.json".to_string(),
                "access_volumes.json".to_string(),
                "access.volumes.json".to_string(),
                "oramPositionMapBackup.json".to_string(),
                "oramPositionMapBackups.json".to_string(),
                "oram_position_map_backup.json".to_string(),
                "oram_position_map_backups.json".to_string(),
                "positionMapBackup.json".to_string(),
                "positionMapBackups.json".to_string(),
                "position_map_backup.json".to_string(),
                "position_map_backups.json".to_string(),
                "stashBackup.json".to_string(),
                "stash_backup.json".to_string(),
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
                "ciphertextSha256.json".to_string(),
                "ciphertextsSha256.json".to_string(),
                "ciphertext_sha256.bin".to_string(),
                "ciphertexts_sha256.bin".to_string(),
                "bucketCommitment.json".to_string(),
                "bucketCommitments.json".to_string(),
                "bucket_commitment.bin".to_string(),
                "bucket.commitment.bin".to_string(),
                "bucket_commitments.bin".to_string(),
                "bucket.commitments.bin".to_string(),
                "updatedBucketCommitment.json".to_string(),
                "updatedBucketCommitments.json".to_string(),
                "updated_bucket_commitment.bin".to_string(),
                "updated.bucket.commitment.bin".to_string(),
                "updated_bucket_commitments.bin".to_string(),
                "updated.bucket.commitments.bin".to_string(),
            ];
        }

        let collection_name = "stashBackup.json";
        let transfer_operation = private_hnsw_transfer_start_operations()
            .into_iter()
            .next()
            .unwrap();
        let replica_operation = private_oram_drop_replica_operation();
        let transfer_state = replica_removal_state(config.clone());

        let errors = [
            (
                "transfer",
                validate_private_oram_cluster_transfer(
                    collection_name,
                    &transfer_state,
                    &transfer_operation,
                )
                .expect_err("private ORAM transfer must fail closed without alias leaks")
                .to_string(),
                "explicit stream_records",
            ),
            (
                "replica-removal",
                validate_private_oram_cluster_replica_removal(
                    collection_name,
                    &replica_removal_state(config.clone()),
                    &replica_operation,
                    2,
                )
                .expect_err("private ORAM replica removal must fail closed without alias leaks")
                .to_string(),
                "replica removal",
            ),
        ];

        for (label, rendered, expected) in errors {
            assert!(
                rendered.contains("private ORAM collections"),
                "unexpected {label} error: {rendered}",
            );
            assert!(
                rendered.contains(expected),
                "unexpected {label} error: {rendered}",
            );
            assert_no_private_oram_config_leak(
                &rendered,
                &[
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
                    "client_state_ciphertexts_sha256",
                    "client_state_ciphertexts_sha256.bin",
                    "client_state_ciphertexts_sha256.json",
                    "encryptedClientStateBackup",
                    "encryptedClientStateBackups",
                    "encryptedClientState",
                    "encryptedClientStates",
                    "encrypted_client_states",
                    "encryptedClientStateSnapshot",
                    "encryptedClientStateSnapshots",
                    "encrypted_client_state_backups",
                    "encrypted_client_state",
                    "encrypted.client.state",
                    "encrypted.client.state.json",
                    "encrypted_client_state.json",
                    "encrypted_client_state_backup",
                    "encrypted_client_state_snapshot",
                    "encrypted.client.state.snapshot",
                    "encrypted.client.state.snapshot.json",
                    "encrypted_client_state_snapshot.bin",
                    "encrypted_client_state_snapshots",
                    "encrypted_client_state_snapshots.json",
                    "encrypted.client.state.snapshots.json",
                    "encrypted_client_state_ciphertext",
                    "encryptedClientStateCiphertext",
                    "encryptedClientStateCiphertextHash",
                    "encryptedClientStateCiphertextHashes",
                    "encryptedClientStateCiphertextSha256",
                    "encryptedClientStateCiphertextsSha256",
                    "encrypted_client_state_ciphertext_hash",
                    "encrypted_client_state_ciphertext_hash.bin",
                    "encrypted_client_state_ciphertext_hash.json",
                    "encrypted_client_state_ciphertext_hashes",
                    "encrypted_client_state_ciphertext_hashes.bin",
                    "encrypted_client_state_ciphertext_hashes.json",
                    "encrypted_client_state_ciphertext_sha256",
                    "encrypted_client_state_ciphertexts_sha256",
                    "encrypted_client_state_ciphertexts_sha256.bin",
                    "encrypted_client_state_ciphertexts_sha256.json",
                    "tokenMapBackup",
                    "tokenMapBackups",
                    "token_map_backup",
                    "token.map.backup",
                    "token.map.backups",
                    "token_map_backups",
                    "tokenPositionMapBackup",
                    "token_position_map_backup",
                    "token.position.map.backup",
                    "token.position.map.backups",
                    "token_position_map_backups",
                    "accessVolume",
                    "accessVolumes",
                    "access_volume",
                    "access.volume",
                    "access_volumes",
                    "access.volumes",
                    "oramPositionMapBackup",
                    "oramPositionMapBackups",
                    "oram_position_map_backup",
                    "oram_position_map_backups",
                    "positionMapBackup",
                    "positionMapBackups",
                    "position_map_backup",
                    "position_map_backups",
                    "stashBackup",
                    "stashBackup.json",
                    "stashBackups",
                    "stashBackups.json",
                    "stash_backup",
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
                    "state_ciphertexts_sha256",
                    "state_ciphertexts_sha256.bin",
                    "state_ciphertexts_sha256.json",
                    "ciphertextSha256",
                    "ciphertextsSha256",
                    "ciphertext_sha256",
                    "ciphertexts_sha256",
                    "bucketCommitment",
                    "bucketCommitments",
                    "bucket_commitment",
                    "bucket.commitment",
                    "bucket_commitments",
                    "bucket.commitments",
                    "updatedBucketCommitment",
                    "updatedBucketCommitments",
                    "updated_bucket_commitment",
                    "updated.bucket.commitment",
                    "updated_bucket_commitments",
                    "updated.bucket.commitments",
                    "tokenPositionMapBackups",
                    PRIVATE_RESULT_ORAM_BINDING,
                    "private_result_oram",
                ],
            );
        }
    }

    #[test]
    fn private_oram_shard_key_route_is_classified_without_config_leakage() {
        for (label, config) in [
            ("private HNSW ORAM", private_hnsw_collection_config()),
            (
                "private result ORAM",
                private_result_oram_collection_config(),
            ),
        ] {
            for operation in private_oram_shard_key_change_operations() {
                assert!(
                    classify_private_oram_cluster_shard_key_change(&config, &operation),
                    "unexpected {label} route for {operation:?}",
                );
            }
        }

        for operation in private_oram_shard_key_change_operations() {
            assert!(!classify_private_oram_cluster_shard_key_change(
                &ordinary_collection_config(),
                &operation,
            ));
        }
    }

    #[test]
    fn private_oram_drop_replica_guard_requires_fully_active_remaining_owner_layout() {
        let operation = private_oram_drop_replica_operation();
        let collection_name = "private-oram-drop-replica-secret-collection";

        for (label, config, sentinels) in [
            (
                "private HNSW ORAM",
                private_hnsw_collection_config(),
                [
                    "tenant-a/vector-private-rk",
                    "docs_text_private_hnsw",
                    PRIVATE_HNSW_ORAM_BINDING,
                    "private_hnsw_oram",
                    collection_name,
                ],
            ),
            (
                "private result ORAM",
                private_result_oram_collection_config(),
                [
                    "tenant-a/result-private-rk",
                    "body_private_result_oram",
                    PRIVATE_RESULT_ORAM_BINDING,
                    "private_result_oram",
                    collection_name,
                ],
            ),
        ] {
            let state = replica_removal_state(config.clone());
            assert!(
                validate_private_oram_cluster_replica_removal(
                    collection_name,
                    &state,
                    &operation,
                    1,
                )
                .expect("fixed-layout private ORAM replica removal must be authorized"),
                "{label} removal must require a reservation",
            );

            let err = validate_private_oram_cluster_replica_removal(
                collection_name,
                &state,
                &operation,
                2,
            )
            .expect_err("the removed peer cannot coordinate private ORAM replica removal");
            assert!(
                err.to_string().contains("replica removal")
                    && err
                        .to_string()
                        .contains("consensus-backed epoch/root ownership"),
                "unexpected {label} replica removal error: {err}",
            );
            assert_no_private_oram_config_leak(&err.to_string(), &sentinels);

            let mut last_replica = replica_removal_state(config.clone());
            last_replica.shards.get_mut(&1).unwrap().replicas.remove(&1);
            validate_private_oram_cluster_replica_removal(
                collection_name,
                &last_replica,
                &operation,
                1,
            )
            .expect_err("the final shard replica must not be removed");

            let mut inactive = replica_removal_state(config);
            inactive
                .shards
                .get_mut(&1)
                .unwrap()
                .replicas
                .insert(2, replica_set_state::ReplicaState::Dead);
            validate_private_oram_cluster_replica_removal(
                collection_name,
                &inactive,
                &operation,
                1,
            )
            .expect_err("private ORAM replica removal requires fully-active replicas");
        }

        assert!(
            !validate_private_oram_cluster_replica_removal(
                collection_name,
                &replica_removal_state(ordinary_collection_config()),
                &operation,
                1,
            )
            .expect("ordinary collection replica removal must stay open")
        );
    }

    #[test]
    fn private_oram_transfer_guard_allows_abort_cleanup_operations() {
        let abort_transfer = ClusterOperations::AbortTransfer(AbortTransferOperation {
            abort_transfer: collection::operations::cluster_ops::AbortShardTransfer {
                shard_id: 1,
                to_shard_id: None,
                from_peer_id: 1,
                to_peer_id: 2,
            },
        });

        assert_eq!(
            validate_private_oram_cluster_transfer(
                "docs",
                &replica_removal_state(private_hnsw_collection_config()),
                &abort_transfer,
            )
            .expect("private HNSW ORAM transfer cleanup abort must remain allowed"),
            PrivateOramClusterTransferRoute::Ordinary,
        );
        assert_eq!(
            validate_private_oram_cluster_transfer(
                "docs",
                &replica_removal_state(private_result_oram_collection_config()),
                &abort_transfer,
            )
            .expect("private result ORAM transfer cleanup abort must remain allowed"),
            PrivateOramClusterTransferRoute::Ordinary,
        );

        let abort_resharding = private_oram_abort_resharding_operation();
        assert!(!classify_private_oram_cluster_resharding_route(
            "docs",
            &private_hnsw_collection_config(),
            &abort_resharding,
        ));
        assert!(!classify_private_oram_cluster_resharding_route(
            "docs",
            &private_result_oram_collection_config(),
            &abort_resharding,
        ));
    }

    #[test]
    fn encrypted_cluster_transfer_rejects_vector_public_material_drift() {
        let settings = crate::settings::Settings {
            crypto: crate::settings::CryptoSettings {
                ckks_grouped_max_candidates: crate::settings::default_ckks_grouped_max_candidates(),
                ckks_scoring_source_batch_max:
                    crate::settings::default_ckks_scoring_source_batch_max(),
                ckks_query_nonce_replay_ttl_secs:
                    crate::settings::default_ckks_query_nonce_replay_ttl_secs(),
                ckks_query_nonce_replay_cache_max_entries:
                    crate::settings::default_ckks_query_nonce_replay_cache_max_entries(),
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    crate::settings::CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            "sym_key".to_string(),
                            "tenant-a/vector-v1".to_string(),
                        )]),
                        backend_ref: Some("openfhe_bridge_v1".to_string()),
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
                        source: Some("env".to_string()),
                        env: Some("QDRANT_TEST_VECTOR_RK".to_string()),
                        ..crate::settings::CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_bridge_v1".to_string(),
                    crate::settings::CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/qdrant-sec-openfhe".to_string()),
                        sha256_b64: Some(BASE64URL_NOPAD.encode(&[17_u8; 32])),
                        signature_public_key_b64: None,
                        signature_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                        max_output_bytes: None,
                        landlock_read_allow_roots: Vec::new(),
                    },
                )]),
                ..crate::settings::CryptoSettings::default()
            },
            ..crate::settings::Settings::new(None).unwrap()
        };
        let local_fingerprint =
            crate::common::crypto::crypto_runtime_capability_fingerprint(&settings);
        let mut peer_with_different_public_material = settings.clone();
        peer_with_different_public_material
            .crypto
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                "public_key_b64".to_string(),
                serde_json::json!(BASE64URL_NOPAD.encode(b"other openfhe public key")),
            );
        let peer_fingerprint = crate::common::crypto::crypto_runtime_capability_fingerprint(
            &peer_with_different_public_material,
        );
        let operation = ClusterOperations::MoveShard(MoveShardOperation {
            move_shard: collection::operations::cluster_ops::MoveShard {
                shard_id: 1,
                to_shard_id: None,
                from_peer_id: 1,
                to_peer_id: 2,
                method: None,
            },
        });
        let metadata = HashMap::from([
            (
                1,
                PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                    local_fingerprint,
                )),
            ),
            (
                2,
                PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                    peer_fingerprint,
                )),
            ),
        ]);

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect_err("OpenFHE public-material drift must fail encrypted shard movement");
        assert!(matches!(err, StorageError::BadRequest { .. }));
        assert!(err.to_string().contains("crypto runtime parity"));
    }

    #[test]
    fn encrypted_cluster_replicate_points_requires_all_peer_crypto_runtime_parity() {
        let operation = ClusterOperations::ReplicatePoints(ReplicatePointsOperation {
            replicate_points: ReplicatePoints {
                filter: None,
                from_shard_key: "source".into(),
                to_shard_key: "target".into(),
            },
        });

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "different-fingerprint".to_string(),
            )),
        );

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect_err("encrypted point replication must fail closed on any peer mismatch");
        assert!(matches!(err, StorageError::BadRequest { .. }));
        assert!(err.to_string().contains("crypto runtime parity"));

        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect("matching all-peer crypto runtime parity should allow point replication");
    }

    #[test]
    fn encrypted_cluster_create_sharding_key_requires_target_peer_crypto_runtime_parity() {
        let operation = ClusterOperations::CreateShardingKey(CreateShardingKeyOperation {
            create_sharding_key: CreateShardingKey {
                shard_key: "tenant-a".into(),
                shards_number: None,
                replication_factor: None,
                placement: Some(vec![1, 2, 3]),
                initial_state: None,
            },
        });

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "different-fingerprint".to_string(),
            )),
        );

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect_err("encrypted create-sharding-key must fail closed on placement peer mismatch");
        assert!(matches!(err, StorageError::BadRequest { .. }));
        assert!(err.to_string().contains("create_sharding_key"));
        assert!(err.to_string().contains("crypto runtime parity"));

        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect("matching placement peer parity should allow encrypted create-sharding-key");

        let operation = ClusterOperations::CreateShardingKey(CreateShardingKeyOperation {
            create_sharding_key: CreateShardingKey {
                shard_key: "tenant-b".into(),
                shards_number: None,
                replication_factor: None,
                placement: None,
                initial_state: None,
            },
        });
        metadata.remove(&3);
        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect_err("default placement must require all candidate peer crypto metadata");
        assert!(err.to_string().contains("peer 3 has not published"));
    }

    #[test]
    fn encrypted_cluster_data_movement_rejects_empty_crypto_runtime_fingerprints() {
        let operation = ClusterOperations::ReplicateShard(ReplicateShardOperation {
            replicate_shard: collection::operations::cluster_ops::ReplicateShard {
                shard_id: 1,
                from_peer_id: 1,
                to_peer_id: 2,
                method: None,
                to_shard_id: None,
            },
        });

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new())),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect_err("encrypted movement must fail closed when local fingerprint is empty");
        assert!(err.to_string().contains("local peer 1 has not published"));

        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new())),
        );

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2],
            &metadata,
        )
        .expect_err("encrypted movement must fail closed when peer fingerprint is empty");
        assert!(err.to_string().contains("peer 2 has not published"));
    }

    #[test]
    fn encrypted_cluster_resharding_requires_target_peer_crypto_runtime_parity() {
        let operation = ClusterOperations::StartResharding(
            collection::operations::cluster_ops::StartReshardingOperation {
                start_resharding: StartResharding {
                    uuid: Some(Uuid::from_u128(1)),
                    direction: ReshardingDirection::Up,
                    peer_id: Some(2),
                    shard_key: None,
                },
            },
        );

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "different-fingerprint".to_string(),
            )),
        );

        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect_err("encrypted resharding must fail closed on target peer mismatch");
        assert!(matches!(err, StorageError::BadRequest { .. }));
        assert!(err.to_string().contains("crypto runtime parity"));

        let operation = ClusterOperations::StartResharding(
            collection::operations::cluster_ops::StartReshardingOperation {
                start_resharding: StartResharding {
                    uuid: Some(Uuid::from_u128(2)),
                    direction: ReshardingDirection::Up,
                    peer_id: None,
                    shard_key: None,
                },
            },
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        let err = validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect_err(
            "encrypted all-peer resharding must fail closed when any peer is missing metadata",
        );
        assert!(matches!(err, StorageError::BadRequest { .. }));
        assert!(err.to_string().contains("peer 3 has not published"));

        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[1, 2, 3],
            &metadata,
        )
        .expect("matching all-peer crypto runtime parity should allow encrypted resharding");
    }

    #[test]
    fn encrypted_cluster_resharding_lifecycle_requires_all_peer_crypto_runtime_parity() {
        let operations = [
            ClusterOperations::FinishMigratingPoints(
                collection::operations::cluster_ops::FinishMigratingPointsOperation {
                    finish_migrating_points:
                        collection::operations::cluster_ops::FinishMigratingPoints {
                            shard_id: Some(1),
                            peer_id: Some(2),
                        },
                },
            ),
            ClusterOperations::CommitReadHashRing(
                collection::operations::cluster_ops::CommitReadHashRingOperation {
                    commit_read_hash_ring:
                        collection::operations::cluster_ops::CommitReadHashRing {},
                },
            ),
            ClusterOperations::CommitWriteHashRing(
                collection::operations::cluster_ops::CommitWriteHashRingOperation {
                    commit_write_hash_ring:
                        collection::operations::cluster_ops::CommitWriteHashRing {},
                },
            ),
            ClusterOperations::FinishResharding(
                collection::operations::cluster_ops::FinishReshardingOperation {
                    finish_resharding: collection::operations::cluster_ops::FinishResharding {},
                },
            ),
        ];

        let mut metadata = HashMap::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "local-fingerprint".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "different-fingerprint".to_string(),
            )),
        );

        for operation in operations {
            let err = validate_encrypted_cluster_data_movement_parity(
                "docs",
                true,
                &operation,
                1,
                &[1, 2, 3],
                &metadata,
            )
            .expect_err("encrypted resharding lifecycle must fail closed on any peer mismatch");
            assert!(
                err.to_string().contains("crypto runtime parity"),
                "unexpected error for {operation:?}: {err}",
            );
        }
    }

    #[test]
    fn encrypted_cluster_non_data_movement_is_not_blocked_by_crypto_guard() {
        let operation = ClusterOperations::AbortTransfer(AbortTransferOperation {
            abort_transfer: collection::operations::cluster_ops::AbortShardTransfer {
                shard_id: 1,
                from_peer_id: 1,
                to_peer_id: 2,
                to_shard_id: None,
            },
        });

        validate_encrypted_cluster_data_movement_parity(
            "docs",
            true,
            &operation,
            1,
            &[],
            &HashMap::new(),
        )
        .expect("abort must remain available for cleanup");
    }
}
