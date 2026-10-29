use std::future::Future;
use std::sync::Arc;

use collection::collection_state::State;
use collection::config::{CollectionConfigInternal, ShardingMethod};
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::PeerId;
use storage::content_manager::collection_meta_ops::{
    CollectionMetaOperations, CreateCollection, CreateCollectionOperation, CreateShardKey,
    SetShardReplicaState,
};
use storage::content_manager::consensus_manager::ConsensusStateRef;
use storage::content_manager::errors::StorageError;
use storage::content_manager::shard_distribution::ShardDistributionProposal;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, AccessRequirements, Auth};

async fn submit_migration_meta_ops<F, Fut>(
    operations: impl IntoIterator<Item = CollectionMetaOperations>,
    mut submit: F,
) -> Result<(), StorageError>
where
    F: FnMut(CollectionMetaOperations) -> Fut,
    Fut: Future<Output = Result<bool, StorageError>>,
{
    for operation in operations {
        let announces_existing_collection =
            matches!(&operation, CollectionMetaOperations::CreateCollection(_));
        match submit(operation).await {
            Ok(_) => {}
            // These collections are already loaded locally. Their creation still needs to
            // be committed for other peers, but its local application reports AlreadyExists.
            // Only acknowledge that specific receipt; all other migration failures are fatal.
            Err(StorageError::AlreadyExists { .. }) if announces_existing_collection => {}
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

/// Processes the existing collections, which were created outside the consensus:
/// - during the migration from single to cluster
/// - during restoring from a backup
pub async fn handle_existing_collections(
    toc_arc: Arc<TableOfContent>,
    consensus_state: ConsensusStateRef,
    dispatcher_arc: Arc<Dispatcher>,
    this_peer_id: PeerId,
    collections: Vec<String>,
) -> Result<(), StorageError> {
    let full_access = Access::full("Migration from single to cluster");
    let full_auth = Auth::new_internal(full_access.clone());
    let multipass =
        full_auth.check_global_access(AccessRequirements::new().manage(), "migration")?;

    consensus_state.is_leader_established.await_ready();
    for collection_name in collections {
        let collection_obj = toc_arc
            .get_collection(&multipass.issue_pass(&collection_name))
            .await?;

        let State {
            config,
            shards,
            resharding: _, // resharding can't exist outside of consensus
            transfers: _,  // transfers can't exist outside of consensus
            shards_key_mapping,
            payload_index_schema: _, // payload index schema doesn't require special handling in this case
        } = collection_obj.state().await;

        let CollectionConfigInternal {
            params,
            hnsw_config,
            optimizer_config,
            wal_config,
            quantization_config,
            strict_mode_config,
            uuid,
            metadata,
        } = config;

        let shards_number = params.shard_number.get();
        let sharding_method = params.sharding_method;
        let encrypted_collection = params.effective_encryption().is_some();

        let mut collection_create_operation = CreateCollectionOperation::new(
            collection_name.clone(),
            CreateCollection {
                vectors: params.vectors,
                sparse_vectors: params.sparse_vectors,
                shard_number: Some(shards_number),
                sharding_method,
                replication_factor: Some(params.replication_factor.get()),
                write_consistency_factor: Some(params.write_consistency_factor.get()),
                on_disk_payload: Some(params.on_disk_payload),
                hnsw_config: Some(hnsw_config.into()),
                wal_config: Some(wal_config.into()),
                optimizers_config: Some(optimizer_config.into()),
                quantization_config,
                encryption: params.encryption,
                strict_mode_config,
                uuid,
                metadata,
            },
        )?;
        if encrypted_collection {
            collection_create_operation.preserve_explicit_uuid_for_internal_migration();
        }

        let mut consensus_operations = Vec::new();

        match sharding_method.unwrap_or_default() {
            ShardingMethod::Auto => {
                collection_create_operation.set_distribution(ShardDistributionProposal {
                    distribution: shards
                        .iter()
                        .filter_map(|(shard_id, shard_info)| {
                            if shard_info.replicas.contains_key(&this_peer_id) {
                                Some((*shard_id, vec![this_peer_id]))
                            } else {
                                None
                            }
                        })
                        .collect(),
                });

                consensus_operations.push(CollectionMetaOperations::CreateCollection(
                    collection_create_operation,
                ));
            }
            ShardingMethod::Custom => {
                // We should create additional consensus operations here to set the shard distribution
                collection_create_operation.set_distribution(ShardDistributionProposal::empty());
                consensus_operations.push(CollectionMetaOperations::CreateCollection(
                    collection_create_operation,
                ));

                for (shard_key, shard_ids) in shards_key_mapping.iter() {
                    let mut placement = Vec::new();

                    for shard_id in shard_ids {
                        let shard_info = shards.get(shard_id).ok_or_else(|| {
                            StorageError::service_error(format!(
                                "collection {collection_name} shard key {shard_key} references missing shard {shard_id}",
                            ))
                        })?;
                        placement.push(shard_info.replicas.keys().copied().collect());
                    }

                    consensus_operations.push(CollectionMetaOperations::CreateShardKey(
                        CreateShardKey {
                            collection_name: collection_name.clone(),
                            shard_key: shard_key.clone(),
                            placement,
                            initial_state: None, // Initial state can't be set during migration
                        },
                    ))
                }
            }
        }

        submit_migration_meta_ops(consensus_operations, |operation| {
            dispatcher_arc.submit_collection_meta_op(operation, full_auth.clone(), None)
        })
        .await?;

        let mut replica_state_operations = Vec::new();

        for (shard_id, shard_info) in shards {
            if shard_info.replicas.contains_key(&this_peer_id) {
                replica_state_operations.push(CollectionMetaOperations::SetShardReplicaState(
                    SetShardReplicaState {
                        collection_name: collection_name.clone(),
                        shard_id,
                        peer_id: this_peer_id,
                        state: ReplicaState::Active,
                        from_state: None,
                    },
                ));
            }
        }

        submit_migration_meta_ops(replica_state_operations, |operation| {
            dispatcher_arc.submit_collection_meta_op(operation, full_auth.clone(), None)
        })
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use collection::operations::types::VectorsConfig;

    use super::*;

    const THIS_PEER_ID: PeerId = 7;

    fn create_collection_operation() -> CollectionMetaOperations {
        CollectionMetaOperations::CreateCollection(
            CreateCollectionOperation::new(
                "docs".to_string(),
                CreateCollection {
                    vectors: VectorsConfig::default(),
                    sparse_vectors: None,
                    shard_number: None,
                    sharding_method: Some(ShardingMethod::Custom),
                    replication_factor: None,
                    write_consistency_factor: None,
                    on_disk_payload: None,
                    hnsw_config: None,
                    wal_config: None,
                    optimizers_config: None,
                    quantization_config: None,
                    encryption: None,
                    strict_mode_config: None,
                    uuid: None,
                    metadata: None,
                },
            )
            .unwrap(),
        )
    }

    fn create_shard_key_operation() -> CollectionMetaOperations {
        CollectionMetaOperations::CreateShardKey(CreateShardKey {
            collection_name: "docs".to_string(),
            shard_key: "tenant-a".into(),
            placement: vec![vec![THIS_PEER_ID]],
            initial_state: None,
        })
    }

    fn replica_state_operation() -> CollectionMetaOperations {
        CollectionMetaOperations::SetShardReplicaState(SetShardReplicaState {
            collection_name: "docs".to_string(),
            shard_id: 0,
            peer_id: THIS_PEER_ID,
            state: ReplicaState::Active,
            from_state: None,
        })
    }

    fn operation_label(operation: &CollectionMetaOperations) -> &'static str {
        match operation {
            CollectionMetaOperations::CreateCollection(_) => "create_collection",
            CollectionMetaOperations::CreateShardKey(_) => "create_shard_key",
            CollectionMetaOperations::SetShardReplicaState(_) => "set_shard_replica_state",
            _ => "other",
        }
    }

    #[tokio::test]
    async fn migration_submission_accepts_existing_collection_announcement() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let operations = vec![
            create_collection_operation(),
            create_shard_key_operation(),
            replica_state_operation(),
        ];

        let result = submit_migration_meta_ops(operations, |operation| {
            let submitted = Arc::clone(&submitted);
            async move {
                let label = operation_label(&operation);
                submitted.lock().unwrap().push(label);

                if label == "create_collection" {
                    Err(StorageError::already_exists(
                        "Collection `docs` already exists!",
                    ))
                } else {
                    Ok(true)
                }
            }
        })
        .await;

        result.unwrap();
        assert_eq!(
            submitted.lock().unwrap().as_slice(),
            [
                "create_collection",
                "create_shard_key",
                "set_shard_replica_state"
            ],
        );
    }

    #[tokio::test]
    async fn migration_submission_does_not_ignore_existing_shard_key() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let operations = vec![
            create_collection_operation(),
            create_shard_key_operation(),
            replica_state_operation(),
        ];

        let result = submit_migration_meta_ops(operations, |operation| {
            let submitted = Arc::clone(&submitted);
            async move {
                let label = operation_label(&operation);
                submitted.lock().unwrap().push(label);

                if label == "create_shard_key" {
                    Err(StorageError::already_exists("injected shard key conflict"))
                } else {
                    Ok(true)
                }
            }
        })
        .await;

        assert!(matches!(
            result.unwrap_err(),
            StorageError::AlreadyExists { description }
                if description == "injected shard key conflict"
        ));
        assert_eq!(
            submitted.lock().unwrap().as_slice(),
            ["create_collection", "create_shard_key"],
        );
    }

    #[tokio::test]
    async fn migration_submission_stops_after_create_collection_failure() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let operations = vec![
            create_collection_operation(),
            create_shard_key_operation(),
            replica_state_operation(),
        ];

        let result = submit_migration_meta_ops(operations, |operation| {
            let submitted = Arc::clone(&submitted);
            async move {
                let label = operation_label(&operation);
                submitted.lock().unwrap().push(label);

                if label == "create_collection" {
                    Err(StorageError::bad_input(
                        "injected create collection failure",
                    ))
                } else {
                    Ok(true)
                }
            }
        })
        .await;

        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("injected create collection failure"),
            "{err}",
        );
        assert_eq!(submitted.lock().unwrap().as_slice(), ["create_collection"]);
    }

    #[tokio::test]
    async fn migration_submission_stops_before_replica_state_after_shard_key_failure() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let operations = vec![
            create_collection_operation(),
            create_shard_key_operation(),
            replica_state_operation(),
        ];

        let result = submit_migration_meta_ops(operations, |operation| {
            let submitted = Arc::clone(&submitted);
            async move {
                let label = operation_label(&operation);
                submitted.lock().unwrap().push(label);

                if label == "create_shard_key" {
                    Err(StorageError::bad_input("injected create shard key failure"))
                } else {
                    Ok(true)
                }
            }
        })
        .await;

        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("injected create shard key failure"),
            "{err}",
        );
        assert_eq!(
            submitted.lock().unwrap().as_slice(),
            ["create_collection", "create_shard_key"],
        );
    }
}
