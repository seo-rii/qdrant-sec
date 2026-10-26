use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use collection::collection_state;
use collection::config::{
    CollectionParams, PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING, ShardingMethod,
};
use collection::events::{CollectionDeletedEvent, IndexCreatedEvent};
use collection::operations::types::PeerMetadata;
use collection::shards::collection_shard_distribution::CollectionShardDistribution;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::PeerId;
use collection::shards::transfer::{ShardTransfer, ShardTransferMethod, ShardTransferRestart};
use collection::shards::{CollectionId, replica_set, transfer};
use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::fs::safe_delete_in_tmp;

use super::{COLLECTION_DELETE_SPIN_INTERVAL, COLLECTION_DELETE_WAIT_TIMEOUT, TableOfContent};
use crate::common::utils::try_unwrap_with_timeout_async;
use crate::content_manager::collection_meta_ops::*;
use crate::content_manager::collections_ops::Checker as _;
use crate::content_manager::consensus_ops::{
    ConsensusOperations, PrivateOramCollectionLayoutTransition, PrivateOramMutationKey,
    PrivateOramReshardingOperation,
};
use crate::content_manager::errors::StorageError;
use crate::content_manager::shard_distribution::ShardDistributionProposal;

static CREATE_CUSTOM_SHARDS_IN_INITIALIZING_STATE: LazyLock<semver::Version> =
    LazyLock::new(|| semver::Version::parse("1.14.2-dev").unwrap());

#[derive(Copy, Clone, Eq, PartialEq)]
enum ReshardingApplyAuthority {
    Ordinary,
    PrivateOramConsensus,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ShardKeyApplyAuthority {
    Ordinary,
    PrivateOramConsensus,
}

fn private_oram_pending_acknowledgement_matches_collection(
    collection_id: &str,
    pending_acknowledgements: &[(PrivateOramMutationKey, PeerId, u64)],
) -> bool {
    pending_acknowledgements
        .iter()
        .any(|(key, _, _)| key.collection_id == collection_id)
}

fn private_oram_archive_ack_fenced_collection_name(
    operation: &CollectionMetaOperations,
) -> Option<&str> {
    match operation {
        CollectionMetaOperations::DeleteCollection(operation) => Some(&operation.0),
        CollectionMetaOperations::CreatePayloadIndex(operation) => Some(&operation.collection_name),
        CollectionMetaOperations::DropPayloadIndex(operation) => Some(&operation.collection_name),
        _ => None,
    }
}

impl TableOfContent {
    pub(super) fn perform_collection_meta_op_sync(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError> {
        self.general_runtime
            .block_on(self.perform_collection_meta_op(operation))
    }

    /// ## Cancel safety
    ///
    /// This function is **not** cancel safe.
    pub async fn perform_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError> {
        self.require_private_oram_external_recovery_meta_allowed(&operation)
            .await?;
        if let Some(collection_name) = private_oram_archive_ack_fenced_collection_name(&operation) {
            match self.get_collection_unfenced(collection_name).await {
                Ok((_, collection)) => {
                    let collection_config = collection.config_snapshot().await;
                    self.require_private_oram_archive_acknowledgement_before_config_change(
                        collection_name,
                        &collection_config,
                    )?;
                }
                Err(StorageError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        match operation {
            CollectionMetaOperations::CreateCollection(mut operation) => {
                log::info!("Creating collection {}", operation.collection_name);
                let distribution = match operation.take_distribution() {
                    None => match operation
                        .create_collection
                        .sharding_method
                        .unwrap_or_default()
                    {
                        ShardingMethod::Auto => {
                            let collection_defaults = self.storage_config.collection.as_ref();

                            let number_of_peers = 1; // this is a single node deployment
                            let suggested_shard_number = collection_defaults
                                .map(|config| config.get_shard_number(number_of_peers));

                            let shard_number = operation
                                .create_collection
                                .shard_number
                                .or(suggested_shard_number);
                            CollectionShardDistribution::all_local(shard_number, self.this_peer_id)
                        }
                        ShardingMethod::Custom => ShardDistributionProposal::empty().into(),
                    },
                    Some(distribution) => distribution.into(),
                };
                self.create_collection(
                    &operation.collection_name,
                    operation.create_collection,
                    distribution,
                )
                .await
            }
            CollectionMetaOperations::UpdateCollection(operation) => {
                log::info!("Updating collection {}", operation.collection_name);
                self.update_collection(operation).await
            }
            CollectionMetaOperations::ApplyCryptoMigration(operation) => {
                log::info!(
                    "Applying crypto migration plan to collection {}",
                    operation.collection_name
                );
                self.apply_crypto_migration_plan(operation).await
            }
            CollectionMetaOperations::DeleteCollection(operation) => {
                log::info!("Deleting collection {}", operation.0);
                self.delete_collection(&operation.0).await
            }
            CollectionMetaOperations::ChangeAliases(operation) => {
                log::debug!("Changing aliases");
                self.update_aliases(operation).await
            }
            CollectionMetaOperations::Resharding(collection, operation) => {
                let operation_kind = match &operation {
                    ReshardingOperation::Start(_) => "start",
                    ReshardingOperation::CommitRead(_) => "commit_read",
                    ReshardingOperation::CommitWrite(_) => "commit_write",
                    ReshardingOperation::Finish(_) => "finish",
                    ReshardingOperation::Abort(_) => "abort",
                };
                log::debug!("Resharding {operation_kind} of {collection}");

                self.handle_resharding(collection, operation, ReshardingApplyAuthority::Ordinary)
                    .await
                    .map(|_| true)
            }
            CollectionMetaOperations::TransferShard(collection, operation) => {
                log::debug!(
                    "Transfer shard {:?} of {collection}",
                    operation.redacted_log()
                );

                self.handle_transfer(collection, operation)
                    .await
                    .map(|()| true)
            }
            CollectionMetaOperations::SetShardReplicaState(operation) => {
                log::debug!(
                    "Set shard replica state for collection {}, shard {}, peer {}, state {:?}, from_state {:?}",
                    operation.collection_name,
                    operation.shard_id,
                    operation.peer_id,
                    operation.state,
                    operation.from_state,
                );
                self.set_shard_replica_state(operation).await.map(|()| true)
            }
            CollectionMetaOperations::Nop { .. } => Ok(true),
            CollectionMetaOperations::CreateShardKey(create_shard_key) => {
                log::debug!(
                    "Create shard key for collection {}, placement {:?}, initial_state {:?}, shard_key_present true",
                    create_shard_key.collection_name,
                    create_shard_key.placement,
                    create_shard_key.initial_state,
                );
                self.create_shard_key(create_shard_key, ShardKeyApplyAuthority::Ordinary)
                    .await
                    .map(|()| true)
            }
            CollectionMetaOperations::DropShardKey(drop_shard_key) => {
                log::debug!(
                    "Drop shard key for collection {}, shard_key_present true",
                    drop_shard_key.collection_name,
                );
                self.drop_shard_key(drop_shard_key, ShardKeyApplyAuthority::Ordinary)
                    .await
                    .map(|()| true)
            }
            CollectionMetaOperations::CreatePayloadIndex(create_payload_index) => {
                log::debug!(
                    "Create payload index for collection {}, field_name_present true, field_schema {:?}",
                    create_payload_index.collection_name,
                    create_payload_index.field_schema,
                );
                self.create_payload_index(create_payload_index)
                    .await
                    .map(|()| true)
            }
            CollectionMetaOperations::DropPayloadIndex(drop_payload_index) => {
                log::debug!(
                    "Drop payload index for collection {}, field_name_present true",
                    drop_payload_index.collection_name,
                );
                self.drop_payload_index(drop_payload_index)
                    .await
                    .map(|()| true)
            }
            #[cfg(feature = "staging")]
            CollectionMetaOperations::TestSlowDown(test_slow_down) => {
                test_slow_down.execute(self.this_peer_id).await;
                Ok(true)
            }
        }
    }

    pub(crate) async fn require_private_oram_external_recovery_meta_allowed(
        &self,
        operation: &CollectionMetaOperations,
    ) -> Result<(), StorageError> {
        let collection_names = match operation {
            CollectionMetaOperations::CreateCollection(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::UpdateCollection(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::ApplyCryptoMigration(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::DeleteCollection(operation) => vec![operation.0.clone()],
            CollectionMetaOperations::ChangeAliases(operation) => {
                let aliases = self.alias_persistence.read().await;
                operation
                    .actions
                    .iter()
                    .filter_map(|action| match action {
                        AliasOperations::CreateAlias(operation) => {
                            Some(operation.create_alias.collection_name.clone())
                        }
                        AliasOperations::DeleteAlias(operation) => {
                            aliases.get(&operation.delete_alias.alias_name)
                        }
                        AliasOperations::RenameAlias(operation) => {
                            aliases.get(&operation.rename_alias.old_alias_name)
                        }
                    })
                    .collect()
            }
            CollectionMetaOperations::Resharding(collection_name, _)
            | CollectionMetaOperations::TransferShard(collection_name, _) => {
                vec![collection_name.clone()]
            }
            CollectionMetaOperations::SetShardReplicaState(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::CreateShardKey(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::DropShardKey(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::CreatePayloadIndex(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::DropPayloadIndex(operation) => {
                vec![operation.collection_name.clone()]
            }
            CollectionMetaOperations::Nop { .. } => Vec::new(),
            #[cfg(feature = "staging")]
            CollectionMetaOperations::TestSlowDown(_) => Vec::new(),
        };

        for collection_name in collection_names {
            match self.get_collection_unfenced(&collection_name).await {
                Ok((_, collection)) => {
                    self.require_private_oram_external_recovery_write_allowed(&collection)
                        .await?;
                }
                Err(StorageError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn update_collection(
        &self,
        mut operation: UpdateCollectionOperation,
    ) -> Result<bool, StorageError> {
        let private_oram_replica_removal_reserved =
            operation.private_oram_replica_removal_reserved();
        let replica_changes = operation.take_shard_replica_changes();
        let UpdateCollection {
            vectors,
            hnsw_config,
            params,
            optimizers_config,
            quantization_config,
            sparse_vectors,
            strict_mode_config: strict_mode,
            metadata,
        } = operation.update_collection;
        let collection = self
            .get_collection_unchecked(&operation.collection_name)
            .await?;
        let collection_config = collection.config_snapshot().await;
        let changes_collection_config = vectors.is_some()
            || hnsw_config.is_some()
            || params.is_some()
            || optimizers_config.is_some()
            || quantization_config.is_some()
            || sparse_vectors.is_some()
            || strict_mode.is_some()
            || metadata.is_some();
        if changes_collection_config {
            self.require_private_oram_archive_acknowledgement_before_config_change(
                &operation.collection_name,
                &collection_config,
            )?;
        }
        validate_private_oram_replica_removal_authorization(
            &operation.collection_name,
            &collection_config.params,
            replica_changes.as_deref(),
            private_oram_replica_removal_reserved,
        )?;
        let mut recreate_optimizers = false;

        if let Some(diff) = optimizers_config {
            collection.update_optimizer_params_from_diff(diff).await?;
            recreate_optimizers = true;
        }
        if let Some(diff) = params {
            collection.update_params_from_diff(diff).await?;
            recreate_optimizers = true;
        }
        if let Some(diff) = hnsw_config {
            collection.update_hnsw_config_from_diff(diff).await?;
            recreate_optimizers = true;
        }
        if let Some(diff) = vectors {
            collection.update_vectors_from_diff(&diff).await?;
            recreate_optimizers = true;
        }
        if let Some(diff) = quantization_config {
            collection
                .update_quantization_config_from_diff(diff)
                .await?;
            recreate_optimizers = true;
        }
        if let Some(diff) = sparse_vectors {
            collection.update_sparse_vectors_from_other(&diff).await?;
            recreate_optimizers = true;
        }
        if let Some(changes) = replica_changes {
            collection
                .handle_replica_changes(changes, private_oram_replica_removal_reserved)
                .await?;
        }
        if let Some(strict_mode) = strict_mode {
            collection.update_strict_mode_config(strict_mode).await?;
        }

        if let Some(metadata) = metadata {
            collection.update_metadata(metadata).await?;
        }

        collection.print_warnings().await;

        // Recreate optimizers
        if recreate_optimizers {
            collection.recreate_optimizers_blocking().await?;
        }
        Ok(true)
    }

    async fn apply_crypto_migration_plan(
        &self,
        operation: ApplyCryptoMigrationPlan,
    ) -> Result<bool, StorageError> {
        let collection = self
            .get_collection_unchecked(&operation.collection_name)
            .await?;
        let collection_config = collection.config_snapshot().await;
        self.require_private_oram_archive_acknowledgement_before_config_change(
            &operation.collection_name,
            &collection_config,
        )?;

        collection
            .apply_crypto_migration_plan(&operation.plan)
            .await?;

        Ok(true)
    }

    fn require_private_oram_archive_acknowledgement_before_config_change(
        &self,
        collection_name: &str,
        collection_config: &collection::config::CollectionConfigInternal,
    ) -> Result<(), StorageError> {
        let Some(dispatcher) = self.toc_dispatcher.lock().clone() else {
            return Ok(());
        };
        let collection_id = collection_config.stable_crypto_id(collection_name)?;
        let pending_acknowledgements = dispatcher
            .consensus_state()
            .private_oram_mutation_pending_acknowledgement_keys()?;
        if private_oram_pending_acknowledgement_matches_collection(
            &collection_id,
            &pending_acknowledgements,
        ) {
            return Err(StorageError::Locked {
                description: "collection configuration is locked until the private ORAM local archive acknowledgement is replicated"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub(super) async fn delete_collection(
        &self,
        collection_name: &str,
    ) -> Result<bool, StorageError> {
        let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        if self.private_oram_external_recovery_collection_is_detached(collection_name) {
            return Err(StorageError::Locked {
                description: "collection is locked by private ORAM external recovery installation"
                    .to_string(),
            });
        }
        self.delete_collection_locked(collection_name).await
    }

    pub(super) async fn delete_collection_locked(
        &self,
        collection_name: &str,
    ) -> Result<bool, StorageError> {
        self.alias_persistence
            .write()
            .await
            .remove_collection(collection_name)?;

        let to_delete;
        let result;
        let collection_path = self.get_collection_path(collection_name);
        let safe_delete_path = self.storage_config.storage_path.join(".deleted");

        let removed_opt = self.collections.write().await.remove(collection_name);
        if let Some(removed) = removed_opt {
            if let Some(state) = removed.resharding_state().await
                && let Err(err) = removed.abort_resharding(state.key(), true).await
            {
                log::error!(
                    "Failed to abort resharding {} when deleting collection {collection_name}: \
                         {err}",
                    state.key(),
                );
            }

            removed.stop_gracefully().await;

            // If we try to wait for the collection to be freed, and fail if it is still busy after timeout
            // it can risk stopping the consensus progress.
            //
            // Instead, we proceed with removal regardless, as it should be safe to remove files
            // at least on Linux.
            let removed_collection_res = try_unwrap_with_timeout_async(
                removed,
                COLLECTION_DELETE_SPIN_INTERVAL,
                COLLECTION_DELETE_WAIT_TIMEOUT,
            )
            .await;

            match removed_collection_res {
                Ok(collection) => drop(collection),
                Err(busy_collection) => {
                    debug_assert!(false, "Collection `{collection_name}` is busy");
                    log::error!(
                        "Collection `{collection_name}` is busy and cannot be removed in time."
                    );
                    drop(busy_collection);
                }
            };

            to_delete = Some(safe_delete_in_tmp(&collection_path, &safe_delete_path)?);

            // Solve all issues related to this collection
            issues::publish(CollectionDeletedEvent {
                collection_id: collection_name.to_string(),
            });

            result = true;
        } else {
            // we hold the collection_create lock to make sure no one is creating this collection
            // otherwise we would delete its content now
            if collection_path.exists() {
                log::warn!(
                    "Collection {collection_name} is not loaded, but its directory still exists. Deleting it."
                );
                to_delete = Some(safe_delete_in_tmp(&collection_path, &safe_delete_path)?);
            } else {
                to_delete = None;
            }

            result = false;
        }

        if let Some(to_delete) = to_delete {
            tokio::task::spawn_blocking(move || {
                if let Err(error) = to_delete.close() {
                    log::error!("Can't delete collection from disk: {error}");
                }
            });
        }

        Ok(result)
    }

    /// performs several alias changes in an atomic fashion
    async fn update_aliases(
        &self,
        operation: ChangeAliasesOperation,
    ) -> Result<bool, StorageError> {
        let _collection_lifecycle_guard = self.collection_lifecycle_lock.lock().await;
        if !self.private_oram_external_recovery_detached.is_empty() {
            return Err(StorageError::Locked {
                description:
                    "collection aliases are locked by private ORAM external recovery installation"
                        .to_string(),
            });
        }
        // Lock all collections for alias changes
        // Prevent search on partially switched collections
        let collection_lock = self.collections.write().await;
        let mut alias_lock = self.alias_persistence.write().await;
        for action in operation.actions {
            match action {
                AliasOperations::CreateAlias(CreateAliasOperation {
                    create_alias:
                        CreateAlias {
                            collection_name,
                            alias_name,
                        },
                }) => {
                    collection_lock.validate_collection_exists(&collection_name)?;
                    collection_lock.validate_collection_not_exists(&alias_name)?;

                    alias_lock.insert(alias_name, collection_name)?;
                }
                AliasOperations::DeleteAlias(DeleteAliasOperation {
                    delete_alias: DeleteAlias { alias_name },
                }) => {
                    alias_lock.remove(&alias_name)?;
                }
                AliasOperations::RenameAlias(RenameAliasOperation {
                    rename_alias:
                        RenameAlias {
                            old_alias_name,
                            new_alias_name,
                        },
                }) => {
                    alias_lock.rename_alias(&old_alias_name, new_alias_name)?;
                }
            };
        }
        Ok(true)
    }

    /// # Cancel safety
    ///
    /// This method is *not* cancel safe.
    pub(super) async fn perform_private_oram_resharding_meta_op(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        let CollectionMetaOperations::Resharding(collection_id, resharding_operation) =
            operation.collection_meta.as_ref()
        else {
            return Err(invalid_private_oram_resharding_consensus_operation());
        };
        let resharding_key = match resharding_operation {
            ReshardingOperation::Start(key) | ReshardingOperation::Finish(key) => key,
            _ => return Err(invalid_private_oram_resharding_consensus_operation()),
        };
        if resharding_key != &operation.transition.resharding_key {
            return Err(invalid_private_oram_resharding_consensus_operation());
        }
        self.handle_resharding(
            collection_id.clone(),
            resharding_operation.clone(),
            ReshardingApplyAuthority::PrivateOramConsensus,
        )
        .await?;
        Ok(true)
    }

    /// # Cancel safety
    ///
    /// This method is *not* cancel safe.
    pub(super) async fn perform_private_oram_collection_layout_meta_op(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<bool, StorageError> {
        let operation = (*transition.collection_meta).clone();
        match operation {
            CollectionMetaOperations::CreateShardKey(operation) => self
                .create_shard_key(operation, ShardKeyApplyAuthority::PrivateOramConsensus)
                .await
                .map(|()| true),
            CollectionMetaOperations::DropShardKey(operation) => self
                .drop_shard_key(operation, ShardKeyApplyAuthority::PrivateOramConsensus)
                .await
                .map(|()| true),
            operation => self.perform_collection_meta_op(operation).await,
        }
    }

    async fn handle_resharding(
        &self,
        collection_id: CollectionId,
        operation: ReshardingOperation,
        authority: ReshardingApplyAuthority,
    ) -> Result<(), StorageError> {
        let collection = self.get_collection_unchecked(&collection_id).await?;
        let Some(proposal_sender) = self.consensus_proposal_sender.clone() else {
            return Err(StorageError::service_error(
                "Can't handle resharding, this is a single node deployment",
            ));
        };
        let collection_config = collection.config_snapshot().await;
        validate_private_oram_resharding_apply_authority(
            &collection_id,
            &collection_config.params,
            &operation,
            authority,
        )?;

        match operation {
            ReshardingOperation::Start(key) => {
                if collection_params_require_crypto_runtime_transfer_parity(
                    &collection_config.params,
                ) {
                    let peer_metadata_by_id = self.channel_service.id_to_metadata.read();
                    let mut peer_ids = self
                        .channel_service
                        .id_to_address
                        .read()
                        .keys()
                        .copied()
                        .collect::<Vec<_>>();
                    peer_ids.extend(peer_metadata_by_id.keys().copied());
                    peer_ids.push(self.this_peer_id);
                    peer_ids.push(key.peer_id);
                    validate_encrypted_resharding_crypto_runtime_parity(
                        &collection_id,
                        self.this_peer_id,
                        peer_ids,
                        &peer_metadata_by_id,
                    )?;
                }

                let consensus = match self.toc_dispatcher.lock().as_ref() {
                    Some(consensus) => Box::new(consensus.clone()),
                    None => {
                        return Err(StorageError::service_error(
                            "Can't handle transfer, this is a single node deployment",
                        ));
                    }
                };

                if authority == ReshardingApplyAuthority::PrivateOramConsensus {
                    collection
                        .start_private_oram_resharding(key, consensus)
                        .await?;
                } else {
                    let on_finish = {
                        let collection_id = collection_id.clone();
                        let key = key.clone();
                        let proposal_sender = proposal_sender.clone();
                        async move {
                            let operation =
                                ConsensusOperations::finish_resharding(collection_id, key);
                            if let Err(error) = proposal_sender.send(operation) {
                                log::error!(
                                    "Can't report resharding progress to consensus: {error}"
                                );
                            };
                        }
                    };

                    let on_failure = {
                        let collection_id = collection_id.clone();
                        let key = key.clone();
                        async move {
                            if let Err(error) = proposal_sender
                                .send(ConsensusOperations::abort_resharding(collection_id, key))
                            {
                                log::error!(
                                    "Can't report resharding progress to consensus: {error}"
                                );
                            };
                        }
                    };

                    collection
                        .start_resharding(key, consensus, on_finish, on_failure)
                        .await?;
                }
            }

            ReshardingOperation::CommitRead(key) => {
                collection.commit_read_hashring(&key).await?;
            }

            ReshardingOperation::CommitWrite(key) => {
                collection.commit_write_hashring(&key).await?;
            }

            ReshardingOperation::Finish(key) => {
                if authority == ReshardingApplyAuthority::PrivateOramConsensus {
                    collection.finish_private_oram_resharding(key).await?;
                } else {
                    collection.finish_resharding(key).await?;
                }
            }

            ReshardingOperation::Abort(key) => {
                collection.abort_resharding(key, false).await?;
            }
        }

        Ok(())
    }

    async fn handle_transfer(
        &self,
        collection_id: CollectionId,
        transfer_operation: ShardTransferOperations,
    ) -> Result<(), StorageError> {
        let collection = self.get_collection_unchecked(&collection_id).await?;
        let collection_config = collection.config_snapshot().await;
        let resharding = collection.resharding_state().await;
        reject_private_oram_shard_transfer_until_supported(
            &collection_id,
            &collection_config.params,
            &transfer_operation,
            resharding.as_ref(),
        )?;
        let Some(proposal_sender) = self.consensus_proposal_sender.clone() else {
            return Err(StorageError::service_error(
                "Can't handle transfer, this is a single node deployment",
            ));
        };

        match transfer_operation {
            ShardTransferOperations::Start(transfer) => {
                if collection_params_require_crypto_runtime_transfer_parity(
                    &collection_config.params,
                ) {
                    validate_encrypted_transfer_crypto_runtime_parity(
                        &collection_id,
                        self.this_peer_id,
                        transfer.from,
                        transfer.to,
                        &self.channel_service.id_to_metadata.read(),
                    )?;
                }
                let collection_state::State {
                    shards,
                    transfers,
                    shards_key_mapping,
                    ..
                } = collection.state().await;
                let all_peers: HashSet<_> = self
                    .channel_service
                    .id_to_address
                    .read()
                    .keys()
                    .cloned()
                    .collect();

                let source_replicas = shards.get(&transfer.shard_id).map(|info| &info.replicas);

                let destination_replicas = transfer
                    .to_shard_id
                    .and_then(|to_shard_id| shards.get(&to_shard_id))
                    .map(|info| &info.replicas);

                // Valid transfer:
                // All peers: 123, 321, 111, 222, 333
                // Peers: shard_id=1 - [{123: Active}]
                // Transfer: {123 -> 321}, shard_id=1

                // Invalid transfer:
                // All peers: 123, 321, 111, 222, 333
                // Peers: shard_id=1 - [{123: Active}]
                // Transfer: {321 -> 123}, shard_id=1

                transfer::helpers::validate_transfer(
                    &transfer,
                    &all_peers,
                    source_replicas,
                    destination_replicas,
                    &transfers,
                    &shards_key_mapping,
                )?;

                let on_finish = {
                    let collection_id = collection_id.clone();
                    let transfer = transfer.clone();
                    let proposal_sender = proposal_sender.clone();
                    async move {
                        let operation =
                            ConsensusOperations::finish_transfer(collection_id, transfer);

                        if let Err(error) = proposal_sender.send(operation) {
                            log::error!("Can't report transfer progress to consensus: {error}");
                        };
                    }
                };

                let on_failure = {
                    let collection_id = collection_id.clone();
                    let transfer = transfer.clone();
                    async move {
                        if let Err(error) =
                            proposal_sender.send(ConsensusOperations::abort_transfer(
                                collection_id,
                                transfer,
                                "transmission failed",
                            ))
                        {
                            log::error!("Can't report transfer progress to consensus: {error}");
                        };
                    }
                };

                let shard_consensus = match self.toc_dispatcher.lock().as_ref() {
                    Some(consensus) => Box::new(consensus.clone()),
                    None => {
                        return Err(StorageError::service_error(
                            "Can't handle transfer, this is a single node deployment",
                        ));
                    }
                };

                let temp_dir = self.optional_temp_or_storage_temp_path()?;
                collection
                    .start_shard_transfer(
                        transfer,
                        shard_consensus,
                        temp_dir,
                        on_finish,
                        on_failure,
                    )
                    .await?;
            }
            ShardTransferOperations::Restart(transfer_restart) => {
                let collection_state = collection.state().await;
                let transfers: HashSet<transfer::ShardTransfer> = collection_state.transfers;
                let resharding = collection_state.resharding;

                let transfer_key = transfer_restart.key();

                let Some(old_transfer) = transfer::helpers::get_transfer(&transfer_key, &transfers)
                else {
                    return Err(StorageError::bad_request(format!(
                        "There is no transfer for shard {} from {} to {}",
                        transfer_key.shard_id, transfer_key.from, transfer_key.to,
                    )));
                };

                validate_private_oram_restart_apply(
                    &collection_config.params,
                    &transfers,
                    resharding.as_ref(),
                    &old_transfer,
                    &transfer_restart,
                )?;

                let private_oram_restart =
                    collection_params_use_private_oram_bucket_store(&collection_config.params);
                let new_transfer = ShardTransfer {
                    shard_id: transfer_restart.shard_id,
                    to_shard_id: transfer_restart.to_shard_id,
                    from: transfer_restart.from,
                    to: transfer_restart.to,
                    sync: old_transfer.sync, // Preserve sync flag from the old transfer
                    method: Some(transfer_restart.method),
                    private_oram_preinstalled: old_transfer.private_oram_preinstalled,
                    private_oram_layout_transition: old_transfer
                        .private_oram_layout_transition
                        .clone(),
                    filter: None,
                };

                if private_oram_restart && !old_transfer.is_resharding() {
                    if collection_params_require_crypto_runtime_transfer_parity(
                        &collection_config.params,
                    ) {
                        validate_encrypted_transfer_crypto_runtime_parity(
                            &collection_id,
                            self.this_peer_id,
                            new_transfer.from,
                            new_transfer.to,
                            &self.channel_service.id_to_metadata.read(),
                        )?;
                    }

                    let on_finish = {
                        let collection_id = collection_id.clone();
                        let transfer = new_transfer.clone();
                        let proposal_sender = proposal_sender.clone();
                        async move {
                            let operation =
                                ConsensusOperations::finish_transfer(collection_id, transfer);

                            if let Err(error) = proposal_sender.send(operation) {
                                log::error!("Can't report transfer progress to consensus: {error}");
                            };
                        }
                    };
                    let on_failure = {
                        let collection_id = collection_id.clone();
                        let transfer = new_transfer.clone();
                        async move {
                            if let Err(error) =
                                proposal_sender.send(ConsensusOperations::abort_transfer(
                                    collection_id,
                                    transfer,
                                    "transmission failed",
                                ))
                            {
                                log::error!("Can't report transfer progress to consensus: {error}");
                            };
                        }
                    };
                    let shard_consensus = match self.toc_dispatcher.lock().as_ref() {
                        Some(consensus) => Box::new(consensus.clone()),
                        None => {
                            return Err(StorageError::service_error(
                                "Can't handle transfer, this is a single node deployment",
                            ));
                        }
                    };
                    let temp_dir = self.optional_temp_or_storage_temp_path()?;
                    collection
                        .restart_private_oram_fixed_shard_transfer_task(
                            new_transfer,
                            shard_consensus,
                            temp_dir,
                            on_finish,
                            on_failure,
                        )
                        .await?;
                } else {
                    if private_oram_restart {
                        collection
                            .abort_shard_transfer_for_restart(old_transfer)
                            .await?;
                    } else {
                        Box::pin(self.handle_transfer(
                            collection_id.clone(),
                            ShardTransferOperations::Abort {
                                transfer: transfer_restart.key(),
                                reason: "restart transfer".into(),
                            },
                        ))
                        .await?;
                    }

                    Box::pin(self.handle_transfer(
                        collection_id,
                        ShardTransferOperations::Start(new_transfer),
                    ))
                    .await?;
                }
            }
            ShardTransferOperations::Finish(transfer) => {
                // Validate transfer exists to prevent double handling
                transfer::helpers::validate_transfer_exists(
                    &transfer.key(),
                    &collection.state().await.transfers,
                )?;

                collection.finish_shard_transfer(transfer, None).await?;
            }
            ShardTransferOperations::RecoveryToPartial(transfer)
            | ShardTransferOperations::SnapshotRecovered(transfer) => {
                // Validate transfer exists to prevent double handling
                transfer::helpers::validate_transfer_exists(
                    &transfer,
                    &collection.state().await.transfers,
                )?;

                let collection = self.get_collection_unchecked(&collection_id).await?;

                let current_state = collection
                    .state()
                    .await
                    .shards
                    .get(&transfer.shard_id)
                    .and_then(|info| info.replicas.get(&transfer.to))
                    .copied();

                let Some(current_state) = current_state else {
                    return Err(StorageError::bad_input(format!(
                        "Replica {} of {collection_id}:{} does not exist",
                        transfer.to, transfer.shard_id,
                    )));
                };

                match current_state {
                    ReplicaState::PartialSnapshot | ReplicaState::Recovery => (),
                    _ => {
                        return Err(StorageError::bad_input(format!(
                            "Replica {} of {collection_id}:{} has unexpected {current_state:?} \
                             (expected {:?} or {:?})",
                            transfer.to,
                            transfer.shard_id,
                            ReplicaState::PartialSnapshot,
                            ReplicaState::Recovery,
                        )));
                    }
                }

                log::debug!(
                    "Set shard replica state from {current_state:?} to {:?}",
                    ReplicaState::Partial,
                );

                collection
                    .set_shard_replica_state(
                        transfer.shard_id,
                        transfer.to,
                        ReplicaState::Partial,
                        Some(current_state),
                    )
                    .await?;
            }
            ShardTransferOperations::Abort { transfer, reason } => {
                // Validate transfer exists to prevent double handling
                transfer::helpers::validate_transfer_exists(
                    &transfer,
                    &collection.state().await.transfers,
                )?;
                log::warn!("Aborting shard transfer: {reason}");
                collection
                    .abort_shard_transfer_and_resharding(transfer, None)
                    .await?;
            }
        };
        Ok(())
    }

    async fn set_shard_replica_state(
        &self,
        operation: SetShardReplicaState,
    ) -> Result<(), StorageError> {
        let collection = self
            .get_collection_unchecked(&operation.collection_name)
            .await?;
        let collection_config = collection.config_snapshot().await;
        reject_private_oram_resharding_replica_state_until_supported(
            &operation.collection_name,
            &collection_config.params,
            &operation,
        )?;
        collection
            .set_shard_replica_state(
                operation.shard_id,
                operation.peer_id,
                operation.state,
                operation.from_state,
            )
            .await?;
        Ok(())
    }

    /// ## Cancel safety
    ///
    /// This function is **not** cancel safe.
    async fn create_shard_key(
        &self,
        operation: CreateShardKey,
        authority: ShardKeyApplyAuthority,
    ) -> Result<(), StorageError> {
        let use_initializing_state = self.is_distributed()
            && self
                .get_channel_service()
                .all_peers_at_version(&CREATE_CUSTOM_SHARDS_IN_INITIALIZING_STATE);

        let init_state = if let Some(initial_state) = operation.initial_state {
            initial_state
        } else if use_initializing_state {
            ReplicaState::Initializing
        } else {
            ReplicaState::Active
        };

        let collection = self
            .get_collection_unchecked(&operation.collection_name)
            .await?;
        let collection_config = collection.config_snapshot().await;
        let private_oram_initial_bootstrap = authority == ShardKeyApplyAuthority::Ordinary
            && collection_params_use_private_oram_bucket_store(&collection_config.params)
            && operation.initial_state == Some(ReplicaState::Active)
            && collection.state().await.shards.is_empty();
        validate_private_oram_shard_key_change_authorization(
            &operation.collection_name,
            &collection_config.params,
            authority,
            private_oram_initial_bootstrap,
        )?;
        if collection_params_require_crypto_runtime_transfer_parity(&collection_config.params) {
            validate_encrypted_create_shard_key_crypto_runtime_parity(
                &operation.collection_name,
                self.this_peer_id,
                &operation.placement,
                &self.channel_service.id_to_metadata.read(),
            )?;
        }

        collection
            .create_shard_key(
                operation.shard_key,
                operation.placement,
                init_state,
                authority == ShardKeyApplyAuthority::PrivateOramConsensus,
            )
            .await?;

        Ok(())
    }

    async fn drop_shard_key(
        &self,
        operation: DropShardKey,
        authority: ShardKeyApplyAuthority,
    ) -> Result<(), StorageError> {
        let collection = self
            .get_collection_unchecked(&operation.collection_name)
            .await?;
        let collection_config = collection.config_snapshot().await;
        validate_private_oram_shard_key_change_authorization(
            &operation.collection_name,
            &collection_config.params,
            authority,
            false,
        )?;
        collection
            .drop_shard_key(
                operation.shard_key,
                authority == ShardKeyApplyAuthority::PrivateOramConsensus,
            )
            .await?;
        Ok(())
    }

    async fn create_payload_index(
        &self,
        operation: CreatePayloadIndex,
    ) -> Result<(), StorageError> {
        // We measure hardware on collection level here to not touch consensus for measurements but still
        // measure hw for payload index creation on all nodes.
        let collection_hw_acc = HwMeasurementAcc::new_with_metrics_drain(
            self.get_collection_hw_metrics(operation.collection_name.clone()),
        );

        self.get_collection_unchecked(&operation.collection_name)
            .await?
            .create_payload_index(
                operation.field_name.clone(),
                operation.field_schema,
                collection_hw_acc,
            )
            .await?;

        // We can solve issues related to this missing index
        issues::publish(IndexCreatedEvent {
            collection_id: operation.collection_name,
            field_name: operation.field_name,
        });

        Ok(())
    }

    async fn drop_payload_index(&self, operation: DropPayloadIndex) -> Result<(), StorageError> {
        self.get_collection_unchecked(&operation.collection_name)
            .await?
            .drop_payload_index(operation.field_name)
            .await?;
        Ok(())
    }
}

fn collection_params_require_crypto_runtime_transfer_parity(params: &CollectionParams) -> bool {
    params.encryption.is_some()
}

fn reject_private_oram_shard_transfer_until_supported(
    _collection_id: &str,
    params: &CollectionParams,
    transfer_operation: &ShardTransferOperations,
    resharding: Option<&collection::shards::resharding::ReshardState>,
) -> Result<(), StorageError> {
    if !collection_params_use_private_oram_bucket_store(params)
        || matches!(transfer_operation, ShardTransferOperations::Abort { .. })
    {
        return Ok(());
    }

    if let ShardTransferOperations::Start(transfer) | ShardTransferOperations::Finish(transfer) =
        transfer_operation
        && transfer.is_private_oram_preinstalled_transfer_for(resharding)
    {
        return Ok(());
    }

    if let ShardTransferOperations::Restart(restart) = transfer_operation {
        let supported_shape = match restart.method {
            ShardTransferMethod::StreamRecords => {
                restart.to_shard_id.is_none() && resharding.is_none()
            }
            ShardTransferMethod::ReshardingStreamRecords => {
                restart.to_shard_id.is_some() && resharding.is_some()
            }
            ShardTransferMethod::Snapshot | ShardTransferMethod::WalDelta => false,
        };
        if supported_shape {
            return Ok(());
        }
    }

    Err(StorageError::bad_input(format!(
        "private ORAM shard transfer requires an unfiltered stream-records transfer with \
         encrypted ORAM stores preinstalled and consensus-backed epoch/root ownership verified; \
         abort the transfer or use the private ORAM transfer coordinator",
    )))
}

fn validate_private_oram_restart_apply(
    params: &CollectionParams,
    active_transfers: &HashSet<ShardTransfer>,
    resharding: Option<&collection::shards::resharding::ReshardState>,
    old_transfer: &ShardTransfer,
    restart: &ShardTransferRestart,
) -> Result<(), StorageError> {
    if !collection_params_use_private_oram_bucket_store(params) {
        if restart.expected_private_oram_transfer.is_some() {
            return Err(StorageError::bad_request(
                "private ORAM restart identity is not valid for an ordinary collection",
            ));
        }
        if old_transfer.method == Some(restart.method) {
            return Err(StorageError::bad_request(format!(
                "Cannot restart transfer for shard {} from {} to {}, its configuration did not change",
                restart.shard_id, restart.from, restart.to,
            )));
        }
        return Ok(());
    }

    let valid = active_transfers.len() == 1
        && active_transfers
            .iter()
            .next()
            .is_some_and(|transfer| transfer == old_transfer)
        && old_transfer.key() == restart.key()
        && old_transfer.is_private_oram_preinstalled_transfer_for(resharding)
        && old_transfer.method == Some(restart.method)
        && restart
            .expected_private_oram_transfer
            .as_deref()
            .is_some_and(|expected| expected == old_transfer);
    if valid {
        return Ok(());
    }

    Err(StorageError::bad_input(
        "private ORAM restart transfer requires the exact active marked transfer with an \
         unchanged method",
    ))
}

fn reject_private_oram_resharding_until_supported(
    _collection_id: &str,
    params: &CollectionParams,
    operation: &ReshardingOperation,
) -> Result<(), StorageError> {
    if !collection_params_use_private_oram_bucket_store(params)
        || matches!(
            operation,
            ReshardingOperation::CommitRead(_)
                | ReshardingOperation::CommitWrite(_)
                | ReshardingOperation::Abort(_)
        )
    {
        return Ok(());
    }

    Err(StorageError::bad_input(format!(
        "private ORAM resharding start and finish require the typed private ORAM coordinator \
         with encrypted bucket installation and consensus-backed layout ownership",
    )))
}

fn validate_private_oram_resharding_apply_authority(
    collection_id: &str,
    params: &CollectionParams,
    operation: &ReshardingOperation,
    authority: ReshardingApplyAuthority,
) -> Result<(), StorageError> {
    match authority {
        ReshardingApplyAuthority::Ordinary => {
            reject_private_oram_resharding_until_supported(collection_id, params, operation)
        }
        ReshardingApplyAuthority::PrivateOramConsensus
            if collection_params_use_private_oram_bucket_store(params)
                && matches!(
                    operation,
                    ReshardingOperation::Start(_) | ReshardingOperation::Finish(_)
                ) =>
        {
            Ok(())
        }
        ReshardingApplyAuthority::PrivateOramConsensus => {
            Err(invalid_private_oram_resharding_consensus_operation())
        }
    }
}

fn invalid_private_oram_resharding_consensus_operation() -> StorageError {
    StorageError::bad_request("private ORAM resharding consensus operation is invalid")
}

fn reject_private_oram_resharding_replica_state_until_supported(
    _collection_id: &str,
    params: &CollectionParams,
    operation: &SetShardReplicaState,
) -> Result<(), StorageError> {
    if !collection_params_use_private_oram_bucket_store(params)
        || !replica_state_operation_touches_resharding_state(operation)
    {
        return Ok(());
    }

    if operation.state == ReplicaState::Active
        && matches!(
            operation.from_state,
            Some(ReplicaState::Resharding | ReplicaState::ReshardingScaleDown)
        )
    {
        return Ok(());
    }

    Err(StorageError::bad_input(format!(
        "private ORAM resharding replica state progress permits only an exact transitional-to-active \
         promotion that is validated against the active resharding state",
    )))
}

fn replica_state_operation_touches_resharding_state(operation: &SetShardReplicaState) -> bool {
    matches!(
        operation.state,
        ReplicaState::Resharding | ReplicaState::ReshardingScaleDown
    ) || matches!(
        operation.from_state,
        Some(ReplicaState::Resharding | ReplicaState::ReshardingScaleDown)
    )
}

fn validate_private_oram_shard_key_change_authorization(
    _collection_id: &str,
    params: &CollectionParams,
    authority: ShardKeyApplyAuthority,
    private_oram_initial_bootstrap: bool,
) -> Result<(), StorageError> {
    let private_oram_collection = collection_params_use_private_oram_bucket_store(params);
    if (private_oram_collection
        && (authority == ShardKeyApplyAuthority::PrivateOramConsensus
            || private_oram_initial_bootstrap))
        || (!private_oram_collection
            && authority == ShardKeyApplyAuthority::Ordinary
            && !private_oram_initial_bootstrap)
    {
        return Ok(());
    }

    Err(StorageError::bad_input(
        "private ORAM shard-key layout change authorization is invalid",
    ))
}

fn validate_private_oram_replica_removal_authorization(
    _collection_id: &str,
    params: &CollectionParams,
    replica_changes: Option<&[replica_set::Change]>,
    private_oram_replica_removal_reserved: bool,
) -> Result<(), StorageError> {
    let private_oram_collection = collection_params_use_private_oram_bucket_store(params);
    let removes_replica = replica_changes_remove_shard_replica(replica_changes);
    if !private_oram_collection && !private_oram_replica_removal_reserved {
        return Ok(());
    }
    if private_oram_collection && !removes_replica && !private_oram_replica_removal_reserved {
        return Ok(());
    }
    if private_oram_collection
        && private_oram_replica_removal_reserved
        && replica_changes.is_some_and(|changes| changes.len() == 1)
        && removes_replica
    {
        return Ok(());
    }

    Err(StorageError::bad_input(
        "private ORAM replica removal requires a reserved exact single-replica update",
    ))
}

fn replica_changes_remove_shard_replica(replica_changes: Option<&[replica_set::Change]>) -> bool {
    replica_changes.is_some_and(|changes| {
        changes
            .iter()
            .any(|change| matches!(change, replica_set::Change::Remove(_, _)))
    })
}

pub(super) fn collection_params_use_private_oram_bucket_store(params: &CollectionParams) -> bool {
    params.encryption.as_ref().is_some_and(|encryption| {
        encryption.rules.iter().any(|rule| {
            matches!(
                rule.binding.as_deref(),
                Some(PRIVATE_HNSW_ORAM_BINDING) | Some(PRIVATE_RESULT_ORAM_BINDING)
            )
        })
    })
}

fn validate_encrypted_transfer_crypto_runtime_parity(
    collection_id: &str,
    local_peer_id: PeerId,
    from_peer_id: PeerId,
    to_peer_id: PeerId,
    peer_metadata_by_id: &HashMap<PeerId, PeerMetadata>,
) -> Result<(), StorageError> {
    validate_encrypted_operation_crypto_runtime_parity(
        "shard transfer",
        collection_id,
        local_peer_id,
        [from_peer_id, to_peer_id, local_peer_id],
        peer_metadata_by_id,
    )
}

fn validate_encrypted_resharding_crypto_runtime_parity(
    collection_id: &str,
    local_peer_id: PeerId,
    peer_ids: impl IntoIterator<Item = PeerId>,
    peer_metadata_by_id: &HashMap<PeerId, PeerMetadata>,
) -> Result<(), StorageError> {
    validate_encrypted_operation_crypto_runtime_parity(
        "resharding",
        collection_id,
        local_peer_id,
        peer_ids,
        peer_metadata_by_id,
    )
}

fn validate_encrypted_create_shard_key_crypto_runtime_parity(
    collection_id: &str,
    local_peer_id: PeerId,
    placement: &[Vec<PeerId>],
    peer_metadata_by_id: &HashMap<PeerId, PeerMetadata>,
) -> Result<(), StorageError> {
    validate_encrypted_operation_crypto_runtime_parity(
        "create shard key",
        collection_id,
        local_peer_id,
        placement.iter().flatten().copied(),
        peer_metadata_by_id,
    )
}

fn validate_encrypted_operation_crypto_runtime_parity(
    operation: &str,
    collection_id: &str,
    local_peer_id: PeerId,
    peer_ids: impl IntoIterator<Item = PeerId>,
    peer_metadata_by_id: &HashMap<PeerId, PeerMetadata>,
) -> Result<(), StorageError> {
    let Some(local_fingerprint) = peer_metadata_by_id
        .get(&local_peer_id)
        .and_then(PeerMetadata::crypto_runtime_capability_fingerprint)
    else {
        return Err(StorageError::bad_input(format!(
            "encrypted collection {operation} for {collection_id} requires local peer \
             {local_peer_id} crypto runtime capability metadata",
        )));
    };

    let mut checked_peer_ids = HashSet::new();
    for peer_id in peer_ids {
        if !checked_peer_ids.insert(peer_id) {
            continue;
        }
        let Some(peer_fingerprint) = peer_metadata_by_id
            .get(&peer_id)
            .and_then(PeerMetadata::crypto_runtime_capability_fingerprint)
        else {
            return Err(StorageError::bad_input(format!(
                "encrypted collection {operation} for {collection_id} requires peer \
                 {peer_id} crypto runtime capability metadata",
            )));
        };

        if peer_fingerprint != local_fingerprint {
            return Err(StorageError::bad_input(format!(
                "encrypted collection {operation} for {collection_id} detected crypto \
                 runtime parity mismatch for peer {peer_id}",
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::num::NonZeroU32;

    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::operations::types::PeerMetadata;
    use collection::shards::replica_set;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::resharding::{ReshardKey, ReshardState, ReshardingStage};
    use collection::shards::shard::PeerId;
    use collection::shards::transfer::{
        ShardTransfer, ShardTransferKey, ShardTransferMethod, ShardTransferRestart,
    };
    use segment::types::{PayloadFieldSchema, PayloadSchemaType};
    use uuid::Uuid;

    use super::{
        PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING, ReshardingApplyAuthority,
        ShardKeyApplyAuthority, collection_params_require_crypto_runtime_transfer_parity,
        private_oram_archive_ack_fenced_collection_name,
        private_oram_pending_acknowledgement_matches_collection,
        reject_private_oram_resharding_replica_state_until_supported,
        reject_private_oram_resharding_until_supported,
        reject_private_oram_shard_transfer_until_supported,
        validate_encrypted_create_shard_key_crypto_runtime_parity,
        validate_encrypted_resharding_crypto_runtime_parity,
        validate_encrypted_transfer_crypto_runtime_parity,
        validate_private_oram_replica_removal_authorization,
        validate_private_oram_resharding_apply_authority, validate_private_oram_restart_apply,
        validate_private_oram_shard_key_change_authorization,
    };
    use crate::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreatePayloadIndex, DeleteCollectionOperation, DropPayloadIndex,
        ReshardingOperation, SetShardReplicaState, ShardTransferOperations,
    };
    use crate::content_manager::consensus_ops::PrivateOramMutationKey;

    #[test]
    fn private_oram_pending_acknowledgement_is_collection_scoped() {
        let pending_acknowledgements = vec![(
            PrivateOramMutationKey {
                collection_id: "collection-a".to_string(),
            },
            101,
            7,
        )];

        assert!(private_oram_pending_acknowledgement_matches_collection(
            "collection-a",
            &pending_acknowledgements,
        ));
        assert!(!private_oram_pending_acknowledgement_matches_collection(
            "collection-b",
            &pending_acknowledgements,
        ));
    }

    #[test]
    fn private_oram_archive_ack_fence_targets_only_destructive_and_payload_schema_ops() {
        let fenced_operations = [
            CollectionMetaOperations::DeleteCollection(DeleteCollectionOperation(
                "docs".to_string(),
            )),
            CollectionMetaOperations::CreatePayloadIndex(CreatePayloadIndex {
                collection_name: "docs".to_string(),
                field_name: "pending-create".parse().unwrap(),
                field_schema: PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            }),
            CollectionMetaOperations::DropPayloadIndex(DropPayloadIndex {
                collection_name: "docs".to_string(),
                field_name: "pending-drop".parse().unwrap(),
            }),
        ];
        for operation in &fenced_operations {
            assert_eq!(
                private_oram_archive_ack_fenced_collection_name(operation),
                Some("docs"),
            );
        }

        let topology_operation = CollectionMetaOperations::Resharding(
            "docs".to_string(),
            ReshardingOperation::Abort(ReshardKey {
                uuid: Uuid::from_u128(17),
                direction: ReshardingDirection::Up,
                peer_id: 101,
                shard_id: 0,
                shard_key: None,
            }),
        );
        assert_eq!(
            private_oram_archive_ack_fenced_collection_name(&topology_operation),
            None,
        );
    }

    fn assert_crypto_fingerprints_redacted(rendered: &str) {
        for sentinel in ["fingerprint-a", "fingerprint-b"] {
            assert!(
                !rendered.contains(sentinel),
                "crypto runtime parity errors must not expose fingerprint `{sentinel}`: {rendered}",
            );
        }
    }

    fn assert_private_oram_consensus_guard_redacts_config(rendered: &str) {
        for sentinel in [
            "docs",
            "tenant-a/vector-private-rk",
            "text_private_hnsw",
            "docs_private_hnsw_v1",
            PRIVATE_HNSW_ORAM_BINDING,
            "private_hnsw_oram",
            "tenant-a/result-private-rk",
            "body_private_result_oram",
            "docs_private_result_oram_v1",
            PRIVATE_RESULT_ORAM_BINDING,
            "private_result_oram",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "private ORAM consensus guard leaked config sentinel `{sentinel}`: {rendered}",
            );
        }
    }

    #[test]
    fn private_oram_consensus_guard_redacts_client_state_aliases() {
        let params = CollectionParams {
            shard_number: NonZeroU32::new(2).unwrap(),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("clientStateCiphertextHash.json".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "encryptedClientStateCiphertext.json".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![
                                "clientState.json".to_string(),
                                "clientStates.json".to_string(),
                                "client_state.json".to_string(),
                                "client_states.json".to_string(),
                                "clientStateBackup.json".to_string(),
                                "clientStateBackups.json".to_string(),
                                "client_state_backup.json".to_string(),
                                "client_state_backups.json".to_string(),
                                "positionMapBackup.json".to_string(),
                                "positionMapBackups.json".to_string(),
                                "position_map_backup.json".to_string(),
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
                                "ciphertextSha256.json".to_string(),
                                "ciphertextsSha256.json".to_string(),
                                "ciphertext_sha256.bin".to_string(),
                                "ciphertexts_sha256.bin".to_string(),
                                "bucketCommitment.json".to_string(),
                                "bucketCommitments.json".to_string(),
                                "bucket_commitment.bin".to_string(),
                                "bucket_commitments.bin".to_string(),
                                "updatedBucketCommitment.json".to_string(),
                                "updatedBucketCommitments.json".to_string(),
                                "updated_bucket_commitment.bin".to_string(),
                                "updated_bucket_commitments.bin".to_string(),
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
                                "position_map_backups.json".to_string(),
                            ],
                        },
                        instance: "oramPositionMapBackup.json".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    },
                    EncryptionRuleRef {
                        id: "tokenMapBackup.json".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec![
                                "stashBackup.json".to_string(),
                                "stashBackups.json".to_string(),
                                "stash_backup.json".to_string(),
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
                                "tokenPositionMapBackup.json".to_string(),
                                "tokenMapBackups.json".to_string(),
                                "token.map.backup.json".to_string(),
                                "token.map.backups.json".to_string(),
                                "token_map_backup.json".to_string(),
                                "token_map_backups.json".to_string(),
                                "tokenPositionMapBackups.json".to_string(),
                                "token.position.map.backup.json".to_string(),
                                "token.position.map.backups.json".to_string(),
                                "token_position_map_backup.json".to_string(),
                                "token_position_map_backups.json".to_string(),
                            ],
                        },
                        instance: "stateCiphertextHash.json".to_string(),
                        binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };
        let operation = ShardTransferOperations::Start(ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
            sync: false,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: false,
            private_oram_layout_transition: None,
            filter: None,
        });

        let err = reject_private_oram_shard_transfer_until_supported(
            "stashBackup.json",
            &params,
            &operation,
            None,
        )
        .expect_err("private ORAM transfer must fail closed without leaking client-state aliases");
        let rendered = err.to_string();

        assert!(rendered.contains("private ORAM shard transfer"));
        assert!(rendered.contains("consensus-backed epoch/root ownership"));
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
            "positionMapBackup",
            "positionMapBackups",
            "position_map_backup",
            "position_map_backups",
            "oramPositionMapBackup",
            "oramPositionMapBackups",
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
            PRIVATE_HNSW_ORAM_BINDING,
            PRIVATE_RESULT_ORAM_BINDING,
            "private_hnsw_oram",
            "private_result_oram",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "private ORAM consensus guard leaked client-state alias `{sentinel}`: {rendered}",
            );
        }

        let ShardTransferOperations::Start(mut authorized_transfer) = operation else {
            unreachable!()
        };
        authorized_transfer.private_oram_preinstalled = true;
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Start(authorized_transfer.clone()),
            None,
        )
        .expect("verified private ORAM preinstall must allow transfer start");
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Finish(authorized_transfer),
            None,
        )
        .expect("verified private ORAM preinstall must allow transfer finish");
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Restart(ShardTransferRestart {
                shard_id: 1,
                to_shard_id: None,
                from: 2,
                to: 3,
                method: ShardTransferMethod::StreamRecords,
                expected_private_oram_transfer: None,
            }),
            None,
        )
        .expect("exact private ORAM stream-records restart must reach apply validation");

        let mut resharding =
            ReshardState::new(Uuid::from_u128(81), ReshardingDirection::Up, 3, 2, None);
        let resharding_transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: Some(2),
            from: 2,
            to: 3,
            sync: true,
            method: Some(ShardTransferMethod::ReshardingStreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        };
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Start(resharding_transfer.clone()),
            Some(&resharding),
        )
        .expect("exact marked private ORAM resharding transfer must start");
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Finish(resharding_transfer.clone()),
            Some(&resharding),
        )
        .expect("exact marked private ORAM resharding transfer must finish");
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Restart(ShardTransferRestart {
                shard_id: resharding_transfer.shard_id,
                to_shard_id: resharding_transfer.to_shard_id,
                from: resharding_transfer.from,
                to: resharding_transfer.to,
                method: ShardTransferMethod::ReshardingStreamRecords,
                expected_private_oram_transfer: None,
            }),
            Some(&resharding),
        )
        .expect("exact private ORAM resharding restart must reach apply validation");

        resharding.stage = ReshardingStage::ReadHashRingCommitted;
        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Start(resharding_transfer),
            Some(&resharding),
        )
        .expect_err("private ORAM resharding transfer must fail after point migration");
    }

    #[test]
    fn private_oram_restart_apply_requires_exact_active_marked_transfer() {
        let private_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/vector-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let restart = ShardTransferRestart {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
            method: ShardTransferMethod::StreamRecords,
            expected_private_oram_transfer: None,
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        };
        validate_private_oram_restart_apply(
            &private_params,
            &HashSet::from([transfer.clone()]),
            None,
            &transfer,
            &restart,
        )
        .expect_err("identity-free private ORAM restart must fail closed");
        let mut exact_restart = restart.clone();
        exact_restart.expected_private_oram_transfer = Some(Box::new(transfer.clone()));
        validate_private_oram_restart_apply(
            &private_params,
            &HashSet::from([transfer.clone()]),
            None,
            &transfer,
            &exact_restart,
        )
        .unwrap();
        let mut stale_restart = exact_restart.clone();
        stale_restart
            .expected_private_oram_transfer
            .as_mut()
            .unwrap()
            .sync = false;
        validate_private_oram_restart_apply(
            &private_params,
            &HashSet::from([transfer.clone()]),
            None,
            &transfer,
            &stale_restart,
        )
        .expect_err("stale same-key private ORAM restart identity must fail closed");
        let active_resharding =
            ReshardState::new(Uuid::from_u128(82), ReshardingDirection::Up, 3, 2, None);
        validate_private_oram_restart_apply(
            &private_params,
            &HashSet::from([transfer.clone()]),
            Some(&active_resharding),
            &transfer,
            &exact_restart,
        )
        .expect_err("fixed-layout private ORAM restart must fail during active resharding");

        let resharding_transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: Some(2),
            from: 2,
            to: 3,
            sync: true,
            method: Some(ShardTransferMethod::ReshardingStreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        };
        let resharding_restart = ShardTransferRestart {
            shard_id: resharding_transfer.shard_id,
            to_shard_id: resharding_transfer.to_shard_id,
            from: resharding_transfer.from,
            to: resharding_transfer.to,
            method: ShardTransferMethod::ReshardingStreamRecords,
            expected_private_oram_transfer: Some(Box::new(resharding_transfer.clone())),
        };
        validate_private_oram_restart_apply(
            &private_params,
            &HashSet::from([resharding_transfer.clone()]),
            Some(&active_resharding),
            &resharding_transfer,
            &resharding_restart,
        )
        .expect("exact marked resharding restart must be accepted during point migration");

        let mut committed_resharding = active_resharding.clone();
        committed_resharding.stage = ReshardingStage::ReadHashRingCommitted;
        validate_private_oram_restart_apply(
            &private_params,
            &HashSet::from([resharding_transfer.clone()]),
            Some(&committed_resharding),
            &resharding_transfer,
            &resharding_restart,
        )
        .expect_err("private ORAM resharding restart must fail after point migration");

        let mut unmarked = transfer.clone();
        unmarked.private_oram_preinstalled = false;
        let mut old_wrong_method = transfer.clone();
        old_wrong_method.method = Some(ShardTransferMethod::Snapshot);
        let mut wrong_method_restart = restart.clone();
        wrong_method_restart.expected_private_oram_transfer =
            Some(Box::new(old_wrong_method.clone()));
        let mut wrong_key = exact_restart.clone();
        wrong_key.to = 4;
        for (candidate, request, active) in [
            (
                unmarked,
                exact_restart.clone(),
                HashSet::from([transfer.clone()]),
            ),
            (
                old_wrong_method.clone(),
                wrong_method_restart,
                HashSet::from([old_wrong_method]),
            ),
            (
                transfer.clone(),
                wrong_key,
                HashSet::from([transfer.clone()]),
            ),
            (
                transfer.clone(),
                exact_restart.clone(),
                HashSet::from([
                    transfer.clone(),
                    ShardTransfer {
                        shard_id: 2,
                        ..transfer.clone()
                    },
                ]),
            ),
        ] {
            let rendered = validate_private_oram_restart_apply(
                &private_params,
                &active,
                None,
                &candidate,
                &request,
            )
            .unwrap_err()
            .to_string();
            assert!(rendered.contains("exact active marked transfer"));
            assert_private_oram_consensus_guard_redacts_config(&rendered);
        }

        let ordinary_params = CollectionParams::empty();
        let unchanged = validate_private_oram_restart_apply(
            &ordinary_params,
            &HashSet::from([transfer.clone()]),
            None,
            &transfer,
            &restart,
        )
        .unwrap_err()
        .to_string();
        assert!(unchanged.contains("configuration did not change"));

        let mut changed_method = restart;
        changed_method.method = ShardTransferMethod::Snapshot;
        validate_private_oram_restart_apply(
            &ordinary_params,
            &HashSet::from([transfer.clone()]),
            None,
            &transfer,
            &changed_method,
        )
        .unwrap();
    }

    #[test]
    fn encrypted_collection_requires_transfer_parity_enforcement() {
        assert!(!collection_params_require_crypto_runtime_transfer_parity(
            &CollectionParams::empty()
        ));

        let generic = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/payload".to_string()),
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
        };
        assert!(collection_params_require_crypto_runtime_transfer_parity(
            &generic
        ));
    }

    #[test]
    fn private_hnsw_consensus_transfer_progress_fails_closed_until_bucket_transfer_exists() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/vector-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
            sync: false,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: false,
            private_oram_layout_transition: None,
            filter: None,
        };
        let transfer_key = ShardTransferKey {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
        };
        let progressing_operations = [
            ShardTransferOperations::Start(transfer.clone()),
            ShardTransferOperations::Restart(ShardTransferRestart {
                shard_id: 1,
                to_shard_id: None,
                from: 2,
                to: 3,
                method: ShardTransferMethod::Snapshot,
                expected_private_oram_transfer: None,
            }),
            ShardTransferOperations::Finish(transfer),
            ShardTransferOperations::RecoveryToPartial(transfer_key),
            ShardTransferOperations::SnapshotRecovered(transfer_key),
        ];

        for operation in progressing_operations {
            let err = reject_private_oram_shard_transfer_until_supported(
                "docs", &params, &operation, None,
            )
            .expect_err("private HNSW ORAM transfer progress must fail closed");
            assert!(
                err.to_string().contains("private ORAM shard transfer")
                    && err
                        .to_string()
                        .contains("consensus-backed epoch/root ownership"),
                "unexpected error for {operation:?}: {err}",
            );
            assert_private_oram_consensus_guard_redacts_config(&err.to_string());
        }

        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Abort {
                transfer: transfer_key,
                reason: "cleanup unsupported private ORAM transfer".to_string(),
            },
            None,
        )
        .expect("abort must remain available to clean up unsupported transfer records");
    }

    #[test]
    fn private_result_oram_consensus_transfer_progress_fails_closed_until_bucket_transfer_exists() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_private_result_oram".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
            sync: false,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: false,
            private_oram_layout_transition: None,
            filter: None,
        };
        let transfer_key = ShardTransferKey {
            shard_id: 1,
            to_shard_id: None,
            from: 2,
            to: 3,
        };
        let progressing_operations = [
            ShardTransferOperations::Start(transfer.clone()),
            ShardTransferOperations::Restart(ShardTransferRestart {
                shard_id: 1,
                to_shard_id: None,
                from: 2,
                to: 3,
                method: ShardTransferMethod::Snapshot,
                expected_private_oram_transfer: None,
            }),
            ShardTransferOperations::Finish(transfer.clone()),
            ShardTransferOperations::RecoveryToPartial(transfer_key),
            ShardTransferOperations::SnapshotRecovered(transfer_key),
        ];

        for operation in progressing_operations {
            let err = reject_private_oram_shard_transfer_until_supported(
                "docs", &params, &operation, None,
            )
            .expect_err("private result ORAM transfer progress must fail closed");
            assert!(
                err.to_string().contains("private ORAM shard transfer")
                    && err
                        .to_string()
                        .contains("consensus-backed epoch/root ownership"),
                "unexpected error for {operation:?}: {err}",
            );
            assert_private_oram_consensus_guard_redacts_config(&err.to_string());
        }

        reject_private_oram_shard_transfer_until_supported(
            "docs",
            &params,
            &ShardTransferOperations::Abort {
                transfer: transfer_key,
                reason: "cleanup unsupported private ORAM transfer".to_string(),
            },
            None,
        )
        .expect("abort must remain available to clean up unsupported transfer records");
    }

    #[test]
    fn private_oram_consensus_resharding_apply_authority_is_phase_scoped() {
        let private_hnsw_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/vector-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let private_result_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_private_result_oram".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let key = ReshardKey {
            uuid: Uuid::from_u128(99),
            direction: ReshardingDirection::Up,
            peer_id: 2,
            shard_id: 1,
            shard_key: None,
        };
        for (label, params) in [
            ("private HNSW ORAM", private_hnsw_params),
            ("private result ORAM", private_result_params),
        ] {
            for operation in [
                ReshardingOperation::Start(key.clone()),
                ReshardingOperation::Finish(key.clone()),
            ] {
                let err =
                    reject_private_oram_resharding_until_supported("docs", &params, &operation)
                        .expect_err("ordinary private ORAM start and finish must fail closed");
                assert!(
                    err.to_string()
                        .contains("private ORAM resharding start and finish")
                        && err.to_string().contains("typed private ORAM coordinator"),
                    "unexpected {label} resharding error for {operation:?}: {err}",
                );
                assert_private_oram_consensus_guard_redacts_config(&err.to_string());
            }

            for operation in [
                ReshardingOperation::CommitRead(key.clone()),
                ReshardingOperation::CommitWrite(key.clone()),
                ReshardingOperation::Abort(key.clone()),
            ] {
                reject_private_oram_resharding_until_supported("docs", &params, &operation)
                    .expect("bounded private ORAM resharding progress must remain available");
            }

            for operation in [
                ReshardingOperation::Start(key.clone()),
                ReshardingOperation::Finish(key.clone()),
            ] {
                validate_private_oram_resharding_apply_authority(
                    "docs",
                    &params,
                    &operation,
                    ReshardingApplyAuthority::PrivateOramConsensus,
                )
                .expect("typed private ORAM start and finish must be authorized");
            }
            for operation in [
                ReshardingOperation::CommitRead(key.clone()),
                ReshardingOperation::CommitWrite(key.clone()),
                ReshardingOperation::Abort(key.clone()),
            ] {
                let err = validate_private_oram_resharding_apply_authority(
                    "docs",
                    &params,
                    &operation,
                    ReshardingApplyAuthority::PrivateOramConsensus,
                )
                .expect_err("typed private ORAM authority must be scoped to start and finish");
                assert_eq!(
                    err.to_string(),
                    "Bad request: private ORAM resharding consensus operation is invalid"
                );
            }

            let replica_progress = SetShardReplicaState {
                collection_name: "docs".to_string(),
                shard_id: 1,
                peer_id: 2,
                state: ReplicaState::Active,
                from_state: Some(ReplicaState::Resharding),
            };
            reject_private_oram_resharding_replica_state_until_supported(
                "docs",
                &params,
                &replica_progress,
            )
            .expect("transitional-to-active promotion shape must pass the TOC guard");
            let invalid_replica_progress = SetShardReplicaState {
                state: ReplicaState::Dead,
                ..replica_progress
            };
            let err = reject_private_oram_resharding_replica_state_until_supported(
                "docs",
                &params,
                &invalid_replica_progress,
            )
            .expect_err("other private ORAM resharding replica-state changes must fail closed");
            assert!(
                err.to_string()
                    .contains("private ORAM resharding replica state progress")
                    && err.to_string().contains("transitional-to-active"),
                "unexpected {label} replica-state error: {err}",
            );
            assert_private_oram_consensus_guard_redacts_config(&err.to_string());
        }

        reject_private_oram_resharding_until_supported(
            "docs",
            &CollectionParams::empty(),
            &ReshardingOperation::Start(key.clone()),
        )
        .expect("ordinary collection resharding guard must stay open");
        validate_private_oram_resharding_apply_authority(
            "docs",
            &CollectionParams::empty(),
            &ReshardingOperation::Start(key.clone()),
            ReshardingApplyAuthority::PrivateOramConsensus,
        )
        .expect_err("private ORAM consensus authority must reject ordinary collections");
        reject_private_oram_resharding_replica_state_until_supported(
            "docs",
            &CollectionParams::empty(),
            &SetShardReplicaState {
                collection_name: "docs".to_string(),
                shard_id: 1,
                peer_id: 2,
                state: ReplicaState::Active,
                from_state: Some(ReplicaState::Resharding),
            },
        )
        .expect("ordinary collection replica-state guard must stay open");
    }

    #[test]
    fn private_oram_shard_key_changes_require_matching_apply_authority() {
        let private_hnsw_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/vector-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let private_result_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_private_result_oram".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        for (label, params) in [
            ("private HNSW ORAM", private_hnsw_params),
            ("private result ORAM", private_result_params),
        ] {
            validate_private_oram_shard_key_change_authorization(
                "docs",
                &params,
                ShardKeyApplyAuthority::PrivateOramConsensus,
                false,
            )
            .expect("private ORAM shard-key changes require consensus authority");
            validate_private_oram_shard_key_change_authorization(
                "docs",
                &params,
                ShardKeyApplyAuthority::Ordinary,
                true,
            )
            .expect("empty private ORAM collections permit initial shard-key bootstrap");
            let err = validate_private_oram_shard_key_change_authorization(
                "docs",
                &params,
                ShardKeyApplyAuthority::Ordinary,
                false,
            )
            .expect_err("ordinary apply authority must reject private ORAM shard-key changes");
            assert!(
                err.to_string()
                    .contains("shard-key layout change authorization is invalid"),
                "unexpected {label} error: {err}",
            );
            assert_private_oram_consensus_guard_redacts_config(&err.to_string());
        }

        validate_private_oram_shard_key_change_authorization(
            "docs",
            &CollectionParams::empty(),
            ShardKeyApplyAuthority::Ordinary,
            false,
        )
        .expect("ordinary collection create_shard_key must stay open");
        let err = validate_private_oram_shard_key_change_authorization(
            "operation-secret-sentinel",
            &CollectionParams::empty(),
            ShardKeyApplyAuthority::PrivateOramConsensus,
            false,
        )
        .expect_err("private ORAM consensus authority must reject ordinary collections");
        assert!(
            err.to_string()
                .contains("shard-key layout change authorization is invalid")
        );
        assert!(!err.to_string().contains("operation-secret-sentinel"));
    }

    #[test]
    fn private_oram_consensus_replica_remove_requires_exact_reservation_marker() {
        let private_hnsw_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/vector-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let private_result_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_private_result_oram".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let changes = [replica_set::Change::Remove(1, 2)];

        for (label, params) in [
            ("private HNSW ORAM", &private_hnsw_params),
            ("private result ORAM", &private_result_params),
        ] {
            let err = validate_private_oram_replica_removal_authorization(
                "docs",
                params,
                Some(&changes),
                false,
            )
            .expect_err("unreserved private ORAM replica removal must fail closed");
            assert!(
                err.to_string().contains("replica removal")
                    && err.to_string().contains("reserved exact single-replica"),
                "unexpected {label} replica removal error: {err}",
            );
            assert_private_oram_consensus_guard_redacts_config(&err.to_string());

            validate_private_oram_replica_removal_authorization(
                "docs",
                params,
                Some(&changes),
                true,
            )
            .expect("reserved exact private ORAM replica removal must reach layout validation");
        }

        validate_private_oram_replica_removal_authorization(
            "docs",
            &CollectionParams::empty(),
            Some(&changes),
            false,
        )
        .expect("ordinary collection replica removal must stay open");
        validate_private_oram_replica_removal_authorization(
            "docs",
            &private_result_params,
            None,
            false,
        )
        .expect("private ORAM update without replica changes must stay open");

        let multiple = [
            replica_set::Change::Remove(1, 2),
            replica_set::Change::Remove(2, 3),
        ];
        validate_private_oram_replica_removal_authorization(
            "docs",
            &private_hnsw_params,
            Some(&multiple),
            true,
        )
        .expect_err("private ORAM replica removal authorization must be exact");
        validate_private_oram_replica_removal_authorization(
            "docs",
            &CollectionParams::empty(),
            Some(&changes),
            true,
        )
        .expect_err("private ORAM reservation marker must not authorize ordinary updates");
    }

    #[test]
    fn encrypted_transfer_requires_matching_crypto_runtime_peer_metadata() {
        let mut metadata = HashMap::<PeerId, PeerMetadata>::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );

        validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect("matching peer metadata should allow encrypted transfer");

        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-b".to_string(),
            )),
        );
        let err = validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect_err("mismatched peer metadata must fail closed");
        let rendered = err.to_string();
        assert!(rendered.contains("crypto runtime parity mismatch"));
        assert_crypto_fingerprints_redacted(&rendered);
    }

    #[test]
    fn encrypted_transfer_requires_complete_crypto_runtime_peer_metadata() {
        let mut metadata = HashMap::<PeerId, PeerMetadata>::new();
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );

        let err = validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect_err("missing local crypto metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires local peer 1 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);

        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.remove(&2);

        let err = validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect_err("missing transfer participant crypto metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires peer 2 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);

        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(None),
        );
        let err = validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect_err("empty transfer participant crypto metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires peer 2 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);

        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new())),
        );
        let err = validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect_err("blank transfer participant crypto metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires peer 2 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);

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
        let err = validate_encrypted_transfer_crypto_runtime_parity("docs", 1, 2, 3, &metadata)
            .expect_err("blank local crypto metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires local peer 1 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);
    }

    #[test]
    fn encrypted_resharding_requires_all_peer_crypto_runtime_parity() {
        let mut metadata = HashMap::<PeerId, PeerMetadata>::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );

        validate_encrypted_resharding_crypto_runtime_parity("docs", 1, [1, 2, 3], &metadata)
            .expect("matching peer metadata should allow encrypted resharding");

        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-b".to_string(),
            )),
        );
        let err =
            validate_encrypted_resharding_crypto_runtime_parity("docs", 1, [1, 2, 3], &metadata)
                .expect_err("mismatched peer metadata must fail closed");
        let rendered = err.to_string();
        assert!(rendered.contains("crypto runtime parity mismatch"));
        assert_crypto_fingerprints_redacted(&rendered);

        metadata.remove(&2);
        let err =
            validate_encrypted_resharding_crypto_runtime_parity("docs", 1, [1, 2, 3], &metadata)
                .expect_err("missing peer metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires peer 2 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);

        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new())),
        );
        let err =
            validate_encrypted_resharding_crypto_runtime_parity("docs", 1, [1, 2, 3], &metadata)
                .expect_err("blank peer crypto metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires peer 2 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);
    }

    #[test]
    fn encrypted_create_shard_key_requires_placement_peer_crypto_runtime_parity() {
        let mut metadata = HashMap::<PeerId, PeerMetadata>::new();
        metadata.insert(
            1,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            2,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-b".to_string(),
            )),
        );
        let placement = vec![vec![1, 2], vec![2, 3]];

        let err = validate_encrypted_create_shard_key_crypto_runtime_parity(
            "docs", 1, &placement, &metadata,
        )
        .expect_err("mismatched create-shard-key placement must fail closed");
        let rendered = err.to_string();
        assert!(rendered.contains("create shard key"));
        assert!(rendered.contains("crypto runtime parity mismatch"));
        assert_crypto_fingerprints_redacted(&rendered);

        metadata.insert(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "fingerprint-a".to_string(),
            )),
        );
        validate_encrypted_create_shard_key_crypto_runtime_parity("docs", 1, &placement, &metadata)
            .expect("matching create-shard-key placement should be allowed");

        metadata.remove(&2);
        let err = validate_encrypted_create_shard_key_crypto_runtime_parity(
            "docs", 1, &placement, &metadata,
        )
        .expect_err("missing create-shard-key placement metadata must fail closed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("requires peer 2 crypto runtime capability metadata"),
            "{rendered}",
        );
        assert_crypto_fingerprints_redacted(&rendered);
    }
}
