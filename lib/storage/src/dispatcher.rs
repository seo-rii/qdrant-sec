use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use api::grpc::qdrant::{
    CompletePrivateOramWritebackRequest, InstallPrivateOramIndexRequest,
    PreparePrivateOramWritebackRequest, PrivateOramReplicationBucket,
    PrivateOramReplicationEpochState, PrivateOramReplicationIndexKind,
    PrivateOramReplicationSignature, PrivateOramReplicationTransition,
};
use api::rest::models::HardwareUsage;
use collection::common::fetch_vectors::CollectionName;
use collection::config::ShardingMethod;
use collection::operations::verification::VerificationPass;
use collection::private_hnsw_oram_store::{
    PrivateHnswOramConsensusWriteback, PrivateHnswOramWritebackBatch,
};
use collection::private_result_oram_store::{
    PrivateResultOramConsensusWriteback, PrivateResultOramWritebackBatch,
};
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::resharding::{ReshardKey, ReshardingStage};
use collection::shards::shard::{PeerId, ShardId};
use collection::shards::transfer::ShardTransfer;
use common::counter::hardware_accumulator::HwSharedDrain;
use common::defaults::CONSENSUS_META_OP_WAIT;
use data_encoding::BASE64URL_NOPAD;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use parking_lot::Mutex;
use segment::types::ShardKey;

use crate::content_manager::collection_meta_ops::AliasOperations;
use crate::content_manager::consensus_manager::ConsensusProposalOutcome;
use crate::content_manager::consensus_ops::{
    CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramLayout,
    CompareAndSwapPrivateOramSessionLease, PrivateOramCollectionLayoutTransition,
    PrivateOramConsensusCollectionStateV2, PrivateOramConsensusEpoch, PrivateOramConsensusLayout,
    PrivateOramEpochKey, PrivateOramExternalRecoveryKey, PrivateOramExternalRecoveryOperation,
    PrivateOramExternalRecoveryState, PrivateOramIndexKind, PrivateOramLayoutIndexStateBinding,
    PrivateOramLayoutKey, PrivateOramLayoutLeaseBinding, PrivateOramMutationKey,
    PrivateOramMutationLease, PrivateOramMutationLeaseSlotV2,
    PrivateOramReshardingLayoutTransition, PrivateOramReshardingOperation, PrivateOramSessionLease,
    PrivateOramShardKeyLayoutChange, PrivateOramShardKeyLayoutChangeKind,
    PrivateOramShardLayoutEntry, PrivateOramShardTransferStart,
    canonical_private_oram_index_state_digest,
    canonical_private_oram_resharding_post_layout_digest,
    canonical_private_oram_shard_layout_digest,
    canonical_private_oram_shard_transfer_post_layout_digest,
    private_oram_shard_key_post_layout_entries,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAdmissionPlanV2, PrivateOramMutationAllOwnersPrestagedV2,
    PrivateOramMutationClearPendingProposalV2, PrivateOramMutationNeedCleanupWitnessV2,
    PrivateOramMutationNeedClearV2, PrivateOramMutationNeedParentProgressV2,
    PrivateOramMutationRecoveryReadinessProposalV2,
    encode_private_oram_mutation_admission_recovery_manifest_v2,
};
use crate::content_manager::shard_distribution::ShardDistributionProposal;
use crate::rbac::{Auth, CollectionMultipass};
use crate::{
    ClusterStatus, CollectionMetaOperations, ConsensusOperations, ConsensusStateRef, StorageError,
    TableOfContent,
};

/// How many times an unresolved private ORAM epoch CAS is re-proposed before the writeback is
/// left prepared for recovery.
const PRIVATE_ORAM_EPOCH_CAS_RESOLVE_ATTEMPTS: usize = 3;
const PRIVATE_ORAM_WRITEBACK_INDETERMINATE: &str =
    "private ORAM writeback outcome is indeterminate";

/// Definitive or unresolved outcome of a private ORAM epoch CAS proposal.
#[derive(Debug)]
pub enum PrivateOramEpochCasOutcome {
    Applied,
    /// The CAS definitively did not apply (rejected, failed, or never submitted).
    Rejected(StorageError),
    /// The proposal may still commit; prepared state must not be rolled back on this basis.
    Indeterminate(StorageError),
}

/// True when a writeback coordinator error means the consensus outcome is still unknown and the
/// prepared writeback was intentionally retained; callers must not abort it.
pub fn private_oram_writeback_outcome_indeterminate(error: &StorageError) -> bool {
    matches!(error, StorageError::Timeout { .. })
}

#[derive(Clone)]
pub struct Dispatcher {
    toc: Arc<TableOfContent>,
    consensus_state: Option<ConsensusStateRef>,
    resharding_enabled: bool,
    private_oram_live_admission_registry: Arc<Mutex<PrivateOramLiveAdmissionRegistryV2>>,
}

const PRIVATE_ORAM_LIVE_ADMISSION_MAX_RECORDS: usize = 1_024;
const PRIVATE_ORAM_LIVE_ADMISSION_MAX_LEASE_SECS: u64 = 600;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrivateOramLiveAdmissionRecordPhaseV2 {
    Seed,
    Bound,
}

struct PrivateOramLiveAdmissionRecordV2 {
    collection_id: String,
    mutation_id: String,
    leader_peer_id: PeerId,
    leader_term: u64,
    expires_at_unix: u64,
    phase: PrivateOramLiveAdmissionRecordPhaseV2,
    session_commitment: Option<String>,
    generation: Option<u64>,
    writer_fence: Option<u64>,
    expected_aggregate_digest: Option<String>,
}

#[derive(Default)]
struct PrivateOramLiveAdmissionRegistryV2 {
    records: HashMap<String, PrivateOramLiveAdmissionRecordV2>,
}

/// Process-local seed issued only while a paired append session is live.
///
/// It is intentionally not serializable. A persisted owner receipt cannot reconstruct it.
#[doc(hidden)]
#[derive(Clone)]
pub struct PrivateOramLiveAdmissionSeedV2 {
    capability_id: String,
    collection_id: String,
    mutation_id: String,
    leader_peer_id: PeerId,
    leader_term: u64,
    expires_at_unix: u64,
}

impl Debug for PrivateOramLiveAdmissionSeedV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramLiveAdmissionSeedV2")
            .field("capability_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("leader_peer_id", &self.leader_peer_id)
            .field("leader_term", &self.leader_term)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// Single-use, non-serializable authority required to build a V2 admission operation.
#[doc(hidden)]
pub struct PrivateOramLiveAdmissionPermitV2 {
    capability_id: String,
    collection_id: String,
    mutation_id: String,
    leader_peer_id: PeerId,
    leader_term: u64,
    expires_at_unix: u64,
    session_commitment: String,
    generation: u64,
    writer_fence: u64,
    expected_aggregate_digest: String,
}

impl Debug for PrivateOramLiveAdmissionPermitV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramLiveAdmissionPermitV2")
            .field("capability_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("leader_peer_id", &self.leader_peer_id)
            .field("leader_term", &self.leader_term)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("session_commitment", &"[redacted]")
            .field("generation", &self.generation)
            .field("writer_fence", &self.writer_fence)
            .field("expected_aggregate_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramReplicaPrepareAck {
    pub peer_id: PeerId,
    pub writeback_digest: String,
}

impl Debug for PrivateOramReplicaPrepareAck {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramReplicaPrepareAck")
            .field("peer_id", &self.peer_id)
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateOramRecoveryAction {
    Clean,
    AbortPending,
    FinalizePending,
}

pub struct PrivateOramEpochRef<'a> {
    pub index_epoch: u64,
    pub root_hash: &'a str,
}

pub struct PrivateOramPendingTransitionRef<'a> {
    pub old: PrivateOramEpochRef<'a>,
    pub new: PrivateOramEpochRef<'a>,
    pub writeback_digest: &'a str,
}

/// Opaque Raft operation built before the caller crosses the append cancellation boundary.
#[doc(hidden)]
pub struct PrivateOramMutationAdmissionSubmissionV2 {
    admission_operation: ConsensusOperations,
    rejection_operation: ConsensusOperations,
    lease: PrivateOramMutationLease,
    recovery_manifest_digest: String,
}

impl Debug for PrivateOramMutationAdmissionSubmissionV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAdmissionSubmissionV2")
            .field("admission_operation", &"[redacted]")
            .field("rejection_operation", &"[redacted]")
            .field("lease", &self.lease)
            .field("recovery_manifest_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramMutationAdmissionOutcomeV2 {
    AppliedExact,
    CommittedRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramMutationAdmissionFailureClassV2 {
    DefinitelyNotSubmitted,
    Unknown,
}

pub struct PrivateOramMutationAdmissionFailureV2 {
    class: PrivateOramMutationAdmissionFailureClassV2,
    source: StorageError,
}

impl PrivateOramMutationAdmissionFailureV2 {
    pub fn class(&self) -> PrivateOramMutationAdmissionFailureClassV2 {
        self.class
    }

    pub fn into_storage_error(self) -> StorageError {
        self.source
    }
}

impl Debug for PrivateOramMutationAdmissionFailureV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAdmissionFailureV2")
            .field("class", &self.class)
            .field("source", &"[redacted]")
            .finish()
    }
}

impl Dispatcher {
    pub fn new(toc: Arc<TableOfContent>) -> Self {
        Self {
            toc,
            consensus_state: None,
            resharding_enabled: false,
            private_oram_live_admission_registry: Arc::new(Mutex::new(
                PrivateOramLiveAdmissionRegistryV2::default(),
            )),
        }
    }

    pub fn with_consensus(self, state_ref: ConsensusStateRef, resharding_enabled: bool) -> Self {
        Self {
            consensus_state: Some(state_ref),
            resharding_enabled,
            ..self
        }
    }

    /// Get the table of content.
    /// The `_auth` and `_verification_pass` parameter are not used, but it's required to verify caller's possession
    /// of both objects.
    pub fn toc(&self, _auth: &Auth, _verification_pass: &VerificationPass) -> &Arc<TableOfContent> {
        &self.toc
    }

    pub fn consensus_state(&self) -> Option<&ConsensusStateRef> {
        self.consensus_state.as_ref()
    }

    pub fn this_peer_id(&self) -> PeerId {
        self.toc.this_peer_id
    }

    pub fn is_resharding_enabled(&self) -> bool {
        self.resharding_enabled
    }

    /// If `wait_timeout` is not supplied - then default duration will be used.
    ///
    /// This function needs to be called from a runtime with timers enabled.
    ///
    /// ## Cancel safety
    ///
    /// This function is cancel safe.
    ///
    /// On deployments without consensus - a submitted operation is always run to completion.
    pub async fn submit_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
        auth: Auth,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        auth.check_collection_meta_operation(&operation)?;
        self.toc
            .require_private_oram_external_recovery_meta_allowed(&operation)
            .await?;

        // if distributed deployment is enabled
        if let Some(state) = self.consensus_state.as_ref() {
            let start = Instant::now();

            // List of operations to await for collection to be operational
            let mut expect_operations: Vec<ConsensusOperations> = vec![];

            let op = match operation {
                CollectionMetaOperations::CreateCollection(mut op) => {
                    if !op.is_distribution_set() {
                        match op.create_collection.sharding_method.unwrap_or_default() {
                            ShardingMethod::Auto => {
                                // Suggest even distribution of shards across nodes
                                let number_of_peers = state.0.peer_count();

                                let collection_defaults =
                                    self.toc.storage_config.collection.as_ref();

                                let shard_distribution = self.toc.suggest_shard_distribution(
                                    &op,
                                    collection_defaults,
                                    number_of_peers,
                                );

                                // Expect all replicas to become active eventually
                                for (shard_id, peer_ids) in &shard_distribution.distribution {
                                    for peer_id in peer_ids {
                                        expect_operations.push(
                                            ConsensusOperations::initialize_replica(
                                                op.collection_name.clone(),
                                                *shard_id,
                                                *peer_id,
                                            ),
                                        );
                                    }
                                }

                                op.set_distribution(shard_distribution);
                            }
                            ShardingMethod::Custom => {
                                // If custom sharding is used - we don't create any shards in advance
                                let empty_distribution = ShardDistributionProposal::empty();
                                op.set_distribution(empty_distribution);
                            }
                        }
                    }

                    if let Some(uuid) = &op.create_collection.uuid {
                        if op.should_preserve_explicit_uuid() {
                            log::info!(
                                "Preserving collection UUID {uuid} for internal create collection {} operation",
                                op.collection_name,
                            );
                        } else {
                            log::warn!(
                                "Collection UUID {uuid} explicitly specified, \
                                 when proposing create collection {} operation, \
                                 new random UUID will be generated instead",
                                op.collection_name,
                            );
                        }
                    }

                    if !op.should_preserve_explicit_uuid() || op.create_collection.uuid.is_none() {
                        op.create_collection.uuid = Some(uuid::Uuid::new_v4());
                    }

                    CollectionMetaOperations::CreateCollection(op)
                }
                CollectionMetaOperations::CreateShardKey(op) => {
                    CollectionMetaOperations::CreateShardKey(op)
                }

                op => op,
            };

            let operation_awaiter =
                // If explicit timeout is set - then we need to wait for all expected operations.
                // E.g. in case of `CreateCollection` we will explicitly wait for all replicas to be activated.
                // We need to register receivers(by calling the function) before submitting the operation.
                if !expect_operations.is_empty() {
                    Some(state.await_for_multiple_operations(expect_operations, wait_timeout))
                } else {
                    None
                };

            let do_sync_nodes = match &op {
                // Sync nodes after collection or shard key creation
                CollectionMetaOperations::CreateCollection(_)
                | CollectionMetaOperations::CreateShardKey(_) => true,

                // Sync nodes when creating or renaming collection aliases
                CollectionMetaOperations::ChangeAliases(changes) => {
                    changes.actions.iter().any(|change| match change {
                        AliasOperations::CreateAlias(_) | AliasOperations::RenameAlias(_) => true,
                        AliasOperations::DeleteAlias(_) => false,
                    })
                }

                // TODO(resharding): Do we need/want to synchronize `Resharding` operations?
                CollectionMetaOperations::Resharding(_, _) => false,

                // No need to sync nodes for other operations
                CollectionMetaOperations::UpdateCollection(_)
                | CollectionMetaOperations::ApplyCryptoMigration(_)
                | CollectionMetaOperations::DeleteCollection(_)
                | CollectionMetaOperations::TransferShard(_, _)
                | CollectionMetaOperations::SetShardReplicaState(_)
                | CollectionMetaOperations::DropShardKey(_)
                | CollectionMetaOperations::CreatePayloadIndex(_)
                | CollectionMetaOperations::DropPayloadIndex(_)
                | CollectionMetaOperations::Nop { .. } => false,

                #[cfg(feature = "staging")]
                CollectionMetaOperations::TestSlowDown(_) => false,
            };

            // During creation of a shard key, we must ensure that all replicas are ready to accept
            // write requests, so the client-side script can rely on the fact that the
            // shard creation request is complete.
            //
            // For this we explicitly wait for validation this, we do following checks:
            //
            // 1. Wait for consensus to accept shard create operation on current machine.
            //    ( here newly created shards should start to report state change from `Inactive` to `Active` )
            // 2. Wait for all local shards to become active.
            //    ( At this stage we are sure, that all consensus operations are created, but might not be applied everywhere )
            // 3. Wait for all remote peers to have at least the same state as the current peer.
            //    ( So we are sure, that all remote peers have also switched to `Active` state )
            let create_shard_key = match &op {
                CollectionMetaOperations::CreateShardKey(op) => {
                    let collection_name: CollectionName = op.collection_name.clone();
                    let shard_key = op.shard_key.clone();
                    let initial_state = op.initial_state;
                    Some((collection_name, shard_key, initial_state))
                }
                _ => None,
            };

            // Send operation to consensus and wait for it to be applied locally
            let res = state
                .propose_consensus_op_with_await(
                    ConsensusOperations::CollectionMeta(Box::new(op)),
                    wait_timeout,
                )
                .await?;

            if let Some(operation_awaiter) = operation_awaiter {
                // Actually await for expected operations to complete on the consensus
                match operation_awaiter.await {
                    Ok(Ok(())) => {} // all good
                    Ok(Err(err)) => {
                        log::warn!("Not all expected operations were completed: {err}")
                    }
                    Err(err) => log::warn!("Awaiting for expected operations timed out: {err}"),
                }
            }

            // Wait for shards activation
            if let Some((collection_name, shard_key, initial_state)) = create_shard_key
                && initial_state.is_none()
            {
                // Only do if initial state is not set because we only wanted to wait for Active since introducing
                // the Initial state which needs a transition to Active.
                let remaining_timeout =
                    wait_timeout.map(|timeout| timeout.saturating_sub(start.elapsed()));
                self.wait_for_shard_key_activation(collection_name, shard_key, remaining_timeout)
                    .await?;
            };

            // On some operations, synchronize all nodes to ensure all are ready for point operations
            if do_sync_nodes {
                let remaining_timeout =
                    wait_timeout.map(|timeout| timeout.saturating_sub(start.elapsed()));
                if let Err(err) = self.await_consensus_sync(remaining_timeout).await {
                    log::warn!(
                        "Failed to synchronize all nodes after collection operation in time, some nodes may not be ready: {err}",
                    );
                }
            }

            Ok(res)
        } else {
            let toc = self.toc.clone();
            tokio::task::spawn(async move { toc.perform_collection_meta_op(operation).await })
                .await?
        }
    }

    pub fn cluster_status(&self) -> ClusterStatus {
        match self.consensus_state.as_ref() {
            Some(state) => state.cluster_status(),
            None => ClusterStatus::Disabled,
        }
    }

    pub async fn submit_private_oram_epoch_cas(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        match self
            .submit_private_oram_epoch_cas_outcome(operation, wait_timeout)
            .await
        {
            PrivateOramEpochCasOutcome::Applied => Ok(()),
            PrivateOramEpochCasOutcome::Rejected(error)
            | PrivateOramEpochCasOutcome::Indeterminate(error) => Err(error),
        }
    }

    /// Proposes the epoch CAS and reports a definitive or indeterminate outcome.
    pub async fn submit_private_oram_epoch_cas_outcome(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        wait_timeout: Option<Duration>,
    ) -> PrivateOramEpochCasOutcome {
        let Some(consensus_state) = self.consensus_state.as_ref() else {
            return PrivateOramEpochCasOutcome::Rejected(StorageError::service_error(
                "private ORAM consensus epoch/root CAS requires distributed mode",
            ));
        };
        match consensus_state
            .propose_consensus_op_with_outcome(
                ConsensusOperations::CompareAndSwapPrivateOramEpoch(operation),
                wait_timeout,
            )
            .await
        {
            ConsensusProposalOutcome::Applied(receipt) if receipt.applied() => {
                PrivateOramEpochCasOutcome::Applied
            }
            ConsensusProposalOutcome::Applied(_) => {
                PrivateOramEpochCasOutcome::Rejected(StorageError::service_error(
                    "private ORAM consensus epoch/root CAS was not applied",
                ))
            }
            ConsensusProposalOutcome::NotSubmitted(error) => {
                PrivateOramEpochCasOutcome::Rejected(error)
            }
            // `Failed` means the entry committed and this peer's apply returned an error. A
            // service error there is local (persistence fenced, indeterminate save) while the
            // other replicas may have applied the CAS, so it must not be read as a rejection
            // that licenses rolling prepared writebacks back.
            ConsensusProposalOutcome::Failed(error @ StorageError::ServiceError { .. }) => {
                PrivateOramEpochCasOutcome::Indeterminate(error)
            }
            ConsensusProposalOutcome::Failed(error) => PrivateOramEpochCasOutcome::Rejected(error),
            ConsensusProposalOutcome::Indeterminate(error) => {
                PrivateOramEpochCasOutcome::Indeterminate(error)
            }
        }
    }

    /// Drives the epoch CAS to a definitive answer where possible.
    ///
    /// An unresolved proposal (timed-out wait, dropped apply channel) is re-proposed: the retry
    /// is ordered after the original entry, so it either applies (the original never did) or is
    /// rejected because the consensus record already carries `new` (the original committed).
    /// Only when every attempt stays unresolved does this return `StorageError::Timeout`, and
    /// callers holding prepared writebacks must then keep them for recovery instead of aborting.
    pub async fn resolve_private_oram_epoch_cas(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let mut last_indeterminate = None;
        for attempt in 0..PRIVATE_ORAM_EPOCH_CAS_RESOLVE_ATTEMPTS {
            match self
                .submit_private_oram_epoch_cas_outcome(operation.clone(), wait_timeout)
                .await
            {
                PrivateOramEpochCasOutcome::Applied => return Ok(()),
                PrivateOramEpochCasOutcome::Rejected(error) => {
                    if self.private_oram_consensus_epoch(&operation.key)?.as_ref()
                        == Some(&operation.new)
                    {
                        // An earlier unresolved attempt (or the same write-back's earlier
                        // proposal) did commit; this attempt lost the CAS against the state it
                        // produced.
                        log::debug!(
                            "private ORAM epoch CAS was rejected on attempt {} against its own committed state",
                            attempt + 1
                        );
                        return Ok(());
                    }
                    return Err(error);
                }
                PrivateOramEpochCasOutcome::Indeterminate(error) => {
                    log::warn!(
                        "private ORAM epoch CAS outcome is unresolved (attempt {}): {error}",
                        attempt + 1
                    );
                    last_indeterminate = Some(error);
                }
            }
        }
        let error = last_indeterminate
            .map(|error| error.to_string())
            .unwrap_or_default();
        Err(StorageError::Timeout {
            description: format!(
                "{PRIVATE_ORAM_WRITEBACK_INDETERMINATE}: the consensus epoch CAS did not resolve; the prepared writeback is retained for recovery ({error})"
            ),
        })
    }

    pub async fn submit_private_oram_session_lease_cas(
        &self,
        operation: CompareAndSwapPrivateOramSessionLease,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus session lease CAS requires distributed mode",
            )
        })?;
        let applied = consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::CompareAndSwapPrivateOramSessionLease(operation),
                wait_timeout,
            )
            .await?;
        if !applied {
            return Err(StorageError::service_error(
                "private ORAM consensus session lease CAS was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_layout_cas(
        &self,
        operation: CompareAndSwapPrivateOramLayout,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus layout CAS requires distributed mode",
            )
        })?;
        let applied = consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::CompareAndSwapPrivateOramLayout(operation),
                wait_timeout,
            )
            .await?;
        if !applied {
            return Err(StorageError::service_error(
                "private ORAM consensus layout CAS was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_external_recovery(
        &self,
        operation: PrivateOramExternalRecoveryOperation,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM external recovery operation requires distributed mode",
            )
        })?;
        let applied = consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::ApplyPrivateOramExternalRecovery(operation),
                wait_timeout,
            )
            .await?;
        if !applied {
            return Err(StorageError::service_error(
                "private ORAM external recovery operation was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_collection_layout_transition(
        &self,
        transition: PrivateOramCollectionLayoutTransition,
        auth: Auth,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        auth.check_collection_meta_operation(&transition.collection_meta)?;
        self.toc
            .require_private_oram_external_recovery_meta_allowed(&transition.collection_meta)
            .await?;
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM collection layout transition requires distributed mode",
            )
        })?;
        consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::ApplyPrivateOramCollectionLayout(transition),
                wait_timeout,
            )
            .await
    }

    pub async fn submit_private_oram_shard_transfer_start(
        &self,
        operation: PrivateOramShardTransferStart,
        auth: Auth,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        auth.check_collection_meta_operation(&operation.collection_meta)?;
        self.toc
            .require_private_oram_external_recovery_meta_allowed(&operation.collection_meta)
            .await?;
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM shard transfer layout transition requires distributed mode",
            )
        })?;
        consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::StartPrivateOramShardTransfer(operation),
                wait_timeout,
            )
            .await
    }

    pub async fn submit_private_oram_resharding_start(
        &self,
        operation: PrivateOramReshardingOperation,
        auth: Auth,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        auth.check_collection_meta_operation(&operation.collection_meta)?;
        self.toc
            .require_private_oram_external_recovery_meta_allowed(&operation.collection_meta)
            .await?;
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM resharding layout transition requires distributed mode",
            )
        })?;
        consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::StartPrivateOramResharding(operation),
                wait_timeout,
            )
            .await
    }

    pub async fn submit_private_oram_resharding_finish(
        &self,
        operation: PrivateOramReshardingOperation,
        auth: Auth,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        auth.check_collection_meta_operation(&operation.collection_meta)?;
        self.toc
            .require_private_oram_external_recovery_meta_allowed(&operation.collection_meta)
            .await?;
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM resharding layout transition requires distributed mode",
            )
        })?;
        consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::FinishPrivateOramResharding(operation),
                wait_timeout,
            )
            .await
    }

    pub fn private_hnsw_oram_writeback_cas(
        &self,
        collection_id: String,
        vector_name: String,
        writeback: &PrivateHnswOramConsensusWriteback,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        self.private_oram_writeback_cas(
            PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: vector_name,
            },
            writeback.old.index_epoch,
            &writeback.old.root_hash,
            writeback.new.index_epoch,
            &writeback.new.root_hash,
            &writeback.writeback_digest,
        )
    }

    pub fn private_result_oram_writeback_cas(
        &self,
        collection_id: String,
        writeback: &PrivateResultOramConsensusWriteback,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        self.private_oram_writeback_cas(
            PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            },
            writeback.old.index_epoch,
            &writeback.old.root_hash,
            writeback.new.index_epoch,
            &writeback.new.root_hash,
            &writeback.writeback_digest,
        )
    }

    pub fn private_oram_initial_epoch_cas(
        &self,
        key: PrivateOramEpochKey,
        index_epoch: u64,
        root_hash: String,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        validate_private_oram_root_hash(&root_hash)?;
        Ok(CompareAndSwapPrivateOramEpoch {
            key,
            expected: None,
            new: PrivateOramConsensusEpoch {
                index_epoch,
                root_hash,
                writeback_digest: None,
            },
        })
    }

    fn private_oram_writeback_cas(
        &self,
        key: PrivateOramEpochKey,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        writeback_digest: &str,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        let expected = self.private_oram_consensus_epoch(&key)?.ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM consensus writeback ownership is not initialized",
            )
        })?;
        if expected.index_epoch != old_epoch || expected.root_hash != old_root_hash {
            return Err(StorageError::bad_request(
                "private ORAM local writeback does not match consensus epoch/root",
            ));
        }
        Ok(CompareAndSwapPrivateOramEpoch {
            key,
            expected: Some(expected),
            new: PrivateOramConsensusEpoch {
                index_epoch: new_epoch,
                root_hash: new_root_hash.to_string(),
                writeback_digest: Some(writeback_digest.to_string()),
            },
        })
    }

    /// Coordinates a private ORAM writeback around the replicated epoch/root commit point.
    ///
    /// `prepare` must durably persist an owner-signed, idempotent local writeback journal.
    /// `abort` must remove that journal only while the active local view is still unchanged.
    /// `finalize` must be safe to retry after the exact consensus CAS has already applied.
    pub async fn coordinate_private_oram_writeback<Prepare, Abort, Finalize>(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        wait_timeout: Option<Duration>,
        prepare: Prepare,
        abort: Abort,
        finalize: Finalize,
    ) -> Result<(), StorageError>
    where
        Prepare: FnOnce() -> Result<(), StorageError>,
        Abort: FnOnce() -> Result<(), StorageError>,
        Finalize: FnOnce() -> Result<(), StorageError>,
    {
        prepare()?;
        if let Err(consensus_error) = self
            .resolve_private_oram_epoch_cas(operation, wait_timeout)
            .await
        {
            if private_oram_writeback_outcome_indeterminate(&consensus_error) {
                // The CAS may still commit: rolling back now could orphan the new epoch.
                return Err(consensus_error);
            }
            abort()?;
            return Err(consensus_error);
        }
        finalize()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_replicated_private_oram_writeback<
        PrepareLocal,
        PrepareReplicas,
        PrepareReplicasFuture,
        AbortLocal,
        AbortReplicas,
        AbortReplicasFuture,
        FinalizeLocal,
        FinalizeReplicas,
        FinalizeReplicasFuture,
    >(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        required_replica_peers: &BTreeSet<PeerId>,
        wait_timeout: Option<Duration>,
        prepare_local: PrepareLocal,
        prepare_replicas: PrepareReplicas,
        abort_local: AbortLocal,
        abort_replicas: AbortReplicas,
        finalize_local: FinalizeLocal,
        finalize_replicas: FinalizeReplicas,
    ) -> Result<(), StorageError>
    where
        PrepareLocal: FnOnce() -> Result<(), StorageError>,
        PrepareReplicas: FnOnce() -> PrepareReplicasFuture,
        PrepareReplicasFuture:
            Future<Output = Result<Vec<PrivateOramReplicaPrepareAck>, StorageError>>,
        AbortLocal: FnOnce() -> Result<(), StorageError>,
        AbortReplicas: FnOnce() -> AbortReplicasFuture,
        AbortReplicasFuture: Future<Output = Result<(), StorageError>>,
        FinalizeLocal: FnOnce() -> Result<(), StorageError>,
        FinalizeReplicas: FnOnce() -> FinalizeReplicasFuture,
        FinalizeReplicasFuture: Future<Output = Result<(), StorageError>>,
    {
        let expected_digest = operation.new.writeback_digest.as_deref().ok_or_else(|| {
            StorageError::bad_request(
                "replicated private ORAM writeback requires a consensus digest",
            )
        })?;
        validate_private_oram_writeback_digest(expected_digest)?;
        prepare_local()?;

        let replica_acks = match prepare_replicas().await {
            Ok(replica_acks) => replica_acks,
            Err(prepare_error) => {
                let remote_abort = abort_replicas().await;
                let local_abort = abort_local();
                remote_abort?;
                local_abort?;
                return Err(prepare_error);
            }
        };
        if let Err(ack_error) = validate_private_oram_replica_prepare_acks(
            required_replica_peers,
            &replica_acks,
            expected_digest,
        ) {
            let remote_abort = abort_replicas().await;
            let local_abort = abort_local();
            remote_abort?;
            local_abort?;
            return Err(ack_error);
        }

        if let Err(consensus_error) = self
            .resolve_private_oram_epoch_cas(operation, wait_timeout)
            .await
        {
            if private_oram_writeback_outcome_indeterminate(&consensus_error) {
                // The CAS may still commit: aborting the prepared journals now could leave
                // consensus at the new epoch with no store holding the buckets. Keep every
                // prepared replica for the recovery path instead.
                return Err(consensus_error);
            }
            let remote_abort = abort_replicas().await;
            let local_abort = abort_local();
            remote_abort?;
            local_abort?;
            return Err(consensus_error);
        }

        finalize_replicas().await?;
        finalize_local()
    }

    /// Resolve the exact peers that must durably prepare a collection-local private ORAM
    /// writeback. Private ORAM storage is not shard-local, so every peer that owns any fully
    /// active shard replica must hold the same encrypted store.
    pub async fn private_oram_replication_peers(
        &self,
        collection_name: &CollectionName,
    ) -> Result<BTreeSet<PeerId>, StorageError> {
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        self.toc
            .require_private_oram_snapshot_recovery_complete(&collection)?;
        let shard_holder = collection.shards_holder().read_owned().await;
        let shard_peer_states = shard_holder
            .all_shards()
            .map(|replica_set| replica_set.peers())
            .collect::<Vec<_>>();
        let peers =
            derive_private_oram_replication_peers(&shard_peer_states, self.toc.this_peer_id)?;

        let known_addresses = self.toc.get_channel_service().id_to_address.read();
        if peers.iter().any(|peer_id| {
            *peer_id != self.toc.this_peer_id && !known_addresses.contains_key(peer_id)
        }) {
            return Err(StorageError::service_error(
                "private ORAM replication peer address is unavailable",
            ));
        }
        Ok(peers)
    }

    pub async fn private_oram_stable_shard_layout_digest(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        let stable_collection_id = config.stable_crypto_id(collection_name).map_err(|_| {
            StorageError::bad_request("private ORAM consensus layout identity is invalid")
        })?;
        if stable_collection_id != collection_id {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout identity is invalid",
            ));
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some()
            || !shard_holder.get_transfers(|_| true).is_empty()
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout requires a stable shard layout",
            ));
        }
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            if peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active) {
                return Err(StorageError::bad_request(
                    "private ORAM consensus layout requires fully active shard replicas",
                ));
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            shard_holder.get_sharding_method(),
            &entries,
        )?;
        if !owner_peer_ids.contains(&self.toc.this_peer_id) {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout coordinator must own an active shard replica",
            ));
        }
        Ok((owner_peer_ids, layout_digest))
    }

    async fn private_oram_shard_transfer_pre_layout_digest(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        transfer: &ShardTransfer,
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        let stable_collection_id = config.stable_crypto_id(collection_name).map_err(|_| {
            StorageError::bad_request("private ORAM consensus layout identity is invalid")
        })?;
        if stable_collection_id != collection_id {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout identity is invalid",
            ));
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some()
            || !shard_holder.get_transfers(|_| true).is_empty()
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout requires a stable shard layout",
            ));
        }
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: private_oram_shard_transfer_pre_layout_owners(
                    shard_id,
                    &replica_set.peers(),
                    transfer,
                )?,
            });
        }
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            shard_holder.get_sharding_method(),
            &entries,
        )?;
        if !owner_peer_ids.contains(&self.toc.this_peer_id) {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout coordinator must own an active shard replica",
            ));
        }
        Ok((owner_peer_ids, layout_digest))
    }

    pub async fn private_oram_reserved_layout_candidate(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        keys: &[PrivateOramEpochKey],
        reservation_lease_id_hash: &str,
        generation: u64,
        transfer: Option<&ShardTransfer>,
    ) -> Result<PrivateOramConsensusLayout, StorageError> {
        if generation == 0
            || keys.is_empty()
            || decode_private_oram_sha256_digest(reservation_lease_id_hash).is_none()
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout reservation is invalid",
            ));
        }
        let now_unix = current_private_oram_unix_secs()?;
        let mut states = Vec::with_capacity(keys.len());
        for key in keys {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) {
                return Err(invalid_private_oram_layout_reservation());
            }
            let state = self.private_oram_consensus_epoch(key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus layout index state is incomplete")
            })?;
            states.push((key.clone(), state));
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)?;
        let (owner_peer_ids, layout_digest) = match transfer {
            Some(transfer) => {
                self.private_oram_shard_transfer_pre_layout_digest(
                    collection_name,
                    collection_id,
                    transfer,
                )
                .await?
            }
            None => {
                self.private_oram_stable_shard_layout_digest(collection_name, collection_id)
                    .await?
            }
        };

        let now_unix = current_private_oram_unix_secs()?;
        for (key, expected_state) in &states {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) || self.private_oram_consensus_epoch(key)?.as_ref() != Some(expected_state)
            {
                return Err(invalid_private_oram_layout_reservation());
            }
        }

        Ok(PrivateOramConsensusLayout {
            generation,
            owner_peer_ids,
            layout_digest,
            index_state_digest,
        })
    }

    pub async fn private_oram_reserved_replica_removal_layouts(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        keys: &[PrivateOramEpochKey],
        reservation_lease_id_hash: &str,
        generation: u64,
        shard_id: ShardId,
        peer_id: PeerId,
    ) -> Result<
        (
            PrivateOramConsensusLayout,
            PrivateOramConsensusLayout,
            Vec<PrivateOramLayoutLeaseBinding>,
        ),
        StorageError,
    > {
        let current = self
            .private_oram_reserved_layout_candidate(
                collection_name,
                collection_id,
                keys,
                reservation_lease_id_hash,
                generation,
                None,
            )
            .await?;
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        if config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_layout_transition())?
            != collection_id
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
        let sharding_method = shard_holder.get_sharding_method();
        let (current_owners, current_layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, &entries)?;
        if current.owner_peer_ids != current_owners
            || current.layout_digest != current_layout_digest
        {
            return Err(invalid_private_oram_layout_transition());
        }
        let entry = entries
            .iter_mut()
            .find(|entry| entry.shard_id == shard_id)
            .ok_or_else(invalid_private_oram_layout_transition)?;
        let owner_index = entry
            .owner_peer_ids
            .iter()
            .position(|owner| *owner == peer_id)
            .ok_or_else(invalid_private_oram_layout_transition)?;
        entry.owner_peer_ids.remove(owner_index);
        let (new_owner_peer_ids, new_layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, &entries)?;
        drop(shard_holder);
        if !new_owner_peer_ids.contains(&self.toc.this_peer_id) {
            return Err(invalid_private_oram_layout_transition());
        }

        let now_unix = current_private_oram_unix_secs()?;
        let mut states = Vec::with_capacity(keys.len());
        let mut leases = Vec::with_capacity(keys.len());
        for key in keys {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) {
                return Err(invalid_private_oram_layout_reservation());
            }
            let state = self.private_oram_consensus_epoch(key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus layout index state is incomplete")
            })?;
            states.push((key.clone(), state));
            leases.push(PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease,
            });
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)?;
        if current.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_layout_reservation());
        }
        let new_generation = generation
            .checked_add(1)
            .ok_or_else(invalid_private_oram_layout_transition)?;
        let new = PrivateOramConsensusLayout {
            generation: new_generation,
            owner_peer_ids: new_owner_peer_ids,
            layout_digest: new_layout_digest,
            index_state_digest,
        };
        Ok((current, new, leases))
    }

    pub async fn private_oram_reserved_shard_key_layouts(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        keys: &[PrivateOramEpochKey],
        reservation_lease_id_hash: &str,
        generation: u64,
        preinstalled_new_owner_peer_ids: &[PeerId],
        collection_meta: &CollectionMetaOperations,
    ) -> Result<
        (
            PrivateOramConsensusLayout,
            PrivateOramConsensusLayout,
            Vec<PrivateOramLayoutLeaseBinding>,
            PrivateOramShardKeyLayoutChange,
        ),
        StorageError,
    > {
        let current = self
            .private_oram_reserved_layout_candidate(
                collection_name,
                collection_id,
                keys,
                reservation_lease_id_hash,
                generation,
                None,
            )
            .await?;
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        if config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_layout_transition())?
            != collection_id
        {
            return Err(invalid_private_oram_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.get_sharding_method() != ShardingMethod::Custom
            || shard_holder.resharding_state().is_some()
            || !shard_holder.get_transfers(|_| true).is_empty()
        {
            return Err(invalid_private_oram_layout_transition());
        }
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            if peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active) {
                return Err(invalid_private_oram_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }
        let (current_owners, current_layout_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &entries,
        )?;
        if current.owner_peer_ids != current_owners
            || current.layout_digest != current_layout_digest
        {
            return Err(invalid_private_oram_layout_transition());
        }

        let change = match collection_meta {
            CollectionMetaOperations::CreateShardKey(operation)
                if operation.collection_name == collection_name.as_str()
                    && operation.initial_state == Some(ReplicaState::Active) =>
            {
                let max_shard_id = entries
                    .iter()
                    .map(|entry| entry.shard_id)
                    .max()
                    .ok_or_else(invalid_private_oram_layout_transition)?;
                let changed_entries = operation
                    .placement
                    .iter()
                    .enumerate()
                    .map(|(offset, owners)| {
                        let offset = ShardId::try_from(offset)
                            .map_err(|_| invalid_private_oram_layout_transition())?;
                        let shard_id = max_shard_id
                            .checked_add(offset)
                            .and_then(|shard_id| shard_id.checked_add(1))
                            .ok_or_else(invalid_private_oram_layout_transition)?;
                        Ok(PrivateOramShardLayoutEntry {
                            shard_id,
                            shard_key: Some(operation.shard_key.clone()),
                            owner_peer_ids: owners.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, StorageError>>()?;
                PrivateOramShardKeyLayoutChange {
                    kind: PrivateOramShardKeyLayoutChangeKind::Create,
                    shard_key: operation.shard_key.clone(),
                    entries: changed_entries,
                    preinstalled_new_owner_peer_ids: preinstalled_new_owner_peer_ids.to_vec(),
                }
            }
            CollectionMetaOperations::DropShardKey(operation)
                if operation.collection_name == collection_name.as_str() =>
            {
                PrivateOramShardKeyLayoutChange {
                    kind: PrivateOramShardKeyLayoutChangeKind::Drop,
                    shard_key: operation.shard_key.clone(),
                    entries: entries
                        .iter()
                        .filter(|entry| entry.shard_key.as_ref() == Some(&operation.shard_key))
                        .cloned()
                        .collect(),
                    preinstalled_new_owner_peer_ids: preinstalled_new_owner_peer_ids.to_vec(),
                }
            }
            _ => return Err(invalid_private_oram_layout_transition()),
        };
        let post_entries = private_oram_shard_key_post_layout_entries(
            collection_id,
            ShardingMethod::Custom,
            &entries,
            &change,
        )?;
        let (new_owner_peer_ids, new_layout_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &post_entries,
        )?;
        drop(shard_holder);
        if !new_owner_peer_ids.contains(&self.toc.this_peer_id) {
            return Err(invalid_private_oram_layout_transition());
        }

        let now_unix = current_private_oram_unix_secs()?;
        let mut states = Vec::with_capacity(keys.len());
        let mut leases = Vec::with_capacity(keys.len());
        for key in keys {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) {
                return Err(invalid_private_oram_layout_reservation());
            }
            let state = self.private_oram_consensus_epoch(key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus layout index state is incomplete")
            })?;
            states.push((key.clone(), state));
            leases.push(PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease,
            });
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)?;
        if current.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_layout_reservation());
        }
        let new = PrivateOramConsensusLayout {
            generation: generation
                .checked_add(1)
                .ok_or_else(invalid_private_oram_layout_transition)?,
            owner_peer_ids: new_owner_peer_ids,
            layout_digest: new_layout_digest,
            index_state_digest,
        };
        Ok((current, new, leases, change))
    }

    pub async fn private_oram_reserved_shard_transfer_layouts(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        keys: &[PrivateOramEpochKey],
        reservation_lease_id_hash: &str,
        generation: u64,
        transfer: &ShardTransfer,
    ) -> Result<
        (
            PrivateOramConsensusLayout,
            PrivateOramConsensusLayout,
            Vec<PrivateOramLayoutLeaseBinding>,
            Vec<(PrivateOramEpochKey, PrivateOramConsensusEpoch)>,
        ),
        StorageError,
    > {
        let current = self
            .private_oram_reserved_layout_candidate(
                collection_name,
                collection_id,
                keys,
                reservation_lease_id_hash,
                generation,
                Some(transfer),
            )
            .await?;
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        if config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_layout_transition())?
            != collection_id
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
        for (shard_id, replica_set) in shard_holder.get_shards() {
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: private_oram_shard_transfer_pre_layout_owners(
                    shard_id,
                    &replica_set.peers(),
                    transfer,
                )?,
            });
        }
        let sharding_method = shard_holder.get_sharding_method();
        let (current_owners, current_layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, &entries)?;
        if current.owner_peer_ids != current_owners
            || current.layout_digest != current_layout_digest
        {
            return Err(invalid_private_oram_layout_transition());
        }
        let (new_owner_peer_ids, new_layout_digest) =
            canonical_private_oram_shard_transfer_post_layout_digest(
                collection_id,
                sharding_method,
                &entries,
                transfer,
            )?;
        drop(shard_holder);

        let now_unix = current_private_oram_unix_secs()?;
        let mut states = Vec::with_capacity(keys.len());
        let mut leases = Vec::with_capacity(keys.len());
        for key in keys {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) {
                return Err(invalid_private_oram_layout_reservation());
            }
            let state = self.private_oram_consensus_epoch(key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus layout index state is incomplete")
            })?;
            states.push((key.clone(), state));
            leases.push(PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease,
            });
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)?;
        if current.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_layout_reservation());
        }
        let new = PrivateOramConsensusLayout {
            generation: generation
                .checked_add(1)
                .ok_or_else(invalid_private_oram_layout_transition)?,
            owner_peer_ids: new_owner_peer_ids,
            layout_digest: new_layout_digest,
            index_state_digest,
        };
        Ok((current, new, leases, states))
    }

    pub async fn private_oram_reserved_resharding_start_transition(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        keys: &[PrivateOramEpochKey],
        reservation_lease_id_hash: &str,
        generation: u64,
        resharding_key: &ReshardKey,
    ) -> Result<
        (
            PrivateOramReshardingLayoutTransition,
            Vec<PrivateOramLayoutLeaseBinding>,
        ),
        StorageError,
    > {
        let current = self
            .private_oram_reserved_layout_candidate(
                collection_name,
                collection_id,
                keys,
                reservation_lease_id_hash,
                generation,
                None,
            )
            .await?;
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        if config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?
            != collection_id
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some()
            || !shard_holder.get_transfers(|_| true).is_empty()
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            if peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active) {
                return Err(invalid_private_oram_resharding_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }
        let sharding_method = shard_holder.get_sharding_method();
        let (current_owners, current_layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, &entries)
                .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        if current.owner_peer_ids != current_owners
            || current.layout_digest != current_layout_digest
            || !current_owners.contains(&self.toc.this_peer_id)
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let target_shard_owner_peer_ids = match resharding_key.direction {
            collection::operations::cluster_ops::ReshardingDirection::Up => {
                vec![resharding_key.peer_id]
            }
            collection::operations::cluster_ops::ReshardingDirection::Down => {
                let mut owners = entries
                    .iter()
                    .find(|entry| entry.shard_id == resharding_key.shard_id)
                    .filter(|entry| entry.shard_key == resharding_key.shard_key)
                    .map(|entry| entry.owner_peer_ids.clone())
                    .ok_or_else(invalid_private_oram_resharding_layout_transition)?;
                owners.sort_unstable();
                if !owners.contains(&resharding_key.peer_id) {
                    return Err(invalid_private_oram_resharding_layout_transition());
                }
                owners
            }
        };
        let (new_owner_peer_ids, new_layout_digest) =
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                sharding_method,
                &entries,
                resharding_key,
            )
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        drop(shard_holder);
        if !new_owner_peer_ids.contains(&self.toc.this_peer_id) {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let now_unix = current_private_oram_unix_secs()?;
        let mut states = Vec::with_capacity(keys.len());
        let mut leases = Vec::with_capacity(keys.len());
        for key in keys {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) {
                return Err(invalid_private_oram_layout_reservation());
            }
            let state = self.private_oram_consensus_epoch(key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus layout index state is incomplete")
            })?;
            states.push((key.clone(), state.clone()));
            leases.push(PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease,
            });
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        if current.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_layout_reservation());
        }
        let new = PrivateOramConsensusLayout {
            generation: generation
                .checked_add(1)
                .ok_or_else(invalid_private_oram_resharding_layout_transition)?,
            owner_peer_ids: new_owner_peer_ids,
            layout_digest: new_layout_digest,
            index_state_digest,
        };

        Ok((
            PrivateOramReshardingLayoutTransition {
                resharding_key: resharding_key.clone(),
                target_shard_owner_peer_ids,
                layout: CompareAndSwapPrivateOramLayout {
                    key: PrivateOramLayoutKey {
                        collection_id: collection_id.to_string(),
                    },
                    expected: Some(current),
                    new,
                },
                index_states: states
                    .into_iter()
                    .map(|(key, state)| PrivateOramLayoutIndexStateBinding { key, state })
                    .collect(),
            },
            leases,
        ))
    }

    pub async fn private_oram_reserved_resharding_finish_transition(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        keys: &[PrivateOramEpochKey],
        reservation_lease_id_hash: &str,
        generation: u64,
        resharding_key: &ReshardKey,
    ) -> Result<
        (
            PrivateOramReshardingLayoutTransition,
            Vec<PrivateOramLayoutLeaseBinding>,
        ),
        StorageError,
    > {
        if generation == 0
            || keys.is_empty()
            || decode_private_oram_sha256_digest(reservation_lease_id_hash).is_none()
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let config = collection.config_snapshot().await;
        if config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?
            != collection_id
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if !shard_holder.get_transfers(|_| true).is_empty()
            || !shard_holder.resharding_state().is_some_and(|state| {
                state.matches(resharding_key)
                    && state.stage == ReshardingStage::WriteHashRingCommitted
            })
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            if peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active) {
                return Err(invalid_private_oram_resharding_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }
        let target_entry = entries
            .iter()
            .find(|entry| entry.shard_id == resharding_key.shard_id)
            .filter(|entry| entry.shard_key == resharding_key.shard_key)
            .ok_or_else(invalid_private_oram_resharding_layout_transition)?;
        let mut target_shard_owner_peer_ids = target_entry.owner_peer_ids.clone();
        target_shard_owner_peer_ids.sort_unstable();
        if !target_shard_owner_peer_ids.contains(&resharding_key.peer_id)
            || matches!(
                resharding_key.direction,
                collection::operations::cluster_ops::ReshardingDirection::Up
            ) && target_shard_owner_peer_ids.as_slice() != [resharding_key.peer_id]
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let pre_entries = match resharding_key.direction {
            collection::operations::cluster_ops::ReshardingDirection::Up => entries
                .iter()
                .filter(|entry| entry.shard_id != resharding_key.shard_id)
                .cloned()
                .collect::<Vec<_>>(),
            collection::operations::cluster_ops::ReshardingDirection::Down => entries,
        };
        let sharding_method = shard_holder.get_sharding_method();
        let (expected_owner_peer_ids, expected_layout_digest) =
            canonical_private_oram_shard_layout_digest(
                collection_id,
                sharding_method,
                &pre_entries,
            )
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        let (new_owner_peer_ids, new_layout_digest) =
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                sharding_method,
                &pre_entries,
                resharding_key,
            )
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        drop(shard_holder);
        if !expected_owner_peer_ids.contains(&self.toc.this_peer_id)
            || !new_owner_peer_ids.contains(&self.toc.this_peer_id)
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let now_unix = current_private_oram_unix_secs()?;
        let mut states = Vec::with_capacity(keys.len());
        let mut leases = Vec::with_capacity(keys.len());
        for key in keys {
            let lease = self
                .private_oram_consensus_session_lease(key)?
                .ok_or_else(invalid_private_oram_layout_reservation)?;
            if !private_oram_layout_reservation_matches(
                &lease,
                self.toc.this_peer_id,
                reservation_lease_id_hash,
                now_unix,
            ) {
                return Err(invalid_private_oram_layout_reservation());
            }
            let state = self.private_oram_consensus_epoch(key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus layout index state is incomplete")
            })?;
            states.push((key.clone(), state.clone()));
            leases.push(PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease,
            });
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        let expected = PrivateOramConsensusLayout {
            generation,
            owner_peer_ids: expected_owner_peer_ids,
            layout_digest: expected_layout_digest,
            index_state_digest: index_state_digest.clone(),
        };
        let new = PrivateOramConsensusLayout {
            generation: generation
                .checked_add(1)
                .ok_or_else(invalid_private_oram_resharding_layout_transition)?,
            owner_peer_ids: new_owner_peer_ids,
            layout_digest: new_layout_digest,
            index_state_digest,
        };

        Ok((
            PrivateOramReshardingLayoutTransition {
                resharding_key: resharding_key.clone(),
                target_shard_owner_peer_ids,
                layout: CompareAndSwapPrivateOramLayout {
                    key: PrivateOramLayoutKey {
                        collection_id: collection_id.to_string(),
                    },
                    expected: Some(expected),
                    new,
                },
                index_states: states
                    .into_iter()
                    .map(|(key, state)| PrivateOramLayoutIndexStateBinding { key, state })
                    .collect(),
            },
            leases,
        ))
    }

    /// Require this peer to own at least one active shard replica before it coordinates a
    /// collection-local private ORAM session. Other replicas may be recovering; the stricter
    /// fully-active owner union is resolved only when a replicated writeback or layout change
    /// needs every owner.
    pub async fn require_private_oram_active_owner(
        &self,
        collection_name: &CollectionName,
    ) -> Result<(), StorageError> {
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        self.toc
            .require_private_oram_snapshot_recovery_complete(&collection)?;
        let shard_holder = collection.shards_holder().read_owned().await;
        let shard_peer_states = shard_holder
            .all_shards()
            .map(|replica_set| replica_set.peers())
            .collect::<Vec<_>>();
        validate_private_oram_session_coordinator_topology(
            &shard_peer_states,
            self.toc.this_peer_id,
            shard_holder.resharding_state().is_some(),
            !shard_holder.get_transfers(|_| true).is_empty(),
        )
    }

    pub async fn prepare_private_hnsw_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        collection_name: &str,
        collection_id: &str,
        vector_name: &str,
        batch: &PrivateHnswOramWritebackBatch,
        transition: &PrivateHnswOramConsensusWriteback,
    ) -> Result<Vec<PrivateOramReplicaPrepareAck>, StorageError> {
        self.prepare_private_oram_replicas(
            replica_peers,
            private_hnsw_oram_prepare_request(
                collection_name,
                collection_id,
                vector_name,
                batch,
                transition,
            )?,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_private_hnsw_oram_writeback<PrepareLocal, AbortLocal, FinalizeLocal>(
        &self,
        collection_name: CollectionName,
        collection_id: String,
        vector_name: String,
        batch: PrivateHnswOramWritebackBatch,
        transition: PrivateHnswOramConsensusWriteback,
        wait_timeout: Option<Duration>,
        prepare_local: PrepareLocal,
        abort_local: AbortLocal,
        finalize_local: FinalizeLocal,
    ) -> Result<(), StorageError>
    where
        PrepareLocal: FnOnce() -> Result<(), StorageError>,
        AbortLocal: FnOnce() -> Result<(), StorageError>,
        FinalizeLocal: FnOnce() -> Result<(), StorageError>,
    {
        let operation = self.private_hnsw_oram_writeback_cas(
            collection_id.clone(),
            vector_name.clone(),
            &transition,
        )?;
        let mut replica_peers = self
            .private_oram_replication_peers(&collection_name)
            .await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let completion_request = private_oram_complete_request(
            &collection_name,
            &collection_id,
            PrivateOramReplicationIndexKind::Hnsw,
            &vector_name,
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            &batch.commit_signature.key_id,
        )?;
        let abort_request = completion_request.clone();
        self.coordinate_replicated_private_oram_writeback(
            operation,
            &replica_peers,
            wait_timeout,
            prepare_local,
            || {
                self.prepare_private_hnsw_oram_replicas(
                    &replica_peers,
                    &collection_name,
                    &collection_id,
                    &vector_name,
                    &batch,
                    &transition,
                )
            },
            abort_local,
            || self.complete_private_oram_replicas(&replica_peers, abort_request, true),
            finalize_local,
            || self.complete_private_oram_replicas(&replica_peers, completion_request, false),
        )
        .await
    }

    pub async fn prepare_private_result_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        collection_name: &str,
        collection_id: &str,
        batch: &PrivateResultOramWritebackBatch,
        transition: &PrivateResultOramConsensusWriteback,
    ) -> Result<Vec<PrivateOramReplicaPrepareAck>, StorageError> {
        self.prepare_private_oram_replicas(
            replica_peers,
            private_result_oram_prepare_request(collection_name, collection_id, batch, transition)?,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_private_result_oram_writeback<PrepareLocal, AbortLocal, FinalizeLocal>(
        &self,
        collection_name: CollectionName,
        collection_id: String,
        batch: PrivateResultOramWritebackBatch,
        transition: PrivateResultOramConsensusWriteback,
        wait_timeout: Option<Duration>,
        prepare_local: PrepareLocal,
        abort_local: AbortLocal,
        finalize_local: FinalizeLocal,
    ) -> Result<(), StorageError>
    where
        PrepareLocal: FnOnce() -> Result<(), StorageError>,
        AbortLocal: FnOnce() -> Result<(), StorageError>,
        FinalizeLocal: FnOnce() -> Result<(), StorageError>,
    {
        let operation =
            self.private_result_oram_writeback_cas(collection_id.clone(), &transition)?;
        let mut replica_peers = self
            .private_oram_replication_peers(&collection_name)
            .await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let completion_request = private_oram_complete_request(
            &collection_name,
            &collection_id,
            PrivateOramReplicationIndexKind::Result,
            "",
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            &batch.commit_signature.key_id,
        )?;
        let abort_request = completion_request.clone();
        self.coordinate_replicated_private_oram_writeback(
            operation,
            &replica_peers,
            wait_timeout,
            prepare_local,
            || {
                self.prepare_private_result_oram_replicas(
                    &replica_peers,
                    &collection_name,
                    &collection_id,
                    &batch,
                    &transition,
                )
            },
            abort_local,
            || self.complete_private_oram_replicas(&replica_peers, abort_request, true),
            finalize_local,
            || self.complete_private_oram_replicas(&replica_peers, completion_request, false),
        )
        .await
    }

    pub async fn complete_private_hnsw_oram_recovery_replicas(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        vector_name: &str,
        transition: &PrivateHnswOramConsensusWriteback,
        signing_key_id: &str,
        abort: bool,
    ) -> Result<(), StorageError> {
        self.complete_private_oram_recovery_replicas(
            collection_name,
            collection_id,
            PrivateOramReplicationIndexKind::Hnsw,
            vector_name,
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            signing_key_id,
            abort,
        )
        .await
    }

    pub async fn complete_private_result_oram_recovery_replicas(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        transition: &PrivateResultOramConsensusWriteback,
        signing_key_id: &str,
        abort: bool,
    ) -> Result<(), StorageError> {
        self.complete_private_oram_recovery_replicas(
            collection_name,
            collection_id,
            PrivateOramReplicationIndexKind::Result,
            "",
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            signing_key_id,
            abort,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_private_oram_recovery_replicas(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        index_kind: PrivateOramReplicationIndexKind,
        index_name: &str,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        writeback_digest: &str,
        signing_key_id: &str,
        abort: bool,
    ) -> Result<(), StorageError> {
        let mut replica_peers = self.private_oram_replication_peers(collection_name).await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let request = private_oram_complete_request(
            collection_name,
            collection_id,
            index_kind,
            index_name,
            old_epoch,
            old_root_hash,
            new_epoch,
            new_root_hash,
            writeback_digest,
            signing_key_id,
        )?;
        self.complete_private_oram_replicas(&replica_peers, request, abort)
            .await
    }

    async fn prepare_private_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        request: PreparePrivateOramWritebackRequest,
    ) -> Result<Vec<PrivateOramReplicaPrepareAck>, StorageError> {
        let channel_service = self.toc.get_channel_service();
        let mut pending = replica_peers
            .iter()
            .map(|peer_id| {
                let peer_id = *peer_id;
                let request = request.clone();
                async move {
                    channel_service
                        .prepare_private_oram_writeback(peer_id, request)
                        .await
                        .map(|writeback_digest| PrivateOramReplicaPrepareAck {
                            peer_id,
                            writeback_digest,
                        })
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut acknowledgements = Vec::with_capacity(replica_peers.len());
        let mut first_error = None;
        while let Some(result) = pending.next().await {
            match result {
                Ok(acknowledgement) => acknowledgements.push(acknowledgement),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        Ok(acknowledgements)
    }

    pub async fn complete_private_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        request: CompletePrivateOramWritebackRequest,
        abort: bool,
    ) -> Result<(), StorageError> {
        let channel_service = self.toc.get_channel_service();
        let mut pending = replica_peers
            .iter()
            .map(|peer_id| {
                let peer_id = *peer_id;
                let request = request.clone();
                async move {
                    let result = if abort {
                        channel_service
                            .abort_private_oram_writeback(peer_id, request)
                            .await
                    } else {
                        channel_service
                            .finalize_private_oram_writeback(peer_id, request)
                            .await
                    };
                    result.and_then(|completed| {
                        if abort || completed {
                            Ok(())
                        } else {
                            Err(
                                collection::operations::types::CollectionError::service_error(
                                    format!(
                                        "private ORAM finalize was not completed on peer {peer_id}"
                                    ),
                                ),
                            )
                        }
                    })
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut first_error = None;
        while let Some(result) = pending.next().await {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_private_oram_initial_install(
        &self,
        collection_name: &CollectionName,
        key: PrivateOramEpochKey,
        request: InstallPrivateOramIndexRequest,
        expected_epoch: u64,
        expected_root_hash: &str,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        validate_private_oram_root_hash(expected_root_hash)?;
        let mut replica_peers = self.private_oram_replication_peers(collection_name).await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let channel_service = self.toc.get_channel_service();
        let mut pending = replica_peers
            .iter()
            .map(|peer_id| {
                let peer_id = *peer_id;
                let request = request.clone();
                async move {
                    channel_service
                        .install_private_oram_index(peer_id, request)
                        .await
                        .and_then(|response| {
                            if response.index_epoch == expected_epoch
                                && response.root_hash == expected_root_hash
                            {
                                Ok(())
                            } else {
                                Err(collection::operations::types::CollectionError::service_error(
                                    format!(
                                        "private ORAM initial install acknowledgement is invalid on peer {peer_id}"
                                    ),
                                ))
                            }
                        })
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut first_error = None;
        while let Some(result) = pending.next().await {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        let operation = self.private_oram_initial_epoch_cas(
            key,
            expected_epoch,
            expected_root_hash.to_string(),
        )?;
        self.submit_private_oram_epoch_cas(operation, wait_timeout)
            .await
    }

    pub fn private_oram_consensus_epoch(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Result<Option<PrivateOramConsensusEpoch>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus epoch/root state requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_epoch(key))
    }

    pub fn private_oram_consensus_session_lease(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Result<Option<PrivateOramSessionLease>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus session lease requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_session_lease(key))
    }

    pub fn private_oram_consensus_mutation_state(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramConsensusCollectionStateV2>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM mutation state requires distributed mode")
        })?;
        Ok(consensus_state.private_oram_mutation_state(key))
    }

    pub fn private_oram_consensus_mutation_lease(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationLease>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM mutation lease requires distributed mode")
        })?;
        Ok(consensus_state.private_oram_mutation_lease(key))
    }

    pub fn private_oram_consensus_mutation_lease_slot(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationLeaseSlotV2>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation lease slot requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_mutation_lease_slot(key))
    }

    pub fn private_oram_consensus_layout(
        &self,
        key: &PrivateOramLayoutKey,
    ) -> Result<Option<PrivateOramConsensusLayout>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus layout state requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_layout(key))
    }

    #[doc(hidden)]
    pub fn issue_private_oram_mutation_live_admission_seed_v2(
        &self,
        collection_id: &str,
        mutation_id: &str,
        expires_at_unix: u64,
    ) -> Result<PrivateOramLiveAdmissionSeedV2, StorageError> {
        let now_unix = current_private_oram_unix_secs()?;
        let (leader_peer_id, leader_term) = self.private_oram_live_admission_leader_token_v2()?;
        if collection_id.is_empty()
            || collection_id.len() > 1_024
            || decode_private_oram_sha256_digest(mutation_id).is_none()
            || expires_at_unix <= now_unix
            || expires_at_unix.saturating_sub(now_unix) > PRIVATE_ORAM_LIVE_ADMISSION_MAX_LEASE_SECS
        {
            return Err(StorageError::bad_request(
                "private ORAM live admission seed request is invalid",
            ));
        }
        let mut registry = self.private_oram_live_admission_registry.lock();
        registry
            .records
            .retain(|_, record| record.expires_at_unix > now_unix);
        if registry.records.len() >= PRIVATE_ORAM_LIVE_ADMISSION_MAX_RECORDS {
            return Err(StorageError::service_error(
                "private ORAM live admission registry is full",
            ));
        }
        let capability_id = (0..4)
            .map(|_| uuid::Uuid::new_v4().to_string())
            .find(|candidate| !registry.records.contains_key(candidate))
            .ok_or_else(|| {
                StorageError::service_error("private ORAM live admission capability collision")
            })?;
        registry.records.insert(
            capability_id.clone(),
            PrivateOramLiveAdmissionRecordV2 {
                collection_id: collection_id.to_string(),
                mutation_id: mutation_id.to_string(),
                leader_peer_id,
                leader_term,
                expires_at_unix,
                phase: PrivateOramLiveAdmissionRecordPhaseV2::Seed,
                session_commitment: None,
                generation: None,
                writer_fence: None,
                expected_aggregate_digest: None,
            },
        );
        Ok(PrivateOramLiveAdmissionSeedV2 {
            capability_id,
            collection_id: collection_id.to_string(),
            mutation_id: mutation_id.to_string(),
            leader_peer_id,
            leader_term,
            expires_at_unix,
        })
    }

    #[doc(hidden)]
    pub fn bind_private_oram_mutation_live_admission_permit_v2(
        &self,
        seed: &PrivateOramLiveAdmissionSeedV2,
        session_commitment: String,
        plan: &PrivateOramMutationAdmissionPlanV2,
        all_owners_prestaged: &PrivateOramMutationAllOwnersPrestagedV2,
    ) -> Result<PrivateOramLiveAdmissionPermitV2, StorageError> {
        let now_unix = current_private_oram_unix_secs()?;
        let (leader_peer_id, leader_term) = self.private_oram_live_admission_leader_token_v2()?;
        all_owners_prestaged
            .validate_admission_plan(plan)
            .map_err(|_| {
                StorageError::bad_request(
                    "private ORAM mutation all-owner pre-stage certificate is invalid",
                )
            })?;
        let lease = plan.lease();
        let generation = lease.generation;
        let writer_fence = lease.writer_fence;
        let expected_aggregate_digest = all_owners_prestaged.expected_aggregate_digest();
        if decode_private_oram_sha256_digest(&session_commitment).is_none()
            || decode_private_oram_sha256_digest(expected_aggregate_digest).is_none()
            || generation == 0
            || writer_fence == 0
            || generation != writer_fence
            || seed.expires_at_unix <= now_unix
            || seed.leader_peer_id != leader_peer_id
            || seed.leader_term != leader_term
        {
            return Err(StorageError::bad_request(
                "private ORAM live admission permit binding is invalid",
            ));
        }
        let mut registry = self.private_oram_live_admission_registry.lock();
        registry
            .records
            .retain(|_, record| record.expires_at_unix > now_unix);
        let record = registry
            .records
            .get_mut(&seed.capability_id)
            .ok_or_else(|| {
                StorageError::bad_request("private ORAM live admission seed is unavailable")
            })?;
        if record.phase != PrivateOramLiveAdmissionRecordPhaseV2::Seed
            || record.collection_id != seed.collection_id
            || record.mutation_id != seed.mutation_id
            || record.leader_peer_id != seed.leader_peer_id
            || record.leader_term != seed.leader_term
            || record.expires_at_unix != seed.expires_at_unix
        {
            return Err(StorageError::bad_request(
                "private ORAM live admission seed is invalid",
            ));
        }
        record.phase = PrivateOramLiveAdmissionRecordPhaseV2::Bound;
        record.session_commitment = Some(session_commitment.clone());
        record.generation = Some(generation);
        record.writer_fence = Some(writer_fence);
        record.expected_aggregate_digest = Some(expected_aggregate_digest.to_string());
        Ok(PrivateOramLiveAdmissionPermitV2 {
            capability_id: seed.capability_id.clone(),
            collection_id: seed.collection_id.clone(),
            mutation_id: seed.mutation_id.clone(),
            leader_peer_id,
            leader_term,
            expires_at_unix: seed.expires_at_unix,
            session_commitment,
            generation,
            writer_fence,
            expected_aggregate_digest: expected_aggregate_digest.to_string(),
        })
    }

    #[doc(hidden)]
    pub fn revoke_private_oram_mutation_live_admission_seed_v2(
        &self,
        seed: &PrivateOramLiveAdmissionSeedV2,
    ) {
        let mut registry = self.private_oram_live_admission_registry.lock();
        if registry
            .records
            .get(&seed.capability_id)
            .is_some_and(|record| {
                record.phase == PrivateOramLiveAdmissionRecordPhaseV2::Seed
                    && record.collection_id == seed.collection_id
                    && record.mutation_id == seed.mutation_id
                    && record.leader_peer_id == seed.leader_peer_id
                    && record.leader_term == seed.leader_term
                    && record.expires_at_unix == seed.expires_at_unix
            })
        {
            registry.records.remove(&seed.capability_id);
        }
    }

    /// Builds the exact admission operation and consumes its process-local permit before return.
    fn prepare_private_oram_mutation_admission_v2(
        &self,
        plan: &PrivateOramMutationAdmissionPlanV2,
        all_owners_prestaged: &PrivateOramMutationAllOwnersPrestagedV2,
        prepared_aggregate_digest: &str,
        permit: &PrivateOramLiveAdmissionPermitV2,
    ) -> Result<PrivateOramMutationAdmissionSubmissionV2, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM mutation admission requires distributed mode")
        })?;
        all_owners_prestaged
            .validate_admission_plan(plan)
            .map_err(|_| {
                StorageError::bad_request(
                    "private ORAM mutation all-owner pre-stage certificate is invalid",
                )
            })?;
        for evidence in all_owners_prestaged.owner_evidence() {
            let pin =
                consensus_state.private_oram_peer_recovery_signer_pin(evidence.owner_peer_id())?;
            if &pin.activation_authority() != all_owners_prestaged.activation_authority()
                || pin.signer() != &evidence.attestation().owner_public_key
            {
                return Err(StorageError::PreconditionFailed {
                    description: "private ORAM mutation owner pre-stage authority changed"
                        .to_string(),
                });
            }
        }
        let recovery_manifest_canonical_json =
            encode_private_oram_mutation_admission_recovery_manifest_v2(all_owners_prestaged)
                .map_err(|_| {
                    StorageError::bad_request(
                        "private ORAM mutation admission recovery manifest is invalid",
                    )
                })?;
        let key = PrivateOramMutationKey {
            collection_id: plan.lease().collection_id.clone(),
        };
        if consensus_state.private_oram_mutation_v2_current_aggregate_digest(&key)?
            != prepared_aggregate_digest
            || consensus_state
                .private_oram_mutation_v2_active_append_attempt(&key)?
                .as_ref()
                .is_none_or(|(reservation, prepared)| {
                    reservation.expected_aggregate_digest()
                        != all_owners_prestaged.expected_aggregate_digest()
                        || prepared.as_ref() != Some(all_owners_prestaged)
                })
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation prepared authority changed".to_string(),
            });
        }
        let expected_aggregate_digest = prepared_aggregate_digest.to_string();
        let admission_operation = consensus_state
            .private_oram_mutation_v2_admission_operation_at_expected(
                plan.lease().clone(),
                recovery_manifest_canonical_json.clone(),
                expected_aggregate_digest.clone(),
            )?;
        let rejection_operation = consensus_state
            .private_oram_mutation_v2_admission_rejected_operation_at_expected(
                plan.lease().clone(),
                recovery_manifest_canonical_json,
                expected_aggregate_digest,
            )?;
        self.consume_private_oram_mutation_live_admission_permit_v2(
            permit,
            plan,
            all_owners_prestaged,
        )?;
        Ok(PrivateOramMutationAdmissionSubmissionV2 {
            admission_operation,
            rejection_operation,
            lease: plan.lease().clone(),
            recovery_manifest_digest: all_owners_prestaged.manifest_digest().to_string(),
        })
    }

    /// Submits an already-built admission. An exact retry is both idempotent and a Raft ordering
    /// barrier: a lost first response cannot be mistaken for a definitive pre-admission failure.
    pub async fn submit_private_oram_mutation_admission_v2(
        &self,
        plan: &PrivateOramMutationAdmissionPlanV2,
        all_owners_prestaged: &PrivateOramMutationAllOwnersPrestagedV2,
        prepared_aggregate_digest: &str,
        permit: PrivateOramLiveAdmissionPermitV2,
        wait_timeout: Option<Duration>,
    ) -> Result<PrivateOramMutationAdmissionOutcomeV2, PrivateOramMutationAdmissionFailureV2> {
        let submission = self
            .prepare_private_oram_mutation_admission_v2(
                plan,
                all_owners_prestaged,
                prepared_aggregate_digest,
                &permit,
            )
            .map_err(|source| PrivateOramMutationAdmissionFailureV2 {
                // Operation construction and all authority checks happen before the process-local
                // permit is consumed. After consumption this function has no fallible work before
                // returning the opaque submission, so an error here cannot have reached Raft.
                class: PrivateOramMutationAdmissionFailureClassV2::DefinitelyNotSubmitted,
                source,
            })?;
        let consensus_state =
            self.consensus_state
                .as_ref()
                .ok_or_else(|| PrivateOramMutationAdmissionFailureV2 {
                    class: PrivateOramMutationAdmissionFailureClassV2::Unknown,
                    source: StorageError::service_error(
                        "private ORAM mutation admission requires distributed mode",
                    ),
                })?;
        for operation in [
            submission.admission_operation.clone(),
            submission.admission_operation.clone(),
            submission.rejection_operation.clone(),
            submission.rejection_operation.clone(),
        ] {
            let _proposal_result = consensus_state
                .propose_consensus_op_with_await(operation, wait_timeout)
                .await;
            if let Ok(Some(outcome)) = self.inspect_private_oram_mutation_admission_outcome_v2(
                &submission.lease,
                &submission.recovery_manifest_digest,
            ) {
                return Ok(outcome);
            }
        }
        Err(PrivateOramMutationAdmissionFailureV2 {
            class: PrivateOramMutationAdmissionFailureClassV2::Unknown,
            source: StorageError::service_error(
                "private ORAM mutation admission outcome requires recovery",
            ),
        })
    }

    #[doc(hidden)]
    pub fn inspect_private_oram_mutation_admission_outcome_v2(
        &self,
        lease: &PrivateOramMutationLease,
        recovery_manifest_digest: &str,
    ) -> Result<Option<PrivateOramMutationAdmissionOutcomeV2>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM mutation admission requires distributed mode")
        })?;
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        if consensus_state.private_oram_mutation_lease(&key) == Some(lease.clone()) {
            return Ok(Some(PrivateOramMutationAdmissionOutcomeV2::AppliedExact));
        }
        if consensus_state.private_oram_mutation_v2_retains_rejected_admission(
            &key,
            lease,
            recovery_manifest_digest,
        )? {
            return Ok(Some(
                PrivateOramMutationAdmissionOutcomeV2::CommittedRejected,
            ));
        }
        Ok(None)
    }

    /// Returns the full consensus-retained owner manifest only while the exact admitted lease is
    /// authoritative. The lease and manifest are read under one persistent-state guard.
    pub fn private_oram_mutation_v2_exact_admitted_recovery_manifest(
        &self,
        lease: &PrivateOramMutationLease,
    ) -> Result<Option<PrivateOramMutationAllOwnersPrestagedV2>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM mutation admission requires distributed mode")
        })?;
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        consensus_state.private_oram_mutation_v2_exact_admitted_recovery_manifest(&key, lease)
    }

    pub fn active_private_oram_mutation_keys(
        &self,
    ) -> Result<Vec<PrivateOramMutationKey>, StorageError> {
        self.consensus_state()
            .ok_or_else(|| {
                StorageError::service_error(
                    "private ORAM mutation discovery requires distributed mode",
                )
            })?
            .active_private_oram_mutation_keys()
    }

    pub fn private_oram_mutation_pending_acknowledgement_keys(
        &self,
    ) -> Result<Vec<(PrivateOramMutationKey, PeerId, u64)>, StorageError> {
        self.consensus_state
            .as_ref()
            .ok_or_else(|| {
                StorageError::service_error(
                    "private ORAM mutation acknowledgement discovery requires distributed mode",
                )
            })?
            .private_oram_mutation_pending_acknowledgement_keys()
    }

    fn private_oram_live_admission_leader_token_v2(&self) -> Result<(PeerId, u64), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM live admission requires distributed mode")
        })?;
        consensus_state.require_private_oram_mutation_coordinator_is_local_leader()?;
        let term = consensus_state.hard_state().term;
        if term == 0 {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM live admission leader term is unavailable".to_string(),
            });
        }
        Ok((self.this_peer_id(), term))
    }

    fn consume_private_oram_mutation_live_admission_permit_v2(
        &self,
        permit: &PrivateOramLiveAdmissionPermitV2,
        plan: &PrivateOramMutationAdmissionPlanV2,
        all_owners_prestaged: &PrivateOramMutationAllOwnersPrestagedV2,
    ) -> Result<(), StorageError> {
        let now_unix = current_private_oram_unix_secs()?;
        let (leader_peer_id, leader_term) = self.private_oram_live_admission_leader_token_v2()?;
        let lease = plan.lease();
        if permit.collection_id != lease.collection_id
            || permit.mutation_id != lease.mutation_id
            || permit.generation != lease.generation
            || permit.writer_fence != lease.writer_fence
            || permit.expected_aggregate_digest != all_owners_prestaged.expected_aggregate_digest()
            || permit.leader_peer_id != leader_peer_id
            || permit.leader_term != leader_term
            || permit.expires_at_unix <= now_unix
        {
            return Err(StorageError::bad_request(
                "private ORAM live admission permit is invalid",
            ));
        }
        let mut registry = self.private_oram_live_admission_registry.lock();
        registry
            .records
            .retain(|_, record| record.expires_at_unix > now_unix);
        let record = registry.records.get(&permit.capability_id).ok_or_else(|| {
            StorageError::bad_request("private ORAM live admission permit is unavailable")
        })?;
        if record.phase != PrivateOramLiveAdmissionRecordPhaseV2::Bound
            || record.collection_id != permit.collection_id
            || record.mutation_id != permit.mutation_id
            || record.leader_peer_id != permit.leader_peer_id
            || record.leader_term != permit.leader_term
            || record.expires_at_unix != permit.expires_at_unix
            || record.session_commitment.as_deref() != Some(&permit.session_commitment)
            || record.generation != Some(permit.generation)
            || record.writer_fence != Some(permit.writer_fence)
            || record.expected_aggregate_digest.as_deref()
                != Some(&permit.expected_aggregate_digest)
        {
            return Err(StorageError::bad_request(
                "private ORAM live admission permit is invalid",
            ));
        }
        registry.records.remove(&permit.capability_id);
        Ok(())
    }

    pub fn private_oram_consensus_external_recovery(
        &self,
        key: &PrivateOramExternalRecoveryKey,
    ) -> Result<Option<PrivateOramExternalRecoveryState>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM external recovery state requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_external_recovery(key))
    }

    pub async fn submit_private_oram_mutation_recovery_readiness_v2(
        &self,
        proposal: PrivateOramMutationRecoveryReadinessProposalV2,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation recovery readiness requires distributed mode",
            )
        })?;
        let operation = consensus_state
            .private_oram_mutation_v2_recovery_capsules_ready_operation(
                proposal.key().clone(),
                proposal.expectation(),
            )?;
        if !consensus_state
            .propose_consensus_op_with_await(operation, wait_timeout)
            .await?
        {
            return Err(StorageError::service_error(
                "private ORAM mutation recovery readiness was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_mutation_parent_progress_v2(
        &self,
        progress: PrivateOramMutationNeedParentProgressV2,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation parent progress requires distributed mode",
            )
        })?;
        let proposal = progress.into_proposal();
        let operation = consensus_state.private_oram_mutation_v2_parent_progress_operation(
            proposal.key().clone(),
            proposal.expectation(),
        )?;
        if !consensus_state
            .propose_consensus_op_with_await(operation, wait_timeout)
            .await?
        {
            return Err(StorageError::service_error(
                "private ORAM mutation parent progress was not applied",
            ));
        }
        Ok(())
    }

    pub fn private_oram_mutation_cleanup_witness_operation_v2(
        &self,
        permit: PrivateOramMutationNeedCleanupWitnessV2,
    ) -> Result<ConsensusOperations, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation cleanup witness requires distributed mode",
            )
        })?;
        let proposal = permit.into_proposal();
        consensus_state.private_oram_mutation_v2_cleanup_witness_operation(
            proposal.key().clone(),
            proposal.expectation(),
        )
    }

    pub async fn submit_private_oram_mutation_clear_pending_v2(
        &self,
        proposal: PrivateOramMutationClearPendingProposalV2,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation clear-pending requires distributed mode",
            )
        })?;
        let (key, generation, witness_digest, clear_attempt_id_digest) = proposal.into_parts();
        let operation = consensus_state.private_oram_mutation_v2_clear_pending_operation(
            key,
            generation,
            &witness_digest,
            clear_attempt_id_digest,
        )?;
        if !consensus_state
            .propose_consensus_op_with_await(operation, wait_timeout)
            .await?
        {
            return Err(StorageError::service_error(
                "private ORAM mutation clear-pending was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_mutation_clear_v2(
        &self,
        permit: PrivateOramMutationNeedClearV2,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error("private ORAM mutation clear requires distributed mode")
        })?;
        let (key, generation, clear_attempt_id_digest) = permit.into_parts();
        let operation = consensus_state.private_oram_mutation_v2_clear_operation(
            key,
            generation,
            &clear_attempt_id_digest,
        )?;
        if !consensus_state
            .propose_consensus_op_with_await(operation, wait_timeout)
            .await?
        {
            return Err(StorageError::service_error(
                "private ORAM mutation clear was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_mutation_clear_acknowledgement_v2(
        &self,
        key: PrivateOramMutationKey,
        expected_owner_peer_id: PeerId,
        expected_generation: u64,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation clear acknowledgement requires distributed mode",
            )
        })?;
        let operation = consensus_state.private_oram_mutation_v2_clear_acknowledgement_operation(
            key,
            expected_owner_peer_id,
            expected_generation,
        )?;
        if !consensus_state
            .propose_consensus_op_with_await(operation, wait_timeout)
            .await?
        {
            return Err(StorageError::service_error(
                "private ORAM mutation clear acknowledgement was not applied",
            ));
        }
        Ok(())
    }

    pub async fn await_consensus_sync(
        &self,
        timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let timeout = timeout.unwrap_or(CONSENSUS_META_OP_WAIT);

        let Some(state) = self.consensus_state.as_ref() else {
            return Ok(());
        };

        let state = state.hard_state();
        let term = state.term;
        let commit = state.commit;
        let channel_service = self.toc.get_channel_service();
        let this_peer_id = self.toc.this_peer_id;

        channel_service
            .await_commit_on_all_peers(this_peer_id, commit, term, timeout)
            .await?;

        log::debug!("Consensus is synchronized with term: {term}, commit: {commit}");

        Ok(())
    }

    /// Waits for all shards of a specific shard key to become active.
    pub async fn wait_for_shard_key_activation(
        &self,
        collection_name: CollectionName,
        shard_key: ShardKey,
        timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let timeout = timeout.unwrap_or(CONSENSUS_META_OP_WAIT);

        let mut wait_for_active = FuturesUnordered::new();

        {
            let shard_holder = self
                .toc
                .get_collection(&CollectionMultipass.issue_pass(&collection_name))
                .await?
                .shards_holder()
                .read_owned()
                .await;

            for replica_set in shard_holder.all_shards() {
                if replica_set.shard_key() != Some(&shard_key) {
                    continue;
                }

                for (peer_id, replica_state) in replica_set.peers() {
                    if replica_state == ReplicaState::Active {
                        continue;
                    }

                    wait_for_active.push(replica_set.wait_for_state(
                        peer_id,
                        ReplicaState::Active,
                        timeout,
                    ));
                }
            }
        }

        while let Some(result) = wait_for_active.next().await {
            result?;
        }

        Ok(())
    }

    pub fn all_hw_metrics(&self) -> HashMap<String, HardwareUsage> {
        self.toc.all_hw_metrics()
    }

    #[must_use]
    pub fn get_collection_hw_metrics(&self, collection: String) -> Arc<HwSharedDrain> {
        self.toc.get_collection_hw_metrics(collection)
    }
}

fn validate_private_oram_replica_prepare_acks(
    required_replica_peers: &BTreeSet<PeerId>,
    replica_acks: &[PrivateOramReplicaPrepareAck],
    expected_digest: &str,
) -> Result<(), StorageError> {
    validate_private_oram_writeback_digest(expected_digest)?;
    let mut acknowledged_peers = BTreeSet::new();
    for ack in replica_acks {
        if ack.writeback_digest != expected_digest || !acknowledged_peers.insert(ack.peer_id) {
            return Err(StorageError::bad_request(
                "private ORAM replica prepare acknowledgements are invalid",
            ));
        }
    }
    if &acknowledged_peers != required_replica_peers {
        return Err(StorageError::bad_request(
            "private ORAM replica prepare acknowledgements are incomplete",
        ));
    }
    Ok(())
}

pub fn private_hnsw_oram_prepare_request(
    collection_name: &str,
    collection_id: &str,
    vector_name: &str,
    batch: &PrivateHnswOramWritebackBatch,
    transition: &PrivateHnswOramConsensusWriteback,
) -> Result<PreparePrivateOramWritebackRequest, StorageError> {
    if batch.old != transition.old || batch.new != transition.new {
        return Err(StorageError::bad_request(
            "private HNSW ORAM replication batch transition does not match",
        ));
    }
    validate_private_oram_writeback_digest(&transition.writeback_digest)?;
    Ok(PreparePrivateOramWritebackRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.to_string(),
        index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
        vector_name: vector_name.to_string(),
        version: u32::from(batch.version),
        transition: Some(private_oram_transition(
            batch.old.index_epoch,
            &batch.old.root_hash,
            batch.new.index_epoch,
            &batch.new.root_hash,
            &transition.writeback_digest,
        )),
        bucket_count: batch.bucket_count,
        updated_buckets: batch
            .updated_buckets
            .iter()
            .map(|bucket| PrivateOramReplicationBucket {
                version: u32::from(bucket.version),
                bucket_id: bucket.bucket_id,
                index_epoch: bucket.index_epoch,
                ciphertext: bucket.ciphertext.clone(),
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
        commit_signature: Some(PrivateOramReplicationSignature {
            alg: batch.commit_signature.alg.clone(),
            key_id: batch.commit_signature.key_id.clone(),
            sig: batch.commit_signature.sig.clone(),
        }),
    })
}

pub fn private_result_oram_prepare_request(
    collection_name: &str,
    collection_id: &str,
    batch: &PrivateResultOramWritebackBatch,
    transition: &PrivateResultOramConsensusWriteback,
) -> Result<PreparePrivateOramWritebackRequest, StorageError> {
    if batch.old != transition.old || batch.new != transition.new {
        return Err(StorageError::bad_request(
            "private result ORAM replication batch transition does not match",
        ));
    }
    validate_private_oram_writeback_digest(&transition.writeback_digest)?;
    Ok(PreparePrivateOramWritebackRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.to_string(),
        index_kind: PrivateOramReplicationIndexKind::Result as i32,
        vector_name: String::new(),
        version: u32::from(batch.version),
        transition: Some(private_oram_transition(
            batch.old.index_epoch,
            &batch.old.root_hash,
            batch.new.index_epoch,
            &batch.new.root_hash,
            &transition.writeback_digest,
        )),
        bucket_count: batch.bucket_count,
        updated_buckets: batch
            .updated_buckets
            .iter()
            .map(|bucket| PrivateOramReplicationBucket {
                version: u32::from(bucket.version),
                bucket_id: bucket.bucket_id,
                index_epoch: bucket.index_epoch,
                ciphertext: bucket.ciphertext.clone(),
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
        commit_signature: Some(PrivateOramReplicationSignature {
            alg: batch.commit_signature.alg.clone(),
            key_id: batch.commit_signature.key_id.clone(),
            sig: batch.commit_signature.sig.clone(),
        }),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn private_oram_complete_request(
    collection_name: &str,
    collection_id: &str,
    index_kind: PrivateOramReplicationIndexKind,
    vector_name: &str,
    old_epoch: u64,
    old_root_hash: &str,
    new_epoch: u64,
    new_root_hash: &str,
    writeback_digest: &str,
    signing_key_id: &str,
) -> Result<CompletePrivateOramWritebackRequest, StorageError> {
    if index_kind == PrivateOramReplicationIndexKind::Unspecified
        || (index_kind == PrivateOramReplicationIndexKind::Hnsw && vector_name.is_empty())
        || (index_kind == PrivateOramReplicationIndexKind::Result && !vector_name.is_empty())
    {
        return Err(StorageError::bad_request(
            "private ORAM replication completion identity is invalid",
        ));
    }
    validate_private_oram_writeback_digest(writeback_digest)?;
    Ok(CompletePrivateOramWritebackRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.to_string(),
        index_kind: index_kind as i32,
        vector_name: vector_name.to_string(),
        transition: Some(private_oram_transition(
            old_epoch,
            old_root_hash,
            new_epoch,
            new_root_hash,
            writeback_digest,
        )),
        signing_key_id: signing_key_id.to_string(),
    })
}

fn private_oram_transition(
    old_epoch: u64,
    old_root_hash: &str,
    new_epoch: u64,
    new_root_hash: &str,
    writeback_digest: &str,
) -> PrivateOramReplicationTransition {
    PrivateOramReplicationTransition {
        old: Some(PrivateOramReplicationEpochState {
            index_epoch: old_epoch,
            root_hash: old_root_hash.to_string(),
        }),
        new: Some(PrivateOramReplicationEpochState {
            index_epoch: new_epoch,
            root_hash: new_root_hash.to_string(),
        }),
        writeback_digest: writeback_digest.to_string(),
    }
}

fn private_oram_shard_transfer_pre_layout_owners(
    shard_id: ShardId,
    peers: &HashMap<PeerId, ReplicaState>,
    transfer: &ShardTransfer,
) -> Result<Vec<PeerId>, StorageError> {
    if peers.is_empty() {
        return Err(invalid_private_oram_layout_transition());
    }

    let mut owner_peer_ids = Vec::with_capacity(peers.len());
    for (&peer_id, &state) in peers {
        if state == ReplicaState::Active
            || state == ReplicaState::Dead
                && peer_id == transfer.to
                && shard_id != transfer.shard_id
        {
            owner_peer_ids.push(peer_id);
        } else if state != ReplicaState::Dead {
            return Err(invalid_private_oram_layout_transition());
        }
    }
    if owner_peer_ids.is_empty() {
        return Err(invalid_private_oram_layout_transition());
    }
    owner_peer_ids.sort_unstable();
    Ok(owner_peer_ids)
}

fn derive_private_oram_replication_peers(
    shard_peer_states: &[HashMap<PeerId, ReplicaState>],
    this_peer_id: PeerId,
) -> Result<BTreeSet<PeerId>, StorageError> {
    if shard_peer_states.is_empty() {
        return Err(StorageError::service_error(
            "private ORAM replication requires at least one shard",
        ));
    }
    if shard_peer_states
        .iter()
        .any(|peers| peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active))
    {
        return Err(StorageError::service_error(
            "private ORAM replication requires fully active shard replicas",
        ));
    }

    let replica_peers = shard_peer_states
        .iter()
        .flat_map(|peers| peers.keys().copied())
        .collect::<BTreeSet<_>>();
    if !replica_peers.contains(&this_peer_id) {
        return Err(StorageError::service_error(
            "private ORAM replication coordinator must own an active shard replica",
        ));
    }
    Ok(replica_peers)
}

fn validate_private_oram_session_coordinator_topology(
    shard_peer_states: &[HashMap<PeerId, ReplicaState>],
    this_peer_id: PeerId,
    resharding_active: bool,
    shard_transfer_active: bool,
) -> Result<(), StorageError> {
    if resharding_active || shard_transfer_active {
        return Err(StorageError::service_error(
            "private ORAM sessions require a stable shard topology",
        ));
    }
    if shard_peer_states
        .iter()
        .any(|peers| peers.get(&this_peer_id) == Some(&ReplicaState::Active))
    {
        return Ok(());
    }
    Err(StorageError::service_error(
        "private ORAM session coordinator must own an active shard replica",
    ))
}

fn current_private_oram_unix_secs() -> Result<u64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StorageError::service_error("private ORAM consensus layout clock is invalid"))
}

fn private_oram_layout_reservation_matches(
    lease: &PrivateOramSessionLease,
    owner_peer_id: PeerId,
    lease_id_hash: &str,
    now_unix: u64,
) -> bool {
    lease.owner_peer_id == owner_peer_id
        && lease.lease_id_hash == lease_id_hash
        && lease.issued_at_unix <= now_unix
        && lease.expires_at_unix > now_unix
}

fn decode_private_oram_sha256_digest(value: &str) -> Option<[u8; 32]> {
    let decoded = BASE64URL_NOPAD.decode(value.as_bytes()).ok()?;
    let digest: [u8; 32] = decoded.try_into().ok()?;
    (BASE64URL_NOPAD.encode(&digest) == value).then_some(digest)
}

fn invalid_private_oram_layout_reservation() -> StorageError {
    StorageError::bad_request("private ORAM consensus layout reservation is invalid")
}

fn invalid_private_oram_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM collection layout transition is invalid")
}

fn invalid_private_oram_resharding_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM resharding layout transition is invalid")
}

fn validate_private_oram_writeback_digest(digest: &str) -> Result<(), StorageError> {
    let decoded = BASE64URL_NOPAD.decode(digest.as_bytes()).map_err(|_| {
        StorageError::bad_request("private ORAM replicated writeback digest is invalid")
    })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != digest {
        return Err(StorageError::bad_request(
            "private ORAM replicated writeback digest is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_root_hash(root_hash: &str) -> Result<(), StorageError> {
    let decoded = BASE64URL_NOPAD
        .decode(root_hash.as_bytes())
        .map_err(|_| StorageError::bad_request("private ORAM consensus root hash is invalid"))?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != root_hash {
        return Err(StorageError::bad_request(
            "private ORAM consensus root hash is invalid",
        ));
    }
    Ok(())
}

pub fn classify_private_oram_recovery(
    consensus: Option<&PrivateOramConsensusEpoch>,
    local: PrivateOramEpochRef<'_>,
    pending: Option<PrivateOramPendingTransitionRef<'_>>,
) -> Result<PrivateOramRecoveryAction, StorageError> {
    validate_private_oram_root_hash(local.root_hash)?;
    let consensus = consensus.ok_or_else(|| {
        StorageError::bad_request("private ORAM consensus ownership is not initialized")
    })?;
    validate_private_oram_root_hash(&consensus.root_hash)?;
    if let Some(digest) = consensus.writeback_digest.as_deref() {
        validate_private_oram_writeback_digest(digest)?;
    }

    let Some(pending) = pending else {
        if local.index_epoch == consensus.index_epoch && local.root_hash == consensus.root_hash {
            return Ok(PrivateOramRecoveryAction::Clean);
        }
        return Err(StorageError::bad_request(
            "private ORAM local state does not match consensus",
        ));
    };

    validate_private_oram_root_hash(pending.old.root_hash)?;
    validate_private_oram_root_hash(pending.new.root_hash)?;
    validate_private_oram_writeback_digest(pending.writeback_digest)?;
    let local_is_old =
        local.index_epoch == pending.old.index_epoch && local.root_hash == pending.old.root_hash;
    let local_is_new =
        local.index_epoch == pending.new.index_epoch && local.root_hash == pending.new.root_hash;
    if pending.new.index_epoch <= pending.old.index_epoch || (!local_is_old && !local_is_new) {
        return Err(StorageError::bad_request(
            "private ORAM pending recovery state is inconsistent",
        ));
    }

    let consensus_is_new = consensus.index_epoch == pending.new.index_epoch
        && consensus.root_hash == pending.new.root_hash
        && consensus.writeback_digest.as_deref() == Some(pending.writeback_digest);
    if consensus_is_new {
        return Ok(PrivateOramRecoveryAction::FinalizePending);
    }

    let consensus_is_old = consensus.index_epoch == pending.old.index_epoch
        && consensus.root_hash == pending.old.root_hash;
    if local_is_old && consensus_is_old {
        return Ok(PrivateOramRecoveryAction::AbortPending);
    }

    Err(StorageError::bad_request(
        "private ORAM pending recovery does not match consensus",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_oram_recovery_requires_exact_consensus_state() {
        let old_root = BASE64URL_NOPAD.encode(&[1; 32]);
        let new_root = BASE64URL_NOPAD.encode(&[2; 32]);
        let unrelated_root = BASE64URL_NOPAD.encode(&[3; 32]);
        let previous_digest = BASE64URL_NOPAD.encode(&[4; 32]);
        let writeback_digest = BASE64URL_NOPAD.encode(&[5; 32]);
        let old_consensus = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: old_root.clone(),
            writeback_digest: Some(previous_digest),
        };
        let new_consensus = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: new_root.clone(),
            writeback_digest: Some(writeback_digest.clone()),
        };
        let local_old = || PrivateOramEpochRef {
            index_epoch: 42,
            root_hash: &old_root,
        };
        let local_new = || PrivateOramEpochRef {
            index_epoch: 43,
            root_hash: &new_root,
        };
        let pending = || PrivateOramPendingTransitionRef {
            old: local_old(),
            new: local_new(),
            writeback_digest: &writeback_digest,
        };

        assert_eq!(
            classify_private_oram_recovery(Some(&old_consensus), local_old(), None).unwrap(),
            PrivateOramRecoveryAction::Clean,
        );
        assert_eq!(
            classify_private_oram_recovery(Some(&old_consensus), local_old(), Some(pending()),)
                .unwrap(),
            PrivateOramRecoveryAction::AbortPending,
        );
        for local in [local_old(), local_new()] {
            assert_eq!(
                classify_private_oram_recovery(Some(&new_consensus), local, Some(pending()),)
                    .unwrap(),
                PrivateOramRecoveryAction::FinalizePending,
            );
        }

        let wrong_digest_consensus = PrivateOramConsensusEpoch {
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[6; 32])),
            ..new_consensus.clone()
        };
        let unrelated_consensus = PrivateOramConsensusEpoch {
            index_epoch: 44,
            root_hash: unrelated_root.clone(),
            writeback_digest: None,
        };
        for mismatch in [
            classify_private_oram_recovery(Some(&new_consensus), local_old(), None).unwrap_err(),
            classify_private_oram_recovery(
                Some(&wrong_digest_consensus),
                local_old(),
                Some(pending()),
            )
            .unwrap_err(),
            classify_private_oram_recovery(Some(&old_consensus), local_new(), Some(pending()))
                .unwrap_err(),
            classify_private_oram_recovery(
                Some(&unrelated_consensus),
                local_old(),
                Some(pending()),
            )
            .unwrap_err(),
            classify_private_oram_recovery(None, local_old(), None).unwrap_err(),
        ] {
            let rendered = mismatch.to_string();
            for sentinel in [
                old_root.as_str(),
                new_root.as_str(),
                unrelated_root.as_str(),
                writeback_digest.as_str(),
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }

        let malformed = "private-oram-recovery-root-sentinel";
        let malformed = classify_private_oram_recovery(
            Some(&old_consensus),
            PrivateOramEpochRef {
                index_epoch: 42,
                root_hash: malformed,
            },
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(malformed.contains("consensus root hash is invalid"));
        assert!(!malformed.contains("sentinel"));
    }

    #[test]
    fn private_oram_replica_prepare_acks_require_exact_peers_and_digest() {
        let digest = BASE64URL_NOPAD.encode(&[42; 32]);
        let required = BTreeSet::from([7, 9]);
        let valid = vec![
            PrivateOramReplicaPrepareAck {
                peer_id: 9,
                writeback_digest: digest.clone(),
            },
            PrivateOramReplicaPrepareAck {
                peer_id: 7,
                writeback_digest: digest.clone(),
            },
        ];
        validate_private_oram_replica_prepare_acks(&required, &valid, &digest).unwrap();

        let rendered = format!("{:?}", valid[0]);
        assert!(rendered.contains("peer_id: 9"), "{rendered}");
        assert!(!rendered.contains(&digest), "{rendered}");

        let missing = validate_private_oram_replica_prepare_acks(&required, &valid[..1], &digest)
            .unwrap_err()
            .to_string();
        assert!(missing.contains("acknowledgements are incomplete"));

        let duplicate = validate_private_oram_replica_prepare_acks(
            &required,
            &[valid[0].clone(), valid[0].clone()],
            &digest,
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("acknowledgements are invalid"));

        let mismatched_digest = BASE64URL_NOPAD.encode(&[43; 32]);
        let mismatch = validate_private_oram_replica_prepare_acks(
            &required,
            &[PrivateOramReplicaPrepareAck {
                peer_id: 7,
                writeback_digest: mismatched_digest.clone(),
            }],
            &digest,
        )
        .unwrap_err()
        .to_string();
        assert!(mismatch.contains("acknowledgements are invalid"));
        assert!(!mismatch.contains(&digest));
        assert!(!mismatch.contains(&mismatched_digest));

        let malformed_digest = "private-oram-replica-digest-sentinel";
        let malformed =
            validate_private_oram_replica_prepare_acks(&BTreeSet::new(), &[], malformed_digest)
                .unwrap_err()
                .to_string();
        assert!(malformed.contains("replicated writeback digest is invalid"));
        assert!(!malformed.contains(malformed_digest));
    }

    #[test]
    fn private_oram_replication_peers_union_fully_active_shard_membership() {
        let active = HashMap::from([(7, ReplicaState::Active), (9, ReplicaState::Active)]);
        let reversed = HashMap::from([(9, ReplicaState::Active), (7, ReplicaState::Active)]);
        assert_eq!(
            derive_private_oram_replication_peers(&[active.clone(), reversed], 7).unwrap(),
            BTreeSet::from([7, 9]),
        );

        let no_shards = derive_private_oram_replication_peers(&[], 7)
            .unwrap_err()
            .to_string();
        assert!(no_shards.contains("at least one shard"));

        let mut transitioning = active.clone();
        transitioning.insert(9, ReplicaState::ActiveRead);
        let transitioning =
            derive_private_oram_replication_peers(&[active.clone(), transitioning], 7)
                .unwrap_err()
                .to_string();
        assert!(transitioning.contains("fully active shard replicas"));

        let distributed = derive_private_oram_replication_peers(
            &[
                active.clone(),
                HashMap::from([(9, ReplicaState::Active), (11, ReplicaState::Active)]),
            ],
            7,
        )
        .unwrap();
        assert_eq!(distributed, BTreeSet::from([7, 9, 11]));

        let local_missing = derive_private_oram_replication_peers(&[active], 11)
            .unwrap_err()
            .to_string();
        assert!(local_missing.contains("coordinator must own an active shard replica"));
        assert!(!local_missing.contains("11"));
    }

    #[test]
    fn private_oram_session_coordinator_requires_stable_topology() {
        let states = [HashMap::from([
            (7, ReplicaState::Active),
            (9, ReplicaState::Resharding),
        ])];
        validate_private_oram_session_coordinator_topology(&states, 7, false, false).unwrap();

        for (resharding_active, shard_transfer_active) in [(true, false), (false, true)] {
            let error = validate_private_oram_session_coordinator_topology(
                &states,
                7,
                resharding_active,
                shard_transfer_active,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("stable shard topology"));
            assert!(!error.contains('7'));
        }

        let error = validate_private_oram_session_coordinator_topology(&states, 11, false, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("coordinator must own an active shard replica"));
        assert!(!error.contains("11"));
    }

    #[test]
    fn private_oram_transfer_pre_layout_excludes_dead_nonowners() {
        let transfer = ShardTransfer {
            shard_id: 3,
            to_shard_id: None,
            to: 9,
            from: 7,
            sync: true,
            method: Some(collection::shards::transfer::ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        };
        let active_source = HashMap::from([(7, ReplicaState::Active)]);
        assert_eq!(
            private_oram_shard_transfer_pre_layout_owners(3, &active_source, &transfer).unwrap(),
            vec![7],
        );

        let dead_target = HashMap::from([(7, ReplicaState::Active), (9, ReplicaState::Dead)]);
        assert_eq!(
            private_oram_shard_transfer_pre_layout_owners(3, &dead_target, &transfer).unwrap(),
            vec![7],
        );
        assert_eq!(
            private_oram_shard_transfer_pre_layout_owners(
                3,
                &HashMap::from([
                    (7, ReplicaState::Active),
                    (9, ReplicaState::Dead),
                    (11, ReplicaState::Dead),
                ]),
                &transfer,
            )
            .unwrap(),
            vec![7],
        );
        assert_eq!(
            private_oram_shard_transfer_pre_layout_owners(
                4,
                &HashMap::from([
                    (9, ReplicaState::Dead),
                    (13, ReplicaState::Active),
                    (11, ReplicaState::Dead),
                ]),
                &transfer,
            )
            .unwrap(),
            vec![9, 13],
        );

        for (shard_id, peers) in [
            (
                3,
                HashMap::from([(7, ReplicaState::Active), (9, ReplicaState::Partial)]),
            ),
            (3, HashMap::from([(9, ReplicaState::Dead)])),
        ] {
            let error = private_oram_shard_transfer_pre_layout_owners(shard_id, &peers, &transfer)
                .unwrap_err()
                .to_string();
            assert!(error.contains("layout transition is invalid"));
        }
    }

    #[test]
    fn private_oram_layout_reservation_requires_exact_live_lease() {
        let lease_hash = BASE64URL_NOPAD.encode(&[31; 32]);
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        assert!(private_oram_layout_reservation_matches(
            &lease,
            7,
            &lease_hash,
            120,
        ));
        assert!(!private_oram_layout_reservation_matches(
            &lease,
            9,
            &lease_hash,
            120,
        ));
        assert!(!private_oram_layout_reservation_matches(
            &lease,
            7,
            &BASE64URL_NOPAD.encode(&[32; 32]),
            120,
        ));
        assert!(!private_oram_layout_reservation_matches(
            &lease,
            7,
            &lease_hash,
            99,
        ));
        assert!(!private_oram_layout_reservation_matches(
            &lease,
            7,
            &lease_hash,
            160,
        ));
        assert!(decode_private_oram_sha256_digest(&lease_hash).is_some());
        assert!(decode_private_oram_sha256_digest("private-oram-layout-lease-sentinel").is_none());
    }

    #[test]
    fn private_oram_completion_wire_request_preserves_exact_transition() {
        let digest = BASE64URL_NOPAD.encode(&[47; 32]);
        let request = private_oram_complete_request(
            "docs",
            "collection-id",
            PrivateOramReplicationIndexKind::Hnsw,
            "text",
            42,
            "old-root",
            43,
            "new-root",
            &digest,
            "owner-key",
        )
        .unwrap();
        assert_eq!(
            request.index_kind,
            PrivateOramReplicationIndexKind::Hnsw as i32
        );
        assert_eq!(request.vector_name, "text");
        assert_eq!(request.transition.unwrap().writeback_digest, digest,);

        let error = private_oram_complete_request(
            "docs",
            "collection-id",
            PrivateOramReplicationIndexKind::Result,
            "text",
            42,
            "old-root",
            43,
            "new-root",
            &BASE64URL_NOPAD.encode(&[48; 32]),
            "owner-key",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("completion identity is invalid"));
        assert!(!error.contains("old-root"));
        assert!(!error.contains("new-root"));

        let root_sentinel = "private-oram-invalid-root-sentinel";
        let error = validate_private_oram_root_hash(root_sentinel)
            .unwrap_err()
            .to_string();
        assert!(error.contains("consensus root hash is invalid"));
        assert!(!error.contains(root_sentinel));
    }
}
