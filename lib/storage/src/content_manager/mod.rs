use collection::shards::shard::PeerId;

use self::collection_meta_ops::CollectionMetaOperations;
use self::consensus_manager::CollectionsSnapshot;
use self::errors::StorageError;

pub mod alias_mapping;
pub mod collection_meta_ops;
pub mod collection_verification;
mod collections_ops;
pub mod consensus;
pub mod consensus_manager;
pub mod conversions;
pub mod errors;
pub mod private_oram_mutation_journal;
mod private_oram_mutation_state_v2;
pub mod private_oram_point_staging;
pub mod shard_distribution;
pub mod snapshots;
#[cfg(feature = "staging")]
pub mod staging;
pub mod toc;

pub mod consensus_ops {
    use std::collections::BTreeSet;
    use std::fmt;

    use collection::config::{
        CollectionConfigInternal, EncryptionSelector, ShardingMethod,
        encryption_rule_uses_private_hnsw_oram, encryption_rule_uses_private_result_oram,
    };
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::operations::types::PeerMetadata;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::replica_set::replica_set_state::ReplicaState::Initializing;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::shard::{PeerId, ShardId};
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferLayoutState,
        PrivateOramTransferLayoutTransition, ShardTransfer, ShardTransferMethod,
    };
    use collection::shards::{CollectionId, replica_set};
    use data_encoding::BASE64URL_NOPAD;
    use raft::eraftpb::Entry as RaftEntry;
    use segment::types::ShardKey;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::collection_meta_ops::ReshardingOperation;
    use crate::content_manager::collection_meta_ops::{
        CollectionMetaOperations, SetShardReplicaState, ShardTransferOperations, UpdateCollection,
        UpdateCollectionOperation,
    };
    use crate::content_manager::errors::StorageError;

    const PRIVATE_ORAM_SHARD_LAYOUT_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-shard-layout-digest/v1";
    const PRIVATE_ORAM_CONSENSUS_STATE_CORE_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-consensus-state-core-digest/v2";
    const PRIVATE_ORAM_CONSENSUS_STATE_RECORD_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-consensus-state-record-digest/v2";
    const PRIVATE_ORAM_MUTATION_RECEIPT_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-mutation-receipt-digest/v2";
    const PRIVATE_ORAM_MUTATION_TRANSITION_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-mutation-transition-digest/v2";
    const PRIVATE_ORAM_CONSENSUS_MAX_RECORDS: usize = 1_000_000;
    const PRIVATE_ORAM_LAYOUT_MAX_OWNERS: usize = 10_000;
    pub const PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION: u16 = 2;
    pub const PRIVATE_ORAM_MUTATION_RECEIPT_VERSION: u16 = 2;
    pub const PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION: u16 = 2;
    pub const PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION: u16 = 1;
    pub const PRIVATE_ORAM_MUTATION_ACTIVATION_BARRIER_VERSION: u16 = 1;
    pub const PRIVATE_ORAM_SNAPSHOT_BARRIER_VERSION: u16 = 1;
    pub const PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION: u16 = 6;
    pub const PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION_V7: u16 = 7;
    pub const PRIVATE_ORAM_MUTATION_ACTIVATION_PROOF_MAX_BYTES: usize = 4 * 1024 * 1024;

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramIndexKind {
        Hnsw,
        ResultPayload,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramEpochKey {
        pub collection_id: CollectionId,
        pub index_kind: PrivateOramIndexKind,
        /// Vector name for HNSW; empty for the collection-wide result payload ORAM.
        pub index_name: String,
    }

    impl fmt::Debug for PrivateOramEpochKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramEpochKey")
                .field("index_kind", &self.index_kind)
                .field("collection_id", &"[redacted]")
                .field("index_name", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramConsensusEpoch {
        pub index_epoch: u64,
        pub root_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub writeback_digest: Option<String>,
    }

    impl fmt::Debug for PrivateOramConsensusEpoch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramConsensusEpoch")
                .field("index_epoch", &self.index_epoch)
                .field("root_hash", &"[redacted]")
                .field("has_writeback_digest", &self.writeback_digest.is_some())
                .finish()
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramEpoch {
        pub key: PrivateOramEpochKey,
        pub expected: Option<PrivateOramConsensusEpoch>,
        pub new: PrivateOramConsensusEpoch,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramSessionLease {
        pub owner_peer_id: PeerId,
        pub lease_id_hash: String,
        pub issued_at_unix: u64,
        pub expires_at_unix: u64,
    }

    impl fmt::Debug for PrivateOramSessionLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramSessionLease")
                .field("owner_peer_id", &self.owner_peer_id)
                .field("lease_id_hash", &"[redacted]")
                .field("issued_at_unix", &self.issued_at_unix)
                .field("expires_at_unix", &self.expires_at_unix)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramSessionLease {
        pub key: PrivateOramEpochKey,
        pub expected: Option<PrivateOramSessionLease>,
        pub new: Option<PrivateOramSessionLease>,
    }

    impl fmt::Debug for CompareAndSwapPrivateOramSessionLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CompareAndSwapPrivateOramSessionLease")
                .field("key", &self.key)
                .field("has_expected", &self.expected.is_some())
                .field("has_new", &self.new.is_some())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramMutationKey {
        pub collection_id: CollectionId,
    }

    impl fmt::Debug for PrivateOramMutationKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramMutationKey")
                .field("collection_id", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramConsensusCollectionIndexStateV2 {
        pub index_kind: PrivateOramIndexKind,
        pub index_name: String,
        pub epoch: PrivateOramConsensusEpoch,
        pub logical_count: u64,
        pub dummy_count: u64,
    }

    impl fmt::Debug for PrivateOramConsensusCollectionIndexStateV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramConsensusCollectionIndexStateV2")
                .field("index_kind", &self.index_kind)
                .field("index_name", &"[redacted]")
                .field("index_epoch", &self.epoch.index_epoch)
                .field("root_hash", &"[redacted]")
                .field(
                    "has_writeback_digest",
                    &self.epoch.writeback_digest.is_some(),
                )
                .field("logical_count", &self.logical_count)
                .field("dummy_count", &self.dummy_count)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramMutationReceiptV2 {
        pub version: u16,
        pub mutation_id: String,
        pub signed_mutation_digest: String,
        pub transition_digest: String,
        pub old_state_sequence: u64,
        pub old_state_digest: String,
        pub new_state_sequence: u64,
        pub new_state_digest: String,
        pub point_operation_digest: String,
        pub writer_lease_digest: String,
        pub writer_fence: u64,
        pub mutation_lease_generation: u64,
    }

    impl fmt::Debug for PrivateOramMutationReceiptV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramMutationReceiptV2")
                .field("version", &self.version)
                .field("mutation_id", &"[redacted]")
                .field("signed_mutation_digest", &"[redacted]")
                .field("transition_digest", &"[redacted]")
                .field("old_state_sequence", &self.old_state_sequence)
                .field("old_state_digest", &"[redacted]")
                .field("new_state_sequence", &self.new_state_sequence)
                .field("new_state_digest", &"[redacted]")
                .field("point_operation_digest", &"[redacted]")
                .field("writer_lease_digest", &"[redacted]")
                .field("writer_fence", &self.writer_fence)
                .field("mutation_lease_generation", &"[redacted]")
                .finish()
        }
    }

    // Mutation receipts are bounded, and direct value semantics keep consensus fixtures simple.
    #[allow(clippy::large_enum_variant)]
    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(
        tag = "kind",
        content = "receipt",
        rename_all = "snake_case",
        deny_unknown_fields
    )]
    pub enum PrivateOramConsensusTransitionV2 {
        Genesis,
        Mutation(PrivateOramMutationReceiptV2),
    }

    impl fmt::Debug for PrivateOramConsensusTransitionV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Genesis => f.write_str("Genesis"),
                Self::Mutation(_) => f.write_str("Mutation([redacted])"),
            }
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramConsensusCollectionStateV2 {
        pub version: u16,
        pub collection_id: CollectionId,
        pub manifest_digest: String,
        pub layout_generation: u64,
        pub layout_digest: String,
        pub state_sequence: u64,
        pub signed_state_digest: String,
        pub indexes: Vec<PrivateOramConsensusCollectionIndexStateV2>,
        pub client_state_digest: String,
        pub last_transition: PrivateOramConsensusTransitionV2,
    }

    impl fmt::Debug for PrivateOramConsensusCollectionStateV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramConsensusCollectionStateV2")
                .field("version", &self.version)
                .field("collection_id", &"[redacted]")
                .field("manifest_digest", &"[redacted]")
                .field("layout_generation", &self.layout_generation)
                .field("layout_digest", &"[redacted]")
                .field("state_sequence", &self.state_sequence)
                .field("signed_state_digest", &"[redacted]")
                .field("index_count", &self.indexes.len())
                .field("client_state_digest", &"[redacted]")
                .field("last_transition", &self.last_transition)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    pub enum PrivateOramMutationLeasePhase {
        Preparing,
        AbortDecided,
        ConsensusCommitted {
            committed_record_digest: String,
            committed_state_sequence: u64,
            committed_signed_state_digest: String,
            receipt_digest: String,
        },
    }

    impl fmt::Debug for PrivateOramMutationLeasePhase {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Preparing => f.write_str("Preparing"),
                Self::AbortDecided => f.write_str("AbortDecided"),
                Self::ConsensusCommitted {
                    committed_state_sequence,
                    ..
                } => f
                    .debug_struct("ConsensusCommitted")
                    .field("committed_state_sequence", committed_state_sequence)
                    .field("committed_record_digest", &"[redacted]")
                    .field("committed_signed_state_digest", &"[redacted]")
                    .field("receipt_digest", &"[redacted]")
                    .finish(),
            }
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramMutationLease {
        pub generation: u64,
        pub collection_id: CollectionId,
        pub owner_peer_id: PeerId,
        pub mutation_id: String,
        pub signed_mutation_digest: String,
        pub transition_digest: String,
        pub base_record_digest: String,
        pub base_state_sequence: u64,
        pub writer_lease_digest: String,
        pub writer_fence: u64,
        pub issued_at_unix: u64,
        pub expires_at_unix: u64,
        pub renewal_revision: u64,
        pub phase: PrivateOramMutationLeasePhase,
    }

    impl fmt::Debug for PrivateOramMutationLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramMutationLease")
                .field("generation", &"[redacted]")
                .field("collection_id", &"[redacted]")
                .field("owner_peer_id", &self.owner_peer_id)
                .field("mutation_id", &"[redacted]")
                .field("signed_mutation_digest", &"[redacted]")
                .field("transition_digest", &"[redacted]")
                .field("base_record_digest", &"[redacted]")
                .field("base_state_sequence", &self.base_state_sequence)
                .field("writer_lease_digest", &"[redacted]")
                .field("writer_fence", &self.writer_fence)
                .field("issued_at_unix", &self.issued_at_unix)
                .field("expires_at_unix", &self.expires_at_unix)
                .field("renewal_revision", &self.renewal_revision)
                .field("phase", &self.phase)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramMutationClearOutcome {
        AbortedBeforeConsensusCommit,
        FinalizedOrReconciledAfterConsensusCommit,
    }

    impl fmt::Debug for PrivateOramMutationClearOutcome {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::AbortedBeforeConsensusCommit => f.write_str("AbortedBeforeConsensusCommit"),
                Self::FinalizedOrReconciledAfterConsensusCommit => {
                    f.write_str("FinalizedOrReconciledAfterConsensusCommit")
                }
            }
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramMutationClearReceiptV1 {
        pub version: u16,
        pub generation: u64,
        pub mutation_id: String,
        pub outcome: PrivateOramMutationClearOutcome,
        pub terminal_state_digest: String,
        pub reconciliation_digest: String,
    }

    impl fmt::Debug for PrivateOramMutationClearReceiptV1 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramMutationClearReceiptV1")
                .field("version", &self.version)
                .field("generation", &"[redacted]")
                .field("mutation_id", &"[redacted]")
                .field("outcome", &self.outcome)
                .field("terminal_state_digest", &"[redacted]")
                .field("reconciliation_digest", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramMutationLeaseSlotV2 {
        pub version: u16,
        pub generation: u64,
        pub active: Option<PrivateOramMutationLease>,
        pub last_clear: Option<PrivateOramMutationClearReceiptV1>,
        pub max_writer_fence: u64,
    }

    impl fmt::Debug for PrivateOramMutationLeaseSlotV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramMutationLeaseSlotV2")
                .field("version", &self.version)
                .field("generation", &"[redacted]")
                .field("has_active", &self.active.is_some())
                .field(
                    "active_phase",
                    &self.active.as_ref().map(|lease| &lease.phase),
                )
                .field("has_last_clear", &self.last_clear.is_some())
                .field("max_writer_fence", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct InitializePrivateOramMutationState {
        pub key: PrivateOramMutationKey,
        pub state: PrivateOramConsensusCollectionStateV2,
    }

    impl fmt::Debug for InitializePrivateOramMutationState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("InitializePrivateOramMutationState")
                .field("key", &self.key)
                .field("state_sequence", &self.state.state_sequence)
                .field("index_count", &self.state.indexes.len())
                .finish()
        }
    }

    /// Atomically binds an already replicated V1 epoch/root set to a signed V2 genesis state.
    ///
    /// Initial V1 uploads intentionally publish epochs without writeback digests. Enrollment is
    /// the only transition allowed to replace those missing digests while also publishing the
    /// first collection layout, mutation state, and empty mutation authority slot.
    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct EnrollPrivateOramMutationStateV2 {
        pub key: PrivateOramMutationKey,
        pub layout: PrivateOramConsensusLayout,
        pub state: PrivateOramConsensusCollectionStateV2,
    }

    impl fmt::Debug for EnrollPrivateOramMutationStateV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("EnrollPrivateOramMutationStateV2")
                .field("key", &self.key)
                .field("layout_generation", &self.layout.generation)
                .field("owner_count", &self.layout.owner_peer_ids.len())
                .field("state_sequence", &self.state.state_sequence)
                .field("index_count", &self.state.indexes.len())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct CompareAndSwapPrivateOramMutationLease {
        pub key: PrivateOramMutationKey,
        pub expected: PrivateOramMutationLeaseSlotV2,
        pub new: PrivateOramMutationLeaseSlotV2,
    }

    impl fmt::Debug for CompareAndSwapPrivateOramMutationLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CompareAndSwapPrivateOramMutationLease")
                .field("key", &self.key)
                .field("expected", &self.expected)
                .field("new", &self.new)
                .finish()
        }
    }

    /// A Raft-applied, read-only fence for coordinator recovery side effects.
    ///
    /// The expected slot is deliberately carried through consensus. Applying this operation
    /// confirms that the exact mutation generation is still authoritative and commits the Raft
    /// apply cursor in the same durable persistent-state transaction.
    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct ConfirmPrivateOramMutationAuthorityV2 {
        pub key: PrivateOramMutationKey,
        pub expected: PrivateOramMutationLeaseSlotV2,
    }

    impl fmt::Debug for ConfirmPrivateOramMutationAuthorityV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ConfirmPrivateOramMutationAuthorityV2")
                .field("collection_id", &"[redacted]")
                .field("generation", &"[redacted]")
                .field(
                    "owner_peer_id",
                    &self
                        .expected
                        .active
                        .as_ref()
                        .map(|lease| lease.owner_peer_id),
                )
                .field(
                    "active_phase",
                    &self.expected.active.as_ref().map(|lease| &lease.phase),
                )
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct ApplyPrivateOramMutation {
        pub key: PrivateOramMutationKey,
        pub mutation_lease_generation: u64,
        pub expected_state: PrivateOramConsensusCollectionStateV2,
        pub new_state: PrivateOramConsensusCollectionStateV2,
    }

    impl fmt::Debug for ApplyPrivateOramMutation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ApplyPrivateOramMutation")
                .field("key", &self.key)
                .field("mutation_lease_generation", &"[redacted]")
                .field("layout_generation", &self.expected_state.layout_generation)
                .field(
                    "expected_state_sequence",
                    &self.expected_state.state_sequence,
                )
                .field("new_state_sequence", &self.new_state.state_sequence)
                .field("index_count", &self.new_state.indexes.len())
                .finish()
        }
    }

    /// Post-activation mutation command. The committed Raft entry supplies its own apply locator;
    /// neither that locator nor the resulting outer authority binding is accepted from callers.
    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct ApplyPrivateOramMutationMaterialV2 {
        version: u16,
        key: PrivateOramMutationKey,
        expected_aggregate_digest: String,
        transition: PrivateOramMutationMaterialTransitionV2,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    pub(crate) enum PrivateOramMutationMaterialTransitionV2 {
        OwnerEnrollmentPrepared {
            prepared_canonical_json: String,
        },
        OwnerEnrollmentActivated {
            commitment_canonical_json: String,
        },
        AppendReservationChallengePrepared {
            challenge_canonical_json: String,
        },
        AppendReservationFinalizedV3 {
            reservation_canonical_json: String,
        },
        AppendReservationChallengeCancelled {
            cancellation_canonical_json: String,
        },
        AppendReservationOutcomeAcknowledged {
            acknowledgement_canonical_json: String,
        },
        AppendReservation {
            reservation_canonical_json: String,
        },
        AppendPrepared {
            recovery_manifest_canonical_json: String,
        },
        ReservedAttemptRejected {
            reservation_canonical_json: String,
        },
        Admission {
            lease: PrivateOramMutationLease,
            recovery_manifest_canonical_json: String,
        },
        AdmissionRejected {
            lease: PrivateOramMutationLease,
            recovery_manifest_canonical_json: String,
        },
        Renewal {
            lease: PrivateOramMutationLease,
        },
        AbortDecision {
            lease: PrivateOramMutationLease,
        },
        ConsensusCommit {
            mutation_lease_generation: u64,
            new_state: PrivateOramConsensusCollectionStateV2,
        },
        ParentProgress {
            watermark_canonical_json: String,
        },
        RecoveryCapsulesReady {
            expectation_canonical_json: String,
        },
        CleanupWitness {
            expectation_canonical_json: String,
        },
        ClearPending {
            clear_attempt_id_digest: String,
        },
        Clear,
        ClearAcknowledgement,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum PrivateOramMutationMaterialTransitionKindV2 {
        OwnerEnrollmentPrepared,
        OwnerEnrollmentActivated,
        AppendReservationChallengePrepared,
        AppendReservationFinalizedV3,
        AppendReservationChallengeCancelled,
        AppendReservationOutcomeAcknowledged,
        AppendReservation,
        AppendPrepared,
        ReservedAttemptRejected,
        Admission,
        AdmissionRejected,
        Renewal,
        AbortDecision,
        ConsensusCommit,
        ParentProgress,
        RecoveryCapsulesReady,
        CleanupWitness,
        ClearPending,
        Clear,
        ClearAcknowledgement,
    }

    impl ApplyPrivateOramMutationMaterialV2 {
        pub(crate) fn owner_enrollment_prepared(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            prepared_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentPrepared {
                    prepared_canonical_json,
                },
            }
        }

        pub(crate) fn owner_enrollment_activated(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            commitment_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentActivated {
                    commitment_canonical_json,
                },
            }
        }

        pub(crate) fn append_reservation(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            reservation_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::AppendReservation {
                    reservation_canonical_json,
                },
            }
        }

        pub(crate) fn append_reservation_challenge_prepared_v3(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            challenge_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION_V7,
                key,
                expected_aggregate_digest,
                transition:
                    PrivateOramMutationMaterialTransitionV2::AppendReservationChallengePrepared {
                        challenge_canonical_json,
                    },
            }
        }

        pub(crate) fn append_reservation_finalized_v3(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            reservation_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION_V7,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::AppendReservationFinalizedV3 {
                    reservation_canonical_json,
                },
            }
        }

        pub(crate) fn append_reservation_challenge_cancelled_v3(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            cancellation_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION_V7,
                key,
                expected_aggregate_digest,
                transition:
                    PrivateOramMutationMaterialTransitionV2::AppendReservationChallengeCancelled {
                        cancellation_canonical_json,
                    },
            }
        }

        pub(crate) fn append_reservation_outcome_acknowledged_v3(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            acknowledgement_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION_V7,
                key,
                expected_aggregate_digest,
                transition:
                    PrivateOramMutationMaterialTransitionV2::AppendReservationOutcomeAcknowledged {
                        acknowledgement_canonical_json,
                    },
            }
        }

        pub(crate) fn append_prepared(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            recovery_manifest_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::AppendPrepared {
                    recovery_manifest_canonical_json,
                },
            }
        }

        pub(crate) fn reserved_attempt_rejected(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            reservation_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::ReservedAttemptRejected {
                    reservation_canonical_json,
                },
            }
        }

        pub(crate) fn admission(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            lease: PrivateOramMutationLease,
            recovery_manifest_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::Admission {
                    lease,
                    recovery_manifest_canonical_json,
                },
            }
        }

        pub(crate) fn admission_rejected(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            lease: PrivateOramMutationLease,
            recovery_manifest_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::AdmissionRejected {
                    lease,
                    recovery_manifest_canonical_json,
                },
            }
        }

        pub(crate) fn renewal(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            lease: PrivateOramMutationLease,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::Renewal { lease },
            }
        }

        #[cfg(test)]
        pub(crate) fn abort_decision(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            lease: PrivateOramMutationLease,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::AbortDecision { lease },
            }
        }

        pub(crate) fn consensus_commit(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            mutation_lease_generation: u64,
            new_state: PrivateOramConsensusCollectionStateV2,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::ConsensusCommit {
                    mutation_lease_generation,
                    new_state,
                },
            }
        }

        pub(in crate::content_manager) fn parent_progress(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            watermark_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::ParentProgress {
                    watermark_canonical_json,
                },
            }
        }

        pub(in crate::content_manager) fn recovery_capsules_ready(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            expectation_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::RecoveryCapsulesReady {
                    expectation_canonical_json,
                },
            }
        }

        pub(in crate::content_manager) fn cleanup_witness(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            expectation_canonical_json: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::CleanupWitness {
                    expectation_canonical_json,
                },
            }
        }

        pub(in crate::content_manager) fn clear_pending(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
            clear_attempt_id_digest: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::ClearPending {
                    clear_attempt_id_digest,
                },
            }
        }

        pub(in crate::content_manager) fn clear(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::Clear,
            }
        }

        pub(in crate::content_manager) fn clear_acknowledgement(
            key: PrivateOramMutationKey,
            expected_aggregate_digest: String,
        ) -> Self {
            Self {
                version: PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION,
                key,
                expected_aggregate_digest,
                transition: PrivateOramMutationMaterialTransitionV2::ClearAcknowledgement,
            }
        }

        pub(crate) fn version(&self) -> u16 {
            self.version
        }

        pub(crate) fn key(&self) -> &PrivateOramMutationKey {
            &self.key
        }

        pub(crate) fn expected_aggregate_digest(&self) -> &str {
            &self.expected_aggregate_digest
        }

        pub(crate) fn transition(&self) -> &PrivateOramMutationMaterialTransitionV2 {
            &self.transition
        }

        pub(crate) fn transition_kind(&self) -> PrivateOramMutationMaterialTransitionKindV2 {
            match &self.transition {
                PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentPrepared { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::OwnerEnrollmentPrepared
                }
                PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentActivated { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::OwnerEnrollmentActivated
                }
                PrivateOramMutationMaterialTransitionV2::AppendReservationChallengePrepared {
                    ..
                } => {
                    PrivateOramMutationMaterialTransitionKindV2::AppendReservationChallengePrepared
                }
                PrivateOramMutationMaterialTransitionV2::AppendReservationFinalizedV3 {
                    ..
                } => PrivateOramMutationMaterialTransitionKindV2::AppendReservationFinalizedV3,
                PrivateOramMutationMaterialTransitionV2::AppendReservationChallengeCancelled {
                    ..
                } => {
                    PrivateOramMutationMaterialTransitionKindV2::AppendReservationChallengeCancelled
                }
                PrivateOramMutationMaterialTransitionV2::AppendReservationOutcomeAcknowledged {
                    ..
                } => {
                    PrivateOramMutationMaterialTransitionKindV2::AppendReservationOutcomeAcknowledged
                }
                PrivateOramMutationMaterialTransitionV2::AppendReservation { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::AppendReservation
                }
                PrivateOramMutationMaterialTransitionV2::AppendPrepared { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::AppendPrepared
                }
                PrivateOramMutationMaterialTransitionV2::ReservedAttemptRejected { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::ReservedAttemptRejected
                }
                PrivateOramMutationMaterialTransitionV2::Admission { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::Admission
                }
                PrivateOramMutationMaterialTransitionV2::AdmissionRejected { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::AdmissionRejected
                }
                PrivateOramMutationMaterialTransitionV2::Renewal { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::Renewal
                }
                PrivateOramMutationMaterialTransitionV2::AbortDecision { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::AbortDecision
                }
                PrivateOramMutationMaterialTransitionV2::ConsensusCommit { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::ConsensusCommit
                }
                PrivateOramMutationMaterialTransitionV2::ParentProgress { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::ParentProgress
                }
                PrivateOramMutationMaterialTransitionV2::RecoveryCapsulesReady { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::RecoveryCapsulesReady
                }
                PrivateOramMutationMaterialTransitionV2::CleanupWitness { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::CleanupWitness
                }
                PrivateOramMutationMaterialTransitionV2::ClearPending { .. } => {
                    PrivateOramMutationMaterialTransitionKindV2::ClearPending
                }
                PrivateOramMutationMaterialTransitionV2::Clear => {
                    PrivateOramMutationMaterialTransitionKindV2::Clear
                }
                PrivateOramMutationMaterialTransitionV2::ClearAcknowledgement => {
                    PrivateOramMutationMaterialTransitionKindV2::ClearAcknowledgement
                }
            }
        }
    }

    impl fmt::Debug for ApplyPrivateOramMutationMaterialV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut debug = f.debug_struct("ApplyPrivateOramMutationMaterialV2");
            debug
                .field("version", &self.version)
                .field("collection_id", &"[redacted]")
                .field("expected_aggregate_digest", &"[redacted]")
                .field("transition_kind", &self.transition_kind());
            match &self.transition {
                PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentPrepared {
                    prepared_canonical_json,
                } => debug.field("payload_bytes", &prepared_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentActivated {
                    commitment_canonical_json,
                } => debug.field("payload_bytes", &commitment_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::AppendReservationChallengePrepared {
                    challenge_canonical_json,
                } => debug.field("payload_bytes", &challenge_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::AppendReservationChallengeCancelled {
                    cancellation_canonical_json,
                } => debug.field("payload_bytes", &cancellation_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::AppendReservationOutcomeAcknowledged {
                    acknowledgement_canonical_json,
                } => debug.field("payload_bytes", &acknowledgement_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::AppendReservationFinalizedV3 {
                    reservation_canonical_json,
                }
                | PrivateOramMutationMaterialTransitionV2::AppendReservation {
                    reservation_canonical_json,
                }
                | PrivateOramMutationMaterialTransitionV2::ReservedAttemptRejected {
                    reservation_canonical_json,
                } => debug.field("payload_bytes", &reservation_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::AppendPrepared {
                    recovery_manifest_canonical_json,
                } => debug.field(
                    "recovery_manifest_bytes",
                    &recovery_manifest_canonical_json.len(),
                ),
                PrivateOramMutationMaterialTransitionV2::Admission {
                    lease,
                    recovery_manifest_canonical_json,
                }
                | PrivateOramMutationMaterialTransitionV2::AdmissionRejected {
                    lease,
                    recovery_manifest_canonical_json,
                } => debug
                    .field("generation", &"[redacted]")
                    .field("owner_peer_id", &lease.owner_peer_id)
                    .field("phase", &lease.phase)
                    .field(
                        "recovery_manifest_bytes",
                        &recovery_manifest_canonical_json.len(),
                    ),
                PrivateOramMutationMaterialTransitionV2::Renewal { lease }
                | PrivateOramMutationMaterialTransitionV2::AbortDecision { lease } => debug
                    .field("generation", &"[redacted]")
                    .field("owner_peer_id", &lease.owner_peer_id)
                    .field("phase", &lease.phase),
                PrivateOramMutationMaterialTransitionV2::ConsensusCommit {
                    mutation_lease_generation: _,
                    new_state,
                } => debug
                    .field("generation", &"[redacted]")
                    .field("new_state_sequence", &new_state.state_sequence)
                    .field("index_count", &new_state.indexes.len()),
                PrivateOramMutationMaterialTransitionV2::ParentProgress {
                    watermark_canonical_json,
                } => debug.field("payload_bytes", &watermark_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::RecoveryCapsulesReady {
                    expectation_canonical_json,
                } => debug.field("payload_bytes", &expectation_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::CleanupWitness {
                    expectation_canonical_json,
                } => debug.field("payload_bytes", &expectation_canonical_json.len()),
                PrivateOramMutationMaterialTransitionV2::ClearPending { .. }
                | PrivateOramMutationMaterialTransitionV2::Clear
                | PrivateOramMutationMaterialTransitionV2::ClearAcknowledgement => &mut debug,
            };
            debug.finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramExternalRecoveryKey {
        pub collection_id: CollectionId,
    }

    impl fmt::Debug for PrivateOramExternalRecoveryKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramExternalRecoveryKey")
                .field("collection_id", &"[redacted]")
                .finish()
        }
    }

    #[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramExternalRecoveryLeasePhase {
        #[default]
        Staging,
        Installing,
    }

    #[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramExternalRecoveryAuthority {
        #[default]
        LegacyV1,
        MutationV2,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramExternalRecoveryLease {
        pub owner_peer_id: PeerId,
        pub operation_id_hash: String,
        pub checkpoint_digest: String,
        pub backup_generation: u64,
        pub issued_at_unix: u64,
        pub expires_at_unix: u64,
        #[serde(default)]
        pub authority: PrivateOramExternalRecoveryAuthority,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub install_intent_digest: Option<String>,
        #[serde(default)]
        pub phase: PrivateOramExternalRecoveryLeasePhase,
    }

    impl fmt::Debug for PrivateOramExternalRecoveryLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramExternalRecoveryLease")
                .field("owner_peer_id", &self.owner_peer_id)
                .field("operation_id_hash", &"[redacted]")
                .field("checkpoint_digest", &"[redacted]")
                .field("backup_generation", &self.backup_generation)
                .field("issued_at_unix", &self.issued_at_unix)
                .field("expires_at_unix", &self.expires_at_unix)
                .field("authority", &self.authority)
                .field(
                    "has_install_intent_digest",
                    &self.install_intent_digest.is_some(),
                )
                .field("phase", &self.phase)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramExternalRecoveryState {
        pub committed_backup_generation: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub committed_checkpoint_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub committed_install_intent_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub active_lease: Option<PrivateOramExternalRecoveryLease>,
    }

    impl fmt::Debug for PrivateOramExternalRecoveryState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramExternalRecoveryState")
                .field(
                    "committed_backup_generation",
                    &self.committed_backup_generation,
                )
                .field(
                    "has_committed_checkpoint_digest",
                    &self.committed_checkpoint_digest.is_some(),
                )
                .field(
                    "has_committed_install_intent_digest",
                    &self.committed_install_intent_digest.is_some(),
                )
                .field("active_lease", &self.active_lease)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramExternalRecovery {
        pub key: PrivateOramExternalRecoveryKey,
        pub expected: Option<PrivateOramExternalRecoveryState>,
        pub new: Option<PrivateOramExternalRecoveryState>,
    }

    impl fmt::Debug for CompareAndSwapPrivateOramExternalRecovery {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CompareAndSwapPrivateOramExternalRecovery")
                .field("key", &self.key)
                .field("has_expected", &self.expected.is_some())
                .field("has_new", &self.new.is_some())
                .finish()
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramExternalRecoveryPhase {
        Begin,
        Renew,
        PrepareInstall,
        RollbackInstall,
        Commit,
        Abort,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramExternalRecoveryOperation {
        pub phase: PrivateOramExternalRecoveryPhase,
        pub recovery: CompareAndSwapPrivateOramExternalRecovery,
        pub layout: PrivateOramConsensusLayout,
        pub index_states: Vec<PrivateOramLayoutIndexStateBinding>,
    }

    impl fmt::Debug for PrivateOramExternalRecoveryOperation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramExternalRecoveryOperation")
                .field("phase", &self.phase)
                .field("has_expected", &self.recovery.expected.is_some())
                .field("has_new", &self.recovery.new.is_some())
                .field("layout_generation", &self.layout.generation)
                .field("index_state_count", &self.index_states.len())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramLayoutKey {
        pub collection_id: CollectionId,
    }

    impl fmt::Debug for PrivateOramLayoutKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramLayoutKey")
                .field("collection_id", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramConsensusLayout {
        /// Starts at one and advances by exactly one for every accepted layout transition.
        pub generation: u64,
        /// Canonical strictly increasing union of peers that own fully-active shard replicas.
        pub owner_peer_ids: Vec<PeerId>,
        /// Base64url SHA-256 of the canonical shard layout.
        pub layout_digest: String,
        /// Base64url SHA-256 of the index epoch/root/completion set at this layout transition.
        pub index_state_digest: String,
    }

    impl fmt::Debug for PrivateOramConsensusLayout {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramConsensusLayout")
                .field("generation", &self.generation)
                .field("owner_peer_count", &self.owner_peer_ids.len())
                .field("layout_digest", &"[redacted]")
                .field("index_state_digest", &"[redacted]")
                .finish()
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramLayout {
        pub key: PrivateOramLayoutKey,
        pub expected: Option<PrivateOramConsensusLayout>,
        pub new: PrivateOramConsensusLayout,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramLayoutIndexStateBinding {
        pub key: PrivateOramEpochKey,
        pub state: PrivateOramConsensusEpoch,
    }

    impl fmt::Debug for PrivateOramLayoutIndexStateBinding {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramLayoutIndexStateBinding")
                .field("index_kind", &self.key.index_kind)
                .field("index_epoch", &self.state.index_epoch)
                .field(
                    "has_writeback_digest",
                    &self.state.writeback_digest.is_some(),
                )
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramReshardingLayoutTransition {
        pub resharding_key: ReshardKey,
        /// Owners of the shard added by scale-up or removed by scale-down.
        pub target_shard_owner_peer_ids: Vec<PeerId>,
        pub layout: CompareAndSwapPrivateOramLayout,
        pub index_states: Vec<PrivateOramLayoutIndexStateBinding>,
    }

    impl fmt::Debug for PrivateOramReshardingLayoutTransition {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramReshardingLayoutTransition")
                .field("direction", &self.resharding_key.direction)
                .field("target_shard_id", &self.resharding_key.shard_id)
                .field("target_peer_id", &self.resharding_key.peer_id)
                .field(
                    "target_shard_owner_count",
                    &self.target_shard_owner_peer_ids.len(),
                )
                .field("has_expected", &self.layout.expected.is_some())
                .field("new_generation", &self.layout.new.generation)
                .field("index_state_count", &self.index_states.len())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramReshardingOperation {
        pub leases: Vec<PrivateOramLayoutLeaseBinding>,
        pub transition: PrivateOramReshardingLayoutTransition,
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramReshardingOperation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let phase = match self.collection_meta.as_ref() {
                CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)) => "start",
                CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)) => "finish",
                _ => "invalid",
            };
            f.debug_struct("PrivateOramReshardingOperation")
                .field("phase", &phase)
                .field("lease_count", &self.leases.len())
                .field("transition", &self.transition)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramLayoutLeaseBinding {
        pub key: PrivateOramEpochKey,
        pub lease: PrivateOramSessionLease,
    }

    impl fmt::Debug for PrivateOramLayoutLeaseBinding {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramLayoutLeaseBinding")
                .field("index_kind", &self.key.index_kind)
                .field("owner_peer_id", &self.lease.owner_peer_id)
                .field("issued_at_unix", &self.lease.issued_at_unix)
                .field("expires_at_unix", &self.lease.expires_at_unix)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramCollectionLayoutTransition {
        pub layout: CompareAndSwapPrivateOramLayout,
        pub leases: Vec<PrivateOramLayoutLeaseBinding>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub shard_key_change: Option<PrivateOramShardKeyLayoutChange>,
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramCollectionLayoutTransition {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramCollectionLayoutTransition")
                .field("has_expected", &self.layout.expected.is_some())
                .field("new_generation", &self.layout.new.generation)
                .field("lease_count", &self.leases.len())
                .field("shard_key_change", &self.shard_key_change)
                .field("collection_meta", &self.collection_meta.redacted_log())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramShardTransferStart {
        pub leases: Vec<PrivateOramLayoutLeaseBinding>,
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramShardTransferStart {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardTransferStart")
                .field("lease_count", &self.leases.len())
                .field("collection_meta", &self.collection_meta.redacted_log())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramShardTransferFinish {
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramShardTransferFinish {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardTransferFinish")
                .field("collection_meta", &self.collection_meta.redacted_log())
                .finish()
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum PrivateOramLayoutTransitionState {
        Pending,
        Applied,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramShardLayoutEntry {
        pub shard_id: ShardId,
        pub shard_key: Option<ShardKey>,
        pub owner_peer_ids: Vec<PeerId>,
    }

    impl fmt::Debug for PrivateOramShardLayoutEntry {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardLayoutEntry")
                .field("shard_id", &self.shard_id)
                .field("shard_key_present", &self.shard_key.is_some())
                .field("owner_peer_count", &self.owner_peer_ids.len())
                .finish()
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramShardKeyLayoutChangeKind {
        Create,
        Drop,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramShardKeyLayoutChange {
        pub kind: PrivateOramShardKeyLayoutChangeKind,
        pub shard_key: ShardKey,
        pub entries: Vec<PrivateOramShardLayoutEntry>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub preinstalled_new_owner_peer_ids: Vec<PeerId>,
    }

    impl fmt::Debug for PrivateOramShardKeyLayoutChange {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardKeyLayoutChange")
                .field("kind", &self.kind)
                .field("shard_key", &"[redacted]")
                .field("entry_count", &self.entries.len())
                .field(
                    "preinstalled_new_owner_count",
                    &self.preinstalled_new_owner_peer_ids.len(),
                )
                .finish()
        }
    }

    pub fn canonical_private_oram_shard_layout_digest(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        if !valid_private_oram_collection_id(collection_id)
            || entries.is_empty()
            || entries.len() > PRIVATE_ORAM_CONSENSUS_MAX_RECORDS
        {
            return Err(invalid_private_oram_layout_digest_input());
        }

        let mut entries = entries.to_vec();
        entries.sort_by_key(|entry| entry.shard_id);
        if entries
            .windows(2)
            .any(|entries| entries[0].shard_id == entries[1].shard_id)
        {
            return Err(invalid_private_oram_layout_digest_input());
        }

        let mut owner_union = BTreeSet::new();
        for entry in &mut entries {
            let valid_shard_key = matches!(
                (sharding_method, entry.shard_key.as_ref()),
                (ShardingMethod::Auto, None) | (ShardingMethod::Custom, Some(_))
            );
            if !valid_shard_key
                || entry.owner_peer_ids.is_empty()
                || entry.owner_peer_ids.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS
            {
                return Err(invalid_private_oram_layout_digest_input());
            }
            entry.owner_peer_ids.sort_unstable();
            if entry
                .owner_peer_ids
                .windows(2)
                .any(|owners| owners[0] == owners[1])
            {
                return Err(invalid_private_oram_layout_digest_input());
            }
            owner_union.extend(entry.owner_peer_ids.iter().copied());
        }
        if owner_union.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS {
            return Err(invalid_private_oram_layout_digest_input());
        }

        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_SHARD_LAYOUT_DIGEST_DOMAIN);
        update_private_oram_length_prefixed(&mut hasher, collection_id.as_bytes());
        hasher.update([match sharding_method {
            ShardingMethod::Auto => 1,
            ShardingMethod::Custom => 2,
        }]);
        hasher.update((entries.len() as u64).to_be_bytes());
        for entry in entries {
            hasher.update(entry.shard_id.to_be_bytes());
            match entry.shard_key {
                None => hasher.update([0]),
                Some(ShardKey::Keyword(value)) => {
                    hasher.update([1]);
                    update_private_oram_length_prefixed(&mut hasher, value.as_bytes());
                }
                Some(ShardKey::Number(value)) => {
                    hasher.update([2]);
                    hasher.update(value.to_be_bytes());
                }
            }
            hasher.update((entry.owner_peer_ids.len() as u64).to_be_bytes());
            for peer_id in entry.owner_peer_ids {
                hasher.update(peer_id.to_be_bytes());
            }
        }

        Ok((
            owner_union.into_iter().collect(),
            BASE64URL_NOPAD.encode(&hasher.finalize()),
        ))
    }

    pub fn canonical_private_oram_resharding_post_layout_digest(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        resharding_key: &ReshardKey,
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        // Validate the complete pre-layout before removing or adding an entry. Otherwise a
        // malformed scale-down target could disappear before canonical validation sees it.
        canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;

        let mut post_entries = entries.to_vec();
        match resharding_key.direction {
            ReshardingDirection::Up => {
                if post_entries
                    .iter()
                    .any(|entry| entry.shard_id == resharding_key.shard_id)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
                post_entries.push(PrivateOramShardLayoutEntry {
                    shard_id: resharding_key.shard_id,
                    shard_key: resharding_key.shard_key.clone(),
                    owner_peer_ids: vec![resharding_key.peer_id],
                });
            }
            ReshardingDirection::Down => {
                let entry_index = post_entries
                    .iter()
                    .position(|entry| entry.shard_id == resharding_key.shard_id)
                    .ok_or_else(invalid_private_oram_resharding_layout_input)?;
                let target = &post_entries[entry_index];
                if target.shard_key != resharding_key.shard_key
                    || !target.owner_peer_ids.contains(&resharding_key.peer_id)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
                post_entries.remove(entry_index);
                if !post_entries
                    .iter()
                    .any(|entry| entry.shard_key == resharding_key.shard_key)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
            }
        }

        canonical_private_oram_shard_layout_digest(collection_id, sharding_method, &post_entries)
            .map_err(|_| invalid_private_oram_resharding_layout_input())
    }

    pub fn classify_private_oram_resharding_layout_transition(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        transition: &PrivateOramReshardingLayoutTransition,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        validate_private_oram_resharding_layout_transition_shape(collection_id, transition)?;
        let expected = transition
            .layout
            .expected
            .as_ref()
            .ok_or_else(invalid_private_oram_resharding_layout_input)?;
        let (owner_peer_ids, layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)
                .map_err(|_| invalid_private_oram_resharding_layout_input())?;

        if private_oram_layout_topology_matches(expected, &owner_peer_ids, &layout_digest) {
            validate_private_oram_resharding_target_owners(entries, transition, true)?;
            let (new_owner_peer_ids, new_layout_digest) =
                canonical_private_oram_resharding_post_layout_digest(
                    collection_id,
                    sharding_method,
                    entries,
                    &transition.resharding_key,
                )?;
            if private_oram_layout_topology_matches(
                &transition.layout.new,
                &new_owner_peer_ids,
                &new_layout_digest,
            ) {
                return Ok(PrivateOramLayoutTransitionState::Pending);
            }
        } else if private_oram_layout_topology_matches(
            &transition.layout.new,
            &owner_peer_ids,
            &layout_digest,
        ) {
            let pre_entries = private_oram_resharding_pre_entries(entries, transition)?;
            let (old_owner_peer_ids, old_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &pre_entries,
                )
                .map_err(|_| invalid_private_oram_resharding_layout_input())?;
            if private_oram_layout_topology_matches(
                expected,
                &old_owner_peer_ids,
                &old_layout_digest,
            ) {
                return Ok(PrivateOramLayoutTransitionState::Applied);
            }
        }

        Err(invalid_private_oram_resharding_layout_input())
    }

    fn validate_private_oram_resharding_layout_transition_shape(
        collection_id: &str,
        transition: &PrivateOramReshardingLayoutTransition,
    ) -> Result<(), StorageError> {
        let Some(expected) = transition.layout.expected.as_ref() else {
            return Err(invalid_private_oram_resharding_layout_input());
        };
        if transition.layout.key.collection_id != collection_id
            || transition.target_shard_owner_peer_ids.is_empty()
            || transition.target_shard_owner_peer_ids.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS
            || transition
                .target_shard_owner_peer_ids
                .windows(2)
                .any(|owners| owners[0] >= owners[1])
            || !transition
                .target_shard_owner_peer_ids
                .contains(&transition.resharding_key.peer_id)
            || matches!(transition.resharding_key.direction, ReshardingDirection::Up)
                && transition.target_shard_owner_peer_ids.as_slice()
                    != [transition.resharding_key.peer_id]
            || expected.index_state_digest != transition.layout.new.index_state_digest
            || expected
                .generation
                .checked_add(1)
                .is_none_or(|generation| generation != transition.layout.new.generation)
            || decode_private_oram_sha256_digest(&expected.index_state_digest).is_none()
        {
            return Err(invalid_private_oram_resharding_layout_input());
        }
        Ok(())
    }

    fn validate_private_oram_resharding_target_owners(
        entries: &[PrivateOramShardLayoutEntry],
        transition: &PrivateOramReshardingLayoutTransition,
        pre_layout: bool,
    ) -> Result<(), StorageError> {
        match transition.resharding_key.direction {
            ReshardingDirection::Up if pre_layout => Ok(()),
            ReshardingDirection::Down if !pre_layout => Ok(()),
            ReshardingDirection::Up | ReshardingDirection::Down => {
                let target = entries
                    .iter()
                    .find(|entry| entry.shard_id == transition.resharding_key.shard_id)
                    .ok_or_else(invalid_private_oram_resharding_layout_input)?;
                let mut owners = target.owner_peer_ids.clone();
                owners.sort_unstable();
                if target.shard_key != transition.resharding_key.shard_key
                    || owners != transition.target_shard_owner_peer_ids
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
                Ok(())
            }
        }
    }

    fn private_oram_resharding_pre_entries(
        entries: &[PrivateOramShardLayoutEntry],
        transition: &PrivateOramReshardingLayoutTransition,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        let mut pre_entries = entries.to_vec();
        match transition.resharding_key.direction {
            ReshardingDirection::Up => {
                validate_private_oram_resharding_target_owners(entries, transition, false)?;
                let target_index = pre_entries
                    .iter()
                    .position(|entry| entry.shard_id == transition.resharding_key.shard_id)
                    .ok_or_else(invalid_private_oram_resharding_layout_input)?;
                pre_entries.remove(target_index);
                if pre_entries.is_empty() {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
            }
            ReshardingDirection::Down => {
                if pre_entries
                    .iter()
                    .any(|entry| entry.shard_id == transition.resharding_key.shard_id)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
                pre_entries.push(PrivateOramShardLayoutEntry {
                    shard_id: transition.resharding_key.shard_id,
                    shard_key: transition.resharding_key.shard_key.clone(),
                    owner_peer_ids: transition.target_shard_owner_peer_ids.clone(),
                });
            }
        }
        Ok(pre_entries)
    }

    pub fn classify_private_oram_replica_removal_layout_transition(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        shard_id: ShardId,
        peer_id: PeerId,
        expected: &PrivateOramConsensusLayout,
        new: &PrivateOramConsensusLayout,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (owner_peer_ids, layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;
        if private_oram_layout_topology_matches(expected, &owner_peer_ids, &layout_digest) {
            let mut post_entries = entries.to_vec();
            let entry = post_entries
                .iter_mut()
                .find(|entry| entry.shard_id == shard_id)
                .ok_or_else(invalid_private_oram_layout_transition_input)?;
            let owner_index = entry
                .owner_peer_ids
                .iter()
                .position(|owner| *owner == peer_id)
                .ok_or_else(invalid_private_oram_layout_transition_input)?;
            entry.owner_peer_ids.remove(owner_index);
            let (new_owner_peer_ids, new_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &post_entries,
                )?;
            if private_oram_layout_topology_matches(new, &new_owner_peer_ids, &new_layout_digest) {
                return Ok(PrivateOramLayoutTransitionState::Pending);
            }
        } else if private_oram_layout_topology_matches(new, &owner_peer_ids, &layout_digest) {
            let mut pre_entries = entries.to_vec();
            let entry = pre_entries
                .iter_mut()
                .find(|entry| entry.shard_id == shard_id)
                .ok_or_else(invalid_private_oram_layout_transition_input)?;
            if entry.owner_peer_ids.contains(&peer_id) {
                return Err(invalid_private_oram_layout_transition_input());
            }
            entry.owner_peer_ids.push(peer_id);
            let (old_owner_peer_ids, old_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &pre_entries,
                )?;
            if private_oram_layout_topology_matches(
                expected,
                &old_owner_peer_ids,
                &old_layout_digest,
            ) {
                return Ok(PrivateOramLayoutTransitionState::Applied);
            }
        }
        Err(invalid_private_oram_layout_transition_input())
    }

    pub fn private_oram_shard_key_post_layout_entries(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        change: &PrivateOramShardKeyLayoutChange,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        let (current_owner_peer_ids, _) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;
        if sharding_method != ShardingMethod::Custom
            || change.entries.is_empty()
            || change.entries.len() > PRIVATE_ORAM_CONSENSUS_MAX_RECORDS
            || change.preinstalled_new_owner_peer_ids.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS
            || change
                .preinstalled_new_owner_peer_ids
                .windows(2)
                .any(|owners| owners[0] >= owners[1])
            || change
                .entries
                .iter()
                .any(|entry| entry.shard_key.as_ref() != Some(&change.shard_key))
        {
            return Err(invalid_private_oram_layout_transition_input());
        }

        let mut changed_entries = change.entries.clone();
        changed_entries.sort_by_key(|entry| entry.shard_id);
        let post_entries = match change.kind {
            PrivateOramShardKeyLayoutChangeKind::Create => {
                if entries
                    .iter()
                    .any(|entry| entry.shard_key.as_ref() == Some(&change.shard_key))
                {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                let max_shard_id = entries
                    .iter()
                    .map(|entry| entry.shard_id)
                    .max()
                    .ok_or_else(invalid_private_oram_layout_transition_input)?;
                for (offset, entry) in changed_entries.iter().enumerate() {
                    let offset = ShardId::try_from(offset)
                        .map_err(|_| invalid_private_oram_layout_transition_input())?;
                    let expected_shard_id = max_shard_id
                        .checked_add(offset)
                        .and_then(|shard_id| shard_id.checked_add(1))
                        .ok_or_else(invalid_private_oram_layout_transition_input)?;
                    if entry.shard_id != expected_shard_id {
                        return Err(invalid_private_oram_layout_transition_input());
                    }
                }
                let mut post_entries = entries.to_vec();
                post_entries.extend(changed_entries);
                post_entries
            }
            PrivateOramShardKeyLayoutChangeKind::Drop => {
                let current_key_entries = entries
                    .iter()
                    .filter(|entry| entry.shard_key.as_ref() == Some(&change.shard_key))
                    .cloned()
                    .collect::<Vec<_>>();
                if !private_oram_shard_layout_entries_match(&current_key_entries, &changed_entries)
                {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                let post_entries = entries
                    .iter()
                    .filter(|entry| entry.shard_key.as_ref() != Some(&change.shard_key))
                    .cloned()
                    .collect::<Vec<_>>();
                if post_entries.is_empty() {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                post_entries
            }
        };
        let (post_owner_peer_ids, _) = canonical_private_oram_shard_layout_digest(
            collection_id,
            sharding_method,
            &post_entries,
        )?;
        let preinstalled_new_owner_peer_ids = post_owner_peer_ids
            .iter()
            .copied()
            .filter(|owner| current_owner_peer_ids.binary_search(owner).is_err())
            .collect::<Vec<_>>();
        match change.kind {
            PrivateOramShardKeyLayoutChangeKind::Create
                if preinstalled_new_owner_peer_ids == change.preinstalled_new_owner_peer_ids => {}
            PrivateOramShardKeyLayoutChangeKind::Drop
                if change.preinstalled_new_owner_peer_ids.is_empty() => {}
            PrivateOramShardKeyLayoutChangeKind::Create
            | PrivateOramShardKeyLayoutChangeKind::Drop => {
                return Err(invalid_private_oram_layout_transition_input());
            }
        }
        Ok(post_entries)
    }

    pub fn classify_private_oram_shard_key_layout_transition(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        change: &PrivateOramShardKeyLayoutChange,
        expected: &PrivateOramConsensusLayout,
        new: &PrivateOramConsensusLayout,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (owner_peer_ids, layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;
        if private_oram_layout_topology_matches(expected, &owner_peer_ids, &layout_digest) {
            let post_entries = private_oram_shard_key_post_layout_entries(
                collection_id,
                sharding_method,
                entries,
                change,
            )?;
            let (new_owner_peer_ids, new_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &post_entries,
                )?;
            if private_oram_layout_topology_matches(new, &new_owner_peer_ids, &new_layout_digest) {
                return Ok(PrivateOramLayoutTransitionState::Pending);
            }
        } else if private_oram_layout_topology_matches(new, &owner_peer_ids, &layout_digest) {
            let pre_entries = private_oram_shard_key_pre_layout_entries(entries, change)?;
            let (old_owner_peer_ids, old_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &pre_entries,
                )?;
            let replayed_post = private_oram_shard_key_post_layout_entries(
                collection_id,
                sharding_method,
                &pre_entries,
                change,
            )?;
            if private_oram_layout_topology_matches(
                expected,
                &old_owner_peer_ids,
                &old_layout_digest,
            ) && private_oram_shard_layout_entries_match(&replayed_post, entries)
            {
                return Ok(PrivateOramLayoutTransitionState::Applied);
            }
        }
        Err(invalid_private_oram_layout_transition_input())
    }

    fn private_oram_shard_key_pre_layout_entries(
        entries: &[PrivateOramShardLayoutEntry],
        change: &PrivateOramShardKeyLayoutChange,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        match change.kind {
            PrivateOramShardKeyLayoutChangeKind::Create => {
                let changed_shard_ids = change
                    .entries
                    .iter()
                    .map(|entry| entry.shard_id)
                    .collect::<BTreeSet<_>>();
                if changed_shard_ids.len() != change.entries.len() {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                let applied_entries = entries
                    .iter()
                    .filter(|entry| changed_shard_ids.contains(&entry.shard_id))
                    .cloned()
                    .collect::<Vec<_>>();
                if !private_oram_shard_layout_entries_match(&applied_entries, &change.entries) {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                let pre_entries = entries
                    .iter()
                    .filter(|entry| !changed_shard_ids.contains(&entry.shard_id))
                    .cloned()
                    .collect::<Vec<_>>();
                if pre_entries.is_empty() {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                Ok(pre_entries)
            }
            PrivateOramShardKeyLayoutChangeKind::Drop => {
                if entries
                    .iter()
                    .any(|entry| entry.shard_key.as_ref() == Some(&change.shard_key))
                {
                    return Err(invalid_private_oram_layout_transition_input());
                }
                let mut pre_entries = entries.to_vec();
                pre_entries.extend(change.entries.clone());
                Ok(pre_entries)
            }
        }
    }

    fn private_oram_shard_layout_entries_match(
        left: &[PrivateOramShardLayoutEntry],
        right: &[PrivateOramShardLayoutEntry],
    ) -> bool {
        fn normalized(entries: &[PrivateOramShardLayoutEntry]) -> Vec<PrivateOramShardLayoutEntry> {
            let mut entries = entries.to_vec();
            for entry in &mut entries {
                entry.owner_peer_ids.sort_unstable();
            }
            entries.sort_by_key(|entry| entry.shard_id);
            entries
        }
        normalized(left) == normalized(right)
    }

    pub fn private_oram_transfer_consensus_layouts(
        transition: &PrivateOramTransferLayoutTransition,
    ) -> (
        PrivateOramLayoutKey,
        PrivateOramConsensusLayout,
        PrivateOramConsensusLayout,
    ) {
        (
            PrivateOramLayoutKey {
                collection_id: transition.collection_id.clone(),
            },
            private_oram_transfer_consensus_layout(&transition.expected),
            private_oram_transfer_consensus_layout(&transition.new),
        )
    }

    pub fn private_oram_transfer_consensus_states(
        transition: &PrivateOramTransferLayoutTransition,
    ) -> Vec<(PrivateOramEpochKey, PrivateOramConsensusEpoch)> {
        transition
            .index_states
            .iter()
            .map(|state| {
                (
                    PrivateOramEpochKey {
                        collection_id: transition.collection_id.clone(),
                        index_kind: match state.index_kind {
                            PrivateOramTransferIndexKind::Hnsw => PrivateOramIndexKind::Hnsw,
                            PrivateOramTransferIndexKind::ResultPayload => {
                                PrivateOramIndexKind::ResultPayload
                            }
                        },
                        index_name: state.index_name.clone(),
                    },
                    PrivateOramConsensusEpoch {
                        index_epoch: state.index_epoch,
                        root_hash: state.root_hash.clone(),
                        writeback_digest: state.writeback_digest.clone(),
                    },
                )
            })
            .collect()
    }

    pub fn classify_private_oram_shard_transfer_layout_transition(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
        expected: &PrivateOramConsensusLayout,
        new: &PrivateOramConsensusLayout,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        validate_private_oram_shard_transfer_shape(transfer)?;
        let transition = transfer
            .private_oram_layout_transition
            .as_ref()
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        let (_, transfer_expected, transfer_new) =
            private_oram_transfer_consensus_layouts(transition);
        if transition.collection_id != collection_id
            || &transfer_expected != expected
            || &transfer_new != new
        {
            return Err(invalid_private_oram_layout_transition_input());
        }
        let (owner_peer_ids, layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;
        if private_oram_layout_topology_matches(expected, &owner_peer_ids, &layout_digest) {
            let post_entries = private_oram_transfer_post_entries(entries, transfer)?;
            let (new_owner_peer_ids, new_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &post_entries,
                )?;
            if private_oram_layout_topology_matches(new, &new_owner_peer_ids, &new_layout_digest) {
                return Ok(PrivateOramLayoutTransitionState::Pending);
            }
        } else if private_oram_layout_topology_matches(new, &owner_peer_ids, &layout_digest) {
            let pre_entries = private_oram_transfer_pre_entries(entries, transfer)?;
            let (old_owner_peer_ids, old_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &pre_entries,
                )?;
            if private_oram_layout_topology_matches(
                expected,
                &old_owner_peer_ids,
                &old_layout_digest,
            ) {
                return Ok(PrivateOramLayoutTransitionState::Applied);
            }
        }
        Err(invalid_private_oram_layout_transition_input())
    }

    pub fn canonical_private_oram_shard_transfer_post_layout_digest(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        validate_private_oram_shard_transfer_shape(transfer)?;
        canonical_private_oram_shard_layout_digest(
            collection_id,
            sharding_method,
            &private_oram_transfer_post_entries(entries, transfer)?,
        )
    }

    fn private_oram_transfer_consensus_layout(
        state: &PrivateOramTransferLayoutState,
    ) -> PrivateOramConsensusLayout {
        PrivateOramConsensusLayout {
            generation: state.generation,
            owner_peer_ids: state.owner_peer_ids.clone(),
            layout_digest: state.layout_digest.clone(),
            index_state_digest: state.index_state_digest.clone(),
        }
    }

    fn validate_private_oram_shard_transfer_shape(
        transfer: &ShardTransfer,
    ) -> Result<(), StorageError> {
        if !transfer.private_oram_preinstalled
            || transfer.to_shard_id.is_some()
            || transfer.from == transfer.to
            || transfer.method != Some(ShardTransferMethod::StreamRecords)
            || transfer.filter.is_some()
        {
            return Err(invalid_private_oram_layout_transition_input());
        }
        Ok(())
    }

    fn private_oram_transfer_post_entries(
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        let mut entries = entries.to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.shard_id == transfer.shard_id)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        if entry.owner_peer_ids.contains(&transfer.to) {
            return Err(invalid_private_oram_layout_transition_input());
        }
        let source_index = entry
            .owner_peer_ids
            .iter()
            .position(|owner| *owner == transfer.from)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        if !transfer.sync {
            entry.owner_peer_ids.remove(source_index);
        }
        entry.owner_peer_ids.push(transfer.to);
        Ok(entries)
    }

    fn private_oram_transfer_pre_entries(
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        let mut entries = entries.to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.shard_id == transfer.shard_id)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        let target_index = entry
            .owner_peer_ids
            .iter()
            .position(|owner| *owner == transfer.to)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        entry.owner_peer_ids.remove(target_index);
        if !transfer.sync {
            if entry.owner_peer_ids.contains(&transfer.from) {
                return Err(invalid_private_oram_layout_transition_input());
            }
            entry.owner_peer_ids.push(transfer.from);
        }
        Ok(entries)
    }

    pub fn canonical_private_oram_consensus_state_core_digest(
        state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<String, StorageError> {
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_CONSENSUS_STATE_CORE_DIGEST_DOMAIN);
        update_private_oram_consensus_state_core(&mut hasher, state)?;
        Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    pub fn canonical_private_oram_consensus_state_record_digest(
        state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<String, StorageError> {
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_CONSENSUS_STATE_RECORD_DIGEST_DOMAIN);
        update_private_oram_consensus_state_core(&mut hasher, state)?;
        match &state.last_transition {
            PrivateOramConsensusTransitionV2::Genesis => hasher.update([0]),
            PrivateOramConsensusTransitionV2::Mutation(receipt) => {
                hasher.update([1]);
                update_private_oram_mutation_receipt(&mut hasher, receipt, true)?;
            }
        }
        Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    pub fn canonical_private_oram_mutation_receipt_digest(
        receipt: &PrivateOramMutationReceiptV2,
    ) -> Result<String, StorageError> {
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_MUTATION_RECEIPT_DIGEST_DOMAIN);
        update_private_oram_mutation_receipt(&mut hasher, receipt, true)?;
        Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    pub fn canonical_private_oram_mutation_transition_digest(
        old_state: &PrivateOramConsensusCollectionStateV2,
        new_state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<String, StorageError> {
        let PrivateOramConsensusTransitionV2::Mutation(receipt) = &new_state.last_transition else {
            return Err(invalid_private_oram_mutation_consensus_digest_input());
        };
        let old_record_digest = canonical_private_oram_consensus_state_record_digest(old_state)?;
        let new_state_core_digest = canonical_private_oram_consensus_state_core_digest(new_state)?;
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_MUTATION_TRANSITION_DIGEST_DOMAIN);
        hasher.update(
            decode_private_oram_sha256_digest(&old_record_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        hasher.update(
            decode_private_oram_sha256_digest(&new_state_core_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        update_private_oram_mutation_receipt(&mut hasher, receipt, false)?;
        Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    fn update_private_oram_consensus_state_core(
        hasher: &mut Sha256,
        state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<(), StorageError> {
        if state.version != PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION
            || !valid_private_oram_collection_id(&state.collection_id)
            || state.layout_generation == 0
            || state.indexes.is_empty()
            || state.indexes.len() > PRIVATE_ORAM_CONSENSUS_MAX_RECORDS
        {
            return Err(invalid_private_oram_mutation_consensus_digest_input());
        }
        hasher.update(state.version.to_be_bytes());
        update_private_oram_length_prefixed(hasher, state.collection_id.as_bytes());
        hasher.update(
            decode_private_oram_sha256_digest(&state.manifest_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        hasher.update(state.layout_generation.to_be_bytes());
        hasher.update(
            decode_private_oram_sha256_digest(&state.layout_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        hasher.update(state.state_sequence.to_be_bytes());
        hasher.update(
            decode_private_oram_sha256_digest(&state.signed_state_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        hasher.update((state.indexes.len() as u64).to_be_bytes());
        let mut previous_order = None;
        for index in &state.indexes {
            let order = (
                private_oram_index_kind_tag(index.index_kind),
                index.index_name.as_bytes(),
            );
            let valid_name = match index.index_kind {
                PrivateOramIndexKind::Hnsw => {
                    !index.index_name.is_empty() && index.index_name.len() <= 128
                }
                PrivateOramIndexKind::ResultPayload => index.index_name.is_empty(),
            };
            if !valid_name
                || previous_order
                    .as_ref()
                    .is_some_and(|previous| previous >= &order)
                || index.logical_count.checked_add(index.dummy_count).is_none()
            {
                return Err(invalid_private_oram_mutation_consensus_digest_input());
            }
            hasher.update([order.0]);
            update_private_oram_length_prefixed(hasher, order.1);
            hasher.update(index.epoch.index_epoch.to_be_bytes());
            hasher.update(
                decode_private_oram_sha256_digest(&index.epoch.root_hash)
                    .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
            );
            match &index.epoch.writeback_digest {
                Some(digest) => {
                    hasher.update([1]);
                    hasher.update(
                        decode_private_oram_sha256_digest(digest)
                            .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
                    );
                }
                None => hasher.update([0]),
            }
            hasher.update(index.logical_count.to_be_bytes());
            hasher.update(index.dummy_count.to_be_bytes());
            previous_order = Some(order);
        }
        hasher.update(
            decode_private_oram_sha256_digest(&state.client_state_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        Ok(())
    }

    fn update_private_oram_mutation_receipt(
        hasher: &mut Sha256,
        receipt: &PrivateOramMutationReceiptV2,
        include_transition_digest: bool,
    ) -> Result<(), StorageError> {
        if receipt.version != PRIVATE_ORAM_MUTATION_RECEIPT_VERSION
            || receipt.writer_fence == 0
            || receipt.mutation_lease_generation == 0
        {
            return Err(invalid_private_oram_mutation_consensus_digest_input());
        }
        hasher.update(receipt.version.to_be_bytes());
        for digest in [&receipt.mutation_id, &receipt.signed_mutation_digest] {
            hasher.update(
                decode_private_oram_sha256_digest(digest)
                    .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
            );
        }
        if include_transition_digest {
            hasher.update(
                decode_private_oram_sha256_digest(&receipt.transition_digest)
                    .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
            );
        }
        hasher.update(receipt.old_state_sequence.to_be_bytes());
        hasher.update(
            decode_private_oram_sha256_digest(&receipt.old_state_digest)
                .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
        );
        hasher.update(receipt.new_state_sequence.to_be_bytes());
        for digest in [
            &receipt.new_state_digest,
            &receipt.point_operation_digest,
            &receipt.writer_lease_digest,
        ] {
            hasher.update(
                decode_private_oram_sha256_digest(digest)
                    .ok_or_else(invalid_private_oram_mutation_consensus_digest_input)?,
            );
        }
        hasher.update(receipt.writer_fence.to_be_bytes());
        hasher.update(receipt.mutation_lease_generation.to_be_bytes());
        Ok(())
    }

    pub fn canonical_private_oram_index_state_digest(
        collection_id: &str,
        states: &[(PrivateOramEpochKey, PrivateOramConsensusEpoch)],
    ) -> Result<String, StorageError> {
        let states = states
            .iter()
            .map(
                |(key, state)| qdrant_sec::PrivateOramRecoveryIndexStateRef {
                    collection_id: &key.collection_id,
                    index_kind: match key.index_kind {
                        PrivateOramIndexKind::Hnsw => {
                            qdrant_sec::PrivateOramRecoveryIndexKind::Hnsw
                        }
                        PrivateOramIndexKind::ResultPayload => {
                            qdrant_sec::PrivateOramRecoveryIndexKind::ResultPayload
                        }
                    },
                    index_name: &key.index_name,
                    index_epoch: state.index_epoch,
                    root_hash: &state.root_hash,
                    writeback_digest: state.writeback_digest.as_deref(),
                },
            )
            .collect::<Vec<_>>();
        qdrant_sec::canonical_private_oram_recovery_index_state_digest(collection_id, &states)
            .map_err(|_| invalid_private_oram_index_state_digest_input())
    }

    pub fn private_oram_index_keys_for_config(
        config: &CollectionConfigInternal,
        collection_name: &str,
    ) -> Result<Vec<PrivateOramEpochKey>, StorageError> {
        let collection_id = config.stable_crypto_id(collection_name)?;
        let Some(encryption) = config.params.effective_encryption() else {
            return Ok(Vec::new());
        };
        let mut hnsw_vectors = BTreeSet::new();
        let mut has_result_payload = false;
        for rule in &encryption.rules {
            if encryption_rule_uses_private_hnsw_oram(rule) {
                let EncryptionSelector::VectorNames { names } = &rule.selector else {
                    return Err(StorageError::bad_request(
                        "private ORAM consensus index configuration is invalid",
                    ));
                };
                hnsw_vectors.extend(names.iter().cloned());
            } else if encryption_rule_uses_private_result_oram(rule) {
                has_result_payload = true;
            }
        }

        let mut keys = hnsw_vectors
            .into_iter()
            .map(|index_name| PrivateOramEpochKey {
                collection_id: collection_id.clone(),
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name,
            })
            .collect::<Vec<_>>();
        if has_result_payload {
            keys.push(PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            });
        }
        Ok(keys)
    }

    fn valid_private_oram_collection_id(collection_id: &str) -> bool {
        !collection_id.is_empty() && collection_id.len() <= 1024
    }

    fn private_oram_index_kind_tag(index_kind: PrivateOramIndexKind) -> u8 {
        match index_kind {
            PrivateOramIndexKind::Hnsw => 1,
            PrivateOramIndexKind::ResultPayload => 2,
        }
    }

    fn decode_private_oram_sha256_digest(value: &str) -> Option<[u8; 32]> {
        let decoded = BASE64URL_NOPAD.decode(value.as_bytes()).ok()?;
        let digest: [u8; 32] = decoded.try_into().ok()?;
        (BASE64URL_NOPAD.encode(&digest) == value).then_some(digest)
    }

    fn update_private_oram_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    fn invalid_private_oram_layout_digest_input() -> StorageError {
        StorageError::bad_request("private ORAM consensus layout digest input is invalid")
    }

    fn invalid_private_oram_index_state_digest_input() -> StorageError {
        StorageError::bad_request("private ORAM consensus index-state digest input is invalid")
    }

    fn invalid_private_oram_mutation_consensus_digest_input() -> StorageError {
        StorageError::bad_request("private ORAM mutation consensus digest input is invalid")
    }

    fn private_oram_layout_topology_matches(
        layout: &PrivateOramConsensusLayout,
        owner_peer_ids: &[PeerId],
        layout_digest: &str,
    ) -> bool {
        layout.owner_peer_ids == owner_peer_ids && layout.layout_digest == layout_digest
    }

    pub fn private_oram_layout_is_precommitted_transfer_recovery(
        current: &PrivateOramConsensusLayout,
        expected: &PrivateOramConsensusLayout,
        new: &PrivateOramConsensusLayout,
    ) -> bool {
        current.generation == expected.generation
            && expected
                .generation
                .checked_add(1)
                .is_some_and(|generation| generation == new.generation)
            && current.owner_peer_ids == new.owner_peer_ids
            && current.layout_digest == new.layout_digest
            && current.index_state_digest == expected.index_state_digest
            && current.index_state_digest == new.index_state_digest
    }

    fn invalid_private_oram_layout_transition_input() -> StorageError {
        StorageError::bad_request("private ORAM collection layout transition is invalid")
    }

    fn invalid_private_oram_resharding_layout_input() -> StorageError {
        StorageError::bad_request("private ORAM resharding layout transition is invalid")
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    pub enum PrivateOramMutationActivationBarrierPhaseV2 {
        PrepareTaggedWrites,
        EnableMutationV2,
        PrepareReservationV3Reads,
        EnableReservationV3Writes,
    }

    /// Canonical aggregate evidence carried by the two-entry mixed-version activation barrier.
    ///
    /// The proof is stored as exact canonical JSON so this consensus operation remains hashable
    /// without treating a caller-supplied digest as the authority for nested evidence.
    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramMutationActivationBarrierV2 {
        version: u16,
        phase: PrivateOramMutationActivationBarrierPhaseV2,
        proof_canonical_json: String,
        proof_digest: String,
    }

    impl fmt::Debug for PrivateOramMutationActivationBarrierV2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramMutationActivationBarrierV2")
                .field("version", &self.version)
                .field("phase", &self.phase)
                .field("proof_bytes", &self.proof_canonical_json.len())
                .field("proof_digest", &"[redacted]")
                .finish()
        }
    }

    impl PrivateOramMutationActivationBarrierV2 {
        pub fn try_new(
            phase: PrivateOramMutationActivationBarrierPhaseV2,
            proof: &qdrant_sec::PrivateOramMixedVersionActivationProofV1,
        ) -> Result<Self, StorageError> {
            let proof_canonical_json = serde_json::to_string(proof).map_err(|_| {
                StorageError::bad_request(
                    "private ORAM mutation activation proof encoding is invalid",
                )
            })?;
            let operation = Self {
                version: PRIVATE_ORAM_MUTATION_ACTIVATION_BARRIER_VERSION,
                phase,
                proof_digest: proof.proof_digest().to_string(),
                proof_canonical_json,
            };
            operation.decode_proof()?;
            Ok(operation)
        }

        pub fn phase(&self) -> PrivateOramMutationActivationBarrierPhaseV2 {
            self.phase
        }

        pub fn proof_digest(&self) -> &str {
            &self.proof_digest
        }

        pub fn decode_proof(
            &self,
        ) -> Result<qdrant_sec::PrivateOramMixedVersionActivationProofV1, StorageError> {
            let invalid =
                || StorageError::bad_request("private ORAM mutation activation proof is invalid");
            if self.version != PRIVATE_ORAM_MUTATION_ACTIVATION_BARRIER_VERSION
                || self.proof_canonical_json.is_empty()
                || self.proof_canonical_json.len()
                    > PRIVATE_ORAM_MUTATION_ACTIVATION_PROOF_MAX_BYTES
                || decode_private_oram_sha256_digest(&self.proof_digest).is_none()
            {
                return Err(invalid());
            }
            let proof: qdrant_sec::PrivateOramMixedVersionActivationProofV1 =
                serde_json::from_str(&self.proof_canonical_json).map_err(|_| invalid())?;
            let canonical = serde_json::to_string(&proof).map_err(|_| invalid())?;
            if canonical != self.proof_canonical_json || proof.proof_digest() != self.proof_digest {
                return Err(invalid());
            }
            Ok(proof)
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    #[serde(deny_unknown_fields)]
    pub struct PrivateOramSnapshotBarrierV2 {
        pub version: u16,
        pub requester_peer_id: PeerId,
        pub process_incarnation: [u8; 16],
        pub sequence: u64,
    }

    impl PrivateOramSnapshotBarrierV2 {
        pub(crate) fn validate(&self) -> Result<(), StorageError> {
            if self.version != PRIVATE_ORAM_SNAPSHOT_BARRIER_VERSION
                || self.requester_peer_id == 0
                || self.process_incarnation == [0; 16]
                || self.sequence == 0
            {
                return Err(StorageError::bad_request(
                    "private ORAM snapshot consensus barrier is invalid",
                ));
            }
            Ok(())
        }
    }

    /// Operation that should pass consensus
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub enum ConsensusOperations {
        CollectionMeta(Box<CollectionMetaOperations>),
        AddPeer {
            peer_id: PeerId,
            uri: String,
        },
        RemovePeer(PeerId),
        UpdatePeerMetadata {
            peer_id: PeerId,
            metadata: PeerMetadata,
        },
        UpdateClusterMetadata {
            key: String,
            value: serde_json::Value,
        },
        CompareAndSwapPrivateOramEpoch(CompareAndSwapPrivateOramEpoch),
        CompareAndSwapPrivateOramSessionLease(CompareAndSwapPrivateOramSessionLease),
        InitializePrivateOramMutationState(InitializePrivateOramMutationState),
        EnrollPrivateOramMutationStateV2(EnrollPrivateOramMutationStateV2),
        CompareAndSwapPrivateOramMutationLease(CompareAndSwapPrivateOramMutationLease),
        ConfirmPrivateOramMutationAuthorityV2(ConfirmPrivateOramMutationAuthorityV2),
        ApplyPrivateOramMutation(ApplyPrivateOramMutation),
        ActivatePrivateOramMutationV2(PrivateOramMutationActivationBarrierV2),
        ApplyPrivateOramMutationMaterialV2(ApplyPrivateOramMutationMaterialV2),
        /// Enrolls a collection into mutation V2 on a cluster where V2 is already active: the
        /// genesis state is initialized and its authority activated in the same entry. A
        /// separate variant (not a new meaning of `InitializePrivateOramMutationState`) so a
        /// binary without enrollment support fails to decode the entry instead of applying it
        /// differently.
        EnrollPrivateOramMutationCollectionV2(InitializePrivateOramMutationState),
        PrivateOramSnapshotBarrierV2(PrivateOramSnapshotBarrierV2),
        CompareAndSwapPrivateOramLayout(CompareAndSwapPrivateOramLayout),
        RequestSnapshot,
        ReportSnapshot {
            peer_id: PeerId,
            status: SnapshotStatus,
        },
        ApplyPrivateOramCollectionLayout(PrivateOramCollectionLayoutTransition),
        StartPrivateOramShardTransfer(PrivateOramShardTransferStart),
        FinishPrivateOramShardTransfer(PrivateOramShardTransferFinish),
        StartPrivateOramResharding(PrivateOramReshardingOperation),
        FinishPrivateOramResharding(PrivateOramReshardingOperation),
        ApplyPrivateOramExternalRecovery(PrivateOramExternalRecoveryOperation),
    }

    impl TryFrom<&RaftEntry> for ConsensusOperations {
        type Error = serde_cbor::Error;

        fn try_from(entry: &RaftEntry) -> Result<Self, Self::Error> {
            serde_cbor::from_slice(entry.get_data())
        }
    }

    impl ConsensusOperations {
        pub fn redacted_log(&self) -> RedactedConsensusOperation<'_> {
            RedactedConsensusOperation(self)
        }

        pub fn abort_transfer(
            collection_id: CollectionId,
            transfer: ShardTransfer,
            reason: &str,
        ) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Abort {
                    transfer: transfer.key(),
                    reason: reason.to_string(),
                },
            )))
        }

        pub fn finish_transfer(collection_id: CollectionId, transfer: ShardTransfer) -> Self {
            let collection_meta = Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Finish(transfer.clone()),
            ));
            if transfer.private_oram_layout_transition.is_some() {
                ConsensusOperations::FinishPrivateOramShardTransfer(
                    PrivateOramShardTransferFinish { collection_meta },
                )
            } else {
                ConsensusOperations::CollectionMeta(collection_meta)
            }
        }

        pub fn abort_resharding(collection_id: CollectionId, reshard_key: ReshardKey) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::Resharding(
                collection_id,
                ReshardingOperation::Abort(reshard_key),
            )))
        }

        pub fn finish_resharding(collection_id: CollectionId, reshard_key: ReshardKey) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::Resharding(
                collection_id,
                ReshardingOperation::Finish(reshard_key),
            )))
        }

        pub fn set_replica_state(
            collection_name: CollectionId,
            shard_id: u32,
            peer_id: PeerId,
            state: ReplicaState,
            from_state: Option<ReplicaState>,
        ) -> Self {
            ConsensusOperations::CollectionMeta(
                CollectionMetaOperations::SetShardReplicaState(SetShardReplicaState {
                    collection_name,
                    shard_id,
                    peer_id,
                    state,
                    from_state,
                })
                .into(),
            )
        }

        pub fn remove_replica(
            collection_name: CollectionId,
            shard_id: u32,
            peer_id: PeerId,
        ) -> Self {
            let mut operation = UpdateCollectionOperation::new(
                collection_name,
                UpdateCollection {
                    vectors: None,
                    optimizers_config: None,
                    params: None,
                    hnsw_config: None,
                    quantization_config: None,
                    sparse_vectors: None,
                    strict_mode_config: None,
                    metadata: None,
                },
            );
            operation
                .set_shard_replica_changes(vec![replica_set::Change::Remove(shard_id, peer_id)]);

            ConsensusOperations::CollectionMeta(
                CollectionMetaOperations::UpdateCollection(operation).into(),
            )
        }

        /// Report that a replica was initialized
        pub fn initialize_replica(
            collection_name: CollectionId,
            shard_id: u32,
            peer_id: PeerId,
        ) -> Self {
            Self::set_replica_state(
                collection_name,
                shard_id,
                peer_id,
                ReplicaState::Active,
                Some(Initializing),
            )
        }

        pub fn start_transfer(collection_id: CollectionId, transfer: ShardTransfer) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Start(transfer),
            )))
        }

        pub fn request_snapshot() -> Self {
            Self::RequestSnapshot
        }

        pub fn report_snapshot(peer_id: PeerId, status: impl Into<SnapshotStatus>) -> Self {
            Self::ReportSnapshot {
                peer_id,
                status: status.into(),
            }
        }
    }

    pub struct RedactedConsensusOperation<'a>(&'a ConsensusOperations);

    impl fmt::Debug for RedactedConsensusOperation<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                ConsensusOperations::CollectionMeta(operation) => f
                    .debug_tuple("CollectionMeta")
                    .field(&operation.redacted_log())
                    .finish(),
                ConsensusOperations::AddPeer { peer_id, uri } => f
                    .debug_struct("AddPeer")
                    .field("peer_id", peer_id)
                    .field("uri_present", &(!uri.is_empty()))
                    .finish(),
                ConsensusOperations::RemovePeer(peer_id) => {
                    f.debug_tuple("RemovePeer").field(peer_id).finish()
                }
                ConsensusOperations::UpdatePeerMetadata { peer_id, metadata } => f
                    .debug_struct("UpdatePeerMetadata")
                    .field("peer_id", peer_id)
                    .field(
                        "crypto_fingerprint_present",
                        &peer_metadata_has_crypto_fingerprint(metadata),
                    )
                    .finish(),
                ConsensusOperations::UpdateClusterMetadata { key, value } => f
                    .debug_struct("UpdateClusterMetadata")
                    .field("key", key)
                    .field("value_type", &json_value_type(value))
                    .finish(),
                ConsensusOperations::CompareAndSwapPrivateOramEpoch(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramEpoch")
                    .field("index_kind", &operation.key.index_kind)
                    .field("has_expected", &operation.expected.is_some())
                    .field("new_epoch", &operation.new.index_epoch)
                    .finish(),
                ConsensusOperations::CompareAndSwapPrivateOramSessionLease(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramSessionLease")
                    .field("index_kind", &operation.key.index_kind)
                    .field("has_expected", &operation.expected.is_some())
                    .field("has_new", &operation.new.is_some())
                    .finish(),
                ConsensusOperations::InitializePrivateOramMutationState(operation) => f
                    .debug_struct("InitializePrivateOramMutationState")
                    .field("state_sequence", &operation.state.state_sequence)
                    .field("index_count", &operation.state.indexes.len())
                    .finish(),
                ConsensusOperations::EnrollPrivateOramMutationCollectionV2(operation) => f
                    .debug_struct("EnrollPrivateOramMutationCollectionV2")
                    .field("state_sequence", &operation.state.state_sequence)
                    .field("index_count", &operation.state.indexes.len())
                    .finish(),
                ConsensusOperations::EnrollPrivateOramMutationStateV2(operation) => f
                    .debug_struct("EnrollPrivateOramMutationStateV2")
                    .field("layout_generation", &operation.layout.generation)
                    .field("owner_count", &operation.layout.owner_peer_ids.len())
                    .field("state_sequence", &operation.state.state_sequence)
                    .field("index_count", &operation.state.indexes.len())
                    .finish(),
                ConsensusOperations::CompareAndSwapPrivateOramMutationLease(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramMutationLease")
                    .field("expected_has_active", &operation.expected.active.is_some())
                    .field("new_has_active", &operation.new.active.is_some())
                    .finish(),
                ConsensusOperations::ConfirmPrivateOramMutationAuthorityV2(operation) => f
                    .debug_tuple("ConfirmPrivateOramMutationAuthorityV2")
                    .field(operation)
                    .finish(),
                ConsensusOperations::ApplyPrivateOramMutation(operation) => f
                    .debug_struct("ApplyPrivateOramMutation")
                    .field(
                        "layout_generation",
                        &operation.expected_state.layout_generation,
                    )
                    .field(
                        "expected_state_sequence",
                        &operation.expected_state.state_sequence,
                    )
                    .field("new_state_sequence", &operation.new_state.state_sequence)
                    .field("index_count", &operation.new_state.indexes.len())
                    .finish(),
                ConsensusOperations::ActivatePrivateOramMutationV2(operation) => f
                    .debug_tuple("ActivatePrivateOramMutationV2")
                    .field(operation)
                    .finish(),
                ConsensusOperations::ApplyPrivateOramMutationMaterialV2(operation) => f
                    .debug_tuple("ApplyPrivateOramMutationMaterialV2")
                    .field(operation)
                    .finish(),
                ConsensusOperations::PrivateOramSnapshotBarrierV2(operation) => f
                    .debug_struct("PrivateOramSnapshotBarrierV2")
                    .field("requester_peer_id", &operation.requester_peer_id)
                    .field("sequence", &operation.sequence)
                    .finish_non_exhaustive(),
                ConsensusOperations::ApplyPrivateOramExternalRecovery(operation) => f
                    .debug_tuple("ApplyPrivateOramExternalRecovery")
                    .field(operation)
                    .finish(),
                ConsensusOperations::CompareAndSwapPrivateOramLayout(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramLayout")
                    .field("has_expected", &operation.expected.is_some())
                    .field("new_generation", &operation.new.generation)
                    .field("owner_peer_count", &operation.new.owner_peer_ids.len())
                    .finish(),
                ConsensusOperations::ApplyPrivateOramCollectionLayout(operation) => f
                    .debug_struct("ApplyPrivateOramCollectionLayout")
                    .field("has_expected", &operation.layout.expected.is_some())
                    .field("new_generation", &operation.layout.new.generation)
                    .field("lease_count", &operation.leases.len())
                    .field("collection_meta", &operation.collection_meta.redacted_log())
                    .finish(),
                ConsensusOperations::StartPrivateOramShardTransfer(operation) => f
                    .debug_struct("StartPrivateOramShardTransfer")
                    .field("lease_count", &operation.leases.len())
                    .field("collection_meta", &operation.collection_meta.redacted_log())
                    .finish(),
                ConsensusOperations::FinishPrivateOramShardTransfer(operation) => f
                    .debug_struct("FinishPrivateOramShardTransfer")
                    .field("collection_meta", &operation.collection_meta.redacted_log())
                    .finish(),
                ConsensusOperations::StartPrivateOramResharding(operation) => f
                    .debug_tuple("StartPrivateOramResharding")
                    .field(operation)
                    .finish(),
                ConsensusOperations::FinishPrivateOramResharding(operation) => f
                    .debug_tuple("FinishPrivateOramResharding")
                    .field(operation)
                    .finish(),
                ConsensusOperations::RequestSnapshot => f.write_str("RequestSnapshot"),
                ConsensusOperations::ReportSnapshot { peer_id, status } => f
                    .debug_struct("ReportSnapshot")
                    .field("peer_id", peer_id)
                    .field("status", status)
                    .finish(),
            }
        }
    }

    fn peer_metadata_has_crypto_fingerprint(metadata: &PeerMetadata) -> bool {
        metadata
            .crypto_runtime_capability_fingerprint()
            .is_some_and(|fingerprint| !fingerprint.is_empty())
    }

    fn json_value_type(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
    pub enum SnapshotStatus {
        Finish,
        Failure,
    }

    impl From<raft::SnapshotStatus> for SnapshotStatus {
        fn from(status: raft::SnapshotStatus) -> Self {
            match status {
                raft::SnapshotStatus::Finish => Self::Finish,
                raft::SnapshotStatus::Failure => Self::Failure,
            }
        }
    }

    impl From<SnapshotStatus> for raft::SnapshotStatus {
        fn from(status: SnapshotStatus) -> Self {
            match status {
                SnapshotStatus::Finish => Self::Finish,
                SnapshotStatus::Failure => Self::Failure,
            }
        }
    }
}

/// Collection container abstraction for consensus
/// Used to mock ToC in consensus state tests
pub trait CollectionContainer {
    fn perform_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError>;

    /// Private ORAM index keys of a live collection, captured before it is deleted so the
    /// consensus state it owned can be pruned. Empty for unknown or non-ORAM collections.
    fn private_oram_index_keys_for_collection(
        &self,
        _collection_name: &str,
    ) -> Result<Vec<consensus_ops::PrivateOramEpochKey>, StorageError> {
        Ok(Vec::new())
    }

    fn perform_private_oram_resharding_meta_op(
        &self,
        operation: &consensus_ops::PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        self.perform_collection_meta_op((*operation.collection_meta).clone())
    }

    fn perform_private_oram_collection_layout_meta_op(
        &self,
        transition: &consensus_ops::PrivateOramCollectionLayoutTransition,
    ) -> Result<bool, StorageError> {
        self.perform_collection_meta_op((*transition.collection_meta).clone())
    }

    fn private_oram_layout_transition_state(
        &self,
        transition: &consensus_ops::PrivateOramCollectionLayoutTransition,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn private_oram_shard_transfer_start_state(
        &self,
        operation: &consensus_ops::PrivateOramShardTransferStart,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn private_oram_shard_transfer_finish_state(
        &self,
        operation: &consensus_ops::PrivateOramShardTransferFinish,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn private_oram_resharding_state(
        &self,
        operation: &consensus_ops::PrivateOramReshardingOperation,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn collections_snapshot(&self) -> CollectionsSnapshot;

    fn apply_collections_snapshot(&self, data: CollectionsSnapshot) -> Result<(), StorageError>;

    /// Applies a collections snapshot, reporting whether a failure happened before or after
    /// local side effects; the default cannot tell and conservatively reports indeterminate.
    fn apply_collections_snapshot_with_private_oram_state(
        &self,
        data: CollectionsSnapshot,
        _private_oram: consensus_manager::PrivateOramSnapshotState<'_>,
    ) -> Result<(), consensus_manager::CollectionsSnapshotApplyError> {
        self.apply_collections_snapshot(data)
            .map_err(consensus_manager::CollectionsSnapshotApplyError::Indeterminate)
    }

    fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError>;

    fn sync_local_state(&self) -> Result<(), StorageError>;
}

#[cfg(test)]
mod test {
    use collection::config::ShardingMethod;
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferIndexState,
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition, ShardTransfer,
        ShardTransferMethod,
    };
    use data_encoding::BASE64URL_NOPAD;
    use segment::types::ShardKey;
    use serde_json::json;
    use uuid::Uuid;

    use super::collection_meta_ops::CollectionMetaOperations;
    use super::consensus::private_oram_mutation_activation_barrier::private_oram_mutation_activation_barrier_fixture_v2_for_test;
    use super::consensus_ops::{
        ApplyPrivateOramMutation, CompareAndSwapPrivateOramEpoch,
        CompareAndSwapPrivateOramExternalRecovery, CompareAndSwapPrivateOramLayout,
        CompareAndSwapPrivateOramMutationLease, CompareAndSwapPrivateOramSessionLease,
        ConsensusOperations, InitializePrivateOramMutationState,
        PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
        PRIVATE_ORAM_MUTATION_ACTIVATION_PROOF_MAX_BYTES, PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
        PRIVATE_ORAM_MUTATION_RECEIPT_VERSION, PrivateOramCollectionLayoutTransition,
        PrivateOramConsensusCollectionIndexStateV2, PrivateOramConsensusCollectionStateV2,
        PrivateOramConsensusEpoch, PrivateOramConsensusLayout, PrivateOramConsensusTransitionV2,
        PrivateOramEpochKey, PrivateOramExternalRecoveryAuthority, PrivateOramExternalRecoveryKey,
        PrivateOramExternalRecoveryLease, PrivateOramExternalRecoveryLeasePhase,
        PrivateOramExternalRecoveryOperation, PrivateOramExternalRecoveryPhase,
        PrivateOramExternalRecoveryState, PrivateOramIndexKind, PrivateOramLayoutIndexStateBinding,
        PrivateOramLayoutKey, PrivateOramLayoutLeaseBinding, PrivateOramLayoutTransitionState,
        PrivateOramMutationActivationBarrierV2, PrivateOramMutationKey, PrivateOramMutationLease,
        PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
        PrivateOramMutationReceiptV2, PrivateOramReshardingLayoutTransition,
        PrivateOramSessionLease, PrivateOramShardKeyLayoutChange,
        PrivateOramShardKeyLayoutChangeKind, PrivateOramShardLayoutEntry,
        canonical_private_oram_index_state_digest,
        canonical_private_oram_resharding_post_layout_digest,
        canonical_private_oram_shard_layout_digest,
        classify_private_oram_replica_removal_layout_transition,
        classify_private_oram_resharding_layout_transition,
        classify_private_oram_shard_key_layout_transition,
        classify_private_oram_shard_transfer_layout_transition,
        private_oram_layout_is_precommitted_transfer_recovery,
    };

    fn private_oram_shard_transfer_fixture(
        sync: bool,
    ) -> (
        Vec<PrivateOramShardLayoutEntry>,
        Vec<PrivateOramShardLayoutEntry>,
        ShardTransfer,
        PrivateOramConsensusLayout,
        PrivateOramConsensusLayout,
    ) {
        let collection_id = "collection-uuid-1";
        let pre_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![7, 11],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: None,
                owner_peer_ids: vec![11],
            },
        ];
        let mut post_entries = pre_entries.clone();
        if !sync {
            post_entries[0].owner_peer_ids.retain(|owner| *owner != 7);
        }
        post_entries[0].owner_peer_ids.push(9);
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &post_entries,
        )
        .unwrap();
        let expected = PrivateOramConsensusLayout {
            generation: 4,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[61; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 5,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[62; 32]),
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 7,
            to: 9,
            sync,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: collection_id.to_string(),
                expected: PrivateOramTransferLayoutState {
                    generation: expected.generation,
                    owner_peer_ids: expected.owner_peer_ids.clone(),
                    layout_digest: expected.layout_digest.clone(),
                    index_state_digest: expected.index_state_digest.clone(),
                },
                new: PrivateOramTransferLayoutState {
                    generation: new.generation,
                    owner_peer_ids: new.owner_peer_ids.clone(),
                    layout_digest: new.layout_digest.clone(),
                    index_state_digest: new.index_state_digest.clone(),
                },
                index_states: vec![PrivateOramTransferIndexState {
                    index_kind: PrivateOramTransferIndexKind::Hnsw,
                    index_name: "text".to_string(),
                    index_epoch: 42,
                    root_hash: BASE64URL_NOPAD.encode(&[63; 32]),
                    writeback_digest: None,
                }],
            }),
            filter: None,
        };
        (pre_entries, post_entries, transfer, expected, new)
    }

    // Consensus messages are serialized to CBOR when sent over network and written into WAL.
    //
    // We are using `serde_json::Value` in `ConsensusOperations::UpdateClusterMetadata`,
    // but the way `serde` works, it is not *strictly* guaranteed that all possible JSON values
    // can be serialized to CBOR, there might be some minor inconsistencies between formats.
    //
    // These tests check that `serde_json::Value` can be serialized to (and deserialized from) CBOR.

    #[test]
    fn serde_json_null_combatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(null));
    }

    #[test]
    fn consensus_operation_log_projection_redacts_cluster_metadata_value() {
        let operation = ConsensusOperations::UpdateClusterMetadata {
            key: "crypto-policy".to_string(),
            value: json!({
                "secret": "qdrant-sec-consensus-secret-sentinel",
                "rk_id": "rk/secret-sentinel",
            }),
        };

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("qdrant-sec-consensus-secret-sentinel"));
        assert!(!log_line.contains("rk/secret-sentinel"));
        assert!(log_line.contains("value_type: \"object\""), "{log_line}");
    }

    #[test]
    fn raw_consensus_operation_debug_still_contains_cluster_metadata_value() {
        let operation = ConsensusOperations::UpdateClusterMetadata {
            key: "crypto-policy".to_string(),
            value: json!({ "secret": "qdrant-sec-raw-consensus-sentinel" }),
        };

        let raw_debug = format!("{operation:?}");

        assert!(raw_debug.contains("qdrant-sec-raw-consensus-sentinel"));
    }

    #[test]
    fn private_oram_epoch_cas_log_projection_redacts_identity_and_roots() {
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramEpoch(CompareAndSwapPrivateOramEpoch {
                key: PrivateOramEpochKey {
                    collection_id: "qdrant-sec-private-oram-collection-sentinel".to_string(),
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: "qdrant-sec-private-oram-vector-sentinel".to_string(),
                },
                expected: Some(PrivateOramConsensusEpoch {
                    index_epoch: 42,
                    root_hash: "qdrant-sec-private-oram-old-root-sentinel".to_string(),
                    writeback_digest: Some(
                        "qdrant-sec-private-oram-old-digest-sentinel".to_string(),
                    ),
                }),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: "qdrant-sec-private-oram-new-root-sentinel".to_string(),
                    writeback_digest: Some(
                        "qdrant-sec-private-oram-new-digest-sentinel".to_string(),
                    ),
                },
            });

        let redacted = format!("{:?}", operation.redacted_log());
        let raw = format!("{operation:?}");

        for rendered in [&redacted, &raw] {
            assert!(
                !rendered.contains("qdrant-sec-private-oram-collection-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-vector-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-old-root-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-new-root-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-old-digest-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-new-digest-sentinel"),
                "{rendered}",
            );
        }
        assert!(redacted.contains("has_expected: true"), "{redacted}");
        assert!(redacted.contains("new_epoch: 43"), "{redacted}");
    }

    #[test]
    fn private_oram_session_lease_log_projection_redacts_identity_and_hash() {
        let lease_hash = "qdrant-sec-private-oram-lease-hash-sentinel";
        let operation = ConsensusOperations::CompareAndSwapPrivateOramSessionLease(
            CompareAndSwapPrivateOramSessionLease {
                key: PrivateOramEpochKey {
                    collection_id: "qdrant-sec-private-oram-lease-collection-sentinel".to_string(),
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: "qdrant-sec-private-oram-lease-vector-sentinel".to_string(),
                },
                expected: None,
                new: Some(PrivateOramSessionLease {
                    owner_peer_id: 7,
                    lease_id_hash: lease_hash.to_string(),
                    issued_at_unix: 100,
                    expires_at_unix: 160,
                }),
            },
        );

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("CompareAndSwapPrivateOramSessionLease"));
            assert!(!rendered.contains(lease_hash), "{rendered}");
            assert!(
                !rendered.contains("lease-collection-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("lease-vector-sentinel"), "{rendered}");
        }
    }

    #[test]
    fn private_oram_mutation_operations_redact_consensus_state_and_receipts() {
        let secret = "qdrant-sec-private-oram-mutation-secret-sentinel";
        let collection_id = "qdrant-sec-private-oram-mutation-collection-sentinel";
        let index_name = "qdrant-sec-private-oram-mutation-index-sentinel";
        let old_state = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.to_string(),
            manifest_digest: secret.to_string(),
            layout_generation: 1,
            layout_digest: secret.to_string(),
            state_sequence: 0,
            signed_state_digest: secret.to_string(),
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: index_name.to_string(),
                epoch: PrivateOramConsensusEpoch {
                    index_epoch: 7,
                    root_hash: secret.to_string(),
                    writeback_digest: Some(secret.to_string()),
                },
                logical_count: 4,
                dummy_count: 6,
            }],
            client_state_digest: secret.to_string(),
            last_transition: PrivateOramConsensusTransitionV2::Genesis,
        };
        let new_state = PrivateOramConsensusCollectionStateV2 {
            state_sequence: 1,
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                epoch: PrivateOramConsensusEpoch {
                    index_epoch: 8,
                    ..old_state.indexes[0].epoch.clone()
                },
                ..old_state.indexes[0].clone()
            }],
            last_transition: PrivateOramConsensusTransitionV2::Mutation(
                PrivateOramMutationReceiptV2 {
                    version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
                    mutation_id: secret.to_string(),
                    signed_mutation_digest: secret.to_string(),
                    transition_digest: secret.to_string(),
                    old_state_sequence: 0,
                    old_state_digest: secret.to_string(),
                    new_state_sequence: 1,
                    new_state_digest: secret.to_string(),
                    point_operation_digest: secret.to_string(),
                    writer_lease_digest: secret.to_string(),
                    writer_fence: 1,
                    mutation_lease_generation: 1,
                },
            ),
            ..old_state.clone()
        };
        let key = PrivateOramMutationKey {
            collection_id: collection_id.to_string(),
        };
        let vacant_slot = PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        };
        let active_slot = PrivateOramMutationLeaseSlotV2 {
            generation: 1,
            active: Some(PrivateOramMutationLease {
                generation: 1,
                collection_id: collection_id.to_string(),
                owner_peer_id: 7,
                mutation_id: secret.to_string(),
                signed_mutation_digest: secret.to_string(),
                transition_digest: secret.to_string(),
                base_record_digest: secret.to_string(),
                base_state_sequence: 0,
                writer_lease_digest: secret.to_string(),
                writer_fence: 1,
                issued_at_unix: 100,
                expires_at_unix: 200,
                renewal_revision: 0,
                phase: PrivateOramMutationLeasePhase::ConsensusCommitted {
                    committed_record_digest: secret.to_string(),
                    committed_state_sequence: 1,
                    committed_signed_state_digest: secret.to_string(),
                    receipt_digest: secret.to_string(),
                },
            }),
            max_writer_fence: 1,
            ..vacant_slot.clone()
        };
        let operations = [
            ConsensusOperations::InitializePrivateOramMutationState(
                InitializePrivateOramMutationState {
                    key: key.clone(),
                    state: old_state.clone(),
                },
            ),
            ConsensusOperations::CompareAndSwapPrivateOramMutationLease(
                CompareAndSwapPrivateOramMutationLease {
                    key: key.clone(),
                    expected: vacant_slot,
                    new: active_slot,
                },
            ),
            ConsensusOperations::ApplyPrivateOramMutation(ApplyPrivateOramMutation {
                key,
                mutation_lease_generation: 1,
                expected_state: old_state,
                new_state,
            }),
        ];

        for operation in operations {
            for rendered in [
                format!("{operation:?}"),
                format!("{:?}", operation.redacted_log()),
            ] {
                assert!(!rendered.contains(secret), "{rendered}");
                assert!(!rendered.contains(collection_id), "{rendered}");
                assert!(!rendered.contains(index_name), "{rendered}");
            }
        }
    }

    #[test]
    fn private_oram_external_recovery_log_projection_redacts_identity_and_hashes() {
        let collection_sentinel = "qdrant-sec-private-oram-recovery-collection-sentinel";
        let operation_hash_sentinel = "qdrant-sec-private-oram-recovery-operation-sentinel";
        let checkpoint_digest_sentinel = "qdrant-sec-private-oram-recovery-checkpoint-sentinel";
        let operation = ConsensusOperations::ApplyPrivateOramExternalRecovery(
            PrivateOramExternalRecoveryOperation {
                phase: PrivateOramExternalRecoveryPhase::Begin,
                recovery: CompareAndSwapPrivateOramExternalRecovery {
                    key: PrivateOramExternalRecoveryKey {
                        collection_id: collection_sentinel.to_string(),
                    },
                    expected: None,
                    new: Some(PrivateOramExternalRecoveryState {
                        committed_backup_generation: 0,
                        committed_checkpoint_digest: None,
                        committed_install_intent_digest: None,
                        active_lease: Some(PrivateOramExternalRecoveryLease {
                            owner_peer_id: 7,
                            operation_id_hash: operation_hash_sentinel.to_string(),
                            checkpoint_digest: checkpoint_digest_sentinel.to_string(),
                            backup_generation: 7,
                            issued_at_unix: 100,
                            expires_at_unix: 160,
                            authority: PrivateOramExternalRecoveryAuthority::LegacyV1,
                            install_intent_digest: None,
                            phase: PrivateOramExternalRecoveryLeasePhase::Staging,
                        }),
                    }),
                },
                layout: PrivateOramConsensusLayout {
                    generation: 1,
                    owner_peer_ids: vec![7],
                    layout_digest: "qdrant-sec-private-oram-recovery-layout-sentinel".to_string(),
                    index_state_digest: "qdrant-sec-private-oram-recovery-index-state-sentinel"
                        .to_string(),
                },
                index_states: Vec::new(),
            },
        );

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("PrivateOramExternalRecovery"));
            assert!(!rendered.contains(collection_sentinel), "{rendered}");
            assert!(!rendered.contains(operation_hash_sentinel), "{rendered}");
            assert!(!rendered.contains(checkpoint_digest_sentinel), "{rendered}");
            assert!(!rendered.contains("recovery-layout-sentinel"), "{rendered}");
            assert!(
                !rendered.contains("recovery-index-state-sentinel"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn private_oram_layout_log_projection_redacts_identity_and_digests() {
        let collection_sentinel = "qdrant-sec-private-oram-layout-collection-sentinel";
        let layout_digest_sentinel = "qdrant-sec-private-oram-layout-digest-sentinel";
        let index_digest_sentinel = "qdrant-sec-private-oram-index-digest-sentinel";
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramLayout(CompareAndSwapPrivateOramLayout {
                key: PrivateOramLayoutKey {
                    collection_id: collection_sentinel.to_string(),
                },
                expected: None,
                new: PrivateOramConsensusLayout {
                    generation: 1,
                    owner_peer_ids: vec![7, 9],
                    layout_digest: layout_digest_sentinel.to_string(),
                    index_state_digest: index_digest_sentinel.to_string(),
                },
            });

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("CompareAndSwapPrivateOramLayout"));
            assert!(rendered.contains("generation: 1"), "{rendered}");
            assert!(!rendered.contains(collection_sentinel), "{rendered}");
            assert!(!rendered.contains(layout_digest_sentinel), "{rendered}");
            assert!(!rendered.contains(index_digest_sentinel), "{rendered}");
        }
    }

    #[test]
    fn private_oram_collection_layout_transition_logs_redact_bound_state() {
        let collection_sentinel = "qdrant-sec-layout-transition-collection-sentinel";
        let lease_sentinel = "qdrant-sec-layout-transition-lease-sentinel";
        let shard_key_sentinel = "qdrant-sec-layout-transition-shard-key-sentinel";
        let operation = ConsensusOperations::ApplyPrivateOramCollectionLayout(
            PrivateOramCollectionLayoutTransition {
                layout: CompareAndSwapPrivateOramLayout {
                    key: PrivateOramLayoutKey {
                        collection_id: collection_sentinel.to_string(),
                    },
                    expected: Some(PrivateOramConsensusLayout {
                        generation: 1,
                        owner_peer_ids: vec![7, 9],
                        layout_digest: BASE64URL_NOPAD.encode(&[51; 32]),
                        index_state_digest: BASE64URL_NOPAD.encode(&[52; 32]),
                    }),
                    new: PrivateOramConsensusLayout {
                        generation: 2,
                        owner_peer_ids: vec![7],
                        layout_digest: BASE64URL_NOPAD.encode(&[53; 32]),
                        index_state_digest: BASE64URL_NOPAD.encode(&[54; 32]),
                    },
                },
                leases: vec![PrivateOramLayoutLeaseBinding {
                    key: PrivateOramEpochKey {
                        collection_id: collection_sentinel.to_string(),
                        index_kind: PrivateOramIndexKind::Hnsw,
                        index_name: "qdrant-sec-layout-transition-index-sentinel".to_string(),
                    },
                    lease: PrivateOramSessionLease {
                        owner_peer_id: 7,
                        lease_id_hash: lease_sentinel.to_string(),
                        issued_at_unix: 100,
                        expires_at_unix: 160,
                    },
                }],
                shard_key_change: Some(PrivateOramShardKeyLayoutChange {
                    kind: PrivateOramShardKeyLayoutChangeKind::Drop,
                    shard_key: ShardKey::Keyword(shard_key_sentinel.into()),
                    entries: vec![PrivateOramShardLayoutEntry {
                        shard_id: 1,
                        shard_key: Some(ShardKey::Keyword(shard_key_sentinel.into())),
                        owner_peer_ids: vec![7],
                    }],
                    preinstalled_new_owner_peer_ids: Vec::new(),
                }),
                collection_meta: Box::new(CollectionMetaOperations::Nop { token: 7 }),
            },
        );

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("ApplyPrivateOramCollectionLayout"));
            assert!(rendered.contains("new_generation: 2"), "{rendered}");
            assert!(!rendered.contains(collection_sentinel), "{rendered}");
            assert!(!rendered.contains(lease_sentinel), "{rendered}");
            assert!(!rendered.contains(shard_key_sentinel), "{rendered}");
            assert!(!rendered.contains("layout-transition-index-sentinel"));
        }
    }

    #[test]
    fn private_oram_shard_layout_digest_is_canonical_and_context_bound() {
        let collection_id = "collection-uuid-1";
        let entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 7,
                shard_key: None,
                owner_peer_ids: vec![9, 7],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: None,
                owner_peer_ids: vec![11, 7],
            },
        ];
        let (owners, digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &entries,
        )
        .unwrap();
        assert_eq!(owners, vec![7, 9, 11]);
        assert_eq!(digest, "qi72wYzZybKDizqgH4R6vJgGR9su3NW21ud7WGBDTXo");

        let mut reordered = entries.clone();
        reordered.reverse();
        for entry in &mut reordered {
            entry.owner_peer_ids.reverse();
        }
        assert_eq!(
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &reordered,
            )
            .unwrap(),
            (owners, digest.clone()),
        );
        assert_ne!(
            canonical_private_oram_shard_layout_digest(
                "collection-uuid-2",
                ShardingMethod::Auto,
                &entries,
            )
            .unwrap()
            .1,
            digest,
        );

        for invalid_entries in [
            Vec::new(),
            vec![entries[0].clone(), entries[0].clone()],
            vec![PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![7, 7],
            }],
        ] {
            let error = canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &invalid_entries,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("layout digest input is invalid"), "{error}");
        }

        let shard_key_sentinel = "qdrant-sec-layout-shard-key-sentinel";
        let custom_entry = PrivateOramShardLayoutEntry {
            shard_id: 1,
            shard_key: Some(ShardKey::from(shard_key_sentinel)),
            owner_peer_ids: vec![7],
        };
        let rendered = format!("{custom_entry:?}");
        assert!(!rendered.contains(shard_key_sentinel), "{rendered}");
        assert!(
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &[custom_entry],
            )
            .unwrap_err()
            .to_string()
            .contains("layout digest input is invalid"),
        );
    }

    #[test]
    fn private_oram_resharding_post_layout_is_canonical_and_fail_closed() {
        let collection_id = "collection-uuid-1";
        let entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![7, 11],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![9],
            },
        ];
        let scale_up = ReshardKey {
            uuid: Uuid::from_u128(1),
            direction: ReshardingDirection::Up,
            peer_id: 9,
            shard_id: 2,
            shard_key: None,
        };
        let mut scaled_up_entries = entries.clone();
        scaled_up_entries.push(PrivateOramShardLayoutEntry {
            shard_id: 2,
            shard_key: None,
            owner_peer_ids: vec![9],
        });
        assert_eq!(
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &entries,
                &scale_up,
            )
            .unwrap(),
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &scaled_up_entries,
            )
            .unwrap(),
        );

        let scale_down = ReshardKey {
            uuid: Uuid::from_u128(2),
            direction: ReshardingDirection::Down,
            peer_id: 9,
            shard_id: 1,
            shard_key: None,
        };
        assert_eq!(
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &entries,
                &scale_down,
            )
            .unwrap(),
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &entries[..1],
            )
            .unwrap(),
        );

        let custom_key = ShardKey::from("tenant-a");
        let custom_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 4,
                shard_key: Some(custom_key.clone()),
                owner_peer_ids: vec![7],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 5,
                shard_key: Some(custom_key.clone()),
                owner_peer_ids: vec![9],
            },
        ];
        let custom_scale_down = ReshardKey {
            uuid: Uuid::from_u128(3),
            direction: ReshardingDirection::Down,
            peer_id: 9,
            shard_id: 5,
            shard_key: Some(custom_key),
        };
        assert_eq!(
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                ShardingMethod::Custom,
                &custom_entries,
                &custom_scale_down,
            )
            .unwrap(),
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Custom,
                &custom_entries[..1],
            )
            .unwrap(),
        );

        let invalid_keys = [
            ReshardKey {
                shard_id: 1,
                ..scale_up.clone()
            },
            ReshardKey {
                peer_id: 13,
                ..scale_down.clone()
            },
            ReshardKey {
                shard_id: 99,
                ..scale_down.clone()
            },
        ];
        for invalid_key in invalid_keys {
            let error = canonical_private_oram_resharding_post_layout_digest(
                "qdrant-sec-resharding-collection-sentinel",
                ShardingMethod::Auto,
                &entries,
                &invalid_key,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("resharding layout transition is invalid"));
            assert!(!error.contains("qdrant-sec-resharding-collection-sentinel"));
        }

        let final_shard = ReshardKey {
            uuid: Uuid::from_u128(4),
            direction: ReshardingDirection::Down,
            peer_id: 7,
            shard_id: 0,
            shard_key: None,
        };
        let error = canonical_private_oram_resharding_post_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &entries[..1],
            &final_shard,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("resharding layout transition is invalid"));
    }

    #[test]
    fn private_oram_resharding_layout_transition_is_replay_safe_and_redacted() {
        let collection_id = "qdrant-sec-resharding-collection-sentinel";
        let index_digest = BASE64URL_NOPAD.encode(&[71; 32]);
        let root_sentinel = BASE64URL_NOPAD.encode(&[72; 32]);
        let index_name_sentinel = "qdrant-sec-resharding-index-sentinel";
        let shard_key_sentinel = "qdrant-sec-resharding-shard-key-sentinel";

        for direction in [ReshardingDirection::Up, ReshardingDirection::Down] {
            let pre_entries = vec![
                PrivateOramShardLayoutEntry {
                    shard_id: 0,
                    shard_key: Some(ShardKey::from(shard_key_sentinel)),
                    owner_peer_ids: vec![7],
                },
                PrivateOramShardLayoutEntry {
                    shard_id: 1,
                    shard_key: Some(ShardKey::from(shard_key_sentinel)),
                    owner_peer_ids: vec![9, 11],
                },
            ];
            let resharding_key = ReshardKey {
                uuid: Uuid::from_u128(11),
                direction,
                peer_id: 9,
                shard_id: match direction {
                    ReshardingDirection::Up => 2,
                    ReshardingDirection::Down => 1,
                },
                shard_key: Some(ShardKey::from(shard_key_sentinel)),
            };
            let target_shard_owner_peer_ids = match direction {
                ReshardingDirection::Up => vec![9],
                ReshardingDirection::Down => vec![9, 11],
            };
            let mut post_entries = pre_entries.clone();
            match direction {
                ReshardingDirection::Up => {
                    post_entries.push(PrivateOramShardLayoutEntry {
                        shard_id: 2,
                        shard_key: Some(ShardKey::from(shard_key_sentinel)),
                        owner_peer_ids: vec![9],
                    });
                }
                ReshardingDirection::Down => {
                    post_entries.retain(|entry| entry.shard_id != 1);
                }
            }
            let (expected_owners, expected_digest) = canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Custom,
                &pre_entries,
            )
            .unwrap();
            let (new_owners, new_digest) = canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Custom,
                &post_entries,
            )
            .unwrap();
            let transition = PrivateOramReshardingLayoutTransition {
                resharding_key,
                target_shard_owner_peer_ids,
                layout: CompareAndSwapPrivateOramLayout {
                    key: PrivateOramLayoutKey {
                        collection_id: collection_id.to_string(),
                    },
                    expected: Some(PrivateOramConsensusLayout {
                        generation: 4,
                        owner_peer_ids: expected_owners,
                        layout_digest: expected_digest,
                        index_state_digest: index_digest.clone(),
                    }),
                    new: PrivateOramConsensusLayout {
                        generation: 5,
                        owner_peer_ids: new_owners,
                        layout_digest: new_digest,
                        index_state_digest: index_digest.clone(),
                    },
                },
                index_states: vec![PrivateOramLayoutIndexStateBinding {
                    key: PrivateOramEpochKey {
                        collection_id: collection_id.to_string(),
                        index_kind: PrivateOramIndexKind::Hnsw,
                        index_name: index_name_sentinel.to_string(),
                    },
                    state: PrivateOramConsensusEpoch {
                        index_epoch: 42,
                        root_hash: root_sentinel.clone(),
                        writeback_digest: None,
                    },
                }],
            };

            let round_trip: PrivateOramReshardingLayoutTransition =
                serde_json::from_value(serde_json::to_value(&transition).unwrap()).unwrap();
            assert_eq!(round_trip, transition);
            assert_eq!(
                classify_private_oram_resharding_layout_transition(
                    collection_id,
                    ShardingMethod::Custom,
                    &pre_entries,
                    &transition,
                )
                .unwrap(),
                PrivateOramLayoutTransitionState::Pending,
            );
            assert_eq!(
                classify_private_oram_resharding_layout_transition(
                    collection_id,
                    ShardingMethod::Custom,
                    &post_entries,
                    &transition,
                )
                .unwrap(),
                PrivateOramLayoutTransitionState::Applied,
            );

            let rendered = format!("{transition:?}");
            for sentinel in [
                collection_id,
                index_name_sentinel,
                &root_sentinel,
                shard_key_sentinel,
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }

            let mut malformed = transition.clone();
            malformed.target_shard_owner_peer_ids = vec![13];
            let error = classify_private_oram_resharding_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &pre_entries,
                &malformed,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("resharding layout transition is invalid"));
            assert!(!error.contains(collection_id));
            assert!(!error.contains(shard_key_sentinel));
        }
    }

    #[test]
    fn private_oram_replica_removal_layout_classifier_is_replay_safe() {
        let collection_id = "collection-uuid-1";
        let pre_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![7, 9],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: None,
                owner_peer_ids: vec![7],
            },
        ];
        let mut post_entries = pre_entries.clone();
        post_entries[0].owner_peer_ids.retain(|owner| *owner != 9);
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &post_entries,
        )
        .unwrap();
        let expected = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[61; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[62; 32]),
        };

        assert_eq!(
            classify_private_oram_replica_removal_layout_transition(
                collection_id,
                ShardingMethod::Auto,
                &pre_entries,
                1,
                9,
                &expected,
                &new,
            )
            .unwrap(),
            PrivateOramLayoutTransitionState::Pending,
        );
        assert_eq!(
            classify_private_oram_replica_removal_layout_transition(
                collection_id,
                ShardingMethod::Auto,
                &post_entries,
                1,
                9,
                &expected,
                &new,
            )
            .unwrap(),
            PrivateOramLayoutTransitionState::Applied,
        );

        let wrong_new = PrivateOramConsensusLayout {
            layout_digest: BASE64URL_NOPAD.encode(&[63; 32]),
            ..new
        };
        let error = classify_private_oram_replica_removal_layout_transition(
            collection_id,
            ShardingMethod::Auto,
            &pre_entries,
            1,
            9,
            &expected,
            &wrong_new,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("layout transition is invalid"), "{error}");
        assert!(!error.contains(collection_id), "{error}");
        assert!(!error.contains(&wrong_new.layout_digest), "{error}");
    }

    #[test]
    fn private_oram_shard_key_create_layout_classifier_is_replay_safe() {
        let collection_id = "collection-uuid-1";
        let alpha = ShardKey::Keyword("alpha".into());
        let beta = ShardKey::Keyword("beta-secret-sentinel".into());
        let pre_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: Some(alpha.clone()),
                owner_peer_ids: vec![7, 9],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: Some(alpha),
                owner_peer_ids: vec![7],
            },
        ];
        let change = PrivateOramShardKeyLayoutChange {
            kind: PrivateOramShardKeyLayoutChangeKind::Create,
            shard_key: beta.clone(),
            entries: vec![
                PrivateOramShardLayoutEntry {
                    shard_id: 3,
                    shard_key: Some(beta.clone()),
                    owner_peer_ids: vec![9],
                },
                PrivateOramShardLayoutEntry {
                    shard_id: 4,
                    shard_key: Some(beta.clone()),
                    owner_peer_ids: vec![7],
                },
            ],
            preinstalled_new_owner_peer_ids: Vec::new(),
        };
        let mut post_entries = pre_entries.clone();
        post_entries.extend(change.entries.clone());
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &post_entries,
        )
        .unwrap();
        let expected = PrivateOramConsensusLayout {
            generation: 3,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[64; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 4,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest: expected.index_state_digest.clone(),
        };

        for (entries, state) in [
            (&pre_entries, PrivateOramLayoutTransitionState::Pending),
            (&post_entries, PrivateOramLayoutTransitionState::Applied),
        ] {
            assert_eq!(
                classify_private_oram_shard_key_layout_transition(
                    collection_id,
                    ShardingMethod::Custom,
                    entries,
                    &change,
                    &expected,
                    &new,
                )
                .unwrap(),
                state,
            );
        }

        let mut new_owner_change = change.clone();
        new_owner_change.entries[0].owner_peer_ids = vec![11];
        let mut new_owner_post_entries = pre_entries.clone();
        new_owner_post_entries.extend(new_owner_change.entries.clone());
        let (new_owner_peer_ids, new_owner_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &new_owner_post_entries,
        )
        .unwrap();
        let new_owner_layout = PrivateOramConsensusLayout {
            generation: 4,
            owner_peer_ids: new_owner_peer_ids,
            layout_digest: new_owner_digest,
            index_state_digest: expected.index_state_digest.clone(),
        };
        let error = classify_private_oram_shard_key_layout_transition(
            collection_id,
            ShardingMethod::Custom,
            &pre_entries,
            &new_owner_change,
            &expected,
            &new_owner_layout,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("layout transition is invalid"), "{error}");
        assert!(!error.contains(collection_id), "{error}");
        assert!(!error.contains("beta-secret-sentinel"), "{error}");

        new_owner_change.preinstalled_new_owner_peer_ids = vec![11];
        for (entries, state) in [
            (&pre_entries, PrivateOramLayoutTransitionState::Pending),
            (
                &new_owner_post_entries,
                PrivateOramLayoutTransitionState::Applied,
            ),
        ] {
            assert_eq!(
                classify_private_oram_shard_key_layout_transition(
                    collection_id,
                    ShardingMethod::Custom,
                    entries,
                    &new_owner_change,
                    &expected,
                    &new_owner_layout,
                )
                .unwrap(),
                state,
            );
        }

        let mut forged_preinstall = new_owner_change;
        forged_preinstall.preinstalled_new_owner_peer_ids = vec![12];
        assert!(
            classify_private_oram_shard_key_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &pre_entries,
                &forged_preinstall,
                &expected,
                &new_owner_layout,
            )
            .is_err()
        );

        let mut skipped_id_change = change;
        skipped_id_change.entries[1].shard_id = 5;
        assert!(
            classify_private_oram_shard_key_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &pre_entries,
                &skipped_id_change,
                &expected,
                &new,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_shard_key_layout_change_defaults_missing_preinstall_marker_closed() {
        let shard_key = ShardKey::Keyword("legacy-key".into());
        let change = PrivateOramShardKeyLayoutChange {
            kind: PrivateOramShardKeyLayoutChangeKind::Create,
            shard_key: shard_key.clone(),
            entries: vec![PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: Some(shard_key),
                owner_peer_ids: vec![7],
            }],
            preinstalled_new_owner_peer_ids: Vec::new(),
        };

        let encoded = serde_cbor::to_vec(&change).unwrap();
        let decoded: PrivateOramShardKeyLayoutChange = serde_cbor::from_slice(&encoded).unwrap();
        assert_eq!(decoded, change);
        assert!(decoded.preinstalled_new_owner_peer_ids.is_empty());
    }

    #[test]
    fn private_oram_shard_key_drop_layout_classifier_is_replay_safe() {
        let collection_id = "collection-uuid-1";
        let alpha = ShardKey::Keyword("alpha".into());
        let beta = ShardKey::Keyword("beta-secret-sentinel".into());
        let retained_entries = vec![PrivateOramShardLayoutEntry {
            shard_id: 1,
            shard_key: Some(alpha),
            owner_peer_ids: vec![7, 9],
        }];
        let dropped_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: Some(beta.clone()),
                owner_peer_ids: vec![9],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 3,
                shard_key: Some(beta.clone()),
                owner_peer_ids: vec![7],
            },
        ];
        let mut pre_entries = retained_entries.clone();
        pre_entries.extend(dropped_entries.clone());
        let change = PrivateOramShardKeyLayoutChange {
            kind: PrivateOramShardKeyLayoutChangeKind::Drop,
            shard_key: beta,
            entries: dropped_entries,
            preinstalled_new_owner_peer_ids: Vec::new(),
        };
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Custom,
            &retained_entries,
        )
        .unwrap();
        let expected = PrivateOramConsensusLayout {
            generation: 5,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[65; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 6,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest: expected.index_state_digest.clone(),
        };

        assert_eq!(
            classify_private_oram_shard_key_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &pre_entries,
                &change,
                &expected,
                &new,
            )
            .unwrap(),
            PrivateOramLayoutTransitionState::Pending,
        );
        assert_eq!(
            classify_private_oram_shard_key_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &retained_entries,
                &change,
                &expected,
                &new,
            )
            .unwrap(),
            PrivateOramLayoutTransitionState::Applied,
        );

        let mut preinstalled_drop = change.clone();
        preinstalled_drop.preinstalled_new_owner_peer_ids = vec![11];
        assert!(
            classify_private_oram_shard_key_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &pre_entries,
                &preinstalled_drop,
                &expected,
                &new,
            )
            .is_err()
        );

        let final_key_expected = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: new.owner_peer_ids.clone(),
            layout_digest: new.layout_digest.clone(),
            index_state_digest: new.index_state_digest.clone(),
        };
        let final_key_change = PrivateOramShardKeyLayoutChange {
            kind: PrivateOramShardKeyLayoutChangeKind::Drop,
            shard_key: retained_entries[0].shard_key.clone().unwrap(),
            entries: retained_entries.clone(),
            preinstalled_new_owner_peer_ids: Vec::new(),
        };
        assert!(
            classify_private_oram_shard_key_layout_transition(
                collection_id,
                ShardingMethod::Custom,
                &retained_entries,
                &final_key_change,
                &final_key_expected,
                &new,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_shard_transfer_layout_classifier_is_replay_safe() {
        let collection_id = "collection-uuid-1";
        for sync in [true, false] {
            let (pre_entries, post_entries, transfer, expected, new) =
                private_oram_shard_transfer_fixture(sync);
            assert_eq!(
                classify_private_oram_shard_transfer_layout_transition(
                    collection_id,
                    ShardingMethod::Auto,
                    &pre_entries,
                    &transfer,
                    &expected,
                    &new,
                )
                .unwrap(),
                PrivateOramLayoutTransitionState::Pending,
            );
            assert_eq!(
                classify_private_oram_shard_transfer_layout_transition(
                    collection_id,
                    ShardingMethod::Auto,
                    &post_entries,
                    &transfer,
                    &expected,
                    &new,
                )
                .unwrap(),
                PrivateOramLayoutTransitionState::Applied,
            );

            let mut malformed = transfer.clone();
            malformed
                .private_oram_layout_transition
                .as_mut()
                .unwrap()
                .collection_id = "qdrant-sec-transfer-collection-sentinel".to_string();
            let error = classify_private_oram_shard_transfer_layout_transition(
                collection_id,
                ShardingMethod::Auto,
                &pre_entries,
                &malformed,
                &expected,
                &new,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("layout transition is invalid"), "{error}");
            assert!(!error.contains("qdrant-sec-transfer-collection-sentinel"));
        }
    }

    #[test]
    fn private_oram_precommitted_transfer_recovery_is_exactly_bounded() {
        let (_, _, _, mut expected, new) = private_oram_shard_transfer_fixture(true);
        expected.index_state_digest = new.index_state_digest.clone();
        let current = PrivateOramConsensusLayout {
            generation: expected.generation,
            owner_peer_ids: new.owner_peer_ids.clone(),
            layout_digest: new.layout_digest.clone(),
            index_state_digest: new.index_state_digest.clone(),
        };

        assert!(private_oram_layout_is_precommitted_transfer_recovery(
            &current, &expected, &new,
        ));
        for malformed in [
            PrivateOramConsensusLayout {
                generation: current.generation + 1,
                ..current.clone()
            },
            PrivateOramConsensusLayout {
                owner_peer_ids: expected.owner_peer_ids.clone(),
                ..current.clone()
            },
            PrivateOramConsensusLayout {
                layout_digest: expected.layout_digest.clone(),
                ..current.clone()
            },
            PrivateOramConsensusLayout {
                index_state_digest: BASE64URL_NOPAD.encode(&[99; 32]),
                ..current.clone()
            },
        ] {
            assert!(!private_oram_layout_is_precommitted_transfer_recovery(
                &malformed, &expected, &new,
            ));
        }

        let mut skipped_generation = new.clone();
        skipped_generation.generation += 1;
        assert!(!private_oram_layout_is_precommitted_transfer_recovery(
            &current,
            &expected,
            &skipped_generation,
        ));
    }

    #[test]
    fn private_oram_finish_transfer_uses_bound_consensus_operation() {
        let (_, _, transfer, _, _) = private_oram_shard_transfer_fixture(true);
        let root_hash = transfer
            .private_oram_layout_transition
            .as_ref()
            .unwrap()
            .index_states[0]
            .root_hash
            .clone();
        let operation = ConsensusOperations::finish_transfer("docs".to_string(), transfer.clone());
        assert!(matches!(
            operation,
            ConsensusOperations::FinishPrivateOramShardTransfer(_)
        ));
        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("FinishPrivateOramShardTransfer"));
            assert!(!rendered.contains(&root_hash), "{rendered}");
        }

        let legacy = ShardTransfer {
            private_oram_layout_transition: None,
            ..transfer
        };
        assert!(matches!(
            ConsensusOperations::finish_transfer("docs".to_string(), legacy),
            ConsensusOperations::CollectionMeta(_)
        ));
    }

    #[test]
    fn private_oram_index_state_digest_is_canonical_and_context_bound() {
        let collection_id = "collection-uuid-1";
        let hnsw = (
            PrivateOramEpochKey {
                collection_id: collection_id.to_string(),
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "text".to_string(),
            },
            PrivateOramConsensusEpoch {
                index_epoch: 42,
                root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                writeback_digest: Some(BASE64URL_NOPAD.encode(&[12; 32])),
            },
        );
        let result = (
            PrivateOramEpochKey {
                collection_id: collection_id.to_string(),
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            },
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                writeback_digest: None,
            },
        );
        let digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[result.clone(), hnsw.clone()],
        )
        .unwrap();
        assert_eq!(digest, "n7nIXIYcknwRMw-RNISCQyIc51XTAfh2mKJDV3-qvFQ");
        assert_eq!(
            canonical_private_oram_index_state_digest(collection_id, &[hnsw.clone(), result])
                .unwrap(),
            digest,
        );

        let malformed_digest_sentinel = "qdrant-sec-index-state-digest-sentinel";
        let malformed = (
            hnsw.0.clone(),
            PrivateOramConsensusEpoch {
                root_hash: malformed_digest_sentinel.to_string(),
                ..hnsw.1.clone()
            },
        );
        for invalid_states in [
            Vec::new(),
            vec![hnsw.clone(), hnsw.clone()],
            vec![malformed],
        ] {
            let error = canonical_private_oram_index_state_digest(collection_id, &invalid_states)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("index-state digest input is invalid"),
                "{error}"
            );
            assert!(!error.contains(malformed_digest_sentinel), "{error}");
        }
    }

    #[test]
    fn private_oram_activation_operation_is_canonical_bounded_and_redacted() {
        let fixture = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let operation = fixture.prepare_operation;
        let encoded = serde_cbor::to_vec(&operation).unwrap();
        let decoded: PrivateOramMutationActivationBarrierV2 =
            serde_cbor::from_slice(&encoded).unwrap();
        assert_eq!(decoded, operation);
        assert_eq!(
            decoded.decode_proof().unwrap().proof_digest(),
            operation.proof_digest()
        );

        let rendered = format!(
            "{:?} {:?}",
            operation,
            ConsensusOperations::ActivatePrivateOramMutationV2(operation.clone()).redacted_log()
        );
        assert!(!rendered.contains(operation.proof_digest()));
        assert!(!rendered.contains("proof_canonical_json"));

        let mut noncanonical = serde_json::to_value(&operation).unwrap();
        let proof = noncanonical["proof_canonical_json"].as_str().unwrap();
        noncanonical["proof_canonical_json"] = serde_json::Value::String(format!(" {proof}"));
        let noncanonical: PrivateOramMutationActivationBarrierV2 =
            serde_json::from_value(noncanonical).unwrap();
        assert!(noncanonical.decode_proof().is_err());

        let mut wrong_digest = serde_json::to_value(&operation).unwrap();
        wrong_digest["proof_digest"] = serde_json::Value::String(BASE64URL_NOPAD.encode(&[99; 32]));
        let wrong_digest: PrivateOramMutationActivationBarrierV2 =
            serde_json::from_value(wrong_digest).unwrap();
        assert!(wrong_digest.decode_proof().is_err());

        let mut oversized = serde_json::to_value(&operation).unwrap();
        oversized["proof_canonical_json"] = serde_json::Value::String(
            "x".repeat(PRIVATE_ORAM_MUTATION_ACTIVATION_PROOF_MAX_BYTES + 1),
        );
        let oversized: PrivateOramMutationActivationBarrierV2 =
            serde_json::from_value(oversized).unwrap();
        assert!(oversized.decode_proof().is_err());
    }

    #[test]
    fn serde_json_integer_combatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(1337));
    }

    #[test]
    fn serde_json_float_combatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(42.69));
    }

    #[test]
    fn serde_json_string_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(
            "Qdrant is the best vector search engine on the market 💪😎👍"
        ));
    }

    #[test]
    fn serde_json_basic_array_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json_array());
    }

    #[test]
    fn serde_json_basic_object_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json_object());
    }

    #[test]
    fn serde_json_nested_array_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!([
            json!([json_array(), json_object()]),
            json!({ "array": json_array(), "object": json_object() }),
        ]));
    }

    #[test]
    fn serde_json_nested_object_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!({
            "array": json!([ json_array(), json_object() ]),
            "object": json!({ "array": json_array(), "object": json_object() }),
        }))
    }

    fn serde_json_value_compatible_with_cbor(input: serde_json::Value) {
        let cbor = serde_cbor::to_vec(&input)
            .unwrap_or_else(|_| panic!("JSON value {input} can be serialized to CBOR"));

        let output: serde_json::Value = serde_cbor::from_slice(&cbor)
            .unwrap_or_else(|_| panic!("JSON value {input} can be deserialized from CBOR"));

        assert_eq!(input, output);
    }

    fn json_array() -> serde_json::Value {
        json!([null, 1337, 42.69, "string"])
    }

    fn json_object() -> serde_json::Value {
        json!({
            "null": null,
            "integer": 1337,
            "float": 42.69,
            "string": "string",
        })
    }
}
