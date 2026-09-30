use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use collection::operations::types::{CollectionError, CollectionResult};
use collection::private_oram_owner_journal::{
    PrivateOramOwnerRecoveryIndexProjectionInputV1, PrivateOramOwnerRecoveryIndexProjectionV1,
    PrivateOramOwnerRecoveryProjectionV1,
};
use collection::shards::channel_service::PrivateOramAuthenticatedOwnerRecoveryResponse;
use collection::shards::shard::PeerId;
use collection::{
    PrivateOramOwnerPrepareParentV2, PrivateOramOwnerPrepareRequirementV2,
    PrivateOramOwnerPreparedEvidenceV2, PrivateOramOwnerPrestagePlanV2,
    PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerRecoveryPairOutcomeV1,
    PrivateOramOwnerRecoveryParentBridgeV1, PrivateOramOwnerRecoveryParentDispositionV1,
    PrivateOramOwnerRecoveryParentInputV1, PrivateOramOwnerRecoveryParentVerifierV1,
    PrivateOramOwnerRecoveryStoreDispositionV1, PrivateOramOwnerRecoveryStorePairResourcesV1,
    PrivateOramOwnerRecoveryTerminalEvidenceV1, classify_private_oram_owner_recovery_store_pair_v1,
    new_private_oram_owner_recovery_parent_bridge_v1,
    recover_private_oram_owner_store_pair_then_v1,
};
use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use fs4::fs_std::FileExt;
use qdrant_sec::{
    PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION, PrivateOramAppendMutationBundleV1,
    PrivateOramAppendWritebackDigestInput, PrivateOramImmutableManifestBundleV2,
    PrivateOramIndexKindV2, PrivateOramMutationError, PrivateOramOwnerPrestageAttestationV2,
    PrivateOramOwnerPrestagePackageV2, PrivateOramOwnerPrestageRequestV2,
    PrivateOramPeerRecoveryPublicKeyV1, PrivateOramPeerRecoveryRequestV2,
    PrivateOramPeerRecoveryTerminalIndexV2, PrivateOramPeerRecoveryTerminalKindV2,
    PrivateOramPeerRecoveryTerminalV2, PrivateOramPointOperationKindV1,
    PrivateOramSignatureVerification, PrivateOramSignedStateV2, PrivateOramValidatedOwnerPrepareV1,
    PrivateOramVisiblePointRecordV1, ResultPrivacyMode,
    decode_private_oram_owner_prestage_package_v2, private_oram_append_mutation_v1_digest,
    private_oram_append_writeback_v1_digest, private_oram_immutable_manifest_v2_digest,
    private_oram_mutation_reservation_protocol_capability_digest_v2,
    private_oram_no_server_point_record_v1_digest, private_oram_owner_prestage_request_digest_v2,
    private_oram_owner_prestage_roster_digest_v2, private_oram_signed_state_v2_digest,
    private_oram_visible_point_record_v1_digest,
    try_private_oram_peer_recovery_terminal_evidence_digest_v2,
    validate_private_oram_append_mutation_v1_shape,
    validate_private_oram_append_mutation_v1_signature,
    validate_private_oram_immutable_manifest_v2_signature,
    validate_private_oram_owner_prestage_attestation_for_signer_v2,
    validate_private_oram_peer_recovery_public_key_v1,
    validate_private_oram_peer_recovery_request_v2_shape,
    validate_private_oram_signed_state_v2_signature,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

use super::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1;
use super::consensus::private_oram_mutation_cleanup::{
    PrivateOramMutationCleanupExpectationStatusV2, PrivateOramMutationCleanupExpectationV2,
    PrivateOramMutationClearedPendingArchivePermitV2,
    derive_private_oram_mutation_cleanup_expectation_v2,
    private_oram_mutation_lease_state_digest_v2,
};
pub use super::consensus::private_oram_mutation_recovery_capsules::PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2;
use super::consensus::private_oram_mutation_recovery_capsules::{
    PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
    derive_private_oram_mutation_recovery_capsules_ready_v2,
};
use super::consensus::private_oram_mutation_watermark::{
    PrivateOramMutationParentWatermarkExpectationV2,
    derive_private_oram_mutation_parent_watermark_at_sequence_v2,
    validate_private_oram_mutation_parent_watermark_v2_cas_transition,
};
use super::consensus_manager::{
    LinearizablePrivateOramMutationReconcileSnapshotV2, PrivateOramMutationReconcileSnapshotV1,
};
use super::consensus_ops::{
    PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION, PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
    PRIVATE_ORAM_MUTATION_RECEIPT_VERSION, PrivateOramConsensusCollectionIndexStateV2,
    PrivateOramConsensusCollectionStateV2, PrivateOramConsensusEpoch,
    PrivateOramConsensusTransitionV2, PrivateOramIndexKind, PrivateOramMutationClearOutcome,
    PrivateOramMutationKey, PrivateOramMutationLease, PrivateOramMutationLeasePhase,
    PrivateOramMutationLeaseSlotV2, PrivateOramMutationReceiptV2,
    canonical_private_oram_consensus_state_record_digest,
    canonical_private_oram_mutation_receipt_digest,
    canonical_private_oram_mutation_transition_digest,
};
use super::private_oram_mutation_state_v2::{
    PrivateOramMutationDecisionEvidenceV2 as RawPrivateOramMutationDecisionEvidenceV2,
    PrivateOramMutationDecisionKindV2 as ValidatedPrivateOramMutationDecisionKindV2,
    PrivateOramMutationJournalPhaseV2, PrivateOramMutationJournalStateV2,
    PrivateOramMutationOwnerTerminalEvidenceV2, PrivateOramMutationOwnerTerminalIndexEvidenceV2,
    PrivateOramMutationOwnerTerminalKindV2,
    PrivateOramMutationPointResolutionEvidenceV2 as RawPrivateOramMutationPointResolutionEvidenceV2,
    private_oram_owner_terminal_evidence_v2_digest, record_digest_at_phase_v2,
};
#[cfg(test)]
use super::private_oram_mutation_state_v2::{
    PrivateOramPointResolutionOutcomeV2, PrivateOramPointResolutionReceiptV2,
};
use super::private_oram_point_staging::{
    PrivateOramDurablePointStageTokenV1, PrivateOramPointStagingError, PrivateOramPointStagingStore,
};

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
mod writer_v2;
pub(in crate::content_manager) use writer_v2::PrivateOramMutationJournalStructuralSnapshotV2;
#[cfg(test)]
pub(crate) use writer_v2::private_oram_owner_recovery_capsule_install_receipt_for_test;
pub use writer_v2::{
    PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramOwnerRecoveryCapsulePackageV2,
    PrivateOramOwnerRecoveryCapsuleStoreV2,
    decode_private_oram_owner_recovery_capsule_install_receipt_v2,
    decode_private_oram_owner_recovery_capsule_package_v2,
    encode_private_oram_owner_recovery_capsule_install_receipt_v2,
    encode_private_oram_owner_recovery_capsule_package_v2,
    validate_private_oram_owner_recovery_capsule_install_receipt_v2,
};

pub const PRIVATE_ORAM_MUTATION_JOURNAL_DIR: &str = "private_oram_mutations";
pub const PRIVATE_ORAM_MUTATION_JOURNAL_VERSION: u16 = 1;

/// Opaque, locally-derived input for one consensus readiness transition.
#[doc(hidden)]
pub struct PrivateOramMutationRecoveryReadinessProposalV2 {
    key: PrivateOramMutationKey,
    expectation: PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
}

impl Debug for PrivateOramMutationRecoveryReadinessProposalV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationRecoveryReadinessProposalV2")
            .field("collection_id", &"[redacted]")
            .field("expectation", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationRecoveryReadinessProposalV2 {
    pub(crate) fn key(&self) -> &PrivateOramMutationKey {
        &self.key
    }

    pub(crate) fn expectation(&self) -> &PrivateOramMutationRecoveryCapsulesReadyExpectationV2 {
        &self.expectation
    }
}

/// Opaque, locally-derived input for one consensus parent-watermark transition.
#[doc(hidden)]
pub struct PrivateOramMutationParentProgressProposalV2 {
    key: PrivateOramMutationKey,
    expectation: PrivateOramMutationParentWatermarkExpectationV2,
}

impl Debug for PrivateOramMutationParentProgressProposalV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationParentProgressProposalV2")
            .field("collection_id", &"[redacted]")
            .field("expectation", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationParentProgressProposalV2 {
    pub(crate) fn key(&self) -> &PrivateOramMutationKey {
        &self.key
    }

    pub(crate) fn expectation(&self) -> &PrivateOramMutationParentWatermarkExpectationV2 {
        &self.expectation
    }
}

const ACTIVE_DIR: &str = "active";
const TEMP_DIR: &str = "temp";
const ACTIVE_TEMP_DIR: &str = "temp";
const LOCK_FILE: &str = "journal.lock";
const DESCRIPTOR_FILE: &str = "descriptor.json";
const IMMUTABLE_MANIFEST_FILE: &str = "immutable_manifest.json";
const STATE_FILE: &str = "state.json";
const MAX_DESCRIPTOR_BYTES: u64 = 512 * 1024 * 1024;
const MAX_IMMUTABLE_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OWNER_REQUIREMENTS: usize = 65_536;
const PARENT_SYNC_ATTEMPTS: usize = 3;
const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-mutation-parent-descriptor/v1";
const STATE_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-mutation-parent-state/v1";
const OWNER_RECOVERY_AUTHORITY_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-recovery-authority/v1";
const ADMISSION_RECOVERY_MANIFEST_VERSION_V1: u16 = 1;
const ADMISSION_RECOVERY_MANIFEST_VERSION_V2: u16 = 2;
const ADMISSION_RECOVERY_MANIFEST_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-admission-recovery-manifest/v2";
const OWNER_CLEANUP_EVIDENCE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-owner-cleanup-evidence/v2";
const POINT_CLEANUP_EVIDENCE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-point-cleanup-evidence/v2";
const LOCAL_CLEANUP_COMPLETE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-local-cleanup-complete/v2";
const TERMINAL_ARCHIVE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-terminal-archive/v2";
const LOCAL_CLEANUP_COMPLETE_FILE_V2: &str = "cleanup_complete_v2.json";
const LOCAL_CLEANUP_COMPLETE_VERSION_V2: u16 = 1;
const MAX_LOCAL_CLEANUP_COMPLETE_BYTES_V2: u64 = 64 * 1024;
const TERMINAL_ARCHIVE_FILE_V2: &str = "terminal_archive_v2.json";
const TERMINAL_ARCHIVE_VERSION_V2: u16 = 1;
const TERMINAL_ARCHIVE_NAME_PREFIX_V2: &str = "completed-v2-";
const MAX_TERMINAL_ARCHIVE_BYTES_V2: u64 = 64 * 1024;
const ADMISSION_RECOVERY_MANIFEST_MAX_CANONICAL_JSON_BYTES_V2: usize = 8 * 1024 * 1024;
const APPEND_RESERVATION_VERSION_V2: u16 = 2;
const APPEND_RESERVATION_TARGET_VERSION_V2: u16 = 2;
const APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V2: usize = 2 * 1024 * 1024;
const APPEND_RESERVATION_MAX_OWNERS_V2: usize = 1_024;
const APPEND_RESERVATION_RESERVED_REJECTION_BYTES_V2: u64 = 4 * 1024 * 1024 + 128 * 1024;
const APPEND_RESERVATION_RESERVED_CLEANUP_BYTES_V2: u64 = 4 * 1024 * 1024 + 128 * 1024;
const APPEND_RESERVATION_TARGET_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-owner-target/v2";
const APPEND_RESERVATION_ATTEMPT_ID_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-attempt-id/v2";
const APPEND_RESERVATION_PLAN_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-plan/v2";
const APPEND_RESERVATION_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-reservation/v2";
const APPEND_RESERVATION_CONTROLLER_ID_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-controller-id/v2";
const APPEND_RESERVATION_ATTEMPT_LEASE_ID_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-attempt-lease-id/v2";
const APPEND_PREPARED_REQUEST_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-prepared-request/v2";
const APPEND_RESERVED_REJECTION_REQUEST_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-reserved-rejection-request/v2";
const POINT_ID_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-staged-point-id-digest/v1";

#[derive(Error)]
pub enum PrivateOramMutationJournalError {
    #[error("private ORAM mutation journal input is invalid")]
    InvalidInput(&'static str),
    #[error("private ORAM mutation journal contains corrupt or inconsistent state")]
    Corrupt,
    #[error("another private ORAM mutation journal is active")]
    ConcurrentMutation,
    #[error("private ORAM mutation journal phase transition is invalid")]
    InvalidTransition,
    #[error("private ORAM mutation journal has a legacy V1 state that requires explicit recovery")]
    LegacyV1State,
    #[error("private ORAM mutation journal signature validation failed")]
    Signature(#[source] PrivateOramMutationError),
    #[error("private ORAM mutation journal I/O failed before publication")]
    Io(#[source] io::Error),
    #[error("private ORAM mutation journal publication outcome is indeterminate")]
    Indeterminate,
    #[error("private ORAM mutation journal requires unsupported filesystem primitives")]
    Unsupported,
    #[error("private ORAM mutation point staging validation failed")]
    PointStaging(#[source] PrivateOramPointStagingError),
}

impl Debug for PrivateOramMutationJournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::Corrupt => f.write_str("Corrupt"),
            Self::ConcurrentMutation => f.write_str("ConcurrentMutation"),
            Self::InvalidTransition => f.write_str("InvalidTransition"),
            Self::LegacyV1State => f.write_str("LegacyV1State"),
            Self::Signature(_) => f.write_str("Signature([redacted])"),
            Self::Io(_) => f.write_str("Io([redacted])"),
            Self::Indeterminate => f.write_str("Indeterminate"),
            Self::Unsupported => f.write_str("Unsupported"),
            Self::PointStaging(_) => f.write_str("PointStaging([redacted])"),
        }
    }
}

impl From<PrivateOramPointStagingError> for PrivateOramMutationJournalError {
    fn from(error: PrivateOramPointStagingError) -> Self {
        Self::PointStaging(error)
    }
}

impl From<PrivateOramMutationError> for PrivateOramMutationJournalError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Signature(error)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerRequirementV1 {
    pub peer_id: PeerId,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub writeback_digest: String,
}

impl Debug for PrivateOramMutationOwnerRequirementV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerRequirementV1")
            .field("peer_id", &self.peer_id)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerPrepareEvidenceV1 {
    pub peer_id: PeerId,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub prepared_journal_digest: String,
}

impl Debug for PrivateOramMutationOwnerPrepareEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerPrepareEvidenceV1")
            .field("peer_id", &self.peer_id)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerFinalizeEvidenceV1 {
    pub peer_id: PeerId,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub prepared_journal_digest: String,
    pub finalized_state_digest: String,
}

impl Debug for PrivateOramMutationOwnerFinalizeEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerFinalizeEvidenceV1")
            .field("peer_id", &self.peer_id)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("finalized_state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PrivateOramMutationPointStageEvidenceV1 {
    PrivateOramPointStaging {
        point_id: String,
        staged_insert_sha256: String,
        canonical_point_id_digest: String,
        child_descriptor_digest: String,
        parent_owners_prepared_record_digest: String,
    },
    NoServerPointRecord {
        parent_owners_prepared_record_digest: String,
    },
}

impl Debug for PrivateOramMutationPointStageEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateOramPointStaging { .. } => {
                f.write_str("PrivateOramPointStaging([redacted])")
            }
            Self::NoServerPointRecord { .. } => f.write_str("NoServerPointRecord([redacted])"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationConsensusEvidenceV1 {
    pub committed_record_digest: String,
    pub committed_state_sequence: u64,
    pub committed_signed_state_digest: String,
    pub receipt_digest: String,
    pub transition_digest: String,
    pub lease_renewal_revision: u64,
}

impl Debug for PrivateOramMutationConsensusEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationConsensusEvidenceV1")
            .field("committed_record_digest", &"[redacted]")
            .field("committed_state_sequence", &self.committed_state_sequence)
            .field("committed_signed_state_digest", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .field("transition_digest", &"[redacted]")
            .field("lease_renewal_revision", &self.lease_renewal_revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramMutationJournalPhaseV1 {
    LeaseAcquired,
    OwnersPrepared,
    PointStageDurable,
    ConsensusCommitted,
    RemotesFinalized,
    LocalFinalized,
    Complete,
}

impl PrivateOramMutationJournalPhaseV1 {
    pub(super) const fn sequence(self) -> u64 {
        match self {
            Self::LeaseAcquired => 1,
            Self::OwnersPrepared => 2,
            Self::PointStageDurable => 3,
            Self::ConsensusCommitted => 4,
            Self::RemotesFinalized => 5,
            Self::LocalFinalized => 6,
            Self::Complete => 7,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationJournalDescriptorV1 {
    pub version: u16,
    pub coordinator_peer_id: PeerId,
    pub mutation_digest: String,
    pub mutation_bundle: PrivateOramAppendMutationBundleV1,
    pub preparing_lease: PrivateOramMutationLease,
    pub expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    pub owner_requirements: Vec<PrivateOramMutationOwnerRequirementV1>,
    pub descriptor_digest: String,
}

impl Debug for PrivateOramMutationJournalDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalDescriptorV1")
            .field("version", &self.version)
            .field("coordinator_peer_id", &self.coordinator_peer_id)
            .field("mutation_digest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("preparing_lease", &self.preparing_lease)
            .field("expected_consensus_old_state", &"[redacted]")
            .field("owner_requirement_count", &self.owner_requirements.len())
            .field("descriptor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationJournalStateV1 {
    pub version: u16,
    pub sequence: u64,
    pub phase: PrivateOramMutationJournalPhaseV1,
    pub previous_record_digest: Option<String>,
    pub owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    pub point_stage: Option<PrivateOramMutationPointStageEvidenceV1>,
    pub consensus: Option<PrivateOramMutationConsensusEvidenceV1>,
    pub remote_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    pub local_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    pub record_digest: String,
}

impl Debug for PrivateOramMutationJournalStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalStateV1")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("phase", &self.phase)
            .field("previous_record_digest", &"[redacted]")
            .field("owner_prepare_count", &self.owner_prepares.len())
            .field("has_point_stage", &self.point_stage.is_some())
            .field("has_consensus_evidence", &self.consensus.is_some())
            .field(
                "remote_finalization_count",
                &self.remote_finalizations.len(),
            )
            .field("local_finalization_count", &self.local_finalizations.len())
            .field("record_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationJournalSnapshotV1 {
    pub descriptor: PrivateOramMutationJournalDescriptorV1,
    pub state: PrivateOramMutationJournalStateV1,
}

impl Debug for PrivateOramMutationJournalSnapshotV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalSnapshotV1")
            .field("descriptor", &self.descriptor)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramMutationReconcileDispositionV1 {
    /// Observation only. Owner or point abort requires a later consensus abort decision.
    ObservedOldNeedsAbortDecision,
    /// Consensus has fenced mutation apply while the collection remains exact old.
    ExactOldAbortDecided,
    ExactNew,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramValidatedMutationReconcileContextV1 {
    snapshot: PrivateOramMutationJournalSnapshotV1,
    active_lease: PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
}

impl Debug for PrivateOramValidatedMutationReconcileContextV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedMutationReconcileContextV1")
            .field("snapshot", &"[redacted]")
            .field("active_lease", &self.active_lease)
            .field("disposition", &self.disposition)
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-B3-A context is consumed by the dormant D3-B3 coordinator"
)]
impl PrivateOramValidatedMutationReconcileContextV1 {
    pub(super) fn snapshot(&self) -> &PrivateOramMutationJournalSnapshotV1 {
        &self.snapshot
    }

    pub(super) fn active_lease(&self) -> &PrivateOramMutationLease {
        &self.active_lease
    }

    pub(super) const fn disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        self.disposition
    }

    fn validated_decision_evidence_v2(
        &self,
    ) -> Result<RawPrivateOramMutationDecisionEvidenceV2, PrivateOramMutationJournalError> {
        build_validated_mutation_decision_evidence_v2(
            &self.snapshot.descriptor,
            &self.active_lease,
            self.disposition,
        )
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedMutationDecisionV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    expected_predecessor_record_digest: String,
}

impl Debug for PrivateOramValidatedMutationDecisionV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedMutationDecisionV2")
            .field("kind", &self.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("expected_predecessor_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
impl PrivateOramValidatedMutationDecisionV2 {
    pub(super) const fn kind(&self) -> ValidatedPrivateOramMutationDecisionKindV2 {
        self.evidence.kind()
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedDecisionDurableV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    decision_record_digest: String,
}

/// Structurally decoded endpoint evidence without logical peer authentication.
///
/// Production recovery must upgrade this claim with an owner-bound signature
/// before any journal transition can consume it.
pub(super) struct PrivateOramAuthenticatedOwnerTerminalClaimV2 {
    kind: PrivateOramMutationOwnerTerminalKindV2,
    evidence: PrivateOramMutationOwnerTerminalEvidenceV2,
}

impl Debug for PrivateOramAuthenticatedOwnerTerminalClaimV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAuthenticatedOwnerTerminalClaimV2")
            .field("owner_peer_id", &self.evidence.owner_peer_id)
            .field("kind", &self.kind)
            .field("evidence", &"[redacted]")
            .finish()
    }
}

impl PrivateOramAuthenticatedOwnerTerminalClaimV2 {
    pub(super) fn try_from_authenticated_response(
        bound: &PrivateOramAuthenticatedOwnerRecoveryResponse,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let terminal = bound.verified().terminal();
        if terminal.owner_peer_id != bound.peer_id() {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let kind = match terminal.terminal_kind {
            qdrant_sec::PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            qdrant_sec::PrivateOramPeerRecoveryTerminalKindV2::AbortedOld => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        let indexes = terminal
            .indexes
            .iter()
            .map(|index| PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index.prepared_journal_digest.clone(),
                terminal_state_digest: index.terminal_state_digest.clone(),
            })
            .collect::<Vec<_>>();
        Ok(Self {
            kind,
            evidence: PrivateOramMutationOwnerTerminalEvidenceV2 {
                owner_peer_id: terminal.owner_peer_id,
                journal_descriptor_digest: terminal.journal_descriptor_digest.clone(),
                prepared_state_digest: terminal.prepared_state_digest.clone(),
                terminal_record_digest: terminal.terminal_record_digest.clone(),
                parent_descriptor_digest: terminal.parent_descriptor_digest.clone(),
                decision_authority_record_digest: terminal.decision_authority_record_digest.clone(),
                reconciliation_authority_digest: terminal.reconciliation_authority_digest.clone(),
                indexes,
                terminal_evidence_digest: terminal.terminal_evidence_digest.clone(),
            },
        })
    }

    #[cfg(test)]
    fn from_evidence_for_test(
        kind: PrivateOramMutationOwnerTerminalKindV2,
        evidence: PrivateOramMutationOwnerTerminalEvidenceV2,
    ) -> Self {
        Self { kind, evidence }
    }
}

impl Debug for PrivateOramValidatedDecisionDurableV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedDecisionDurableV2")
            .field("kind", &self.evidence.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("decision_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedRemotesTerminalV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    remotes_terminal_record_digest: String,
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedLocalTerminalV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    local_terminal_record_digest: String,
}

impl Debug for PrivateOramValidatedLocalTerminalV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedLocalTerminalV2")
            .field("kind", &self.evidence.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("local_terminal_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramValidatedRemotesTerminalV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedRemotesTerminalV2")
            .field("kind", &self.evidence.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("remotes_terminal_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

fn build_validated_mutation_decision_evidence_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
) -> Result<RawPrivateOramMutationDecisionEvidenceV2, PrivateOramMutationJournalError> {
    let evidence = match disposition {
        PrivateOramMutationReconcileDispositionV1::ExactNew => {
            let committed_state = expected_consensus_new_state(descriptor)?;
            RawPrivateOramMutationDecisionEvidenceV2::ExactNew {
                consensus: derive_consensus_evidence(descriptor, active_lease, &committed_state)?,
                committed_lease: Box::new(active_lease.clone()),
            }
        }
        PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
            let old = &descriptor.expected_consensus_old_state;
            RawPrivateOramMutationDecisionEvidenceV2::ExactOldAbort {
                old_consensus_record_digest: canonical_private_oram_consensus_state_record_digest(
                    old,
                )
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
                old_consensus_state_sequence: old.state_sequence,
                old_consensus_signed_state_digest: old.signed_state_digest.clone(),
                abort_decided_lease: Box::new(active_lease.clone()),
            }
        }
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    };
    Ok(evidence)
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrivateOramValidatedOwnerRecoveryIndexV1 {
    requirement: PrivateOramMutationOwnerRequirementV1,
    prepared: PrivateOramMutationOwnerPrepareEvidenceV1,
}

impl Debug for PrivateOramValidatedOwnerRecoveryIndexV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerRecoveryIndexV1")
            .field("peer_id", &self.requirement.peer_id)
            .field("kind", &self.requirement.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.requirement.old_epoch)
            .field("new_epoch", &self.requirement.new_epoch)
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-B3 restart owner authority is consumed by the dormant owner RPC bridge"
)]
impl PrivateOramValidatedOwnerRecoveryIndexV1 {
    pub(super) fn requirement(&self) -> &PrivateOramMutationOwnerRequirementV1 {
        &self.requirement
    }

    pub(super) fn prepared(&self) -> &PrivateOramMutationOwnerPrepareEvidenceV1 {
        &self.prepared
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrivateOramValidatedOwnerRecoveryAuthorityV1 {
    owner_peer_id: PeerId,
    disposition: PrivateOramMutationReconcileDispositionV1,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    parent_owners_prepared_record_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
    indexes: Vec<PrivateOramValidatedOwnerRecoveryIndexV1>,
}

impl Debug for PrivateOramValidatedOwnerRecoveryAuthorityV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerRecoveryAuthorityV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("disposition", &self.disposition)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("parent_owners_prepared_record_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-B3 restart owner authority is consumed by the dormant owner RPC bridge"
)]
impl PrivateOramValidatedOwnerRecoveryAuthorityV1 {
    pub(super) const fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub(super) const fn disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        self.disposition
    }

    pub(super) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(super) fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub(super) fn parent_owners_prepared_record_digest(&self) -> &str {
        &self.parent_owners_prepared_record_digest
    }

    pub(super) fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub(super) fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub(super) fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }

    pub(super) fn indexes(&self) -> &[PrivateOramValidatedOwnerRecoveryIndexV1] {
        &self.indexes
    }

    pub(super) fn pair_recovery_projection(
        &self,
    ) -> Result<PrivateOramOwnerRecoveryProjectionV1, PrivateOramMutationJournalError> {
        if self.indexes.len() != 2
            || self.indexes[0].requirement.kind != PrivateOramIndexKindV2::Hnsw
            || self.indexes[1].requirement.kind != PrivateOramIndexKindV2::Result
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let indexes = self
            .indexes
            .iter()
            .map(|index| {
                let requirement = &index.requirement;
                let prepared = &index.prepared;
                if requirement.peer_id != self.owner_peer_id
                    || prepared.peer_id != self.owner_peer_id
                    || requirement.kind != prepared.kind
                    || requirement.index_name != prepared.index_name
                {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
                PrivateOramOwnerRecoveryIndexProjectionV1::try_from_input(
                    PrivateOramOwnerRecoveryIndexProjectionInputV1 {
                        kind: requirement.kind,
                        index_name: &requirement.index_name,
                        old_epoch: requirement.old_epoch,
                        new_epoch: requirement.new_epoch,
                        old_root_hash: &requirement.old_root_hash,
                        new_root_hash: &requirement.new_root_hash,
                        writeback_digest: &requirement.writeback_digest,
                        prepared_journal_digest: &prepared.prepared_journal_digest,
                    },
                )
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        PrivateOramOwnerRecoveryProjectionV1::try_new(
            self.owner_peer_id,
            &self.parent_descriptor_digest,
            &self.parent_lease_acquired_record_digest,
            &self.mutation_bundle,
            indexes,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
    }

    pub(super) fn classify_pair_recovery_stores_v1(
        &self,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> CollectionResult<PrivateOramOwnerRecoveryStoreDispositionV1> {
        let projection = self.pair_recovery_projection().map_err(|_| {
            CollectionError::bad_request("private ORAM owner recovery authority is invalid")
        })?;
        classify_private_oram_owner_recovery_store_pair_v1(&projection, resources)
    }
}

/// Parent-tip authority that cannot outlive the held mutation-journal lock.
///
/// The consensus state and lease are an atomically captured, monotonic reconciliation snapshot;
/// this value deliberately does not retain the consensus read guard across filesystem work.
struct PrivateOramLiveOwnerRecoveryAuthorityV1<'lock, ParentLock = PrivateOramMutationJournalLock> {
    authority: PrivateOramValidatedOwnerRecoveryAuthorityV1,
    parent_lock: &'lock ParentLock,
    parent_bridge: &'lock PrivateOramOwnerRecoveryParentBridgeV1,
    parent_verifier: &'lock PrivateOramOwnerRecoveryParentVerifierV1,
}

#[allow(
    dead_code,
    reason = "D3-C consumes validated owner terminal evidence after paired recovery"
)]
pub(super) enum PrivateOramValidatedOwnerRecoveryOutcomeV1 {
    ObservedOld,
    Finalized {
        terminal: PrivateOramOwnerRecoveryTerminalEvidenceV1,
        owner_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    },
    AbortedOld {
        terminal: PrivateOramOwnerRecoveryTerminalEvidenceV1,
    },
}

impl Debug for PrivateOramValidatedOwnerRecoveryOutcomeV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservedOld => f.write_str("ObservedOld"),
            Self::Finalized {
                owner_finalizations,
                ..
            } => f
                .debug_struct("Finalized")
                .field("owner_finalization_count", &owner_finalizations.len())
                .field("terminal", &"[redacted]")
                .finish(),
            Self::AbortedOld { .. } => f.write_str("AbortedOld([redacted])"),
        }
    }
}

#[allow(
    dead_code,
    reason = "D3-C consumes validated owner terminal evidence after paired recovery"
)]
impl PrivateOramValidatedOwnerRecoveryOutcomeV1 {
    pub(super) fn owner_finalizations(
        &self,
    ) -> Option<&[PrivateOramMutationOwnerFinalizeEvidenceV1]> {
        match self {
            Self::Finalized {
                owner_finalizations,
                ..
            } => Some(owner_finalizations),
            Self::ObservedOld | Self::AbortedOld { .. } => None,
        }
    }

    pub(super) fn terminal(&self) -> Option<&PrivateOramOwnerRecoveryTerminalEvidenceV1> {
        match self {
            Self::ObservedOld => None,
            Self::Finalized { terminal, .. } | Self::AbortedOld { terminal } => Some(terminal),
        }
    }
}

impl<ParentLock> Debug for PrivateOramLiveOwnerRecoveryAuthorityV1<'_, ParentLock> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramLiveOwnerRecoveryAuthorityV1")
            .field("authority", &self.authority)
            .field("parent_lock", &"[held]")
            .finish()
    }
}

impl<'lock, ParentLock> PrivateOramLiveOwnerRecoveryAuthorityV1<'lock, ParentLock> {
    fn new(
        authority: PrivateOramValidatedOwnerRecoveryAuthorityV1,
        parent_lock: &'lock ParentLock,
        parent_bridge: &'lock PrivateOramOwnerRecoveryParentBridgeV1,
        parent_verifier: &'lock PrivateOramOwnerRecoveryParentVerifierV1,
    ) -> Self {
        Self {
            authority,
            parent_lock,
            parent_bridge,
            parent_verifier,
        }
    }
}

#[allow(
    dead_code,
    reason = "D3-B3 restart owner authority is consumed by the dormant mutating recovery bridge"
)]
impl<ParentLock> PrivateOramLiveOwnerRecoveryAuthorityV1<'_, ParentLock> {
    pub(super) const fn owner_peer_id(&self) -> PeerId {
        self.authority.owner_peer_id()
    }

    pub(super) const fn disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        self.authority.disposition()
    }

    pub(super) fn parent_descriptor_digest(&self) -> &str {
        self.authority.parent_descriptor_digest()
    }

    pub(super) fn parent_lease_acquired_record_digest(&self) -> &str {
        self.authority.parent_lease_acquired_record_digest()
    }

    pub(super) fn parent_owners_prepared_record_digest(&self) -> &str {
        self.authority.parent_owners_prepared_record_digest()
    }

    pub(super) fn consensus_authority_record_digest(&self) -> &str {
        self.authority.consensus_authority_record_digest()
    }

    pub(super) fn reconciliation_authority_digest(&self) -> &str {
        self.authority.reconciliation_authority_digest()
    }

    pub(super) fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        self.authority.mutation_bundle()
    }

    fn recover_pair_v1(
        &self,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> CollectionResult<PrivateOramValidatedOwnerRecoveryOutcomeV1> {
        match self.recover_pair_then_v1(resources, Ok::<_, Infallible>)? {
            Ok(outcome) => Ok(outcome),
            Err(never) => match never {},
        }
    }

    fn recover_pair_then_v1<R, E>(
        &self,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
        continuation: impl FnOnce(PrivateOramValidatedOwnerRecoveryOutcomeV1) -> Result<R, E>,
    ) -> CollectionResult<Result<R, E>> {
        let input = PrivateOramOwnerRecoveryParentInputV1 {
            projection: self.authority.pair_recovery_projection().map_err(|_| {
                CollectionError::bad_request("private ORAM owner recovery authority is invalid")
            })?,
            disposition: match self.authority.disposition() {
                PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => {
                    PrivateOramOwnerRecoveryParentDispositionV1::ObservedOldNeedsAbortDecision
                }
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactOldAbortDecided
                }
                PrivateOramMutationReconcileDispositionV1::ExactNew => {
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactNew
                }
            },
            authenticated_owner_peer_id: self.authority.owner_peer_id(),
            parent_descriptor_digest: self.authority.parent_descriptor_digest().to_string(),
            parent_owners_prepared_record_digest: self
                .authority
                .parent_owners_prepared_record_digest()
                .to_string(),
            consensus_authority_record_digest: self
                .authority
                .consensus_authority_record_digest()
                .to_string(),
            reconciliation_authority_digest: self
                .authority
                .reconciliation_authority_digest()
                .to_string(),
        };
        // SAFETY: this authority owns the matching private bridge endpoints, `parent_lock` is the
        // pinned EX lock borrowed by `with_live_owner_recovery_authority_v1`, and `input` was
        // rebuilt from typed consensus/lease authority under that same lock.
        unsafe {
            self.parent_bridge
                .with_live_parent_v1(self.parent_lock, input, |parent| {
                    recover_private_oram_owner_store_pair_then_v1(
                        self.parent_verifier,
                        parent,
                        resources,
                        |outcome| {
                            let validated = self.bind_pair_outcome_v1(outcome)?;
                            Ok(continuation(validated))
                        },
                    )
                })
        }
    }

    fn bind_pair_outcome_v1(
        &self,
        outcome: PrivateOramOwnerRecoveryPairOutcomeV1,
    ) -> CollectionResult<PrivateOramValidatedOwnerRecoveryOutcomeV1> {
        match (self.authority.disposition(), outcome) {
            (
                PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision,
                PrivateOramOwnerRecoveryPairOutcomeV1::ObservedOld,
            ) => Ok(PrivateOramValidatedOwnerRecoveryOutcomeV1::ObservedOld),
            (
                PrivateOramMutationReconcileDispositionV1::ExactNew,
                PrivateOramOwnerRecoveryPairOutcomeV1::Finalized(terminal),
            ) => {
                self.validate_terminal_evidence_v1(&terminal)?;
                let owner_finalizations = terminal
                    .indexes()
                    .iter()
                    .map(|index| PrivateOramMutationOwnerFinalizeEvidenceV1 {
                        peer_id: terminal.owner_peer_id(),
                        kind: index.kind(),
                        index_name: index.index_name().to_string(),
                        prepared_journal_digest: index.prepared_journal_digest().to_string(),
                        finalized_state_digest: index.terminal_state_digest().to_string(),
                    })
                    .collect();
                Ok(PrivateOramValidatedOwnerRecoveryOutcomeV1::Finalized {
                    terminal,
                    owner_finalizations,
                })
            }
            (
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
                PrivateOramOwnerRecoveryPairOutcomeV1::AbortedOld(terminal),
            ) => {
                self.validate_terminal_evidence_v1(&terminal)?;
                Ok(PrivateOramValidatedOwnerRecoveryOutcomeV1::AbortedOld { terminal })
            }
            _ => Err(CollectionError::bad_request(
                "private ORAM owner recovery outcome is invalid",
            )),
        }
    }

    fn validate_terminal_evidence_v1(
        &self,
        terminal: &PrivateOramOwnerRecoveryTerminalEvidenceV1,
    ) -> CollectionResult<()> {
        if terminal.owner_peer_id() != self.authority.owner_peer_id()
            || terminal.parent_descriptor_digest() != self.authority.parent_descriptor_digest()
            || terminal.consensus_authority_record_digest()
                != self.authority.consensus_authority_record_digest()
            || terminal.reconciliation_authority_digest()
                != self.authority.reconciliation_authority_digest()
            || terminal.indexes().len() != self.authority.indexes().len()
        {
            return Err(CollectionError::bad_request(
                "private ORAM owner recovery outcome is invalid",
            ));
        }
        for (terminal_index, expected) in terminal.indexes().iter().zip(self.authority.indexes()) {
            if terminal_index.kind() != expected.requirement().kind
                || terminal_index.index_name() != expected.requirement().index_name
                || terminal_index.prepared_journal_digest()
                    != expected.prepared().prepared_journal_digest
            {
                return Err(CollectionError::bad_request(
                    "private ORAM owner recovery outcome is invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateOramValidatedPointStageParentPhaseV1 {
    OwnersPrepared,
    PointStageDurable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramValidatedPointStageParentV1 {
    descriptor: PrivateOramMutationJournalDescriptorV1,
    owners_prepared_record_digest: String,
    phase: PrivateOramValidatedPointStageParentPhaseV1,
    expected_child_descriptor_digest: Option<String>,
}

impl Debug for PrivateOramValidatedPointStageParentV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedPointStageParentV1")
            .field("descriptor", &"[redacted]")
            .field("owners_prepared_record_digest", &"[redacted]")
            .field("phase", &self.phase)
            .field(
                "has_expected_child_descriptor_digest",
                &self.expected_child_descriptor_digest.is_some(),
            )
            .finish()
    }
}

impl PrivateOramValidatedPointStageParentV1 {
    pub(super) fn descriptor(&self) -> &PrivateOramMutationJournalDescriptorV1 {
        &self.descriptor
    }

    pub(super) fn owners_prepared_record_digest(&self) -> &str {
        &self.owners_prepared_record_digest
    }

    pub(super) fn permits_new_child_install(&self) -> bool {
        self.phase == PrivateOramValidatedPointStageParentPhaseV1::OwnersPrepared
    }

    pub(super) fn expected_child_descriptor_digest(&self) -> Option<&str> {
        self.expected_child_descriptor_digest.as_deref()
    }
}

#[derive(Clone)]
pub struct PrivateOramMutationJournal {
    root: PathBuf,
    expected_owner_signing_key_id: String,
    owner_public_key: Vec<u8>,
    owner_recovery_parent_bridge: PrivateOramOwnerRecoveryParentBridgeV1,
    owner_recovery_parent_verifier: PrivateOramOwnerRecoveryParentVerifierV1,
}

/// Restart material loaded only from the canonical V2 parent journal.
///
/// This value is inert. A recovery transition must pass it back to the same journal, which
/// reopens the parent under its exclusive lock and compares both signed bundles exactly.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationRecoveryMaterialV2 {
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
}

/// Canonical V2 consensus admission derived from a server-validated owner prepare.
///
/// Fields are private so callers cannot splice a lease from a different mutation or state.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationAdmissionPlanV2 {
    lease: PrivateOramMutationLease,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
    expected_old_state: PrivateOramConsensusCollectionStateV2,
    expected_new_state: PrivateOramConsensusCollectionStateV2,
    mutation_digest: String,
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationReservedOwnerTargetV2 {
    version: u16,
    owner_index: u32,
    owner_peer_id: PeerId,
    owner_signer: PrivateOramPeerRecoveryPublicKeyV1,
    owner_request_digest: String,
    intent_key: String,
    package_sha256: String,
    package_len: u64,
    target_digest: String,
}

impl Debug for PrivateOramMutationReservedOwnerTargetV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationReservedOwnerTargetV2")
            .field("version", &self.version)
            .field("owner_index", &self.owner_index)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("package_len", &self.package_len)
            .field("owner_signer", &"[redacted]")
            .field("owner_request_digest", &"[redacted]")
            .field("intent_key", &"[redacted]")
            .field("package_sha256", &"[redacted]")
            .field("target_digest", &"[redacted]")
            .finish()
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationAppendAuthorityContextV2 {
    expected_aggregate_digest: String,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    attempt_sequence: u64,
}

impl Debug for PrivateOramMutationAppendAuthorityContextV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendAuthorityContextV2")
            .field("attempt_sequence", &self.attempt_sequence)
            .field("expected_aggregate_digest", &"[redacted]")
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("collection_lifetime_id_digest", &"[redacted]")
            .field("collection_incarnation_digest", &"[redacted]")
            .field("activation_anchor_digest", &"[redacted]")
            .finish()
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramMutationAppendRecoveryPolicyV2 {
    RejectOnOrphanV1,
}

/// Consensus-owned obligation committed before the first owner pre-stage write.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationAppendReservationV2 {
    version: u16,
    protocol_capability_digest: String,
    attempt_id: String,
    attempt_sequence: u64,
    expected_aggregate_digest: String,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    controller_id: String,
    controller_peer_id: PeerId,
    controller_term: u64,
    attempt_lease_id: String,
    attempt_lease_expires_at_unix: u64,
    absolute_resolution_deadline_unix: u64,
    recovery_policy: PrivateOramMutationAppendRecoveryPolicyV2,
    collection_id: String,
    mutation_id: String,
    mutation_digest: String,
    transition_digest: String,
    preparing_lease: PrivateOramMutationLease,
    preparing_lease_state_digest: String,
    immutable_plan_digest: String,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    owner_roster_digest: String,
    owner_targets: Vec<PrivateOramMutationReservedOwnerTargetV2>,
    reserved_rejection_bytes: u64,
    reserved_cleanup_bytes: u64,
    reservation_digest: String,
}

impl Debug for PrivateOramMutationAppendReservationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendReservationV2")
            .field("version", &self.version)
            .field("attempt_sequence", &self.attempt_sequence)
            .field("controller_peer_id", &self.controller_peer_id)
            .field("controller_term", &self.controller_term)
            .field(
                "attempt_lease_expires_at_unix",
                &self.attempt_lease_expires_at_unix,
            )
            .field(
                "absolute_resolution_deadline_unix",
                &self.absolute_resolution_deadline_unix,
            )
            .field("recovery_policy", &self.recovery_policy)
            .field("owner_count", &self.owner_targets.len())
            .field("reserved_rejection_bytes", &self.reserved_rejection_bytes)
            .field("reserved_cleanup_bytes", &self.reserved_cleanup_bytes)
            .field("protocol_capability_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("controller_id", &"[redacted]")
            .field("attempt_lease_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("reservation_digest", &"[redacted]")
            .finish()
    }
}

/// Deterministic parent namespace calculated before Raft admission.
///
/// This value can bind inert owner pre-staging only. It is deliberately distinct from
/// `PrivateOramMutationParentLeaseAcquiredV2`, which is returned only after the parent journal is
/// durably published following exact admission.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationPlannedParentV2 {
    descriptor_digest: String,
    lease_acquired_record_digest: String,
    preparing_lease: PrivateOramMutationLease,
    owner_requirements: Vec<PrivateOramMutationOwnerRequirementV1>,
}

/// One exact owner receipt paired with its reusable, activation-pinned signature.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerPrestageEvidenceV2 {
    receipt: PrivateOramOwnerPrestageReceiptV2,
    attestation: PrivateOramOwnerPrestageAttestationV2,
}

/// Opaque proof that every owner in the exact planned roster durably installed the mutation.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationAllOwnersPrestagedV2 {
    version: u16,
    expected_aggregate_digest: String,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    collection_id: String,
    mutation_id: String,
    mutation_digest: String,
    transition_digest: String,
    lease_generation: u64,
    writer_fence: u64,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    owner_roster_digest: String,
    owner_evidence: Vec<PrivateOramMutationOwnerPrestageEvidenceV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coordinator_recovery_package_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_old_state: Option<PrivateOramConsensusCollectionStateV2>,
    manifest_digest: String,
}

/// Durable sequence-1 parent authority returned only after the canonical V2 journal exists.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationParentLeaseAcquiredV2 {
    descriptor_digest: String,
    lease_acquired_record_digest: String,
    preparing_lease: PrivateOramMutationLease,
    owner_requirements: Vec<PrivateOramMutationOwnerRequirementV1>,
}

/// One owner's durable Prepared journal projected into the exact parent namespace.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationPreparedOwnerProjectionV2 {
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    owner_peer_id: PeerId,
    owner_journal_descriptor_digest: String,
    indexes: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
}

/// Durable sequence-2 parent authority. It can mint only the configured point-stage child.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationOwnersPreparedV2 {
    descriptor_digest: String,
    owners_prepared_record_digest: String,
}

/// Durable sequence-3 parent authority with an optional live visible-point child token.
#[doc(hidden)]
pub struct PrivateOramMutationPointStageDurableV2 {
    descriptor_digest: String,
    point_stage_record_digest: String,
    durable_point_stage: Option<PrivateOramDurablePointStageTokenV1>,
}

struct PrivateOramMutationResumeAuthorityV2 {
    reconcile: PrivateOramMutationReconcileSnapshotV1,
    applied_index: u64,
}

impl PrivateOramMutationResumeAuthorityV2 {
    fn from_linearizable(authority: LinearizablePrivateOramMutationReconcileSnapshotV2) -> Self {
        let applied_index = authority.applied_index();
        Self {
            reconcile: authority.into_snapshot(),
            applied_index,
        }
    }
}

/// Opaque next action for the coordinator-owned V2 recovery state machine.
#[doc(hidden)]
pub enum PrivateOramMutationResumeV2 {
    NeedParentProgress(PrivateOramMutationNeedParentProgressV2),
    NeedDecision(PrivateOramMutationNeedDecisionV2),
    NeedRemoteTerminals(PrivateOramMutationNeedRemoteTerminalsV2),
    NeedLocalTerminal(PrivateOramMutationNeedLocalTerminalV2),
    NeedPointResolution(PrivateOramMutationNeedPointResolutionV2),
    Complete(PrivateOramMutationTerminalCompleteV2),
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedParentProgressV2 {
    proposal: PrivateOramMutationParentProgressProposalV2,
}

impl PrivateOramMutationNeedParentProgressV2 {
    pub(crate) fn into_proposal(self) -> PrivateOramMutationParentProgressProposalV2 {
        self.proposal
    }
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedDecisionV2 {
    authority: PrivateOramMutationResumeAuthorityV2,
    decision: PrivateOramValidatedMutationDecisionV2,
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedRemoteTerminalsV2 {
    decision: PrivateOramValidatedDecisionDurableV2,
    requests: Vec<PrivateOramPeerRecoveryRequestV2>,
}

impl PrivateOramMutationNeedRemoteTerminalsV2 {
    pub fn requests(&self) -> &[PrivateOramPeerRecoveryRequestV2] {
        &self.requests
    }
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedLocalTerminalV2 {
    authority: PrivateOramMutationResumeAuthorityV2,
    remotes: PrivateOramValidatedRemotesTerminalV2,
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedPointResolutionV2 {
    authority: PrivateOramMutationResumeAuthorityV2,
    local: PrivateOramValidatedLocalTerminalV2,
}

#[doc(hidden)]
pub struct PrivateOramMutationTerminalCompleteV2 {
    authority: PrivateOramMutationResumeAuthorityV2,
}

/// Opaque next action for the terminal cleanup chain.
#[doc(hidden)]
pub enum PrivateOramMutationCleanupV2 {
    NeedCleanupWitness(PrivateOramMutationNeedCleanupWitnessV2),
    NeedLocalCleanup(PrivateOramMutationNeedLocalCleanupV2),
    NeedClear(PrivateOramMutationNeedClearV2),
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedCleanupWitnessV2 {
    proposal: PrivateOramMutationCleanupWitnessProposalV2,
}

#[doc(hidden)]
pub struct PrivateOramMutationCleanupWitnessProposalV2 {
    key: PrivateOramMutationKey,
    expectation: PrivateOramMutationCleanupExpectationV2,
}

impl PrivateOramMutationCleanupWitnessProposalV2 {
    pub(crate) fn key(&self) -> &PrivateOramMutationKey {
        &self.key
    }

    pub(crate) fn expectation(&self) -> &PrivateOramMutationCleanupExpectationV2 {
        &self.expectation
    }
}

impl PrivateOramMutationNeedCleanupWitnessV2 {
    pub(crate) fn into_proposal(self) -> PrivateOramMutationCleanupWitnessProposalV2 {
        self.proposal
    }
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedLocalCleanupV2 {
    collection_id: String,
    mutation_id: String,
    owner_peer_id: PeerId,
    descriptor_digest: String,
    terminal_record_digest: String,
    generation: u64,
    witness_digest: String,
    cleanup_evidence_digest: String,
}

impl PrivateOramMutationNeedLocalCleanupV2 {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    pub fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub fn cleanup_claim_binding(&self) -> (&str, &str, &str, &str) {
        (
            &self.descriptor_digest,
            &self.terminal_record_digest,
            &self.witness_digest,
            &self.cleanup_evidence_digest,
        )
    }
}

#[doc(hidden)]
pub struct PrivateOramMutationNeedClearV2 {
    key: PrivateOramMutationKey,
    generation: u64,
    expected_clear_attempt_id_digest: String,
}

#[doc(hidden)]
pub struct PrivateOramMutationClearPendingProposalV2 {
    key: PrivateOramMutationKey,
    generation: u64,
    witness_digest: String,
    clear_attempt_id_digest: String,
}

impl PrivateOramMutationClearPendingProposalV2 {
    pub(crate) fn into_parts(self) -> (PrivateOramMutationKey, u64, String, String) {
        (
            self.key,
            self.generation,
            self.witness_digest,
            self.clear_attempt_id_digest,
        )
    }
}

impl PrivateOramMutationNeedClearV2 {
    pub(crate) fn into_parts(self) -> (PrivateOramMutationKey, u64, String) {
        (
            self.key,
            self.generation,
            self.expected_clear_attempt_id_digest,
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationLocalCleanupCompleteV2 {
    version: u16,
    generation: u64,
    descriptor_digest: String,
    terminal_record_digest: String,
    witness_digest: String,
    cleanup_evidence_digest: String,
    clear_attempt_id_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationTerminalArchiveV2 {
    version: u16,
    generation: u64,
    descriptor_digest: String,
    terminal_record_digest: String,
    witness_digest: String,
    cleanup_evidence_digest: String,
    clear_attempt_id_digest: String,
    clear_receipt_digest: String,
    tombstone_digest: String,
    archive_digest: String,
}

impl Debug for PrivateOramMutationCleanupV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NeedCleanupWitness(_) => "NeedCleanupWitness([redacted])",
            Self::NeedLocalCleanup(_) => "NeedLocalCleanup([redacted])",
            Self::NeedClear(_) => "NeedClear([redacted])",
        })
    }
}

impl Debug for PrivateOramMutationResumeV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NeedParentProgress(_) => "NeedParentProgress([redacted])",
            Self::NeedDecision(_) => "NeedDecision([redacted])",
            Self::NeedRemoteTerminals(_) => "NeedRemoteTerminals([redacted])",
            Self::NeedLocalTerminal(_) => "NeedLocalTerminal([redacted])",
            Self::NeedPointResolution(_) => "NeedPointResolution([redacted])",
            Self::Complete(_) => "Complete([redacted])",
        })
    }
}

impl Debug for PrivateOramMutationParentLeaseAcquiredV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationParentLeaseAcquiredV2")
            .field("descriptor_digest", &"[redacted]")
            .field("lease_acquired_record_digest", &"[redacted]")
            .field("preparing_lease", &self.preparing_lease)
            .field("owner_requirement_count", &self.owner_requirements.len())
            .finish()
    }
}

impl Debug for PrivateOramMutationPlannedParentV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationPlannedParentV2")
            .field("descriptor_digest", &"[redacted]")
            .field("lease_acquired_record_digest", &"[redacted]")
            .field("preparing_lease", &self.preparing_lease)
            .field("owner_requirement_count", &self.owner_requirements.len())
            .finish()
    }
}

impl Debug for PrivateOramMutationOwnerPrestageEvidenceV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationOwnerPrestageEvidenceV2")
            .field("owner_peer_id", &self.receipt.owner_peer_id())
            .field("receipt", &"[redacted]")
            .field("attestation", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramMutationAllOwnersPrestagedV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAllOwnersPrestagedV2")
            .field("version", &self.version)
            .field("expected_aggregate_digest", &"[redacted]")
            .field("activation_authority", &self.activation_authority)
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("owner_count", &self.owner_evidence.len())
            .field("manifest_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PrivateOramMutationOwnerPrestageEvidenceV2 {
    pub fn from_signed_attestation(
        receipt: PrivateOramOwnerPrestageReceiptV2,
        attestation: PrivateOramOwnerPrestageAttestationV2,
        expected_signer: &PrivateOramPeerRecoveryPublicKeyV1,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        collection::validate_private_oram_owner_prestage_receipt_v2(&receipt)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("prestage_receipt"))?;
        let verified = validate_private_oram_owner_prestage_attestation_for_signer_v2(
            &attestation,
            expected_signer,
        )
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("prestage_attestation"))?;
        let statement = verified.statement();
        if statement.collection_id != receipt.collection_id()
            || statement.mutation_id != receipt.mutation_id()
            || statement.mutation_digest != receipt.mutation_digest()
            || statement.expected_aggregate_digest != receipt.expected_aggregate_digest()
            || statement.lease_generation != receipt.lease_generation()
            || statement.writer_fence != receipt.writer_fence()
            || statement.parent_descriptor_digest != receipt.parent_descriptor_digest()
            || statement.parent_lease_acquired_record_digest
                != receipt.parent_lease_acquired_record_digest()
            || statement.owner_roster_digest != receipt.owner_roster_digest()
            || statement.owner_peer_id != receipt.owner_peer_id()
            || statement.activation_registry_generation != receipt.activation_registry_generation()
            || statement.activation_manifest_digest != receipt.activation_manifest_digest()
            || statement.intent_key != receipt.intent_key()
            || statement.package_sha256 != receipt.package_sha256()
            || statement.receipt_digest != receipt.receipt_digest()
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "prestage_evidence",
            ));
        }
        Ok(Self {
            receipt,
            attestation,
        })
    }

    pub fn owner_peer_id(&self) -> PeerId {
        self.receipt.owner_peer_id()
    }

    pub fn receipt(&self) -> &PrivateOramOwnerPrestageReceiptV2 {
        &self.receipt
    }

    pub fn attestation(&self) -> &PrivateOramOwnerPrestageAttestationV2 {
        &self.attestation
    }
}

impl PrivateOramMutationPlannedParentV2 {
    pub fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub fn lease_acquired_record_digest(&self) -> &str {
        &self.lease_acquired_record_digest
    }

    pub fn preparing_lease(&self) -> &PrivateOramMutationLease {
        &self.preparing_lease
    }

    pub fn owner_peer_ids(&self) -> Vec<PeerId> {
        let mut peers = self
            .owner_requirements
            .iter()
            .map(|requirement| requirement.peer_id)
            .collect::<Vec<_>>();
        peers.dedup();
        peers
    }

    pub fn requirements_for_owner(
        &self,
        owner_peer_id: PeerId,
    ) -> Vec<PrivateOramMutationOwnerRequirementV1> {
        self.owner_requirements
            .iter()
            .filter(|requirement| requirement.peer_id == owner_peer_id)
            .cloned()
            .collect()
    }

    pub fn owner_prestage_plan(
        &self,
        owner_peer_id: PeerId,
    ) -> Result<PrivateOramOwnerPrestagePlanV2, PrivateOramMutationJournalError> {
        let requirements = self
            .requirements_for_owner(owner_peer_id)
            .into_iter()
            .map(|requirement| PrivateOramOwnerPrepareRequirementV2 {
                kind: requirement.kind,
                index_name: requirement.index_name,
                old_epoch: requirement.old_epoch,
                new_epoch: requirement.new_epoch,
                old_root_hash: requirement.old_root_hash,
                new_root_hash: requirement.new_root_hash,
                writeback_digest: requirement.writeback_digest,
            })
            .collect::<Vec<_>>();
        if requirements.is_empty() {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "owner_peer_id",
            ));
        }
        PrivateOramOwnerPrestagePlanV2::try_new(
            self.descriptor_digest.clone(),
            self.lease_acquired_record_digest.clone(),
            owner_peer_id,
            requirements,
        )
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_prestage_plan"))
    }
}

pub fn derive_private_oram_mutation_all_owners_prestaged_v2(
    planned: &PrivateOramMutationPlannedParentV2,
    admission: &PrivateOramMutationAdmissionPlanV2,
    expected_aggregate_digest: String,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    mut owner_evidence: Vec<PrivateOramMutationOwnerPrestageEvidenceV2>,
    coordinator_recovery_package_canonical_json: Vec<u8>,
) -> Result<PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationJournalError> {
    if !is_sha256_digest(&expected_aggregate_digest)
        || planned.preparing_lease != admission.lease
        || activation_authority.registry_generation() == 0
        || !is_sha256_digest(activation_authority.manifest_digest())
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "all_owners_prestaged",
        ));
    }
    owner_evidence.sort_by_key(PrivateOramMutationOwnerPrestageEvidenceV2::owner_peer_id);
    let owner_peer_ids = planned.owner_peer_ids();
    if owner_evidence.len() != owner_peer_ids.len()
        || owner_evidence
            .iter()
            .map(PrivateOramMutationOwnerPrestageEvidenceV2::owner_peer_id)
            .ne(owner_peer_ids.iter().copied())
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "owner_prestage_roster",
        ));
    }
    let owner_roster_digest = private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_prestage_roster"))?;
    let lease = admission.lease();
    for evidence in &owner_evidence {
        let receipt = evidence.receipt();
        let statement = &evidence.attestation().statement;
        if receipt.collection_id() != lease.collection_id
            || receipt.mutation_id() != lease.mutation_id
            || receipt.mutation_digest() != admission.mutation_digest
            || receipt.expected_aggregate_digest() != expected_aggregate_digest
            || receipt.lease_generation() != lease.generation
            || receipt.writer_fence() != lease.writer_fence
            || receipt.parent_descriptor_digest() != planned.descriptor_digest
            || receipt.parent_lease_acquired_record_digest() != planned.lease_acquired_record_digest
            || receipt.owner_roster_digest() != owner_roster_digest
            || receipt.activation_registry_generation()
                != activation_authority.registry_generation()
            || receipt.activation_manifest_digest() != activation_authority.manifest_digest()
            || statement.transition_digest != lease.transition_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "owner_prestage_evidence",
            ));
        }
    }
    let mut manifest = PrivateOramMutationAllOwnersPrestagedV2 {
        version: ADMISSION_RECOVERY_MANIFEST_VERSION_V2,
        expected_aggregate_digest,
        activation_authority,
        collection_id: lease.collection_id.clone(),
        mutation_id: lease.mutation_id.clone(),
        mutation_digest: admission.mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        lease_generation: lease.generation,
        writer_fence: lease.writer_fence,
        parent_descriptor_digest: planned.descriptor_digest.clone(),
        parent_lease_acquired_record_digest: planned.lease_acquired_record_digest.clone(),
        owner_roster_digest,
        owner_evidence,
        coordinator_recovery_package_b64: Some(
            BASE64URL_NOPAD.encode(&coordinator_recovery_package_canonical_json),
        ),
        expected_old_state: Some(admission.expected_old_state.clone()),
        manifest_digest: String::new(),
    };
    manifest.manifest_digest = admission_recovery_manifest_digest_v2(&manifest)?;
    validate_admission_recovery_manifest_v2(&manifest)?;
    Ok(manifest)
}

impl PrivateOramMutationAllOwnersPrestagedV2 {
    pub(crate) fn expected_aggregate_digest(&self) -> &str {
        &self.expected_aggregate_digest
    }

    pub(crate) fn activation_authority(&self) -> &PrivateOramActivationAuthorityLocatorV1 {
        &self.activation_authority
    }

    pub(crate) fn owner_evidence(&self) -> &[PrivateOramMutationOwnerPrestageEvidenceV2] {
        &self.owner_evidence
    }

    #[doc(hidden)]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub(crate) fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub(crate) fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    pub(crate) fn mutation_digest(&self) -> &str {
        &self.mutation_digest
    }

    pub(crate) const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    pub(crate) fn contains_owner_peer_id(&self, peer_id: PeerId) -> bool {
        self.owner_evidence
            .iter()
            .any(|evidence| evidence.owner_peer_id() == peer_id)
    }

    #[doc(hidden)]
    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    #[doc(hidden)]
    pub fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    #[doc(hidden)]
    pub fn owner_receipt(
        &self,
        owner_peer_id: PeerId,
    ) -> Option<&PrivateOramOwnerPrestageReceiptV2> {
        self.owner_evidence
            .iter()
            .find(|evidence| evidence.owner_peer_id() == owner_peer_id)
            .map(PrivateOramMutationOwnerPrestageEvidenceV2::receipt)
    }

    #[doc(hidden)]
    pub fn coordinator_recovery_envelope(
        &self,
    ) -> Result<
        (
            PrivateOramOwnerPrestagePackageV2,
            &PrivateOramConsensusCollectionStateV2,
        ),
        PrivateOramMutationJournalError,
    > {
        validate_admission_recovery_manifest_v2(self)?;
        let package = self
            .coordinator_recovery_package_b64
            .as_deref()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            .and_then(|encoded| {
                let bytes = BASE64URL_NOPAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
                decode_private_oram_owner_prestage_package_v2(&bytes)
                    .map_err(|_| PrivateOramMutationJournalError::Corrupt)
            })?;
        let expected_old_state = self
            .expected_old_state
            .as_ref()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        Ok((package, expected_old_state))
    }

    pub(crate) fn validate_admission_lease(
        &self,
        lease: &PrivateOramMutationLease,
    ) -> Result<(), PrivateOramMutationJournalError> {
        validate_admission_recovery_manifest_v2(self)?;
        if self.collection_id != lease.collection_id
            || self.mutation_id != lease.mutation_id
            || self.mutation_digest != lease.signed_mutation_digest
            || self.transition_digest != lease.transition_digest
            || self.lease_generation != lease.generation
            || self.writer_fence != lease.writer_fence
            || !self.contains_owner_peer_id(lease.owner_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(())
    }

    pub(crate) fn validate_admission_plan(
        &self,
        plan: &PrivateOramMutationAdmissionPlanV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let lease = plan.lease();
        validate_admission_recovery_manifest_v2(self)?;
        if self.collection_id != lease.collection_id
            || self.mutation_id != lease.mutation_id
            || self.mutation_digest != plan.mutation_digest
            || self.transition_digest != lease.transition_digest
            || self.lease_generation != lease.generation
            || self.writer_fence != lease.writer_fence
            || self.parent_descriptor_digest.is_empty()
            || self.parent_lease_acquired_record_digest.is_empty()
            || self.owner_roster_digest.is_empty()
            || self.owner_evidence.is_empty()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PrivateOramMutationAdmissionRecoveryManifestBodyV2<'a> {
    version: u16,
    expected_aggregate_digest: &'a str,
    activation_authority: &'a PrivateOramActivationAuthorityLocatorV1,
    collection_id: &'a str,
    mutation_id: &'a str,
    mutation_digest: &'a str,
    transition_digest: &'a str,
    lease_generation: u64,
    writer_fence: u64,
    parent_descriptor_digest: &'a str,
    parent_lease_acquired_record_digest: &'a str,
    owner_roster_digest: &'a str,
    owner_evidence: &'a [PrivateOramMutationOwnerPrestageEvidenceV2],
    #[serde(skip_serializing_if = "Option::is_none")]
    coordinator_recovery_package_b64: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_old_state: Option<&'a PrivateOramConsensusCollectionStateV2>,
}

fn admission_recovery_manifest_body_v2(
    manifest: &PrivateOramMutationAllOwnersPrestagedV2,
) -> PrivateOramMutationAdmissionRecoveryManifestBodyV2<'_> {
    PrivateOramMutationAdmissionRecoveryManifestBodyV2 {
        version: manifest.version,
        expected_aggregate_digest: &manifest.expected_aggregate_digest,
        activation_authority: &manifest.activation_authority,
        collection_id: &manifest.collection_id,
        mutation_id: &manifest.mutation_id,
        mutation_digest: &manifest.mutation_digest,
        transition_digest: &manifest.transition_digest,
        lease_generation: manifest.lease_generation,
        writer_fence: manifest.writer_fence,
        parent_descriptor_digest: &manifest.parent_descriptor_digest,
        parent_lease_acquired_record_digest: &manifest.parent_lease_acquired_record_digest,
        owner_roster_digest: &manifest.owner_roster_digest,
        owner_evidence: &manifest.owner_evidence,
        coordinator_recovery_package_b64: manifest.coordinator_recovery_package_b64.as_deref(),
        expected_old_state: manifest.expected_old_state.as_ref(),
    }
}

fn admission_recovery_manifest_digest_v2(
    manifest: &PrivateOramMutationAllOwnersPrestagedV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let body = serde_json::to_vec(&admission_recovery_manifest_body_v2(manifest))
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if body.is_empty() || body.len() > ADMISSION_RECOVERY_MANIFEST_MAX_CANONICAL_JSON_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_recovery_manifest",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_RECOVERY_MANIFEST_DIGEST_DOMAIN_V2);
    hasher.update(
        u64::try_from(body.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(body);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_admission_recovery_manifest_v2(
    manifest: &PrivateOramMutationAllOwnersPrestagedV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if !matches!(
        manifest.version,
        ADMISSION_RECOVERY_MANIFEST_VERSION_V1 | ADMISSION_RECOVERY_MANIFEST_VERSION_V2
    ) || !is_sha256_digest(&manifest.expected_aggregate_digest)
        || manifest.activation_authority.registry_generation() == 0
        || !is_sha256_digest(manifest.activation_authority.manifest_digest())
        || manifest.collection_id.is_empty()
        || !is_sha256_digest(&manifest.mutation_id)
        || !is_sha256_digest(&manifest.mutation_digest)
        || !is_sha256_digest(&manifest.transition_digest)
        || manifest.lease_generation == 0
        || manifest.writer_fence != manifest.lease_generation
        || !is_sha256_digest(&manifest.parent_descriptor_digest)
        || !is_sha256_digest(&manifest.parent_lease_acquired_record_digest)
        || !is_sha256_digest(&manifest.owner_roster_digest)
        || manifest.owner_evidence.is_empty()
        || !is_sha256_digest(&manifest.manifest_digest)
        || admission_recovery_manifest_digest_v2(manifest)? != manifest.manifest_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_recovery_manifest",
        ));
    }
    let owner_peer_ids = manifest
        .owner_evidence
        .iter()
        .map(PrivateOramMutationOwnerPrestageEvidenceV2::owner_peer_id)
        .collect::<Vec<_>>();
    if owner_peer_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids).map_err(|_| {
            PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
        })? != manifest.owner_roster_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_recovery_manifest",
        ));
    }
    for evidence in &manifest.owner_evidence {
        let verified = PrivateOramMutationOwnerPrestageEvidenceV2::from_signed_attestation(
            evidence.receipt.clone(),
            evidence.attestation.clone(),
            &evidence.attestation.owner_public_key,
        )?;
        let receipt = verified.receipt();
        let statement = &verified.attestation().statement;
        if &verified != evidence
            || receipt.collection_id() != manifest.collection_id
            || receipt.mutation_id() != manifest.mutation_id
            || receipt.mutation_digest() != manifest.mutation_digest
            || receipt.expected_aggregate_digest() != manifest.expected_aggregate_digest
            || receipt.lease_generation() != manifest.lease_generation
            || receipt.writer_fence() != manifest.writer_fence
            || receipt.parent_descriptor_digest() != manifest.parent_descriptor_digest
            || receipt.parent_lease_acquired_record_digest()
                != manifest.parent_lease_acquired_record_digest
            || receipt.owner_roster_digest() != manifest.owner_roster_digest
            || receipt.activation_registry_generation()
                != manifest.activation_authority.registry_generation()
            || receipt.activation_manifest_digest()
                != manifest.activation_authority.manifest_digest()
            || statement.transition_digest != manifest.transition_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "admission_recovery_manifest",
            ));
        }
    }
    match manifest.version {
        ADMISSION_RECOVERY_MANIFEST_VERSION_V1 => {
            if manifest.coordinator_recovery_package_b64.is_some()
                || manifest.expected_old_state.is_some()
            {
                return Err(PrivateOramMutationJournalError::InvalidInput(
                    "admission_recovery_manifest",
                ));
            }
        }
        ADMISSION_RECOVERY_MANIFEST_VERSION_V2 => {
            let encoded = manifest.coordinator_recovery_package_b64.as_deref().ok_or(
                PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest"),
            )?;
            if encoded.is_empty() {
                return Err(PrivateOramMutationJournalError::InvalidInput(
                    "admission_recovery_manifest",
                ));
            }
            let package_bytes = BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| {
                PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
            })?;
            if package_bytes.is_empty()
                || package_bytes.len() > PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2
            {
                return Err(PrivateOramMutationJournalError::InvalidInput(
                    "admission_recovery_manifest",
                ));
            }
            let package =
                decode_private_oram_owner_prestage_package_v2(&package_bytes).map_err(|_| {
                    PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
                })?;
            let expected_old_state = manifest.expected_old_state.as_ref().ok_or(
                PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest"),
            )?;
            let mutation = &package.owner_prepare.mutation_bundle.mutation;
            let old_signed_state_digest =
                private_oram_signed_state_v2_digest(&mutation.old_state.state).map_err(|_| {
                    PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
                })?;
            let expected_old_record_digest = canonical_private_oram_consensus_state_record_digest(
                expected_old_state,
            )
            .map_err(|_| {
                PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
            })?;
            let coordinator_receipt = manifest
                .owner_evidence
                .iter()
                .find(|evidence| evidence.owner_peer_id() == package.coordinator_peer_id)
                .map(PrivateOramMutationOwnerPrestageEvidenceV2::receipt)
                .ok_or(PrivateOramMutationJournalError::InvalidInput(
                    "admission_recovery_manifest",
                ))?;
            if package.owner_peer_id != package.coordinator_peer_id
                || package.collection_id != manifest.collection_id
                || package.mutation_id != manifest.mutation_id
                || package.mutation_digest != manifest.mutation_digest
                || package.transition_digest != manifest.transition_digest
                || package.expected_aggregate_digest != manifest.expected_aggregate_digest
                || package.lease_generation != manifest.lease_generation
                || package.writer_fence != manifest.writer_fence
                || package.parent_descriptor_digest != manifest.parent_descriptor_digest
                || package.parent_lease_acquired_record_digest
                    != manifest.parent_lease_acquired_record_digest
                || package.owner_peer_ids != owner_peer_ids
                || package.owner_roster_digest != manifest.owner_roster_digest
                || package.activation_registry_generation
                    != manifest.activation_authority.registry_generation()
                || package.activation_manifest_digest
                    != manifest.activation_authority.manifest_digest()
                || mutation.collection_id != manifest.collection_id
                || mutation.mutation_id != manifest.mutation_id
                || private_oram_append_mutation_v1_digest(mutation)? != manifest.mutation_digest
                || expected_old_record_digest != package.base_record_digest
                || expected_old_state.collection_id != manifest.collection_id
                || expected_old_state.manifest_digest != mutation.old_state.state.manifest_digest
                || expected_old_state.layout_generation
                    != mutation.old_state.state.layout_generation
                || expected_old_state.layout_digest != mutation.old_state.state.layout_digest
                || expected_old_state.state_sequence != mutation.old_state.state.state_sequence
                || expected_old_state.signed_state_digest != old_signed_state_digest
                || coordinator_receipt.intent_key().is_empty()
                || coordinator_receipt.package_sha256()
                    != BASE64URL_NOPAD.encode(&Sha256::digest(&package_bytes))
                || coordinator_receipt.package_len()
                    != u64::try_from(package_bytes.len()).map_err(|_| {
                        PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
                    })?
            {
                return Err(PrivateOramMutationJournalError::InvalidInput(
                    "admission_recovery_manifest",
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) fn encode_private_oram_mutation_admission_recovery_manifest_v2(
    manifest: &PrivateOramMutationAllOwnersPrestagedV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_admission_recovery_manifest_v2(manifest)?;
    let encoded =
        serde_json::to_string(manifest).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > ADMISSION_RECOVERY_MANIFEST_MAX_CANONICAL_JSON_BYTES_V2
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_recovery_manifest",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_admission_recovery_manifest_v2(
    encoded: &str,
) -> Result<PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > ADMISSION_RECOVERY_MANIFEST_MAX_CANONICAL_JSON_BYTES_V2
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_recovery_manifest",
        ));
    }
    let manifest = serde_json::from_str::<PrivateOramMutationAllOwnersPrestagedV2>(encoded)
        .map_err(|_| {
            PrivateOramMutationJournalError::InvalidInput("admission_recovery_manifest")
        })?;
    validate_admission_recovery_manifest_v2(&manifest)?;
    if serde_json::to_string(&manifest).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_recovery_manifest",
        ));
    }
    Ok(manifest)
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_admission_recovery_manifest_for_test(
    lease: &PrivateOramMutationLease,
    expected_aggregate_digest: &str,
) -> String {
    use ring::signature::Ed25519KeyPair;

    fn test_digest(domain: &[u8], lease: &PrivateOramMutationLease) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(lease.collection_id.as_bytes());
        hasher.update(lease.mutation_id.as_bytes());
        hasher.update(lease.generation.to_be_bytes());
        BASE64URL_NOPAD.encode(&hasher.finalize())
    }

    let owner_peer_ids = vec![lease.owner_peer_id];
    let owner_roster_digest = private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids)
        .expect("test owner roster must be canonical");
    let parent_descriptor_digest = test_digest(b"test-parent", lease);
    let parent_lease_acquired_record_digest = test_digest(b"test-parent-seq1", lease);
    let activation_manifest_digest = test_digest(b"test-activation", lease);
    let intent_key = test_digest(b"test-intent", lease);
    let package_sha256 = test_digest(b"test-package", lease);
    let receipt = PrivateOramOwnerPrestageReceiptV2::from_parts_for_test(
        intent_key.clone(),
        lease.collection_id.clone(),
        lease.mutation_id.clone(),
        lease.signed_mutation_digest.clone(),
        expected_aggregate_digest.to_string(),
        lease.generation,
        lease.writer_fence,
        lease.owner_peer_id,
        parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest.clone(),
        owner_roster_digest.clone(),
        1,
        activation_manifest_digest.clone(),
        package_sha256.clone(),
        1,
        test_digest(b"test-owner-request", lease),
        test_digest(b"test-owner-journal", lease),
        test_digest(b"test-prepared-state", lease),
    );
    let receipt_canonical_json =
        collection::encode_private_oram_owner_prestage_receipt_v2(&receipt)
            .expect("test receipt must encode");
    let statement = qdrant_sec::PrivateOramOwnerPrestageAttestationStatementV2 {
        protocol_version: qdrant_sec::PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
        collection_id: lease.collection_id.clone(),
        mutation_id: lease.mutation_id.clone(),
        mutation_digest: lease.signed_mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        expected_aggregate_digest: expected_aggregate_digest.to_string(),
        lease_generation: lease.generation,
        writer_fence: lease.writer_fence,
        parent_descriptor_digest: parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.clone(),
        owner_roster_digest: owner_roster_digest.clone(),
        owner_peer_id: lease.owner_peer_id,
        activation_registry_generation: 1,
        activation_manifest_digest: activation_manifest_digest.clone(),
        intent_key,
        package_sha256,
        receipt_digest: receipt.receipt_digest().to_string(),
        receipt_sha256: BASE64URL_NOPAD.encode(&Sha256::digest(&receipt_canonical_json)),
    };
    let seed = [lease.owner_peer_id.to_le_bytes()[0].wrapping_add(1); 32];
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("test key must be valid");
    let attestation =
        qdrant_sec::sign_private_oram_owner_prestage_attestation_v2(&key_pair, 1, &statement)
            .expect("test attestation must sign");
    let evidence = PrivateOramMutationOwnerPrestageEvidenceV2::from_signed_attestation(
        receipt,
        attestation,
        &qdrant_sec::private_oram_peer_recovery_public_key_v1(&key_pair, 1)
            .expect("test public key must derive"),
    )
    .expect("test evidence must validate");
    let mut manifest = PrivateOramMutationAllOwnersPrestagedV2 {
        version: ADMISSION_RECOVERY_MANIFEST_VERSION_V1,
        expected_aggregate_digest: expected_aggregate_digest.to_string(),
        activation_authority: PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(
            1,
            activation_manifest_digest,
        ),
        collection_id: lease.collection_id.clone(),
        mutation_id: lease.mutation_id.clone(),
        mutation_digest: lease.signed_mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        lease_generation: lease.generation,
        writer_fence: lease.writer_fence,
        parent_descriptor_digest,
        parent_lease_acquired_record_digest,
        owner_roster_digest,
        owner_evidence: vec![evidence],
        coordinator_recovery_package_b64: None,
        expected_old_state: None,
        manifest_digest: String::new(),
    };
    manifest.manifest_digest = admission_recovery_manifest_digest_v2(&manifest)
        .expect("test recovery manifest digest must derive");
    encode_private_oram_mutation_admission_recovery_manifest_v2(&manifest)
        .expect("test recovery manifest must encode")
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_append_fixture_for_test(
    lease: &PrivateOramMutationLease,
    authority_context: PrivateOramMutationAppendAuthorityContextV2,
    controller_term: u64,
    owner_peer_ids: &[PeerId],
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
) -> (
    PrivateOramMutationAppendReservationV2,
    PrivateOramMutationAllOwnersPrestagedV2,
) {
    private_oram_mutation_append_fixture_with_owner_signer_seeds_for_test(
        lease,
        authority_context,
        controller_term,
        owner_peer_ids,
        activation_authority,
        &[],
    )
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_append_fixture_with_owner_signer_seeds_for_test(
    lease: &PrivateOramMutationLease,
    authority_context: PrivateOramMutationAppendAuthorityContextV2,
    controller_term: u64,
    owner_peer_ids: &[PeerId],
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    owner_signer_seeds: &[(PeerId, u8)],
) -> (
    PrivateOramMutationAppendReservationV2,
    PrivateOramMutationAllOwnersPrestagedV2,
) {
    use ring::signature::Ed25519KeyPair;

    fn test_digest(
        domain: &[u8],
        lease: &PrivateOramMutationLease,
        owner_peer_id: Option<PeerId>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(lease.collection_id.as_bytes());
        hasher.update(lease.mutation_id.as_bytes());
        hasher.update(lease.generation.to_be_bytes());
        if let Some(owner_peer_id) = owner_peer_id {
            hasher.update(owner_peer_id.to_be_bytes());
        }
        BASE64URL_NOPAD.encode(&hasher.finalize())
    }

    authority_context
        .validate()
        .expect("test authority context must validate");
    assert!(controller_term > 0);
    let expected_aggregate_digest = authority_context.expected_aggregate_digest.clone();
    assert!(!owner_peer_ids.is_empty());
    assert!(owner_peer_ids.windows(2).all(|pair| pair[0] < pair[1]));
    let owner_roster_digest = private_oram_owner_prestage_roster_digest_v2(owner_peer_ids)
        .expect("test owner roster must be canonical");
    let parent_descriptor_digest = test_digest(b"test-parent", lease, None);
    let parent_lease_acquired_record_digest = test_digest(b"test-parent-seq1", lease, None);
    let mut owner_evidence = Vec::with_capacity(owner_peer_ids.len());
    let mut owner_targets = Vec::with_capacity(owner_peer_ids.len());

    for (owner_index, &owner_peer_id) in owner_peer_ids.iter().enumerate() {
        let intent_key = test_digest(b"test-intent", lease, Some(owner_peer_id));
        let package_sha256 = test_digest(b"test-package", lease, Some(owner_peer_id));
        let receipt = PrivateOramOwnerPrestageReceiptV2::from_parts_for_test(
            intent_key.clone(),
            lease.collection_id.clone(),
            lease.mutation_id.clone(),
            lease.signed_mutation_digest.clone(),
            expected_aggregate_digest.clone(),
            lease.generation,
            lease.writer_fence,
            owner_peer_id,
            parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest.clone(),
            owner_roster_digest.clone(),
            activation_authority.registry_generation(),
            activation_authority.manifest_digest().to_string(),
            package_sha256.clone(),
            1,
            test_digest(b"test-owner-request", lease, Some(owner_peer_id)),
            test_digest(b"test-owner-journal", lease, Some(owner_peer_id)),
            test_digest(b"test-prepared-state", lease, Some(owner_peer_id)),
        );
        let receipt_canonical_json =
            collection::encode_private_oram_owner_prestage_receipt_v2(&receipt)
                .expect("test receipt must encode");
        let statement = qdrant_sec::PrivateOramOwnerPrestageAttestationStatementV2 {
            protocol_version: qdrant_sec::PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
            collection_id: lease.collection_id.clone(),
            mutation_id: lease.mutation_id.clone(),
            mutation_digest: lease.signed_mutation_digest.clone(),
            transition_digest: lease.transition_digest.clone(),
            expected_aggregate_digest: expected_aggregate_digest.clone(),
            lease_generation: lease.generation,
            writer_fence: lease.writer_fence,
            parent_descriptor_digest: parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.clone(),
            owner_roster_digest: owner_roster_digest.clone(),
            owner_peer_id,
            activation_registry_generation: activation_authority.registry_generation(),
            activation_manifest_digest: activation_authority.manifest_digest().to_string(),
            intent_key: intent_key.clone(),
            package_sha256: package_sha256.clone(),
            receipt_digest: receipt.receipt_digest().to_string(),
            receipt_sha256: BASE64URL_NOPAD.encode(&Sha256::digest(&receipt_canonical_json)),
        };
        let seed_byte = owner_signer_seeds
            .iter()
            .find_map(|(peer_id, seed)| (*peer_id == owner_peer_id).then_some(*seed))
            .unwrap_or_else(|| match owner_peer_id {
                // Seed 19 belongs to peer 9 in the shared activation-authority fixture.
                9 => 19,
                _ => owner_peer_id.to_le_bytes()[0].wrapping_add(1),
            });
        let seed = [seed_byte; 32];
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(&seed).expect("test owner key must be valid");
        let owner_signer = qdrant_sec::private_oram_peer_recovery_public_key_v1(&key_pair, 1)
            .expect("test owner signer must derive");
        let attestation =
            qdrant_sec::sign_private_oram_owner_prestage_attestation_v2(&key_pair, 1, &statement)
                .expect("test owner attestation must sign");
        owner_evidence.push(
            PrivateOramMutationOwnerPrestageEvidenceV2::from_signed_attestation(
                receipt,
                attestation,
                &owner_signer,
            )
            .expect("test owner evidence must validate"),
        );
        let mut target = PrivateOramMutationReservedOwnerTargetV2 {
            version: APPEND_RESERVATION_TARGET_VERSION_V2,
            owner_index: u32::try_from(owner_index).expect("test owner index must fit"),
            owner_peer_id,
            owner_signer,
            owner_request_digest: test_digest(b"test-owner-request", lease, Some(owner_peer_id)),
            intent_key,
            package_sha256,
            package_len: 1,
            target_digest: String::new(),
        };
        target.target_digest = append_reservation_target_digest_v2(&target)
            .expect("test owner target digest must derive");
        owner_targets.push(target);
    }

    let mut manifest = PrivateOramMutationAllOwnersPrestagedV2 {
        version: ADMISSION_RECOVERY_MANIFEST_VERSION_V1,
        expected_aggregate_digest: expected_aggregate_digest.clone(),
        activation_authority: activation_authority.clone(),
        collection_id: lease.collection_id.clone(),
        mutation_id: lease.mutation_id.clone(),
        mutation_digest: lease.signed_mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        lease_generation: lease.generation,
        writer_fence: lease.writer_fence,
        parent_descriptor_digest: parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.clone(),
        owner_roster_digest: owner_roster_digest.clone(),
        owner_evidence,
        coordinator_recovery_package_b64: None,
        expected_old_state: None,
        manifest_digest: String::new(),
    };
    manifest.manifest_digest = admission_recovery_manifest_digest_v2(&manifest)
        .expect("test recovery manifest digest must derive");

    let preparing_lease_state_digest =
        private_oram_mutation_lease_state_digest_v2(lease).expect("test lease digest must derive");
    let immutable_plan_digest = test_digest(b"test-immutable-plan", lease, None);
    let attempt_id = append_reservation_attempt_id_v2(
        &lease.collection_id,
        &lease.mutation_id,
        &authority_context,
        &preparing_lease_state_digest,
        &immutable_plan_digest,
    )
    .expect("test append attempt id must derive");
    let controller_peer_id = lease.owner_peer_id;
    let controller_id = append_reservation_controller_id_v2(
        &lease.collection_id,
        &lease.mutation_id,
        controller_peer_id,
        controller_term,
    )
    .expect("test controller id must derive");
    let recovery_policy = PrivateOramMutationAppendRecoveryPolicyV2::RejectOnOrphanV1;
    let attempt_lease_id = append_reservation_attempt_lease_id_v2(
        &attempt_id,
        &controller_id,
        controller_peer_id,
        controller_term,
        lease.expires_at_unix,
        lease.expires_at_unix,
        recovery_policy,
    )
    .expect("test attempt lease id must derive");
    let mut reservation = PrivateOramMutationAppendReservationV2 {
        version: APPEND_RESERVATION_VERSION_V2,
        protocol_capability_digest: private_oram_mutation_reservation_protocol_capability_digest_v2(
        ),
        attempt_id,
        attempt_sequence: authority_context.attempt_sequence,
        expected_aggregate_digest,
        consensus_history_id_digest: authority_context.consensus_history_id_digest,
        raft_group_id_digest: authority_context.raft_group_id_digest,
        collection_lifetime_id_digest: authority_context.collection_lifetime_id_digest,
        collection_incarnation_digest: authority_context.collection_incarnation_digest,
        activation_anchor_digest: authority_context.activation_anchor_digest,
        activation_authority,
        controller_id,
        controller_peer_id,
        controller_term,
        attempt_lease_id,
        attempt_lease_expires_at_unix: lease.expires_at_unix,
        absolute_resolution_deadline_unix: lease.expires_at_unix,
        recovery_policy,
        collection_id: lease.collection_id.clone(),
        mutation_id: lease.mutation_id.clone(),
        mutation_digest: lease.signed_mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        preparing_lease: lease.clone(),
        preparing_lease_state_digest,
        immutable_plan_digest,
        parent_descriptor_digest,
        parent_lease_acquired_record_digest,
        owner_roster_digest,
        owner_targets,
        reserved_rejection_bytes: APPEND_RESERVATION_RESERVED_REJECTION_BYTES_V2,
        reserved_cleanup_bytes: APPEND_RESERVATION_RESERVED_CLEANUP_BYTES_V2,
        reservation_digest: String::new(),
    };
    reservation.reservation_digest =
        append_reservation_digest_v2(&reservation).expect("test reservation digest must derive");
    validate_private_oram_mutation_append_reservation_manifest_v2(&reservation, &manifest)
        .expect("test append fixture must validate");
    (reservation, manifest)
}

impl Debug for PrivateOramMutationPreparedOwnerProjectionV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationPreparedOwnerProjectionV2")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("owner_journal_descriptor_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl Debug for PrivateOramMutationOwnersPreparedV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnersPreparedV2")
            .field("descriptor_digest", &"[redacted]")
            .field("owners_prepared_record_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramMutationPointStageDurableV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationPointStageDurableV2")
            .field("descriptor_digest", &"[redacted]")
            .field("point_stage_record_digest", &"[redacted]")
            .field(
                "has_durable_visible_point_stage",
                &self.durable_point_stage.is_some(),
            )
            .finish()
    }
}

impl PrivateOramMutationParentLeaseAcquiredV2 {
    pub fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub fn lease_acquired_record_digest(&self) -> &str {
        &self.lease_acquired_record_digest
    }

    pub fn preparing_lease(&self) -> &PrivateOramMutationLease {
        &self.preparing_lease
    }

    pub fn owner_requirements(&self) -> &[PrivateOramMutationOwnerRequirementV1] {
        &self.owner_requirements
    }

    pub fn requirements_for_owner(
        &self,
        owner_peer_id: PeerId,
    ) -> Vec<PrivateOramMutationOwnerRequirementV1> {
        self.owner_requirements
            .iter()
            .filter(|requirement| requirement.peer_id == owner_peer_id)
            .cloned()
            .collect()
    }

    pub fn owner_prepare_parent(
        &self,
        owner_peer_id: PeerId,
    ) -> Result<PrivateOramOwnerPrepareParentV2, PrivateOramMutationJournalError> {
        let requirements = self.requirements_for_owner(owner_peer_id);
        if requirements.is_empty() {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "owner_peer_id",
            ));
        }
        PrivateOramOwnerPrepareParentV2::try_new(
            self.descriptor_digest.clone(),
            self.lease_acquired_record_digest.clone(),
            owner_peer_id,
            requirements
                .into_iter()
                .map(|requirement| PrivateOramOwnerPrepareRequirementV2 {
                    kind: requirement.kind,
                    index_name: requirement.index_name,
                    old_epoch: requirement.old_epoch,
                    new_epoch: requirement.new_epoch,
                    old_root_hash: requirement.old_root_hash,
                    new_root_hash: requirement.new_root_hash,
                    writeback_digest: requirement.writeback_digest,
                })
                .collect(),
        )
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_prepare_parent"))
    }

    pub fn project_local_owner_prepared(
        &self,
        evidence: &PrivateOramOwnerPreparedEvidenceV2,
    ) -> Result<PrivateOramMutationPreparedOwnerProjectionV2, PrivateOramMutationJournalError> {
        if evidence.parent_descriptor_digest() != self.descriptor_digest
            || evidence.parent_lease_acquired_record_digest() != self.lease_acquired_record_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let requirements = self.requirements_for_owner(evidence.owner_peer_id());
        if requirements.len() != evidence.indexes().len()
            || requirements
                .iter()
                .zip(evidence.indexes())
                .any(|(requirement, index)| {
                    requirement.kind != index.kind()
                        || requirement.index_name != index.index_name()
                        || !is_sha256_digest(index.prepared_journal_digest())
                })
            || !is_sha256_digest(evidence.journal_descriptor_digest())
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(PrivateOramMutationPreparedOwnerProjectionV2 {
            parent_descriptor_digest: self.descriptor_digest.clone(),
            parent_lease_acquired_record_digest: self.lease_acquired_record_digest.clone(),
            owner_peer_id: evidence.owner_peer_id(),
            owner_journal_descriptor_digest: evidence.journal_descriptor_digest().to_string(),
            indexes: evidence
                .indexes()
                .iter()
                .map(|index| PrivateOramMutationOwnerPrepareEvidenceV1 {
                    peer_id: evidence.owner_peer_id(),
                    kind: index.kind(),
                    index_name: index.index_name().to_string(),
                    prepared_journal_digest: index.prepared_journal_digest().to_string(),
                })
                .collect(),
        })
    }
}

impl Debug for PrivateOramMutationAdmissionPlanV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationAdmissionPlanV2")
            .field("lease", &self.lease)
            .field("mutation_bundle", &"[redacted]")
            .field("expected_old_state", &"[redacted]")
            .field("expected_new_state", &"[redacted]")
            .field("mutation_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationAdmissionPlanV2 {
    pub fn lease(&self) -> &PrivateOramMutationLease {
        &self.lease
    }

    pub fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }

    pub fn expected_old_state(&self) -> &PrivateOramConsensusCollectionStateV2 {
        &self.expected_old_state
    }

    pub fn expected_new_state(&self) -> &PrivateOramConsensusCollectionStateV2 {
        &self.expected_new_state
    }

    pub fn mutation_digest(&self) -> &str {
        &self.mutation_digest
    }
}

impl PrivateOramMutationReservedOwnerTargetV2 {
    pub fn owner_index(&self) -> u32 {
        self.owner_index
    }

    pub fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub fn owner_signer(&self) -> &PrivateOramPeerRecoveryPublicKeyV1 {
        &self.owner_signer
    }

    pub fn owner_request_digest(&self) -> &str {
        &self.owner_request_digest
    }

    pub fn intent_key(&self) -> &str {
        &self.intent_key
    }

    pub fn package_sha256(&self) -> &str {
        &self.package_sha256
    }

    pub fn package_len(&self) -> u64 {
        self.package_len
    }

    pub(crate) fn target_digest(&self) -> &str {
        &self.target_digest
    }
}

impl PrivateOramMutationAppendAuthorityContextV2 {
    pub(in crate::content_manager) fn from_authority(
        expected_aggregate_digest: String,
        consensus_history_id_digest: String,
        raft_group_id_digest: String,
        collection_lifetime_id_digest: String,
        collection_incarnation_digest: String,
        activation_anchor_digest: String,
        attempt_sequence: u64,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let context = Self {
            expected_aggregate_digest,
            consensus_history_id_digest,
            raft_group_id_digest,
            collection_lifetime_id_digest,
            collection_incarnation_digest,
            activation_anchor_digest,
            attempt_sequence,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn expected_aggregate_digest(&self) -> &str {
        &self.expected_aggregate_digest
    }

    pub fn attempt_sequence(&self) -> u64 {
        self.attempt_sequence
    }

    fn validate(&self) -> Result<(), PrivateOramMutationJournalError> {
        if self.attempt_sequence == 0
            || [
                &self.expected_aggregate_digest,
                &self.consensus_history_id_digest,
                &self.raft_group_id_digest,
                &self.collection_lifetime_id_digest,
                &self.collection_incarnation_digest,
                &self.activation_anchor_digest,
            ]
            .into_iter()
            .any(|digest| !is_sha256_digest(digest))
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "append_authority_context",
            ));
        }
        Ok(())
    }
}

impl PrivateOramMutationAppendReservationV2 {
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn attempt_sequence(&self) -> u64 {
        self.attempt_sequence
    }

    pub fn expected_aggregate_digest(&self) -> &str {
        &self.expected_aggregate_digest
    }

    pub fn consensus_history_id_digest(&self) -> &str {
        &self.consensus_history_id_digest
    }

    pub fn raft_group_id_digest(&self) -> &str {
        &self.raft_group_id_digest
    }

    pub fn collection_lifetime_id_digest(&self) -> &str {
        &self.collection_lifetime_id_digest
    }

    pub fn collection_incarnation_digest(&self) -> &str {
        &self.collection_incarnation_digest
    }

    pub fn activation_anchor_digest(&self) -> &str {
        &self.activation_anchor_digest
    }

    pub fn activation_authority(&self) -> &PrivateOramActivationAuthorityLocatorV1 {
        &self.activation_authority
    }

    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    pub fn controller_peer_id(&self) -> PeerId {
        self.controller_peer_id
    }

    pub fn controller_term(&self) -> u64 {
        self.controller_term
    }

    pub fn attempt_lease_id(&self) -> &str {
        &self.attempt_lease_id
    }

    pub fn attempt_lease_expires_at_unix(&self) -> u64 {
        self.attempt_lease_expires_at_unix
    }

    pub fn absolute_resolution_deadline_unix(&self) -> u64 {
        self.absolute_resolution_deadline_unix
    }

    pub fn recovery_policy(&self) -> PrivateOramMutationAppendRecoveryPolicyV2 {
        self.recovery_policy
    }

    pub fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    pub fn mutation_digest(&self) -> &str {
        &self.mutation_digest
    }

    pub fn transition_digest(&self) -> &str {
        &self.transition_digest
    }

    pub fn preparing_lease(&self) -> &PrivateOramMutationLease {
        &self.preparing_lease
    }

    pub fn preparing_lease_state_digest(&self) -> &str {
        &self.preparing_lease_state_digest
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub fn owner_roster_digest(&self) -> &str {
        &self.owner_roster_digest
    }

    pub fn owner_targets(&self) -> &[PrivateOramMutationReservedOwnerTargetV2] {
        &self.owner_targets
    }

    pub fn reservation_digest(&self) -> &str {
        &self.reservation_digest
    }

    pub fn protocol_capability_digest(&self) -> &str {
        &self.protocol_capability_digest
    }

    pub(crate) fn reserved_rejection_bytes(&self) -> u64 {
        self.reserved_rejection_bytes
    }

    pub(crate) fn reserved_cleanup_bytes(&self) -> u64 {
        self.reserved_cleanup_bytes
    }
}

pub fn derive_private_oram_mutation_append_reservation_v2(
    planned: &PrivateOramMutationPlannedParentV2,
    admission: &PrivateOramMutationAdmissionPlanV2,
    authority_context: PrivateOramMutationAppendAuthorityContextV2,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    controller_peer_id: PeerId,
    controller_term: u64,
    owner_requests_and_signers: Vec<(
        PrivateOramOwnerPrestageRequestV2,
        PrivateOramPeerRecoveryPublicKeyV1,
    )>,
) -> Result<PrivateOramMutationAppendReservationV2, PrivateOramMutationJournalError> {
    authority_context.validate()?;
    if controller_peer_id == 0
        || controller_term == 0
        || activation_authority.registry_generation() == 0
        || !is_sha256_digest(activation_authority.manifest_digest())
        || planned.preparing_lease != admission.lease
        || owner_requests_and_signers.is_empty()
        || owner_requests_and_signers.len() > APPEND_RESERVATION_MAX_OWNERS_V2
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let lease = admission.lease();
    if controller_peer_id != lease.owner_peer_id {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let expected_aggregate_digest = authority_context.expected_aggregate_digest.clone();
    let owner_peer_ids = owner_requests_and_signers
        .iter()
        .map(|(request, _)| request.owner_peer_id)
        .collect::<Vec<_>>();
    if owner_peer_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let owner_roster_digest = private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("append_reservation"))?;
    let mut owner_targets = Vec::with_capacity(owner_requests_and_signers.len());
    for (owner_index, (request, owner_signer)) in owner_requests_and_signers.into_iter().enumerate()
    {
        if request.collection_id != lease.collection_id
            || request.mutation_id != lease.mutation_id
            || request.mutation_digest != admission.mutation_digest
            || request.transition_digest != lease.transition_digest
            || request.expected_aggregate_digest != expected_aggregate_digest
            || request.lease_generation != lease.generation
            || request.writer_fence != lease.writer_fence
            || request.parent_descriptor_digest != planned.descriptor_digest
            || request.parent_lease_acquired_record_digest != planned.lease_acquired_record_digest
            || request.owner_roster_digest != owner_roster_digest
            || request.coordinator_peer_id != lease.owner_peer_id
            || request.activation_registry_generation != activation_authority.registry_generation()
            || request.activation_manifest_digest != activation_authority.manifest_digest()
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "append_reservation",
            ));
        }
        validate_private_oram_peer_recovery_public_key_v1(&owner_signer)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("append_reservation"))?;
        let owner_index = u32::try_from(owner_index)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("append_reservation"))?;
        let owner_request_digest = private_oram_owner_prestage_request_digest_v2(&request)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("append_reservation"))?;
        let mut target = PrivateOramMutationReservedOwnerTargetV2 {
            version: APPEND_RESERVATION_TARGET_VERSION_V2,
            owner_index,
            owner_peer_id: request.owner_peer_id,
            owner_signer,
            owner_request_digest,
            intent_key: request.intent_key,
            package_sha256: request.package_sha256,
            package_len: request.package_len,
            target_digest: String::new(),
        };
        target.target_digest = append_reservation_target_digest_v2(&target)?;
        validate_private_oram_mutation_reserved_owner_target_v2(&target)?;
        owner_targets.push(target);
    }
    let preparing_lease_state_digest = private_oram_mutation_lease_state_digest_v2(lease)?;
    let immutable_plan_digest = append_reservation_plan_digest_v2(admission, planned)?;
    let attempt_id = append_reservation_attempt_id_v2(
        &lease.collection_id,
        &lease.mutation_id,
        &authority_context,
        &preparing_lease_state_digest,
        &immutable_plan_digest,
    )?;
    let controller_id = append_reservation_controller_id_v2(
        &lease.collection_id,
        &lease.mutation_id,
        controller_peer_id,
        controller_term,
    )?;
    let attempt_lease_expires_at_unix = lease.expires_at_unix;
    let absolute_resolution_deadline_unix = lease.expires_at_unix;
    let recovery_policy = PrivateOramMutationAppendRecoveryPolicyV2::RejectOnOrphanV1;
    let attempt_lease_id = append_reservation_attempt_lease_id_v2(
        &attempt_id,
        &controller_id,
        controller_peer_id,
        controller_term,
        attempt_lease_expires_at_unix,
        absolute_resolution_deadline_unix,
        recovery_policy,
    )?;
    let mut reservation = PrivateOramMutationAppendReservationV2 {
        version: APPEND_RESERVATION_VERSION_V2,
        protocol_capability_digest: private_oram_mutation_reservation_protocol_capability_digest_v2(
        ),
        attempt_id,
        attempt_sequence: authority_context.attempt_sequence,
        expected_aggregate_digest,
        consensus_history_id_digest: authority_context.consensus_history_id_digest,
        raft_group_id_digest: authority_context.raft_group_id_digest,
        collection_lifetime_id_digest: authority_context.collection_lifetime_id_digest,
        collection_incarnation_digest: authority_context.collection_incarnation_digest,
        activation_anchor_digest: authority_context.activation_anchor_digest,
        activation_authority,
        controller_id,
        controller_peer_id,
        controller_term,
        attempt_lease_id,
        attempt_lease_expires_at_unix,
        absolute_resolution_deadline_unix,
        recovery_policy,
        collection_id: lease.collection_id.clone(),
        mutation_id: lease.mutation_id.clone(),
        mutation_digest: admission.mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        preparing_lease: lease.clone(),
        preparing_lease_state_digest,
        immutable_plan_digest,
        parent_descriptor_digest: planned.descriptor_digest.clone(),
        parent_lease_acquired_record_digest: planned.lease_acquired_record_digest.clone(),
        owner_roster_digest,
        owner_targets,
        reserved_rejection_bytes: APPEND_RESERVATION_RESERVED_REJECTION_BYTES_V2,
        reserved_cleanup_bytes: APPEND_RESERVATION_RESERVED_CLEANUP_BYTES_V2,
        reservation_digest: String::new(),
    };
    reservation.reservation_digest = append_reservation_digest_v2(&reservation)?;
    validate_private_oram_mutation_append_reservation_v2(&reservation)?;
    Ok(reservation)
}

pub(crate) fn encode_private_oram_mutation_append_reservation_v2(
    reservation: &PrivateOramMutationAppendReservationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_append_reservation_v2(reservation)?;
    let encoded =
        serde_json::to_string(reservation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_append_reservation_v2(
    encoded: &str,
) -> Result<PrivateOramMutationAppendReservationV2, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let reservation: PrivateOramMutationAppendReservationV2 =
        serde_json::from_str(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_private_oram_mutation_append_reservation_v2(&reservation)?;
    if serde_json::to_string(&reservation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    Ok(reservation)
}

fn validate_private_oram_mutation_reserved_owner_target_v2(
    target: &PrivateOramMutationReservedOwnerTargetV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_peer_recovery_public_key_v1(&target.owner_signer)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("append_reservation"))?;
    if target.version != APPEND_RESERVATION_TARGET_VERSION_V2
        || target.owner_peer_id == 0
        || !is_sha256_digest(&target.owner_request_digest)
        || !is_sha256_digest(&target.intent_key)
        || !is_sha256_digest(&target.package_sha256)
        || target.package_len == 0
        || target.package_len
            > u64::try_from(PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2)
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        || !is_sha256_digest(&target.target_digest)
        || target.target_digest != append_reservation_target_digest_v2(target)?
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    Ok(())
}

pub(crate) fn validate_private_oram_mutation_append_reservation_v2(
    reservation: &PrivateOramMutationAppendReservationV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if reservation.version != APPEND_RESERVATION_VERSION_V2
        || reservation.protocol_capability_digest
            != private_oram_mutation_reservation_protocol_capability_digest_v2()
        || !is_sha256_digest(&reservation.attempt_id)
        || reservation.attempt_sequence == 0
        || !is_sha256_digest(&reservation.expected_aggregate_digest)
        || !is_sha256_digest(&reservation.consensus_history_id_digest)
        || !is_sha256_digest(&reservation.raft_group_id_digest)
        || !is_sha256_digest(&reservation.collection_lifetime_id_digest)
        || !is_sha256_digest(&reservation.collection_incarnation_digest)
        || !is_sha256_digest(&reservation.activation_anchor_digest)
        || reservation.activation_authority.registry_generation() == 0
        || !is_sha256_digest(reservation.activation_authority.manifest_digest())
        || !is_sha256_digest(&reservation.controller_id)
        || reservation.controller_peer_id == 0
        || reservation.controller_term == 0
        || !is_sha256_digest(&reservation.attempt_lease_id)
        || reservation.attempt_lease_expires_at_unix == 0
        || reservation.absolute_resolution_deadline_unix == 0
        || reservation.recovery_policy
            != PrivateOramMutationAppendRecoveryPolicyV2::RejectOnOrphanV1
        || reservation.collection_id.is_empty()
        || !is_sha256_digest(&reservation.mutation_id)
        || !is_sha256_digest(&reservation.mutation_digest)
        || !is_sha256_digest(&reservation.transition_digest)
        || !is_sha256_digest(&reservation.preparing_lease_state_digest)
        || !is_sha256_digest(&reservation.immutable_plan_digest)
        || !is_sha256_digest(&reservation.parent_descriptor_digest)
        || !is_sha256_digest(&reservation.parent_lease_acquired_record_digest)
        || !is_sha256_digest(&reservation.owner_roster_digest)
        || reservation.owner_targets.is_empty()
        || reservation.owner_targets.len() > APPEND_RESERVATION_MAX_OWNERS_V2
        || reservation.reserved_rejection_bytes != APPEND_RESERVATION_RESERVED_REJECTION_BYTES_V2
        || reservation.reserved_cleanup_bytes != APPEND_RESERVATION_RESERVED_CLEANUP_BYTES_V2
        || !is_sha256_digest(&reservation.reservation_digest)
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    super::consensus::private_oram_mutation_cleanup::validate_lease_v2(
        &reservation.preparing_lease,
    )?;
    if !matches!(
        reservation.preparing_lease.phase,
        PrivateOramMutationLeasePhase::Preparing
    ) || reservation.collection_id != reservation.preparing_lease.collection_id
        || reservation.mutation_id != reservation.preparing_lease.mutation_id
        || reservation.mutation_digest != reservation.preparing_lease.signed_mutation_digest
        || reservation.transition_digest != reservation.preparing_lease.transition_digest
        || reservation.preparing_lease_state_digest
            != private_oram_mutation_lease_state_digest_v2(&reservation.preparing_lease)?
        || reservation.controller_peer_id != reservation.preparing_lease.owner_peer_id
        || reservation.controller_id
            != append_reservation_controller_id_v2(
                &reservation.collection_id,
                &reservation.mutation_id,
                reservation.controller_peer_id,
                reservation.controller_term,
            )?
        || reservation.attempt_lease_expires_at_unix != reservation.preparing_lease.expires_at_unix
        || reservation.absolute_resolution_deadline_unix
            != reservation.preparing_lease.expires_at_unix
        || reservation.attempt_id
            != append_reservation_attempt_id_v2(
                &reservation.collection_id,
                &reservation.mutation_id,
                &PrivateOramMutationAppendAuthorityContextV2 {
                    expected_aggregate_digest: reservation.expected_aggregate_digest.clone(),
                    consensus_history_id_digest: reservation.consensus_history_id_digest.clone(),
                    raft_group_id_digest: reservation.raft_group_id_digest.clone(),
                    collection_lifetime_id_digest: reservation
                        .collection_lifetime_id_digest
                        .clone(),
                    collection_incarnation_digest: reservation
                        .collection_incarnation_digest
                        .clone(),
                    activation_anchor_digest: reservation.activation_anchor_digest.clone(),
                    attempt_sequence: reservation.attempt_sequence,
                },
                &reservation.preparing_lease_state_digest,
                &reservation.immutable_plan_digest,
            )?
        || reservation.attempt_lease_id
            != append_reservation_attempt_lease_id_v2(
                &reservation.attempt_id,
                &reservation.controller_id,
                reservation.controller_peer_id,
                reservation.controller_term,
                reservation.attempt_lease_expires_at_unix,
                reservation.absolute_resolution_deadline_unix,
                reservation.recovery_policy,
            )?
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let mut owner_peer_ids = Vec::with_capacity(reservation.owner_targets.len());
    for (owner_index, target) in reservation.owner_targets.iter().enumerate() {
        validate_private_oram_mutation_reserved_owner_target_v2(target)?;
        if usize::try_from(target.owner_index).ok() != Some(owner_index) {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "append_reservation",
            ));
        }
        owner_peer_ids.push(target.owner_peer_id);
    }
    if owner_peer_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("append_reservation"))?
            != reservation.owner_roster_digest
        || reservation.reservation_digest != append_reservation_digest_v2(reservation)?
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let encoded =
        serde_json::to_vec(reservation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    Ok(())
}

pub(crate) fn validate_private_oram_mutation_append_reservation_manifest_v2(
    reservation: &PrivateOramMutationAppendReservationV2,
    manifest: &PrivateOramMutationAllOwnersPrestagedV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_append_reservation_v2(reservation)?;
    validate_admission_recovery_manifest_v2(manifest)?;
    manifest.validate_admission_lease(reservation.preparing_lease())?;
    if manifest.expected_aggregate_digest != reservation.expected_aggregate_digest
        || manifest.activation_authority != reservation.activation_authority
        || manifest.collection_id != reservation.collection_id
        || manifest.mutation_id != reservation.mutation_id
        || manifest.mutation_digest != reservation.mutation_digest
        || manifest.transition_digest != reservation.transition_digest
        || manifest.lease_generation != reservation.preparing_lease.generation
        || manifest.writer_fence != reservation.preparing_lease.writer_fence
        || manifest.parent_descriptor_digest != reservation.parent_descriptor_digest
        || manifest.parent_lease_acquired_record_digest
            != reservation.parent_lease_acquired_record_digest
        || manifest.owner_roster_digest != reservation.owner_roster_digest
        || manifest.owner_evidence.len() != reservation.owner_targets.len()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (evidence, target) in manifest
        .owner_evidence
        .iter()
        .zip(&reservation.owner_targets)
    {
        let receipt = evidence.receipt();
        if evidence.owner_peer_id() != target.owner_peer_id
            || evidence.attestation().owner_public_key != target.owner_signer
            || receipt.intent_key() != target.intent_key
            || receipt.package_sha256() != target.package_sha256
            || receipt.package_len() != target.package_len
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

pub(crate) fn private_oram_mutation_append_prepared_request_digest_v2(
    reservation: &PrivateOramMutationAppendReservationV2,
    manifest: &PrivateOramMutationAllOwnersPrestagedV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_append_reservation_manifest_v2(reservation, manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(APPEND_PREPARED_REQUEST_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, reservation.reservation_digest())?;
    hash_digest(&mut hasher, manifest.manifest_digest())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_reserved_rejection_request_digest_v2(
    reservation: &PrivateOramMutationAppendReservationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_append_reservation_v2(reservation)?;
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVED_REJECTION_REQUEST_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, reservation.reservation_digest())?;
    hash_digest(&mut hasher, reservation.attempt_id())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_reservation_target_digest_v2(
    target: &PrivateOramMutationReservedOwnerTargetV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let signer = serde_json::to_vec(&target.owner_signer)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_TARGET_DIGEST_DOMAIN_V2);
    hasher.update(target.version.to_be_bytes());
    hasher.update(target.owner_index.to_be_bytes());
    hasher.update(target.owner_peer_id.to_be_bytes());
    hash_len(&mut hasher, signer.len())?;
    hasher.update(signer);
    hash_digest(&mut hasher, &target.owner_request_digest)?;
    hash_digest(&mut hasher, &target.intent_key)?;
    hash_digest(&mut hasher, &target.package_sha256)?;
    hasher.update(target.package_len.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_reservation_attempt_id_v2(
    collection_id: &str,
    mutation_id: &str,
    authority_context: &PrivateOramMutationAppendAuthorityContextV2,
    preparing_lease_state_digest: &str,
    immutable_plan_digest: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    authority_context.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_ATTEMPT_ID_DOMAIN_V2);
    hash_string(&mut hasher, collection_id)?;
    hash_digest(&mut hasher, mutation_id)?;
    for digest in [
        &authority_context.expected_aggregate_digest,
        &authority_context.consensus_history_id_digest,
        &authority_context.raft_group_id_digest,
        &authority_context.collection_lifetime_id_digest,
        &authority_context.collection_incarnation_digest,
        &authority_context.activation_anchor_digest,
    ] {
        hash_digest(&mut hasher, digest)?;
    }
    hasher.update(authority_context.attempt_sequence.to_be_bytes());
    hash_digest(&mut hasher, preparing_lease_state_digest)?;
    hash_digest(&mut hasher, immutable_plan_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_reservation_controller_id_v2(
    collection_id: &str,
    mutation_id: &str,
    controller_peer_id: PeerId,
    controller_term: u64,
) -> Result<String, PrivateOramMutationJournalError> {
    if controller_peer_id == 0 || controller_term == 0 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_CONTROLLER_ID_DOMAIN_V2);
    hash_string(&mut hasher, collection_id)?;
    hash_digest(&mut hasher, mutation_id)?;
    hasher.update(controller_peer_id.to_be_bytes());
    hasher.update(controller_term.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_reservation_attempt_lease_id_v2(
    attempt_id: &str,
    controller_id: &str,
    controller_peer_id: PeerId,
    controller_term: u64,
    attempt_lease_expires_at_unix: u64,
    absolute_resolution_deadline_unix: u64,
    recovery_policy: PrivateOramMutationAppendRecoveryPolicyV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_ATTEMPT_LEASE_ID_DOMAIN_V2);
    hash_digest(&mut hasher, attempt_id)?;
    hash_digest(&mut hasher, controller_id)?;
    hasher.update(controller_peer_id.to_be_bytes());
    hasher.update(controller_term.to_be_bytes());
    hasher.update(attempt_lease_expires_at_unix.to_be_bytes());
    hasher.update(absolute_resolution_deadline_unix.to_be_bytes());
    match recovery_policy {
        PrivateOramMutationAppendRecoveryPolicyV2::RejectOnOrphanV1 => hasher.update([1]),
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_reservation_plan_digest_v2(
    admission: &PrivateOramMutationAdmissionPlanV2,
    planned: &PrivateOramMutationPlannedParentV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_PLAN_DIGEST_DOMAIN_V2);
    hash_digest(
        &mut hasher,
        &private_oram_mutation_lease_state_digest_v2(admission.lease())?,
    )?;
    hash_digest(&mut hasher, admission.mutation_digest())?;
    hash_digest(
        &mut hasher,
        &canonical_private_oram_consensus_state_record_digest(admission.expected_old_state())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
    )?;
    hash_digest(
        &mut hasher,
        &canonical_private_oram_consensus_state_record_digest(admission.expected_new_state())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
    )?;
    hash_digest(&mut hasher, planned.descriptor_digest())?;
    hash_digest(&mut hasher, planned.lease_acquired_record_digest())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_reservation_digest_v2(
    reservation: &PrivateOramMutationAppendReservationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_DIGEST_DOMAIN_V2);
    hasher.update(reservation.version.to_be_bytes());
    hash_digest(&mut hasher, &reservation.protocol_capability_digest)?;
    hash_digest(&mut hasher, &reservation.attempt_id)?;
    hasher.update(reservation.attempt_sequence.to_be_bytes());
    for digest in [
        &reservation.expected_aggregate_digest,
        &reservation.consensus_history_id_digest,
        &reservation.raft_group_id_digest,
        &reservation.collection_lifetime_id_digest,
        &reservation.collection_incarnation_digest,
        &reservation.activation_anchor_digest,
    ] {
        hash_digest(&mut hasher, digest)?;
    }
    hasher.update(
        reservation
            .activation_authority
            .registry_generation()
            .to_be_bytes(),
    );
    hash_digest(
        &mut hasher,
        reservation.activation_authority.manifest_digest(),
    )?;
    hash_digest(&mut hasher, &reservation.controller_id)?;
    hasher.update(reservation.controller_peer_id.to_be_bytes());
    hasher.update(reservation.controller_term.to_be_bytes());
    hash_digest(&mut hasher, &reservation.attempt_lease_id)?;
    hasher.update(reservation.attempt_lease_expires_at_unix.to_be_bytes());
    hasher.update(reservation.absolute_resolution_deadline_unix.to_be_bytes());
    match reservation.recovery_policy {
        PrivateOramMutationAppendRecoveryPolicyV2::RejectOnOrphanV1 => hasher.update([1]),
    }
    hash_string(&mut hasher, &reservation.collection_id)?;
    for digest in [
        &reservation.mutation_id,
        &reservation.mutation_digest,
        &reservation.transition_digest,
        &reservation.preparing_lease_state_digest,
        &reservation.immutable_plan_digest,
        &reservation.parent_descriptor_digest,
        &reservation.parent_lease_acquired_record_digest,
        &reservation.owner_roster_digest,
    ] {
        hash_digest(&mut hasher, digest)?;
    }
    hash_len(&mut hasher, reservation.owner_targets.len())?;
    for target in &reservation.owner_targets {
        hash_digest(&mut hasher, target.target_digest())?;
    }
    hasher.update(reservation.reserved_rejection_bytes.to_be_bytes());
    hasher.update(reservation.reserved_cleanup_bytes.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn derive_private_oram_mutation_admission_plan_v2(
    coordinator_peer_id: PeerId,
    expected_generation: u64,
    expected_writer_fence: u64,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    current_state: &PrivateOramConsensusCollectionStateV2,
    validated: &PrivateOramValidatedOwnerPrepareV1,
) -> Result<PrivateOramMutationAdmissionPlanV2, PrivateOramMutationJournalError> {
    let mutation = &validated.mutation_bundle().mutation;
    let mutation_digest = private_oram_append_mutation_v1_digest(mutation)?;
    if mutation_digest != validated.mutation_digest()
        || current_slot.version != PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION
        || current_slot.active.is_some()
        || current_slot.generation.checked_add(1) != Some(expected_generation)
        || current_slot.max_writer_fence.checked_add(1) != Some(expected_writer_fence)
        || expected_generation != expected_writer_fence
        || mutation.writer_fence != expected_writer_fence
        || mutation.old_state.state.state_sequence != current_state.state_sequence
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "admission_plan",
        ));
    }
    let base_record_digest = canonical_private_oram_consensus_state_record_digest(current_state)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("consensus_old_state"))?;
    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)?;
    let new_state_digest = private_oram_signed_state_v2_digest(&mutation.new_state.state)?;
    let receipt = PrivateOramMutationReceiptV2 {
        version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
        mutation_id: mutation.mutation_id.clone(),
        signed_mutation_digest: mutation_digest.clone(),
        transition_digest: String::new(),
        old_state_sequence: mutation.old_state.state.state_sequence,
        old_state_digest,
        new_state_sequence: mutation.new_state.state.state_sequence,
        new_state_digest: new_state_digest.clone(),
        point_operation_digest: mutation.point_operation_digest.clone(),
        writer_lease_digest: mutation.writer_lease_digest.clone(),
        writer_fence: mutation.writer_fence,
        mutation_lease_generation: expected_generation,
    };
    let new_signed = &mutation.new_state.state;
    let mut expected_new_state = PrivateOramConsensusCollectionStateV2 {
        version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
        collection_id: new_signed.collection_id.clone(),
        manifest_digest: new_signed.manifest_digest.clone(),
        layout_generation: new_signed.layout_generation,
        layout_digest: new_signed.layout_digest.clone(),
        state_sequence: new_signed.state_sequence,
        signed_state_digest: new_state_digest,
        indexes: consensus_indexes_from_signed(new_signed),
        client_state_digest: new_signed.client_state_digest.clone(),
        last_transition: PrivateOramConsensusTransitionV2::Mutation(receipt),
    };
    let transition_digest =
        canonical_private_oram_mutation_transition_digest(current_state, &expected_new_state)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("transition_digest"))?;
    let PrivateOramConsensusTransitionV2::Mutation(receipt) =
        &mut expected_new_state.last_transition
    else {
        unreachable!();
    };
    receipt.transition_digest = transition_digest.clone();
    canonical_private_oram_consensus_state_record_digest(&expected_new_state)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("consensus_new_state"))?;
    let lease = PrivateOramMutationLease {
        generation: expected_generation,
        collection_id: mutation.collection_id.clone(),
        owner_peer_id: coordinator_peer_id,
        mutation_id: mutation.mutation_id.clone(),
        signed_mutation_digest: mutation_digest.clone(),
        transition_digest,
        base_record_digest,
        base_state_sequence: mutation.old_state.state.state_sequence,
        writer_lease_digest: mutation.writer_lease_digest.clone(),
        writer_fence: expected_writer_fence,
        issued_at_unix: mutation.issued_at_unix,
        expires_at_unix: mutation.expires_at_unix,
        renewal_revision: 0,
        phase: PrivateOramMutationLeasePhase::Preparing,
    };
    validate_preparing_lease(
        coordinator_peer_id,
        validated.mutation_bundle(),
        &mutation_digest,
        &lease,
    )?;
    validate_expected_consensus_old_state(validated.mutation_bundle(), &lease, current_state)?;
    Ok(PrivateOramMutationAdmissionPlanV2 {
        lease,
        mutation_bundle: validated.mutation_bundle().clone(),
        expected_old_state: current_state.clone(),
        expected_new_state,
        mutation_digest,
    })
}

pub fn derive_private_oram_mutation_admitted_recovery_plan_v2(
    active_lease: &PrivateOramMutationLease,
    current_state: &PrivateOramConsensusCollectionStateV2,
    recovery_manifest: &PrivateOramMutationAllOwnersPrestagedV2,
    validated: &PrivateOramValidatedOwnerPrepareV1,
) -> Result<PrivateOramMutationAdmissionPlanV2, PrivateOramMutationJournalError> {
    if !matches!(
        active_lease.phase,
        PrivateOramMutationLeasePhase::ConsensusCommitted { .. }
    ) || active_lease.generation == 0
        || active_lease.writer_fence == 0
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let (package, expected_old_state) = recovery_manifest.coordinator_recovery_envelope()?;
    if package.owner_prepare.mutation_bundle != *validated.mutation_bundle() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let previous_generation = active_lease
        .generation
        .checked_sub(1)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let previous_fence = active_lease
        .writer_fence
        .checked_sub(1)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let previous_slot = PrivateOramMutationLeaseSlotV2 {
        version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
        generation: previous_generation,
        active: None,
        last_clear: None,
        max_writer_fence: previous_fence,
    };
    let plan = derive_private_oram_mutation_admission_plan_v2(
        active_lease.owner_peer_id,
        active_lease.generation,
        active_lease.writer_fence,
        &previous_slot,
        expected_old_state,
        validated,
    )?;
    let mut expected_active_lease = active_lease.clone();
    expected_active_lease.phase = PrivateOramMutationLeasePhase::Preparing;
    if plan.lease != expected_active_lease || plan.expected_new_state != *current_state {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    recovery_manifest.validate_admission_plan(&plan)?;
    Ok(plan)
}

impl Debug for PrivateOramMutationRecoveryMaterialV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationRecoveryMaterialV2")
            .field("immutable_manifest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationRecoveryMaterialV2 {
    pub fn immutable_manifest(&self) -> &PrivateOramImmutableManifestBundleV2 {
        &self.immutable_manifest
    }

    pub fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }
}

impl Debug for PrivateOramMutationJournal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournal")
            .field("root", &"[redacted]")
            .field("expected_owner_signing_key_id", &"[redacted]")
            .field("owner_public_key", &"[redacted]")
            .field("owner_recovery_parent_bridge", &"[redacted]")
            .field("owner_recovery_parent_verifier", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationJournal {
    pub fn new(
        collection_path: &Path,
        expected_owner_signing_key_id: impl Into<String>,
        owner_public_key: Vec<u8>,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let expected_owner_signing_key_id = expected_owner_signing_key_id.into();
        if expected_owner_signing_key_id.is_empty()
            || expected_owner_signing_key_id.len() > 256
            || owner_public_key.len() != 32
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "signature_verification",
            ));
        }
        let (owner_recovery_parent_bridge, owner_recovery_parent_verifier) =
            new_private_oram_owner_recovery_parent_bridge_v1();
        Ok(Self {
            root: collection_path.join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR),
            expected_owner_signing_key_id,
            owner_public_key,
            owner_recovery_parent_bridge,
            owner_recovery_parent_verifier,
        })
    }

    /// Reopens the canonical parent journal and derives the exact sequence-3 readiness proposal.
    /// Callers can supply only owner-signed install evidence; the parent watermark itself is never
    /// accepted over an API boundary.
    pub fn recovery_readiness_proposal_v2(
        &self,
        activation_authority: PrivateOramActivationAuthorityLocatorV1,
        owner_evidence: Vec<PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2>,
    ) -> Result<PrivateOramMutationRecoveryReadinessProposalV2, PrivateOramMutationJournalError>
    {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let point_stage = derive_private_oram_mutation_parent_watermark_at_sequence_v2(
            &snapshot,
            PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence(),
        )?;
        let expectation = derive_private_oram_mutation_recovery_capsules_ready_v2(
            &point_stage,
            activation_authority,
            owner_evidence,
        )?;
        let key = PrivateOramMutationKey {
            collection_id: snapshot
                .validated_descriptor()
                .mutation_bundle
                .mutation
                .collection_id
                .clone(),
        };
        Ok(PrivateOramMutationRecoveryReadinessProposalV2 { key, expectation })
    }

    pub fn begin(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        let descriptor = self.build_descriptor(
            coordinator_peer_id,
            owner_peer_ids,
            mutation_bundle,
            preparing_lease,
            expected_consensus_old_state,
        )?;
        self.ensure_root_layout()?;
        let _lock = self.acquire_lock()?;
        if path_entry_exists(&self.active_path())? {
            let current = self.load_locked()?;
            if current.descriptor == descriptor {
                sync_directory(&self.root)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                return Ok(current);
            }
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }

        let mut state = PrivateOramMutationJournalStateV1 {
            version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
            sequence: PrivateOramMutationJournalPhaseV1::LeaseAcquired.sequence(),
            phase: PrivateOramMutationJournalPhaseV1::LeaseAcquired,
            previous_record_digest: None,
            owner_prepares: Vec::new(),
            point_stage: None,
            consensus: None,
            remote_finalizations: Vec::new(),
            local_finalizations: Vec::new(),
            record_digest: String::new(),
        };
        state.record_digest = state_record_digest(&descriptor.descriptor_digest, &state)?;
        validate_state(&descriptor, &state)?;

        let staging = tempfile::Builder::new()
            .prefix("begin-")
            .tempdir_in(self.temp_path())
            .map_err(PrivateOramMutationJournalError::Io)?;
        set_private_directory_permissions(staging.path())?;
        create_private_directory(&staging.path().join(ACTIVE_TEMP_DIR))?;
        write_new_json_private(
            &staging.path().join(DESCRIPTOR_FILE),
            &descriptor,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_json_private(&staging.path().join(STATE_FILE), &state, MAX_STATE_BYTES)?;
        sync_directory(staging.path())?;

        let staging_path = staging.keep();
        match fs::rename(&staging_path, self.active_path()) {
            Ok(()) => {}
            Err(error) => {
                if path_entry_exists(&self.active_path())? {
                    let current = self.load_locked()?;
                    if current.descriptor == descriptor && current.state == state {
                        sync_directory(&self.root)?;
                        return Ok(current);
                    }
                }
                return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                    PrivateOramMutationJournalError::ConcurrentMutation
                } else {
                    PrivateOramMutationJournalError::Indeterminate
                });
            }
        }
        sync_directory(&self.root).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        self.load_locked()
    }

    pub fn load(
        &self,
    ) -> Result<Option<PrivateOramMutationJournalSnapshotV1>, PrivateOramMutationJournalError> {
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let _lock = self.acquire_lock()?;
        if !path_entry_exists(&self.active_path())? {
            return Ok(None);
        }
        self.load_locked().map(Some)
    }

    fn validated_reconcile_context(
        &self,
        consensus_state: &PrivateOramConsensusCollectionStateV2,
        lease_slot: &PrivateOramMutationLeaseSlotV2,
    ) -> Result<PrivateOramValidatedMutationReconcileContextV1, PrivateOramMutationJournalError>
    {
        let snapshot = self
            .load()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        validated_reconcile_context_for_snapshot(snapshot, consensus_state, lease_slot)
    }

    #[allow(
        dead_code,
        reason = "D3-B3 coordinator consumes only an atomically captured consensus snapshot"
    )]
    pub(super) fn validated_reconcile_snapshot(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
    ) -> Result<PrivateOramValidatedMutationReconcileContextV1, PrivateOramMutationJournalError>
    {
        self.validated_reconcile_context(
            reconcile_snapshot.consensus_state(),
            reconcile_snapshot.lease_slot(),
        )
    }

    #[allow(
        dead_code,
        reason = "D3-B3 restart owner authority is consumed by the dormant owner RPC bridge"
    )]
    pub(super) fn validated_owner_recovery_authority(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_owner_peer_id: PeerId,
    ) -> Result<PrivateOramValidatedOwnerRecoveryAuthorityV1, PrivateOramMutationJournalError> {
        let context = self.validated_reconcile_snapshot(reconcile_snapshot)?;
        build_owner_recovery_authority(&context, authenticated_owner_peer_id)
    }

    #[allow(
        dead_code,
        reason = "D3-B3 mutating recovery bridge is wired after writer-wide store locking"
    )]
    fn with_live_owner_recovery_authority_v1<R>(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_owner_peer_id: PeerId,
        action: impl for<'lock> FnOnce(&PrivateOramLiveOwnerRecoveryAuthorityV1<'lock>) -> R,
    ) -> Result<R, PrivateOramMutationJournalError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let parent_lock = self.acquire_lock()?;
        let snapshot = self.load_pinned_locked(&parent_lock)?;
        let context = validated_reconcile_context_for_snapshot(
            snapshot,
            reconcile_snapshot.consensus_state(),
            reconcile_snapshot.lease_slot(),
        )?;
        let expected_parent = context.snapshot.clone();
        let live = PrivateOramLiveOwnerRecoveryAuthorityV1::new(
            build_owner_recovery_authority(&context, authenticated_owner_peer_id)?,
            &parent_lock,
            &self.owner_recovery_parent_bridge,
            &self.owner_recovery_parent_verifier,
        );
        let output = action(&live);
        drop(live);
        let revalidated_parent = self.load_pinned_locked(&parent_lock)?;
        if revalidated_parent != expected_parent {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        parent_lock.validate_root_identity()?;
        drop(parent_lock);
        Ok(output)
    }

    #[allow(
        dead_code,
        reason = "D3-B3 paired recovery is wired before the dormant owner RPC bridge"
    )]
    pub(super) fn recover_live_owner_pair_v1(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        CollectionResult<PrivateOramValidatedOwnerRecoveryOutcomeV1>,
        PrivateOramMutationJournalError,
    > {
        self.validate_owner_recovery_resources_v1(&resources)?;
        self.with_live_owner_recovery_authority_v1(
            reconcile_snapshot,
            authenticated_owner_peer_id,
            |live| live.recover_pair_v1(resources),
        )
    }

    fn validate_owner_recovery_resources_v1(
        &self,
        resources: &PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let collection_path = resources
            .hnsw_store
            .root_path()
            .parent()
            .and_then(Path::parent)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let result_collection_path = resources
            .result_store
            .root_path()
            .parent()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if result_collection_path != collection_path
            || self.root != collection_path.join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        Ok(())
    }

    pub fn mark_owners_prepared(
        &self,
        owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            validate_owner_prepares(descriptor, &owner_prepares)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::OwnersPrepared.sequence()
            {
                return (current.owner_prepares == owner_prepares)
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::LeaseAcquired {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.owner_prepares = owner_prepares;
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::OwnersPrepared,
            )))
        })
    }

    pub fn validated_point_stage_parent(
        &self,
    ) -> Result<PrivateOramValidatedPointStageParentV1, PrivateOramMutationJournalError> {
        let snapshot = self
            .load()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let (phase, owners_prepared_record_digest, expected_child_descriptor_digest) =
            match (&snapshot.state.phase, snapshot.state.point_stage.as_ref()) {
                (PrivateOramMutationJournalPhaseV1::OwnersPrepared, None) => (
                    PrivateOramValidatedPointStageParentPhaseV1::OwnersPrepared,
                    snapshot.state.record_digest.clone(),
                    None,
                ),
                (
                    PrivateOramMutationJournalPhaseV1::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
                        child_descriptor_digest,
                        parent_owners_prepared_record_digest,
                        ..
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    Some(child_descriptor_digest.clone()),
                ),
                (
                    PrivateOramMutationJournalPhaseV1::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
                        parent_owners_prepared_record_digest,
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    None,
                ),
                _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
            };
        Ok(PrivateOramValidatedPointStageParentV1 {
            descriptor: snapshot.descriptor,
            owners_prepared_record_digest,
            phase,
            expected_child_descriptor_digest,
        })
    }

    pub fn mark_private_point_stage_durable(
        &self,
        durable_stage: &PrivateOramDurablePointStageTokenV1,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        let point_stage = PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id: durable_stage.point_id().to_string(),
            staged_insert_sha256: durable_stage.frame_sha256().to_string(),
            canonical_point_id_digest: durable_stage.canonical_point_id_digest().to_string(),
            child_descriptor_digest: durable_stage.child_descriptor_digest().to_string(),
            parent_owners_prepared_record_digest: durable_stage
                .parent_owners_prepared_record_digest()
                .to_string(),
        };
        self.mark_point_stage_durable_from_tip(
            durable_stage.parent_descriptor_digest(),
            durable_stage.parent_owners_prepared_record_digest(),
            point_stage,
        )
    }

    pub fn mark_no_server_point_stage_durable(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.mark_point_stage_durable_from_tip(
            &parent.descriptor.descriptor_digest,
            &parent.owners_prepared_record_digest,
            PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
                parent_owners_prepared_record_digest: parent.owners_prepared_record_digest.clone(),
            },
        )
    }

    fn mark_point_stage_durable_from_tip(
        &self,
        expected_parent_descriptor_digest: &str,
        expected_owners_prepared_record_digest: &str,
        point_stage: PrivateOramMutationPointStageEvidenceV1,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            if descriptor.descriptor_digest != expected_parent_descriptor_digest {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            validate_point_stage(descriptor, &current.owner_prepares, &point_stage)?;
            if current.phase == PrivateOramMutationJournalPhaseV1::PointStageDurable {
                return (current.point_stage.as_ref() == Some(&point_stage))
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::OwnersPrepared
                || current.record_digest != expected_owners_prepared_record_digest
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.point_stage = Some(point_stage);
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::PointStageDurable,
            )))
        })
    }

    pub fn mark_consensus_committed(
        &self,
        committed_lease: &PrivateOramMutationLease,
        committed_state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            let consensus =
                derive_consensus_evidence(descriptor, committed_lease, committed_state)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::ConsensusCommitted.sequence()
            {
                return (current.consensus.as_ref() == Some(&consensus))
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::PointStageDurable {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.consensus = Some(consensus);
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::ConsensusCommitted,
            )))
        })
    }

    pub fn mark_remotes_finalized(
        &self,
        remote_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            validate_finalizations(descriptor, current, &remote_finalizations, false)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::RemotesFinalized.sequence()
            {
                return (current.remote_finalizations == remote_finalizations)
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::ConsensusCommitted {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.remote_finalizations = remote_finalizations;
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::RemotesFinalized,
            )))
        })
    }

    pub fn mark_local_finalized(
        &self,
        local_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            validate_finalizations(descriptor, current, &local_finalizations, true)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::LocalFinalized.sequence()
            {
                return (current.local_finalizations == local_finalizations)
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::RemotesFinalized {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.local_finalizations = local_finalizations;
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::LocalFinalized,
            )))
        })
    }

    pub fn mark_complete(
        &self,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|_, current| {
            if current.phase == PrivateOramMutationJournalPhaseV1::Complete {
                return Ok(None);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::LocalFinalized {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            Ok(Some((
                current.clone(),
                PrivateOramMutationJournalPhaseV1::Complete,
            )))
        })
    }

    fn build_descriptor(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalDescriptorV1, PrivateOramMutationJournalError> {
        let verification = self.signature_verification();
        validate_private_oram_append_mutation_v1_shape(&mutation_bundle.mutation)?;
        validate_private_oram_signed_state_v2_signature(
            &mutation_bundle.mutation.old_state.state,
            Some(&mutation_bundle.mutation.old_state.signature),
            verification,
        )?;
        validate_private_oram_signed_state_v2_signature(
            &mutation_bundle.mutation.new_state.state,
            Some(&mutation_bundle.mutation.new_state.signature),
            verification,
        )?;
        validate_private_oram_append_mutation_v1_signature(
            &mutation_bundle.mutation,
            Some(&mutation_bundle.signature),
            verification,
        )?;
        let mutation_digest = private_oram_append_mutation_v1_digest(&mutation_bundle.mutation)?;
        validate_preparing_lease(
            coordinator_peer_id,
            &mutation_bundle,
            &mutation_digest,
            &preparing_lease,
        )?;
        validate_expected_consensus_old_state(
            &mutation_bundle,
            &preparing_lease,
            &expected_consensus_old_state,
        )?;
        let owner_requirements = derive_owner_requirements(&mutation_bundle, owner_peer_ids)?;
        if !owner_requirements
            .iter()
            .any(|requirement| requirement.peer_id == coordinator_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "coordinator_peer_id",
            ));
        }
        let mut descriptor = PrivateOramMutationJournalDescriptorV1 {
            version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
            coordinator_peer_id,
            mutation_digest,
            mutation_bundle,
            preparing_lease,
            expected_consensus_old_state,
            owner_requirements,
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        validate_descriptor(&descriptor, verification)?;
        Ok(descriptor)
    }

    fn validate_immutable_manifest_for_descriptor(
        &self,
        immutable_manifest: &PrivateOramImmutableManifestBundleV2,
        descriptor: &PrivateOramMutationJournalDescriptorV1,
    ) -> Result<(), PrivateOramMutationJournalError> {
        validate_private_oram_immutable_manifest_v2_signature(
            &immutable_manifest.manifest,
            Some(&immutable_manifest.signature),
            self.signature_verification(),
        )?;
        let mutation = &descriptor.mutation_bundle.mutation;
        if private_oram_immutable_manifest_v2_digest(&immutable_manifest.manifest)?
            != mutation.manifest_digest
            || immutable_manifest.manifest.collection_id != mutation.collection_id
            || immutable_manifest.manifest.owner_signing_key_id != mutation.owner_signing_key_id
            || immutable_manifest.manifest.indexes.len() != mutation.old_state.state.indexes.len()
            || !immutable_manifest
                .manifest
                .indexes
                .iter()
                .zip(&mutation.old_state.state.indexes)
                .all(|(manifest_index, state_index)| {
                    manifest_index.kind() == state_index.kind
                        && manifest_index.index_name == state_index.index_name
                })
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "immutable_manifest",
            ));
        }
        Ok(())
    }

    fn transition<F>(
        &self,
        update: F,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError>
    where
        F: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV1,
        ) -> Result<
            Option<(
                PrivateOramMutationJournalStateV1,
                PrivateOramMutationJournalPhaseV1,
            )>,
            PrivateOramMutationJournalError,
        >,
    {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let _lock = self.acquire_lock()?;
        let current = self.load_locked()?;
        let Some((mut next, phase)) = update(&current.descriptor, &current.state)? else {
            sync_directory(&self.active_path())
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            return Ok(current);
        };
        if phase.sequence() != current.state.sequence + 1 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        next.version = PRIVATE_ORAM_MUTATION_JOURNAL_VERSION;
        next.sequence = phase.sequence();
        next.phase = phase;
        next.previous_record_digest = Some(current.state.record_digest.clone());
        next.record_digest = state_record_digest(&current.descriptor.descriptor_digest, &next)?;
        validate_state(&current.descriptor, &next)?;
        let previous_file_sha256 = file_sha256(&self.state_path(), MAX_STATE_BYTES)?;
        write_json_atomic_classified(
            &self.state_path(),
            &self.active_temp_path(),
            &next,
            previous_file_sha256,
            &FilesystemJournalSaveBackend,
        )?;
        Ok(PrivateOramMutationJournalSnapshotV1 {
            descriptor: current.descriptor,
            state: next,
        })
    }

    fn load_locked(
        &self,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.load_locked_at_root(&self.root)
    }

    fn load_pinned_locked(
        &self,
        lock: &PrivateOramMutationJournalLock,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.load_locked_at_root(&lock.pinned_root_path())
    }

    fn load_locked_at_root(
        &self,
        root: &Path,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        let active = root.join(ACTIVE_DIR);
        let active_temp = active.join(ACTIVE_TEMP_DIR);
        validate_private_directory(&active)?;
        validate_private_directory(&active_temp)?;
        let descriptor: PrivateOramMutationJournalDescriptorV1 =
            read_json_private(&active.join(DESCRIPTOR_FILE), MAX_DESCRIPTOR_BYTES)?;
        validate_descriptor(&descriptor, self.signature_verification())?;
        let state: PrivateOramMutationJournalStateV1 =
            read_json_private(&active.join(STATE_FILE), MAX_STATE_BYTES)?;
        validate_state(&descriptor, &state)?;
        Ok(PrivateOramMutationJournalSnapshotV1 { descriptor, state })
    }

    fn signature_verification(&self) -> PrivateOramSignatureVerification<'_> {
        PrivateOramSignatureVerification {
            expected_key_id: &self.expected_owner_signing_key_id,
            public_key: &self.owner_public_key,
        }
    }

    fn ensure_root_layout(&self) -> Result<(), PrivateOramMutationJournalError> {
        let collection_path = self
            .root
            .parent()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let metadata =
            fs::symlink_metadata(collection_path).map_err(PrivateOramMutationJournalError::Io)?;
        if !metadata.file_type().is_dir() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        create_private_directory(&self.root)?;
        create_private_directory(&self.temp_path())
    }

    fn acquire_lock(
        &self,
    ) -> Result<PrivateOramMutationJournalLock, PrivateOramMutationJournalError> {
        let root = open_pinned_private_directory(&self.root)?;
        let path = pinned_directory_entry_path(&root, &self.root, LOCK_FILE)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        secure_open_options(&mut options, true);
        let file = options
            .open(&path)
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_file_metadata(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            0,
        )?;
        FileExt::lock_exclusive(file.file()).map_err(PrivateOramMutationJournalError::Io)?;
        let current = fs::symlink_metadata(&path).map_err(PrivateOramMutationJournalError::Io)?;
        ensure_same_file(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &current,
        )?;
        validate_private_file_metadata(&current, 0)?;
        file.sync_all()
            .map_err(PrivateOramMutationJournalError::Io)?;
        root.validate_at_path(&self.root)?;
        sync_directory(&root.pinned_path(&self.root))?;
        Ok(PrivateOramMutationJournalLock {
            _file: file,
            root,
            root_path: self.root.clone(),
        })
    }

    fn active_path(&self) -> PathBuf {
        self.root.join(ACTIVE_DIR)
    }

    fn temp_path(&self) -> PathBuf {
        self.root.join(TEMP_DIR)
    }

    fn active_temp_path(&self) -> PathBuf {
        self.active_path().join(ACTIVE_TEMP_DIR)
    }

    fn state_path(&self) -> PathBuf {
        self.active_path().join(STATE_FILE)
    }
}

struct PinnedPrivateDirectory {
    directory: File,
}

impl PinnedPrivateDirectory {
    fn pinned_path(&self, fallback: &Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let _ = fallback;
            PathBuf::from("/proc/self/fd").join(self.directory.file().as_raw_fd().to_string())
        }
        #[cfg(not(target_os = "linux"))]
        {
            fallback.to_path_buf()
        }
    }

    fn validate_at_path(&self, path: &Path) -> Result<(), PrivateOramMutationJournalError> {
        let opened = self
            .directory
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_directory_metadata(&opened)?;
        let current = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_directory_metadata(&current)?;
        ensure_same_directory(&opened, &current)
    }
}

fn open_pinned_private_directory(
    path: &Path,
) -> Result<PinnedPrivateDirectory, PrivateOramMutationJournalError> {
    let before = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    let directory = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    let opened = directory
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_directory_metadata(&opened)?;
    ensure_same_directory(&before, &opened)?;
    let pinned = PinnedPrivateDirectory { directory };
    pinned.validate_at_path(path)?;
    Ok(pinned)
}

fn pinned_directory_entry_path(
    directory: &PinnedPrivateDirectory,
    fallback_root: &Path,
    name: &str,
) -> Result<PathBuf, PrivateOramMutationJournalError> {
    if name.is_empty() || Path::new(name).components().count() != 1 || matches!(name, "." | "..") {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(directory.pinned_path(fallback_root).join(name))
}

fn ensure_same_directory(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if !before.file_type().is_dir() || !after.file_type().is_dir() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

struct PrivateOramMutationJournalLock {
    _file: File,
    root: PinnedPrivateDirectory,
    root_path: PathBuf,
}

impl PrivateOramMutationJournalLock {
    fn pinned_root_path(&self) -> PathBuf {
        self.root.pinned_path(&self.root_path)
    }

    fn validate_root_identity(&self) -> Result<(), PrivateOramMutationJournalError> {
        self.root.validate_at_path(&self.root_path)
    }
}

fn validate_preparing_lease(
    coordinator_peer_id: PeerId,
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    mutation_digest: &str,
    lease: &PrivateOramMutationLease,
) -> Result<(), PrivateOramMutationJournalError> {
    let mutation = &mutation_bundle.mutation;
    if !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing)
        || lease.generation == 0
        || lease.owner_peer_id != coordinator_peer_id
        || lease.collection_id != mutation.collection_id
        || lease.mutation_id != mutation.mutation_id
        || lease.signed_mutation_digest != mutation_digest
        || lease.base_state_sequence != mutation.old_state.state.state_sequence
        || lease.writer_lease_digest != mutation.writer_lease_digest
        || lease.writer_fence != mutation.writer_fence
        || lease.issued_at_unix > mutation.issued_at_unix
        || lease.expires_at_unix < mutation.expires_at_unix
        || lease.issued_at_unix == 0
        || lease.expires_at_unix <= lease.issued_at_unix
        || !is_sha256_digest(&lease.transition_digest)
        || !is_sha256_digest(&lease.base_record_digest)
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "preparing_lease",
        ));
    }
    Ok(())
}

fn validate_expected_consensus_old_state(
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    preparing_lease: &PrivateOramMutationLease,
    consensus: &PrivateOramConsensusCollectionStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let signed = &mutation_bundle.mutation.old_state.state;
    let signed_state_digest = private_oram_signed_state_v2_digest(signed)?;
    let consensus_record_digest =
        canonical_private_oram_consensus_state_record_digest(consensus)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("consensus_old_state"))?;
    if consensus.collection_id != signed.collection_id
        || consensus.manifest_digest != signed.manifest_digest
        || consensus.layout_generation != signed.layout_generation
        || consensus.layout_digest != signed.layout_digest
        || consensus.state_sequence != signed.state_sequence
        || consensus.signed_state_digest != signed_state_digest
        || consensus.client_state_digest != signed.client_state_digest
        || consensus.indexes != consensus_indexes_from_signed(signed)
        || consensus_record_digest != preparing_lease.base_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "consensus_old_state",
        ));
    }
    Ok(())
}

fn consensus_indexes_from_signed(
    state: &PrivateOramSignedStateV2,
) -> Vec<PrivateOramConsensusCollectionIndexStateV2> {
    state
        .indexes
        .iter()
        .map(|index| PrivateOramConsensusCollectionIndexStateV2 {
            index_kind: match index.kind {
                PrivateOramIndexKindV2::Hnsw => PrivateOramIndexKind::Hnsw,
                PrivateOramIndexKindV2::Result => PrivateOramIndexKind::ResultPayload,
            },
            index_name: match index.kind {
                PrivateOramIndexKindV2::Hnsw => index.index_name.clone(),
                PrivateOramIndexKindV2::Result => String::new(),
            },
            epoch: PrivateOramConsensusEpoch {
                index_epoch: index.index_epoch,
                root_hash: index.root_hash.clone(),
                writeback_digest: Some(index.last_writeback_digest.clone()),
            },
            logical_count: index.logical_count,
            dummy_count: index.dummy_count,
        })
        .collect()
}

fn derive_owner_requirements(
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    owner_peer_ids: &[PeerId],
) -> Result<Vec<PrivateOramMutationOwnerRequirementV1>, PrivateOramMutationJournalError> {
    let requirement_count = owner_peer_ids
        .len()
        .checked_mul(mutation_bundle.mutation.writebacks.len())
        .ok_or(PrivateOramMutationJournalError::InvalidInput(
            "owner_peer_ids",
        ))?;
    if owner_peer_ids.is_empty()
        || owner_peer_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || mutation_bundle.mutation.writebacks.is_empty()
        || requirement_count > MAX_OWNER_REQUIREMENTS
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "owner_peer_ids",
        ));
    }
    let mutation = &mutation_bundle.mutation;
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    if old.indexes.len() != mutation.writebacks.len()
        || new.indexes.len() != mutation.writebacks.len()
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "mutation_indexes",
        ));
    }
    let mut index_requirements = Vec::with_capacity(mutation.writebacks.len());
    for ((old_index, new_index), writeback) in old
        .indexes
        .iter()
        .zip(&new.indexes)
        .zip(&mutation.writebacks)
    {
        if old_index.kind != writeback.kind
            || new_index.kind != writeback.kind
            || old_index.index_name != writeback.index_name
            || new_index.index_name != writeback.index_name
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "mutation_indexes",
            ));
        }
        let writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &mutation.collection_id,
                manifest_digest: &mutation.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: &old_index.root_hash,
                new_root_hash: &new_index.root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })?;
        if new_index.last_writeback_digest != writeback_digest {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "writeback_digest",
            ));
        }
        index_requirements.push((old_index, new_index, writeback_digest));
    }

    let mut requirements = Vec::with_capacity(requirement_count);
    for peer_id in owner_peer_ids {
        for (old_index, new_index, writeback_digest) in &index_requirements {
            requirements.push(PrivateOramMutationOwnerRequirementV1 {
                peer_id: *peer_id,
                kind: old_index.kind,
                index_name: old_index.index_name.clone(),
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: old_index.root_hash.clone(),
                new_root_hash: new_index.root_hash.clone(),
                writeback_digest: writeback_digest.clone(),
            });
        }
    }
    requirements.sort_by(requirement_order);
    Ok(requirements)
}

fn validate_descriptor(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    verification: PrivateOramSignatureVerification<'_>,
) -> Result<(), PrivateOramMutationJournalError> {
    if descriptor.version != PRIVATE_ORAM_MUTATION_JOURNAL_VERSION
        || descriptor.owner_requirements.is_empty()
        || !is_sha256_digest(&descriptor.mutation_digest)
        || !is_sha256_digest(&descriptor.descriptor_digest)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_private_oram_append_mutation_v1_shape(&descriptor.mutation_bundle.mutation)?;
    validate_private_oram_signed_state_v2_signature(
        &descriptor.mutation_bundle.mutation.old_state.state,
        Some(&descriptor.mutation_bundle.mutation.old_state.signature),
        verification,
    )?;
    validate_private_oram_signed_state_v2_signature(
        &descriptor.mutation_bundle.mutation.new_state.state,
        Some(&descriptor.mutation_bundle.mutation.new_state.signature),
        verification,
    )?;
    validate_private_oram_append_mutation_v1_signature(
        &descriptor.mutation_bundle.mutation,
        Some(&descriptor.mutation_bundle.signature),
        verification,
    )?;
    if descriptor.mutation_digest
        != private_oram_append_mutation_v1_digest(&descriptor.mutation_bundle.mutation)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_preparing_lease(
        descriptor.coordinator_peer_id,
        &descriptor.mutation_bundle,
        &descriptor.mutation_digest,
        &descriptor.preparing_lease,
    )?;
    validate_expected_consensus_old_state(
        &descriptor.mutation_bundle,
        &descriptor.preparing_lease,
        &descriptor.expected_consensus_old_state,
    )?;
    expected_consensus_new_state(descriptor)?;
    if descriptor.descriptor_digest != descriptor_digest(descriptor)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if descriptor
        .owner_requirements
        .windows(2)
        .any(|pair| requirement_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let owner_peer_ids = descriptor
        .owner_requirements
        .iter()
        .map(|requirement| requirement.peer_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if derive_owner_requirements(&descriptor.mutation_bundle, &owner_peer_ids)?
        != descriptor.owner_requirements
        || !owner_peer_ids.contains(&descriptor.coordinator_peer_id)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(super) fn validate_state(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.version != PRIVATE_ORAM_MUTATION_JOURNAL_VERSION
        || state.sequence != state.phase.sequence()
        || state.record_digest != state_record_digest(&descriptor.descriptor_digest, state)?
        || (state.sequence == 1) != state.previous_record_digest.is_none()
        || state
            .previous_record_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256_digest(digest))
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let rank = state.phase.sequence();
    if (rank >= 2) == state.owner_prepares.is_empty()
        || (rank >= 3) != state.point_stage.is_some()
        || (rank >= 4) != state.consensus.is_some()
        || (rank < 5 && !state.remote_finalizations.is_empty())
        || (rank < 6 && !state.local_finalizations.is_empty())
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if rank >= 2 {
        validate_owner_prepares(descriptor, &state.owner_prepares)?;
    }
    if let Some(point_stage) = &state.point_stage {
        validate_point_stage(descriptor, &state.owner_prepares, point_stage)?;
    }
    if let Some(consensus) = &state.consensus {
        validate_consensus_evidence_shape(descriptor, consensus)?;
    }
    if rank >= 5 {
        validate_finalizations(descriptor, state, &state.remote_finalizations, false)?;
    }
    if rank >= 6 {
        validate_finalizations(descriptor, state, &state.local_finalizations, true)?;
    }
    Ok(())
}

pub(super) fn validate_owner_prepares(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    evidence: &[PrivateOramMutationOwnerPrepareEvidenceV1],
) -> Result<(), PrivateOramMutationJournalError> {
    if evidence.len() != descriptor.owner_requirements.len()
        || evidence
            .windows(2)
            .any(|pair| prepare_evidence_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (requirement, evidence) in descriptor.owner_requirements.iter().zip(evidence) {
        if !same_owner_key(
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
            evidence.peer_id,
            evidence.kind,
            &evidence.index_name,
        ) || !is_sha256_digest(&evidence.prepared_journal_digest)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_point_stage(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    evidence: &PrivateOramMutationPointStageEvidenceV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let mutation = &descriptor.mutation_bundle.mutation;
    let expected_parent_record_digest = owners_prepared_record_digest(descriptor, owner_prepares)?;
    let (kind, digest) = match evidence {
        PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            child_descriptor_digest,
            parent_owners_prepared_record_digest,
        } => {
            if parent_owners_prepared_record_digest != &expected_parent_record_digest
                || !is_sha256_digest(staged_insert_sha256)
                || !is_sha256_digest(canonical_point_id_digest)
                || !is_sha256_digest(child_descriptor_digest)
                || canonical_point_id_digest != &private_oram_point_id_digest(point_id)?
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            (
                PrivateOramPointOperationKindV1::VisiblePointRecord,
                private_oram_visible_point_record_v1_digest(
                    &mutation.collection_id,
                    &mutation.manifest_digest,
                    &mutation.mutation_id,
                    PrivateOramVisiblePointRecordV1 {
                        point_id,
                        staged_insert_sha256,
                    },
                )?,
            )
        }
        PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        } => {
            if parent_owners_prepared_record_digest != &expected_parent_record_digest {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            (
                PrivateOramPointOperationKindV1::NoServerPointRecord,
                private_oram_no_server_point_record_v1_digest(
                    &mutation.collection_id,
                    &mutation.manifest_digest,
                    &mutation.mutation_id,
                )?,
            )
        }
    };
    if mutation.point_operation_kind != kind || mutation.point_operation_digest != digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn owners_prepared_record_digest(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
) -> Result<String, PrivateOramMutationJournalError> {
    let lease_acquired_record_digest = lease_acquired_record_digest(descriptor)?;
    let mut owners_prepared = PrivateOramMutationJournalStateV1 {
        version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
        sequence: PrivateOramMutationJournalPhaseV1::OwnersPrepared.sequence(),
        phase: PrivateOramMutationJournalPhaseV1::OwnersPrepared,
        previous_record_digest: Some(lease_acquired_record_digest),
        owner_prepares: owner_prepares.to_vec(),
        point_stage: None,
        consensus: None,
        remote_finalizations: Vec::new(),
        local_finalizations: Vec::new(),
        record_digest: String::new(),
    };
    owners_prepared.record_digest =
        state_record_digest(&descriptor.descriptor_digest, &owners_prepared)?;
    Ok(owners_prepared.record_digest)
}

fn lease_acquired_record_digest(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let lease_acquired = PrivateOramMutationJournalStateV1 {
        version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
        sequence: PrivateOramMutationJournalPhaseV1::LeaseAcquired.sequence(),
        phase: PrivateOramMutationJournalPhaseV1::LeaseAcquired,
        previous_record_digest: None,
        owner_prepares: Vec::new(),
        point_stage: None,
        consensus: None,
        remote_finalizations: Vec::new(),
        local_finalizations: Vec::new(),
        record_digest: String::new(),
    };
    state_record_digest(&descriptor.descriptor_digest, &lease_acquired)
}

struct PrivateOramOwnerRecoveryPhaseDigests {
    lease_acquired: String,
    owners_prepared: String,
}

struct PrivateOramOwnerRecoveryPhaseDigestsV1(PrivateOramOwnerRecoveryPhaseDigests);

struct PrivateOramOwnerRecoveryPhaseDigestsV2(PrivateOramOwnerRecoveryPhaseDigests);

fn owner_recovery_phase_digests_v1(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
) -> Result<PrivateOramOwnerRecoveryPhaseDigestsV1, PrivateOramMutationJournalError> {
    Ok(PrivateOramOwnerRecoveryPhaseDigestsV1(
        PrivateOramOwnerRecoveryPhaseDigests {
            lease_acquired: lease_acquired_record_digest(descriptor)?,
            owners_prepared: owners_prepared_record_digest(descriptor, owner_prepares)?,
        },
    ))
}

fn owner_recovery_phase_digests_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<PrivateOramOwnerRecoveryPhaseDigestsV2, PrivateOramMutationJournalError> {
    Ok(PrivateOramOwnerRecoveryPhaseDigestsV2(
        PrivateOramOwnerRecoveryPhaseDigests {
            lease_acquired: record_digest_at_phase_v2(
                descriptor,
                state,
                PrivateOramMutationJournalPhaseV2::LeaseAcquired,
            )?,
            owners_prepared: record_digest_at_phase_v2(
                descriptor,
                state,
                PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            )?,
        },
    ))
}

fn build_owner_recovery_authority(
    context: &PrivateOramValidatedMutationReconcileContextV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<PrivateOramValidatedOwnerRecoveryAuthorityV1, PrivateOramMutationJournalError> {
    let snapshot = &context.snapshot;
    if snapshot.state.phase.sequence()
        < PrivateOramMutationJournalPhaseV1::OwnersPrepared.sequence()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let phase_digests =
        owner_recovery_phase_digests_v1(&snapshot.descriptor, &snapshot.state.owner_prepares)?;
    build_owner_recovery_authority_with_phase_digests(
        &snapshot.descriptor,
        &snapshot.state.owner_prepares,
        &phase_digests.0,
        &context.active_lease,
        context.disposition,
        authenticated_owner_peer_id,
    )
}

pub(super) fn build_owner_recovery_authority_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<PrivateOramValidatedOwnerRecoveryAuthorityV1, PrivateOramMutationJournalError> {
    let phase_digests = owner_recovery_phase_digests_v2(descriptor, state)?;
    build_owner_recovery_authority_with_phase_digests(
        descriptor,
        &state.owner_prepares,
        &phase_digests.0,
        active_lease,
        disposition,
        authenticated_owner_peer_id,
    )
}

fn build_owner_recovery_authority_with_phase_digests(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    phase_digests: &PrivateOramOwnerRecoveryPhaseDigests,
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<PrivateOramValidatedOwnerRecoveryAuthorityV1, PrivateOramMutationJournalError> {
    let indexes = descriptor
        .owner_requirements
        .iter()
        .zip(owner_prepares)
        .filter(|(requirement, _)| requirement.peer_id == authenticated_owner_peer_id)
        .map(
            |(requirement, prepared)| PrivateOramValidatedOwnerRecoveryIndexV1 {
                requirement: requirement.clone(),
                prepared: prepared.clone(),
            },
        )
        .collect::<Vec<_>>();
    if indexes.is_empty() || indexes.len() != descriptor.mutation_bundle.mutation.writebacks.len() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let consensus_authority_record_digest = match disposition {
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
        | PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
            active_lease.base_record_digest.clone()
        }
        PrivateOramMutationReconcileDispositionV1::ExactNew => {
            let PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            } = &active_lease.phase
            else {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            };
            committed_record_digest.clone()
        }
    };
    let (expected_consensus_authority_record_digest, reconciliation_authority_digest) =
        expected_owner_recovery_authority_digest_with_phase_digests(
            descriptor,
            owner_prepares,
            phase_digests,
            active_lease,
            disposition,
            authenticated_owner_peer_id,
        )?;
    if expected_consensus_authority_record_digest != consensus_authority_record_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramValidatedOwnerRecoveryAuthorityV1 {
        owner_peer_id: authenticated_owner_peer_id,
        disposition,
        parent_descriptor_digest: descriptor.descriptor_digest.clone(),
        parent_lease_acquired_record_digest: phase_digests.lease_acquired.clone(),
        parent_owners_prepared_record_digest: phase_digests.owners_prepared.clone(),
        consensus_authority_record_digest,
        reconciliation_authority_digest,
        mutation_bundle: descriptor.mutation_bundle.clone(),
        indexes,
    })
}

fn expected_owner_recovery_authority_digest_with_phase_digests(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    phase_digests: &PrivateOramOwnerRecoveryPhaseDigests,
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<(String, String), PrivateOramMutationJournalError> {
    validate_owner_prepares(descriptor, owner_prepares)?;
    if !is_sha256_digest(&phase_digests.lease_acquired)
        || !is_sha256_digest(&phase_digests.owners_prepared)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let consensus_authority_record_digest = match (disposition, &active_lease.phase) {
        (
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision,
            PrivateOramMutationLeasePhase::Preparing,
        )
        | (
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
            PrivateOramMutationLeasePhase::AbortDecided,
        ) => active_lease.base_record_digest.clone(),
        (
            PrivateOramMutationReconcileDispositionV1::ExactNew,
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            },
        ) => committed_record_digest.clone(),
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    };
    let indexes = descriptor
        .owner_requirements
        .iter()
        .zip(owner_prepares)
        .filter(|(requirement, _)| requirement.peer_id == authenticated_owner_peer_id)
        .map(
            |(requirement, prepared)| PrivateOramValidatedOwnerRecoveryIndexV1 {
                requirement: requirement.clone(),
                prepared: prepared.clone(),
            },
        )
        .collect::<Vec<_>>();
    if indexes.is_empty() || indexes.len() != descriptor.mutation_bundle.mutation.writebacks.len() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let mut hasher = Sha256::new();
    hasher.update(OWNER_RECOVERY_AUTHORITY_DIGEST_DOMAIN);
    hash_digest(&mut hasher, &descriptor.descriptor_digest)?;
    hash_digest(&mut hasher, &phase_digests.lease_acquired)?;
    hash_digest(&mut hasher, &phase_digests.owners_prepared)?;
    hash_digest(&mut hasher, &consensus_authority_record_digest)?;
    hasher.update(authenticated_owner_peer_id.to_be_bytes());
    hasher.update([match disposition {
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => 1,
        PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => 2,
        PrivateOramMutationReconcileDispositionV1::ExactNew => 3,
    }]);

    let lease = active_lease;
    hasher.update(lease.generation.to_be_bytes());
    hash_string(&mut hasher, &lease.collection_id)?;
    hasher.update(lease.owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &lease.mutation_id)?;
    hash_digest(&mut hasher, &lease.signed_mutation_digest)?;
    hash_digest(&mut hasher, &lease.transition_digest)?;
    hash_digest(&mut hasher, &lease.base_record_digest)?;
    hasher.update(lease.base_state_sequence.to_be_bytes());
    hash_digest(&mut hasher, &lease.writer_lease_digest)?;
    hasher.update(lease.writer_fence.to_be_bytes());
    hasher.update(lease.issued_at_unix.to_be_bytes());
    match &lease.phase {
        PrivateOramMutationLeasePhase::Preparing => hasher.update([1]),
        PrivateOramMutationLeasePhase::AbortDecided => hasher.update([2]),
        PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_record_digest,
            committed_state_sequence,
            committed_signed_state_digest,
            receipt_digest,
        } => {
            hasher.update([3]);
            hash_digest(&mut hasher, committed_record_digest)?;
            hasher.update(committed_state_sequence.to_be_bytes());
            hash_digest(&mut hasher, committed_signed_state_digest)?;
            hash_digest(&mut hasher, receipt_digest)?;
        }
    }

    hash_len(&mut hasher, indexes.len())?;
    for index in indexes {
        let requirement = &index.requirement;
        hash_owner_key(
            &mut hasher,
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
        )?;
        hasher.update(requirement.old_epoch.to_be_bytes());
        hasher.update(requirement.new_epoch.to_be_bytes());
        hash_digest(&mut hasher, &requirement.old_root_hash)?;
        hash_digest(&mut hasher, &requirement.new_root_hash)?;
        hash_digest(&mut hasher, &requirement.writeback_digest)?;
        hash_digest(&mut hasher, &index.prepared.prepared_journal_digest)?;
    }
    Ok((
        consensus_authority_record_digest,
        BASE64URL_NOPAD.encode(&hasher.finalize()),
    ))
}

#[cfg(test)]
fn expected_owner_recovery_authority_digest_v1(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<(String, String), PrivateOramMutationJournalError> {
    let phase_digests = owner_recovery_phase_digests_v1(descriptor, owner_prepares)?;
    expected_owner_recovery_authority_digest_with_phase_digests(
        descriptor,
        owner_prepares,
        &phase_digests.0,
        active_lease,
        disposition,
        authenticated_owner_peer_id,
    )
}

pub(super) fn expected_owner_recovery_authority_digest_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<(String, String), PrivateOramMutationJournalError> {
    let phase_digests = owner_recovery_phase_digests_v2(descriptor, state)?;
    expected_owner_recovery_authority_digest_with_phase_digests(
        descriptor,
        &state.owner_prepares,
        &phase_digests.0,
        active_lease,
        disposition,
        authenticated_owner_peer_id,
    )
}

fn validated_reconcile_context_for_snapshot(
    snapshot: PrivateOramMutationJournalSnapshotV1,
    consensus_state: &PrivateOramConsensusCollectionStateV2,
    lease_slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<PrivateOramValidatedMutationReconcileContextV1, PrivateOramMutationJournalError> {
    let active_lease = validate_reconcile_lease_slot(&snapshot.descriptor, lease_slot)?;
    let expected_new = expected_consensus_new_state(&snapshot.descriptor)?;
    let disposition = if consensus_state == &snapshot.descriptor.expected_consensus_old_state {
        if snapshot.state.phase.sequence()
            > PrivateOramMutationJournalPhaseV1::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        match &active_lease.phase {
            PrivateOramMutationLeasePhase::Preparing => {
                PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
            }
            PrivateOramMutationLeasePhase::AbortDecided => {
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
            }
            PrivateOramMutationLeasePhase::ConsensusCommitted { .. } => {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
    } else if consensus_state == &expected_new {
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV1::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let derived =
            derive_consensus_evidence(&snapshot.descriptor, &active_lease, consensus_state)?;
        if snapshot.state.consensus.as_ref().is_some_and(|recorded| {
            recorded.committed_record_digest != derived.committed_record_digest
                || recorded.committed_state_sequence != derived.committed_state_sequence
                || recorded.committed_signed_state_digest != derived.committed_signed_state_digest
                || recorded.receipt_digest != derived.receipt_digest
                || recorded.transition_digest != derived.transition_digest
                || recorded.lease_renewal_revision > derived.lease_renewal_revision
        }) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        PrivateOramMutationReconcileDispositionV1::ExactNew
    } else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    Ok(PrivateOramValidatedMutationReconcileContextV1 {
        snapshot,
        active_lease,
        disposition,
    })
}

pub(super) fn private_oram_point_id_digest(
    point_id: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(POINT_ID_DIGEST_DOMAIN);
    hash_string(&mut hasher, point_id)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_reconcile_lease_slot(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<PrivateOramMutationLease, PrivateOramMutationJournalError> {
    let Some(active) = slot.active.as_ref() else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let preparing = &descriptor.preparing_lease;
    if slot.version != PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION
        || slot.generation != slot.max_writer_fence
        || slot.generation != active.generation
        || slot.max_writer_fence != active.writer_fence
        || slot
            .last_clear
            .as_ref()
            .is_some_and(|clear| clear.generation >= active.generation)
        || active.generation != preparing.generation
        || active.collection_id != preparing.collection_id
        || active.owner_peer_id != preparing.owner_peer_id
        || active.mutation_id != preparing.mutation_id
        || active.signed_mutation_digest != preparing.signed_mutation_digest
        || active.transition_digest != preparing.transition_digest
        || active.base_record_digest != preparing.base_record_digest
        || active.base_state_sequence != preparing.base_state_sequence
        || active.writer_lease_digest != preparing.writer_lease_digest
        || active.writer_fence != preparing.writer_fence
        || active.issued_at_unix != preparing.issued_at_unix
        || active.expires_at_unix < preparing.expires_at_unix
        || active.renewal_revision < preparing.renewal_revision
        || (active.renewal_revision == preparing.renewal_revision
            && active.expires_at_unix != preparing.expires_at_unix)
        || (active.renewal_revision > preparing.renewal_revision
            && active.expires_at_unix <= preparing.expires_at_unix)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(active.clone())
}

pub(super) fn derive_consensus_evidence(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    committed_lease: &PrivateOramMutationLease,
    committed_state: &PrivateOramConsensusCollectionStateV2,
) -> Result<PrivateOramMutationConsensusEvidenceV1, PrivateOramMutationJournalError> {
    let preparing = &descriptor.preparing_lease;
    if committed_lease.generation != preparing.generation
        || committed_lease.collection_id != preparing.collection_id
        || committed_lease.owner_peer_id != preparing.owner_peer_id
        || committed_lease.mutation_id != preparing.mutation_id
        || committed_lease.signed_mutation_digest != preparing.signed_mutation_digest
        || committed_lease.transition_digest != preparing.transition_digest
        || committed_lease.base_record_digest != preparing.base_record_digest
        || committed_lease.base_state_sequence != preparing.base_state_sequence
        || committed_lease.writer_lease_digest != preparing.writer_lease_digest
        || committed_lease.writer_fence != preparing.writer_fence
        || committed_lease.issued_at_unix != preparing.issued_at_unix
        || committed_lease.expires_at_unix < preparing.expires_at_unix
        || committed_lease.renewal_revision < preparing.renewal_revision
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramMutationLeasePhase::ConsensusCommitted {
        committed_record_digest,
        committed_state_sequence,
        committed_signed_state_digest,
        receipt_digest,
    } = &committed_lease.phase
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let expected_state = expected_consensus_new_state(descriptor)?;
    if committed_state != &expected_state {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &expected_state.last_transition
    else {
        unreachable!();
    };
    let expected_receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt)
        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let expected_record_digest =
        canonical_private_oram_consensus_state_record_digest(&expected_state)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let transition_digest = canonical_private_oram_mutation_transition_digest(
        &descriptor.expected_consensus_old_state,
        &expected_state,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    if committed_record_digest != &expected_record_digest
        || committed_state_sequence != &expected_state.state_sequence
        || committed_signed_state_digest != &expected_state.signed_state_digest
        || receipt_digest != &expected_receipt_digest
        || transition_digest != preparing.transition_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramMutationConsensusEvidenceV1 {
        committed_record_digest: expected_record_digest,
        committed_state_sequence: expected_state.state_sequence,
        committed_signed_state_digest: expected_state.signed_state_digest,
        receipt_digest: expected_receipt_digest,
        transition_digest,
        lease_renewal_revision: committed_lease.renewal_revision,
    })
}

pub(super) fn validate_consensus_evidence_shape(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    evidence: &PrivateOramMutationConsensusEvidenceV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let expected_state = expected_consensus_new_state(descriptor)?;
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &expected_state.last_transition
    else {
        unreachable!();
    };
    let expected_record_digest =
        canonical_private_oram_consensus_state_record_digest(&expected_state)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let expected_receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if evidence.committed_record_digest != expected_record_digest
        || evidence.receipt_digest != expected_receipt_digest
        || evidence.transition_digest != descriptor.preparing_lease.transition_digest
        || evidence.committed_state_sequence != expected_state.state_sequence
        || evidence.committed_signed_state_digest != expected_state.signed_state_digest
        || evidence.lease_renewal_revision < descriptor.preparing_lease.renewal_revision
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn expected_consensus_new_state(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<PrivateOramConsensusCollectionStateV2, PrivateOramMutationJournalError> {
    let mutation = &descriptor.mutation_bundle.mutation;
    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)?;
    let new_state_digest = private_oram_signed_state_v2_digest(&mutation.new_state.state)?;
    let receipt = PrivateOramMutationReceiptV2 {
        version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
        mutation_id: mutation.mutation_id.clone(),
        signed_mutation_digest: descriptor.mutation_digest.clone(),
        transition_digest: descriptor.preparing_lease.transition_digest.clone(),
        old_state_sequence: mutation.old_state.state.state_sequence,
        old_state_digest,
        new_state_sequence: mutation.new_state.state.state_sequence,
        new_state_digest: new_state_digest.clone(),
        point_operation_digest: mutation.point_operation_digest.clone(),
        writer_lease_digest: mutation.writer_lease_digest.clone(),
        writer_fence: mutation.writer_fence,
        mutation_lease_generation: descriptor.preparing_lease.generation,
    };
    let state = &mutation.new_state.state;
    let consensus = PrivateOramConsensusCollectionStateV2 {
        version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
        collection_id: state.collection_id.clone(),
        manifest_digest: state.manifest_digest.clone(),
        layout_generation: state.layout_generation,
        layout_digest: state.layout_digest.clone(),
        state_sequence: state.state_sequence,
        signed_state_digest: new_state_digest,
        indexes: consensus_indexes_from_signed(state),
        client_state_digest: state.client_state_digest.clone(),
        last_transition: PrivateOramConsensusTransitionV2::Mutation(receipt),
    };
    let transition_digest = canonical_private_oram_mutation_transition_digest(
        &descriptor.expected_consensus_old_state,
        &consensus,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    if transition_digest != descriptor.preparing_lease.transition_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(consensus)
}

fn validate_finalizations(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV1,
    evidence: &[PrivateOramMutationOwnerFinalizeEvidenceV1],
    local: bool,
) -> Result<(), PrivateOramMutationJournalError> {
    let requirements = descriptor
        .owner_requirements
        .iter()
        .filter(|requirement| (requirement.peer_id == descriptor.coordinator_peer_id) == local)
        .collect::<Vec<_>>();
    if evidence.len() != requirements.len()
        || evidence
            .windows(2)
            .any(|pair| finalize_evidence_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (requirement, finalized) in requirements.into_iter().zip(evidence) {
        let prepared = state.owner_prepares.iter().find(|prepared| {
            same_owner_key(
                requirement.peer_id,
                requirement.kind,
                &requirement.index_name,
                prepared.peer_id,
                prepared.kind,
                &prepared.index_name,
            )
        });
        if prepared.is_none_or(|prepared| {
            prepared.prepared_journal_digest != finalized.prepared_journal_digest
        }) || !same_owner_key(
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
            finalized.peer_id,
            finalized.kind,
            &finalized.index_name,
        ) || !is_sha256_digest(&finalized.finalized_state_digest)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

fn descriptor_digest(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DIGEST_DOMAIN);
    hasher.update(descriptor.version.to_be_bytes());
    hasher.update(descriptor.coordinator_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &descriptor.mutation_digest)?;
    hash_lease(&mut hasher, &descriptor.preparing_lease)?;
    hash_digest(
        &mut hasher,
        &canonical_private_oram_consensus_state_record_digest(
            &descriptor.expected_consensus_old_state,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
    )?;
    hash_len(&mut hasher, descriptor.owner_requirements.len())?;
    for requirement in &descriptor.owner_requirements {
        hash_owner_key(
            &mut hasher,
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
        )?;
        hasher.update(requirement.old_epoch.to_be_bytes());
        hasher.update(requirement.new_epoch.to_be_bytes());
        hash_digest(&mut hasher, &requirement.old_root_hash)?;
        hash_digest(&mut hasher, &requirement.new_root_hash)?;
        hash_digest(&mut hasher, &requirement.writeback_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn state_record_digest(
    descriptor_digest: &str,
    state: &PrivateOramMutationJournalStateV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN);
    hash_digest(&mut hasher, descriptor_digest)?;
    hasher.update(state.version.to_be_bytes());
    hasher.update(state.sequence.to_be_bytes());
    hasher.update([state.phase.sequence() as u8]);
    hash_optional_digest(&mut hasher, state.previous_record_digest.as_deref())?;
    hash_len(&mut hasher, state.owner_prepares.len())?;
    for evidence in &state.owner_prepares {
        hash_owner_key(
            &mut hasher,
            evidence.peer_id,
            evidence.kind,
            &evidence.index_name,
        )?;
        hash_digest(&mut hasher, &evidence.prepared_journal_digest)?;
    }
    match &state.point_stage {
        None => hasher.update([0]),
        Some(PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            child_descriptor_digest,
            parent_owners_prepared_record_digest,
        }) => {
            hasher.update([1]);
            hash_string(&mut hasher, point_id)?;
            hash_digest(&mut hasher, staged_insert_sha256)?;
            hash_digest(&mut hasher, canonical_point_id_digest)?;
            hash_digest(&mut hasher, child_descriptor_digest)?;
            hash_digest(&mut hasher, parent_owners_prepared_record_digest)?;
        }
        Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) => {
            hasher.update([2]);
            hash_digest(&mut hasher, parent_owners_prepared_record_digest)?;
        }
    }
    match &state.consensus {
        None => hasher.update([0]),
        Some(evidence) => {
            hasher.update([1]);
            hash_digest(&mut hasher, &evidence.committed_record_digest)?;
            hasher.update(evidence.committed_state_sequence.to_be_bytes());
            hash_digest(&mut hasher, &evidence.committed_signed_state_digest)?;
            hash_digest(&mut hasher, &evidence.receipt_digest)?;
            hash_digest(&mut hasher, &evidence.transition_digest)?;
            hasher.update(evidence.lease_renewal_revision.to_be_bytes());
        }
    }
    hash_finalizations(&mut hasher, &state.remote_finalizations)?;
    hash_finalizations(&mut hasher, &state.local_finalizations)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_lease(
    hasher: &mut Sha256,
    lease: &PrivateOramMutationLease,
) -> Result<(), PrivateOramMutationJournalError> {
    hasher.update(lease.generation.to_be_bytes());
    hash_string(hasher, &lease.collection_id)?;
    hasher.update(lease.owner_peer_id.to_be_bytes());
    hash_digest(hasher, &lease.mutation_id)?;
    hash_digest(hasher, &lease.signed_mutation_digest)?;
    hash_digest(hasher, &lease.transition_digest)?;
    hash_digest(hasher, &lease.base_record_digest)?;
    hasher.update(lease.base_state_sequence.to_be_bytes());
    hash_digest(hasher, &lease.writer_lease_digest)?;
    hasher.update(lease.writer_fence.to_be_bytes());
    hasher.update(lease.issued_at_unix.to_be_bytes());
    hasher.update(lease.expires_at_unix.to_be_bytes());
    hasher.update(lease.renewal_revision.to_be_bytes());
    if !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing) {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "preparing_lease",
        ));
    }
    hasher.update([1]);
    Ok(())
}

fn hash_finalizations(
    hasher: &mut Sha256,
    evidence: &[PrivateOramMutationOwnerFinalizeEvidenceV1],
) -> Result<(), PrivateOramMutationJournalError> {
    hash_len(hasher, evidence.len())?;
    for evidence in evidence {
        hash_owner_key(
            hasher,
            evidence.peer_id,
            evidence.kind,
            &evidence.index_name,
        )?;
        hash_digest(hasher, &evidence.prepared_journal_digest)?;
        hash_digest(hasher, &evidence.finalized_state_digest)?;
    }
    Ok(())
}

fn hash_owner_key(
    hasher: &mut Sha256,
    peer_id: PeerId,
    kind: PrivateOramIndexKindV2,
    index_name: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    hasher.update(peer_id.to_be_bytes());
    hasher.update([index_kind_tag(kind)]);
    hash_string(hasher, index_name)
}

fn hash_optional_digest(
    hasher: &mut Sha256,
    value: Option<&str>,
) -> Result<(), PrivateOramMutationJournalError> {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_digest(hasher, value)
        }
        None => {
            hasher.update([0]);
            Ok(())
        }
    }
}

fn hash_digest(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if decoded.len() != 32 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(decoded);
    Ok(())
}

fn hash_string(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let len = u64::try_from(value.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(len.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_len(hasher: &mut Sha256, len: usize) -> Result<(), PrivateOramMutationJournalError> {
    let len = u64::try_from(len).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(len.to_be_bytes());
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .is_ok_and(|decoded| decoded.len() == 32)
}

fn requirement_order(
    left: &PrivateOramMutationOwnerRequirementV1,
    right: &PrivateOramMutationOwnerRequirementV1,
) -> Ordering {
    owner_key_order(
        left.peer_id,
        left.kind,
        &left.index_name,
        right.peer_id,
        right.kind,
        &right.index_name,
    )
}

fn prepare_evidence_order(
    left: &PrivateOramMutationOwnerPrepareEvidenceV1,
    right: &PrivateOramMutationOwnerPrepareEvidenceV1,
) -> Ordering {
    owner_key_order(
        left.peer_id,
        left.kind,
        &left.index_name,
        right.peer_id,
        right.kind,
        &right.index_name,
    )
}

fn finalize_evidence_order(
    left: &PrivateOramMutationOwnerFinalizeEvidenceV1,
    right: &PrivateOramMutationOwnerFinalizeEvidenceV1,
) -> Ordering {
    owner_key_order(
        left.peer_id,
        left.kind,
        &left.index_name,
        right.peer_id,
        right.kind,
        &right.index_name,
    )
}

fn owner_key_order(
    left_peer: PeerId,
    left_kind: PrivateOramIndexKindV2,
    left_name: &str,
    right_peer: PeerId,
    right_kind: PrivateOramIndexKindV2,
    right_name: &str,
) -> Ordering {
    (left_peer, index_kind_tag(left_kind), left_name.as_bytes()).cmp(&(
        right_peer,
        index_kind_tag(right_kind),
        right_name.as_bytes(),
    ))
}

fn same_owner_key(
    left_peer: PeerId,
    left_kind: PrivateOramIndexKindV2,
    left_name: &str,
    right_peer: PeerId,
    right_kind: PrivateOramIndexKindV2,
    right_name: &str,
) -> bool {
    left_peer == right_peer && left_kind == right_kind && left_name == right_name
}

const fn index_kind_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => 1,
        PrivateOramIndexKindV2::Result => 2,
    }
}

trait JournalSaveBackend {
    fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()>;
    fn sync_parent(&self, parent: &Path) -> io::Result<()>;
}

struct FilesystemJournalSaveBackend;

impl JournalSaveBackend for FilesystemJournalSaveBackend {
    fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            candidate
                .persist(destination)
                .map(|_| ())
                .map_err(|error| error.error)
        }
        #[cfg(not(unix))]
        {
            atomicwrites::replace_atomic(candidate.path(), destination)
        }
    }

    fn sync_parent(&self, parent: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(parent)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Ok(())
        }
    }
}

fn write_json_atomic_classified<T: Serialize>(
    destination: &Path,
    temp_dir: &Path,
    value: &T,
    previous_file_sha256: [u8; 32],
    backend: &impl JournalSaveBackend,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_directory(temp_dir)?;
    let parent = destination
        .parent()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    validate_private_directory(parent)?;
    let mut candidate =
        NamedTempFile::new_in(temp_dir).map_err(PrivateOramMutationJournalError::Io)?;
    let mut candidate_hasher = Sha256::new();
    {
        let mut writer = Sha256Writer {
            inner: &mut candidate,
            hasher: &mut candidate_hasher,
        };
        serde_json::to_writer(&mut writer, value)
            .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
        writer
            .flush()
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    let candidate_file = File::from_parts(
        candidate
            .reopen()
            .map_err(PrivateOramMutationJournalError::Io)?,
        candidate.path().to_path_buf(),
    );
    candidate_file
        .sync_all()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(
        &candidate_file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        MAX_STATE_BYTES,
    )?;
    let candidate_sha256: [u8; 32] = candidate_hasher.finalize().into();
    if let Err(error) = backend.publish(candidate, destination) {
        match file_sha256(destination, MAX_STATE_BYTES) {
            Ok(actual) if actual == candidate_sha256 => {
                return sync_parent_after_publish(destination, parent, candidate_sha256, backend);
            }
            Ok(actual) if actual == previous_file_sha256 => {
                return Err(PrivateOramMutationJournalError::Io(error));
            }
            _ => return Err(PrivateOramMutationJournalError::Indeterminate),
        }
    }
    if file_sha256(destination, MAX_STATE_BYTES)
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?
        != candidate_sha256
    {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    sync_parent_after_publish(destination, parent, candidate_sha256, backend)
}

fn sync_parent_after_publish(
    destination: &Path,
    parent: &Path,
    candidate_sha256: [u8; 32],
    backend: &impl JournalSaveBackend,
) -> Result<(), PrivateOramMutationJournalError> {
    for _ in 0..PARENT_SYNC_ATTEMPTS {
        if backend.sync_parent(parent).is_ok() {
            return if file_sha256(destination, MAX_STATE_BYTES)
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?
                == candidate_sha256
            {
                Ok(())
            } else {
                Err(PrivateOramMutationJournalError::Indeterminate)
            };
        }
        if file_sha256(destination, MAX_STATE_BYTES)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?
            != candidate_sha256
        {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
    }
    Err(PrivateOramMutationJournalError::Indeterminate)
}

struct Sha256Writer<'a, W> {
    inner: W,
    hasher: &'a mut Sha256,
}

impl<W: Write> Write for Sha256Writer<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) fn create_private_directory(path: &Path) -> Result<(), PrivateOramMutationJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(PrivateOramMutationJournalError::Io)?;
            set_private_directory_permissions(path)?;
            let parent = path
                .parent()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?;
            sync_directory(parent)?;
            validate_private_directory(path)
        }
        Err(error) => Err(PrivateOramMutationJournalError::Io(error)),
    }
}

pub(super) fn path_entry_exists(path: &Path) -> Result<bool, PrivateOramMutationJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PrivateOramMutationJournalError::Io(error)),
    }
}

pub(super) fn set_private_directory_permissions(
    path: &Path,
) -> Result<(), PrivateOramMutationJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    Ok(())
}

pub(super) fn validate_private_directory(
    path: &Path,
) -> Result<(), PrivateOramMutationJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_directory_metadata(&metadata)
}

fn validate_private_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7077 != 0
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn write_new_json_private<T: Serialize>(
    path: &Path,
    value: &T,
    max_bytes: u64,
) -> Result<(), PrivateOramMutationJournalError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    secure_open_options(&mut options, true);
    let mut file = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    serde_json::to_writer(&mut file, value)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    file.flush().map_err(PrivateOramMutationJournalError::Io)?;
    let metadata = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(&metadata, max_bytes)?;
    file.sync_all().map_err(PrivateOramMutationJournalError::Io)
}

pub(super) fn read_json_private<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, PrivateOramMutationJournalError> {
    let file = open_private_file(path, max_bytes)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let mut reader = file.take(read_limit);
    let value = serde_json::from_reader(&mut reader)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if reader.limit() == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(value)
}

pub(super) fn read_private_bytes_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    let file = open_private_file(path, max_bytes)?;
    let initial_length = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?
        .len()
        .min(max_bytes);
    let capacity =
        usize::try_from(initial_length).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(PrivateOramMutationJournalError::Io)?;
    if u64::try_from(bytes.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)? > max_bytes
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(bytes)
}

pub(super) fn file_sha256(
    path: &Path,
    max_bytes: u64,
) -> Result<[u8; 32], PrivateOramMutationJournalError> {
    let file = open_private_file(path, max_bytes)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let mut limited = file.take(read_limit);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = limited
            .read(&mut buffer)
            .map_err(PrivateOramMutationJournalError::Io)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| PrivateOramMutationJournalError::Corrupt)?)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if total > max_bytes {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

pub(super) fn open_private_file(
    path: &Path,
    max_bytes: u64,
) -> Result<File, PrivateOramMutationJournalError> {
    let before = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    secure_open_options(&mut options, false);
    let file = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    let opened = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    ensure_same_file(&before, &opened)?;
    validate_private_file_metadata(&opened, max_bytes)?;
    Ok(file)
}

pub(super) fn secure_open_options(options: &mut OpenOptions, create_private: bool) {
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        if create_private {
            options.mode(0o600);
        }
    }
}

pub(super) fn validate_private_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramMutationJournalError> {
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7177 != 0
            || metadata.nlink() != 1
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn ensure_same_file(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if before.len() != after.len() || before.file_type().is_file() != after.file_type().is_file() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), PrivateOramMutationJournalError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use collection::private_oram_owner_journal::PrivateOramOwnerJournalPhaseV1;
    use collection::private_oram_owner_store_test_fixture::PrivateOramOwnerStorePairTestFixtureV1;
    use qdrant_sec::{
        DistanceKind, FixedBudgetParams, OramKind, OramParams, PRIVATE_HNSW_ORAM_V2_BINDING,
        PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION, PrivateHnswParams, PrivateHnswVectorEncoding,
        PrivateOramAppendBucketRefV1, PrivateOramAppendIndexWritebackV1,
        PrivateOramAppendMutationV1, PrivateOramImmutableIndexParamsV2,
        PrivateOramImmutableIndexV2, PrivateOramImmutableManifestV2, PrivateOramIndexCapacityV2,
        PrivateOramIndexStateV2, PrivateOramSignedStateV2, PrivateOramStagedInsertFrameV1,
        PrivateOramStagedPointIdV1, PrivateOramStagedPointV1, ResultPrivacyMode,
        VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, encode_private_oram_staged_insert_frame_v1,
        package_private_oram_append_mutation_v1, package_private_oram_immutable_manifest_v2,
        package_private_oram_signed_state_v2, private_oram_no_server_point_record_v1_digest,
        private_oram_staged_insert_frame_v1_digest, private_oram_staged_point_semantic_v1_digest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use tempfile::TempDir;

    use super::writer_v2::{
        PrivateOramMutationJournalStructuralSnapshotV2, set_fail_immutable_json_after_rename_v2,
    };
    use super::*;
    use crate::content_manager::consensus::private_oram_mutation_cleanup::authority::{
        PrivateOramMutationAuthorityStateV2, PrivateOramMutationMaterialOperationV2,
        acknowledge_private_oram_mutation_authority_clear_v2,
        activate_private_oram_mutation_authority_v2,
        apply_private_oram_mutation_authority_admission_v2,
        apply_private_oram_mutation_authority_append_prepared_v2,
        apply_private_oram_mutation_authority_cleanup_witness_v2,
        apply_private_oram_mutation_authority_clear_pending_v2,
        apply_private_oram_mutation_authority_clear_v2,
        apply_private_oram_mutation_authority_create_append_reservation_v2,
        apply_private_oram_mutation_authority_lease_transition_v2,
        apply_private_oram_mutation_authority_parent_progress_v2,
        apply_private_oram_mutation_authority_recovery_capsules_ready_v2,
        private_oram_mutation_activation_context_for_test,
        private_oram_mutation_aggregate_apply_context_for_test,
        private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test,
        private_oram_mutation_authority_key_v2,
        private_oram_mutation_authority_request_digest_for_ack_for_test,
        private_oram_mutation_authority_request_digest_for_cleanup_for_test,
        private_oram_mutation_authority_request_digest_for_clear_for_test,
        private_oram_mutation_authority_request_digest_for_lease_for_test,
        private_oram_mutation_authority_request_digest_for_parent_for_test,
        private_oram_mutation_legacy_authority_v2,
        private_oram_mutation_terminal_material_transferable_for_test,
        validate_private_oram_mutation_authority_state_v2,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::{
        PrivateOramMutationCleanupActiveV2, PrivateOramMutationCleanupLifecycleV2,
        PrivateOramMutationClearResolutionV2, acknowledge_private_oram_mutation_clear_v2,
        apply_private_oram_mutation_admission_v2, apply_private_oram_mutation_cleanup_witness_v2,
        apply_private_oram_mutation_clear_pending_v2, apply_private_oram_mutation_clear_v2,
        apply_private_oram_mutation_parent_progress_v2,
        private_oram_admission_applied_entry_for_test, private_oram_cleanup_expectation_for_test,
        private_oram_cleanup_gc_exclusion_permit_for_test,
        private_oram_cleanup_witness_applied_entry_for_test,
        private_oram_clear_acknowledgement_applied_entry_for_test,
        private_oram_clear_applied_entry_for_test,
        private_oram_clear_pending_applied_entry_for_test,
        private_oram_cleared_pending_archive_permit_for_test,
        private_oram_mutation_cleanup_gc_checkpoint_v2,
        private_oram_mutation_cleanup_lifecycle_genesis_v2,
        private_oram_parent_progress_applied_entry_for_test,
        replace_private_oram_applied_entry_namespace_for_test,
        replace_private_oram_applied_entry_operation_digest_for_test,
        validate_private_oram_mutation_cleanup_lifecycle_v2,
        validate_private_oram_mutation_cleanup_pair_v2,
    };
    use crate::content_manager::consensus::private_oram_mutation_recovery_capsules::{
        PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
        PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2,
        decode_private_oram_mutation_recovery_capsules_ready_v2,
        derive_private_oram_mutation_recovery_capsules_ready_v2,
        encode_private_oram_mutation_recovery_capsules_ready_v2,
    };
    use crate::content_manager::consensus::private_oram_mutation_watermark::{
        PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationParentWatermarkV2,
        derive_private_oram_mutation_parent_watermark_expectation_v2,
        replace_private_oram_mutation_parent_watermark_record_for_test,
        truncate_private_oram_mutation_parent_watermark_expectation_for_test,
        validate_private_oram_mutation_parent_watermark_v2_cas_transition,
        validate_private_oram_mutation_parent_watermark_v2_shape,
        validate_private_oram_mutation_parent_watermark_v2_snapshot_transition,
    };
    use crate::content_manager::consensus_ops::{
        PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION, PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
        PrivateOramConsensusCollectionIndexStateV2, PrivateOramConsensusEpoch,
        PrivateOramIndexKind, PrivateOramMutationClearOutcome, PrivateOramMutationReceiptV2,
    };
    use crate::content_manager::private_oram_mutation_state_v2::{
        DecodedPrivateOramMutationStateUntrusted, PRIVATE_ORAM_MUTATION_STATE_V2_VERSION,
        PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION, PrivateOramMutationDecisionEvidenceV2,
        PrivateOramMutationDecisionKindV2, PrivateOramMutationJournalPhaseV2,
        PrivateOramMutationJournalStateV2, PrivateOramMutationOwnerJournalEvidenceV2,
        PrivateOramMutationOwnerTerminalBatchV2, PrivateOramMutationOwnerTerminalEvidenceV2,
        PrivateOramMutationOwnerTerminalIndexEvidenceV2, PrivateOramMutationOwnerTerminalKindV2,
        PrivateOramMutationPointResolutionEvidenceV2, PrivateOramMutationPointStageEvidenceV2,
        PrivateOramMutationStateOriginV2, PrivateOramMutationStatePredecessorV2,
        PrivateOramPointReplicaObservationV2, PrivateOramPointReplicaTargetV2,
        PrivateOramPointResolutionOutcomeV2, PrivateOramPointResolutionReceiptV2,
        canonical_private_oram_mutation_state_history_v2,
        canonical_private_oram_mutation_state_v2_for_test,
        decode_untrusted_private_oram_mutation_state, exact_new_decision_v2_for_test,
        exact_old_abort_decision_v2_for_test, next_private_oram_mutation_state_v2,
        private_oram_collection_id_digest_v2, private_oram_owner_terminal_evidence_v2_digest,
        private_oram_point_replica_set_digest_v2, private_oram_point_resolution_receipt_v2_digest,
        private_oram_point_stage_evidence_v2_from_durable_token, record_digest_at_phase_v2,
        state_record_digest_v2_for_test, validate_private_oram_mutation_state_v2_structure,
    };
    use crate::content_manager::private_oram_point_staging::PrivateOramPointStagingStore;

    const PAIRED_STORE_NON_SECRET_TEST_OWNER_SEED: [u8; 32] = [37; 32];

    struct Fixture {
        public_key: Vec<u8>,
        immutable_manifest: PrivateOramImmutableManifestBundleV2,
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        committed_lease: PrivateOramMutationLease,
        old_consensus: PrivateOramConsensusCollectionStateV2,
        new_consensus: PrivateOramConsensusCollectionStateV2,
        staged_frame_bytes: Option<Vec<u8>>,
    }

    fn digest(fill: u8) -> String {
        BASE64URL_NOPAD.encode(&[fill; 32])
    }

    #[test]
    fn admission_recovery_manifest_round_trips_and_rejects_tampering() {
        let fixture = fixture(31, 71);
        let expected_aggregate_digest = digest(201);
        let encoded = private_oram_mutation_admission_recovery_manifest_for_test(
            &fixture.preparing_lease,
            &expected_aggregate_digest,
        );
        let decoded =
            decode_private_oram_mutation_admission_recovery_manifest_v2(&encoded).unwrap();
        decoded
            .validate_admission_lease(&fixture.preparing_lease)
            .unwrap();
        assert_eq!(
            decoded.expected_aggregate_digest(),
            expected_aggregate_digest
        );
        assert_eq!(
            encode_private_oram_mutation_admission_recovery_manifest_v2(&decoded).unwrap(),
            encoded
        );
        assert!(decoded.coordinator_recovery_envelope().is_err());
        assert!(!encoded.contains("coordinator_recovery_package_b64"));
        assert!(!encoded.contains("expected_old_state"));

        let mut tampered = serde_json::from_str::<serde_json::Value>(&encoded).unwrap();
        tampered["owner_evidence"][0]["receipt"]["package_sha256"] = serde_json::json!(digest(202));
        assert!(
            decode_private_oram_mutation_admission_recovery_manifest_v2(
                &serde_json::to_string(&tampered).unwrap(),
            )
            .is_err()
        );
        assert!(
            decode_private_oram_mutation_admission_recovery_manifest_v2(&format!(" {encoded}"))
                .is_err()
        );
        let mut wrong_lease = fixture.preparing_lease;
        wrong_lease.mutation_id = digest(203);
        assert!(decoded.validate_admission_lease(&wrong_lease).is_err());

        let rendered = format!("{decoded:?}");
        assert!(!rendered.contains(decoded.manifest_digest()));
        assert!(!rendered.contains(decoded.parent_descriptor_digest()));
    }

    fn signed_owner_install_evidence_v2(
        fixture: &Fixture,
        receipt: PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
    ) -> PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2 {
        let receipt_canonical_json =
            encode_private_oram_owner_recovery_capsule_install_receipt_v2(&receipt).unwrap();
        let statement = qdrant_sec::PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
            protocol_version: qdrant_sec::PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
            collection_id: fixture.preparing_lease.collection_id.clone(),
            mutation_id: fixture.preparing_lease.mutation_id.clone(),
            parent_descriptor_digest: receipt.parent_descriptor_digest().to_string(),
            owner_peer_id: receipt.owner_peer_id(),
            activation_registry_generation: receipt.activation_authority().registry_generation(),
            activation_manifest_digest: receipt
                .activation_authority()
                .manifest_digest()
                .to_string(),
            capsule_digest: receipt.capsule_digest().to_string(),
            capsule_set_digest: receipt.capsule_set_digest().to_string(),
            receipt_digest: receipt.receipt_digest().to_string(),
            receipt_canonical_sha256: qdrant_sec::private_oram_owner_capsule_canonical_sha256_v2(
                &receipt_canonical_json,
            ),
        };
        let key_pair =
            Ed25519KeyPair::from_seed_unchecked(&[receipt.owner_peer_id() as u8; 32]).unwrap();
        let attestation = qdrant_sec::sign_private_oram_owner_capsule_install_attestation_v2(
            &key_pair, 1, &statement,
        )
        .unwrap();
        PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2::from_signed_attestation(
            receipt,
            attestation,
        )
        .unwrap()
    }

    fn pair_recovery_authority(
        seed: u8,
        marker: u8,
    ) -> PrivateOramValidatedOwnerRecoveryAuthorityV1 {
        let base = fixture(seed, marker);
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let mut mutation = base.mutation_bundle.mutation.clone();
        let result_old_root = digest(marker.wrapping_add(30));
        let result_new_root = digest(marker.wrapping_add(31));
        let result_writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: "private-result".to_string(),
            read_path_count: 1,
            read_transcript_digest: digest(marker.wrapping_add(32)),
            updated_buckets: vec![PrivateOramAppendBucketRefV1 {
                bucket_id: 1,
                ciphertext_sha256: digest(marker.wrapping_add(33)),
                bucket_commitment: digest(marker.wrapping_add(34)),
            }],
        };
        let result_writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &mutation.collection_id,
                manifest_digest: &mutation.manifest_digest,
                kind: result_writeback.kind,
                index_name: &result_writeback.index_name,
                old_epoch: 21,
                new_epoch: 22,
                old_root_hash: &result_old_root,
                new_root_hash: &result_new_root,
                read_path_count: result_writeback.read_path_count,
                read_transcript_digest: &result_writeback.read_transcript_digest,
                updated_buckets: &result_writeback.updated_buckets,
            })
            .unwrap();
        let mut old_state = mutation.old_state.state.clone();
        old_state.indexes.push(PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: result_writeback.index_name.clone(),
            index_epoch: 21,
            root_hash: result_old_root,
            logical_count: 8,
            dummy_count: 24,
            last_writeback_digest: digest(marker.wrapping_add(35)),
        });
        let mut new_state = mutation.new_state.state.clone();
        new_state.indexes.push(PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: result_writeback.index_name.clone(),
            index_epoch: 22,
            root_hash: result_new_root,
            logical_count: 9,
            dummy_count: 23,
            last_writeback_digest: result_writeback_digest,
        });
        mutation.old_state = package_private_oram_signed_state_v2(&key_pair, old_state).unwrap();
        mutation.new_state = package_private_oram_signed_state_v2(&key_pair, new_state).unwrap();
        mutation.writebacks.push(result_writeback);
        let mutation_bundle = package_private_oram_append_mutation_v1(&key_pair, mutation).unwrap();
        let indexes = mutation_bundle
            .mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation_bundle.mutation.new_state.state.indexes)
            .enumerate()
            .map(
                |(position, (old, new))| PrivateOramValidatedOwnerRecoveryIndexV1 {
                    requirement: PrivateOramMutationOwnerRequirementV1 {
                        peer_id: 11,
                        kind: old.kind,
                        index_name: old.index_name.clone(),
                        old_epoch: old.index_epoch,
                        new_epoch: new.index_epoch,
                        old_root_hash: old.root_hash.clone(),
                        new_root_hash: new.root_hash.clone(),
                        writeback_digest: new.last_writeback_digest.clone(),
                    },
                    prepared: PrivateOramMutationOwnerPrepareEvidenceV1 {
                        peer_id: 11,
                        kind: old.kind,
                        index_name: old.index_name.clone(),
                        prepared_journal_digest: digest(
                            marker.wrapping_add(36).wrapping_add(position as u8),
                        ),
                    },
                },
            )
            .collect();
        PrivateOramValidatedOwnerRecoveryAuthorityV1 {
            owner_peer_id: 11,
            disposition: PrivateOramMutationReconcileDispositionV1::ExactNew,
            parent_descriptor_digest: digest(marker.wrapping_add(38)),
            parent_lease_acquired_record_digest: digest(marker.wrapping_add(39)),
            parent_owners_prepared_record_digest: digest(marker.wrapping_add(40)),
            consensus_authority_record_digest: digest(marker.wrapping_add(41)),
            reconciliation_authority_digest: digest(marker.wrapping_add(42)),
            mutation_bundle,
            indexes,
        }
    }

    fn fixture(seed: u8, marker: u8) -> Fixture {
        fixture_at_sequence(seed, marker, 0, false)
    }

    fn fixture_at_sequence(seed: u8, marker: u8, old_sequence: u64, visible: bool) -> Fixture {
        fixture_at_sequence_and_lease(seed, marker, old_sequence, visible, 9, 9)
    }

    fn fixture_at_sequence_and_lease(
        seed: u8,
        marker: u8,
        old_sequence: u64,
        visible: bool,
        mutation_lease_generation: u64,
        writer_fence: u64,
    ) -> Fixture {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let collection_id = "collection-uuid-1".to_string();
        let key_id = "tenant-a/private-oram-owner-v2".to_string();
        let immutable_manifest = PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: collection_id.clone(),
            manifest_nonce: digest(marker),
            indexes: vec![PrivateOramImmutableIndexV2 {
                index_name: "secret-index".to_string(),
                params: PrivateOramImmutableIndexParamsV2::Hnsw {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                    key_id: "tenant-a/private-hnsw-v2".to_string(),
                    rk_id: "tenant-a/private-hnsw-v2".to_string(),
                    rk_epoch: 7,
                    dim: 2,
                    vector_encoding: PrivateHnswVectorEncoding::F32Le,
                    distance: DistanceKind::Cosine,
                    hnsw: PrivateHnswParams {
                        m: 1,
                        ef_construction: 4,
                        max_layers: 2,
                        fixed_neighbor_slots: 2,
                    },
                    oram: OramParams {
                        kind: OramKind::PathOram,
                        bucket_size: 16,
                        block_size_bytes: 512,
                        tree_height: 1,
                        path_batch_size: 1,
                    },
                    fixed_search_budget: FixedBudgetParams {
                        enabled: true,
                        upper_layer_steps: 2,
                        base_layer_steps: 4,
                        paths_per_round: 1,
                        fixed_result_k: 1,
                    },
                    max_neighbor_rewrites: 1,
                },
                capacity: PrivateOramIndexCapacityV2 {
                    bucket_count: 3,
                    logical_capacity: 32,
                    reserved_physical_slots: 1,
                    max_client_stash_blocks: 1,
                    fixed_append_read_path_count: 3,
                    fixed_append_write_bucket_count: 6,
                },
            }],
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: key_id.clone(),
            created_at_unix: 1,
        };
        let manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let immutable_manifest =
            package_private_oram_immutable_manifest_v2(&key_pair, immutable_manifest).unwrap();
        let layout_digest = digest(marker.wrapping_add(1));
        let mutation_id = digest(marker.wrapping_add(2));
        let previous_mutation_id = digest(marker.wrapping_add(13));
        let writer_lease_digest = digest(marker.wrapping_add(3));
        let old_root_hash = digest(marker.wrapping_add(4));
        let new_root_hash = digest(marker.wrapping_add(5));
        let old_writeback_digest = digest(marker.wrapping_add(6));
        let read_transcript_digest = digest(marker.wrapping_add(7));
        let writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "secret-index".to_string(),
            read_path_count: 1,
            read_transcript_digest,
            updated_buckets: vec![PrivateOramAppendBucketRefV1 {
                bucket_id: 0,
                ciphertext_sha256: digest(marker.wrapping_add(8)),
                bucket_commitment: digest(marker.wrapping_add(9)),
            }],
        };
        let new_writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &collection_id,
                manifest_digest: &manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &old_root_hash,
                new_root_hash: &new_root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })
            .unwrap();
        let old_state = PrivateOramSignedStateV2 {
            version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            state_sequence: old_sequence,
            indexes: vec![PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: "secret-index".to_string(),
                index_epoch: 11,
                root_hash: old_root_hash.clone(),
                logical_count: 8,
                dummy_count: 24,
                last_writeback_digest: old_writeback_digest.clone(),
            }],
            client_state_digest: digest(marker.wrapping_add(10)),
            last_mutation_id: (old_sequence > 0).then_some(previous_mutation_id.clone()),
            owner_signing_key_id: key_id.clone(),
            signed_at_unix: 80,
        };
        let new_state = PrivateOramSignedStateV2 {
            version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            state_sequence: old_sequence + 1,
            indexes: vec![PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: "secret-index".to_string(),
                index_epoch: 12,
                root_hash: new_root_hash.clone(),
                logical_count: 9,
                dummy_count: 23,
                last_writeback_digest: new_writeback_digest.clone(),
            }],
            client_state_digest: digest(marker.wrapping_add(11)),
            last_mutation_id: Some(mutation_id.clone()),
            owner_signing_key_id: key_id.clone(),
            signed_at_unix: 120,
        };
        let old_state_bundle = package_private_oram_signed_state_v2(&key_pair, old_state).unwrap();
        let new_state_bundle = package_private_oram_signed_state_v2(&key_pair, new_state).unwrap();
        let staged_frame = visible.then(|| PrivateOramStagedInsertFrameV1 {
            version: PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            mutation_id: mutation_id.clone(),
            old_state_digest: private_oram_signed_state_v2_digest(&old_state_bundle.state).unwrap(),
            new_state_digest: private_oram_signed_state_v2_digest(&new_state_bundle.state).unwrap(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            old_state_sequence: old_sequence,
            new_state_sequence: old_sequence + 1,
            writer_lease_digest: writer_lease_digest.clone(),
            writer_fence,
            target_shard_ids: vec![11],
            shard_key: None,
            point: PrivateOramStagedPointV1 {
                id: PrivateOramStagedPointIdV1::Numeric { value: 42 },
                vectors: Vec::new(),
                payload: None,
            },
        });
        let staged_frame_bytes = staged_frame
            .as_ref()
            .map(encode_private_oram_staged_insert_frame_v1)
            .transpose()
            .unwrap();
        let (point_operation_kind, point_operation_digest) = if visible {
            let staged_insert_sha256 =
                private_oram_staged_insert_frame_v1_digest(staged_frame.as_ref().unwrap()).unwrap();
            (
                PrivateOramPointOperationKindV1::VisiblePointRecord,
                private_oram_visible_point_record_v1_digest(
                    &collection_id,
                    &manifest_digest,
                    &mutation_id,
                    PrivateOramVisiblePointRecordV1 {
                        point_id: "42",
                        staged_insert_sha256: &staged_insert_sha256,
                    },
                )
                .unwrap(),
            )
        } else {
            (
                PrivateOramPointOperationKindV1::NoServerPointRecord,
                private_oram_no_server_point_record_v1_digest(
                    &collection_id,
                    &manifest_digest,
                    &mutation_id,
                )
                .unwrap(),
            )
        };
        let mutation_bundle = package_private_oram_append_mutation_v1(
            &key_pair,
            PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: mutation_id.clone(),
                collection_id: collection_id.clone(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 5,
                writer_lease_digest: writer_lease_digest.clone(),
                writer_fence,
                issued_at_unix: 100,
                expires_at_unix: 200,
                old_state: old_state_bundle,
                new_state: new_state_bundle,
                point_operation_kind,
                point_operation_digest: point_operation_digest.clone(),
                writebacks: vec![writeback],
                owner_signing_key_id: key_id,
            },
        )
        .unwrap();
        let signed_mutation_digest =
            private_oram_append_mutation_v1_digest(&mutation_bundle.mutation).unwrap();
        let old_state_digest =
            private_oram_signed_state_v2_digest(&mutation_bundle.mutation.old_state.state).unwrap();
        let new_state_digest =
            private_oram_signed_state_v2_digest(&mutation_bundle.mutation.new_state.state).unwrap();
        let old_consensus = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            state_sequence: old_sequence,
            signed_state_digest: old_state_digest.clone(),
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "secret-index".to_string(),
                epoch: PrivateOramConsensusEpoch {
                    index_epoch: 11,
                    root_hash: old_root_hash,
                    writeback_digest: Some(old_writeback_digest),
                },
                logical_count: 8,
                dummy_count: 24,
            }],
            client_state_digest: mutation_bundle
                .mutation
                .old_state
                .state
                .client_state_digest
                .clone(),
            last_transition: if old_sequence == 0 {
                PrivateOramConsensusTransitionV2::Genesis
            } else {
                PrivateOramConsensusTransitionV2::Mutation(PrivateOramMutationReceiptV2 {
                    version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
                    mutation_id: previous_mutation_id,
                    signed_mutation_digest: digest(marker.wrapping_add(14)),
                    transition_digest: digest(marker.wrapping_add(15)),
                    old_state_sequence: old_sequence - 1,
                    old_state_digest: digest(marker.wrapping_add(16)),
                    new_state_sequence: old_sequence,
                    new_state_digest: old_state_digest.clone(),
                    point_operation_digest: digest(marker.wrapping_add(17)),
                    writer_lease_digest: digest(marker.wrapping_add(18)),
                    writer_fence: 1,
                    mutation_lease_generation: 1,
                })
            },
        };
        let base_record_digest =
            canonical_private_oram_consensus_state_record_digest(&old_consensus).unwrap();
        let receipt = PrivateOramMutationReceiptV2 {
            version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
            mutation_id: mutation_id.clone(),
            signed_mutation_digest: signed_mutation_digest.clone(),
            transition_digest: digest(marker.wrapping_add(12)),
            old_state_sequence: old_sequence,
            old_state_digest,
            new_state_sequence: old_sequence + 1,
            new_state_digest: new_state_digest.clone(),
            point_operation_digest,
            writer_lease_digest: writer_lease_digest.clone(),
            writer_fence,
            mutation_lease_generation,
        };
        let mut new_consensus = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest,
            layout_generation: 5,
            layout_digest,
            state_sequence: old_sequence + 1,
            signed_state_digest: new_state_digest,
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "secret-index".to_string(),
                epoch: PrivateOramConsensusEpoch {
                    index_epoch: 12,
                    root_hash: new_root_hash,
                    writeback_digest: Some(new_writeback_digest),
                },
                logical_count: 9,
                dummy_count: 23,
            }],
            client_state_digest: mutation_bundle
                .mutation
                .new_state
                .state
                .client_state_digest
                .clone(),
            last_transition: PrivateOramConsensusTransitionV2::Mutation(receipt),
        };
        let transition_digest =
            canonical_private_oram_mutation_transition_digest(&old_consensus, &new_consensus)
                .unwrap();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &mut new_consensus.last_transition
        else {
            unreachable!();
        };
        receipt.transition_digest = transition_digest.clone();
        let receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt).unwrap();
        let committed_record_digest =
            canonical_private_oram_consensus_state_record_digest(&new_consensus).unwrap();
        let preparing_lease = PrivateOramMutationLease {
            generation: mutation_lease_generation,
            collection_id,
            owner_peer_id: 11,
            mutation_id,
            signed_mutation_digest,
            transition_digest,
            base_record_digest,
            base_state_sequence: old_sequence,
            writer_lease_digest,
            writer_fence,
            issued_at_unix: 90,
            expires_at_unix: 210,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let mut committed_lease = preparing_lease.clone();
        committed_lease.phase = PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_record_digest,
            committed_state_sequence: old_sequence + 1,
            committed_signed_state_digest: new_consensus.signed_state_digest.clone(),
            receipt_digest,
        };
        Fixture {
            public_key: key_pair.public_key().as_ref().to_vec(),
            immutable_manifest,
            mutation_bundle,
            preparing_lease,
            committed_lease,
            old_consensus,
            new_consensus,
            staged_frame_bytes,
        }
    }

    fn paired_store_fixture(temp: &TempDir) -> (PrivateOramOwnerStorePairTestFixtureV1, Fixture) {
        let collection_path = temp.path().join("collection");
        fs::create_dir(&collection_path).unwrap();
        let pair = PrivateOramOwnerStorePairTestFixtureV1::new(
            &collection_path,
            PAIRED_STORE_NON_SECRET_TEST_OWNER_SEED,
        );
        let mutation_bundle = pair.mutation_bundle().clone();
        let mutation = &mutation_bundle.mutation;
        let old_state = &mutation.old_state.state;
        let new_state = &mutation.new_state.state;
        let old_state_digest = private_oram_signed_state_v2_digest(old_state).unwrap();
        let new_state_digest = private_oram_signed_state_v2_digest(new_state).unwrap();
        let signed_mutation_digest = private_oram_append_mutation_v1_digest(mutation).unwrap();
        let consensus_indexes = |state: &PrivateOramSignedStateV2| {
            state
                .indexes
                .iter()
                .map(|index| PrivateOramConsensusCollectionIndexStateV2 {
                    index_kind: match index.kind {
                        PrivateOramIndexKindV2::Hnsw => PrivateOramIndexKind::Hnsw,
                        PrivateOramIndexKindV2::Result => PrivateOramIndexKind::ResultPayload,
                    },
                    index_name: match index.kind {
                        PrivateOramIndexKindV2::Hnsw => index.index_name.clone(),
                        PrivateOramIndexKindV2::Result => String::new(),
                    },
                    epoch: PrivateOramConsensusEpoch {
                        index_epoch: index.index_epoch,
                        root_hash: index.root_hash.clone(),
                        writeback_digest: Some(index.last_writeback_digest.clone()),
                    },
                    logical_count: index.logical_count,
                    dummy_count: index.dummy_count,
                })
                .collect::<Vec<_>>()
        };
        let old_consensus = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: old_state.collection_id.clone(),
            manifest_digest: old_state.manifest_digest.clone(),
            layout_generation: old_state.layout_generation,
            layout_digest: old_state.layout_digest.clone(),
            state_sequence: old_state.state_sequence,
            signed_state_digest: old_state_digest.clone(),
            indexes: consensus_indexes(old_state),
            client_state_digest: old_state.client_state_digest.clone(),
            last_transition: PrivateOramConsensusTransitionV2::Genesis,
        };
        let base_record_digest =
            canonical_private_oram_consensus_state_record_digest(&old_consensus).unwrap();
        let mutation_lease_generation = mutation.writer_fence;
        let receipt = PrivateOramMutationReceiptV2 {
            version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest: signed_mutation_digest.clone(),
            transition_digest: digest(240),
            old_state_sequence: old_state.state_sequence,
            old_state_digest,
            new_state_sequence: new_state.state_sequence,
            new_state_digest: new_state_digest.clone(),
            point_operation_digest: mutation.point_operation_digest.clone(),
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            mutation_lease_generation,
        };
        let mut new_consensus = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: new_state.collection_id.clone(),
            manifest_digest: new_state.manifest_digest.clone(),
            layout_generation: new_state.layout_generation,
            layout_digest: new_state.layout_digest.clone(),
            state_sequence: new_state.state_sequence,
            signed_state_digest: new_state_digest,
            indexes: consensus_indexes(new_state),
            client_state_digest: new_state.client_state_digest.clone(),
            last_transition: PrivateOramConsensusTransitionV2::Mutation(receipt),
        };
        let transition_digest =
            canonical_private_oram_mutation_transition_digest(&old_consensus, &new_consensus)
                .unwrap();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &mut new_consensus.last_transition
        else {
            unreachable!();
        };
        receipt.transition_digest = transition_digest.clone();
        let receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt).unwrap();
        let committed_record_digest =
            canonical_private_oram_consensus_state_record_digest(&new_consensus).unwrap();
        let preparing_lease = PrivateOramMutationLease {
            generation: mutation_lease_generation,
            collection_id: mutation.collection_id.clone(),
            owner_peer_id: 11,
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest,
            transition_digest,
            base_record_digest,
            base_state_sequence: old_state.state_sequence,
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            issued_at_unix: mutation.issued_at_unix.saturating_sub(1),
            expires_at_unix: mutation.expires_at_unix.saturating_add(30),
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let mut committed_lease = preparing_lease.clone();
        committed_lease.phase = PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_record_digest,
            committed_state_sequence: new_state.state_sequence,
            committed_signed_state_digest: new_consensus.signed_state_digest.clone(),
            receipt_digest,
        };
        let immutable_manifest = pair.resources().immutable_manifest.clone();
        let fixture = Fixture {
            public_key: pair.public_key().to_vec(),
            immutable_manifest,
            mutation_bundle,
            preparing_lease,
            committed_lease,
            old_consensus,
            new_consensus,
            staged_frame_bytes: None,
        };
        (pair, fixture)
    }

    fn admission_recovery_manifest_v2_fixture()
    -> (String, PrivateOramOwnerPrestagePackageV2, Fixture) {
        let temp = TempDir::new().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let lease = &fixture.preparing_lease;
        let expected_aggregate_digest = digest(201);
        let activation_manifest_digest = digest(202);
        let parent_descriptor_digest = digest(203);
        let parent_lease_acquired_record_digest = digest(204);
        let owner_peer_ids = vec![lease.owner_peer_id];
        let owner_roster_digest =
            private_oram_owner_prestage_roster_digest_v2(&owner_peer_ids).unwrap();
        let mutation = &fixture.mutation_bundle.mutation;
        let package = PrivateOramOwnerPrestagePackageV2 {
            version: qdrant_sec::PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
            collection_name: "docs".to_string(),
            collection_id: lease.collection_id.clone(),
            mutation_id: lease.mutation_id.clone(),
            mutation_digest: lease.signed_mutation_digest.clone(),
            transition_digest: lease.transition_digest.clone(),
            base_record_digest: lease.base_record_digest.clone(),
            expected_aggregate_digest: expected_aggregate_digest.clone(),
            lease_generation: lease.generation,
            writer_fence: lease.writer_fence,
            coordinator_peer_id: lease.owner_peer_id,
            owner_peer_id: lease.owner_peer_id,
            vector_name: mutation.old_state.state.indexes[0].index_name.clone(),
            owner_signing_key_id: mutation.owner_signing_key_id.clone(),
            activation_registry_generation: 1,
            activation_manifest_digest: activation_manifest_digest.clone(),
            parent_descriptor_digest: parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.clone(),
            owner_peer_ids,
            owner_roster_digest: owner_roster_digest.clone(),
            immutable_manifest: fixture.immutable_manifest.clone(),
            owner_prepare: pair.owner_prepare_bundle(),
            durable_read_observations:
                qdrant_sec::private_oram_owner_prestage_read_observations_v2(
                    pair.read_transcripts(),
                )
                .unwrap(),
            staged_insert_frame_b64: None,
        };
        let package_bytes =
            qdrant_sec::encode_private_oram_owner_prestage_package_v2(&package).unwrap();
        let package_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(&package_bytes));
        let package_len = u64::try_from(package_bytes.len()).unwrap();
        let intent_key = digest(205);
        let receipt = PrivateOramOwnerPrestageReceiptV2::from_parts_for_test(
            intent_key.clone(),
            lease.collection_id.clone(),
            lease.mutation_id.clone(),
            lease.signed_mutation_digest.clone(),
            expected_aggregate_digest.clone(),
            lease.generation,
            lease.writer_fence,
            lease.owner_peer_id,
            parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest.clone(),
            owner_roster_digest.clone(),
            1,
            activation_manifest_digest.clone(),
            package_sha256.clone(),
            package_len,
            digest(206),
            digest(207),
            digest(208),
        );
        let receipt_canonical_json =
            collection::encode_private_oram_owner_prestage_receipt_v2(&receipt).unwrap();
        let statement = qdrant_sec::PrivateOramOwnerPrestageAttestationStatementV2 {
            protocol_version: qdrant_sec::PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
            collection_id: lease.collection_id.clone(),
            mutation_id: lease.mutation_id.clone(),
            mutation_digest: lease.signed_mutation_digest.clone(),
            transition_digest: lease.transition_digest.clone(),
            expected_aggregate_digest: expected_aggregate_digest.clone(),
            lease_generation: lease.generation,
            writer_fence: lease.writer_fence,
            parent_descriptor_digest: parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.clone(),
            owner_roster_digest: owner_roster_digest.clone(),
            owner_peer_id: lease.owner_peer_id,
            activation_registry_generation: 1,
            activation_manifest_digest: activation_manifest_digest.clone(),
            intent_key,
            package_sha256,
            receipt_digest: receipt.receipt_digest().to_string(),
            receipt_sha256: BASE64URL_NOPAD.encode(&Sha256::digest(&receipt_canonical_json)),
        };
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[12; 32]).unwrap();
        let attestation =
            qdrant_sec::sign_private_oram_owner_prestage_attestation_v2(&key_pair, 1, &statement)
                .unwrap();
        let evidence = PrivateOramMutationOwnerPrestageEvidenceV2::from_signed_attestation(
            receipt,
            attestation,
            &qdrant_sec::private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap(),
        )
        .unwrap();
        let mut manifest = PrivateOramMutationAllOwnersPrestagedV2 {
            version: ADMISSION_RECOVERY_MANIFEST_VERSION_V2,
            expected_aggregate_digest,
            activation_authority: PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(
                1,
                activation_manifest_digest,
            ),
            collection_id: lease.collection_id.clone(),
            mutation_id: lease.mutation_id.clone(),
            mutation_digest: lease.signed_mutation_digest.clone(),
            transition_digest: lease.transition_digest.clone(),
            lease_generation: lease.generation,
            writer_fence: lease.writer_fence,
            parent_descriptor_digest,
            parent_lease_acquired_record_digest,
            owner_roster_digest,
            owner_evidence: vec![evidence],
            coordinator_recovery_package_b64: Some(BASE64URL_NOPAD.encode(&package_bytes)),
            expected_old_state: Some(fixture.old_consensus.clone()),
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = admission_recovery_manifest_digest_v2(&manifest).unwrap();
        let encoded =
            encode_private_oram_mutation_admission_recovery_manifest_v2(&manifest).unwrap();
        (encoded, package, fixture)
    }

    #[test]
    fn admission_recovery_manifest_v2_binds_durable_recovery_envelope() {
        let (encoded, expected_package, fixture) = admission_recovery_manifest_v2_fixture();
        let decoded = decode_private_oram_mutation_admission_recovery_manifest_v2(&encoded)
            .expect("V2 recovery manifest must decode");
        let (package, old_state) = decoded.coordinator_recovery_envelope().unwrap();
        assert_eq!(package, expected_package);
        assert_eq!(old_state, &fixture.old_consensus);
        assert_eq!(
            encode_private_oram_mutation_admission_recovery_manifest_v2(&decoded).unwrap(),
            encoded
        );

        let mut package_tampered = decoded.clone();
        let mut package = expected_package.clone();
        package.base_record_digest = digest(209);
        let package_bytes =
            qdrant_sec::encode_private_oram_owner_prestage_package_v2(&package).unwrap();
        package_tampered.coordinator_recovery_package_b64 =
            Some(BASE64URL_NOPAD.encode(&package_bytes));
        package_tampered.manifest_digest =
            admission_recovery_manifest_digest_v2(&package_tampered).unwrap();
        assert!(
            encode_private_oram_mutation_admission_recovery_manifest_v2(&package_tampered).is_err()
        );

        let mut state_tampered = decoded;
        state_tampered
            .expected_old_state
            .as_mut()
            .unwrap()
            .client_state_digest = digest(210);
        state_tampered.manifest_digest =
            admission_recovery_manifest_digest_v2(&state_tampered).unwrap();
        assert!(
            encode_private_oram_mutation_admission_recovery_manifest_v2(&state_tampered).is_err()
        );
    }

    fn journal(temp: &TempDir, fixture: &Fixture) -> PrivateOramMutationJournal {
        let collection = temp.path().join("collection");
        if !collection.exists() {
            fs::create_dir(&collection).unwrap();
        }
        PrivateOramMutationJournal::new(
            &collection,
            "tenant-a/private-oram-owner-v2",
            fixture.public_key.clone(),
        )
        .unwrap()
    }

    fn begin(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        owners: &[PeerId],
    ) -> PrivateOramMutationJournalSnapshotV1 {
        journal
            .begin(
                11,
                owners,
                fixture.mutation_bundle.clone(),
                fixture.preparing_lease.clone(),
                fixture.old_consensus.clone(),
            )
            .unwrap()
    }

    fn owner_prepares(
        snapshot: &PrivateOramMutationJournalSnapshotV1,
    ) -> Vec<PrivateOramMutationOwnerPrepareEvidenceV1> {
        owner_prepares_for_descriptor(&snapshot.descriptor)
    }

    fn owner_prepares_v2(
        snapshot: &writer_v2::PrivateOramMutationJournalStructuralSnapshotV2,
    ) -> Vec<PrivateOramMutationOwnerPrepareEvidenceV1> {
        owner_prepares_for_descriptor(&snapshot.descriptor)
    }

    fn owner_prepares_for_descriptor(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
    ) -> Vec<PrivateOramMutationOwnerPrepareEvidenceV1> {
        descriptor
            .owner_requirements
            .iter()
            .enumerate()
            .map(
                |(offset, requirement)| PrivateOramMutationOwnerPrepareEvidenceV1 {
                    peer_id: requirement.peer_id,
                    kind: requirement.kind,
                    index_name: requirement.index_name.clone(),
                    prepared_journal_digest: digest(150 + u8::try_from(offset).unwrap()),
                },
            )
            .collect()
    }

    fn owner_journals_for_prepares(
        prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    ) -> Vec<PrivateOramMutationOwnerJournalEvidenceV2> {
        prepares
            .iter()
            .map(|prepared| (prepared.peer_id, prepared.prepared_journal_digest.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .map(|(owner_peer_id, journal_descriptor_digest)| {
                PrivateOramMutationOwnerJournalEvidenceV2 {
                    owner_peer_id,
                    journal_descriptor_digest,
                }
            })
            .collect()
    }

    fn begin_v2(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        owners: &[PeerId],
    ) -> writer_v2::PrivateOramMutationJournalStructuralSnapshotV2 {
        journal
            .begin_v2(
                11,
                owners,
                fixture.immutable_manifest.clone(),
                fixture.mutation_bundle.clone(),
                fixture.preparing_lease.clone(),
                fixture.old_consensus.clone(),
            )
            .unwrap()
    }

    fn finalizations(
        snapshot: &PrivateOramMutationJournalSnapshotV1,
        local: bool,
    ) -> Vec<PrivateOramMutationOwnerFinalizeEvidenceV1> {
        snapshot
            .state
            .owner_prepares
            .iter()
            .filter(|evidence| {
                (evidence.peer_id == snapshot.descriptor.coordinator_peer_id) == local
            })
            .enumerate()
            .map(
                |(offset, evidence)| PrivateOramMutationOwnerFinalizeEvidenceV1 {
                    peer_id: evidence.peer_id,
                    kind: evidence.kind,
                    index_name: evidence.index_name.clone(),
                    prepared_journal_digest: evidence.prepared_journal_digest.clone(),
                    finalized_state_digest: digest(180 + u8::try_from(offset).unwrap()),
                },
            )
            .collect()
    }

    fn mark_no_server_point_stage(
        journal: &PrivateOramMutationJournal,
    ) -> PrivateOramMutationJournalSnapshotV1 {
        let parent = journal.validated_point_stage_parent().unwrap();
        journal.mark_no_server_point_stage_durable(&parent).unwrap()
    }

    fn active_lease_slot(lease: PrivateOramMutationLease) -> PrivateOramMutationLeaseSlotV2 {
        PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: lease.generation,
            active: Some(lease.clone()),
            last_clear: None,
            max_writer_fence: lease.writer_fence,
        }
    }

    fn inactive_lease_slot() -> PrivateOramMutationLeaseSlotV2 {
        PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        }
    }

    fn reconcile_snapshot(
        consensus_state: &PrivateOramConsensusCollectionStateV2,
        lease: PrivateOramMutationLease,
    ) -> PrivateOramMutationReconcileSnapshotV1 {
        PrivateOramMutationReconcileSnapshotV1::from_parts_for_test(
            consensus_state.clone(),
            active_lease_slot(lease),
        )
    }

    fn prepare_paired_recovery_v2(
        journal: &PrivateOramMutationJournal,
        pair: &PrivateOramOwnerStorePairTestFixtureV1,
        fixture: &Fixture,
        disposition: PrivateOramMutationReconcileDispositionV1,
    ) -> (
        PrivateOramMutationReconcileSnapshotV1,
        PrivateOramValidatedRemotesTerminalV2,
    ) {
        let initial = begin_v2(journal, fixture, &[11]);
        let prepared_indexes = pair.prepare_owner(
            initial.descriptor.coordinator_peer_id,
            &initial.descriptor.descriptor_digest,
            &initial.state.record_digest,
        );
        let owner_journals = vec![PrivateOramMutationOwnerJournalEvidenceV2 {
            owner_peer_id: initial.descriptor.coordinator_peer_id,
            journal_descriptor_digest: prepared_indexes[0].owner_journal_descriptor_digest.clone(),
        }];
        let prepares = prepared_indexes
            .into_iter()
            .map(|prepared| PrivateOramMutationOwnerPrepareEvidenceV1 {
                peer_id: initial.descriptor.coordinator_peer_id,
                kind: prepared.kind,
                index_name: prepared.index_name,
                prepared_journal_digest: prepared.prepared_journal_digest,
            })
            .collect();
        journal
            .mark_owners_prepared_with_owner_journals_v2(owner_journals, prepares)
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        let reconcile = match disposition {
            PrivateOramMutationReconcileDispositionV1::ExactNew => {
                reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone())
            }
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
                let mut abort_decided = fixture.preparing_lease.clone();
                abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
                reconcile_snapshot(&fixture.old_consensus, abort_decided)
            }
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => {
                panic!("paired terminal recovery requires a durable decision")
            }
        };
        let decision = journal
            .validated_decision_for_v2_state(&reconcile, None)
            .unwrap();
        let (_, decision_durable) = journal.mark_decision_durable_v2(&decision).unwrap();
        let (_, remotes) = journal
            .mark_remotes_terminal_v2(&decision_durable, &[])
            .unwrap();
        (reconcile, remotes)
    }

    fn prepare_no_server_decision_v2(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        owner_peer_ids: &[PeerId],
    ) -> (
        PrivateOramMutationJournalStructuralSnapshotV2,
        PrivateOramValidatedDecisionDurableV2,
    ) {
        let initial = begin_v2(journal, fixture, owner_peer_ids);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        let decision = journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                None,
            )
            .unwrap();
        journal.mark_decision_durable_v2(&decision).unwrap()
    }

    fn assert_pair_store_state(
        pair: &PrivateOramOwnerStorePairTestFixtureV1,
        state: &PrivateOramSignedStateV2,
        terminal_phase: PrivateOramOwnerJournalPhaseV1,
    ) {
        let hnsw = state
            .indexes
            .iter()
            .find(|index| index.kind == PrivateOramIndexKindV2::Hnsw)
            .unwrap();
        let result = state
            .indexes
            .iter()
            .find(|index| index.kind == PrivateOramIndexKindV2::Result)
            .unwrap();
        let hnsw_epoch = pair.hnsw_store().read_current_epoch().unwrap();
        let result_epoch = pair.result_store().read_current_epoch().unwrap();
        assert_eq!(hnsw_epoch.index_epoch, hnsw.index_epoch);
        assert_eq!(hnsw_epoch.root_hash, hnsw.root_hash);
        assert_eq!(result_epoch.index_epoch, result.index_epoch);
        assert_eq!(result_epoch.root_hash, result.root_hash);
        assert_eq!(
            pair.owner_journal()
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .unwrap()
                .phase,
            terminal_phase
        );
    }

    fn empty_v2_state(
        phase: PrivateOramMutationJournalPhaseV2,
    ) -> PrivateOramMutationJournalStateV2 {
        PrivateOramMutationJournalStateV2 {
            version: PRIVATE_ORAM_MUTATION_STATE_V2_VERSION,
            sequence: phase.sequence(),
            phase,
            origin: PrivateOramMutationStateOriginV2::FreshV2,
            predecessor: PrivateOramMutationStatePredecessorV2::Genesis,
            owner_journals: Vec::new(),
            owner_prepares: Vec::new(),
            point_stage: None,
            decision: None,
            remote_terminals: None,
            local_terminals: None,
            point_resolution: None,
            record_digest: String::new(),
        }
    }

    fn v2_terminal_evidence(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        state: &PrivateOramMutationJournalStateV2,
        owner_peer_id: PeerId,
        kind: PrivateOramMutationOwnerTerminalKindV2,
        marker: u8,
    ) -> PrivateOramMutationOwnerTerminalEvidenceV2 {
        let decision = state.decision.as_ref().unwrap();
        let (decision_authority_record_digest, reconciliation_authority_digest) =
            expected_owner_recovery_authority_digest_v2(
                descriptor,
                state,
                decision.decided_lease(),
                decision.reconcile_disposition(),
                owner_peer_id,
            )
            .unwrap();
        let indexes = descriptor
            .owner_requirements
            .iter()
            .filter(|requirement| requirement.peer_id == owner_peer_id)
            .enumerate()
            .map(|(offset, requirement)| {
                let prepared = state
                    .owner_prepares
                    .iter()
                    .find(|prepared| {
                        prepared.peer_id == owner_peer_id
                            && prepared.kind == requirement.kind
                            && prepared.index_name == requirement.index_name
                    })
                    .unwrap();
                PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
                    kind: requirement.kind,
                    index_name: requirement.index_name.clone(),
                    prepared_journal_digest: prepared.prepared_journal_digest.clone(),
                    terminal_state_digest: digest(
                        marker.wrapping_add(8).wrapping_add(offset as u8),
                    ),
                }
            })
            .collect();
        let journal_descriptor_digest = state
            .owner_journals
            .iter()
            .find(|owner| owner.owner_peer_id == owner_peer_id)
            .unwrap()
            .journal_descriptor_digest
            .clone();
        let mut evidence = PrivateOramMutationOwnerTerminalEvidenceV2 {
            owner_peer_id,
            journal_descriptor_digest,
            prepared_state_digest: digest(marker.wrapping_add(1)),
            terminal_record_digest: digest(marker.wrapping_add(2)),
            parent_descriptor_digest: descriptor.descriptor_digest.clone(),
            decision_authority_record_digest,
            reconciliation_authority_digest,
            indexes,
            terminal_evidence_digest: String::new(),
        };
        evidence.terminal_evidence_digest = private_oram_owner_terminal_evidence_v2_digest(
            &descriptor.descriptor_digest,
            kind,
            &evidence,
        )
        .unwrap();
        evidence
    }

    fn v2_no_server_terminal_state(
        initial: &PrivateOramMutationJournalSnapshotV1,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
        target_phase: PrivateOramMutationJournalPhaseV2,
    ) -> PrivateOramMutationJournalStateV2 {
        v2_no_server_terminal_state_for_descriptor(
            &initial.descriptor,
            fixture,
            decision_kind,
            target_phase,
        )
    }

    fn v2_no_server_terminal_state_for_descriptor(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
        target_phase: PrivateOramMutationJournalPhaseV2,
    ) -> PrivateOramMutationJournalStateV2 {
        v2_no_server_terminal_state_from_point_stage(
            descriptor,
            fixture,
            decision_kind,
            target_phase,
            None,
        )
    }

    fn v2_no_server_terminal_state_from_point_stage(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
        target_phase: PrivateOramMutationJournalPhaseV2,
        exact_point_stage: Option<&PrivateOramMutationJournalStateV2>,
    ) -> PrivateOramMutationJournalStateV2 {
        assert!(
            target_phase.sequence()
                >= PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
        );
        assert!(!descriptor.owner_requirements.is_empty());
        assert!(
            descriptor
                .owner_requirements
                .iter()
                .all(|requirement| requirement.peer_id == descriptor.coordinator_peer_id)
        );

        let point_stage = exact_point_stage.cloned().unwrap_or_else(|| {
            let mut prepared = empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
            prepared.owner_prepares = owner_prepares_for_descriptor(descriptor);
            prepared.owner_journals = owner_journals_for_prepares(&prepared.owner_prepares);
            let prepared =
                canonical_private_oram_mutation_state_v2_for_test(descriptor, &prepared).unwrap();
            let mut point_stage =
                empty_v2_state(PrivateOramMutationJournalPhaseV2::PointStageDurable);
            point_stage.owner_journals = prepared.owner_journals;
            point_stage.owner_prepares = prepared.owner_prepares;
            point_stage.point_stage = Some(
                PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                    parent_owners_prepared_record_digest: prepared.record_digest,
                },
            );
            canonical_private_oram_mutation_state_v2_for_test(descriptor, &point_stage).unwrap()
        });
        assert_eq!(
            point_stage.phase,
            PrivateOramMutationJournalPhaseV2::PointStageDurable
        );
        assert_eq!(
            point_stage.sequence,
            PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
        );
        let decision = match decision_kind {
            PrivateOramMutationDecisionKindV2::ExactNew => exact_new_decision_v2_for_test(
                descriptor,
                &fixture.committed_lease,
                &fixture.new_consensus,
            )
            .unwrap(),
            PrivateOramMutationDecisionKindV2::ExactOldAbort => {
                let mut abort_decided = fixture.preparing_lease.clone();
                abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
                exact_old_abort_decision_v2_for_test(
                    descriptor,
                    &abort_decided,
                    &fixture.old_consensus,
                )
                .unwrap()
            }
        };
        let terminal_kind = match decision_kind {
            PrivateOramMutationDecisionKindV2::ExactNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            PrivateOramMutationDecisionKindV2::ExactOldAbort => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        let mut state = empty_v2_state(target_phase);
        state.owner_journals = point_stage.owner_journals;
        state.owner_prepares = point_stage.owner_prepares;
        state.point_stage = point_stage.point_stage;
        state.decision = Some(decision);
        if target_phase.sequence() >= PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence()
        {
            state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
                kind: terminal_kind,
                owners: Vec::new(),
            });
        }
        if target_phase.sequence() >= PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence() {
            let terminal = v2_terminal_evidence(
                descriptor,
                &state,
                descriptor.coordinator_peer_id,
                terminal_kind,
                211,
            );
            state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
                kind: terminal_kind,
                owners: vec![terminal],
            });
        }
        if target_phase == PrivateOramMutationJournalPhaseV2::PointResolved {
            let local_terminal = canonical_private_oram_mutation_state_v2_for_test(
                descriptor,
                &PrivateOramMutationJournalStateV2 {
                    phase: PrivateOramMutationJournalPhaseV2::LocalTerminal,
                    sequence: PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence(),
                    point_resolution: None,
                    ..state.clone()
                },
            )
            .unwrap();
            state.point_resolution = Some(
                PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                    decision_kind,
                    parent_local_terminal_record_digest: local_terminal.record_digest,
                },
            );
        }
        canonical_private_oram_mutation_state_v2_for_test(descriptor, &state).unwrap()
    }

    fn v2_parent_watermark_expectation(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
        target_phase: PrivateOramMutationJournalPhaseV2,
    ) -> PrivateOramMutationParentWatermarkExpectationV2 {
        let initial = begin_v2(journal, fixture, &[11]);
        let exact_point_stage = (initial.effective_state().phase
            == PrivateOramMutationJournalPhaseV2::PointStageDurable)
            .then_some(initial.effective_state());
        let state = v2_no_server_terminal_state_from_point_stage(
            &initial.descriptor,
            fixture,
            decision_kind,
            target_phase,
            exact_point_stage,
        );
        let snapshot = initial.with_effective_state_for_test(state).unwrap();
        derive_private_oram_mutation_parent_watermark_expectation_v2(&snapshot).unwrap()
    }

    fn cleanup_lifecycle_at_terminal_parent(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
    ) -> (
        PrivateOramMutationCleanupLifecycleV2,
        PrivateOramMutationLeaseSlotV2,
        PrivateOramMutationParentWatermarkExpectationV2,
    ) {
        let genesis = private_oram_mutation_cleanup_lifecycle_genesis_v2(
            &fixture.preparing_lease.collection_id,
            digest(245),
            digest(246),
        )
        .unwrap();
        let inactive_slot = inactive_lease_slot();
        let admitted = apply_private_oram_mutation_admission_v2(
            &genesis,
            &inactive_slot,
            fixture.preparing_lease.clone(),
            private_oram_mutation_admission_recovery_manifest_for_test(
                &fixture.preparing_lease,
                genesis.lifecycle_digest(),
            ),
            private_oram_admission_applied_entry_for_test(
                &genesis,
                &inactive_slot,
                &fixture.preparing_lease,
                1,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        let terminal = v2_parent_watermark_expectation(
            journal,
            fixture,
            decision_kind,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let mut lifecycle = admitted.lifecycle().clone();
        let lease_slot = admitted.lease_slot().clone();
        for sequence in 1..=7 {
            let expected = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                &terminal, sequence,
            )
            .unwrap();
            let applied = private_oram_parent_progress_applied_entry_for_test(
                &lifecycle,
                &lease_slot,
                &expected,
                1,
                10 + sequence,
            )
            .unwrap();
            lifecycle = apply_private_oram_mutation_parent_progress_v2(
                &lifecycle,
                &lease_slot,
                &expected,
                applied,
            )
            .unwrap();
        }
        (lifecycle, lease_slot, terminal)
    }

    fn admitted_cleanup_authority(fixture: &Fixture) -> PrivateOramMutationAuthorityStateV2 {
        let authority_key = private_oram_mutation_authority_key_v2(
            &fixture.preparing_lease.collection_id,
            digest(245),
            digest(246),
            digest(242),
        )
        .unwrap();
        let legacy = private_oram_mutation_legacy_authority_v2(
            authority_key,
            inactive_lease_slot(),
            digest(241),
        )
        .unwrap();
        let mut authority = activate_private_oram_mutation_authority_v2(
            &legacy,
            &fixture.preparing_lease.collection_id,
            private_oram_mutation_activation_context_for_test(
                digest(245),
                digest(246),
                1,
                1,
                1,
                digest(244),
            )
            .unwrap(),
        )
        .unwrap();
        let manifest_seed = private_oram_mutation_admission_recovery_manifest_for_test(
            &fixture.preparing_lease,
            authority.aggregate().unwrap().aggregate_digest(),
        );
        let manifest_seed =
            decode_private_oram_mutation_admission_recovery_manifest_v2(&manifest_seed).unwrap();
        let (reservation, reservation_manifest) = private_oram_mutation_append_fixture_for_test(
            &fixture.preparing_lease,
            authority
                .aggregate()
                .unwrap()
                .append_authority_context()
                .unwrap(),
            1,
            &[fixture.preparing_lease.owner_peer_id],
            manifest_seed.activation_authority().clone(),
        );
        let decoded_manifest = reservation_manifest;
        let admission_manifest =
            encode_private_oram_mutation_admission_recovery_manifest_v2(&decoded_manifest).unwrap();
        let admission_manifest_digest = decoded_manifest.manifest_digest().to_string();
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap();
        authority = apply_private_oram_mutation_authority_create_append_reservation_v2(
            &authority,
            reservation_canonical_json,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::AppendReservation,
                reservation.reservation_digest().to_string(),
                1,
                8,
            )
            .unwrap(),
        )
        .unwrap();
        let append_prepared_request = private_oram_mutation_append_prepared_request_digest_v2(
            &reservation,
            &decoded_manifest,
        )
        .unwrap();
        authority = apply_private_oram_mutation_authority_append_prepared_v2(
            &authority,
            admission_manifest.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::AppendPrepared,
                append_prepared_request,
                1,
                9,
            )
            .unwrap(),
        )
        .unwrap();
        let admission_request = crate::content_manager::consensus::private_oram_mutation_cleanup::private_oram_mutation_admission_request_digest_v2(
            &fixture.preparing_lease,
            &admission_manifest_digest,
        )
        .unwrap();
        authority = apply_private_oram_mutation_authority_admission_v2(
            &authority,
            fixture.preparing_lease.clone(),
            admission_manifest.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::Admission,
                admission_request.clone(),
                1,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        let replayed = apply_private_oram_mutation_authority_admission_v2(
            &authority,
            fixture.preparing_lease.clone(),
            admission_manifest,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::Admission,
                admission_request,
                1,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replayed, authority);
        authority
    }

    fn cleanup_authority_at_terminal_parent(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
        activation_authority: crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1,
        owner_evidence: PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2,
    ) -> (
        PrivateOramMutationAuthorityStateV2,
        PrivateOramMutationParentWatermarkExpectationV2,
        PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
    ) {
        let mut authority = admitted_cleanup_authority(fixture);
        let terminal = v2_parent_watermark_expectation(
            journal,
            fixture,
            decision_kind,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        for sequence in 1..=3 {
            let expected = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                &terminal, sequence,
            )
            .unwrap();
            let request =
                private_oram_mutation_authority_request_digest_for_parent_for_test(&expected);
            authority = apply_private_oram_mutation_authority_parent_progress_v2(
                &authority,
                &expected,
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ParentProgress,
                    request,
                    1,
                    10 + sequence,
                )
                .unwrap(),
            )
            .unwrap();
        }
        let point_stage = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
            &terminal,
            PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence(),
        )
        .unwrap();
        let recovery_capsules_ready = derive_private_oram_mutation_recovery_capsules_ready_v2(
            &point_stage,
            activation_authority,
            vec![owner_evidence],
        )
        .unwrap();
        authority = apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
            &authority,
            &recovery_capsules_ready,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
                recovery_capsules_ready.ready().ready_digest().to_string(),
                1,
                14,
            )
            .unwrap(),
        )
        .unwrap();
        for sequence in 4..=7 {
            let expected = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                &terminal, sequence,
            )
            .unwrap();
            let request =
                private_oram_mutation_authority_request_digest_for_parent_for_test(&expected);
            authority = apply_private_oram_mutation_authority_parent_progress_v2(
                &authority,
                &expected,
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ParentProgress,
                    request,
                    1,
                    11 + sequence,
                )
                .unwrap(),
            )
            .unwrap();
        }
        (authority, terminal, recovery_capsules_ready)
    }

    fn v2_visible_point_resolved_state(
        initial: &PrivateOramMutationJournalSnapshotV1,
        fixture: &Fixture,
        outcome: PrivateOramPointResolutionOutcomeV2,
    ) -> PrivateOramMutationJournalStateV2 {
        assert_eq!(initial.descriptor.owner_requirements.len(), 1);
        let frame_bytes = fixture.staged_frame_bytes.as_ref().unwrap();
        let staged_insert_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(frame_bytes));
        let child_descriptor_digest = digest(231);
        let canonical_point_id_digest = private_oram_point_id_digest("42").unwrap();

        let mut prepared = empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
        prepared.owner_prepares = owner_prepares(initial);
        prepared.owner_journals = owner_journals_for_prepares(&prepared.owner_prepares);
        let prepared =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &prepared)
                .unwrap();
        let (decision_kind, terminal_kind, decision) = match outcome {
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew => (
                PrivateOramMutationDecisionKindV2::ExactNew,
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                exact_new_decision_v2_for_test(
                    &initial.descriptor,
                    &fixture.committed_lease,
                    &fixture.new_consensus,
                )
                .unwrap(),
            ),
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                let mut abort_decided = fixture.preparing_lease.clone();
                abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
                (
                    PrivateOramMutationDecisionKindV2::ExactOldAbort,
                    PrivateOramMutationOwnerTerminalKindV2::AbortedOld,
                    exact_old_abort_decision_v2_for_test(
                        &initial.descriptor,
                        &abort_decided,
                        &fixture.old_consensus,
                    )
                    .unwrap(),
                )
            }
        };
        let mut state = empty_v2_state(PrivateOramMutationJournalPhaseV2::LocalTerminal);
        state.owner_journals = prepared.owner_journals;
        state.owner_prepares = prepared.owner_prepares;
        state.point_stage = Some(
            PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
                point_id: "42".to_string(),
                staged_insert_sha256: staged_insert_sha256.clone(),
                canonical_point_id_digest: canonical_point_id_digest.clone(),
                point_semantic_digest: digest(232),
                child_descriptor_digest: child_descriptor_digest.clone(),
                target_shard_ids: vec![11],
                parent_owners_prepared_record_digest: prepared.record_digest,
            },
        );
        state.decision = Some(decision);
        state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: terminal_kind,
            owners: Vec::new(),
        });
        state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: terminal_kind,
            owners: vec![v2_terminal_evidence(
                &initial.descriptor,
                &state,
                initial.descriptor.coordinator_peer_id,
                terminal_kind,
                221,
            )],
        });
        let local_terminal =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap();
        let observations = match outcome {
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
                vec![PrivateOramPointReplicaObservationV2::Exact {
                    shard_id: 11,
                    peer_id: 11,
                    point_semantic_digest: digest(232),
                }]
            }
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                vec![PrivateOramPointReplicaObservationV2::Absent {
                    shard_id: 11,
                    peer_id: 11,
                }]
            }
        };
        let replicas = vec![PrivateOramPointReplicaTargetV2 {
            shard_id: 11,
            peer_id: 11,
        }];
        let mutation = &initial.descriptor.mutation_bundle.mutation;
        let mut receipt = PrivateOramPointResolutionReceiptV2 {
            version: PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION,
            collection_id_digest: private_oram_collection_id_digest_v2(&mutation.collection_id)
                .unwrap(),
            mutation_digest: initial.descriptor.mutation_digest.clone(),
            point_operation_digest: mutation.point_operation_digest.clone(),
            child_descriptor_digest,
            staged_insert_sha256,
            canonical_point_id_digest,
            layout_generation: mutation.layout_generation,
            layout_digest: mutation.new_state.state.layout_digest.clone(),
            target_shard_ids: vec![11],
            replica_set_digest: private_oram_point_replica_set_digest_v2(&replicas).unwrap(),
            replicas,
            expected_point_semantic_digest: digest(232),
            observations,
            parent_local_terminal_record_digest: local_terminal.record_digest.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest =
            private_oram_point_resolution_receipt_v2_digest(outcome, &receipt).unwrap();
        state = local_terminal;
        state.phase = PrivateOramMutationJournalPhaseV2::PointResolved;
        state.sequence = PrivateOramMutationJournalPhaseV2::PointResolved.sequence();
        state.point_resolution = Some(match (decision_kind, outcome) {
            (
                PrivateOramMutationDecisionKindV2::ExactNew,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            ) => PrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt },
            (
                PrivateOramMutationDecisionKindV2::ExactOldAbort,
                PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
            ) => PrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt },
            _ => unreachable!(),
        });
        canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap()
    }

    fn point_resolution_receipt_for_local_state(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        local_state: &PrivateOramMutationJournalStateV2,
        outcome: PrivateOramPointResolutionOutcomeV2,
    ) -> PrivateOramPointResolutionReceiptV2 {
        let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            staged_insert_sha256,
            canonical_point_id_digest,
            point_semantic_digest,
            child_descriptor_digest,
            target_shard_ids,
            ..
        } = local_state.point_stage.as_ref().unwrap()
        else {
            panic!("expected visible point stage");
        };
        let replicas = target_shard_ids
            .iter()
            .map(|shard_id| PrivateOramPointReplicaTargetV2 {
                shard_id: *shard_id,
                peer_id: descriptor.coordinator_peer_id,
            })
            .collect::<Vec<_>>();
        let observations = replicas
            .iter()
            .map(|replica| match outcome {
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
                    PrivateOramPointReplicaObservationV2::Exact {
                        shard_id: replica.shard_id,
                        peer_id: replica.peer_id,
                        point_semantic_digest: point_semantic_digest.clone(),
                    }
                }
                PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                    PrivateOramPointReplicaObservationV2::Absent {
                        shard_id: replica.shard_id,
                        peer_id: replica.peer_id,
                    }
                }
            })
            .collect();
        let mutation = &descriptor.mutation_bundle.mutation;
        let mut receipt = PrivateOramPointResolutionReceiptV2 {
            version: PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION,
            collection_id_digest: private_oram_collection_id_digest_v2(&mutation.collection_id)
                .unwrap(),
            mutation_digest: descriptor.mutation_digest.clone(),
            point_operation_digest: mutation.point_operation_digest.clone(),
            child_descriptor_digest: child_descriptor_digest.clone(),
            staged_insert_sha256: staged_insert_sha256.clone(),
            canonical_point_id_digest: canonical_point_id_digest.clone(),
            layout_generation: mutation.layout_generation,
            layout_digest: mutation.new_state.state.layout_digest.clone(),
            target_shard_ids: target_shard_ids.clone(),
            replica_set_digest: private_oram_point_replica_set_digest_v2(&replicas).unwrap(),
            replicas,
            expected_point_semantic_digest: point_semantic_digest.clone(),
            observations,
            parent_local_terminal_record_digest: local_state.record_digest.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest =
            private_oram_point_resolution_receipt_v2_digest(outcome, &receipt).unwrap();
        receipt
    }

    fn v2_record_path(journal: &PrivateOramMutationJournal, sequence: u64) -> PathBuf {
        journal
            .active_path()
            .join("state_records")
            .join(format!("{sequence:020}.json"))
    }

    fn install_v2_state_for_test(
        journal: &PrivateOramMutationJournal,
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        state: &PrivateOramMutationJournalStateV2,
    ) {
        let history = canonical_private_oram_mutation_state_history_v2(descriptor, state).unwrap();
        for record in history.iter().skip(1) {
            let path = v2_record_path(journal, record.sequence);
            if path.exists() {
                let existing: PrivateOramMutationJournalStateV2 =
                    read_json_private(&path, MAX_STATE_BYTES).unwrap();
                assert_eq!(&existing, record);
            } else {
                write_new_json_private(&path, record, MAX_STATE_BYTES).unwrap();
            }
        }
        fs::write(journal.state_path(), serde_json::to_vec(state).unwrap()).unwrap();
        sync_directory(&journal.active_path().join("state_records")).unwrap();
        sync_directory(&journal.active_path()).unwrap();
    }

    fn v1_snapshot_for_descriptor(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
    ) -> PrivateOramMutationJournalSnapshotV1 {
        PrivateOramMutationJournalSnapshotV1 {
            descriptor: descriptor.clone(),
            state: PrivateOramMutationJournalStateV1 {
                version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
                sequence: 1,
                phase: PrivateOramMutationJournalPhaseV1::LeaseAcquired,
                previous_record_digest: None,
                owner_prepares: Vec::new(),
                point_stage: None,
                consensus: None,
                remote_finalizations: Vec::new(),
                local_finalizations: Vec::new(),
                record_digest: digest(250),
            },
        }
    }

    fn activation_locator_for_capsule_test(
        marker: u8,
    ) -> crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1
{
        crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(
            u64::from(marker).saturating_add(1),
            digest(marker),
        )
    }

    fn point_stage_owner_capsule_package_v2(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        pair: &PrivateOramOwnerStorePairTestFixtureV1,
        owner_peer_id: PeerId,
        activation_authority: crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1,
    ) -> PrivateOramOwnerRecoveryCapsulePackageV2 {
        let initial = begin_v2(journal, fixture, &[owner_peer_id]);
        let prepared_indexes = pair.prepare_owner(
            owner_peer_id,
            &initial.descriptor.descriptor_digest,
            &initial.state.record_digest,
        );
        let owner_journals = vec![PrivateOramMutationOwnerJournalEvidenceV2 {
            owner_peer_id,
            journal_descriptor_digest: prepared_indexes[0].owner_journal_descriptor_digest.clone(),
        }];
        let prepares = prepared_indexes
            .into_iter()
            .map(|prepared| PrivateOramMutationOwnerPrepareEvidenceV1 {
                peer_id: owner_peer_id,
                kind: prepared.kind,
                index_name: prepared.index_name,
                prepared_journal_digest: prepared.prepared_journal_digest,
            })
            .collect();
        journal
            .mark_owners_prepared_with_owner_journals_v2(owner_journals, prepares)
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        journal
            .owner_recovery_capsule_package_v2(owner_peer_id, activation_authority)
            .unwrap()
    }

    fn owner_capsule_store_v2(
        collection_path: &Path,
        fixture: &Fixture,
        owner_peer_id: PeerId,
    ) -> PrivateOramOwnerRecoveryCapsuleStoreV2 {
        PrivateOramOwnerRecoveryCapsuleStoreV2::new(
            collection_path,
            fixture.mutation_bundle.mutation.collection_id.clone(),
            owner_peer_id,
            "tenant-a/private-oram-owner-v2",
            fixture.public_key.clone(),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "stale fixture: begin_v2 pins the lease generation and writer fence to the signed                 mutation bundle and immutable manifest, and the paired store fixture has no                 knob to mint a coherent next-generation bundle; the supersede rule is covered                 by the conflicting-package and exact-replay tests"]
    fn v2_owner_recovery_capsule_store_supersedes_previous_generation() {
        let parent_temp = tempfile::tempdir().unwrap();
        let next_parent_temp = tempfile::tempdir().unwrap();
        let owner_temp = tempfile::tempdir().unwrap();
        let next_owner_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&owner_temp);
        let activation = activation_locator_for_capsule_test(213);
        let parent_journal = journal(&parent_temp, &fixture);
        let package = point_stage_owner_capsule_package_v2(
            &parent_journal,
            &fixture,
            &pair,
            11,
            activation.clone(),
        );
        let owner_store =
            owner_capsule_store_v2(&owner_temp.path().join("collection"), &fixture, 11);
        owner_store
            .install(&package, &activation, pair.resources())
            .unwrap();

        // The next mutation of the same collection mints a capsule for the next lease
        // generation; the store must accept it instead of treating the collection as one-shot.
        let (next_pair, next_base) = paired_store_fixture(&next_owner_temp);
        let mut next_lease = next_base.preparing_lease.clone();
        next_lease.generation += 1;
        next_lease.writer_fence += 1;
        let next_fixture = Fixture {
            public_key: next_base.public_key.clone(),
            immutable_manifest: next_base.immutable_manifest.clone(),
            mutation_bundle: next_base.mutation_bundle.clone(),
            preparing_lease: next_lease,
            committed_lease: next_base.committed_lease.clone(),
            old_consensus: next_base.old_consensus.clone(),
            new_consensus: next_base.new_consensus.clone(),
            staged_frame_bytes: next_base.staged_frame_bytes.clone(),
        };
        let next_journal = journal(&next_parent_temp, &next_fixture);
        let next_package = point_stage_owner_capsule_package_v2(
            &next_journal,
            &next_fixture,
            &next_pair,
            11,
            activation.clone(),
        );
        assert_ne!(next_package, package);
        assert_eq!(
            next_package.lease_generation(),
            package.lease_generation() + 1
        );
        owner_store
            .install(&next_package, &activation, next_pair.resources())
            .unwrap();
        // The current capsule stays idempotent, a replay of the previous generation is refused,
        // and the store serves the newest material.
        owner_store
            .install(&next_package, &activation, next_pair.resources())
            .unwrap();
        assert!(matches!(
            owner_store
                .install(&package, &activation, pair.resources())
                .unwrap_err(),
            PrivateOramMutationJournalError::ConcurrentMutation
        ));
        owner_store.load_recovery_material_v2(&activation).unwrap();
    }

    #[test]
    fn v2_owner_recovery_capsule_requires_point_stage_durable_parent() {
        let parent_temp = tempfile::tempdir().unwrap();
        let owner_temp = tempfile::tempdir().unwrap();
        let (_pair, fixture) = paired_store_fixture(&owner_temp);
        let journal = journal(&parent_temp, &fixture);
        begin_v2(&journal, &fixture, &[11]);

        assert!(matches!(
            journal
                .owner_recovery_capsule_package_v2(11, activation_locator_for_capsule_test(201),),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn v2_owner_recovery_capsule_install_is_insert_only_and_exactly_replayable() {
        let parent_temp = tempfile::tempdir().unwrap();
        let remote_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&remote_temp);
        let journal = journal(&parent_temp, &fixture);
        let activation = activation_locator_for_capsule_test(202);
        let package =
            point_stage_owner_capsule_package_v2(&journal, &fixture, &pair, 11, activation.clone());
        let remote_collection = remote_temp.path().join("collection");
        let store = owner_capsule_store_v2(&remote_collection, &fixture, 11);

        let first = store
            .install(&package, &activation, pair.resources())
            .unwrap();
        let replay = store
            .install(&package, &activation, pair.resources())
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.owner_peer_id(), 11);
        assert_eq!(
            first.parent_descriptor_digest(),
            package.parent_descriptor_digest()
        );
        assert_eq!(first.capsule_digest(), package.capsule_digest());
        assert_eq!(first.capsule_set_digest(), package.capsule_set_digest());

        let material = store.load_recovery_material_v2(&activation).unwrap();
        assert_eq!(material.immutable_manifest(), &fixture.immutable_manifest);
        assert_eq!(material.mutation_bundle(), &fixture.mutation_bundle);

        let debug = format!("{package:?}");
        assert!(!debug.contains(package.parent_descriptor_digest()));
        assert!(!debug.contains(package.capsule_digest()));
        assert!(!debug.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_owner_recovery_capsule_rejects_wrong_owner_authority_and_tampering() {
        let parent_temp = tempfile::tempdir().unwrap();
        let remote_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&remote_temp);
        let journal = journal(&parent_temp, &fixture);
        let activation = activation_locator_for_capsule_test(204);
        let package =
            point_stage_owner_capsule_package_v2(&journal, &fixture, &pair, 11, activation.clone());
        let remote_collection = remote_temp.path().join("collection");

        let wrong_owner_store = owner_capsule_store_v2(&remote_collection, &fixture, 12);
        assert!(matches!(
            wrong_owner_store.install(&package, &activation, pair.resources()),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let store = owner_capsule_store_v2(&remote_collection, &fixture, 11);
        assert!(matches!(
            store.install(
                &package,
                &activation_locator_for_capsule_test(205),
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let mut encoded = serde_json::to_value(&package).unwrap();
        encoded["capsule"]["capsule_digest"] = serde_json::Value::String(digest(253));
        let tampered: PrivateOramOwnerRecoveryCapsulePackageV2 =
            serde_json::from_value(encoded).unwrap();
        assert!(matches!(
            store.install(&tampered, &activation, pair.resources()),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_owner_recovery_capsule_rejects_a_conflicting_valid_package() {
        let parent_temp = tempfile::tempdir().unwrap();
        let remote_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&remote_temp);
        let parent = journal(&parent_temp, &fixture);
        let first_activation = activation_locator_for_capsule_test(206);
        let first = point_stage_owner_capsule_package_v2(
            &parent,
            &fixture,
            &pair,
            11,
            first_activation.clone(),
        );
        let second_activation = activation_locator_for_capsule_test(207);
        let second = parent
            .owner_recovery_capsule_package_v2(11, second_activation.clone())
            .unwrap();
        assert_ne!(first, second);

        let remote_collection = remote_temp.path().join("collection");
        let store = owner_capsule_store_v2(&remote_collection, &fixture, 11);
        store
            .install(&first, &first_activation, pair.resources())
            .unwrap();
        assert!(
            store
                .install(&second, &second_activation, pair.resources())
                .is_err()
        );
        assert_eq!(
            store
                .load_recovery_material_v2(&first_activation)
                .unwrap()
                .mutation_bundle(),
            &fixture.mutation_bundle
        );
    }

    #[test]
    fn v2_owner_recovery_capsule_rejects_non_old_physical_pair_before_publication() {
        let parent_temp = tempfile::tempdir().unwrap();
        let remote_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&remote_temp);
        let parent = journal(&parent_temp, &fixture);
        let activation = activation_locator_for_capsule_test(208);
        let package =
            point_stage_owner_capsule_package_v2(&parent, &fixture, &pair, 11, activation.clone());
        pair.install_hnsw_exact_new_for_recovery();
        let store = owner_capsule_store_v2(&remote_temp.path().join("collection"), &fixture, 11);

        assert!(matches!(
            store.install(&package, &activation, pair.resources()),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        assert!(store.load_recovery_material_v2(&activation).is_err());
    }

    #[test]
    fn v2_owner_recovery_capsule_fuses_consensus_authority_and_paired_recovery() {
        let parent_temp = tempfile::tempdir().unwrap();
        let owner_11_temp = tempfile::tempdir().unwrap();
        let owner_12_temp = tempfile::tempdir().unwrap();
        let (pair_11, fixture) = paired_store_fixture(&owner_11_temp);
        let (pair_12, fixture_12) = paired_store_fixture(&owner_12_temp);
        assert_eq!(fixture_12.immutable_manifest, fixture.immutable_manifest);
        assert_eq!(fixture_12.mutation_bundle, fixture.mutation_bundle);
        let parent = journal(&parent_temp, &fixture);
        let activation = activation_locator_for_capsule_test(212);
        let initial = begin_v2(&parent, &fixture, &[11, 12]);
        let prepared_owners = [(11, &pair_11), (12, &pair_12)]
            .into_iter()
            .flat_map(|(owner_peer_id, pair)| {
                pair.prepare_owner(
                    owner_peer_id,
                    &initial.descriptor.descriptor_digest,
                    &initial.state.record_digest,
                )
                .into_iter()
                .map(move |prepared| (owner_peer_id, prepared))
            })
            .collect::<Vec<_>>();
        let owner_journals = prepared_owners
            .iter()
            .map(|(owner_peer_id, prepared)| {
                (
                    *owner_peer_id,
                    prepared.owner_journal_descriptor_digest.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .map(|(owner_peer_id, journal_descriptor_digest)| {
                PrivateOramMutationOwnerJournalEvidenceV2 {
                    owner_peer_id,
                    journal_descriptor_digest,
                }
            })
            .collect::<Vec<_>>();
        let prepares = initial
            .descriptor
            .owner_requirements
            .iter()
            .map(|requirement| {
                let (_, prepared) = prepared_owners
                    .iter()
                    .find(|(owner_peer_id, prepared)| {
                        *owner_peer_id == requirement.peer_id
                            && prepared.kind == requirement.kind
                            && prepared.index_name == requirement.index_name
                    })
                    .unwrap();
                PrivateOramMutationOwnerPrepareEvidenceV1 {
                    peer_id: requirement.peer_id,
                    kind: prepared.kind,
                    index_name: prepared.index_name.clone(),
                    prepared_journal_digest: prepared.prepared_journal_digest.clone(),
                }
            })
            .collect();
        parent
            .mark_owners_prepared_with_owner_journals_v2(owner_journals, prepares)
            .unwrap();
        let point_parent = parent.validated_point_stage_parent_v2().unwrap();
        parent
            .mark_no_server_point_stage_durable_v2(&point_parent)
            .unwrap();
        let package_11 = parent
            .owner_recovery_capsule_package_v2(11, activation.clone())
            .unwrap();
        let package_12 = parent
            .owner_recovery_capsule_package_v2(12, activation.clone())
            .unwrap();
        let owner_11_store =
            owner_capsule_store_v2(&owner_11_temp.path().join("collection"), &fixture, 11);
        let owner_12_store =
            owner_capsule_store_v2(&owner_12_temp.path().join("collection"), &fixture, 12);
        let receipt_11 = owner_11_store
            .install(&package_11, &activation, pair_11.resources())
            .unwrap();
        let receipt_12 = owner_12_store
            .install(&package_12, &activation, pair_12.resources())
            .unwrap();
        let evidence_11 = signed_owner_install_evidence_v2(&fixture, receipt_11);
        let evidence_12 = signed_owner_install_evidence_v2(&fixture, receipt_12);
        let snapshot = begin_v2(&parent, &fixture, &[11, 12]);
        let point_stage =
            derive_private_oram_mutation_parent_watermark_expectation_v2(&snapshot).unwrap();
        let recovery_capsules_ready = derive_private_oram_mutation_recovery_capsules_ready_v2(
            &point_stage,
            activation.clone(),
            vec![evidence_12, evidence_11],
        )
        .unwrap();
        let mut authority = admitted_cleanup_authority(&fixture);
        for sequence in 1..=3 {
            let expected = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                &point_stage,
                sequence,
            )
            .unwrap();
            authority = apply_private_oram_mutation_authority_parent_progress_v2(
                &authority,
                &expected,
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ParentProgress,
                    private_oram_mutation_authority_request_digest_for_parent_for_test(&expected),
                    1,
                    10 + sequence,
                )
                .unwrap(),
            )
            .unwrap();
        }
        authority = apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
            &authority,
            &recovery_capsules_ready,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
                recovery_capsules_ready.ready().ready_digest().to_string(),
                1,
                14,
            )
            .unwrap(),
        )
        .unwrap();
        let authority = apply_private_oram_mutation_authority_lease_transition_v2(
            &authority,
            fixture.committed_lease.clone(),
            private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                private_oram_mutation_authority_request_digest_for_lease_for_test(
                    &fixture.committed_lease,
                )
                .unwrap(),
                digest(240),
                1,
                15,
            )
            .unwrap(),
        )
        .unwrap();
        let recovery_certificate = authority
            .aggregate()
            .unwrap()
            .recovery_capsules_certificate()
            .unwrap()
            .clone();
        let reconcile =
            PrivateOramMutationReconcileSnapshotV1::from_parts_with_recovery_capsules_for_test(
                fixture.new_consensus.clone(),
                active_lease_slot(fixture.committed_lease.clone()),
                recovery_certificate.clone(),
                activation.clone(),
            );
        let decision = build_validated_mutation_decision_evidence_v2(
            &snapshot.descriptor,
            &fixture.committed_lease,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        )
        .unwrap();
        let request = PrivateOramPeerRecoveryRequestV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: BASE64URL_NOPAD.encode(&[93; 16]),
            collection_name: "docs".to_string(),
            collection_id: fixture.mutation_bundle.mutation.collection_id.clone(),
            mutation_id: fixture.mutation_bundle.mutation.mutation_id.clone(),
            parent_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
            decision_record_digest: decision.authority_record_digest().to_string(),
            coordinator_peer_id: 11,
            owner_peer_id: 12,
            vector_name: fixture
                .immutable_manifest
                .manifest
                .indexes
                .iter()
                .find(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
                .unwrap()
                .index_name
                .clone(),
            owner_signing_key_id: fixture
                .immutable_manifest
                .manifest
                .owner_signing_key_id
                .clone(),
        };

        let missing_certificate =
            reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone());
        assert!(matches!(
            owner_12_store.recover_remote_owner_pair_v2(
                &missing_certificate,
                &request,
                pair_12.resources(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let wrong_activation =
            PrivateOramMutationReconcileSnapshotV1::from_parts_with_recovery_capsules_for_test(
                fixture.new_consensus.clone(),
                active_lease_slot(fixture.committed_lease.clone()),
                recovery_certificate,
                activation_locator_for_capsule_test(213),
            );
        assert!(
            owner_12_store
                .recover_remote_owner_pair_v2(&wrong_activation, &request, pair_12.resources())
                .is_err()
        );

        let terminal = owner_12_store
            .recover_remote_owner_pair_v2(&reconcile, &request, pair_12.resources())
            .unwrap();
        assert_eq!(terminal.challenge_nonce, request.challenge_nonce);
        assert_eq!(terminal.owner_peer_id, 12);
        assert_eq!(
            terminal.terminal_kind,
            PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew
        );
        assert_pair_store_state(
            &pair_12,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );
        let replayed = owner_12_store
            .recover_remote_owner_pair_v2(&reconcile, &request, pair_12.resources())
            .unwrap();
        assert_eq!(replayed, terminal);
    }

    #[test]
    fn v2_writer_persists_exact_new_decision_as_actual_history() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(43, 150);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        assert_eq!(
            initial.state.phase,
            PrivateOramMutationJournalPhaseV2::LeaseAcquired
        );

        let prepared = journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        assert_eq!(
            parent.owners_prepared_record_digest(),
            prepared.state.record_digest
        );
        let staged = journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        assert_eq!(
            staged.state.phase,
            PrivateOramMutationJournalPhaseV2::PointStageDurable
        );
        assert!(
            journal
                .validated_decision_for_v2_state(
                    &reconcile_snapshot(&fixture.old_consensus, fixture.preparing_lease.clone(),),
                    None
                )
                .is_err()
        );

        let decision = journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                None,
            )
            .unwrap();
        assert_eq!(decision.kind(), PrivateOramMutationDecisionKindV2::ExactNew);
        let (decided, decision_durable) = journal.mark_decision_durable_v2(&decision).unwrap();
        assert_eq!(
            decided.state.phase,
            PrivateOramMutationJournalPhaseV2::DecisionDurable
        );
        assert_eq!(decided.state.sequence, 4);
        assert!(decided.pending_next_for_test().is_none());
        let (_, mut wrong_predecessor) = journal.mark_decision_durable_v2(&decision).unwrap();
        wrong_predecessor.decision_record_digest = digest(249);
        assert!(matches!(
            journal.mark_remotes_terminal_v2(&wrong_predecessor, &[]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let (remotes, remotes_terminal) = journal
            .mark_remotes_terminal_v2(&decision_durable, &[])
            .unwrap();
        assert_eq!(
            remotes.state.phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
        assert!(matches!(
            journal.mark_local_terminal_v2(
                &remotes_terminal,
                &PrivateOramValidatedOwnerRecoveryOutcomeV1::ObservedOld,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        assert_eq!(
            fs::read_dir(journal.active_path().join("state_records"))
                .unwrap()
                .count(),
            5
        );
        assert_eq!(journal.load_v2().unwrap().unwrap(), remotes);
        let rendered =
            format!("{decision:?} {decision_durable:?} {remotes_terminal:?} {remotes:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_remote_terminal_claims_require_exact_peer_set_and_replay_exactly() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(143, 250);
        let journal = journal(&temp, &fixture);
        let (decided, decision) = prepare_no_server_decision_v2(&journal, &fixture, &[11, 12]);
        assert!(matches!(
            journal.mark_remote_terminal_claims_v2_for_test(&decision, &[]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let evidence = v2_terminal_evidence(
            &decided.descriptor,
            &decided.state,
            12,
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            60,
        );
        let claim = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            evidence.clone(),
        );
        let (terminal, first_token) = journal
            .mark_remote_terminal_claims_v2_for_test(&decision, &[claim])
            .unwrap();
        assert_eq!(
            terminal.state.phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
        assert_eq!(
            terminal.state.remote_terminals.as_ref().unwrap().owners[0],
            evidence
        );

        let replay_claim = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            evidence.clone(),
        );
        let (replayed, replay_token) = journal
            .mark_remote_terminal_claims_v2_for_test(&decision, &[replay_claim])
            .unwrap();
        assert_eq!(replayed, terminal);
        assert_eq!(
            replay_token.remotes_terminal_record_digest,
            first_token.remotes_terminal_record_digest
        );
        let rendered = format!("{first_token:?} {replay_token:?}");
        assert!(!rendered.contains(&evidence.terminal_record_digest));
        assert!(!rendered.contains(&evidence.terminal_evidence_digest));
    }

    #[test]
    fn v2_remote_terminal_claims_reject_identity_kind_digest_and_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(144, 251);
        let journal = journal(&temp, &fixture);
        let (decided, decision) = prepare_no_server_decision_v2(&journal, &fixture, &[11, 12]);
        let evidence = v2_terminal_evidence(
            &decided.descriptor,
            &decided.state,
            12,
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            70,
        );
        let mut tampered = evidence.clone();
        tampered.terminal_evidence_digest = digest(200);
        let tampered = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            tampered,
        );
        assert!(matches!(
            journal.mark_remote_terminal_claims_v2_for_test(&decision, &[tampered]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let first = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            evidence.clone(),
        );
        let second = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            evidence.clone(),
        );
        assert!(matches!(
            journal.mark_remote_terminal_claims_v2_for_test(&decision, &[first, second]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut wrong_kind_evidence = evidence.clone();
        wrong_kind_evidence.terminal_evidence_digest =
            private_oram_owner_terminal_evidence_v2_digest(
                &decided.descriptor.descriptor_digest,
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld,
                &wrong_kind_evidence,
            )
            .unwrap();
        let wrong_kind = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::AbortedOld,
            wrong_kind_evidence,
        );
        assert!(matches!(
            journal.mark_remote_terminal_claims_v2_for_test(&decision, &[wrong_kind]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let local_evidence = v2_terminal_evidence(
            &decided.descriptor,
            &decided.state,
            11,
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            80,
        );
        let local = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            local_evidence,
        );
        assert!(matches!(
            journal.mark_remote_terminal_claims_v2_for_test(&decision, &[local]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let valid = PrivateOramAuthenticatedOwnerTerminalClaimV2::from_evidence_for_test(
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            evidence,
        );
        journal
            .mark_remote_terminal_claims_v2_for_test(&decision, &[valid])
            .unwrap();
    }

    #[test]
    fn v2_remote_owner_recovery_requires_exact_persisted_material_and_request_binding() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11, 12]);
        let remote_prepared_indexes = pair.prepare_owner(
            12,
            &initial.descriptor.descriptor_digest,
            &initial.state.record_digest,
        );
        let remote_owner_journal_descriptor_digest = remote_prepared_indexes[0]
            .owner_journal_descriptor_digest
            .clone();
        let remote_prepares = remote_prepared_indexes
            .into_iter()
            .map(|prepared| {
                (
                    (prepared.kind, prepared.index_name.clone()),
                    prepared.prepared_journal_digest,
                )
            })
            .collect::<Vec<_>>();
        let prepares = initial
            .descriptor
            .owner_requirements
            .iter()
            .enumerate()
            .map(
                |(offset, requirement)| PrivateOramMutationOwnerPrepareEvidenceV1 {
                    peer_id: requirement.peer_id,
                    kind: requirement.kind,
                    index_name: requirement.index_name.clone(),
                    prepared_journal_digest: if requirement.peer_id == 12 {
                        remote_prepares
                            .iter()
                            .find(|((kind, index_name), _)| {
                                *kind == requirement.kind && index_name == &requirement.index_name
                            })
                            .map(|(_, digest)| digest)
                            .unwrap()
                            .clone()
                    } else {
                        digest(170 + u8::try_from(offset).unwrap())
                    },
                },
            )
            .collect::<Vec<_>>();
        let mut owner_journals = owner_journals_for_prepares(&prepares);
        owner_journals
            .iter_mut()
            .find(|owner| owner.owner_peer_id == 12)
            .unwrap()
            .journal_descriptor_digest = remote_owner_journal_descriptor_digest;
        journal
            .mark_owners_prepared_with_owner_journals_v2(owner_journals, prepares)
            .unwrap();
        let point_parent = journal.validated_point_stage_parent_v2().unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(&point_parent)
            .unwrap();
        let point_stage = journal.load_v2().unwrap().unwrap();
        let parent_watermark = derive_private_oram_mutation_parent_watermark_at_sequence_v2(
            &point_stage,
            PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence(),
        )
        .unwrap()
        .watermark()
        .clone();
        let reconcile = reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone())
            .with_parent_watermark_for_test(parent_watermark);
        let decision = journal
            .validated_decision_for_v2_state(&reconcile, None)
            .unwrap();
        let (decided, _) = journal.mark_decision_durable_v2(&decision).unwrap();
        let persisted = journal.load_recovery_material_v2().unwrap();
        let decision = decided.state.decision.as_ref().unwrap();
        let mut request = PrivateOramPeerRecoveryRequestV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: BASE64URL_NOPAD.encode(&[91; 16]),
            collection_name: "docs".to_string(),
            collection_id: fixture.mutation_bundle.mutation.collection_id.clone(),
            mutation_id: fixture.mutation_bundle.mutation.mutation_id.clone(),
            parent_descriptor_digest: decided.descriptor.descriptor_digest.clone(),
            decision_record_digest: decision.authority_record_digest().to_string(),
            coordinator_peer_id: 11,
            owner_peer_id: 12,
            vector_name: fixture.immutable_manifest.manifest.indexes[0]
                .index_name
                .clone(),
            owner_signing_key_id: fixture
                .immutable_manifest
                .manifest
                .owner_signing_key_id
                .clone(),
        };

        request.vector_name = "substituted-vector".to_string();
        assert!(matches!(
            journal.recover_remote_owner_pair_v2(
                &reconcile,
                &request,
                &persisted,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        request.vector_name = fixture.immutable_manifest.manifest.indexes[0]
            .index_name
            .clone();

        let mut foreign_material = persisted.clone();
        foreign_material.mutation_bundle.mutation.mutation_id = digest(219);
        assert!(matches!(
            journal.recover_remote_owner_pair_v2(
                &reconcile,
                &request,
                &foreign_material,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let terminal = journal
            .recover_remote_owner_pair_v2(&reconcile, &request, &persisted, pair.resources())
            .unwrap();
        assert_eq!(terminal.challenge_nonce, request.challenge_nonce);
        assert_eq!(terminal.owner_peer_id, 12);
        assert_eq!(
            terminal.terminal_kind,
            PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew
        );
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );
        let rendered = format!("{persisted:?} {terminal:?}");
        assert!(!rendered.contains(&request.mutation_id));
        assert!(!rendered.contains(&request.challenge_nonce));
    }

    #[test]
    fn v2_local_terminal_fuses_exact_new_and_revalidates_child_on_replay() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );

        let (resolved, local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_eq!(resolved.state.sequence, 6);
        assert!(resolved.pending_next_for_test().is_none());
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );

        let (replayed, replayed_local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(replayed, resolved);
        assert_eq!(
            replayed_local.local_terminal_record_digest,
            local.local_terminal_record_digest
        );

        fs::remove_dir_all(pair.owner_journal().root_path()).unwrap();
        assert!(matches!(
            journal.recover_local_owner_and_mark_terminal_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
    }

    #[test]
    fn v2_local_terminal_replays_hnsw_published_before_result() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );
        pair.install_hnsw_exact_new_for_recovery();

        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        assert_eq!(
            pair.hnsw_store().read_current_epoch().unwrap().index_epoch,
            new[0].index_epoch
        );
        assert_eq!(
            pair.result_store()
                .read_current_epoch()
                .unwrap()
                .index_epoch,
            old[1].index_epoch
        );
        assert_eq!(
            pair.owner_journal()
                .inspect_structural()
                .unwrap()
                .unwrap()
                .state
                .phase,
            PrivateOramOwnerJournalPhaseV1::Prepared
        );

        let resolved = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap()
            .0;
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );
        assert_eq!(
            journal
                .recover_local_owner_and_mark_terminal_v2(
                    &remotes,
                    &reconcile,
                    11,
                    pair.resources(),
                )
                .unwrap()
                .0,
            resolved
        );
    }

    #[test]
    fn v2_local_terminal_replays_both_stores_published_before_child() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );
        pair.install_hnsw_exact_new_for_recovery();
        pair.install_result_exact_new_for_recovery();

        let child = pair.owner_journal().inspect_structural().unwrap().unwrap();
        assert_eq!(child.state.phase, PrivateOramOwnerJournalPhaseV1::Prepared);
        assert!(child.terminal.is_none());
        let resolved = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap()
            .0;
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );
        assert_eq!(
            journal
                .recover_local_owner_and_mark_terminal_v2(
                    &remotes,
                    &reconcile,
                    11,
                    pair.resources(),
                )
                .unwrap()
                .0,
            resolved
        );
    }

    #[test]
    fn v2_local_terminal_fuses_exact_old_pair_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
        );

        let (resolved, local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_eq!(resolved.state.sequence, 6);
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.old_state.state,
            PrivateOramOwnerJournalPhaseV1::AbortedOld,
        );
        let (replayed, replayed_local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(replayed, resolved);
        assert_eq!(
            replayed_local.local_terminal_record_digest,
            local.local_terminal_record_digest
        );

        fs::remove_dir_all(pair.owner_journal().root_path()).unwrap();
        assert!(matches!(
            journal.recover_local_owner_and_mark_terminal_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
    }

    #[test]
    fn v2_local_terminal_exact_old_replays_child_terminal_before_parent() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
        );

        assert!(matches!(
            journal.recover_local_owner_with_parent_terminal_failure_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        let stranded = journal.load_v2().unwrap().unwrap();
        assert_eq!(
            stranded.state.phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
        assert_eq!(stranded.state.sequence, 5);
        assert!(stranded.pending_next_for_test().is_none());
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.old_state.state,
            PrivateOramOwnerJournalPhaseV1::AbortedOld,
        );

        let (recovered, local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(
            recovered.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_eq!(recovered.state.sequence, 6);
        assert!(recovered.pending_next_for_test().is_none());
        let (replayed, replayed_local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(replayed, recovered);
        assert_eq!(
            replayed_local.local_terminal_record_digest,
            local.local_terminal_record_digest
        );
    }

    #[test]
    fn v2_local_terminal_exact_old_replays_parent_before_lock_release() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
        );

        assert!(matches!(
            journal.recover_local_owner_with_post_parent_terminal_failure_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        let published = journal.load_v2().unwrap().unwrap();
        assert_eq!(
            published.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_eq!(published.state.sequence, 6);
        assert!(published.pending_next_for_test().is_none());
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.old_state.state,
            PrivateOramOwnerJournalPhaseV1::AbortedOld,
        );
        assert_eq!(
            journal
                .recover_local_owner_and_mark_terminal_v2(
                    &remotes,
                    &reconcile,
                    11,
                    pair.resources(),
                )
                .unwrap()
                .0,
            published
        );
    }

    #[test]
    fn v2_local_terminal_classifies_parent_failure_after_child_terminal_as_indeterminate() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );

        assert!(matches!(
            journal.recover_local_owner_with_parent_terminal_failure_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        let stranded = journal.load_v2().unwrap().unwrap();
        assert_eq!(
            stranded.state.phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
        assert_eq!(stranded.state.sequence, 5);
        assert!(stranded.pending_next_for_test().is_none());
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );

        let (recovered, local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(
            recovered.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_eq!(recovered.state.sequence, 6);
        assert!(recovered.pending_next_for_test().is_none());
        let (replayed, replayed_local) = journal
            .recover_local_owner_and_mark_terminal_v2(&remotes, &reconcile, 11, pair.resources())
            .unwrap();
        assert_eq!(replayed, recovered);
        assert_eq!(
            replayed_local.local_terminal_record_digest,
            local.local_terminal_record_digest
        );
        assert_eq!(
            replayed_local.expected_descriptor_digest,
            local.expected_descriptor_digest
        );
    }

    #[test]
    fn v2_local_terminal_replays_parent_published_before_lock_release() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );

        assert!(matches!(
            journal.recover_local_owner_with_post_parent_terminal_failure_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        let published = journal.load_v2().unwrap().unwrap();
        assert_eq!(
            published.state.phase,
            PrivateOramMutationJournalPhaseV2::LocalTerminal
        );
        assert_eq!(published.state.sequence, 6);
        assert_pair_store_state(
            &pair,
            &fixture.mutation_bundle.mutation.new_state.state,
            PrivateOramOwnerJournalPhaseV1::Finalized,
        );

        assert_eq!(
            journal
                .recover_local_owner_and_mark_terminal_v2(
                    &remotes,
                    &reconcile,
                    11,
                    pair.resources(),
                )
                .unwrap()
                .0,
            published
        );
    }

    #[test]
    fn v2_local_terminal_rolls_forward_exact_pending_sequence_six() {
        let expected_temp = tempfile::tempdir().unwrap();
        let (expected_pair, expected_fixture) = paired_store_fixture(&expected_temp);
        let expected_journal = journal(&expected_temp, &expected_fixture);
        let (expected_reconcile, expected_remotes) = prepare_paired_recovery_v2(
            &expected_journal,
            &expected_pair,
            &expected_fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );
        let expected = expected_journal
            .recover_local_owner_and_mark_terminal_v2(
                &expected_remotes,
                &expected_reconcile,
                11,
                expected_pair.resources(),
            )
            .unwrap()
            .0;

        let pending_temp = tempfile::tempdir().unwrap();
        let (pending_pair, pending_fixture) = paired_store_fixture(&pending_temp);
        let pending_journal = journal(&pending_temp, &pending_fixture);
        let (pending_reconcile, pending_remotes) = prepare_paired_recovery_v2(
            &pending_journal,
            &pending_pair,
            &pending_fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );
        assert!(matches!(
            pending_journal.recover_local_owner_with_parent_terminal_failure_v2(
                &pending_remotes,
                &pending_reconcile,
                11,
                pending_pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        let before = pending_journal.load_v2().unwrap().unwrap();
        assert_eq!(before.descriptor, expected.descriptor);
        assert_eq!(
            before.state.phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
        write_new_json_private(
            &v2_record_path(&pending_journal, 6),
            &expected.state,
            MAX_STATE_BYTES,
        )
        .unwrap();
        sync_directory(&pending_journal.active_path().join("state_records")).unwrap();
        let pending = pending_journal.load_v2().unwrap().unwrap();
        assert_eq!(pending.state, before.state);
        assert_eq!(pending.pending_next_for_test(), Some(&expected.state));

        let rolled = pending_journal
            .recover_local_owner_and_mark_terminal_v2(
                &pending_remotes,
                &pending_reconcile,
                11,
                pending_pair.resources(),
            )
            .unwrap()
            .0;
        assert_eq!(rolled, expected);
        assert!(rolled.pending_next_for_test().is_none());
    }

    #[test]
    fn v2_local_terminal_rejects_pending_remotes_before_child_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );
        let decision: PrivateOramMutationJournalStateV2 =
            read_json_private(&v2_record_path(&journal, 4), MAX_STATE_BYTES).unwrap();
        fs::write(journal.state_path(), serde_json::to_vec(&decision).unwrap()).unwrap();
        sync_directory(&journal.active_path()).unwrap();
        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(
            observed.state.phase,
            PrivateOramMutationJournalPhaseV2::DecisionDurable
        );
        assert_eq!(
            observed.pending_next_for_test().unwrap().phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );

        assert!(matches!(
            journal.recover_local_owner_and_mark_terminal_v2(
                &remotes,
                &reconcile,
                11,
                pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        assert_eq!(
            pair.hnsw_store().read_current_epoch().unwrap().index_epoch,
            old[0].index_epoch
        );
        assert_eq!(
            pair.result_store()
                .read_current_epoch()
                .unwrap()
                .index_epoch,
            old[1].index_epoch
        );
        let child = pair.owner_journal().inspect_structural().unwrap().unwrap();
        assert_eq!(child.state.phase, PrivateOramOwnerJournalPhaseV1::Prepared);
        assert!(child.terminal.is_none());
    }

    #[test]
    fn v2_local_terminal_rejects_cross_collection_store_resources_before_mutation() {
        let local_temp = tempfile::tempdir().unwrap();
        let (local_pair, fixture) = paired_store_fixture(&local_temp);
        let journal = journal(&local_temp, &fixture);
        let (reconcile, remotes) = prepare_paired_recovery_v2(
            &journal,
            &local_pair,
            &fixture,
            PrivateOramMutationReconcileDispositionV1::ExactNew,
        );

        let foreign_temp = tempfile::tempdir().unwrap();
        let (foreign_pair, foreign_fixture) = paired_store_fixture(&foreign_temp);
        assert!(matches!(
            journal.recover_local_owner_and_mark_terminal_v2(
                &remotes,
                &reconcile,
                11,
                foreign_pair.resources(),
            ),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        assert_eq!(
            local_pair
                .hnsw_store()
                .read_current_epoch()
                .unwrap()
                .index_epoch,
            old[0].index_epoch
        );
        assert_eq!(
            local_pair
                .result_store()
                .read_current_epoch()
                .unwrap()
                .index_epoch,
            old[1].index_epoch
        );
        let child = local_pair
            .owner_journal()
            .inspect_structural()
            .unwrap()
            .unwrap();
        assert_eq!(child.state.phase, PrivateOramOwnerJournalPhaseV1::Prepared);
        assert!(child.terminal.is_none());
        let foreign_old = &foreign_fixture
            .mutation_bundle
            .mutation
            .old_state
            .state
            .indexes;
        assert_eq!(
            foreign_pair
                .hnsw_store()
                .read_current_epoch()
                .unwrap()
                .index_epoch,
            foreign_old[0].index_epoch
        );
        assert_eq!(
            foreign_pair
                .result_store()
                .read_current_epoch()
                .unwrap()
                .index_epoch,
            foreign_old[1].index_epoch
        );
        assert!(
            foreign_pair
                .owner_journal()
                .inspect_structural()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn v2_writer_requires_abort_decision_for_exact_old() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(44, 160);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        assert!(
            journal
                .validated_decision_for_v2_state(
                    &reconcile_snapshot(&fixture.old_consensus, fixture.preparing_lease.clone(),),
                    None
                )
                .is_err()
        );

        let mut abort_decided = fixture.preparing_lease.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let decision = journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(&fixture.old_consensus, abort_decided),
                None,
            )
            .unwrap();
        assert_eq!(
            decision.kind(),
            PrivateOramMutationDecisionKindV2::ExactOldAbort
        );
        let (decided, decision_durable) = journal.mark_decision_durable_v2(&decision).unwrap();
        assert_eq!(
            decided.state.phase,
            PrivateOramMutationJournalPhaseV2::DecisionDurable
        );
        assert_eq!(
            journal
                .mark_remotes_terminal_v2(&decision_durable, &[])
                .unwrap()
                .0
                .state
                .phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
    }

    #[test]
    fn v2_writer_point_resolution_requires_exact_local_terminal_token() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(59, 120);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let synthetic = v1_snapshot_for_descriptor(&initial.descriptor);
        let local_state = v2_no_server_terminal_state(
            &synthetic,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        install_v2_state_for_test(&journal, &initial.descriptor, &local_state);

        let local = journal.validated_local_terminal_for_current_v2().unwrap();
        let resolved = journal.mark_no_server_point_resolved_v2(&local).unwrap();
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::PointResolved
        );
        assert_eq!(resolved.state.sequence, 7);
        assert_eq!(
            journal.mark_no_server_point_resolved_v2(&local).unwrap(),
            resolved
        );

        let mut wrong_local = journal.validated_local_terminal_for_current_v2().unwrap();
        wrong_local.local_terminal_record_digest = digest(249);
        assert!(matches!(
            journal.mark_no_server_point_resolved_v2(&wrong_local),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let rendered = format!("{local:?} {wrong_local:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_writer_rolls_forward_only_the_exact_pending_point_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(61, 160);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let synthetic = v1_snapshot_for_descriptor(&initial.descriptor);
        let local_state = v2_no_server_terminal_state(
            &synthetic,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        install_v2_state_for_test(&journal, &initial.descriptor, &local_state);
        let pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &local_state,
            PrivateOramMutationJournalPhaseV2::PointResolved,
            |next| {
                next.point_resolution = Some(
                    PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                        decision_kind: PrivateOramMutationDecisionKindV2::ExactNew,
                        parent_local_terminal_record_digest: local_state.record_digest.clone(),
                    },
                );
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();
        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, local_state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));

        let local = journal.validated_local_terminal_for_current_v2().unwrap();
        let resolved = journal.mark_no_server_point_resolved_v2(&local).unwrap();
        assert_eq!(resolved.state, pending);
        assert!(resolved.pending_next_for_test().is_none());
    }

    #[test]
    fn v2_writer_validates_visible_point_receipt_under_live_stage_lock() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(60, 140, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        let collection_path = temp.path().join("collection");
        let point_store = PrivateOramPointStagingStore::new(&collection_path);
        let (_, durable) = point_store
            .prepare(fixture.staged_frame_bytes.as_deref().unwrap(), &parent)
            .unwrap();
        let staged = journal
            .mark_private_point_stage_durable_v2(&durable)
            .unwrap();

        let mut local_state = staged.state.clone();
        local_state.phase = PrivateOramMutationJournalPhaseV2::LocalTerminal;
        local_state.sequence = PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence();
        local_state.decision = Some(
            exact_new_decision_v2_for_test(
                &staged.descriptor,
                &fixture.committed_lease,
                &fixture.new_consensus,
            )
            .unwrap(),
        );
        local_state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: Vec::new(),
        });
        local_state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: vec![v2_terminal_evidence(
                &staged.descriptor,
                &local_state,
                staged.descriptor.coordinator_peer_id,
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                241,
            )],
        });
        local_state =
            canonical_private_oram_mutation_state_v2_for_test(&staged.descriptor, &local_state)
                .unwrap();
        install_v2_state_for_test(&journal, &staged.descriptor, &local_state);

        let local = journal.validated_local_terminal_for_current_v2().unwrap();
        let receipt = point_resolution_receipt_for_local_state(
            &staged.descriptor,
            &local_state,
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
        );
        let foreign_collection = temp.path().join("foreign-collection");
        fs::create_dir(&foreign_collection).unwrap();
        let foreign_store = PrivateOramPointStagingStore::new(&foreign_collection);
        assert!(matches!(
            journal.mark_private_point_resolved_v2(
                &local,
                &foreign_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                receipt.clone(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut wrong = receipt.clone();
        wrong.observations[0] = PrivateOramPointReplicaObservationV2::Absent {
            shard_id: wrong.replicas[0].shard_id,
            peer_id: wrong.replicas[0].peer_id,
        };
        wrong.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            &wrong,
        )
        .unwrap();
        assert!(matches!(
            journal.mark_private_point_resolved_v2(
                &local,
                &point_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                wrong,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let resolved = journal
            .mark_private_point_resolved_v2(
                &local,
                &point_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                receipt.clone(),
            )
            .unwrap();
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::PointResolved
        );
        fs::remove_dir_all(collection_path.join(
            crate::content_manager::private_oram_point_staging::PRIVATE_ORAM_POINT_STAGING_DIR,
        ))
        .unwrap();
        assert_eq!(
            journal
                .mark_private_point_resolved_v2(
                    &local,
                    &point_store,
                    PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                    receipt.clone(),
                )
                .unwrap(),
            resolved
        );
        let mut different_after_cleanup = receipt;
        different_after_cleanup.observations[0] = PrivateOramPointReplicaObservationV2::Absent {
            shard_id: different_after_cleanup.replicas[0].shard_id,
            peer_id: different_after_cleanup.replicas[0].peer_id,
        };
        different_after_cleanup.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            &different_after_cleanup,
        )
        .unwrap();
        assert!(matches!(
            journal.mark_private_point_resolved_v2(
                &local,
                &point_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                different_after_cleanup,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let rendered = format!("{local:?} {resolved:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_phase_tokens_reject_cross_descriptor_reuse_and_replay_exactly() {
        let first_temp = tempfile::tempdir().unwrap();
        let first_fixture = fixture(54, 20);
        let first_journal = journal(&first_temp, &first_fixture);
        let first_initial = begin_v2(&first_journal, &first_fixture, &[11]);
        first_journal
            .mark_owners_prepared_v2(owner_prepares_v2(&first_initial))
            .unwrap();
        let first_parent = first_journal.validated_point_stage_parent_v2().unwrap();
        first_journal
            .mark_no_server_point_stage_durable_v2(&first_parent)
            .unwrap();
        let first_decision = first_journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(
                    &first_fixture.new_consensus,
                    first_fixture.committed_lease.clone(),
                ),
                None,
            )
            .unwrap();
        let (_, first_decision_durable) = first_journal
            .mark_decision_durable_v2(&first_decision)
            .unwrap();

        let second_temp = tempfile::tempdir().unwrap();
        let second_fixture = fixture(55, 40);
        let second_journal = journal(&second_temp, &second_fixture);
        let second_initial = begin_v2(&second_journal, &second_fixture, &[11]);
        second_journal
            .mark_owners_prepared_v2(owner_prepares_v2(&second_initial))
            .unwrap();
        let second_parent = second_journal.validated_point_stage_parent_v2().unwrap();
        second_journal
            .mark_no_server_point_stage_durable_v2(&second_parent)
            .unwrap();
        let second_decision = second_journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(
                    &second_fixture.new_consensus,
                    second_fixture.committed_lease.clone(),
                ),
                None,
            )
            .unwrap();
        let (_, second_decision_durable) = second_journal
            .mark_decision_durable_v2(&second_decision)
            .unwrap();

        assert!(matches!(
            second_journal.mark_remotes_terminal_v2(&first_decision_durable, &[]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let (first_remote, first_remote_token) = second_journal
            .mark_remotes_terminal_v2(&second_decision_durable, &[])
            .unwrap();
        let (replayed_remote, replayed_remote_token) = second_journal
            .mark_remotes_terminal_v2(&second_decision_durable, &[])
            .unwrap();
        assert_eq!(replayed_remote, first_remote);
        assert_eq!(
            replayed_remote_token.remotes_terminal_record_digest,
            first_remote_token.remotes_terminal_record_digest
        );
    }

    #[test]
    fn v2_writer_accepts_only_durable_visible_point_stage_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(51, 230, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        let point_store = PrivateOramPointStagingStore::new(&temp.path().join("collection"));
        let (_, durable) = point_store
            .prepare(fixture.staged_frame_bytes.as_deref().unwrap(), &parent)
            .unwrap();
        let staged = journal
            .mark_private_point_stage_durable_v2(&durable)
            .unwrap();
        let Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            point_semantic_digest,
            target_shard_ids,
            ..
        }) = staged.state.point_stage.as_ref()
        else {
            panic!("expected visible private point stage");
        };
        assert_eq!(point_semantic_digest, durable.point_semantic_digest());
        assert_eq!(target_shard_ids, durable.target_shard_ids());
        assert_eq!(journal.load_v2().unwrap().unwrap(), staged);
        let reconcile = reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone());
        assert!(
            journal
                .validated_decision_for_v2_state(&reconcile, None)
                .is_err()
        );
        let decision = journal
            .validated_decision_for_v2_state(&reconcile, Some(&durable))
            .unwrap();
        assert_eq!(decision.kind(), PrivateOramMutationDecisionKindV2::ExactNew);
    }

    #[test]
    fn v2_writer_rejects_legacy_and_mixed_active_layouts() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(45, 170);
        let journal = journal(&temp, &fixture);
        begin(&journal, &fixture, &[11]);
        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::LegacyV1State)
        ));
        assert!(matches!(
            journal.begin_v2(
                11,
                &[11],
                fixture.immutable_manifest.clone(),
                fixture.mutation_bundle.clone(),
                fixture.preparing_lease.clone(),
                fixture.old_consensus.clone(),
            ),
            Err(PrivateOramMutationJournalError::LegacyV1State)
        ));

        write_new_json_private(
            &journal.active_path().join("format.json"),
            &json!({
                "state_version": 2,
                "descriptor_digest": digest(250),
            }),
            1 << 12,
        )
        .unwrap();
        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_opaque_resume_facade_advances_no_server_terminal_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepared_indexes = pair.prepare_owner(
            initial.descriptor.coordinator_peer_id,
            &initial.descriptor.descriptor_digest,
            &initial.state.record_digest,
        );
        let owner_journals = vec![PrivateOramMutationOwnerJournalEvidenceV2 {
            owner_peer_id: initial.descriptor.coordinator_peer_id,
            journal_descriptor_digest: prepared_indexes[0].owner_journal_descriptor_digest.clone(),
        }];
        let prepares = prepared_indexes
            .into_iter()
            .map(|prepared| PrivateOramMutationOwnerPrepareEvidenceV1 {
                peer_id: initial.descriptor.coordinator_peer_id,
                kind: prepared.kind,
                index_name: prepared.index_name,
                prepared_journal_digest: prepared.prepared_journal_digest,
            })
            .collect();
        let owners = journal
            .mark_owners_prepared_with_owner_journals_v2(owner_journals, prepares)
            .unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(
                &journal.validated_point_stage_parent_v2().unwrap(),
            )
            .unwrap();
        assert_eq!(
            owners.state.phase,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared
        );

        let authority_at = |sequence| {
            let snapshot = journal.load_v2().unwrap().unwrap();
            let parent_watermark =
                derive_private_oram_mutation_parent_watermark_at_sequence_v2(&snapshot, sequence)
                    .unwrap()
                    .watermark()
                    .clone();
            let reconcile =
                reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone())
                    .with_parent_watermark_for_test(parent_watermark);
            LinearizablePrivateOramMutationReconcileSnapshotV2::from_snapshot_for_test(
                reconcile, 100,
            )
        };
        let PrivateOramMutationResumeV2::NeedDecision(decision) = journal
            .open_private_oram_mutation_resume_v2(authority_at(3), "docs")
            .unwrap()
        else {
            panic!("expected decision resume phase")
        };
        journal.resume_private_oram_decision_v2(decision).unwrap();
        assert!(matches!(
            journal
                .open_private_oram_mutation_resume_v2(authority_at(3), "docs")
                .unwrap(),
            PrivateOramMutationResumeV2::NeedParentProgress(_)
        ));

        let PrivateOramMutationResumeV2::NeedRemoteTerminals(remotes) = journal
            .open_private_oram_mutation_resume_v2(authority_at(4), "docs")
            .unwrap()
        else {
            panic!("expected remote terminal resume phase")
        };
        assert!(remotes.requests().is_empty());
        journal
            .resume_private_oram_remote_terminals_v2(remotes, authority_at(4), &[])
            .unwrap();
        assert!(matches!(
            journal
                .open_private_oram_mutation_resume_v2(authority_at(4), "docs")
                .unwrap(),
            PrivateOramMutationResumeV2::NeedParentProgress(_)
        ));

        let PrivateOramMutationResumeV2::NeedLocalTerminal(local) = journal
            .open_private_oram_mutation_resume_v2(authority_at(5), "docs")
            .unwrap()
        else {
            panic!("expected local terminal resume phase")
        };
        journal
            .resume_private_oram_local_terminal_v2(local, 11, pair.resources())
            .unwrap();
        assert!(matches!(
            journal
                .open_private_oram_mutation_resume_v2(authority_at(5), "docs")
                .unwrap(),
            PrivateOramMutationResumeV2::NeedParentProgress(_)
        ));

        let PrivateOramMutationResumeV2::NeedPointResolution(point) = journal
            .open_private_oram_mutation_resume_v2(authority_at(6), "docs")
            .unwrap()
        else {
            panic!("expected point resolution resume phase")
        };
        journal
            .resume_private_oram_no_server_point_resolution_v2(point)
            .unwrap();
        assert!(matches!(
            journal
                .open_private_oram_mutation_resume_v2(authority_at(6), "docs")
                .unwrap(),
            PrivateOramMutationResumeV2::NeedParentProgress(_)
        ));
        let genesis = private_oram_mutation_cleanup_lifecycle_genesis_v2(
            &fixture.preparing_lease.collection_id,
            digest(245),
            digest(246),
        )
        .unwrap();
        let inactive_slot = inactive_lease_slot();
        let admitted = apply_private_oram_mutation_admission_v2(
            &genesis,
            &inactive_slot,
            fixture.preparing_lease.clone(),
            private_oram_mutation_admission_recovery_manifest_for_test(
                &fixture.preparing_lease,
                genesis.lifecycle_digest(),
            ),
            private_oram_admission_applied_entry_for_test(
                &genesis,
                &inactive_slot,
                &fixture.preparing_lease,
                1,
                10,
            )
            .unwrap(),
        )
        .unwrap();
        let terminal_snapshot = journal.load_v2().unwrap().unwrap();
        let terminal_expectation = derive_private_oram_mutation_parent_watermark_at_sequence_v2(
            &terminal_snapshot,
            PrivateOramMutationJournalPhaseV2::PointResolved.sequence(),
        )
        .unwrap();
        let mut cleanup_lifecycle = admitted.lifecycle().clone();
        let preparing_slot = admitted.lease_slot().clone();
        for sequence in 1..=7 {
            let expectation = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                &terminal_expectation,
                sequence,
            )
            .unwrap();
            cleanup_lifecycle = apply_private_oram_mutation_parent_progress_v2(
                &cleanup_lifecycle,
                &preparing_slot,
                &expectation,
                private_oram_parent_progress_applied_entry_for_test(
                    &cleanup_lifecycle,
                    &preparing_slot,
                    &expectation,
                    1,
                    10 + sequence,
                )
                .unwrap(),
            )
            .unwrap();
        }
        let terminal_slot = active_lease_slot(fixture.committed_lease.clone());
        let authority_with_cleanup = |lifecycle: &PrivateOramMutationCleanupLifecycleV2| {
            let snapshot = journal.load_v2().unwrap().unwrap();
            let parent_watermark =
                derive_private_oram_mutation_parent_watermark_at_sequence_v2(&snapshot, 7)
                    .unwrap()
                    .watermark()
                    .clone();
            let reconcile =
                reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone())
                    .with_parent_watermark_for_test(parent_watermark)
                    .with_cleanup_lifecycle_for_test(lifecycle.clone());
            LinearizablePrivateOramMutationReconcileSnapshotV2::from_snapshot_for_test(
                reconcile, 101,
            )
        };
        let terminal = match journal
            .open_private_oram_mutation_resume_v2(
                authority_with_cleanup(&cleanup_lifecycle),
                "docs",
            )
            .unwrap()
        {
            PrivateOramMutationResumeV2::Complete(terminal) => terminal,
            other => panic!("expected terminal cleanup authority, got {other:?}"),
        };
        let PrivateOramMutationCleanupV2::NeedCleanupWitness(witness_permit) = journal
            .open_private_oram_mutation_cleanup_v2(terminal)
            .unwrap()
        else {
            panic!("expected cleanup witness")
        };
        let witness_proposal = witness_permit.into_proposal();
        let witness_applied = private_oram_cleanup_witness_applied_entry_for_test(
            &cleanup_lifecycle,
            &terminal_slot,
            witness_proposal.expectation(),
            1,
            30,
        )
        .unwrap();
        cleanup_lifecycle = apply_private_oram_mutation_cleanup_witness_v2(
            &cleanup_lifecycle,
            &terminal_slot,
            witness_proposal.expectation(),
            witness_applied,
        )
        .unwrap();

        let terminal = match journal
            .open_private_oram_mutation_resume_v2(
                authority_with_cleanup(&cleanup_lifecycle),
                "docs",
            )
            .unwrap()
        {
            PrivateOramMutationResumeV2::Complete(terminal) => terminal,
            other => panic!("expected terminal cleanup authority, got {other:?}"),
        };
        let PrivateOramMutationCleanupV2::NeedLocalCleanup(local_cleanup) = journal
            .open_private_oram_mutation_cleanup_v2(terminal)
            .unwrap()
        else {
            panic!("expected local cleanup")
        };
        assert!(
            cleanup_lifecycle
                .matches_cleanup_witness(local_cleanup.generation, &local_cleanup.witness_digest)
                .unwrap()
        );
        assert!(
            !cleanup_lifecycle
                .matches_cleanup_witness(
                    local_cleanup.generation + 1,
                    &local_cleanup.witness_digest,
                )
                .unwrap()
        );
        set_fail_immutable_json_after_rename_v2(true);
        assert!(matches!(
            journal.complete_private_oram_mutation_local_cleanup_v2(local_cleanup),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        set_fail_immutable_json_after_rename_v2(false);
        let terminal = match journal
            .open_private_oram_mutation_resume_v2(
                authority_with_cleanup(&cleanup_lifecycle),
                "docs",
            )
            .unwrap()
        {
            PrivateOramMutationResumeV2::Complete(terminal) => terminal,
            other => {
                panic!("expected terminal cleanup authority after marker fault, got {other:?}")
            }
        };
        let PrivateOramMutationCleanupV2::NeedLocalCleanup(local_cleanup) = journal
            .open_private_oram_mutation_cleanup_v2(terminal)
            .unwrap()
        else {
            panic!("expected local cleanup replay after marker fault")
        };
        let clear_pending = journal
            .complete_private_oram_mutation_local_cleanup_v2(local_cleanup)
            .unwrap();
        let (clear_key, clear_generation, clear_witness_digest, clear_attempt) =
            clear_pending.into_parts();
        assert_eq!(
            clear_key.collection_id,
            fixture.mutation_bundle.mutation.collection_id
        );
        assert_eq!(clear_generation, terminal_slot.generation);
        let terminal = match journal
            .open_private_oram_mutation_resume_v2(
                authority_with_cleanup(&cleanup_lifecycle),
                "docs",
            )
            .unwrap()
        {
            PrivateOramMutationResumeV2::Complete(terminal) => terminal,
            other => panic!("expected terminal cleanup replay authority, got {other:?}"),
        };
        let PrivateOramMutationCleanupV2::NeedLocalCleanup(replayed_local_cleanup) = journal
            .open_private_oram_mutation_cleanup_v2(terminal)
            .unwrap()
        else {
            panic!("expected local cleanup replay before clear-pending")
        };
        let (
            replayed_clear_key,
            replayed_clear_generation,
            replayed_clear_witness_digest,
            replayed_clear_attempt,
        ) = journal
            .complete_private_oram_mutation_local_cleanup_v2(replayed_local_cleanup)
            .unwrap()
            .into_parts();
        assert_eq!(replayed_clear_key, clear_key);
        assert_eq!(replayed_clear_generation, clear_generation);
        assert_eq!(replayed_clear_witness_digest, clear_witness_digest);
        assert_eq!(replayed_clear_attempt, clear_attempt);
        cleanup_lifecycle = apply_private_oram_mutation_clear_pending_v2(
            &cleanup_lifecycle,
            &terminal_slot,
            clear_attempt.clone(),
            private_oram_clear_pending_applied_entry_for_test(
                &cleanup_lifecycle,
                &terminal_slot,
                &clear_attempt,
                1,
                31,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            cleanup_lifecycle
                .matches_clear_pending(clear_generation, &clear_attempt)
                .unwrap()
        );
        assert!(
            !cleanup_lifecycle
                .matches_clear_pending(clear_generation + 1, &clear_attempt)
                .unwrap()
        );

        let terminal = match journal
            .open_private_oram_mutation_resume_v2(
                authority_with_cleanup(&cleanup_lifecycle),
                "docs",
            )
            .unwrap()
        {
            PrivateOramMutationResumeV2::Complete(terminal) => terminal,
            other => panic!("expected terminal cleanup authority, got {other:?}"),
        };
        let PrivateOramMutationCleanupV2::NeedClear(clear_permit) = journal
            .open_private_oram_mutation_cleanup_v2(terminal)
            .unwrap()
        else {
            panic!("expected exact-generation clear")
        };
        assert_eq!(clear_permit.expected_clear_attempt_id_digest, clear_attempt);
        let cleared = apply_private_oram_mutation_clear_v2(
            &cleanup_lifecycle,
            &terminal_slot,
            private_oram_clear_applied_entry_for_test(&cleanup_lifecycle, &terminal_slot, 1, 32)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            cleared.lifecycle().pending_acknowledgement_owner().unwrap(),
            Some((11, terminal_slot.generation))
        );
        let restarted_cleanup_lifecycle: PrivateOramMutationCleanupLifecycleV2 =
            serde_json::from_slice(&serde_json::to_vec(cleared.lifecycle()).unwrap()).unwrap();
        assert_eq!(
            restarted_cleanup_lifecycle
                .pending_acknowledgement_owner()
                .unwrap(),
            Some((11, terminal_slot.generation))
        );
        let archive_permit = private_oram_cleared_pending_archive_permit_for_test(
            cleared.lifecycle(),
            fixture.mutation_bundle.mutation.collection_id.clone(),
            fixture.immutable_manifest.manifest.indexes[0]
                .index_name
                .clone(),
            fixture
                .immutable_manifest
                .manifest
                .owner_signing_key_id
                .clone(),
            11,
            terminal_slot.generation,
        )
        .unwrap();
        set_fail_immutable_json_after_rename_v2(true);
        assert!(matches!(
            journal.archive_private_oram_mutation_after_clear_v2(archive_permit),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        set_fail_immutable_json_after_rename_v2(false);
        assert!(journal.load_v2().unwrap().is_none());
        let replay_permit = private_oram_cleared_pending_archive_permit_for_test(
            cleared.lifecycle(),
            fixture.mutation_bundle.mutation.collection_id.clone(),
            fixture.immutable_manifest.manifest.indexes[0]
                .index_name
                .clone(),
            fixture
                .immutable_manifest
                .manifest
                .owner_signing_key_id
                .clone(),
            11,
            terminal_slot.generation,
        )
        .unwrap();
        journal
            .archive_private_oram_mutation_after_clear_v2(replay_permit)
            .unwrap();

        let archive_name = format!(
            "{TERMINAL_ARCHIVE_NAME_PREFIX_V2}{:020}",
            terminal_slot.generation
        );
        let archive_path = journal.root.join(&archive_name);
        create_private_directory(&journal.active_path()).unwrap();
        let duplicate_permit = private_oram_cleared_pending_archive_permit_for_test(
            cleared.lifecycle(),
            fixture.mutation_bundle.mutation.collection_id.clone(),
            fixture.immutable_manifest.manifest.indexes[0]
                .index_name
                .clone(),
            fixture
                .immutable_manifest
                .manifest
                .owner_signing_key_id
                .clone(),
            11,
            terminal_slot.generation,
        )
        .unwrap();
        assert!(matches!(
            journal.archive_private_oram_mutation_after_clear_v2(duplicate_permit),
            Err(PrivateOramMutationJournalError::ConcurrentMutation)
        ));
        fs::remove_dir(journal.active_path()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let parked_archive = journal.root.join("terminal-archive-symlink-target-v2");
            fs::rename(&archive_path, &parked_archive).unwrap();
            symlink(&parked_archive, &archive_path).unwrap();
            let symlink_permit = private_oram_cleared_pending_archive_permit_for_test(
                cleared.lifecycle(),
                fixture.mutation_bundle.mutation.collection_id.clone(),
                fixture.immutable_manifest.manifest.indexes[0]
                    .index_name
                    .clone(),
                fixture
                    .immutable_manifest
                    .manifest
                    .owner_signing_key_id
                    .clone(),
                11,
                terminal_slot.generation,
            )
            .unwrap();
            assert!(
                journal
                    .archive_private_oram_mutation_after_clear_v2(symlink_permit)
                    .is_err()
            );
            fs::remove_file(&archive_path).unwrap();
            fs::rename(parked_archive, &archive_path).unwrap();
        }

        let restored_archive_permit = private_oram_cleared_pending_archive_permit_for_test(
            cleared.lifecycle(),
            fixture.mutation_bundle.mutation.collection_id.clone(),
            fixture.immutable_manifest.manifest.indexes[0]
                .index_name
                .clone(),
            fixture
                .immutable_manifest
                .manifest
                .owner_signing_key_id
                .clone(),
            11,
            terminal_slot.generation,
        )
        .unwrap();
        journal
            .archive_private_oram_mutation_after_clear_v2(restored_archive_permit)
            .unwrap();
        let acknowledged = acknowledge_private_oram_mutation_clear_v2(
            cleared.lifecycle(),
            cleared.lease_slot(),
            private_oram_clear_acknowledgement_applied_entry_for_test(
                cleared.lifecycle(),
                cleared.lease_slot(),
                1,
                33,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(acknowledged.pending_acknowledgement_owner().unwrap(), None);
    }

    #[test]
    fn v2_opaque_resume_rejects_ids_visible_before_terminal_side_effects() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(201, 33);
        assert_eq!(
            fixture.immutable_manifest.manifest.result_privacy,
            ResultPrivacyMode::IdsVisible
        );
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        journal
            .mark_owners_prepared_with_owner_journals_v2(
                owner_journals_for_prepares(&prepares),
                prepares,
            )
            .unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(
                &journal.validated_point_stage_parent_v2().unwrap(),
            )
            .unwrap();
        let snapshot = journal.load_v2().unwrap().unwrap();
        let parent_watermark = derive_private_oram_mutation_parent_watermark_at_sequence_v2(
            &snapshot,
            PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence(),
        )
        .unwrap()
        .watermark()
        .clone();
        let reconcile = reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone())
            .with_parent_watermark_for_test(parent_watermark);
        let authority = LinearizablePrivateOramMutationReconcileSnapshotV2::from_snapshot_for_test(
            reconcile, 102,
        );
        assert!(matches!(
            journal.open_private_oram_mutation_resume_v2(authority, "docs"),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        assert_eq!(
            journal.load_v2().unwrap().unwrap().state.phase,
            PrivateOramMutationJournalPhaseV2::PointStageDurable
        );
    }

    #[test]
    fn v2_writer_resumes_only_an_exact_pending_typed_transition() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(46, 180);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_journals = owner_journals_for_prepares(&prepares);
                next.owner_prepares = prepares.clone();
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();

        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, initial.state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));
        let resumed = journal.mark_owners_prepared_v2(prepares).unwrap();
        assert_eq!(resumed.state, pending);
        assert!(resumed.pending_next_for_test().is_none());
    }

    #[test]
    fn v2_writer_resumes_a_pending_decision_durable_record() {
        // A crash between publishing the DecisionDurable record and moving the pointer leaves
        // the record as `pending_next`; restart resume must republish it, not refuse forever.
        let temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&temp);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepared_indexes = pair.prepare_owner(
            initial.descriptor.coordinator_peer_id,
            &initial.descriptor.descriptor_digest,
            &initial.state.record_digest,
        );
        let owner_journals = vec![PrivateOramMutationOwnerJournalEvidenceV2 {
            owner_peer_id: initial.descriptor.coordinator_peer_id,
            journal_descriptor_digest: prepared_indexes[0].owner_journal_descriptor_digest.clone(),
        }];
        let prepares = prepared_indexes
            .into_iter()
            .map(|prepared| PrivateOramMutationOwnerPrepareEvidenceV1 {
                peer_id: initial.descriptor.coordinator_peer_id,
                kind: prepared.kind,
                index_name: prepared.index_name,
                prepared_journal_digest: prepared.prepared_journal_digest,
            })
            .collect();
        journal
            .mark_owners_prepared_with_owner_journals_v2(owner_journals, prepares)
            .unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(
                &journal.validated_point_stage_parent_v2().unwrap(),
            )
            .unwrap();
        let authority_at = |sequence| {
            let snapshot = journal.load_v2().unwrap().unwrap();
            let parent_watermark =
                derive_private_oram_mutation_parent_watermark_at_sequence_v2(&snapshot, sequence)
                    .unwrap()
                    .watermark()
                    .clone();
            let reconcile =
                reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone())
                    .with_parent_watermark_for_test(parent_watermark);
            LinearizablePrivateOramMutationReconcileSnapshotV2::from_snapshot_for_test(
                reconcile, 100,
            )
        };

        // Publish the DecisionDurable record without moving the pointer.
        let PrivateOramMutationResumeV2::NeedDecision(permit) = journal
            .open_private_oram_mutation_resume_v2(authority_at(3), "docs")
            .unwrap()
        else {
            panic!("expected decision resume phase")
        };
        let point_stage = journal.load_v2().unwrap().unwrap();
        let pending = next_private_oram_mutation_state_v2(
            &point_stage.descriptor,
            &point_stage.state,
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
            |next| {
                next.decision = Some(permit.decision.evidence.clone());
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();
        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, point_stage.state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));

        // Resume still mints the decision permit and applying it completes the transition.
        let PrivateOramMutationResumeV2::NeedDecision(resumed) = journal
            .open_private_oram_mutation_resume_v2(authority_at(3), "docs")
            .unwrap()
        else {
            panic!("a pending decision record must resume as NeedDecision")
        };
        journal.resume_private_oram_decision_v2(resumed).unwrap();
        let completed = journal.load_v2().unwrap().unwrap();
        assert_eq!(completed.state, pending);
        assert!(completed.pending_next_for_test().is_none());

        // The journal continues from the durable decision.
        assert!(matches!(
            journal
                .open_private_oram_mutation_resume_v2(authority_at(4), "docs")
                .unwrap(),
            PrivateOramMutationResumeV2::NeedRemoteTerminals(_)
        ));
    }

    #[test]
    fn v2_writer_rejects_different_evidence_for_pending_record() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(47, 190);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_journals = owner_journals_for_prepares(&prepares);
                next.owner_prepares = prepares.clone();
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();

        let mut different = prepares;
        different[0].prepared_journal_digest = digest(249);
        assert!(matches!(
            journal.mark_owners_prepared_v2(different),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, initial.state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));
    }

    #[test]
    fn v2_writer_rejects_structurally_invalid_pending_record() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(52, 240);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let mut pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_journals = owner_journals_for_prepares(&prepares);
                next.owner_prepares = prepares;
                Ok(())
            },
        )
        .unwrap();
        pending.owner_prepares[0].prepared_journal_digest = digest(248);
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();

        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_bounds_history_directory_iteration() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(53, 250);
        let journal = journal(&temp, &fixture);
        begin_v2(&journal, &fixture, &[11]);
        let records = journal.active_path().join("state_records");
        for index in 0..7 {
            write_new_json_private(
                &records.join(format!("extra-{index}.json")),
                &json!({ "unexpected": index }),
                1024,
            )
            .unwrap();
        }

        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_rejects_history_gap_pointer_ahead_and_missing_format() {
        let gap_temp = tempfile::tempdir().unwrap();
        let gap_fixture = fixture(48, 200);
        let gap_journal = journal(&gap_temp, &gap_fixture);
        begin_v2(&gap_journal, &gap_fixture, &[11]);
        fs::remove_file(v2_record_path(&gap_journal, 1)).unwrap();
        assert!(matches!(
            gap_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let pointer_temp = tempfile::tempdir().unwrap();
        let pointer_fixture = fixture(49, 210);
        let pointer_journal = journal(&pointer_temp, &pointer_fixture);
        let initial = begin_v2(&pointer_journal, &pointer_fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let pointer_ahead = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_journals = owner_journals_for_prepares(&prepares);
                next.owner_prepares = prepares;
                Ok(())
            },
        )
        .unwrap();
        fs::write(
            pointer_journal.state_path(),
            serde_json::to_vec(&pointer_ahead).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            pointer_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let format_temp = tempfile::tempdir().unwrap();
        let format_fixture = fixture(50, 220);
        let format_journal = journal(&format_temp, &format_fixture);
        begin_v2(&format_journal, &format_fixture, &[11]);
        fs::remove_file(format_journal.active_path().join("format.json")).unwrap();
        assert!(matches!(
            format_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_classifies_missing_mandatory_artifacts_as_corrupt() {
        let descriptor_temp = tempfile::tempdir().unwrap();
        let descriptor_fixture = fixture(56, 60);
        let descriptor_journal = journal(&descriptor_temp, &descriptor_fixture);
        begin_v2(&descriptor_journal, &descriptor_fixture, &[11]);
        fs::remove_file(descriptor_journal.active_path().join(DESCRIPTOR_FILE)).unwrap();
        assert!(matches!(
            descriptor_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let state_temp = tempfile::tempdir().unwrap();
        let state_fixture = fixture(57, 80);
        let state_journal = journal(&state_temp, &state_fixture);
        begin_v2(&state_journal, &state_fixture, &[11]);
        fs::remove_file(state_journal.state_path()).unwrap();
        assert!(matches!(
            state_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let records_temp = tempfile::tempdir().unwrap();
        let records_fixture = fixture(58, 100);
        let records_journal = journal(&records_temp, &records_fixture);
        begin_v2(&records_journal, &records_fixture, &[11]);
        fs::remove_dir_all(records_journal.active_path().join("state_records")).unwrap();
        assert!(matches!(
            records_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let manifest_temp = tempfile::tempdir().unwrap();
        let manifest_fixture = fixture(59, 120);
        let manifest_journal = journal(&manifest_temp, &manifest_fixture);
        begin_v2(&manifest_journal, &manifest_fixture, &[11]);
        fs::remove_file(manifest_journal.active_path().join(IMMUTABLE_MANIFEST_FILE)).unwrap();
        assert!(matches!(
            manifest_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_rejects_tampered_or_cross_bound_immutable_manifest() {
        let tampered_temp = tempfile::tempdir().unwrap();
        let tampered_fixture = fixture(60, 140);
        let tampered_journal = journal(&tampered_temp, &tampered_fixture);
        begin_v2(&tampered_journal, &tampered_fixture, &[11]);
        let mut tampered = tampered_fixture.immutable_manifest.clone();
        tampered.signature.sig = digest(201);
        fs::write(
            tampered_journal.active_path().join(IMMUTABLE_MANIFEST_FILE),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            tampered_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let cross_bound_temp = tempfile::tempdir().unwrap();
        let cross_bound_fixture = fixture(61, 160);
        let foreign_fixture = fixture(62, 180);
        let cross_bound_journal = journal(&cross_bound_temp, &cross_bound_fixture);
        begin_v2(&cross_bound_journal, &cross_bound_fixture, &[11]);
        fs::write(
            cross_bound_journal
                .active_path()
                .join(IMMUTABLE_MANIFEST_FILE),
            serde_json::to_vec(&foreign_fixture.immutable_manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            cross_bound_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_restart_returns_exact_immutable_manifest_authority() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(63, 200);
        let initial_journal = journal(&temp, &fixture);
        begin_v2(&initial_journal, &fixture, &[11]);

        let reopened = journal(&temp, &fixture).load_v2().unwrap().unwrap();
        assert_eq!(reopened.immutable_manifest(), &fixture.immutable_manifest);

        let debug = format!("{reopened:?}");
        assert!(!debug.contains(&fixture.immutable_manifest.manifest.manifest_nonce));
        assert!(!debug.contains(&fixture.immutable_manifest.signature.sig));
    }

    #[test]
    fn parent_journal_persists_exact_seven_phase_progression() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(17, 1);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        assert_eq!(
            initial.state.phase,
            PrivateOramMutationJournalPhaseV1::LeaseAcquired
        );
        assert!(matches!(
            journal.validated_point_stage_parent(),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let prepares = owner_prepares(&initial);
        assert!(matches!(
            journal.mark_owners_prepared(prepares[..1].to_vec()),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let prepared = journal.mark_owners_prepared(prepares.clone()).unwrap();
        assert_eq!(
            prepared.state.phase,
            PrivateOramMutationJournalPhaseV1::OwnersPrepared
        );
        assert_eq!(
            journal
                .mark_owners_prepared(prepares)
                .unwrap()
                .state
                .sequence,
            2
        );
        let point = mark_no_server_point_stage(&journal);
        assert_eq!(point.state.sequence, 3);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        assert_eq!(committed.state.sequence, 4);
        let remote = finalizations(&committed, false);
        let remotes = journal.mark_remotes_finalized(remote).unwrap();
        assert_eq!(remotes.state.sequence, 5);
        let local = finalizations(&remotes, true);
        let local = journal.mark_local_finalized(local).unwrap();
        assert_eq!(local.state.sequence, 6);
        let complete = journal.mark_complete().unwrap();
        assert_eq!(
            complete.state.phase,
            PrivateOramMutationJournalPhaseV1::Complete
        );
        assert_eq!(complete.state.sequence, 7);
        assert_eq!(journal.mark_complete().unwrap(), complete);

        let reopened = journal.load().unwrap().unwrap();
        assert_eq!(reopened, complete);
        let rendered = format!("{reopened:?}");
        assert!(!rendered.contains("collection-uuid-1"));
        assert!(!rendered.contains("secret-index"));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_state_binds_both_decisions_and_empty_remote_terminal_batch() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(41, 31);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);

        for decision_kind in [
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
        ] {
            let state = v2_no_server_terminal_state(
                &initial,
                &fixture,
                decision_kind,
                PrivateOramMutationJournalPhaseV2::PointResolved,
            );
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &state).unwrap();
            assert_eq!(state.sequence, 7);
            assert!(
                state
                    .remote_terminals
                    .as_ref()
                    .is_some_and(|batch| batch.owners.is_empty())
            );
            assert!(matches!(
                state.point_resolution,
                Some(PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                    decision_kind: recorded,
                    ..
                }) if recorded == decision_kind
            ));
            let rendered = format!("{state:?}");
            assert!(!rendered.contains("collection-uuid-1"));
            assert!(!rendered.contains("secret-index"));
            assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
        }
    }

    #[test]
    fn v2_parent_watermark_candidate_binds_the_complete_canonical_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(78, 91);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let state = v2_no_server_terminal_state_for_descriptor(
            &initial.descriptor,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let snapshot = initial
            .with_effective_state_for_test(state.clone())
            .unwrap();
        let expectation =
            derive_private_oram_mutation_parent_watermark_expectation_v2(&snapshot).unwrap();
        let watermark = expectation.watermark();

        validate_private_oram_mutation_parent_watermark_v2_shape(watermark).unwrap();
        assert_eq!(
            watermark.lease_generation(),
            fixture.preparing_lease.generation
        );
        assert_eq!(watermark.mutation_id(), fixture.preparing_lease.mutation_id);
        assert_eq!(
            watermark.descriptor_digest(),
            initial.descriptor.descriptor_digest
        );
        assert_eq!(watermark.sequence(), 7);
        assert_eq!(watermark.phase_sequence(), 7);
        assert_eq!(
            watermark.record_digest(),
            Some(state.record_digest.as_str())
        );
        assert_eq!(
            watermark.watermark_digest(),
            "Gz6USAXhnVKBwJMI6iPtBhuGtTAPK7xWjlzDSTpQbew",
        );

        let rendered = format!("{watermark:?}");
        let encoded = serde_json::to_value(watermark).unwrap();
        for field in [
            "collection_id_digest",
            "mutation_id",
            "signed_mutation_digest",
            "transition_digest",
            "base_record_digest",
            "writer_lease_digest",
            "lease_lineage_digest",
            "descriptor_digest",
            "watermark_digest",
        ] {
            let secret = encoded[field].as_str().unwrap();
            assert!(!rendered.contains(secret));
        }
        assert!(!rendered.contains(&format!(
            "lease_generation: {}",
            fixture.preparing_lease.generation
        )));
        assert!(!rendered.contains(&format!(
            "writer_fence: {}",
            fixture.preparing_lease.writer_fence
        )));
        assert!(!rendered.contains(&format!(
            "owner_peer_id: {}",
            fixture.preparing_lease.owner_peer_id
        )));
        assert!(!rendered.contains(&state.record_digest));
    }

    #[test]
    fn v2_parent_watermark_transitions_reject_skip_rollback_fork_and_cross_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let first_fixture = fixture(79, 93);
        let first_journal = journal(&temp, &first_fixture);
        let watermark_at = |phase| {
            v2_parent_watermark_expectation(
                &first_journal,
                &first_fixture,
                PrivateOramMutationDecisionKindV2::ExactNew,
                phase,
            )
        };
        let decision = watermark_at(PrivateOramMutationJournalPhaseV2::DecisionDurable);
        let remotes = watermark_at(PrivateOramMutationJournalPhaseV2::RemotesTerminal);
        let resolved = watermark_at(PrivateOramMutationJournalPhaseV2::PointResolved);

        validate_private_oram_mutation_parent_watermark_v2_cas_transition(
            decision.watermark(),
            decision.watermark(),
            &decision,
        )
        .unwrap();
        validate_private_oram_mutation_parent_watermark_v2_cas_transition(
            decision.watermark(),
            remotes.watermark(),
            &remotes,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_parent_watermark_v2_cas_transition(
                decision.watermark(),
                resolved.watermark(),
                &resolved,
            )
            .is_err()
        );
        validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
            Some(decision.watermark()),
            Some(resolved.watermark()),
            Some(&resolved),
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
                Some(resolved.watermark()),
                Some(decision.watermark()),
                Some(&decision),
            )
            .is_err()
        );
        let forged_suffix = replace_private_oram_mutation_parent_watermark_record_for_test(
            remotes.watermark().clone(),
            PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence(),
            digest(253),
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_parent_watermark_v2_cas_transition(
                decision.watermark(),
                &forged_suffix,
                &remotes,
            )
            .is_err()
        );
        assert!(
            validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
                Some(decision.watermark()),
                Some(&forged_suffix),
                Some(&remotes),
            )
            .is_err()
        );
        assert!(
            validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
                None,
                Some(decision.watermark()),
                Some(&decision),
            )
            .is_err()
        );

        let other_temp = tempfile::tempdir().unwrap();
        let other_fixture = fixture(80, 95);
        let other_journal = journal(&other_temp, &other_fixture);
        let other = v2_parent_watermark_expectation(
            &other_journal,
            &other_fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        );
        assert!(
            validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
                Some(decision.watermark()),
                Some(other.watermark()),
                Some(&other),
            )
            .is_err()
        );

        assert!(
            validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
                Some(decision.watermark()),
                None,
                None,
            )
            .is_err()
        );
        validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(None, None, None)
            .unwrap();
    }

    #[test]
    fn v2_parent_watermark_serde_rejects_unknown_tampered_and_oversized_fields() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(81, 97);
        let journal = journal(&temp, &fixture);
        let expectation = v2_parent_watermark_expectation(
            &journal,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let watermark = expectation.watermark();
        let mut encoded = serde_json::to_value(watermark).unwrap();
        encoded["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrivateOramMutationParentWatermarkV2>(encoded).is_err());

        let mut tampered = serde_json::to_value(watermark).unwrap();
        tampered["history"][0]["record_digest"] = serde_json::json!(digest(252));
        let tampered = serde_json::from_value(tampered).unwrap();
        assert!(validate_private_oram_mutation_parent_watermark_v2_shape(&tampered).is_err());

        let encoded = serde_json::to_value(watermark).unwrap();
        let entry = encoded["history"][0].clone();
        for entry_count in [8, 1_024] {
            let mut oversized = encoded.clone();
            oversized["history"] = serde_json::Value::Array(vec![entry.clone(); entry_count]);
            assert!(
                serde_json::from_value::<PrivateOramMutationParentWatermarkV2>(oversized).is_err()
            );
        }
    }

    #[test]
    fn v2_cleanup_lifecycle_requires_acknowledged_clear_before_next_generation() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence_and_lease(82, 99, 0, false, 1, 1);
        let journal = journal(&temp, &fixture);
        let (terminal_parent, _, _) = cleanup_lifecycle_at_terminal_parent(
            &journal,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
        );
        assert!(matches!(
            terminal_parent.active(),
            Some(PrivateOramMutationCleanupActiveV2::ParentProgress(_))
        ));
        let terminal_state_digest = match &fixture.committed_lease.phase {
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            } => committed_record_digest.clone(),
            _ => unreachable!(),
        };
        let cleanup = private_oram_cleanup_expectation_for_test(
            &terminal_parent,
            &fixture.committed_lease,
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
            terminal_state_digest.clone(),
            digest(220),
            digest(221),
        )
        .unwrap();
        let terminal_slot = active_lease_slot(fixture.committed_lease.clone());
        let witnessed = apply_private_oram_mutation_cleanup_witness_v2(
            &terminal_parent,
            &terminal_slot,
            &cleanup,
            private_oram_cleanup_witness_applied_entry_for_test(
                &terminal_parent,
                &terminal_slot,
                &cleanup,
                1,
                18,
            )
            .unwrap(),
        )
        .unwrap();
        let clear_attempt = digest(222);
        let pending = apply_private_oram_mutation_clear_pending_v2(
            &witnessed,
            &terminal_slot,
            clear_attempt.clone(),
            private_oram_clear_pending_applied_entry_for_test(
                &witnessed,
                &terminal_slot,
                &clear_attempt,
                1,
                20,
            )
            .unwrap(),
        )
        .unwrap();
        let cleared = apply_private_oram_mutation_clear_v2(
            &pending,
            &terminal_slot,
            private_oram_clear_applied_entry_for_test(&pending, &terminal_slot, 1, 30).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cleared.lifecycle().last_cleared().unwrap().clear_receipt(),
            cleared.lease_slot().last_clear.as_ref().unwrap()
        );
        assert!(matches!(
            cleared.lifecycle().last_cleared().unwrap().resolution(),
            PrivateOramMutationClearResolutionV2::Pending
        ));
        assert!(
            private_oram_cleanup_gc_exclusion_permit_for_test(
                cleared.lifecycle(),
                cleared.lease_slot(),
            )
            .is_err()
        );

        let mut next_lease = fixture.preparing_lease.clone();
        next_lease.generation += 1;
        next_lease.writer_fence += 1;
        next_lease.mutation_id = digest(223);
        next_lease.signed_mutation_digest = digest(224);
        next_lease.transition_digest = digest(225);
        next_lease.base_record_digest = terminal_state_digest;
        next_lease.base_state_sequence += 1;
        next_lease.writer_lease_digest = digest(226);
        next_lease.issued_at_unix = 300;
        next_lease.expires_at_unix = 400;
        assert!(
            apply_private_oram_mutation_admission_v2(
                cleared.lifecycle(),
                cleared.lease_slot(),
                next_lease.clone(),
                private_oram_mutation_admission_recovery_manifest_for_test(
                    &next_lease,
                    cleared.lifecycle().lifecycle_digest(),
                ),
                private_oram_admission_applied_entry_for_test(
                    cleared.lifecycle(),
                    cleared.lease_slot(),
                    &next_lease,
                    1,
                    40,
                )
                .unwrap(),
            )
            .is_err()
        );

        let acknowledgement_applied = private_oram_clear_acknowledgement_applied_entry_for_test(
            cleared.lifecycle(),
            cleared.lease_slot(),
            1,
            40,
        )
        .unwrap();
        let acknowledged = acknowledge_private_oram_mutation_clear_v2(
            cleared.lifecycle(),
            cleared.lease_slot(),
            acknowledgement_applied,
        )
        .unwrap();
        assert!(matches!(
            acknowledged.last_cleared().unwrap().resolution(),
            PrivateOramMutationClearResolutionV2::Acknowledged(_)
        ));
        let gc_permit =
            private_oram_cleanup_gc_exclusion_permit_for_test(&acknowledged, cleared.lease_slot())
                .unwrap();
        let gc_checkpoint = private_oram_mutation_cleanup_gc_checkpoint_v2(
            &acknowledged,
            cleared.lease_slot(),
            &gc_permit,
        )
        .unwrap();
        assert_eq!(
            gc_checkpoint.generation(),
            fixture.preparing_lease.generation
        );
        let (witness_digest, clear_receipt_digest, tombstone_digest) = gc_checkpoint.digests();
        assert!(
            [witness_digest, clear_receipt_digest, tombstone_digest]
                .into_iter()
                .all(|digest| digest.len() == 43)
        );
        assert_eq!(
            acknowledged
                .last_cleared()
                .unwrap()
                .clear_receipt_digest()
                .len(),
            43
        );
        let next = apply_private_oram_mutation_admission_v2(
            &acknowledged,
            cleared.lease_slot(),
            next_lease.clone(),
            private_oram_mutation_admission_recovery_manifest_for_test(
                &next_lease,
                acknowledged.lifecycle_digest(),
            ),
            private_oram_admission_applied_entry_for_test(
                &acknowledged,
                cleared.lease_slot(),
                &next_lease,
                1,
                50,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(next.lease_slot().active.as_ref(), Some(&next_lease));
        assert_eq!(
            next.lease_slot().last_clear.as_ref(),
            acknowledged
                .last_cleared()
                .map(|cleared| cleared.clear_receipt())
        );
        validate_private_oram_mutation_cleanup_pair_v2(next.lifecycle(), next.lease_slot())
            .unwrap();
    }

    #[test]
    fn v2_authority_terminal_decision_requires_exact_seq3_recovery_capsule_readiness() {
        let parent_temp = tempfile::tempdir().unwrap();
        let owner_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&owner_temp);
        let journal = journal(&parent_temp, &fixture);
        let activation = activation_locator_for_capsule_test(210);
        let package =
            point_stage_owner_capsule_package_v2(&journal, &fixture, &pair, 11, activation.clone());
        let owner_store =
            owner_capsule_store_v2(&owner_temp.path().join("collection"), &fixture, 11);
        let receipt = owner_store
            .install(&package, &activation, pair.resources())
            .unwrap();
        let terminal = v2_parent_watermark_expectation(
            &journal,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let point_stage = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
            &terminal,
            PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence(),
        )
        .unwrap();
        let evidence = signed_owner_install_evidence_v2(&fixture, receipt.clone());
        let ready = derive_private_oram_mutation_recovery_capsules_ready_v2(
            &point_stage,
            activation.clone(),
            vec![evidence.clone()],
        )
        .unwrap();
        let proposal = journal
            .recovery_readiness_proposal_v2(activation.clone(), vec![evidence])
            .unwrap();
        assert_eq!(
            proposal.key.collection_id,
            fixture.preparing_lease.collection_id
        );
        assert_eq!(proposal.expectation.ready(), ready.ready());

        let encoded = encode_private_oram_mutation_recovery_capsules_ready_v2(&ready).unwrap();
        assert_eq!(
            decode_private_oram_mutation_recovery_capsules_ready_v2(&encoded)
                .unwrap()
                .ready(),
            ready.ready()
        );
        assert!(
            decode_private_oram_mutation_recovery_capsules_ready_v2(&format!(" {encoded}"))
                .is_err()
        );
        let mut tampered: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        tampered["ready_digest"] = serde_json::Value::String(digest(252));
        assert!(
            decode_private_oram_mutation_recovery_capsules_ready_v2(
                &serde_json::to_string(&tampered).unwrap(),
            )
            .is_err()
        );
        assert!(
            derive_private_oram_mutation_recovery_capsules_ready_v2(
                &point_stage,
                activation_locator_for_capsule_test(211),
                vec![signed_owner_install_evidence_v2(&fixture, receipt)],
            )
            .is_err()
        );

        let mut authority = admitted_cleanup_authority(&fixture);
        let commit_request = private_oram_mutation_authority_request_digest_for_lease_for_test(
            &fixture.committed_lease,
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_authority_lease_transition_v2(
                &authority,
                fixture.committed_lease.clone(),
                private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                    commit_request.clone(),
                    digest(240),
                    1,
                    11,
                )
                .unwrap(),
            )
            .is_err()
        );
        for sequence in 1..=2 {
            let expected = truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                &terminal, sequence,
            )
            .unwrap();
            authority = apply_private_oram_mutation_authority_parent_progress_v2(
                &authority,
                &expected,
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ParentProgress,
                    private_oram_mutation_authority_request_digest_for_parent_for_test(&expected),
                    1,
                    10 + sequence,
                )
                .unwrap(),
            )
            .unwrap();
        }
        assert!(
            apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
                &authority,
                &ready,
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
                    ready.ready().ready_digest().to_string(),
                    1,
                    13,
                )
                .unwrap(),
            )
            .is_err()
        );
        authority = apply_private_oram_mutation_authority_parent_progress_v2(
            &authority,
            &point_stage,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ParentProgress,
                private_oram_mutation_authority_request_digest_for_parent_for_test(&point_stage),
                1,
                13,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_authority_lease_transition_v2(
                &authority,
                fixture.committed_lease.clone(),
                private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                    commit_request.clone(),
                    digest(240),
                    1,
                    14,
                )
                .unwrap(),
            )
            .is_err()
        );
        authority = apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
            &authority,
            &ready,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
                ready.ready().ready_digest().to_string(),
                1,
                14,
            )
            .unwrap(),
        )
        .unwrap();
        let replayed = apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
            &authority,
            &ready,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
                ready.ready().ready_digest().to_string(),
                1,
                14,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replayed, authority);
        let recovery_certificate_digest = authority
            .aggregate()
            .unwrap()
            .recovery_capsules_certificate()
            .unwrap()
            .certificate_digest()
            .to_string();
        authority = apply_private_oram_mutation_authority_lease_transition_v2(
            &authority,
            fixture.committed_lease.clone(),
            private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                commit_request,
                digest(240),
                1,
                15,
            )
            .unwrap(),
        )
        .unwrap();
        let encoded_authority = serde_json::to_value(&authority).unwrap();
        assert_eq!(
            encoded_authority["state"]["terminal_decision_certificate"]["recovery_capsules_certificate_digest"],
            recovery_certificate_digest
        );
    }

    #[test]
    fn v2_authority_retains_acknowledged_gc_obligation_across_next_admission() {
        let parent_temp = tempfile::tempdir().unwrap();
        let owner_temp = tempfile::tempdir().unwrap();
        let (pair, fixture) = paired_store_fixture(&owner_temp);
        let journal = journal(&parent_temp, &fixture);
        let activation = activation_locator_for_capsule_test(209);
        let package =
            point_stage_owner_capsule_package_v2(&journal, &fixture, &pair, 11, activation.clone());
        let owner_store =
            owner_capsule_store_v2(&owner_temp.path().join("collection"), &fixture, 11);
        let receipt = owner_store
            .install(&package, &activation, pair.resources())
            .unwrap();
        let evidence = signed_owner_install_evidence_v2(&fixture, receipt);
        let (mut authority, terminal, recovery_capsules_ready) =
            cleanup_authority_at_terminal_parent(
                &journal,
                &fixture,
                PrivateOramMutationDecisionKindV2::ExactNew,
                activation,
                evidence,
            );
        let aggregate = authority.aggregate().unwrap();
        assert_eq!(aggregate.transition_ordinal(), 12);
        assert_eq!(
            aggregate.recovery_capsules_certificate().unwrap().ready(),
            recovery_capsules_ready.ready()
        );
        assert!(aggregate.outstanding_gc_obligations().is_empty());
        let first_parent =
            truncate_private_oram_mutation_parent_watermark_expectation_for_test(&terminal, 1)
                .unwrap();
        authority = apply_private_oram_mutation_authority_parent_progress_v2(
            &authority,
            &first_parent,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ParentProgress,
                private_oram_mutation_authority_request_digest_for_parent_for_test(&first_parent),
                1,
                11,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority.aggregate().unwrap().transition_ordinal(), 12);
        assert!(
            apply_private_oram_mutation_authority_parent_progress_v2(
                &authority,
                &first_parent,
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ParentProgress,
                    private_oram_mutation_authority_request_digest_for_parent_for_test(
                        &first_parent,
                    ),
                    2,
                    11,
                )
                .unwrap(),
            )
            .is_err()
        );
        let later_semantic_prefix = apply_private_oram_mutation_authority_parent_progress_v2(
            &authority,
            &first_parent,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ParentProgress,
                private_oram_mutation_authority_request_digest_for_parent_for_test(&first_parent),
                1,
                19,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(later_semantic_prefix, authority);
        authority = apply_private_oram_mutation_authority_parent_progress_v2(
            &authority,
            &terminal,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ParentProgress,
                private_oram_mutation_authority_request_digest_for_parent_for_test(&terminal),
                1,
                18,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority.aggregate().unwrap().transition_ordinal(), 12);

        authority = apply_private_oram_mutation_authority_lease_transition_v2(
            &authority,
            fixture.committed_lease.clone(),
            private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                private_oram_mutation_authority_request_digest_for_lease_for_test(
                    &fixture.committed_lease,
                )
                .unwrap(),
                digest(240),
                1,
                20,
            )
            .unwrap(),
        )
        .unwrap();
        let committed = authority.clone();
        authority = apply_private_oram_mutation_authority_lease_transition_v2(
            &authority,
            fixture.committed_lease.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                private_oram_mutation_authority_request_digest_for_lease_for_test(
                    &fixture.committed_lease,
                )
                .unwrap(),
                1,
                20,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority, committed);
        let mut conflicting_abort = fixture.preparing_lease.clone();
        conflicting_abort.phase = PrivateOramMutationLeasePhase::AbortDecided;
        assert!(
            apply_private_oram_mutation_authority_lease_transition_v2(
                &authority,
                conflicting_abort.clone(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::AbortDecision,
                    private_oram_mutation_authority_request_digest_for_lease_for_test(
                        &conflicting_abort,
                    )
                    .unwrap(),
                    1,
                    21,
                )
                .unwrap(),
            )
            .is_err()
        );
        let mut illegal_renewal = fixture.committed_lease.clone();
        illegal_renewal.expires_at_unix += 1;
        illegal_renewal.renewal_revision += 1;
        assert!(
            apply_private_oram_mutation_authority_lease_transition_v2(
                &authority,
                illegal_renewal.clone(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::Renewal,
                    private_oram_mutation_authority_request_digest_for_lease_for_test(
                        &illegal_renewal,
                    )
                    .unwrap(),
                    1,
                    21,
                )
                .unwrap(),
            )
            .is_err()
        );
        let committed_record_digest = match &fixture.committed_lease.phase {
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            } => committed_record_digest.clone(),
            _ => unreachable!(),
        };
        let cleanup = private_oram_cleanup_expectation_for_test(
            authority.aggregate().unwrap().lifecycle(),
            &fixture.committed_lease,
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
            committed_record_digest.clone(),
            digest(234),
            digest(235),
        )
        .unwrap();
        authority = apply_private_oram_mutation_authority_cleanup_witness_v2(
            &authority,
            &cleanup,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::CleanupWitness,
                private_oram_mutation_authority_request_digest_for_cleanup_for_test(&cleanup),
                1,
                22,
            )
            .unwrap(),
        )
        .unwrap();
        let witnessed = authority.clone();
        authority = apply_private_oram_mutation_authority_cleanup_witness_v2(
            &authority,
            &cleanup,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::CleanupWitness,
                private_oram_mutation_authority_request_digest_for_cleanup_for_test(&cleanup),
                1,
                22,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority, witnessed);
        let replayed_terminal = apply_private_oram_mutation_authority_lease_transition_v2(
            &authority,
            fixture.committed_lease.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                private_oram_mutation_authority_request_digest_for_lease_for_test(
                    &fixture.committed_lease,
                )
                .unwrap(),
                1,
                20,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replayed_terminal, authority);

        let clear_attempt = digest(236);
        authority = apply_private_oram_mutation_authority_clear_pending_v2(
            &authority,
            clear_attempt.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ClearPending,
                clear_attempt,
                1,
                23,
            )
            .unwrap(),
        )
        .unwrap();
        let clear_pending = authority.clone();
        authority = apply_private_oram_mutation_authority_clear_pending_v2(
            &authority,
            digest(236),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ClearPending,
                digest(236),
                1,
                23,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority, clear_pending);
        let clear_request =
            private_oram_mutation_authority_request_digest_for_clear_for_test(&authority).unwrap();
        authority = apply_private_oram_mutation_authority_clear_v2(
            &authority,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::Clear,
                clear_request,
                1,
                24,
            )
            .unwrap(),
        )
        .unwrap();
        let cleared = authority.clone();
        authority = apply_private_oram_mutation_authority_clear_v2(
            &authority,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::Clear,
                private_oram_mutation_authority_request_digest_for_clear_for_test(&authority)
                    .unwrap(),
                1,
                24,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority, cleared);
        assert!(
            !private_oram_mutation_terminal_material_transferable_for_test(&authority).unwrap()
        );
        assert!(matches!(
            authority
                .aggregate()
                .unwrap()
                .lifecycle()
                .last_cleared()
                .unwrap()
                .resolution(),
            PrivateOramMutationClearResolutionV2::Pending
        ));
        let acknowledgement_request =
            private_oram_mutation_authority_request_digest_for_ack_for_test(&authority).unwrap();
        authority = acknowledge_private_oram_mutation_authority_clear_v2(
            &authority,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ClearAcknowledgement,
                acknowledgement_request,
                1,
                25,
            )
            .unwrap(),
        )
        .unwrap();
        let acknowledged = authority.clone();
        authority = acknowledge_private_oram_mutation_authority_clear_v2(
            &authority,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::ClearAcknowledgement,
                private_oram_mutation_authority_request_digest_for_ack_for_test(&authority)
                    .unwrap(),
                1,
                25,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(authority, acknowledged);
        assert!(private_oram_mutation_terminal_material_transferable_for_test(&authority).unwrap());
        for missing_certificate in [
            "recovery_capsules_certificate",
            "terminal_decision_certificate",
        ] {
            let mut partial = serde_json::to_value(&authority).unwrap();
            partial["state"][missing_certificate] = serde_json::Value::Null;
            let partial: PrivateOramMutationAuthorityStateV2 =
                serde_json::from_value(partial).unwrap();
            assert!(validate_private_oram_mutation_authority_state_v2(&partial).is_err());
        }
        assert!(
            authority
                .aggregate()
                .unwrap()
                .outstanding_gc_obligations()
                .is_empty()
        );

        let mut next_lease = fixture.preparing_lease.clone();
        next_lease.generation += 1;
        next_lease.writer_fence += 1;
        next_lease.mutation_id = digest(237);
        next_lease.signed_mutation_digest = digest(238);
        next_lease.transition_digest = digest(239);
        next_lease.base_record_digest = committed_record_digest;
        next_lease.base_state_sequence += 1;
        next_lease.writer_lease_digest = digest(240);
        next_lease.issued_at_unix = 300;
        next_lease.expires_at_unix = 400;
        let manifest_seed = private_oram_mutation_admission_recovery_manifest_for_test(
            &next_lease,
            authority.aggregate().unwrap().aggregate_digest(),
        );
        let manifest_seed =
            decode_private_oram_mutation_admission_recovery_manifest_v2(&manifest_seed).unwrap();
        let (reservation, reservation_manifest) = private_oram_mutation_append_fixture_for_test(
            &next_lease,
            authority
                .aggregate()
                .unwrap()
                .append_authority_context()
                .unwrap(),
            1,
            &[next_lease.owner_peer_id],
            manifest_seed.activation_authority().clone(),
        );
        let decoded_manifest = reservation_manifest;
        let admission_manifest =
            encode_private_oram_mutation_admission_recovery_manifest_v2(&decoded_manifest).unwrap();
        authority = apply_private_oram_mutation_authority_create_append_reservation_v2(
            &authority,
            encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::AppendReservation,
                reservation.reservation_digest().to_string(),
                1,
                26,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(private_oram_mutation_terminal_material_transferable_for_test(&authority).unwrap());
        let append_prepared_request = private_oram_mutation_append_prepared_request_digest_v2(
            &reservation,
            &decoded_manifest,
        )
        .unwrap();
        authority = apply_private_oram_mutation_authority_append_prepared_v2(
            &authority,
            admission_manifest.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::AppendPrepared,
                append_prepared_request,
                1,
                27,
            )
            .unwrap(),
        )
        .unwrap();
        let admission_request = crate::content_manager::consensus::private_oram_mutation_cleanup::private_oram_mutation_admission_request_digest_v2(
            &next_lease,
            decoded_manifest.manifest_digest(),
        )
        .unwrap();
        authority = apply_private_oram_mutation_authority_admission_v2(
            &authority,
            next_lease.clone(),
            admission_manifest,
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::Admission,
                admission_request,
                1,
                28,
            )
            .unwrap(),
        )
        .unwrap();

        let aggregate = authority.aggregate().unwrap();
        assert_eq!(aggregate.lease_slot().active.as_ref(), Some(&next_lease));
        assert_eq!(authority.lease_slot(), aggregate.lease_slot());
        assert_ne!(aggregate.outer_binding_digest(), digest(240));
        assert_eq!(aggregate.outer_binding_digest().len(), 43);
        assert_eq!(aggregate.aggregate_digest().len(), 43);
        assert_eq!(aggregate.outstanding_gc_obligations().len(), 1);
        let obligation = &aggregate.outstanding_gc_obligations()[0];
        assert_eq!(obligation.generation(), 1);
        assert_eq!(obligation.cleanup_target().target_digest().len(), 43);
        validate_private_oram_mutation_authority_state_v2(&authority).unwrap();
        let replayed_old_generation_terminal =
            apply_private_oram_mutation_authority_lease_transition_v2(
                &authority,
                fixture.committed_lease.clone(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &authority,
                    PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                    private_oram_mutation_authority_request_digest_for_lease_for_test(
                        &fixture.committed_lease,
                    )
                    .unwrap(),
                    1,
                    20,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(replayed_old_generation_terminal, authority);

        let encoded = serde_json::to_value(&authority).unwrap();
        let debug = format!("{authority:?}");
        for secret in [
            &fixture.preparing_lease.collection_id,
            &fixture.preparing_lease.mutation_id,
            obligation.cleanup_target().target_digest(),
        ] {
            assert!(!debug.contains(secret));
        }
        let mut omitted = encoded.clone();
        omitted.as_object_mut().unwrap().remove("state");
        assert!(serde_json::from_value::<PrivateOramMutationAuthorityStateV2>(omitted).is_err());
        let mut tampered = encoded;
        tampered["state"]["outstanding_gc_obligations"][0]["cleanup_target"]["generation"] =
            serde_json::json!(2);
        let tampered: PrivateOramMutationAuthorityStateV2 =
            serde_json::from_value(tampered).unwrap();
        assert!(validate_private_oram_mutation_authority_state_v2(&tampered).is_err());
    }

    #[test]
    fn v2_authority_activation_is_one_way_and_requires_exact_quiescent_legacy_state() {
        let fixture = fixture_at_sequence_and_lease(88, 111, 0, false, 1, 1);
        let authority_key = private_oram_mutation_authority_key_v2(
            &fixture.preparing_lease.collection_id,
            digest(245),
            digest(246),
            digest(242),
        )
        .unwrap();
        let active_legacy = private_oram_mutation_legacy_authority_v2(
            authority_key.clone(),
            active_lease_slot(fixture.preparing_lease.clone()),
            digest(241),
        )
        .unwrap();
        assert!(
            activate_private_oram_mutation_authority_v2(
                &active_legacy,
                &fixture.preparing_lease.collection_id,
                private_oram_mutation_activation_context_for_test(
                    digest(245),
                    digest(246),
                    2,
                    1,
                    1,
                    digest(243),
                )
                .unwrap(),
            )
            .is_err()
        );

        let legacy = private_oram_mutation_legacy_authority_v2(
            authority_key,
            inactive_lease_slot(),
            digest(241),
        )
        .unwrap();
        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            &fixture.preparing_lease.collection_id,
            private_oram_mutation_activation_context_for_test(
                digest(245),
                digest(246),
                2,
                1,
                1,
                digest(243),
            )
            .unwrap(),
        )
        .unwrap();
        let replayed = activate_private_oram_mutation_authority_v2(
            &activated,
            &fixture.preparing_lease.collection_id,
            private_oram_mutation_activation_context_for_test(
                digest(245),
                digest(246),
                2,
                1,
                1,
                digest(243),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replayed, activated);
        assert!(
            activate_private_oram_mutation_authority_v2(
                &activated,
                &fixture.preparing_lease.collection_id,
                private_oram_mutation_activation_context_for_test(
                    digest(245),
                    digest(246),
                    2,
                    2,
                    1,
                    digest(243),
                )
                .unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn v2_authority_binds_collection_lifetime_and_outer_mutation_image() {
        let fixture = fixture_at_sequence_and_lease(89, 113, 0, false, 1, 1);
        let activate = |lifetime: String| {
            let key = private_oram_mutation_authority_key_v2(
                &fixture.preparing_lease.collection_id,
                digest(245),
                digest(246),
                lifetime,
            )
            .unwrap();
            let legacy =
                private_oram_mutation_legacy_authority_v2(key, inactive_lease_slot(), digest(241))
                    .unwrap();
            activate_private_oram_mutation_authority_v2(
                &legacy,
                &fixture.preparing_lease.collection_id,
                private_oram_mutation_activation_context_for_test(
                    digest(245),
                    digest(246),
                    3,
                    1,
                    1,
                    digest(244),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let authority = activate(digest(242));
        let other_lifetime = activate(digest(243));
        assert_ne!(
            authority.aggregate().unwrap().aggregate_digest(),
            other_lifetime.aggregate().unwrap().aggregate_digest()
        );

        let manifest_seed = private_oram_mutation_admission_recovery_manifest_for_test(
            &fixture.preparing_lease,
            authority.aggregate().unwrap().aggregate_digest(),
        );
        let manifest_seed =
            decode_private_oram_mutation_admission_recovery_manifest_v2(&manifest_seed).unwrap();
        let (reservation, admission_manifest) = private_oram_mutation_append_fixture_for_test(
            &fixture.preparing_lease,
            authority
                .aggregate()
                .unwrap()
                .append_authority_context()
                .unwrap(),
            3,
            &[fixture.preparing_lease.owner_peer_id],
            manifest_seed.activation_authority().clone(),
        );
        let admission_manifest_canonical =
            encode_private_oram_mutation_admission_recovery_manifest_v2(&admission_manifest)
                .unwrap();
        let authority = apply_private_oram_mutation_authority_create_append_reservation_v2(
            &authority,
            encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::AppendReservation,
                reservation.reservation_digest().to_string(),
                3,
                2,
            )
            .unwrap(),
        )
        .unwrap();
        let append_prepared_request = private_oram_mutation_append_prepared_request_digest_v2(
            &reservation,
            &admission_manifest,
        )
        .unwrap();
        let authority = apply_private_oram_mutation_authority_append_prepared_v2(
            &authority,
            admission_manifest_canonical.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::AppendPrepared,
                append_prepared_request,
                3,
                3,
            )
            .unwrap(),
        )
        .unwrap();
        let admission_request = crate::content_manager::consensus::private_oram_mutation_cleanup::private_oram_mutation_admission_request_digest_v2(
            &fixture.preparing_lease,
            admission_manifest.manifest_digest(),
        )
        .unwrap();
        let alternate_outer_image = apply_private_oram_mutation_authority_admission_v2(
            &authority,
            fixture.preparing_lease.clone(),
            admission_manifest_canonical,
            private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                &authority,
                PrivateOramMutationMaterialOperationV2::Admission,
                admission_request,
                digest(240),
                3,
                4,
            )
            .unwrap(),
        );
        let alternate_outer_image = alternate_outer_image.unwrap();
        assert_eq!(
            alternate_outer_image
                .aggregate()
                .unwrap()
                .outer_binding_digest(),
            digest(240)
        );
        assert_ne!(
            alternate_outer_image
                .aggregate()
                .unwrap()
                .aggregate_digest(),
            authority.aggregate().unwrap().aggregate_digest()
        );

        let mut tampered = serde_json::to_value(&authority).unwrap();
        tampered["state"]["outer_binding_digest"] = serde_json::json!(digest(240));
        let tampered: PrivateOramMutationAuthorityStateV2 =
            serde_json::from_value(tampered).unwrap();
        assert!(validate_private_oram_mutation_authority_state_v2(&tampered).is_err());
    }

    #[test]
    fn v2_cleanup_lifecycle_accepts_abort_terminal_and_freezes_renewed_terminal_lease() {
        let abort_temp = tempfile::tempdir().unwrap();
        let abort_fixture = fixture_at_sequence_and_lease(84, 103, 0, false, 1, 1);
        let abort_journal = journal(&abort_temp, &abort_fixture);
        let (abort_parent, _, _) = cleanup_lifecycle_at_terminal_parent(
            &abort_journal,
            &abort_fixture,
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
        );
        let mut abort_lease = abort_fixture.preparing_lease.clone();
        abort_lease.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let abort_slot = active_lease_slot(abort_lease.clone());
        assert!(
            private_oram_cleanup_expectation_for_test(
                &abort_parent,
                &abort_lease,
                PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
                abort_lease.base_record_digest.clone(),
                digest(227),
                digest(228),
            )
            .is_err()
        );
        let abort_cleanup = private_oram_cleanup_expectation_for_test(
            &abort_parent,
            &abort_lease,
            PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit,
            abort_lease.base_record_digest.clone(),
            digest(227),
            digest(228),
        )
        .unwrap();
        let abort_witnessed = apply_private_oram_mutation_cleanup_witness_v2(
            &abort_parent,
            &abort_slot,
            &abort_cleanup,
            private_oram_cleanup_witness_applied_entry_for_test(
                &abort_parent,
                &abort_slot,
                &abort_cleanup,
                1,
                18,
            )
            .unwrap(),
        )
        .unwrap();
        let abort_attempt = digest(229);
        let abort_pending = apply_private_oram_mutation_clear_pending_v2(
            &abort_witnessed,
            &abort_slot,
            abort_attempt.clone(),
            private_oram_clear_pending_applied_entry_for_test(
                &abort_witnessed,
                &abort_slot,
                &abort_attempt,
                1,
                20,
            )
            .unwrap(),
        )
        .unwrap();
        let abort_cleared = apply_private_oram_mutation_clear_v2(
            &abort_pending,
            &abort_slot,
            private_oram_clear_applied_entry_for_test(&abort_pending, &abort_slot, 1, 30).unwrap(),
        )
        .unwrap();
        assert_eq!(
            abort_cleared
                .lifecycle()
                .last_cleared()
                .unwrap()
                .clear_receipt()
                .outcome,
            PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit
        );
        validate_private_oram_mutation_cleanup_pair_v2(
            abort_cleared.lifecycle(),
            abort_cleared.lease_slot(),
        )
        .unwrap();

        let renew_temp = tempfile::tempdir().unwrap();
        let renew_fixture = fixture_at_sequence_and_lease(85, 105, 0, false, 1, 1);
        let renew_journal = journal(&renew_temp, &renew_fixture);
        let (renew_parent, _, _) = cleanup_lifecycle_at_terminal_parent(
            &renew_journal,
            &renew_fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
        );
        let mut renewed_terminal_lease = renew_fixture.committed_lease.clone();
        renewed_terminal_lease.expires_at_unix += 10;
        renewed_terminal_lease.renewal_revision += 1;
        let renewed_terminal_slot = active_lease_slot(renewed_terminal_lease.clone());
        let committed_record_digest = match &renew_fixture.committed_lease.phase {
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            } => committed_record_digest.clone(),
            _ => unreachable!(),
        };
        let stale_cleanup = private_oram_cleanup_expectation_for_test(
            &renew_parent,
            &renew_fixture.committed_lease,
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
            committed_record_digest.clone(),
            digest(230),
            digest(231),
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_cleanup_witness_v2(
                &renew_parent,
                &renewed_terminal_slot,
                &stale_cleanup,
                private_oram_cleanup_witness_applied_entry_for_test(
                    &renew_parent,
                    &renewed_terminal_slot,
                    &stale_cleanup,
                    1,
                    18,
                )
                .unwrap(),
            )
            .is_err()
        );
        let renewed_cleanup = private_oram_cleanup_expectation_for_test(
            &renew_parent,
            &renewed_terminal_lease,
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
            committed_record_digest,
            digest(232),
            digest(233),
        )
        .unwrap();
        let renewed_witness = apply_private_oram_mutation_cleanup_witness_v2(
            &renew_parent,
            &renewed_terminal_slot,
            &renewed_cleanup,
            private_oram_cleanup_witness_applied_entry_for_test(
                &renew_parent,
                &renewed_terminal_slot,
                &renewed_cleanup,
                1,
                18,
            )
            .unwrap(),
        )
        .unwrap();
        let mut changed_after_witness = renewed_terminal_lease;
        changed_after_witness.expires_at_unix += 10;
        changed_after_witness.renewal_revision += 1;
        assert!(
            validate_private_oram_mutation_cleanup_pair_v2(
                &renewed_witness,
                &active_lease_slot(changed_after_witness),
            )
            .is_err()
        );
    }

    #[test]
    fn v2_cleanup_locator_order_rejects_namespace_term_and_index_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence_and_lease(86, 107, 0, false, 1, 1);
        let journal = journal(&temp, &fixture);
        let genesis = private_oram_mutation_cleanup_lifecycle_genesis_v2(
            &fixture.preparing_lease.collection_id,
            digest(245),
            digest(246),
        )
        .unwrap();
        let inactive_slot = inactive_lease_slot();
        let admitted = apply_private_oram_mutation_admission_v2(
            &genesis,
            &inactive_slot,
            fixture.preparing_lease.clone(),
            private_oram_mutation_admission_recovery_manifest_for_test(
                &fixture.preparing_lease,
                genesis.lifecycle_digest(),
            ),
            private_oram_admission_applied_entry_for_test(
                &genesis,
                &inactive_slot,
                &fixture.preparing_lease,
                2,
                100,
            )
            .unwrap(),
        )
        .unwrap();
        let terminal = v2_parent_watermark_expectation(
            &journal,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let first =
            truncate_private_oram_mutation_parent_watermark_expectation_for_test(&terminal, 1)
                .unwrap();
        let first_progress = apply_private_oram_mutation_parent_progress_v2(
            admitted.lifecycle(),
            admitted.lease_slot(),
            &first,
            private_oram_parent_progress_applied_entry_for_test(
                admitted.lifecycle(),
                admitted.lease_slot(),
                &first,
                2,
                101,
            )
            .unwrap(),
        )
        .unwrap();
        let replayed = apply_private_oram_mutation_parent_progress_v2(
            &first_progress,
            admitted.lease_slot(),
            &first,
            private_oram_parent_progress_applied_entry_for_test(
                &first_progress,
                admitted.lease_slot(),
                &first,
                3,
                102,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(replayed, first_progress);

        let second =
            truncate_private_oram_mutation_parent_watermark_expectation_for_test(&terminal, 2)
                .unwrap();
        for (term, index) in [(3, 101), (1, 103)] {
            assert!(
                apply_private_oram_mutation_parent_progress_v2(
                    &first_progress,
                    admitted.lease_slot(),
                    &second,
                    private_oram_parent_progress_applied_entry_for_test(
                        &first_progress,
                        admitted.lease_slot(),
                        &second,
                        term,
                        index,
                    )
                    .unwrap(),
                )
                .is_err()
            );
        }
        for (history, group) in [(digest(247), digest(246)), (digest(245), digest(248))] {
            let applied = private_oram_parent_progress_applied_entry_for_test(
                &first_progress,
                admitted.lease_slot(),
                &second,
                3,
                103,
            )
            .unwrap();
            let applied =
                replace_private_oram_applied_entry_namespace_for_test(applied, history, group)
                    .unwrap();
            assert!(
                apply_private_oram_mutation_parent_progress_v2(
                    &first_progress,
                    admitted.lease_slot(),
                    &second,
                    applied,
                )
                .is_err()
            );
        }
        apply_private_oram_mutation_parent_progress_v2(
            &first_progress,
            admitted.lease_slot(),
            &second,
            private_oram_parent_progress_applied_entry_for_test(
                &first_progress,
                admitted.lease_slot(),
                &second,
                3,
                103,
            )
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn v2_cleanup_lifecycle_rejects_skips_stale_authority_and_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence_and_lease(83, 101, 0, false, 1, 1);
        let journal = journal(&temp, &fixture);
        let genesis = private_oram_mutation_cleanup_lifecycle_genesis_v2(
            &fixture.preparing_lease.collection_id,
            digest(245),
            digest(246),
        )
        .unwrap();
        let inactive_slot = inactive_lease_slot();
        let admitted = apply_private_oram_mutation_admission_v2(
            &genesis,
            &inactive_slot,
            fixture.preparing_lease.clone(),
            private_oram_mutation_admission_recovery_manifest_for_test(
                &fixture.preparing_lease,
                genesis.lifecycle_digest(),
            ),
            private_oram_admission_applied_entry_for_test(
                &genesis,
                &inactive_slot,
                &fixture.preparing_lease,
                2,
                100,
            )
            .unwrap(),
        )
        .unwrap();
        let terminal = v2_parent_watermark_expectation(
            &journal,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let second =
            truncate_private_oram_mutation_parent_watermark_expectation_for_test(&terminal, 2)
                .unwrap();
        let second_applied = private_oram_parent_progress_applied_entry_for_test(
            admitted.lifecycle(),
            admitted.lease_slot(),
            &second,
            2,
            101,
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_parent_progress_v2(
                admitted.lifecycle(),
                admitted.lease_slot(),
                &second,
                second_applied,
            )
            .is_err()
        );
        let first =
            truncate_private_oram_mutation_parent_watermark_expectation_for_test(&terminal, 1)
                .unwrap();
        let first_applied = private_oram_parent_progress_applied_entry_for_test(
            admitted.lifecycle(),
            admitted.lease_slot(),
            &first,
            2,
            101,
        )
        .unwrap();
        let first_progress = apply_private_oram_mutation_parent_progress_v2(
            admitted.lifecycle(),
            admitted.lease_slot(),
            &first,
            first_applied,
        )
        .unwrap();
        assert!(
            private_oram_cleanup_expectation_for_test(
                &first_progress,
                &fixture.committed_lease,
                PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
                digest(230),
                digest(231),
                digest(232),
            )
            .is_err()
        );

        let (terminal_parent, _, _) = cleanup_lifecycle_at_terminal_parent(
            &journal,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
        );
        let terminal_slot = active_lease_slot(fixture.committed_lease.clone());
        let terminal_state_digest = match &fixture.committed_lease.phase {
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            } => committed_record_digest.clone(),
            _ => unreachable!(),
        };
        let cleanup = private_oram_cleanup_expectation_for_test(
            &terminal_parent,
            &fixture.committed_lease,
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
            terminal_state_digest,
            digest(233),
            digest(234),
        )
        .unwrap();
        let witnessed = apply_private_oram_mutation_cleanup_witness_v2(
            &terminal_parent,
            &terminal_slot,
            &cleanup,
            private_oram_cleanup_witness_applied_entry_for_test(
                &terminal_parent,
                &terminal_slot,
                &cleanup,
                2,
                108,
            )
            .unwrap(),
        )
        .unwrap();
        let clear_attempt = digest(235);
        assert!(
            apply_private_oram_mutation_clear_pending_v2(
                &witnessed,
                &terminal_slot,
                clear_attempt.clone(),
                private_oram_clear_pending_applied_entry_for_test(
                    &witnessed,
                    &terminal_slot,
                    &clear_attempt,
                    2,
                    108,
                )
                .unwrap(),
            )
            .is_err()
        );
        let pending = apply_private_oram_mutation_clear_pending_v2(
            &witnessed,
            &terminal_slot,
            clear_attempt.clone(),
            private_oram_clear_pending_applied_entry_for_test(
                &witnessed,
                &terminal_slot,
                &clear_attempt,
                2,
                110,
            )
            .unwrap(),
        )
        .unwrap();
        let wrong_slot = active_lease_slot(fixture.preparing_lease.clone());
        assert!(
            apply_private_oram_mutation_clear_v2(
                &pending,
                &wrong_slot,
                private_oram_clear_applied_entry_for_test(&pending, &wrong_slot, 2, 120).unwrap(),
            )
            .is_err()
        );
        let cleared = apply_private_oram_mutation_clear_v2(
            &pending,
            &terminal_slot,
            private_oram_clear_applied_entry_for_test(&pending, &terminal_slot, 2, 120).unwrap(),
        )
        .unwrap();
        let wrong_acknowledgement_applied =
            replace_private_oram_applied_entry_operation_digest_for_test(
                private_oram_clear_acknowledgement_applied_entry_for_test(
                    cleared.lifecycle(),
                    cleared.lease_slot(),
                    2,
                    130,
                )
                .unwrap(),
                digest(236),
            )
            .unwrap();
        assert!(
            acknowledge_private_oram_mutation_clear_v2(
                cleared.lifecycle(),
                cleared.lease_slot(),
                wrong_acknowledgement_applied,
            )
            .is_err()
        );
        let stale_acknowledgement_applied =
            private_oram_clear_acknowledgement_applied_entry_for_test(
                cleared.lifecycle(),
                cleared.lease_slot(),
                2,
                120,
            )
            .unwrap();
        assert!(
            acknowledge_private_oram_mutation_clear_v2(
                cleared.lifecycle(),
                cleared.lease_slot(),
                stale_acknowledgement_applied,
            )
            .is_err()
        );

        let mut unknown = serde_json::to_value(cleared.lifecycle()).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrivateOramMutationCleanupLifecycleV2>(unknown).is_err());
        let mut tampered = serde_json::to_value(cleared.lifecycle()).unwrap();
        tampered["last_cleared"]["witness_digest"] = serde_json::json!(digest(237));
        let tampered: PrivateOramMutationCleanupLifecycleV2 =
            serde_json::from_value(tampered).unwrap();
        assert!(validate_private_oram_mutation_cleanup_lifecycle_v2(&tampered).is_err());
        let rendered = format!("{:?}", cleared.lifecycle());
        let encoded = serde_json::to_value(cleared.lifecycle()).unwrap();
        for secret in [
            encoded["collection_id_digest"].as_str().unwrap(),
            encoded["last_cleared"]["mutation_id"].as_str().unwrap(),
            encoded["last_cleared"]["witness_digest"].as_str().unwrap(),
            encoded["lifecycle_digest"].as_str().unwrap(),
        ] {
            assert!(!rendered.contains(secret));
        }
        assert_eq!(
            cleared.lifecycle().lifecycle_digest(),
            "7gxqxVChnLhfOV2tsoIAURpG_LfY0QMuqm-o52epsqw",
        );
    }

    #[test]
    fn v2_state_rejects_terminal_kind_and_predecessor_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(42, 33);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let state = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );

        let mut wrong_terminal_kind = state.clone();
        wrong_terminal_kind.local_terminals.as_mut().unwrap().kind =
            PrivateOramMutationOwnerTerminalKindV2::AbortedOld;
        wrong_terminal_kind = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_terminal_kind,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_terminal_kind,
            )
            .is_err()
        );

        let mut wrong_predecessor = state;
        let PrivateOramMutationStatePredecessorV2::PreviousV2 { record_digest, .. } =
            &mut wrong_predecessor.predecessor
        else {
            panic!("expected V2 predecessor");
        };
        *record_digest = digest(249);
        wrong_predecessor.record_digest = state_record_digest_v2_for_test(
            &initial.descriptor.descriptor_digest,
            &wrong_predecessor,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_predecessor,
            )
            .is_err()
        );

        let mut wrong_authority = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        let decision = wrong_authority.decision.as_ref().unwrap();
        let (_, v1_reconciliation_authority_digest) = expected_owner_recovery_authority_digest_v1(
            &initial.descriptor,
            &wrong_authority.owner_prepares,
            decision.decided_lease(),
            decision.reconcile_disposition(),
            11,
        )
        .unwrap();
        let batch = wrong_authority.local_terminals.as_mut().unwrap();
        assert_ne!(
            batch.owners[0].reconciliation_authority_digest,
            v1_reconciliation_authority_digest
        );
        batch.owners[0].reconciliation_authority_digest = v1_reconciliation_authority_digest;
        batch.owners[0].terminal_evidence_digest = private_oram_owner_terminal_evidence_v2_digest(
            &initial.descriptor.descriptor_digest,
            batch.kind,
            &batch.owners[0],
        )
        .unwrap();
        wrong_authority = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_authority,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_authority,
            )
            .is_err()
        );

        let mut unsupported_legacy_origin = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        unsupported_legacy_origin.origin = PrivateOramMutationStateOriginV2::MigratedV1 {
            legacy_phase: PrivateOramMutationJournalPhaseV1::Complete,
            legacy_record_digest: digest(247),
            legacy_state_file_sha256: digest(246),
        };
        unsupported_legacy_origin.record_digest = state_record_digest_v2_for_test(
            &initial.descriptor.descriptor_digest,
            &unsupported_legacy_origin,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &unsupported_legacy_origin,
            )
            .is_err()
        );

        let mut wrong_decided_lease = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        let Some(PrivateOramMutationDecisionEvidenceV2::ExactNew {
            committed_lease, ..
        }) = wrong_decided_lease.decision.as_mut()
        else {
            unreachable!();
        };
        committed_lease.base_record_digest = digest(244);
        wrong_decided_lease = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_decided_lease,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_decided_lease,
            )
            .is_err()
        );
    }

    #[test]
    fn v2_point_resolution_receipts_bind_outcome_route_and_raw_replica_observations() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(45, 38, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);

        for outcome in [
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
        ] {
            let state = v2_visible_point_resolved_state(&initial, &fixture, outcome);
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &state).unwrap();
        }

        let mut wrong_observation = v2_visible_point_resolved_state(
            &initial,
            &fixture,
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
        );
        let Some(PrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt }) =
            wrong_observation.point_resolution.as_mut()
        else {
            unreachable!();
        };
        receipt.observations[0] = PrivateOramPointReplicaObservationV2::Exact {
            shard_id: 11,
            peer_id: 11,
            point_semantic_digest: digest(245),
        };
        receipt.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            receipt,
        )
        .unwrap();
        wrong_observation = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_observation,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_observation,
            )
            .is_err()
        );

        let mut wrong_route = v2_visible_point_resolved_state(
            &initial,
            &fixture,
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
        );
        let Some(PrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt }) =
            wrong_route.point_resolution.as_mut()
        else {
            unreachable!();
        };
        receipt.target_shard_ids = vec![12];
        receipt.replicas = vec![PrivateOramPointReplicaTargetV2 {
            shard_id: 12,
            peer_id: 11,
        }];
        receipt.replica_set_digest =
            private_oram_point_replica_set_digest_v2(&receipt.replicas).unwrap();
        receipt.observations = vec![PrivateOramPointReplicaObservationV2::Absent {
            shard_id: 12,
            peer_id: 11,
        }];
        receipt.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
            receipt,
        )
        .unwrap();
        wrong_route =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &wrong_route)
                .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &wrong_route,)
                .is_err()
        );
    }

    #[test]
    fn v2_terminal_batches_require_every_owner_once_in_canonical_order() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(46, 39);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12, 13]);
        let mut prepared = empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
        prepared.owner_prepares = owner_prepares(&initial);
        prepared.owner_journals = owner_journals_for_prepares(&prepared.owner_prepares);
        let prepared =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &prepared)
                .unwrap();
        let mut state = empty_v2_state(PrivateOramMutationJournalPhaseV2::LocalTerminal);
        state.owner_journals = prepared.owner_journals;
        state.owner_prepares = prepared.owner_prepares;
        state.point_stage = Some(
            PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                parent_owners_prepared_record_digest: prepared.record_digest,
            },
        );
        state.decision = Some(
            exact_new_decision_v2_for_test(
                &initial.descriptor,
                &fixture.committed_lease,
                &fixture.new_consensus,
            )
            .unwrap(),
        );
        state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: vec![
                v2_terminal_evidence(
                    &initial.descriptor,
                    &state,
                    12,
                    PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                    201,
                ),
                v2_terminal_evidence(
                    &initial.descriptor,
                    &state,
                    13,
                    PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                    211,
                ),
            ],
        });
        state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: vec![v2_terminal_evidence(
                &initial.descriptor,
                &state,
                11,
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                221,
            )],
        });
        let state =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap();
        validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &state).unwrap();

        let mut reversed = state.clone();
        reversed.remote_terminals.as_mut().unwrap().owners.reverse();
        reversed =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &reversed)
                .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &reversed)
                .is_err()
        );

        let mut missing = state.clone();
        missing.remote_terminals.as_mut().unwrap().owners.pop();
        missing = canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &missing)
            .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &missing)
                .is_err()
        );

        let mut duplicate = state;
        let duplicate_owner = duplicate.remote_terminals.as_ref().unwrap().owners[0].clone();
        duplicate.remote_terminals.as_mut().unwrap().owners[1] = duplicate_owner;
        duplicate =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &duplicate)
                .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &duplicate)
                .is_err()
        );
    }

    #[test]
    fn dual_state_decoder_keeps_v1_complete_distinct_from_v2_point_resolved() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(43, 35);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        journal
            .mark_remotes_finalized(finalizations(&committed, false))
            .unwrap();
        let remotes = journal.load().unwrap().unwrap();
        journal
            .mark_local_finalized(finalizations(&remotes, true))
            .unwrap();
        let complete = journal.mark_complete().unwrap();
        let v1_bytes = serde_json::to_vec(&complete.state).unwrap();
        let DecodedPrivateOramMutationStateUntrusted::V1(decoded_v1) =
            decode_untrusted_private_oram_mutation_state(&complete.descriptor, &v1_bytes).unwrap()
        else {
            panic!("expected V1 state");
        };
        assert_eq!(
            decoded_v1.phase,
            PrivateOramMutationJournalPhaseV1::Complete
        );
        assert!(serde_json::from_slice::<PrivateOramMutationJournalStateV2>(&v1_bytes).is_err());

        let v2 = v2_no_server_terminal_state(
            &prepared,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        let DecodedPrivateOramMutationStateUntrusted::UntrustedV2(decoded_v2) =
            decode_untrusted_private_oram_mutation_state(&prepared.descriptor, &v2_bytes).unwrap()
        else {
            panic!("expected V2 state");
        };
        assert_eq!(
            decoded_v2.phase,
            PrivateOramMutationJournalPhaseV2::PointResolved
        );

        let mut unknown_field = serde_json::to_value(&v2).unwrap();
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), json!(true));
        assert!(
            decode_untrusted_private_oram_mutation_state(
                &prepared.descriptor,
                &serde_json::to_vec(&unknown_field).unwrap(),
            )
            .is_err()
        );

        let mut unknown_version = serde_json::to_value(&v2).unwrap();
        unknown_version["version"] = json!(99);
        assert!(
            decode_untrusted_private_oram_mutation_state(
                &prepared.descriptor,
                &serde_json::to_vec(&unknown_version).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn v1_state_wire_fixture_remains_frozen_for_dual_decoder() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(47, 40);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let encoded = String::from_utf8(serde_json::to_vec(&initial.state).unwrap()).unwrap();
        assert_eq!(
            encoded,
            "{\"version\":1,\"sequence\":1,\"phase\":\"lease_acquired\",\"previous_record_digest\":null,\"owner_prepares\":[],\"point_stage\":null,\"consensus\":null,\"remote_finalizations\":[],\"local_finalizations\":[],\"record_digest\":\"vbwidPilGJSpvsVQu7WbSVZSljQxVyo2gd0NGBgUDpI\"}"
        );
        assert!(matches!(
            decode_untrusted_private_oram_mutation_state(&initial.descriptor, encoded.as_bytes())
                .unwrap(),
            DecodedPrivateOramMutationStateUntrusted::V1(_)
        ));
    }

    #[test]
    fn v2_parent_state_digest_has_known_answer() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(44, 37);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let state = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        assert_eq!(
            state.record_digest,
            "y0M6uWHhrJynEMe5tTqx1rH-JXGTjELHHDLAAbr2Qb0"
        );
    }

    #[test]
    fn owner_recovery_authority_v1_and_v2_phase_domains_have_known_answers() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(68, 73);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepares = owner_prepares(&initial);
        let mut abort_decided = fixture.preparing_lease.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;

        let v1_lease = lease_acquired_record_digest(&initial.descriptor).unwrap();
        let v1_prepared = owners_prepared_record_digest(&initial.descriptor, &prepares).unwrap();
        let mut v2_prepared_state =
            empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
        v2_prepared_state.owner_prepares = prepares.clone();
        v2_prepared_state.owner_journals =
            owner_journals_for_prepares(&v2_prepared_state.owner_prepares);
        let v2_prepared_state = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &v2_prepared_state,
        )
        .unwrap();
        let v2_lease = record_digest_at_phase_v2(
            &initial.descriptor,
            &v2_prepared_state,
            PrivateOramMutationJournalPhaseV2::LeaseAcquired,
        )
        .unwrap();
        let v2_prepared = record_digest_at_phase_v2(
            &initial.descriptor,
            &v2_prepared_state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
        )
        .unwrap();
        assert_ne!(v1_lease, v2_lease);
        assert_ne!(v1_prepared, v2_prepared);

        let v1 = expected_owner_recovery_authority_digest_v1(
            &initial.descriptor,
            &prepares,
            &abort_decided,
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
            11,
        )
        .unwrap()
        .1;
        let v2 = expected_owner_recovery_authority_digest_v2(
            &initial.descriptor,
            &v2_prepared_state,
            &abort_decided,
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
            11,
        )
        .unwrap()
        .1;
        assert_eq!(
            (v1.as_str(), v2.as_str()),
            (
                "6noFrX_iEH8fBQiww1QG8RNmmjdqHsr3vxqOwbNBehY",
                "qcKsUL-31A_NoBAgr95iiXc0M-z13jue4JmeDWBEqUg",
            )
        );
    }

    #[test]
    fn no_server_stage_binds_exact_owners_prepared_chain_tip() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(18, 10);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent().unwrap();
        assert_eq!(
            parent.owners_prepared_record_digest(),
            prepared.state.record_digest
        );

        let staged = journal.mark_no_server_point_stage_durable(&parent).unwrap();
        let Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) = staged.state.point_stage.as_ref()
        else {
            panic!("expected no-server point-stage evidence");
        };
        assert_eq!(
            parent_owners_prepared_record_digest,
            &prepared.state.record_digest
        );
        let replay_parent = journal.validated_point_stage_parent().unwrap();
        assert!(!replay_parent.permits_new_child_install());
        assert_eq!(replay_parent.expected_child_descriptor_digest(), None);
        assert_eq!(
            journal.mark_no_server_point_stage_durable(&parent).unwrap(),
            staged
        );

        let mut tampered = staged;
        let Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) = tampered.state.point_stage.as_mut()
        else {
            unreachable!();
        };
        *parent_owners_prepared_record_digest = digest(252);
        tampered.state.record_digest =
            state_record_digest(&tampered.descriptor.descriptor_digest, &tampered.state).unwrap();
        fs::write(
            journal.state_path(),
            serde_json::to_vec(&tampered.state).unwrap(),
        )
        .unwrap();
        assert!(journal.load().is_err());
    }

    #[test]
    fn reconciliation_context_classifies_only_valid_old_and_new_authority() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(19, 20);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);

        let mut renewed_preparing = fixture.preparing_lease.clone();
        renewed_preparing.expires_at_unix += 10;
        renewed_preparing.renewal_revision += 1;
        let old = journal
            .validated_reconcile_context(
                &fixture.old_consensus,
                &active_lease_slot(renewed_preparing.clone()),
            )
            .unwrap();
        assert_eq!(
            old.disposition(),
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
        );
        assert_eq!(old.active_lease(), &renewed_preparing);
        assert!(old.validated_decision_evidence_v2().is_err());
        assert_eq!(
            old.snapshot().state.phase,
            PrivateOramMutationJournalPhaseV1::PointStageDurable
        );
        let rendered = format!("{old:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));

        let mut abort_decided = renewed_preparing.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let abort = journal
            .validated_reconcile_context(
                &fixture.old_consensus,
                &active_lease_slot(abort_decided.clone()),
            )
            .unwrap();
        assert_eq!(
            abort.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
        );
        assert_eq!(abort.active_lease(), &abort_decided);
        let abort_decision = abort.validated_decision_evidence_v2().unwrap();
        assert_eq!(
            abort_decision.kind(),
            PrivateOramMutationDecisionKindV2::ExactOldAbort
        );

        let new = journal
            .validated_reconcile_context(
                &fixture.new_consensus,
                &active_lease_slot(fixture.committed_lease.clone()),
            )
            .unwrap();
        assert_eq!(
            new.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactNew
        );
        assert_eq!(new.active_lease(), &fixture.committed_lease);
        let new_decision = new.validated_decision_evidence_v2().unwrap();
        assert_eq!(
            new_decision.kind(),
            PrivateOramMutationDecisionKindV2::ExactNew
        );
        let rendered = format!("{new_decision:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
        let mut renewed_committed = fixture.committed_lease.clone();
        renewed_committed.expires_at_unix += 20;
        renewed_committed.renewal_revision += 1;
        journal
            .mark_consensus_committed(&renewed_committed, &fixture.new_consensus)
            .unwrap();
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(fixture.committed_lease.clone()),
                )
                .is_err()
        );
        assert_eq!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(renewed_committed),
                )
                .unwrap()
                .disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactNew
        );
    }

    #[test]
    fn owner_recovery_authority_binds_owner_and_is_stable_across_parent_progress() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(44, 170);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        assert!(matches!(
            journal.validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.old_consensus, fixture.preparing_lease.clone()),
                12,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let prepares = owner_prepares(&initial);
        journal.mark_owners_prepared(prepares.clone()).unwrap();
        mark_no_server_point_stage(&journal);

        let mut renewed_preparing = fixture.preparing_lease.clone();
        renewed_preparing.expires_at_unix += 10;
        renewed_preparing.renewal_revision += 1;
        let observed_snapshot =
            reconcile_snapshot(&fixture.old_consensus, renewed_preparing.clone());
        let snapshot_debug = format!("{observed_snapshot:?}");
        assert!(!snapshot_debug.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!snapshot_debug.contains(&fixture.preparing_lease.base_record_digest));
        let observed = journal
            .validated_owner_recovery_authority(&observed_snapshot, 12)
            .unwrap();
        assert_eq!(observed.owner_peer_id(), 12);
        assert_eq!(
            observed.disposition(),
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
        );
        assert_eq!(
            observed.parent_descriptor_digest(),
            initial.descriptor.descriptor_digest
        );
        assert_eq!(
            observed.parent_lease_acquired_record_digest(),
            initial.state.record_digest
        );
        assert_eq!(
            observed.consensus_authority_record_digest(),
            fixture.preparing_lease.base_record_digest
        );
        assert_eq!(observed.mutation_bundle(), &fixture.mutation_bundle);
        assert_eq!(observed.indexes().len(), 1);
        assert_eq!(observed.indexes()[0].requirement().peer_id, 12);
        assert_eq!(observed.indexes()[0].prepared(), &prepares[1]);
        assert_eq!(observed.reconciliation_authority_digest().len(), 43);
        let coordinator_owner = journal
            .validated_owner_recovery_authority(&observed_snapshot, 11)
            .unwrap();
        assert_ne!(
            observed.reconciliation_authority_digest(),
            coordinator_owner.reconciliation_authority_digest()
        );
        assert!(matches!(
            journal.validated_owner_recovery_authority(&observed_snapshot, 13),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut abort_decided = renewed_preparing;
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let abort = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.old_consensus, abort_decided),
                12,
            )
            .unwrap();
        assert_eq!(
            abort.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
        );
        assert_eq!(
            abort.consensus_authority_record_digest(),
            observed.consensus_authority_record_digest()
        );
        assert_ne!(
            abort.reconciliation_authority_digest(),
            observed.reconciliation_authority_digest()
        );

        let before_parent_progress = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                12,
            )
            .unwrap();
        let mut renewed_committed = fixture.committed_lease.clone();
        renewed_committed.expires_at_unix += 20;
        renewed_committed.renewal_revision += 1;
        journal
            .mark_consensus_committed(&renewed_committed, &fixture.new_consensus)
            .unwrap();
        let after_parent_progress = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.new_consensus, renewed_committed),
                12,
            )
            .unwrap();
        assert_eq!(
            before_parent_progress.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactNew
        );
        assert_eq!(
            before_parent_progress.consensus_authority_record_digest(),
            canonical_private_oram_consensus_state_record_digest(&fixture.new_consensus).unwrap()
        );
        assert_eq!(
            before_parent_progress.parent_owners_prepared_record_digest(),
            after_parent_progress.parent_owners_prepared_record_digest()
        );
        assert_eq!(
            before_parent_progress.reconciliation_authority_digest(),
            after_parent_progress.reconciliation_authority_digest()
        );

        let rendered = format!("{after_parent_progress:?}");
        for secret in [
            fixture.mutation_bundle.mutation.collection_id.as_str(),
            fixture.mutation_bundle.mutation.mutation_id.as_str(),
            observed.indexes()[0].requirement().index_name.as_str(),
            after_parent_progress.reconciliation_authority_digest(),
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn owner_recovery_authority_digest_has_known_answer() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(45, 180);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let authority = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                12,
            )
            .unwrap();

        assert_eq!(
            authority.reconciliation_authority_digest(),
            "yqZo_QdiGYEpKs96GFGhucr_5LRROmSL9KRbSxgU1_8"
        );
    }

    #[test]
    fn live_owner_recovery_authority_holds_and_revalidates_parent_lock() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(47, 200);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let reconcile = reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone());

        let authority_digest = journal
            .with_live_owner_recovery_authority_v1(&reconcile, 12, |live| {
                assert_eq!(live.owner_peer_id(), 12);
                assert_eq!(
                    live.disposition(),
                    PrivateOramMutationReconcileDispositionV1::ExactNew
                );
                assert_eq!(
                    live.parent_descriptor_digest(),
                    initial.descriptor.descriptor_digest
                );
                assert_eq!(live.mutation_bundle(), &fixture.mutation_bundle);

                let second = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(journal.root.join(LOCK_FILE))
                    .unwrap();
                assert!(!FileExt::try_lock_exclusive(second.file()).unwrap());

                let rendered = format!("{live:?}");
                assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
                assert!(!rendered.contains(live.reconciliation_authority_digest()));
                live.reconciliation_authority_digest().to_string()
            })
            .unwrap();
        assert_eq!(authority_digest.len(), 43);

        let original_state = fs::read(journal.state_path()).unwrap();
        let error = journal
            .with_live_owner_recovery_authority_v1(&reconcile, 12, |_| {
                fs::write(journal.state_path(), b"{\"tampered\":true}").unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, PrivateOramMutationJournalError::Corrupt));
        fs::write(journal.state_path(), original_state).unwrap();

        let displaced_root = temp.path().join("displaced-parent-journal");
        let error = journal
            .with_live_owner_recovery_authority_v1(&reconcile, 12, |_| {
                fs::rename(&journal.root, &displaced_root).unwrap();
                fs::create_dir(&journal.root).unwrap();
                set_private_directory_permissions(&journal.root).unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, PrivateOramMutationJournalError::Corrupt));
        fs::remove_dir(&journal.root).unwrap();
        fs::rename(displaced_root, &journal.root).unwrap();
        assert!(journal.load().unwrap().is_some());
    }

    #[test]
    fn owner_recovery_pair_projection_requires_canonical_authenticated_pair() {
        let authority = pair_recovery_authority(46, 190);
        let projection = authority.pair_recovery_projection().unwrap();
        let rendered = format!("{projection:?}");
        assert!(!rendered.contains(&authority.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&authority.indexes[0].prepared.prepared_journal_digest));

        let mut hnsw_only = authority.clone();
        hnsw_only.indexes.pop();
        assert!(matches!(
            hnsw_only.pair_recovery_projection(),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut reordered = authority.clone();
        reordered.indexes.swap(0, 1);
        assert!(matches!(
            reordered.pair_recovery_projection(),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut foreign_owner = authority;
        foreign_owner.indexes[1].prepared.peer_id = 12;
        assert!(matches!(
            foreign_owner.pair_recovery_projection(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn reconciliation_context_rejects_mixed_ambiguous_and_aba_state() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(20, 30);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(fixture.committed_lease.clone()),
                )
                .is_err()
        );
        mark_no_server_point_stage(&journal);

        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(fixture.committed_lease.clone()),
                )
                .is_err()
        );
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(fixture.preparing_lease.clone()),
                )
                .is_err()
        );
        let mut abort_decided = fixture.preparing_lease.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(abort_decided.clone()),
                )
                .is_err()
        );

        let mut ambiguous_state = fixture.old_consensus.clone();
        ambiguous_state.state_sequence += 10;
        assert!(
            journal
                .validated_reconcile_context(
                    &ambiguous_state,
                    &active_lease_slot(fixture.preparing_lease.clone()),
                )
                .is_err()
        );

        let mut aba_slot = active_lease_slot(fixture.preparing_lease.clone());
        aba_slot.generation += 1;
        aba_slot.max_writer_fence += 1;
        assert!(
            journal
                .validated_reconcile_context(&fixture.old_consensus, &aba_slot)
                .is_err()
        );

        let mut forged_renewal = fixture.preparing_lease.clone();
        forged_renewal.expires_at_unix += 1;
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(forged_renewal),
                )
                .is_err()
        );

        journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(fixture.preparing_lease.clone()),
                )
                .is_err()
        );
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(abort_decided),
                )
                .is_err()
        );
    }

    #[test]
    fn begin_is_exactly_idempotent_and_rejects_another_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let original = fixture(19, 20);
        let journal = journal(&temp, &original);
        let first = begin(&journal, &original, &[11, 12]);
        let replay = begin(&journal, &original, &[11, 12]);
        assert_eq!(first, replay);

        let conflicting = fixture(19, 40);
        assert!(matches!(
            journal.begin(
                11,
                &[11, 12],
                conflicting.mutation_bundle,
                conflicting.preparing_lease,
                conflicting.old_consensus,
            ),
            Err(PrivateOramMutationJournalError::ConcurrentMutation)
        ));
    }

    #[test]
    fn parent_journal_digest_format_has_known_answer() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(41, 130);
        let journal = journal(&temp, &fixture);
        let snapshot = begin(&journal, &fixture, &[11, 12]);

        assert_eq!(
            (
                snapshot.descriptor.descriptor_digest.as_str(),
                snapshot.state.record_digest.as_str(),
            ),
            (
                "zIeq0vyJ2rfE9f0DoK4KbbGVIJrnhJXFjUd5hlaj6hw",
                "2GM2Cm_6cDUFHl8DLlS_Y7dTl059XK0PlOaiewAiBNU",
            )
        );
    }

    #[test]
    fn begin_rejects_noncanonical_consensus_transition_digest() {
        let temp = tempfile::tempdir().unwrap();
        let mut fixture = fixture(42, 140);
        fixture.preparing_lease.transition_digest = digest(250);
        let journal = journal(&temp, &fixture);

        assert!(matches!(
            journal.begin(
                11,
                &[11, 12],
                fixture.mutation_bundle,
                fixture.preparing_lease,
                fixture.old_consensus,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn single_owner_records_empty_remote_finalize_phase() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(23, 60);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        let remote = journal.mark_remotes_finalized(Vec::new()).unwrap();
        assert_eq!(remote.state.sequence, 5);
        let local = finalizations(&prepared, true);
        journal.mark_local_finalized(local).unwrap();
        assert_eq!(journal.mark_complete().unwrap().state.sequence, 7);
        assert_eq!(committed.state.remote_finalizations, Vec::new());
    }

    #[test]
    fn parent_journal_binds_non_genesis_consensus_record() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(27, 70, 7, false);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        assert_eq!(
            initial
                .descriptor
                .expected_consensus_old_state
                .state_sequence,
            7
        );
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        assert_eq!(
            committed.state.consensus.unwrap().committed_state_sequence,
            8
        );
    }

    #[test]
    fn visible_point_phase_requires_private_staging_token() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(28, 75, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent().unwrap();
        assert!(parent.permits_new_child_install());
        assert_eq!(
            parent.owners_prepared_record_digest(),
            prepared.state.record_digest
        );
        assert!(journal.mark_no_server_point_stage_durable(&parent).is_err());

        let point_store = PrivateOramPointStagingStore::new(&temp.path().join("collection"));
        let (point_stage, durable_token) = point_store
            .prepare(fixture.staged_frame_bytes.as_deref().unwrap(), &parent)
            .unwrap();
        let staged = journal
            .mark_private_point_stage_durable(&durable_token)
            .unwrap();
        assert_eq!(
            staged.state.phase,
            PrivateOramMutationJournalPhaseV1::PointStageDurable
        );
        let Some(PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            child_descriptor_digest,
            parent_owners_prepared_record_digest,
        }) = staged.state.point_stage.as_ref()
        else {
            panic!("expected private point-staging evidence");
        };
        assert_eq!(point_id, durable_token.point_id());
        assert_eq!(staged_insert_sha256, durable_token.frame_sha256());
        assert_eq!(
            canonical_point_id_digest,
            durable_token.canonical_point_id_digest()
        );
        assert_eq!(
            durable_token.target_shard_ids(),
            point_stage.frame.target_shard_ids.as_slice()
        );
        assert_eq!(
            durable_token.point_semantic_digest(),
            private_oram_staged_point_semantic_v1_digest(&point_stage.frame.point).unwrap()
        );
        let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            point_semantic_digest,
            target_shard_ids,
            ..
        } = private_oram_point_stage_evidence_v2_from_durable_token(&durable_token)
        else {
            unreachable!();
        };
        assert_eq!(point_semantic_digest, durable_token.point_semantic_digest());
        assert_eq!(target_shard_ids, durable_token.target_shard_ids());
        assert_eq!(
            child_descriptor_digest,
            &point_stage.descriptor.descriptor_digest
        );
        assert_eq!(
            parent_owners_prepared_record_digest,
            &prepared.state.record_digest
        );

        let replay_parent = journal.validated_point_stage_parent().unwrap();
        assert!(!replay_parent.permits_new_child_install());
        assert_eq!(
            replay_parent.expected_child_descriptor_digest(),
            Some(point_stage.descriptor.descriptor_digest.as_str())
        );
        let (_, replay_token) = point_store.load(&replay_parent).unwrap().unwrap();
        assert_eq!(replay_token, durable_token);
        assert_eq!(
            journal
                .mark_private_point_stage_durable(&replay_token)
                .unwrap(),
            staged
        );
    }

    #[test]
    fn changed_consensus_receipt_or_owner_evidence_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(29, 80);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        let mut prepares = owner_prepares(&initial);
        prepares[0].prepared_journal_digest = "not-a-digest".to_string();
        assert!(matches!(
            journal.mark_owners_prepared(prepares),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let mut changed = fixture.new_consensus.clone();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) = &mut changed.last_transition
        else {
            unreachable!();
        };
        receipt.point_operation_digest = digest(250);
        assert!(matches!(
            journal.mark_consensus_committed(&fixture.committed_lease, &changed),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn recomputed_parent_digest_cannot_replace_consensus_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(30, 90);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let mut committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        committed
            .state
            .consensus
            .as_mut()
            .unwrap()
            .committed_record_digest = digest(249);
        committed.state.record_digest =
            state_record_digest(&committed.descriptor.descriptor_digest, &committed.state).unwrap();
        fs::write(
            journal.state_path(),
            serde_json::to_vec(&committed.state).unwrap(),
        )
        .unwrap();
        assert!(journal.load().is_err());
    }

    #[test]
    fn on_disk_state_digest_and_signature_tampering_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(31, 100);
        let journal = journal(&temp, &fixture);
        begin(&journal, &fixture, &[11]);
        let mut state: serde_json::Value =
            serde_json::from_reader(File::open(journal.state_path()).unwrap()).unwrap();
        state["record_digest"] = json!(digest(251));
        fs::write(journal.state_path(), serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(
            journal.load(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let wrong_key = PrivateOramMutationJournal::new(
            temp.path().join("collection").as_path(),
            "tenant-a/private-oram-owner-v2",
            Ed25519KeyPair::from_seed_unchecked(&[99; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .to_vec(),
        )
        .unwrap();
        assert!(matches!(
            wrong_key.load(),
            Err(PrivateOramMutationJournalError::Signature(_))
                | Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    struct FailBeforePublish;

    impl JournalSaveBackend for FailBeforePublish {
        fn publish(&self, _candidate: NamedTempFile, _destination: &Path) -> io::Result<()> {
            Err(io::Error::other("injected pre-publish failure"))
        }

        fn sync_parent(&self, _parent: &Path) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailAfterPublish;

    impl JournalSaveBackend for FailAfterPublish {
        fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.publish(candidate, destination)?;
            Err(io::Error::other("injected post-publish failure"))
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.sync_parent(parent)
        }
    }

    struct ExhaustParentSync {
        calls: AtomicUsize,
    }

    impl JournalSaveBackend for ExhaustParentSync {
        fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.publish(candidate, destination)
        }

        fn sync_parent(&self, _parent: &Path) -> io::Result<()> {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            Err(io::Error::other("injected parent sync failure"))
        }
    }

    struct RemoveAfterPublish;

    impl JournalSaveBackend for RemoveAfterPublish {
        fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.publish(candidate, destination)?;
            fs::remove_file(destination)
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.sync_parent(parent)
        }
    }

    fn atomic_save_fixture() -> (TempDir, PathBuf, PathBuf, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("active");
        create_private_directory(&parent).unwrap();
        let temp_dir = parent.join("temp");
        create_private_directory(&temp_dir).unwrap();
        let destination = parent.join("state.json");
        write_new_json_private(&destination, &json!({ "value": "old" }), 4096).unwrap();
        let old_sha = file_sha256(&destination, 4096).unwrap();
        (temp, destination, temp_dir, old_sha)
    }

    #[test]
    fn atomic_state_save_classifies_before_and_after_publish_failures() {
        let (_temp, destination, temp_dir, old_sha) = atomic_save_fixture();
        let definitive = write_json_atomic_classified(
            &destination,
            &temp_dir,
            &json!({ "value": "new" }),
            old_sha,
            &FailBeforePublish,
        );
        assert!(matches!(
            definitive,
            Err(PrivateOramMutationJournalError::Io(_))
        ));
        assert_eq!(
            read_json_private::<serde_json::Value>(&destination, 4096).unwrap(),
            json!({ "value": "old" })
        );

        write_json_atomic_classified(
            &destination,
            &temp_dir,
            &json!({ "value": "new" }),
            old_sha,
            &FailAfterPublish,
        )
        .unwrap();
        assert_eq!(
            read_json_private::<serde_json::Value>(&destination, 4096).unwrap(),
            json!({ "value": "new" })
        );
    }

    #[test]
    fn exhausted_parent_sync_is_indeterminate_after_publish() {
        let (_temp, destination, temp_dir, old_sha) = atomic_save_fixture();
        let backend = ExhaustParentSync {
            calls: AtomicUsize::new(0),
        };
        assert!(matches!(
            write_json_atomic_classified(
                &destination,
                &temp_dir,
                &json!({ "value": "new" }),
                old_sha,
                &backend,
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        assert_eq!(
            backend.calls.load(AtomicOrdering::Relaxed),
            PARENT_SYNC_ATTEMPTS
        );
        assert_eq!(
            read_json_private::<serde_json::Value>(&destination, 4096).unwrap(),
            json!({ "value": "new" })
        );
    }

    #[test]
    fn post_publish_read_failure_is_indeterminate() {
        let (_temp, destination, temp_dir, old_sha) = atomic_save_fixture();
        assert!(matches!(
            write_json_atomic_classified(
                &destination,
                &temp_dir,
                &json!({ "value": "new" }),
                old_sha,
                &RemoveAfterPublish,
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn private_json_read_rejects_content_beyond_the_callers_bound() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bounded.json");
        write_new_json_private(&path, &json!({ "value": "too-large" }), 4096).unwrap();
        assert!(matches!(
            read_json_private::<serde_json::Value>(&path, 2),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_file_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(37, 120);
        let journal = journal(&temp, &fixture);
        begin(&journal, &fixture, &[11]);
        fs::remove_file(journal.state_path()).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"{}").unwrap();
        symlink(target, journal.state_path()).unwrap();
        assert!(journal.load().is_err());
    }
}
