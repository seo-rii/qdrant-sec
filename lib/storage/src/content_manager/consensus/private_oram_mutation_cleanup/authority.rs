//! Mandatory authority envelope and pure aggregate transitions for private-ORAM mutation V2.
//!
//! Production construction of activation and apply contexts remains intentionally unavailable.
//! The Raft apply loop will become the sole constructor when mixed-version activation is wired.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::rc::Rc;

use collection::private_oram_owner_journal::{
    PrivateOramOwnerAcknowledgedArchiveExpectationV2, PrivateOramOwnerCompactedArchiveHistoryV1,
    PrivateOramOwnerNewGenerationReadinessExpectationV2,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateOramOwnerCleanupSignerV1, PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    PrivateOramOwnerEnrollmentPreparedV1, PrivateOramOwnerReservationResolutionDispositionV1,
    SignedPrivateOramOwnerReservationResolutionReceiptV1,
    decode_signed_private_oram_owner_reservation_resolution_receipt_v1,
    encode_signed_private_oram_owner_reservation_resolution_receipt_v1,
    prepare_private_oram_owner_enrollment_v1, private_oram_mutation_protocol_capability_digest_v2,
    private_oram_owner_cleanup_signer_from_peer_key_v1,
    private_oram_owner_lifecycle_genesis_state_v1,
    validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1,
};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::append_reservation_v3::{
    DecodedPrivateOramMutationAppendReservation, PrivateOramMutationPreparedReservationChallengeV3,
    decode_private_oram_mutation_append_reservation_v3,
    decode_private_oram_mutation_append_reservation_wire,
    decode_private_oram_mutation_prepared_reservation_challenge_v3,
    encode_private_oram_mutation_append_reservation_v3,
    encode_private_oram_mutation_prepared_reservation_challenge_v3,
};
use super::format::{
    PrivateOramMutationFormatFloorV2, validate_private_oram_mutation_format_floor_v2,
};
use super::owner_checkpoint::{
    PrivateOramOwnerCheckpointTableV1, PrivateOramOwnerNegativeSettlementV1,
    acknowledge_private_oram_owner_negative_settlement_v1,
    activate_private_oram_owner_enrollment_transition_v1,
    lease_private_oram_owner_checkpoints_for_reservation_v1,
    prepare_private_oram_owner_enrollment_transition_v1,
    private_oram_owner_checkpoint_table_genesis_v1,
    validate_private_oram_owner_checkpoint_active_reservation_v1,
    validate_private_oram_owner_checkpoint_reservation_context_for_table_v1,
    validate_private_oram_owner_checkpoint_table_scope_v1,
};
use super::{
    PrivateOramAppliedEntryV2, PrivateOramMutationCleanupActiveV2,
    PrivateOramMutationCleanupExpectationV2, PrivateOramMutationCleanupLifecycleV2,
    PrivateOramMutationCleanupOperationKindV2, PrivateOramMutationClearResolutionV2,
    PrivateOramMutationClearedStateV2, PrivateOramRaftApplyLocatorV2,
    acknowledge_private_oram_mutation_clear_v2, active_admitted, applied_operation_digest_v2,
    apply_private_oram_mutation_admission_v2, apply_private_oram_mutation_cleanup_witness_v2,
    apply_private_oram_mutation_clear_pending_v2, apply_private_oram_mutation_clear_v2,
    apply_private_oram_mutation_parent_progress_v2, clear_resolution_digest_v2,
    cleared_state_digest_v2, locator_is_at_or_after, locator_is_strictly_after,
    private_oram_mutation_admission_request_digest_v2,
    private_oram_mutation_cleanup_lifecycle_genesis_v2, private_oram_mutation_lease_slot_digest_v2,
    private_oram_mutation_lease_state_digest_v2, validate_apply_locator_v2,
    validate_cleared_state_v2, validate_digest, validate_lease_slot_v2, validate_lease_v2,
    validate_private_oram_mutation_cleanup_pair_v2,
};
use crate::content_manager::consensus::private_oram_mutation_recovery_capsules::{
    PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
    PrivateOramMutationRecoveryCapsulesReadyV2,
    validate_private_oram_mutation_recovery_capsules_ready_v2,
};
use crate::content_manager::consensus::private_oram_mutation_watermark::{
    PrivateOramMutationParentWatermarkExpectationV2,
    private_oram_mutation_parent_watermark_is_canonical_prefix_v2,
};
use crate::content_manager::consensus_ops::{
    PrivateOramMutationClearReceiptV1, PrivateOramMutationKey, PrivateOramMutationLease,
    PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationAppendAuthorityContextV2,
    PrivateOramMutationAppendReservationV2, PrivateOramMutationJournalError,
    decode_private_oram_mutation_admission_recovery_manifest_v2,
    encode_private_oram_mutation_append_reservation_v2,
};
use crate::content_manager::private_oram_mutation_state_v2::private_oram_collection_id_digest_v2;

const AUTHORITY_KEY_VERSION: u16 = 1;
const LEGACY_AUTHORITY_VERSION: u16 = 1;
const ACTIVATION_ANCHOR_VERSION: u16 = 1;
const AGGREGATE_VERSION_V6: u16 = 6;
const AGGREGATE_VERSION_V7: u16 = 7;
const MATERIAL_TRANSITION_RECEIPT_VERSION: u16 = 1;
const TERMINAL_DECISION_CERTIFICATE_VERSION: u16 = 2;
const RECOVERY_CAPSULES_CERTIFICATE_VERSION: u16 = 1;
const GC_OBLIGATION_VERSION: u16 = 1;
const REJECTED_ADMISSION_VERSION: u16 = 1;
const ACTIVE_APPEND_ATTEMPT_VERSION: u16 = 1;
const ACTIVE_APPEND_ATTEMPT_VERSION_V3: u16 = 2;
const OWNER_CHECKPOINT_LEASE_TRANSITION_VERSION: u16 = 1;
const PREPARED_APPEND_VERSION: u16 = 1;
const APPEND_OUTCOME_VERSION: u16 = 1;
const PENDING_RESERVATION_CHALLENGE_VERSION: u16 = 1;
const RESERVATION_CHALLENGE_OUTCOME_VERSION_V1: u16 = 1;
const RESERVATION_CHALLENGE_OUTCOME_VERSION_V2: u16 = 2;
const RESERVATION_CHALLENGE_OUTCOME_VERSION_V3: u16 = 3;
const RESERVATION_CHALLENGE_CANCELLATION_VERSION: u16 = 1;
const RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_VERSION: u16 = 1;
const RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_VERSION: u16 = 1;
const CLEANUP_TARGET_VERSION: u16 = 1;
const CLEANUP_STORAGE_NAMESPACE_VERSION: u16 = 1;
const MAX_OUTSTANDING_GC_OBLIGATIONS: usize = 1_024;
const MAX_OUTSTANDING_GC_OBLIGATION_BYTES: usize = 10 * 1024 * 1024;
const MAX_REJECTED_ADMISSIONS: usize = 256;
const MAX_REJECTED_ADMISSION_BYTES: usize = 8 * 1024 * 1024;
const MAX_APPEND_OUTCOMES: usize = 4_096;
const MAX_APPEND_OUTCOME_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESERVATION_CHALLENGE_OUTCOMES: usize = 4_096;
const MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES: usize = 12 * 1024 * 1024;
const MAX_RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_BYTES: usize = 8 * 1024 * 1024;
const APPEND_RESERVATION_MANDATORY_HEADROOM_BYTES: usize = 512 * 1024;
const APPEND_RESERVATION_V3_FINAL_WIRE_RESERVE_BYTES: usize = 8 * 1024 * 1024;
const MAX_AUTHORITY_WIRE_BYTES: usize = 20 * 1024 * 1024;
const AUTHORITY_WIRE_ENVELOPE_VERSION: u16 = 7;

const AUTHORITY_KEY_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-authority-key/v2";
const COLLECTION_LIFETIME_ID_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-collection-lifetime/v2";
const OUTER_BINDING_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-outer-binding/v2";
const ACTIVATION_REQUEST_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-activation-request/v2";
const LEGACY_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-legacy-authority/v2";
const ACTIVATION_ANCHOR_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-activation-anchor/v2";
const COLLECTION_INCARNATION_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-collection-incarnation/v2";
const MATERIAL_TRANSITION_RECEIPT_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-material-transition-receipt/v2";
const TERMINAL_DECISION_CERTIFICATE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-terminal-decision-certificate/v2";
const RECOVERY_CAPSULES_CERTIFICATE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-recovery-capsules-certificate/v2";
const CLEANUP_TARGET_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-cleanup-target/v2";
const CLEANUP_LOGICAL_OBJECT_SET_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-cleanup-logical-object-set/v2";
const GC_OBLIGATION_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-gc-obligation/v2";
const REJECTED_ADMISSION_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-rejected-admission/v2";
const ACTIVE_APPEND_ATTEMPT_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-active-append-attempt/v2";
const OWNER_CHECKPOINT_LEASE_TRANSITION_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-checkpoint-lease-transition/v1";
const PREPARED_APPEND_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-prepared-append/v2";
const APPEND_OUTCOME_KEY_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-outcome-key/v2";
const APPEND_OUTCOME_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-outcome/v2";
const AGGREGATE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-consensus-aggregate/v2";
const AGGREGATE_CORE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-consensus-aggregate-core/v2";
const OWNER_CHECKPOINT_COMPONENT_TAG_V1: &[u8] = b"owner-checkpoint-table/v1";
const OWNER_ARCHIVE_HISTORY_COMPONENT_TAG_V1: &[u8] = b"owner-archive-history/v1";
pub(crate) const OWNER_ARCHIVE_HISTORY_MIN_PROTOCOL_V1: u16 = 9;
const RESERVATION_CHALLENGE_COMPONENT_TAG_V1: &[u8] = b"reservation-challenge-state/v1";
const PENDING_RESERVATION_CHALLENGE_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-mutation-pending-reservation-challenge/v1";
const RESERVATION_CHALLENGE_OUTCOME_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-challenge-outcome/v1";
const RESERVATION_CHALLENGE_CANCELLATION_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-challenge-cancellation/v1";
const RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-challenge-outcome-acknowledgement/v1";
const RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-challenge-outcome-accumulator/v1";
const RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_COMPONENT_TAG_V1: &[u8] =
    b"reservation-challenge-outcome-accumulator/v1";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationMaterialOperationV2 {
    Activation,
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationAuthorityKeyV2 {
    version: u16,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_lifetime_id_digest: String,
    collection_key_digest: String,
    key_digest: String,
}

impl Debug for PrivateOramMutationAuthorityKeyV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAuthorityKeyV2")
            .field("version", &self.version)
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("collection_lifetime_id_digest", &"[redacted]")
            .field("collection_key_digest", &"[redacted]")
            .field("key_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationLegacyAuthorityV2 {
    version: u16,
    authority_key: PrivateOramMutationAuthorityKeyV2,
    exact_legacy_slot: PrivateOramMutationLeaseSlotV2,
    outer_binding_digest: String,
    authority_digest: String,
}

impl Debug for PrivateOramMutationLegacyAuthorityV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationLegacyAuthorityV2")
            .field("version", &self.version)
            .field("authority_key", &self.authority_key)
            .field("exact_legacy_slot", &self.exact_legacy_slot)
            .field("outer_binding_digest", &"[redacted]")
            .field("authority_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationActivationAnchorV2 {
    version: u16,
    compatibility_epoch: u64,
    authority_key: PrivateOramMutationAuthorityKeyV2,
    collection_incarnation_digest: String,
    activation_applied: PrivateOramRaftApplyLocatorV2,
    preactivation_authority_digest: String,
    preactivation_outer_binding_digest: String,
    activation_request_digest: String,
    anchor_digest: String,
}

impl Debug for PrivateOramMutationActivationAnchorV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationActivationAnchorV2")
            .field("version", &self.version)
            .field("compatibility_epoch", &self.compatibility_epoch)
            .field("authority_key", &self.authority_key)
            .field("activation_applied", &self.activation_applied)
            .field("collection_incarnation_digest", &"[redacted]")
            .field("preactivation_authority_digest", &"[redacted]")
            .field("preactivation_outer_binding_digest", &"[redacted]")
            .field("activation_request_digest", &"[redacted]")
            .field("anchor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMaterialTransitionReceiptV2 {
    version: u16,
    ordinal: u64,
    locator: PrivateOramRaftApplyLocatorV2,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    request_digest: String,
    prior_authority_digest: String,
    prior_outer_binding_digest: String,
    next_authority_core_digest: String,
    next_outer_binding_digest: String,
    receipt_digest: String,
}

impl Debug for PrivateOramMaterialTransitionReceiptV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMaterialTransitionReceiptV2")
            .field("version", &self.version)
            .field("ordinal", &self.ordinal)
            .field("locator", &self.locator)
            .field("operation_kind", &self.operation_kind)
            .field("request_digest", &"[redacted]")
            .field("prior_authority_digest", &"[redacted]")
            .field("prior_outer_binding_digest", &"[redacted]")
            .field("next_authority_core_digest", &"[redacted]")
            .field("next_outer_binding_digest", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationTerminalDecisionCertificateV2 {
    version: u16,
    generation: u64,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    locator: PrivateOramRaftApplyLocatorV2,
    request_digest: String,
    terminal_lease_state_digest: String,
    recovery_capsules_certificate_digest: String,
    next_outer_binding_digest: String,
    certificate_digest: String,
}

impl Debug for PrivateOramMutationTerminalDecisionCertificateV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationTerminalDecisionCertificateV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field("operation_kind", &self.operation_kind)
            .field("locator", &self.locator)
            .field("request_digest", &"[redacted]")
            .field("terminal_lease_state_digest", &"[redacted]")
            .field("recovery_capsules_certificate_digest", &"[redacted]")
            .field("next_outer_binding_digest", &"[redacted]")
            .field("certificate_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationRecoveryCapsulesCertificateV2 {
    version: u16,
    generation: u64,
    ready: PrivateOramMutationRecoveryCapsulesReadyV2,
    locator: PrivateOramRaftApplyLocatorV2,
    certificate_digest: String,
}

impl Debug for PrivateOramMutationRecoveryCapsulesCertificateV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationRecoveryCapsulesCertificateV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field("ready", &self.ready)
            .field("locator", &self.locator)
            .field("certificate_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationRecoveryCapsulesCertificateV2 {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn ready(&self) -> &PrivateOramMutationRecoveryCapsulesReadyV2 {
        &self.ready
    }

    pub(crate) fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationCleanupTargetV2 {
    version: u16,
    storage_namespace_version: u16,
    collection_key_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    generation: u64,
    retired_outer_binding_digest: String,
    logical_object_set_digest: String,
    tombstone_digest: String,
    acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
    target_digest: String,
}

impl Debug for PrivateOramMutationCleanupTargetV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationCleanupTargetV2")
            .field("version", &self.version)
            .field("storage_namespace_version", &self.storage_namespace_version)
            .field("generation", &"[redacted]")
            .field("acknowledgement_applied", &self.acknowledgement_applied)
            .field("collection_key_digest", &"[redacted]")
            .field("collection_lifetime_id_digest", &"[redacted]")
            .field("collection_incarnation_digest", &"[redacted]")
            .field("activation_anchor_digest", &"[redacted]")
            .field("retired_outer_binding_digest", &"[redacted]")
            .field("logical_object_set_digest", &"[redacted]")
            .field("tombstone_digest", &"[redacted]")
            .field("target_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramAcknowledgedGcObligationV2 {
    version: u16,
    collection_key_digest: String,
    collection_incarnation_digest: String,
    generation: u64,
    terminal_decision_certificate: PrivateOramMutationTerminalDecisionCertificateV2,
    acknowledged_tombstone: PrivateOramMutationClearedStateV2,
    cleanup_target: PrivateOramMutationCleanupTargetV2,
    obligation_digest: String,
}

impl Debug for PrivateOramAcknowledgedGcObligationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramAcknowledgedGcObligationV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field(
                "terminal_decision_certificate",
                &self.terminal_decision_certificate,
            )
            .field("acknowledged_tombstone", &self.acknowledged_tombstone)
            .field("cleanup_target", &self.cleanup_target)
            .field("collection_key_digest", &"[redacted]")
            .field("collection_incarnation_digest", &"[redacted]")
            .field("obligation_digest", &"[redacted]")
            .finish()
    }
}

/// A committed negative answer for one exact admission CAS.
///
/// The canonical recovery manifest is retained so owner-side intents created before admission can
/// be found and tombstoned after an indeterminate proposal outcome. The record does not advance the
/// lease generation: it only consumes the exact aggregate digest against which admission raced.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationRejectedAdmissionV2 {
    version: u16,
    lease: PrivateOramMutationLease,
    attempt_id: String,
    reservation_canonical_json: String,
    recovery_manifest_canonical_json: Option<String>,
    resolution_request_digest: String,
    admission_request_digest: Option<String>,
    outcome_key: String,
    rejected_from_aggregate_digest: String,
    rejection_applied: PrivateOramRaftApplyLocatorV2,
    rejection_digest: String,
}

impl Debug for PrivateOramMutationRejectedAdmissionV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationRejectedAdmissionV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &self.lease.owner_peer_id)
            .field(
                "recovery_manifest_bytes",
                &self
                    .recovery_manifest_canonical_json
                    .as_ref()
                    .map_or(0, String::len),
            )
            .field("rejection_applied", &self.rejection_applied)
            .field("admission_request_digest", &"[redacted]")
            .field("rejected_from_aggregate_digest", &"[redacted]")
            .field("rejection_digest", &"[redacted]")
            .finish()
    }
}

/// One consensus snapshot of the exact prepared attempt and its admission CAS authority.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationPreparedAppendSnapshotV2 {
    reservation: PrivateOramMutationAppendReservationV2,
    prepared: PrivateOramMutationAllOwnersPrestagedV2,
    expected_aggregate_digest: String,
}

impl PrivateOramMutationPreparedAppendSnapshotV2 {
    pub fn reservation(&self) -> &PrivateOramMutationAppendReservationV2 {
        &self.reservation
    }

    pub fn prepared(&self) -> &PrivateOramMutationAllOwnersPrestagedV2 {
        &self.prepared
    }

    pub fn expected_aggregate_digest(&self) -> &str {
        &self.expected_aggregate_digest
    }
}

/// Durable work before admission, or its exact rejected outcome awaiting owner acknowledgement.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationPreadmissionRecoveryCandidateV2 {
    key: PrivateOramMutationKey,
    lease: PrivateOramMutationLease,
    manifest: PrivateOramMutationAllOwnersPrestagedV2,
    prepared_snapshot: Option<PrivateOramMutationPreparedAppendSnapshotV2>,
}

impl PrivateOramMutationPreadmissionRecoveryCandidateV2 {
    pub fn key(&self) -> &PrivateOramMutationKey {
        &self.key
    }

    pub fn lease(&self) -> &PrivateOramMutationLease {
        &self.lease
    }

    pub fn manifest(&self) -> &PrivateOramMutationAllOwnersPrestagedV2 {
        &self.manifest
    }

    pub fn prepared_snapshot(&self) -> Option<&PrivateOramMutationPreparedAppendSnapshotV2> {
        self.prepared_snapshot.as_ref()
    }
}

impl Debug for PrivateOramMutationPreadmissionRecoveryCandidateV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationPreadmissionRecoveryCandidateV2")
            .field("generation", &self.lease.generation)
            .field("prepared", &self.prepared_snapshot.is_some())
            .finish_non_exhaustive()
    }
}

/// Exact negative admission and its completed owner acknowledgement, read together.
///
/// This is not an admitted cleanup permit and does not consume a lease generation.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationRejectedAdmissionAcknowledgementV2 {
    lease: PrivateOramMutationLease,
    recovery_manifest_digest: String,
    rejection_digest: String,
}

impl PrivateOramMutationRejectedAdmissionAcknowledgementV2 {
    pub fn lease(&self) -> &PrivateOramMutationLease {
        &self.lease
    }

    pub fn recovery_manifest_digest(&self) -> &str {
        &self.recovery_manifest_digest
    }

    pub fn rejection_digest(&self) -> &str {
        &self.rejection_digest
    }
}

impl Debug for PrivateOramMutationRejectedAdmissionAcknowledgementV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationRejectedAdmissionAcknowledgementV2")
            .field("generation", &self.lease.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationPreparedAppendV2 {
    version: u16,
    recovery_manifest_canonical_json: String,
    prepare_request_digest: String,
    admission_request_digest: String,
    prepared_applied: PrivateOramRaftApplyLocatorV2,
    prepared_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointLeaseTransitionV1 {
    version: u16,
    prelease_table_sequence: u64,
    prelease_table_digest: String,
    postlease_table_sequence: u64,
    postlease_table_digest: String,
    owner_checkpoint_roster_digest: String,
    reservation_context_digest: String,
    reservation_digest: String,
    transition_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointLeaseTransitionV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointLeaseTransitionV1")
            .field("version", &self.version)
            .field("prelease_table_sequence", &self.prelease_table_sequence)
            .field("postlease_table_sequence", &self.postlease_table_sequence)
            .field("prelease_table_digest", &"[redacted]")
            .field("postlease_table_digest", &"[redacted]")
            .field("owner_checkpoint_roster_digest", &"[redacted]")
            .field("reservation_context_digest", &"[redacted]")
            .field("reservation_digest", &"[redacted]")
            .field("transition_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationActiveAppendAttemptV2 {
    version: u16,
    reservation_canonical_json: String,
    reservation_request_digest: String,
    reservation_applied: PrivateOramRaftApplyLocatorV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint_lease_transition: Option<PrivateOramOwnerCheckpointLeaseTransitionV1>,
    prepared: Option<PrivateOramMutationPreparedAppendV2>,
    attempt_digest: String,
}

impl Debug for PrivateOramMutationActiveAppendAttemptV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationActiveAppendAttemptV2")
            .field("version", &self.version)
            .field("reservation_bytes", &self.reservation_canonical_json.len())
            .field(
                "checkpoint_lease_transition",
                &self.checkpoint_lease_transition.is_some(),
            )
            .field("prepared", &self.prepared.is_some())
            .field("reservation_request_digest", &"[redacted]")
            .field("attempt_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationActiveAppendAttemptV2 {
    pub(crate) fn reservation_canonical_json(&self) -> &str {
        &self.reservation_canonical_json
    }

    pub(crate) fn prepared_manifest_canonical_json(&self) -> Option<&str> {
        self.prepared
            .as_ref()
            .map(|prepared| prepared.recovery_manifest_canonical_json.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationAppendOutcomeKindV2 {
    Admitted,
    AdmissionRejected,
    PrestageAborted,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationAppendOutcomeV2 {
    version: u16,
    outcome_key: String,
    kind: PrivateOramMutationAppendOutcomeKindV2,
    protocol_capability_digest: String,
    collection_incarnation_digest: String,
    attempt_id: String,
    mutation_id: String,
    preparing_lease_state_digest: String,
    resolved_from_aggregate_digest: String,
    resolution_request_digest: String,
    admission_request_digest: Option<String>,
    manifest_digest: Option<String>,
    owner_roster_digest: String,
    resolution_applied: PrivateOramRaftApplyLocatorV2,
    outcome_digest: String,
}

impl Debug for PrivateOramMutationAppendOutcomeV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendOutcomeV2")
            .field("kind", &self.kind)
            .field("resolution_applied", &self.resolution_applied)
            .field("outcome_key", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("outcome_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationPendingReservationChallengeV1 {
    version: u16,
    challenge_canonical_json: String,
    challenge_digest: String,
    reservation_intent_digest: String,
    attempt_id: String,
    attempt_sequence: u64,
    pre_challenge_aggregate_digest: String,
    challenge_applied: PrivateOramRaftApplyLocatorV2,
    prepared_ordinal: u64,
    pending_digest: String,
}

impl Debug for PrivateOramMutationPendingReservationChallengeV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationPendingReservationChallengeV1")
            .field("version", &self.version)
            .field("challenge_bytes", &self.challenge_canonical_json.len())
            .field("challenge_applied", &self.challenge_applied)
            .field("prepared_ordinal", &self.prepared_ordinal)
            .field("challenge_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("pending_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationPendingReservationChallengeV1 {
    pub(crate) fn challenge_canonical_json(&self) -> &str {
        &self.challenge_canonical_json
    }

    pub(crate) fn challenge_digest(&self) -> &str {
        &self.challenge_digest
    }

    pub(crate) fn challenge_applied(&self) -> &PrivateOramRaftApplyLocatorV2 {
        &self.challenge_applied
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationReservationChallengeOutcomeKindV1 {
    FinalizedV3,
    Cancelled,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationReservationChallengeOutcomeV1 {
    version: u16,
    kind: PrivateOramMutationReservationChallengeOutcomeKindV1,
    challenge_digest: String,
    challenge_applied: PrivateOramRaftApplyLocatorV2,
    reservation_intent_digest: String,
    attempt_id: String,
    attempt_sequence: u64,
    resolution_request_digest: String,
    resolution_applied: PrivateOramRaftApplyLocatorV2,
    finalized_reservation_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge_canonical_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finalized_reservation_canonical_json: Option<String>,
    outcome_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationReservationChallengeCancellationV1 {
    version: u16,
    collection_key_digest: String,
    challenge_digest: String,
    reservation_intent_digest: String,
    attempt_id: String,
    attempt_sequence: u64,
    cancellation_operation_id: String,
    cancellation_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationReservationOutcomeAcknowledgementV1 {
    version: u16,
    outcome_digest: String,
    owner_resolution_receipts_canonical_json: Vec<String>,
    acknowledgement_digest: String,
}

struct ExpectedOwnerReservationCompletionV1 {
    collection_id: String,
    owner_peer_id: u64,
    owner_enrollment_id: String,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
    committed_challenge_digest: String,
    reservation_intent_digest: String,
    attempt_id: String,
    challenge_applied: PrivateOramRaftApplyLocatorV2,
    resolution_applied: PrivateOramRaftApplyLocatorV2,
    reserved_terminal_intent_key: String,
    finalized_reservation_digest: Option<String>,
    owner_store_incarnation_digest: String,
    owner_store_binding_digest: String,
    durable_fence_record_digest: Option<String>,
    installed_prestage_receipt_digest: Option<String>,
    installed_package_sha256: String,
}

impl Debug for PrivateOramMutationReservationOutcomeAcknowledgementV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationReservationOutcomeAcknowledgementV1")
            .field("version", &self.version)
            .field(
                "owner_resolution_receipt_count",
                &self.owner_resolution_receipts_canonical_json.len(),
            )
            .field("outcome_digest", &"[redacted]")
            .field("acknowledgement_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationReservationOutcomeAcknowledgementV1 {
    pub(crate) fn outcome_digest(&self) -> &str {
        &self.outcome_digest
    }

    pub(crate) fn acknowledgement_digest(&self) -> &str {
        &self.acknowledgement_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationReservationOutcomeAccumulatorV1 {
    version: u16,
    compacted_outcome_count: u64,
    prior_accumulator_digest: Option<String>,
    last_challenge_digest: String,
    last_attempt_sequence: u64,
    last_resolution_applied: PrivateOramRaftApplyLocatorV2,
    last_acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
    last_outcome_digest: String,
    last_acknowledgement_digest: String,
    accumulator_digest: String,
}

impl Debug for PrivateOramMutationReservationOutcomeAccumulatorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationReservationOutcomeAccumulatorV1")
            .field("version", &self.version)
            .field("compacted_outcome_count", &self.compacted_outcome_count)
            .field("last_attempt_sequence", &self.last_attempt_sequence)
            .field("last_resolution_applied", &self.last_resolution_applied)
            .field(
                "last_acknowledgement_applied",
                &self.last_acknowledgement_applied,
            )
            .field("prior_accumulator_digest", &"[redacted]")
            .field("last_challenge_digest", &"[redacted]")
            .field("last_outcome_digest", &"[redacted]")
            .field("last_acknowledgement_digest", &"[redacted]")
            .field("accumulator_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramMutationReservationChallengeCancellationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationReservationChallengeCancellationV1")
            .field("version", &self.version)
            .field("attempt_sequence", &self.attempt_sequence)
            .field("challenge_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("cancellation_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationReservationChallengeCancellationV1 {
    pub(crate) fn collection_key_digest(&self) -> &str {
        &self.collection_key_digest
    }

    pub(crate) fn cancellation_digest(&self) -> &str {
        &self.cancellation_digest
    }
}

impl Debug for PrivateOramMutationReservationChallengeOutcomeV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationReservationChallengeOutcomeV1")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("challenge_applied", &self.challenge_applied)
            .field("resolution_applied", &self.resolution_applied)
            .field("challenge_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("outcome_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationReservationChallengeOutcomeV1 {
    pub(crate) const fn kind(&self) -> PrivateOramMutationReservationChallengeOutcomeKindV1 {
        self.kind
    }

    pub(crate) fn challenge_digest(&self) -> &str {
        &self.challenge_digest
    }

    pub(crate) fn challenge_applied(&self) -> &PrivateOramRaftApplyLocatorV2 {
        &self.challenge_applied
    }

    pub(crate) fn reservation_intent_digest(&self) -> &str {
        &self.reservation_intent_digest
    }

    pub(crate) fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub(crate) fn resolution_applied(&self) -> &PrivateOramRaftApplyLocatorV2 {
        &self.resolution_applied
    }

    pub(crate) fn finalized_reservation_digest(&self) -> Option<&str> {
        self.finalized_reservation_digest.as_deref()
    }

    pub(crate) fn challenge_canonical_json(&self) -> Option<&str> {
        self.challenge_canonical_json.as_deref()
    }

    pub(crate) fn finalized_reservation_canonical_json(&self) -> Option<&str> {
        self.finalized_reservation_canonical_json.as_deref()
    }

    pub(crate) fn outcome_digest(&self) -> &str {
        &self.outcome_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationConsensusAggregateV2 {
    version: u16,
    activation: PrivateOramMutationActivationAnchorV2,
    outer_binding_digest: String,
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
    recovery_capsules_certificate: Option<PrivateOramMutationRecoveryCapsulesCertificateV2>,
    terminal_decision_certificate: Option<PrivateOramMutationTerminalDecisionCertificateV2>,
    transition_ordinal: u64,
    last_material_transition: PrivateOramMaterialTransitionReceiptV2,
    outstanding_gc_obligations: Vec<PrivateOramAcknowledgedGcObligationV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    compacted_owner_archive_histories: Vec<PrivateOramOwnerCompactedArchiveHistoryV1>,
    rejected_admissions: Vec<PrivateOramMutationRejectedAdmissionV2>,
    active_append_attempt: Option<PrivateOramMutationActiveAppendAttemptV2>,
    append_outcomes: Vec<PrivateOramMutationAppendOutcomeV2>,
    owner_checkpoint_table: PrivateOramOwnerCheckpointTableV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_reservation_challenge: Option<PrivateOramMutationPendingReservationChallengeV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reservation_challenge_outcomes: Vec<PrivateOramMutationReservationChallengeOutcomeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reservation_challenge_outcome_accumulator:
        Option<PrivateOramMutationReservationOutcomeAccumulatorV1>,
    authority_core_digest: String,
    aggregate_digest: String,
}

impl Debug for PrivateOramMutationConsensusAggregateV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationConsensusAggregateV2")
            .field("version", &self.version)
            .field("activation", &self.activation)
            .field("outer_binding_digest", &"[redacted]")
            .field("lifecycle", &self.lifecycle)
            .field("lease_slot", &self.lease_slot)
            .field(
                "recovery_capsules_certificate",
                &self.recovery_capsules_certificate,
            )
            .field(
                "terminal_decision_certificate",
                &self.terminal_decision_certificate,
            )
            .field("transition_ordinal", &self.transition_ordinal)
            .field("last_material_transition", &self.last_material_transition)
            .field(
                "outstanding_gc_obligation_count",
                &self.outstanding_gc_obligations.len(),
            )
            .field("rejected_admission_count", &self.rejected_admissions.len())
            .field(
                "compacted_owner_archive_histories",
                &self.compacted_owner_archive_histories,
            )
            .field("active_append_attempt", &self.active_append_attempt)
            .field("append_outcome_count", &self.append_outcomes.len())
            .field("owner_checkpoint_table", &self.owner_checkpoint_table)
            .field(
                "pending_reservation_challenge",
                &self.pending_reservation_challenge,
            )
            .field(
                "reservation_challenge_outcome_count",
                &self.reservation_challenge_outcomes.len(),
            )
            .field(
                "reservation_challenge_outcome_accumulator",
                &self.reservation_challenge_outcome_accumulator,
            )
            .field("authority_core_digest", &"[redacted]")
            .field("aggregate_digest", &"[redacted]")
            .finish()
    }
}

/// Mandatory value for every enrolled private-ORAM mutation collection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(
    tag = "mode",
    content = "state",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum PrivateOramMutationAuthorityStateV2 {
    Legacy(PrivateOramMutationLegacyAuthorityV2),
    Activated(Box<PrivateOramMutationConsensusAggregateV2>),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationTaggedAuthorityEnvelopeV2 {
    envelope_version: u16,
    authority: PrivateOramMutationAuthorityStateV2,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PrivateOramMutationAuthorityWireFormatV2 {
    HistoricalRawLeaseSlotV2,
    TaggedAuthorityV2,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum DecodedPrivateOramMutationAuthorityWireV2 {
    HistoricalRawLeaseSlotV2(PrivateOramMutationLeaseSlotV2),
    TaggedAuthorityV2(PrivateOramMutationAuthorityStateV2),
}

impl DecodedPrivateOramMutationAuthorityWireV2 {
    pub(crate) fn format(&self) -> PrivateOramMutationAuthorityWireFormatV2 {
        match self {
            Self::HistoricalRawLeaseSlotV2(_) => {
                PrivateOramMutationAuthorityWireFormatV2::HistoricalRawLeaseSlotV2
            }
            Self::TaggedAuthorityV2(_) => {
                PrivateOramMutationAuthorityWireFormatV2::TaggedAuthorityV2
            }
        }
    }

    pub(crate) fn lease_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        match self {
            Self::HistoricalRawLeaseSlotV2(slot) => slot,
            Self::TaggedAuthorityV2(authority) => authority.lease_slot(),
        }
    }

    pub(crate) fn tagged_authority(&self) -> Option<&PrivateOramMutationAuthorityStateV2> {
        match self {
            Self::HistoricalRawLeaseSlotV2(_) => None,
            Self::TaggedAuthorityV2(authority) => Some(authority),
        }
    }

    pub(crate) fn historical_raw_slot(&self) -> Option<&PrivateOramMutationLeaseSlotV2> {
        match self {
            Self::HistoricalRawLeaseSlotV2(slot) => Some(slot),
            Self::TaggedAuthorityV2(_) => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), PrivateOramMutationJournalError> {
        match self {
            Self::HistoricalRawLeaseSlotV2(slot) => validate_lease_slot_v2(slot),
            Self::TaggedAuthorityV2(authority) => {
                validate_private_oram_mutation_authority_state_v2(authority)
            }
        }
    }
}

impl From<PrivateOramMutationLeaseSlotV2> for DecodedPrivateOramMutationAuthorityWireV2 {
    fn from(slot: PrivateOramMutationLeaseSlotV2) -> Self {
        Self::HistoricalRawLeaseSlotV2(slot)
    }
}

impl Serialize for DecodedPrivateOramMutationAuthorityWireV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::HistoricalRawLeaseSlotV2(slot) => slot.serialize(serializer),
            Self::TaggedAuthorityV2(authority) => PrivateOramMutationTaggedAuthorityEnvelopeV2 {
                envelope_version: AUTHORITY_WIRE_ENVELOPE_VERSION,
                authority: authority.clone(),
            }
            .serialize(serializer),
        }
    }
}

#[derive(Default)]
struct PrivateOramMutationAuthorityWireProbe {
    keys: HashSet<String>,
    tagged_marker_observed: bool,
    envelope_version: Option<u16>,
    authority: Option<PrivateOramMutationAuthorityStateV2>,
    raw_version: Option<u16>,
    raw_generation: Option<u64>,
    raw_active: Option<Option<PrivateOramMutationLease>>,
    raw_last_clear: Option<Option<PrivateOramMutationClearReceiptV1>>,
    raw_max_writer_fence: Option<u64>,
}

struct PrivateOramMutationAuthorityWireProbeVisitor;

impl<'de> Visitor<'de> for PrivateOramMutationAuthorityWireProbeVisitor {
    type Value = PrivateOramMutationAuthorityWireProbe;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a private ORAM mutation authority object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<PrivateOramMutationAuthorityWireProbe, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut probe = PrivateOramMutationAuthorityWireProbe::default();
        while let Some(key) = map.next_key::<String>()? {
            if !probe.keys.insert(key.clone()) {
                return Err(serde::de::Error::duplicate_field("authority field"));
            }
            match key.as_str() {
                "envelope_version" => {
                    probe.tagged_marker_observed = true;
                    probe.envelope_version = Some(map.next_value()?);
                }
                "authority" => {
                    probe.tagged_marker_observed = true;
                    probe.authority = Some(map.next_value()?);
                }
                // Old direct tags still classify the value as tagged and therefore cannot fall
                // back to the historical raw shape.
                "mode" | "state" => {
                    probe.tagged_marker_observed = true;
                    map.next_value::<IgnoredAny>()?;
                }
                "version" => probe.raw_version = Some(map.next_value()?),
                "generation" => probe.raw_generation = Some(map.next_value()?),
                "active" => probe.raw_active = Some(map.next_value()?),
                "last_clear" => probe.raw_last_clear = Some(map.next_value()?),
                "max_writer_fence" => probe.raw_max_writer_fence = Some(map.next_value()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(probe)
    }
}

impl PrivateOramMutationAuthorityWireProbe {
    fn finish<E>(self) -> Result<DecodedPrivateOramMutationAuthorityWireV2, E>
    where
        E: serde::de::Error,
    {
        if self.tagged_marker_observed {
            if self.keys.len() != 2
                || !self.keys.contains("envelope_version")
                || !self.keys.contains("authority")
                || self.envelope_version != Some(AUTHORITY_WIRE_ENVELOPE_VERSION)
            {
                return Err(E::custom(
                    "invalid private ORAM mutation authority envelope",
                ));
            }
            let authority = self
                .authority
                .ok_or_else(|| E::custom("missing private ORAM mutation authority"))?;
            validate_private_oram_mutation_authority_state_v2(&authority)
                .map_err(|_| E::custom("invalid private ORAM mutation authority"))?;
            return Ok(DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(authority));
        }

        const RAW_KEYS: [&str; 5] = [
            "version",
            "generation",
            "active",
            "last_clear",
            "max_writer_fence",
        ];
        if self.keys.len() != RAW_KEYS.len() || RAW_KEYS.iter().any(|key| !self.keys.contains(*key))
        {
            return Err(E::custom(
                "invalid historical private ORAM mutation lease slot",
            ));
        }
        let slot = PrivateOramMutationLeaseSlotV2 {
            version: self
                .raw_version
                .ok_or_else(|| E::custom("missing historical lease slot version"))?,
            generation: self
                .raw_generation
                .ok_or_else(|| E::custom("missing historical lease slot generation"))?,
            active: self
                .raw_active
                .ok_or_else(|| E::custom("missing historical active lease"))?,
            last_clear: self
                .raw_last_clear
                .ok_or_else(|| E::custom("missing historical clear receipt"))?,
            max_writer_fence: self
                .raw_max_writer_fence
                .ok_or_else(|| E::custom("missing historical writer fence"))?,
        };
        validate_lease_slot_v2(&slot)
            .map_err(|_| E::custom("invalid historical private ORAM mutation lease slot"))?;
        Ok(DecodedPrivateOramMutationAuthorityWireV2::HistoricalRawLeaseSlotV2(slot))
    }
}

impl<'de> Deserialize<'de> for DecodedPrivateOramMutationAuthorityWireV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_map(PrivateOramMutationAuthorityWireProbeVisitor)?
            .finish()
    }
}

/// Strict shadow decoder used before the first tagged write is enabled.
///
/// Detection is performed once from the original JSON object. A tagged marker is never retried as
/// historical raw state, including when its envelope version, mode, or nested payload is malformed.
pub(crate) fn decode_private_oram_mutation_authority_wire_json_v2(
    encoded: &[u8],
) -> Result<DecodedPrivateOramMutationAuthorityWireV2, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > MAX_AUTHORITY_WIRE_BYTES {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    serde_json::from_slice(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

/// Canonical tagged encoder. Production persistence keeps writing the historical raw value until
/// a committed format floor makes tagged writes irreversible across every eligible peer.
pub(crate) fn encode_private_oram_mutation_tagged_authority_wire_json_v2(
    authority: &PrivateOramMutationAuthorityStateV2,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_authority_state_v2(authority)?;
    let encoded = serde_json::to_vec(&PrivateOramMutationTaggedAuthorityEnvelopeV2 {
        envelope_version: AUTHORITY_WIRE_ENVELOPE_VERSION,
        authority: authority.clone(),
    })
    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.len() > MAX_AUTHORITY_WIRE_BYTES {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(encoded)
}

/// Converts either accepted Legacy wire representation into the same contextual authority value.
pub(crate) fn canonical_private_oram_mutation_legacy_authority_from_wire_v2(
    decoded: &DecodedPrivateOramMutationAuthorityWireV2,
    authority_key: &PrivateOramMutationAuthorityKeyV2,
    outer_binding_digest: &str,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    if matches!(
        decoded.tagged_authority(),
        Some(PrivateOramMutationAuthorityStateV2::Activated(_))
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let canonical = private_oram_mutation_legacy_authority_v2(
        authority_key.clone(),
        decoded.lease_slot().clone(),
        outer_binding_digest.to_string(),
    )?;
    if let Some(tagged) = decoded.tagged_authority()
        && tagged != &canonical
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(canonical)
}

/// Non-serializable authority minted from the committed activation Raft entry.
pub(crate) struct PrivateOramMutationActivationContextV2 {
    locator: PrivateOramRaftApplyLocatorV2,
    compatibility_epoch: u64,
    activation_request_digest: String,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

/// Non-serializable authority minted from one committed mutation Raft entry.
pub(crate) struct PrivateOramMutationAggregateApplyContextV2 {
    locator: PrivateOramRaftApplyLocatorV2,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    request_digest: String,
    expected_aggregate_digest: String,
    next_outer_binding_digest: String,
    retain_compacted_owner_archive_history: bool,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl PrivateOramMutationAggregateApplyContextV2 {
    /// The applied writer floor, not the running binary version, chooses replay semantics.
    pub(crate) fn with_owner_archive_history_floor(
        mut self,
        floor: &PrivateOramMutationFormatFloorV2,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        validate_private_oram_mutation_format_floor_v2(floor)?;
        if !matches!(
            self.operation_kind,
            PrivateOramMutationMaterialOperationV2::Admission
                | PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared
        ) || !floor.activation_enabled()
            || floor.minimum_reader_protocol() < OWNER_ARCHIVE_HISTORY_MIN_PROTOCOL_V1
            || floor.minimum_writer_protocol() < OWNER_ARCHIVE_HISTORY_MIN_PROTOCOL_V1
            || !locator_is_strictly_after(&self.locator, floor.floor_applied_locator())
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        self.retain_compacted_owner_archive_history = true;
        Ok(self)
    }
}

impl Debug for PrivateOramMutationActivationContextV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationActivationContextV2")
            .field("locator", &self.locator)
            .field("compatibility_epoch", &self.compatibility_epoch)
            .field("activation_request_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Debug for PrivateOramMutationAggregateApplyContextV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAggregateApplyContextV2")
            .field("locator", &self.locator)
            .field("operation_kind", &self.operation_kind)
            .field("request_digest", &"[redacted]")
            .field("expected_aggregate_digest", &"[redacted]")
            .field("next_outer_binding_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PrivateOramMutationAuthorityStateV2 {
    pub(crate) fn lease_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        match self {
            Self::Legacy(legacy) => &legacy.exact_legacy_slot,
            Self::Activated(aggregate) => &aggregate.lease_slot,
        }
    }

    pub(crate) fn aggregate(&self) -> Option<&PrivateOramMutationConsensusAggregateV2> {
        match self {
            Self::Legacy(_) => None,
            Self::Activated(aggregate) => Some(aggregate),
        }
    }

    pub(crate) fn consensus_history_id_digest(&self) -> &str {
        match self {
            Self::Legacy(legacy) => &legacy.authority_key.consensus_history_id_digest,
            Self::Activated(aggregate) => {
                &aggregate
                    .activation
                    .authority_key
                    .consensus_history_id_digest
            }
        }
    }

    pub(crate) fn raft_group_id_digest(&self) -> &str {
        match self {
            Self::Legacy(legacy) => &legacy.authority_key.raft_group_id_digest,
            Self::Activated(aggregate) => &aggregate.activation.authority_key.raft_group_id_digest,
        }
    }

    pub(crate) fn collection_key_digest(&self) -> &str {
        match self {
            Self::Legacy(legacy) => &legacy.authority_key.collection_key_digest,
            Self::Activated(aggregate) => &aggregate.activation.authority_key.collection_key_digest,
        }
    }

    pub(crate) fn outer_binding_digest(&self) -> &str {
        match self {
            Self::Legacy(legacy) => &legacy.outer_binding_digest,
            Self::Activated(aggregate) => &aggregate.outer_binding_digest,
        }
    }
}

impl PrivateOramMutationConsensusAggregateV2 {
    pub(crate) fn lifecycle(&self) -> &PrivateOramMutationCleanupLifecycleV2 {
        &self.lifecycle
    }

    pub(crate) fn lease_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        &self.lease_slot
    }

    pub(crate) fn transition_ordinal(&self) -> u64 {
        self.transition_ordinal
    }

    pub(crate) fn aggregate_digest(&self) -> &str {
        &self.aggregate_digest
    }

    pub(crate) fn append_authority_context(
        &self,
    ) -> Result<PrivateOramMutationAppendAuthorityContextV2, PrivateOramMutationJournalError> {
        PrivateOramMutationAppendAuthorityContextV2::from_authority(
            self.aggregate_digest.clone(),
            self.activation
                .authority_key
                .consensus_history_id_digest
                .clone(),
            self.activation.authority_key.raft_group_id_digest.clone(),
            self.activation
                .authority_key
                .collection_lifetime_id_digest
                .clone(),
            self.activation.collection_incarnation_digest.clone(),
            self.activation.anchor_digest.clone(),
            self.transition_ordinal
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
        )
    }

    pub(crate) fn outer_binding_digest(&self) -> &str {
        &self.outer_binding_digest
    }

    pub(crate) fn recovery_capsules_certificate(
        &self,
    ) -> Option<&PrivateOramMutationRecoveryCapsulesCertificateV2> {
        self.recovery_capsules_certificate.as_ref()
    }

    pub(crate) fn parent_watermark(
        &self,
    ) -> Option<
        &crate::content_manager::consensus::private_oram_mutation_watermark::PrivateOramMutationParentWatermarkV2,
    >{
        retained_parent_progress_v2(&self.lifecycle).map(|(watermark, _)| watermark)
    }

    pub(crate) fn outstanding_gc_obligations(&self) -> &[PrivateOramAcknowledgedGcObligationV2] {
        &self.outstanding_gc_obligations
    }

    pub(crate) fn has_compacted_owner_archive_history(&self) -> bool {
        !self.compacted_owner_archive_histories.is_empty()
    }

    pub(crate) fn owner_new_generation_readiness_expectation(
        &self,
        collection_id: &str,
        owner_peer_id: u64,
    ) -> Result<PrivateOramOwnerNewGenerationReadinessExpectationV2, PrivateOramMutationJournalError>
    {
        validate_aggregate_v2(self)?;
        require_complete_acknowledged_archive_history_v1(self)?;
        if owner_peer_id == 0
            || private_oram_collection_id_digest_v2(collection_id)?
                != self.activation.authority_key.collection_key_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let mut checkpoints = self
            .owner_checkpoint_table
            .checkpoints()
            .iter()
            .filter(|checkpoint| checkpoint.owner_peer_id() == owner_peer_id);
        let checkpoint = checkpoints
            .next()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        if checkpoints.next().is_some() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let expected = self.acknowledged_owner_archive_expectations(owner_peer_id)?;
        PrivateOramOwnerNewGenerationReadinessExpectationV2::try_new_with_compacted_history(
            collection_id.to_string(),
            checkpoint.owner_store_incarnation_digest().to_string(),
            self.aggregate_digest.clone(),
            expected,
            self.compacted_owner_archive_histories
                .iter()
                .find(|history| history.owner_peer_id() == owner_peer_id)
                .cloned(),
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
    }

    pub(crate) fn acknowledged_owner_archive_expectations(
        &self,
        owner_peer_id: u64,
    ) -> Result<
        Vec<PrivateOramOwnerAcknowledgedArchiveExpectationV2>,
        PrivateOramMutationJournalError,
    > {
        validate_aggregate_v2(self)?;
        if owner_peer_id == 0 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let mut expected = std::collections::BTreeMap::new();
        let mut retain = |cleared: &PrivateOramMutationClearedStateV2| {
            if !matches!(
                cleared.resolution,
                PrivateOramMutationClearResolutionV2::Acknowledged(_)
            ) {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            if cleared.owner_peer_id != owner_peer_id {
                return Ok(());
            }
            let archive = acknowledged_owner_archive_expectation_v2(cleared)?;
            if let Some(existing) = expected.insert(cleared.generation, archive.clone())
                && existing != archive
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
            Ok(())
        };
        for obligation in &self.outstanding_gc_obligations {
            retain(&obligation.acknowledged_tombstone)?;
        }
        if let Some(cleared) = self.lifecycle.last_cleared.as_ref()
            && matches!(
                cleared.resolution,
                PrivateOramMutationClearResolutionV2::Acknowledged(_)
            )
        {
            retain(cleared)?;
        }
        Ok(expected.into_values().collect())
    }

    pub(crate) fn rejected_admissions(&self) -> &[PrivateOramMutationRejectedAdmissionV2] {
        &self.rejected_admissions
    }

    pub(crate) fn active_append_attempt(
        &self,
    ) -> Option<&PrivateOramMutationActiveAppendAttemptV2> {
        self.active_append_attempt.as_ref()
    }

    pub(crate) fn preadmission_recovery_candidate(
        &self,
    ) -> Result<
        Option<PrivateOramMutationPreadmissionRecoveryCandidateV2>,
        PrivateOramMutationJournalError,
    > {
        if let Some(active) = self.active_append_attempt.as_ref()
            && let Some(prepared) = active.prepared.as_ref()
        {
            let reservation = decode_private_oram_mutation_append_reservation_wire(
                &active.reservation_canonical_json,
            )?;
            let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
                &prepared.recovery_manifest_canonical_json,
            )?;
            reservation.validate_manifest(&manifest)?;
            let reservation = reservation.base_reservation().clone();
            return Ok(Some(PrivateOramMutationPreadmissionRecoveryCandidateV2 {
                key: PrivateOramMutationKey {
                    collection_id: reservation.collection_id().to_string(),
                },
                lease: reservation.preparing_lease().clone(),
                manifest: manifest.clone(),
                prepared_snapshot: Some(PrivateOramMutationPreparedAppendSnapshotV2 {
                    reservation,
                    prepared: manifest,
                    expected_aggregate_digest: self.aggregate_digest.clone(),
                }),
            }));
        }

        // An earlier cancelled challenge may still be at the FIFO head. The retained
        // rejection supplies this collection's recovery descriptor, while each ACK still
        // uses the existing exact authority and signed receipts for its own FIFO head.
        let Some(rejected) = self
            .reservation_challenge_outcomes
            .iter()
            .filter(|outcome| {
                outcome.kind == PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3
            })
            .find_map(|outcome| {
                self.rejected_admissions.iter().find(|rejected| {
                    rejected.attempt_id == outcome.attempt_id
                        && rejected.admission_request_digest.is_some()
                })
            })
        else {
            return Ok(None);
        };
        let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
            rejected
                .recovery_manifest_canonical_json
                .as_deref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        )?;
        manifest.validate_admission_lease(&rejected.lease)?;
        Ok(Some(PrivateOramMutationPreadmissionRecoveryCandidateV2 {
            key: PrivateOramMutationKey {
                collection_id: rejected.lease.collection_id.clone(),
            },
            lease: rejected.lease.clone(),
            manifest,
            prepared_snapshot: None,
        }))
    }

    pub(crate) fn rejected_admission_acknowledgement(
        &self,
        lease: &PrivateOramMutationLease,
    ) -> Result<
        Option<PrivateOramMutationRejectedAdmissionAcknowledgementV2>,
        PrivateOramMutationJournalError,
    > {
        let mut matching = self.rejected_admissions.iter().filter(|rejected| {
            rejected.lease == *lease && rejected.admission_request_digest.is_some()
        });
        let Some(rejected) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let DecodedPrivateOramMutationAppendReservation::CheckpointBoundV3(reservation) =
            decode_private_oram_mutation_append_reservation_wire(
                &rejected.reservation_canonical_json,
            )?
        else {
            // Historical reservations have no signed owner-resolution ACK evidence.
            return Ok(None);
        };
        let Some(accumulator) = self.reservation_challenge_outcome_accumulator.as_ref() else {
            return Ok(None);
        };
        let base = reservation.base_reservation();
        if self
            .reservation_challenge_outcomes
            .iter()
            .any(|outcome| outcome.attempt_id == rejected.attempt_id)
            || accumulator.last_attempt_sequence < base.attempt_sequence()
            || !locator_is_strictly_after(
                &accumulator.last_acknowledgement_applied,
                &rejected.rejection_applied,
            )
            || (accumulator.last_attempt_sequence == base.attempt_sequence()
                && accumulator.last_challenge_digest
                    != reservation.prepared_challenge().prepared_challenge_digest())
        {
            return Ok(None);
        }
        // The accumulator advances only after signed receipts settle a FIFO outcome. Its
        // retained sequence and locator prove completion even after a later ACK, while the
        // exact rejected record keeps a pruned or different attempt from authorizing cleanup.
        let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
            rejected
                .recovery_manifest_canonical_json
                .as_deref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        )?;
        manifest.validate_admission_lease(lease)?;
        Ok(Some(
            PrivateOramMutationRejectedAdmissionAcknowledgementV2 {
                lease: lease.clone(),
                recovery_manifest_digest: manifest.manifest_digest().to_string(),
                rejection_digest: rejected.rejection_digest.clone(),
            },
        ))
    }

    pub(crate) fn append_outcomes(&self) -> &[PrivateOramMutationAppendOutcomeV2] {
        &self.append_outcomes
    }

    pub(crate) fn prestage_aborted_outcome_digest(
        &self,
        attempt_id: &str,
    ) -> Result<Option<&str>, PrivateOramMutationJournalError> {
        let mut matching = self.append_outcomes.iter().filter(|outcome| {
            outcome.kind == PrivateOramMutationAppendOutcomeKindV2::PrestageAborted
                && outcome.attempt_id == attempt_id
        });
        let outcome = matching
            .next()
            .map(|outcome| outcome.outcome_digest.as_str());
        if matching.next().is_some() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        Ok(outcome)
    }

    pub(crate) fn owner_checkpoint_table(&self) -> &PrivateOramOwnerCheckpointTableV1 {
        &self.owner_checkpoint_table
    }

    pub(crate) fn pending_reservation_challenge(
        &self,
    ) -> Option<&PrivateOramMutationPendingReservationChallengeV1> {
        self.pending_reservation_challenge.as_ref()
    }

    pub(crate) fn reservation_challenge_outcomes(
        &self,
    ) -> &[PrivateOramMutationReservationChallengeOutcomeV1] {
        &self.reservation_challenge_outcomes
    }

    pub(crate) fn reservation_challenge_outcome_accumulator(
        &self,
    ) -> Option<&PrivateOramMutationReservationOutcomeAccumulatorV1> {
        self.reservation_challenge_outcome_accumulator.as_ref()
    }

    pub(crate) fn is_reservation_v3_floor_quiescent(&self) -> bool {
        self.pending_reservation_challenge.is_none()
            && self.active_append_attempt.is_none()
            && self.reservation_challenge_outcomes.is_empty()
    }

    pub(crate) fn retained_terminal_lease(&self) -> Option<&PrivateOramMutationLease> {
        retained_terminal_lease_v2(&self.lifecycle)
    }

    pub(crate) fn active_admission_recovery_manifest(
        &self,
    ) -> Result<Option<PrivateOramMutationAllOwnersPrestagedV2>, PrivateOramMutationJournalError>
    {
        validate_aggregate_v2(self)?;
        self.lifecycle
            .active
            .as_ref()
            .map(active_admitted)
            .map(|admitted| {
                decode_private_oram_mutation_admission_recovery_manifest_v2(
                    &admitted.recovery_manifest_canonical_json,
                )
            })
            .transpose()
    }

    pub(crate) fn retains_admission(
        &self,
        lease: &PrivateOramMutationLease,
        recovery_manifest_digest: &str,
    ) -> Result<bool, PrivateOramMutationJournalError> {
        let request_digest =
            private_oram_mutation_admission_request_digest_v2(lease, recovery_manifest_digest)?;
        if self
            .lifecycle
            .active
            .as_ref()
            .map(active_admitted)
            .is_some_and(|admitted| {
                admitted.generation == lease.generation
                    && admitted.admission_request_digest == request_digest
            })
        {
            return Ok(true);
        }
        let lease_digest = private_oram_mutation_lease_state_digest_v2(lease)?;
        Ok(self.append_outcomes.iter().any(|outcome| {
            outcome.kind == PrivateOramMutationAppendOutcomeKindV2::Admitted
                && outcome.preparing_lease_state_digest == lease_digest
                && outcome.admission_request_digest.as_deref() == Some(request_digest.as_str())
        }))
    }

    pub(crate) fn retains_rejected_admission(
        &self,
        lease: &PrivateOramMutationLease,
        recovery_manifest_digest: &str,
    ) -> Result<bool, PrivateOramMutationJournalError> {
        let request_digest =
            private_oram_mutation_admission_request_digest_v2(lease, recovery_manifest_digest)?;
        let lease_digest = private_oram_mutation_lease_state_digest_v2(lease)?;
        Ok(self.rejected_admissions.iter().any(|rejected| {
            rejected.lease == *lease
                && rejected.admission_request_digest.as_deref() == Some(request_digest.as_str())
        }) || self.append_outcomes.iter().any(|outcome| {
            outcome.kind == PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected
                && outcome.preparing_lease_state_digest == lease_digest
                && outcome.admission_request_digest.as_deref() == Some(request_digest.as_str())
        }))
    }

    pub(crate) fn clear_transition_preview(
        &self,
    ) -> Result<(String, PrivateOramMutationLeaseSlotV2, bool), PrivateOramMutationJournalError>
    {
        match self.lifecycle.active.as_ref() {
            Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) => {
                let mut next_slot = self.lease_slot.clone();
                next_slot.active = None;
                next_slot.last_clear = Some(pending.witness.expected_clear_receipt()?);
                Ok((pending.pending_digest.clone(), next_slot, false))
            }
            None => {
                let cleared = self
                    .lifecycle
                    .last_cleared
                    .as_ref()
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
                Ok((
                    cleared.clear_pending_digest.clone(),
                    self.lease_slot.clone(),
                    true,
                ))
            }
            _ => Err(PrivateOramMutationJournalError::InvalidTransition),
        }
    }

    pub(crate) fn clear_acknowledgement_request_digest(
        &self,
    ) -> Result<&str, PrivateOramMutationJournalError> {
        self.lifecycle
            .last_cleared
            .as_ref()
            .map(|cleared| cleared.clear_core_digest.as_str())
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PrivateOramMutationOwnerEnrollmentPlanV2 {
    Missing(PrivateOramOwnerEnrollmentPreparedV1),
    Pending(PrivateOramOwnerEnrollmentPreparedV1),
    Active,
}

pub(crate) fn private_oram_mutation_owner_enrollment_plan_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    collection_id: &str,
    owner_peer_id: u64,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
    owner_store_incarnation_digest: String,
    owner_enrollment_id: String,
    authority_registry_digest: String,
    owner_registry_digest: String,
    enrollment_operation_id: String,
) -> Result<PrivateOramMutationOwnerEnrollmentPlanV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let expected_genesis_state =
        private_oram_owner_lifecycle_genesis_state_v1(owner_store_incarnation_digest.clone())
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_lifecycle"))?;
    let membership_epoch = aggregate
        .owner_checkpoint_table
        .roster_membership_epoch()
        .unwrap_or(aggregate.activation.activation_applied.index);
    let prepared = prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
        version: 0,
        consensus_history_id_digest: aggregate
            .activation
            .authority_key
            .consensus_history_id_digest
            .clone(),
        raft_group_id_digest: aggregate
            .activation
            .authority_key
            .raft_group_id_digest
            .clone(),
        collection_id: collection_id.to_string(),
        collection_lifetime_id_digest: aggregate
            .activation
            .authority_key
            .collection_lifetime_id_digest
            .clone(),
        collection_incarnation_digest: aggregate.activation.collection_incarnation_digest.clone(),
        activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
        capability_epoch: aggregate.activation.compatibility_epoch,
        protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
        membership_epoch,
        owner_enrollment_id,
        owner_peer_id,
        owner_signer,
        owner_store_incarnation_digest,
        expected_genesis_state: expected_genesis_state.clone(),
        authority_registry_digest,
        owner_registry_digest,
        enrollment_operation_id,
        prepared_record_digest: String::new(),
    })
    .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_enrollment"))?;

    if let Some(checkpoint) = aggregate
        .owner_checkpoint_table
        .checkpoint_for_owner(owner_peer_id)
    {
        if checkpoint.owner_enrollment_id() != prepared.owner_enrollment_id
            || checkpoint.owner_signer() != &prepared.owner_signer
            || checkpoint.owner_store_incarnation_digest()
                != prepared.owner_store_incarnation_digest
            || checkpoint.lifecycle_state() != &expected_genesis_state
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(PrivateOramMutationOwnerEnrollmentPlanV2::Active);
    }
    if let Some(pending) = aggregate
        .owner_checkpoint_table
        .pending_enrollment_for_owner(owner_peer_id)
    {
        if pending != &prepared {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(PrivateOramMutationOwnerEnrollmentPlanV2::Pending(prepared));
    }
    Ok(PrivateOramMutationOwnerEnrollmentPlanV2::Missing(prepared))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct PrivateOramMutationActivatedFloorProjectionV2 {
    pub(super) consensus_history_id_digest: String,
    pub(super) raft_group_id_digest: String,
    pub(super) collection_lifetime_id_digest: String,
    pub(super) collection_key_digest: String,
    pub(super) compatibility_epoch: u64,
    pub(super) activation_anchor_digest: String,
    pub(super) transition_ordinal: u64,
    pub(super) aggregate_digest: String,
    pub(super) outer_binding_digest: String,
    pub(super) latest_material_locator: PrivateOramRaftApplyLocatorV2,
}

pub(super) fn private_oram_mutation_activated_floor_projection_v2(
    authority: &PrivateOramMutationAuthorityStateV2,
) -> Result<Option<PrivateOramMutationActivatedFloorProjectionV2>, PrivateOramMutationJournalError>
{
    validate_private_oram_mutation_authority_state_v2(authority)?;
    let PrivateOramMutationAuthorityStateV2::Activated(aggregate) = authority else {
        return Ok(None);
    };
    Ok(Some(PrivateOramMutationActivatedFloorProjectionV2 {
        consensus_history_id_digest: aggregate
            .activation
            .authority_key
            .consensus_history_id_digest
            .clone(),
        raft_group_id_digest: aggregate
            .activation
            .authority_key
            .raft_group_id_digest
            .clone(),
        collection_lifetime_id_digest: aggregate
            .activation
            .authority_key
            .collection_lifetime_id_digest
            .clone(),
        collection_key_digest: aggregate
            .activation
            .authority_key
            .collection_key_digest
            .clone(),
        compatibility_epoch: aggregate.activation.compatibility_epoch,
        activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
        transition_ordinal: aggregate.transition_ordinal,
        aggregate_digest: aggregate.aggregate_digest.clone(),
        outer_binding_digest: aggregate.outer_binding_digest.clone(),
        latest_material_locator: aggregate.last_material_transition.locator.clone(),
    }))
}

impl PrivateOramAcknowledgedGcObligationV2 {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn cleanup_target(&self) -> &PrivateOramMutationCleanupTargetV2 {
        &self.cleanup_target
    }
}

impl PrivateOramMutationCleanupTargetV2 {
    pub(crate) fn target_digest(&self) -> &str {
        &self.target_digest
    }
}

pub(crate) fn private_oram_mutation_authority_key_v2(
    collection_id: &str,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_lifetime_id_digest: String,
) -> Result<PrivateOramMutationAuthorityKeyV2, PrivateOramMutationJournalError> {
    let mut authority_key = PrivateOramMutationAuthorityKeyV2 {
        version: AUTHORITY_KEY_VERSION,
        consensus_history_id_digest,
        raft_group_id_digest,
        collection_lifetime_id_digest,
        collection_key_digest: private_oram_collection_id_digest_v2(collection_id)?,
        key_digest: String::new(),
    };
    authority_key.key_digest = authority_key_digest_v2(&authority_key)?;
    validate_authority_key_v2(&authority_key)?;
    Ok(authority_key)
}

pub(crate) fn private_oram_mutation_collection_lifetime_id_digest_v2(
    collection_id: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let collection_key_digest = private_oram_collection_id_digest_v2(collection_id)?;
    let mut hasher = Sha256::new();
    hasher.update(COLLECTION_LIFETIME_ID_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &collection_key_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

/// Binds the authority envelope to the exact consensus collection record and lease slot image.
pub(crate) fn private_oram_mutation_outer_binding_digest_v2(
    collection_id: &str,
    consensus_state_record_digest: &str,
    lease_slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let collection_key_digest = private_oram_collection_id_digest_v2(collection_id)?;
    validate_digest(consensus_state_record_digest)?;
    let lease_slot_digest = private_oram_mutation_lease_slot_digest_v2(lease_slot)?;
    let mut hasher = Sha256::new();
    hasher.update(OUTER_BINDING_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &collection_key_digest)?;
    hash_digest(&mut hasher, consensus_state_record_digest)?;
    hash_digest(&mut hasher, &lease_slot_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_legacy_authority_v2(
    authority_key: PrivateOramMutationAuthorityKeyV2,
    exact_legacy_slot: PrivateOramMutationLeaseSlotV2,
    outer_binding_digest: String,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    validate_authority_key_v2(&authority_key)?;
    validate_lease_slot_v2(&exact_legacy_slot)?;
    validate_digest(&outer_binding_digest)?;
    let mut legacy = PrivateOramMutationLegacyAuthorityV2 {
        version: LEGACY_AUTHORITY_VERSION,
        authority_key,
        exact_legacy_slot,
        outer_binding_digest,
        authority_digest: String::new(),
    };
    legacy.authority_digest = legacy_authority_digest_v2(&legacy)?;
    validate_legacy_authority_v2(&legacy)?;
    Ok(PrivateOramMutationAuthorityStateV2::Legacy(legacy))
}

pub(crate) fn activate_private_oram_mutation_authority_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    collection_id: &str,
    context: PrivateOramMutationActivationContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_authority_state_v2(current)?;
    validate_activation_context_v2(&context)?;
    let collection_key_digest = private_oram_collection_id_digest_v2(collection_id)?;

    if let PrivateOramMutationAuthorityStateV2::Activated(aggregate) = current {
        if aggregate.activation.authority_key.collection_key_digest == collection_key_digest
            && aggregate.activation.compatibility_epoch == context.compatibility_epoch
            && aggregate.activation.activation_request_digest == context.activation_request_digest
            && aggregate.activation.activation_applied == context.locator
        {
            return Ok(current.clone());
        }
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramMutationAuthorityStateV2::Legacy(legacy) = current else {
        unreachable!();
    };
    if legacy.authority_key.collection_key_digest != collection_key_digest
        || context.locator.consensus_history_id_digest
            != legacy.authority_key.consensus_history_id_digest
        || context.locator.raft_group_id_digest != legacy.authority_key.raft_group_id_digest
        || !legacy_slot_is_activation_quiescent(&legacy.exact_legacy_slot)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let collection_incarnation_digest = collection_incarnation_digest_v2(
        &legacy.authority_key,
        &context.locator,
        &legacy.authority_digest,
    )?;
    let mut activation = PrivateOramMutationActivationAnchorV2 {
        version: ACTIVATION_ANCHOR_VERSION,
        compatibility_epoch: context.compatibility_epoch,
        authority_key: legacy.authority_key.clone(),
        collection_incarnation_digest,
        activation_applied: context.locator.clone(),
        preactivation_authority_digest: legacy.authority_digest.clone(),
        preactivation_outer_binding_digest: legacy.outer_binding_digest.clone(),
        activation_request_digest: context.activation_request_digest.clone(),
        anchor_digest: String::new(),
    };
    activation.anchor_digest = activation_anchor_digest_v2(&activation)?;
    validate_activation_anchor_v2(&activation)?;

    let lifecycle = private_oram_mutation_cleanup_lifecycle_genesis_v2(
        collection_id,
        legacy.authority_key.consensus_history_id_digest.clone(),
        legacy.authority_key.raft_group_id_digest.clone(),
    )?;
    let owner_checkpoint_table = private_oram_owner_checkpoint_table_genesis_v1(
        legacy.authority_key.consensus_history_id_digest.clone(),
        legacy.authority_key.raft_group_id_digest.clone(),
        legacy.authority_key.collection_key_digest.clone(),
        legacy.authority_key.collection_lifetime_id_digest.clone(),
        activation.collection_incarnation_digest.clone(),
        activation.anchor_digest.clone(),
        activation.activation_applied.clone(),
        activation.compatibility_epoch,
        private_oram_mutation_protocol_capability_digest_v2(),
    )?;
    let authority_core_digest = aggregate_core_digest_from_parts_v2(
        AGGREGATE_VERSION_V6,
        &activation,
        &legacy.outer_binding_digest,
        &lifecycle,
        &legacy.exact_legacy_slot,
        None,
        None,
        &[],
        &[],
        None,
        &[],
        &owner_checkpoint_table,
        None,
        &[],
        None,
        &[],
    )?;
    let last_material_transition = new_material_transition_receipt_v2(
        1,
        context.locator,
        PrivateOramMutationMaterialOperationV2::Activation,
        context.activation_request_digest,
        legacy.authority_digest.clone(),
        legacy.outer_binding_digest.clone(),
        authority_core_digest.clone(),
        legacy.outer_binding_digest.clone(),
    )?;
    let mut aggregate = PrivateOramMutationConsensusAggregateV2 {
        version: AGGREGATE_VERSION_V6,
        activation,
        outer_binding_digest: legacy.outer_binding_digest.clone(),
        lifecycle,
        lease_slot: legacy.exact_legacy_slot.clone(),
        recovery_capsules_certificate: None,
        terminal_decision_certificate: None,
        transition_ordinal: 1,
        last_material_transition,
        outstanding_gc_obligations: Vec::new(),
        compacted_owner_archive_histories: Vec::new(),
        rejected_admissions: Vec::new(),
        active_append_attempt: None,
        append_outcomes: Vec::new(),
        owner_checkpoint_table,
        pending_reservation_challenge: None,
        reservation_challenge_outcomes: Vec::new(),
        reservation_challenge_outcome_accumulator: None,
        authority_core_digest,
        aggregate_digest: String::new(),
    };
    aggregate.aggregate_digest = aggregate_digest_v2(&aggregate)?;
    validate_aggregate_v2(&aggregate)?;
    Ok(PrivateOramMutationAuthorityStateV2::Activated(Box::new(
        aggregate,
    )))
}

/// Creates collection activation authority from one applied aggregate barrier entry.
pub(crate) fn private_oram_mutation_activation_context_from_barrier_v2(
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    term: u64,
    index: u64,
    compatibility_epoch: u64,
    aggregate_activation_proof_digest: &str,
    collection_id: &str,
) -> Result<PrivateOramMutationActivationContextV2, PrivateOramMutationJournalError> {
    validate_digest(aggregate_activation_proof_digest)?;
    let collection_key_digest = private_oram_collection_id_digest_v2(collection_id)?;
    let mut hasher = Sha256::new();
    hasher.update(ACTIVATION_REQUEST_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, aggregate_activation_proof_digest)?;
    hash_digest(&mut hasher, &collection_key_digest)?;
    hasher.update(compatibility_epoch.to_be_bytes());
    hasher.update(term.to_be_bytes());
    hasher.update(index.to_be_bytes());
    let activation_request_digest = BASE64URL_NOPAD.encode(&hasher.finalize());
    let context = PrivateOramMutationActivationContextV2 {
        locator: PrivateOramRaftApplyLocatorV2 {
            version: crate::content_manager::consensus::private_oram_mutation_cleanup::APPLY_LOCATOR_VERSION,
            consensus_history_id_digest,
            raft_group_id_digest,
            term,
            index,
        },
        compatibility_epoch,
        activation_request_digest,
        _not_send_or_sync: PhantomData,
    };
    validate_activation_context_v2(&context)?;
    Ok(context)
}

pub(crate) fn apply_private_oram_mutation_authority_owner_enrollment_prepared_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    prepared: PrivateOramOwnerEnrollmentPreparedV1,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let request_digest = prepared.prepared_record_digest.clone();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared,
        &request_digest,
    )?;
    if let Some(retained_applied) = aggregate
        .owner_checkpoint_table
        .pending_enrollment_applied(&request_digest)
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            retained_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || !aggregate_allows_owner_enrollment_v2(aggregate)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let next_table = prepare_private_oram_owner_enrollment_transition_v1(
        &aggregate.owner_checkpoint_table,
        prepared,
        context.locator.clone(),
    )?;
    advance_aggregate_with_owner_checkpoint_table_v2(aggregate, next_table, context)
}

pub(crate) fn apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    commitment: PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let request_digest = commitment.commitment_digest.clone();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
        &request_digest,
    )?;
    if let Some(retained_applied) = aggregate
        .owner_checkpoint_table
        .enrollment_genesis_applied(&request_digest)
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            retained_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || !aggregate_allows_owner_enrollment_v2(aggregate)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let next_table = activate_private_oram_owner_enrollment_transition_v1(
        &aggregate.owner_checkpoint_table,
        &commitment,
        context.locator.clone(),
    )?;
    advance_aggregate_with_owner_checkpoint_table_v2(aggregate, next_table, context)
}

pub(crate) fn apply_private_oram_mutation_authority_prepare_append_reservation_challenge_v3(
    current: &PrivateOramMutationAuthorityStateV2,
    challenge_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    apply_prepare_append_reservation_challenge_with_gc_limits_v3(
        current,
        challenge_canonical_json,
        context,
        MAX_OUTSTANDING_GC_OBLIGATIONS,
        MAX_OUTSTANDING_GC_OBLIGATION_BYTES,
    )
}

fn apply_prepare_append_reservation_challenge_with_gc_limits_v3(
    current: &PrivateOramMutationAuthorityStateV2,
    challenge_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
    maximum_gc_count: usize,
    maximum_gc_bytes: usize,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let challenge =
        decode_private_oram_mutation_prepared_reservation_challenge_v3(&challenge_canonical_json)?;
    let request_digest = challenge.prepared_challenge_digest();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
        request_digest,
    )?;
    if let Some(pending) = aggregate
        .pending_reservation_challenge
        .as_ref()
        .filter(|pending| {
            pending.challenge_digest == request_digest
                && pending.challenge_canonical_json == challenge_canonical_json
        })
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &pending.challenge_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let base_reservation = challenge.base_reservation();
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || base_reservation.expected_aggregate_digest() != aggregate.aggregate_digest
        || base_reservation.attempt_sequence()
            != aggregate
                .transition_ordinal
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?
        || base_reservation.consensus_history_id_digest()
            != aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
        || base_reservation.raft_group_id_digest()
            != aggregate.activation.authority_key.raft_group_id_digest
        || base_reservation.collection_lifetime_id_digest()
            != aggregate
                .activation
                .authority_key
                .collection_lifetime_id_digest
        || base_reservation.collection_incarnation_digest()
            != aggregate.activation.collection_incarnation_digest
        || base_reservation.activation_anchor_digest() != aggregate.activation.anchor_digest
        || private_oram_collection_id_digest_v2(base_reservation.collection_id())?
            != aggregate.activation.authority_key.collection_key_digest
        || aggregate.pending_reservation_challenge.is_some()
        || aggregate.active_append_attempt.is_some()
        || aggregate.lifecycle.active.is_some()
        || aggregate.lease_slot.active.is_some()
        || aggregate.owner_checkpoint_table.has_active_leases()
        || !terminal_material_is_transferable_to_next_admission_v2(aggregate)
        || aggregate.reservation_challenge_outcomes.len() >= MAX_RESERVATION_CHALLENGE_OUTCOMES
        || reservation_challenge_outcomes_serialized_len_v1(
            &aggregate.reservation_challenge_outcomes,
        )? >= MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_private_oram_owner_checkpoint_reservation_context_for_table_v1(
        challenge.checkpoint_context(),
        &aggregate.owner_checkpoint_table,
    )?;
    let outstanding_gc_obligations = if context.retain_compacted_owner_archive_history {
        project_gc_retention_for_reservation_v3(
            aggregate,
            &challenge_canonical_json,
            base_reservation,
            maximum_gc_count,
            maximum_gc_bytes,
        )?
    } else {
        // The applied floor selects this branch, preserving wire-8 replay and its digests.
        validate_prepared_reservation_challenge_capacity_v3(
            aggregate,
            &challenge_canonical_json,
            base_reservation,
            maximum_gc_bytes,
        )?;
        aggregate.outstanding_gc_obligations.clone()
    };
    let pending = pending_reservation_challenge_v1(
        challenge,
        challenge_canonical_json,
        aggregate.aggregate_digest.clone(),
        context.locator.clone(),
    )?;
    validate_reservation_challenge_outcome_reserve_v1(
        &aggregate.reservation_challenge_outcomes,
        &pending,
    )?;
    advance_aggregate_with_challenge_state_v2(
        aggregate,
        AGGREGATE_VERSION_V7,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        outstanding_gc_obligations,
        aggregate.rejected_admissions.clone(),
        None,
        aggregate.append_outcomes.clone(),
        aggregate.owner_checkpoint_table.clone(),
        Some(pending),
        aggregate.reservation_challenge_outcomes.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_create_append_reservation_v3(
    current: &PrivateOramMutationAuthorityStateV2,
    reservation_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let reservation =
        decode_private_oram_mutation_append_reservation_v3(&reservation_canonical_json)?;
    let base_reservation = reservation.base_reservation();
    let request_digest = reservation.reservation_digest_v3();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3,
        request_digest,
    )?;
    if let Some(active) = aggregate.active_append_attempt.as_ref().filter(|active| {
        active.reservation_request_digest == request_digest
            && active.reservation_canonical_json == reservation_canonical_json
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &active.reservation_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let pending = aggregate
        .pending_reservation_challenge
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let prepared_challenge_canonical_json =
        encode_private_oram_mutation_prepared_reservation_challenge_v3(
            reservation.prepared_challenge(),
        )?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || reservation.expected_aggregate_digest() != pending.pre_challenge_aggregate_digest
        || pending.challenge_canonical_json != prepared_challenge_canonical_json
        || pending.challenge_digest != reservation.prepared_challenge().prepared_challenge_digest()
        || &pending.challenge_applied != reservation.challenge_applied()
        || pending.reservation_intent_digest != reservation.reservation_intent().intent_digest()
        || pending.attempt_id != reservation.attempt_id()
        || pending.attempt_sequence != reservation.attempt_sequence()
        || pending.prepared_ordinal != reservation.attempt_sequence()
        || reservation.consensus_history_id_digest()
            != aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
        || reservation.raft_group_id_digest()
            != aggregate.activation.authority_key.raft_group_id_digest
        || reservation.collection_lifetime_id_digest()
            != aggregate
                .activation
                .authority_key
                .collection_lifetime_id_digest
        || reservation.collection_incarnation_digest()
            != aggregate.activation.collection_incarnation_digest
        || reservation.activation_anchor_digest() != aggregate.activation.anchor_digest
        || aggregate.transition_ordinal != pending.prepared_ordinal
        || reservation.controller_term() > context.locator.term
        || private_oram_collection_id_digest_v2(reservation.collection_id())?
            != aggregate.activation.authority_key.collection_key_digest
        || aggregate.active_append_attempt.is_some()
        || aggregate.lifecycle.active.is_some()
        || aggregate.lease_slot.active.is_some()
        || !terminal_material_is_transferable_to_next_admission_v2(aggregate)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_private_oram_owner_checkpoint_reservation_context_for_table_v1(
        reservation.checkpoint_context(),
        &aggregate.owner_checkpoint_table,
    )?;
    let next_checkpoint_table = lease_private_oram_owner_checkpoints_for_reservation_v1(
        &aggregate.owner_checkpoint_table,
        base_reservation.attempt_id(),
        reservation.checkpoint_context().context_digest(),
        reservation.reservation_digest_v3(),
        reservation.checkpoint_bindings(),
        context.locator.clone(),
    )?;
    validate_append_reservation_capacity_v2(
        aggregate,
        &reservation_canonical_json,
        base_reservation,
    )?;
    let checkpoint_lease_transition = private_oram_owner_checkpoint_lease_transition_v1(
        &aggregate.owner_checkpoint_table,
        &next_checkpoint_table,
        reservation.checkpoint_context().context_digest(),
        reservation.reservation_digest_v3(),
    )?;
    let mut active = PrivateOramMutationActiveAppendAttemptV2 {
        version: ACTIVE_APPEND_ATTEMPT_VERSION_V3,
        reservation_canonical_json: reservation_canonical_json.clone(),
        reservation_request_digest: request_digest.to_string(),
        reservation_applied: context.locator.clone(),
        checkpoint_lease_transition: Some(checkpoint_lease_transition),
        prepared: None,
        attempt_digest: String::new(),
    };
    active.attempt_digest = active_append_attempt_digest_v2(&active)?;
    validate_active_append_attempt_v2(&active, &aggregate.activation)?;
    let mut challenge_outcomes = aggregate.reservation_challenge_outcomes.clone();
    challenge_outcomes.push(reservation_challenge_outcome_v1(
        pending,
        PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3,
        request_digest.to_string(),
        context.locator.clone(),
        Some(request_digest.to_string()),
        Some(reservation_canonical_json),
    )?);
    validate_reservation_challenge_outcome_history_capacity_v1(&challenge_outcomes)?;
    advance_aggregate_with_challenge_state_v2(
        aggregate,
        AGGREGATE_VERSION_V7,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        aggregate.rejected_admissions.clone(),
        Some(active),
        aggregate.append_outcomes.clone(),
        next_checkpoint_table,
        None,
        challenge_outcomes,
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_create_append_reservation_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    reservation_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let reservation = crate::content_manager::private_oram_mutation_journal::decode_private_oram_mutation_append_reservation_v2(
        &reservation_canonical_json,
    )?;
    let request_digest = reservation.reservation_digest();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AppendReservation,
        request_digest,
    )?;
    if let Some(active) = aggregate.active_append_attempt.as_ref().filter(|active| {
        active.reservation_request_digest == request_digest
            && active.reservation_canonical_json == reservation_canonical_json
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &active.reservation_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || reservation.expected_aggregate_digest() != context.expected_aggregate_digest
        || reservation.consensus_history_id_digest()
            != aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
        || reservation.raft_group_id_digest()
            != aggregate.activation.authority_key.raft_group_id_digest
        || reservation.collection_lifetime_id_digest()
            != aggregate
                .activation
                .authority_key
                .collection_lifetime_id_digest
        || reservation.collection_incarnation_digest()
            != aggregate.activation.collection_incarnation_digest
        || reservation.activation_anchor_digest() != aggregate.activation.anchor_digest
        || reservation.attempt_sequence()
            != aggregate
                .transition_ordinal
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?
        || reservation.controller_term() > context.locator.term
        || private_oram_collection_id_digest_v2(reservation.collection_id())?
            != aggregate.activation.authority_key.collection_key_digest
        || aggregate.pending_reservation_challenge.is_some()
        || aggregate.active_append_attempt.is_some()
        || aggregate.lifecycle.active.is_some()
        || aggregate.lease_slot.active.is_some()
        || aggregate.owner_checkpoint_table.has_active_leases()
        || !terminal_material_is_transferable_to_next_admission_v2(aggregate)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_append_reservation_capacity_v2(aggregate, &reservation_canonical_json, &reservation)?;
    let mut active = PrivateOramMutationActiveAppendAttemptV2 {
        version: ACTIVE_APPEND_ATTEMPT_VERSION,
        reservation_canonical_json,
        reservation_request_digest: request_digest.to_string(),
        reservation_applied: context.locator.clone(),
        checkpoint_lease_transition: None,
        prepared: None,
        attempt_digest: String::new(),
    };
    active.attempt_digest = active_append_attempt_digest_v2(&active)?;
    validate_active_append_attempt_v2(&active, &aggregate.activation)?;
    advance_aggregate_with_rejected_admissions_v2(
        aggregate,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        aggregate.rejected_admissions.clone(),
        Some(active),
        aggregate.append_outcomes.clone(),
        aggregate.owner_checkpoint_table.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_cancel_append_reservation_challenge_v3(
    current: &PrivateOramMutationAuthorityStateV2,
    cancellation_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let cancellation = decode_private_oram_mutation_reservation_challenge_cancellation_v1(
        &cancellation_canonical_json,
    )?;
    let request_digest = cancellation.cancellation_digest.as_str();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled,
        request_digest,
    )?;
    if let Some(outcome) = aggregate
        .reservation_challenge_outcomes
        .iter()
        .find(|outcome| {
            outcome.kind == PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled
                && outcome.challenge_digest == cancellation.challenge_digest
                && outcome.resolution_request_digest == request_digest
        })
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &outcome.resolution_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let pending = aggregate
        .pending_reservation_challenge
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || cancellation.challenge_digest != pending.challenge_digest
        || cancellation.reservation_intent_digest != pending.reservation_intent_digest
        || cancellation.attempt_id != pending.attempt_id
        || cancellation.attempt_sequence != pending.attempt_sequence
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut outcomes = aggregate.reservation_challenge_outcomes.clone();
    outcomes.push(reservation_challenge_outcome_v1(
        pending,
        PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled,
        request_digest.to_string(),
        context.locator.clone(),
        None,
        None,
    )?);
    validate_reservation_challenge_outcome_history_capacity_v1(&outcomes)?;
    advance_aggregate_with_challenge_state_v2(
        aggregate,
        AGGREGATE_VERSION_V7,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        aggregate.rejected_admissions.clone(),
        aggregate.active_append_attempt.clone(),
        aggregate.append_outcomes.clone(),
        aggregate.owner_checkpoint_table.clone(),
        None,
        outcomes,
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
    current: &PrivateOramMutationAuthorityStateV2,
    acknowledgement_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let acknowledgement = decode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
        &acknowledgement_canonical_json,
    )?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
        acknowledgement.acknowledgement_digest(),
    )?;
    if aggregate
        .reservation_challenge_outcome_accumulator
        .as_ref()
        .is_some_and(|accumulator| {
            accumulator.last_outcome_digest == acknowledgement.outcome_digest
                && accumulator.last_acknowledgement_digest == acknowledgement.acknowledgement_digest
        })
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &aggregate
                .reservation_challenge_outcome_accumulator
                .as_ref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?
                .last_acknowledgement_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let outcome = aggregate
        .reservation_challenge_outcomes
        .first()
        .filter(|outcome| outcome.outcome_digest == acknowledgement.outcome_digest)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if outcome.version != RESERVATION_CHALLENGE_OUTCOME_VERSION_V3 {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || aggregate.version != AGGREGATE_VERSION_V7
        || aggregate.pending_reservation_challenge.is_some()
        || aggregate.active_append_attempt.is_some()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_reservation_outcome_owner_resolution_receipts_v1(
        outcome,
        aggregate,
        &acknowledgement,
    )?;
    let next_owner_checkpoint_table = settle_owner_checkpoint_reservation_completion_v1(
        outcome,
        aggregate,
        &acknowledgement,
        context.locator.clone(),
    )?;
    let accumulator = reservation_challenge_outcome_accumulator_v1(
        aggregate.reservation_challenge_outcome_accumulator.as_ref(),
        outcome,
        &acknowledgement,
        context.locator.clone(),
    )?;
    let outcomes = aggregate.reservation_challenge_outcomes[1..].to_vec();
    advance_aggregate_with_challenge_history_v2(
        aggregate,
        AGGREGATE_VERSION_V7,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        aggregate.rejected_admissions.clone(),
        None,
        aggregate.append_outcomes.clone(),
        next_owner_checkpoint_table,
        None,
        outcomes,
        Some(accumulator),
        context,
    )
}

/// Recovery manifest of the admission that produced `append_outcome`.
///
/// The reservation-outcome acknowledgement may legitimately arrive after the generation was
/// already cleared (the owner-driven lifecycle does not wait for the controller's ack), so the
/// manifest is also looked up in the retained tombstone witness instead of only in the active
/// admission. Without that fallback the ack could never apply and owner checkpoint leases stayed
/// held forever.
fn admission_recovery_manifest_for_outcome_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    append_outcome: &PrivateOramMutationAppendOutcomeV2,
) -> Result<PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationJournalError> {
    let request_digest = append_outcome
        .admission_request_digest
        .as_deref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let admitted = aggregate
        .lifecycle
        .active
        .as_ref()
        .map(active_admitted)
        .filter(|admitted| admitted.admission_request_digest == request_digest)
        .or_else(|| {
            aggregate
                .lifecycle
                .last_cleared
                .as_ref()
                .map(|cleared| &cleared.cleanup_witness.admitted)
                .filter(|admitted| admitted.admission_request_digest == request_digest)
        })
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    decode_private_oram_mutation_admission_recovery_manifest_v2(
        &admitted.recovery_manifest_canonical_json,
    )
}

fn expected_owner_reservation_completions_v1(
    outcome: &PrivateOramMutationReservationChallengeOutcomeV1,
    aggregate: &PrivateOramMutationConsensusAggregateV2,
) -> Result<Vec<ExpectedOwnerReservationCompletionV1>, PrivateOramMutationJournalError> {
    if outcome.version != RESERVATION_CHALLENGE_OUTCOME_VERSION_V3 {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
        outcome
            .challenge_canonical_json
            .as_deref()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
    )?;
    let targets = challenge.base_reservation().owner_targets();
    let expectations = challenge.checkpoint_context().owner_expectations();
    if expectations.len() != targets.len() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let finalized_reservation = match outcome.kind {
        PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3 => {
            Some(decode_private_oram_mutation_append_reservation_v3(
                outcome
                    .finalized_reservation_canonical_json
                    .as_deref()
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
            )?)
        }
        PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled => None,
    };
    if finalized_reservation
        .as_ref()
        .is_some_and(|reservation| reservation.checkpoint_bindings().len() != targets.len())
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let recovery_manifest =
        if outcome.kind == PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3 {
            let mut matching_outcomes = aggregate
                .append_outcomes
                .iter()
                .filter(|candidate| candidate.attempt_id == outcome.attempt_id);
            let append_outcome = matching_outcomes
                .next()
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
            if matching_outcomes.next().is_some() {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
            match append_outcome.kind {
                PrivateOramMutationAppendOutcomeKindV2::Admitted => Some(
                    admission_recovery_manifest_for_outcome_v2(aggregate, append_outcome)?,
                ),
                PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected => {
                    let mut matching_rejections = aggregate
                        .rejected_admissions
                        .iter()
                        .filter(|candidate| candidate.attempt_id == outcome.attempt_id);
                    let rejected = matching_rejections
                        .next()
                        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
                    if matching_rejections.next().is_some() {
                        return Err(PrivateOramMutationJournalError::Corrupt);
                    }
                    Some(decode_private_oram_mutation_admission_recovery_manifest_v2(
                        rejected
                            .recovery_manifest_canonical_json
                            .as_deref()
                            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
                    )?)
                }
                PrivateOramMutationAppendOutcomeKindV2::PrestageAborted => None,
            }
        } else {
            None
        };
    targets
        .iter()
        .zip(expectations)
        .enumerate()
        .map(|(owner_index, (target, expectation))| {
            let expected_signer =
                private_oram_owner_cleanup_signer_from_peer_key_v1(target.owner_signer())
                    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
            if expectation.owner_peer_id() != target.owner_peer_id()
                || expectation.owner_signer() != &expected_signer
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let durable_fence_record_digest = finalized_reservation
                .as_ref()
                .map(|reservation| {
                    reservation
                        .checkpoint_bindings()
                        .get(owner_index)
                        .ok_or(PrivateOramMutationJournalError::InvalidTransition)
                })
                .transpose()?
                .map(|binding| {
                    if binding.owner_index() as usize != owner_index
                        || binding.expected_checkpoint_record_digest()
                            != expectation.expected_checkpoint_record_digest()
                        || binding.reservation_prepare().owner_signer != expected_signer
                    {
                        return Err(PrivateOramMutationJournalError::InvalidTransition);
                    }
                    Ok(binding
                        .reservation_prepare()
                        .durable_fence_record_digest
                        .clone())
                })
                .transpose()?;
            let installed_prestage_receipt_digest = recovery_manifest
                .as_ref()
                .map(|manifest| {
                    manifest
                        .owner_evidence()
                        .iter()
                        .find(|evidence| evidence.owner_peer_id() == target.owner_peer_id())
                        .map(|evidence| evidence.receipt().receipt_digest().to_string())
                        .ok_or(PrivateOramMutationJournalError::InvalidTransition)
                })
                .transpose()?;
            Ok(ExpectedOwnerReservationCompletionV1 {
                collection_id: challenge.base_reservation().collection_id().to_string(),
                owner_peer_id: target.owner_peer_id(),
                owner_enrollment_id: expectation.owner_enrollment_id().to_string(),
                owner_signer: expected_signer,
                committed_challenge_digest: outcome.challenge_digest.clone(),
                reservation_intent_digest: outcome.reservation_intent_digest.clone(),
                attempt_id: outcome.attempt_id.clone(),
                challenge_applied: outcome.challenge_applied.clone(),
                resolution_applied: outcome.resolution_applied.clone(),
                reserved_terminal_intent_key: target.intent_key().to_string(),
                finalized_reservation_digest: outcome.finalized_reservation_digest.clone(),
                owner_store_incarnation_digest: expectation
                    .owner_store_incarnation_digest()
                    .to_string(),
                owner_store_binding_digest: expectation
                    .expected_checkpoint_record_digest()
                    .to_string(),
                durable_fence_record_digest,
                installed_prestage_receipt_digest,
                installed_package_sha256: target.package_sha256().to_string(),
            })
        })
        .collect()
}

fn validate_reservation_outcome_owner_resolution_receipts_v1(
    outcome: &PrivateOramMutationReservationChallengeOutcomeV1,
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    acknowledgement: &PrivateOramMutationReservationOutcomeAcknowledgementV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let expected = expected_owner_reservation_completions_v1(outcome, aggregate)?;
    if expected.len()
        != acknowledgement
            .owner_resolution_receipts_canonical_json
            .len()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (expected, encoded) in expected
        .iter()
        .zip(&acknowledgement.owner_resolution_receipts_canonical_json)
    {
        let signed =
            decode_signed_private_oram_owner_reservation_resolution_receipt_v1(encoded.as_bytes())
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
        let receipt = &signed.receipt;
        let _verified =
            validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1(
                &signed,
            )
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
        let disposition_valid = match outcome.kind {
            PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled => {
                receipt.disposition
                    == PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased
            }
            PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3 => {
                match receipt.disposition {
                    PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled => {
                        receipt.installed_prestage_receipt_digest.is_some()
                            && receipt.installed_package_sha256.as_deref()
                                == Some(expected.installed_package_sha256.as_str())
                            && expected
                                .installed_prestage_receipt_digest
                                .as_ref()
                                .is_none_or(|digest| {
                                    receipt.installed_prestage_receipt_digest.as_deref()
                                        == Some(digest.as_str())
                                })
                    }
                    PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort => {
                        receipt.abort_release_marker_digest.is_some()
                            && receipt.abort_release_authority_digest.as_deref().is_some_and(
                                |authority_digest| {
                                aggregate.append_outcomes.iter().any(|append_outcome| {
                                    append_outcome.kind
                                        == PrivateOramMutationAppendOutcomeKindV2::PrestageAborted
                                        && append_outcome.attempt_id == outcome.attempt_id
                                        && append_outcome.outcome_digest == authority_digest
                                })
                                },
                            )
                    }
                    PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased => false,
                }
            }
        };
        if !disposition_valid
            || signed.owner_signer != expected.owner_signer
            || receipt.owner_store_incarnation_digest != expected.owner_store_incarnation_digest
            || receipt.owner_store_binding_digest != expected.owner_store_binding_digest
            || expected
                .durable_fence_record_digest
                .as_ref()
                .is_some_and(|digest| receipt.durable_fence_record_digest != *digest)
            || receipt.collection_id != expected.collection_id
            || receipt.owner_peer_id != expected.owner_peer_id
            || receipt.committed_challenge_digest != expected.committed_challenge_digest
            || receipt.reservation_intent_digest != expected.reservation_intent_digest
            || receipt.attempt_id != expected.attempt_id
            || receipt.challenge_applied_term != expected.challenge_applied.term
            || receipt.challenge_applied_index != expected.challenge_applied.index
            || receipt.resolution_applied_term != expected.resolution_applied.term
            || receipt.resolution_applied_index != expected.resolution_applied.index
            || receipt.reserved_terminal_intent_key != expected.reserved_terminal_intent_key
            || receipt.finalized_reservation_digest != expected.finalized_reservation_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

fn settle_owner_checkpoint_reservation_completion_v1(
    outcome: &PrivateOramMutationReservationChallengeOutcomeV1,
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    acknowledgement: &PrivateOramMutationReservationOutcomeAcknowledgementV1,
    acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    if outcome.kind == PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled {
        // Cancellation never acquired a checkpoint lease. Leases for a later finalized outcome
        // are unrelated and must survive removal of this FIFO head.
        return Ok(aggregate.owner_checkpoint_table.clone());
    }
    let expected = expected_owner_reservation_completions_v1(outcome, aggregate)?;
    if expected.len()
        != acknowledgement
            .owner_resolution_receipts_canonical_json
            .len()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let settlements = expected
        .iter()
        .zip(&acknowledgement.owner_resolution_receipts_canonical_json)
        .enumerate()
        .map(|(owner_index, (expected, encoded))| {
            let signed = decode_signed_private_oram_owner_reservation_resolution_receipt_v1(
                encoded.as_bytes(),
            )
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
            Ok(
                PrivateOramOwnerNegativeSettlementV1::ReservationCompletionCommitted {
                    owner_index: u32::try_from(owner_index)
                        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
                    owner_enrollment_id: expected.owner_enrollment_id.clone(),
                    completion_receipt_digest: signed.receipt_digest,
                },
            )
        })
        .collect::<Result<Vec<_>, PrivateOramMutationJournalError>>()?;
    acknowledge_private_oram_owner_negative_settlement_v1(
        &aggregate.owner_checkpoint_table,
        &outcome.attempt_id,
        outcome
            .finalized_reservation_digest
            .as_deref()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
        &acknowledgement.acknowledgement_digest,
        &settlements,
        acknowledgement_applied,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_append_prepared_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    recovery_manifest_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let active = aggregate
        .active_append_attempt
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let reservation =
        decode_private_oram_mutation_append_reservation_wire(&active.reservation_canonical_json)?;
    let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &recovery_manifest_canonical_json,
    )?;
    reservation.validate_manifest(&manifest)?;
    let request_digest = reservation.append_prepared_request_digest(&manifest)?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AppendPrepared,
        &request_digest,
    )?;
    if let Some(prepared) = active.prepared.as_ref().filter(|prepared| {
        prepared.prepare_request_digest == request_digest
            && prepared.recovery_manifest_canonical_json == recovery_manifest_canonical_json
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &prepared.prepared_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || active.prepared.is_some()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let admission_request_digest = private_oram_mutation_admission_request_digest_v2(
        reservation.base_reservation().preparing_lease(),
        manifest.manifest_digest(),
    )?;
    let mut prepared = PrivateOramMutationPreparedAppendV2 {
        version: PREPARED_APPEND_VERSION,
        recovery_manifest_canonical_json,
        prepare_request_digest: request_digest,
        admission_request_digest,
        prepared_applied: context.locator.clone(),
        prepared_digest: String::new(),
    };
    prepared.prepared_digest = prepared_append_digest_v2(&prepared)?;
    let mut next_active = active.clone();
    next_active.prepared = Some(prepared);
    next_active.attempt_digest = active_append_attempt_digest_v2(&next_active)?;
    validate_active_append_attempt_v2(&next_active, &aggregate.activation)?;
    advance_aggregate_with_rejected_admissions_v2(
        aggregate,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        aggregate.rejected_admissions.clone(),
        Some(next_active),
        aggregate.append_outcomes.clone(),
        aggregate.owner_checkpoint_table.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_reserved_attempt_rejected_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    reservation_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let reservation =
        decode_private_oram_mutation_append_reservation_wire(&reservation_canonical_json)?;
    let request_digest = reservation.reserved_rejection_request_digest()?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected,
        &request_digest,
    )?;
    if let Some(outcome) = aggregate.append_outcomes.iter().find(|outcome| {
        outcome.kind == PrivateOramMutationAppendOutcomeKindV2::PrestageAborted
            && outcome.attempt_id == reservation.base_reservation().attempt_id()
            && outcome.resolution_request_digest == request_digest
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &outcome.resolution_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let reservation_matches_active =
        aggregate
            .active_append_attempt
            .as_ref()
            .is_some_and(|active| {
                active.prepared.is_none()
                    && active.reservation_canonical_json == reservation_canonical_json
                    && active.reservation_request_digest == reservation.reservation_digest()
            });
    if !reservation_matches_active
        || context.next_outer_binding_digest != aggregate.outer_binding_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let outcome = new_append_outcome_v2(
        aggregate,
        &reservation,
        PrivateOramMutationAppendOutcomeKindV2::PrestageAborted,
        context.expected_aggregate_digest.clone(),
        request_digest.clone(),
        None,
        None,
        context.locator.clone(),
    )?;
    let mut rejected = new_rejected_append_v2(
        &reservation,
        None,
        request_digest,
        None,
        outcome.outcome_key.clone(),
        context.expected_aggregate_digest.clone(),
        context.locator.clone(),
    )?;
    rejected.rejection_digest = rejected_admission_digest_v2(&rejected)?;
    validate_rejected_admission_v2(&rejected, &aggregate.activation)?;
    let mut rejected_admissions = aggregate.rejected_admissions.clone();
    rejected_admissions.push(rejected);
    let mut append_outcomes = aggregate.append_outcomes.clone();
    append_outcomes.push(outcome);
    prune_append_history_to_capacity_v2(&mut rejected_admissions, &mut append_outcomes)?;
    advance_aggregate_with_rejected_admissions_v2(
        aggregate,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        rejected_admissions,
        None,
        append_outcomes,
        aggregate.owner_checkpoint_table.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_admission_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    lease: PrivateOramMutationLease,
    recovery_manifest_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &recovery_manifest_canonical_json,
    )?;
    recovery_manifest.validate_admission_lease(&lease)?;
    let request_digest = private_oram_mutation_admission_request_digest_v2(
        &lease,
        recovery_manifest.manifest_digest(),
    )?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::Admission,
        &request_digest,
    )?;

    if let Some(admitted) = aggregate
        .lifecycle
        .active
        .as_ref()
        .map(active_admitted)
        .filter(|admitted| {
            admitted.generation == lease.generation
                && admitted.admission_request_digest == request_digest
        })
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &admitted.admission_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    let lease_state_digest = private_oram_mutation_lease_state_digest_v2(&lease)?;
    if let Some(outcome) = aggregate.append_outcomes.iter().find(|outcome| {
        outcome.kind == PrivateOramMutationAppendOutcomeKindV2::Admitted
            && outcome.preparing_lease_state_digest == lease_state_digest
            && outcome.admission_request_digest.as_deref() == Some(request_digest.as_str())
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &outcome.resolution_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let active = aggregate
        .active_append_attempt
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let prepared = active
        .prepared
        .as_ref()
        .filter(|prepared| {
            prepared.recovery_manifest_canonical_json == recovery_manifest_canonical_json
                && prepared.admission_request_digest == request_digest
        })
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let reservation =
        decode_private_oram_mutation_append_reservation_wire(&active.reservation_canonical_json)?;
    reservation.validate_manifest(&recovery_manifest)?;
    if reservation.base_reservation().preparing_lease() != &lease
        || !locator_is_strictly_after(&context.locator, &prepared.prepared_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if context.next_outer_binding_digest == aggregate.outer_binding_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let applied_entry = cleanup_applied_entry_v2(
        aggregate,
        &context,
        PrivateOramMutationCleanupOperationKindV2::Admission,
        &request_digest,
    )?;
    let applied = apply_private_oram_mutation_admission_v2(
        &aggregate.lifecycle,
        &aggregate.lease_slot,
        lease,
        recovery_manifest_canonical_json,
        applied_entry,
    )?;
    let mut obligations = aggregate.outstanding_gc_obligations.clone();
    retain_acknowledged_gc_obligation_v2(aggregate, &mut obligations)?;
    let outcome = new_append_outcome_v2(
        aggregate,
        &reservation,
        PrivateOramMutationAppendOutcomeKindV2::Admitted,
        context.expected_aggregate_digest.clone(),
        request_digest.clone(),
        Some(request_digest),
        Some(recovery_manifest.manifest_digest().to_string()),
        context.locator.clone(),
    )?;
    let mut rejected_admissions = aggregate.rejected_admissions.clone();
    let mut append_outcomes = aggregate.append_outcomes.clone();
    append_outcomes.push(outcome);
    prune_append_history_to_capacity_v2(&mut rejected_admissions, &mut append_outcomes)?;
    advance_aggregate_with_rejected_admissions_v2(
        aggregate,
        applied.lifecycle,
        applied.lease_slot,
        None,
        None,
        obligations,
        rejected_admissions,
        None,
        append_outcomes,
        aggregate.owner_checkpoint_table.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_admission_rejected_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    lease: PrivateOramMutationLease,
    recovery_manifest_canonical_json: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &recovery_manifest_canonical_json,
    )?;
    recovery_manifest.validate_admission_lease(&lease)?;
    let request_digest = private_oram_mutation_admission_request_digest_v2(
        &lease,
        recovery_manifest.manifest_digest(),
    )?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::AdmissionRejected,
        &request_digest,
    )?;

    if let Some(rejected) = aggregate.rejected_admissions.iter().find(|rejected| {
        rejected.lease == lease
            && rejected.admission_request_digest.as_deref() == Some(request_digest.as_str())
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &rejected.rejection_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    let lease_state_digest = private_oram_mutation_lease_state_digest_v2(&lease)?;
    if let Some(outcome) = aggregate.append_outcomes.iter().find(|outcome| {
        outcome.kind == PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected
            && outcome.preparing_lease_state_digest == lease_state_digest
            && outcome.admission_request_digest.as_deref() == Some(request_digest.as_str())
    }) {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &outcome.resolution_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }

    validate_new_material_context_v2(aggregate, &context)?;
    if context.next_outer_binding_digest != aggregate.outer_binding_digest
        || aggregate.lifecycle.active.is_some()
        || aggregate.lease_slot.active.is_some()
        || !terminal_material_is_transferable_to_next_admission_v2(aggregate)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let active = aggregate
        .active_append_attempt
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let prepared = active
        .prepared
        .as_ref()
        .filter(|prepared| {
            prepared.recovery_manifest_canonical_json == recovery_manifest_canonical_json
                && prepared.admission_request_digest == request_digest
        })
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let reservation =
        decode_private_oram_mutation_append_reservation_wire(&active.reservation_canonical_json)?;
    reservation.validate_manifest(&recovery_manifest)?;
    if reservation.base_reservation().preparing_lease() != &lease
        || !locator_is_strictly_after(&context.locator, &prepared.prepared_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let outcome = new_append_outcome_v2(
        aggregate,
        &reservation,
        PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected,
        context.expected_aggregate_digest.clone(),
        request_digest.clone(),
        Some(request_digest.clone()),
        Some(recovery_manifest.manifest_digest().to_string()),
        context.locator.clone(),
    )?;
    let mut rejected = new_rejected_append_v2(
        &reservation,
        Some(recovery_manifest_canonical_json),
        request_digest.clone(),
        Some(request_digest),
        outcome.outcome_key.clone(),
        context.expected_aggregate_digest.clone(),
        context.locator.clone(),
    )?;
    rejected.rejection_digest = rejected_admission_digest_v2(&rejected)?;
    validate_rejected_admission_v2(&rejected, &aggregate.activation)?;

    let mut rejected_admissions = aggregate.rejected_admissions.clone();
    rejected_admissions.push(rejected);
    let mut append_outcomes = aggregate.append_outcomes.clone();
    append_outcomes.push(outcome);
    prune_append_history_to_capacity_v2(&mut rejected_admissions, &mut append_outcomes)?;
    advance_aggregate_with_rejected_admissions_v2(
        aggregate,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        rejected_admissions,
        None,
        append_outcomes,
        aggregate.owner_checkpoint_table.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_lease_transition_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    new_lease: PrivateOramMutationLease,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let request_digest = private_oram_mutation_lease_state_digest_v2(&new_lease)?;
    validate_apply_context_v2(aggregate, &context, context.operation_kind, &request_digest)?;
    if !matches!(
        context.operation_kind,
        PrivateOramMutationMaterialOperationV2::Renewal
            | PrivateOramMutationMaterialOperationV2::AbortDecision
            | PrivateOramMutationMaterialOperationV2::ConsensusCommit
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if aggregate.lease_slot.active.as_ref() == Some(&new_lease) {
        let original = match context.operation_kind {
            PrivateOramMutationMaterialOperationV2::Renewal
                if aggregate.last_material_transition.operation_kind
                    == PrivateOramMutationMaterialOperationV2::Renewal
                    && aggregate.last_material_transition.request_digest == request_digest =>
            {
                &aggregate.last_material_transition.locator
            }
            PrivateOramMutationMaterialOperationV2::AbortDecision
            | PrivateOramMutationMaterialOperationV2::ConsensusCommit => {
                let certificate =
                    terminal_certificate_for_generation_v2(aggregate, new_lease.generation)
                        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
                validate_terminal_retry_certificate_v2(
                    certificate,
                    &new_lease,
                    &context,
                    &request_digest,
                )?;
                &certificate.locator
            }
            _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
        };
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            original,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    if retained_terminal_lease_v2(&aggregate.lifecycle) == Some(&new_lease) {
        let certificate = terminal_certificate_for_generation_v2(aggregate, new_lease.generation)
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        validate_terminal_retry_certificate_v2(certificate, &new_lease, &context, &request_digest)?;
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &certificate.locator,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    if context.next_outer_binding_digest == aggregate.outer_binding_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_new_material_context_v2(aggregate, &context)?;
    if !matches!(
        aggregate.lifecycle.active,
        Some(
            PrivateOramMutationCleanupActiveV2::Admitted(_)
                | PrivateOramMutationCleanupActiveV2::ParentProgress(_)
        )
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let current_lease = aggregate
        .lease_slot
        .active
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    validate_lease_transition_v2(current_lease, &new_lease, context.operation_kind)?;
    let terminal_decision_certificate = match context.operation_kind {
        PrivateOramMutationMaterialOperationV2::AbortDecision
        | PrivateOramMutationMaterialOperationV2::ConsensusCommit => {
            let recovery = aggregate
                .recovery_capsules_certificate
                .as_ref()
                .filter(|certificate| certificate.generation == new_lease.generation)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
            Some(new_terminal_decision_certificate_v2(
                new_lease.generation,
                context.operation_kind,
                context.locator.clone(),
                request_digest.clone(),
                recovery.certificate_digest.clone(),
                context.next_outer_binding_digest.clone(),
            )?)
        }
        PrivateOramMutationMaterialOperationV2::Renewal => {
            aggregate.terminal_decision_certificate.clone()
        }
        _ => unreachable!(),
    };
    let mut lease_slot = aggregate.lease_slot.clone();
    lease_slot.active = Some(new_lease);
    validate_private_oram_mutation_cleanup_pair_v2(&aggregate.lifecycle, &lease_slot)?;
    advance_aggregate_v2(
        aggregate,
        aggregate.lifecycle.clone(),
        lease_slot,
        aggregate.recovery_capsules_certificate.clone(),
        terminal_decision_certificate,
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_parent_progress_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let request_digest = expected.watermark().watermark_digest();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::ParentProgress,
        request_digest,
    )?;
    if let Some((retained, applied_history)) = retained_parent_progress_v2(&aggregate.lifecycle)
        && private_oram_mutation_parent_watermark_is_canonical_prefix_v2(
            expected.watermark(),
            retained,
        )?
    {
        let applied_index = usize::try_from(
            expected
                .watermark()
                .sequence()
                .checked_sub(1)
                .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        let original = applied_history
            .get(applied_index)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        validate_retained_retry_locator_v2(
            &context.locator,
            original,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let applied_entry = cleanup_applied_entry_v2(
        aggregate,
        &context,
        PrivateOramMutationCleanupOperationKindV2::ParentProgress,
        request_digest,
    )?;
    let lifecycle = apply_private_oram_mutation_parent_progress_v2(
        &aggregate.lifecycle,
        &aggregate.lease_slot,
        expected,
        applied_entry,
    )?;
    if lifecycle == aggregate.lifecycle {
        return Ok(current.clone());
    }
    advance_aggregate_v2(
        aggregate,
        lifecycle,
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    expected: &PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let ready = expected.ready();
    validate_private_oram_mutation_recovery_capsules_ready_v2(ready)?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
        ready.ready_digest(),
    )?;
    if let Some(certificate) = aggregate
        .recovery_capsules_certificate
        .as_ref()
        .filter(|certificate| certificate.ready == *ready)
    {
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &certificate.locator,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    if aggregate.recovery_capsules_certificate.is_some()
        || aggregate.terminal_decision_certificate.is_some()
        || aggregate.lease_slot.active.as_ref().is_none_or(|lease| {
            lease.generation != ready.generation()
                || !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing)
        })
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let (retained_watermark, _) = retained_parent_progress_v2(&aggregate.lifecycle)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if retained_watermark != ready.point_stage_watermark() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let certificate = new_recovery_capsules_certificate_v2(ready.clone(), context.locator.clone())?;
    advance_aggregate_v2(
        aggregate,
        aggregate.lifecycle.clone(),
        aggregate.lease_slot.clone(),
        Some(certificate),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_cleanup_witness_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    expected: &PrivateOramMutationCleanupExpectationV2,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::CleanupWitness,
        &expected.evidence_digest,
    )?;
    if let Some(witness) = retained_cleanup_witness_v2(&aggregate.lifecycle)
        && super::cleanup_expectation_matches_witness_v2(expected, witness)
    {
        validate_retained_retry_locator_v2(
            &context.locator,
            &witness.witness_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let applied_entry = cleanup_applied_entry_v2(
        aggregate,
        &context,
        PrivateOramMutationCleanupOperationKindV2::CleanupWitness,
        &expected.evidence_digest,
    )?;
    let lifecycle = apply_private_oram_mutation_cleanup_witness_v2(
        &aggregate.lifecycle,
        &aggregate.lease_slot,
        expected,
        applied_entry,
    )?;
    advance_aggregate_v2(
        aggregate,
        lifecycle,
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_clear_pending_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    clear_attempt_id_digest: String,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::ClearPending,
        &clear_attempt_id_digest,
    )?;
    if let Some(original) =
        retained_clear_pending_locator_v2(&aggregate.lifecycle, &clear_attempt_id_digest)
    {
        validate_retained_retry_locator_v2(
            &context.locator,
            original,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let applied_entry = cleanup_applied_entry_v2(
        aggregate,
        &context,
        PrivateOramMutationCleanupOperationKindV2::ClearPending,
        &clear_attempt_id_digest,
    )?;
    let lifecycle = apply_private_oram_mutation_clear_pending_v2(
        &aggregate.lifecycle,
        &aggregate.lease_slot,
        clear_attempt_id_digest,
        applied_entry,
    )?;
    advance_aggregate_v2(
        aggregate,
        lifecycle,
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn apply_private_oram_mutation_authority_clear_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    // The tombstone of the previous generation is retained forever, so its presence alone does
    // not make this entry a retry: only a Clear carrying that tombstone's own request digest is
    // replayed as a no-op. Any other Clear must apply against the currently pending clear of
    // the newer generation below.
    if let Some(cleared) = aggregate.lifecycle.last_cleared.as_ref()
        && context.request_digest == cleared.clear_pending_digest
    {
        validate_apply_context_v2(
            aggregate,
            &context,
            PrivateOramMutationMaterialOperationV2::Clear,
            &cleared.clear_pending_digest,
        )?;
        if context.next_outer_binding_digest != aggregate.outer_binding_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_retained_retry_locator_v2(
            &context.locator,
            &cleared.clear_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    let Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) =
        aggregate.lifecycle.active.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let request_digest = pending.pending_digest.clone();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::Clear,
        &request_digest,
    )?;
    validate_new_material_context_v2(aggregate, &context)?;
    if context.next_outer_binding_digest == aggregate.outer_binding_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let applied_entry = cleanup_applied_entry_v2(
        aggregate,
        &context,
        PrivateOramMutationCleanupOperationKindV2::Clear,
        &request_digest,
    )?;
    let applied = apply_private_oram_mutation_clear_v2(
        &aggregate.lifecycle,
        &aggregate.lease_slot,
        applied_entry,
    )?;
    advance_aggregate_v2(
        aggregate,
        applied.lifecycle,
        applied.lease_slot,
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn acknowledge_private_oram_mutation_authority_clear_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let Some(cleared) = aggregate.lifecycle.last_cleared.as_ref() else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let request_digest = cleared.clear_core_digest.clone();
    validate_apply_context_v2(
        aggregate,
        &context,
        PrivateOramMutationMaterialOperationV2::ClearAcknowledgement,
        &request_digest,
    )?;
    if let PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) = &cleared.resolution {
        validate_retained_retry_locator_v2(
            &context.locator,
            &acknowledged.acknowledgement_applied,
            &aggregate.last_material_transition.locator,
        )?;
        return Ok(current.clone());
    }
    validate_new_material_context_v2(aggregate, &context)?;
    let applied_entry = cleanup_applied_entry_v2(
        aggregate,
        &context,
        PrivateOramMutationCleanupOperationKindV2::ClearAcknowledgement,
        &request_digest,
    )?;
    let lifecycle = acknowledge_private_oram_mutation_clear_v2(
        &aggregate.lifecycle,
        &aggregate.lease_slot,
        applied_entry,
    )?;
    advance_aggregate_v2(
        aggregate,
        lifecycle,
        aggregate.lease_slot.clone(),
        aggregate.recovery_capsules_certificate.clone(),
        aggregate.terminal_decision_certificate.clone(),
        aggregate.outstanding_gc_obligations.clone(),
        context,
    )
}

pub(crate) fn validate_private_oram_mutation_authority_state_v2(
    state: &PrivateOramMutationAuthorityStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match state {
        PrivateOramMutationAuthorityStateV2::Legacy(legacy) => validate_legacy_authority_v2(legacy),
        PrivateOramMutationAuthorityStateV2::Activated(aggregate) => {
            validate_aggregate_v2(aggregate)
        }
    }
}

fn require_aggregate_v2(
    current: &PrivateOramMutationAuthorityStateV2,
) -> Result<&PrivateOramMutationConsensusAggregateV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_authority_state_v2(current)?;
    match current {
        PrivateOramMutationAuthorityStateV2::Legacy(_) => {
            Err(PrivateOramMutationJournalError::InvalidTransition)
        }
        PrivateOramMutationAuthorityStateV2::Activated(aggregate) => Ok(aggregate),
    }
}

fn aggregate_allows_owner_enrollment_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
) -> bool {
    aggregate.lifecycle.active.is_none()
        && aggregate.lease_slot.active.is_none()
        && aggregate.recovery_capsules_certificate.is_none()
        && aggregate.terminal_decision_certificate.is_none()
        && aggregate.active_append_attempt.is_none()
        && aggregate.outstanding_gc_obligations.is_empty()
        && !aggregate.owner_checkpoint_table.has_active_leases()
        && !aggregate.owner_checkpoint_table.has_pending_repair()
}

fn terminal_material_is_transferable_to_next_admission_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
) -> bool {
    match (
        aggregate.recovery_capsules_certificate.as_ref(),
        aggregate.terminal_decision_certificate.as_ref(),
    ) {
        (None, None) => true,
        (Some(_), Some(_)) => aggregate
            .lifecycle
            .last_cleared
            .as_ref()
            .is_some_and(|cleared| new_gc_obligation_v2(aggregate, cleared.clone()).is_ok()),
        _ => false,
    }
}

fn advance_aggregate_v2(
    current: &PrivateOramMutationConsensusAggregateV2,
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
    recovery_capsules_certificate: Option<PrivateOramMutationRecoveryCapsulesCertificateV2>,
    terminal_decision_certificate: Option<PrivateOramMutationTerminalDecisionCertificateV2>,
    outstanding_gc_obligations: Vec<PrivateOramAcknowledgedGcObligationV2>,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    advance_aggregate_with_rejected_admissions_v2(
        current,
        lifecycle,
        lease_slot,
        recovery_capsules_certificate,
        terminal_decision_certificate,
        outstanding_gc_obligations,
        current.rejected_admissions.clone(),
        current.active_append_attempt.clone(),
        current.append_outcomes.clone(),
        current.owner_checkpoint_table.clone(),
        context,
    )
}

fn advance_aggregate_with_owner_checkpoint_table_v2(
    current: &PrivateOramMutationConsensusAggregateV2,
    owner_checkpoint_table: PrivateOramOwnerCheckpointTableV1,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    advance_aggregate_with_rejected_admissions_v2(
        current,
        current.lifecycle.clone(),
        current.lease_slot.clone(),
        current.recovery_capsules_certificate.clone(),
        current.terminal_decision_certificate.clone(),
        current.outstanding_gc_obligations.clone(),
        current.rejected_admissions.clone(),
        current.active_append_attempt.clone(),
        current.append_outcomes.clone(),
        owner_checkpoint_table,
        context,
    )
}

fn advance_aggregate_with_rejected_admissions_v2(
    current: &PrivateOramMutationConsensusAggregateV2,
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
    recovery_capsules_certificate: Option<PrivateOramMutationRecoveryCapsulesCertificateV2>,
    terminal_decision_certificate: Option<PrivateOramMutationTerminalDecisionCertificateV2>,
    outstanding_gc_obligations: Vec<PrivateOramAcknowledgedGcObligationV2>,
    rejected_admissions: Vec<PrivateOramMutationRejectedAdmissionV2>,
    active_append_attempt: Option<PrivateOramMutationActiveAppendAttemptV2>,
    append_outcomes: Vec<PrivateOramMutationAppendOutcomeV2>,
    owner_checkpoint_table: PrivateOramOwnerCheckpointTableV1,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    advance_aggregate_with_challenge_state_v2(
        current,
        current.version,
        lifecycle,
        lease_slot,
        recovery_capsules_certificate,
        terminal_decision_certificate,
        outstanding_gc_obligations,
        rejected_admissions,
        active_append_attempt,
        append_outcomes,
        owner_checkpoint_table,
        current.pending_reservation_challenge.clone(),
        current.reservation_challenge_outcomes.clone(),
        context,
    )
}

#[allow(clippy::too_many_arguments)]
fn advance_aggregate_with_challenge_state_v2(
    current: &PrivateOramMutationConsensusAggregateV2,
    aggregate_version: u16,
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
    recovery_capsules_certificate: Option<PrivateOramMutationRecoveryCapsulesCertificateV2>,
    terminal_decision_certificate: Option<PrivateOramMutationTerminalDecisionCertificateV2>,
    outstanding_gc_obligations: Vec<PrivateOramAcknowledgedGcObligationV2>,
    rejected_admissions: Vec<PrivateOramMutationRejectedAdmissionV2>,
    active_append_attempt: Option<PrivateOramMutationActiveAppendAttemptV2>,
    append_outcomes: Vec<PrivateOramMutationAppendOutcomeV2>,
    owner_checkpoint_table: PrivateOramOwnerCheckpointTableV1,
    pending_reservation_challenge: Option<PrivateOramMutationPendingReservationChallengeV1>,
    reservation_challenge_outcomes: Vec<PrivateOramMutationReservationChallengeOutcomeV1>,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    advance_aggregate_with_challenge_history_v2(
        current,
        aggregate_version,
        lifecycle,
        lease_slot,
        recovery_capsules_certificate,
        terminal_decision_certificate,
        outstanding_gc_obligations,
        rejected_admissions,
        active_append_attempt,
        append_outcomes,
        owner_checkpoint_table,
        pending_reservation_challenge,
        reservation_challenge_outcomes,
        current.reservation_challenge_outcome_accumulator.clone(),
        context,
    )
}

#[allow(clippy::too_many_arguments)]
fn advance_aggregate_with_challenge_history_v2(
    current: &PrivateOramMutationConsensusAggregateV2,
    aggregate_version: u16,
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
    recovery_capsules_certificate: Option<PrivateOramMutationRecoveryCapsulesCertificateV2>,
    terminal_decision_certificate: Option<PrivateOramMutationTerminalDecisionCertificateV2>,
    outstanding_gc_obligations: Vec<PrivateOramAcknowledgedGcObligationV2>,
    rejected_admissions: Vec<PrivateOramMutationRejectedAdmissionV2>,
    active_append_attempt: Option<PrivateOramMutationActiveAppendAttemptV2>,
    append_outcomes: Vec<PrivateOramMutationAppendOutcomeV2>,
    owner_checkpoint_table: PrivateOramOwnerCheckpointTableV1,
    pending_reservation_challenge: Option<PrivateOramMutationPendingReservationChallengeV1>,
    reservation_challenge_outcomes: Vec<PrivateOramMutationReservationChallengeOutcomeV1>,
    reservation_challenge_outcome_accumulator: Option<
        PrivateOramMutationReservationOutcomeAccumulatorV1,
    >,
    context: PrivateOramMutationAggregateApplyContextV2,
) -> Result<PrivateOramMutationAuthorityStateV2, PrivateOramMutationJournalError> {
    let transition_ordinal = current
        .transition_ordinal
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let compacted_owner_archive_histories = advance_compacted_owner_archive_histories_v1(
        current,
        &outstanding_gc_obligations,
        context.operation_kind,
        context.retain_compacted_owner_archive_history,
    )?;
    let authority_core_digest = aggregate_core_digest_from_parts_v2(
        aggregate_version,
        &current.activation,
        &context.next_outer_binding_digest,
        &lifecycle,
        &lease_slot,
        recovery_capsules_certificate.as_ref(),
        terminal_decision_certificate.as_ref(),
        &outstanding_gc_obligations,
        &rejected_admissions,
        active_append_attempt.as_ref(),
        &append_outcomes,
        &owner_checkpoint_table,
        pending_reservation_challenge.as_ref(),
        &reservation_challenge_outcomes,
        reservation_challenge_outcome_accumulator.as_ref(),
        &compacted_owner_archive_histories,
    )?;
    let last_material_transition = new_material_transition_receipt_v2(
        transition_ordinal,
        context.locator,
        context.operation_kind,
        context.request_digest,
        current.aggregate_digest.clone(),
        current.outer_binding_digest.clone(),
        authority_core_digest.clone(),
        context.next_outer_binding_digest.clone(),
    )?;
    let mut aggregate = PrivateOramMutationConsensusAggregateV2 {
        version: aggregate_version,
        activation: current.activation.clone(),
        outer_binding_digest: context.next_outer_binding_digest,
        lifecycle,
        lease_slot,
        recovery_capsules_certificate,
        terminal_decision_certificate,
        transition_ordinal,
        last_material_transition,
        outstanding_gc_obligations,
        compacted_owner_archive_histories,
        rejected_admissions,
        active_append_attempt,
        append_outcomes,
        owner_checkpoint_table,
        pending_reservation_challenge,
        reservation_challenge_outcomes,
        reservation_challenge_outcome_accumulator,
        authority_core_digest,
        aggregate_digest: String::new(),
    };
    aggregate.aggregate_digest = aggregate_digest_v2(&aggregate)?;
    validate_aggregate_v2(&aggregate)?;
    Ok(PrivateOramMutationAuthorityStateV2::Activated(Box::new(
        aggregate,
    )))
}

fn retain_acknowledged_gc_obligation_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    obligations: &mut Vec<PrivateOramAcknowledgedGcObligationV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    retain_acknowledged_gc_obligation_with_limits_v2(
        aggregate,
        obligations,
        MAX_OUTSTANDING_GC_OBLIGATIONS,
        MAX_OUTSTANDING_GC_OBLIGATION_BYTES,
    )
}

fn retain_acknowledged_gc_obligation_with_limits_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    obligations: &mut Vec<PrivateOramAcknowledgedGcObligationV2>,
    maximum_count: usize,
    maximum_bytes: usize,
) -> Result<(), PrivateOramMutationJournalError> {
    if maximum_count == 0 {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let Some(cleared) = aggregate.lifecycle.last_cleared.as_ref() else {
        return Ok(());
    };
    if !matches!(
        cleared.resolution,
        PrivateOramMutationClearResolutionV2::Acknowledged(_)
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let candidate = new_gc_obligation_v2(aggregate, cleared.clone())?;
    if let Some(existing) = obligations
        .iter()
        .find(|obligation| obligation.generation == candidate.generation)
    {
        if existing != &candidate {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(());
    }
    if obligations
        .last()
        .is_some_and(|previous| previous.generation >= candidate.generation)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    obligations.push(candidate);
    // Detailed obligations are retained newest-last. The aggregate transition commits the
    // removed prefix in compacted_owner_archive_histories before publishing this suffix.
    while obligations.len() > maximum_count
        || (obligations.len() > 1 && gc_obligations_serialized_len_v2(obligations)? > maximum_bytes)
    {
        obligations.remove(0);
    }
    if gc_obligations_serialized_len_v2(obligations)? > maximum_bytes {
        obligations.pop();
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn acknowledged_owner_archive_expectation_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<PrivateOramOwnerAcknowledgedArchiveExpectationV2, PrivateOramMutationJournalError> {
    if !matches!(
        cleared.resolution,
        PrivateOramMutationClearResolutionV2::Acknowledged(_)
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut pending = cleared.clone();
    pending.resolution = PrivateOramMutationClearResolutionV2::Pending;
    pending.resolution_digest = clear_resolution_digest_v2(&pending)?;
    pending.tombstone_digest = cleared_state_digest_v2(&pending)?;
    validate_cleared_state_v2(&pending)?;
    PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
        cleared.generation,
        cleared.owner_peer_id,
        cleared.terminal_record_digest.clone(),
        pending.tombstone_digest,
        cleared.clear_receipt_digest.clone(),
    )
    .map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

fn advance_compacted_owner_archive_histories_v1(
    current: &PrivateOramMutationConsensusAggregateV2,
    next: &[PrivateOramAcknowledgedGcObligationV2],
    operation: PrivateOramMutationMaterialOperationV2,
    retain_history: bool,
) -> Result<Vec<PrivateOramOwnerCompactedArchiveHistoryV1>, PrivateOramMutationJournalError> {
    if retain_history {
        require_complete_acknowledged_archive_history_v1(current)?;
    }
    let mut histories = current.compacted_owner_archive_histories.clone();
    if next == current.outstanding_gc_obligations {
        return Ok(histories);
    }
    if !retain_history {
        // Historical entries must reproduce their original aggregate digest. Once history is
        // committed, a missing/downgraded floor must never discard it on a later admission.
        return if histories.is_empty() {
            Ok(histories)
        } else {
            Err(PrivateOramMutationJournalError::InvalidTransition)
        };
    }
    // Reservation preparation may only compact an exact prefix. Admission may additionally
    // append the acknowledged predecessor. Neither path may drop a hole or replace a tuple.
    let removed = next
        .first()
        .map_or(current.outstanding_gc_obligations.len(), |first| {
            current
                .outstanding_gc_obligations
                .partition_point(|obligation| obligation.generation < first.generation)
        });
    let retained = &current.outstanding_gc_obligations[removed..];
    match operation {
        PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared
            if next == retained => {}
        PrivateOramMutationMaterialOperationV2::Admission => {
            let cleared = current
                .lifecycle
                .last_cleared
                .as_ref()
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
            if next.len() != retained.len() + 1
                || !next.starts_with(retained)
                || next.last() != Some(&new_gc_obligation_v2(current, cleared.clone())?)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    }
    for obligation in &current.outstanding_gc_obligations[..removed] {
        let owner = obligation.acknowledged_tombstone.owner_peer_id;
        let binding =
            acknowledged_owner_archive_expectation_v2(&obligation.acknowledged_tombstone)?;
        let index = histories.binary_search_by_key(&owner, |history| history.owner_peer_id());
        let history = PrivateOramOwnerCompactedArchiveHistoryV1::append(
            index.ok().map(|index| &histories[index]),
            &binding,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        match index {
            Ok(index) => histories[index] = history,
            Err(index) => histories.insert(index, history),
        }
    }
    Ok(histories)
}

/// Exercises the retention boundary with two real, fully acknowledged generations supplied by
/// the parent-journal integration fixture, without creating thousands of cryptographic journals.
#[cfg(test)]
pub(crate) fn assert_gc_compaction_retains_owner_history_for_test(
    state: &PrivateOramMutationAuthorityStateV2,
    previous_lease: &PrivateOramMutationLease,
) {
    let current = require_aggregate_v2(state).unwrap();
    assert_eq!(current.outstanding_gc_obligations.len(), 1);
    let first = &current.outstanding_gc_obligations[0];
    assert_eq!(first.generation, 1);
    let next_obligation =
        new_gc_obligation_v2(current, current.lifecycle.last_cleared.clone().unwrap()).unwrap();
    assert_eq!(next_obligation.generation, 2);
    let expected = PrivateOramOwnerCompactedArchiveHistoryV1::append(
        None,
        &acknowledged_owner_archive_expectation_v2(&first.acknowledged_tombstone).unwrap(),
    )
    .unwrap();
    let next_bytes =
        gc_obligations_serialized_len_v2(std::slice::from_ref(&next_obligation)).unwrap();
    for (max_count, max_bytes) in [
        (1, MAX_OUTSTANDING_GC_OBLIGATION_BYTES),
        (MAX_OUTSTANDING_GC_OBLIGATIONS, next_bytes),
    ] {
        let mut next = current.outstanding_gc_obligations.clone();
        retain_acknowledged_gc_obligation_with_limits_v2(current, &mut next, max_count, max_bytes)
            .unwrap();
        assert_eq!(next, vec![next_obligation.clone()]);
        let histories = advance_compacted_owner_archive_histories_v1(
            current,
            &next,
            PrivateOramMutationMaterialOperationV2::Admission,
            true,
        )
        .unwrap();
        assert_eq!(histories, vec![expected.clone()]);
        assert_eq!(
            serde_json::from_slice::<Vec<PrivateOramOwnerCompactedArchiveHistoryV1>>(
                &serde_json::to_vec(&histories).unwrap()
            )
            .unwrap(),
            histories
        );
        // Replaying the same historical pre-wire9 admission preserves its old empty proof.
        assert!(
            advance_compacted_owner_archive_histories_v1(
                current,
                &next,
                PrivateOramMutationMaterialOperationV2::Admission,
                false,
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            advance_compacted_owner_archive_histories_v1(
                current,
                &next,
                PrivateOramMutationMaterialOperationV2::Renewal,
                true,
            )
            .is_err()
        );
    }
    let mut missing_legacy_prefix = current.clone();
    missing_legacy_prefix.outstanding_gc_obligations.clear();
    assert!(require_complete_acknowledged_archive_history_v1(&missing_legacy_prefix).is_err());
    assert!(
        advance_compacted_owner_archive_histories_v1(
            &missing_legacy_prefix,
            &[next_obligation],
            PrivateOramMutationMaterialOperationV2::Admission,
            true,
        )
        .is_err()
    );
    wire_tests::assert_reservation_compacts_gc_at_capacity(state, previous_lease, &expected);
}

fn require_complete_acknowledged_archive_history_v1(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    // Activation starts at generation zero; every admitted successor requires the preceding
    // generation's acknowledgement. A legacy suffix above one cannot establish the missing
    // prefix, even if the corresponding old owner archives have also disappeared locally.
    let mut count = 0_u64;
    let mut through = 0_u64;
    for history in &aggregate.compacted_owner_archive_histories {
        count = count
            .checked_add(history.archive_count())
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        through = through.max(history.through_generation());
    }
    if count != through {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for obligation in &aggregate.outstanding_gc_obligations {
        if through.checked_add(1) != Some(obligation.generation) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        through = obligation.generation;
    }
    let complete = match aggregate.lifecycle.last_cleared.as_ref() {
        Some(cleared)
            if matches!(
                cleared.resolution,
                PrivateOramMutationClearResolutionV2::Acknowledged(_)
            ) =>
        {
            // The newest acknowledgement joins the GC suffix on the following admission.
            through == cleared.generation || through.checked_add(1) == Some(cleared.generation)
        }
        Some(cleared) => through.checked_add(1) == Some(cleared.generation),
        None => through == 0,
    };
    if !complete {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn new_gc_obligation_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    acknowledged_tombstone: PrivateOramMutationClearedStateV2,
) -> Result<PrivateOramAcknowledgedGcObligationV2, PrivateOramMutationJournalError> {
    validate_cleared_state_v2(&acknowledged_tombstone)?;
    let PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) =
        &acknowledged_tombstone.resolution
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let mut cleanup_target = PrivateOramMutationCleanupTargetV2 {
        version: CLEANUP_TARGET_VERSION,
        storage_namespace_version: CLEANUP_STORAGE_NAMESPACE_VERSION,
        collection_key_digest: aggregate
            .activation
            .authority_key
            .collection_key_digest
            .clone(),
        collection_lifetime_id_digest: aggregate
            .activation
            .authority_key
            .collection_lifetime_id_digest
            .clone(),
        collection_incarnation_digest: aggregate.activation.collection_incarnation_digest.clone(),
        activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
        generation: acknowledged_tombstone.generation,
        retired_outer_binding_digest: aggregate.outer_binding_digest.clone(),
        logical_object_set_digest: cleanup_logical_object_set_digest_v2(&acknowledged_tombstone)?,
        tombstone_digest: acknowledged_tombstone.tombstone_digest.clone(),
        acknowledgement_applied: acknowledged.acknowledgement_applied.clone(),
        target_digest: String::new(),
    };
    cleanup_target.target_digest = cleanup_target_digest_v2(&cleanup_target)?;
    let mut obligation = PrivateOramAcknowledgedGcObligationV2 {
        version: GC_OBLIGATION_VERSION,
        collection_key_digest: aggregate
            .activation
            .authority_key
            .collection_key_digest
            .clone(),
        collection_incarnation_digest: aggregate.activation.collection_incarnation_digest.clone(),
        generation: acknowledged_tombstone.generation,
        terminal_decision_certificate: aggregate
            .terminal_decision_certificate
            .clone()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
        acknowledged_tombstone,
        cleanup_target,
        obligation_digest: String::new(),
    };
    obligation.obligation_digest = gc_obligation_digest_v2(&obligation)?;
    validate_gc_obligation_v2(&obligation, &aggregate.activation)?;
    Ok(obligation)
}

fn validate_aggregate_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if !matches!(
        aggregate.version,
        AGGREGATE_VERSION_V6 | AGGREGATE_VERSION_V7
    ) || aggregate.transition_ordinal == 0
        || aggregate.transition_ordinal != aggregate.last_material_transition.ordinal
        || (aggregate.version == AGGREGATE_VERSION_V6
            && (aggregate.pending_reservation_challenge.is_some()
                || !aggregate.reservation_challenge_outcomes.is_empty()
                || aggregate
                    .reservation_challenge_outcome_accumulator
                    .is_some()))
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_activation_anchor_v2(&aggregate.activation)?;
    validate_private_oram_mutation_cleanup_pair_v2(&aggregate.lifecycle, &aggregate.lease_slot)?;
    validate_private_oram_owner_checkpoint_table_scope_v1(
        &aggregate.owner_checkpoint_table,
        &aggregate
            .activation
            .authority_key
            .consensus_history_id_digest,
        &aggregate.activation.authority_key.raft_group_id_digest,
        &aggregate.activation.authority_key.collection_key_digest,
        &aggregate
            .activation
            .authority_key
            .collection_lifetime_id_digest,
        &aggregate.activation.collection_incarnation_digest,
        &aggregate.activation.anchor_digest,
        &aggregate.activation.activation_applied,
        aggregate.activation.compatibility_epoch,
        &private_oram_mutation_protocol_capability_digest_v2(),
    )?;
    validate_material_transition_receipt_v2(&aggregate.last_material_transition)?;
    if let Some(certificate) = &aggregate.recovery_capsules_certificate {
        validate_recovery_capsules_certificate_v2(certificate)?;
        let generation = aggregate
            .lease_slot
            .active
            .as_ref()
            .map(|lease| lease.generation)
            .or_else(|| {
                retained_terminal_lease_v2(&aggregate.lifecycle).map(|lease| lease.generation)
            })
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let (retained_watermark, applied_history) =
            retained_parent_progress_v2(&aggregate.lifecycle)
                .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let point_stage_applied = applied_history
            .get(2)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if certificate.generation != generation
            || !private_oram_mutation_parent_watermark_is_canonical_prefix_v2(
                certificate.ready.point_stage_watermark(),
                retained_watermark,
            )?
            || !locator_is_strictly_after(&certificate.locator, point_stage_applied)
            || !locator_is_at_or_after(
                &aggregate.last_material_transition.locator,
                &certificate.locator,
            )
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if let Some(certificate) = &aggregate.terminal_decision_certificate {
        validate_terminal_decision_certificate_v2(certificate)?;
        if aggregate
            .recovery_capsules_certificate
            .as_ref()
            .is_none_or(|recovery| {
                recovery.generation != certificate.generation
                    || recovery.certificate_digest
                        != certificate.recovery_capsules_certificate_digest
            })
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    match current_generation_terminal_lease_v2(&aggregate.lifecycle, &aggregate.lease_slot) {
        Some(terminal_lease) => {
            let certificate = aggregate
                .terminal_decision_certificate
                .as_ref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?;
            if !terminal_certificate_matches_lease_v2(certificate, terminal_lease)? {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
        }
        None if aggregate.terminal_decision_certificate.is_some() => {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        None => {}
    }
    validate_digest(&aggregate.outer_binding_digest)?;
    validate_digest(&aggregate.authority_core_digest)?;
    if aggregate.lifecycle.collection_id_digest
        != aggregate.activation.authority_key.collection_key_digest
        || aggregate.lifecycle.consensus_history_id_digest
            != aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
        || aggregate.lifecycle.raft_group_id_digest
            != aggregate.activation.authority_key.raft_group_id_digest
        || !locator_is_at_or_after(
            &aggregate.last_material_transition.locator,
            &aggregate.activation.activation_applied,
        )
        || !locator_is_at_or_after(
            &aggregate.last_material_transition.locator,
            aggregate.owner_checkpoint_table.maximum_material_locator(),
        )
        || lifecycle_frontier_locator_v2(&aggregate.lifecycle).is_some_and(|frontier| {
            !locator_is_at_or_after(&aggregate.last_material_transition.locator, frontier)
        })
        || aggregate
            .last_material_transition
            .next_authority_core_digest
            != aggregate.authority_core_digest
        || aggregate.last_material_transition.next_outer_binding_digest
            != aggregate.outer_binding_digest
        || aggregate.authority_core_digest
            != aggregate_core_digest_from_parts_v2(
                aggregate.version,
                &aggregate.activation,
                &aggregate.outer_binding_digest,
                &aggregate.lifecycle,
                &aggregate.lease_slot,
                aggregate.recovery_capsules_certificate.as_ref(),
                aggregate.terminal_decision_certificate.as_ref(),
                &aggregate.outstanding_gc_obligations,
                &aggregate.rejected_admissions,
                aggregate.active_append_attempt.as_ref(),
                &aggregate.append_outcomes,
                &aggregate.owner_checkpoint_table,
                aggregate.pending_reservation_challenge.as_ref(),
                &aggregate.reservation_challenge_outcomes,
                aggregate.reservation_challenge_outcome_accumulator.as_ref(),
                &aggregate.compacted_owner_archive_histories,
            )?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if aggregate.transition_ordinal == 1
        && (aggregate.last_material_transition.operation_kind
            != PrivateOramMutationMaterialOperationV2::Activation
            || aggregate.last_material_transition.locator
                != aggregate.activation.activation_applied
            || aggregate.last_material_transition.request_digest
                != aggregate.activation.activation_request_digest
            || aggregate.last_material_transition.prior_authority_digest
                != aggregate.activation.preactivation_authority_digest
            || aggregate
                .last_material_transition
                .prior_outer_binding_digest
                != aggregate.activation.preactivation_outer_binding_digest)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if let Some(pending) = &aggregate.pending_reservation_challenge {
        validate_pending_reservation_challenge_v1(pending)?;
        if aggregate.version != AGGREGATE_VERSION_V7
            || pending.challenge_applied != aggregate.last_material_transition.locator
            || pending.challenge_digest != aggregate.last_material_transition.request_digest
            || pending.prepared_ordinal != aggregate.transition_ordinal
            || aggregate.last_material_transition.operation_kind
                != PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared
            || pending.challenge_applied.consensus_history_id_digest
                != aggregate
                    .activation
                    .authority_key
                    .consensus_history_id_digest
            || pending.challenge_applied.raft_group_id_digest
                != aggregate.activation.authority_key.raft_group_id_digest
            || aggregate.active_append_attempt.is_some()
            || aggregate.lifecycle.active.is_some()
            || aggregate.lease_slot.active.is_some()
            || aggregate.owner_checkpoint_table.has_active_leases()
            || aggregate
                .reservation_challenge_outcomes
                .iter()
                .any(|outcome| outcome.challenge_digest == pending.challenge_digest)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if aggregate.reservation_challenge_outcomes.len() > MAX_RESERVATION_CHALLENGE_OUTCOMES
        || reservation_challenge_outcomes_serialized_len_v1(
            &aggregate.reservation_challenge_outcomes,
        )? > MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut challenge_digests = HashSet::new();
    if let Some(accumulator) = &aggregate.reservation_challenge_outcome_accumulator {
        validate_reservation_challenge_outcome_accumulator_v1(accumulator)?;
        if aggregate.version != AGGREGATE_VERSION_V7
            || !locator_is_at_or_after(
                &aggregate.last_material_transition.locator,
                &accumulator.last_resolution_applied,
            )
            || !locator_is_at_or_after(
                &aggregate.last_material_transition.locator,
                &accumulator.last_acknowledgement_applied,
            )
            || accumulator
                .last_resolution_applied
                .consensus_history_id_digest
                != aggregate
                    .activation
                    .authority_key
                    .consensus_history_id_digest
            || accumulator.last_resolution_applied.raft_group_id_digest
                != aggregate.activation.authority_key.raft_group_id_digest
            || accumulator
                .last_acknowledgement_applied
                .consensus_history_id_digest
                != aggregate
                    .activation
                    .authority_key
                    .consensus_history_id_digest
            || accumulator
                .last_acknowledgement_applied
                .raft_group_id_digest
                != aggregate.activation.authority_key.raft_group_id_digest
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    let mut previous_challenge_resolution = aggregate
        .reservation_challenge_outcome_accumulator
        .as_ref()
        .map(|accumulator| &accumulator.last_resolution_applied);
    let mut previous_attempt_sequence = aggregate
        .reservation_challenge_outcome_accumulator
        .as_ref()
        .map(|accumulator| accumulator.last_attempt_sequence);
    for outcome in &aggregate.reservation_challenge_outcomes {
        validate_reservation_challenge_outcome_v1(outcome)?;
        if aggregate.version != AGGREGATE_VERSION_V7
            || !challenge_digests.insert(outcome.challenge_digest.clone())
            || previous_challenge_resolution.is_some_and(|previous| {
                !locator_is_strictly_after(&outcome.challenge_applied, previous)
            })
            || previous_attempt_sequence
                .is_some_and(|previous| outcome.attempt_sequence <= previous)
            || !locator_is_at_or_after(
                &aggregate.last_material_transition.locator,
                &outcome.resolution_applied,
            )
            || outcome.challenge_applied.consensus_history_id_digest
                != aggregate
                    .activation
                    .authority_key
                    .consensus_history_id_digest
            || outcome.challenge_applied.raft_group_id_digest
                != aggregate.activation.authority_key.raft_group_id_digest
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous_challenge_resolution = Some(&outcome.resolution_applied);
        previous_attempt_sequence = Some(outcome.attempt_sequence);
    }
    if let Some(pending) = aggregate.pending_reservation_challenge.as_ref()
        && (previous_challenge_resolution.is_some_and(|previous| {
            !locator_is_strictly_after(&pending.challenge_applied, previous)
        }) || previous_attempt_sequence
            .is_some_and(|previous| pending.attempt_sequence <= previous))
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if aggregate.compacted_owner_archive_histories.len()
        > aggregate.owner_checkpoint_table.checkpoints().len()
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut previous_owner = None;
    let mut compacted_through = 0;
    let mut compacted_count = 0_u64;
    for history in &aggregate.compacted_owner_archive_histories {
        history
            .validate()
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if previous_owner.is_some_and(|owner| owner >= history.owner_peer_id())
            || aggregate
                .owner_checkpoint_table
                .checkpoint_for_owner(history.owner_peer_id())
                .is_none()
            || history.through_generation() >= aggregate.lease_slot.generation
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous_owner = Some(history.owner_peer_id());
        compacted_through = compacted_through.max(history.through_generation());
        compacted_count = compacted_count
            .checked_add(history.archive_count())
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    }
    if compacted_count > compacted_through
        || aggregate
            .lifecycle
            .last_cleared
            .as_ref()
            .is_some_and(|cleared| cleared.generation <= compacted_through)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut previous_generation = Some(compacted_through);
    if aggregate.outstanding_gc_obligations.len() > MAX_OUTSTANDING_GC_OBLIGATIONS
        || gc_obligations_serialized_len_v2(&aggregate.outstanding_gc_obligations)?
            > MAX_OUTSTANDING_GC_OBLIGATION_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for obligation in &aggregate.outstanding_gc_obligations {
        validate_gc_obligation_v2(obligation, &aggregate.activation)?;
        if previous_generation.is_some_and(|previous| previous >= obligation.generation)
            || obligation.generation >= aggregate.lease_slot.generation
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous_generation = Some(obligation.generation);
    }
    if !aggregate.compacted_owner_archive_histories.is_empty() {
        require_complete_acknowledged_archive_history_v1(aggregate)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    }
    if aggregate.rejected_admissions.len() > MAX_REJECTED_ADMISSIONS
        || rejected_admissions_serialized_len_v2(&aggregate.rejected_admissions)?
            > MAX_REJECTED_ADMISSION_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut previous_rejection_locator = None;
    let mut rejected_keys = HashSet::new();
    for rejected in &aggregate.rejected_admissions {
        validate_rejected_admission_v2(rejected, &aggregate.activation)?;
        if previous_rejection_locator.is_some_and(|previous| {
            !locator_is_strictly_after(&rejected.rejection_applied, previous)
        }) || !locator_is_at_or_after(
            &aggregate.last_material_transition.locator,
            &rejected.rejection_applied,
        ) || !rejected_keys.insert((
            rejected.rejected_from_aggregate_digest.clone(),
            rejected.resolution_request_digest.clone(),
        )) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous_rejection_locator = Some(&rejected.rejection_applied);
    }
    if let Some(active) = &aggregate.active_append_attempt {
        validate_active_append_attempt_v2(active, &aggregate.activation)?;
        let reservation = decode_private_oram_mutation_append_reservation_wire(
            &active.reservation_canonical_json,
        )?;
        let base_reservation = reservation.base_reservation();
        if aggregate.lifecycle.active.is_some()
            || aggregate.lease_slot.active.is_some()
            || !terminal_material_is_transferable_to_next_admission_v2(aggregate)
            || base_reservation.preparing_lease().generation
                != aggregate
                    .lease_slot
                    .generation
                    .checked_add(1)
                    .ok_or(PrivateOramMutationJournalError::Corrupt)?
            || base_reservation.preparing_lease().writer_fence
                <= aggregate.lease_slot.max_writer_fence
            || !locator_is_at_or_after(
                &aggregate.last_material_transition.locator,
                active
                    .prepared
                    .as_ref()
                    .map_or(&active.reservation_applied, |prepared| {
                        &prepared.prepared_applied
                    }),
            )
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        match reservation {
            DecodedPrivateOramMutationAppendReservation::HistoricalV2(_) => {
                if aggregate.owner_checkpoint_table.has_active_leases() {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
            }
            DecodedPrivateOramMutationAppendReservation::CheckpointBoundV3(reservation) => {
                if !aggregate
                    .reservation_challenge_outcomes
                    .iter()
                    .any(|outcome| {
                        outcome.kind
                            == PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3
                            && outcome.challenge_digest
                                == reservation.prepared_challenge().prepared_challenge_digest()
                            && outcome.challenge_applied == *reservation.challenge_applied()
                            && outcome.finalized_reservation_digest.as_deref()
                                == Some(reservation.reservation_digest_v3())
                            && outcome.resolution_applied == active.reservation_applied
                    })
                {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
                let transition = active
                    .checkpoint_lease_transition
                    .as_ref()
                    .ok_or(PrivateOramMutationJournalError::Corrupt)?;
                if transition.prelease_table_sequence
                    != reservation.checkpoint_context().checkpoint_table_sequence()
                    || transition.prelease_table_digest
                        != reservation.checkpoint_context().checkpoint_table_digest()
                    || transition.postlease_table_sequence
                        != aggregate.owner_checkpoint_table.table_sequence()
                    || transition.postlease_table_digest
                        != aggregate.owner_checkpoint_table.table_digest()
                    || transition.owner_checkpoint_roster_digest
                        != reservation
                            .checkpoint_context()
                            .owner_checkpoint_roster_digest()
                    || transition.owner_checkpoint_roster_digest
                        != aggregate.owner_checkpoint_table.owner_roster_digest()
                {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
                validate_private_oram_owner_checkpoint_active_reservation_v1(
                    &aggregate.owner_checkpoint_table,
                    reservation.checkpoint_context(),
                    reservation.attempt_id(),
                    reservation.reservation_digest_v3(),
                    &active.reservation_applied,
                    reservation.checkpoint_bindings(),
                )?;
            }
        }
    } else if aggregate.owner_checkpoint_table.has_active_leases() {
        let mut pending_settlements =
            aggregate
                .reservation_challenge_outcomes
                .iter()
                .filter(|outcome| {
                    outcome.kind
                        == PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3
                        && aggregate
                            .append_outcomes
                            .iter()
                            .any(|append_outcome| append_outcome.attempt_id == outcome.attempt_id)
                });
        let pending = pending_settlements
            .next()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if pending_settlements.next().is_some() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let reservation = decode_private_oram_mutation_append_reservation_v3(
            pending
                .finalized_reservation_canonical_json
                .as_deref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        )?;
        if pending.finalized_reservation_digest.as_deref()
            != Some(reservation.reservation_digest_v3())
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        validate_private_oram_owner_checkpoint_active_reservation_v1(
            &aggregate.owner_checkpoint_table,
            reservation.checkpoint_context(),
            reservation.attempt_id(),
            reservation.reservation_digest_v3(),
            &pending.resolution_applied,
            reservation.checkpoint_bindings(),
        )?;
    }
    if aggregate.append_outcomes.len() > MAX_APPEND_OUTCOMES
        || append_outcomes_serialized_len_v2(&aggregate.append_outcomes)? > MAX_APPEND_OUTCOME_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut outcome_keys = HashSet::new();
    let mut previous_outcome_locator = None;
    for outcome in &aggregate.append_outcomes {
        validate_append_outcome_v2(outcome, &aggregate.activation)?;
        if !outcome_keys.insert(outcome.outcome_key.clone())
            || previous_outcome_locator.is_some_and(|previous| {
                !locator_is_strictly_after(&outcome.resolution_applied, previous)
            })
            || !locator_is_at_or_after(
                &aggregate.last_material_transition.locator,
                &outcome.resolution_applied,
            )
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous_outcome_locator = Some(&outcome.resolution_applied);
    }
    for rejected in &aggregate.rejected_admissions {
        let expected_kind = if rejected.admission_request_digest.is_some() {
            PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected
        } else {
            PrivateOramMutationAppendOutcomeKindV2::PrestageAborted
        };
        if !aggregate.append_outcomes.iter().any(|outcome| {
            outcome.outcome_key == rejected.outcome_key
                && outcome.kind == expected_kind
                && outcome.resolution_applied == rejected.rejection_applied
        }) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if aggregate.aggregate_digest != aggregate_digest_v2(aggregate)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_authority_key_v2(
    authority_key: &PrivateOramMutationAuthorityKeyV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if authority_key.version != AUTHORITY_KEY_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &authority_key.consensus_history_id_digest,
        &authority_key.raft_group_id_digest,
        &authority_key.collection_lifetime_id_digest,
        &authority_key.collection_key_digest,
        &authority_key.key_digest,
    ] {
        validate_digest(digest)?;
    }
    if authority_key.key_digest != authority_key_digest_v2(authority_key)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_legacy_authority_v2(
    legacy: &PrivateOramMutationLegacyAuthorityV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if legacy.version != LEGACY_AUTHORITY_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_authority_key_v2(&legacy.authority_key)?;
    validate_lease_slot_v2(&legacy.exact_legacy_slot)?;
    validate_digest(&legacy.outer_binding_digest)?;
    if legacy.authority_digest != legacy_authority_digest_v2(legacy)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_activation_anchor_v2(
    activation: &PrivateOramMutationActivationAnchorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if activation.version != ACTIVATION_ANCHOR_VERSION || activation.compatibility_epoch == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_authority_key_v2(&activation.authority_key)?;
    validate_apply_locator_v2(&activation.activation_applied)?;
    for digest in [
        &activation.collection_incarnation_digest,
        &activation.preactivation_authority_digest,
        &activation.preactivation_outer_binding_digest,
        &activation.activation_request_digest,
        &activation.anchor_digest,
    ] {
        validate_digest(digest)?;
    }
    if activation.collection_incarnation_digest
        != collection_incarnation_digest_v2(
            &activation.authority_key,
            &activation.activation_applied,
            &activation.preactivation_authority_digest,
        )?
        || activation.activation_applied.consensus_history_id_digest
            != activation.authority_key.consensus_history_id_digest
        || activation.activation_applied.raft_group_id_digest
            != activation.authority_key.raft_group_id_digest
        || activation.anchor_digest != activation_anchor_digest_v2(activation)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_material_transition_receipt_v2(
    receipt: &PrivateOramMaterialTransitionReceiptV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if receipt.version != MATERIAL_TRANSITION_RECEIPT_VERSION || receipt.ordinal == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_apply_locator_v2(&receipt.locator)?;
    for digest in [
        &receipt.request_digest,
        &receipt.prior_authority_digest,
        &receipt.prior_outer_binding_digest,
        &receipt.next_authority_core_digest,
        &receipt.next_outer_binding_digest,
        &receipt.receipt_digest,
    ] {
        validate_digest(digest)?;
    }
    if receipt.receipt_digest != material_transition_receipt_digest_v2(receipt)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_decision_certificate_v2(
    certificate: &PrivateOramMutationTerminalDecisionCertificateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if certificate.version != TERMINAL_DECISION_CERTIFICATE_VERSION
        || certificate.generation == 0
        || !matches!(
            certificate.operation_kind,
            PrivateOramMutationMaterialOperationV2::AbortDecision
                | PrivateOramMutationMaterialOperationV2::ConsensusCommit
        )
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_apply_locator_v2(&certificate.locator)?;
    for digest in [
        &certificate.request_digest,
        &certificate.terminal_lease_state_digest,
        &certificate.recovery_capsules_certificate_digest,
        &certificate.next_outer_binding_digest,
        &certificate.certificate_digest,
    ] {
        validate_digest(digest)?;
    }
    if certificate.request_digest != certificate.terminal_lease_state_digest
        || certificate.certificate_digest != terminal_decision_certificate_digest_v2(certificate)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_recovery_capsules_certificate_v2(
    certificate: &PrivateOramMutationRecoveryCapsulesCertificateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_recovery_capsules_ready_v2(&certificate.ready)?;
    validate_apply_locator_v2(&certificate.locator)?;
    validate_digest(&certificate.certificate_digest)?;
    if certificate.version != RECOVERY_CAPSULES_CERTIFICATE_VERSION
        || certificate.generation == 0
        || certificate.generation != certificate.ready.generation()
        || certificate.certificate_digest != recovery_capsules_certificate_digest_v2(certificate)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_gc_obligation_v2(
    obligation: &PrivateOramAcknowledgedGcObligationV2,
    activation: &PrivateOramMutationActivationAnchorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if obligation.version != GC_OBLIGATION_VERSION || obligation.generation == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_cleared_state_v2(&obligation.acknowledged_tombstone)?;
    validate_terminal_decision_certificate_v2(&obligation.terminal_decision_certificate)?;
    validate_cleanup_target_v2(&obligation.cleanup_target)?;
    validate_digest(&obligation.obligation_digest)?;
    if obligation.collection_key_digest != activation.authority_key.collection_key_digest
        || obligation.collection_incarnation_digest != activation.collection_incarnation_digest
        || obligation.generation != obligation.acknowledged_tombstone.generation
        || obligation.generation != obligation.terminal_decision_certificate.generation
        || !terminal_certificate_matches_lease_v2(
            &obligation.terminal_decision_certificate,
            &obligation
                .acknowledged_tombstone
                .cleanup_witness
                .terminal_lease,
        )?
        || obligation.generation != obligation.cleanup_target.generation
        || obligation.cleanup_target.collection_incarnation_digest
            != obligation.collection_incarnation_digest
        || obligation.cleanup_target.collection_key_digest != obligation.collection_key_digest
        || obligation.cleanup_target.collection_lifetime_id_digest
            != activation.authority_key.collection_lifetime_id_digest
        || obligation.cleanup_target.activation_anchor_digest != activation.anchor_digest
        || obligation.cleanup_target.tombstone_digest
            != obligation.acknowledged_tombstone.tombstone_digest
        || obligation.cleanup_target.logical_object_set_digest
            != cleanup_logical_object_set_digest_v2(&obligation.acknowledged_tombstone)?
        || match &obligation.acknowledged_tombstone.resolution {
            PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) => {
                obligation.cleanup_target.acknowledgement_applied
                    != acknowledged.acknowledgement_applied
            }
            PrivateOramMutationClearResolutionV2::Pending => true,
        }
        || obligation.obligation_digest != gc_obligation_digest_v2(obligation)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_active_append_attempt_v2(
    active: &PrivateOramMutationActiveAppendAttemptV2,
    activation: &PrivateOramMutationActivationAnchorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if !matches!(
        active.version,
        ACTIVE_APPEND_ATTEMPT_VERSION | ACTIVE_APPEND_ATTEMPT_VERSION_V3
    ) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_digest(&active.reservation_request_digest)?;
    validate_digest(&active.attempt_digest)?;
    validate_apply_locator_v2(&active.reservation_applied)?;
    let reservation =
        decode_private_oram_mutation_append_reservation_wire(&active.reservation_canonical_json)?;
    let base_reservation = reservation.base_reservation();
    if active.reservation_request_digest != reservation.reservation_digest()
        || match &reservation {
            DecodedPrivateOramMutationAppendReservation::HistoricalV2(_) => {
                active.version != ACTIVE_APPEND_ATTEMPT_VERSION
                    || active.checkpoint_lease_transition.is_some()
            }
            DecodedPrivateOramMutationAppendReservation::CheckpointBoundV3(reservation) => {
                active.version != ACTIVE_APPEND_ATTEMPT_VERSION_V3
                    || active
                        .checkpoint_lease_transition
                        .as_ref()
                        .is_none_or(|transition| {
                            validate_private_oram_owner_checkpoint_lease_transition_v1(transition)
                                .is_err()
                                || transition.reservation_context_digest
                                    != reservation.checkpoint_context().context_digest()
                                || transition.reservation_digest
                                    != reservation.reservation_digest_v3()
                        })
            }
        }
        || private_oram_collection_id_digest_v2(base_reservation.collection_id())?
            != activation.authority_key.collection_key_digest
        || !locator_is_strictly_after(&active.reservation_applied, &activation.activation_applied)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if let Some(prepared) = &active.prepared {
        if prepared.version != PREPARED_APPEND_VERSION {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        for digest in [
            &prepared.prepare_request_digest,
            &prepared.admission_request_digest,
            &prepared.prepared_digest,
        ] {
            validate_digest(digest)?;
        }
        validate_apply_locator_v2(&prepared.prepared_applied)?;
        let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
            &prepared.recovery_manifest_canonical_json,
        )?;
        reservation.validate_manifest(&manifest)?;
        if prepared.prepare_request_digest
            != reservation.append_prepared_request_digest(&manifest)?
            || prepared.admission_request_digest
                != private_oram_mutation_admission_request_digest_v2(
                    base_reservation.preparing_lease(),
                    manifest.manifest_digest(),
                )?
            || !locator_is_strictly_after(&prepared.prepared_applied, &active.reservation_applied)
            || prepared.prepared_digest != prepared_append_digest_v2(prepared)?
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if active.attempt_digest != active_append_attempt_digest_v2(active)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_append_outcome_v2(
    outcome: &PrivateOramMutationAppendOutcomeV2,
    activation: &PrivateOramMutationActivationAnchorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if outcome.version != APPEND_OUTCOME_VERSION
        || outcome.protocol_capability_digest
            != private_oram_mutation_protocol_capability_digest_v2()
        || outcome.collection_incarnation_digest != activation.collection_incarnation_digest
        || outcome.mutation_id.is_empty()
        || !locator_is_strictly_after(&outcome.resolution_applied, &activation.activation_applied)
        || match outcome.kind {
            PrivateOramMutationAppendOutcomeKindV2::Admitted
            | PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected => {
                outcome.admission_request_digest.is_none() || outcome.manifest_digest.is_none()
            }
            PrivateOramMutationAppendOutcomeKindV2::PrestageAborted => {
                outcome.admission_request_digest.is_some() || outcome.manifest_digest.is_some()
            }
        }
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &outcome.outcome_key,
        &outcome.protocol_capability_digest,
        &outcome.collection_incarnation_digest,
        &outcome.attempt_id,
        &outcome.mutation_id,
        &outcome.preparing_lease_state_digest,
        &outcome.resolved_from_aggregate_digest,
        &outcome.resolution_request_digest,
        &outcome.owner_roster_digest,
        &outcome.outcome_digest,
    ] {
        validate_digest(digest)?;
    }
    for digest in [
        outcome.admission_request_digest.as_deref(),
        outcome.manifest_digest.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_digest(digest)?;
    }
    if outcome.outcome_key != append_outcome_key_v2(outcome)?
        || outcome.outcome_digest != append_outcome_digest_v2(outcome)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn new_append_outcome_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    reservation: &DecodedPrivateOramMutationAppendReservation,
    kind: PrivateOramMutationAppendOutcomeKindV2,
    resolved_from_aggregate_digest: String,
    resolution_request_digest: String,
    admission_request_digest: Option<String>,
    manifest_digest: Option<String>,
    resolution_applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramMutationAppendOutcomeV2, PrivateOramMutationJournalError> {
    let base_reservation = reservation.base_reservation();
    let mut outcome = PrivateOramMutationAppendOutcomeV2 {
        version: APPEND_OUTCOME_VERSION,
        outcome_key: String::new(),
        kind,
        protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
        collection_incarnation_digest: aggregate.activation.collection_incarnation_digest.clone(),
        attempt_id: base_reservation.attempt_id().to_string(),
        mutation_id: base_reservation.mutation_id().to_string(),
        preparing_lease_state_digest: base_reservation.preparing_lease_state_digest().to_string(),
        resolved_from_aggregate_digest,
        resolution_request_digest,
        admission_request_digest,
        manifest_digest,
        owner_roster_digest: base_reservation.owner_roster_digest().to_string(),
        resolution_applied,
        outcome_digest: String::new(),
    };
    outcome.outcome_key = append_outcome_key_v2(&outcome)?;
    outcome.outcome_digest = append_outcome_digest_v2(&outcome)?;
    validate_append_outcome_v2(&outcome, &aggregate.activation)?;
    if aggregate
        .append_outcomes
        .iter()
        .any(|retained| retained.outcome_key == outcome.outcome_key)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn new_rejected_append_v2(
    reservation: &DecodedPrivateOramMutationAppendReservation,
    recovery_manifest_canonical_json: Option<String>,
    resolution_request_digest: String,
    admission_request_digest: Option<String>,
    outcome_key: String,
    rejected_from_aggregate_digest: String,
    rejection_applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramMutationRejectedAdmissionV2, PrivateOramMutationJournalError> {
    let base_reservation = reservation.base_reservation();
    let reservation_canonical_json = match reservation {
        DecodedPrivateOramMutationAppendReservation::HistoricalV2(reservation) => {
            encode_private_oram_mutation_append_reservation_v2(reservation)?
        }
        DecodedPrivateOramMutationAppendReservation::CheckpointBoundV3(reservation) => {
            encode_private_oram_mutation_append_reservation_v3(reservation)?
        }
    };
    Ok(PrivateOramMutationRejectedAdmissionV2 {
        version: REJECTED_ADMISSION_VERSION,
        lease: base_reservation.preparing_lease().clone(),
        attempt_id: base_reservation.attempt_id().to_string(),
        reservation_canonical_json,
        recovery_manifest_canonical_json,
        resolution_request_digest,
        admission_request_digest,
        outcome_key,
        rejected_from_aggregate_digest,
        rejection_applied,
        rejection_digest: String::new(),
    })
}

fn validate_append_reservation_capacity_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    reservation_canonical_json: &str,
    reservation: &PrivateOramMutationAppendReservationV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_append_reservation_capacity_with_gc_limit_v2(
        aggregate,
        reservation_canonical_json,
        reservation,
        MAX_OUTSTANDING_GC_OBLIGATION_BYTES,
    )
}

fn validate_append_reservation_capacity_with_gc_limit_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    reservation_canonical_json: &str,
    reservation: &PrivateOramMutationAppendReservationV2,
    maximum_gc_bytes: usize,
) -> Result<(), PrivateOramMutationJournalError> {
    let reserved_rejection = usize::try_from(reservation.reserved_rejection_bytes())
        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let reserved_cleanup = usize::try_from(reservation.reserved_cleanup_bytes())
        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let rejected_bytes = rejected_admissions_serialized_len_v2(&aggregate.rejected_admissions)?;
    let gc_bytes = gc_obligations_serialized_len_v2(&aggregate.outstanding_gc_obligations)?;
    let outcome_bytes = append_outcomes_serialized_len_v2(&aggregate.append_outcomes)?;
    let committed_bytes = serde_json::to_vec(aggregate)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        .len();
    let global_reserved = committed_bytes
        .checked_add(reservation_canonical_json.len())
        .and_then(|value| value.checked_add(reserved_rejection))
        .and_then(|value| value.checked_add(reserved_cleanup))
        .and_then(|value| value.checked_add(APPEND_RESERVATION_MANDATORY_HEADROOM_BYTES))
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if rejected_bytes
        .checked_add(reserved_rejection)
        .is_none_or(|bytes| bytes > MAX_REJECTED_ADMISSION_BYTES)
        || gc_bytes
            .checked_add(reserved_cleanup)
            .is_none_or(|bytes| bytes > maximum_gc_bytes)
        || outcome_bytes
            .checked_add(APPEND_RESERVATION_MANDATORY_HEADROOM_BYTES)
            .is_none_or(|bytes| bytes > MAX_APPEND_OUTCOME_BYTES)
        || global_reserved > MAX_AUTHORITY_WIRE_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_prepared_reservation_challenge_capacity_v3(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    challenge_canonical_json: &str,
    reservation: &PrivateOramMutationAppendReservationV2,
    maximum_gc_bytes: usize,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_append_reservation_capacity_with_gc_limit_v2(
        aggregate,
        challenge_canonical_json,
        reservation,
        maximum_gc_bytes,
    )?;
    let committed_bytes = serde_json::to_vec(aggregate)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        .len();
    if committed_bytes
        .checked_add(challenge_canonical_json.len())
        .and_then(|bytes| bytes.checked_add(APPEND_RESERVATION_V3_FINAL_WIRE_RESERVE_BYTES))
        .is_none_or(|bytes| bytes > MAX_AUTHORITY_WIRE_BYTES)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn project_gc_retention_for_reservation_v3(
    current: &PrivateOramMutationConsensusAggregateV2,
    challenge_canonical_json: &str,
    reservation: &PrivateOramMutationAppendReservationV2,
    maximum_gc_count: usize,
    maximum_gc_bytes: usize,
) -> Result<Vec<PrivateOramAcknowledgedGcObligationV2>, PrivateOramMutationJournalError> {
    require_complete_acknowledged_archive_history_v1(current)?;
    if maximum_gc_count == 0
        || maximum_gc_count > MAX_OUTSTANDING_GC_OBLIGATIONS
        || maximum_gc_bytes > MAX_OUTSTANDING_GC_OBLIGATION_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let available_gc_bytes = maximum_gc_bytes
        .checked_sub(
            usize::try_from(reservation.reserved_cleanup_bytes())
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
        )
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    // Reserve one entry for the predecessor transferred by the next admission. Search the
    // bounded suffix instead of repeatedly serializing and removing one large obligation.
    let mut removed = current
        .outstanding_gc_obligations
        .len()
        .saturating_sub(maximum_gc_count - 1);
    let mut upper = current.outstanding_gc_obligations.len();
    while removed < upper {
        let middle = removed + (upper - removed) / 2;
        if gc_obligations_serialized_len_v2(&current.outstanding_gc_obligations[middle..])?
            > available_gc_bytes
        {
            removed = middle + 1;
        } else {
            upper = middle;
        }
    }
    let mut projected = current.clone();
    projected.outstanding_gc_obligations.drain(..removed);
    projected.compacted_owner_archive_histories = advance_compacted_owner_archive_histories_v1(
        current,
        &projected.outstanding_gc_obligations,
        PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
        true,
    )?;
    // Count the proof metadata in every byte budget. The projected digest strings have the
    // same fixed encoded size; the actual transition recomputes them from the original state.
    if validate_prepared_reservation_challenge_capacity_v3(
        &projected,
        challenge_canonical_json,
        reservation,
        maximum_gc_bytes,
    )
    .is_err()
        && !projected.outstanding_gc_obligations.is_empty()
    {
        // The aggregate-wide budget can require more space than the dedicated GC budget.
        // Compact the remaining prefix in one bounded pass, then recheck every original cap.
        projected.outstanding_gc_obligations.clear();
        projected.compacted_owner_archive_histories = advance_compacted_owner_archive_histories_v1(
            current,
            &[],
            PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
            true,
        )?;
    }
    validate_prepared_reservation_challenge_capacity_v3(
        &projected,
        challenge_canonical_json,
        reservation,
        maximum_gc_bytes,
    )?;
    Ok(projected.outstanding_gc_obligations)
}

fn pending_reservation_challenge_v1(
    challenge: PrivateOramMutationPreparedReservationChallengeV3,
    challenge_canonical_json: String,
    pre_challenge_aggregate_digest: String,
    challenge_applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramMutationPendingReservationChallengeV1, PrivateOramMutationJournalError> {
    if encode_private_oram_mutation_prepared_reservation_challenge_v3(&challenge)?
        != challenge_canonical_json
        || challenge.base_reservation().expected_aggregate_digest()
            != pre_challenge_aggregate_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut pending = PrivateOramMutationPendingReservationChallengeV1 {
        version: PENDING_RESERVATION_CHALLENGE_VERSION,
        challenge_canonical_json,
        challenge_digest: challenge.prepared_challenge_digest().to_string(),
        reservation_intent_digest: challenge.reservation_intent().intent_digest().to_string(),
        attempt_id: challenge.base_reservation().attempt_id().to_string(),
        attempt_sequence: challenge.base_reservation().attempt_sequence(),
        pre_challenge_aggregate_digest,
        challenge_applied,
        prepared_ordinal: challenge.base_reservation().attempt_sequence(),
        pending_digest: String::new(),
    };
    pending.pending_digest = pending_reservation_challenge_digest_v1(&pending)?;
    validate_pending_reservation_challenge_v1(&pending)?;
    Ok(pending)
}

fn validate_pending_reservation_challenge_v1(
    pending: &PrivateOramMutationPendingReservationChallengeV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if pending.version != PENDING_RESERVATION_CHALLENGE_VERSION
        || pending.attempt_sequence == 0
        || pending.prepared_ordinal != pending.attempt_sequence
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &pending.challenge_digest,
        &pending.reservation_intent_digest,
        &pending.attempt_id,
        &pending.pre_challenge_aggregate_digest,
        &pending.pending_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_apply_locator_v2(&pending.challenge_applied)?;
    let challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
        &pending.challenge_canonical_json,
    )?;
    if challenge.prepared_challenge_digest() != pending.challenge_digest
        || challenge.reservation_intent().intent_digest() != pending.reservation_intent_digest
        || challenge.base_reservation().attempt_id() != pending.attempt_id
        || challenge.base_reservation().attempt_sequence() != pending.attempt_sequence
        || challenge.base_reservation().expected_aggregate_digest()
            != pending.pre_challenge_aggregate_digest
        || pending.pending_digest != pending_reservation_challenge_digest_v1(pending)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn pending_reservation_challenge_digest_v1(
    pending: &PrivateOramMutationPendingReservationChallengeV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PENDING_RESERVATION_CHALLENGE_DIGEST_DOMAIN_V1);
    hasher.update(pending.version.to_be_bytes());
    hash_digest(&mut hasher, &pending.challenge_digest)?;
    hash_digest(&mut hasher, &pending.reservation_intent_digest)?;
    hash_digest(&mut hasher, &pending.attempt_id)?;
    hasher.update(pending.attempt_sequence.to_be_bytes());
    hash_digest(&mut hasher, &pending.pre_challenge_aggregate_digest)?;
    hash_digest(
        &mut hasher,
        &pending.challenge_applied.consensus_history_id_digest,
    )?;
    hash_digest(&mut hasher, &pending.challenge_applied.raft_group_id_digest)?;
    hasher.update(pending.challenge_applied.term.to_be_bytes());
    hasher.update(pending.challenge_applied.index.to_be_bytes());
    hasher.update(pending.prepared_ordinal.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn reservation_challenge_outcome_v1(
    pending: &PrivateOramMutationPendingReservationChallengeV1,
    kind: PrivateOramMutationReservationChallengeOutcomeKindV1,
    resolution_request_digest: String,
    resolution_applied: PrivateOramRaftApplyLocatorV2,
    finalized_reservation_digest: Option<String>,
    finalized_reservation_canonical_json: Option<String>,
) -> Result<PrivateOramMutationReservationChallengeOutcomeV1, PrivateOramMutationJournalError> {
    let mut outcome = PrivateOramMutationReservationChallengeOutcomeV1 {
        version: RESERVATION_CHALLENGE_OUTCOME_VERSION_V3,
        kind,
        challenge_digest: pending.challenge_digest.clone(),
        challenge_applied: pending.challenge_applied.clone(),
        reservation_intent_digest: pending.reservation_intent_digest.clone(),
        attempt_id: pending.attempt_id.clone(),
        attempt_sequence: pending.attempt_sequence,
        resolution_request_digest,
        resolution_applied,
        finalized_reservation_digest,
        challenge_canonical_json: Some(pending.challenge_canonical_json.clone()),
        finalized_reservation_canonical_json,
        outcome_digest: String::new(),
    };
    outcome.outcome_digest = reservation_challenge_outcome_digest_v1(&outcome)?;
    validate_reservation_challenge_outcome_v1(&outcome)?;
    Ok(outcome)
}

fn validate_reservation_challenge_outcome_v1(
    outcome: &PrivateOramMutationReservationChallengeOutcomeV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if !matches!(
        outcome.version,
        RESERVATION_CHALLENGE_OUTCOME_VERSION_V1
            | RESERVATION_CHALLENGE_OUTCOME_VERSION_V2
            | RESERVATION_CHALLENGE_OUTCOME_VERSION_V3
    ) || outcome.attempt_sequence == 0
        || matches!(
            (&outcome.kind, &outcome.finalized_reservation_digest),
            (
                PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3,
                None
            ) | (
                PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled,
                Some(_)
            )
        )
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &outcome.challenge_digest,
        &outcome.reservation_intent_digest,
        &outcome.attempt_id,
        &outcome.resolution_request_digest,
        &outcome.outcome_digest,
    ] {
        validate_digest(digest)?;
    }
    if let Some(digest) = &outcome.finalized_reservation_digest {
        validate_digest(digest)?;
    }
    let challenge = match (outcome.version, outcome.challenge_canonical_json.as_deref()) {
        (RESERVATION_CHALLENGE_OUTCOME_VERSION_V1, None) => None,
        (
            RESERVATION_CHALLENGE_OUTCOME_VERSION_V2 | RESERVATION_CHALLENGE_OUTCOME_VERSION_V3,
            Some(canonical),
        ) => {
            let challenge =
                decode_private_oram_mutation_prepared_reservation_challenge_v3(canonical)?;
            if challenge.prepared_challenge_digest() != outcome.challenge_digest
                || challenge.reservation_intent().intent_digest()
                    != outcome.reservation_intent_digest
                || challenge.base_reservation().attempt_id() != outcome.attempt_id
                || challenge.base_reservation().attempt_sequence() != outcome.attempt_sequence
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
            Some(challenge)
        }
        _ => return Err(PrivateOramMutationJournalError::Corrupt),
    };
    match (
        outcome.version,
        outcome.kind,
        outcome.finalized_reservation_canonical_json.as_deref(),
    ) {
        (
            RESERVATION_CHALLENGE_OUTCOME_VERSION_V1 | RESERVATION_CHALLENGE_OUTCOME_VERSION_V2,
            _,
            None,
        )
        | (
            RESERVATION_CHALLENGE_OUTCOME_VERSION_V3,
            PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled,
            None,
        ) => {}
        (
            RESERVATION_CHALLENGE_OUTCOME_VERSION_V3,
            PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3,
            Some(canonical),
        ) => {
            let reservation = decode_private_oram_mutation_append_reservation_v3(canonical)?;
            let challenge = challenge.ok_or(PrivateOramMutationJournalError::Corrupt)?;
            if reservation.reservation_digest_v3()
                != outcome
                    .finalized_reservation_digest
                    .as_deref()
                    .ok_or(PrivateOramMutationJournalError::Corrupt)?
                || reservation.prepared_challenge() != &challenge
                || reservation.challenge_applied() != &outcome.challenge_applied
                || reservation.attempt_id() != outcome.attempt_id
                || reservation.attempt_sequence() != outcome.attempt_sequence
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
        }
        _ => return Err(PrivateOramMutationJournalError::Corrupt),
    }
    validate_apply_locator_v2(&outcome.challenge_applied)?;
    validate_apply_locator_v2(&outcome.resolution_applied)?;
    if !locator_is_strictly_after(&outcome.resolution_applied, &outcome.challenge_applied)
        || outcome.outcome_digest != reservation_challenge_outcome_digest_v1(outcome)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn reservation_challenge_outcome_digest_v1(
    outcome: &PrivateOramMutationReservationChallengeOutcomeV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_CHALLENGE_OUTCOME_DIGEST_DOMAIN_V1);
    hasher.update(outcome.version.to_be_bytes());
    hasher.update([match outcome.kind {
        PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3 => 1,
        PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled => 2,
    }]);
    hash_digest(&mut hasher, &outcome.challenge_digest)?;
    hash_digest(&mut hasher, &outcome.reservation_intent_digest)?;
    hash_digest(&mut hasher, &outcome.attempt_id)?;
    hasher.update(outcome.attempt_sequence.to_be_bytes());
    hash_digest(&mut hasher, &outcome.resolution_request_digest)?;
    hash_digest(
        &mut hasher,
        &outcome.challenge_applied.consensus_history_id_digest,
    )?;
    hash_digest(&mut hasher, &outcome.challenge_applied.raft_group_id_digest)?;
    hasher.update(outcome.challenge_applied.term.to_be_bytes());
    hasher.update(outcome.challenge_applied.index.to_be_bytes());
    hasher.update(outcome.resolution_applied.term.to_be_bytes());
    hasher.update(outcome.resolution_applied.index.to_be_bytes());
    match &outcome.finalized_reservation_digest {
        None => hasher.update([0]),
        Some(digest) => {
            hasher.update([1]);
            hash_digest(&mut hasher, digest)?;
        }
    }
    if outcome.version >= RESERVATION_CHALLENGE_OUTCOME_VERSION_V2 {
        hash_len_prefixed_bytes(
            &mut hasher,
            outcome
                .challenge_canonical_json
                .as_deref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?
                .as_bytes(),
        )?;
    }
    if outcome.version >= RESERVATION_CHALLENGE_OUTCOME_VERSION_V3 {
        match outcome.finalized_reservation_canonical_json.as_deref() {
            None => hasher.update([0]),
            Some(canonical) => {
                hasher.update([1]);
                hash_len_prefixed_bytes(&mut hasher, canonical.as_bytes())?;
            }
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_reservation_outcome_acknowledgement_v1(
    outcome_digest: String,
    mut owner_resolution_receipts: Vec<SignedPrivateOramOwnerReservationResolutionReceiptV1>,
) -> Result<PrivateOramMutationReservationOutcomeAcknowledgementV1, PrivateOramMutationJournalError>
{
    owner_resolution_receipts.sort_by_key(|receipt| receipt.receipt.owner_peer_id);
    let owner_resolution_receipts_canonical_json = owner_resolution_receipts
        .iter()
        .map(|receipt| {
            let encoded =
                encode_signed_private_oram_owner_reservation_resolution_receipt_v1(receipt)
                    .map_err(|_| {
                        PrivateOramMutationJournalError::InvalidInput("resolution_receipt")
                    })?;
            String::from_utf8(encoded)
                .map_err(|_| PrivateOramMutationJournalError::InvalidInput("resolution_receipt"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut acknowledgement = PrivateOramMutationReservationOutcomeAcknowledgementV1 {
        version: RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_VERSION,
        outcome_digest,
        owner_resolution_receipts_canonical_json,
        acknowledgement_digest: String::new(),
    };
    acknowledgement.acknowledgement_digest =
        reservation_challenge_outcome_acknowledgement_digest_v1(&acknowledgement)?;
    validate_reservation_challenge_outcome_acknowledgement_v1(&acknowledgement)?;
    Ok(acknowledgement)
}

pub(crate) fn encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
    acknowledgement: &PrivateOramMutationReservationOutcomeAcknowledgementV1,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_reservation_challenge_outcome_acknowledgement_v1(acknowledgement)?;
    let encoded = serde_json::to_string(acknowledgement)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > MAX_RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_outcome_acknowledgement",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
    encoded: &str,
) -> Result<PrivateOramMutationReservationOutcomeAcknowledgementV1, PrivateOramMutationJournalError>
{
    if encoded.is_empty() || encoded.len() > MAX_RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_outcome_acknowledgement",
        ));
    }
    let acknowledgement =
        serde_json::from_str(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_reservation_challenge_outcome_acknowledgement_v1(&acknowledgement)?;
    if serde_json::to_string(&acknowledgement)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_outcome_acknowledgement",
        ));
    }
    Ok(acknowledgement)
}

fn validate_reservation_challenge_outcome_acknowledgement_v1(
    acknowledgement: &PrivateOramMutationReservationOutcomeAcknowledgementV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if acknowledgement.version != RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_VERSION
        || acknowledgement
            .owner_resolution_receipts_canonical_json
            .is_empty()
        || acknowledgement
            .owner_resolution_receipts_canonical_json
            .len()
            > 1_024
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_digest(&acknowledgement.outcome_digest)?;
    validate_digest(&acknowledgement.acknowledgement_digest)?;
    let mut total_bytes = 0_usize;
    for encoded in &acknowledgement.owner_resolution_receipts_canonical_json {
        total_bytes = total_bytes
            .checked_add(encoded.len())
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let receipt =
            decode_signed_private_oram_owner_reservation_resolution_receipt_v1(encoded.as_bytes())
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if encode_signed_private_oram_owner_reservation_resolution_receipt_v1(&receipt)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            != encoded.as_bytes()
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if total_bytes > MAX_RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_BYTES
        || acknowledgement.acknowledgement_digest
            != reservation_challenge_outcome_acknowledgement_digest_v1(acknowledgement)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn reservation_challenge_outcome_acknowledgement_digest_v1(
    acknowledgement: &PrivateOramMutationReservationOutcomeAcknowledgementV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_CHALLENGE_OUTCOME_ACKNOWLEDGEMENT_DIGEST_DOMAIN_V1);
    hasher.update(acknowledgement.version.to_be_bytes());
    hash_digest(&mut hasher, &acknowledgement.outcome_digest)?;
    hasher.update(
        u64::try_from(
            acknowledgement
                .owner_resolution_receipts_canonical_json
                .len(),
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        .to_be_bytes(),
    );
    for receipt in &acknowledgement.owner_resolution_receipts_canonical_json {
        hash_len_prefixed_bytes(&mut hasher, receipt.as_bytes())?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn reservation_challenge_outcome_accumulator_v1(
    previous: Option<&PrivateOramMutationReservationOutcomeAccumulatorV1>,
    outcome: &PrivateOramMutationReservationChallengeOutcomeV1,
    acknowledgement: &PrivateOramMutationReservationOutcomeAcknowledgementV1,
    acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramMutationReservationOutcomeAccumulatorV1, PrivateOramMutationJournalError> {
    let compacted_outcome_count = previous.map_or(Ok(1), |previous| {
        previous
            .compacted_outcome_count
            .checked_add(1)
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)
    })?;
    let mut accumulator = PrivateOramMutationReservationOutcomeAccumulatorV1 {
        version: RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_VERSION,
        compacted_outcome_count,
        prior_accumulator_digest: previous.map(|value| value.accumulator_digest.clone()),
        last_challenge_digest: outcome.challenge_digest.clone(),
        last_attempt_sequence: outcome.attempt_sequence,
        last_resolution_applied: outcome.resolution_applied.clone(),
        last_acknowledgement_applied: acknowledgement_applied,
        last_outcome_digest: outcome.outcome_digest.clone(),
        last_acknowledgement_digest: acknowledgement.acknowledgement_digest.clone(),
        accumulator_digest: String::new(),
    };
    accumulator.accumulator_digest =
        reservation_challenge_outcome_accumulator_digest_v1(&accumulator)?;
    validate_reservation_challenge_outcome_accumulator_v1(&accumulator)?;
    Ok(accumulator)
}

fn validate_reservation_challenge_outcome_accumulator_v1(
    accumulator: &PrivateOramMutationReservationOutcomeAccumulatorV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if accumulator.version != RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_VERSION
        || accumulator.compacted_outcome_count == 0
        || accumulator.last_attempt_sequence == 0
        || (accumulator.compacted_outcome_count == 1)
            != accumulator.prior_accumulator_digest.is_none()
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &accumulator.last_challenge_digest,
        &accumulator.last_outcome_digest,
        &accumulator.last_acknowledgement_digest,
        &accumulator.accumulator_digest,
    ] {
        validate_digest(digest)?;
    }
    if let Some(digest) = &accumulator.prior_accumulator_digest {
        validate_digest(digest)?;
    }
    validate_apply_locator_v2(&accumulator.last_resolution_applied)?;
    validate_apply_locator_v2(&accumulator.last_acknowledgement_applied)?;
    if !locator_is_strictly_after(
        &accumulator.last_acknowledgement_applied,
        &accumulator.last_resolution_applied,
    ) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if accumulator.accumulator_digest
        != reservation_challenge_outcome_accumulator_digest_v1(accumulator)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn reservation_challenge_outcome_accumulator_digest_v1(
    accumulator: &PrivateOramMutationReservationOutcomeAccumulatorV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_DIGEST_DOMAIN_V1);
    hasher.update(accumulator.version.to_be_bytes());
    hasher.update(accumulator.compacted_outcome_count.to_be_bytes());
    match &accumulator.prior_accumulator_digest {
        None => hasher.update([0]),
        Some(digest) => {
            hasher.update([1]);
            hash_digest(&mut hasher, digest)?;
        }
    }
    hash_digest(&mut hasher, &accumulator.last_challenge_digest)?;
    hasher.update(accumulator.last_attempt_sequence.to_be_bytes());
    hash_digest(
        &mut hasher,
        &accumulator
            .last_resolution_applied
            .consensus_history_id_digest,
    )?;
    hash_digest(
        &mut hasher,
        &accumulator.last_resolution_applied.raft_group_id_digest,
    )?;
    hasher.update(accumulator.last_resolution_applied.term.to_be_bytes());
    hasher.update(accumulator.last_resolution_applied.index.to_be_bytes());
    hash_digest(
        &mut hasher,
        &accumulator
            .last_acknowledgement_applied
            .consensus_history_id_digest,
    )?;
    hash_digest(
        &mut hasher,
        &accumulator
            .last_acknowledgement_applied
            .raft_group_id_digest,
    )?;
    hasher.update(accumulator.last_acknowledgement_applied.term.to_be_bytes());
    hasher.update(accumulator.last_acknowledgement_applied.index.to_be_bytes());
    hash_digest(&mut hasher, &accumulator.last_outcome_digest)?;
    hash_digest(&mut hasher, &accumulator.last_acknowledgement_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_reservation_challenge_cancellation_v1(
    pending: &PrivateOramMutationPendingReservationChallengeV1,
    cancellation_operation_id: String,
) -> Result<PrivateOramMutationReservationChallengeCancellationV1, PrivateOramMutationJournalError>
{
    validate_pending_reservation_challenge_v1(pending)?;
    validate_digest(&cancellation_operation_id)?;
    let challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
        &pending.challenge_canonical_json,
    )?;
    let mut cancellation = PrivateOramMutationReservationChallengeCancellationV1 {
        version: RESERVATION_CHALLENGE_CANCELLATION_VERSION,
        collection_key_digest: private_oram_collection_id_digest_v2(
            challenge.base_reservation().collection_id(),
        )?,
        challenge_digest: pending.challenge_digest.clone(),
        reservation_intent_digest: pending.reservation_intent_digest.clone(),
        attempt_id: pending.attempt_id.clone(),
        attempt_sequence: pending.attempt_sequence,
        cancellation_operation_id,
        cancellation_digest: String::new(),
    };
    cancellation.cancellation_digest = reservation_challenge_cancellation_digest_v1(&cancellation)?;
    validate_reservation_challenge_cancellation_v1(&cancellation)?;
    Ok(cancellation)
}

pub(crate) fn encode_private_oram_mutation_reservation_challenge_cancellation_v1(
    cancellation: &PrivateOramMutationReservationChallengeCancellationV1,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_reservation_challenge_cancellation_v1(cancellation)?;
    let encoded = serde_json::to_string(cancellation)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > 64 * 1024 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_challenge_cancellation",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_reservation_challenge_cancellation_v1(
    encoded: &str,
) -> Result<PrivateOramMutationReservationChallengeCancellationV1, PrivateOramMutationJournalError>
{
    if encoded.is_empty() || encoded.len() > 64 * 1024 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_challenge_cancellation",
        ));
    }
    let cancellation: PrivateOramMutationReservationChallengeCancellationV1 =
        serde_json::from_str(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_reservation_challenge_cancellation_v1(&cancellation)?;
    if serde_json::to_string(&cancellation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_challenge_cancellation",
        ));
    }
    Ok(cancellation)
}

fn validate_reservation_challenge_cancellation_v1(
    cancellation: &PrivateOramMutationReservationChallengeCancellationV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if cancellation.version != RESERVATION_CHALLENGE_CANCELLATION_VERSION
        || cancellation.attempt_sequence == 0
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &cancellation.challenge_digest,
        &cancellation.collection_key_digest,
        &cancellation.reservation_intent_digest,
        &cancellation.attempt_id,
        &cancellation.cancellation_operation_id,
        &cancellation.cancellation_digest,
    ] {
        validate_digest(digest)?;
    }
    if cancellation.cancellation_digest
        != reservation_challenge_cancellation_digest_v1(cancellation)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn reservation_challenge_cancellation_digest_v1(
    cancellation: &PrivateOramMutationReservationChallengeCancellationV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_CHALLENGE_CANCELLATION_DIGEST_DOMAIN_V1);
    hasher.update(cancellation.version.to_be_bytes());
    hash_digest(&mut hasher, &cancellation.collection_key_digest)?;
    hash_digest(&mut hasher, &cancellation.challenge_digest)?;
    hash_digest(&mut hasher, &cancellation.reservation_intent_digest)?;
    hash_digest(&mut hasher, &cancellation.attempt_id)?;
    hasher.update(cancellation.attempt_sequence.to_be_bytes());
    hash_digest(&mut hasher, &cancellation.cancellation_operation_id)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

/// Drops the oldest retained rejections/outcomes until both histories fit their caps.
///
/// The histories only serve idempotent replay detection and audit; a collection must never
/// become unable to admit mutations because its bounded history filled up. Pruning happens
/// deterministically inside the apply path, so every peer keeps the same aggregate.
fn prune_append_history_to_capacity_v2(
    rejected: &mut Vec<PrivateOramMutationRejectedAdmissionV2>,
    outcomes: &mut Vec<PrivateOramMutationAppendOutcomeV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    while rejected.len() > MAX_REJECTED_ADMISSIONS
        || (!rejected.is_empty()
            && rejected_admissions_serialized_len_v2(rejected)? > MAX_REJECTED_ADMISSION_BYTES)
    {
        rejected.remove(0);
    }
    while outcomes.len() > MAX_APPEND_OUTCOMES
        || (!outcomes.is_empty()
            && append_outcomes_serialized_len_v2(outcomes)? > MAX_APPEND_OUTCOME_BYTES)
    {
        outcomes.remove(0);
    }
    validate_append_history_capacity_v2(rejected, outcomes)
}

fn validate_append_history_capacity_v2(
    rejected: &[PrivateOramMutationRejectedAdmissionV2],
    outcomes: &[PrivateOramMutationAppendOutcomeV2],
) -> Result<(), PrivateOramMutationJournalError> {
    if rejected.len() > MAX_REJECTED_ADMISSIONS
        || outcomes.len() > MAX_APPEND_OUTCOMES
        || rejected_admissions_serialized_len_v2(rejected)? > MAX_REJECTED_ADMISSION_BYTES
        || append_outcomes_serialized_len_v2(outcomes)? > MAX_APPEND_OUTCOME_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_reservation_challenge_outcome_history_capacity_v1(
    outcomes: &[PrivateOramMutationReservationChallengeOutcomeV1],
) -> Result<(), PrivateOramMutationJournalError> {
    if outcomes.len() > MAX_RESERVATION_CHALLENGE_OUTCOMES
        || reservation_challenge_outcomes_serialized_len_v1(outcomes)?
            > MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_reservation_challenge_outcome_reserve_v1(
    outcomes: &[PrivateOramMutationReservationChallengeOutcomeV1],
    pending: &PrivateOramMutationPendingReservationChallengeV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if outcomes.len() >= MAX_RESERVATION_CHALLENGE_OUTCOMES {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let reserve = PrivateOramMutationReservationChallengeOutcomeV1 {
        version: RESERVATION_CHALLENGE_OUTCOME_VERSION_V3,
        kind: PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3,
        challenge_digest: pending.challenge_digest.clone(),
        challenge_applied: pending.challenge_applied.clone(),
        reservation_intent_digest: pending.reservation_intent_digest.clone(),
        attempt_id: pending.attempt_id.clone(),
        attempt_sequence: pending.attempt_sequence,
        resolution_request_digest: pending.challenge_digest.clone(),
        resolution_applied: PrivateOramRaftApplyLocatorV2 {
            version: pending.challenge_applied.version,
            consensus_history_id_digest: pending
                .challenge_applied
                .consensus_history_id_digest
                .clone(),
            raft_group_id_digest: pending.challenge_applied.raft_group_id_digest.clone(),
            term: u64::MAX,
            index: u64::MAX,
        },
        finalized_reservation_digest: Some(pending.challenge_digest.clone()),
        challenge_canonical_json: Some(pending.challenge_canonical_json.clone()),
        finalized_reservation_canonical_json: None,
        outcome_digest: pending.challenge_digest.clone(),
    };
    let mut reserved = Vec::with_capacity(outcomes.len() + 1);
    reserved.extend_from_slice(outcomes);
    reserved.push(reserve);
    if reservation_challenge_outcomes_serialized_len_v1(&reserved)?
        .checked_add(APPEND_RESERVATION_V3_FINAL_WIRE_RESERVE_BYTES)
        .is_none_or(|reserved_bytes| reserved_bytes > MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn reservation_challenge_outcomes_serialized_len_v1(
    outcomes: &[PrivateOramMutationReservationChallengeOutcomeV1],
) -> Result<usize, PrivateOramMutationJournalError> {
    serde_json::to_vec(outcomes)
        .map(|bytes| bytes.len())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

fn validate_rejected_admission_v2(
    rejected: &PrivateOramMutationRejectedAdmissionV2,
    activation: &PrivateOramMutationActivationAnchorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if rejected.version != REJECTED_ADMISSION_VERSION
        || !matches!(
            rejected.lease.phase,
            PrivateOramMutationLeasePhase::Preparing
        )
        || rejected.lease.generation == 0
        || rejected.lease.writer_fence != rejected.lease.generation
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_lease_v2(&rejected.lease)?;
    validate_apply_locator_v2(&rejected.rejection_applied)?;
    for digest in [
        &rejected.attempt_id,
        &rejected.resolution_request_digest,
        &rejected.outcome_key,
        &rejected.rejected_from_aggregate_digest,
        &rejected.rejection_digest,
    ] {
        validate_digest(digest)?;
    }
    let reservation =
        decode_private_oram_mutation_append_reservation_wire(&rejected.reservation_canonical_json)?;
    let base_reservation = reservation.base_reservation();
    if private_oram_collection_id_digest_v2(&rejected.lease.collection_id)?
        != activation.authority_key.collection_key_digest
        || rejected.attempt_id != base_reservation.attempt_id()
        || rejected.lease != *base_reservation.preparing_lease()
        || rejected.outcome_key
            != append_outcome_key_from_parts_v2(
                &activation.collection_incarnation_digest,
                &rejected.attempt_id,
                &rejected.rejected_from_aggregate_digest,
                &rejected.resolution_request_digest,
            )?
        || !locator_is_strictly_after(&rejected.rejection_applied, &activation.activation_applied)
        || rejected.rejection_digest != rejected_admission_digest_v2(rejected)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    match (
        &rejected.recovery_manifest_canonical_json,
        &rejected.admission_request_digest,
    ) {
        (Some(encoded), Some(admission_request_digest)) => {
            let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(encoded)?;
            reservation.validate_manifest(&manifest)?;
            if rejected.resolution_request_digest != *admission_request_digest
                || *admission_request_digest
                    != private_oram_mutation_admission_request_digest_v2(
                        &rejected.lease,
                        manifest.manifest_digest(),
                    )?
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
        }
        (None, None) => {
            if rejected.resolution_request_digest
                != reservation.reserved_rejection_request_digest()?
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
        }
        _ => return Err(PrivateOramMutationJournalError::Corrupt),
    }
    Ok(())
}

fn validate_cleanup_target_v2(
    target: &PrivateOramMutationCleanupTargetV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if target.version != CLEANUP_TARGET_VERSION
        || target.storage_namespace_version != CLEANUP_STORAGE_NAMESPACE_VERSION
        || target.generation == 0
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_apply_locator_v2(&target.acknowledgement_applied)?;
    for digest in [
        &target.collection_key_digest,
        &target.collection_lifetime_id_digest,
        &target.collection_incarnation_digest,
        &target.activation_anchor_digest,
        &target.retired_outer_binding_digest,
        &target.logical_object_set_digest,
        &target.tombstone_digest,
        &target.target_digest,
    ] {
        validate_digest(digest)?;
    }
    if target.target_digest != cleanup_target_digest_v2(target)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_activation_context_v2(
    context: &PrivateOramMutationActivationContextV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_apply_locator_v2(&context.locator)?;
    validate_digest(&context.activation_request_digest)?;
    if context.compatibility_epoch == 0 {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_apply_context_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    context: &PrivateOramMutationAggregateApplyContextV2,
    expected_kind: PrivateOramMutationMaterialOperationV2,
    expected_request_digest: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_apply_locator_v2(&context.locator)?;
    validate_digest(&context.request_digest)?;
    validate_digest(&context.expected_aggregate_digest)?;
    validate_digest(&context.next_outer_binding_digest)?;
    if context.operation_kind != expected_kind
        || context.request_digest != expected_request_digest
        || context.locator.consensus_history_id_digest
            != aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
        || context.locator.raft_group_id_digest
            != aggregate.activation.authority_key.raft_group_id_digest
        || (matches!(
            context.operation_kind,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared
                | PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated
                | PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared
                | PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3
                | PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled
                | PrivateOramMutationMaterialOperationV2::AppendReservation
                | PrivateOramMutationMaterialOperationV2::AppendPrepared
                | PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected
                | PrivateOramMutationMaterialOperationV2::AdmissionRejected
                | PrivateOramMutationMaterialOperationV2::ParentProgress
                | PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady
                | PrivateOramMutationMaterialOperationV2::CleanupWitness
                | PrivateOramMutationMaterialOperationV2::ClearPending
                | PrivateOramMutationMaterialOperationV2::ClearAcknowledgement
        ) && context.next_outer_binding_digest != aggregate.outer_binding_digest)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_new_material_context_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    context: &PrivateOramMutationAggregateApplyContextV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if context.expected_aggregate_digest != aggregate.aggregate_digest
        || !locator_is_strictly_after(
            &context.locator,
            &aggregate.last_material_transition.locator,
        )
        || (aggregate.pending_reservation_challenge.is_some()
            && !matches!(
                context.operation_kind,
                PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3
                    | PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled
            ))
        || (aggregate.pending_reservation_challenge.is_none()
            && matches!(
                context.operation_kind,
                PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3
                    | PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled
            ))
        || (aggregate.active_append_attempt.is_some()
            && !matches!(
                context.operation_kind,
                PrivateOramMutationMaterialOperationV2::AppendPrepared
                    | PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected
                    | PrivateOramMutationMaterialOperationV2::Admission
                    | PrivateOramMutationMaterialOperationV2::AdmissionRejected
            ))
        || (aggregate.active_append_attempt.is_none()
            && matches!(
                context.operation_kind,
                PrivateOramMutationMaterialOperationV2::AppendPrepared
                    | PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected
            ))
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_retained_retry_locator_v2(
    retry: &PrivateOramRaftApplyLocatorV2,
    original: &PrivateOramRaftApplyLocatorV2,
    current_frontier: &PrivateOramRaftApplyLocatorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if retry == original || locator_is_strictly_after(retry, current_frontier) {
        Ok(())
    } else {
        Err(PrivateOramMutationJournalError::InvalidTransition)
    }
}

fn validate_lease_transition_v2(
    current: &PrivateOramMutationLease,
    new: &PrivateOramMutationLease,
    operation: PrivateOramMutationMaterialOperationV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_lease_v2(current)?;
    validate_lease_v2(new)?;
    if super::private_oram_mutation_lease_lineage_digest_v2(current)?
        != super::private_oram_mutation_lease_lineage_digest_v2(new)?
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    match operation {
        PrivateOramMutationMaterialOperationV2::Renewal => {
            if !matches!(current.phase, PrivateOramMutationLeasePhase::Preparing)
                || !matches!(new.phase, PrivateOramMutationLeasePhase::Preparing)
                || current.renewal_revision.checked_add(1) != Some(new.renewal_revision)
                || new.expires_at_unix <= current.expires_at_unix
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        PrivateOramMutationMaterialOperationV2::AbortDecision => {
            if !matches!(current.phase, PrivateOramMutationLeasePhase::Preparing)
                || !matches!(new.phase, PrivateOramMutationLeasePhase::AbortDecided)
                || current.renewal_revision != new.renewal_revision
                || current.expires_at_unix != new.expires_at_unix
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        PrivateOramMutationMaterialOperationV2::ConsensusCommit => {
            if !matches!(current.phase, PrivateOramMutationLeasePhase::Preparing)
                || !matches!(
                    new.phase,
                    PrivateOramMutationLeasePhase::ConsensusCommitted { .. }
                )
                || current.renewal_revision != new.renewal_revision
                || current.expires_at_unix != new.expires_at_unix
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    }
    Ok(())
}

fn retained_terminal_lease_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> Option<&PrivateOramMutationLease> {
    match lifecycle.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness)) => {
            Some(&witness.terminal_lease)
        }
        Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) => {
            Some(&pending.witness.terminal_lease)
        }
        _ => lifecycle
            .last_cleared
            .as_ref()
            .map(|cleared| &cleared.cleanup_witness.terminal_lease),
    }
}

fn current_generation_terminal_lease_v2<'a>(
    lifecycle: &'a PrivateOramMutationCleanupLifecycleV2,
    lease_slot: &'a PrivateOramMutationLeaseSlotV2,
) -> Option<&'a PrivateOramMutationLease> {
    if let Some(lease) = lease_slot.active.as_ref()
        && !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing)
    {
        return Some(lease);
    }
    match lifecycle.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness)) => {
            Some(&witness.terminal_lease)
        }
        Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) => {
            Some(&pending.witness.terminal_lease)
        }
        None => lifecycle
            .last_cleared
            .as_ref()
            .filter(|cleared| cleared.generation == lease_slot.generation)
            .map(|cleared| &cleared.cleanup_witness.terminal_lease),
        _ => None,
    }
}

fn terminal_certificate_matches_lease_v2(
    certificate: &PrivateOramMutationTerminalDecisionCertificateV2,
    lease: &PrivateOramMutationLease,
) -> Result<bool, PrivateOramMutationJournalError> {
    let operation_matches = matches!(
        (&certificate.operation_kind, &lease.phase),
        (
            PrivateOramMutationMaterialOperationV2::AbortDecision,
            PrivateOramMutationLeasePhase::AbortDecided,
        ) | (
            PrivateOramMutationMaterialOperationV2::ConsensusCommit,
            PrivateOramMutationLeasePhase::ConsensusCommitted { .. },
        )
    );
    Ok(operation_matches
        && certificate.generation == lease.generation
        && certificate.terminal_lease_state_digest
            == private_oram_mutation_lease_state_digest_v2(lease)?)
}

fn terminal_certificate_for_generation_v2<'a>(
    aggregate: &'a PrivateOramMutationConsensusAggregateV2,
    generation: u64,
) -> Option<&'a PrivateOramMutationTerminalDecisionCertificateV2> {
    aggregate
        .terminal_decision_certificate
        .as_ref()
        .filter(|certificate| certificate.generation == generation)
        .or_else(|| {
            aggregate
                .outstanding_gc_obligations
                .iter()
                .find(|obligation| obligation.generation == generation)
                .map(|obligation| &obligation.terminal_decision_certificate)
        })
}

fn validate_terminal_retry_certificate_v2(
    certificate: &PrivateOramMutationTerminalDecisionCertificateV2,
    lease: &PrivateOramMutationLease,
    context: &PrivateOramMutationAggregateApplyContextV2,
    request_digest: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    if certificate.operation_kind != context.operation_kind
        || certificate.request_digest != request_digest
        || !terminal_certificate_matches_lease_v2(certificate, lease)?
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn retained_parent_progress_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> Option<(
    &crate::content_manager::consensus::private_oram_mutation_watermark::PrivateOramMutationParentWatermarkV2,
    &[PrivateOramRaftApplyLocatorV2],
)>{
    match lifecycle.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::ParentProgress(progress)) => {
            Some((&progress.watermark, &progress.progress_applied_history))
        }
        Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness)) => Some((
            &witness.terminal_watermark,
            &witness.parent_progress_applied_history,
        )),
        Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) => Some((
            &pending.witness.terminal_watermark,
            &pending.witness.parent_progress_applied_history,
        )),
        _ => lifecycle.last_cleared.as_ref().map(|cleared| {
            (
                &cleared.terminal_watermark,
                cleared
                    .cleanup_witness
                    .parent_progress_applied_history
                    .as_slice(),
            )
        }),
    }
}

fn retained_cleanup_witness_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> Option<&super::PrivateOramMutationCleanupWitnessV2> {
    match lifecycle.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness)) => Some(witness),
        Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) => Some(&pending.witness),
        _ => lifecycle
            .last_cleared
            .as_ref()
            .map(|cleared| &cleared.cleanup_witness),
    }
}

fn retained_clear_pending_locator_v2<'a>(
    lifecycle: &'a PrivateOramMutationCleanupLifecycleV2,
    clear_attempt_id_digest: &str,
) -> Option<&'a PrivateOramRaftApplyLocatorV2> {
    match lifecycle.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending))
            if pending.clear_attempt_id_digest == clear_attempt_id_digest =>
        {
            Some(&pending.pending_applied)
        }
        _ => lifecycle.last_cleared.as_ref().and_then(|cleared| {
            (cleared.clear_attempt_id_digest == clear_attempt_id_digest)
                .then_some(&cleared.pending_applied)
        }),
    }
}

fn cleanup_applied_entry_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
    context: &PrivateOramMutationAggregateApplyContextV2,
    operation_kind: PrivateOramMutationCleanupOperationKindV2,
    payload_digest: &str,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    Ok(PrivateOramAppliedEntryV2 {
        locator: context.locator.clone(),
        operation_kind,
        operation_digest: applied_operation_digest_v2(
            operation_kind,
            &aggregate.lifecycle,
            Some(&aggregate.lease_slot),
            payload_digest,
        )?,
        _not_send_or_sync: PhantomData,
    })
}

fn lifecycle_frontier_locator_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> Option<&PrivateOramRaftApplyLocatorV2> {
    if let Some(active) = lifecycle.active.as_ref() {
        return Some(match active {
            PrivateOramMutationCleanupActiveV2::Admitted(admitted) => &admitted.admission_applied,
            PrivateOramMutationCleanupActiveV2::ParentProgress(progress) => {
                &progress.progress_applied
            }
            PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness) => {
                &witness.witness_applied
            }
            PrivateOramMutationCleanupActiveV2::ClearPending(pending) => &pending.pending_applied,
        });
    }
    let cleared = lifecycle.last_cleared.as_ref()?;
    Some(match &cleared.resolution {
        PrivateOramMutationClearResolutionV2::Pending => &cleared.clear_applied,
        PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) => {
            &acknowledged.acknowledgement_applied
        }
    })
}

fn legacy_slot_is_activation_quiescent(slot: &PrivateOramMutationLeaseSlotV2) -> bool {
    slot.generation == 0
        && slot.active.is_none()
        && slot.last_clear.is_none()
        && slot.max_writer_fence == 0
}

fn new_material_transition_receipt_v2(
    ordinal: u64,
    locator: PrivateOramRaftApplyLocatorV2,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    request_digest: String,
    prior_authority_digest: String,
    prior_outer_binding_digest: String,
    next_authority_core_digest: String,
    next_outer_binding_digest: String,
) -> Result<PrivateOramMaterialTransitionReceiptV2, PrivateOramMutationJournalError> {
    let mut receipt = PrivateOramMaterialTransitionReceiptV2 {
        version: MATERIAL_TRANSITION_RECEIPT_VERSION,
        ordinal,
        locator,
        operation_kind,
        request_digest,
        prior_authority_digest,
        prior_outer_binding_digest,
        next_authority_core_digest,
        next_outer_binding_digest,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = material_transition_receipt_digest_v2(&receipt)?;
    validate_material_transition_receipt_v2(&receipt)?;
    Ok(receipt)
}

fn new_terminal_decision_certificate_v2(
    generation: u64,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    locator: PrivateOramRaftApplyLocatorV2,
    terminal_lease_state_digest: String,
    recovery_capsules_certificate_digest: String,
    next_outer_binding_digest: String,
) -> Result<PrivateOramMutationTerminalDecisionCertificateV2, PrivateOramMutationJournalError> {
    let mut certificate = PrivateOramMutationTerminalDecisionCertificateV2 {
        version: TERMINAL_DECISION_CERTIFICATE_VERSION,
        generation,
        operation_kind,
        locator,
        request_digest: terminal_lease_state_digest.clone(),
        terminal_lease_state_digest,
        recovery_capsules_certificate_digest,
        next_outer_binding_digest,
        certificate_digest: String::new(),
    };
    certificate.certificate_digest = terminal_decision_certificate_digest_v2(&certificate)?;
    validate_terminal_decision_certificate_v2(&certificate)?;
    Ok(certificate)
}

fn new_recovery_capsules_certificate_v2(
    ready: PrivateOramMutationRecoveryCapsulesReadyV2,
    locator: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramMutationRecoveryCapsulesCertificateV2, PrivateOramMutationJournalError> {
    let mut certificate = PrivateOramMutationRecoveryCapsulesCertificateV2 {
        version: RECOVERY_CAPSULES_CERTIFICATE_VERSION,
        generation: ready.generation(),
        ready,
        locator,
        certificate_digest: String::new(),
    };
    certificate.certificate_digest = recovery_capsules_certificate_digest_v2(&certificate)?;
    validate_recovery_capsules_certificate_v2(&certificate)?;
    Ok(certificate)
}

fn authority_key_digest_v2(
    authority_key: &PrivateOramMutationAuthorityKeyV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_KEY_DIGEST_DOMAIN_V2);
    hasher.update(authority_key.version.to_be_bytes());
    hash_digest(&mut hasher, &authority_key.consensus_history_id_digest)?;
    hash_digest(&mut hasher, &authority_key.raft_group_id_digest)?;
    hash_digest(&mut hasher, &authority_key.collection_lifetime_id_digest)?;
    hash_digest(&mut hasher, &authority_key.collection_key_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn legacy_authority_digest_v2(
    legacy: &PrivateOramMutationLegacyAuthorityV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_AUTHORITY_DIGEST_DOMAIN_V2);
    hasher.update(legacy.version.to_be_bytes());
    hash_digest(&mut hasher, &legacy.authority_key.key_digest)?;
    hash_digest(
        &mut hasher,
        &private_oram_mutation_lease_slot_digest_v2(&legacy.exact_legacy_slot)?,
    )?;
    hash_digest(&mut hasher, &legacy.outer_binding_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn collection_incarnation_digest_v2(
    authority_key: &PrivateOramMutationAuthorityKeyV2,
    activation_applied: &PrivateOramRaftApplyLocatorV2,
    preactivation_authority_digest: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(COLLECTION_INCARNATION_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &authority_key.key_digest)?;
    hash_digest(&mut hasher, &authority_key.collection_lifetime_id_digest)?;
    super::hash_apply_locator(&mut hasher, activation_applied)?;
    hash_digest(&mut hasher, preactivation_authority_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn activation_anchor_digest_v2(
    activation: &PrivateOramMutationActivationAnchorV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(ACTIVATION_ANCHOR_DIGEST_DOMAIN_V2);
    hasher.update(activation.version.to_be_bytes());
    hasher.update(activation.compatibility_epoch.to_be_bytes());
    hash_digest(&mut hasher, &activation.authority_key.key_digest)?;
    hash_digest(&mut hasher, &activation.collection_incarnation_digest)?;
    super::hash_apply_locator(&mut hasher, &activation.activation_applied)?;
    hash_digest(&mut hasher, &activation.preactivation_authority_digest)?;
    hash_digest(&mut hasher, &activation.preactivation_outer_binding_digest)?;
    hash_digest(&mut hasher, &activation.activation_request_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn material_transition_receipt_digest_v2(
    receipt: &PrivateOramMaterialTransitionReceiptV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(MATERIAL_TRANSITION_RECEIPT_DIGEST_DOMAIN_V2);
    hasher.update(receipt.version.to_be_bytes());
    hasher.update(receipt.ordinal.to_be_bytes());
    super::hash_apply_locator(&mut hasher, &receipt.locator)?;
    hasher.update([material_operation_tag(receipt.operation_kind)]);
    hash_digest(&mut hasher, &receipt.request_digest)?;
    hash_digest(&mut hasher, &receipt.prior_authority_digest)?;
    hash_digest(&mut hasher, &receipt.prior_outer_binding_digest)?;
    hash_digest(&mut hasher, &receipt.next_authority_core_digest)?;
    hash_digest(&mut hasher, &receipt.next_outer_binding_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn terminal_decision_certificate_digest_v2(
    certificate: &PrivateOramMutationTerminalDecisionCertificateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_DECISION_CERTIFICATE_DIGEST_DOMAIN_V2);
    hasher.update(certificate.version.to_be_bytes());
    hasher.update(certificate.generation.to_be_bytes());
    hasher.update([material_operation_tag(certificate.operation_kind)]);
    super::hash_apply_locator(&mut hasher, &certificate.locator)?;
    hash_digest(&mut hasher, &certificate.request_digest)?;
    hash_digest(&mut hasher, &certificate.terminal_lease_state_digest)?;
    hash_digest(
        &mut hasher,
        &certificate.recovery_capsules_certificate_digest,
    )?;
    hash_digest(&mut hasher, &certificate.next_outer_binding_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn recovery_capsules_certificate_digest_v2(
    certificate: &PrivateOramMutationRecoveryCapsulesCertificateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_CAPSULES_CERTIFICATE_DIGEST_DOMAIN_V2);
    hasher.update(certificate.version.to_be_bytes());
    hasher.update(certificate.generation.to_be_bytes());
    hash_digest(&mut hasher, certificate.ready.ready_digest())?;
    super::hash_apply_locator(&mut hasher, &certificate.locator)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn cleanup_target_digest_v2(
    target: &PrivateOramMutationCleanupTargetV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEANUP_TARGET_DIGEST_DOMAIN_V2);
    hasher.update(target.version.to_be_bytes());
    hasher.update(target.storage_namespace_version.to_be_bytes());
    hash_digest(&mut hasher, &target.collection_key_digest)?;
    hash_digest(&mut hasher, &target.collection_lifetime_id_digest)?;
    hash_digest(&mut hasher, &target.collection_incarnation_digest)?;
    hash_digest(&mut hasher, &target.activation_anchor_digest)?;
    hasher.update(target.generation.to_be_bytes());
    hash_digest(&mut hasher, &target.retired_outer_binding_digest)?;
    hash_digest(&mut hasher, &target.logical_object_set_digest)?;
    hash_digest(&mut hasher, &target.tombstone_digest)?;
    super::hash_apply_locator(&mut hasher, &target.acknowledgement_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn cleanup_logical_object_set_digest_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEANUP_LOGICAL_OBJECT_SET_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &cleared.descriptor_digest)?;
    hash_digest(&mut hasher, &cleared.terminal_record_digest)?;
    hash_digest(
        &mut hasher,
        &cleared.cleanup_witness.owner_cleanup_evidence_digest,
    )?;
    hash_digest(
        &mut hasher,
        &cleared.cleanup_witness.point_cleanup_evidence_digest,
    )?;
    hash_digest(&mut hasher, &cleared.witness_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn gc_obligations_serialized_len_v2(
    obligations: &[PrivateOramAcknowledgedGcObligationV2],
) -> Result<usize, PrivateOramMutationJournalError> {
    serde_cbor::to_vec(&obligations)
        .map(|encoded| encoded.len())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

fn rejected_admissions_serialized_len_v2(
    rejected: &[PrivateOramMutationRejectedAdmissionV2],
) -> Result<usize, PrivateOramMutationJournalError> {
    serde_cbor::to_vec(&rejected)
        .map(|encoded| encoded.len())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

fn append_outcomes_serialized_len_v2(
    outcomes: &[PrivateOramMutationAppendOutcomeV2],
) -> Result<usize, PrivateOramMutationJournalError> {
    serde_cbor::to_vec(&outcomes)
        .map(|encoded| encoded.len())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

fn prepared_append_digest_v2(
    prepared: &PrivateOramMutationPreparedAppendV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_APPEND_DIGEST_DOMAIN_V2);
    hasher.update(prepared.version.to_be_bytes());
    hash_len_prefixed_bytes(
        &mut hasher,
        prepared.recovery_manifest_canonical_json.as_bytes(),
    )?;
    hash_digest(&mut hasher, &prepared.prepare_request_digest)?;
    hash_digest(&mut hasher, &prepared.admission_request_digest)?;
    super::hash_apply_locator(&mut hasher, &prepared.prepared_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn active_append_attempt_digest_v2(
    active: &PrivateOramMutationActiveAppendAttemptV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(ACTIVE_APPEND_ATTEMPT_DIGEST_DOMAIN_V2);
    hasher.update(active.version.to_be_bytes());
    hash_len_prefixed_bytes(&mut hasher, active.reservation_canonical_json.as_bytes())?;
    hash_digest(&mut hasher, &active.reservation_request_digest)?;
    super::hash_apply_locator(&mut hasher, &active.reservation_applied)?;
    match &active.prepared {
        None => hasher.update([0]),
        Some(prepared) => {
            hasher.update([1]);
            hash_digest(&mut hasher, &prepared.prepared_digest)?;
        }
    }
    if active.version == ACTIVE_APPEND_ATTEMPT_VERSION_V3 {
        let transition = active
            .checkpoint_lease_transition
            .as_ref()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        hash_digest(&mut hasher, &transition.transition_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn private_oram_owner_checkpoint_lease_transition_v1(
    prelease: &PrivateOramOwnerCheckpointTableV1,
    postlease: &PrivateOramOwnerCheckpointTableV1,
    reservation_context_digest: &str,
    reservation_digest: &str,
) -> Result<PrivateOramOwnerCheckpointLeaseTransitionV1, PrivateOramMutationJournalError> {
    let mut transition = PrivateOramOwnerCheckpointLeaseTransitionV1 {
        version: OWNER_CHECKPOINT_LEASE_TRANSITION_VERSION,
        prelease_table_sequence: prelease.table_sequence(),
        prelease_table_digest: prelease.table_digest().to_string(),
        postlease_table_sequence: postlease.table_sequence(),
        postlease_table_digest: postlease.table_digest().to_string(),
        owner_checkpoint_roster_digest: prelease.owner_roster_digest().to_string(),
        reservation_context_digest: reservation_context_digest.to_string(),
        reservation_digest: reservation_digest.to_string(),
        transition_digest: String::new(),
    };
    if prelease.owner_roster_digest() != postlease.owner_roster_digest()
        || transition.postlease_table_sequence
            != transition
                .prelease_table_sequence
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    transition.transition_digest = owner_checkpoint_lease_transition_digest_v1(&transition)?;
    validate_private_oram_owner_checkpoint_lease_transition_v1(&transition)?;
    Ok(transition)
}

fn validate_private_oram_owner_checkpoint_lease_transition_v1(
    transition: &PrivateOramOwnerCheckpointLeaseTransitionV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if transition.version != OWNER_CHECKPOINT_LEASE_TRANSITION_VERSION
        || transition.prelease_table_sequence == 0
        || transition.postlease_table_sequence
            != transition
                .prelease_table_sequence
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::Corrupt)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &transition.prelease_table_digest,
        &transition.postlease_table_digest,
        &transition.owner_checkpoint_roster_digest,
        &transition.reservation_context_digest,
        &transition.reservation_digest,
        &transition.transition_digest,
    ] {
        validate_digest(digest)?;
    }
    if transition.transition_digest != owner_checkpoint_lease_transition_digest_v1(transition)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn owner_checkpoint_lease_transition_digest_v1(
    transition: &PrivateOramOwnerCheckpointLeaseTransitionV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_CHECKPOINT_LEASE_TRANSITION_DIGEST_DOMAIN_V1);
    hasher.update(transition.version.to_be_bytes());
    hasher.update(transition.prelease_table_sequence.to_be_bytes());
    hash_digest(&mut hasher, &transition.prelease_table_digest)?;
    hasher.update(transition.postlease_table_sequence.to_be_bytes());
    hash_digest(&mut hasher, &transition.postlease_table_digest)?;
    hash_digest(&mut hasher, &transition.owner_checkpoint_roster_digest)?;
    hash_digest(&mut hasher, &transition.reservation_context_digest)?;
    hash_digest(&mut hasher, &transition.reservation_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_outcome_key_from_parts_v2(
    collection_incarnation_digest: &str,
    attempt_id: &str,
    resolved_from_aggregate_digest: &str,
    resolution_request_digest: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(APPEND_OUTCOME_KEY_DOMAIN_V2);
    hash_digest(&mut hasher, collection_incarnation_digest)?;
    hash_digest(&mut hasher, attempt_id)?;
    hash_digest(&mut hasher, resolved_from_aggregate_digest)?;
    hash_digest(&mut hasher, resolution_request_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn append_outcome_key_v2(
    outcome: &PrivateOramMutationAppendOutcomeV2,
) -> Result<String, PrivateOramMutationJournalError> {
    append_outcome_key_from_parts_v2(
        &outcome.collection_incarnation_digest,
        &outcome.attempt_id,
        &outcome.resolved_from_aggregate_digest,
        &outcome.resolution_request_digest,
    )
}

fn append_outcome_digest_v2(
    outcome: &PrivateOramMutationAppendOutcomeV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(APPEND_OUTCOME_DIGEST_DOMAIN_V2);
    hasher.update(outcome.version.to_be_bytes());
    hasher.update([match outcome.kind {
        PrivateOramMutationAppendOutcomeKindV2::Admitted => 1,
        PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected => 2,
        PrivateOramMutationAppendOutcomeKindV2::PrestageAborted => 3,
    }]);
    for digest in [
        &outcome.outcome_key,
        &outcome.protocol_capability_digest,
        &outcome.collection_incarnation_digest,
        &outcome.attempt_id,
        &outcome.mutation_id,
        &outcome.preparing_lease_state_digest,
        &outcome.resolved_from_aggregate_digest,
        &outcome.resolution_request_digest,
    ] {
        hash_digest(&mut hasher, digest)?;
    }
    hash_optional_digest(&mut hasher, outcome.admission_request_digest.as_deref())?;
    hash_optional_digest(&mut hasher, outcome.manifest_digest.as_deref())?;
    hash_digest(&mut hasher, &outcome.owner_roster_digest)?;
    super::hash_apply_locator(&mut hasher, &outcome.resolution_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn gc_obligation_digest_v2(
    obligation: &PrivateOramAcknowledgedGcObligationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(GC_OBLIGATION_DIGEST_DOMAIN_V2);
    hasher.update(obligation.version.to_be_bytes());
    hash_digest(&mut hasher, &obligation.collection_key_digest)?;
    hash_digest(&mut hasher, &obligation.collection_incarnation_digest)?;
    hasher.update(obligation.generation.to_be_bytes());
    hash_digest(
        &mut hasher,
        &obligation.terminal_decision_certificate.certificate_digest,
    )?;
    hash_digest(
        &mut hasher,
        &obligation.acknowledged_tombstone.tombstone_digest,
    )?;
    hash_digest(&mut hasher, &obligation.cleanup_target.target_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn rejected_admission_digest_v2(
    rejected: &PrivateOramMutationRejectedAdmissionV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(REJECTED_ADMISSION_DIGEST_DOMAIN_V2);
    hasher.update(rejected.version.to_be_bytes());
    hash_digest(
        &mut hasher,
        &private_oram_mutation_lease_state_digest_v2(&rejected.lease)?,
    )?;
    hash_digest(&mut hasher, &rejected.attempt_id)?;
    hash_len_prefixed_bytes(&mut hasher, rejected.reservation_canonical_json.as_bytes())?;
    match &rejected.recovery_manifest_canonical_json {
        None => hasher.update([0]),
        Some(manifest) => {
            hasher.update([1]);
            hash_len_prefixed_bytes(&mut hasher, manifest.as_bytes())?;
        }
    }
    hash_digest(&mut hasher, &rejected.resolution_request_digest)?;
    hash_optional_digest(&mut hasher, rejected.admission_request_digest.as_deref())?;
    hash_digest(&mut hasher, &rejected.outcome_key)?;
    hash_digest(&mut hasher, &rejected.rejected_from_aggregate_digest)?;
    super::hash_apply_locator(&mut hasher, &rejected.rejection_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_optional_digest(
    hasher: &mut Sha256,
    value: Option<&str>,
) -> Result<(), PrivateOramMutationJournalError> {
    match value {
        None => hasher.update([0]),
        Some(value) => {
            hasher.update([1]);
            hash_digest(hasher, value)?;
        }
    }
    Ok(())
}

fn hash_len_prefixed_bytes(
    hasher: &mut Sha256,
    value: &[u8],
) -> Result<(), PrivateOramMutationJournalError> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(value);
    Ok(())
}

fn aggregate_digest_v2(
    aggregate: &PrivateOramMutationConsensusAggregateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(AGGREGATE_DIGEST_DOMAIN_V2);
    hasher.update(aggregate.version.to_be_bytes());
    hash_digest(&mut hasher, &aggregate.authority_core_digest)?;
    hasher.update(aggregate.transition_ordinal.to_be_bytes());
    hash_digest(
        &mut hasher,
        &aggregate.last_material_transition.receipt_digest,
    )?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn aggregate_core_digest_from_parts_v2(
    aggregate_version: u16,
    activation: &PrivateOramMutationActivationAnchorV2,
    outer_binding_digest: &str,
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    lease_slot: &PrivateOramMutationLeaseSlotV2,
    recovery_capsules_certificate: Option<&PrivateOramMutationRecoveryCapsulesCertificateV2>,
    terminal_decision_certificate: Option<&PrivateOramMutationTerminalDecisionCertificateV2>,
    outstanding_gc_obligations: &[PrivateOramAcknowledgedGcObligationV2],
    rejected_admissions: &[PrivateOramMutationRejectedAdmissionV2],
    active_append_attempt: Option<&PrivateOramMutationActiveAppendAttemptV2>,
    append_outcomes: &[PrivateOramMutationAppendOutcomeV2],
    owner_checkpoint_table: &PrivateOramOwnerCheckpointTableV1,
    pending_reservation_challenge: Option<&PrivateOramMutationPendingReservationChallengeV1>,
    reservation_challenge_outcomes: &[PrivateOramMutationReservationChallengeOutcomeV1],
    reservation_challenge_outcome_accumulator: Option<
        &PrivateOramMutationReservationOutcomeAccumulatorV1,
    >,
    compacted_owner_archive_histories: &[PrivateOramOwnerCompactedArchiveHistoryV1],
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(AGGREGATE_CORE_DIGEST_DOMAIN_V2);
    hasher.update(aggregate_version.to_be_bytes());
    hash_digest(&mut hasher, &activation.anchor_digest)?;
    hash_digest(&mut hasher, outer_binding_digest)?;
    hash_digest(&mut hasher, lifecycle.lifecycle_digest())?;
    hasher.update([1]);
    hash_digest(
        &mut hasher,
        &private_oram_mutation_lease_slot_digest_v2(lease_slot)?,
    )?;
    match recovery_capsules_certificate {
        None => hasher.update([0]),
        Some(certificate) => {
            hasher.update([1]);
            hash_digest(&mut hasher, &certificate.certificate_digest)?;
        }
    }
    match terminal_decision_certificate {
        None => hasher.update([0]),
        Some(certificate) => {
            hasher.update([1]);
            hash_digest(&mut hasher, &certificate.certificate_digest)?;
        }
    }
    hasher.update((outstanding_gc_obligations.len() as u64).to_be_bytes());
    for obligation in outstanding_gc_obligations {
        hash_digest(&mut hasher, &obligation.obligation_digest)?;
    }
    hasher.update((rejected_admissions.len() as u64).to_be_bytes());
    for rejected in rejected_admissions {
        hash_digest(&mut hasher, &rejected.rejection_digest)?;
    }
    match active_append_attempt {
        None => hasher.update([0]),
        Some(attempt) => {
            hasher.update([1]);
            hash_digest(&mut hasher, &attempt.attempt_digest)?;
        }
    }
    hasher.update((append_outcomes.len() as u64).to_be_bytes());
    for outcome in append_outcomes {
        hash_digest(&mut hasher, &outcome.outcome_digest)?;
    }
    hash_len_prefixed_bytes(&mut hasher, OWNER_CHECKPOINT_COMPONENT_TAG_V1)?;
    hash_digest(&mut hasher, owner_checkpoint_table.table_digest())?;
    if aggregate_version >= AGGREGATE_VERSION_V7 {
        hash_len_prefixed_bytes(&mut hasher, RESERVATION_CHALLENGE_COMPONENT_TAG_V1)?;
        match pending_reservation_challenge {
            None => hasher.update([0]),
            Some(pending) => {
                hasher.update([1]);
                hash_digest(&mut hasher, &pending.pending_digest)?;
            }
        }
        hasher.update(
            u64::try_from(reservation_challenge_outcomes.len())
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
                .to_be_bytes(),
        );
        for outcome in reservation_challenge_outcomes {
            hash_digest(&mut hasher, &outcome.outcome_digest)?;
        }
        if let Some(accumulator) = reservation_challenge_outcome_accumulator {
            hash_len_prefixed_bytes(
                &mut hasher,
                RESERVATION_CHALLENGE_OUTCOME_ACCUMULATOR_COMPONENT_TAG_V1,
            )?;
            hash_digest(&mut hasher, &accumulator.accumulator_digest)?;
        }
    }
    // Empty history preserves old aggregate digests. Present metadata is fully committed so a
    // snapshot cannot change the owner, count, or floor while retaining the same chain root.
    if !compacted_owner_archive_histories.is_empty() {
        hash_len_prefixed_bytes(&mut hasher, OWNER_ARCHIVE_HISTORY_COMPONENT_TAG_V1)?;
        hasher.update((compacted_owner_archive_histories.len() as u64).to_be_bytes());
        for history in compacted_owner_archive_histories {
            hash_digest(
                &mut hasher,
                &history
                    .commitment_digest()
                    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
            )?;
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn material_operation_tag(operation: PrivateOramMutationMaterialOperationV2) -> u8 {
    match operation {
        PrivateOramMutationMaterialOperationV2::Activation => 1,
        PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared => 16,
        PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated => 17,
        PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared => 18,
        PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3 => 19,
        PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled => 20,
        PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged => 21,
        PrivateOramMutationMaterialOperationV2::AppendReservation => 13,
        PrivateOramMutationMaterialOperationV2::AppendPrepared => 14,
        PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected => 15,
        PrivateOramMutationMaterialOperationV2::Admission => 2,
        PrivateOramMutationMaterialOperationV2::AdmissionRejected => 12,
        PrivateOramMutationMaterialOperationV2::Renewal => 3,
        PrivateOramMutationMaterialOperationV2::AbortDecision => 4,
        PrivateOramMutationMaterialOperationV2::ConsensusCommit => 5,
        PrivateOramMutationMaterialOperationV2::ParentProgress => 6,
        PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady => 11,
        PrivateOramMutationMaterialOperationV2::CleanupWitness => 7,
        PrivateOramMutationMaterialOperationV2::ClearPending => 8,
        PrivateOramMutationMaterialOperationV2::Clear => 9,
        PrivateOramMutationMaterialOperationV2::ClearAcknowledgement => 10,
    }
}

fn hash_digest(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(decoded);
    Ok(())
}

/// Creates apply authority from the actual committed Raft entry. The serialized operation carries
/// only its expected aggregate digest and semantic payload; callers cannot supply the locator.
pub(crate) fn private_oram_mutation_aggregate_apply_context_v2(
    current: &PrivateOramMutationAuthorityStateV2,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    request_digest: String,
    expected_aggregate_digest: String,
    next_outer_binding_digest: String,
    term: u64,
    index: u64,
) -> Result<PrivateOramMutationAggregateApplyContextV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let context = PrivateOramMutationAggregateApplyContextV2 {
        locator: PrivateOramRaftApplyLocatorV2 {
            version: super::APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
                .clone(),
            raft_group_id_digest: aggregate
                .activation
                .authority_key
                .raft_group_id_digest
                .clone(),
            term,
            index,
        },
        operation_kind,
        request_digest,
        expected_aggregate_digest,
        next_outer_binding_digest,
        retain_compacted_owner_archive_history: false,
        _not_send_or_sync: PhantomData,
    };
    validate_apply_locator_v2(&context.locator)?;
    validate_digest(&context.request_digest)?;
    validate_digest(&context.expected_aggregate_digest)?;
    validate_digest(&context.next_outer_binding_digest)?;
    Ok(context)
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_activation_context_for_test(
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    term: u64,
    index: u64,
    compatibility_epoch: u64,
    activation_request_digest: String,
) -> Result<PrivateOramMutationActivationContextV2, PrivateOramMutationJournalError> {
    let context = PrivateOramMutationActivationContextV2 {
        locator: PrivateOramRaftApplyLocatorV2 {
            version: super::APPLY_LOCATOR_VERSION,
            consensus_history_id_digest,
            raft_group_id_digest,
            term,
            index,
        },
        compatibility_epoch,
        activation_request_digest,
        _not_send_or_sync: PhantomData,
    };
    validate_activation_context_v2(&context)?;
    Ok(context)
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_aggregate_apply_context_for_test(
    current: &PrivateOramMutationAuthorityStateV2,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    request_digest: String,
    term: u64,
    index: u64,
) -> Result<PrivateOramMutationAggregateApplyContextV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let retained = match operation_kind {
        PrivateOramMutationMaterialOperationV2::Admission => {
            aggregate
                .lifecycle
                .active
                .as_ref()
                .map(active_admitted)
                .is_some_and(|admitted| admitted.admission_request_digest == request_digest)
                || aggregate.append_outcomes.iter().any(|outcome| {
                    outcome.kind == PrivateOramMutationAppendOutcomeKindV2::Admitted
                        && outcome.admission_request_digest.as_deref()
                            == Some(request_digest.as_str())
                })
        }
        PrivateOramMutationMaterialOperationV2::AdmissionRejected => {
            aggregate.rejected_admissions.iter().any(|rejected| {
                rejected.admission_request_digest.as_deref() == Some(request_digest.as_str())
            }) || aggregate.append_outcomes.iter().any(|outcome| {
                outcome.kind == PrivateOramMutationAppendOutcomeKindV2::AdmissionRejected
                    && outcome.admission_request_digest.as_deref() == Some(request_digest.as_str())
            })
        }
        PrivateOramMutationMaterialOperationV2::Renewal
        | PrivateOramMutationMaterialOperationV2::AbortDecision
        | PrivateOramMutationMaterialOperationV2::ConsensusCommit => {
            aggregate.lease_slot.active.as_ref().is_some_and(|lease| {
                private_oram_mutation_lease_state_digest_v2(lease)
                    .is_ok_and(|digest| digest == request_digest)
            }) || retained_terminal_lease_v2(&aggregate.lifecycle).is_some_and(|lease| {
                private_oram_mutation_lease_state_digest_v2(lease)
                    .is_ok_and(|digest| digest == request_digest)
            })
        }
        PrivateOramMutationMaterialOperationV2::Clear => aggregate
            .lifecycle
            .last_cleared
            .as_ref()
            .is_some_and(|cleared| cleared.clear_pending_digest == request_digest),
        _ => true,
    };
    let next_outer_binding_digest = if retained {
        aggregate.outer_binding_digest.clone()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(b"qdrant-sec/private-oram-test-next-outer-binding/v2");
        hash_digest(&mut hasher, &aggregate.outer_binding_digest)?;
        hasher.update([material_operation_tag(operation_kind)]);
        hash_digest(&mut hasher, &request_digest)?;
        BASE64URL_NOPAD.encode(&hasher.finalize())
    };
    private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
        current,
        operation_kind,
        request_digest,
        next_outer_binding_digest,
        term,
        index,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
    current: &PrivateOramMutationAuthorityStateV2,
    operation_kind: PrivateOramMutationMaterialOperationV2,
    request_digest: String,
    next_outer_binding_digest: String,
    term: u64,
    index: u64,
) -> Result<PrivateOramMutationAggregateApplyContextV2, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    let context = PrivateOramMutationAggregateApplyContextV2 {
        locator: PrivateOramRaftApplyLocatorV2 {
            version: super::APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: aggregate
                .activation
                .activation_applied
                .consensus_history_id_digest
                .clone(),
            raft_group_id_digest: aggregate
                .activation
                .activation_applied
                .raft_group_id_digest
                .clone(),
            term,
            index,
        },
        operation_kind,
        request_digest,
        expected_aggregate_digest: aggregate.aggregate_digest.clone(),
        next_outer_binding_digest,
        retain_compacted_owner_archive_history: false,
        _not_send_or_sync: PhantomData,
    };
    validate_apply_locator_v2(&context.locator)?;
    Ok(context)
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_authority_request_digest_for_lease_for_test(
    lease: &PrivateOramMutationLease,
) -> Result<String, PrivateOramMutationJournalError> {
    private_oram_mutation_lease_state_digest_v2(lease)
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_authority_request_digest_for_parent_for_test(
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
) -> String {
    expected.watermark().watermark_digest().to_string()
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_authority_request_digest_for_cleanup_for_test(
    expected: &PrivateOramMutationCleanupExpectationV2,
) -> String {
    expected.evidence_digest.clone()
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_authority_request_digest_for_clear_for_test(
    current: &PrivateOramMutationAuthorityStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    match aggregate.lifecycle.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) => {
            Ok(pending.pending_digest.clone())
        }
        _ => aggregate
            .lifecycle
            .last_cleared
            .as_ref()
            .map(|cleared| cleared.clear_pending_digest.clone())
            .ok_or(PrivateOramMutationJournalError::InvalidTransition),
    }
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_authority_request_digest_for_ack_for_test(
    current: &PrivateOramMutationAuthorityStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let aggregate = require_aggregate_v2(current)?;
    aggregate
        .lifecycle
        .last_cleared
        .as_ref()
        .map(|cleared| cleared.clear_core_digest.clone())
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_terminal_material_transferable_for_test(
    current: &PrivateOramMutationAuthorityStateV2,
) -> Result<bool, PrivateOramMutationJournalError> {
    Ok(terminal_material_is_transferable_to_next_admission_v2(
        require_aggregate_v2(current)?,
    ))
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_owner_enrollment_fixture_for_test(
    current: &PrivateOramMutationAuthorityStateV2,
    collection_id: &str,
    membership_epoch: u64,
    owner_peer_id: u64,
    owner_key: &ring::signature::Ed25519KeyPair,
    discriminator: u8,
) -> Result<
    (
        PrivateOramOwnerEnrollmentPreparedV1,
        PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    ),
    PrivateOramMutationJournalError,
> {
    let aggregate = require_aggregate_v2(current)?;
    let digest = |byte: u8| BASE64URL_NOPAD.encode(&[byte; 32]);
    let owner_store_incarnation_digest = digest(discriminator);
    let prepared = qdrant_sec::prepare_private_oram_owner_enrollment_v1(
        PrivateOramOwnerEnrollmentPreparedV1 {
            version: 0,
            consensus_history_id_digest: aggregate
                .activation
                .authority_key
                .consensus_history_id_digest
                .clone(),
            raft_group_id_digest: aggregate
                .activation
                .authority_key
                .raft_group_id_digest
                .clone(),
            collection_id: collection_id.to_string(),
            collection_lifetime_id_digest: aggregate
                .activation
                .authority_key
                .collection_lifetime_id_digest
                .clone(),
            collection_incarnation_digest: aggregate
                .activation
                .collection_incarnation_digest
                .clone(),
            activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
            capability_epoch: aggregate.activation.compatibility_epoch,
            protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
            membership_epoch,
            owner_enrollment_id: digest(discriminator.wrapping_add(1)),
            owner_peer_id,
            owner_signer: qdrant_sec::private_oram_owner_cleanup_signer_v1(owner_key, 1)
                .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_signer"))?,
            owner_store_incarnation_digest: owner_store_incarnation_digest.clone(),
            expected_genesis_state: qdrant_sec::private_oram_owner_lifecycle_genesis_state_v1(
                owner_store_incarnation_digest,
            )
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_lifecycle"))?,
            authority_registry_digest: digest(discriminator.wrapping_add(2)),
            owner_registry_digest: digest(discriminator.wrapping_add(3)),
            enrollment_operation_id: digest(discriminator.wrapping_add(4)),
            prepared_record_digest: String::new(),
        },
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_enrollment"))?;
    let commitment =
        qdrant_sec::sign_private_oram_owner_enrollment_genesis_commitment_v1(owner_key, &prepared)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_enrollment"))?;
    Ok((prepared, commitment))
}

#[cfg(test)]
mod wire_tests {
    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
        PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
        PrivateOramOwnerReservationPrepareChallengeV1,
        PrivateOramOwnerReservationResolutionDispositionV1,
        PrivateOramOwnerReservationResolutionReceiptV1, prepare_private_oram_owner_enrollment_v1,
        private_oram_owner_cleanup_signer_v1, private_oram_owner_lifecycle_genesis_state_v1,
        sign_private_oram_owner_enrollment_genesis_commitment_v1,
        sign_private_oram_owner_reservation_prepare_v1,
        sign_private_oram_owner_reservation_resolution_receipt_v1,
    };
    use ring::signature::Ed25519KeyPair;
    use serde_json::json;

    use super::*;
    use crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1;
    use crate::content_manager::consensus::private_oram_mutation_cleanup::APPLY_LOCATOR_VERSION;
    use crate::content_manager::consensus::private_oram_mutation_cleanup::append_reservation_v3::{
        private_oram_mutation_append_reservation_v3,
        private_oram_mutation_prepared_reservation_challenge_v3,
        private_oram_mutation_reservation_intent_v3,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::owner_checkpoint::{
        private_oram_owner_checkpoint_reservation_binding_v1,
        private_oram_owner_checkpoint_reservation_context_v1,
    };
    use crate::content_manager::consensus_ops::PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION;
    use crate::content_manager::private_oram_mutation_journal::private_oram_mutation_append_fixture_for_test;

    fn digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn refresh_aggregate_digests_for_test(aggregate: &mut PrivateOramMutationConsensusAggregateV2) {
        let authority_core_digest = aggregate_core_digest_from_parts_v2(
            aggregate.version,
            &aggregate.activation,
            &aggregate.outer_binding_digest,
            &aggregate.lifecycle,
            &aggregate.lease_slot,
            aggregate.recovery_capsules_certificate.as_ref(),
            aggregate.terminal_decision_certificate.as_ref(),
            &aggregate.outstanding_gc_obligations,
            &aggregate.rejected_admissions,
            aggregate.active_append_attempt.as_ref(),
            &aggregate.append_outcomes,
            &aggregate.owner_checkpoint_table,
            aggregate.pending_reservation_challenge.as_ref(),
            &aggregate.reservation_challenge_outcomes,
            aggregate.reservation_challenge_outcome_accumulator.as_ref(),
            &aggregate.compacted_owner_archive_histories,
        )
        .unwrap();
        aggregate.authority_core_digest = authority_core_digest.clone();
        aggregate
            .last_material_transition
            .next_authority_core_digest = authority_core_digest;
        aggregate.last_material_transition.receipt_digest =
            material_transition_receipt_digest_v2(&aggregate.last_material_transition).unwrap();
        aggregate.aggregate_digest = aggregate_digest_v2(aggregate).unwrap();
    }

    pub(super) fn assert_reservation_compacts_gc_at_capacity(
        state: &PrivateOramMutationAuthorityStateV2,
        previous_lease: &PrivateOramMutationLease,
        expected_history: &PrivateOramOwnerCompactedArchiveHistoryV1,
    ) {
        use super::super::format::{
            PrivateOramMutationFormatFloorBarrierInputV2,
            private_oram_mutation_format_floor_from_barrier_v2,
        };
        use crate::content_manager::private_oram_mutation_journal::encode_private_oram_mutation_admission_recovery_manifest_v2;

        let current = state.aggregate().unwrap();
        assert_eq!(current.owner_checkpoint_table.checkpoints().len(), 1);
        let checkpoint = &current.owner_checkpoint_table.checkpoints()[0];
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[12; 32]).unwrap();
        let mut lease = previous_lease.clone();
        lease.generation = current.lease_slot.generation + 1;
        lease.writer_fence = current.lease_slot.max_writer_fence + 1;
        let predecessor = current.lifecycle.last_cleared.as_ref().unwrap();
        lease.base_record_digest = predecessor
            .cleanup_witness
            .terminal_consensus_state_digest
            .clone();
        lease.base_state_sequence = predecessor
            .cleanup_witness
            .terminal_consensus_state_sequence;
        lease.mutation_id = digest(160);
        lease.signed_mutation_digest = digest(161);
        lease.transition_digest = digest(162);
        lease.phase = PrivateOramMutationLeasePhase::Preparing;
        let (base, manifest) = private_oram_mutation_append_fixture_for_test(
            &lease,
            current.append_authority_context().unwrap(),
            1,
            &[lease.owner_peer_id],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(163)),
        );
        let intent = private_oram_mutation_reservation_intent_v3(&base).unwrap();
        let checkpoint_context = private_oram_owner_checkpoint_reservation_context_v1(
            current.owner_checkpoint_table(),
            intent.intent_digest().to_string(),
        )
        .unwrap();
        let nonce = BASE64URL_NOPAD.encode(&[164; 16]);
        let challenge = private_oram_mutation_prepared_reservation_challenge_v3(
            base.clone(),
            intent.clone(),
            checkpoint_context.clone(),
            vec![nonce.clone()],
        )
        .unwrap();
        let challenge_json =
            encode_private_oram_mutation_prepared_reservation_challenge_v3(&challenge).unwrap();
        let mut challenge_applied = current.last_material_transition.locator.clone();
        challenge_applied.index += 2;
        let floor = private_oram_mutation_format_floor_from_barrier_v2(
            PrivateOramMutationFormatFloorBarrierInputV2 {
                consensus_history_id_digest: current
                    .activation
                    .authority_key
                    .consensus_history_id_digest
                    .clone(),
                raft_group_id_digest: current
                    .activation
                    .authority_key
                    .raft_group_id_digest
                    .clone(),
                format_epoch: 6,
                minimum_reader_protocol: 9,
                minimum_writer_protocol: 9,
                snapshot_format_epoch: 6,
                membership_generation: 1,
                eligible_peer_set_digest: digest(165),
                eligible_process_incarnations_digest: digest(166),
                capability_manifest_digest: digest(167),
                required_binary_capability_digest: digest(168),
                activation_enabled: true,
                term: challenge_applied.term,
                index: challenge_applied.index - 1,
            },
        )
        .unwrap();
        let target = &base.owner_targets()[0];
        let signed_prepare = sign_private_oram_owner_reservation_prepare_v1(
            &owner_key,
            PrivateOramOwnerReservationPrepareChallengeV1 {
                version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
                consensus_history_id_digest: current
                    .activation
                    .authority_key
                    .consensus_history_id_digest
                    .clone(),
                raft_group_id_digest: current
                    .activation
                    .authority_key
                    .raft_group_id_digest
                    .clone(),
                collection_id: lease.collection_id.clone(),
                collection_lifetime_id_digest: current
                    .activation
                    .authority_key
                    .collection_lifetime_id_digest
                    .clone(),
                collection_incarnation_digest: current
                    .activation
                    .collection_incarnation_digest
                    .clone(),
                activation_anchor_digest: current.activation.anchor_digest.clone(),
                capability_epoch: current.activation.compatibility_epoch,
                protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
                membership_epoch: 7,
                reservation_intent_digest: intent.intent_digest().to_string(),
                checkpoint_context_digest: checkpoint_context.context_digest().to_string(),
                committed_challenge_digest: challenge.prepared_challenge_digest().to_string(),
                challenge_applied_term: challenge_applied.term,
                challenge_applied_index: challenge_applied.index,
                attempt_id: base.attempt_id().to_string(),
                challenge_nonce: nonce,
                expected_checkpoint_record_digest: checkpoint
                    .checkpoint_record_digest()
                    .to_string(),
                expected_checkpoint_sequence: checkpoint.checkpoint_sequence(),
                expected_owner_target_digest: target.target_digest().to_string(),
                reserved_terminal_intent_key: target.intent_key().to_string(),
                owner_index: 0,
                owner_count: 1,
                owner_enrollment_id: checkpoint.owner_enrollment_id().to_string(),
                owner_peer_id: checkpoint.owner_peer_id(),
                owner_store_incarnation_digest: checkpoint
                    .lifecycle_state()
                    .owner_store_incarnation_digest
                    .clone(),
                authority_registry_digest: digest(22),
                owner_registry_digest: digest(23),
            },
            checkpoint.lifecycle_state().clone(),
            checkpoint.lifecycle_state().generation,
            digest(169),
            checkpoint.owner_signer().clone(),
        )
        .unwrap();
        let binding =
            private_oram_owner_checkpoint_reservation_binding_v1(0, checkpoint, signed_prepare)
                .unwrap();
        let reservation = private_oram_mutation_append_reservation_v3(
            base.clone(),
            intent,
            checkpoint_context,
            challenge.clone(),
            challenge_applied.clone(),
            vec![binding],
        )
        .unwrap();
        let reservation_json =
            encode_private_oram_mutation_append_reservation_v3(&reservation).unwrap();
        let gc_bytes =
            gc_obligations_serialized_len_v2(&current.outstanding_gc_obligations).unwrap();
        let byte_boundary = usize::try_from(base.reserved_cleanup_bytes()).unwrap() + gc_bytes - 1;
        let original = encode_private_oram_mutation_tagged_authority_wire_json_v2(state).unwrap();
        for (max_count, max_bytes) in [
            (1, MAX_OUTSTANDING_GC_OBLIGATION_BYTES),
            (MAX_OUTSTANDING_GC_OBLIGATIONS, byte_boundary),
        ] {
            let context = |current: &PrivateOramMutationAuthorityStateV2, kind, request, offset| {
                private_oram_mutation_aggregate_apply_context_for_test(
                    current,
                    kind,
                    request,
                    challenge_applied.term,
                    challenge_applied.index + offset,
                )
                .unwrap()
            };
            // Exercise the historical branch through the same real prepare transition.
            let legacy = apply_prepare_append_reservation_challenge_with_gc_limits_v3(
                state,
                challenge_json.clone(),
                context(
                    state,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
                    challenge.prepared_challenge_digest().to_string(),
                    0,
                ),
                max_count,
                max_bytes,
            );
            if max_bytes == byte_boundary {
                assert!(
                    legacy.is_err(),
                    "old capacity gate rejects before admission can prune"
                );
            } else {
                let legacy = legacy.unwrap();
                assert_eq!(
                    legacy.aggregate().unwrap().outstanding_gc_obligations,
                    current.outstanding_gc_obligations
                );
                assert!(
                    legacy
                        .aggregate()
                        .unwrap()
                        .compacted_owner_archive_histories
                        .is_empty()
                );
            }
            let challenged = apply_prepare_append_reservation_challenge_with_gc_limits_v3(
                state,
                challenge_json.clone(),
                context(
                    state,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
                    challenge.prepared_challenge_digest().to_string(),
                    0,
                )
                .with_owner_archive_history_floor(&floor)
                .unwrap(),
                max_count,
                max_bytes,
            )
            .unwrap();
            let projected = challenged.aggregate().unwrap();
            assert!(projected.outstanding_gc_obligations.is_empty());
            assert_eq!(
                projected.compacted_owner_archive_histories,
                vec![expected_history.clone()]
            );
            assert_eq!(
                projected
                    .pending_reservation_challenge
                    .as_ref()
                    .unwrap()
                    .pre_challenge_aggregate_digest,
                current.aggregate_digest
            );
            assert_eq!(
                projected
                    .pending_reservation_challenge
                    .as_ref()
                    .unwrap()
                    .attempt_sequence,
                current.transition_ordinal + 1
            );
            assert_eq!(
                apply_prepare_append_reservation_challenge_with_gc_limits_v3(
                    &challenged,
                    challenge_json.clone(),
                    context(
                        &challenged,
                        PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
                        challenge.prepared_challenge_digest().to_string(),
                        0
                    )
                    .with_owner_archive_history_floor(&floor)
                    .unwrap(),
                    max_count,
                    max_bytes,
                )
                .unwrap(),
                challenged
            );
            assert_eq!(
                encode_private_oram_mutation_tagged_authority_wire_json_v2(state).unwrap(),
                original
            );

            let reserved = apply_private_oram_mutation_authority_create_append_reservation_v3(
                &challenged,
                reservation_json.clone(),
                context(
                    &challenged,
                    PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3,
                    reservation.reservation_digest_v3().to_string(),
                    1,
                ),
            )
            .unwrap();
            let manifest_json =
                encode_private_oram_mutation_admission_recovery_manifest_v2(&manifest).unwrap();
            let prepared_request =
                decode_private_oram_mutation_append_reservation_wire(&reservation_json)
                    .unwrap()
                    .append_prepared_request_digest(&manifest)
                    .unwrap();
            let prepared = apply_private_oram_mutation_authority_append_prepared_v2(
                &reserved,
                manifest_json.clone(),
                context(
                    &reserved,
                    PrivateOramMutationMaterialOperationV2::AppendPrepared,
                    prepared_request,
                    2,
                ),
            )
            .unwrap();
            let admission_request = private_oram_mutation_admission_request_digest_v2(
                &lease,
                manifest.manifest_digest(),
            )
            .unwrap();
            let admitted = apply_private_oram_mutation_authority_admission_v2(
                &prepared,
                lease.clone(),
                manifest_json,
                context(
                    &prepared,
                    PrivateOramMutationMaterialOperationV2::Admission,
                    admission_request,
                    3,
                )
                .with_owner_archive_history_floor(&floor)
                .unwrap(),
            )
            .unwrap();
            let result = admitted.aggregate().unwrap();
            assert_eq!(result.lease_slot.active.as_ref(), Some(&lease));
            assert_eq!(
                result.compacted_owner_archive_histories,
                vec![expected_history.clone()]
            );
            assert_eq!(result.outstanding_gc_obligations.len(), 1);
            assert_eq!(result.outstanding_gc_obligations[0].generation, 2);
            require_complete_acknowledged_archive_history_v1(result).unwrap();
            let encoded =
                encode_private_oram_mutation_tagged_authority_wire_json_v2(&admitted).unwrap();
            assert!(decode_private_oram_mutation_authority_wire_json_v2(&encoded).is_ok());
        }
    }

    #[test]
    fn compacted_archive_metadata_is_committed_by_the_aggregate_digest() {
        let mut aggregate = activated_authority().aggregate().unwrap().clone();
        let historical = aggregate.authority_core_digest.clone();
        let encoded = serde_json::to_value(&aggregate).unwrap();
        assert!(encoded.get("compacted_owner_archive_histories").is_none());
        let decoded: PrivateOramMutationConsensusAggregateV2 =
            serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, aggregate);
        let binding = PrivateOramOwnerAcknowledgedArchiveExpectationV2::try_new(
            2,
            11,
            digest(60),
            digest(61),
            digest(62),
        )
        .unwrap();
        let history = PrivateOramOwnerCompactedArchiveHistoryV1::append(None, &binding).unwrap();
        aggregate.compacted_owner_archive_histories = vec![history.clone()];
        refresh_aggregate_digests_for_test(&mut aggregate);
        let committed = aggregate.authority_core_digest.clone();
        assert_ne!(historical, committed);
        for (field, value) in [
            ("owner_peer_id", json!(13)),
            ("archive_count", json!(2)),
            ("through_generation", json!(3)),
            ("history_digest", json!(digest(63))),
        ] {
            let mut changed = serde_json::to_value(&history).unwrap();
            changed[field] = value;
            aggregate.compacted_owner_archive_histories =
                vec![serde_json::from_value(changed).unwrap()];
            refresh_aggregate_digests_for_test(&mut aggregate);
            assert_ne!(aggregate.authority_core_digest, committed, "{field}");
        }
    }

    #[test]
    fn compacted_archive_history_requires_an_applied_reader_and_writer_floor() {
        use super::super::format::{
            PrivateOramMutationFormatFloorBarrierInputV2,
            private_oram_mutation_format_floor_from_barrier_v2,
        };
        let state = activated_authority();
        let context = || {
            private_oram_mutation_aggregate_apply_context_for_test(
                &state,
                PrivateOramMutationMaterialOperationV2::Admission,
                digest(60),
                1,
                20,
            )
            .unwrap()
        };
        assert!(!context().retain_compacted_owner_archive_history);
        for (reader, writer, index, valid) in [
            (8, 8, 19, false),
            (9, 8, 19, false),
            (8, 9, 19, false),
            (9, 9, 19, true),
            (9, 9, 20, false),
        ] {
            let floor = private_oram_mutation_format_floor_from_barrier_v2(
                PrivateOramMutationFormatFloorBarrierInputV2 {
                    consensus_history_id_digest: digest(1),
                    raft_group_id_digest: digest(2),
                    format_epoch: 4,
                    minimum_reader_protocol: reader,
                    minimum_writer_protocol: writer,
                    snapshot_format_epoch: 4,
                    membership_generation: 1,
                    eligible_peer_set_digest: digest(61),
                    eligible_process_incarnations_digest: digest(62),
                    capability_manifest_digest: digest(63),
                    required_binary_capability_digest: digest(64),
                    activation_enabled: true,
                    term: 1,
                    index,
                },
            )
            .unwrap();
            let result = context().with_owner_archive_history_floor(&floor);
            assert_eq!(result.is_ok(), valid);
            if valid {
                assert!(result.unwrap().retain_compacted_owner_archive_history);
            }
        }
    }

    fn raw_slot() -> PrivateOramMutationLeaseSlotV2 {
        PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        }
    }

    fn authority_key() -> PrivateOramMutationAuthorityKeyV2 {
        private_oram_mutation_authority_key_v2("collection-a", digest(1), digest(2), digest(3))
            .unwrap()
    }

    fn activated_authority() -> PrivateOramMutationAuthorityStateV2 {
        let legacy =
            private_oram_mutation_legacy_authority_v2(authority_key(), raw_slot(), digest(4))
                .unwrap();
        activate_private_oram_mutation_authority_v2(
            &legacy,
            "collection-a",
            private_oram_mutation_activation_context_for_test(
                digest(1),
                digest(2),
                1,
                10,
                1,
                digest(5),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn enrolled_authority(owner_key: &Ed25519KeyPair) -> PrivateOramMutationAuthorityStateV2 {
        let activated = activated_authority();
        let aggregate = activated.aggregate().unwrap();
        let owner_store_incarnation_digest = digest(20);
        let prepared =
            prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
                version: 0,
                consensus_history_id_digest: digest(1),
                raft_group_id_digest: digest(2),
                collection_id: "collection-a".to_string(),
                collection_lifetime_id_digest: digest(3),
                collection_incarnation_digest: aggregate
                    .activation
                    .collection_incarnation_digest
                    .clone(),
                activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
                capability_epoch: aggregate.activation.compatibility_epoch,
                protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
                membership_epoch: 7,
                owner_enrollment_id: digest(21),
                owner_peer_id: 11,
                owner_signer: private_oram_owner_cleanup_signer_v1(owner_key, 1).unwrap(),
                owner_store_incarnation_digest: owner_store_incarnation_digest.clone(),
                expected_genesis_state: private_oram_owner_lifecycle_genesis_state_v1(
                    owner_store_incarnation_digest,
                )
                .unwrap(),
                authority_registry_digest: digest(22),
                owner_registry_digest: digest(23),
                enrollment_operation_id: digest(24),
                prepared_record_digest: String::new(),
            })
            .unwrap();
        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(owner_key, &prepared).unwrap();
        let prepare_context = private_oram_mutation_aggregate_apply_context_for_test(
            &activated,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared,
            prepared.prepared_record_digest.clone(),
            1,
            11,
        )
        .unwrap();
        let pending = apply_private_oram_mutation_authority_owner_enrollment_prepared_v2(
            &activated,
            prepared,
            prepare_context,
        )
        .unwrap();
        let activate_context = private_oram_mutation_aggregate_apply_context_for_test(
            &pending,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
            commitment.commitment_digest.clone(),
            1,
            12,
        )
        .unwrap();
        apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
            &pending,
            commitment,
            activate_context,
        )
        .unwrap()
    }

    #[test]
    fn strict_wire_decoder_canonicalizes_raw_and_tagged_legacy_identically() {
        let slot = raw_slot();
        let key = authority_key();
        let outer_binding = digest(4);
        let raw_bytes = serde_json::to_vec(&slot).unwrap();
        let raw = decode_private_oram_mutation_authority_wire_json_v2(&raw_bytes).unwrap();
        assert_eq!(
            raw.format(),
            PrivateOramMutationAuthorityWireFormatV2::HistoricalRawLeaseSlotV2
        );

        let tagged = private_oram_mutation_legacy_authority_v2(
            key.clone(),
            slot.clone(),
            outer_binding.clone(),
        )
        .unwrap();
        let tagged_bytes =
            encode_private_oram_mutation_tagged_authority_wire_json_v2(&tagged).unwrap();
        let decoded_tagged =
            decode_private_oram_mutation_authority_wire_json_v2(&tagged_bytes).unwrap();
        assert_eq!(
            decoded_tagged.format(),
            PrivateOramMutationAuthorityWireFormatV2::TaggedAuthorityV2
        );
        assert_eq!(decoded_tagged.lease_slot(), &slot);

        let canonical_raw = canonical_private_oram_mutation_legacy_authority_from_wire_v2(
            &raw,
            &key,
            &outer_binding,
        )
        .unwrap();
        let canonical_tagged = canonical_private_oram_mutation_legacy_authority_from_wire_v2(
            &decoded_tagged,
            &key,
            &outer_binding,
        )
        .unwrap();
        assert_eq!(canonical_raw, tagged);
        assert_eq!(canonical_tagged, tagged);
    }

    #[test]
    fn strict_wire_serde_preserves_raw_and_tagged_values_across_json_and_cbor() {
        let slot = raw_slot();
        let raw = DecodedPrivateOramMutationAuthorityWireV2::from(slot.clone());
        assert_eq!(
            serde_json::to_vec(&raw).unwrap(),
            serde_json::to_vec(&slot).unwrap(),
        );
        assert_eq!(
            serde_json::from_slice::<DecodedPrivateOramMutationAuthorityWireV2>(
                &serde_json::to_vec(&raw).unwrap(),
            )
            .unwrap(),
            raw,
        );
        assert_eq!(
            serde_cbor::from_slice::<DecodedPrivateOramMutationAuthorityWireV2>(
                &serde_cbor::to_vec(&raw).unwrap(),
            )
            .unwrap(),
            raw,
        );

        let authority =
            private_oram_mutation_legacy_authority_v2(authority_key(), slot, digest(4)).unwrap();
        let tagged = DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(authority);
        assert_eq!(
            serde_json::to_vec(&tagged).unwrap(),
            encode_private_oram_mutation_tagged_authority_wire_json_v2(
                tagged.tagged_authority().unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            serde_json::from_slice::<DecodedPrivateOramMutationAuthorityWireV2>(
                &serde_json::to_vec(&tagged).unwrap(),
            )
            .unwrap(),
            tagged,
        );
        assert_eq!(
            serde_cbor::from_slice::<DecodedPrivateOramMutationAuthorityWireV2>(
                &serde_cbor::to_vec(&tagged).unwrap(),
            )
            .unwrap(),
            tagged,
        );
    }

    #[test]
    fn strict_wire_decoder_round_trips_activated_but_never_reclassifies_it_as_legacy() {
        let key = authority_key();
        let outer_binding = digest(4);
        let legacy = private_oram_mutation_legacy_authority_v2(
            key.clone(),
            raw_slot(),
            outer_binding.clone(),
        )
        .unwrap();
        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            "collection-a",
            private_oram_mutation_activation_context_for_test(
                digest(1),
                digest(2),
                1,
                10,
                1,
                digest(5),
            )
            .unwrap(),
        )
        .unwrap();
        let decoded = decode_private_oram_mutation_authority_wire_json_v2(
            &encode_private_oram_mutation_tagged_authority_wire_json_v2(&activated).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decoded.tagged_authority(),
            Some(&activated),
            "tagged Activated must survive shadow decode exactly"
        );
        assert!(matches!(
            canonical_private_oram_mutation_legacy_authority_from_wire_v2(
                &decoded,
                &key,
                &outer_binding,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn activated_wire_requires_an_integrity_bound_owner_checkpoint_table() {
        let legacy =
            private_oram_mutation_legacy_authority_v2(authority_key(), raw_slot(), digest(4))
                .unwrap();
        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            "collection-a",
            private_oram_mutation_activation_context_for_test(
                digest(1),
                digest(2),
                1,
                10,
                1,
                digest(5),
            )
            .unwrap(),
        )
        .unwrap();
        let encoded =
            encode_private_oram_mutation_tagged_authority_wire_json_v2(&activated).unwrap();
        let mut missing: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        missing["authority"]["state"]
            .as_object_mut()
            .unwrap()
            .remove("owner_checkpoint_table");
        assert!(matches!(
            decode_private_oram_mutation_authority_wire_json_v2(
                &serde_json::to_vec(&missing).unwrap()
            ),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let mut tampered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        tampered["authority"]["state"]["owner_checkpoint_table"]["table_digest"] =
            serde_json::Value::String(digest(99));
        assert!(matches!(
            decode_private_oram_mutation_authority_wire_json_v2(
                &serde_json::to_vec(&tampered).unwrap()
            ),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn owner_enrollment_requires_committed_prepare_then_exact_signed_genesis() {
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[41; 32]).unwrap();
        let activated = activated_authority();
        let aggregate = activated.aggregate().unwrap();
        let owner_store_incarnation_digest = digest(20);
        let prepared =
            prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
                version: 0,
                consensus_history_id_digest: digest(1),
                raft_group_id_digest: digest(2),
                collection_id: "collection-a".to_string(),
                collection_lifetime_id_digest: digest(3),
                collection_incarnation_digest: aggregate
                    .activation
                    .collection_incarnation_digest
                    .clone(),
                activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
                capability_epoch: aggregate.activation.compatibility_epoch,
                protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
                membership_epoch: 7,
                owner_enrollment_id: digest(21),
                owner_peer_id: 11,
                owner_signer: private_oram_owner_cleanup_signer_v1(&owner_key, 3).unwrap(),
                owner_store_incarnation_digest: owner_store_incarnation_digest.clone(),
                expected_genesis_state: private_oram_owner_lifecycle_genesis_state_v1(
                    owner_store_incarnation_digest,
                )
                .unwrap(),
                authority_registry_digest: digest(22),
                owner_registry_digest: digest(23),
                enrollment_operation_id: digest(24),
                prepared_record_digest: String::new(),
            })
            .unwrap();
        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(&owner_key, &prepared)
                .unwrap();

        let premature_context = private_oram_mutation_aggregate_apply_context_for_test(
            &activated,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
            commitment.commitment_digest.clone(),
            1,
            11,
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
                &activated,
                commitment.clone(),
                premature_context,
            )
            .is_err()
        );

        let prepare_context = private_oram_mutation_aggregate_apply_context_for_test(
            &activated,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared,
            prepared.prepared_record_digest.clone(),
            1,
            11,
        )
        .unwrap();
        let pending = apply_private_oram_mutation_authority_owner_enrollment_prepared_v2(
            &activated,
            prepared,
            prepare_context,
        )
        .unwrap();
        assert_eq!(
            pending
                .aggregate()
                .unwrap()
                .owner_checkpoint_table()
                .pending_enrollment_count(),
            1
        );
        assert_eq!(
            pending
                .aggregate()
                .unwrap()
                .owner_checkpoint_table()
                .checkpoint_count(),
            0
        );

        let activate_context = private_oram_mutation_aggregate_apply_context_for_test(
            &pending,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
            commitment.commitment_digest.clone(),
            1,
            12,
        )
        .unwrap();
        let enrolled = apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
            &pending,
            commitment.clone(),
            activate_context,
        )
        .unwrap();
        assert_eq!(
            enrolled
                .aggregate()
                .unwrap()
                .owner_checkpoint_table()
                .pending_enrollment_count(),
            0
        );
        assert_eq!(
            enrolled
                .aggregate()
                .unwrap()
                .owner_checkpoint_table()
                .checkpoint_count(),
            1
        );

        let retry_context = private_oram_mutation_aggregate_apply_context_for_test(
            &enrolled,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
            commitment.commitment_digest.clone(),
            1,
            13,
        )
        .unwrap();
        let retried = apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
            &enrolled,
            commitment,
            retry_context,
        )
        .unwrap();
        assert_eq!(retried, enrolled);
    }

    #[test]
    fn owner_enrollment_planner_is_deterministic_and_resumes_pending_then_active() {
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[61; 32]).unwrap();
        let owner_signer = private_oram_owner_cleanup_signer_v1(&owner_key, 3).unwrap();
        let activated = activated_authority();
        let plan = || {
            private_oram_mutation_owner_enrollment_plan_v2(
                &activated,
                "collection-a",
                11,
                owner_signer.clone(),
                digest(62),
                digest(63),
                digest(64),
                digest(65),
                digest(66),
            )
        };
        let PrivateOramMutationOwnerEnrollmentPlanV2::Missing(prepared) = plan().unwrap() else {
            panic!("fresh authority must require owner enrollment prepare");
        };
        let PrivateOramMutationOwnerEnrollmentPlanV2::Missing(repeated) = plan().unwrap() else {
            panic!("unchanged authority must retain the deterministic prepare plan");
        };
        assert_eq!(prepared, repeated);
        assert_eq!(prepared.membership_epoch, 10);

        let prepare_context = private_oram_mutation_aggregate_apply_context_for_test(
            &activated,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared,
            prepared.prepared_record_digest.clone(),
            1,
            11,
        )
        .unwrap();
        let pending = apply_private_oram_mutation_authority_owner_enrollment_prepared_v2(
            &activated,
            prepared.clone(),
            prepare_context,
        )
        .unwrap();
        assert!(matches!(
            private_oram_mutation_owner_enrollment_plan_v2(
                &pending,
                "collection-a",
                11,
                owner_signer.clone(),
                digest(62),
                digest(63),
                digest(64),
                digest(65),
                digest(66),
            )
            .unwrap(),
            PrivateOramMutationOwnerEnrollmentPlanV2::Pending(ref retained)
                if retained == &prepared
        ));

        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(&owner_key, &prepared)
                .unwrap();
        let activate_context = private_oram_mutation_aggregate_apply_context_for_test(
            &pending,
            PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
            commitment.commitment_digest.clone(),
            1,
            12,
        )
        .unwrap();
        let active = apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
            &pending,
            commitment,
            activate_context,
        )
        .unwrap();
        assert!(matches!(
            private_oram_mutation_owner_enrollment_plan_v2(
                &active,
                "collection-a",
                11,
                owner_signer.clone(),
                digest(62),
                digest(63),
                digest(64),
                digest(65),
                digest(66),
            )
            .unwrap(),
            PrivateOramMutationOwnerEnrollmentPlanV2::Active
        ));
        assert!(
            private_oram_mutation_owner_enrollment_plan_v2(
                &active,
                "collection-a",
                11,
                owner_signer,
                digest(99),
                digest(63),
                digest(64),
                digest(65),
                digest(66),
            )
            .is_err()
        );
    }

    #[test]
    fn checkpoint_bound_reservation_retains_atomic_pre_and_postlease_commits() {
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[12; 32]).unwrap();
        let enrolled = enrolled_authority(&owner_key);
        let aggregate = enrolled.aggregate().unwrap();
        assert!(aggregate.is_reservation_v3_floor_quiescent());
        let lease = PrivateOramMutationLease {
            generation: 1,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 11,
            mutation_id: digest(30),
            signed_mutation_digest: digest(31),
            transition_digest: digest(32),
            base_record_digest: digest(33),
            base_state_sequence: 0,
            writer_lease_digest: digest(34),
            writer_fence: 1,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let (base_reservation, manifest) = private_oram_mutation_append_fixture_for_test(
            &lease,
            aggregate.append_authority_context().unwrap(),
            1,
            &[11],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(35)),
        );
        let reservation_intent =
            private_oram_mutation_reservation_intent_v3(&base_reservation).unwrap();
        let checkpoint_context = private_oram_owner_checkpoint_reservation_context_v1(
            aggregate.owner_checkpoint_table(),
            reservation_intent.intent_digest().to_string(),
        )
        .unwrap();
        let checkpoint = &aggregate.owner_checkpoint_table().checkpoints()[0];
        let owner_target = &base_reservation.owner_targets()[0];
        let owner_nonce = BASE64URL_NOPAD.encode(&[42; 16]);
        let prepared_challenge = private_oram_mutation_prepared_reservation_challenge_v3(
            base_reservation.clone(),
            reservation_intent.clone(),
            checkpoint_context.clone(),
            vec![owner_nonce.clone()],
        )
        .unwrap();
        let challenge_applied = PrivateOramRaftApplyLocatorV2 {
            version: APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            term: 1,
            index: 13,
        };
        let prepared_challenge_canonical_json =
            encode_private_oram_mutation_prepared_reservation_challenge_v3(&prepared_challenge)
                .unwrap();
        let challenge_context = private_oram_mutation_aggregate_apply_context_for_test(
            &enrolled,
            PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
            prepared_challenge.prepared_challenge_digest().to_string(),
            1,
            13,
        )
        .unwrap();
        let challenged =
            apply_private_oram_mutation_authority_prepare_append_reservation_challenge_v3(
                &enrolled,
                prepared_challenge_canonical_json.clone(),
                challenge_context,
            )
            .unwrap();
        assert_eq!(
            challenged
                .aggregate()
                .unwrap()
                .pending_reservation_challenge()
                .unwrap()
                .challenge_digest(),
            prepared_challenge.prepared_challenge_digest()
        );
        let cancellation = private_oram_mutation_reservation_challenge_cancellation_v1(
            challenged
                .aggregate()
                .unwrap()
                .pending_reservation_challenge()
                .unwrap(),
            digest(45),
        )
        .unwrap();
        let cancellation_canonical_json =
            encode_private_oram_mutation_reservation_challenge_cancellation_v1(&cancellation)
                .unwrap();
        let cancellation_context = private_oram_mutation_aggregate_apply_context_for_test(
            &challenged,
            PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled,
            cancellation.cancellation_digest.clone(),
            1,
            14,
        )
        .unwrap();
        let cancelled =
            apply_private_oram_mutation_authority_cancel_append_reservation_challenge_v3(
                &challenged,
                cancellation_canonical_json.clone(),
                cancellation_context,
            )
            .unwrap();
        assert!(
            !cancelled
                .aggregate()
                .unwrap()
                .is_reservation_v3_floor_quiescent()
        );
        assert!(
            cancelled
                .aggregate()
                .unwrap()
                .pending_reservation_challenge()
                .is_none()
        );
        assert_eq!(
            cancelled
                .aggregate()
                .unwrap()
                .reservation_challenge_outcomes()[0]
                .kind,
            PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled
        );
        let current_outcome = &cancelled
            .aggregate()
            .unwrap()
            .reservation_challenge_outcomes()[0];
        assert_eq!(
            current_outcome.version,
            RESERVATION_CHALLENGE_OUTCOME_VERSION_V3
        );
        assert_eq!(
            current_outcome.challenge_canonical_json.as_deref(),
            Some(prepared_challenge_canonical_json.as_str())
        );
        let mut legacy_outcome = current_outcome.clone();
        legacy_outcome.version = RESERVATION_CHALLENGE_OUTCOME_VERSION_V1;
        legacy_outcome.challenge_canonical_json = None;
        legacy_outcome.outcome_digest =
            reservation_challenge_outcome_digest_v1(&legacy_outcome).unwrap();
        validate_reservation_challenge_outcome_v1(&legacy_outcome).unwrap();
        let legacy_json = serde_json::to_string(&legacy_outcome).unwrap();
        assert!(!legacy_json.contains("challenge_canonical_json"));
        let decoded_legacy: PrivateOramMutationReservationChallengeOutcomeV1 =
            serde_json::from_str(&legacy_json).unwrap();
        validate_reservation_challenge_outcome_v1(&decoded_legacy).unwrap();

        let oversized_history =
            vec![current_outcome.clone(); MAX_RESERVATION_CHALLENGE_OUTCOMES + 1];
        assert!(matches!(
            validate_reservation_challenge_outcome_history_capacity_v1(&oversized_history),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let item_len = serde_json::to_vec(current_outcome).unwrap().len();
        let retained_count = ((MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES - 1) / (item_len + 1))
            .min(MAX_RESERVATION_CHALLENGE_OUTCOMES - 1);
        let near_byte_limit = vec![current_outcome.clone(); retained_count];
        assert!(
            reservation_challenge_outcomes_serialized_len_v1(&near_byte_limit).unwrap()
                <= MAX_RESERVATION_CHALLENGE_OUTCOME_BYTES
        );
        assert!(matches!(
            validate_reservation_challenge_outcome_reserve_v1(
                &near_byte_limit,
                challenged
                    .aggregate()
                    .unwrap()
                    .pending_reservation_challenge()
                    .unwrap(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let cancellation_retry_context = private_oram_mutation_aggregate_apply_context_for_test(
            &cancelled,
            PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled,
            cancellation.cancellation_digest.clone(),
            1,
            15,
        )
        .unwrap();
        assert_eq!(
            apply_private_oram_mutation_authority_cancel_append_reservation_challenge_v3(
                &cancelled,
                cancellation_canonical_json,
                cancellation_retry_context,
            )
            .unwrap(),
            cancelled
        );
        let resolution_signer = private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap();
        let signed_resolution = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &owner_key,
            PrivateOramOwnerReservationResolutionReceiptV1 {
                version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
                disposition: PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased,
                collection_id: "collection-a".to_string(),
                owner_peer_id: 11,
                committed_challenge_digest: current_outcome.challenge_digest.clone(),
                reservation_intent_digest: current_outcome.reservation_intent_digest.clone(),
                attempt_id: current_outcome.attempt_id.clone(),
                challenge_applied_term: current_outcome.challenge_applied.term,
                challenge_applied_index: current_outcome.challenge_applied.index,
                resolution_applied_term: current_outcome.resolution_applied.term,
                resolution_applied_index: current_outcome.resolution_applied.index,
                reserved_terminal_intent_key: owner_target.intent_key().to_string(),
                finalized_reservation_digest: None,
                durable_fence_record_digest: digest(89),
                owner_store_incarnation_digest: checkpoint_context.owner_expectations()[0]
                    .owner_store_incarnation_digest()
                    .to_string(),
                owner_store_binding_digest: checkpoint_context.owner_expectations()[0]
                    .expected_checkpoint_record_digest()
                    .to_string(),
                installed_intent_marker_digest: None,
                installed_prestage_receipt_digest: None,
                installed_package_sha256: None,
                abort_release_authority_digest: None,
                abort_release_marker_digest: None,
                local_resolution_record_digest: digest(90),
            },
            resolution_signer,
        )
        .unwrap();
        let mut legacy_v2_outcome = current_outcome.clone();
        legacy_v2_outcome.version = RESERVATION_CHALLENGE_OUTCOME_VERSION_V2;
        legacy_v2_outcome.finalized_reservation_canonical_json = None;
        legacy_v2_outcome.outcome_digest =
            reservation_challenge_outcome_digest_v1(&legacy_v2_outcome).unwrap();
        validate_reservation_challenge_outcome_v1(&legacy_v2_outcome).unwrap();
        for legacy_head in [legacy_outcome.clone(), legacy_v2_outcome] {
            let mut legacy_state = cancelled.clone();
            let PrivateOramMutationAuthorityStateV2::Activated(legacy_aggregate) =
                &mut legacy_state
            else {
                panic!("cancelled fixture must be activated");
            };
            legacy_aggregate.reservation_challenge_outcomes = vec![legacy_head.clone()];
            refresh_aggregate_digests_for_test(legacy_aggregate);
            validate_aggregate_v2(legacy_aggregate).unwrap();
            let legacy_acknowledgement =
                private_oram_mutation_reservation_outcome_acknowledgement_v1(
                    legacy_head.outcome_digest.clone(),
                    vec![signed_resolution.clone()],
                )
                .unwrap();
            let legacy_context = private_oram_mutation_aggregate_apply_context_for_test(
                &legacy_state,
                PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                legacy_acknowledgement.acknowledgement_digest.clone(),
                1,
                16,
            )
            .unwrap();
            let before =
                encode_private_oram_mutation_tagged_authority_wire_json_v2(&legacy_state).unwrap();
            assert!(
                apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                    &legacy_state,
                    encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                        &legacy_acknowledgement,
                    )
                    .unwrap(),
                    legacy_context,
                )
                .is_err()
            );
            assert_eq!(
                encode_private_oram_mutation_tagged_authority_wire_json_v2(&legacy_state).unwrap(),
                before
            );
        }
        let mut tampered_resolution = signed_resolution.clone();
        tampered_resolution.signature.sig = BASE64URL_NOPAD.encode(&[0; 64]);
        let tampered_acknowledgement =
            private_oram_mutation_reservation_outcome_acknowledgement_v1(
                current_outcome.outcome_digest.clone(),
                vec![tampered_resolution],
            )
            .unwrap();
        let tampered_acknowledgement_canonical_json =
            encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                &tampered_acknowledgement,
            )
            .unwrap();
        let tampered_acknowledgement_context =
            private_oram_mutation_aggregate_apply_context_for_test(
                &cancelled,
                PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                tampered_acknowledgement.acknowledgement_digest.clone(),
                1,
                16,
            )
            .unwrap();
        assert!(
            apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                &cancelled,
                tampered_acknowledgement_canonical_json,
                tampered_acknowledgement_context,
            )
            .is_err()
        );
        let acknowledgement = private_oram_mutation_reservation_outcome_acknowledgement_v1(
            current_outcome.outcome_digest.clone(),
            vec![signed_resolution],
        )
        .unwrap();
        let acknowledgement_canonical_json =
            encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(&acknowledgement)
                .unwrap();
        let acknowledgement_context = private_oram_mutation_aggregate_apply_context_for_test(
            &cancelled,
            PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
            acknowledgement.acknowledgement_digest.clone(),
            1,
            16,
        )
        .unwrap();
        let compacted = apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
            &cancelled,
            acknowledgement_canonical_json.clone(),
            acknowledgement_context,
        )
        .unwrap();
        let compacted_aggregate = compacted.aggregate().unwrap();
        assert!(compacted_aggregate.is_reservation_v3_floor_quiescent());
        assert!(
            compacted_aggregate
                .reservation_challenge_outcomes()
                .is_empty()
        );
        let accumulator = compacted_aggregate
            .reservation_challenge_outcome_accumulator()
            .unwrap();
        assert_eq!(accumulator.compacted_outcome_count, 1);
        assert_eq!(
            accumulator.last_outcome_digest,
            current_outcome.outcome_digest
        );
        let compacted_wire =
            encode_private_oram_mutation_tagged_authority_wire_json_v2(&compacted).unwrap();
        assert!(decode_private_oram_mutation_authority_wire_json_v2(&compacted_wire).is_ok());
        let acknowledgement_retry_context = private_oram_mutation_aggregate_apply_context_for_test(
            &compacted,
            PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
            acknowledgement.acknowledgement_digest.clone(),
            1,
            17,
        )
        .unwrap();
        assert_eq!(
            apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                &compacted,
                acknowledgement_canonical_json,
                acknowledgement_retry_context,
            )
            .unwrap(),
            compacted
        );
        let challenge = PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: aggregate
                .activation
                .collection_incarnation_digest
                .clone(),
            activation_anchor_digest: aggregate.activation.anchor_digest.clone(),
            capability_epoch: aggregate.activation.compatibility_epoch,
            protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
            membership_epoch: 7,
            reservation_intent_digest: reservation_intent.intent_digest().to_string(),
            checkpoint_context_digest: checkpoint_context.context_digest().to_string(),
            committed_challenge_digest: prepared_challenge.prepared_challenge_digest().to_string(),
            challenge_applied_term: challenge_applied.term,
            challenge_applied_index: challenge_applied.index,
            attempt_id: base_reservation.attempt_id().to_string(),
            challenge_nonce: owner_nonce,
            expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest().to_string(),
            expected_checkpoint_sequence: checkpoint.checkpoint_sequence(),
            expected_owner_target_digest: owner_target.target_digest().to_string(),
            reserved_terminal_intent_key: owner_target.intent_key().to_string(),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: checkpoint.owner_enrollment_id().to_string(),
            owner_peer_id: checkpoint.owner_peer_id(),
            owner_store_incarnation_digest: checkpoint
                .lifecycle_state()
                .owner_store_incarnation_digest
                .clone(),
            authority_registry_digest: digest(22),
            owner_registry_digest: digest(23),
        };
        let prepare = sign_private_oram_owner_reservation_prepare_v1(
            &owner_key,
            challenge,
            checkpoint.lifecycle_state().clone(),
            checkpoint.lifecycle_state().generation,
            digest(37),
            checkpoint.owner_signer().clone(),
        )
        .unwrap();
        let binding =
            private_oram_owner_checkpoint_reservation_binding_v1(0, checkpoint, prepare).unwrap();
        let reservation = private_oram_mutation_append_reservation_v3(
            base_reservation,
            reservation_intent,
            checkpoint_context.clone(),
            prepared_challenge,
            challenge_applied,
            vec![binding],
        )
        .unwrap();
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v3(&reservation).unwrap();
        let stale_final_context = private_oram_mutation_aggregate_apply_context_for_test(
            &cancelled,
            PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3,
            reservation.reservation_digest_v3().to_string(),
            1,
            16,
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_authority_create_append_reservation_v3(
                &cancelled,
                reservation_canonical_json.clone(),
                stale_final_context,
            )
            .is_err()
        );
        let apply_context = private_oram_mutation_aggregate_apply_context_for_test(
            &challenged,
            PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3,
            reservation.reservation_digest_v3().to_string(),
            1,
            14,
        )
        .unwrap();
        let reserved = apply_private_oram_mutation_authority_create_append_reservation_v3(
            &challenged,
            reservation_canonical_json.clone(),
            apply_context,
        )
        .unwrap();
        let reserved_aggregate = reserved.aggregate().unwrap();
        let active = reserved_aggregate.active_append_attempt().unwrap();
        let transition = active.checkpoint_lease_transition.as_ref().unwrap();
        assert_eq!(active.version, ACTIVE_APPEND_ATTEMPT_VERSION_V3);
        assert_eq!(
            transition.prelease_table_sequence,
            checkpoint_context.checkpoint_table_sequence()
        );
        assert_eq!(
            transition.prelease_table_digest,
            checkpoint_context.checkpoint_table_digest()
        );
        assert_eq!(
            transition.postlease_table_sequence,
            reserved_aggregate.owner_checkpoint_table().table_sequence()
        );
        assert_eq!(
            transition.postlease_table_digest,
            reserved_aggregate.owner_checkpoint_table().table_digest()
        );

        let encoded =
            encode_private_oram_mutation_tagged_authority_wire_json_v2(&reserved).unwrap();
        assert!(decode_private_oram_mutation_authority_wire_json_v2(&encoded).is_ok());
        let mut tampered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        tampered["authority"]["state"]["active_append_attempt"]["checkpoint_lease_transition"]["postlease_table_digest"] =
            serde_json::Value::String(digest(99));
        assert!(matches!(
            decode_private_oram_mutation_authority_wire_json_v2(
                &serde_json::to_vec(&tampered).unwrap()
            ),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        assert_prepared_rejection_requires_owner_acknowledgement(
            &reserved, &manifest, &owner_key, None,
        );

        let rejection_request_digest =
            decode_private_oram_mutation_append_reservation_wire(&reservation_canonical_json)
                .unwrap()
                .reserved_rejection_request_digest()
                .unwrap();
        let rejection_context = private_oram_mutation_aggregate_apply_context_for_test(
            &reserved,
            PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected,
            rejection_request_digest,
            1,
            15,
        )
        .unwrap();
        let rejected = apply_private_oram_mutation_authority_reserved_attempt_rejected_v2(
            &reserved,
            reservation_canonical_json,
            rejection_context,
        )
        .unwrap();
        let rejected_aggregate = rejected.aggregate().unwrap();
        assert!(
            rejected_aggregate
                .preadmission_recovery_candidate()
                .unwrap()
                .is_none()
        );
        assert!(
            rejected_aggregate
                .rejected_admission_acknowledgement(&lease)
                .unwrap()
                .is_none()
        );
        let finalized_outcome = &rejected_aggregate.reservation_challenge_outcomes()[0];
        let abort_authority_digest = rejected_aggregate
            .append_outcomes()
            .iter()
            .find(|outcome| {
                outcome.kind == PrivateOramMutationAppendOutcomeKindV2::PrestageAborted
                    && outcome.attempt_id == finalized_outcome.attempt_id
            })
            .unwrap()
            .outcome_digest
            .clone();
        let exact_unsigned = PrivateOramOwnerReservationResolutionReceiptV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
            disposition:
                PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 11,
            committed_challenge_digest: finalized_outcome.challenge_digest.clone(),
            reservation_intent_digest: finalized_outcome.reservation_intent_digest.clone(),
            attempt_id: finalized_outcome.attempt_id.clone(),
            challenge_applied_term: finalized_outcome.challenge_applied.term,
            challenge_applied_index: finalized_outcome.challenge_applied.index,
            resolution_applied_term: finalized_outcome.resolution_applied.term,
            resolution_applied_index: finalized_outcome.resolution_applied.index,
            reserved_terminal_intent_key: reservation.base_reservation().owner_targets()[0]
                .intent_key()
                .to_string(),
            finalized_reservation_digest: finalized_outcome.finalized_reservation_digest.clone(),
            durable_fence_record_digest: digest(37),
            owner_store_incarnation_digest: checkpoint_context.owner_expectations()[0]
                .owner_store_incarnation_digest()
                .to_string(),
            owner_store_binding_digest: checkpoint_context.owner_expectations()[0]
                .expected_checkpoint_record_digest()
                .to_string(),
            installed_intent_marker_digest: None,
            installed_prestage_receipt_digest: None,
            installed_package_sha256: None,
            abort_release_authority_digest: Some(abort_authority_digest),
            abort_release_marker_digest: Some(digest(91)),
            local_resolution_record_digest: digest(92),
        };
        let mut wrong_fence_unsigned = exact_unsigned.clone();
        wrong_fence_unsigned.durable_fence_record_digest = digest(93);
        let wrong_fence_receipt = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &owner_key,
            wrong_fence_unsigned,
            private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap(),
        )
        .unwrap();
        let wrong_fence_acknowledgement =
            private_oram_mutation_reservation_outcome_acknowledgement_v1(
                finalized_outcome.outcome_digest.clone(),
                vec![wrong_fence_receipt],
            )
            .unwrap();
        let wrong_fence_context = private_oram_mutation_aggregate_apply_context_for_test(
            &rejected,
            PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
            wrong_fence_acknowledgement.acknowledgement_digest.clone(),
            1,
            16,
        )
        .unwrap();
        assert!(
            apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                &rejected,
                encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                    &wrong_fence_acknowledgement,
                )
                .unwrap(),
                wrong_fence_context,
            )
            .is_err()
        );

        let exact_receipt = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &owner_key,
            exact_unsigned,
            private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap(),
        )
        .unwrap();
        let exact_acknowledgement = private_oram_mutation_reservation_outcome_acknowledgement_v1(
            finalized_outcome.outcome_digest.clone(),
            vec![exact_receipt],
        )
        .unwrap();
        let exact_context = private_oram_mutation_aggregate_apply_context_for_test(
            &rejected,
            PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
            exact_acknowledgement.acknowledgement_digest.clone(),
            1,
            16,
        )
        .unwrap();
        let finalized_compacted =
            apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                &rejected,
                encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                    &exact_acknowledgement,
                )
                .unwrap(),
                exact_context,
            )
            .unwrap();
        assert!(
            finalized_compacted
                .aggregate()
                .unwrap()
                .reservation_challenge_outcomes()
                .is_empty()
        );
    }

    fn assert_prepared_rejection_requires_owner_acknowledgement(
        reserved: &PrivateOramMutationAuthorityStateV2,
        manifest: &PrivateOramMutationAllOwnersPrestagedV2,
        owner_key: &Ed25519KeyPair,
        preceding_acknowledgement: Option<&PrivateOramMutationReservationOutcomeAcknowledgementV1>,
    ) {
        use crate::content_manager::private_oram_mutation_journal::encode_private_oram_mutation_admission_recovery_manifest_v2;

        let aggregate = reserved.aggregate().unwrap();
        let base_index = aggregate.last_material_transition.locator.index;
        assert!(
            aggregate
                .preadmission_recovery_candidate()
                .unwrap()
                .is_none()
        );
        let active = aggregate.active_append_attempt().unwrap();
        let reservation = decode_private_oram_mutation_append_reservation_wire(
            &active.reservation_canonical_json,
        )
        .unwrap();
        let lease = reservation.base_reservation().preparing_lease();
        let manifest_json =
            encode_private_oram_mutation_admission_recovery_manifest_v2(manifest).unwrap();
        let prepared = apply_private_oram_mutation_authority_append_prepared_v2(
            reserved,
            manifest_json.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                reserved,
                PrivateOramMutationMaterialOperationV2::AppendPrepared,
                reservation
                    .append_prepared_request_digest(manifest)
                    .unwrap(),
                1,
                base_index + 1,
            )
            .unwrap(),
        )
        .unwrap();
        let candidate = prepared
            .aggregate()
            .unwrap()
            .preadmission_recovery_candidate()
            .unwrap()
            .unwrap();
        assert_eq!(candidate.lease(), lease);
        assert_eq!(candidate.manifest(), manifest);
        let snapshot = candidate.prepared_snapshot().unwrap();
        assert_eq!(snapshot.reservation(), reservation.base_reservation());
        assert_eq!(snapshot.prepared(), manifest);
        assert_eq!(
            snapshot.expected_aggregate_digest(),
            prepared.aggregate().unwrap().aggregate_digest
        );

        // Reserved-only cancellation must remain unavailable once an append is prepared.
        assert!(
            apply_private_oram_mutation_authority_reserved_attempt_rejected_v2(
                &prepared,
                active.reservation_canonical_json.clone(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &prepared,
                    PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected,
                    reservation.reserved_rejection_request_digest().unwrap(),
                    1,
                    base_index + 2,
                )
                .unwrap(),
            )
            .is_err()
        );
        let rejected = apply_private_oram_mutation_authority_admission_rejected_v2(
            &prepared,
            lease.clone(),
            manifest_json,
            // Rejection advances aggregate history without changing the lease/state binding.
            private_oram_mutation_aggregate_apply_context_with_outer_binding_for_test(
                &prepared,
                PrivateOramMutationMaterialOperationV2::AdmissionRejected,
                private_oram_mutation_admission_request_digest_v2(
                    lease,
                    manifest.manifest_digest(),
                )
                .unwrap(),
                prepared.aggregate().unwrap().outer_binding_digest.clone(),
                1,
                base_index + 2,
            )
            .unwrap(),
        )
        .unwrap();
        let rejected_aggregate = rejected.aggregate().unwrap();
        assert_eq!(rejected_aggregate.lease_slot, aggregate.lease_slot);
        assert!(rejected_aggregate.active_append_attempt().is_none());
        let candidate = rejected_aggregate
            .preadmission_recovery_candidate()
            .unwrap()
            .unwrap();
        assert_eq!(candidate.lease(), lease);
        assert_eq!(candidate.manifest(), manifest);
        assert!(candidate.prepared_snapshot().is_none());
        assert!(
            rejected_aggregate
                .rejected_admission_acknowledgement(lease)
                .unwrap()
                .is_none()
        );

        let ack_ready = if let Some(acknowledgement) = preceding_acknowledgement {
            assert_eq!(rejected_aggregate.reservation_challenge_outcomes().len(), 2);
            let after_head = apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                &rejected,
                encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(acknowledgement).unwrap(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &rejected,
                    PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                    acknowledgement.acknowledgement_digest.clone(),
                    1,
                    base_index + 3,
                ).unwrap(),
            ).unwrap();
            let after_head_aggregate = after_head.aggregate().unwrap();
            assert_eq!(
                after_head_aggregate.reservation_challenge_outcomes().len(),
                1
            );
            assert!(
                after_head_aggregate
                    .rejected_admission_acknowledgement(lease)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                after_head_aggregate
                    .preadmission_recovery_candidate()
                    .unwrap()
                    .unwrap(),
                candidate
            );
            after_head
        } else {
            rejected.clone()
        };
        let rejected_aggregate = ack_ready.aggregate().unwrap();

        let outcome = &rejected_aggregate.reservation_challenge_outcomes()[0];
        let expected =
            expected_owner_reservation_completions_v1(outcome, rejected_aggregate).unwrap();
        assert_eq!(expected.len(), 1);
        let expected = &expected[0];
        let receipt = sign_private_oram_owner_reservation_resolution_receipt_v1(
            owner_key,
            PrivateOramOwnerReservationResolutionReceiptV1 {
                version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
                disposition: PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled,
                collection_id: expected.collection_id.clone(),
                owner_peer_id: expected.owner_peer_id,
                committed_challenge_digest: expected.committed_challenge_digest.clone(),
                reservation_intent_digest: expected.reservation_intent_digest.clone(),
                attempt_id: expected.attempt_id.clone(),
                challenge_applied_term: expected.challenge_applied.term,
                challenge_applied_index: expected.challenge_applied.index,
                resolution_applied_term: expected.resolution_applied.term,
                resolution_applied_index: expected.resolution_applied.index,
                reserved_terminal_intent_key: expected.reserved_terminal_intent_key.clone(),
                finalized_reservation_digest: expected.finalized_reservation_digest.clone(),
                durable_fence_record_digest: expected.durable_fence_record_digest.clone().unwrap(),
                owner_store_incarnation_digest: expected.owner_store_incarnation_digest.clone(),
                owner_store_binding_digest: expected.owner_store_binding_digest.clone(),
                installed_intent_marker_digest: Some(digest(94)),
                installed_prestage_receipt_digest: expected
                    .installed_prestage_receipt_digest
                    .clone(),
                installed_package_sha256: Some(expected.installed_package_sha256.clone()),
                abort_release_authority_digest: None,
                abort_release_marker_digest: None,
                local_resolution_record_digest: digest(95),
            },
            private_oram_owner_cleanup_signer_v1(owner_key, 1).unwrap(),
        )
        .unwrap();
        let acknowledgement = private_oram_mutation_reservation_outcome_acknowledgement_v1(
            outcome.outcome_digest.clone(),
            vec![receipt],
        )
        .unwrap();
        let acknowledged =
            apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                &ack_ready,
                encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                    &acknowledgement,
                )
                .unwrap(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &ack_ready,
                    PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                    acknowledgement.acknowledgement_digest.clone(),
                    1,
                    base_index + 3 + u64::from(preceding_acknowledgement.is_some()),
                )
                .unwrap(),
            )
            .unwrap();
        let acknowledged_aggregate = acknowledged.aggregate().unwrap();
        assert!(
            acknowledged_aggregate
                .reservation_challenge_outcomes()
                .is_empty()
        );
        assert!(
            acknowledged_aggregate
                .preadmission_recovery_candidate()
                .unwrap()
                .is_none()
        );
        let proof = acknowledged_aggregate
            .rejected_admission_acknowledgement(lease)
            .unwrap()
            .unwrap();
        assert_eq!(proof.lease(), lease);
        assert_eq!(proof.recovery_manifest_digest(), manifest.manifest_digest());
        assert_eq!(
            proof.rejection_digest(),
            rejected_aggregate.rejected_admissions[0].rejection_digest
        );
        let mut different_lease = lease.clone();
        different_lease.mutation_id = digest(96);
        assert!(
            acknowledged_aggregate
                .rejected_admission_acknowledgement(&different_lease)
                .unwrap()
                .is_none()
        );

        // Reopening consensus data preserves the exact proof after the pending outcome is gone.
        let encoded =
            encode_private_oram_mutation_tagged_authority_wire_json_v2(&acknowledged).unwrap();
        let decoded = decode_private_oram_mutation_authority_wire_json_v2(&encoded).unwrap();
        let reopened = decoded.tagged_authority().unwrap().aggregate().unwrap();
        assert_eq!(
            reopened.rejected_admission_acknowledgement(lease).unwrap(),
            Some(proof)
        );
        let mut missing_rejection = reopened.clone();
        missing_rejection.rejected_admissions.clear();
        assert!(
            missing_rejection
                .rejected_admission_acknowledgement(lease)
                .unwrap()
                .is_none()
        );
        let mut missing_acknowledgement = reopened.clone();
        missing_acknowledgement.reservation_challenge_outcome_accumulator = None;
        assert!(
            missing_acknowledgement
                .rejected_admission_acknowledgement(lease)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cancelled_fifo_head_ack_preserves_later_finalized_checkpoint_leases() {
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[12; 32]).unwrap();
        let enrolled = enrolled_authority(&owner_key);
        let enrolled_aggregate = enrolled.aggregate().unwrap();
        let lease_a = PrivateOramMutationLease {
            generation: 1,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 11,
            mutation_id: digest(101),
            signed_mutation_digest: digest(102),
            transition_digest: digest(103),
            base_record_digest: digest(104),
            base_state_sequence: 0,
            writer_lease_digest: digest(105),
            writer_fence: 1,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let (base_a, _) = private_oram_mutation_append_fixture_for_test(
            &lease_a,
            enrolled_aggregate.append_authority_context().unwrap(),
            1,
            &[11],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(106)),
        );
        let intent_a = private_oram_mutation_reservation_intent_v3(&base_a).unwrap();
        let checkpoints_a = private_oram_owner_checkpoint_reservation_context_v1(
            enrolled_aggregate.owner_checkpoint_table(),
            intent_a.intent_digest().to_string(),
        )
        .unwrap();
        let challenge_a = private_oram_mutation_prepared_reservation_challenge_v3(
            base_a.clone(),
            intent_a,
            checkpoints_a.clone(),
            vec![BASE64URL_NOPAD.encode(&[107; 16])],
        )
        .unwrap();
        let challenged_a =
            apply_private_oram_mutation_authority_prepare_append_reservation_challenge_v3(
                &enrolled,
                encode_private_oram_mutation_prepared_reservation_challenge_v3(&challenge_a)
                    .unwrap(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &enrolled,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
                    challenge_a.prepared_challenge_digest().to_string(),
                    1,
                    13,
                )
                .unwrap(),
            )
            .unwrap();
        let cancellation_a = private_oram_mutation_reservation_challenge_cancellation_v1(
            challenged_a
                .aggregate()
                .unwrap()
                .pending_reservation_challenge()
                .unwrap(),
            digest(108),
        )
        .unwrap();
        let cancelled_a =
            apply_private_oram_mutation_authority_cancel_append_reservation_challenge_v3(
                &challenged_a,
                encode_private_oram_mutation_reservation_challenge_cancellation_v1(&cancellation_a)
                    .unwrap(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &challenged_a,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled,
                    cancellation_a.cancellation_digest.clone(),
                    1,
                    14,
                )
                .unwrap(),
            )
            .unwrap();
        let outcome_a = cancelled_a
            .aggregate()
            .unwrap()
            .reservation_challenge_outcomes()[0]
            .clone();
        let owner_target_a = &base_a.owner_targets()[0];
        let receipt_a = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &owner_key,
            PrivateOramOwnerReservationResolutionReceiptV1 {
                version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
                disposition: PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased,
                collection_id: "collection-a".to_string(),
                owner_peer_id: 11,
                committed_challenge_digest: outcome_a.challenge_digest.clone(),
                reservation_intent_digest: outcome_a.reservation_intent_digest.clone(),
                attempt_id: outcome_a.attempt_id.clone(),
                challenge_applied_term: outcome_a.challenge_applied.term,
                challenge_applied_index: outcome_a.challenge_applied.index,
                resolution_applied_term: outcome_a.resolution_applied.term,
                resolution_applied_index: outcome_a.resolution_applied.index,
                reserved_terminal_intent_key: owner_target_a.intent_key().to_string(),
                finalized_reservation_digest: None,
                durable_fence_record_digest: digest(109),
                owner_store_incarnation_digest: checkpoints_a.owner_expectations()[0]
                    .owner_store_incarnation_digest()
                    .to_string(),
                owner_store_binding_digest: checkpoints_a.owner_expectations()[0]
                    .expected_checkpoint_record_digest()
                    .to_string(),
                installed_intent_marker_digest: None,
                installed_prestage_receipt_digest: None,
                installed_package_sha256: None,
                abort_release_authority_digest: None,
                abort_release_marker_digest: None,
                local_resolution_record_digest: digest(110),
            },
            private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap(),
        )
        .unwrap();

        let cancelled_aggregate = cancelled_a.aggregate().unwrap();
        let lease_b = PrivateOramMutationLease {
            generation: 1,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 11,
            mutation_id: digest(111),
            signed_mutation_digest: digest(112),
            transition_digest: digest(113),
            base_record_digest: digest(114),
            base_state_sequence: 0,
            writer_lease_digest: digest(115),
            writer_fence: 1,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let (base_b, manifest_b) = private_oram_mutation_append_fixture_for_test(
            &lease_b,
            cancelled_aggregate.append_authority_context().unwrap(),
            1,
            &[11],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(116)),
        );
        let intent_b = private_oram_mutation_reservation_intent_v3(&base_b).unwrap();
        let checkpoints_b = private_oram_owner_checkpoint_reservation_context_v1(
            cancelled_aggregate.owner_checkpoint_table(),
            intent_b.intent_digest().to_string(),
        )
        .unwrap();
        let challenge_b = private_oram_mutation_prepared_reservation_challenge_v3(
            base_b.clone(),
            intent_b.clone(),
            checkpoints_b.clone(),
            vec![BASE64URL_NOPAD.encode(&[117; 16])],
        )
        .unwrap();
        let challenge_b_applied = PrivateOramRaftApplyLocatorV2 {
            version: APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            term: 1,
            index: 15,
        };
        let challenged_b =
            apply_private_oram_mutation_authority_prepare_append_reservation_challenge_v3(
                &cancelled_a,
                encode_private_oram_mutation_prepared_reservation_challenge_v3(&challenge_b)
                    .unwrap(),
                private_oram_mutation_aggregate_apply_context_for_test(
                    &cancelled_a,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
                    challenge_b.prepared_challenge_digest().to_string(),
                    1,
                    15,
                )
                .unwrap(),
            )
            .unwrap();
        let checkpoint_b = &cancelled_aggregate.owner_checkpoint_table().checkpoints()[0];
        let owner_target_b = &base_b.owner_targets()[0];
        let owner_challenge_b = PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: cancelled_aggregate
                .activation
                .collection_incarnation_digest
                .clone(),
            activation_anchor_digest: cancelled_aggregate.activation.anchor_digest.clone(),
            capability_epoch: cancelled_aggregate.activation.compatibility_epoch,
            protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
            membership_epoch: 7,
            reservation_intent_digest: intent_b.intent_digest().to_string(),
            checkpoint_context_digest: checkpoints_b.context_digest().to_string(),
            committed_challenge_digest: challenge_b.prepared_challenge_digest().to_string(),
            challenge_applied_term: challenge_b_applied.term,
            challenge_applied_index: challenge_b_applied.index,
            attempt_id: base_b.attempt_id().to_string(),
            challenge_nonce: BASE64URL_NOPAD.encode(&[117; 16]),
            expected_checkpoint_record_digest: checkpoint_b.checkpoint_record_digest().to_string(),
            expected_checkpoint_sequence: checkpoint_b.checkpoint_sequence(),
            expected_owner_target_digest: owner_target_b.target_digest().to_string(),
            reserved_terminal_intent_key: owner_target_b.intent_key().to_string(),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: checkpoint_b.owner_enrollment_id().to_string(),
            owner_peer_id: checkpoint_b.owner_peer_id(),
            owner_store_incarnation_digest: checkpoint_b
                .lifecycle_state()
                .owner_store_incarnation_digest
                .clone(),
            authority_registry_digest: digest(22),
            owner_registry_digest: digest(23),
        };
        let durable_fence_digest_b = digest(118);
        let prepare_b = sign_private_oram_owner_reservation_prepare_v1(
            &owner_key,
            owner_challenge_b,
            checkpoint_b.lifecycle_state().clone(),
            checkpoint_b.lifecycle_state().generation,
            durable_fence_digest_b.clone(),
            checkpoint_b.owner_signer().clone(),
        )
        .unwrap();
        let binding_b =
            private_oram_owner_checkpoint_reservation_binding_v1(0, checkpoint_b, prepare_b)
                .unwrap();
        let reservation_b = private_oram_mutation_append_reservation_v3(
            base_b,
            intent_b,
            checkpoints_b.clone(),
            challenge_b,
            challenge_b_applied,
            vec![binding_b],
        )
        .unwrap();
        let reservation_b_json =
            encode_private_oram_mutation_append_reservation_v3(&reservation_b).unwrap();
        let reserved_b = apply_private_oram_mutation_authority_create_append_reservation_v3(
            &challenged_b,
            reservation_b_json.clone(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &challenged_b,
                PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3,
                reservation_b.reservation_digest_v3().to_string(),
                1,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let rejection_digest_b =
            decode_private_oram_mutation_append_reservation_wire(&reservation_b_json)
                .unwrap()
                .reserved_rejection_request_digest()
                .unwrap();
        let preceding_acknowledgement =
            private_oram_mutation_reservation_outcome_acknowledgement_v1(
                outcome_a.outcome_digest.clone(),
                vec![receipt_a.clone()],
            )
            .unwrap();
        assert_prepared_rejection_requires_owner_acknowledgement(
            &reserved_b,
            &manifest_b,
            &owner_key,
            Some(&preceding_acknowledgement),
        );
        let rejected_b = apply_private_oram_mutation_authority_reserved_attempt_rejected_v2(
            &reserved_b,
            reservation_b_json,
            private_oram_mutation_aggregate_apply_context_for_test(
                &reserved_b,
                PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected,
                rejection_digest_b,
                1,
                17,
            )
            .unwrap(),
        )
        .unwrap();
        let rejected_b_aggregate = rejected_b.aggregate().unwrap();
        assert_eq!(
            rejected_b_aggregate.reservation_challenge_outcomes().len(),
            2
        );
        assert!(
            rejected_b_aggregate
                .owner_checkpoint_table()
                .has_active_leases()
        );
        let leased_table_digest = rejected_b_aggregate
            .owner_checkpoint_table()
            .table_digest()
            .to_string();

        let acknowledgement_a = private_oram_mutation_reservation_outcome_acknowledgement_v1(
            outcome_a.outcome_digest.clone(),
            vec![receipt_a],
        )
        .unwrap();
        let after_a = apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
            &rejected_b,
            encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(&acknowledgement_a)
                .unwrap(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &rejected_b,
                PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                acknowledgement_a.acknowledgement_digest.clone(),
                1,
                18,
            )
            .unwrap(),
        )
        .unwrap();
        let after_a_aggregate = after_a.aggregate().unwrap();
        assert_eq!(after_a_aggregate.reservation_challenge_outcomes().len(), 1);
        assert_eq!(
            after_a_aggregate.owner_checkpoint_table().table_digest(),
            leased_table_digest
        );
        assert!(
            after_a_aggregate
                .owner_checkpoint_table()
                .has_active_leases()
        );

        let outcome_b = &after_a_aggregate.reservation_challenge_outcomes()[0];
        let abort_authority_b = after_a_aggregate
            .append_outcomes()
            .iter()
            .find(|outcome| {
                outcome.kind == PrivateOramMutationAppendOutcomeKindV2::PrestageAborted
                    && outcome.attempt_id == outcome_b.attempt_id
            })
            .unwrap()
            .outcome_digest
            .clone();
        let receipt_b = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &owner_key,
            PrivateOramOwnerReservationResolutionReceiptV1 {
                version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
                disposition:
                    PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort,
                collection_id: "collection-a".to_string(),
                owner_peer_id: 11,
                committed_challenge_digest: outcome_b.challenge_digest.clone(),
                reservation_intent_digest: outcome_b.reservation_intent_digest.clone(),
                attempt_id: outcome_b.attempt_id.clone(),
                challenge_applied_term: outcome_b.challenge_applied.term,
                challenge_applied_index: outcome_b.challenge_applied.index,
                resolution_applied_term: outcome_b.resolution_applied.term,
                resolution_applied_index: outcome_b.resolution_applied.index,
                reserved_terminal_intent_key: reservation_b.base_reservation().owner_targets()[0]
                    .intent_key()
                    .to_string(),
                finalized_reservation_digest: outcome_b.finalized_reservation_digest.clone(),
                durable_fence_record_digest: durable_fence_digest_b,
                owner_store_incarnation_digest: checkpoints_b.owner_expectations()[0]
                    .owner_store_incarnation_digest()
                    .to_string(),
                owner_store_binding_digest: checkpoints_b.owner_expectations()[0]
                    .expected_checkpoint_record_digest()
                    .to_string(),
                installed_intent_marker_digest: None,
                installed_prestage_receipt_digest: None,
                installed_package_sha256: None,
                abort_release_authority_digest: Some(abort_authority_b),
                abort_release_marker_digest: Some(digest(119)),
                local_resolution_record_digest: digest(120),
            },
            private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap(),
        )
        .unwrap();
        let acknowledgement_b = private_oram_mutation_reservation_outcome_acknowledgement_v1(
            outcome_b.outcome_digest.clone(),
            vec![receipt_b],
        )
        .unwrap();
        let after_b = apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
            &after_a,
            encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(&acknowledgement_b)
                .unwrap(),
            private_oram_mutation_aggregate_apply_context_for_test(
                &after_a,
                PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                acknowledgement_b.acknowledgement_digest.clone(),
                1,
                19,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            after_b
                .aggregate()
                .unwrap()
                .reservation_challenge_outcomes()
                .is_empty()
        );
        assert!(
            !after_b
                .aggregate()
                .unwrap()
                .owner_checkpoint_table()
                .has_active_leases()
        );
    }

    #[test]
    fn strict_wire_decoder_never_falls_back_after_a_tag_is_observed() {
        let slot = raw_slot();
        let malformed_tagged = serde_json::to_vec(&json!({
            "envelope_version": AUTHORITY_WIRE_ENVELOPE_VERSION,
            "authority": {
                "mode": "legacy",
                "state": slot,
            },
        }))
        .unwrap();
        assert!(matches!(
            decode_private_oram_mutation_authority_wire_json_v2(&malformed_tagged),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        for malformed in [
            br#"{"envelope_version":2}"#.as_slice(),
            br#"{"envelope_version":3,"authority":{"mode":"legacy","state":{}}}"#.as_slice(),
            br#"{"envelope_version":2,"authority":{"mode":"unknown","state":{}}}"#.as_slice(),
            br#"{"envelope_version":2,"authority":{},"extra":0}"#.as_slice(),
            br#"{"envelope_version":2,"envelope_version":2,"authority":{}}"#.as_slice(),
            br#"{"envelope_version":2,"authority":{"mode":"legacy","mode":"legacy","state":{}}}"#
                .as_slice(),
            br#"{"mode":"legacy","state":{}}"#.as_slice(),
        ] {
            assert!(matches!(
                decode_private_oram_mutation_authority_wire_json_v2(malformed),
                Err(PrivateOramMutationJournalError::Corrupt)
            ));
        }
    }

    #[test]
    fn strict_wire_decoder_rejects_noncanonical_historical_raw_objects() {
        let duplicate = br#"{"version":2,"version":2,"generation":0,"active":null,"last_clear":null,"max_writer_fence":0}"#;
        let unknown = br#"{"version":2,"generation":0,"active":null,"last_clear":null,"max_writer_fence":0,"extra":0}"#;
        let missing = br#"{"version":2,"generation":0,"active":null,"last_clear":null}"#;
        let unsupported =
            br#"{"version":1,"generation":0,"active":null,"last_clear":null,"max_writer_fence":0}"#;
        let trailing = br#"{"version":2,"generation":0,"active":null,"last_clear":null,"max_writer_fence":0} false"#;
        for malformed in [
            duplicate.as_slice(),
            unknown.as_slice(),
            missing.as_slice(),
            unsupported.as_slice(),
            trailing.as_slice(),
        ] {
            assert!(matches!(
                decode_private_oram_mutation_authority_wire_json_v2(malformed),
                Err(PrivateOramMutationJournalError::Corrupt)
            ));
        }

        assert!(matches!(
            decode_private_oram_mutation_authority_wire_json_v2(&vec![
                b' ';
                MAX_AUTHORITY_WIRE_BYTES + 1
            ]),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn tagged_legacy_context_substitution_is_rejected() {
        let tagged =
            private_oram_mutation_legacy_authority_v2(authority_key(), raw_slot(), digest(4))
                .unwrap();
        let decoded = decode_private_oram_mutation_authority_wire_json_v2(
            &encode_private_oram_mutation_tagged_authority_wire_json_v2(&tagged).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            canonical_private_oram_mutation_legacy_authority_from_wire_v2(
                &decoded,
                &authority_key(),
                &digest(9),
            ),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }
}
