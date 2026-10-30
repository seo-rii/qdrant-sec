//! Dormant consensus lifecycle model for private-ORAM mutation cleanup.
//!
//! The model binds lease admission, the complete parent journal watermark, cleanup evidence, and
//! lease clearing into one generation chain. Production constructors for applied-entry and cleanup
//! authority are intentionally absent until the lifecycle is persisted in the Raft state machine.

#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod append_reservation_v3;
pub(crate) mod authority;
pub(crate) mod floor_store;
pub(crate) mod format;
pub(crate) mod owner_checkpoint;

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::rc::Rc;

use collection::PrivateOramOwnerPrestageReceiptV2;
use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::private_oram_mutation_watermark::{
    PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationParentWatermarkV2,
    private_oram_mutation_lease_lineage_digest_v2,
    validate_private_oram_mutation_parent_watermark_v2_cas_transition,
    validate_private_oram_mutation_parent_watermark_v2_shape,
};
use crate::content_manager::consensus_ops::{
    PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION, PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
    PrivateOramMutationClearOutcome, PrivateOramMutationClearReceiptV1, PrivateOramMutationLease,
    PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationJournalError, decode_private_oram_mutation_admission_recovery_manifest_v2,
};
use crate::content_manager::private_oram_mutation_state_v2::private_oram_collection_id_digest_v2;

pub(crate) const PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION: u16 = 1;

const APPLY_LOCATOR_VERSION: u16 = 1;
const ADMITTED_VERSION: u16 = 2;
const PARENT_PROGRESS_VERSION: u16 = 1;
const CLEANUP_WITNESS_VERSION: u16 = 1;
const CLEAR_PENDING_VERSION: u16 = 1;
const CLEARED_STATE_VERSION: u16 = 1;
const GC_CHECKPOINT_VERSION: u16 = 1;
const MAX_LEASE_DURATION_SECS: u64 = 3_600;

const LEASE_STATE_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-lease-state/v2";
const ADMISSION_REQUEST_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-admission-request/v2";
const CLEAR_RECEIPT_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-clear-receipt/v2";
const ADMITTED_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-cleanup-admitted/v2";
const PARENT_PROGRESS_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-cleanup-parent-progress/v2";
const CLEANUP_WITNESS_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-cleanup-witness/v2";
const CLEAR_PENDING_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-clear-pending/v2";
const CLEAR_CORE_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-clear-core/v2";
const CLEAR_RESOLUTION_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-clear-resolution/v2";
const CLEARED_STATE_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-cleared-state/v2";
const LIFECYCLE_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-cleanup-lifecycle/v2";
const CLEANUP_EVIDENCE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-cleanup-evidence/v2";
const LEASE_SLOT_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-lease-slot/v2";
const APPLIED_OPERATION_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-applied-operation/v2";
const CLEANUP_EXPECTATION_WIRE_VERSION_V2: u16 = 1;
const MAX_CLEANUP_EXPECTATION_CANONICAL_JSON_BYTES_V2: usize = 256 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramRaftApplyLocatorV2 {
    version: u16,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    term: u64,
    index: u64,
}

impl PrivateOramRaftApplyLocatorV2 {
    pub(crate) fn term(&self) -> u64 {
        self.term
    }

    pub(crate) fn index(&self) -> u64 {
        self.index
    }
}

impl Debug for PrivateOramRaftApplyLocatorV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramRaftApplyLocatorV2")
            .field("version", &self.version)
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("term", &self.term)
            .field("index", &self.index)
            .finish()
    }
}

/// Proof that a lifecycle transition is executing from an applied Raft entry.
///
/// This token is deliberately non-serializable, non-cloneable, and neither `Send` nor `Sync`.
pub(crate) struct PrivateOramAppliedEntryV2 {
    locator: PrivateOramRaftApplyLocatorV2,
    operation_kind: PrivateOramMutationCleanupOperationKindV2,
    operation_digest: String,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Debug for PrivateOramAppliedEntryV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramAppliedEntryV2")
            .field("locator", &self.locator)
            .field("operation_kind", &self.operation_kind)
            .field("operation_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PrivateOramMutationCleanupOperationKindV2 {
    Admission,
    ParentProgress,
    CleanupWitness,
    ClearPending,
    Clear,
    ClearAcknowledgement,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationAdmittedV2 {
    version: u16,
    collection_id_digest: String,
    generation: u64,
    owner_peer_id: PeerId,
    mutation_id: String,
    signed_mutation_digest: String,
    base_record_digest: String,
    lease_lineage_digest: String,
    admitted_lease_state_digest: String,
    recovery_manifest_digest: String,
    recovery_manifest_canonical_json: String,
    admission_request_digest: String,
    predecessor_tombstone_digest: Option<String>,
    admission_applied: PrivateOramRaftApplyLocatorV2,
    admitted_digest: String,
}

impl Debug for PrivateOramMutationAdmittedV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAdmittedV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("admission_applied", &self.admission_applied)
            .field("collection_id_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("base_record_digest", &"[redacted]")
            .field("lease_lineage_digest", &"[redacted]")
            .field("admitted_lease_state_digest", &"[redacted]")
            .field("recovery_manifest_digest", &"[redacted]")
            .field(
                "recovery_manifest_bytes",
                &self.recovery_manifest_canonical_json.len(),
            )
            .field("admission_request_digest", &"[redacted]")
            .field("predecessor_tombstone_digest", &"[redacted]")
            .field("admitted_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationParentProgressV2 {
    version: u16,
    admitted: PrivateOramMutationAdmittedV2,
    watermark: PrivateOramMutationParentWatermarkV2,
    progress_applied_history: Vec<PrivateOramRaftApplyLocatorV2>,
    progress_applied: PrivateOramRaftApplyLocatorV2,
    progress_digest: String,
}

impl Debug for PrivateOramMutationParentProgressV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationParentProgressV2")
            .field("version", &self.version)
            .field("admitted", &self.admitted)
            .field("watermark", &self.watermark)
            .field(
                "progress_applied_history_count",
                &self.progress_applied_history.len(),
            )
            .field("progress_applied", &self.progress_applied)
            .field("progress_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationCleanupWitnessV2 {
    version: u16,
    admitted: PrivateOramMutationAdmittedV2,
    terminal_watermark: PrivateOramMutationParentWatermarkV2,
    terminal_record_digest: String,
    terminal_lease: PrivateOramMutationLease,
    terminal_lease_state_digest: String,
    outcome: PrivateOramMutationClearOutcome,
    terminal_consensus_state_digest: String,
    terminal_consensus_state_sequence: u64,
    owner_cleanup_evidence_digest: String,
    point_cleanup_evidence_digest: String,
    parent_progress_applied_history: Vec<PrivateOramRaftApplyLocatorV2>,
    parent_progress_applied: PrivateOramRaftApplyLocatorV2,
    witness_applied: PrivateOramRaftApplyLocatorV2,
    witness_digest: String,
}

impl Debug for PrivateOramMutationCleanupWitnessV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationCleanupWitnessV2")
            .field("version", &self.version)
            .field("admitted", &self.admitted)
            .field("terminal_watermark", &self.terminal_watermark)
            .field("outcome", &self.outcome)
            .field("terminal_lease", &self.terminal_lease)
            .field("terminal_record_digest", &"[redacted]")
            .field("terminal_lease_state_digest", &"[redacted]")
            .field("terminal_consensus_state_digest", &"[redacted]")
            .field(
                "terminal_consensus_state_sequence",
                &self.terminal_consensus_state_sequence,
            )
            .field("owner_cleanup_evidence_digest", &"[redacted]")
            .field("point_cleanup_evidence_digest", &"[redacted]")
            .field(
                "parent_progress_applied_history_count",
                &self.parent_progress_applied_history.len(),
            )
            .field("parent_progress_applied", &self.parent_progress_applied)
            .field("witness_applied", &self.witness_applied)
            .field("witness_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationClearPendingV2 {
    version: u16,
    witness: PrivateOramMutationCleanupWitnessV2,
    clear_attempt_id_digest: String,
    expected_clear_receipt_digest: String,
    pending_applied: PrivateOramRaftApplyLocatorV2,
    pending_digest: String,
}

impl Debug for PrivateOramMutationClearPendingV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationClearPendingV2")
            .field("version", &self.version)
            .field("witness", &self.witness)
            .field("pending_applied", &self.pending_applied)
            .field("clear_attempt_id_digest", &"[redacted]")
            .field("expected_clear_receipt_digest", &"[redacted]")
            .field("pending_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationClearResolutionV2 {
    Pending,
    Acknowledged(PrivateOramMutationClearAcknowledgedV2),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationClearAcknowledgedV2 {
    acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationClearedStateV2 {
    version: u16,
    collection_id_digest: String,
    generation: u64,
    owner_peer_id: PeerId,
    mutation_id: String,
    signed_mutation_digest: String,
    descriptor_digest: String,
    terminal_watermark: PrivateOramMutationParentWatermarkV2,
    terminal_record_digest: String,
    lease_lineage_digest: String,
    terminal_lease_state_digest: String,
    cleanup_witness: PrivateOramMutationCleanupWitnessV2,
    witness_digest: String,
    clear_attempt_id_digest: String,
    clear_pending_digest: String,
    pending_applied: PrivateOramRaftApplyLocatorV2,
    clear_receipt: PrivateOramMutationClearReceiptV1,
    clear_receipt_digest: String,
    clear_applied: PrivateOramRaftApplyLocatorV2,
    previous_tombstone_digest: Option<String>,
    clear_core_digest: String,
    resolution: PrivateOramMutationClearResolutionV2,
    resolution_digest: String,
    tombstone_digest: String,
}

impl Debug for PrivateOramMutationClearedStateV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationClearedStateV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("terminal_watermark", &self.terminal_watermark)
            .field("clear_applied", &self.clear_applied)
            .field("resolution", &self.resolution)
            .field("collection_id_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("descriptor_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("lease_lineage_digest", &"[redacted]")
            .field("terminal_lease_state_digest", &"[redacted]")
            .field("cleanup_witness", &self.cleanup_witness)
            .field("witness_digest", &"[redacted]")
            .field("clear_attempt_id_digest", &"[redacted]")
            .field("clear_pending_digest", &"[redacted]")
            .field("pending_applied", &self.pending_applied)
            .field("clear_receipt", &self.clear_receipt)
            .field("clear_receipt_digest", &"[redacted]")
            .field("previous_tombstone_digest", &"[redacted]")
            .field("clear_core_digest", &"[redacted]")
            .field("resolution_digest", &"[redacted]")
            .field("tombstone_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationCleanupActiveV2 {
    Admitted(PrivateOramMutationAdmittedV2),
    ParentProgress(PrivateOramMutationParentProgressV2),
    CleanupWitnessDurable(PrivateOramMutationCleanupWitnessV2),
    ClearPending(PrivateOramMutationClearPendingV2),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationCleanupLifecycleV2 {
    version: u16,
    collection_id_digest: String,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    last_cleared: Option<PrivateOramMutationClearedStateV2>,
    active: Option<PrivateOramMutationCleanupActiveV2>,
    lifecycle_digest: String,
}

impl Debug for PrivateOramMutationCleanupLifecycleV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationCleanupLifecycleV2")
            .field("version", &self.version)
            .field("has_last_cleared", &self.last_cleared.is_some())
            .field("active", &self.active)
            .field("collection_id_digest", &"[redacted]")
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("lifecycle_digest", &"[redacted]")
            .finish()
    }
}

/// Non-serializable cleanup evidence derived from authenticated owner and point cleanup.
pub(crate) struct PrivateOramMutationCleanupExpectationV2 {
    terminal_watermark: PrivateOramMutationParentWatermarkV2,
    terminal_record_digest: String,
    terminal_lease: PrivateOramMutationLease,
    terminal_lease_state_digest: String,
    outcome: PrivateOramMutationClearOutcome,
    terminal_consensus_state_digest: String,
    terminal_consensus_state_sequence: u64,
    owner_cleanup_evidence_digest: String,
    point_cleanup_evidence_digest: String,
    evidence_digest: String,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum PrivateOramMutationCleanupExpectationStatusV2 {
    NeedsWitness,
    WitnessDurable {
        witness_digest: String,
    },
    ClearPending {
        witness_digest: String,
        clear_attempt_id_digest: String,
    },
    ClearedPendingAcknowledgement {
        owner_peer_id: PeerId,
        generation: u64,
    },
    Acknowledged {
        owner_peer_id: PeerId,
        generation: u64,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationCleanupExpectationWireV2 {
    version: u16,
    terminal_watermark: PrivateOramMutationParentWatermarkV2,
    terminal_record_digest: String,
    terminal_lease: PrivateOramMutationLease,
    terminal_lease_state_digest: String,
    outcome: PrivateOramMutationClearOutcome,
    terminal_consensus_state_digest: String,
    terminal_consensus_state_sequence: u64,
    owner_cleanup_evidence_digest: String,
    point_cleanup_evidence_digest: String,
    evidence_digest: String,
}

impl Debug for PrivateOramMutationCleanupExpectationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationCleanupExpectationV2")
            .field("terminal_watermark", &self.terminal_watermark)
            .field("outcome", &self.outcome)
            .field("terminal_lease", &self.terminal_lease)
            .field(
                "terminal_consensus_state_sequence",
                &self.terminal_consensus_state_sequence,
            )
            .field("terminal_record_digest", &"[redacted]")
            .field("terminal_lease_state_digest", &"[redacted]")
            .field("terminal_consensus_state_digest", &"[redacted]")
            .field("owner_cleanup_evidence_digest", &"[redacted]")
            .field("point_cleanup_evidence_digest", &"[redacted]")
            .field("evidence_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationCleanupExpectationV2 {
    pub(crate) fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

pub(crate) fn derive_private_oram_mutation_cleanup_expectation_v2(
    terminal_watermark: PrivateOramMutationParentWatermarkV2,
    terminal_lease: PrivateOramMutationLease,
    outcome: PrivateOramMutationClearOutcome,
    terminal_consensus_state_digest: String,
    terminal_consensus_state_sequence: u64,
    owner_cleanup_evidence_digest: String,
    point_cleanup_evidence_digest: String,
) -> Result<PrivateOramMutationCleanupExpectationV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_parent_watermark_v2_shape(&terminal_watermark)?;
    validate_lease_v2(&terminal_lease)?;
    for digest in [
        &terminal_consensus_state_digest,
        &owner_cleanup_evidence_digest,
        &point_cleanup_evidence_digest,
    ] {
        validate_digest(digest)?;
    }
    if terminal_watermark.sequence() != 7
        || private_oram_mutation_lease_lineage_digest_v2(&terminal_lease)?
            != terminal_watermark.lease_lineage_digest()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let terminal_record_digest = terminal_watermark
        .record_digest()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?
        .to_string();
    let mut expected = PrivateOramMutationCleanupExpectationV2 {
        terminal_watermark,
        terminal_record_digest,
        terminal_lease: terminal_lease.clone(),
        terminal_lease_state_digest: private_oram_mutation_lease_state_digest_v2(&terminal_lease)?,
        outcome,
        terminal_consensus_state_digest,
        terminal_consensus_state_sequence,
        owner_cleanup_evidence_digest,
        point_cleanup_evidence_digest,
        evidence_digest: String::new(),
        _not_send_or_sync: PhantomData,
    };
    if !terminal_lease_matches_outcome(
        &terminal_lease,
        &expected.outcome,
        &expected.terminal_consensus_state_digest,
        expected.terminal_consensus_state_sequence,
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    expected.evidence_digest = cleanup_evidence_digest_v2(&expected)?;
    validate_cleanup_expectation_v2(&expected)?;
    Ok(expected)
}

pub(in crate::content_manager) fn encode_private_oram_mutation_cleanup_expectation_v2(
    expectation: &PrivateOramMutationCleanupExpectationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_cleanup_expectation_v2(expectation)?;
    let wire = PrivateOramMutationCleanupExpectationWireV2 {
        version: CLEANUP_EXPECTATION_WIRE_VERSION_V2,
        terminal_watermark: expectation.terminal_watermark.clone(),
        terminal_record_digest: expectation.terminal_record_digest.clone(),
        terminal_lease: expectation.terminal_lease.clone(),
        terminal_lease_state_digest: expectation.terminal_lease_state_digest.clone(),
        outcome: expectation.outcome.clone(),
        terminal_consensus_state_digest: expectation.terminal_consensus_state_digest.clone(),
        terminal_consensus_state_sequence: expectation.terminal_consensus_state_sequence,
        owner_cleanup_evidence_digest: expectation.owner_cleanup_evidence_digest.clone(),
        point_cleanup_evidence_digest: expectation.point_cleanup_evidence_digest.clone(),
        evidence_digest: expectation.evidence_digest.clone(),
    };
    let encoded =
        serde_json::to_string(&wire).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.len() > MAX_CLEANUP_EXPECTATION_CANONICAL_JSON_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "cleanup_expectation",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_cleanup_expectation_v2(
    encoded: &str,
) -> Result<PrivateOramMutationCleanupExpectationV2, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > MAX_CLEANUP_EXPECTATION_CANONICAL_JSON_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "cleanup_expectation",
        ));
    }
    let wire: PrivateOramMutationCleanupExpectationWireV2 = serde_json::from_str(encoded)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("cleanup_expectation"))?;
    if wire.version != CLEANUP_EXPECTATION_WIRE_VERSION_V2
        || serde_json::to_string(&wire).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "cleanup_expectation",
        ));
    }
    let expectation = PrivateOramMutationCleanupExpectationV2 {
        terminal_watermark: wire.terminal_watermark,
        terminal_record_digest: wire.terminal_record_digest,
        terminal_lease: wire.terminal_lease,
        terminal_lease_state_digest: wire.terminal_lease_state_digest,
        outcome: wire.outcome,
        terminal_consensus_state_digest: wire.terminal_consensus_state_digest,
        terminal_consensus_state_sequence: wire.terminal_consensus_state_sequence,
        owner_cleanup_evidence_digest: wire.owner_cleanup_evidence_digest,
        point_cleanup_evidence_digest: wire.point_cleanup_evidence_digest,
        evidence_digest: wire.evidence_digest,
        _not_send_or_sync: PhantomData,
    };
    validate_cleanup_expectation_v2(&expectation)?;
    Ok(expectation)
}

pub(crate) struct PrivateOramMutationAdmissionApplyV2 {
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
}

pub(crate) struct PrivateOramMutationClearApplyV2 {
    lifecycle: PrivateOramMutationCleanupLifecycleV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
}

/// Exclusive local authority held across pin admission and physical cleanup.
pub(crate) struct PrivateOramMutationCleanupGcExclusionPermitV2 {
    collection_id_digest: String,
    generation: u64,
    tombstone_digest: String,
    acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl Debug for PrivateOramMutationCleanupGcExclusionPermitV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationCleanupGcExclusionPermitV2")
            .field("generation", &"[redacted]")
            .field("acknowledgement_applied", &self.acknowledgement_applied)
            .field("collection_id_digest", &"[redacted]")
            .field("tombstone_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

pub(crate) struct PrivateOramMutationCleanupGcCheckpointV2 {
    version: u16,
    generation: u64,
    witness_digest: String,
    clear_receipt_digest: String,
    tombstone_digest: String,
    acknowledgement_applied: PrivateOramRaftApplyLocatorV2,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

/// Opaque authority to retire the exact terminal parent namespace before clear acknowledgement.
#[doc(hidden)]
pub struct PrivateOramMutationClearedPendingArchivePermitV2 {
    collection_id: String,
    vector_name: String,
    owner_signing_key_id: String,
    owner_prestage_receipt: PrivateOramOwnerPrestageReceiptV2,
    generation: u64,
    owner_peer_id: PeerId,
    descriptor_digest: String,
    terminal_record_digest: String,
    witness_digest: String,
    cleanup_evidence_digest: String,
    clear_attempt_id_digest: String,
    clear_receipt_digest: String,
    tombstone_digest: String,
}

impl Debug for PrivateOramMutationClearedPendingArchivePermitV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationClearedPendingArchivePermitV2")
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("authority", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationClearedPendingArchivePermitV2 {
    pub(in crate::content_manager) fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub fn vector_name(&self) -> &str {
        &self.vector_name
    }

    pub fn owner_signing_key_id(&self) -> &str {
        &self.owner_signing_key_id
    }

    pub(in crate::content_manager) fn owner_prestage_receipt(
        &self,
    ) -> &PrivateOramOwnerPrestageReceiptV2 {
        &self.owner_prestage_receipt
    }

    pub(in crate::content_manager) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(in crate::content_manager) const fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub(in crate::content_manager) fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub(in crate::content_manager) fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }

    pub(in crate::content_manager) fn witness_digest(&self) -> &str {
        &self.witness_digest
    }

    pub(in crate::content_manager) fn cleanup_evidence_digest(&self) -> &str {
        &self.cleanup_evidence_digest
    }

    pub(in crate::content_manager) fn clear_attempt_id_digest(&self) -> &str {
        &self.clear_attempt_id_digest
    }

    pub(in crate::content_manager) fn clear_receipt_digest(&self) -> &str {
        &self.clear_receipt_digest
    }

    pub(in crate::content_manager) fn archive_binding_digest(&self) -> &str {
        &self.tombstone_digest
    }
}

impl Debug for PrivateOramMutationCleanupGcCheckpointV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationCleanupGcCheckpointV2")
            .field("version", &self.version)
            .field("generation", &"[redacted]")
            .field("acknowledgement_applied", &self.acknowledgement_applied)
            .field("witness_digest", &"[redacted]")
            .field("clear_receipt_digest", &"[redacted]")
            .field("tombstone_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl PrivateOramMutationCleanupGcCheckpointV2 {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn digests(&self) -> (&str, &str, &str) {
        (
            &self.witness_digest,
            &self.clear_receipt_digest,
            &self.tombstone_digest,
        )
    }
}

impl PrivateOramMutationCleanupLifecycleV2 {
    pub(crate) fn active(&self) -> Option<&PrivateOramMutationCleanupActiveV2> {
        self.active.as_ref()
    }

    pub(crate) fn last_cleared(&self) -> Option<&PrivateOramMutationClearedStateV2> {
        self.last_cleared.as_ref()
    }

    pub(crate) fn lifecycle_digest(&self) -> &str {
        &self.lifecycle_digest
    }

    pub(crate) fn expectation_status(
        &self,
        expected: &PrivateOramMutationCleanupExpectationV2,
    ) -> Result<PrivateOramMutationCleanupExpectationStatusV2, PrivateOramMutationJournalError>
    {
        validate_private_oram_mutation_cleanup_lifecycle_v2(self)?;
        validate_cleanup_expectation_v2(expected)?;
        match self.active.as_ref() {
            Some(PrivateOramMutationCleanupActiveV2::ParentProgress(progress))
                if progress.watermark == expected.terminal_watermark =>
            {
                Ok(PrivateOramMutationCleanupExpectationStatusV2::NeedsWitness)
            }
            Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness))
                if cleanup_expectation_matches_witness_v2(expected, witness) =>
            {
                Ok(
                    PrivateOramMutationCleanupExpectationStatusV2::WitnessDurable {
                        witness_digest: witness.witness_digest.clone(),
                    },
                )
            }
            Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending))
                if cleanup_expectation_matches_witness_v2(expected, &pending.witness) =>
            {
                Ok(
                    PrivateOramMutationCleanupExpectationStatusV2::ClearPending {
                        witness_digest: pending.witness.witness_digest.clone(),
                        clear_attempt_id_digest: pending.clear_attempt_id_digest.clone(),
                    },
                )
            }
            None => {
                let cleared = self
                    .last_cleared
                    .as_ref()
                    .filter(|cleared| {
                        cleanup_expectation_matches_witness_v2(expected, &cleared.cleanup_witness)
                    })
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
                match cleared.resolution {
                    PrivateOramMutationClearResolutionV2::Pending => Ok(
                        PrivateOramMutationCleanupExpectationStatusV2::ClearedPendingAcknowledgement {
                            owner_peer_id: cleared.owner_peer_id,
                            generation: cleared.generation,
                        },
                    ),
                    PrivateOramMutationClearResolutionV2::Acknowledged(_) => Ok(
                        PrivateOramMutationCleanupExpectationStatusV2::Acknowledged {
                            owner_peer_id: cleared.owner_peer_id,
                            generation: cleared.generation,
                        },
                    ),
                }
            }
            _ => Err(PrivateOramMutationJournalError::InvalidTransition),
        }
    }

    pub(crate) fn pending_acknowledgement_owner(
        &self,
    ) -> Result<Option<(PeerId, u64)>, PrivateOramMutationJournalError> {
        validate_private_oram_mutation_cleanup_lifecycle_v2(self)?;
        if self.active.is_some() {
            return Ok(None);
        }
        Ok(self.last_cleared.as_ref().and_then(|cleared| {
            matches!(
                cleared.resolution,
                PrivateOramMutationClearResolutionV2::Pending
            )
            .then_some((cleared.owner_peer_id, cleared.generation))
        }))
    }

    pub(crate) fn matches_cleanup_witness(
        &self,
        expected_generation: u64,
        expected_witness_digest: &str,
    ) -> Result<bool, PrivateOramMutationJournalError> {
        validate_private_oram_mutation_cleanup_lifecycle_v2(self)?;
        Ok(matches!(
            self.active.as_ref(),
            Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness))
                if witness.admitted.generation == expected_generation
                    && witness.witness_digest == expected_witness_digest
        ))
    }

    pub(crate) fn matches_clear_pending(
        &self,
        expected_generation: u64,
        expected_clear_attempt_id_digest: &str,
    ) -> Result<bool, PrivateOramMutationJournalError> {
        validate_private_oram_mutation_cleanup_lifecycle_v2(self)?;
        Ok(matches!(
            self.active.as_ref(),
            Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending))
                if pending.witness.admitted.generation == expected_generation
                    && pending.clear_attempt_id_digest == expected_clear_attempt_id_digest
        ))
    }

    pub(crate) fn cleared_pending_archive_permit(
        &self,
        collection_id: String,
        expected_owner_peer_id: PeerId,
        expected_generation: u64,
    ) -> Result<PrivateOramMutationClearedPendingArchivePermitV2, PrivateOramMutationJournalError>
    {
        validate_private_oram_mutation_cleanup_lifecycle_v2(self)?;
        if private_oram_collection_id_digest_v2(&collection_id)? != self.collection_id_digest
            || self.active.is_some()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let cleared = self
            .last_cleared
            .as_ref()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        if !matches!(
            cleared.resolution,
            PrivateOramMutationClearResolutionV2::Pending
        ) || cleared.owner_peer_id != expected_owner_peer_id
            || cleared.generation != expected_generation
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
            &cleared
                .cleanup_witness
                .admitted
                .recovery_manifest_canonical_json,
        )?;
        let (package, _) = recovery_manifest.coordinator_recovery_envelope()?;
        let owner_prestage_receipt = recovery_manifest
            .owner_receipt(expected_owner_peer_id)
            .cloned()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        if package.collection_id != collection_id
            || package.coordinator_peer_id != expected_owner_peer_id
            || owner_prestage_receipt.collection_id() != collection_id
            || owner_prestage_receipt.owner_peer_id() != expected_owner_peer_id
            || owner_prestage_receipt.lease_generation() != expected_generation
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(PrivateOramMutationClearedPendingArchivePermitV2 {
            collection_id,
            vector_name: package.vector_name.clone(),
            owner_signing_key_id: package.owner_signing_key_id.clone(),
            owner_prestage_receipt,
            generation: cleared.generation,
            owner_peer_id: cleared.owner_peer_id,
            descriptor_digest: cleared.descriptor_digest.clone(),
            terminal_record_digest: cleared.terminal_record_digest.clone(),
            witness_digest: cleared.witness_digest.clone(),
            cleanup_evidence_digest: cleared.cleanup_witness.evidence_digest_for_archive_v2()?,
            clear_attempt_id_digest: cleared.clear_attempt_id_digest.clone(),
            clear_receipt_digest: cleared.clear_receipt_digest.clone(),
            tombstone_digest: cleared.tombstone_digest.clone(),
        })
    }
}

pub(crate) fn cleanup_expectation_matches_witness_v2(
    expected: &PrivateOramMutationCleanupExpectationV2,
    witness: &PrivateOramMutationCleanupWitnessV2,
) -> bool {
    expected.terminal_watermark == witness.terminal_watermark
        && expected.terminal_record_digest == witness.terminal_record_digest
        && expected.terminal_lease == witness.terminal_lease
        && expected.terminal_lease_state_digest == witness.terminal_lease_state_digest
        && expected.outcome == witness.outcome
        && expected.terminal_consensus_state_digest == witness.terminal_consensus_state_digest
        && expected.terminal_consensus_state_sequence == witness.terminal_consensus_state_sequence
        && expected.owner_cleanup_evidence_digest == witness.owner_cleanup_evidence_digest
        && expected.point_cleanup_evidence_digest == witness.point_cleanup_evidence_digest
}

impl PrivateOramMutationCleanupWitnessV2 {
    pub(crate) fn expected_clear_receipt(
        &self,
    ) -> Result<PrivateOramMutationClearReceiptV1, PrivateOramMutationJournalError> {
        validate_cleanup_witness_v2(self)?;
        Ok(PrivateOramMutationClearReceiptV1 {
            version: PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION,
            generation: self.admitted.generation,
            mutation_id: self.admitted.mutation_id.clone(),
            outcome: self.outcome.clone(),
            terminal_state_digest: self.terminal_consensus_state_digest.clone(),
            reconciliation_digest: self.witness_digest.clone(),
        })
    }

    fn evidence_digest_for_archive_v2(&self) -> Result<String, PrivateOramMutationJournalError> {
        let expected = PrivateOramMutationCleanupExpectationV2 {
            terminal_watermark: self.terminal_watermark.clone(),
            terminal_record_digest: self.terminal_record_digest.clone(),
            terminal_lease: self.terminal_lease.clone(),
            terminal_lease_state_digest: self.terminal_lease_state_digest.clone(),
            outcome: self.outcome.clone(),
            terminal_consensus_state_digest: self.terminal_consensus_state_digest.clone(),
            terminal_consensus_state_sequence: self.terminal_consensus_state_sequence,
            owner_cleanup_evidence_digest: self.owner_cleanup_evidence_digest.clone(),
            point_cleanup_evidence_digest: self.point_cleanup_evidence_digest.clone(),
            evidence_digest: String::new(),
            _not_send_or_sync: PhantomData,
        };
        cleanup_evidence_digest_v2(&expected)
    }
}

impl PrivateOramMutationClearedStateV2 {
    pub(crate) fn clear_receipt(&self) -> &PrivateOramMutationClearReceiptV1 {
        &self.clear_receipt
    }

    #[cfg(test)]
    pub(crate) fn clear_receipt_digest(&self) -> &str {
        &self.clear_receipt_digest
    }

    #[cfg(test)]
    pub(crate) fn tombstone_digest(&self) -> &str {
        &self.tombstone_digest
    }

    pub(crate) fn resolution(&self) -> &PrivateOramMutationClearResolutionV2 {
        &self.resolution
    }
}

#[cfg(test)]
impl PrivateOramMutationAdmissionApplyV2 {
    pub(crate) fn lifecycle(&self) -> &PrivateOramMutationCleanupLifecycleV2 {
        &self.lifecycle
    }

    pub(crate) fn lease_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        &self.lease_slot
    }
}

#[cfg(test)]
impl PrivateOramMutationClearApplyV2 {
    pub(crate) fn lifecycle(&self) -> &PrivateOramMutationCleanupLifecycleV2 {
        &self.lifecycle
    }

    pub(crate) fn lease_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        &self.lease_slot
    }
}

pub(crate) fn private_oram_mutation_cleanup_lifecycle_genesis_v2(
    collection_id: &str,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
) -> Result<PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationJournalError> {
    let mut lifecycle = PrivateOramMutationCleanupLifecycleV2 {
        version: PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION,
        collection_id_digest: private_oram_collection_id_digest_v2(collection_id)?,
        consensus_history_id_digest,
        raft_group_id_digest,
        last_cleared: None,
        active: None,
        lifecycle_digest: String::new(),
    };
    lifecycle.lifecycle_digest = cleanup_lifecycle_digest_v2(&lifecycle)?;
    validate_private_oram_mutation_cleanup_lifecycle_v2(&lifecycle)?;
    Ok(lifecycle)
}

/// Atomically models publication of the active lease slot and its admitted lifecycle state.
pub(crate) fn apply_private_oram_mutation_admission_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    lease: PrivateOramMutationLease,
    recovery_manifest_canonical_json: String,
    applied_entry: PrivateOramAppliedEntryV2,
) -> Result<PrivateOramMutationAdmissionApplyV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(current, current_slot)?;
    validate_lease_v2(&lease)?;
    let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &recovery_manifest_canonical_json,
    )?;
    recovery_manifest.validate_admission_lease(&lease)?;
    let admitted_lease_state_digest = private_oram_mutation_lease_state_digest_v2(&lease)?;
    let admission_request_digest = private_oram_mutation_admission_request_digest_v2(
        &lease,
        recovery_manifest.manifest_digest(),
    )?;
    validate_applied_entry_v2(
        &applied_entry,
        current,
        PrivateOramMutationCleanupOperationKindV2::Admission,
        &applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::Admission,
            current,
            Some(current_slot),
            &admission_request_digest,
        )?,
    )?;
    if current.active.is_some()
        || current_slot.active.is_some()
        || !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing)
        || lease.renewal_revision != 0
        || private_oram_collection_id_digest_v2(&lease.collection_id)?
            != current.collection_id_digest
        || current_slot.generation.checked_add(1) != Some(lease.generation)
        || current_slot.max_writer_fence.checked_add(1) != Some(lease.writer_fence)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let predecessor_tombstone_digest = match &current.last_cleared {
        None => {
            if current_slot.generation != 0 || current_slot.last_clear.is_some() {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            None
        }
        Some(previous) => {
            let PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) =
                &previous.resolution
            else {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            };
            if current_slot.generation != previous.generation
                || current_slot.last_clear.as_ref() != Some(&previous.clear_receipt)
                || lease.base_record_digest
                    != previous.cleanup_witness.terminal_consensus_state_digest
                || lease.base_state_sequence
                    != previous.cleanup_witness.terminal_consensus_state_sequence
                || !locator_is_strictly_after(
                    &applied_entry.locator,
                    &acknowledged.acknowledgement_applied,
                )
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            Some(previous.tombstone_digest.clone())
        }
    };

    let mut admitted = PrivateOramMutationAdmittedV2 {
        version: ADMITTED_VERSION,
        collection_id_digest: current.collection_id_digest.clone(),
        generation: lease.generation,
        owner_peer_id: lease.owner_peer_id,
        mutation_id: lease.mutation_id.clone(),
        signed_mutation_digest: lease.signed_mutation_digest.clone(),
        base_record_digest: lease.base_record_digest.clone(),
        lease_lineage_digest: private_oram_mutation_lease_lineage_digest_v2(&lease)?,
        admitted_lease_state_digest,
        recovery_manifest_digest: recovery_manifest.manifest_digest().to_string(),
        recovery_manifest_canonical_json,
        admission_request_digest,
        predecessor_tombstone_digest,
        admission_applied: applied_entry.locator,
        admitted_digest: String::new(),
    };
    admitted.admitted_digest = admitted_digest_v2(&admitted)?;
    validate_admitted_v2(&admitted)?;

    let mut lifecycle = PrivateOramMutationCleanupLifecycleV2 {
        version: PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION,
        collection_id_digest: current.collection_id_digest.clone(),
        consensus_history_id_digest: current.consensus_history_id_digest.clone(),
        raft_group_id_digest: current.raft_group_id_digest.clone(),
        last_cleared: current.last_cleared.clone(),
        active: Some(PrivateOramMutationCleanupActiveV2::Admitted(admitted)),
        lifecycle_digest: String::new(),
    };
    lifecycle.lifecycle_digest = cleanup_lifecycle_digest_v2(&lifecycle)?;
    let lease_slot = PrivateOramMutationLeaseSlotV2 {
        version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
        generation: lease.generation,
        active: Some(lease.clone()),
        last_clear: current_slot.last_clear.clone(),
        max_writer_fence: lease.writer_fence,
    };
    validate_private_oram_mutation_cleanup_pair_v2(&lifecycle, &lease_slot)?;
    Ok(PrivateOramMutationAdmissionApplyV2 {
        lifecycle,
        lease_slot,
    })
}

pub(crate) fn apply_private_oram_mutation_parent_progress_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
    applied_entry: PrivateOramAppliedEntryV2,
) -> Result<PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(current, current_slot)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(expected.watermark())?;
    validate_applied_entry_v2(
        &applied_entry,
        current,
        PrivateOramMutationCleanupOperationKindV2::ParentProgress,
        &applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::ParentProgress,
            current,
            Some(current_slot),
            expected.watermark().watermark_digest(),
        )?,
    )?;
    let progress = match current.active.as_ref() {
        Some(PrivateOramMutationCleanupActiveV2::Admitted(admitted)) => {
            if expected.watermark().sequence() != 1
                || !admitted_matches_watermark(admitted, expected.watermark())
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            new_parent_progress_v2(
                admitted.clone(),
                expected.watermark().clone(),
                Vec::new(),
                applied_entry.locator,
            )?
        }
        Some(PrivateOramMutationCleanupActiveV2::ParentProgress(progress)) => {
            if progress.watermark == *expected.watermark() {
                if !locator_is_at_or_after(&applied_entry.locator, &progress.progress_applied) {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                return Ok(current.clone());
            }
            if !locator_is_strictly_after(&applied_entry.locator, &progress.progress_applied) {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            validate_private_oram_mutation_parent_watermark_v2_cas_transition(
                &progress.watermark,
                expected.watermark(),
                expected,
            )?;
            new_parent_progress_v2(
                progress.admitted.clone(),
                expected.watermark().clone(),
                progress.progress_applied_history.clone(),
                applied_entry.locator,
            )?
        }
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    };
    replace_active_v2(
        current,
        PrivateOramMutationCleanupActiveV2::ParentProgress(progress),
    )
}

pub(crate) fn apply_private_oram_mutation_cleanup_witness_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    expected: &PrivateOramMutationCleanupExpectationV2,
    applied_entry: PrivateOramAppliedEntryV2,
) -> Result<PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(current, current_slot)?;
    validate_cleanup_expectation_v2(expected)?;
    validate_applied_entry_v2(
        &applied_entry,
        current,
        PrivateOramMutationCleanupOperationKindV2::CleanupWitness,
        &applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::CleanupWitness,
            current,
            Some(current_slot),
            &expected.evidence_digest,
        )?,
    )?;
    let Some(PrivateOramMutationCleanupActiveV2::ParentProgress(progress)) =
        current.active.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let terminal_lease = current_slot
        .active
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if progress.watermark.sequence() != 7
        || progress.watermark != expected.terminal_watermark
        || private_oram_mutation_lease_state_digest_v2(terminal_lease)?
            != expected.terminal_lease_state_digest
        || !locator_is_strictly_after(&applied_entry.locator, &progress.progress_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut witness = PrivateOramMutationCleanupWitnessV2 {
        version: CLEANUP_WITNESS_VERSION,
        admitted: progress.admitted.clone(),
        terminal_watermark: expected.terminal_watermark.clone(),
        terminal_record_digest: expected.terminal_record_digest.clone(),
        terminal_lease: expected.terminal_lease.clone(),
        terminal_lease_state_digest: expected.terminal_lease_state_digest.clone(),
        outcome: expected.outcome.clone(),
        terminal_consensus_state_digest: expected.terminal_consensus_state_digest.clone(),
        terminal_consensus_state_sequence: expected.terminal_consensus_state_sequence,
        owner_cleanup_evidence_digest: expected.owner_cleanup_evidence_digest.clone(),
        point_cleanup_evidence_digest: expected.point_cleanup_evidence_digest.clone(),
        parent_progress_applied_history: progress.progress_applied_history.clone(),
        parent_progress_applied: progress.progress_applied.clone(),
        witness_applied: applied_entry.locator,
        witness_digest: String::new(),
    };
    witness.witness_digest = cleanup_witness_digest_v2(&witness)?;
    validate_cleanup_witness_v2(&witness)?;
    replace_active_v2(
        current,
        PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness),
    )
}

pub(crate) fn apply_private_oram_mutation_clear_pending_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    clear_attempt_id_digest: String,
    applied_entry: PrivateOramAppliedEntryV2,
) -> Result<PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(current, current_slot)?;
    validate_digest(&clear_attempt_id_digest)?;
    validate_applied_entry_v2(
        &applied_entry,
        current,
        PrivateOramMutationCleanupOperationKindV2::ClearPending,
        &applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::ClearPending,
            current,
            Some(current_slot),
            &clear_attempt_id_digest,
        )?,
    )?;
    let Some(PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness)) =
        current.active.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    if !locator_is_strictly_after(&applied_entry.locator, &witness.witness_applied) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let expected_clear_receipt_digest =
        private_oram_mutation_clear_receipt_digest_v2(&witness.expected_clear_receipt()?)?;
    let mut pending = PrivateOramMutationClearPendingV2 {
        version: CLEAR_PENDING_VERSION,
        witness: witness.clone(),
        clear_attempt_id_digest,
        expected_clear_receipt_digest,
        pending_applied: applied_entry.locator,
        pending_digest: String::new(),
    };
    pending.pending_digest = clear_pending_digest_v2(&pending)?;
    validate_clear_pending_v2(&pending)?;
    replace_active_v2(
        current,
        PrivateOramMutationCleanupActiveV2::ClearPending(pending),
    )
}

/// Atomically models installation of the clear receipt and the lifecycle tombstone.
pub(crate) fn apply_private_oram_mutation_clear_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    applied_entry: PrivateOramAppliedEntryV2,
) -> Result<PrivateOramMutationClearApplyV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(current, current_slot)?;
    let Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) = current.active.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    validate_applied_entry_v2(
        &applied_entry,
        current,
        PrivateOramMutationCleanupOperationKindV2::Clear,
        &applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::Clear,
            current,
            Some(current_slot),
            &pending.pending_digest,
        )?,
    )?;
    let Some(active_lease) = current_slot.active.as_ref() else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let witness = &pending.witness;
    if current_slot.generation != witness.admitted.generation
        || private_oram_mutation_lease_lineage_digest_v2(active_lease)?
            != witness.admitted.lease_lineage_digest
        || private_oram_mutation_lease_state_digest_v2(active_lease)?
            != witness.terminal_lease_state_digest
        || !terminal_lease_matches_witness(active_lease, witness)?
        || !locator_is_strictly_after(&applied_entry.locator, &pending.pending_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    match &current.last_cleared {
        None if current_slot.last_clear.is_none() => {}
        Some(previous) if current_slot.last_clear.as_ref() == Some(&previous.clear_receipt) => {}
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    }

    let clear_receipt = witness.expected_clear_receipt()?;
    let clear_receipt_digest = private_oram_mutation_clear_receipt_digest_v2(&clear_receipt)?;
    if clear_receipt_digest != pending.expected_clear_receipt_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut tombstone = PrivateOramMutationClearedStateV2 {
        version: CLEARED_STATE_VERSION,
        collection_id_digest: witness.admitted.collection_id_digest.clone(),
        generation: witness.admitted.generation,
        owner_peer_id: witness.admitted.owner_peer_id,
        mutation_id: witness.admitted.mutation_id.clone(),
        signed_mutation_digest: witness.admitted.signed_mutation_digest.clone(),
        descriptor_digest: witness.terminal_watermark.descriptor_digest().to_string(),
        terminal_watermark: witness.terminal_watermark.clone(),
        terminal_record_digest: witness.terminal_record_digest.clone(),
        lease_lineage_digest: witness.admitted.lease_lineage_digest.clone(),
        terminal_lease_state_digest: witness.terminal_lease_state_digest.clone(),
        cleanup_witness: witness.clone(),
        witness_digest: witness.witness_digest.clone(),
        clear_attempt_id_digest: pending.clear_attempt_id_digest.clone(),
        clear_pending_digest: pending.pending_digest.clone(),
        pending_applied: pending.pending_applied.clone(),
        clear_receipt: clear_receipt.clone(),
        clear_receipt_digest,
        clear_applied: applied_entry.locator,
        previous_tombstone_digest: current
            .last_cleared
            .as_ref()
            .map(|previous| previous.tombstone_digest.clone()),
        clear_core_digest: String::new(),
        resolution: PrivateOramMutationClearResolutionV2::Pending,
        resolution_digest: String::new(),
        tombstone_digest: String::new(),
    };
    tombstone.clear_core_digest = clear_core_digest_v2(&tombstone)?;
    tombstone.resolution_digest = clear_resolution_digest_v2(&tombstone)?;
    tombstone.tombstone_digest = cleared_state_digest_v2(&tombstone)?;
    validate_cleared_state_v2(&tombstone)?;

    let mut lifecycle = PrivateOramMutationCleanupLifecycleV2 {
        version: PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION,
        collection_id_digest: current.collection_id_digest.clone(),
        consensus_history_id_digest: current.consensus_history_id_digest.clone(),
        raft_group_id_digest: current.raft_group_id_digest.clone(),
        last_cleared: Some(tombstone),
        active: None,
        lifecycle_digest: String::new(),
    };
    lifecycle.lifecycle_digest = cleanup_lifecycle_digest_v2(&lifecycle)?;
    let lease_slot = PrivateOramMutationLeaseSlotV2 {
        version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
        generation: current_slot.generation,
        active: None,
        last_clear: Some(clear_receipt),
        max_writer_fence: current_slot.max_writer_fence,
    };
    validate_private_oram_mutation_cleanup_pair_v2(&lifecycle, &lease_slot)?;
    Ok(PrivateOramMutationClearApplyV2 {
        lifecycle,
        lease_slot,
    })
}

pub(crate) fn acknowledge_private_oram_mutation_clear_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    applied_entry: PrivateOramAppliedEntryV2,
) -> Result<PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(current, current_slot)?;
    if current.active.is_some() || current_slot.active.is_some() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let Some(previous) = current.last_cleared.as_ref() else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    validate_applied_entry_v2(
        &applied_entry,
        current,
        PrivateOramMutationCleanupOperationKindV2::ClearAcknowledgement,
        &applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::ClearAcknowledgement,
            current,
            Some(current_slot),
            &previous.clear_core_digest,
        )?,
    )?;
    if !matches!(
        previous.resolution,
        PrivateOramMutationClearResolutionV2::Pending
    ) || current_slot.generation != previous.generation
        || current_slot.last_clear.as_ref() != Some(&previous.clear_receipt)
        || !locator_is_strictly_after(&applied_entry.locator, &previous.clear_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut acknowledged = previous.clone();
    acknowledged.resolution = PrivateOramMutationClearResolutionV2::Acknowledged(
        PrivateOramMutationClearAcknowledgedV2 {
            acknowledgement_applied: applied_entry.locator,
        },
    );
    acknowledged.resolution_digest = clear_resolution_digest_v2(&acknowledged)?;
    acknowledged.tombstone_digest = cleared_state_digest_v2(&acknowledged)?;
    validate_cleared_state_v2(&acknowledged)?;
    let mut lifecycle = PrivateOramMutationCleanupLifecycleV2 {
        version: PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION,
        collection_id_digest: current.collection_id_digest.clone(),
        consensus_history_id_digest: current.consensus_history_id_digest.clone(),
        raft_group_id_digest: current.raft_group_id_digest.clone(),
        last_cleared: Some(acknowledged),
        active: None,
        lifecycle_digest: String::new(),
    };
    lifecycle.lifecycle_digest = cleanup_lifecycle_digest_v2(&lifecycle)?;
    validate_private_oram_mutation_cleanup_lifecycle_v2(&lifecycle)?;
    Ok(lifecycle)
}

/// Returns the durable identities a local GC implementation must pin before deleting witness data.
pub(crate) fn private_oram_mutation_cleanup_gc_checkpoint_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    current_slot: &PrivateOramMutationLeaseSlotV2,
    exclusion_permit: &PrivateOramMutationCleanupGcExclusionPermitV2,
) -> Result<PrivateOramMutationCleanupGcCheckpointV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(lifecycle, current_slot)?;
    if lifecycle.active.is_some() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let Some(cleared) = lifecycle.last_cleared.as_ref() else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) = &cleared.resolution
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    if exclusion_permit.collection_id_digest != lifecycle.collection_id_digest
        || exclusion_permit.generation != cleared.generation
        || exclusion_permit.tombstone_digest != cleared.tombstone_digest
        || exclusion_permit.acknowledgement_applied != acknowledged.acknowledgement_applied
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_apply_locator_v2(&exclusion_permit.acknowledgement_applied)?;
    Ok(PrivateOramMutationCleanupGcCheckpointV2 {
        version: GC_CHECKPOINT_VERSION,
        generation: cleared.generation,
        witness_digest: cleared.witness_digest.clone(),
        clear_receipt_digest: cleared.clear_receipt_digest.clone(),
        tombstone_digest: cleared.tombstone_digest.clone(),
        acknowledgement_applied: acknowledged.acknowledgement_applied.clone(),
        _not_send_or_sync: PhantomData,
    })
}

pub(crate) fn validate_private_oram_mutation_cleanup_lifecycle_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if lifecycle.version != PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &lifecycle.collection_id_digest,
        &lifecycle.consensus_history_id_digest,
        &lifecycle.raft_group_id_digest,
    ] {
        validate_digest(digest)?;
    }
    if let Some(cleared) = &lifecycle.last_cleared {
        validate_cleared_state_v2(cleared)?;
        if cleared.collection_id_digest != lifecycle.collection_id_digest
            || !locator_matches_lifecycle_namespace(&cleared.clear_applied, lifecycle)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if let Some(active) = &lifecycle.active {
        validate_active_v2(active)?;
        let admitted = active_admitted(active);
        if admitted.collection_id_digest != lifecycle.collection_id_digest
            || !locator_matches_lifecycle_namespace(&admitted.admission_applied, lifecycle)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        match &lifecycle.last_cleared {
            None if admitted.generation == 1 && admitted.predecessor_tombstone_digest.is_none() => {
            }
            Some(previous)
                if admitted.generation == previous.generation.checked_add(1).unwrap_or(0)
                    && admitted.predecessor_tombstone_digest.as_deref()
                        == Some(previous.tombstone_digest.as_str())
                    && match &previous.resolution {
                        PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) => {
                            locator_is_strictly_after(
                                &admitted.admission_applied,
                                &acknowledged.acknowledgement_applied,
                            )
                        }
                        PrivateOramMutationClearResolutionV2::Pending => false,
                    } => {}
            _ => return Err(PrivateOramMutationJournalError::Corrupt),
        }
    }
    if lifecycle.lifecycle_digest != cleanup_lifecycle_digest_v2(lifecycle)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(crate) fn validate_private_oram_mutation_cleanup_pair_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_lifecycle_v2(lifecycle)?;
    validate_lease_slot_v2(slot)?;
    match lifecycle.active.as_ref() {
        Some(active) => {
            let admitted = active_admitted(active);
            let lease = slot
                .active
                .as_ref()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?;
            if slot.generation != admitted.generation
                || private_oram_collection_id_digest_v2(&lease.collection_id)?
                    != lifecycle.collection_id_digest
                || private_oram_mutation_lease_lineage_digest_v2(lease)?
                    != admitted.lease_lineage_digest
                || slot.last_clear.as_ref()
                    != lifecycle
                        .last_cleared
                        .as_ref()
                        .map(|cleared| &cleared.clear_receipt)
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
            match active {
                PrivateOramMutationCleanupActiveV2::Admitted(_)
                | PrivateOramMutationCleanupActiveV2::ParentProgress(_) => {}
                PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness)
                | PrivateOramMutationCleanupActiveV2::ClearPending(
                    PrivateOramMutationClearPendingV2 { witness, .. },
                ) => {
                    if private_oram_mutation_lease_state_digest_v2(lease)?
                        != witness.terminal_lease_state_digest
                        || !terminal_lease_matches_witness(lease, witness)?
                    {
                        return Err(PrivateOramMutationJournalError::Corrupt);
                    }
                }
            }
        }
        None => match lifecycle.last_cleared.as_ref() {
            None if slot.generation == 0 && slot.active.is_none() && slot.last_clear.is_none() => {}
            Some(cleared)
                if slot.generation == cleared.generation
                    && slot.active.is_none()
                    && slot.last_clear.as_ref() == Some(&cleared.clear_receipt) => {}
            _ => return Err(PrivateOramMutationJournalError::Corrupt),
        },
    }
    Ok(())
}

fn replace_active_v2(
    current: &PrivateOramMutationCleanupLifecycleV2,
    active: PrivateOramMutationCleanupActiveV2,
) -> Result<PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationJournalError> {
    let mut lifecycle = PrivateOramMutationCleanupLifecycleV2 {
        version: PRIVATE_ORAM_MUTATION_CLEANUP_LIFECYCLE_VERSION,
        collection_id_digest: current.collection_id_digest.clone(),
        consensus_history_id_digest: current.consensus_history_id_digest.clone(),
        raft_group_id_digest: current.raft_group_id_digest.clone(),
        last_cleared: current.last_cleared.clone(),
        active: Some(active),
        lifecycle_digest: String::new(),
    };
    lifecycle.lifecycle_digest = cleanup_lifecycle_digest_v2(&lifecycle)?;
    validate_private_oram_mutation_cleanup_lifecycle_v2(&lifecycle)?;
    Ok(lifecycle)
}

fn new_parent_progress_v2(
    admitted: PrivateOramMutationAdmittedV2,
    watermark: PrivateOramMutationParentWatermarkV2,
    mut progress_applied_history: Vec<PrivateOramRaftApplyLocatorV2>,
    progress_applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramMutationParentProgressV2, PrivateOramMutationJournalError> {
    progress_applied_history.push(progress_applied.clone());
    let mut progress = PrivateOramMutationParentProgressV2 {
        version: PARENT_PROGRESS_VERSION,
        admitted,
        watermark,
        progress_applied_history,
        progress_applied,
        progress_digest: String::new(),
    };
    progress.progress_digest = parent_progress_digest_v2(&progress)?;
    validate_parent_progress_v2(&progress)?;
    Ok(progress)
}

fn active_admitted(active: &PrivateOramMutationCleanupActiveV2) -> &PrivateOramMutationAdmittedV2 {
    match active {
        PrivateOramMutationCleanupActiveV2::Admitted(admitted) => admitted,
        PrivateOramMutationCleanupActiveV2::ParentProgress(progress) => &progress.admitted,
        PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness) => &witness.admitted,
        PrivateOramMutationCleanupActiveV2::ClearPending(pending) => &pending.witness.admitted,
    }
}

fn active_digest(active: &PrivateOramMutationCleanupActiveV2) -> &str {
    match active {
        PrivateOramMutationCleanupActiveV2::Admitted(admitted) => &admitted.admitted_digest,
        PrivateOramMutationCleanupActiveV2::ParentProgress(progress) => &progress.progress_digest,
        PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness) => {
            &witness.witness_digest
        }
        PrivateOramMutationCleanupActiveV2::ClearPending(pending) => &pending.pending_digest,
    }
}

fn active_tag(active: &PrivateOramMutationCleanupActiveV2) -> u8 {
    match active {
        PrivateOramMutationCleanupActiveV2::Admitted(_) => 1,
        PrivateOramMutationCleanupActiveV2::ParentProgress(_) => 2,
        PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(_) => 3,
        PrivateOramMutationCleanupActiveV2::ClearPending(_) => 4,
    }
}

fn validate_active_v2(
    active: &PrivateOramMutationCleanupActiveV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match active {
        PrivateOramMutationCleanupActiveV2::Admitted(admitted) => validate_admitted_v2(admitted),
        PrivateOramMutationCleanupActiveV2::ParentProgress(progress) => {
            validate_parent_progress_v2(progress)
        }
        PrivateOramMutationCleanupActiveV2::CleanupWitnessDurable(witness) => {
            validate_cleanup_witness_v2(witness)
        }
        PrivateOramMutationCleanupActiveV2::ClearPending(pending) => {
            validate_clear_pending_v2(pending)
        }
    }
}

fn validate_admitted_v2(
    admitted: &PrivateOramMutationAdmittedV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if admitted.version != ADMITTED_VERSION || admitted.generation == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &admitted.collection_id_digest,
        &admitted.mutation_id,
        &admitted.signed_mutation_digest,
        &admitted.base_record_digest,
        &admitted.lease_lineage_digest,
        &admitted.admitted_lease_state_digest,
        &admitted.recovery_manifest_digest,
        &admitted.admission_request_digest,
        &admitted.admitted_digest,
    ] {
        validate_digest(digest)?;
    }
    let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &admitted.recovery_manifest_canonical_json,
    )?;
    if recovery_manifest.manifest_digest() != admitted.recovery_manifest_digest
        || recovery_manifest.lease_generation() != admitted.generation
        || private_oram_collection_id_digest_v2(recovery_manifest.collection_id())?
            != admitted.collection_id_digest
        || recovery_manifest.mutation_id() != admitted.mutation_id
        || recovery_manifest.mutation_digest() != admitted.signed_mutation_digest
        || !recovery_manifest.contains_owner_peer_id(admitted.owner_peer_id)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if admission_request_digest_from_parts_v2(
        &admitted.admitted_lease_state_digest,
        &admitted.recovery_manifest_digest,
    )? != admitted.admission_request_digest
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_optional_digest(admitted.predecessor_tombstone_digest.as_deref())?;
    validate_apply_locator_v2(&admitted.admission_applied)?;
    if admitted.admitted_digest != admitted_digest_v2(admitted)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_parent_progress_v2(
    progress: &PrivateOramMutationParentProgressV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if progress.version != PARENT_PROGRESS_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_admitted_v2(&progress.admitted)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&progress.watermark)?;
    validate_apply_locator_v2(&progress.progress_applied)?;
    validate_apply_locator_history_v2(
        &progress.progress_applied_history,
        &progress.admitted.admission_applied,
    )?;
    validate_digest(&progress.progress_digest)?;
    if !admitted_matches_watermark(&progress.admitted, &progress.watermark)
        || usize::try_from(progress.watermark.sequence()).ok()
            != Some(progress.progress_applied_history.len())
        || progress.progress_applied_history.last() != Some(&progress.progress_applied)
        || !locator_is_strictly_after(
            &progress.progress_applied,
            &progress.admitted.admission_applied,
        )
        || progress.progress_digest != parent_progress_digest_v2(progress)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_cleanup_witness_v2(
    witness: &PrivateOramMutationCleanupWitnessV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if witness.version != CLEANUP_WITNESS_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_admitted_v2(&witness.admitted)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&witness.terminal_watermark)?;
    validate_lease_v2(&witness.terminal_lease)?;
    validate_apply_locator_v2(&witness.parent_progress_applied)?;
    validate_apply_locator_history_v2(
        &witness.parent_progress_applied_history,
        &witness.admitted.admission_applied,
    )?;
    validate_apply_locator_v2(&witness.witness_applied)?;
    for digest in [
        &witness.terminal_record_digest,
        &witness.terminal_lease_state_digest,
        &witness.terminal_consensus_state_digest,
        &witness.owner_cleanup_evidence_digest,
        &witness.point_cleanup_evidence_digest,
        &witness.witness_digest,
    ] {
        validate_digest(digest)?;
    }
    if witness.terminal_watermark.sequence() != 7
        || witness.terminal_watermark.phase_sequence() != 7
        || witness.parent_progress_applied_history.len() != 7
        || witness.parent_progress_applied_history.last() != Some(&witness.parent_progress_applied)
        || !admitted_matches_watermark(&witness.admitted, &witness.terminal_watermark)
        || witness.terminal_watermark.record_digest() != Some(&witness.terminal_record_digest)
        || private_oram_mutation_lease_lineage_digest_v2(&witness.terminal_lease)?
            != witness.admitted.lease_lineage_digest
        || private_oram_mutation_lease_state_digest_v2(&witness.terminal_lease)?
            != witness.terminal_lease_state_digest
        || !terminal_lease_matches_outcome(
            &witness.terminal_lease,
            &witness.outcome,
            &witness.terminal_consensus_state_digest,
            witness.terminal_consensus_state_sequence,
        )
        || !locator_is_strictly_after(
            &witness.parent_progress_applied,
            &witness.admitted.admission_applied,
        )
        || !locator_is_strictly_after(&witness.witness_applied, &witness.parent_progress_applied)
        || witness.witness_digest != cleanup_witness_digest_v2(witness)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_cleanup_expectation_v2(
    expected: &PrivateOramMutationCleanupExpectationV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_parent_watermark_v2_shape(&expected.terminal_watermark)?;
    validate_lease_v2(&expected.terminal_lease)?;
    for digest in [
        &expected.terminal_record_digest,
        &expected.terminal_lease_state_digest,
        &expected.terminal_consensus_state_digest,
        &expected.owner_cleanup_evidence_digest,
        &expected.point_cleanup_evidence_digest,
        &expected.evidence_digest,
    ] {
        validate_digest(digest)?;
    }
    if expected.terminal_watermark.sequence() != 7
        || expected.terminal_watermark.phase_sequence() != 7
        || expected.terminal_watermark.record_digest()
            != Some(expected.terminal_record_digest.as_str())
        || private_oram_mutation_lease_lineage_digest_v2(&expected.terminal_lease)?
            != expected.terminal_watermark.lease_lineage_digest()
        || private_oram_mutation_lease_state_digest_v2(&expected.terminal_lease)?
            != expected.terminal_lease_state_digest
        || !terminal_lease_matches_outcome(
            &expected.terminal_lease,
            &expected.outcome,
            &expected.terminal_consensus_state_digest,
            expected.terminal_consensus_state_sequence,
        )
        || expected.evidence_digest != cleanup_evidence_digest_v2(expected)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_clear_pending_v2(
    pending: &PrivateOramMutationClearPendingV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if pending.version != CLEAR_PENDING_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_cleanup_witness_v2(&pending.witness)?;
    for digest in [
        &pending.clear_attempt_id_digest,
        &pending.expected_clear_receipt_digest,
        &pending.pending_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_apply_locator_v2(&pending.pending_applied)?;
    if !locator_is_strictly_after(&pending.pending_applied, &pending.witness.witness_applied)
        || pending.expected_clear_receipt_digest
            != private_oram_mutation_clear_receipt_digest_v2(
                &pending.witness.expected_clear_receipt()?,
            )?
        || pending.pending_digest != clear_pending_digest_v2(pending)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_cleared_state_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if cleared.version != CLEARED_STATE_VERSION || cleared.generation == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_private_oram_mutation_parent_watermark_v2_shape(&cleared.terminal_watermark)?;
    validate_cleanup_witness_v2(&cleared.cleanup_witness)?;
    for digest in [
        &cleared.collection_id_digest,
        &cleared.mutation_id,
        &cleared.signed_mutation_digest,
        &cleared.descriptor_digest,
        &cleared.terminal_record_digest,
        &cleared.lease_lineage_digest,
        &cleared.terminal_lease_state_digest,
        &cleared.witness_digest,
        &cleared.clear_attempt_id_digest,
        &cleared.clear_pending_digest,
        &cleared.clear_receipt_digest,
        &cleared.clear_core_digest,
        &cleared.resolution_digest,
        &cleared.tombstone_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_optional_digest(cleared.previous_tombstone_digest.as_deref())?;
    validate_clear_receipt_v2(&cleared.clear_receipt)?;
    validate_apply_locator_v2(&cleared.pending_applied)?;
    validate_apply_locator_v2(&cleared.clear_applied)?;
    if (cleared.generation == 1) != cleared.previous_tombstone_digest.is_none()
        || cleared.collection_id_digest != cleared.terminal_watermark.collection_id_digest()
        || cleared.generation != cleared.terminal_watermark.lease_generation()
        || cleared.owner_peer_id != cleared.terminal_watermark.owner_peer_id()
        || cleared.mutation_id != cleared.terminal_watermark.mutation_id()
        || cleared.signed_mutation_digest != cleared.terminal_watermark.signed_mutation_digest()
        || cleared.descriptor_digest != cleared.terminal_watermark.descriptor_digest()
        || cleared.terminal_watermark.sequence() != 7
        || cleared.terminal_record_digest
            != cleared.terminal_watermark.record_digest().unwrap_or("")
        || cleared.lease_lineage_digest != cleared.terminal_watermark.lease_lineage_digest()
        || cleared.cleanup_witness.terminal_watermark != cleared.terminal_watermark
        || cleared.cleanup_witness.terminal_record_digest != cleared.terminal_record_digest
        || cleared.cleanup_witness.terminal_lease_state_digest
            != cleared.terminal_lease_state_digest
        || cleared.cleanup_witness.witness_digest != cleared.witness_digest
        || !locator_is_strictly_after(
            &cleared.pending_applied,
            &cleared.cleanup_witness.witness_applied,
        )
        || !locator_is_strictly_after(&cleared.clear_applied, &cleared.pending_applied)
        || cleared.clear_receipt.generation != cleared.generation
        || cleared.clear_receipt.mutation_id != cleared.mutation_id
        || cleared.clear_receipt.outcome != cleared.cleanup_witness.outcome
        || cleared.clear_receipt.terminal_state_digest
            != cleared.cleanup_witness.terminal_consensus_state_digest
        || cleared.clear_receipt.reconciliation_digest != cleared.witness_digest
        || cleared.clear_pending_digest != clear_pending_digest_from_cleared_v2(cleared)?
        || !locator_is_strictly_after(
            &cleared.clear_applied,
            &cleared.cleanup_witness.witness_applied,
        )
        || cleared.clear_receipt_digest
            != private_oram_mutation_clear_receipt_digest_v2(&cleared.clear_receipt)?
        || cleared.clear_core_digest != clear_core_digest_v2(cleared)?
        || cleared.resolution_digest != clear_resolution_digest_v2(cleared)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    match &cleared.resolution {
        PrivateOramMutationClearResolutionV2::Pending => {}
        PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) => {
            validate_apply_locator_v2(&acknowledged.acknowledgement_applied)?;
            if !locator_is_strictly_after(
                &acknowledged.acknowledgement_applied,
                &cleared.clear_applied,
            ) {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
        }
    }
    if cleared.tombstone_digest != cleared_state_digest_v2(cleared)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn admitted_matches_watermark(
    admitted: &PrivateOramMutationAdmittedV2,
    watermark: &PrivateOramMutationParentWatermarkV2,
) -> bool {
    admitted.collection_id_digest == watermark.collection_id_digest()
        && admitted.generation == watermark.lease_generation()
        && admitted.owner_peer_id == watermark.owner_peer_id()
        && admitted.mutation_id == watermark.mutation_id()
        && admitted.signed_mutation_digest == watermark.signed_mutation_digest()
        && admitted.base_record_digest == watermark.base_record_digest()
        && admitted.lease_lineage_digest == watermark.lease_lineage_digest()
}

fn terminal_lease_matches_witness(
    lease: &PrivateOramMutationLease,
    witness: &PrivateOramMutationCleanupWitnessV2,
) -> Result<bool, PrivateOramMutationJournalError> {
    Ok(lease == &witness.terminal_lease
        && terminal_lease_matches_outcome(
            lease,
            &witness.outcome,
            &witness.terminal_consensus_state_digest,
            witness.terminal_consensus_state_sequence,
        )
        && private_oram_mutation_lease_lineage_digest_v2(lease)?
            == witness.admitted.lease_lineage_digest
        && private_oram_mutation_lease_state_digest_v2(lease)?
            == witness.terminal_lease_state_digest)
}

fn terminal_lease_matches_outcome(
    lease: &PrivateOramMutationLease,
    outcome: &PrivateOramMutationClearOutcome,
    terminal_consensus_state_digest: &str,
    terminal_consensus_state_sequence: u64,
) -> bool {
    match (&lease.phase, outcome) {
        (
            PrivateOramMutationLeasePhase::AbortDecided,
            PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit,
        ) => {
            lease.base_record_digest == terminal_consensus_state_digest
                && lease.base_state_sequence == terminal_consensus_state_sequence
        }
        (
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                committed_state_sequence,
                ..
            },
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
        ) => {
            committed_record_digest == terminal_consensus_state_digest
                && *committed_state_sequence == terminal_consensus_state_sequence
        }
        _ => false,
    }
}

pub(crate) fn private_oram_mutation_lease_state_digest_v2(
    lease: &PrivateOramMutationLease,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_lease_v2(lease)?;
    let mut hasher = Sha256::new();
    hasher.update(LEASE_STATE_DIGEST_DOMAIN_V2);
    hash_digest(
        &mut hasher,
        &private_oram_mutation_lease_lineage_digest_v2(lease)?,
    )?;
    hasher.update(lease.expires_at_unix.to_be_bytes());
    hasher.update(lease.renewal_revision.to_be_bytes());
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
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_admission_request_digest_v2(
    lease: &PrivateOramMutationLease,
    recovery_manifest_digest: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    admission_request_digest_from_parts_v2(
        &private_oram_mutation_lease_state_digest_v2(lease)?,
        recovery_manifest_digest,
    )
}

fn admission_request_digest_from_parts_v2(
    admitted_lease_state_digest: &str,
    recovery_manifest_digest: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_REQUEST_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, admitted_lease_state_digest)?;
    hash_digest(&mut hasher, recovery_manifest_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_clear_receipt_digest_v2(
    receipt: &PrivateOramMutationClearReceiptV1,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_clear_receipt_v2(receipt)?;
    let mut hasher = Sha256::new();
    hasher.update(CLEAR_RECEIPT_DIGEST_DOMAIN_V2);
    hasher.update(receipt.version.to_be_bytes());
    hasher.update(receipt.generation.to_be_bytes());
    hash_digest(&mut hasher, &receipt.mutation_id)?;
    hash_clear_outcome(&mut hasher, &receipt.outcome);
    hash_digest(&mut hasher, &receipt.terminal_state_digest)?;
    hash_digest(&mut hasher, &receipt.reconciliation_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn admitted_digest_v2(
    admitted: &PrivateOramMutationAdmittedV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(ADMITTED_DIGEST_DOMAIN_V2);
    hasher.update(admitted.version.to_be_bytes());
    hash_digest(&mut hasher, &admitted.collection_id_digest)?;
    hasher.update(admitted.generation.to_be_bytes());
    hasher.update(admitted.owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &admitted.mutation_id)?;
    hash_digest(&mut hasher, &admitted.signed_mutation_digest)?;
    hash_digest(&mut hasher, &admitted.base_record_digest)?;
    hash_digest(&mut hasher, &admitted.lease_lineage_digest)?;
    hash_digest(&mut hasher, &admitted.admitted_lease_state_digest)?;
    hash_digest(&mut hasher, &admitted.recovery_manifest_digest)?;
    hash_digest(&mut hasher, &admitted.admission_request_digest)?;
    hash_optional_digest(
        &mut hasher,
        admitted.predecessor_tombstone_digest.as_deref(),
    )?;
    hash_apply_locator(&mut hasher, &admitted.admission_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn parent_progress_digest_v2(
    progress: &PrivateOramMutationParentProgressV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PARENT_PROGRESS_DIGEST_DOMAIN_V2);
    hasher.update(progress.version.to_be_bytes());
    hash_digest(&mut hasher, &progress.admitted.admitted_digest)?;
    hash_digest(&mut hasher, progress.watermark.watermark_digest())?;
    hasher.update((progress.progress_applied_history.len() as u64).to_be_bytes());
    for locator in &progress.progress_applied_history {
        hash_apply_locator(&mut hasher, locator)?;
    }
    hash_apply_locator(&mut hasher, &progress.progress_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn cleanup_witness_digest_v2(
    witness: &PrivateOramMutationCleanupWitnessV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEANUP_WITNESS_DIGEST_DOMAIN_V2);
    hasher.update(witness.version.to_be_bytes());
    hash_digest(&mut hasher, &witness.admitted.admitted_digest)?;
    hash_digest(&mut hasher, witness.terminal_watermark.watermark_digest())?;
    hash_digest(&mut hasher, &witness.terminal_record_digest)?;
    hash_digest(&mut hasher, &witness.terminal_lease_state_digest)?;
    hash_clear_outcome(&mut hasher, &witness.outcome);
    hash_digest(&mut hasher, &witness.terminal_consensus_state_digest)?;
    hasher.update(witness.terminal_consensus_state_sequence.to_be_bytes());
    hash_digest(&mut hasher, &witness.owner_cleanup_evidence_digest)?;
    hash_digest(&mut hasher, &witness.point_cleanup_evidence_digest)?;
    hasher.update((witness.parent_progress_applied_history.len() as u64).to_be_bytes());
    for locator in &witness.parent_progress_applied_history {
        hash_apply_locator(&mut hasher, locator)?;
    }
    hash_apply_locator(&mut hasher, &witness.parent_progress_applied)?;
    hash_apply_locator(&mut hasher, &witness.witness_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn clear_pending_digest_v2(
    pending: &PrivateOramMutationClearPendingV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEAR_PENDING_DIGEST_DOMAIN_V2);
    hasher.update(pending.version.to_be_bytes());
    hash_digest(&mut hasher, &pending.witness.witness_digest)?;
    hash_digest(&mut hasher, &pending.clear_attempt_id_digest)?;
    hash_digest(&mut hasher, &pending.expected_clear_receipt_digest)?;
    hash_apply_locator(&mut hasher, &pending.pending_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn clear_pending_digest_from_cleared_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEAR_PENDING_DIGEST_DOMAIN_V2);
    hasher.update(CLEAR_PENDING_VERSION.to_be_bytes());
    hash_digest(&mut hasher, &cleared.witness_digest)?;
    hash_digest(&mut hasher, &cleared.clear_attempt_id_digest)?;
    hash_digest(&mut hasher, &cleared.clear_receipt_digest)?;
    hash_apply_locator(&mut hasher, &cleared.pending_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn clear_core_digest_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEAR_CORE_DIGEST_DOMAIN_V2);
    hasher.update(cleared.version.to_be_bytes());
    hash_digest(&mut hasher, &cleared.collection_id_digest)?;
    hasher.update(cleared.generation.to_be_bytes());
    hasher.update(cleared.owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &cleared.mutation_id)?;
    hash_digest(&mut hasher, &cleared.signed_mutation_digest)?;
    hash_digest(&mut hasher, &cleared.descriptor_digest)?;
    hash_digest(&mut hasher, cleared.terminal_watermark.watermark_digest())?;
    hash_digest(&mut hasher, &cleared.terminal_record_digest)?;
    hash_digest(&mut hasher, &cleared.lease_lineage_digest)?;
    hash_digest(&mut hasher, &cleared.terminal_lease_state_digest)?;
    hash_digest(&mut hasher, &cleared.witness_digest)?;
    hash_digest(&mut hasher, &cleared.clear_attempt_id_digest)?;
    hash_digest(&mut hasher, &cleared.clear_pending_digest)?;
    hash_apply_locator(&mut hasher, &cleared.pending_applied)?;
    hash_digest(&mut hasher, &cleared.clear_receipt_digest)?;
    hash_apply_locator(&mut hasher, &cleared.clear_applied)?;
    hash_optional_digest(&mut hasher, cleared.previous_tombstone_digest.as_deref())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn clear_resolution_digest_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEAR_RESOLUTION_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &cleared.clear_core_digest)?;
    match &cleared.resolution {
        PrivateOramMutationClearResolutionV2::Pending => hasher.update([1]),
        PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) => {
            hasher.update([2]);
            hash_apply_locator(&mut hasher, &acknowledged.acknowledgement_applied)?;
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn cleared_state_digest_v2(
    cleared: &PrivateOramMutationClearedStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEARED_STATE_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, &cleared.clear_core_digest)?;
    hash_digest(&mut hasher, &cleared.resolution_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn cleanup_lifecycle_digest_v2(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(LIFECYCLE_DIGEST_DOMAIN_V2);
    hasher.update(lifecycle.version.to_be_bytes());
    hash_digest(&mut hasher, &lifecycle.collection_id_digest)?;
    hash_digest(&mut hasher, &lifecycle.consensus_history_id_digest)?;
    hash_digest(&mut hasher, &lifecycle.raft_group_id_digest)?;
    hash_optional_digest(
        &mut hasher,
        lifecycle
            .last_cleared
            .as_ref()
            .map(|cleared| cleared.tombstone_digest.as_str()),
    )?;
    match &lifecycle.active {
        None => hasher.update([0]),
        Some(active) => {
            hasher.update([active_tag(active)]);
            hash_digest(&mut hasher, active_digest(active))?;
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn cleanup_evidence_digest_v2(
    expected: &PrivateOramMutationCleanupExpectationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CLEANUP_EVIDENCE_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, expected.terminal_watermark.watermark_digest())?;
    hash_digest(&mut hasher, &expected.terminal_record_digest)?;
    hash_digest(&mut hasher, &expected.terminal_lease_state_digest)?;
    hash_clear_outcome(&mut hasher, &expected.outcome);
    hash_digest(&mut hasher, &expected.terminal_consensus_state_digest)?;
    hasher.update(expected.terminal_consensus_state_sequence.to_be_bytes());
    hash_digest(&mut hasher, &expected.owner_cleanup_evidence_digest)?;
    hash_digest(&mut hasher, &expected.point_cleanup_evidence_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn private_oram_mutation_lease_slot_digest_v2(
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_lease_slot_v2(slot)?;
    let mut hasher = Sha256::new();
    hasher.update(LEASE_SLOT_DIGEST_DOMAIN_V2);
    hasher.update(slot.version.to_be_bytes());
    hasher.update(slot.generation.to_be_bytes());
    match &slot.active {
        None => hasher.update([0]),
        Some(lease) => {
            hasher.update([1]);
            hash_digest(
                &mut hasher,
                &private_oram_mutation_lease_state_digest_v2(lease)?,
            )?;
        }
    }
    match &slot.last_clear {
        None => hasher.update([0]),
        Some(receipt) => {
            hasher.update([1]);
            hash_digest(
                &mut hasher,
                &private_oram_mutation_clear_receipt_digest_v2(receipt)?,
            )?;
        }
    }
    hasher.update(slot.max_writer_fence.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn applied_operation_digest_v2(
    operation_kind: PrivateOramMutationCleanupOperationKindV2,
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: Option<&PrivateOramMutationLeaseSlotV2>,
    payload_digest: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_lifecycle_v2(lifecycle)?;
    validate_digest(payload_digest)?;
    let mut hasher = Sha256::new();
    hasher.update(APPLIED_OPERATION_DIGEST_DOMAIN_V2);
    hasher.update([operation_kind_tag(operation_kind)]);
    hash_digest(&mut hasher, &lifecycle.collection_id_digest)?;
    hash_digest(&mut hasher, &lifecycle.lifecycle_digest)?;
    match slot {
        None => hasher.update([0]),
        Some(slot) => {
            hasher.update([1]);
            hash_digest(
                &mut hasher,
                &private_oram_mutation_lease_slot_digest_v2(slot)?,
            )?;
        }
    }
    hash_digest(&mut hasher, payload_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_applied_entry_v2(
    applied_entry: &PrivateOramAppliedEntryV2,
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    expected_kind: PrivateOramMutationCleanupOperationKindV2,
    expected_operation_digest: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_apply_locator_v2(&applied_entry.locator)?;
    validate_digest(&applied_entry.operation_digest)?;
    if !locator_matches_lifecycle_namespace(&applied_entry.locator, lifecycle)
        || applied_entry.operation_kind != expected_kind
        || applied_entry.operation_digest != expected_operation_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn operation_kind_tag(kind: PrivateOramMutationCleanupOperationKindV2) -> u8 {
    match kind {
        PrivateOramMutationCleanupOperationKindV2::Admission => 1,
        PrivateOramMutationCleanupOperationKindV2::ParentProgress => 2,
        PrivateOramMutationCleanupOperationKindV2::CleanupWitness => 3,
        PrivateOramMutationCleanupOperationKindV2::ClearPending => 4,
        PrivateOramMutationCleanupOperationKindV2::Clear => 5,
        PrivateOramMutationCleanupOperationKindV2::ClearAcknowledgement => 6,
    }
}

pub(crate) fn validate_lease_v2(
    lease: &PrivateOramMutationLease,
) -> Result<(), PrivateOramMutationJournalError> {
    if lease.generation == 0
        || lease.collection_id.is_empty()
        || lease.collection_id.len() > 1024
        || lease.writer_fence == 0
        || lease.issued_at_unix == 0
        || lease.expires_at_unix <= lease.issued_at_unix
        || lease.expires_at_unix - lease.issued_at_unix > MAX_LEASE_DURATION_SECS
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &lease.mutation_id,
        &lease.signed_mutation_digest,
        &lease.transition_digest,
        &lease.base_record_digest,
        &lease.writer_lease_digest,
    ] {
        validate_digest(digest)?;
    }
    if let PrivateOramMutationLeasePhase::ConsensusCommitted {
        committed_record_digest,
        committed_state_sequence,
        committed_signed_state_digest,
        receipt_digest,
    } = &lease.phase
    {
        for digest in [
            committed_record_digest,
            committed_signed_state_digest,
            receipt_digest,
        ] {
            validate_digest(digest)?;
        }
        if lease.base_state_sequence.checked_add(1) != Some(*committed_state_sequence) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

fn validate_lease_slot_v2(
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if slot.version != PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION
        || slot.generation != slot.max_writer_fence
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if let Some(receipt) = &slot.last_clear {
        validate_clear_receipt_v2(receipt)?;
        if receipt.generation > slot.generation {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    match &slot.active {
        Some(lease) => {
            validate_lease_v2(lease)?;
            if lease.generation != slot.generation
                || lease.writer_fence != slot.max_writer_fence
                || slot
                    .last_clear
                    .as_ref()
                    .is_some_and(|receipt| receipt.generation >= lease.generation)
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
        }
        None if slot.generation == 0 && slot.last_clear.is_none() => {}
        None if slot
            .last_clear
            .as_ref()
            .is_some_and(|receipt| receipt.generation == slot.generation) => {}
        None => return Err(PrivateOramMutationJournalError::Corrupt),
    }
    Ok(())
}

fn validate_clear_receipt_v2(
    receipt: &PrivateOramMutationClearReceiptV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if receipt.version != PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION || receipt.generation == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &receipt.mutation_id,
        &receipt.terminal_state_digest,
        &receipt.reconciliation_digest,
    ] {
        validate_digest(digest)?;
    }
    Ok(())
}

fn validate_apply_locator_v2(
    locator: &PrivateOramRaftApplyLocatorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if locator.version != APPLY_LOCATOR_VERSION || locator.term == 0 || locator.index == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_digest(&locator.consensus_history_id_digest)?;
    validate_digest(&locator.raft_group_id_digest)?;
    Ok(())
}

fn validate_apply_locator_history_v2(
    history: &[PrivateOramRaftApplyLocatorV2],
    predecessor: &PrivateOramRaftApplyLocatorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if history.is_empty() || history.len() > 7 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut previous = predecessor;
    for locator in history {
        validate_apply_locator_v2(locator)?;
        if !locator_is_strictly_after(locator, previous) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous = locator;
    }
    Ok(())
}

fn locator_is_strictly_after(
    later: &PrivateOramRaftApplyLocatorV2,
    earlier: &PrivateOramRaftApplyLocatorV2,
) -> bool {
    locator_has_same_namespace(later, earlier)
        && later.index > earlier.index
        && later.term >= earlier.term
}

fn locator_is_at_or_after(
    later: &PrivateOramRaftApplyLocatorV2,
    earlier: &PrivateOramRaftApplyLocatorV2,
) -> bool {
    locator_has_same_namespace(later, earlier)
        && ((later.index == earlier.index && later.term == earlier.term)
            || (later.index > earlier.index && later.term >= earlier.term))
}

fn locator_has_same_namespace(
    left: &PrivateOramRaftApplyLocatorV2,
    right: &PrivateOramRaftApplyLocatorV2,
) -> bool {
    left.consensus_history_id_digest == right.consensus_history_id_digest
        && left.raft_group_id_digest == right.raft_group_id_digest
}

fn locator_matches_lifecycle_namespace(
    locator: &PrivateOramRaftApplyLocatorV2,
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
) -> bool {
    locator.consensus_history_id_digest == lifecycle.consensus_history_id_digest
        && locator.raft_group_id_digest == lifecycle.raft_group_id_digest
}

fn hash_apply_locator(
    hasher: &mut Sha256,
    locator: &PrivateOramRaftApplyLocatorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_apply_locator_v2(locator)?;
    hasher.update(locator.version.to_be_bytes());
    hash_digest(hasher, &locator.consensus_history_id_digest)?;
    hash_digest(hasher, &locator.raft_group_id_digest)?;
    hasher.update(locator.term.to_be_bytes());
    hasher.update(locator.index.to_be_bytes());
    Ok(())
}

fn hash_clear_outcome(hasher: &mut Sha256, outcome: &PrivateOramMutationClearOutcome) {
    hasher.update([match outcome {
        PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit => 1,
        PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit => 2,
    }]);
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

fn validate_optional_digest(value: Option<&str>) -> Result<(), PrivateOramMutationJournalError> {
    if let Some(value) = value {
        validate_digest(value)?;
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hash_digest(&mut hasher, value)
}

#[cfg(test)]
fn private_oram_applied_entry_for_operation_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    operation_kind: PrivateOramMutationCleanupOperationKindV2,
    operation_digest: String,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    let locator = PrivateOramRaftApplyLocatorV2 {
        version: APPLY_LOCATOR_VERSION,
        consensus_history_id_digest: lifecycle.consensus_history_id_digest.clone(),
        raft_group_id_digest: lifecycle.raft_group_id_digest.clone(),
        term,
        index,
    };
    validate_apply_locator_v2(&locator)?;
    validate_digest(&operation_digest)?;
    Ok(PrivateOramAppliedEntryV2 {
        locator,
        operation_kind,
        operation_digest,
        _not_send_or_sync: PhantomData,
    })
}

#[cfg(test)]
pub(crate) fn private_oram_admission_applied_entry_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    lease: &PrivateOramMutationLease,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    let recovery_manifest_canonical_json = crate::content_manager::private_oram_mutation_journal::private_oram_mutation_admission_recovery_manifest_for_test(
        lease,
        &lifecycle.lifecycle_digest,
    );
    let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &recovery_manifest_canonical_json,
    )?;
    private_oram_applied_entry_for_operation_for_test(
        lifecycle,
        PrivateOramMutationCleanupOperationKindV2::Admission,
        applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::Admission,
            lifecycle,
            Some(slot),
            &private_oram_mutation_admission_request_digest_v2(
                lease,
                recovery_manifest.manifest_digest(),
            )?,
        )?,
        term,
        index,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_parent_progress_applied_entry_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    private_oram_applied_entry_for_operation_for_test(
        lifecycle,
        PrivateOramMutationCleanupOperationKindV2::ParentProgress,
        applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::ParentProgress,
            lifecycle,
            Some(slot),
            expected.watermark().watermark_digest(),
        )?,
        term,
        index,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_cleanup_expectation_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    terminal_lease: &PrivateOramMutationLease,
    outcome: PrivateOramMutationClearOutcome,
    terminal_consensus_state_digest: String,
    owner_cleanup_evidence_digest: String,
    point_cleanup_evidence_digest: String,
) -> Result<PrivateOramMutationCleanupExpectationV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_lifecycle_v2(lifecycle)?;
    validate_lease_v2(terminal_lease)?;
    for digest in [
        &terminal_consensus_state_digest,
        &owner_cleanup_evidence_digest,
        &point_cleanup_evidence_digest,
    ] {
        validate_digest(digest)?;
    }
    let Some(PrivateOramMutationCleanupActiveV2::ParentProgress(progress)) =
        lifecycle.active.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    if progress.watermark.sequence() != 7
        || private_oram_mutation_lease_lineage_digest_v2(terminal_lease)?
            != progress.admitted.lease_lineage_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let terminal_consensus_state_sequence = match &terminal_lease.phase {
        PrivateOramMutationLeasePhase::AbortDecided => terminal_lease.base_state_sequence,
        PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_state_sequence,
            ..
        } => *committed_state_sequence,
        PrivateOramMutationLeasePhase::Preparing => {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    };
    derive_private_oram_mutation_cleanup_expectation_v2(
        progress.watermark.clone(),
        terminal_lease.clone(),
        outcome,
        terminal_consensus_state_digest,
        terminal_consensus_state_sequence,
        owner_cleanup_evidence_digest,
        point_cleanup_evidence_digest,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_cleanup_witness_applied_entry_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    expected: &PrivateOramMutationCleanupExpectationV2,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    private_oram_applied_entry_for_operation_for_test(
        lifecycle,
        PrivateOramMutationCleanupOperationKindV2::CleanupWitness,
        applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::CleanupWitness,
            lifecycle,
            Some(slot),
            &expected.evidence_digest,
        )?,
        term,
        index,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_clear_pending_applied_entry_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    clear_attempt_id_digest: &str,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    private_oram_applied_entry_for_operation_for_test(
        lifecycle,
        PrivateOramMutationCleanupOperationKindV2::ClearPending,
        applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::ClearPending,
            lifecycle,
            Some(slot),
            clear_attempt_id_digest,
        )?,
        term,
        index,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_clear_applied_entry_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    let Some(PrivateOramMutationCleanupActiveV2::ClearPending(pending)) = lifecycle.active.as_ref()
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    private_oram_applied_entry_for_operation_for_test(
        lifecycle,
        PrivateOramMutationCleanupOperationKindV2::Clear,
        applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::Clear,
            lifecycle,
            Some(slot),
            &pending.pending_digest,
        )?,
        term,
        index,
    )
}

#[cfg(test)]
pub(crate) fn replace_private_oram_applied_entry_namespace_for_test(
    mut applied_entry: PrivateOramAppliedEntryV2,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    validate_digest(&consensus_history_id_digest)?;
    validate_digest(&raft_group_id_digest)?;
    applied_entry.locator.consensus_history_id_digest = consensus_history_id_digest;
    applied_entry.locator.raft_group_id_digest = raft_group_id_digest;
    validate_apply_locator_v2(&applied_entry.locator)?;
    Ok(applied_entry)
}

#[cfg(test)]
pub(crate) fn replace_private_oram_applied_entry_operation_digest_for_test(
    mut applied_entry: PrivateOramAppliedEntryV2,
    operation_digest: String,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    validate_digest(&operation_digest)?;
    applied_entry.operation_digest = operation_digest;
    Ok(applied_entry)
}

#[cfg(test)]
pub(crate) fn private_oram_cleanup_gc_exclusion_permit_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<PrivateOramMutationCleanupGcExclusionPermitV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_pair_v2(lifecycle, slot)?;
    let cleared = lifecycle
        .last_cleared
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let PrivateOramMutationClearResolutionV2::Acknowledged(acknowledged) = &cleared.resolution
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    Ok(PrivateOramMutationCleanupGcExclusionPermitV2 {
        collection_id_digest: lifecycle.collection_id_digest.clone(),
        generation: cleared.generation,
        tombstone_digest: cleared.tombstone_digest.clone(),
        acknowledgement_applied: acknowledged.acknowledgement_applied.clone(),
        _not_send_or_sync: PhantomData,
    })
}

#[cfg(test)]
pub(crate) fn private_oram_cleared_pending_archive_permit_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    collection_id: String,
    vector_name: String,
    owner_signing_key_id: String,
    expected_owner_peer_id: PeerId,
    expected_generation: u64,
) -> Result<PrivateOramMutationClearedPendingArchivePermitV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_cleanup_lifecycle_v2(lifecycle)?;
    let cleared = lifecycle
        .last_cleared
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if lifecycle.active.is_some()
        || !matches!(
            cleared.resolution,
            PrivateOramMutationClearResolutionV2::Pending
        )
        || private_oram_collection_id_digest_v2(&collection_id)? != lifecycle.collection_id_digest
        || cleared.owner_peer_id != expected_owner_peer_id
        || cleared.generation != expected_generation
        || vector_name.is_empty()
        || owner_signing_key_id.is_empty()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
        &cleared
            .cleanup_witness
            .admitted
            .recovery_manifest_canonical_json,
    )?;
    let owner_prestage_receipt = recovery_manifest
        .owner_receipt(expected_owner_peer_id)
        .cloned()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if owner_prestage_receipt.collection_id() != collection_id
        || owner_prestage_receipt.owner_peer_id() != expected_owner_peer_id
        || owner_prestage_receipt.lease_generation() != expected_generation
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramMutationClearedPendingArchivePermitV2 {
        collection_id,
        vector_name,
        owner_signing_key_id,
        owner_prestage_receipt,
        generation: cleared.generation,
        owner_peer_id: cleared.owner_peer_id,
        descriptor_digest: cleared.descriptor_digest.clone(),
        terminal_record_digest: cleared.terminal_record_digest.clone(),
        witness_digest: cleared.witness_digest.clone(),
        cleanup_evidence_digest: cleared.cleanup_witness.evidence_digest_for_archive_v2()?,
        clear_attempt_id_digest: cleared.clear_attempt_id_digest.clone(),
        clear_receipt_digest: cleared.clear_receipt_digest.clone(),
        tombstone_digest: cleared.tombstone_digest.clone(),
    })
}

#[cfg(test)]
pub(crate) fn replace_private_oram_archive_prestage_receipt_for_test(
    mut permit: PrivateOramMutationClearedPendingArchivePermitV2,
    receipt: PrivateOramOwnerPrestageReceiptV2,
) -> Result<PrivateOramMutationClearedPendingArchivePermitV2, PrivateOramMutationJournalError> {
    if receipt.collection_id() != permit.collection_id
        || receipt.owner_peer_id() != permit.owner_peer_id
        || receipt.lease_generation() != permit.generation
        || receipt.parent_descriptor_digest() != permit.descriptor_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    permit.owner_prestage_receipt = receipt;
    Ok(permit)
}

#[cfg(test)]
pub(crate) fn private_oram_clear_acknowledgement_applied_entry_for_test(
    lifecycle: &PrivateOramMutationCleanupLifecycleV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    term: u64,
    index: u64,
) -> Result<PrivateOramAppliedEntryV2, PrivateOramMutationJournalError> {
    let cleared = lifecycle
        .last_cleared
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    private_oram_applied_entry_for_operation_for_test(
        lifecycle,
        PrivateOramMutationCleanupOperationKindV2::ClearAcknowledgement,
        applied_operation_digest_v2(
            PrivateOramMutationCleanupOperationKindV2::ClearAcknowledgement,
            lifecycle,
            Some(slot),
            &cleared.clear_core_digest,
        )?,
        term,
        index,
    )
}
