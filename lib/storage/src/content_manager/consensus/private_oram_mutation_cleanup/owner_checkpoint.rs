//! Retained owner lifecycle checkpoints for the dormant private-ORAM mutation protocol.
//!
//! The table is consensus state. Owner-local attestations are accepted only when they match an
//! exact retained checkpoint. Reservations lease that predecessor, and a negative-attempt
//! acknowledgement advances every affected checkpoint atomically.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1, PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerCleanupTerminalStateV1, PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    PrivateOramOwnerEnrollmentPreparedV1, PrivateOramOwnerLifecycleStateV1,
    PrivateOramOwnerLifecycleStatusAttestationV1, PrivateOramOwnerReservationPrepareV1,
    prepare_private_oram_owner_enrollment_v1, private_oram_owner_lifecycle_genesis_state_v1,
    private_oram_owner_lifecycle_state_root_v1,
    validate_private_oram_owner_enrollment_genesis_commitment_v1,
    validate_private_oram_owner_enrollment_prepared_v1,
    validate_private_oram_owner_lifecycle_signer_v1,
    validate_private_oram_owner_lifecycle_state_v1,
    validate_private_oram_owner_lifecycle_status_attestation_v1,
    validate_private_oram_owner_reservation_prepare_v1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    PrivateOramRaftApplyLocatorV2, locator_is_strictly_after, validate_apply_locator_v2,
    validate_digest,
};
use crate::content_manager::private_oram_mutation_journal::PrivateOramMutationJournalError;
use crate::content_manager::private_oram_mutation_state_v2::private_oram_collection_id_digest_v2;

const TABLE_VERSION: u16 = 1;
const PENDING_ENROLLMENT_VERSION: u16 = 1;
const CHECKPOINT_RECORD_VERSION: u16 = 1;
const RESERVATION_EXPECTATION_VERSION: u16 = 1;
const RESERVATION_CONTEXT_VERSION: u16 = 1;
const RESERVATION_BINDING_VERSION: u16 = 1;
const ACTIVE_LEASE_VERSION: u16 = 1;
const SUCCESSOR_VERSION: u16 = 1;
const MAX_OWNERS: usize = 1_024;
const MAX_CHECKPOINT_TABLE_BYTES: usize = 4 * 1024 * 1024;

const TABLE_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-checkpoint-table/v1";
const PENDING_ENROLLMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-enrollment-pending/v1";
const CHECKPOINT_RECORD_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-checkpoint-record/v1";
const RESERVATION_EXPECTATION_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-checkpoint-reservation-expectation/v1";
const RESERVATION_CONTEXT_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-checkpoint-reservation-context/v1";
const RESERVATION_BINDING_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-checkpoint-reservation-binding/v1";
const ACTIVE_LEASE_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-checkpoint-active-lease/v1";
const SUCCESSOR_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-checkpoint-successor/v1";
const OWNER_ROSTER_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-checkpoint-roster/v1";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramOwnerCheckpointSourceKindV1 {
    EnrollmentGenesis,
    NegativeCleanupAcknowledgement,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerPendingEnrollmentV1 {
    version: u16,
    prepared: PrivateOramOwnerEnrollmentPreparedV1,
    prepared_applied: PrivateOramRaftApplyLocatorV2,
    pending_digest: String,
}

impl Debug for PrivateOramOwnerPendingEnrollmentV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerPendingEnrollmentV1")
            .field("version", &self.version)
            .field("prepared", &self.prepared)
            .field("prepared_applied", &self.prepared_applied)
            .field("pending_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointRecordV1 {
    version: u16,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_key_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    capability_epoch: u64,
    protocol_capability_digest: String,
    membership_epoch: u64,
    owner_enrollment_id: String,
    owner_peer_id: u64,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
    owner_store_incarnation_digest: String,
    checkpoint_sequence: u64,
    lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    source_kind: PrivateOramOwnerCheckpointSourceKindV1,
    source_record_digest: String,
    source_applied: PrivateOramRaftApplyLocatorV2,
    authority_registry_digest: String,
    owner_registry_digest: String,
    checkpoint_record_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointRecordV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointRecordV1")
            .field("version", &self.version)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("checkpoint_sequence", &self.checkpoint_sequence)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("source_kind", &self.source_kind)
            .field("source_applied", &self.source_applied)
            .field("owner_enrollment_id", &"[redacted]")
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("source_record_digest", &"[redacted]")
            .field("checkpoint_record_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCheckpointRecordV1 {
    pub(crate) fn owner_enrollment_id(&self) -> &str {
        &self.owner_enrollment_id
    }

    pub(crate) fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    pub(crate) fn lifecycle_state(&self) -> &PrivateOramOwnerLifecycleStateV1 {
        &self.lifecycle_state
    }

    pub(crate) fn checkpoint_record_digest(&self) -> &str {
        &self.checkpoint_record_digest
    }

    pub(crate) fn owner_signer(&self) -> &PrivateOramOwnerCleanupSignerV1 {
        &self.owner_signer
    }

    pub(crate) fn owner_store_incarnation_digest(&self) -> &str {
        &self.owner_store_incarnation_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointReservationExpectationV1 {
    version: u16,
    owner_index: u32,
    owner_enrollment_id: String,
    owner_peer_id: u64,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
    owner_store_incarnation_digest: String,
    membership_epoch: u64,
    expected_checkpoint_sequence: u64,
    expected_checkpoint_record_digest: String,
    expected_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    authority_registry_digest: String,
    owner_registry_digest: String,
    expectation_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointReservationExpectationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointReservationExpectationV1")
            .field("version", &self.version)
            .field("owner_index", &self.owner_index)
            .field("owner_peer_id", &self.owner_peer_id)
            .field(
                "expected_checkpoint_sequence",
                &self.expected_checkpoint_sequence,
            )
            .field("expected_lifecycle_state", &self.expected_lifecycle_state)
            .field("owner_enrollment_id", &"[redacted]")
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("expected_checkpoint_record_digest", &"[redacted]")
            .field("expectation_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCheckpointReservationExpectationV1 {
    pub(crate) fn owner_index(&self) -> u32 {
        self.owner_index
    }

    pub(crate) fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn owner_enrollment_id(&self) -> &str {
        &self.owner_enrollment_id
    }

    pub(crate) fn owner_signer(&self) -> &PrivateOramOwnerCleanupSignerV1 {
        &self.owner_signer
    }

    pub(crate) fn owner_store_incarnation_digest(&self) -> &str {
        &self.owner_store_incarnation_digest
    }

    pub(crate) fn expected_checkpoint_sequence(&self) -> u64 {
        self.expected_checkpoint_sequence
    }

    pub(crate) fn expected_checkpoint_record_digest(&self) -> &str {
        &self.expected_checkpoint_record_digest
    }

    pub(crate) fn expected_lifecycle_state(&self) -> &PrivateOramOwnerLifecycleStateV1 {
        &self.expected_lifecycle_state
    }

    pub(crate) fn authority_registry_digest(&self) -> &str {
        &self.authority_registry_digest
    }

    pub(crate) fn owner_registry_digest(&self) -> &str {
        &self.owner_registry_digest
    }

    pub(crate) fn expectation_digest(&self) -> &str {
        &self.expectation_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointReservationContextV1 {
    version: u16,
    reservation_intent_digest: String,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_key_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    capability_epoch: u64,
    protocol_capability_digest: String,
    membership_epoch: u64,
    checkpoint_table_sequence: u64,
    checkpoint_table_digest: String,
    owner_checkpoint_roster_digest: String,
    owner_expectations: Vec<PrivateOramOwnerCheckpointReservationExpectationV1>,
    context_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointReservationContextV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointReservationContextV1")
            .field("version", &self.version)
            .field("capability_epoch", &self.capability_epoch)
            .field("membership_epoch", &self.membership_epoch)
            .field("checkpoint_table_sequence", &self.checkpoint_table_sequence)
            .field("owner_count", &self.owner_expectations.len())
            .field("reservation_intent_digest", &"[redacted]")
            .field("checkpoint_table_digest", &"[redacted]")
            .field("owner_checkpoint_roster_digest", &"[redacted]")
            .field("context_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCheckpointReservationContextV1 {
    pub(crate) fn reservation_intent_digest(&self) -> &str {
        &self.reservation_intent_digest
    }

    pub(crate) fn checkpoint_table_sequence(&self) -> u64 {
        self.checkpoint_table_sequence
    }

    pub(crate) fn checkpoint_table_digest(&self) -> &str {
        &self.checkpoint_table_digest
    }

    pub(crate) fn owner_checkpoint_roster_digest(&self) -> &str {
        &self.owner_checkpoint_roster_digest
    }

    pub(crate) fn owner_expectations(
        &self,
    ) -> &[PrivateOramOwnerCheckpointReservationExpectationV1] {
        &self.owner_expectations
    }

    pub(crate) fn context_digest(&self) -> &str {
        &self.context_digest
    }

    pub(crate) fn consensus_history_id_digest(&self) -> &str {
        &self.consensus_history_id_digest
    }

    pub(crate) fn raft_group_id_digest(&self) -> &str {
        &self.raft_group_id_digest
    }

    pub(crate) fn collection_key_digest(&self) -> &str {
        &self.collection_key_digest
    }

    pub(crate) fn collection_lifetime_id_digest(&self) -> &str {
        &self.collection_lifetime_id_digest
    }

    pub(crate) fn collection_incarnation_digest(&self) -> &str {
        &self.collection_incarnation_digest
    }

    pub(crate) fn activation_anchor_digest(&self) -> &str {
        &self.activation_anchor_digest
    }

    pub(crate) fn protocol_capability_digest(&self) -> &str {
        &self.protocol_capability_digest
    }

    pub(crate) fn capability_epoch(&self) -> u64 {
        self.capability_epoch
    }

    pub(crate) fn membership_epoch(&self) -> u64 {
        self.membership_epoch
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointReservationBindingV1 {
    version: u16,
    owner_index: u32,
    owner_enrollment_id: String,
    expected_checkpoint_sequence: u64,
    expected_checkpoint_record_digest: String,
    expected_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    reservation_prepare: PrivateOramOwnerReservationPrepareV1,
    binding_digest: String,
}

impl PrivateOramOwnerCheckpointReservationBindingV1 {
    pub(crate) fn owner_index(&self) -> u32 {
        self.owner_index
    }

    pub(crate) fn owner_enrollment_id(&self) -> &str {
        &self.owner_enrollment_id
    }

    pub(crate) fn expected_checkpoint_sequence(&self) -> u64 {
        self.expected_checkpoint_sequence
    }

    pub(crate) fn expected_checkpoint_record_digest(&self) -> &str {
        &self.expected_checkpoint_record_digest
    }

    pub(crate) fn reservation_prepare(&self) -> &PrivateOramOwnerReservationPrepareV1 {
        &self.reservation_prepare
    }

    pub(crate) fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}

impl Debug for PrivateOramOwnerCheckpointReservationBindingV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointReservationBindingV1")
            .field("version", &self.version)
            .field("owner_index", &self.owner_index)
            .field(
                "expected_checkpoint_sequence",
                &self.expected_checkpoint_sequence,
            )
            .field("owner_enrollment_id", &"[redacted]")
            .field("expected_checkpoint_record_digest", &"[redacted]")
            .field("expected_lifecycle_state", &self.expected_lifecycle_state)
            .field("reservation_prepare", &"[redacted]")
            .field("binding_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointActiveLeaseV1 {
    version: u16,
    owner_index: u32,
    owner_enrollment_id: String,
    checkpoint_record_digest: String,
    attempt_id: String,
    attempt_context_digest: String,
    reservation_digest: String,
    reservation_applied: PrivateOramRaftApplyLocatorV2,
    lease_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointActiveLeaseV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointActiveLeaseV1")
            .field("version", &self.version)
            .field("owner_index", &self.owner_index)
            .field("reservation_applied", &self.reservation_applied)
            .field("owner_enrollment_id", &"[redacted]")
            .field("checkpoint_record_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("attempt_context_digest", &"[redacted]")
            .field("reservation_digest", &"[redacted]")
            .field("lease_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointTableV1 {
    version: u16,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_key_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    activation_applied: PrivateOramRaftApplyLocatorV2,
    capability_epoch: u64,
    protocol_capability_digest: String,
    roster_membership_epoch: Option<u64>,
    owner_roster_digest: String,
    table_sequence: u64,
    pending_enrollments: Vec<PrivateOramOwnerPendingEnrollmentV1>,
    checkpoints: Vec<PrivateOramOwnerCheckpointRecordV1>,
    active_leases: Vec<PrivateOramOwnerCheckpointActiveLeaseV1>,
    repair_pending_owner_enrollment_ids: Vec<String>,
    table_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointTableV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointTableV1")
            .field("version", &self.version)
            .field("capability_epoch", &self.capability_epoch)
            .field("roster_membership_epoch", &self.roster_membership_epoch)
            .field("table_sequence", &self.table_sequence)
            .field("pending_enrollment_count", &self.pending_enrollments.len())
            .field("checkpoint_count", &self.checkpoints.len())
            .field("active_lease_count", &self.active_leases.len())
            .field(
                "repair_pending_count",
                &self.repair_pending_owner_enrollment_ids.len(),
            )
            .field("table_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCheckpointTableV1 {
    pub(crate) fn table_digest(&self) -> &str {
        &self.table_digest
    }

    pub(crate) fn table_sequence(&self) -> u64 {
        self.table_sequence
    }

    pub(crate) fn checkpoints(&self) -> &[PrivateOramOwnerCheckpointRecordV1] {
        &self.checkpoints
    }

    pub(crate) fn roster_membership_epoch(&self) -> Option<u64> {
        self.roster_membership_epoch
    }

    pub(crate) fn pending_enrollment_for_owner(
        &self,
        owner_peer_id: u64,
    ) -> Option<&PrivateOramOwnerEnrollmentPreparedV1> {
        self.pending_enrollments
            .iter()
            .find(|pending| pending.prepared.owner_peer_id == owner_peer_id)
            .map(|pending| &pending.prepared)
    }

    pub(crate) fn checkpoint_for_owner(
        &self,
        owner_peer_id: u64,
    ) -> Option<&PrivateOramOwnerCheckpointRecordV1> {
        self.checkpoints
            .iter()
            .find(|checkpoint| checkpoint.owner_peer_id == owner_peer_id)
    }

    pub(crate) fn enrollment_roster_is_active(&self, owner_peer_ids: &[u64]) -> bool {
        let mut checkpoint_owner_peer_ids = self
            .checkpoints
            .iter()
            .map(|checkpoint| checkpoint.owner_peer_id)
            .collect::<Vec<_>>();
        checkpoint_owner_peer_ids.sort_unstable();
        self.roster_membership_epoch.is_some()
            && self.pending_enrollments.is_empty()
            && self.active_leases.is_empty()
            && self.repair_pending_owner_enrollment_ids.is_empty()
            && checkpoint_owner_peer_ids == owner_peer_ids
    }

    pub(crate) fn pending_enrollment_count(&self) -> usize {
        self.pending_enrollments.len()
    }

    pub(crate) fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    pub(crate) fn has_pending_repair(&self) -> bool {
        !self.repair_pending_owner_enrollment_ids.is_empty()
    }

    pub(crate) fn has_active_leases(&self) -> bool {
        !self.active_leases.is_empty()
    }

    pub(crate) fn owner_roster_digest(&self) -> &str {
        &self.owner_roster_digest
    }

    pub(crate) fn maximum_material_locator(&self) -> &PrivateOramRaftApplyLocatorV2 {
        let mut maximum = &self.activation_applied;
        for candidate in self
            .pending_enrollments
            .iter()
            .map(|pending| &pending.prepared_applied)
            .chain(
                self.checkpoints
                    .iter()
                    .map(|checkpoint| &checkpoint.source_applied),
            )
            .chain(
                self.active_leases
                    .iter()
                    .map(|lease| &lease.reservation_applied),
            )
        {
            if locator_is_strictly_after(candidate, maximum) {
                maximum = candidate;
            }
        }
        maximum
    }

    pub(crate) fn pending_enrollment_applied(
        &self,
        prepared_record_digest: &str,
    ) -> Option<&PrivateOramRaftApplyLocatorV2> {
        self.pending_enrollments
            .iter()
            .find(|pending| pending.prepared.prepared_record_digest == prepared_record_digest)
            .map(|pending| &pending.prepared_applied)
    }

    pub(crate) fn enrollment_genesis_applied(
        &self,
        commitment_digest: &str,
    ) -> Option<&PrivateOramRaftApplyLocatorV2> {
        self.checkpoints
            .iter()
            .find(|checkpoint| {
                checkpoint.source_kind == PrivateOramOwnerCheckpointSourceKindV1::EnrollmentGenesis
                    && checkpoint.source_record_digest == commitment_digest
            })
            .map(|checkpoint| &checkpoint.source_applied)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramOwnerCheckpointSuccessorV1 {
    version: u16,
    owner_index: u32,
    owner_enrollment_id: String,
    previous_checkpoint_sequence: u64,
    previous_checkpoint_record_digest: String,
    previous_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    new_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    terminal_state: PrivateOramOwnerCleanupTerminalStateV1,
    terminal_marker_digest: String,
    intent_identity_digest: String,
    cleanup_operation_id: String,
    grant_digest: String,
    committed_terminal_evidence_digest: String,
    successor_digest: String,
}

impl Debug for PrivateOramOwnerCheckpointSuccessorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCheckpointSuccessorV1")
            .field("version", &self.version)
            .field("owner_index", &self.owner_index)
            .field(
                "previous_checkpoint_sequence",
                &self.previous_checkpoint_sequence,
            )
            .field("terminal_state", &self.terminal_state)
            .field("owner_enrollment_id", &"[redacted]")
            .field("previous_checkpoint_record_digest", &"[redacted]")
            .field("previous_lifecycle_state", &self.previous_lifecycle_state)
            .field("new_lifecycle_state", &self.new_lifecycle_state)
            .field("successor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(crate) enum PrivateOramOwnerNegativeSettlementV1 {
    CleanupTerminalCommitted(PrivateOramOwnerCheckpointSuccessorV1),
    NoPrestageWrite {
        owner_index: u32,
        owner_enrollment_id: String,
        disposition_digest: String,
    },
    ReservationCompletionCommitted {
        owner_index: u32,
        owner_enrollment_id: String,
        completion_receipt_digest: String,
    },
}

pub(crate) fn private_oram_owner_checkpoint_table_genesis_v1(
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_key_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    activation_applied: PrivateOramRaftApplyLocatorV2,
    capability_epoch: u64,
    protocol_capability_digest: String,
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    let mut table = PrivateOramOwnerCheckpointTableV1 {
        version: TABLE_VERSION,
        consensus_history_id_digest,
        raft_group_id_digest,
        collection_key_digest,
        collection_lifetime_id_digest,
        collection_incarnation_digest,
        activation_anchor_digest,
        activation_applied,
        capability_epoch,
        protocol_capability_digest,
        roster_membership_epoch: None,
        owner_roster_digest: String::new(),
        table_sequence: 0,
        pending_enrollments: Vec::new(),
        checkpoints: Vec::new(),
        active_leases: Vec::new(),
        repair_pending_owner_enrollment_ids: Vec::new(),
        table_digest: String::new(),
    };
    table.owner_roster_digest = owner_roster_digest_v1(&table)?;
    table.table_digest = checkpoint_table_digest_v1(&table)?;
    validate_private_oram_owner_checkpoint_table_v1(&table)?;
    Ok(table)
}

pub(crate) fn prepare_private_oram_owner_enrollment_transition_v1(
    current: &PrivateOramOwnerCheckpointTableV1,
    prepared: PrivateOramOwnerEnrollmentPreparedV1,
    applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(current)?;
    validate_private_oram_owner_enrollment_prepared_v1(&prepared)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_enrollment"))?;
    validate_apply_locator_v2(&applied)?;
    if current
        .roster_membership_epoch
        .is_some_and(|epoch| epoch != prepared.membership_epoch)
        || !current.active_leases.is_empty()
        || !current.repair_pending_owner_enrollment_ids.is_empty()
        || current.pending_enrollments.iter().any(|pending| {
            pending.prepared.owner_enrollment_id == prepared.owner_enrollment_id
                || pending.prepared.owner_peer_id == prepared.owner_peer_id
                || pending.prepared.owner_store_incarnation_digest
                    == prepared.owner_store_incarnation_digest
        })
        || current.checkpoints.iter().any(|checkpoint| {
            checkpoint.owner_enrollment_id == prepared.owner_enrollment_id
                || checkpoint.owner_peer_id == prepared.owner_peer_id
                || checkpoint.owner_store_incarnation_digest
                    == prepared.owner_store_incarnation_digest
        })
        || current.pending_enrollments.len() + current.checkpoints.len() >= MAX_OWNERS
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut next = current.clone();
    if next.roster_membership_epoch.is_none() {
        next.roster_membership_epoch = Some(prepared.membership_epoch);
    }
    validate_scope_for_prepared(&next, &prepared, &applied)?;
    let mut pending = PrivateOramOwnerPendingEnrollmentV1 {
        version: PENDING_ENROLLMENT_VERSION,
        prepared,
        prepared_applied: applied,
        pending_digest: String::new(),
    };
    pending.pending_digest = pending_enrollment_digest_v1(&pending)?;
    validate_pending_enrollment_v1(&pending, &next)?;
    next.pending_enrollments.push(pending);
    next.pending_enrollments.sort_by(|left, right| {
        left.prepared
            .owner_enrollment_id
            .cmp(&right.prepared.owner_enrollment_id)
    });
    advance_table_sequence(&mut next)?;
    Ok(next)
}

pub(crate) fn activate_private_oram_owner_enrollment_transition_v1(
    current: &PrivateOramOwnerCheckpointTableV1,
    commitment: &PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(current)?;
    validate_apply_locator_v2(&applied)?;
    let pending_index = current
        .pending_enrollments
        .iter()
        .position(|pending| {
            pending.prepared.prepared_record_digest == commitment.prepared_record_digest
        })
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    let pending = &current.pending_enrollments[pending_index];
    if !locator_is_strictly_after(&applied, &pending.prepared_applied) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let verified =
        validate_private_oram_owner_enrollment_genesis_commitment_v1(commitment, &pending.prepared)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let commitment = verified.commitment();
    let mut checkpoint = PrivateOramOwnerCheckpointRecordV1 {
        version: CHECKPOINT_RECORD_VERSION,
        consensus_history_id_digest: current.consensus_history_id_digest.clone(),
        raft_group_id_digest: current.raft_group_id_digest.clone(),
        collection_key_digest: current.collection_key_digest.clone(),
        collection_lifetime_id_digest: current.collection_lifetime_id_digest.clone(),
        collection_incarnation_digest: current.collection_incarnation_digest.clone(),
        activation_anchor_digest: current.activation_anchor_digest.clone(),
        capability_epoch: current.capability_epoch,
        protocol_capability_digest: current.protocol_capability_digest.clone(),
        membership_epoch: pending.prepared.membership_epoch,
        owner_enrollment_id: commitment.owner_enrollment_id.clone(),
        owner_peer_id: commitment.owner_peer_id,
        owner_signer: commitment.owner_signer.clone(),
        owner_store_incarnation_digest: commitment.owner_store_incarnation_digest.clone(),
        checkpoint_sequence: 1,
        lifecycle_state: commitment.lifecycle_state.clone(),
        source_kind: PrivateOramOwnerCheckpointSourceKindV1::EnrollmentGenesis,
        source_record_digest: commitment.commitment_digest.clone(),
        source_applied: applied,
        authority_registry_digest: pending.prepared.authority_registry_digest.clone(),
        owner_registry_digest: pending.prepared.owner_registry_digest.clone(),
        checkpoint_record_digest: String::new(),
    };
    checkpoint.checkpoint_record_digest = checkpoint_record_digest_v1(&checkpoint)?;
    validate_checkpoint_record_v1(&checkpoint, current)?;
    let mut next = current.clone();
    next.pending_enrollments.remove(pending_index);
    next.checkpoints.push(checkpoint);
    next.checkpoints
        .sort_by(|left, right| left.owner_enrollment_id.cmp(&right.owner_enrollment_id));
    advance_table_sequence(&mut next)?;
    Ok(next)
}

/// The next owner enrollment step for a collection whose owner roster is `owner_peer_ids`
/// (docs/private-oram-v2-enrollment.md): owners enroll one at a time, in peer id order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum PrivateOramOwnerEnrollmentNextStepV1 {
    /// Every roster owner holds an enrollment checkpoint.
    Complete,
    /// The owner has neither a pending enrollment nor a checkpoint.
    Prepare { owner_peer_id: u64 },
    /// The owner's prepared enrollment is committed and awaits its genesis commitment.
    Activate {
        prepared: Box<PrivateOramOwnerEnrollmentPreparedV1>,
    },
}

pub(crate) fn private_oram_owner_enrollment_next_step_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
    owner_peer_ids: &[u64],
) -> Result<PrivateOramOwnerEnrollmentNextStepV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(table)?;
    let roster = owner_peer_ids.iter().copied().collect::<BTreeSet<_>>();
    if roster.is_empty()
        || roster.len() != owner_peer_ids.len()
        || table
            .pending_enrollments
            .iter()
            .any(|pending| !roster.contains(&pending.prepared.owner_peer_id))
        || table
            .checkpoints
            .iter()
            .any(|checkpoint| !roster.contains(&checkpoint.owner_peer_id))
        || !table.active_leases.is_empty()
        || !table.repair_pending_owner_enrollment_ids.is_empty()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if let Some(pending) = table.pending_enrollments.first() {
        return Ok(PrivateOramOwnerEnrollmentNextStepV1::Activate {
            prepared: Box::new(pending.prepared.clone()),
        });
    }
    Ok(roster
        .into_iter()
        .find(|owner_peer_id| {
            !table
                .checkpoints
                .iter()
                .any(|checkpoint| checkpoint.owner_peer_id == *owner_peer_id)
        })
        .map_or(
            PrivateOramOwnerEnrollmentNextStepV1::Complete,
            |owner_peer_id| PrivateOramOwnerEnrollmentNextStepV1::Prepare { owner_peer_id },
        ))
}

/// The prepared enrollment of one owner, scoped to the table's activation. `membership_epoch`
/// is used only while the table has no roster epoch yet.
#[allow(clippy::too_many_arguments)]
pub(crate) fn private_oram_owner_enrollment_prepared_for_table_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
    collection_id: &str,
    membership_epoch: u64,
    owner_peer_id: u64,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
    owner_store_incarnation_digest: String,
    owner_enrollment_id: String,
    enrollment_operation_id: String,
    authority_registry_digest: String,
    owner_registry_digest: String,
) -> Result<PrivateOramOwnerEnrollmentPreparedV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(table)?;
    if private_oram_collection_id_digest_v2(collection_id)? != table.collection_key_digest {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "collection_id",
        ));
    }
    let expected_genesis_state =
        private_oram_owner_lifecycle_genesis_state_v1(owner_store_incarnation_digest.clone())
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_store"))?;
    prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
        version: PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1,
        consensus_history_id_digest: table.consensus_history_id_digest.clone(),
        raft_group_id_digest: table.raft_group_id_digest.clone(),
        collection_id: collection_id.to_string(),
        collection_lifetime_id_digest: table.collection_lifetime_id_digest.clone(),
        collection_incarnation_digest: table.collection_incarnation_digest.clone(),
        activation_anchor_digest: table.activation_anchor_digest.clone(),
        capability_epoch: table.capability_epoch,
        protocol_capability_digest: table.protocol_capability_digest.clone(),
        membership_epoch: table.roster_membership_epoch.unwrap_or(membership_epoch),
        owner_enrollment_id,
        owner_peer_id,
        owner_signer,
        owner_store_incarnation_digest,
        expected_genesis_state,
        authority_registry_digest,
        owner_registry_digest,
        enrollment_operation_id,
        prepared_record_digest: String::new(),
    })
    .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_enrollment"))
}

pub(crate) fn private_oram_owner_checkpoint_reservation_context_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
    reservation_intent_digest: String,
) -> Result<PrivateOramOwnerCheckpointReservationContextV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(table)?;
    validate_digest(&reservation_intent_digest)?;
    let membership_epoch = table
        .roster_membership_epoch
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if table.checkpoints.is_empty()
        || !table.pending_enrollments.is_empty()
        || !table.active_leases.is_empty()
        || !table.repair_pending_owner_enrollment_ids.is_empty()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut canonical_checkpoints = table.checkpoints.iter().collect::<Vec<_>>();
    canonical_checkpoints.sort_by_key(|checkpoint| checkpoint.owner_peer_id);
    let mut owner_expectations = Vec::with_capacity(canonical_checkpoints.len());
    for (position, checkpoint) in canonical_checkpoints.into_iter().enumerate() {
        let mut expectation = PrivateOramOwnerCheckpointReservationExpectationV1 {
            version: RESERVATION_EXPECTATION_VERSION,
            owner_index: u32::try_from(position)
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
            owner_enrollment_id: checkpoint.owner_enrollment_id.clone(),
            owner_peer_id: checkpoint.owner_peer_id,
            owner_signer: checkpoint.owner_signer.clone(),
            owner_store_incarnation_digest: checkpoint.owner_store_incarnation_digest.clone(),
            membership_epoch: checkpoint.membership_epoch,
            expected_checkpoint_sequence: checkpoint.checkpoint_sequence,
            expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest.clone(),
            expected_lifecycle_state: checkpoint.lifecycle_state.clone(),
            authority_registry_digest: checkpoint.authority_registry_digest.clone(),
            owner_registry_digest: checkpoint.owner_registry_digest.clone(),
            expectation_digest: String::new(),
        };
        expectation.expectation_digest = reservation_expectation_digest_v1(&expectation)?;
        validate_reservation_expectation_v1(&expectation)?;
        owner_expectations.push(expectation);
    }
    let mut context = PrivateOramOwnerCheckpointReservationContextV1 {
        version: RESERVATION_CONTEXT_VERSION,
        reservation_intent_digest,
        consensus_history_id_digest: table.consensus_history_id_digest.clone(),
        raft_group_id_digest: table.raft_group_id_digest.clone(),
        collection_key_digest: table.collection_key_digest.clone(),
        collection_lifetime_id_digest: table.collection_lifetime_id_digest.clone(),
        collection_incarnation_digest: table.collection_incarnation_digest.clone(),
        activation_anchor_digest: table.activation_anchor_digest.clone(),
        capability_epoch: table.capability_epoch,
        protocol_capability_digest: table.protocol_capability_digest.clone(),
        membership_epoch,
        checkpoint_table_sequence: table.table_sequence,
        checkpoint_table_digest: table.table_digest.clone(),
        owner_checkpoint_roster_digest: table.owner_roster_digest.clone(),
        owner_expectations,
        context_digest: String::new(),
    };
    context.context_digest = reservation_context_digest_v1(&context)?;
    validate_private_oram_owner_checkpoint_reservation_context_v1(&context)?;
    Ok(context)
}

pub(crate) fn private_oram_owner_checkpoint_reservation_binding_v1(
    owner_index: u32,
    checkpoint: &PrivateOramOwnerCheckpointRecordV1,
    reservation_prepare: PrivateOramOwnerReservationPrepareV1,
) -> Result<PrivateOramOwnerCheckpointReservationBindingV1, PrivateOramMutationJournalError> {
    let _verified_prepare = validate_private_oram_owner_reservation_prepare_v1(
        &reservation_prepare,
        &reservation_prepare.challenge,
        &checkpoint.owner_signer,
        &checkpoint.lifecycle_state,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_reservation_prepare"))?;
    let mut binding = PrivateOramOwnerCheckpointReservationBindingV1 {
        version: RESERVATION_BINDING_VERSION,
        owner_index,
        owner_enrollment_id: checkpoint.owner_enrollment_id.clone(),
        expected_checkpoint_sequence: checkpoint.checkpoint_sequence,
        expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest.clone(),
        expected_lifecycle_state: checkpoint.lifecycle_state.clone(),
        reservation_prepare,
        binding_digest: String::new(),
    };
    binding.binding_digest = reservation_binding_digest_v1(&binding)?;
    Ok(binding)
}

pub(crate) fn lease_private_oram_owner_checkpoints_for_reservation_v1(
    current: &PrivateOramOwnerCheckpointTableV1,
    attempt_id: &str,
    attempt_context_digest: &str,
    reservation_digest: &str,
    bindings: &[PrivateOramOwnerCheckpointReservationBindingV1],
    applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(current)?;
    validate_digest(attempt_id)?;
    validate_digest(attempt_context_digest)?;
    validate_digest(reservation_digest)?;
    validate_apply_locator_v2(&applied)?;
    if bindings.is_empty()
        || bindings.len() > MAX_OWNERS
        || bindings.len() != current.checkpoints.len()
        || !current.pending_enrollments.is_empty()
        || !current.active_leases.is_empty()
        || !current.repair_pending_owner_enrollment_ids.is_empty()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut leases = Vec::with_capacity(bindings.len());
    let mut seen_enrollments = BTreeSet::new();
    let mut canonical_checkpoints = current.checkpoints.iter().collect::<Vec<_>>();
    canonical_checkpoints.sort_by_key(|checkpoint| checkpoint.owner_peer_id);
    for (position, binding) in bindings.iter().enumerate() {
        let owner_index = u32::try_from(position)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
        validate_reservation_binding_v1(binding)?;
        if binding.owner_index != owner_index
            || binding.owner_enrollment_id != canonical_checkpoints[position].owner_enrollment_id
            || !seen_enrollments.insert(binding.owner_enrollment_id.clone())
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let checkpoint = find_checkpoint(current, &binding.owner_enrollment_id)?;
        if binding.expected_checkpoint_sequence != checkpoint.checkpoint_sequence
            || binding.expected_checkpoint_record_digest != checkpoint.checkpoint_record_digest
            || binding.expected_lifecycle_state != checkpoint.lifecycle_state
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_status_against_checkpoint(
            current,
            checkpoint,
            owner_index,
            attempt_id,
            attempt_context_digest,
            &binding.reservation_prepare,
        )?;
        let mut lease = PrivateOramOwnerCheckpointActiveLeaseV1 {
            version: ACTIVE_LEASE_VERSION,
            owner_index,
            owner_enrollment_id: binding.owner_enrollment_id.clone(),
            checkpoint_record_digest: checkpoint.checkpoint_record_digest.clone(),
            attempt_id: attempt_id.to_string(),
            attempt_context_digest: attempt_context_digest.to_string(),
            reservation_digest: reservation_digest.to_string(),
            reservation_applied: applied.clone(),
            lease_digest: String::new(),
        };
        lease.lease_digest = active_lease_digest_v1(&lease)?;
        validate_active_lease_v1(&lease, current)?;
        leases.push(lease);
    }
    let mut next = current.clone();
    next.active_leases = leases;
    advance_table_sequence(&mut next)?;
    Ok(next)
}

pub(crate) fn private_oram_owner_checkpoint_successor_v1(
    owner_index: u32,
    checkpoint: &PrivateOramOwnerCheckpointRecordV1,
    new_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    terminal_state: PrivateOramOwnerCleanupTerminalStateV1,
    terminal_marker_digest: String,
    intent_identity_digest: String,
    cleanup_operation_id: String,
    grant_digest: String,
    committed_terminal_evidence_digest: String,
) -> Result<PrivateOramOwnerCheckpointSuccessorV1, PrivateOramMutationJournalError> {
    let mut successor = PrivateOramOwnerCheckpointSuccessorV1 {
        version: SUCCESSOR_VERSION,
        owner_index,
        owner_enrollment_id: checkpoint.owner_enrollment_id.clone(),
        previous_checkpoint_sequence: checkpoint.checkpoint_sequence,
        previous_checkpoint_record_digest: checkpoint.checkpoint_record_digest.clone(),
        previous_lifecycle_state: checkpoint.lifecycle_state.clone(),
        new_lifecycle_state,
        terminal_state,
        terminal_marker_digest,
        intent_identity_digest,
        cleanup_operation_id,
        grant_digest,
        committed_terminal_evidence_digest,
        successor_digest: String::new(),
    };
    successor.successor_digest = checkpoint_successor_digest_v1(&successor)?;
    validate_checkpoint_successor_v1(&successor)?;
    Ok(successor)
}

pub(crate) fn acknowledge_private_oram_owner_negative_settlement_v1(
    current: &PrivateOramOwnerCheckpointTableV1,
    attempt_id: &str,
    reservation_digest: &str,
    certificate_digest: &str,
    settlements: &[PrivateOramOwnerNegativeSettlementV1],
    applied: PrivateOramRaftApplyLocatorV2,
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(current)?;
    validate_digest(attempt_id)?;
    validate_digest(reservation_digest)?;
    validate_digest(certificate_digest)?;
    validate_apply_locator_v2(&applied)?;
    if settlements.len() != current.active_leases.len() || settlements.is_empty() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut updates = BTreeMap::new();
    let mut repair_pending = BTreeSet::new();
    for (position, (settlement, lease)) in
        settlements.iter().zip(&current.active_leases).enumerate()
    {
        let owner_index = u32::try_from(position)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
        if lease.owner_index != owner_index
            || lease.attempt_id != attempt_id
            || lease.reservation_digest != reservation_digest
            || !locator_is_strictly_after(&applied, &lease.reservation_applied)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let checkpoint = find_checkpoint(current, &lease.owner_enrollment_id)?;
        if checkpoint.checkpoint_record_digest != lease.checkpoint_record_digest {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        match settlement {
            PrivateOramOwnerNegativeSettlementV1::CleanupTerminalCommitted(successor) => {
                validate_checkpoint_successor_v1(successor)?;
                if successor.owner_index != owner_index
                    || successor.owner_enrollment_id != lease.owner_enrollment_id
                    || successor.previous_checkpoint_sequence != checkpoint.checkpoint_sequence
                    || successor.previous_checkpoint_record_digest
                        != checkpoint.checkpoint_record_digest
                    || successor.previous_lifecycle_state != checkpoint.lifecycle_state
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                let mut next_checkpoint = checkpoint.clone();
                next_checkpoint.checkpoint_sequence = checkpoint
                    .checkpoint_sequence
                    .checked_add(1)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
                next_checkpoint.lifecycle_state = successor.new_lifecycle_state.clone();
                next_checkpoint.source_kind =
                    PrivateOramOwnerCheckpointSourceKindV1::NegativeCleanupAcknowledgement;
                next_checkpoint.source_record_digest = certificate_digest.to_string();
                next_checkpoint.source_applied = applied.clone();
                next_checkpoint.checkpoint_record_digest.clear();
                next_checkpoint.checkpoint_record_digest =
                    checkpoint_record_digest_v1(&next_checkpoint)?;
                validate_checkpoint_record_v1(&next_checkpoint, current)?;
                updates.insert(lease.owner_enrollment_id.clone(), next_checkpoint);
                repair_pending.insert(lease.owner_enrollment_id.clone());
            }
            PrivateOramOwnerNegativeSettlementV1::NoPrestageWrite {
                owner_index: settlement_index,
                owner_enrollment_id,
                disposition_digest,
            } => {
                validate_digest(disposition_digest)?;
                if *settlement_index != owner_index
                    || owner_enrollment_id != &lease.owner_enrollment_id
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
            }
            PrivateOramOwnerNegativeSettlementV1::ReservationCompletionCommitted {
                owner_index: settlement_index,
                owner_enrollment_id,
                completion_receipt_digest,
            } => {
                validate_digest(completion_receipt_digest)?;
                if *settlement_index != owner_index
                    || owner_enrollment_id != &lease.owner_enrollment_id
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
            }
        }
    }
    let mut next = current.clone();
    for checkpoint in &mut next.checkpoints {
        if let Some(replacement) = updates.remove(&checkpoint.owner_enrollment_id) {
            *checkpoint = replacement;
        }
    }
    if !updates.is_empty() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    next.active_leases.clear();
    next.repair_pending_owner_enrollment_ids = repair_pending.into_iter().collect();
    advance_table_sequence(&mut next)?;
    Ok(next)
}

pub(crate) fn complete_private_oram_owner_checkpoint_repairs_v1(
    current: &PrivateOramOwnerCheckpointTableV1,
    repair_operation_id: &str,
    repair_context_digest: &str,
    attestations: &[PrivateOramOwnerLifecycleStatusAttestationV1],
) -> Result<PrivateOramOwnerCheckpointTableV1, PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(current)?;
    validate_digest(repair_operation_id)?;
    validate_digest(repair_context_digest)?;
    if current.repair_pending_owner_enrollment_ids.is_empty()
        || attestations.len() != current.repair_pending_owner_enrollment_ids.len()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (enrollment_id, attestation) in current
        .repair_pending_owner_enrollment_ids
        .iter()
        .zip(attestations)
    {
        let checkpoint = find_checkpoint(current, enrollment_id)?;
        let challenge = &attestation.challenge;
        if challenge.owner_enrollment_id != *enrollment_id
            || private_oram_collection_id_digest_v2(&challenge.collection_id)?
                != current.collection_key_digest
            || challenge.attempt_id != repair_operation_id
            || challenge.attempt_context_digest != repair_context_digest
            || challenge.consensus_history_id_digest != current.consensus_history_id_digest
            || challenge.raft_group_id_digest != current.raft_group_id_digest
            || challenge.collection_lifetime_id_digest != current.collection_lifetime_id_digest
            || challenge.collection_incarnation_digest != current.collection_incarnation_digest
            || challenge.activation_anchor_digest != current.activation_anchor_digest
            || challenge.capability_epoch != current.capability_epoch
            || challenge.protocol_capability_digest != current.protocol_capability_digest
            || challenge.expected_checkpoint_sequence != checkpoint.checkpoint_sequence
            || challenge.expected_checkpoint_record_digest != checkpoint.checkpoint_record_digest
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let _verified_status = validate_private_oram_owner_lifecycle_status_attestation_v1(
            attestation,
            challenge,
            &checkpoint.owner_signer,
            &checkpoint.lifecycle_state,
        )
        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    }
    let mut next = current.clone();
    next.repair_pending_owner_enrollment_ids.clear();
    advance_table_sequence(&mut next)?;
    Ok(next)
}

pub(crate) fn validate_private_oram_owner_checkpoint_table_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if table.version != TABLE_VERSION
        || table.capability_epoch == 0
        || table.roster_membership_epoch == Some(0)
        || (table.roster_membership_epoch.is_none()
            != (table.pending_enrollments.is_empty() && table.checkpoints.is_empty()))
        || table.pending_enrollments.len() > MAX_OWNERS
        || table.checkpoints.len() > MAX_OWNERS
        || table.active_leases.len() > MAX_OWNERS
        || table.repair_pending_owner_enrollment_ids.len() > MAX_OWNERS
        || table.pending_enrollments.len() + table.checkpoints.len() > MAX_OWNERS
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &table.consensus_history_id_digest,
        &table.raft_group_id_digest,
        &table.collection_key_digest,
        &table.collection_lifetime_id_digest,
        &table.collection_incarnation_digest,
        &table.activation_anchor_digest,
        &table.protocol_capability_digest,
        &table.owner_roster_digest,
        &table.table_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_apply_locator_v2(&table.activation_applied)?;
    if table.activation_applied.consensus_history_id_digest != table.consensus_history_id_digest
        || table.activation_applied.raft_group_id_digest != table.raft_group_id_digest
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    require_sorted_unique(
        table
            .pending_enrollments
            .iter()
            .map(|pending| pending.prepared.owner_enrollment_id.as_str()),
    )?;
    require_sorted_unique(
        table
            .checkpoints
            .iter()
            .map(|checkpoint| checkpoint.owner_enrollment_id.as_str()),
    )?;
    require_sorted_unique(
        table
            .repair_pending_owner_enrollment_ids
            .iter()
            .map(String::as_str),
    )?;
    let mut peer_ids = BTreeSet::new();
    let mut enrollment_ids = BTreeSet::new();
    let mut incarnations = BTreeSet::new();
    for pending in &table.pending_enrollments {
        validate_pending_enrollment_v1(pending, table)?;
        if !enrollment_ids.insert(pending.prepared.owner_enrollment_id.as_str())
            || !peer_ids.insert(pending.prepared.owner_peer_id)
            || !incarnations.insert(pending.prepared.owner_store_incarnation_digest.as_str())
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    for checkpoint in &table.checkpoints {
        validate_checkpoint_record_v1(checkpoint, table)?;
        if !enrollment_ids.insert(checkpoint.owner_enrollment_id.as_str())
            || !peer_ids.insert(checkpoint.owner_peer_id)
            || !incarnations.insert(checkpoint.owner_store_incarnation_digest.as_str())
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    let mut leased_enrollments = BTreeSet::new();
    for (position, lease) in table.active_leases.iter().enumerate() {
        validate_active_lease_v1(lease, table)?;
        if lease.owner_index
            != u32::try_from(position).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            || !leased_enrollments.insert(lease.owner_enrollment_id.as_str())
            || table.active_leases.first().is_some_and(|first| {
                first.attempt_id != lease.attempt_id
                    || first.attempt_context_digest != lease.attempt_context_digest
                    || first.reservation_digest != lease.reservation_digest
                    || first.reservation_applied != lease.reservation_applied
            })
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    for enrollment_id in &table.repair_pending_owner_enrollment_ids {
        validate_digest(enrollment_id)?;
        find_checkpoint(table, enrollment_id)?;
    }
    if (!table.pending_enrollments.is_empty()
        && (!table.active_leases.is_empty()
            || !table.repair_pending_owner_enrollment_ids.is_empty()))
        || (!table.active_leases.is_empty()
            && !table.repair_pending_owner_enrollment_ids.is_empty())
        || table.owner_roster_digest != owner_roster_digest_v1(table)?
        || table.table_digest != checkpoint_table_digest_v1(table)?
        || serde_json::to_vec(table)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .len()
            > MAX_CHECKPOINT_TABLE_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_private_oram_owner_checkpoint_table_scope_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
    consensus_history_id_digest: &str,
    raft_group_id_digest: &str,
    collection_key_digest: &str,
    collection_lifetime_id_digest: &str,
    collection_incarnation_digest: &str,
    activation_anchor_digest: &str,
    activation_applied: &PrivateOramRaftApplyLocatorV2,
    capability_epoch: u64,
    protocol_capability_digest: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(table)?;
    if table.consensus_history_id_digest != consensus_history_id_digest
        || table.raft_group_id_digest != raft_group_id_digest
        || table.collection_key_digest != collection_key_digest
        || table.collection_lifetime_id_digest != collection_lifetime_id_digest
        || table.collection_incarnation_digest != collection_incarnation_digest
        || table.activation_anchor_digest != activation_anchor_digest
        || &table.activation_applied != activation_applied
        || table.capability_epoch != capability_epoch
        || table.protocol_capability_digest != protocol_capability_digest
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_scope_for_prepared(
    table: &PrivateOramOwnerCheckpointTableV1,
    prepared: &PrivateOramOwnerEnrollmentPreparedV1,
    applied: &PrivateOramRaftApplyLocatorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if prepared.consensus_history_id_digest != table.consensus_history_id_digest
        || prepared.raft_group_id_digest != table.raft_group_id_digest
        || private_oram_collection_id_digest_v2(&prepared.collection_id)?
            != table.collection_key_digest
        || prepared.collection_lifetime_id_digest != table.collection_lifetime_id_digest
        || prepared.collection_incarnation_digest != table.collection_incarnation_digest
        || prepared.activation_anchor_digest != table.activation_anchor_digest
        || prepared.capability_epoch != table.capability_epoch
        || prepared.protocol_capability_digest != table.protocol_capability_digest
        || Some(prepared.membership_epoch) != table.roster_membership_epoch
        || applied.consensus_history_id_digest != table.consensus_history_id_digest
        || applied.raft_group_id_digest != table.raft_group_id_digest
        || !locator_is_strictly_after(applied, &table.activation_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_pending_enrollment_v1(
    pending: &PrivateOramOwnerPendingEnrollmentV1,
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if pending.version != PENDING_ENROLLMENT_VERSION {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_private_oram_owner_enrollment_prepared_v1(&pending.prepared)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_apply_locator_v2(&pending.prepared_applied)?;
    validate_scope_for_prepared(table, &pending.prepared, &pending.prepared_applied)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_digest(&pending.pending_digest)?;
    if pending.pending_digest != pending_enrollment_digest_v1(pending)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_checkpoint_record_v1(
    checkpoint: &PrivateOramOwnerCheckpointRecordV1,
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if checkpoint.version != CHECKPOINT_RECORD_VERSION
        || checkpoint.owner_peer_id == 0
        || checkpoint.membership_epoch == 0
        || checkpoint.checkpoint_sequence == 0
        || checkpoint.owner_store_incarnation_digest
            != checkpoint.lifecycle_state.owner_store_incarnation_digest
        || checkpoint.consensus_history_id_digest != table.consensus_history_id_digest
        || checkpoint.raft_group_id_digest != table.raft_group_id_digest
        || checkpoint.collection_key_digest != table.collection_key_digest
        || checkpoint.collection_lifetime_id_digest != table.collection_lifetime_id_digest
        || checkpoint.collection_incarnation_digest != table.collection_incarnation_digest
        || checkpoint.activation_anchor_digest != table.activation_anchor_digest
        || checkpoint.capability_epoch != table.capability_epoch
        || checkpoint.protocol_capability_digest != table.protocol_capability_digest
        || Some(checkpoint.membership_epoch) != table.roster_membership_epoch
        || checkpoint.source_applied.consensus_history_id_digest
            != table.consensus_history_id_digest
        || checkpoint.source_applied.raft_group_id_digest != table.raft_group_id_digest
        || !locator_is_strictly_after(&checkpoint.source_applied, &table.activation_applied)
        || (checkpoint.checkpoint_sequence == 1
            && checkpoint.source_kind != PrivateOramOwnerCheckpointSourceKindV1::EnrollmentGenesis)
        || (checkpoint.checkpoint_sequence > 1
            && checkpoint.source_kind
                != PrivateOramOwnerCheckpointSourceKindV1::NegativeCleanupAcknowledgement)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &checkpoint.owner_enrollment_id,
        &checkpoint.owner_store_incarnation_digest,
        &checkpoint.source_record_digest,
        &checkpoint.authority_registry_digest,
        &checkpoint.owner_registry_digest,
        &checkpoint.checkpoint_record_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_apply_locator_v2(&checkpoint.source_applied)?;
    validate_private_oram_owner_lifecycle_signer_v1(&checkpoint.owner_signer)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_private_oram_owner_lifecycle_state_v1(&checkpoint.lifecycle_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if checkpoint.checkpoint_record_digest != checkpoint_record_digest_v1(checkpoint)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_reservation_expectation_v1(
    expectation: &PrivateOramOwnerCheckpointReservationExpectationV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if expectation.version != RESERVATION_EXPECTATION_VERSION
        || expectation.owner_peer_id == 0
        || expectation.membership_epoch == 0
        || expectation.expected_checkpoint_sequence == 0
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &expectation.owner_enrollment_id,
        &expectation.owner_store_incarnation_digest,
        &expectation.expected_checkpoint_record_digest,
        &expectation.authority_registry_digest,
        &expectation.owner_registry_digest,
        &expectation.expectation_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_private_oram_owner_lifecycle_signer_v1(&expectation.owner_signer)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_private_oram_owner_lifecycle_state_v1(&expectation.expected_lifecycle_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if expectation
        .expected_lifecycle_state
        .owner_store_incarnation_digest
        != expectation.owner_store_incarnation_digest
        || expectation.expectation_digest != reservation_expectation_digest_v1(expectation)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(crate) fn validate_private_oram_owner_checkpoint_reservation_context_v1(
    context: &PrivateOramOwnerCheckpointReservationContextV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if context.version != RESERVATION_CONTEXT_VERSION
        || context.capability_epoch == 0
        || context.membership_epoch == 0
        || context.checkpoint_table_sequence == 0
        || context.owner_expectations.is_empty()
        || context.owner_expectations.len() > MAX_OWNERS
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &context.reservation_intent_digest,
        &context.consensus_history_id_digest,
        &context.raft_group_id_digest,
        &context.collection_key_digest,
        &context.collection_lifetime_id_digest,
        &context.collection_incarnation_digest,
        &context.activation_anchor_digest,
        &context.protocol_capability_digest,
        &context.checkpoint_table_digest,
        &context.owner_checkpoint_roster_digest,
        &context.context_digest,
    ] {
        validate_digest(digest)?;
    }
    let mut enrollment_ids = BTreeSet::new();
    let mut peer_ids = BTreeSet::new();
    for (position, expectation) in context.owner_expectations.iter().enumerate() {
        validate_reservation_expectation_v1(expectation)?;
        if expectation.owner_index
            != u32::try_from(position).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            || expectation.membership_epoch != context.membership_epoch
            || !enrollment_ids.insert(expectation.owner_enrollment_id.as_str())
            || !peer_ids.insert(expectation.owner_peer_id)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if context.context_digest != reservation_context_digest_v1(context)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(crate) fn validate_private_oram_owner_checkpoint_reservation_context_for_table_v1(
    context: &PrivateOramOwnerCheckpointReservationContextV1,
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_reservation_context_v1(context)?;
    let expected = private_oram_owner_checkpoint_reservation_context_v1(
        table,
        context.reservation_intent_digest.clone(),
    )?;
    if &expected != context {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

pub(crate) fn validate_private_oram_owner_checkpoint_active_reservation_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
    context: &PrivateOramOwnerCheckpointReservationContextV1,
    attempt_id: &str,
    reservation_digest: &str,
    reservation_applied: &PrivateOramRaftApplyLocatorV2,
    bindings: &[PrivateOramOwnerCheckpointReservationBindingV1],
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_table_v1(table)?;
    validate_digest(attempt_id)?;
    validate_digest(reservation_digest)?;
    validate_apply_locator_v2(reservation_applied)?;
    if table.table_sequence
        != context
            .checkpoint_table_sequence
            .checked_add(1)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?
        || table.active_leases.len() != bindings.len()
        || table.active_leases.is_empty()
        || !table.pending_enrollments.is_empty()
        || !table.repair_pending_owner_enrollment_ids.is_empty()
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut predecessor = table.clone();
    predecessor.active_leases.clear();
    predecessor.table_sequence = context.checkpoint_table_sequence;
    predecessor.owner_roster_digest = owner_roster_digest_v1(&predecessor)?;
    predecessor.table_digest = checkpoint_table_digest_v1(&predecessor)?;
    validate_private_oram_owner_checkpoint_reservation_context_for_table_v1(context, &predecessor)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    for (position, (lease, binding)) in table.active_leases.iter().zip(bindings).enumerate() {
        if lease.owner_index
            != u32::try_from(position).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            || lease.owner_enrollment_id != binding.owner_enrollment_id
            || lease.checkpoint_record_digest != binding.expected_checkpoint_record_digest
            || lease.attempt_id != attempt_id
            || lease.attempt_context_digest != context.context_digest
            || lease.reservation_digest != reservation_digest
            || &lease.reservation_applied != reservation_applied
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(crate) fn validate_private_oram_owner_checkpoint_binding_context_v1(
    context: &PrivateOramOwnerCheckpointReservationContextV1,
    binding: &PrivateOramOwnerCheckpointReservationBindingV1,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_owner_checkpoint_reservation_context_v1(context)?;
    validate_reservation_binding_v1(binding)?;
    let expectation = context
        .owner_expectations
        .get(
            usize::try_from(binding.owner_index)
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
        )
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if binding.owner_enrollment_id != expectation.owner_enrollment_id
        || binding.expected_checkpoint_sequence != expectation.expected_checkpoint_sequence
        || binding.expected_checkpoint_record_digest
            != expectation.expected_checkpoint_record_digest
        || binding.expected_lifecycle_state != expectation.expected_lifecycle_state
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let challenge = &binding.reservation_prepare.challenge;
    if challenge.consensus_history_id_digest != context.consensus_history_id_digest
        || challenge.raft_group_id_digest != context.raft_group_id_digest
        || private_oram_collection_id_digest_v2(&challenge.collection_id)?
            != context.collection_key_digest
        || challenge.collection_lifetime_id_digest != context.collection_lifetime_id_digest
        || challenge.collection_incarnation_digest != context.collection_incarnation_digest
        || challenge.activation_anchor_digest != context.activation_anchor_digest
        || challenge.capability_epoch != context.capability_epoch
        || challenge.protocol_capability_digest != context.protocol_capability_digest
        || challenge.membership_epoch != context.membership_epoch
        || challenge.reservation_intent_digest != context.reservation_intent_digest
        || challenge.checkpoint_context_digest != context.context_digest
        || usize::try_from(challenge.owner_count).ok() != Some(context.owner_expectations.len())
        || challenge.expected_checkpoint_record_digest
            != expectation.expected_checkpoint_record_digest
        || challenge.expected_checkpoint_sequence != expectation.expected_checkpoint_sequence
        || challenge.owner_index != expectation.owner_index
        || challenge.owner_enrollment_id != expectation.owner_enrollment_id
        || challenge.owner_peer_id != expectation.owner_peer_id
        || challenge.owner_store_incarnation_digest != expectation.owner_store_incarnation_digest
        || challenge.authority_registry_digest != expectation.authority_registry_digest
        || challenge.owner_registry_digest != expectation.owner_registry_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let _verified_prepare = validate_private_oram_owner_reservation_prepare_v1(
        &binding.reservation_prepare,
        challenge,
        &expectation.owner_signer,
        &expectation.expected_lifecycle_state,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    Ok(())
}

fn validate_reservation_binding_v1(
    binding: &PrivateOramOwnerCheckpointReservationBindingV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if binding.version != RESERVATION_BINDING_VERSION || binding.expected_checkpoint_sequence == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_digest(&binding.owner_enrollment_id)?;
    validate_digest(&binding.expected_checkpoint_record_digest)?;
    validate_digest(&binding.binding_digest)?;
    validate_private_oram_owner_lifecycle_state_v1(&binding.expected_lifecycle_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if binding.binding_digest != reservation_binding_digest_v1(binding)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_status_against_checkpoint(
    table: &PrivateOramOwnerCheckpointTableV1,
    checkpoint: &PrivateOramOwnerCheckpointRecordV1,
    owner_index: u32,
    attempt_id: &str,
    attempt_context_digest: &str,
    prepare: &PrivateOramOwnerReservationPrepareV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let challenge = &prepare.challenge;
    if challenge.consensus_history_id_digest != table.consensus_history_id_digest
        || challenge.raft_group_id_digest != table.raft_group_id_digest
        || private_oram_collection_id_digest_v2(&challenge.collection_id)?
            != table.collection_key_digest
        || challenge.collection_lifetime_id_digest != table.collection_lifetime_id_digest
        || challenge.collection_incarnation_digest != table.collection_incarnation_digest
        || challenge.activation_anchor_digest != table.activation_anchor_digest
        || challenge.capability_epoch != table.capability_epoch
        || challenge.protocol_capability_digest != table.protocol_capability_digest
        || challenge.membership_epoch != checkpoint.membership_epoch
        || challenge.attempt_id != attempt_id
        || challenge.checkpoint_context_digest != attempt_context_digest
        || usize::try_from(challenge.owner_count).ok() != Some(table.checkpoints.len())
        || challenge.expected_checkpoint_record_digest != checkpoint.checkpoint_record_digest
        || challenge.expected_checkpoint_sequence != checkpoint.checkpoint_sequence
        || challenge.owner_index != owner_index
        || challenge.owner_enrollment_id != checkpoint.owner_enrollment_id
        || challenge.owner_peer_id != checkpoint.owner_peer_id
        || challenge.owner_store_incarnation_digest != checkpoint.owner_store_incarnation_digest
        || challenge.authority_registry_digest != checkpoint.authority_registry_digest
        || challenge.owner_registry_digest != checkpoint.owner_registry_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let _verified_prepare = validate_private_oram_owner_reservation_prepare_v1(
        prepare,
        challenge,
        &checkpoint.owner_signer,
        &checkpoint.lifecycle_state,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    Ok(())
}

fn validate_active_lease_v1(
    lease: &PrivateOramOwnerCheckpointActiveLeaseV1,
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if lease.version != ACTIVE_LEASE_VERSION
        || lease.reservation_applied.consensus_history_id_digest
            != table.consensus_history_id_digest
        || lease.reservation_applied.raft_group_id_digest != table.raft_group_id_digest
        || !locator_is_strictly_after(&lease.reservation_applied, &table.activation_applied)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &lease.owner_enrollment_id,
        &lease.checkpoint_record_digest,
        &lease.attempt_id,
        &lease.attempt_context_digest,
        &lease.reservation_digest,
        &lease.lease_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_apply_locator_v2(&lease.reservation_applied)?;
    let checkpoint = find_checkpoint(table, &lease.owner_enrollment_id)?;
    if checkpoint.checkpoint_record_digest != lease.checkpoint_record_digest
        || lease.lease_digest != active_lease_digest_v1(lease)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_checkpoint_successor_v1(
    successor: &PrivateOramOwnerCheckpointSuccessorV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if successor.version != SUCCESSOR_VERSION
        || successor.previous_checkpoint_sequence == 0
        || successor.new_lifecycle_state.owner_store_incarnation_digest
            != successor
                .previous_lifecycle_state
                .owner_store_incarnation_digest
        || successor.new_lifecycle_state.generation
            != successor
                .previous_lifecycle_state
                .generation
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::Corrupt)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &successor.owner_enrollment_id,
        &successor.previous_checkpoint_record_digest,
        &successor.terminal_marker_digest,
        &successor.intent_identity_digest,
        &successor.cleanup_operation_id,
        &successor.grant_digest,
        &successor.committed_terminal_evidence_digest,
        &successor.successor_digest,
    ] {
        validate_digest(digest)?;
    }
    validate_private_oram_owner_lifecycle_state_v1(&successor.previous_lifecycle_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_private_oram_owner_lifecycle_state_v1(&successor.new_lifecycle_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let expected_root = private_oram_owner_lifecycle_state_root_v1(
        &successor.previous_lifecycle_state,
        successor.new_lifecycle_state.generation,
        &successor.terminal_marker_digest,
        &successor.intent_identity_digest,
        &successor.terminal_state,
    )
    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if successor.new_lifecycle_state.state_root != expected_root
        || successor.successor_digest != checkpoint_successor_digest_v1(successor)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn find_checkpoint<'a>(
    table: &'a PrivateOramOwnerCheckpointTableV1,
    owner_enrollment_id: &str,
) -> Result<&'a PrivateOramOwnerCheckpointRecordV1, PrivateOramMutationJournalError> {
    table
        .checkpoints
        .binary_search_by(|checkpoint| {
            checkpoint
                .owner_enrollment_id
                .as_str()
                .cmp(owner_enrollment_id)
        })
        .ok()
        .and_then(|index| table.checkpoints.get(index))
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)
}

fn advance_table_sequence(
    table: &mut PrivateOramOwnerCheckpointTableV1,
) -> Result<(), PrivateOramMutationJournalError> {
    table.table_sequence = table
        .table_sequence
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    table.owner_roster_digest = owner_roster_digest_v1(table)?;
    table.table_digest = checkpoint_table_digest_v1(table)?;
    validate_private_oram_owner_checkpoint_table_v1(table)
}

fn require_sorted_unique<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<(), PrivateOramMutationJournalError> {
    let mut previous: Option<&str> = None;
    for value in values {
        validate_digest(value)?;
        if previous.is_some_and(|previous| previous >= value) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous = Some(value);
    }
    Ok(())
}

fn pending_enrollment_digest_v1(
    pending: &PrivateOramOwnerPendingEnrollmentV1,
) -> Result<String, PrivateOramMutationJournalError> {
    digest_serialized(
        PENDING_ENROLLMENT_DIGEST_DOMAIN_V1,
        &(
            pending.version,
            &pending.prepared,
            &pending.prepared_applied,
        ),
    )
}

fn checkpoint_record_digest_v1(
    checkpoint: &PrivateOramOwnerCheckpointRecordV1,
) -> Result<String, PrivateOramMutationJournalError> {
    #[derive(Serialize)]
    struct Core<'a> {
        version: u16,
        consensus_history_id_digest: &'a str,
        raft_group_id_digest: &'a str,
        collection_lifetime_id_digest: &'a str,
        collection_key_digest: &'a str,
        collection_incarnation_digest: &'a str,
        activation_anchor_digest: &'a str,
        capability_epoch: u64,
        protocol_capability_digest: &'a str,
        membership_epoch: u64,
        owner_enrollment_id: &'a str,
        owner_peer_id: u64,
        owner_signer: &'a PrivateOramOwnerCleanupSignerV1,
        owner_store_incarnation_digest: &'a str,
        checkpoint_sequence: u64,
        lifecycle_state: &'a PrivateOramOwnerLifecycleStateV1,
        source_kind: PrivateOramOwnerCheckpointSourceKindV1,
        source_record_digest: &'a str,
        source_applied: &'a PrivateOramRaftApplyLocatorV2,
        authority_registry_digest: &'a str,
        owner_registry_digest: &'a str,
    }
    digest_serialized(
        CHECKPOINT_RECORD_DIGEST_DOMAIN_V1,
        &Core {
            version: checkpoint.version,
            consensus_history_id_digest: &checkpoint.consensus_history_id_digest,
            raft_group_id_digest: &checkpoint.raft_group_id_digest,
            collection_lifetime_id_digest: &checkpoint.collection_lifetime_id_digest,
            collection_key_digest: &checkpoint.collection_key_digest,
            collection_incarnation_digest: &checkpoint.collection_incarnation_digest,
            activation_anchor_digest: &checkpoint.activation_anchor_digest,
            capability_epoch: checkpoint.capability_epoch,
            protocol_capability_digest: &checkpoint.protocol_capability_digest,
            membership_epoch: checkpoint.membership_epoch,
            owner_enrollment_id: &checkpoint.owner_enrollment_id,
            owner_peer_id: checkpoint.owner_peer_id,
            owner_signer: &checkpoint.owner_signer,
            owner_store_incarnation_digest: &checkpoint.owner_store_incarnation_digest,
            checkpoint_sequence: checkpoint.checkpoint_sequence,
            lifecycle_state: &checkpoint.lifecycle_state,
            source_kind: checkpoint.source_kind,
            source_record_digest: &checkpoint.source_record_digest,
            source_applied: &checkpoint.source_applied,
            authority_registry_digest: &checkpoint.authority_registry_digest,
            owner_registry_digest: &checkpoint.owner_registry_digest,
        },
    )
}

fn reservation_expectation_digest_v1(
    expectation: &PrivateOramOwnerCheckpointReservationExpectationV1,
) -> Result<String, PrivateOramMutationJournalError> {
    digest_serialized(
        RESERVATION_EXPECTATION_DIGEST_DOMAIN_V1,
        &(
            expectation.version,
            expectation.owner_index,
            &expectation.owner_enrollment_id,
            expectation.owner_peer_id,
            &expectation.owner_signer,
            &expectation.owner_store_incarnation_digest,
            expectation.membership_epoch,
            expectation.expected_checkpoint_sequence,
            &expectation.expected_checkpoint_record_digest,
            &expectation.expected_lifecycle_state,
            &expectation.authority_registry_digest,
            &expectation.owner_registry_digest,
        ),
    )
}

fn reservation_context_digest_v1(
    context: &PrivateOramOwnerCheckpointReservationContextV1,
) -> Result<String, PrivateOramMutationJournalError> {
    #[derive(Serialize)]
    struct ReservationContextDigestInput<'a> {
        version: u16,
        reservation_intent_digest: &'a str,
        consensus_history_id_digest: &'a str,
        raft_group_id_digest: &'a str,
        collection_key_digest: &'a str,
        collection_lifetime_id_digest: &'a str,
        collection_incarnation_digest: &'a str,
        activation_anchor_digest: &'a str,
        capability_epoch: u64,
        protocol_capability_digest: &'a str,
        membership_epoch: u64,
        checkpoint_table_sequence: u64,
        checkpoint_table_digest: &'a str,
        owner_checkpoint_roster_digest: &'a str,
        owner_expectation_digests: Vec<&'a str>,
    }

    digest_serialized(
        RESERVATION_CONTEXT_DIGEST_DOMAIN_V1,
        &ReservationContextDigestInput {
            version: context.version,
            reservation_intent_digest: &context.reservation_intent_digest,
            consensus_history_id_digest: &context.consensus_history_id_digest,
            raft_group_id_digest: &context.raft_group_id_digest,
            collection_key_digest: &context.collection_key_digest,
            collection_lifetime_id_digest: &context.collection_lifetime_id_digest,
            collection_incarnation_digest: &context.collection_incarnation_digest,
            activation_anchor_digest: &context.activation_anchor_digest,
            capability_epoch: context.capability_epoch,
            protocol_capability_digest: &context.protocol_capability_digest,
            membership_epoch: context.membership_epoch,
            checkpoint_table_sequence: context.checkpoint_table_sequence,
            checkpoint_table_digest: &context.checkpoint_table_digest,
            owner_checkpoint_roster_digest: &context.owner_checkpoint_roster_digest,
            owner_expectation_digests: context
                .owner_expectations
                .iter()
                .map(|expectation| expectation.expectation_digest.as_str())
                .collect(),
        },
    )
}

fn reservation_binding_digest_v1(
    binding: &PrivateOramOwnerCheckpointReservationBindingV1,
) -> Result<String, PrivateOramMutationJournalError> {
    digest_serialized(
        RESERVATION_BINDING_DIGEST_DOMAIN_V1,
        &(
            binding.version,
            binding.owner_index,
            &binding.owner_enrollment_id,
            binding.expected_checkpoint_sequence,
            &binding.expected_checkpoint_record_digest,
            &binding.expected_lifecycle_state,
            &binding.reservation_prepare,
        ),
    )
}

fn active_lease_digest_v1(
    lease: &PrivateOramOwnerCheckpointActiveLeaseV1,
) -> Result<String, PrivateOramMutationJournalError> {
    digest_serialized(
        ACTIVE_LEASE_DIGEST_DOMAIN_V1,
        &(
            lease.version,
            lease.owner_index,
            &lease.owner_enrollment_id,
            &lease.checkpoint_record_digest,
            &lease.attempt_id,
            &lease.attempt_context_digest,
            &lease.reservation_digest,
            &lease.reservation_applied,
        ),
    )
}

fn checkpoint_successor_digest_v1(
    successor: &PrivateOramOwnerCheckpointSuccessorV1,
) -> Result<String, PrivateOramMutationJournalError> {
    digest_serialized(
        SUCCESSOR_DIGEST_DOMAIN_V1,
        &(
            successor.version,
            successor.owner_index,
            &successor.owner_enrollment_id,
            successor.previous_checkpoint_sequence,
            &successor.previous_checkpoint_record_digest,
            &successor.previous_lifecycle_state,
            &successor.new_lifecycle_state,
            &successor.terminal_state,
            &successor.terminal_marker_digest,
            &successor.intent_identity_digest,
            &successor.cleanup_operation_id,
            &successor.grant_digest,
            &successor.committed_terminal_evidence_digest,
        ),
    )
}

fn checkpoint_table_digest_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<String, PrivateOramMutationJournalError> {
    #[derive(Serialize)]
    struct CheckpointTableDigestInput<'a> {
        version: u16,
        consensus_history_id_digest: &'a str,
        raft_group_id_digest: &'a str,
        collection_key_digest: &'a str,
        collection_lifetime_id_digest: &'a str,
        collection_incarnation_digest: &'a str,
        activation_anchor_digest: &'a str,
        activation_applied: &'a PrivateOramRaftApplyLocatorV2,
        capability_epoch: u64,
        protocol_capability_digest: &'a str,
        roster_membership_epoch: Option<u64>,
        owner_roster_digest: &'a str,
        table_sequence: u64,
        pending_enrollment_digests: Vec<&'a str>,
        checkpoint_record_digests: Vec<&'a str>,
        active_lease_digests: Vec<&'a str>,
        repair_pending_owner_enrollment_ids: &'a [String],
    }

    digest_serialized(
        TABLE_DIGEST_DOMAIN_V1,
        &CheckpointTableDigestInput {
            version: table.version,
            consensus_history_id_digest: &table.consensus_history_id_digest,
            raft_group_id_digest: &table.raft_group_id_digest,
            collection_key_digest: &table.collection_key_digest,
            collection_lifetime_id_digest: &table.collection_lifetime_id_digest,
            collection_incarnation_digest: &table.collection_incarnation_digest,
            activation_anchor_digest: &table.activation_anchor_digest,
            activation_applied: &table.activation_applied,
            capability_epoch: table.capability_epoch,
            protocol_capability_digest: &table.protocol_capability_digest,
            roster_membership_epoch: table.roster_membership_epoch,
            owner_roster_digest: &table.owner_roster_digest,
            table_sequence: table.table_sequence,
            pending_enrollment_digests: table
                .pending_enrollments
                .iter()
                .map(|pending| pending.pending_digest.as_str())
                .collect::<Vec<_>>(),
            checkpoint_record_digests: table
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.checkpoint_record_digest.as_str())
                .collect::<Vec<_>>(),
            active_lease_digests: table
                .active_leases
                .iter()
                .map(|lease| lease.lease_digest.as_str())
                .collect::<Vec<_>>(),
            repair_pending_owner_enrollment_ids: &table.repair_pending_owner_enrollment_ids,
        },
    )
}

fn owner_roster_digest_v1(
    table: &PrivateOramOwnerCheckpointTableV1,
) -> Result<String, PrivateOramMutationJournalError> {
    digest_serialized(
        OWNER_ROSTER_DIGEST_DOMAIN_V1,
        &(
            table.roster_membership_epoch,
            table
                .checkpoints
                .iter()
                .map(|checkpoint| {
                    (
                        checkpoint.owner_enrollment_id.as_str(),
                        checkpoint.owner_peer_id,
                        &checkpoint.owner_signer,
                        checkpoint.owner_store_incarnation_digest.as_str(),
                        checkpoint.authority_registry_digest.as_str(),
                        checkpoint.owner_registry_digest.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
        ),
    )
}

fn digest_serialized<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, PrivateOramMutationJournalError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
        PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1, PrivateOramOwnerEnrollmentPreparedV1,
        PrivateOramOwnerLifecycleStatusChallengeV1, PrivateOramOwnerLifecycleStatusModeV1,
        PrivateOramOwnerReservationPrepareChallengeV1, PrivateOramOwnerReservationPrepareV1,
        prepare_private_oram_owner_enrollment_v1, private_oram_owner_cleanup_signer_v1,
        private_oram_owner_lifecycle_genesis_state_v1,
        sign_private_oram_owner_enrollment_genesis_commitment_v1,
        sign_private_oram_owner_lifecycle_status_attestation_v1,
        sign_private_oram_owner_reservation_prepare_v1,
    };
    use ring::signature::Ed25519KeyPair;

    use super::*;

    fn digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; 32])
    }

    fn locator(term: u64, index: u64) -> PrivateOramRaftApplyLocatorV2 {
        PrivateOramRaftApplyLocatorV2 {
            version: super::super::APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            term,
            index,
        }
    }

    fn table() -> PrivateOramOwnerCheckpointTableV1 {
        private_oram_owner_checkpoint_table_genesis_v1(
            digest(1),
            digest(2),
            private_oram_collection_id_digest_v2("collection-a").unwrap(),
            digest(3),
            digest(4),
            digest(5),
            locator(1, 1),
            2,
            digest(6),
        )
        .unwrap()
    }

    fn prepared(
        key: &Ed25519KeyPair,
        peer: u64,
        enrollment_seed: u8,
        incarnation_seed: u8,
    ) -> PrivateOramOwnerEnrollmentPreparedV1 {
        let incarnation = digest(incarnation_seed);
        prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
            version: 0,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 2,
            protocol_capability_digest: digest(6),
            membership_epoch: 9,
            owner_enrollment_id: digest(enrollment_seed),
            owner_peer_id: peer,
            owner_signer: private_oram_owner_cleanup_signer_v1(key, 3).unwrap(),
            owner_store_incarnation_digest: incarnation.clone(),
            expected_genesis_state: private_oram_owner_lifecycle_genesis_state_v1(incarnation)
                .unwrap(),
            authority_registry_digest: digest(7),
            owner_registry_digest: digest(8),
            enrollment_operation_id: digest(enrollment_seed.wrapping_add(1)),
            prepared_record_digest: String::new(),
        })
        .unwrap()
    }

    fn enroll(
        table: &PrivateOramOwnerCheckpointTableV1,
        key: &Ed25519KeyPair,
        peer: u64,
        enrollment_seed: u8,
        incarnation_seed: u8,
        index: u64,
    ) -> PrivateOramOwnerCheckpointTableV1 {
        let prepared = prepared(key, peer, enrollment_seed, incarnation_seed);
        let pending = prepare_private_oram_owner_enrollment_transition_v1(
            table,
            prepared.clone(),
            locator(1, index),
        )
        .unwrap();
        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(key, &prepared).unwrap();
        activate_private_oram_owner_enrollment_transition_v1(
            &pending,
            &commitment,
            locator(1, index + 1),
        )
        .unwrap()
    }

    fn status(
        key: &Ed25519KeyPair,
        checkpoint: &PrivateOramOwnerCheckpointRecordV1,
        owner_index: u32,
        attempt_id: String,
        attempt_context_digest: String,
    ) -> PrivateOramOwnerLifecycleStatusAttestationV1 {
        let challenge = PrivateOramOwnerLifecycleStatusChallengeV1 {
            version: PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 2,
            protocol_capability_digest: digest(6),
            membership_epoch: 9,
            attempt_id,
            attempt_context_digest,
            challenge_nonce: BASE64URL_NOPAD.encode(&[owner_index as u8 + 1; 16]),
            expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest.clone(),
            expected_checkpoint_sequence: checkpoint.checkpoint_sequence,
            owner_index,
            owner_enrollment_id: checkpoint.owner_enrollment_id.clone(),
            owner_peer_id: checkpoint.owner_peer_id,
            owner_store_incarnation_digest: checkpoint.owner_store_incarnation_digest.clone(),
            authority_registry_digest: checkpoint.authority_registry_digest.clone(),
            owner_registry_digest: checkpoint.owner_registry_digest.clone(),
        };
        sign_private_oram_owner_lifecycle_status_attestation_v1(
            key,
            challenge,
            checkpoint.lifecycle_state.clone(),
            PrivateOramOwnerLifecycleStatusModeV1::ReadyExact,
            true,
            checkpoint.owner_signer.clone(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn reservation_prepare(
        key: &Ed25519KeyPair,
        checkpoint: &PrivateOramOwnerCheckpointRecordV1,
        owner_index: u32,
        owner_count: u32,
        attempt_id: String,
        reservation_intent_digest: String,
        checkpoint_context_digest: String,
    ) -> PrivateOramOwnerReservationPrepareV1 {
        let challenge = PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 2,
            protocol_capability_digest: digest(6),
            membership_epoch: 9,
            reservation_intent_digest,
            checkpoint_context_digest,
            committed_challenge_digest: digest(100),
            challenge_applied_term: 1,
            challenge_applied_index: 5,
            attempt_id,
            challenge_nonce: BASE64URL_NOPAD.encode(&[owner_index as u8 + 1; 16]),
            expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest.clone(),
            expected_checkpoint_sequence: checkpoint.checkpoint_sequence,
            expected_owner_target_digest: digest(101_u8.wrapping_add(owner_index as u8)),
            reserved_terminal_intent_key: digest(111_u8.wrapping_add(owner_index as u8)),
            owner_index,
            owner_count,
            owner_enrollment_id: checkpoint.owner_enrollment_id.clone(),
            owner_peer_id: checkpoint.owner_peer_id,
            owner_store_incarnation_digest: checkpoint.owner_store_incarnation_digest.clone(),
            authority_registry_digest: checkpoint.authority_registry_digest.clone(),
            owner_registry_digest: checkpoint.owner_registry_digest.clone(),
        };
        sign_private_oram_owner_reservation_prepare_v1(
            key,
            challenge,
            checkpoint.lifecycle_state.clone(),
            checkpoint.lifecycle_state.generation,
            digest(120_u8.wrapping_add(owner_index as u8)),
            checkpoint.owner_signer.clone(),
        )
        .unwrap()
    }

    #[test]
    fn enrollment_creates_only_protocol_genesis_and_replay_is_scoped() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let base = table();
        let enrollment = prepared(&key, 11, 20, 30);
        let pending = prepare_private_oram_owner_enrollment_transition_v1(
            &base,
            enrollment.clone(),
            locator(1, 2),
        )
        .unwrap();
        assert!(pending.checkpoints.is_empty());
        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(&key, &enrollment).unwrap();
        let active = activate_private_oram_owner_enrollment_transition_v1(
            &pending,
            &commitment,
            locator(1, 3),
        )
        .unwrap();
        assert_eq!(active.checkpoints.len(), 1);
        assert_eq!(active.checkpoints[0].checkpoint_sequence, 1);
        assert_eq!(active.checkpoints[0].lifecycle_state.generation, 0);

        let other = prepared(&key, 11, 21, 31);
        let other_pending =
            prepare_private_oram_owner_enrollment_transition_v1(&base, other, locator(1, 4))
                .unwrap();
        assert!(
            activate_private_oram_owner_enrollment_transition_v1(
                &other_pending,
                &commitment,
                locator(1, 5)
            )
            .is_err()
        );
    }

    #[test]
    fn enrollment_roster_readiness_requires_exact_fully_active_owners() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[41; 32]).unwrap();
        let base = table();
        let enrollment = prepared(&key, 11, 20, 30);
        let pending = prepare_private_oram_owner_enrollment_transition_v1(
            &base,
            enrollment.clone(),
            locator(1, 2),
        )
        .unwrap();
        assert!(!base.enrollment_roster_is_active(&[11]));
        assert!(!pending.enrollment_roster_is_active(&[11]));

        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(&key, &enrollment).unwrap();
        let active = activate_private_oram_owner_enrollment_transition_v1(
            &pending,
            &commitment,
            locator(1, 3),
        )
        .unwrap();
        assert!(active.enrollment_roster_is_active(&[11]));
        assert!(!active.enrollment_roster_is_active(&[]));
        assert!(!active.enrollment_roster_is_active(&[11, 12]));
        assert!(!active.enrollment_roster_is_active(&[12]));
    }

    #[test]
    fn reservation_checkpoint_cas_allows_exactly_one_consumer() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[32; 32]).unwrap();
        let enrolled = enroll(&table(), &key, 11, 20, 30, 2);
        let checkpoint = &enrolled.checkpoints[0];
        let attempt_id = digest(40);
        let reservation_digest = digest(42);
        let prepare = reservation_prepare(
            &key,
            checkpoint,
            0,
            1,
            attempt_id.clone(),
            reservation_digest.clone(),
            reservation_digest.clone(),
        );
        let binding =
            private_oram_owner_checkpoint_reservation_binding_v1(0, checkpoint, prepare).unwrap();
        let leased = lease_private_oram_owner_checkpoints_for_reservation_v1(
            &enrolled,
            &attempt_id,
            &reservation_digest,
            &reservation_digest,
            std::slice::from_ref(&binding),
            locator(1, 4),
        )
        .unwrap();
        assert_eq!(leased.active_leases.len(), 1);
        assert!(
            lease_private_oram_owner_checkpoints_for_reservation_v1(
                &leased,
                &digest(43),
                &digest(44),
                &digest(45),
                &[binding],
                locator(1, 5),
            )
            .is_err()
        );
    }

    #[test]
    fn reservation_requires_complete_canonical_roster_and_signed_context() {
        let key0 = Ed25519KeyPair::from_seed_unchecked(&[35; 32]).unwrap();
        let key1 = Ed25519KeyPair::from_seed_unchecked(&[36; 32]).unwrap();
        let first = enroll(&table(), &key0, 12, 20, 30, 2);
        let enrolled = enroll(&first, &key1, 11, 40, 50, 4);
        let attempt_id = digest(60);
        let reservation_digest = digest(62);
        let context = private_oram_owner_checkpoint_reservation_context_v1(
            &enrolled,
            reservation_digest.clone(),
        )
        .unwrap();
        let attempt_context_digest = context.context_digest().to_string();
        let mut canonical_checkpoints = enrolled.checkpoints.iter().collect::<Vec<_>>();
        canonical_checkpoints.sort_by_key(|checkpoint| checkpoint.owner_peer_id);
        let bindings = canonical_checkpoints
            .into_iter()
            .enumerate()
            .map(|(index, checkpoint)| {
                let key = if checkpoint.owner_peer_id == 11 {
                    &key1
                } else {
                    &key0
                };
                private_oram_owner_checkpoint_reservation_binding_v1(
                    index as u32,
                    checkpoint,
                    reservation_prepare(
                        key,
                        checkpoint,
                        index as u32,
                        2,
                        attempt_id.clone(),
                        reservation_digest.clone(),
                        attempt_context_digest.clone(),
                    ),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        for binding in &bindings {
            validate_private_oram_owner_checkpoint_binding_context_v1(&context, binding).unwrap();
        }

        assert!(
            lease_private_oram_owner_checkpoints_for_reservation_v1(
                &enrolled,
                &attempt_id,
                &attempt_context_digest,
                &reservation_digest,
                &bindings[..1],
                locator(1, 6),
            )
            .is_err()
        );

        let mut reversed = bindings.clone();
        reversed.reverse();
        assert!(
            lease_private_oram_owner_checkpoints_for_reservation_v1(
                &enrolled,
                &attempt_id,
                &attempt_context_digest,
                &reservation_digest,
                &reversed,
                locator(1, 6),
            )
            .is_err()
        );
        assert!(
            lease_private_oram_owner_checkpoints_for_reservation_v1(
                &enrolled,
                &attempt_id,
                &digest(63),
                &reservation_digest,
                &bindings,
                locator(1, 6),
            )
            .is_err()
        );
    }

    #[test]
    fn settlement_advances_all_checkpoints_atomically_and_requires_repair_status() {
        let key0 = Ed25519KeyPair::from_seed_unchecked(&[33; 32]).unwrap();
        let key1 = Ed25519KeyPair::from_seed_unchecked(&[34; 32]).unwrap();
        let first = enroll(&table(), &key0, 11, 20, 30, 2);
        let enrolled = enroll(&first, &key1, 12, 40, 50, 4);
        let attempt_id = digest(60);
        let reservation_digest = digest(61);
        let bindings = enrolled
            .checkpoints
            .iter()
            .enumerate()
            .map(|(index, checkpoint)| {
                let key = if checkpoint.owner_peer_id == 11 {
                    &key0
                } else {
                    &key1
                };
                private_oram_owner_checkpoint_reservation_binding_v1(
                    index as u32,
                    checkpoint,
                    reservation_prepare(
                        key,
                        checkpoint,
                        index as u32,
                        2,
                        attempt_id.clone(),
                        reservation_digest.clone(),
                        reservation_digest.clone(),
                    ),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let leased = lease_private_oram_owner_checkpoints_for_reservation_v1(
            &enrolled,
            &attempt_id,
            &reservation_digest,
            &reservation_digest,
            &bindings,
            locator(1, 6),
        )
        .unwrap();

        let settlements = leased
            .checkpoints
            .iter()
            .enumerate()
            .map(|(index, checkpoint)| {
                let terminal_marker_digest = digest(80 + index as u8);
                let intent_identity_digest = digest(82 + index as u8);
                let generation = checkpoint.lifecycle_state.generation + 1;
                let terminal_state = PrivateOramOwnerCleanupTerminalStateV1::Quarantined;
                let mut next = checkpoint.lifecycle_state.clone();
                next.generation = generation;
                next.state_root = private_oram_owner_lifecycle_state_root_v1(
                    &checkpoint.lifecycle_state,
                    generation,
                    &terminal_marker_digest,
                    &intent_identity_digest,
                    &terminal_state,
                )
                .unwrap();
                PrivateOramOwnerNegativeSettlementV1::CleanupTerminalCommitted(
                    private_oram_owner_checkpoint_successor_v1(
                        index as u32,
                        checkpoint,
                        next,
                        terminal_state,
                        terminal_marker_digest,
                        intent_identity_digest,
                        digest(84 + index as u8),
                        digest(86 + index as u8),
                        digest(88 + index as u8),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let mut altered = settlements.clone();
        if let PrivateOramOwnerNegativeSettlementV1::CleanupTerminalCommitted(successor) =
            &mut altered[1]
        {
            successor.previous_checkpoint_record_digest = digest(99);
            successor.successor_digest = checkpoint_successor_digest_v1(successor).unwrap();
        }
        assert!(
            acknowledge_private_oram_owner_negative_settlement_v1(
                &leased,
                &attempt_id,
                &reservation_digest,
                &digest(90),
                &altered,
                locator(1, 7),
            )
            .is_err()
        );
        assert!(
            leased
                .checkpoints
                .iter()
                .all(|record| record.checkpoint_sequence == 1)
        );

        let acknowledged = acknowledge_private_oram_owner_negative_settlement_v1(
            &leased,
            &attempt_id,
            &reservation_digest,
            &digest(90),
            &settlements,
            locator(1, 7),
        )
        .unwrap();
        assert!(acknowledged.active_leases.is_empty());
        assert!(acknowledged.has_pending_repair());
        assert!(
            acknowledged
                .checkpoints
                .iter()
                .all(|record| record.checkpoint_sequence == 2)
        );

        let repair_attestations = acknowledged
            .checkpoints
            .iter()
            .enumerate()
            .map(|(index, checkpoint)| {
                let key = if checkpoint.owner_peer_id == 11 {
                    &key0
                } else {
                    &key1
                };
                status(key, checkpoint, index as u32, digest(91), digest(92))
            })
            .collect::<Vec<_>>();
        let ready = complete_private_oram_owner_checkpoint_repairs_v1(
            &acknowledged,
            &digest(91),
            &digest(92),
            &repair_attestations,
        )
        .unwrap();
        assert!(!ready.has_pending_repair());
    }
}
