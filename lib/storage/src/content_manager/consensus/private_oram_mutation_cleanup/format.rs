//! Dormant format/write floors and snapshot anti-rollback guards for private-ORAM mutation V2.
//!
//! Constructors remain test-only until a mixed-version Raft activation barrier can mint these
//! values from committed entries. Floors are reject-only authority and never synthesize mutation
//! state or authorize cleanup.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::authority::{
    DecodedPrivateOramMutationAuthorityWireV2, PrivateOramMutationAuthorityStateV2,
    private_oram_mutation_activated_floor_projection_v2,
};
use super::{
    PrivateOramRaftApplyLocatorV2, locator_is_at_or_after, locator_is_strictly_after,
    validate_apply_locator_v2, validate_digest,
};
use crate::content_manager::private_oram_mutation_journal::PrivateOramMutationJournalError;

const FORMAT_FLOOR_VERSION: u16 = 2;
const AUTHORITY_FLOOR_VERSION: u16 = 1;
const ENROLLMENT_FLOOR_VERSION: u16 = 1;
const FORMAT_FLOOR_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-format-floor/v2";
const AUTHORITY_FLOOR_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-authority-floor/v2";
const ENROLLMENT_FLOOR_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-enrollment-floor/v2";

/// Cluster-wide irreversible minimum format known to one Raft history and group.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationFormatFloorV2 {
    version: u16,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    format_epoch: u64,
    minimum_reader_protocol: u16,
    minimum_writer_protocol: u16,
    snapshot_format_epoch: u64,
    membership_generation: u64,
    eligible_peer_set_digest: String,
    eligible_process_incarnations_digest: String,
    capability_manifest_digest: String,
    required_binary_capability_digest: String,
    tagged_write_required: bool,
    activation_enabled: bool,
    floor_applied: PrivateOramRaftApplyLocatorV2,
    floor_digest: String,
}

impl Debug for PrivateOramMutationFormatFloorV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationFormatFloorV2")
            .field("version", &self.version)
            .field("format_epoch", &self.format_epoch)
            .field("minimum_reader_protocol", &self.minimum_reader_protocol)
            .field("minimum_writer_protocol", &self.minimum_writer_protocol)
            .field("snapshot_format_epoch", &self.snapshot_format_epoch)
            .field("membership_generation", &self.membership_generation)
            .field("tagged_write_required", &self.tagged_write_required)
            .field("activation_enabled", &self.activation_enabled)
            .field("floor_applied", &self.floor_applied)
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("eligible_peer_set_digest", &"[redacted]")
            .field("eligible_process_incarnations_digest", &"[redacted]")
            .field("capability_manifest_digest", &"[redacted]")
            .field("required_binary_capability_digest", &"[redacted]")
            .field("floor_digest", &"[redacted]")
            .finish()
    }
}

/// Local monotonic guard retained outside an installed Raft snapshot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationAuthorityFloorV2 {
    version: u16,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_lifetime_id_digest: String,
    collection_key_digest: String,
    compatibility_epoch: u64,
    activation_anchor_digest: String,
    maximum_authority_ordinal: u64,
    aggregate_digest_at_ordinal: String,
    outer_binding_digest_at_ordinal: String,
    latest_material_locator: PrivateOramRaftApplyLocatorV2,
    accepted_state_applied_index: u64,
    floor_digest: String,
}

/// Snapshot-independent proof that one collection entered the V2 mutation authority domain.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationEnrollmentFloorV2 {
    version: u16,
    collection_key_digest: String,
    manifest_digest: String,
    enrollment_applied_index: u64,
    floor_digest: String,
}

impl Debug for PrivateOramMutationEnrollmentFloorV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationEnrollmentFloorV2")
            .field("version", &self.version)
            .field("enrollment_applied_index", &self.enrollment_applied_index)
            .field("collection_key_digest", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("floor_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramMutationAuthorityFloorV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAuthorityFloorV2")
            .field("version", &self.version)
            .field("compatibility_epoch", &self.compatibility_epoch)
            .field("maximum_authority_ordinal", &self.maximum_authority_ordinal)
            .field("latest_material_locator", &self.latest_material_locator)
            .field(
                "accepted_state_applied_index",
                &self.accepted_state_applied_index,
            )
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("collection_lifetime_id_digest", &"[redacted]")
            .field("collection_key_digest", &"[redacted]")
            .field("activation_anchor_digest", &"[redacted]")
            .field("aggregate_digest_at_ordinal", &"[redacted]")
            .field("outer_binding_digest_at_ordinal", &"[redacted]")
            .field("floor_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationFormatFloorV2 {
    pub(crate) fn consensus_history_id_digest(&self) -> &str {
        &self.consensus_history_id_digest
    }

    pub(crate) fn raft_group_id_digest(&self) -> &str {
        &self.raft_group_id_digest
    }

    pub(crate) fn format_epoch(&self) -> u64 {
        self.format_epoch
    }

    pub(crate) fn activation_enabled(&self) -> bool {
        self.activation_enabled
    }

    pub(crate) fn minimum_reader_protocol(&self) -> u16 {
        self.minimum_reader_protocol
    }

    pub(crate) fn minimum_writer_protocol(&self) -> u16 {
        self.minimum_writer_protocol
    }

    pub(crate) fn snapshot_format_epoch(&self) -> u64 {
        self.snapshot_format_epoch
    }

    pub(crate) fn tagged_write_required(&self) -> bool {
        self.tagged_write_required
    }

    pub(crate) fn required_binary_capability_digest(&self) -> &str {
        &self.required_binary_capability_digest
    }

    pub(crate) fn floor_applied_index(&self) -> u64 {
        self.floor_applied.index
    }

    pub(crate) fn floor_applied_locator(&self) -> &PrivateOramRaftApplyLocatorV2 {
        &self.floor_applied
    }

    pub(crate) fn floor_digest(&self) -> &str {
        &self.floor_digest
    }
}

impl PrivateOramMutationAuthorityFloorV2 {
    pub(crate) fn maximum_authority_ordinal(&self) -> u64 {
        self.maximum_authority_ordinal
    }

    pub(crate) fn accepted_state_applied_index(&self) -> u64 {
        self.accepted_state_applied_index
    }

    pub(super) fn collection_key_digest(&self) -> &str {
        &self.collection_key_digest
    }

    pub(super) fn floor_digest(&self) -> &str {
        &self.floor_digest
    }
}

impl PrivateOramMutationEnrollmentFloorV2 {
    pub(crate) fn collection_key_digest(&self) -> &str {
        &self.collection_key_digest
    }

    pub(super) fn floor_digest(&self) -> &str {
        &self.floor_digest
    }
}

pub(crate) fn validate_private_oram_mutation_enrollment_floor_v2(
    floor: &PrivateOramMutationEnrollmentFloorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if floor.version != ENROLLMENT_FLOOR_VERSION || floor.enrollment_applied_index == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for digest in [
        &floor.collection_key_digest,
        &floor.manifest_digest,
        &floor.floor_digest,
    ] {
        validate_digest(digest)?;
    }
    if floor.floor_digest != enrollment_floor_digest_v2(floor)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(crate) fn plan_private_oram_mutation_enrollment_floor_v2(
    current: Option<&PrivateOramMutationEnrollmentFloorV2>,
    collection_key_digest: &str,
    manifest_digest: &str,
    applied_index: u64,
) -> Result<PrivateOramMutationEnrollmentFloorV2, PrivateOramMutationJournalError> {
    validate_digest(collection_key_digest)?;
    validate_digest(manifest_digest)?;
    if applied_index == 0 {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if let Some(current) = current {
        validate_private_oram_mutation_enrollment_floor_v2(current)?;
        if current.collection_key_digest != collection_key_digest
            || current.manifest_digest != manifest_digest
            || applied_index < current.enrollment_applied_index
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(current.clone());
    }
    let mut candidate = PrivateOramMutationEnrollmentFloorV2 {
        version: ENROLLMENT_FLOOR_VERSION,
        collection_key_digest: collection_key_digest.to_string(),
        manifest_digest: manifest_digest.to_string(),
        enrollment_applied_index: applied_index,
        floor_digest: String::new(),
    };
    candidate.floor_digest = enrollment_floor_digest_v2(&candidate)?;
    validate_private_oram_mutation_enrollment_floor_v2(&candidate)?;
    Ok(candidate)
}

pub(crate) fn validate_private_oram_mutation_format_floor_v2(
    floor: &PrivateOramMutationFormatFloorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if floor.version != FORMAT_FLOOR_VERSION
        || floor.format_epoch == 0
        || floor.minimum_reader_protocol == 0
        || floor.minimum_writer_protocol == 0
        || floor.snapshot_format_epoch == 0
        || floor.membership_generation == 0
        || !floor.tagged_write_required
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_apply_locator_v2(&floor.floor_applied)?;
    for digest in [
        &floor.consensus_history_id_digest,
        &floor.raft_group_id_digest,
        &floor.eligible_peer_set_digest,
        &floor.eligible_process_incarnations_digest,
        &floor.capability_manifest_digest,
        &floor.required_binary_capability_digest,
        &floor.floor_digest,
    ] {
        validate_digest(digest)?;
    }
    if floor.consensus_history_id_digest != floor.floor_applied.consensus_history_id_digest
        || floor.raft_group_id_digest != floor.floor_applied.raft_group_id_digest
        || floor.floor_digest != format_floor_digest_v2(floor)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

/// Accepts an exact replay or the immediate monotonic successor. Epoch skips fail closed because
/// this V1 floor record does not carry a bounded descendant proof chain.
pub(crate) fn plan_private_oram_mutation_format_floor_transition_v2(
    current: Option<&PrivateOramMutationFormatFloorV2>,
    candidate: &PrivateOramMutationFormatFloorV2,
) -> Result<PrivateOramMutationFormatFloorV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_format_floor_v2(candidate)?;
    let Some(current) = current else {
        if candidate.format_epoch != 1 || candidate.activation_enabled {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(candidate.clone());
    };
    validate_private_oram_mutation_format_floor_v2(current)?;
    if candidate == current {
        return Ok(current.clone());
    }
    if candidate.consensus_history_id_digest != current.consensus_history_id_digest
        || candidate.raft_group_id_digest != current.raft_group_id_digest
        || candidate.format_epoch
            != current
                .format_epoch
                .checked_add(1)
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)?
        || candidate.minimum_reader_protocol < current.minimum_reader_protocol
        || candidate.minimum_writer_protocol < current.minimum_writer_protocol
        || candidate.snapshot_format_epoch < current.snapshot_format_epoch
        || candidate.membership_generation < current.membership_generation
        || current.activation_enabled && !candidate.activation_enabled
        || !locator_is_strictly_after(&candidate.floor_applied, &current.floor_applied)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let membership_evidence_changed = candidate.eligible_peer_set_digest
        != current.eligible_peer_set_digest
        || candidate.eligible_process_incarnations_digest
            != current.eligible_process_incarnations_digest
        || candidate.capability_manifest_digest != current.capability_manifest_digest
        || candidate.required_binary_capability_digest != current.required_binary_capability_digest;
    if membership_evidence_changed
        && candidate.membership_generation <= current.membership_generation
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(candidate.clone())
}

pub(crate) fn validate_private_oram_mutation_authority_floor_v2(
    floor: &PrivateOramMutationAuthorityFloorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if floor.version != AUTHORITY_FLOOR_VERSION
        || floor.compatibility_epoch == 0
        || floor.maximum_authority_ordinal == 0
        || floor.accepted_state_applied_index < floor.latest_material_locator.index
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_apply_locator_v2(&floor.latest_material_locator)?;
    for digest in [
        &floor.consensus_history_id_digest,
        &floor.raft_group_id_digest,
        &floor.collection_lifetime_id_digest,
        &floor.collection_key_digest,
        &floor.activation_anchor_digest,
        &floor.aggregate_digest_at_ordinal,
        &floor.outer_binding_digest_at_ordinal,
        &floor.floor_digest,
    ] {
        validate_digest(digest)?;
    }
    if floor.consensus_history_id_digest
        != floor.latest_material_locator.consensus_history_id_digest
        || floor.raft_group_id_digest != floor.latest_material_locator.raft_group_id_digest
        || floor.floor_digest != authority_floor_digest_v2(floor)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

/// Validates one snapshot-independent authority floor against the cluster format floor and an
/// optional previous local value. The format floor may advance beyond the authority's activation
/// epoch, but it may never move behind it.
pub(crate) fn plan_private_oram_mutation_authority_floor_transition_v2(
    current: Option<&PrivateOramMutationAuthorityFloorV2>,
    format_floor: &PrivateOramMutationFormatFloorV2,
    candidate: &PrivateOramMutationAuthorityFloorV2,
) -> Result<PrivateOramMutationAuthorityFloorV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_format_floor_v2(format_floor)?;
    validate_private_oram_mutation_authority_floor_v2(candidate)?;
    if !format_floor.activation_enabled
        || candidate.consensus_history_id_digest != format_floor.consensus_history_id_digest
        || candidate.raft_group_id_digest != format_floor.raft_group_id_digest
        || candidate.compatibility_epoch > format_floor.format_epoch
        || candidate.latest_material_locator.index > candidate.accepted_state_applied_index
        || format_floor.floor_applied.index > candidate.accepted_state_applied_index
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let Some(current) = current else {
        return Ok(candidate.clone());
    };
    validate_private_oram_mutation_authority_floor_v2(current)?;
    if candidate.consensus_history_id_digest != current.consensus_history_id_digest
        || candidate.raft_group_id_digest != current.raft_group_id_digest
        || candidate.collection_lifetime_id_digest != current.collection_lifetime_id_digest
        || candidate.collection_key_digest != current.collection_key_digest
        || candidate.compatibility_epoch != current.compatibility_epoch
        || candidate.activation_anchor_digest != current.activation_anchor_digest
        || candidate.maximum_authority_ordinal < current.maximum_authority_ordinal
        || candidate.accepted_state_applied_index < current.accepted_state_applied_index
        || !locator_is_at_or_after(
            &candidate.latest_material_locator,
            &current.latest_material_locator,
        )
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    if candidate.maximum_authority_ordinal == current.maximum_authority_ordinal {
        if candidate.aggregate_digest_at_ordinal != current.aggregate_digest_at_ordinal
            || candidate.outer_binding_digest_at_ordinal != current.outer_binding_digest_at_ordinal
            || candidate.latest_material_locator != current.latest_material_locator
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    } else if !locator_is_strictly_after(
        &candidate.latest_material_locator,
        &current.latest_material_locator,
    ) {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(candidate.clone())
}

/// Plans acceptance of one Activated authority image against a snapshot-independent local floor.
pub(crate) fn plan_private_oram_mutation_authority_floor_acceptance_v2(
    current: Option<&PrivateOramMutationAuthorityFloorV2>,
    format_floor: &PrivateOramMutationFormatFloorV2,
    authority: &PrivateOramMutationAuthorityStateV2,
    accepted_state_applied_index: u64,
) -> Result<PrivateOramMutationAuthorityFloorV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_format_floor_v2(format_floor)?;
    if !format_floor.activation_enabled {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let projection = private_oram_mutation_activated_floor_projection_v2(authority)?
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    if projection.consensus_history_id_digest != format_floor.consensus_history_id_digest
        || projection.raft_group_id_digest != format_floor.raft_group_id_digest
        || projection.compatibility_epoch > format_floor.format_epoch
        || projection.latest_material_locator.index > accepted_state_applied_index
        || format_floor.floor_applied.index > accepted_state_applied_index
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut candidate = PrivateOramMutationAuthorityFloorV2 {
        version: AUTHORITY_FLOOR_VERSION,
        consensus_history_id_digest: projection.consensus_history_id_digest,
        raft_group_id_digest: projection.raft_group_id_digest,
        collection_lifetime_id_digest: projection.collection_lifetime_id_digest,
        collection_key_digest: projection.collection_key_digest,
        compatibility_epoch: projection.compatibility_epoch,
        activation_anchor_digest: projection.activation_anchor_digest,
        maximum_authority_ordinal: projection.transition_ordinal,
        aggregate_digest_at_ordinal: projection.aggregate_digest,
        outer_binding_digest_at_ordinal: projection.outer_binding_digest,
        latest_material_locator: projection.latest_material_locator,
        accepted_state_applied_index,
        floor_digest: String::new(),
    };
    candidate.floor_digest = authority_floor_digest_v2(&candidate)?;
    plan_private_oram_mutation_authority_floor_transition_v2(current, format_floor, &candidate)
}

/// Snapshot helper that rejects omission, historical raw, and tagged Legacy once a local
/// Activated floor exists.
pub(crate) fn plan_private_oram_mutation_snapshot_authority_acceptance_v2(
    current: &PrivateOramMutationAuthorityFloorV2,
    format_floor: &PrivateOramMutationFormatFloorV2,
    decoded: Option<&DecodedPrivateOramMutationAuthorityWireV2>,
    snapshot_applied_index: u64,
) -> Result<PrivateOramMutationAuthorityFloorV2, PrivateOramMutationJournalError> {
    let authority = decoded
        .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
        .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
    plan_private_oram_mutation_authority_floor_acceptance_v2(
        Some(current),
        format_floor,
        authority,
        snapshot_applied_index,
    )
}

fn format_floor_digest_v2(
    floor: &PrivateOramMutationFormatFloorV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(FORMAT_FLOOR_DIGEST_DOMAIN_V2);
    hasher.update(floor.version.to_be_bytes());
    hash_digest(&mut hasher, &floor.consensus_history_id_digest)?;
    hash_digest(&mut hasher, &floor.raft_group_id_digest)?;
    hasher.update(floor.format_epoch.to_be_bytes());
    hasher.update(floor.minimum_reader_protocol.to_be_bytes());
    hasher.update(floor.minimum_writer_protocol.to_be_bytes());
    hasher.update(floor.snapshot_format_epoch.to_be_bytes());
    hasher.update(floor.membership_generation.to_be_bytes());
    hash_digest(&mut hasher, &floor.eligible_peer_set_digest)?;
    hash_digest(&mut hasher, &floor.eligible_process_incarnations_digest)?;
    hash_digest(&mut hasher, &floor.capability_manifest_digest)?;
    hash_digest(&mut hasher, &floor.required_binary_capability_digest)?;
    hasher.update([u8::from(floor.tagged_write_required)]);
    hasher.update([u8::from(floor.activation_enabled)]);
    hash_locator(&mut hasher, &floor.floor_applied)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn authority_floor_digest_v2(
    floor: &PrivateOramMutationAuthorityFloorV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_FLOOR_DIGEST_DOMAIN_V2);
    hasher.update(floor.version.to_be_bytes());
    hash_digest(&mut hasher, &floor.consensus_history_id_digest)?;
    hash_digest(&mut hasher, &floor.raft_group_id_digest)?;
    hash_digest(&mut hasher, &floor.collection_lifetime_id_digest)?;
    hash_digest(&mut hasher, &floor.collection_key_digest)?;
    hasher.update(floor.compatibility_epoch.to_be_bytes());
    hash_digest(&mut hasher, &floor.activation_anchor_digest)?;
    hasher.update(floor.maximum_authority_ordinal.to_be_bytes());
    hash_digest(&mut hasher, &floor.aggregate_digest_at_ordinal)?;
    hash_digest(&mut hasher, &floor.outer_binding_digest_at_ordinal)?;
    hash_locator(&mut hasher, &floor.latest_material_locator)?;
    hasher.update(floor.accepted_state_applied_index.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn enrollment_floor_digest_v2(
    floor: &PrivateOramMutationEnrollmentFloorV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(ENROLLMENT_FLOOR_DIGEST_DOMAIN_V2);
    hasher.update(floor.version.to_be_bytes());
    hash_digest(&mut hasher, &floor.collection_key_digest)?;
    hash_digest(&mut hasher, &floor.manifest_digest)?;
    hasher.update(floor.enrollment_applied_index.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_locator(
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

pub(crate) struct PrivateOramMutationFormatFloorBarrierInputV2 {
    pub(crate) consensus_history_id_digest: String,
    pub(crate) raft_group_id_digest: String,
    pub(crate) format_epoch: u64,
    pub(crate) minimum_reader_protocol: u16,
    pub(crate) minimum_writer_protocol: u16,
    pub(crate) snapshot_format_epoch: u64,
    pub(crate) membership_generation: u64,
    pub(crate) eligible_peer_set_digest: String,
    pub(crate) eligible_process_incarnations_digest: String,
    pub(crate) capability_manifest_digest: String,
    pub(crate) required_binary_capability_digest: String,
    pub(crate) activation_enabled: bool,
    pub(crate) term: u64,
    pub(crate) index: u64,
}

/// Mints a floor only from fields revalidated by the committed activation barrier reducer.
pub(crate) fn private_oram_mutation_format_floor_from_barrier_v2(
    input: PrivateOramMutationFormatFloorBarrierInputV2,
) -> Result<PrivateOramMutationFormatFloorV2, PrivateOramMutationJournalError> {
    let mut floor = PrivateOramMutationFormatFloorV2 {
        version: FORMAT_FLOOR_VERSION,
        consensus_history_id_digest: input.consensus_history_id_digest.clone(),
        raft_group_id_digest: input.raft_group_id_digest.clone(),
        format_epoch: input.format_epoch,
        minimum_reader_protocol: input.minimum_reader_protocol,
        minimum_writer_protocol: input.minimum_writer_protocol,
        snapshot_format_epoch: input.snapshot_format_epoch,
        membership_generation: input.membership_generation,
        eligible_peer_set_digest: input.eligible_peer_set_digest,
        eligible_process_incarnations_digest: input.eligible_process_incarnations_digest,
        capability_manifest_digest: input.capability_manifest_digest,
        required_binary_capability_digest: input.required_binary_capability_digest,
        tagged_write_required: true,
        activation_enabled: input.activation_enabled,
        floor_applied: PrivateOramRaftApplyLocatorV2 {
            version: super::APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: input.consensus_history_id_digest,
            raft_group_id_digest: input.raft_group_id_digest,
            term: input.term,
            index: input.index,
        },
        floor_digest: String::new(),
    };
    floor.floor_digest = format_floor_digest_v2(&floor)?;
    validate_private_oram_mutation_format_floor_v2(&floor)?;
    Ok(floor)
}

#[cfg(test)]
pub(crate) struct PrivateOramMutationFormatFloorTestInputV2 {
    pub(crate) consensus_history_id_digest: String,
    pub(crate) raft_group_id_digest: String,
    pub(crate) format_epoch: u64,
    pub(crate) minimum_reader_protocol: u16,
    pub(crate) minimum_writer_protocol: u16,
    pub(crate) snapshot_format_epoch: u64,
    pub(crate) membership_generation: u64,
    pub(crate) eligible_peer_set_digest: String,
    pub(crate) eligible_process_incarnations_digest: String,
    pub(crate) capability_manifest_digest: String,
    pub(crate) required_binary_capability_digest: String,
    pub(crate) activation_enabled: bool,
    pub(crate) term: u64,
    pub(crate) index: u64,
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_format_floor_for_test(
    input: PrivateOramMutationFormatFloorTestInputV2,
) -> Result<PrivateOramMutationFormatFloorV2, PrivateOramMutationJournalError> {
    private_oram_mutation_format_floor_from_barrier_v2(
        PrivateOramMutationFormatFloorBarrierInputV2 {
            consensus_history_id_digest: input.consensus_history_id_digest,
            raft_group_id_digest: input.raft_group_id_digest,
            format_epoch: input.format_epoch,
            minimum_reader_protocol: input.minimum_reader_protocol,
            minimum_writer_protocol: input.minimum_writer_protocol,
            snapshot_format_epoch: input.snapshot_format_epoch,
            membership_generation: input.membership_generation,
            eligible_peer_set_digest: input.eligible_peer_set_digest,
            eligible_process_incarnations_digest: input.eligible_process_incarnations_digest,
            capability_manifest_digest: input.capability_manifest_digest,
            required_binary_capability_digest: input.required_binary_capability_digest,
            activation_enabled: input.activation_enabled,
            term: input.term,
            index: input.index,
        },
    )
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        PrivateOramOwnerEnrollmentPreparedV1, prepare_private_oram_owner_enrollment_v1,
        private_oram_mutation_protocol_capability_digest_v2, private_oram_owner_cleanup_signer_v1,
        private_oram_owner_lifecycle_genesis_state_v1,
    };
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1;
    use crate::content_manager::consensus::private_oram_mutation_cleanup::authority::{
        PrivateOramMutationMaterialOperationV2, activate_private_oram_mutation_authority_v2,
        apply_private_oram_mutation_authority_owner_enrollment_prepared_v2,
        decode_private_oram_mutation_authority_wire_json_v2,
        encode_private_oram_mutation_tagged_authority_wire_json_v2,
        private_oram_mutation_activation_context_for_test,
        private_oram_mutation_aggregate_apply_context_for_test,
        private_oram_mutation_authority_key_v2, private_oram_mutation_legacy_authority_v2,
    };
    use crate::content_manager::consensus_ops::{
        PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION, PrivateOramMutationLease,
        PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
    };
    use crate::content_manager::private_oram_mutation_journal::private_oram_mutation_append_fixture_for_test;

    fn digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn floor_input(
        format_epoch: u64,
        membership_generation: u64,
        activation_enabled: bool,
        index: u64,
    ) -> PrivateOramMutationFormatFloorTestInputV2 {
        PrivateOramMutationFormatFloorTestInputV2 {
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            format_epoch,
            minimum_reader_protocol: 2,
            minimum_writer_protocol: 2,
            snapshot_format_epoch: format_epoch,
            membership_generation,
            eligible_peer_set_digest: digest(3_u8.wrapping_add(format_epoch as u8)),
            eligible_process_incarnations_digest: digest(13_u8.wrapping_add(format_epoch as u8)),
            capability_manifest_digest: digest(23_u8.wrapping_add(format_epoch as u8)),
            required_binary_capability_digest: digest(33_u8.wrapping_add(format_epoch as u8)),
            activation_enabled,
            term: 1,
            index,
        }
    }

    fn slot() -> PrivateOramMutationLeaseSlotV2 {
        PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        }
    }

    fn legacy_authority() -> PrivateOramMutationAuthorityStateV2 {
        private_oram_mutation_legacy_authority_v2(
            private_oram_mutation_authority_key_v2(
                "collection-a",
                digest(1),
                digest(2),
                digest(30),
            )
            .unwrap(),
            slot(),
            digest(31),
        )
        .unwrap()
    }

    fn activated_authority() -> PrivateOramMutationAuthorityStateV2 {
        activate_private_oram_mutation_authority_v2(
            &legacy_authority(),
            "collection-a",
            private_oram_mutation_activation_context_for_test(
                digest(1),
                digest(2),
                1,
                10,
                2,
                digest(32),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn activation_floor() -> PrivateOramMutationFormatFloorV2 {
        private_oram_mutation_format_floor_for_test(floor_input(2, 2, true, 6)).unwrap()
    }

    #[test]
    fn format_floor_requires_genesis_then_immediate_monotonic_successors() {
        let genesis =
            private_oram_mutation_format_floor_for_test(floor_input(1, 1, false, 5)).unwrap();
        assert_eq!(
            plan_private_oram_mutation_format_floor_transition_v2(None, &genesis).unwrap(),
            genesis
        );
        assert_eq!(genesis.format_epoch(), 1);
        assert!(!genesis.activation_enabled());
        let activated = activation_floor();
        assert!(activated.activation_enabled());
        assert_eq!(
            plan_private_oram_mutation_format_floor_transition_v2(Some(&genesis), &activated)
                .unwrap(),
            activated
        );

        let illegal_genesis =
            private_oram_mutation_format_floor_for_test(floor_input(1, 1, true, 5)).unwrap();
        assert!(matches!(
            plan_private_oram_mutation_format_floor_transition_v2(None, &illegal_genesis),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let skipped =
            private_oram_mutation_format_floor_for_test(floor_input(3, 3, true, 7)).unwrap();
        assert!(matches!(
            plan_private_oram_mutation_format_floor_transition_v2(Some(&genesis), &skipped),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        assert!(matches!(
            plan_private_oram_mutation_format_floor_transition_v2(Some(&activated), &genesis),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn format_floor_rejects_membership_evidence_change_without_generation_advance() {
        let genesis =
            private_oram_mutation_format_floor_for_test(floor_input(1, 1, false, 5)).unwrap();
        let candidate =
            private_oram_mutation_format_floor_for_test(floor_input(2, 1, false, 6)).unwrap();
        assert!(matches!(
            plan_private_oram_mutation_format_floor_transition_v2(Some(&genesis), &candidate),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut binary_only_input = floor_input(2, 1, false, 6);
        binary_only_input.eligible_peer_set_digest = genesis.eligible_peer_set_digest.clone();
        binary_only_input.eligible_process_incarnations_digest =
            genesis.eligible_process_incarnations_digest.clone();
        binary_only_input.capability_manifest_digest = genesis.capability_manifest_digest.clone();
        binary_only_input.required_binary_capability_digest = digest(99);
        let binary_only_candidate =
            private_oram_mutation_format_floor_for_test(binary_only_input).unwrap();
        assert!(matches!(
            plan_private_oram_mutation_format_floor_transition_v2(
                Some(&genesis),
                &binary_only_candidate,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn activated_authority_floor_rejects_omission_legacy_and_global_rollback() {
        let format_floor = activation_floor();
        let activated = activated_authority();
        let floor = plan_private_oram_mutation_authority_floor_acceptance_v2(
            None,
            &format_floor,
            &activated,
            10,
        )
        .unwrap();
        assert_eq!(floor.maximum_authority_ordinal(), 1);

        let decoded_activated = decode_private_oram_mutation_authority_wire_json_v2(
            &encode_private_oram_mutation_tagged_authority_wire_json_v2(&activated).unwrap(),
        )
        .unwrap();
        let advanced_cursor = plan_private_oram_mutation_snapshot_authority_acceptance_v2(
            &floor,
            &format_floor,
            Some(&decoded_activated),
            12,
        )
        .unwrap();
        assert_eq!(advanced_cursor.maximum_authority_ordinal(), 1);

        let raw = decode_private_oram_mutation_authority_wire_json_v2(
            &serde_json::to_vec(&slot()).unwrap(),
        )
        .unwrap();
        let tagged_legacy = decode_private_oram_mutation_authority_wire_json_v2(
            &encode_private_oram_mutation_tagged_authority_wire_json_v2(&legacy_authority())
                .unwrap(),
        )
        .unwrap();
        for candidate in [None, Some(&raw), Some(&tagged_legacy)] {
            assert!(matches!(
                plan_private_oram_mutation_snapshot_authority_acceptance_v2(
                    &floor,
                    &format_floor,
                    candidate,
                    12,
                ),
                Err(PrivateOramMutationJournalError::InvalidTransition)
            ));
        }
        assert!(matches!(
            plan_private_oram_mutation_snapshot_authority_acceptance_v2(
                &advanced_cursor,
                &format_floor,
                Some(&decoded_activated),
                11,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn authority_floor_remains_valid_after_a_later_format_epoch() {
        let activation = activation_floor();
        let later_format =
            private_oram_mutation_format_floor_for_test(floor_input(3, 3, true, 12)).unwrap();
        plan_private_oram_mutation_format_floor_transition_v2(Some(&activation), &later_format)
            .unwrap();

        let floor = plan_private_oram_mutation_authority_floor_acceptance_v2(
            None,
            &later_format,
            &activated_authority(),
            12,
        )
        .unwrap();
        assert_eq!(floor.compatibility_epoch, 2);
        assert_eq!(floor.maximum_authority_ordinal(), 1);
    }

    #[test]
    fn authority_floor_advances_only_with_a_later_ordinal_and_locator() {
        let format_floor = activation_floor();
        let activated = activated_authority();
        let floor = plan_private_oram_mutation_authority_floor_acceptance_v2(
            None,
            &format_floor,
            &activated,
            10,
        )
        .unwrap();
        let lease = PrivateOramMutationLease {
            generation: 1,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 7,
            mutation_id: digest(40),
            signed_mutation_digest: digest(41),
            transition_digest: digest(42),
            base_record_digest: digest(43),
            base_state_sequence: 0,
            writer_lease_digest: digest(44),
            writer_fence: 1,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let (reservation, _) = private_oram_mutation_append_fixture_for_test(
            &lease,
            activated
                .aggregate()
                .unwrap()
                .append_authority_context()
                .unwrap(),
            1,
            &[7],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(45)),
        );
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[51; 32]).unwrap();
        let owner_store_incarnation_digest = digest(52);
        let prepared =
            prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
                version: 0,
                consensus_history_id_digest: reservation.consensus_history_id_digest().to_string(),
                raft_group_id_digest: reservation.raft_group_id_digest().to_string(),
                collection_id: reservation.collection_id().to_string(),
                collection_lifetime_id_digest: reservation
                    .collection_lifetime_id_digest()
                    .to_string(),
                collection_incarnation_digest: reservation
                    .collection_incarnation_digest()
                    .to_string(),
                activation_anchor_digest: reservation.activation_anchor_digest().to_string(),
                capability_epoch: 2,
                protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
                membership_epoch: 7,
                owner_enrollment_id: digest(53),
                owner_peer_id: 7,
                owner_signer: private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap(),
                owner_store_incarnation_digest: owner_store_incarnation_digest.clone(),
                expected_genesis_state: private_oram_owner_lifecycle_genesis_state_v1(
                    owner_store_incarnation_digest,
                )
                .unwrap(),
                authority_registry_digest: digest(54),
                owner_registry_digest: digest(55),
                enrollment_operation_id: digest(56),
                prepared_record_digest: String::new(),
            })
            .unwrap();
        let request_digest = prepared.prepared_record_digest.clone();
        let reserved = apply_private_oram_mutation_authority_owner_enrollment_prepared_v2(
            &activated,
            prepared,
            private_oram_mutation_aggregate_apply_context_for_test(
                &activated,
                PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared,
                request_digest,
                1,
                11,
            )
            .unwrap(),
        )
        .unwrap();
        let advanced = plan_private_oram_mutation_authority_floor_acceptance_v2(
            Some(&floor),
            &format_floor,
            &reserved,
            11,
        )
        .unwrap();
        assert_eq!(advanced.maximum_authority_ordinal(), 2);
        assert!(matches!(
            plan_private_oram_mutation_authority_floor_acceptance_v2(
                Some(&advanced),
                &format_floor,
                &activated,
                12,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn floor_codecs_reject_unknown_fields_and_digest_tampering() {
        let format_floor = activation_floor();
        let mut missing_binary_digest = serde_json::to_value(&format_floor).unwrap();
        missing_binary_digest
            .as_object_mut()
            .unwrap()
            .remove("required_binary_capability_digest");
        assert!(
            serde_json::from_value::<PrivateOramMutationFormatFloorV2>(missing_binary_digest)
                .is_err()
        );

        let mut format_json = serde_json::to_value(&format_floor).unwrap();
        format_json
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), serde_json::json!(1));
        assert!(serde_json::from_value::<PrivateOramMutationFormatFloorV2>(format_json).is_err());

        let mut tampered = format_floor.clone();
        tampered.floor_digest = digest(99);
        assert!(matches!(
            validate_private_oram_mutation_format_floor_v2(&tampered),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        let debug = format!("{format_floor:?}");
        for secret in [
            digest(1),
            digest(2),
            digest(3),
            digest(13),
            digest(23),
            digest(35),
        ] {
            assert!(!debug.contains(&secret), "{debug}");
        }
    }

    #[test]
    fn floor_digests_match_known_answer_vectors() {
        let format_floor = activation_floor();
        assert_eq!(
            format_floor.floor_digest,
            "5Sh6_SDBwko9xTwYmvtyAt_kJoSbxaYryDJ7ZLZf2u0"
        );

        let authority_floor = plan_private_oram_mutation_authority_floor_acceptance_v2(
            None,
            &format_floor,
            &activated_authority(),
            10,
        )
        .unwrap();
        assert_eq!(
            authority_floor.floor_digest,
            "AjDiVC1ZUooHpzCZb77GfXjpxTkqdWFWBXakC9mSZ1c"
        );
    }
}
