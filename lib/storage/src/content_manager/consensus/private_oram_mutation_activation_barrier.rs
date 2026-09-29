//! Applied-entry validation for the irreversible private-ORAM mutation V2 activation barrier.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION, PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
    PrivateOramActivationPeerUriSchemeV1, PrivateOramConsensusConfigurationV1,
    PrivateOramMixedVersionActivationProofV1, private_oram_consensus_configuration_member_ids_v1,
    try_private_oram_activation_peer_uri_digest_v1,
    validate_private_oram_mixed_version_activation_proof_v1,
};
use raft::eraftpb::ConfState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::private_oram_activation_authority::PrivateOramActivationAuthorityCurrentAtReadV1;
use super::private_oram_mutation_cleanup::format::{
    PrivateOramMutationFormatFloorBarrierInputV2, PrivateOramMutationFormatFloorV2,
    plan_private_oram_mutation_format_floor_transition_v2,
    private_oram_mutation_format_floor_from_barrier_v2,
    validate_private_oram_mutation_format_floor_v2,
};
use crate::content_manager::consensus_ops::{
    PrivateOramMutationActivationBarrierPhaseV2, PrivateOramMutationActivationBarrierV2,
};
use crate::content_manager::errors::StorageError;
use crate::types::PeerAddressById;

const CONSENSUS_HISTORY_ID_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-consensus-history-id/v2";
const RAFT_GROUP_ID_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-raft-group-id/v2";
const ACTIVATION_PENDING_VERSION_V2: u16 = 1;

/// Durable recovery token installed by the first activation barrier and consumed by the second.
///
/// The complete, canonical proof is retained because a leader or process may change between the
/// two committed entries. It is public evidence, but its body and digest are still redacted from
/// diagnostics to keep request-derived material out of logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationActivationPendingV2 {
    version: u16,
    prepare_operation: PrivateOramMutationActivationBarrierV2,
    prepare_entry_term: u64,
    prepare_entry_index: u64,
}

impl Debug for PrivateOramMutationActivationPendingV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationActivationPendingV2")
            .field("version", &self.version)
            .field("prepare_entry_term", &self.prepare_entry_term)
            .field("prepare_entry_index", &self.prepare_entry_index)
            .field("prepare_operation", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationActivationPendingV2 {
    fn from_verified_prepare(
        operation: &PrivateOramMutationActivationBarrierV2,
        facts: PrivateOramMutationActivationApplyFactsV2,
    ) -> Result<Self, StorageError> {
        let pending = Self {
            version: ACTIVATION_PENDING_VERSION_V2,
            prepare_operation: operation.clone(),
            prepare_entry_term: facts.entry_term,
            prepare_entry_index: facts.entry_index,
        };
        pending.validate()?;
        Ok(pending)
    }

    fn validate(&self) -> Result<PrivateOramMixedVersionActivationProofV1, StorageError> {
        let invalid = || {
            StorageError::bad_request("private ORAM mutation activation recovery state is invalid")
        };
        if self.version != ACTIVATION_PENDING_VERSION_V2
            || self.prepare_entry_term == 0
            || !matches!(
                self.prepare_operation.phase(),
                PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites
                    | PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads
            )
        {
            return Err(invalid());
        }
        let proof = self.prepare_operation.decode_proof()?;
        if proof.expected_current_term() != self.prepare_entry_term
            || proof
                .expected_hard_commit()
                .checked_add(1)
                .is_none_or(|index| index != self.prepare_entry_index)
        {
            return Err(invalid());
        }
        Ok(proof)
    }

    pub(crate) fn enable_operation(
        &self,
    ) -> Result<PrivateOramMutationActivationBarrierV2, StorageError> {
        let phase = match self.prepare_operation.phase() {
            PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites => {
                PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2
            }
            PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => {
                PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes
            }
            _ => {
                return Err(StorageError::bad_request(
                    "private ORAM mutation activation recovery state is invalid",
                ));
            }
        };
        PrivateOramMutationActivationBarrierV2::try_new(phase, &self.validate()?)
    }

    pub(crate) fn prepare_phase(&self) -> PrivateOramMutationActivationBarrierPhaseV2 {
        self.prepare_operation.phase()
    }

    pub(crate) fn prepare_entry_term(&self) -> u64 {
        self.prepare_entry_term
    }

    pub(crate) fn prepare_entry_index(&self) -> u64 {
        self.prepare_entry_index
    }
}

pub(crate) fn validate_private_oram_mutation_activation_pending_v2(
    pending: Option<&PrivateOramMutationActivationPendingV2>,
    format_floor: Option<&PrivateOramMutationFormatFloorV2>,
    applied_index: u64,
    activation_authority_present: bool,
) -> Result<(), StorageError> {
    let invalid =
        || StorageError::bad_request("private ORAM mutation activation recovery state is invalid");
    let Some(format_floor) = format_floor else {
        return if pending.is_none() {
            Ok(())
        } else {
            Err(invalid())
        };
    };
    validate_private_oram_mutation_format_floor_v2(format_floor).map_err(|_| invalid())?;

    let Some(pending) = pending else {
        if format_floor.activation_enabled() {
            return Ok(());
        }
        // Synthetic pre-release floor fixtures did not retain the proof. A real activation floor
        // always has an externally anchored authority and must therefore carry recovery state.
        return if activation_authority_present {
            Err(invalid())
        } else {
            Ok(())
        };
    };
    let proof = pending.validate()?;
    if pending.prepare_entry_index > applied_index {
        return Err(invalid());
    }
    let (format_epoch, minimum_reader_protocol, minimum_writer_protocol, activation_enabled) =
        match pending.prepare_phase() {
            PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites => (
                1,
                proof.required_consensus_wire_protocol(),
                proof.required_consensus_wire_protocol(),
                false,
            ),
            PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => (
                3,
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION,
                true,
            ),
            _ => return Err(invalid()),
        };
    let expected_floor = private_oram_mutation_format_floor_from_barrier_v2(
        PrivateOramMutationFormatFloorBarrierInputV2 {
            consensus_history_id_digest: format_floor.consensus_history_id_digest().to_string(),
            raft_group_id_digest: format_floor.raft_group_id_digest().to_string(),
            format_epoch,
            minimum_reader_protocol,
            minimum_writer_protocol,
            snapshot_format_epoch: format_epoch,
            membership_generation: proof.expected_hard_commit(),
            eligible_peer_set_digest: proof.eligible_peer_set_digest().to_string(),
            eligible_process_incarnations_digest: proof
                .eligible_process_incarnations_digest()
                .to_string(),
            capability_manifest_digest: proof.expected_runtime_capability_fingerprint().to_string(),
            activation_enabled,
            term: pending.prepare_entry_term,
            index: pending.prepare_entry_index,
        },
    )
    .map_err(|_| invalid())?;
    if format_floor != &expected_floor {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) struct VerifiedPrivateOramMutationActivationBarrierV2 {
    proof: PrivateOramMixedVersionActivationProofV1,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    next_format_floor: PrivateOramMutationFormatFloorV2,
    next_pending: Option<PrivateOramMutationActivationPendingV2>,
}

impl VerifiedPrivateOramMutationActivationBarrierV2 {
    pub(crate) fn proof(&self) -> &PrivateOramMixedVersionActivationProofV1 {
        &self.proof
    }

    pub(crate) fn consensus_history_id_digest(&self) -> &str {
        &self.consensus_history_id_digest
    }

    pub(crate) fn raft_group_id_digest(&self) -> &str {
        &self.raft_group_id_digest
    }

    pub(crate) fn next_format_floor(&self) -> &PrivateOramMutationFormatFloorV2 {
        &self.next_format_floor
    }

    pub(crate) fn next_pending(&self) -> Option<&PrivateOramMutationActivationPendingV2> {
        self.next_pending.as_ref()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PrivateOramMutationActivationApplyFactsV2 {
    pub(crate) entry_term: u64,
    pub(crate) entry_index: u64,
    pub(crate) prior_applied_index: u64,
    pub(crate) barrier_base_entry_term: u64,
}

pub(crate) fn validate_private_oram_mutation_activation_barrier_v2(
    operation: &PrivateOramMutationActivationBarrierV2,
    authority: &PrivateOramActivationAuthorityCurrentAtReadV1,
    current_format_floor: Option<&PrivateOramMutationFormatFloorV2>,
    current_pending: Option<&PrivateOramMutationActivationPendingV2>,
    conf_state: &ConfState,
    peer_addresses: &PeerAddressById,
    facts: PrivateOramMutationActivationApplyFactsV2,
) -> Result<VerifiedPrivateOramMutationActivationBarrierV2, StorageError> {
    let invalid =
        || StorageError::bad_request("private ORAM mutation activation barrier is invalid");
    let proof = operation.decode_proof()?;
    let verified_authority = authority.verified_manifest().ok_or_else(invalid)?;
    let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
        &conf_state.voters,
        &conf_state.voters_outgoing,
        &conf_state.learners,
        &conf_state.learners_next,
        conf_state.auto_leave,
    )
    .map_err(|_| invalid())?;
    if !configuration.voters_outgoing().is_empty()
        || !configuration.learners().is_empty()
        || !configuration.learners_next().is_empty()
        || configuration.auto_leave()
        || proof.configuration() != &configuration
        || proof.expected_commit_entry_term() != facts.barrier_base_entry_term
    {
        return Err(invalid());
    }

    let base_index = proof.expected_hard_commit();
    let expected_entry_index = match operation.phase() {
        PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites
        | PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => {
            if proof.expected_current_term() != facts.entry_term || current_pending.is_some() {
                return Err(invalid());
            }
            base_index.checked_add(1).ok_or_else(invalid)?
        }
        PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2
        | PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes => {
            let pending = current_pending.ok_or_else(invalid)?;
            let expected_operation = pending.enable_operation()?;
            if operation != &expected_operation
                || proof.expected_current_term() != pending.prepare_entry_term()
                || facts.entry_term < pending.prepare_entry_term()
                || facts.entry_index <= pending.prepare_entry_index()
            {
                return Err(invalid());
            }
            facts.entry_index
        }
    };
    if facts.entry_index != expected_entry_index
        || facts.prior_applied_index != facts.entry_index.saturating_sub(1)
    {
        return Err(invalid());
    }

    let members = private_oram_consensus_configuration_member_ids_v1(&configuration)
        .map_err(|_| invalid())?;
    let mut peer_uri_digests = BTreeMap::new();
    for peer_id in members {
        let uri = peer_addresses.get(&peer_id).ok_or_else(invalid)?;
        let digest = private_oram_activation_uri_digest(uri).map_err(|_| invalid())?;
        peer_uri_digests.insert(peer_id, digest);
    }
    let _verified = validate_private_oram_mixed_version_activation_proof_v1(
        &proof,
        verified_authority,
        &peer_uri_digests,
    )
    .map_err(|_| invalid())?;

    let manifest = verified_authority.manifest();
    let (consensus_history_id_digest, raft_group_id_digest) =
        private_oram_activation_history_and_group_digests(
            &manifest.cluster_identity_digest,
            manifest.cluster_first_voter_peer_id,
        )
        .map_err(|_| invalid())?;

    let (format_epoch, minimum_reader_protocol, minimum_writer_protocol, activation_enabled) =
        match operation.phase() {
            PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites => (
                1,
                proof.required_consensus_wire_protocol(),
                proof.required_consensus_wire_protocol(),
                false,
            ),
            PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2 => (
                2,
                proof.required_consensus_wire_protocol(),
                proof.required_consensus_wire_protocol(),
                true,
            ),
            PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => (
                3,
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION,
                true,
            ),
            PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes => (
                4,
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                true,
            ),
        };
    if matches!(
        operation.phase(),
        PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads
            | PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes
    ) && proof.required_consensus_wire_protocol() != PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
    {
        return Err(invalid());
    };
    let next_format_floor = private_oram_mutation_format_floor_from_barrier_v2(
        PrivateOramMutationFormatFloorBarrierInputV2 {
            consensus_history_id_digest: consensus_history_id_digest.clone(),
            raft_group_id_digest: raft_group_id_digest.clone(),
            format_epoch,
            minimum_reader_protocol,
            minimum_writer_protocol,
            snapshot_format_epoch: format_epoch,
            membership_generation: proof.expected_hard_commit(),
            eligible_peer_set_digest: proof.eligible_peer_set_digest().to_string(),
            eligible_process_incarnations_digest: proof
                .eligible_process_incarnations_digest()
                .to_string(),
            capability_manifest_digest: proof.expected_runtime_capability_fingerprint().to_string(),
            activation_enabled,
            term: facts.entry_term,
            index: facts.entry_index,
        },
    )
    .map_err(|_| invalid())?;

    match operation.phase() {
        PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites => {
            if current_format_floor.is_some() || current_pending.is_some() {
                return Err(invalid());
            }
        }
        PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2 => {
            let expected_prepare_floor = private_oram_mutation_format_floor_from_barrier_v2(
                PrivateOramMutationFormatFloorBarrierInputV2 {
                    consensus_history_id_digest: consensus_history_id_digest.clone(),
                    raft_group_id_digest: raft_group_id_digest.clone(),
                    format_epoch: 1,
                    minimum_reader_protocol: proof.required_consensus_wire_protocol(),
                    minimum_writer_protocol: proof.required_consensus_wire_protocol(),
                    snapshot_format_epoch: 1,
                    membership_generation: proof.expected_hard_commit(),
                    eligible_peer_set_digest: proof.eligible_peer_set_digest().to_string(),
                    eligible_process_incarnations_digest: proof
                        .eligible_process_incarnations_digest()
                        .to_string(),
                    capability_manifest_digest: proof
                        .expected_runtime_capability_fingerprint()
                        .to_string(),
                    activation_enabled: false,
                    term: current_pending.ok_or_else(invalid)?.prepare_entry_term(),
                    index: current_pending.ok_or_else(invalid)?.prepare_entry_index(),
                },
            )
            .map_err(|_| invalid())?;
            if current_format_floor != Some(&expected_prepare_floor) {
                return Err(invalid());
            }
        }
        PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => {
            let floor = current_format_floor.ok_or_else(invalid)?;
            if current_pending.is_some()
                || !floor.activation_enabled()
                || floor.format_epoch() != 2
                || floor.snapshot_format_epoch() != 2
                || floor.minimum_reader_protocol()
                    != PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
                || floor.minimum_writer_protocol()
                    != PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
            {
                return Err(invalid());
            }
        }
        PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes => {
            let pending = current_pending.ok_or_else(invalid)?;
            if pending.prepare_phase()
                != PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads
            {
                return Err(invalid());
            }
            let expected_prepare_floor = private_oram_mutation_format_floor_from_barrier_v2(
                PrivateOramMutationFormatFloorBarrierInputV2 {
                    consensus_history_id_digest: consensus_history_id_digest.clone(),
                    raft_group_id_digest: raft_group_id_digest.clone(),
                    format_epoch: 3,
                    minimum_reader_protocol: PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                    minimum_writer_protocol: PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION,
                    snapshot_format_epoch: 3,
                    membership_generation: proof.expected_hard_commit(),
                    eligible_peer_set_digest: proof.eligible_peer_set_digest().to_string(),
                    eligible_process_incarnations_digest: proof
                        .eligible_process_incarnations_digest()
                        .to_string(),
                    capability_manifest_digest: proof
                        .expected_runtime_capability_fingerprint()
                        .to_string(),
                    activation_enabled: true,
                    term: pending.prepare_entry_term(),
                    index: pending.prepare_entry_index(),
                },
            )
            .map_err(|_| invalid())?;
            if current_format_floor != Some(&expected_prepare_floor) {
                return Err(invalid());
            }
        }
    }
    plan_private_oram_mutation_format_floor_transition_v2(current_format_floor, &next_format_floor)
        .map_err(|_| invalid())?;

    let next_pending = match operation.phase() {
        PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites
        | PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => {
            Some(PrivateOramMutationActivationPendingV2::from_verified_prepare(operation, facts)?)
        }
        PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2
        | PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes => None,
    };

    Ok(VerifiedPrivateOramMutationActivationBarrierV2 {
        proof,
        consensus_history_id_digest,
        raft_group_id_digest,
        next_format_floor,
        next_pending,
    })
}

pub(crate) fn private_oram_activation_uri_digest(uri: &http::Uri) -> Result<String, ()> {
    let scheme = match uri.scheme_str() {
        Some("http") => PrivateOramActivationPeerUriSchemeV1::Http,
        Some("https") => PrivateOramActivationPeerUriSchemeV1::Https,
        _ => return Err(()),
    };
    if uri
        .path_and_query()
        .is_some_and(|path| path.as_str() != "/")
    {
        return Err(());
    }
    // Host names are case-insensitive and `http::Uri` preserves the configured case, so the
    // canonical (lowercase) form is what gets pinned; bracketed IPv6 literals are handled by
    // the digest function.
    let host = uri.host().ok_or(())?.to_ascii_lowercase();
    let port = uri.port_u16().unwrap_or(match scheme {
        PrivateOramActivationPeerUriSchemeV1::Http => 80,
        PrivateOramActivationPeerUriSchemeV1::Https => 443,
    });
    try_private_oram_activation_peer_uri_digest_v1(scheme, &host, port).map_err(|_| ())
}

fn private_oram_activation_history_and_group_digests(
    cluster_identity_digest: &str,
    cluster_first_voter_peer_id: u64,
) -> Result<(String, String), ()> {
    let cluster_identity = BASE64URL_NOPAD
        .decode(cluster_identity_digest.as_bytes())
        .map_err(|_| ())?;
    if cluster_identity.len() != 32
        || BASE64URL_NOPAD.encode(&cluster_identity) != cluster_identity_digest
        || cluster_first_voter_peer_id == 0
    {
        return Err(());
    }
    let mut history_hasher = Sha256::new();
    history_hasher.update(CONSENSUS_HISTORY_ID_DIGEST_DOMAIN_V2);
    history_hasher.update(&cluster_identity);
    let consensus_history_id_digest = BASE64URL_NOPAD.encode(&history_hasher.finalize());

    let mut group_hasher = Sha256::new();
    group_hasher.update(RAFT_GROUP_ID_DIGEST_DOMAIN_V2);
    group_hasher.update(
        BASE64URL_NOPAD
            .decode(consensus_history_id_digest.as_bytes())
            .map_err(|_| ())?,
    );
    group_hasher.update(cluster_first_voter_peer_id.to_be_bytes());
    let raft_group_id_digest = BASE64URL_NOPAD.encode(&group_hasher.finalize());
    Ok((consensus_history_id_digest, raft_group_id_digest))
}

#[cfg(test)]
pub(crate) struct PrivateOramMutationActivationBarrierFixtureV2 {
    pub(crate) authority: PrivateOramActivationAuthorityCurrentAtReadV1,
    pub(crate) conf_state: ConfState,
    pub(crate) peer_addresses: PeerAddressById,
    pub(crate) prepare_operation: PrivateOramMutationActivationBarrierV2,
    pub(crate) enable_operation: PrivateOramMutationActivationBarrierV2,
    pub(crate) base_index: u64,
    pub(crate) current_term: u64,
    pub(crate) base_entry_term: u64,
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_activation_barrier_fixture_v2_for_test()
-> PrivateOramMutationActivationBarrierFixtureV2 {
    private_oram_mutation_activation_barrier_fixture_for_test(
        PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION,
        101,
        4,
        3,
        PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites,
        PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2,
    )
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_v3_floor_upgrade_fixture_for_test(
    base_index: u64,
    current_term: u64,
    base_entry_term: u64,
) -> PrivateOramMutationActivationBarrierFixtureV2 {
    private_oram_mutation_activation_barrier_fixture_for_test(
        PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
        base_index,
        current_term,
        base_entry_term,
        PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads,
        PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes,
    )
}

#[cfg(test)]
fn private_oram_mutation_activation_barrier_fixture_for_test(
    required_consensus_wire_protocol: u16,
    base_index: u64,
    current_term: u64,
    base_entry_term: u64,
    prepare_phase: PrivateOramMutationActivationBarrierPhaseV2,
    enable_phase: PrivateOramMutationActivationBarrierPhaseV2,
) -> PrivateOramMutationActivationBarrierFixtureV2 {
    use qdrant_sec::{
        PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION,
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION, PrivateOramPeerActivationChallengeV1,
        PrivateOramPeerActivationEvidenceV1, PrivateOramPeerActivationObservationV1,
        package_private_oram_mixed_version_activation_proof_v1,
        sign_private_oram_peer_activation_ack_v1,
        try_private_oram_consensus_configuration_digest_v1,
    };
    use ring::signature::Ed25519KeyPair;

    use super::private_oram_activation_authority::{
        PrivateOramActivationAuthorityStoreInstanceId,
        plan_private_oram_activation_authority_cas_v1,
        private_oram_activation_authority_fixture_v1_for_test,
        verify_private_oram_activation_authority_current_at_read_v1,
    };

    let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
    let store_instance_id = PrivateOramActivationAuthorityStoreInstanceId::default();
    let empty = verify_private_oram_activation_authority_current_at_read_v1(
        None,
        &trust_anchor,
        store_instance_id,
    )
    .unwrap();
    let authority_state = plan_private_oram_activation_authority_cas_v1(
        None,
        empty,
        &bundle,
        &trust_anchor,
        store_instance_id,
    )
    .unwrap();
    let authority = verify_private_oram_activation_authority_current_at_read_v1(
        Some(&authority_state),
        &trust_anchor,
        store_instance_id,
    )
    .unwrap();
    let verified_authority = authority.verified_manifest().unwrap();

    let conf_state = ConfState {
        voters: vec![11, 13],
        ..Default::default()
    };
    let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
        &conf_state.voters,
        &conf_state.voters_outgoing,
        &conf_state.learners,
        &conf_state.learners_next,
        conf_state.auto_leave,
    )
    .unwrap();
    let configuration_digest =
        try_private_oram_consensus_configuration_digest_v1(&configuration).unwrap();
    let peer_addresses = [
        (11, "https://node-11.internal:6335"),
        (13, "https://node-13.internal:6335"),
    ]
    .into_iter()
    .map(|(peer_id, uri)| (peer_id, uri.parse().unwrap()))
    .collect::<PeerAddressById>();
    let peer_uri_digests = peer_addresses
        .iter()
        .map(|(peer_id, uri)| (*peer_id, private_oram_activation_uri_digest(uri).unwrap()))
        .collect::<BTreeMap<_, _>>();

    let digest = |byte: u8| BASE64URL_NOPAD.encode(&[byte; 32]);
    let evidence = [(11, 21_u8), (13, 22_u8)]
        .into_iter()
        .map(|(peer_id, seed)| {
            let challenge = PrivateOramPeerActivationChallengeV1 {
                protocol_version: PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
                activation_id: digest(20),
                activation_generation: 1,
                challenge_nonce: digest(30 + seed),
                cluster_identity_digest: verified_authority
                    .manifest()
                    .cluster_identity_digest
                    .clone(),
                cluster_first_voter_peer_id: verified_authority
                    .manifest()
                    .cluster_first_voter_peer_id,
                coordinator_peer_id: 11,
                target_peer_id: peer_id,
                target_peer_uri_digest: peer_uri_digests[&peer_id].clone(),
                membership_generation: base_index,
                required_consensus_wire_protocol,
                expected_current_term: current_term,
                expected_hard_commit: base_index,
                expected_last_applied: base_index,
                expected_last_log_index: base_index,
                expected_pending_conf_index: 0,
                expected_commit_entry_term: base_entry_term,
                expected_configuration_digest: configuration_digest.clone(),
                expected_runtime_capability_fingerprint: digest(40),
                pin_registry_generation: verified_authority.manifest().registry_generation,
                pin_registry_digest: verified_authority.manifest_digest().to_string(),
                required_capability: verified_authority.manifest().required_capability.clone(),
                required_binary_capability_digest: verified_authority
                    .manifest()
                    .required_binary_capability_digest
                    .clone(),
            };
            let observation = PrivateOramPeerActivationObservationV1 {
                responder_peer_id: peer_id,
                process_incarnation: digest(60 + seed),
                qdrant_version: "1.17.1-sec-v2".to_string(),
                capability: challenge.required_capability.clone(),
                binary_capability_digest: challenge.required_binary_capability_digest.clone(),
                cluster_identity_digest: challenge.cluster_identity_digest.clone(),
                runtime_capability_fingerprint: challenge
                    .expected_runtime_capability_fingerprint
                    .clone(),
                membership_generation: challenge.membership_generation,
                supported_consensus_wire_protocol_min:
                    PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION,
                supported_consensus_wire_protocol_max: PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                observed_current_term: challenge.expected_current_term,
                observed_hard_commit: challenge.expected_hard_commit,
                observed_last_applied: challenge.expected_last_applied,
                observed_last_log_index: challenge.expected_last_log_index,
                observed_pending_conf_index: challenge.expected_pending_conf_index,
                observed_commit_entry_term: challenge.expected_commit_entry_term,
                observed_configuration_digest: challenge.expected_configuration_digest.clone(),
                pin_registry_generation: challenge.pin_registry_generation,
                pin_registry_digest: challenge.pin_registry_digest.clone(),
            };
            let signer = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
            let signed_ack =
                sign_private_oram_peer_activation_ack_v1(&signer, 1, &challenge, observation)
                    .unwrap();
            PrivateOramPeerActivationEvidenceV1 {
                challenge,
                signed_ack,
            }
        })
        .collect();
    let proof = package_private_oram_mixed_version_activation_proof_v1(
        verified_authority,
        configuration,
        &peer_uri_digests,
        evidence,
    )
    .unwrap();
    let prepare_operation =
        PrivateOramMutationActivationBarrierV2::try_new(prepare_phase, &proof).unwrap();
    let enable_operation =
        PrivateOramMutationActivationBarrierV2::try_new(enable_phase, &proof).unwrap();

    PrivateOramMutationActivationBarrierFixtureV2 {
        authority,
        conf_state,
        peer_addresses,
        prepare_operation,
        enable_operation,
        base_index,
        current_term,
        base_entry_term,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_phase_barrier_survives_term_change_and_rejects_duplicate_index() {
        let fixture = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let prepared = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.prepare_operation,
            &fixture.authority,
            None,
            None,
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term,
                entry_index: fixture.base_index + 1,
                prior_applied_index: fixture.base_index,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        assert_eq!(prepared.next_format_floor().format_epoch(), 1);
        assert!(!prepared.next_format_floor().activation_enabled());
        assert!(prepared.next_format_floor().tagged_write_required());

        let enabled = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.enable_operation,
            &fixture.authority,
            Some(prepared.next_format_floor()),
            prepared.next_pending(),
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term + 1,
                entry_index: fixture.base_index + 3,
                prior_applied_index: fixture.base_index + 2,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        assert_eq!(enabled.next_format_floor().format_epoch(), 2);
        assert!(enabled.next_format_floor().activation_enabled());

        let error = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.enable_operation,
            &fixture.authority,
            Some(prepared.next_format_floor()),
            prepared.next_pending(),
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term,
                entry_index: fixture.base_index + 1,
                prior_applied_index: fixture.base_index,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("barrier is invalid"));
    }

    #[test]
    fn reservation_v3_reader_then_writer_floor_upgrades_an_active_v6_cluster() {
        let initial = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let prepared = validate_private_oram_mutation_activation_barrier_v2(
            &initial.prepare_operation,
            &initial.authority,
            None,
            None,
            &initial.conf_state,
            &initial.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: initial.current_term,
                entry_index: initial.base_index + 1,
                prior_applied_index: initial.base_index,
                barrier_base_entry_term: initial.base_entry_term,
            },
        )
        .unwrap();
        let active_v6 = validate_private_oram_mutation_activation_barrier_v2(
            &initial.enable_operation,
            &initial.authority,
            Some(prepared.next_format_floor()),
            prepared.next_pending(),
            &initial.conf_state,
            &initial.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: initial.current_term,
                entry_index: initial.base_index + 2,
                prior_applied_index: initial.base_index + 1,
                barrier_base_entry_term: initial.base_entry_term,
            },
        )
        .unwrap();
        assert_eq!(active_v6.next_format_floor().format_epoch(), 2);
        assert_eq!(
            active_v6.next_format_floor().minimum_writer_protocol(),
            PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
        );

        let upgrade = private_oram_mutation_v3_floor_upgrade_fixture_for_test(
            initial.base_index + 2,
            initial.current_term,
            initial.current_term,
        );
        let readers_v7 = validate_private_oram_mutation_activation_barrier_v2(
            &upgrade.prepare_operation,
            &upgrade.authority,
            Some(active_v6.next_format_floor()),
            active_v6.next_pending(),
            &upgrade.conf_state,
            &upgrade.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: upgrade.current_term,
                entry_index: upgrade.base_index + 1,
                prior_applied_index: upgrade.base_index,
                barrier_base_entry_term: upgrade.base_entry_term,
            },
        )
        .unwrap();
        assert_eq!(readers_v7.next_format_floor().format_epoch(), 3);
        assert_eq!(
            readers_v7.next_format_floor().minimum_reader_protocol(),
            PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
        );
        assert_eq!(
            readers_v7.next_format_floor().minimum_writer_protocol(),
            PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
        );
        assert!(readers_v7.next_format_floor().activation_enabled());
        validate_private_oram_mutation_activation_pending_v2(
            readers_v7.next_pending(),
            Some(readers_v7.next_format_floor()),
            upgrade.base_index + 1,
            true,
        )
        .unwrap();

        let writers_v7 = validate_private_oram_mutation_activation_barrier_v2(
            &upgrade.enable_operation,
            &upgrade.authority,
            Some(readers_v7.next_format_floor()),
            readers_v7.next_pending(),
            &upgrade.conf_state,
            &upgrade.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: upgrade.current_term + 1,
                entry_index: upgrade.base_index + 2,
                prior_applied_index: upgrade.base_index + 1,
                barrier_base_entry_term: upgrade.base_entry_term,
            },
        )
        .unwrap();
        assert_eq!(writers_v7.next_format_floor().format_epoch(), 4);
        assert_eq!(
            writers_v7.next_format_floor().minimum_reader_protocol(),
            PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
        );
        assert_eq!(
            writers_v7.next_format_floor().minimum_writer_protocol(),
            PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
        );
        assert!(writers_v7.next_pending().is_none());
    }

    #[test]
    fn barrier_rejects_topology_uri_and_term_drift() {
        let fixture = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let facts = PrivateOramMutationActivationApplyFactsV2 {
            entry_term: fixture.current_term,
            entry_index: fixture.base_index + 1,
            prior_applied_index: fixture.base_index,
            barrier_base_entry_term: fixture.base_entry_term,
        };

        let mut with_learner = fixture.conf_state.clone();
        with_learner.learners.push(17);
        assert!(
            validate_private_oram_mutation_activation_barrier_v2(
                &fixture.prepare_operation,
                &fixture.authority,
                None,
                None,
                &with_learner,
                &fixture.peer_addresses,
                facts,
            )
            .is_err()
        );

        let mut changed_uri = fixture.peer_addresses.clone();
        changed_uri.insert(13, "https://node-13.internal:7443".parse().unwrap());
        assert!(
            validate_private_oram_mutation_activation_barrier_v2(
                &fixture.prepare_operation,
                &fixture.authority,
                None,
                None,
                &fixture.conf_state,
                &changed_uri,
                facts,
            )
            .is_err()
        );

        assert!(
            validate_private_oram_mutation_activation_barrier_v2(
                &fixture.prepare_operation,
                &fixture.authority,
                None,
                None,
                &fixture.conf_state,
                &fixture.peer_addresses,
                PrivateOramMutationActivationApplyFactsV2 {
                    entry_term: fixture.current_term + 1,
                    ..facts
                },
            )
            .is_err()
        );
    }

    #[test]
    fn pending_recovery_state_is_floor_bound_tamper_evident_and_redacted() {
        let fixture = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let prepared = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.prepare_operation,
            &fixture.authority,
            None,
            None,
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term,
                entry_index: fixture.base_index + 1,
                prior_applied_index: fixture.base_index,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        let pending = prepared.next_pending().unwrap();
        validate_private_oram_mutation_activation_pending_v2(
            Some(pending),
            Some(prepared.next_format_floor()),
            fixture.base_index + 1,
            true,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_activation_pending_v2(
                None,
                Some(prepared.next_format_floor()),
                fixture.base_index + 1,
                true,
            )
            .is_err()
        );

        let rendered = format!("{pending:?}");
        assert!(!rendered.contains(fixture.prepare_operation.proof_digest()));
        assert!(!rendered.contains("proof_canonical_json"));

        let mut tampered = serde_json::to_value(pending).unwrap();
        tampered["prepare_entry_index"] = serde_json::json!(fixture.base_index + 2);
        let tampered: PrivateOramMutationActivationPendingV2 =
            serde_json::from_value(tampered).unwrap();
        assert!(
            validate_private_oram_mutation_activation_pending_v2(
                Some(&tampered),
                Some(prepared.next_format_floor()),
                fixture.base_index + 2,
                true,
            )
            .is_err()
        );
    }
}
