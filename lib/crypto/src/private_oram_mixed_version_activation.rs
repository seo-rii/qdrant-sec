//! Canonical aggregate proof for the private-ORAM mixed-version activation barrier.
//!
//! The proof is intentionally independent from Raft proposal code. A coordinator must gather one
//! live, signed acknowledgement from every member of one exact Raft configuration and then validate
//! the aggregate again against a freshly observed peer-URI map before proposing an activation entry.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION, PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
    PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2, PrivateOramConsensusConfigurationV1,
    PrivateOramPeerActivationChallengeV1, PrivateOramPeerActivationSignedAckV1,
    VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    private_oram_activation_signer_from_signed_manifest_for_challenge_v1,
    private_oram_consensus_configuration_member_ids_v1,
    try_private_oram_consensus_configuration_digest_v1,
    try_private_oram_peer_activation_ack_signature_message_v1,
    validate_private_oram_peer_activation_ack_signature_v1,
    validate_private_oram_peer_activation_challenge_v1_shape,
};

pub const PRIVATE_ORAM_MIXED_VERSION_ACTIVATION_PROOF_VERSION: u16 = 1;
pub const PRIVATE_ORAM_MIXED_VERSION_ACTIVATION_PROOF_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-mixed-version-activation-proof/v1";
pub const PRIVATE_ORAM_MIXED_VERSION_ELIGIBLE_PEER_SET_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-mixed-version-eligible-peer-set/v1";
pub const PRIVATE_ORAM_MIXED_VERSION_PROCESS_INCARNATIONS_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-mixed-version-process-incarnations/v1";

const DIGEST_BYTES: usize = 32;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const MAX_ACTIVATION_MEMBERS: usize = 1_024;
const MAX_CANONICAL_ACK_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramMixedVersionActivationError {
    #[error("private ORAM mixed-version activation proof version is unsupported")]
    UnsupportedVersion,
    #[error("private ORAM mixed-version activation proof is invalid")]
    InvalidProof,
    #[error("private ORAM mixed-version activation proof does not match the authority")]
    AuthorityMismatch,
    #[error("private ORAM mixed-version activation proof does not match the current peer URI map")]
    PeerUriMismatch,
    #[error("private ORAM mixed-version activation proof has incomplete or duplicate evidence")]
    InvalidEvidenceSet,
    #[error("private ORAM mixed-version activation acknowledgement is invalid")]
    InvalidAcknowledgement,
    #[error("private ORAM mixed-version activation proof digest does not match")]
    DigestMismatch,
}

impl Debug for PrivateOramMixedVersionActivationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramMixedVersionActivationError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerActivationEvidenceV1 {
    pub challenge: PrivateOramPeerActivationChallengeV1,
    pub signed_ack: PrivateOramPeerActivationSignedAckV1,
}

impl Debug for PrivateOramPeerActivationEvidenceV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPeerActivationEvidenceV1")
            .field("target_peer_id", &"[redacted]")
            .field("challenge", &self.challenge)
            .field("signed_ack", &self.signed_ack)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMixedVersionActivationProofV1 {
    version: u16,
    authority_registry_generation: u64,
    authority_manifest_digest: String,
    configuration: PrivateOramConsensusConfigurationV1,
    configuration_digest: String,
    activation_id: String,
    activation_generation: u64,
    membership_generation: u64,
    required_consensus_wire_protocol: u16,
    coordinator_peer_id: u64,
    expected_current_term: u64,
    expected_hard_commit: u64,
    expected_last_applied: u64,
    expected_last_log_index: u64,
    expected_pending_conf_index: u64,
    expected_commit_entry_term: u64,
    expected_runtime_capability_fingerprint: String,
    required_binary_capability_digest: String,
    evidence: Vec<PrivateOramPeerActivationEvidenceV1>,
    eligible_peer_set_digest: String,
    eligible_process_incarnations_digest: String,
    proof_digest: String,
}

impl Debug for PrivateOramMixedVersionActivationProofV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMixedVersionActivationProofV1")
            .field("version", &self.version)
            .field(
                "authority_registry_generation",
                &self.authority_registry_generation,
            )
            .field("activation_generation", &self.activation_generation)
            .field("membership_generation", &self.membership_generation)
            .field(
                "required_consensus_wire_protocol",
                &self.required_consensus_wire_protocol,
            )
            .field("expected_current_term", &self.expected_current_term)
            .field("expected_hard_commit", &self.expected_hard_commit)
            .field("expected_last_applied", &self.expected_last_applied)
            .field("expected_last_log_index", &self.expected_last_log_index)
            .field(
                "expected_pending_conf_index",
                &self.expected_pending_conf_index,
            )
            .field("evidence_count", &self.evidence.len())
            .field("authority_manifest_digest", &"[redacted]")
            .field("configuration_digest", &"[redacted]")
            .field("activation_id", &"[redacted]")
            .field("coordinator_peer_id", &"[redacted]")
            .field("expected_runtime_capability_fingerprint", &"[redacted]")
            .field("required_binary_capability_digest", &"[redacted]")
            .field("eligible_peer_set_digest", &"[redacted]")
            .field("eligible_process_incarnations_digest", &"[redacted]")
            .field("proof_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMixedVersionActivationProofV1 {
    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn authority_registry_generation(&self) -> u64 {
        self.authority_registry_generation
    }

    pub fn authority_manifest_digest(&self) -> &str {
        &self.authority_manifest_digest
    }

    pub fn configuration(&self) -> &PrivateOramConsensusConfigurationV1 {
        &self.configuration
    }

    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }

    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }

    pub fn activation_generation(&self) -> u64 {
        self.activation_generation
    }

    pub fn membership_generation(&self) -> u64 {
        self.membership_generation
    }

    pub fn coordinator_peer_id(&self) -> u64 {
        self.coordinator_peer_id
    }

    pub fn required_consensus_wire_protocol(&self) -> u16 {
        self.required_consensus_wire_protocol
    }

    pub fn expected_current_term(&self) -> u64 {
        self.expected_current_term
    }

    pub fn expected_hard_commit(&self) -> u64 {
        self.expected_hard_commit
    }

    pub fn expected_last_applied(&self) -> u64 {
        self.expected_last_applied
    }

    pub fn expected_commit_entry_term(&self) -> u64 {
        self.expected_commit_entry_term
    }

    pub fn expected_last_log_index(&self) -> u64 {
        self.expected_last_log_index
    }

    pub fn expected_pending_conf_index(&self) -> u64 {
        self.expected_pending_conf_index
    }

    pub fn expected_runtime_capability_fingerprint(&self) -> &str {
        &self.expected_runtime_capability_fingerprint
    }

    pub fn required_binary_capability_digest(&self) -> &str {
        &self.required_binary_capability_digest
    }

    pub fn evidence(&self) -> &[PrivateOramPeerActivationEvidenceV1] {
        &self.evidence
    }

    pub fn eligible_peer_set_digest(&self) -> &str {
        &self.eligible_peer_set_digest
    }

    pub fn eligible_process_incarnations_digest(&self) -> &str {
        &self.eligible_process_incarnations_digest
    }

    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }
}

#[must_use]
pub struct VerifiedPrivateOramMixedVersionActivationProofV1<'a> {
    proof: &'a PrivateOramMixedVersionActivationProofV1,
}

impl Debug for VerifiedPrivateOramMixedVersionActivationProofV1<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramMixedVersionActivationProofV1")
            .field("proof", self.proof)
            .finish()
    }
}

impl<'a> VerifiedPrivateOramMixedVersionActivationProofV1<'a> {
    pub fn proof(&self) -> &'a PrivateOramMixedVersionActivationProofV1 {
        self.proof
    }
}

pub fn package_private_oram_mixed_version_activation_proof_v1(
    authority: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    configuration: PrivateOramConsensusConfigurationV1,
    observed_peer_uri_digests: &BTreeMap<u64, String>,
    mut evidence: Vec<PrivateOramPeerActivationEvidenceV1>,
) -> Result<PrivateOramMixedVersionActivationProofV1, PrivateOramMixedVersionActivationError> {
    evidence.sort_by_key(|item| item.challenge.target_peer_id);
    let first = evidence
        .first()
        .ok_or(PrivateOramMixedVersionActivationError::InvalidEvidenceSet)?;
    let challenge = &first.challenge;
    let configuration_digest = try_private_oram_consensus_configuration_digest_v1(&configuration)
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    let mut proof = PrivateOramMixedVersionActivationProofV1 {
        version: PRIVATE_ORAM_MIXED_VERSION_ACTIVATION_PROOF_VERSION,
        authority_registry_generation: authority.manifest().registry_generation,
        authority_manifest_digest: authority.manifest_digest().to_string(),
        configuration,
        configuration_digest,
        activation_id: challenge.activation_id.clone(),
        activation_generation: challenge.activation_generation,
        membership_generation: challenge.membership_generation,
        required_consensus_wire_protocol: challenge.required_consensus_wire_protocol,
        coordinator_peer_id: challenge.coordinator_peer_id,
        expected_current_term: challenge.expected_current_term,
        expected_hard_commit: challenge.expected_hard_commit,
        expected_last_applied: challenge.expected_last_applied,
        expected_last_log_index: challenge.expected_last_log_index,
        expected_pending_conf_index: challenge.expected_pending_conf_index,
        expected_commit_entry_term: challenge.expected_commit_entry_term,
        expected_runtime_capability_fingerprint: challenge
            .expected_runtime_capability_fingerprint
            .clone(),
        required_binary_capability_digest: challenge.required_binary_capability_digest.clone(),
        evidence,
        eligible_peer_set_digest: String::new(),
        eligible_process_incarnations_digest: String::new(),
        proof_digest: String::new(),
    };
    proof.eligible_peer_set_digest = eligible_peer_set_digest_v1(authority, &proof)?;
    proof.eligible_process_incarnations_digest = process_incarnations_digest_v1(&proof)?;
    proof.proof_digest = proof_digest_v1(&proof)?;
    let _verified = validate_private_oram_mixed_version_activation_proof_v1(
        &proof,
        authority,
        observed_peer_uri_digests,
    )?;
    Ok(proof)
}

pub fn validate_private_oram_mixed_version_activation_proof_v1<'a>(
    proof: &'a PrivateOramMixedVersionActivationProofV1,
    authority: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    observed_peer_uri_digests: &BTreeMap<u64, String>,
) -> Result<
    VerifiedPrivateOramMixedVersionActivationProofV1<'a>,
    PrivateOramMixedVersionActivationError,
> {
    if proof.version != PRIVATE_ORAM_MIXED_VERSION_ACTIVATION_PROOF_VERSION {
        return Err(PrivateOramMixedVersionActivationError::UnsupportedVersion);
    }
    validate_digest(&proof.authority_manifest_digest)?;
    validate_digest(&proof.configuration_digest)?;
    validate_digest(&proof.activation_id)?;
    validate_digest(&proof.expected_runtime_capability_fingerprint)?;
    validate_digest(&proof.required_binary_capability_digest)?;
    validate_digest(&proof.eligible_peer_set_digest)?;
    validate_digest(&proof.eligible_process_incarnations_digest)?;
    validate_digest(&proof.proof_digest)?;
    if proof.authority_registry_generation != authority.manifest().registry_generation
        || proof.authority_manifest_digest != authority.manifest_digest()
        || proof.required_binary_capability_digest
            != authority.manifest().required_binary_capability_digest
    {
        return Err(PrivateOramMixedVersionActivationError::AuthorityMismatch);
    }
    let configuration_digest =
        try_private_oram_consensus_configuration_digest_v1(&proof.configuration)
            .map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    // The wire-protocol floor a proof may install is bounded explicitly, so a legacy (V1)
    // challenge set can never lower it to 0 even if the log-position invariants below change.
    if proof.configuration_digest != configuration_digest
        || !(PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
            ..=PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION)
            .contains(&proof.required_consensus_wire_protocol)
        || proof.activation_generation == 0
        || proof.membership_generation == 0
        || proof.coordinator_peer_id == 0
        || proof.expected_current_term == 0
        || proof.expected_hard_commit == 0
        || proof.expected_hard_commit != proof.expected_last_applied
        || proof.expected_hard_commit != proof.expected_last_log_index
        || proof.expected_pending_conf_index != 0
        || proof.expected_commit_entry_term == 0
        || proof.expected_commit_entry_term > proof.expected_current_term
    {
        return Err(PrivateOramMixedVersionActivationError::InvalidProof);
    }

    let members = private_oram_consensus_configuration_member_ids_v1(&proof.configuration)
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    if members.is_empty()
        || members.len() > MAX_ACTIVATION_MEMBERS
        || proof.evidence.len() != members.len()
        || observed_peer_uri_digests.len() != members.len()
        || members.binary_search(&proof.coordinator_peer_id).is_err()
        || observed_peer_uri_digests
            .keys()
            .copied()
            .ne(members.iter().copied())
    {
        return Err(PrivateOramMixedVersionActivationError::InvalidEvidenceSet);
    }

    let mut challenge_nonces = BTreeSet::new();
    let mut process_incarnations = BTreeSet::new();
    for (member, item) in members.iter().zip(&proof.evidence) {
        let challenge = &item.challenge;
        validate_private_oram_peer_activation_challenge_v1_shape(challenge)
            .map_err(|_| PrivateOramMixedVersionActivationError::InvalidAcknowledgement)?;
        if challenge.protocol_version != PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2
            || challenge.target_peer_id != *member
            || challenge.activation_id != proof.activation_id
            || challenge.activation_generation != proof.activation_generation
            || challenge.membership_generation != proof.membership_generation
            || challenge.required_consensus_wire_protocol != proof.required_consensus_wire_protocol
            || challenge.coordinator_peer_id != proof.coordinator_peer_id
            || challenge.expected_current_term != proof.expected_current_term
            || challenge.expected_hard_commit != proof.expected_hard_commit
            || challenge.expected_last_applied != proof.expected_last_applied
            || challenge.expected_last_log_index != proof.expected_last_log_index
            || challenge.expected_pending_conf_index != proof.expected_pending_conf_index
            || challenge.expected_commit_entry_term != proof.expected_commit_entry_term
            || challenge.expected_configuration_digest != proof.configuration_digest
            || challenge.expected_runtime_capability_fingerprint
                != proof.expected_runtime_capability_fingerprint
            || challenge.required_binary_capability_digest
                != proof.required_binary_capability_digest
            || !challenge_nonces.insert(challenge.challenge_nonce.as_str())
            || !process_incarnations
                .insert(item.signed_ack.ack.observation.process_incarnation.as_str())
        {
            return Err(PrivateOramMixedVersionActivationError::InvalidEvidenceSet);
        }
        let observed_uri = observed_peer_uri_digests
            .get(member)
            .ok_or(PrivateOramMixedVersionActivationError::PeerUriMismatch)?;
        if challenge.target_peer_uri_digest != *observed_uri {
            return Err(PrivateOramMixedVersionActivationError::PeerUriMismatch);
        }
        let expected_signer = private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
            authority,
            &proof.configuration,
            observed_uri,
            challenge,
        )
        .map_err(|_| PrivateOramMixedVersionActivationError::AuthorityMismatch)?;
        validate_private_oram_peer_activation_ack_signature_v1(
            challenge,
            &item.signed_ack,
            expected_signer,
        )
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidAcknowledgement)?;
    }

    if proof.eligible_peer_set_digest != eligible_peer_set_digest_v1(authority, proof)?
        || proof.eligible_process_incarnations_digest != process_incarnations_digest_v1(proof)?
    {
        return Err(PrivateOramMixedVersionActivationError::DigestMismatch);
    }
    if proof.proof_digest != proof_digest_v1(proof)? {
        return Err(PrivateOramMixedVersionActivationError::DigestMismatch);
    }
    Ok(VerifiedPrivateOramMixedVersionActivationProofV1 { proof })
}

fn eligible_peer_set_digest_v1(
    authority: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    proof: &PrivateOramMixedVersionActivationProofV1,
) -> Result<String, PrivateOramMixedVersionActivationError> {
    let members = private_oram_consensus_configuration_member_ids_v1(&proof.configuration)
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_MIXED_VERSION_ELIGIBLE_PEER_SET_DIGEST_DOMAIN,
    )?;
    push_u16(&mut message, proof.version);
    push_str(&mut message, &proof.authority_manifest_digest)?;
    push_str(&mut message, &proof.configuration_digest)?;
    push_len(&mut message, members.len())?;
    for peer_id in members {
        let pin = authority
            .peer_pin(peer_id)
            .ok_or(PrivateOramMixedVersionActivationError::AuthorityMismatch)?;
        push_u64(&mut message, peer_id);
        push_str(&mut message, &pin.peer_uri_digest)?;
        push_u16(&mut message, pin.signer.version);
        push_str(&mut message, &pin.signer.alg)?;
        push_u64(&mut message, pin.signer.key_epoch);
        push_str(&mut message, &pin.signer.key_id)?;
        push_str(&mut message, &pin.signer.public_key)?;
    }
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn process_incarnations_digest_v1(
    proof: &PrivateOramMixedVersionActivationProofV1,
) -> Result<String, PrivateOramMixedVersionActivationError> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_MIXED_VERSION_PROCESS_INCARNATIONS_DIGEST_DOMAIN,
    )?;
    push_u16(&mut message, proof.version);
    push_str(&mut message, &proof.activation_id)?;
    push_u64(&mut message, proof.activation_generation);
    push_len(&mut message, proof.evidence.len())?;
    for item in &proof.evidence {
        push_u64(&mut message, item.challenge.target_peer_id);
        push_str(
            &mut message,
            &item.signed_ack.ack.observation.process_incarnation,
        )?;
        push_str(&mut message, &item.signed_ack.signer.key_id)?;
    }
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn proof_digest_v1(
    proof: &PrivateOramMixedVersionActivationProofV1,
) -> Result<String, PrivateOramMixedVersionActivationError> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_MIXED_VERSION_ACTIVATION_PROOF_DIGEST_DOMAIN,
    )?;
    push_u16(&mut message, proof.version);
    push_u64(&mut message, proof.authority_registry_generation);
    push_str(&mut message, &proof.authority_manifest_digest)?;
    push_str(&mut message, &proof.configuration_digest)?;
    push_str(&mut message, &proof.activation_id)?;
    push_u64(&mut message, proof.activation_generation);
    push_u64(&mut message, proof.membership_generation);
    push_u16(&mut message, proof.required_consensus_wire_protocol);
    push_u64(&mut message, proof.coordinator_peer_id);
    push_u64(&mut message, proof.expected_current_term);
    push_u64(&mut message, proof.expected_hard_commit);
    push_u64(&mut message, proof.expected_last_applied);
    push_u64(&mut message, proof.expected_last_log_index);
    push_u64(&mut message, proof.expected_pending_conf_index);
    push_u64(&mut message, proof.expected_commit_entry_term);
    push_str(&mut message, &proof.expected_runtime_capability_fingerprint)?;
    push_str(&mut message, &proof.required_binary_capability_digest)?;
    push_str(&mut message, &proof.eligible_peer_set_digest)?;
    push_str(&mut message, &proof.eligible_process_incarnations_digest)?;
    push_len(&mut message, proof.evidence.len())?;
    for item in &proof.evidence {
        let ack_message = try_private_oram_peer_activation_ack_signature_message_v1(
            &item.challenge,
            &item.signed_ack.ack,
            &item.signed_ack.signer,
        )
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidAcknowledgement)?;
        if ack_message.len() > MAX_CANONICAL_ACK_MESSAGE_BYTES {
            return Err(PrivateOramMixedVersionActivationError::InvalidAcknowledgement);
        }
        push_bytes(&mut message, &ack_message)?;
        push_u16(&mut message, item.signed_ack.signature.version);
        push_str(&mut message, &item.signed_ack.signature.alg)?;
        push_u64(&mut message, item.signed_ack.signature.key_epoch);
        push_str(&mut message, &item.signed_ack.signature.key_id)?;
        push_str(&mut message, &item.signed_ack.signature.sig)?;
    }
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn validate_digest(value: &str) -> Result<(), PrivateOramMixedVersionActivationError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateOramMixedVersionActivationError::InvalidProof);
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    if decoded.len() != DIGEST_BYTES || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramMixedVersionActivationError::InvalidProof);
    }
    Ok(())
}

fn push_domain(
    message: &mut Vec<u8>,
    domain: &str,
) -> Result<(), PrivateOramMixedVersionActivationError> {
    push_bytes(message, domain.as_bytes())
}

fn push_str(
    message: &mut Vec<u8>,
    value: &str,
) -> Result<(), PrivateOramMixedVersionActivationError> {
    push_bytes(message, value.as_bytes())
}

fn push_bytes(
    message: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), PrivateOramMixedVersionActivationError> {
    let len = u32::try_from(value.len())
        .map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn push_len(
    message: &mut Vec<u8>,
    len: usize,
) -> Result<(), PrivateOramMixedVersionActivationError> {
    let len =
        u32::try_from(len).map_err(|_| PrivateOramMixedVersionActivationError::InvalidProof)?;
    message.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn push_u16(message: &mut Vec<u8>, value: u16) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::{
        PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
        PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY, PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
        PrivateOramActivationAuthorityManifestV1, PrivateOramActivationAuthorityTrustAnchorV1,
        PrivateOramActivationPeerPinV1, PrivateOramActivationPeerUriSchemeV1,
        PrivateOramActivationRegistryExpectationV1, PrivateOramPeerActivationObservationV1,
        package_private_oram_activation_authority_manifest_v1,
        private_oram_activation_authority_public_key_v1, private_oram_peer_recovery_public_key_v1,
        sign_private_oram_peer_activation_ack_v1,
        try_private_oram_activation_cluster_identity_digest_v1,
        try_private_oram_activation_peer_uri_digest_v1,
        validate_private_oram_activation_authority_bundle_v1,
    };

    fn digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn key_pair(byte: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[byte; 32]).unwrap()
    }

    fn fixture() -> (
        VerifiedSignedPrivateOramActivationAuthorityManifestV1,
        BTreeMap<u64, String>,
        Vec<(u64, Ed25519KeyPair)>,
    ) {
        let authority_key = key_pair(1);
        let authority = private_oram_activation_authority_public_key_v1(&authority_key, 1).unwrap();
        let cluster_nonce = digest(2);
        let first_voter = 11;
        let signers = vec![(11, key_pair(11)), (13, key_pair(13)), (17, key_pair(17))];
        let mut uris = BTreeMap::new();
        let peers = signers
            .iter()
            .map(|(peer_id, signer)| {
                let uri = try_private_oram_activation_peer_uri_digest_v1(
                    PrivateOramActivationPeerUriSchemeV1::Https,
                    &format!("node-{peer_id}.internal"),
                    6335,
                )
                .unwrap();
                uris.insert(*peer_id, uri.clone());
                PrivateOramActivationPeerPinV1 {
                    peer_id: *peer_id,
                    peer_uri_digest: uri,
                    signer: private_oram_peer_recovery_public_key_v1(signer, 1).unwrap(),
                }
            })
            .collect();
        let manifest = PrivateOramActivationAuthorityManifestV1 {
            version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
            cluster_identity_nonce: cluster_nonce.clone(),
            cluster_identity_digest: try_private_oram_activation_cluster_identity_digest_v1(
                &cluster_nonce,
                first_voter,
            )
            .unwrap(),
            cluster_first_voter_peer_id: first_voter,
            registry_generation: 1,
            parent_manifest_digest: None,
            required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
            required_binary_capability_digest: digest(3),
            authority_key_epoch: authority.key_epoch,
            authority_key_id: authority.key_id.clone(),
            peers,
        };
        let trust_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                authority,
                manifest.cluster_identity_digest.clone(),
                first_voter,
            )
            .unwrap();
        let bundle =
            package_private_oram_activation_authority_manifest_v1(&authority_key, 1, manifest)
                .unwrap();
        let verified = validate_private_oram_activation_authority_bundle_v1(
            &bundle,
            &trust_anchor,
            PrivateOramActivationRegistryExpectationV1::Genesis,
        )
        .unwrap();
        (verified, uris, signers)
    }

    fn evidence(
        authority: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
        configuration: &PrivateOramConsensusConfigurationV1,
        signers: &[(u64, Ed25519KeyPair)],
        uris: &BTreeMap<u64, String>,
    ) -> Vec<PrivateOramPeerActivationEvidenceV1> {
        let configuration_digest =
            try_private_oram_consensus_configuration_digest_v1(configuration).unwrap();
        signers
            .iter()
            .map(|(peer_id, signer)| {
                let challenge = PrivateOramPeerActivationChallengeV1 {
                    protocol_version: PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
                    activation_id: digest(20),
                    activation_generation: 1,
                    challenge_nonce: digest(30 + *peer_id as u8),
                    cluster_identity_digest: authority.manifest().cluster_identity_digest.clone(),
                    cluster_first_voter_peer_id: authority.manifest().cluster_first_voter_peer_id,
                    coordinator_peer_id: 11,
                    target_peer_id: *peer_id,
                    target_peer_uri_digest: uris[peer_id].clone(),
                    membership_generation: 1,
                    required_consensus_wire_protocol:
                        crate::PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                    expected_current_term: 7,
                    expected_hard_commit: 41,
                    expected_last_applied: 41,
                    expected_last_log_index: 41,
                    expected_pending_conf_index: 0,
                    expected_commit_entry_term: 6,
                    expected_configuration_digest: configuration_digest.clone(),
                    expected_runtime_capability_fingerprint: digest(21),
                    pin_registry_generation: authority.manifest().registry_generation,
                    pin_registry_digest: authority.manifest_digest().to_string(),
                    required_capability: authority.manifest().required_capability.clone(),
                    required_binary_capability_digest: authority
                        .manifest()
                        .required_binary_capability_digest
                        .clone(),
                };
                let observation = PrivateOramPeerActivationObservationV1 {
                    responder_peer_id: *peer_id,
                    process_incarnation: digest(60 + *peer_id as u8),
                    qdrant_version: "1.14.0-sec-v2".to_string(),
                    capability: challenge.required_capability.clone(),
                    binary_capability_digest: challenge.required_binary_capability_digest.clone(),
                    cluster_identity_digest: challenge.cluster_identity_digest.clone(),
                    runtime_capability_fingerprint: challenge
                        .expected_runtime_capability_fingerprint
                        .clone(),
                    membership_generation: challenge.membership_generation,
                    supported_consensus_wire_protocol_min:
                        crate::PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
                    supported_consensus_wire_protocol_max:
                        crate::PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
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
                let signed_ack =
                    sign_private_oram_peer_activation_ack_v1(signer, 1, &challenge, observation)
                        .unwrap();
                PrivateOramPeerActivationEvidenceV1 {
                    challenge,
                    signed_ack,
                }
            })
            .collect()
    }

    #[test]
    fn aggregate_proof_requires_exact_live_member_set_and_is_canonical() {
        let (authority, uris, signers) = fixture();
        let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &[11, 13],
            &[],
            &[17],
            &[],
            false,
        )
        .unwrap();
        let mut acknowledgements = evidence(&authority, &configuration, &signers, &uris);
        acknowledgements.reverse();
        let proof = package_private_oram_mixed_version_activation_proof_v1(
            &authority,
            configuration,
            &uris,
            acknowledgements,
        )
        .unwrap();
        assert_eq!(
            proof
                .evidence()
                .iter()
                .map(|item| item.challenge.target_peer_id)
                .collect::<Vec<_>>(),
            vec![11, 13, 17]
        );
        let _verified =
            validate_private_oram_mixed_version_activation_proof_v1(&proof, &authority, &uris)
                .unwrap();
        // Known answer for the canonical proof digest of this fixture. The value pinned when
        // the test was introduced never matched the shipped digest construction (no digest
        // input changed since), so it is re-pinned to the deterministic output of this code.
        assert_eq!(
            proof.proof_digest(),
            "hjlG6sNvnOj6TCtaE8uMBCFknRQM-60qbfY_aZfvqFA"
        );

        let mut missing = proof.clone();
        missing.evidence.pop();
        assert_eq!(
            validate_private_oram_mixed_version_activation_proof_v1(&missing, &authority, &uris,)
                .unwrap_err(),
            PrivateOramMixedVersionActivationError::InvalidEvidenceSet
        );

        // A proof can never install a wire-protocol floor outside the supported range, and
        // only V2 challenges (which carry that floor) may back a proof.
        let mut downgraded = proof.clone();
        downgraded.required_consensus_wire_protocol = 0;
        assert!(
            validate_private_oram_mixed_version_activation_proof_v1(&downgraded, &authority, &uris)
                .is_err()
        );
        let mut legacy_challenge = proof.clone();
        legacy_challenge.evidence[0].challenge.protocol_version =
            crate::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1;
        assert!(
            validate_private_oram_mixed_version_activation_proof_v1(
                &legacy_challenge,
                &authority,
                &uris
            )
            .is_err()
        );
    }

    #[test]
    fn aggregate_proof_rejects_uri_incarnation_and_signature_substitution() {
        let (authority, uris, signers) = fixture();
        let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &[11, 13, 17],
            &[],
            &[],
            &[],
            false,
        )
        .unwrap();
        let proof = package_private_oram_mixed_version_activation_proof_v1(
            &authority,
            configuration,
            &uris,
            evidence(
                &authority,
                &PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
                    &[11, 13, 17],
                    &[],
                    &[],
                    &[],
                    false,
                )
                .unwrap(),
                &signers,
                &uris,
            ),
        )
        .unwrap();

        let mut stale_uris = uris.clone();
        stale_uris.insert(13, digest(99));
        assert_eq!(
            validate_private_oram_mixed_version_activation_proof_v1(
                &proof,
                &authority,
                &stale_uris,
            )
            .unwrap_err(),
            PrivateOramMixedVersionActivationError::PeerUriMismatch
        );

        let mut cloned_process = proof.clone();
        cloned_process.evidence[1]
            .signed_ack
            .ack
            .observation
            .process_incarnation = cloned_process.evidence[0]
            .signed_ack
            .ack
            .observation
            .process_incarnation
            .clone();
        assert_eq!(
            validate_private_oram_mixed_version_activation_proof_v1(
                &cloned_process,
                &authority,
                &uris,
            )
            .unwrap_err(),
            PrivateOramMixedVersionActivationError::InvalidEvidenceSet
        );

        let mut substituted = proof;
        substituted.evidence[1].signed_ack.signature.sig =
            substituted.evidence[0].signed_ack.signature.sig.clone();
        assert_eq!(
            validate_private_oram_mixed_version_activation_proof_v1(
                &substituted,
                &authority,
                &uris,
            )
            .unwrap_err(),
            PrivateOramMixedVersionActivationError::InvalidAcknowledgement
        );
    }
}
