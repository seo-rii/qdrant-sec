//! Dormant cryptographic primitives for a live private-ORAM process probe.
//!
//! This module deliberately does not aggregate acknowledgements into an activation proof and does
//! not establish signer authority. A caller must obtain the expected signer from an independently
//! authenticated, immutable pin registry. The response observation must come from one atomic local
//! process/consensus snapshot; it must never be synthesized from the coordinator's challenge.

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramPeerRecoveryPublicKeyV1, private_oram_peer_recovery_public_key_v1,
    validate_private_oram_peer_recovery_public_key_v1,
};

pub const PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2: u16 = 2;
pub const PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION: u16 =
    PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2;
pub const PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION: u16 = 6;
pub const PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION: u16 = 8;
pub const PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY: &str =
    "qdrant-sec/private-oram-consensus-wire/v2";
pub const PRIVATE_ORAM_PEER_ACTIVATION_CONFIGURATION_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-peer-activation-configuration-digest/v1";
pub const PRIVATE_ORAM_PEER_ACTIVATION_ACK_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-peer-activation-ack-signature/v1";
pub const PRIVATE_ORAM_MUTATION_PROTOCOL_CAPABILITY_DESCRIPTOR_V2: &str = "private-oram-mutation-v2;wire=6;material=6;authority=6;envelope=7;reservation=3;outcome=1;owner-prestage=2;owner-checkpoint=1;owner-tombstone=0";
pub const PRIVATE_ORAM_MUTATION_RESERVATION_CAPABILITY_DESCRIPTOR_V2: &str = "private-oram-mutation-v2;wire=6;material=6;authority=6;envelope=7;reservation=2;outcome=1;owner-prestage=2;owner-checkpoint=1;owner-tombstone=0";
pub const PRIVATE_ORAM_MUTATION_PROTOCOL_CAPABILITY_DESCRIPTOR_V3: &str = "private-oram-mutation-v3;wire=8;material=7;authority=7;envelope=7;reservation=3;outcome=1;owner-prestage=2;owner-checkpoint=1;owner-tombstone=1;external-recovery-authority=1;snapshot-barrier=1;enrollment-floor=1";

pub fn private_oram_mutation_protocol_capability_digest_v2() -> String {
    private_oram_mutation_protocol_capability_digest_for_descriptor_v2(
        6,
        PRIVATE_ORAM_MUTATION_PROTOCOL_CAPABILITY_DESCRIPTOR_V2,
    )
}

pub fn private_oram_mutation_reservation_protocol_capability_digest_v2() -> String {
    private_oram_mutation_protocol_capability_digest_for_descriptor_v2(
        6,
        PRIVATE_ORAM_MUTATION_RESERVATION_CAPABILITY_DESCRIPTOR_V2,
    )
}

pub fn private_oram_mutation_protocol_capability_digest_v3() -> String {
    private_oram_mutation_protocol_capability_digest_for_descriptor_v2(
        PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
        PRIVATE_ORAM_MUTATION_PROTOCOL_CAPABILITY_DESCRIPTOR_V3,
    )
}

fn private_oram_mutation_protocol_capability_digest_for_descriptor_v2(
    wire_protocol: u16,
    descriptor: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"qdrant-sec/private-oram-mutation-protocol-capability/v2");
    hasher.update(wire_protocol.to_be_bytes());
    hasher.update((descriptor.len() as u64).to_be_bytes());
    hasher.update(descriptor.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_CONFIGURATION_PEERS: usize = 1_024;
const MAX_QDRANT_VERSION_BYTES: usize = 64;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;

const fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

const fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramPeerActivationError {
    #[error("private ORAM peer activation protocol version is unsupported")]
    UnsupportedProtocolVersion,
    #[error("private ORAM peer activation field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM peer activation configuration is invalid")]
    InvalidConfiguration,
    #[error("private ORAM peer activation response context does not match")]
    ResponseContextMismatch(&'static str),
    #[error("private ORAM peer activation signer pin does not match")]
    SignerPinMismatch,
    #[error("private ORAM peer activation signature is invalid")]
    InvalidSignature,
}

impl Debug for PrivateOramPeerActivationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateOramPeerActivationError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramConsensusConfigurationV1 {
    voters: Vec<u64>,
    voters_outgoing: Vec<u64>,
    learners: Vec<u64>,
    learners_next: Vec<u64>,
    auto_leave: bool,
}

impl Debug for PrivateOramConsensusConfigurationV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramConsensusConfigurationV1")
            .field("voter_count", &self.voters.len())
            .field("outgoing_voter_count", &self.voters_outgoing.len())
            .field("learner_count", &self.learners.len())
            .field("next_learner_count", &self.learners_next.len())
            .field("auto_leave", &self.auto_leave)
            .finish()
    }
}

impl PrivateOramConsensusConfigurationV1 {
    pub fn from_raft_peer_sets(
        voters: &[u64],
        voters_outgoing: &[u64],
        learners: &[u64],
        learners_next: &[u64],
        auto_leave: bool,
    ) -> Result<Self, PrivateOramPeerActivationError> {
        let mut configuration = Self {
            voters: voters.to_vec(),
            voters_outgoing: voters_outgoing.to_vec(),
            learners: learners.to_vec(),
            learners_next: learners_next.to_vec(),
            auto_leave,
        };
        for peers in [
            &mut configuration.voters,
            &mut configuration.voters_outgoing,
            &mut configuration.learners,
            &mut configuration.learners_next,
        ] {
            peers.sort_unstable();
            peers.dedup();
        }
        validate_private_oram_consensus_configuration_v1(&configuration)?;
        Ok(configuration)
    }

    pub fn voters(&self) -> &[u64] {
        &self.voters
    }

    pub fn voters_outgoing(&self) -> &[u64] {
        &self.voters_outgoing
    }

    pub fn learners(&self) -> &[u64] {
        &self.learners
    }

    pub fn learners_next(&self) -> &[u64] {
        &self.learners_next
    }

    pub fn auto_leave(&self) -> bool {
        self.auto_leave
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerActivationChallengeV1 {
    pub protocol_version: u16,
    pub activation_id: String,
    pub activation_generation: u64,
    pub challenge_nonce: String,
    pub cluster_identity_digest: String,
    pub cluster_first_voter_peer_id: u64,
    pub coordinator_peer_id: u64,
    pub target_peer_id: u64,
    pub target_peer_uri_digest: String,
    pub membership_generation: u64,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub required_consensus_wire_protocol: u16,
    pub expected_current_term: u64,
    pub expected_hard_commit: u64,
    pub expected_last_applied: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub expected_last_log_index: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub expected_pending_conf_index: u64,
    pub expected_commit_entry_term: u64,
    pub expected_configuration_digest: String,
    pub expected_runtime_capability_fingerprint: String,
    pub pin_registry_generation: u64,
    pub pin_registry_digest: String,
    pub required_capability: String,
    pub required_binary_capability_digest: String,
}

impl Debug for PrivateOramPeerActivationChallengeV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerActivationChallengeV1")
            .field("protocol_version", &self.protocol_version)
            .field("activation_id", &"[redacted]")
            .field("activation_generation", &self.activation_generation)
            .field("challenge_nonce", &"[redacted]")
            .field("cluster_identity_digest", &"[redacted]")
            .field("cluster_first_voter_peer_id", &"[redacted]")
            .field("coordinator_peer_id", &"[redacted]")
            .field("target_peer_id", &"[redacted]")
            .field("target_peer_uri_digest", &"[redacted]")
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
            .field(
                "expected_commit_entry_term",
                &self.expected_commit_entry_term,
            )
            .field("expected_configuration_digest", &"[redacted]")
            .field("expected_runtime_capability_fingerprint", &"[redacted]")
            .field("pin_registry_generation", &self.pin_registry_generation)
            .field("pin_registry_digest", &"[redacted]")
            .field("required_capability", &"[redacted]")
            .field("required_binary_capability_digest", &"[redacted]")
            .finish()
    }
}

/// Values captured by the responder from its own live process and consensus state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerActivationObservationV1 {
    pub responder_peer_id: u64,
    pub process_incarnation: String,
    pub qdrant_version: String,
    pub capability: String,
    pub binary_capability_digest: String,
    pub cluster_identity_digest: String,
    pub runtime_capability_fingerprint: String,
    pub membership_generation: u64,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub supported_consensus_wire_protocol_min: u16,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub supported_consensus_wire_protocol_max: u16,
    pub observed_current_term: u64,
    pub observed_hard_commit: u64,
    pub observed_last_applied: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub observed_last_log_index: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub observed_pending_conf_index: u64,
    pub observed_commit_entry_term: u64,
    pub observed_configuration_digest: String,
    pub pin_registry_generation: u64,
    pub pin_registry_digest: String,
}

impl Debug for PrivateOramPeerActivationObservationV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerActivationObservationV1")
            .field("responder_peer_id", &"[redacted]")
            .field("process_incarnation", &"[redacted]")
            .field("qdrant_version", &"[redacted]")
            .field("capability", &"[redacted]")
            .field("binary_capability_digest", &"[redacted]")
            .field("cluster_identity_digest", &"[redacted]")
            .field("runtime_capability_fingerprint", &"[redacted]")
            .field("membership_generation", &self.membership_generation)
            .field(
                "supported_consensus_wire_protocol_min",
                &self.supported_consensus_wire_protocol_min,
            )
            .field(
                "supported_consensus_wire_protocol_max",
                &self.supported_consensus_wire_protocol_max,
            )
            .field("observed_current_term", &self.observed_current_term)
            .field("observed_hard_commit", &self.observed_hard_commit)
            .field("observed_last_applied", &self.observed_last_applied)
            .field("observed_last_log_index", &self.observed_last_log_index)
            .field(
                "observed_pending_conf_index",
                &self.observed_pending_conf_index,
            )
            .field(
                "observed_commit_entry_term",
                &self.observed_commit_entry_term,
            )
            .field("observed_configuration_digest", &"[redacted]")
            .field("pin_registry_generation", &self.pin_registry_generation)
            .field("pin_registry_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerActivationAckV1 {
    pub protocol_version: u16,
    pub activation_id: String,
    pub activation_generation: u64,
    pub observation: PrivateOramPeerActivationObservationV1,
}

impl Debug for PrivateOramPeerActivationAckV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerActivationAckV1")
            .field("protocol_version", &self.protocol_version)
            .field("activation_id", &"[redacted]")
            .field("activation_generation", &self.activation_generation)
            .field("observation", &self.observation)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerActivationSignatureV1 {
    pub version: u16,
    pub alg: String,
    pub key_epoch: u64,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateOramPeerActivationSignatureV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerActivationSignatureV1")
            .field("version", &self.version)
            .field("alg", &"[redacted]")
            .field("key_epoch", &self.key_epoch)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerActivationSignedAckV1 {
    pub ack: PrivateOramPeerActivationAckV1,
    pub signer: PrivateOramPeerRecoveryPublicKeyV1,
    pub signature: PrivateOramPeerActivationSignatureV1,
}

impl Debug for PrivateOramPeerActivationSignedAckV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerActivationSignedAckV1")
            .field("ack", &self.ack)
            .field("signer", &self.signer)
            .field("signature", &self.signature)
            .finish()
    }
}

pub fn validate_private_oram_consensus_configuration_v1(
    configuration: &PrivateOramConsensusConfigurationV1,
) -> Result<(), PrivateOramPeerActivationError> {
    if configuration.voters.is_empty() {
        return Err(PrivateOramPeerActivationError::InvalidConfiguration);
    }
    for peers in [
        &configuration.voters,
        &configuration.voters_outgoing,
        &configuration.learners,
        &configuration.learners_next,
    ] {
        if peers.len() > MAX_CONFIGURATION_PEERS
            || peers.contains(&0)
            || !peers.windows(2).all(|window| window[0] < window[1])
        {
            return Err(PrivateOramPeerActivationError::InvalidConfiguration);
        }
    }

    let voters = configuration
        .voters
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let outgoing = configuration
        .voters_outgoing
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let learners = configuration
        .learners
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let learners_next = configuration
        .learners_next
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    if !voters.is_disjoint(&learners)
        || !outgoing.is_disjoint(&learners)
        || !voters.is_disjoint(&learners_next)
        || !learners.is_disjoint(&learners_next)
        || !learners_next.is_subset(&outgoing)
        || (outgoing.is_empty() && (configuration.auto_leave || !learners_next.is_empty()))
    {
        return Err(PrivateOramPeerActivationError::InvalidConfiguration);
    }

    let mut all_peers = voters;
    all_peers.extend(outgoing);
    all_peers.extend(learners);
    all_peers.extend(learners_next);
    if all_peers.len() > MAX_CONFIGURATION_PEERS {
        return Err(PrivateOramPeerActivationError::InvalidConfiguration);
    }
    Ok(())
}

pub fn private_oram_consensus_configuration_member_ids_v1(
    configuration: &PrivateOramConsensusConfigurationV1,
) -> Result<Vec<u64>, PrivateOramPeerActivationError> {
    validate_private_oram_consensus_configuration_v1(configuration)?;
    let mut members = BTreeSet::new();
    members.extend(configuration.voters.iter().copied());
    members.extend(configuration.voters_outgoing.iter().copied());
    members.extend(configuration.learners.iter().copied());
    members.extend(configuration.learners_next.iter().copied());
    Ok(members.into_iter().collect())
}

pub fn try_private_oram_consensus_configuration_digest_v1(
    configuration: &PrivateOramConsensusConfigurationV1,
) -> Result<String, PrivateOramPeerActivationError> {
    validate_private_oram_consensus_configuration_v1(configuration)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_PEER_ACTIVATION_CONFIGURATION_DIGEST_DOMAIN,
    )?;
    // This digest is the immutable V1 configuration contract and must not change when the
    // activation acknowledgement protocol gains a new version.
    push_u16(
        &mut message,
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1,
    );
    push_peer_ids(&mut message, &configuration.voters)?;
    push_peer_ids(&mut message, &configuration.voters_outgoing)?;
    push_peer_ids(&mut message, &configuration.learners)?;
    push_peer_ids(&mut message, &configuration.learners_next)?;
    message.push(u8::from(configuration.auto_leave));
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

pub fn validate_private_oram_peer_activation_challenge_v1_shape(
    challenge: &PrivateOramPeerActivationChallengeV1,
) -> Result<(), PrivateOramPeerActivationError> {
    if !matches!(
        challenge.protocol_version,
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1
            | PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2
    ) {
        return Err(PrivateOramPeerActivationError::UnsupportedProtocolVersion);
    }
    for (value, field) in [
        (&challenge.activation_id, "activation_id"),
        (&challenge.challenge_nonce, "challenge_nonce"),
        (
            &challenge.cluster_identity_digest,
            "cluster_identity_digest",
        ),
        (&challenge.target_peer_uri_digest, "target_peer_uri_digest"),
        (
            &challenge.expected_configuration_digest,
            "expected_configuration_digest",
        ),
        (
            &challenge.expected_runtime_capability_fingerprint,
            "expected_runtime_capability_fingerprint",
        ),
        (&challenge.pin_registry_digest, "pin_registry_digest"),
        (
            &challenge.required_binary_capability_digest,
            "required_binary_capability_digest",
        ),
    ] {
        validate_digest(value, field)?;
    }
    if challenge.activation_generation == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "activation_generation",
        ));
    }
    if challenge.cluster_first_voter_peer_id == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "cluster_first_voter_peer_id",
        ));
    }
    if challenge.coordinator_peer_id == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "coordinator_peer_id",
        ));
    }
    if challenge.target_peer_id == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "target_peer_id",
        ));
    }
    if challenge.membership_generation == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "membership_generation",
        ));
    }
    match challenge.protocol_version {
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1 => {
            if challenge.required_consensus_wire_protocol != 0
                || challenge.expected_last_log_index != 0
                || challenge.expected_pending_conf_index != 0
            {
                return Err(PrivateOramPeerActivationError::InvalidField(
                    "legacy_extension_fields",
                ));
            }
        }
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2 => {
            if !(PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
                ..=PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION)
                .contains(&challenge.required_consensus_wire_protocol)
            {
                return Err(PrivateOramPeerActivationError::InvalidField(
                    "required_consensus_wire_protocol",
                ));
            }
        }
        _ => unreachable!("protocol version was validated above"),
    }
    if challenge.expected_current_term == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "expected_current_term",
        ));
    }
    if challenge.expected_hard_commit == 0
        || challenge.expected_last_applied != challenge.expected_hard_commit
        || (challenge.protocol_version == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2
            && challenge.expected_last_log_index != challenge.expected_hard_commit)
    {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "expected_hard_commit",
        ));
    }
    if challenge.expected_pending_conf_index != 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "expected_pending_conf_index",
        ));
    }
    if challenge.expected_commit_entry_term == 0
        || challenge.expected_commit_entry_term > challenge.expected_current_term
    {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "expected_commit_entry_term",
        ));
    }
    if challenge.pin_registry_generation == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "pin_registry_generation",
        ));
    }
    if challenge.required_capability != PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "required_capability",
        ));
    }
    Ok(())
}

pub fn validate_private_oram_peer_activation_observation_v1_shape(
    observation: &PrivateOramPeerActivationObservationV1,
) -> Result<(), PrivateOramPeerActivationError> {
    if observation.responder_peer_id == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "responder_peer_id",
        ));
    }
    for (value, field) in [
        (&observation.process_incarnation, "process_incarnation"),
        (
            &observation.binary_capability_digest,
            "binary_capability_digest",
        ),
        (
            &observation.cluster_identity_digest,
            "cluster_identity_digest",
        ),
        (
            &observation.runtime_capability_fingerprint,
            "runtime_capability_fingerprint",
        ),
        (
            &observation.observed_configuration_digest,
            "observed_configuration_digest",
        ),
        (&observation.pin_registry_digest, "pin_registry_digest"),
    ] {
        validate_digest(value, field)?;
    }
    if observation.qdrant_version.is_empty()
        || observation.qdrant_version.len() > MAX_QDRANT_VERSION_BYTES
        || !observation
            .qdrant_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "qdrant_version",
        ));
    }
    if observation.capability != PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY {
        return Err(PrivateOramPeerActivationError::InvalidField("capability"));
    }
    if observation.membership_generation == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "membership_generation",
        ));
    }
    let legacy_extensions = observation.supported_consensus_wire_protocol_min == 0
        && observation.supported_consensus_wire_protocol_max == 0
        && observation.observed_last_log_index == 0
        && observation.observed_pending_conf_index == 0;
    let current_extensions = observation.supported_consensus_wire_protocol_min
        >= PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
        && observation.supported_consensus_wire_protocol_min
            <= observation.supported_consensus_wire_protocol_max
        && observation.supported_consensus_wire_protocol_max
            <= PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION;
    if !legacy_extensions && !current_extensions {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "supported_consensus_wire_protocol",
        ));
    }
    if observation.observed_current_term == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "observed_current_term",
        ));
    }
    if observation.observed_hard_commit == 0
        || observation.observed_last_applied != observation.observed_hard_commit
        || (!legacy_extensions
            && observation.observed_last_log_index != observation.observed_hard_commit)
    {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "observed_hard_commit",
        ));
    }
    if observation.observed_pending_conf_index != 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "observed_pending_conf_index",
        ));
    }
    if observation.observed_commit_entry_term == 0
        || observation.observed_commit_entry_term > observation.observed_current_term
    {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "observed_commit_entry_term",
        ));
    }
    if observation.pin_registry_generation == 0 {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "pin_registry_generation",
        ));
    }
    Ok(())
}

pub fn try_private_oram_peer_activation_ack_signature_message_v1(
    challenge: &PrivateOramPeerActivationChallengeV1,
    ack: &PrivateOramPeerActivationAckV1,
    signer: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramPeerActivationError> {
    validate_private_oram_peer_activation_challenge_v1_shape(challenge)?;
    validate_ack_context(challenge, ack)?;
    validate_private_oram_peer_recovery_public_key_v1(signer)
        .map_err(|_| PrivateOramPeerActivationError::InvalidField("signer"))?;

    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_PEER_ACTIVATION_ACK_SIGNATURE_DOMAIN,
    )?;
    push_u16(&mut message, challenge.protocol_version);
    push_str(&mut message, &challenge.activation_id)?;
    push_u64(&mut message, challenge.activation_generation);
    push_str(&mut message, &challenge.challenge_nonce)?;
    push_str(&mut message, &challenge.cluster_identity_digest)?;
    push_u64(&mut message, challenge.cluster_first_voter_peer_id);
    push_u64(&mut message, challenge.coordinator_peer_id);
    push_u64(&mut message, challenge.target_peer_id);
    push_str(&mut message, &challenge.target_peer_uri_digest)?;
    push_u64(&mut message, challenge.membership_generation);
    if challenge.protocol_version == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2 {
        push_u16(&mut message, challenge.required_consensus_wire_protocol);
    }
    push_u64(&mut message, challenge.expected_current_term);
    push_u64(&mut message, challenge.expected_hard_commit);
    push_u64(&mut message, challenge.expected_last_applied);
    if challenge.protocol_version == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2 {
        push_u64(&mut message, challenge.expected_last_log_index);
        push_u64(&mut message, challenge.expected_pending_conf_index);
    }
    push_u64(&mut message, challenge.expected_commit_entry_term);
    push_str(&mut message, &challenge.expected_configuration_digest)?;
    push_str(
        &mut message,
        &challenge.expected_runtime_capability_fingerprint,
    )?;
    push_u64(&mut message, challenge.pin_registry_generation);
    push_str(&mut message, &challenge.pin_registry_digest)?;
    push_str(&mut message, &challenge.required_capability)?;
    push_str(&mut message, &challenge.required_binary_capability_digest)?;

    push_u16(&mut message, ack.protocol_version);
    push_str(&mut message, &ack.activation_id)?;
    push_u64(&mut message, ack.activation_generation);
    push_u64(&mut message, ack.observation.responder_peer_id);
    push_str(&mut message, &ack.observation.process_incarnation)?;
    push_str(&mut message, &ack.observation.qdrant_version)?;
    push_str(&mut message, &ack.observation.capability)?;
    push_str(&mut message, &ack.observation.binary_capability_digest)?;
    push_str(&mut message, &ack.observation.cluster_identity_digest)?;
    push_str(
        &mut message,
        &ack.observation.runtime_capability_fingerprint,
    )?;
    push_u64(&mut message, ack.observation.membership_generation);
    if challenge.protocol_version == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2 {
        push_u16(
            &mut message,
            ack.observation.supported_consensus_wire_protocol_min,
        );
        push_u16(
            &mut message,
            ack.observation.supported_consensus_wire_protocol_max,
        );
    }
    push_u64(&mut message, ack.observation.observed_current_term);
    push_u64(&mut message, ack.observation.observed_hard_commit);
    push_u64(&mut message, ack.observation.observed_last_applied);
    if challenge.protocol_version == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2 {
        push_u64(&mut message, ack.observation.observed_last_log_index);
        push_u64(&mut message, ack.observation.observed_pending_conf_index);
    }
    push_u64(&mut message, ack.observation.observed_commit_entry_term);
    push_str(&mut message, &ack.observation.observed_configuration_digest)?;
    push_u64(&mut message, ack.observation.pin_registry_generation);
    push_str(&mut message, &ack.observation.pin_registry_digest)?;

    push_u16(&mut message, signer.version);
    push_str(&mut message, &signer.alg)?;
    push_u64(&mut message, signer.key_epoch);
    push_str(&mut message, &signer.key_id)?;
    push_str(&mut message, &signer.public_key)?;
    Ok(message)
}

/// Signs a caller-supplied local observation after requiring exact challenge agreement.
///
/// The caller is responsible for capturing `observation` atomically from the responder's own live
/// process and Raft state. Passing values copied from `challenge` defeats the protocol.
pub fn sign_private_oram_peer_activation_ack_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    challenge: &PrivateOramPeerActivationChallengeV1,
    observation: PrivateOramPeerActivationObservationV1,
) -> Result<PrivateOramPeerActivationSignedAckV1, PrivateOramPeerActivationError> {
    validate_private_oram_peer_activation_challenge_v1_shape(challenge)?;
    validate_observation_context(challenge, &observation)?;
    let signer = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramPeerActivationError::InvalidField("signer"))?;
    let ack = PrivateOramPeerActivationAckV1 {
        protocol_version: challenge.protocol_version,
        activation_id: challenge.activation_id.clone(),
        activation_generation: challenge.activation_generation,
        observation,
    };
    let message =
        try_private_oram_peer_activation_ack_signature_message_v1(challenge, &ack, &signer)?;
    let signature = PrivateOramPeerActivationSignatureV1 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: signer.key_id.clone(),
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    };
    Ok(PrivateOramPeerActivationSignedAckV1 {
        ack,
        signer,
        signature,
    })
}

/// Verifies one acknowledgement against a signer pin supplied by a separate authority layer.
pub fn validate_private_oram_peer_activation_ack_signature_v1(
    challenge: &PrivateOramPeerActivationChallengeV1,
    signed_ack: &PrivateOramPeerActivationSignedAckV1,
    expected_signer: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<(), PrivateOramPeerActivationError> {
    if &signed_ack.signer != expected_signer {
        return Err(PrivateOramPeerActivationError::SignerPinMismatch);
    }
    let public_key = validate_private_oram_peer_recovery_public_key_v1(expected_signer)
        .map_err(|_| PrivateOramPeerActivationError::InvalidField("expected_signer"))?;
    validate_activation_signature_shape(&signed_ack.signature)?;
    if signed_ack.signature.key_epoch != expected_signer.key_epoch
        || signed_ack.signature.key_id != expected_signer.key_id
    {
        return Err(PrivateOramPeerActivationError::SignerPinMismatch);
    }
    let signature = decode_canonical::<SIGNATURE_BYTES>(
        &signed_ack.signature.sig,
        BASE64URL_NOPAD_64_BYTE_LEN,
        "signature",
    )?;
    let message = try_private_oram_peer_activation_ack_signature_message_v1(
        challenge,
        &signed_ack.ack,
        &signed_ack.signer,
    )?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| PrivateOramPeerActivationError::InvalidSignature)
}

fn validate_ack_context(
    challenge: &PrivateOramPeerActivationChallengeV1,
    ack: &PrivateOramPeerActivationAckV1,
) -> Result<(), PrivateOramPeerActivationError> {
    if ack.protocol_version != challenge.protocol_version {
        return Err(PrivateOramPeerActivationError::UnsupportedProtocolVersion);
    }
    validate_digest(&ack.activation_id, "activation_id")?;
    if ack.activation_id != challenge.activation_id {
        return Err(PrivateOramPeerActivationError::ResponseContextMismatch(
            "activation_id",
        ));
    }
    if ack.activation_generation != challenge.activation_generation {
        return Err(PrivateOramPeerActivationError::ResponseContextMismatch(
            "activation_generation",
        ));
    }
    validate_observation_context(challenge, &ack.observation)
}

fn validate_observation_context(
    challenge: &PrivateOramPeerActivationChallengeV1,
    observation: &PrivateOramPeerActivationObservationV1,
) -> Result<(), PrivateOramPeerActivationError> {
    validate_private_oram_peer_activation_observation_v1_shape(observation)?;
    let wire_protocol_matches = match challenge.protocol_version {
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1 => {
            observation.supported_consensus_wire_protocol_min == 0
                && observation.supported_consensus_wire_protocol_max == 0
        }
        PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2 => {
            observation.supported_consensus_wire_protocol_min
                <= challenge.required_consensus_wire_protocol
                && observation.supported_consensus_wire_protocol_max
                    >= challenge.required_consensus_wire_protocol
        }
        _ => false,
    };
    let last_log_matches = challenge.protocol_version
        == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1
        || observation.observed_last_log_index == challenge.expected_last_log_index;
    let pending_conf_matches = challenge.protocol_version
        == PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1
        || observation.observed_pending_conf_index == challenge.expected_pending_conf_index;
    for (matches, field) in [
        (
            observation.responder_peer_id == challenge.target_peer_id,
            "responder_peer_id",
        ),
        (
            observation.capability == challenge.required_capability,
            "capability",
        ),
        (
            observation.binary_capability_digest == challenge.required_binary_capability_digest,
            "binary_capability_digest",
        ),
        (
            observation.cluster_identity_digest == challenge.cluster_identity_digest,
            "cluster_identity_digest",
        ),
        (
            observation.runtime_capability_fingerprint
                == challenge.expected_runtime_capability_fingerprint,
            "runtime_capability_fingerprint",
        ),
        (
            observation.membership_generation == challenge.membership_generation,
            "membership_generation",
        ),
        (wire_protocol_matches, "supported_consensus_wire_protocol"),
        (
            observation.observed_current_term == challenge.expected_current_term,
            "observed_current_term",
        ),
        (
            observation.observed_hard_commit == challenge.expected_hard_commit,
            "observed_hard_commit",
        ),
        (
            observation.observed_last_applied == challenge.expected_last_applied,
            "observed_last_applied",
        ),
        (last_log_matches, "observed_last_log_index"),
        (pending_conf_matches, "observed_pending_conf_index"),
        (
            observation.observed_commit_entry_term == challenge.expected_commit_entry_term,
            "observed_commit_entry_term",
        ),
        (
            observation.observed_configuration_digest == challenge.expected_configuration_digest,
            "observed_configuration_digest",
        ),
        (
            observation.pin_registry_generation == challenge.pin_registry_generation,
            "pin_registry_generation",
        ),
        (
            observation.pin_registry_digest == challenge.pin_registry_digest,
            "pin_registry_digest",
        ),
    ] {
        if !matches {
            return Err(PrivateOramPeerActivationError::ResponseContextMismatch(
                field,
            ));
        }
    }
    Ok(())
}

fn validate_activation_signature_shape(
    signature: &PrivateOramPeerActivationSignatureV1,
) -> Result<(), PrivateOramPeerActivationError> {
    if signature.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "signature_version",
        ));
    }
    if signature.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM {
        return Err(PrivateOramPeerActivationError::InvalidField(
            "signature_algorithm",
        ));
    }
    if signature.key_epoch == 0 || signature.key_id.is_empty() {
        return Err(PrivateOramPeerActivationError::InvalidField("signature"));
    }
    decode_canonical::<SIGNATURE_BYTES>(&signature.sig, BASE64URL_NOPAD_64_BYTE_LEN, "signature")?;
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), PrivateOramPeerActivationError> {
    decode_canonical::<DIGEST_BYTES>(value, BASE64URL_NOPAD_32_BYTE_LEN, field).map(|_| ())
}

fn decode_canonical<const N: usize>(
    value: &str,
    expected_len: usize,
    field: &'static str,
) -> Result<[u8; N], PrivateOramPeerActivationError> {
    if value.len() != expected_len {
        return Err(PrivateOramPeerActivationError::InvalidField(field));
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramPeerActivationError::InvalidField(field))?;
    let bytes: [u8; N] = bytes
        .try_into()
        .map_err(|_| PrivateOramPeerActivationError::InvalidField(field))?;
    if BASE64URL_NOPAD.encode(&bytes) != value {
        return Err(PrivateOramPeerActivationError::InvalidField(field));
    }
    Ok(bytes)
}

fn push_domain(message: &mut Vec<u8>, domain: &str) -> Result<(), PrivateOramPeerActivationError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramPeerActivationError::InvalidField("signature_message"))?;
    push_u32(message, len);
    message.extend_from_slice(domain.as_bytes());
    Ok(())
}

fn push_peer_ids(
    message: &mut Vec<u8>,
    peer_ids: &[u64],
) -> Result<(), PrivateOramPeerActivationError> {
    let len = u32::try_from(peer_ids.len())
        .map_err(|_| PrivateOramPeerActivationError::InvalidField("configuration"))?;
    push_u32(message, len);
    for peer_id in peer_ids {
        push_u64(message, *peer_id);
    }
    Ok(())
}

fn push_str(message: &mut Vec<u8>, value: &str) -> Result<(), PrivateOramPeerActivationError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramPeerActivationError::InvalidField("signature_message"))?;
    push_u64(message, len);
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(message: &mut Vec<u8>, value: u16) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(message: &mut Vec<u8>, value: u32) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> String {
        BASE64URL_NOPAD.encode(&[value; DIGEST_BYTES])
    }

    fn key_pair(value: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[value; 32]).unwrap()
    }

    fn configuration() -> PrivateOramConsensusConfigurationV1 {
        PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &[13, 11, 13],
            &[19, 17],
            &[23],
            &[17],
            true,
        )
        .unwrap()
    }

    fn challenge() -> PrivateOramPeerActivationChallengeV1 {
        PrivateOramPeerActivationChallengeV1 {
            protocol_version: PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
            activation_id: digest(1),
            activation_generation: 3,
            challenge_nonce: digest(2),
            cluster_identity_digest: digest(3),
            cluster_first_voter_peer_id: 7,
            coordinator_peer_id: 11,
            target_peer_id: 13,
            target_peer_uri_digest: digest(4),
            membership_generation: 9,
            required_consensus_wire_protocol: PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
            expected_current_term: 5,
            expected_hard_commit: 101,
            expected_last_applied: 101,
            expected_last_log_index: 101,
            expected_pending_conf_index: 0,
            expected_commit_entry_term: 4,
            expected_configuration_digest: digest(5),
            expected_runtime_capability_fingerprint: digest(6),
            pin_registry_generation: 4,
            pin_registry_digest: digest(7),
            required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
            required_binary_capability_digest: digest(8),
        }
    }

    fn observation() -> PrivateOramPeerActivationObservationV1 {
        PrivateOramPeerActivationObservationV1 {
            responder_peer_id: 13,
            process_incarnation: digest(9),
            qdrant_version: "1.17.1-sec.2".to_string(),
            capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
            binary_capability_digest: digest(8),
            cluster_identity_digest: digest(3),
            runtime_capability_fingerprint: digest(6),
            membership_generation: 9,
            supported_consensus_wire_protocol_min: PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
            supported_consensus_wire_protocol_max: PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
            observed_current_term: 5,
            observed_hard_commit: 101,
            observed_last_applied: 101,
            observed_last_log_index: 101,
            observed_pending_conf_index: 0,
            observed_commit_entry_term: 4,
            observed_configuration_digest: digest(5),
            pin_registry_generation: 4,
            pin_registry_digest: digest(7),
        }
    }

    #[test]
    fn configuration_digest_is_a_known_answer_and_covers_joint_membership() {
        let configuration = configuration();
        assert_eq!(
            try_private_oram_consensus_configuration_digest_v1(&configuration).unwrap(),
            "rO3UxLTnc_z-Y-kG7vOHr7sOHIU47Uw61pnOaBye-gA",
        );
        assert_eq!(
            private_oram_consensus_configuration_member_ids_v1(&configuration).unwrap(),
            vec![11, 13, 17, 19, 23],
        );
    }

    #[test]
    fn ack_message_and_signature_are_known_answers() {
        let challenge = challenge();
        let signed_ack =
            sign_private_oram_peer_activation_ack_v1(&key_pair(10), 1, &challenge, observation())
                .unwrap();
        let message = try_private_oram_peer_activation_ack_signature_message_v1(
            &challenge,
            &signed_ack.ack,
            &signed_ack.signer,
        )
        .unwrap();
        assert_eq!(
            BASE64URL_NOPAD.encode(&Sha256::digest(&message)),
            "j96yfi-euBGUJie_HItlgIb-ISmbWIEXB3Vn74wfEj4",
        );
        assert_eq!(
            signed_ack.signature.sig,
            "zcc8ypl7oAMFFhTF9ihQiiedsz2oCq8d9crNRb3QEr0egw4UfHSICr_4ZxLm0se5q_g3m2MWl636XJpewfCcAg",
        );
        validate_private_oram_peer_activation_ack_signature_v1(
            &challenge,
            &signed_ack,
            &signed_ack.signer,
        )
        .unwrap();
    }

    #[test]
    fn legacy_v1_ack_remains_byte_and_signature_compatible() {
        let mut challenge = challenge();
        challenge.protocol_version = PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1;
        challenge.required_consensus_wire_protocol = 0;
        challenge.expected_last_log_index = 0;
        challenge.expected_pending_conf_index = 0;
        let mut observation = observation();
        observation.supported_consensus_wire_protocol_min = 0;
        observation.supported_consensus_wire_protocol_max = 0;
        observation.observed_last_log_index = 0;
        observation.observed_pending_conf_index = 0;
        let signed_ack =
            sign_private_oram_peer_activation_ack_v1(&key_pair(10), 1, &challenge, observation)
                .unwrap();
        let message = try_private_oram_peer_activation_ack_signature_message_v1(
            &challenge,
            &signed_ack.ack,
            &signed_ack.signer,
        )
        .unwrap();
        assert_eq!(
            BASE64URL_NOPAD.encode(&Sha256::digest(&message)),
            "vZs5rircPv9L1v-viHIYGD9DUf_V0DIsyN4kveQojgw",
        );
        assert_eq!(
            signed_ack.signature.sig,
            "-DJ2lvIHnO4niZ4TENq_ko90Y8U9MS75CQzFdvIRRC2Z9NZ4IbMxeN2DtfxqWQXB8MBjR41sfwG3Ydds7jrYAg",
        );
        let encoded_challenge = serde_json::to_value(&challenge).unwrap();
        assert!(
            encoded_challenge
                .get("required_consensus_wire_protocol")
                .is_none()
        );
        assert!(encoded_challenge.get("expected_last_log_index").is_none());
        validate_private_oram_peer_activation_ack_signature_v1(
            &challenge,
            &signed_ack,
            &signed_ack.signer,
        )
        .unwrap();
    }

    #[test]
    fn signer_rejects_observation_not_matching_the_challenge() {
        let challenge = challenge();
        let mut mutations = Vec::new();
        let mut value = observation();
        value.responder_peer_id = 17;
        mutations.push(value);
        let mut value = observation();
        value.binary_capability_digest = digest(21);
        mutations.push(value);
        let mut value = observation();
        value.cluster_identity_digest = digest(22);
        mutations.push(value);
        let mut value = observation();
        value.runtime_capability_fingerprint = digest(23);
        mutations.push(value);
        let mut value = observation();
        value.membership_generation += 1;
        mutations.push(value);
        let mut value = observation();
        value.supported_consensus_wire_protocol_max -= 1;
        mutations.push(value);
        let mut value = observation();
        value.observed_current_term += 1;
        mutations.push(value);
        let mut value = observation();
        value.observed_hard_commit += 1;
        value.observed_last_applied += 1;
        value.observed_last_log_index += 1;
        mutations.push(value);
        let mut value = observation();
        value.observed_last_log_index -= 1;
        mutations.push(value);
        let mut value = observation();
        value.observed_pending_conf_index = 99;
        mutations.push(value);
        let mut value = observation();
        value.observed_commit_entry_term -= 1;
        mutations.push(value);
        let mut value = observation();
        value.observed_configuration_digest = digest(24);
        mutations.push(value);
        let mut value = observation();
        value.pin_registry_generation += 1;
        mutations.push(value);
        let mut value = observation();
        value.pin_registry_digest = digest(25);
        mutations.push(value);

        for mutation in mutations {
            assert!(
                sign_private_oram_peer_activation_ack_v1(&key_pair(10), 1, &challenge, mutation,)
                    .is_err()
            );
        }
    }

    #[test]
    fn every_challenge_context_field_is_signed() {
        let challenge = challenge();
        let signed_ack =
            sign_private_oram_peer_activation_ack_v1(&key_pair(10), 1, &challenge, observation())
                .unwrap();
        let mut mutations = Vec::new();
        let mut value = challenge.clone();
        value.activation_id = digest(31);
        mutations.push(value);
        let mut value = challenge.clone();
        value.activation_generation += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.challenge_nonce = digest(32);
        mutations.push(value);
        let mut value = challenge.clone();
        value.cluster_identity_digest = digest(33);
        mutations.push(value);
        let mut value = challenge.clone();
        value.cluster_first_voter_peer_id += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.coordinator_peer_id += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.target_peer_id += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.target_peer_uri_digest = digest(34);
        mutations.push(value);
        let mut value = challenge.clone();
        value.membership_generation += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.required_consensus_wire_protocol += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_current_term += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_hard_commit += 1;
        value.expected_last_applied += 1;
        value.expected_last_log_index += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_last_log_index -= 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_pending_conf_index = 99;
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_commit_entry_term -= 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_configuration_digest = digest(35);
        mutations.push(value);
        let mut value = challenge.clone();
        value.expected_runtime_capability_fingerprint = digest(36);
        mutations.push(value);
        let mut value = challenge.clone();
        value.pin_registry_generation += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.pin_registry_digest = digest(37);
        mutations.push(value);
        let mut value = challenge;
        value.required_binary_capability_digest = digest(38);
        mutations.push(value);

        for mutation in mutations {
            assert!(
                validate_private_oram_peer_activation_ack_signature_v1(
                    &mutation,
                    &signed_ack,
                    &signed_ack.signer,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn verifier_rejects_unpinned_key_and_signature_mutation() {
        let challenge = challenge();
        let signed_ack =
            sign_private_oram_peer_activation_ack_v1(&key_pair(10), 1, &challenge, observation())
                .unwrap();
        let other = private_oram_peer_recovery_public_key_v1(&key_pair(11), 1).unwrap();
        assert_eq!(
            validate_private_oram_peer_activation_ack_signature_v1(&challenge, &signed_ack, &other),
            Err(PrivateOramPeerActivationError::SignerPinMismatch),
        );
        let mut mutated = signed_ack.clone();
        mutated.ack.observation.process_incarnation = digest(41);
        let signer = mutated.signer.clone();
        assert_eq!(
            validate_private_oram_peer_activation_ack_signature_v1(&challenge, &mutated, &signer),
            Err(PrivateOramPeerActivationError::InvalidSignature),
        );
    }

    #[test]
    fn invalid_raft_configurations_are_rejected() {
        let mut unordered = configuration();
        unordered.voters.reverse();
        assert_eq!(
            validate_private_oram_consensus_configuration_v1(&unordered),
            Err(PrivateOramPeerActivationError::InvalidConfiguration)
        );
        let mut outgoing_learner = configuration();
        outgoing_learner.learners = vec![19, 23];
        assert_eq!(
            validate_private_oram_consensus_configuration_v1(&outgoing_learner),
            Err(PrivateOramPeerActivationError::InvalidConfiguration)
        );
        let mut invalid_next = configuration();
        invalid_next.learners_next = vec![29];
        assert_eq!(
            validate_private_oram_consensus_configuration_v1(&invalid_next),
            Err(PrivateOramPeerActivationError::InvalidConfiguration)
        );
    }

    #[test]
    fn challenge_and_observation_require_applied_commit_parity() {
        let mut challenge = challenge();
        challenge.expected_last_applied -= 1;
        assert_eq!(
            validate_private_oram_peer_activation_challenge_v1_shape(&challenge),
            Err(PrivateOramPeerActivationError::InvalidField(
                "expected_hard_commit"
            ))
        );
        let mut observation = observation();
        observation.observed_last_applied -= 1;
        assert_eq!(
            validate_private_oram_peer_activation_observation_v1_shape(&observation),
            Err(PrivateOramPeerActivationError::InvalidField(
                "observed_hard_commit"
            ))
        );
    }

    #[test]
    fn debug_and_errors_redact_activation_evidence() {
        let challenge = challenge();
        let signed_ack =
            sign_private_oram_peer_activation_ack_v1(&key_pair(10), 1, &challenge, observation())
                .unwrap();
        let debug = format!("{challenge:?} {signed_ack:?}");
        assert!(!debug.contains(&challenge.activation_id));
        assert!(!debug.contains(&challenge.challenge_nonce));
        assert!(!debug.contains(&signed_ack.signature.sig));
        assert!(
            !format!("{:?}", PrivateOramPeerActivationError::InvalidSignature)
                .contains(&challenge.activation_id)
        );
    }

    #[test]
    fn serde_rejects_unknown_activation_fields() {
        let mut value = serde_json::to_value(challenge()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<PrivateOramPeerActivationChallengeV1>(value).is_err());
    }

    #[test]
    fn capability_does_not_advertise_owner_tombstones_before_activation() {
        assert!(
            PRIVATE_ORAM_MUTATION_PROTOCOL_CAPABILITY_DESCRIPTOR_V2.contains(";owner-tombstone=0")
        );
        assert!(
            !PRIVATE_ORAM_MUTATION_PROTOCOL_CAPABILITY_DESCRIPTOR_V2.contains(";owner-tombstone=1")
        );
    }
}
