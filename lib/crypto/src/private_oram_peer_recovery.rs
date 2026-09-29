use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::PrivateOramIndexKindV2;

pub const PRIVATE_ORAM_PEER_RECOVERY_RESPONSE_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-peer-recovery-response-signature/v2";
pub const PRIVATE_ORAM_PEER_RECOVERY_KEY_ID_DOMAIN: &str =
    "qdrant-sec/private-oram-peer-recovery-key-id/v1";
pub const PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION: u16 = 2;
pub const PRIVATE_ORAM_PEER_RECOVERY_PUBLIC_KEY_VERSION: u16 = 1;
pub const PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION: u16 = 1;
pub const PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const PRIVATE_ORAM_PEER_RECOVERY_TERMINAL_EVIDENCE_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-mutation-owner-terminal-evidence/v2";
pub const PRIVATE_ORAM_OWNER_ADOPTION_REQUEST_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-adoption-request-signature/v1";
pub const PRIVATE_ORAM_OWNER_ADOPTION_RESPONSE_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-adoption-response-signature/v1";
pub const PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_PEER_RECOVERY_REQUEST_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-peer-recovery-request-signature/v2";

const PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES: usize = 16;
const PRIVATE_ORAM_PEER_RECOVERY_REQUIRED_INDEXES: usize = 2;
const MAX_COLLECTION_NAME_BYTES: usize = 255;
const MAX_VECTOR_NAME_BYTES: usize = 255;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const BASE64URL_NOPAD_16_BYTE_LEN: usize = 22;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramPeerRecoveryError {
    #[error("private ORAM peer recovery protocol version is unsupported")]
    UnsupportedProtocolVersion(u16),
    #[error("private ORAM peer recovery public key version is unsupported")]
    UnsupportedPublicKeyVersion(u16),
    #[error("private ORAM peer recovery signature version is unsupported")]
    UnsupportedSignatureVersion(u16),
    #[error("private ORAM peer recovery field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM peer recovery response context does not match")]
    ResponseContextMismatch(&'static str),
    #[error("private ORAM peer recovery signature algorithm is unsupported")]
    UnsupportedSignatureAlgorithm,
    #[error("private ORAM peer recovery signature key does not match")]
    SignatureKeyMismatch,
    #[error("private ORAM peer recovery public key is malformed")]
    MalformedPublicKey,
    #[error("private ORAM peer recovery signature is malformed")]
    MalformedSignature,
    #[error("private ORAM peer recovery signature verification failed")]
    InvalidSignature,
    #[error("private ORAM peer recovery terminal evidence digest does not match")]
    TerminalEvidenceDigestMismatch,
    #[error("private ORAM peer recovery secure randomness is unavailable")]
    RandomnessUnavailable,
}

impl Debug for PrivateOramPeerRecoveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateOramPeerRecoveryError")
            .field(&self.to_string())
            .finish()
    }
}

pub fn new_private_oram_peer_recovery_challenge_nonce_v2()
-> Result<String, PrivateOramPeerRecoveryError> {
    let mut challenge = [0_u8; PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| PrivateOramPeerRecoveryError::RandomnessUnavailable)?;
    Ok(BASE64URL_NOPAD.encode(&challenge))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerRecoveryRequestV2 {
    pub protocol_version: u16,
    pub challenge_nonce: String,
    pub collection_name: String,
    pub collection_id: String,
    pub mutation_id: String,
    pub parent_descriptor_digest: String,
    pub decision_record_digest: String,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub vector_name: String,
    pub owner_signing_key_id: String,
}

impl Debug for PrivateOramPeerRecoveryRequestV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerRecoveryRequestV2")
            .field("protocol_version", &self.protocol_version)
            .field("challenge_nonce", &"[redacted]")
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("decision_record_digest", &"[redacted]")
            .field("coordinator_peer_id", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("owner_signing_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramPeerRecoveryTerminalKindV2 {
    FinalizedNew,
    AbortedOld,
}

impl PrivateOramPeerRecoveryTerminalKindV2 {
    const fn tag(self) -> u8 {
        match self {
            Self::FinalizedNew => 1,
            Self::AbortedOld => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerRecoveryTerminalIndexV2 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub prepared_journal_digest: String,
    pub terminal_state_digest: String,
}

impl Debug for PrivateOramPeerRecoveryTerminalIndexV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerRecoveryTerminalIndexV2")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("terminal_state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerRecoveryTerminalV2 {
    pub protocol_version: u16,
    pub challenge_nonce: String,
    pub owner_peer_id: u64,
    pub terminal_kind: PrivateOramPeerRecoveryTerminalKindV2,
    pub journal_descriptor_digest: String,
    pub prepared_state_digest: String,
    pub terminal_record_digest: String,
    pub parent_descriptor_digest: String,
    pub decision_authority_record_digest: String,
    pub reconciliation_authority_digest: String,
    pub indexes: Vec<PrivateOramPeerRecoveryTerminalIndexV2>,
    pub terminal_evidence_digest: String,
}

impl Debug for PrivateOramPeerRecoveryTerminalV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerRecoveryTerminalV2")
            .field("protocol_version", &self.protocol_version)
            .field("challenge_nonce", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("terminal_kind", &self.terminal_kind)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("decision_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .field("terminal_evidence_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerRecoveryPublicKeyV1 {
    pub version: u16,
    pub alg: String,
    pub key_epoch: u64,
    pub key_id: String,
    pub public_key: String,
}

impl Debug for PrivateOramPeerRecoveryPublicKeyV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerRecoveryPublicKeyV1")
            .field("version", &self.version)
            .field("alg", &"[redacted]")
            .field("key_epoch", &self.key_epoch)
            .field("key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramPeerRecoverySignatureV2 {
    pub version: u16,
    pub alg: String,
    pub key_epoch: u64,
    pub key_id: String,
    pub sig: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerAdoptionRequestV1 {
    pub version: u16,
    pub challenge_nonce: String,
    pub collection_name: String,
    pub collection_id: String,
    pub mutation_id: String,
    pub mutation_digest: String,
    pub transition_digest: String,
    pub lease_generation: u64,
    pub writer_fence: u64,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub vector_name: String,
    pub owner_signing_key_id: String,
    pub intent_key: String,
    pub package_sha256: String,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub parent_canonical_sha256: String,
    pub parent_canonical_len: u64,
}

impl Debug for PrivateOramOwnerAdoptionRequestV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerAdoptionRequestV1")
            .field("version", &self.version)
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("coordinator_peer_id", &self.coordinator_peer_id)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("parent_canonical_len", &self.parent_canonical_len)
            .field("challenge_nonce", &"[redacted]")
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("intent_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerAdoptionResponseV1 {
    pub version: u16,
    pub challenge_nonce: String,
    pub owner_peer_id: u64,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub journal_descriptor_digest: String,
    pub evidence_canonical_sha256: String,
    pub evidence_canonical_len: u64,
}

impl Debug for PrivateOramOwnerAdoptionResponseV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerAdoptionResponseV1")
            .field("version", &self.version)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("evidence_canonical_len", &self.evidence_canonical_len)
            .field("challenge_nonce", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("journal_descriptor_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerAdoptionRequestV1 {
    request: PrivateOramOwnerAdoptionRequestV1,
}

impl VerifiedPrivateOramOwnerAdoptionRequestV1 {
    pub fn request(&self) -> &PrivateOramOwnerAdoptionRequestV1 {
        &self.request
    }
}

impl Debug for PrivateOramPeerRecoverySignatureV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPeerRecoverySignatureV2")
            .field("version", &self.version)
            .field("alg", &"[redacted]")
            .field("key_epoch", &self.key_epoch)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramPeerRecoveryResponseV2 {
    request: PrivateOramPeerRecoveryRequestV2,
    terminal: PrivateOramPeerRecoveryTerminalV2,
    public_key: PrivateOramPeerRecoveryPublicKeyV1,
    signature: PrivateOramPeerRecoverySignatureV2,
}

impl Debug for VerifiedPrivateOramPeerRecoveryResponseV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedPrivateOramPeerRecoveryResponseV2")
            .field("request", &"[redacted]")
            .field("terminal", &"[redacted]")
            .field("public_key", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl VerifiedPrivateOramPeerRecoveryResponseV2 {
    pub fn request(&self) -> &PrivateOramPeerRecoveryRequestV2 {
        &self.request
    }

    pub fn terminal(&self) -> &PrivateOramPeerRecoveryTerminalV2 {
        &self.terminal
    }

    pub fn public_key(&self) -> &PrivateOramPeerRecoveryPublicKeyV1 {
        &self.public_key
    }

    pub fn signature(&self) -> &PrivateOramPeerRecoverySignatureV2 {
        &self.signature
    }
}

pub fn validate_private_oram_peer_recovery_request_v2_shape(
    request: &PrivateOramPeerRecoveryRequestV2,
) -> Result<(), PrivateOramPeerRecoveryError> {
    if request.protocol_version != PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION {
        return Err(PrivateOramPeerRecoveryError::UnsupportedProtocolVersion(
            request.protocol_version,
        ));
    }
    decode_base64url_exact::<PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES>(
        &request.challenge_nonce,
        BASE64URL_NOPAD_16_BYTE_LEN,
        "challenge_nonce",
    )?;
    validate_bounded_name(
        &request.collection_name,
        MAX_COLLECTION_NAME_BYTES,
        "collection_name",
    )?;
    validate_resource_id(&request.collection_id, "collection_id")?;
    decode_base64url_32(&request.mutation_id, "mutation_id")?;
    decode_base64url_32(
        &request.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    decode_base64url_32(&request.decision_record_digest, "decision_record_digest")?;
    // Peer id 0 is Raft's "no peer" sentinel: a request naming it as either party is
    // meaningless, and the adoption and capsule-transport requests already refuse it.
    if request.coordinator_peer_id == 0 || request.coordinator_peer_id == request.owner_peer_id {
        return Err(PrivateOramPeerRecoveryError::InvalidField(
            "coordinator_peer_id",
        ));
    }
    if request.owner_peer_id == 0 {
        return Err(PrivateOramPeerRecoveryError::InvalidField("owner_peer_id"));
    }
    validate_bounded_name(&request.vector_name, MAX_VECTOR_NAME_BYTES, "vector_name")?;
    validate_resource_id(&request.owner_signing_key_id, "owner_signing_key_id")?;
    Ok(())
}

pub fn validate_private_oram_peer_recovery_terminal_v2(
    request: &PrivateOramPeerRecoveryRequestV2,
    terminal: &PrivateOramPeerRecoveryTerminalV2,
) -> Result<(), PrivateOramPeerRecoveryError> {
    let expected = try_private_oram_peer_recovery_terminal_evidence_digest_v2(request, terminal)?;
    decode_base64url_32(
        &terminal.terminal_evidence_digest,
        "terminal_evidence_digest",
    )?;
    if terminal.terminal_evidence_digest != expected {
        return Err(PrivateOramPeerRecoveryError::TerminalEvidenceDigestMismatch);
    }
    Ok(())
}

pub fn try_private_oram_peer_recovery_terminal_evidence_digest_v2(
    request: &PrivateOramPeerRecoveryRequestV2,
    terminal: &PrivateOramPeerRecoveryTerminalV2,
) -> Result<String, PrivateOramPeerRecoveryError> {
    validate_private_oram_peer_recovery_terminal_evidence_fields_v2(request, terminal)?;

    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_PEER_RECOVERY_TERMINAL_EVIDENCE_DIGEST_DOMAIN.as_bytes());
    hash_base64url_32(
        &mut hasher,
        &request.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    hasher.update([terminal.terminal_kind.tag()]);
    hasher.update(terminal.owner_peer_id.to_be_bytes());
    hash_base64url_32(
        &mut hasher,
        &terminal.journal_descriptor_digest,
        "journal_descriptor_digest",
    )?;
    hash_base64url_32(
        &mut hasher,
        &terminal.prepared_state_digest,
        "prepared_state_digest",
    )?;
    hash_base64url_32(
        &mut hasher,
        &terminal.terminal_record_digest,
        "terminal_record_digest",
    )?;
    hash_base64url_32(
        &mut hasher,
        &terminal.parent_descriptor_digest,
        "terminal.parent_descriptor_digest",
    )?;
    hash_base64url_32(
        &mut hasher,
        &terminal.decision_authority_record_digest,
        "decision_authority_record_digest",
    )?;
    hash_base64url_32(
        &mut hasher,
        &terminal.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )?;
    hash_usize(&mut hasher, terminal.indexes.len())?;
    for index in &terminal.indexes {
        hasher.update([index_kind_tag(index.kind)]);
        hash_str(&mut hasher, &index.index_name)?;
        hash_base64url_32(
            &mut hasher,
            &index.prepared_journal_digest,
            "prepared_journal_digest",
        )?;
        hash_base64url_32(
            &mut hasher,
            &index.terminal_state_digest,
            "terminal_state_digest",
        )?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_private_oram_peer_recovery_terminal_evidence_fields_v2(
    request: &PrivateOramPeerRecoveryRequestV2,
    terminal: &PrivateOramPeerRecoveryTerminalV2,
) -> Result<(), PrivateOramPeerRecoveryError> {
    validate_private_oram_peer_recovery_request_v2_shape(request)?;
    if terminal.protocol_version != PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION {
        return Err(PrivateOramPeerRecoveryError::UnsupportedProtocolVersion(
            terminal.protocol_version,
        ));
    }
    decode_base64url_exact::<PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES>(
        &terminal.challenge_nonce,
        BASE64URL_NOPAD_16_BYTE_LEN,
        "terminal.challenge_nonce",
    )?;
    if terminal.challenge_nonce != request.challenge_nonce {
        return Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
            "challenge_nonce",
        ));
    }
    if terminal.owner_peer_id != request.owner_peer_id {
        return Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
            "owner_peer_id",
        ));
    }
    decode_base64url_32(
        &terminal.journal_descriptor_digest,
        "journal_descriptor_digest",
    )?;
    decode_base64url_32(&terminal.prepared_state_digest, "prepared_state_digest")?;
    decode_base64url_32(&terminal.terminal_record_digest, "terminal_record_digest")?;
    decode_base64url_32(
        &terminal.parent_descriptor_digest,
        "terminal.parent_descriptor_digest",
    )?;
    if terminal.parent_descriptor_digest != request.parent_descriptor_digest {
        return Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
            "parent_descriptor_digest",
        ));
    }
    decode_base64url_32(
        &terminal.decision_authority_record_digest,
        "decision_authority_record_digest",
    )?;
    if terminal.decision_authority_record_digest != request.decision_record_digest {
        return Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
            "decision_authority_record_digest",
        ));
    }
    decode_base64url_32(
        &terminal.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )?;
    validate_terminal_indexes(&terminal.indexes)?;
    Ok(())
}

pub fn private_oram_peer_recovery_key_id(public_key: &[u8; 32]) -> String {
    let mut message =
        Vec::with_capacity(4 + PRIVATE_ORAM_PEER_RECOVERY_KEY_ID_DOMAIN.len() + public_key.len());
    push_u32(
        &mut message,
        u32::try_from(PRIVATE_ORAM_PEER_RECOVERY_KEY_ID_DOMAIN.len())
            .expect("private ORAM peer recovery key-id domain length fits u32"),
    );
    message.extend_from_slice(PRIVATE_ORAM_PEER_RECOVERY_KEY_ID_DOMAIN.as_bytes());
    message.extend_from_slice(public_key);
    BASE64URL_NOPAD.encode(Sha256::digest(&message).as_ref())
}

pub fn private_oram_peer_recovery_public_key_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
) -> Result<PrivateOramPeerRecoveryPublicKeyV1, PrivateOramPeerRecoveryError> {
    if key_epoch == 0 {
        return Err(PrivateOramPeerRecoveryError::InvalidField("key_epoch"));
    }
    let public_key: [u8; 32] = key_pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| PrivateOramPeerRecoveryError::MalformedPublicKey)?;
    Ok(PrivateOramPeerRecoveryPublicKeyV1 {
        version: PRIVATE_ORAM_PEER_RECOVERY_PUBLIC_KEY_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: private_oram_peer_recovery_key_id(&public_key),
        public_key: BASE64URL_NOPAD.encode(&public_key),
    })
}

pub fn validate_private_oram_peer_recovery_public_key_v1(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<[u8; 32], PrivateOramPeerRecoveryError> {
    if public_key.version != PRIVATE_ORAM_PEER_RECOVERY_PUBLIC_KEY_VERSION {
        return Err(PrivateOramPeerRecoveryError::UnsupportedPublicKeyVersion(
            public_key.version,
        ));
    }
    if public_key.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM {
        return Err(PrivateOramPeerRecoveryError::UnsupportedSignatureAlgorithm);
    }
    if public_key.key_epoch == 0 {
        return Err(PrivateOramPeerRecoveryError::InvalidField("key_epoch"));
    }
    let decoded = decode_public_key(&public_key.public_key)?;
    if public_key.key_id != private_oram_peer_recovery_key_id(&decoded) {
        return Err(PrivateOramPeerRecoveryError::SignatureKeyMismatch);
    }
    Ok(decoded)
}

pub fn validate_private_oram_peer_recovery_signature_v2_shape(
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<(), PrivateOramPeerRecoveryError> {
    if signature.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION {
        return Err(PrivateOramPeerRecoveryError::UnsupportedSignatureVersion(
            signature.version,
        ));
    }
    if signature.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM {
        return Err(PrivateOramPeerRecoveryError::UnsupportedSignatureAlgorithm);
    }
    if signature.key_epoch == 0 {
        return Err(PrivateOramPeerRecoveryError::InvalidField(
            "signature.key_epoch",
        ));
    }
    decode_base64url_32(&signature.key_id, "signature.key_id")?;
    decode_signature(&signature.sig)?;
    Ok(())
}

pub fn validate_private_oram_owner_adoption_request_v1(
    request: &PrivateOramOwnerAdoptionRequestV1,
) -> Result<(), PrivateOramPeerRecoveryError> {
    if request.version != PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1 {
        return Err(PrivateOramPeerRecoveryError::UnsupportedProtocolVersion(
            request.version,
        ));
    }
    decode_base64url_exact::<PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES>(
        &request.challenge_nonce,
        BASE64URL_NOPAD_16_BYTE_LEN,
        "challenge_nonce",
    )?;
    validate_bounded_name(
        &request.collection_name,
        MAX_COLLECTION_NAME_BYTES,
        "collection_name",
    )?;
    validate_resource_id(&request.collection_id, "collection_id")?;
    validate_resource_id(&request.owner_signing_key_id, "owner_signing_key_id")?;
    validate_resource_id(&request.intent_key, "intent_key")?;
    validate_bounded_name(&request.vector_name, MAX_VECTOR_NAME_BYTES, "vector_name")?;
    for (value, field) in [
        (&request.mutation_id, "mutation_id"),
        (&request.mutation_digest, "mutation_digest"),
        (&request.transition_digest, "transition_digest"),
        (&request.package_sha256, "package_sha256"),
        (
            &request.parent_descriptor_digest,
            "parent_descriptor_digest",
        ),
        (
            &request.parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        ),
        (&request.parent_canonical_sha256, "parent_canonical_sha256"),
    ] {
        decode_base64url_32(value, field)?;
    }
    if request.lease_generation == 0
        || request.writer_fence == 0
        || request.lease_generation != request.writer_fence
        || request.coordinator_peer_id == 0
        || request.owner_peer_id == 0
        || request.coordinator_peer_id == request.owner_peer_id
        || request.parent_canonical_len == 0
        || request.parent_canonical_len > 64 * 1024
    {
        return Err(PrivateOramPeerRecoveryError::InvalidField(
            "owner_adoption_request",
        ));
    }
    Ok(())
}

pub fn validate_private_oram_owner_adoption_response_v1(
    request: &PrivateOramOwnerAdoptionRequestV1,
    response: &PrivateOramOwnerAdoptionResponseV1,
    evidence_canonical_json: &[u8],
) -> Result<(), PrivateOramPeerRecoveryError> {
    validate_private_oram_owner_adoption_request_v1(request)?;
    if response.version != PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1
        || response.challenge_nonce != request.challenge_nonce
        || response.owner_peer_id != request.owner_peer_id
        || response.parent_descriptor_digest != request.parent_descriptor_digest
        || response.parent_lease_acquired_record_digest
            != request.parent_lease_acquired_record_digest
        || response.evidence_canonical_len
            != u64::try_from(evidence_canonical_json.len())
                .map_err(|_| PrivateOramPeerRecoveryError::InvalidField("evidence_canonical_len"))?
        || response.evidence_canonical_len == 0
        || response.evidence_canonical_len > 64 * 1024
    {
        return Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
            "owner_adoption_response",
        ));
    }
    decode_base64url_32(
        &response.journal_descriptor_digest,
        "journal_descriptor_digest",
    )?;
    decode_base64url_32(
        &response.evidence_canonical_sha256,
        "evidence_canonical_sha256",
    )?;
    if response.evidence_canonical_sha256 != sha256_base64url(evidence_canonical_json) {
        return Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
            "evidence_canonical_sha256",
        ));
    }
    Ok(())
}

pub fn sign_private_oram_owner_adoption_request_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramOwnerAdoptionRequestV1,
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerRecoveryError> {
    let public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)?;
    let message = private_oram_owner_adoption_request_signature_message_v1(request, &public_key)?;
    Ok(peer_signature(key_pair, public_key, &message))
}

pub fn validate_private_oram_owner_adoption_request_signature_v1(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramOwnerAdoptionRequestV1,
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<VerifiedPrivateOramOwnerAdoptionRequestV1, PrivateOramPeerRecoveryError> {
    let public_key_bytes = validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    validate_private_oram_peer_recovery_signature_v2_shape(signature)?;
    validate_signature_matches_public_key(signature, public_key)?;
    let message = private_oram_owner_adoption_request_signature_message_v1(request, public_key)?;
    verify_peer_signature(public_key_bytes, signature, &message)?;
    Ok(VerifiedPrivateOramOwnerAdoptionRequestV1 {
        request: request.clone(),
    })
}

pub fn sign_private_oram_owner_adoption_response_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramOwnerAdoptionRequestV1,
    response: &PrivateOramOwnerAdoptionResponseV1,
    evidence_canonical_json: &[u8],
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerRecoveryError> {
    let public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)?;
    let message = private_oram_owner_adoption_response_signature_message_v1(
        request,
        response,
        evidence_canonical_json,
        &public_key,
    )?;
    Ok(peer_signature(key_pair, public_key, &message))
}

pub fn validate_private_oram_owner_adoption_response_signature_v1(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramOwnerAdoptionRequestV1,
    response: &PrivateOramOwnerAdoptionResponseV1,
    evidence_canonical_json: &[u8],
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<(), PrivateOramPeerRecoveryError> {
    let public_key_bytes = validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    validate_private_oram_peer_recovery_signature_v2_shape(signature)?;
    validate_signature_matches_public_key(signature, public_key)?;
    let message = private_oram_owner_adoption_response_signature_message_v1(
        request,
        response,
        evidence_canonical_json,
        public_key,
    )?;
    verify_peer_signature(public_key_bytes, signature, &message)
}

fn private_oram_owner_adoption_request_signature_message_v1(
    request: &PrivateOramOwnerAdoptionRequestV1,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramPeerRecoveryError> {
    validate_private_oram_owner_adoption_request_v1(request)?;
    validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_ADOPTION_REQUEST_SIGNATURE_DOMAIN_V1.as_bytes(),
    )?;
    push_owner_adoption_request(&mut message, request)?;
    push_peer_public_key(&mut message, public_key)?;
    Ok(message)
}

fn private_oram_owner_adoption_response_signature_message_v1(
    request: &PrivateOramOwnerAdoptionRequestV1,
    response: &PrivateOramOwnerAdoptionResponseV1,
    evidence_canonical_json: &[u8],
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramPeerRecoveryError> {
    validate_private_oram_owner_adoption_response_v1(request, response, evidence_canonical_json)?;
    validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_ADOPTION_RESPONSE_SIGNATURE_DOMAIN_V1.as_bytes(),
    )?;
    push_owner_adoption_request(&mut message, request)?;
    push_u16(&mut message, response.version);
    try_push_str(&mut message, &response.challenge_nonce)?;
    push_u64(&mut message, response.owner_peer_id);
    try_push_str(&mut message, &response.parent_descriptor_digest)?;
    try_push_str(&mut message, &response.parent_lease_acquired_record_digest)?;
    try_push_str(&mut message, &response.journal_descriptor_digest)?;
    try_push_str(&mut message, &response.evidence_canonical_sha256)?;
    push_u64(&mut message, response.evidence_canonical_len);
    push_peer_public_key(&mut message, public_key)?;
    Ok(message)
}

fn push_owner_adoption_request(
    message: &mut Vec<u8>,
    request: &PrivateOramOwnerAdoptionRequestV1,
) -> Result<(), PrivateOramPeerRecoveryError> {
    push_u16(message, request.version);
    try_push_str(message, &request.challenge_nonce)?;
    try_push_str(message, &request.collection_name)?;
    try_push_str(message, &request.collection_id)?;
    try_push_str(message, &request.mutation_id)?;
    try_push_str(message, &request.mutation_digest)?;
    try_push_str(message, &request.transition_digest)?;
    push_u64(message, request.lease_generation);
    push_u64(message, request.writer_fence);
    push_u64(message, request.coordinator_peer_id);
    push_u64(message, request.owner_peer_id);
    try_push_str(message, &request.vector_name)?;
    try_push_str(message, &request.owner_signing_key_id)?;
    try_push_str(message, &request.intent_key)?;
    try_push_str(message, &request.package_sha256)?;
    try_push_str(message, &request.parent_descriptor_digest)?;
    try_push_str(message, &request.parent_lease_acquired_record_digest)?;
    try_push_str(message, &request.parent_canonical_sha256)?;
    push_u64(message, request.parent_canonical_len);
    Ok(())
}

fn push_peer_public_key(
    message: &mut Vec<u8>,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<(), PrivateOramPeerRecoveryError> {
    push_u16(message, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION);
    push_u16(message, public_key.version);
    try_push_str(message, &public_key.alg)?;
    push_u64(message, public_key.key_epoch);
    try_push_str(message, &public_key.key_id)?;
    try_push_str(message, &public_key.public_key)
}

fn peer_signature(
    key_pair: &Ed25519KeyPair,
    public_key: PrivateOramPeerRecoveryPublicKeyV1,
    message: &[u8],
) -> PrivateOramPeerRecoverySignatureV2 {
    PrivateOramPeerRecoverySignatureV2 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: public_key.alg,
        key_epoch: public_key.key_epoch,
        key_id: public_key.key_id,
        sig: BASE64URL_NOPAD.encode(key_pair.sign(message).as_ref()),
    }
}

fn validate_signature_matches_public_key(
    signature: &PrivateOramPeerRecoverySignatureV2,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<(), PrivateOramPeerRecoveryError> {
    if signature.alg != public_key.alg
        || signature.key_epoch != public_key.key_epoch
        || signature.key_id != public_key.key_id
    {
        return Err(PrivateOramPeerRecoveryError::SignatureKeyMismatch);
    }
    Ok(())
}

fn verify_peer_signature(
    public_key_bytes: [u8; 32],
    signature: &PrivateOramPeerRecoverySignatureV2,
    message: &[u8],
) -> Result<(), PrivateOramPeerRecoveryError> {
    let signature_bytes = decode_signature(&signature.sig)?;
    UnparsedPublicKey::new(&ED25519, public_key_bytes)
        .verify(message, &signature_bytes)
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidSignature)
}

fn sha256_base64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(bytes))
}

pub fn try_private_oram_peer_recovery_response_signature_message_v2(
    request: &PrivateOramPeerRecoveryRequestV2,
    terminal: &PrivateOramPeerRecoveryTerminalV2,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramPeerRecoveryError> {
    validate_private_oram_peer_recovery_terminal_v2(request, terminal)?;
    validate_private_oram_peer_recovery_public_key_v1(public_key)?;

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_PEER_RECOVERY_RESPONSE_SIGNATURE_DOMAIN.as_bytes(),
    )?;
    push_u16(&mut message, request.protocol_version);
    try_push_str(&mut message, &request.challenge_nonce)?;
    try_push_str(&mut message, &request.collection_name)?;
    try_push_str(&mut message, &request.collection_id)?;
    try_push_str(&mut message, &request.mutation_id)?;
    try_push_str(&mut message, &request.parent_descriptor_digest)?;
    try_push_str(&mut message, &request.decision_record_digest)?;
    push_u64(&mut message, request.coordinator_peer_id);
    push_u64(&mut message, request.owner_peer_id);
    try_push_str(&mut message, &request.vector_name)?;
    try_push_str(&mut message, &request.owner_signing_key_id)?;

    push_u16(&mut message, terminal.protocol_version);
    try_push_str(&mut message, &terminal.challenge_nonce)?;
    push_u64(&mut message, terminal.owner_peer_id);
    message.push(terminal.terminal_kind.tag());
    try_push_str(&mut message, &terminal.journal_descriptor_digest)?;
    try_push_str(&mut message, &terminal.prepared_state_digest)?;
    try_push_str(&mut message, &terminal.terminal_record_digest)?;
    try_push_str(&mut message, &terminal.parent_descriptor_digest)?;
    try_push_str(&mut message, &terminal.decision_authority_record_digest)?;
    try_push_str(&mut message, &terminal.reconciliation_authority_digest)?;
    push_u32(
        &mut message,
        u32::try_from(terminal.indexes.len())
            .map_err(|_| PrivateOramPeerRecoveryError::InvalidField("indexes"))?,
    );
    for index in &terminal.indexes {
        message.push(index_kind_tag(index.kind));
        try_push_str(&mut message, &index.index_name)?;
        try_push_str(&mut message, &index.prepared_journal_digest)?;
        try_push_str(&mut message, &index.terminal_state_digest)?;
    }
    try_push_str(&mut message, &terminal.terminal_evidence_digest)?;

    push_u16(&mut message, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION);
    push_u16(&mut message, public_key.version);
    try_push_str(&mut message, &public_key.alg)?;
    push_u64(&mut message, public_key.key_epoch);
    try_push_str(&mut message, &public_key.key_id)?;
    try_push_str(&mut message, &public_key.public_key)?;
    Ok(message)
}

fn private_oram_peer_recovery_request_signature_message_v2(
    request: &PrivateOramPeerRecoveryRequestV2,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramPeerRecoveryError> {
    validate_private_oram_peer_recovery_request_v2_shape(request)?;
    validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_PEER_RECOVERY_REQUEST_SIGNATURE_DOMAIN_V2.as_bytes(),
    )?;
    push_u16(&mut message, request.protocol_version);
    try_push_str(&mut message, &request.challenge_nonce)?;
    try_push_str(&mut message, &request.collection_name)?;
    try_push_str(&mut message, &request.collection_id)?;
    try_push_str(&mut message, &request.mutation_id)?;
    try_push_str(&mut message, &request.parent_descriptor_digest)?;
    try_push_str(&mut message, &request.decision_record_digest)?;
    push_u64(&mut message, request.coordinator_peer_id);
    push_u64(&mut message, request.owner_peer_id);
    try_push_str(&mut message, &request.vector_name)?;
    try_push_str(&mut message, &request.owner_signing_key_id)?;
    push_peer_public_key(&mut message, public_key)?;
    Ok(message)
}

/// Signs a peer recovery request as the coordinator. An owner verifies this against its pinned
/// coordinator identity before it takes lifecycle locks, reads its journal and signs a fresh
/// terminal for the caller's nonce, so reaching the internal endpoint is not enough to make an
/// owner do that work.
pub fn sign_private_oram_peer_recovery_request_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramPeerRecoveryRequestV2,
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerRecoveryError> {
    let public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)?;
    let message = private_oram_peer_recovery_request_signature_message_v2(request, &public_key)?;
    Ok(peer_signature(key_pair, public_key, &message))
}

pub fn validate_private_oram_peer_recovery_request_signature_v2(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramPeerRecoveryRequestV2,
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<(), PrivateOramPeerRecoveryError> {
    let public_key_bytes = validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    validate_private_oram_peer_recovery_signature_v2_shape(signature)?;
    validate_signature_matches_public_key(signature, public_key)?;
    let message = private_oram_peer_recovery_request_signature_message_v2(request, public_key)?;
    verify_peer_signature(public_key_bytes, signature, &message)
}

pub fn sign_private_oram_peer_recovery_response_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramPeerRecoveryRequestV2,
    terminal: &PrivateOramPeerRecoveryTerminalV2,
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerRecoveryError> {
    let public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)?;
    let message = try_private_oram_peer_recovery_response_signature_message_v2(
        request,
        terminal,
        &public_key,
    )?;
    Ok(PrivateOramPeerRecoverySignatureV2 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: public_key.alg,
        key_epoch: public_key.key_epoch,
        key_id: public_key.key_id,
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

pub fn validate_private_oram_peer_recovery_response_signature_v2(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramPeerRecoveryRequestV2,
    terminal: &PrivateOramPeerRecoveryTerminalV2,
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<VerifiedPrivateOramPeerRecoveryResponseV2, PrivateOramPeerRecoveryError> {
    let public_key_bytes = validate_private_oram_peer_recovery_public_key_v1(public_key)?;
    validate_private_oram_peer_recovery_signature_v2_shape(signature)?;
    if signature.alg != public_key.alg
        || signature.key_epoch != public_key.key_epoch
        || signature.key_id != public_key.key_id
    {
        return Err(PrivateOramPeerRecoveryError::SignatureKeyMismatch);
    }
    let signature_bytes = decode_signature(&signature.sig)?;
    let message = try_private_oram_peer_recovery_response_signature_message_v2(
        request, terminal, public_key,
    )?;
    UnparsedPublicKey::new(&ED25519, public_key_bytes)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidSignature)?;
    Ok(VerifiedPrivateOramPeerRecoveryResponseV2 {
        request: request.clone(),
        terminal: terminal.clone(),
        public_key: public_key.clone(),
        signature: signature.clone(),
    })
}

fn validate_terminal_indexes(
    indexes: &[PrivateOramPeerRecoveryTerminalIndexV2],
) -> Result<(), PrivateOramPeerRecoveryError> {
    if indexes.len() != PRIVATE_ORAM_PEER_RECOVERY_REQUIRED_INDEXES {
        return Err(PrivateOramPeerRecoveryError::InvalidField("indexes"));
    }
    if indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || indexes[1].kind != PrivateOramIndexKindV2::Result
    {
        return Err(PrivateOramPeerRecoveryError::InvalidField("indexes"));
    }
    for index in indexes {
        validate_bounded_name(&index.index_name, MAX_RESOURCE_ID_BYTES, "index_name")?;
        decode_base64url_32(&index.prepared_journal_digest, "prepared_journal_digest")?;
        decode_base64url_32(&index.terminal_state_digest, "terminal_state_digest")?;
    }
    Ok(())
}

const fn index_kind_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => 1,
        PrivateOramIndexKindV2::Result => 2,
    }
}

fn validate_bounded_name(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), PrivateOramPeerRecoveryError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(PrivateOramPeerRecoveryError::InvalidField(field));
    }
    Ok(())
}

fn validate_resource_id(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramPeerRecoveryError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(PrivateOramPeerRecoveryError::InvalidField(field));
    }
    Ok(())
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], PrivateOramPeerRecoveryError> {
    decode_base64url_exact::<32>(value, BASE64URL_NOPAD_32_BYTE_LEN, field)
}

fn decode_base64url_exact<const N: usize>(
    value: &str,
    encoded_len: usize,
    field: &'static str,
) -> Result<[u8; N], PrivateOramPeerRecoveryError> {
    if value.len() != encoded_len {
        return Err(PrivateOramPeerRecoveryError::InvalidField(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidField(field))?;
    if BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramPeerRecoveryError::InvalidField(field));
    }
    decoded
        .try_into()
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidField(field))
}

/// Public keys and signatures follow the same length-then-decode-then-re-encode rule as every
/// other fixed-size field, so one canonical string maps to one byte string everywhere.
fn decode_public_key(value: &str) -> Result<[u8; 32], PrivateOramPeerRecoveryError> {
    decode_base64url_exact::<32>(value, BASE64URL_NOPAD_32_BYTE_LEN, "public_key")
        .map_err(|_| PrivateOramPeerRecoveryError::MalformedPublicKey)
}

fn decode_signature(value: &str) -> Result<[u8; 64], PrivateOramPeerRecoveryError> {
    decode_base64url_exact::<64>(value, BASE64URL_NOPAD_64_BYTE_LEN, "signature")
        .map_err(|_| PrivateOramPeerRecoveryError::MalformedSignature)
}

fn hash_base64url_32(
    hasher: &mut Sha256,
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramPeerRecoveryError> {
    hasher.update(decode_base64url_32(value, field)?);
    Ok(())
}

fn hash_str(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramPeerRecoveryError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidField("terminal_evidence"))?;
    hasher.update(len.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_usize(hasher: &mut Sha256, value: usize) -> Result<(), PrivateOramPeerRecoveryError> {
    let value = u64::try_from(value)
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidField("terminal_evidence"))?;
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn try_push_domain(
    message: &mut Vec<u8>,
    domain: &[u8],
) -> Result<(), PrivateOramPeerRecoveryError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidField("signature_message"))?;
    push_u32(message, len);
    message.extend_from_slice(domain);
    Ok(())
}

fn try_push_str(message: &mut Vec<u8>, value: &str) -> Result<(), PrivateOramPeerRecoveryError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramPeerRecoveryError::InvalidField("signature_message"))?;
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

    fn deterministic_key_pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn digest(value: u8) -> String {
        BASE64URL_NOPAD.encode(&[value; 32])
    }

    fn request() -> PrivateOramPeerRecoveryRequestV2 {
        PrivateOramPeerRecoveryRequestV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: BASE64URL_NOPAD.encode(&[7; 16]),
            collection_name: "docs".to_string(),
            collection_id: "collection-uuid-1".to_string(),
            mutation_id: digest(13),
            parent_descriptor_digest: digest(11),
            decision_record_digest: digest(12),
            coordinator_peer_id: 17,
            owner_peer_id: 23,
            vector_name: "text".to_string(),
            owner_signing_key_id: "tenant-a/private-oram-owner-v1".to_string(),
        }
    }

    fn terminal(request: &PrivateOramPeerRecoveryRequestV2) -> PrivateOramPeerRecoveryTerminalV2 {
        let mut terminal = PrivateOramPeerRecoveryTerminalV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: request.challenge_nonce.clone(),
            owner_peer_id: request.owner_peer_id,
            terminal_kind: PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew,
            journal_descriptor_digest: digest(21),
            prepared_state_digest: digest(22),
            terminal_record_digest: digest(23),
            parent_descriptor_digest: request.parent_descriptor_digest.clone(),
            decision_authority_record_digest: request.decision_record_digest.clone(),
            reconciliation_authority_digest: digest(24),
            indexes: vec![
                PrivateOramPeerRecoveryTerminalIndexV2 {
                    kind: PrivateOramIndexKindV2::Hnsw,
                    index_name: "text".to_string(),
                    prepared_journal_digest: digest(31),
                    terminal_state_digest: digest(32),
                },
                PrivateOramPeerRecoveryTerminalIndexV2 {
                    kind: PrivateOramIndexKindV2::Result,
                    index_name: "payload".to_string(),
                    prepared_journal_digest: digest(33),
                    terminal_state_digest: digest(34),
                },
            ],
            terminal_evidence_digest: String::new(),
        };
        terminal.terminal_evidence_digest =
            try_private_oram_peer_recovery_terminal_evidence_digest_v2(request, &terminal).unwrap();
        terminal
    }

    #[test]
    fn peer_recovery_request_shape_rejects_the_no_peer_sentinel_for_either_party() {
        validate_private_oram_peer_recovery_request_v2_shape(&request()).unwrap();

        let mut zero_owner = request();
        zero_owner.owner_peer_id = 0;
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&zero_owner).unwrap_err(),
            PrivateOramPeerRecoveryError::InvalidField("owner_peer_id"),
        );

        let mut zero_coordinator = request();
        zero_coordinator.coordinator_peer_id = 0;
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&zero_coordinator).unwrap_err(),
            PrivateOramPeerRecoveryError::InvalidField("coordinator_peer_id"),
        );

        let mut same_peer = request();
        same_peer.coordinator_peer_id = same_peer.owner_peer_id;
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&same_peer).unwrap_err(),
            PrivateOramPeerRecoveryError::InvalidField("coordinator_peer_id"),
        );
    }

    #[test]
    fn peer_recovery_challenge_nonce_uses_fresh_fixed_width_randomness() {
        let first = new_private_oram_peer_recovery_challenge_nonce_v2().unwrap();
        let second = new_private_oram_peer_recovery_challenge_nonce_v2().unwrap();

        assert_eq!(first.len(), BASE64URL_NOPAD_16_BYTE_LEN);
        assert_eq!(BASE64URL_NOPAD.decode(first.as_bytes()).unwrap().len(), 16);
        assert_eq!(second.len(), BASE64URL_NOPAD_16_BYTE_LEN);
        assert_eq!(BASE64URL_NOPAD.decode(second.as_bytes()).unwrap().len(), 16);
        assert_ne!(first, second);
    }

    #[test]
    fn peer_recovery_signature_known_answer_is_stable() {
        let key_pair = deterministic_key_pair(29);
        let request = request();
        let terminal = terminal(&request);
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        assert_eq!(
            terminal.terminal_evidence_digest,
            "0u73kqaaMHmjC1TZCifJLWqowSeRtn4VCUxZeEns_wE"
        );
        let message = try_private_oram_peer_recovery_response_signature_message_v2(
            &request,
            &terminal,
            &public_key,
        )
        .unwrap();
        assert_eq!(
            BASE64URL_NOPAD.encode(Sha256::digest(&message).as_ref()),
            "23_OFcMuUlqgtoH1AL9NB8JejpYM3tECJWwTMzvKQrI"
        );
        assert_eq!(
            public_key.key_id,
            "Tnsw6SHwxa_8oKrmNDTKjGKX-HA2lqq-dItw9cGgP1k"
        );
        let signature =
            sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal).unwrap();
        assert_eq!(
            signature.sig,
            "uNtuu4ebIiX6DMMsX12f9u1tOThYUTVoaU7j4i8d9GgzKfB7oP4YQkzHQ4eQBDL5g3kR9RRRAULEyeGEEDpRAA"
        );
    }

    #[test]
    fn peer_recovery_signature_round_trips_and_binds_every_request_locator() {
        let key_pair = deterministic_key_pair(29);
        let request = request();
        let terminal = terminal(&request);
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        let signature =
            sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal).unwrap();
        let verified = validate_private_oram_peer_recovery_response_signature_v2(
            &public_key,
            &request,
            &terminal,
            &signature,
        )
        .unwrap();
        assert_eq!(verified.request(), &request);
        assert_eq!(verified.terminal(), &terminal);
        assert_eq!(verified.public_key(), &public_key);
        assert_eq!(verified.signature(), &signature);

        let mut variants = Vec::new();
        let mut value = request.clone();
        value.challenge_nonce = BASE64URL_NOPAD.encode(&[8; 16]);
        variants.push(value);
        let mut value = request.clone();
        value.collection_name = "other-docs".to_string();
        variants.push(value);
        let mut value = request.clone();
        value.collection_id = "collection-uuid-2".to_string();
        variants.push(value);
        let mut value = request.clone();
        value.mutation_id = digest(50);
        variants.push(value);
        let mut value = request.clone();
        value.parent_descriptor_digest = digest(51);
        variants.push(value);
        let mut value = request.clone();
        value.decision_record_digest = digest(52);
        variants.push(value);
        let mut value = request.clone();
        value.coordinator_peer_id = 19;
        variants.push(value);
        let mut value = request.clone();
        value.owner_peer_id = 29;
        variants.push(value);
        let mut value = request.clone();
        value.vector_name = "other-vector".to_string();
        variants.push(value);
        let mut value = request.clone();
        value.owner_signing_key_id = "tenant-a/private-oram-owner-v2".to_string();
        variants.push(value);

        for tampered in variants {
            assert!(
                validate_private_oram_peer_recovery_response_signature_v2(
                    &public_key,
                    &tampered,
                    &terminal,
                    &signature,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn peer_recovery_signature_binds_terminal_and_index_evidence() {
        let key_pair = deterministic_key_pair(29);
        let request = request();
        let terminal = terminal(&request);
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        let signature =
            sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal).unwrap();

        let mut variants = Vec::new();
        let mut value = terminal.clone();
        value.terminal_kind = PrivateOramPeerRecoveryTerminalKindV2::AbortedOld;
        variants.push(value);
        let mut value = terminal.clone();
        value.journal_descriptor_digest = digest(61);
        variants.push(value);
        let mut value = terminal.clone();
        value.prepared_state_digest = digest(62);
        variants.push(value);
        let mut value = terminal.clone();
        value.terminal_record_digest = digest(63);
        variants.push(value);
        let mut value = terminal.clone();
        value.reconciliation_authority_digest = digest(64);
        variants.push(value);
        let mut value = terminal.clone();
        value.indexes[0].index_name = "other-text".to_string();
        variants.push(value);
        let mut value = terminal.clone();
        value.indexes[0].prepared_journal_digest = digest(65);
        variants.push(value);
        let mut value = terminal.clone();
        value.indexes[1].terminal_state_digest = digest(66);
        variants.push(value);
        for mut tampered in variants {
            tampered.terminal_evidence_digest =
                try_private_oram_peer_recovery_terminal_evidence_digest_v2(&request, &tampered)
                    .unwrap();
            assert_eq!(
                validate_private_oram_peer_recovery_response_signature_v2(
                    &public_key,
                    &request,
                    &tampered,
                    &signature,
                ),
                Err(PrivateOramPeerRecoveryError::InvalidSignature)
            );
        }

        let mut mismatched_digest = terminal.clone();
        mismatched_digest.terminal_evidence_digest = digest(67);
        assert_eq!(
            validate_private_oram_peer_recovery_terminal_v2(&request, &mismatched_digest),
            Err(PrivateOramPeerRecoveryError::TerminalEvidenceDigestMismatch)
        );
    }

    #[test]
    fn peer_recovery_rejects_context_replay_noncanonical_indexes_and_wrong_key() {
        let key_pair = deterministic_key_pair(29);
        let request = request();
        let terminal = terminal(&request);
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        let signature =
            sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal).unwrap();

        let mut stale = terminal.clone();
        stale.challenge_nonce = BASE64URL_NOPAD.encode(&[8; 16]);
        assert!(matches!(
            validate_private_oram_peer_recovery_response_signature_v2(
                &public_key,
                &request,
                &stale,
                &signature,
            ),
            Err(PrivateOramPeerRecoveryError::ResponseContextMismatch(
                "challenge_nonce"
            ))
        ));

        let mut reordered = terminal.clone();
        reordered.indexes.swap(0, 1);
        assert!(matches!(
            validate_private_oram_peer_recovery_terminal_v2(&request, &reordered),
            Err(PrivateOramPeerRecoveryError::InvalidField("indexes"))
        ));

        let mut duplicate = terminal.clone();
        duplicate.indexes[1] = duplicate.indexes[0].clone();
        assert!(matches!(
            validate_private_oram_peer_recovery_terminal_v2(&request, &duplicate),
            Err(PrivateOramPeerRecoveryError::InvalidField("indexes"))
        ));

        let mut hnsw_only = terminal.clone();
        hnsw_only.indexes.pop();
        assert_eq!(
            validate_private_oram_peer_recovery_terminal_v2(&request, &hnsw_only),
            Err(PrivateOramPeerRecoveryError::InvalidField("indexes"))
        );

        let mut oversized = terminal.clone();
        oversized.indexes.push(oversized.indexes[1].clone());
        assert_eq!(
            validate_private_oram_peer_recovery_terminal_v2(&request, &oversized),
            Err(PrivateOramPeerRecoveryError::InvalidField("indexes"))
        );

        let wrong_public_key =
            private_oram_peer_recovery_public_key_v1(&deterministic_key_pair(30), 1).unwrap();
        assert_eq!(
            validate_private_oram_peer_recovery_response_signature_v2(
                &wrong_public_key,
                &request,
                &terminal,
                &signature,
            ),
            Err(PrivateOramPeerRecoveryError::SignatureKeyMismatch)
        );

        let mut malformed = signature;
        malformed.sig = "signature-sentinel".to_string();
        assert_eq!(
            validate_private_oram_peer_recovery_response_signature_v2(
                &public_key,
                &request,
                &terminal,
                &malformed,
            ),
            Err(PrivateOramPeerRecoveryError::MalformedSignature)
        );
    }

    #[test]
    fn peer_recovery_request_requires_canonical_locators_and_bounded_names() {
        let request = request();
        validate_private_oram_peer_recovery_request_v2_shape(&request).unwrap();

        let mut non_digest_mutation = request.clone();
        non_digest_mutation.mutation_id = "mutation-uuid-1".to_string();
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&non_digest_mutation),
            Err(PrivateOramPeerRecoveryError::InvalidField("mutation_id"))
        );

        let mut padded_mutation = request.clone();
        padded_mutation.mutation_id.push('=');
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&padded_mutation),
            Err(PrivateOramPeerRecoveryError::InvalidField("mutation_id"))
        );

        let mut noncanonical_trailing_bits = request.clone();
        assert!(noncanonical_trailing_bits.mutation_id.ends_with('0'));
        noncanonical_trailing_bits.mutation_id.pop();
        noncanonical_trailing_bits.mutation_id.push('1');
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&noncanonical_trailing_bits),
            Err(PrivateOramPeerRecoveryError::InvalidField("mutation_id"))
        );

        let mut max_name = request.clone();
        max_name.collection_name = "a".repeat(MAX_COLLECTION_NAME_BYTES);
        max_name.vector_name = "text-\u{00e9}".to_string();
        validate_private_oram_peer_recovery_request_v2_shape(&max_name).unwrap();

        let mut oversized_name = request.clone();
        oversized_name.collection_name = "a".repeat(MAX_COLLECTION_NAME_BYTES + 1);
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&oversized_name),
            Err(PrivateOramPeerRecoveryError::InvalidField(
                "collection_name"
            ))
        );

        let mut control_name = request;
        control_name.vector_name = "text\nsecret".to_string();
        assert_eq!(
            validate_private_oram_peer_recovery_request_v2_shape(&control_name),
            Err(PrivateOramPeerRecoveryError::InvalidField("vector_name"))
        );
    }

    #[test]
    fn peer_recovery_public_key_descriptor_is_self_authenticating() {
        let public_key =
            private_oram_peer_recovery_public_key_v1(&deterministic_key_pair(29), 1).unwrap();
        validate_private_oram_peer_recovery_public_key_v1(&public_key).unwrap();

        let mut wrong_version = public_key.clone();
        wrong_version.version += 1;
        assert!(matches!(
            validate_private_oram_peer_recovery_public_key_v1(&wrong_version),
            Err(PrivateOramPeerRecoveryError::UnsupportedPublicKeyVersion(_))
        ));

        let mut wrong_algorithm = public_key.clone();
        wrong_algorithm.alg = "other".to_string();
        assert_eq!(
            validate_private_oram_peer_recovery_public_key_v1(&wrong_algorithm),
            Err(PrivateOramPeerRecoveryError::UnsupportedSignatureAlgorithm)
        );

        let mut zero_epoch = public_key.clone();
        zero_epoch.key_epoch = 0;
        assert_eq!(
            validate_private_oram_peer_recovery_public_key_v1(&zero_epoch),
            Err(PrivateOramPeerRecoveryError::InvalidField("key_epoch"))
        );

        let mut wrong_key_id = public_key.clone();
        wrong_key_id.key_id = digest(90);
        assert_eq!(
            validate_private_oram_peer_recovery_public_key_v1(&wrong_key_id),
            Err(PrivateOramPeerRecoveryError::SignatureKeyMismatch)
        );

        let mut substituted_key = public_key;
        substituted_key.public_key = BASE64URL_NOPAD.encode(&[91; 32]);
        assert_eq!(
            validate_private_oram_peer_recovery_public_key_v1(&substituted_key),
            Err(PrivateOramPeerRecoveryError::SignatureKeyMismatch)
        );
    }

    #[test]
    fn peer_recovery_debug_redacts_identity_and_evidence() {
        let key_pair = deterministic_key_pair(29);
        let request = request();
        let terminal = terminal(&request);
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        let signature =
            sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal).unwrap();
        let verified = validate_private_oram_peer_recovery_response_signature_v2(
            &public_key,
            &request,
            &terminal,
            &signature,
        )
        .unwrap();
        let rendered =
            format!("{request:?} {terminal:?} {public_key:?} {signature:?} {verified:?}");
        for sentinel in [
            &request.challenge_nonce,
            &request.collection_id,
            &request.mutation_id,
            &terminal.terminal_record_digest,
            &terminal.indexes[0].prepared_journal_digest,
            &public_key.public_key,
            &public_key.key_id,
            &signature.sig,
        ] {
            assert!(!rendered.contains(sentinel));
        }
    }

    #[test]
    fn peer_recovery_request_signature_round_trips_and_binds_the_coordinator_key() {
        let coordinator = deterministic_key_pair(33);
        let request = request();
        let public_key = private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
        let signature =
            sign_private_oram_peer_recovery_request_v2(&coordinator, 1, &request).unwrap();
        validate_private_oram_peer_recovery_request_signature_v2(&public_key, &request, &signature)
            .unwrap();

        let other =
            private_oram_peer_recovery_public_key_v1(&deterministic_key_pair(34), 1).unwrap();
        assert!(
            validate_private_oram_peer_recovery_request_signature_v2(&other, &request, &signature)
                .is_err()
        );
        let mut replayed = request.clone();
        replayed.challenge_nonce = BASE64URL_NOPAD.encode(&[9; 16]);
        assert!(
            validate_private_oram_peer_recovery_request_signature_v2(
                &public_key,
                &replayed,
                &signature
            )
            .is_err()
        );
        let mut other_owner = request.clone();
        other_owner.owner_peer_id += 1;
        assert!(
            validate_private_oram_peer_recovery_request_signature_v2(
                &public_key,
                &other_owner,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn owner_adoption_signatures_bind_parent_and_evidence() {
        let coordinator = deterministic_key_pair(31);
        let owner = deterministic_key_pair(32);
        let coordinator_public = private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
        let owner_public = private_oram_peer_recovery_public_key_v1(&owner, 1).unwrap();
        let request = PrivateOramOwnerAdoptionRequestV1 {
            version: PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1,
            challenge_nonce: BASE64URL_NOPAD
                .encode(&[7; PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES]),
            collection_name: "docs".to_string(),
            collection_id: "collection-a".to_string(),
            mutation_id: digest(1),
            mutation_digest: digest(2),
            transition_digest: digest(3),
            lease_generation: 7,
            writer_fence: 7,
            coordinator_peer_id: 11,
            owner_peer_id: 12,
            vector_name: "text".to_string(),
            owner_signing_key_id: "owner-key".to_string(),
            intent_key: "intent-key".to_string(),
            package_sha256: digest(4),
            parent_descriptor_digest: digest(5),
            parent_lease_acquired_record_digest: digest(6),
            parent_canonical_sha256: digest(7),
            parent_canonical_len: 512,
        };
        let request_signature =
            sign_private_oram_owner_adoption_request_v1(&coordinator, 1, &request).unwrap();
        let _verified_request = validate_private_oram_owner_adoption_request_signature_v1(
            &coordinator_public,
            &request,
            &request_signature,
        )
        .unwrap();

        let evidence = br#"{"owner_peer_id":12}"#;
        let response = PrivateOramOwnerAdoptionResponseV1 {
            version: PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1,
            challenge_nonce: request.challenge_nonce.clone(),
            owner_peer_id: request.owner_peer_id,
            parent_descriptor_digest: request.parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: request
                .parent_lease_acquired_record_digest
                .clone(),
            journal_descriptor_digest: digest(8),
            evidence_canonical_sha256: sha256_base64url(evidence),
            evidence_canonical_len: evidence.len() as u64,
        };
        let response_signature =
            sign_private_oram_owner_adoption_response_v1(&owner, 1, &request, &response, evidence)
                .unwrap();
        validate_private_oram_owner_adoption_response_signature_v1(
            &owner_public,
            &request,
            &response,
            evidence,
            &response_signature,
        )
        .unwrap();

        let mut substituted_parent = request.clone();
        substituted_parent.parent_descriptor_digest = digest(9);
        assert!(
            validate_private_oram_owner_adoption_request_signature_v1(
                &coordinator_public,
                &substituted_parent,
                &request_signature,
            )
            .is_err()
        );
        assert!(
            validate_private_oram_owner_adoption_response_signature_v1(
                &owner_public,
                &request,
                &response,
                br#"{"owner_peer_id":13}"#,
                &response_signature,
            )
            .is_err()
        );

        let rendered =
            format!("{request:?} {response:?} {request_signature:?} {response_signature:?}");
        for sentinel in [
            &request.challenge_nonce,
            &request.collection_id,
            &request.mutation_id,
            &request.parent_descriptor_digest,
            &response.evidence_canonical_sha256,
            &request_signature.sig,
            &response_signature.sig,
        ] {
            assert!(!rendered.contains(sentinel));
        }
    }

    mod field_mutation_fuzz {
        use proptest::prelude::*;

        use super::*;
        use crate::json_mutation::mutate_json_leaf;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(192))]

            /// Every scalar field of a recovery request, its terminal, the response signature
            /// and an adoption request is covered by the signature: changing any one of them is
            /// rejected.
            #[test]
            fn every_field_mutation_is_rejected(index in any::<usize>(), salt in any::<u8>()) {
                let key_pair = deterministic_key_pair(29);
                let request = request();
                let terminal = terminal(&request);
                let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
                let signature =
                    sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal)
                        .unwrap();

                let mut value = serde_json::to_value(&request).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) = serde_json::from_value::<PrivateOramPeerRecoveryRequestV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_peer_recovery_response_signature_v2(
                            &public_key,
                            &mutated,
                            &terminal,
                            &signature,
                        )
                        .is_err(),
                        "request mutation at {} was accepted",
                        path
                    );
                }
                let mut value = serde_json::to_value(&terminal).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramPeerRecoveryTerminalV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_peer_recovery_response_signature_v2(
                            &public_key,
                            &request,
                            &mutated,
                            &signature,
                        )
                        .is_err(),
                        "terminal mutation at {} was accepted",
                        path
                    );
                }
                let mut value = serde_json::to_value(&signature).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramPeerRecoverySignatureV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_peer_recovery_response_signature_v2(
                            &public_key,
                            &request,
                            &terminal,
                            &mutated,
                        )
                        .is_err(),
                        "signature mutation at {} was accepted",
                        path
                    );
                }

                let coordinator = deterministic_key_pair(31);
                let coordinator_public =
                    private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
                let adoption = PrivateOramOwnerAdoptionRequestV1 {
                    version: PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1,
                    challenge_nonce: BASE64URL_NOPAD
                        .encode(&[7; PRIVATE_ORAM_PEER_RECOVERY_CHALLENGE_BYTES]),
                    collection_name: "docs".to_string(),
                    collection_id: "collection-a".to_string(),
                    mutation_id: digest(1),
                    mutation_digest: digest(2),
                    transition_digest: digest(3),
                    lease_generation: 7,
                    writer_fence: 7,
                    coordinator_peer_id: 11,
                    owner_peer_id: 12,
                    vector_name: "text".to_string(),
                    owner_signing_key_id: "owner-key".to_string(),
                    intent_key: "intent-key".to_string(),
                    package_sha256: digest(4),
                    parent_descriptor_digest: digest(5),
                    parent_lease_acquired_record_digest: digest(6),
                    parent_canonical_sha256: digest(7),
                    parent_canonical_len: 512,
                };
                let adoption_signature =
                    sign_private_oram_owner_adoption_request_v1(&coordinator, 1, &adoption).unwrap();
                let mut value = serde_json::to_value(&adoption).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramOwnerAdoptionRequestV1>(value)
                {
                    prop_assert!(
                        validate_private_oram_owner_adoption_request_signature_v1(
                            &coordinator_public,
                            &mutated,
                            &adoption_signature,
                        )
                        .is_err(),
                        "adoption request mutation at {} was accepted",
                        path
                    );
                }

                let request_signature =
                    sign_private_oram_peer_recovery_request_v2(&coordinator, 1, &request).unwrap();
                let mut value = serde_json::to_value(&request).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramPeerRecoveryRequestV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_peer_recovery_request_signature_v2(
                            &coordinator_public,
                            &mutated,
                            &request_signature,
                        )
                        .is_err(),
                        "recovery request mutation at {} was accepted",
                        path
                    );
                }
            }
        }
    }
}
