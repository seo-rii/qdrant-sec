//! Owner-signed receipt for resolving an exact committed reservation challenge.

use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramOwnerCleanupSignerV1, PrivateOramPeerRecoveryPublicKeyV1,
    validate_private_oram_peer_recovery_public_key_v1,
};

pub const PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-reservation-resolution-signature/v1";

const RESOLUTION_RECEIPT_DIGEST_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-reservation-resolution-receipt/v1";
const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_CANONICAL_BYTES: usize = 128 * 1024;

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = encoded.parse::<u64>().map_err(serde::de::Error::custom)?;
        if encoded != value.to_string() {
            return Err(serde::de::Error::custom("non-canonical integer"));
        }
        Ok(value)
    }
}

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramOwnerReservationResolutionError {
    #[error("private ORAM owner reservation resolution field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM owner reservation resolution context does not match")]
    ContextMismatch,
    #[error("private ORAM owner reservation resolution signer does not match")]
    SignerMismatch,
    #[error("private ORAM owner reservation resolution signature is invalid")]
    InvalidSignature,
    #[error("private ORAM owner reservation resolution encoding is not canonical")]
    NonCanonicalEncoding,
}

impl Debug for PrivateOramOwnerReservationResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramOwnerReservationResolutionError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerReservationResolutionDispositionV1 {
    FinalizedInstalled,
    FinalizedReleasedAfterAbort,
    CancelledReleased,
}

impl PrivateOramOwnerReservationResolutionDispositionV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::FinalizedInstalled => 1,
            Self::FinalizedReleasedAfterAbort => 2,
            Self::CancelledReleased => 3,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerReservationResolutionUnsignedReceiptV1 {
    pub version: u16,
    pub disposition: PrivateOramOwnerReservationResolutionDispositionV1,
    pub collection_id: String,
    #[serde(with = "decimal_u64")]
    pub owner_peer_id: u64,
    pub committed_challenge_digest: String,
    pub reservation_intent_digest: String,
    pub attempt_id: String,
    #[serde(with = "decimal_u64")]
    pub challenge_applied_term: u64,
    #[serde(with = "decimal_u64")]
    pub challenge_applied_index: u64,
    #[serde(with = "decimal_u64")]
    pub resolution_applied_term: u64,
    #[serde(with = "decimal_u64")]
    pub resolution_applied_index: u64,
    pub reserved_terminal_intent_key: String,
    pub finalized_reservation_digest: Option<String>,
    pub durable_fence_record_digest: String,
    pub owner_store_incarnation_digest: String,
    pub owner_store_binding_digest: String,
    pub installed_intent_marker_digest: Option<String>,
    pub installed_prestage_receipt_digest: Option<String>,
    pub installed_package_sha256: Option<String>,
    pub abort_release_authority_digest: Option<String>,
    pub abort_release_marker_digest: Option<String>,
    pub local_resolution_record_digest: String,
}

impl Debug for PrivateOramOwnerReservationResolutionUnsignedReceiptV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationResolutionUnsignedReceiptV1")
            .field("version", &self.version)
            .field("disposition", &self.disposition)
            .field("collection_id", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("committed_challenge_digest", &"[redacted]")
            .field("reservation_intent_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("challenge_applied_term", &"[redacted]")
            .field("challenge_applied_index", &"[redacted]")
            .field("resolution_applied_term", &"[redacted]")
            .field("resolution_applied_index", &"[redacted]")
            .field("reserved_terminal_intent_key", &"[redacted]")
            .field("finalized_reservation_digest", &"[redacted]")
            .field("durable_fence_record_digest", &"[redacted]")
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("owner_store_binding_digest", &"[redacted]")
            .field("installed_intent_marker_digest", &"[redacted]")
            .field("installed_prestage_receipt_digest", &"[redacted]")
            .field("installed_package_sha256", &"[redacted]")
            .field("abort_release_authority_digest", &"[redacted]")
            .field("abort_release_marker_digest", &"[redacted]")
            .field("local_resolution_record_digest", &"[redacted]")
            .finish()
    }
}

pub type PrivateOramOwnerReservationResolutionReceiptV1 =
    PrivateOramOwnerReservationResolutionUnsignedReceiptV1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerReservationResolutionSignatureV1 {
    pub version: u16,
    pub alg: String,
    #[serde(with = "decimal_u64")]
    pub key_epoch: u64,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateOramOwnerReservationResolutionSignatureV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationResolutionSignatureV1")
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
pub struct SignedPrivateOramOwnerReservationResolutionReceiptV1 {
    pub version: u16,
    pub receipt: PrivateOramOwnerReservationResolutionReceiptV1,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub receipt_digest: String,
    pub signature: PrivateOramOwnerReservationResolutionSignatureV1,
}

impl Debug for SignedPrivateOramOwnerReservationResolutionReceiptV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPrivateOramOwnerReservationResolutionReceiptV1")
            .field("version", &self.version)
            .field("receipt", &self.receipt)
            .field("owner_signer", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerReservationResolutionReceiptV1 {
    signed_receipt: SignedPrivateOramOwnerReservationResolutionReceiptV1,
}

impl VerifiedPrivateOramOwnerReservationResolutionReceiptV1 {
    pub fn signed_receipt(&self) -> &SignedPrivateOramOwnerReservationResolutionReceiptV1 {
        &self.signed_receipt
    }

    pub fn receipt(&self) -> &PrivateOramOwnerReservationResolutionReceiptV1 {
        &self.signed_receipt.receipt
    }
}

impl Debug for VerifiedPrivateOramOwnerReservationResolutionReceiptV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerReservationResolutionReceiptV1")
            .field("signed_receipt", &"[verified]")
            .finish()
    }
}

pub fn sign_private_oram_owner_reservation_resolution_receipt_v1(
    owner_key: &Ed25519KeyPair,
    receipt: PrivateOramOwnerReservationResolutionReceiptV1,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
) -> Result<
    SignedPrivateOramOwnerReservationResolutionReceiptV1,
    PrivateOramOwnerReservationResolutionError,
> {
    validate_receipt(&receipt)?;
    validate_signer(&owner_signer)?;
    let public_key = decode_base64_exact(&owner_signer.public_key, DIGEST_BYTES, "public_key")?;
    if owner_key.public_key().as_ref() != public_key.as_slice() {
        return Err(PrivateOramOwnerReservationResolutionError::SignerMismatch);
    }

    let receipt_digest = resolution_receipt_digest(&receipt)?;
    let message = signature_message(&receipt_digest, &owner_signer)?;
    let signature = owner_key.sign(&message);
    let signed_receipt = SignedPrivateOramOwnerReservationResolutionReceiptV1 {
        version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
        receipt,
        owner_signer: owner_signer.clone(),
        receipt_digest,
        signature: PrivateOramOwnerReservationResolutionSignatureV1 {
            version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
            alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
            key_epoch: owner_signer.key_epoch,
            key_id: owner_signer.key_id,
            sig: BASE64URL_NOPAD.encode(signature.as_ref()),
        },
    };
    validate_signed_receipt_shape(&signed_receipt)?;
    Ok(signed_receipt)
}

pub fn validate_private_oram_owner_reservation_resolution_receipt_v1(
    signed_receipt: &SignedPrivateOramOwnerReservationResolutionReceiptV1,
    expected_owner_signer: &PrivateOramOwnerCleanupSignerV1,
    expected_receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<
    VerifiedPrivateOramOwnerReservationResolutionReceiptV1,
    PrivateOramOwnerReservationResolutionError,
> {
    validate_signed_receipt_shape(signed_receipt)?;
    validate_signer(expected_owner_signer)?;
    validate_receipt(expected_receipt)?;
    if &signed_receipt.owner_signer != expected_owner_signer {
        return Err(PrivateOramOwnerReservationResolutionError::SignerMismatch);
    }
    if &signed_receipt.receipt != expected_receipt {
        return Err(PrivateOramOwnerReservationResolutionError::ContextMismatch);
    }
    verify_signature(
        expected_owner_signer,
        &signed_receipt.signature,
        &signed_receipt.receipt_digest,
    )?;
    Ok(VerifiedPrivateOramOwnerReservationResolutionReceiptV1 {
        signed_receipt: signed_receipt.clone(),
    })
}

pub fn validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1(
    signed_receipt: &SignedPrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<
    VerifiedPrivateOramOwnerReservationResolutionReceiptV1,
    PrivateOramOwnerReservationResolutionError,
> {
    validate_signed_receipt_shape(signed_receipt)?;
    verify_signature(
        &signed_receipt.owner_signer,
        &signed_receipt.signature,
        &signed_receipt.receipt_digest,
    )?;
    Ok(VerifiedPrivateOramOwnerReservationResolutionReceiptV1 {
        signed_receipt: signed_receipt.clone(),
    })
}

pub fn validate_private_oram_owner_reservation_resolution_receipt_shape_v1(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    validate_receipt(receipt)
}

pub fn private_oram_owner_reservation_resolution_receipt_digest_v1(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<String, PrivateOramOwnerReservationResolutionError> {
    validate_receipt(receipt)?;
    resolution_receipt_digest(receipt)
}

pub fn private_oram_owner_reservation_resolution_signature_message_v1(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
    owner_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    validate_receipt(receipt)?;
    validate_signer(owner_signer)?;
    signature_message(&resolution_receipt_digest(receipt)?, owner_signer)
}

pub fn encode_private_oram_owner_reservation_resolution_receipt_v1(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    validate_receipt(receipt)?;
    canonical_json(receipt)
}

pub fn decode_private_oram_owner_reservation_resolution_receipt_v1(
    bytes: &[u8],
) -> Result<
    PrivateOramOwnerReservationResolutionReceiptV1,
    PrivateOramOwnerReservationResolutionError,
> {
    let receipt = canonical_decode(bytes)?;
    validate_receipt(&receipt)?;
    Ok(receipt)
}

pub fn encode_signed_private_oram_owner_reservation_resolution_receipt_v1(
    signed_receipt: &SignedPrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    validate_signed_receipt_shape(signed_receipt)?;
    canonical_json(signed_receipt)
}

pub fn decode_signed_private_oram_owner_reservation_resolution_receipt_v1(
    bytes: &[u8],
) -> Result<
    SignedPrivateOramOwnerReservationResolutionReceiptV1,
    PrivateOramOwnerReservationResolutionError,
> {
    let signed_receipt = canonical_decode(bytes)?;
    validate_signed_receipt_shape(&signed_receipt)?;
    Ok(signed_receipt)
}

fn validate_receipt(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    if receipt.version != PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1
        || receipt.owner_peer_id == 0
        || receipt.challenge_applied_term == 0
        || receipt.challenge_applied_index == 0
        || receipt.resolution_applied_term == 0
        || receipt.resolution_applied_index == 0
        || receipt.resolution_applied_term < receipt.challenge_applied_term
        || receipt.resolution_applied_index <= receipt.challenge_applied_index
    {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "receipt",
        ));
    }
    validate_identifier(&receipt.collection_id, "collection_id")?;
    for (value, field) in [
        (
            &receipt.committed_challenge_digest,
            "committed_challenge_digest",
        ),
        (
            &receipt.reservation_intent_digest,
            "reservation_intent_digest",
        ),
        (&receipt.attempt_id, "attempt_id"),
        (
            &receipt.reserved_terminal_intent_key,
            "reserved_terminal_intent_key",
        ),
        (
            &receipt.local_resolution_record_digest,
            "local_resolution_record_digest",
        ),
    ] {
        validate_digest(value, field)?;
    }
    match (
        receipt.disposition,
        receipt.finalized_reservation_digest.as_deref(),
    ) {
        (PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled, Some(digest))
        | (
            PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort,
            Some(digest),
        ) => validate_digest(digest, "finalized_reservation_digest"),
        (PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased, None) => Ok(()),
        _ => Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "finalized_reservation_digest",
        )),
    }?;
    for (value, field) in [
        (
            &receipt.durable_fence_record_digest,
            "durable_fence_record_digest",
        ),
        (
            &receipt.owner_store_incarnation_digest,
            "owner_store_incarnation_digest",
        ),
        (
            &receipt.owner_store_binding_digest,
            "owner_store_binding_digest",
        ),
    ] {
        validate_digest(value, field)?;
    }
    let completion_shape_valid = match receipt.disposition {
        PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled => {
            receipt.installed_intent_marker_digest.is_some()
                && receipt.installed_prestage_receipt_digest.is_some()
                && receipt.installed_package_sha256.is_some()
                && receipt.abort_release_authority_digest.is_none()
                && receipt.abort_release_marker_digest.is_none()
        }
        PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort => {
            receipt.installed_intent_marker_digest.is_none()
                && receipt.installed_prestage_receipt_digest.is_none()
                && receipt.installed_package_sha256.is_none()
                && receipt.abort_release_authority_digest.is_some()
                && receipt.abort_release_marker_digest.is_some()
        }
        PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased => {
            receipt.installed_intent_marker_digest.is_none()
                && receipt.installed_prestage_receipt_digest.is_none()
                && receipt.installed_package_sha256.is_none()
                && receipt.abort_release_authority_digest.is_none()
                && receipt.abort_release_marker_digest.is_none()
        }
    };
    if !completion_shape_valid {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "completion_evidence",
        ));
    }
    for (value, field) in [
        (
            receipt.installed_intent_marker_digest.as_deref(),
            "installed_intent_marker_digest",
        ),
        (
            receipt.installed_prestage_receipt_digest.as_deref(),
            "installed_prestage_receipt_digest",
        ),
        (
            receipt.installed_package_sha256.as_deref(),
            "installed_package_sha256",
        ),
        (
            receipt.abort_release_authority_digest.as_deref(),
            "abort_release_authority_digest",
        ),
        (
            receipt.abort_release_marker_digest.as_deref(),
            "abort_release_marker_digest",
        ),
    ] {
        if let Some(value) = value {
            validate_digest(value, field)?;
        }
    }
    ensure_canonical_size(receipt)
}

fn validate_signed_receipt_shape(
    signed_receipt: &SignedPrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    if signed_receipt.version != PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1 {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "version",
        ));
    }
    validate_receipt(&signed_receipt.receipt)?;
    validate_signer(&signed_receipt.owner_signer)?;
    validate_digest(&signed_receipt.receipt_digest, "receipt_digest")?;
    validate_signature_shape(&signed_receipt.signature, &signed_receipt.owner_signer)?;
    if signed_receipt.receipt_digest != resolution_receipt_digest(&signed_receipt.receipt)? {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "receipt_digest",
        ));
    }
    ensure_canonical_size(signed_receipt)
}

fn resolution_receipt_digest(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<String, PrivateOramOwnerReservationResolutionError> {
    let message = receipt_digest_message(receipt)?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn receipt_digest_message(
    receipt: &PrivateOramOwnerReservationResolutionReceiptV1,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    let mut message = Vec::new();
    append_domain(&mut message, RESOLUTION_RECEIPT_DIGEST_DOMAIN_V1.as_bytes())?;
    message.extend_from_slice(&receipt.version.to_be_bytes());
    message.push(receipt.disposition.tag());
    append_bytes(&mut message, receipt.collection_id.as_bytes())?;
    message.extend_from_slice(&receipt.owner_peer_id.to_be_bytes());
    append_digest(&mut message, &receipt.committed_challenge_digest)?;
    append_digest(&mut message, &receipt.reservation_intent_digest)?;
    append_digest(&mut message, &receipt.attempt_id)?;
    message.extend_from_slice(&receipt.challenge_applied_term.to_be_bytes());
    message.extend_from_slice(&receipt.challenge_applied_index.to_be_bytes());
    message.extend_from_slice(&receipt.resolution_applied_term.to_be_bytes());
    message.extend_from_slice(&receipt.resolution_applied_index.to_be_bytes());
    append_digest(&mut message, &receipt.reserved_terminal_intent_key)?;
    match &receipt.finalized_reservation_digest {
        Some(digest) => {
            message.push(1);
            append_digest(&mut message, digest)?;
        }
        None => message.push(0),
    }
    append_digest(&mut message, &receipt.durable_fence_record_digest)?;
    append_digest(&mut message, &receipt.owner_store_incarnation_digest)?;
    append_digest(&mut message, &receipt.owner_store_binding_digest)?;
    for value in [
        &receipt.installed_intent_marker_digest,
        &receipt.installed_prestage_receipt_digest,
        &receipt.installed_package_sha256,
        &receipt.abort_release_authority_digest,
        &receipt.abort_release_marker_digest,
    ] {
        match value {
            Some(digest) => {
                message.push(1);
                append_digest(&mut message, digest)?;
            }
            None => message.push(0),
        }
    }
    append_digest(&mut message, &receipt.local_resolution_record_digest)?;
    Ok(message)
}

fn signature_message(
    receipt_digest: &str,
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    let mut message = Vec::new();
    append_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_SIGNATURE_DOMAIN_V1.as_bytes(),
    )?;
    append_digest(&mut message, receipt_digest)?;
    message.extend_from_slice(&signer.version.to_be_bytes());
    append_bytes(&mut message, signer.alg.as_bytes())?;
    message.extend_from_slice(&signer.key_epoch.to_be_bytes());
    append_bytes(&mut message, signer.key_id.as_bytes())?;
    let public_key = decode_base64_exact(&signer.public_key, DIGEST_BYTES, "public_key")?;
    append_bytes(&mut message, &public_key)?;
    Ok(message)
}

fn append_digest(
    message: &mut Vec<u8>,
    value: &str,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    let digest = decode_base64_exact(value, DIGEST_BYTES, "digest")?;
    append_bytes(message, &digest)
}

fn append_domain(
    message: &mut Vec<u8>,
    domain: &[u8],
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    message.extend_from_slice(
        &u32::try_from(domain.len())
            .map_err(|_| PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding)?
            .to_be_bytes(),
    );
    message.extend_from_slice(domain);
    Ok(())
}

fn append_bytes(
    message: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    message.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding)?
            .to_be_bytes(),
    );
    message.extend_from_slice(value);
    Ok(())
}

fn verify_signature(
    signer: &PrivateOramOwnerCleanupSignerV1,
    signature: &PrivateOramOwnerReservationResolutionSignatureV1,
    receipt_digest: &str,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    let public_key = decode_base64_exact(&signer.public_key, DIGEST_BYTES, "public_key")?;
    let signature_bytes = decode_base64_exact(&signature.sig, SIGNATURE_BYTES, "signature")?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &signature_message(receipt_digest, signer)?,
            &signature_bytes,
        )
        .map_err(|_| PrivateOramOwnerReservationResolutionError::InvalidSignature)
}

fn validate_signer(
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    validate_private_oram_peer_recovery_public_key_v1(&PrivateOramPeerRecoveryPublicKeyV1 {
        version: signer.version,
        alg: signer.alg.clone(),
        key_epoch: signer.key_epoch,
        key_id: signer.key_id.clone(),
        public_key: signer.public_key.clone(),
    })
    .map(|_| ())
    .map_err(|_| PrivateOramOwnerReservationResolutionError::InvalidField("signer"))
}

fn validate_signature_shape(
    signature: &PrivateOramOwnerReservationResolutionSignatureV1,
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    if signature.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION
        || signature.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM
        || signature.key_epoch != signer.key_epoch
        || signature.key_id != signer.key_id
    {
        return Err(PrivateOramOwnerReservationResolutionError::SignerMismatch);
    }
    decode_base64_exact(&signature.sig, SIGNATURE_BYTES, "signature").map(|_| ())
}

fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    decode_base64_exact(value, DIGEST_BYTES, field).map(|_| ())
}

fn decode_base64_exact(
    value: &str,
    expected_len: usize,
    field: &'static str,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    // Encoded length first, so an oversized field is refused before any decoding.
    if value.len() != BASE64URL_NOPAD.encode_len(expected_len) {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            field,
        ));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerReservationResolutionError::InvalidField(field))?;
    if decoded.len() != expected_len || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            field,
        ));
    }
    Ok(decoded)
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            field,
        ));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, PrivateOramOwnerReservationResolutionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding)?;
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "canonical_bytes",
        ));
    }
    Ok(bytes)
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T, PrivateOramOwnerReservationResolutionError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerReservationResolutionError::InvalidField(
            "canonical_bytes",
        ));
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|_| PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding)?;
    if canonical_json(&value)? != bytes {
        return Err(PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn ensure_canonical_size<T: Serialize>(
    value: &T,
) -> Result<(), PrivateOramOwnerReservationResolutionError> {
    canonical_json(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::private_oram_owner_cleanup_signer_v1;

    fn digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; DIGEST_BYTES])
    }

    fn receipt() -> PrivateOramOwnerReservationResolutionReceiptV1 {
        PrivateOramOwnerReservationResolutionReceiptV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
            disposition: PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 11,
            committed_challenge_digest: digest(1),
            reservation_intent_digest: digest(2),
            attempt_id: digest(3),
            challenge_applied_term: 7,
            challenge_applied_index: 41,
            resolution_applied_term: 8,
            resolution_applied_index: 52,
            reserved_terminal_intent_key: digest(4),
            finalized_reservation_digest: Some(digest(5)),
            durable_fence_record_digest: digest(6),
            owner_store_incarnation_digest: digest(7),
            owner_store_binding_digest: digest(8),
            installed_intent_marker_digest: Some(digest(9)),
            installed_prestage_receipt_digest: Some(digest(10)),
            installed_package_sha256: Some(digest(11)),
            abort_release_authority_digest: None,
            abort_release_marker_digest: None,
            local_resolution_record_digest: digest(12),
        }
    }

    fn signed_fixture() -> (
        PrivateOramOwnerCleanupSignerV1,
        SignedPrivateOramOwnerReservationResolutionReceiptV1,
    ) {
        let key = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let signer = private_oram_owner_cleanup_signer_v1(&key, 4).unwrap();
        let signed = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &key,
            receipt(),
            signer.clone(),
        )
        .unwrap();
        (signer, signed)
    }

    #[test]
    fn resolution_receipt_signature_known_answer() {
        let (signer, signed) = signed_fixture();
        let message = private_oram_owner_reservation_resolution_signature_message_v1(
            &signed.receipt,
            &signer,
        )
        .unwrap();
        assert_eq!(
            BASE64URL_NOPAD.encode(&message),
            "AAAAQXFkcmFudC1zZWMvcHJpdmF0ZS1vcmFtLW93bmVyLXJlc2VydmF0aW9uLXJlc29sdXRpb24tc2lnbmF0dXJlL3YxAAAAAAAAACB9a1uIJHpDNTd8K9OiPqXDSN-SQHCF_OVlCwFMgZn5IAABAAAAAAAAAAdlZDI1NTE5AAAAAAAAAAQAAAAAAAAAK25hTVFiZHplcHF4MXNUX0JEajNhRENxQTNMVzBDMVpUWjJ5QWdtR3BCV1UAAAAAAAAAIEMEa_5AkrPpSZTq2hXcwg2Kqge2WP05VOuODvuL3KXe"
        );
        assert_eq!(
            signed.receipt_digest,
            "fWtbiCR6QzU3fCvToj6lw0jfkkBwhfzlZQsBTIGZ-SA"
        );
        assert_eq!(
            signed.signature.sig,
            "BnrLc30PZtv5ccxwI7RH5J0XwtrlLcUWvBVCDFk2WGLnP3PrAXwSH6wDJb1JDG2Oo-AB6ECZP84HbJ6UFAaCDA"
        );

        let verified = validate_private_oram_owner_reservation_resolution_receipt_v1(
            &signed,
            &signer,
            &signed.receipt,
        )
        .unwrap();
        assert_eq!(verified.receipt(), &signed.receipt);
        let encoded =
            encode_signed_private_oram_owner_reservation_resolution_receipt_v1(&signed).unwrap();
        assert_eq!(
            decode_signed_private_oram_owner_reservation_resolution_receipt_v1(&encoded).unwrap(),
            signed
        );
    }

    #[test]
    fn every_resolution_context_field_is_signature_bound() {
        let (signer, signed) = signed_fixture();
        let mut mutations = Vec::new();

        let mut value = signed.clone();
        value.receipt.collection_id = "collection-b".to_string();
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.owner_peer_id = 12;
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.committed_challenge_digest = digest(11);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.reservation_intent_digest = digest(12);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.attempt_id = digest(13);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.challenge_applied_term = 6;
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.challenge_applied_index = 40;
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.resolution_applied_term = 9;
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.resolution_applied_index = 53;
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.reserved_terminal_intent_key = digest(14);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.finalized_reservation_digest = Some(digest(15));
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.local_resolution_record_digest = digest(16);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.durable_fence_record_digest = digest(17);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.owner_store_incarnation_digest = digest(18);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.owner_store_binding_digest = digest(19);
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.installed_intent_marker_digest = Some(digest(20));
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.installed_prestage_receipt_digest = Some(digest(21));
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.installed_package_sha256 = Some(digest(22));
        mutations.push(value);
        let mut value = signed.clone();
        value.receipt.disposition =
            PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased;
        value.receipt.finalized_reservation_digest = None;
        value.receipt.installed_intent_marker_digest = None;
        value.receipt.installed_prestage_receipt_digest = None;
        value.receipt.installed_package_sha256 = None;
        mutations.push(value);

        for mut mutation in mutations {
            mutation.receipt_digest = resolution_receipt_digest(&mutation.receipt).unwrap();
            assert_eq!(
                validate_private_oram_owner_reservation_resolution_receipt_v1(
                    &mutation,
                    &signer,
                    &mutation.receipt,
                ),
                Err(PrivateOramOwnerReservationResolutionError::InvalidSignature)
            );
        }

        let key = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let mut abort_receipt = receipt();
        abort_receipt.disposition =
            PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort;
        abort_receipt.installed_intent_marker_digest = None;
        abort_receipt.installed_prestage_receipt_digest = None;
        abort_receipt.installed_package_sha256 = None;
        abort_receipt.abort_release_authority_digest = Some(digest(23));
        abort_receipt.abort_release_marker_digest = Some(digest(24));
        let abort_signed = sign_private_oram_owner_reservation_resolution_receipt_v1(
            &key,
            abort_receipt,
            signer.clone(),
        )
        .unwrap();
        for (index, mut mutation) in [abort_signed.clone(), abort_signed].into_iter().enumerate() {
            if index == 0 {
                mutation.receipt.abort_release_authority_digest = Some(digest(25));
            } else {
                mutation.receipt.abort_release_marker_digest = Some(digest(26));
            }
            mutation.receipt_digest = resolution_receipt_digest(&mutation.receipt).unwrap();
            assert_eq!(
                validate_private_oram_owner_reservation_resolution_receipt_v1(
                    &mutation,
                    &signer,
                    &mutation.receipt,
                ),
                Err(PrivateOramOwnerReservationResolutionError::InvalidSignature)
            );
        }
    }

    #[test]
    fn resolution_receipt_rejects_context_signer_and_signature_tampering() {
        let (signer, signed) = signed_fixture();

        let mut expected = signed.receipt.clone();
        expected.local_resolution_record_digest = digest(21);
        assert_eq!(
            validate_private_oram_owner_reservation_resolution_receipt_v1(
                &signed, &signer, &expected,
            ),
            Err(PrivateOramOwnerReservationResolutionError::ContextMismatch)
        );

        let other_key = Ed25519KeyPair::from_seed_unchecked(&[30; 32]).unwrap();
        let other_signer = private_oram_owner_cleanup_signer_v1(&other_key, 4).unwrap();
        assert_eq!(
            validate_private_oram_owner_reservation_resolution_receipt_v1(
                &signed,
                &other_signer,
                &signed.receipt,
            ),
            Err(PrivateOramOwnerReservationResolutionError::SignerMismatch)
        );

        let mut bad_signature = signed.clone();
        bad_signature.signature.sig = BASE64URL_NOPAD.encode(&[7; SIGNATURE_BYTES]);
        assert_eq!(
            validate_private_oram_owner_reservation_resolution_receipt_v1(
                &bad_signature,
                &signer,
                &bad_signature.receipt,
            ),
            Err(PrivateOramOwnerReservationResolutionError::InvalidSignature)
        );
    }

    #[test]
    fn resolution_receipt_enforces_disposition_locator_and_canonical_encoding() {
        let mut invalid = receipt();
        invalid.finalized_reservation_digest = None;
        assert_eq!(
            validate_private_oram_owner_reservation_resolution_receipt_shape_v1(&invalid),
            Err(PrivateOramOwnerReservationResolutionError::InvalidField(
                "finalized_reservation_digest"
            ))
        );

        invalid = receipt();
        invalid.disposition = PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased;
        assert_eq!(
            validate_private_oram_owner_reservation_resolution_receipt_shape_v1(&invalid),
            Err(PrivateOramOwnerReservationResolutionError::InvalidField(
                "finalized_reservation_digest"
            ))
        );

        invalid = receipt();
        invalid.resolution_applied_index = invalid.challenge_applied_index;
        assert_eq!(
            validate_private_oram_owner_reservation_resolution_receipt_shape_v1(&invalid),
            Err(PrivateOramOwnerReservationResolutionError::InvalidField(
                "receipt"
            ))
        );

        let encoded =
            encode_private_oram_owner_reservation_resolution_receipt_v1(&receipt()).unwrap();
        let mut non_canonical = b" ".to_vec();
        non_canonical.extend_from_slice(&encoded);
        assert_eq!(
            decode_private_oram_owner_reservation_resolution_receipt_v1(&non_canonical),
            Err(PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding)
        );

        let mut json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), serde_json::Value::Bool(true));
        assert_eq!(
            decode_private_oram_owner_reservation_resolution_receipt_v1(
                &serde_json::to_vec(&json).unwrap()
            ),
            Err(PrivateOramOwnerReservationResolutionError::NonCanonicalEncoding)
        );
    }

    mod field_mutation_fuzz {
        use proptest::prelude::*;

        use super::*;
        use crate::json_mutation::mutate_json_leaf;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(192))]

            /// Every scalar field of a signed resolution receipt, its embedded signer included,
            /// is covered by the signature: changing any one of them is rejected.
            #[test]
            fn every_field_mutation_is_rejected(index in any::<usize>(), salt in any::<u8>()) {
                let (_signer, signed) = signed_fixture();
                let mut value = serde_json::to_value(&signed).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) = serde_json::from_value::<
                    SignedPrivateOramOwnerReservationResolutionReceiptV1,
                >(value)
                {
                    prop_assert!(
                        validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1(
                            &mutated,
                        )
                        .is_err(),
                        "mutation at {} was accepted",
                        path
                    );
                }
            }
        }
    }
}
