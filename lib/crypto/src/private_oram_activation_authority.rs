//! Dormant cryptographic authority for private-ORAM cluster activation.
//!
//! A manifest is signed only after verification against an administrator public key obtained from
//! configuration outside the manifest bundle. This module can compare a bundle with an explicit
//! caller-supplied registry expectation, but neither that expectation nor the resulting type proves
//! durable current-state provenance. The storage layer must establish that provenance atomically
//! before using a signed manifest for activation. This module does not provide TOFU, persist state,
//! aggregate activation proofs, or wire runtime behavior. Callers must bound untrusted transport or
//! file bytes before deserialization.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::net::IpAddr;

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY, PrivateOramConsensusConfigurationV1,
    PrivateOramPeerActivationChallengeV1, PrivateOramPeerRecoveryPublicKeyV1,
    private_oram_consensus_configuration_member_ids_v1,
    try_private_oram_consensus_configuration_digest_v1,
    validate_private_oram_peer_activation_challenge_v1_shape,
    validate_private_oram_peer_recovery_public_key_v1,
};

pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION: u16 = 1;
pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_PUBLIC_KEY_VERSION: u16 = 1;
pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_VERSION: u16 = 1;
pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_KEY_ID_DOMAIN: &str =
    "qdrant-sec/private-oram-activation-authority-key-id/v1";
pub const PRIVATE_ORAM_ACTIVATION_CLUSTER_IDENTITY_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-activation-cluster-identity-digest/v1";
pub const PRIVATE_ORAM_ACTIVATION_PEER_URI_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-activation-peer-uri-digest/v1";
pub const PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-activation-authority-manifest-signature/v1";

const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_AUTHORIZED_PEERS: usize = 1_024;
const MAX_CANONICAL_PEER_HOST_BYTES: usize = 253;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;

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
            return Err(serde::de::Error::custom(
                "expected canonical unsigned decimal string",
            ));
        }
        Ok(value)
    }
}

mod private_oram_peer_signer_json_v1 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::PrivateOramPeerRecoveryPublicKeyV1;

    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct WireRef<'a> {
        version: u16,
        alg: &'a str,
        #[serde(with = "super::decimal_u64")]
        key_epoch: u64,
        key_id: &'a str,
        public_key: &'a str,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireOwned {
        version: u16,
        alg: String,
        #[serde(with = "super::decimal_u64")]
        key_epoch: u64,
        key_id: String,
        public_key: String,
    }

    pub fn serialize<S>(
        value: &PrivateOramPeerRecoveryPublicKeyV1,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireRef {
            version: value.version,
            alg: &value.alg,
            key_epoch: value.key_epoch,
            key_id: &value.key_id,
            public_key: &value.public_key,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<PrivateOramPeerRecoveryPublicKeyV1, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireOwned::deserialize(deserializer)?;
        Ok(PrivateOramPeerRecoveryPublicKeyV1 {
            version: wire.version,
            alg: wire.alg,
            key_epoch: wire.key_epoch,
            key_id: wire.key_id,
            public_key: wire.public_key,
        })
    }
}

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramActivationAuthorityError {
    #[error("private ORAM activation authority manifest version is unsupported")]
    UnsupportedManifestVersion,
    #[error("private ORAM activation authority public key version is unsupported")]
    UnsupportedPublicKeyVersion,
    #[error("private ORAM activation authority signature version is unsupported")]
    UnsupportedSignatureVersion,
    #[error("private ORAM activation authority field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM activation authority manifest is invalid")]
    InvalidManifest,
    #[error("private ORAM activation authority key does not match")]
    AuthorityKeyMismatch,
    #[error("private ORAM activation authority signature is invalid")]
    InvalidSignature,
    #[error("private ORAM activation authority transition is invalid")]
    InvalidTransition,
    #[error("private ORAM activation challenge does not match the provided authority state")]
    ChallengeContextMismatch(&'static str),
}

impl Debug for PrivateOramActivationAuthorityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramActivationAuthorityError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramActivationAuthorityPublicKeyV1 {
    pub version: u16,
    pub alg: String,
    #[serde(with = "decimal_u64")]
    pub key_epoch: u64,
    pub key_id: String,
    pub public_key: String,
}

impl Debug for PrivateOramActivationAuthorityPublicKeyV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthorityPublicKeyV1")
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
pub struct PrivateOramActivationAuthoritySignatureV1 {
    pub version: u16,
    pub alg: String,
    #[serde(with = "decimal_u64")]
    pub key_epoch: u64,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateOramActivationAuthoritySignatureV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthoritySignatureV1")
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
pub struct PrivateOramActivationPeerPinV1 {
    #[serde(with = "decimal_u64")]
    pub peer_id: u64,
    pub peer_uri_digest: String,
    #[serde(with = "private_oram_peer_signer_json_v1")]
    pub signer: PrivateOramPeerRecoveryPublicKeyV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramActivationPeerUriSchemeV1 {
    Http,
    Https,
}

impl PrivateOramActivationPeerUriSchemeV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Http => 1,
            Self::Https => 2,
        }
    }
}

impl Debug for PrivateOramActivationPeerPinV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationPeerPinV1")
            .field("peer_id", &"[redacted]")
            .field("peer_uri_digest", &"[redacted]")
            .field("signer", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramActivationAuthorityManifestV1 {
    pub version: u16,
    pub cluster_identity_nonce: String,
    pub cluster_identity_digest: String,
    #[serde(with = "decimal_u64")]
    pub cluster_first_voter_peer_id: u64,
    #[serde(with = "decimal_u64")]
    pub registry_generation: u64,
    pub parent_manifest_digest: Option<String>,
    pub required_capability: String,
    pub required_binary_capability_digest: String,
    #[serde(with = "decimal_u64")]
    pub authority_key_epoch: u64,
    pub authority_key_id: String,
    /// Cumulative peer identity history, not the current Raft membership list.
    ///
    /// V1 transitions may append peers or change a pinned URI, but may not remove a peer, reuse a
    /// peer ID, or rotate an existing peer signer.
    pub peers: Vec<PrivateOramActivationPeerPinV1>,
}

impl Debug for PrivateOramActivationAuthorityManifestV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthorityManifestV1")
            .field("version", &self.version)
            .field("cluster_identity_nonce", &"[redacted]")
            .field("cluster_identity_digest", &"[redacted]")
            .field("cluster_first_voter_peer_id", &"[redacted]")
            .field("registry_generation", &self.registry_generation)
            .field("parent_manifest_digest", &"[redacted]")
            .field("required_capability", &"[redacted]")
            .field("required_binary_capability_digest", &"[redacted]")
            .field("authority_key_epoch", &self.authority_key_epoch)
            .field("authority_key_id", &"[redacted]")
            .field("peer_count", &self.peers.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramActivationAuthorityBundleV1 {
    pub manifest: PrivateOramActivationAuthorityManifestV1,
    pub signature: PrivateOramActivationAuthoritySignatureV1,
}

impl Debug for PrivateOramActivationAuthorityBundleV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthorityBundleV1")
            .field("manifest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// An administrator key and cluster identity provisioned outside a manifest bundle.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramActivationAuthorityTrustAnchorV1 {
    authority: PrivateOramActivationAuthorityPublicKeyV1,
    cluster_identity_digest: String,
    cluster_first_voter_peer_id: u64,
}

impl Debug for PrivateOramActivationAuthorityTrustAnchorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramActivationAuthorityTrustAnchorV1")
            .field("authority", &"[redacted]")
            .field("cluster_identity_digest", &"[redacted]")
            .field("cluster_first_voter_peer_id", &"[redacted]")
            .finish()
    }
}

impl PrivateOramActivationAuthorityTrustAnchorV1 {
    pub fn from_external_configuration(
        authority: PrivateOramActivationAuthorityPublicKeyV1,
        cluster_identity_digest: String,
        cluster_first_voter_peer_id: u64,
    ) -> Result<Self, PrivateOramActivationAuthorityError> {
        validate_private_oram_activation_authority_public_key_v1(&authority)?;
        validate_digest(&cluster_identity_digest, "cluster_identity_digest")?;
        if cluster_first_voter_peer_id == 0 {
            return Err(PrivateOramActivationAuthorityError::InvalidField(
                "cluster_first_voter_peer_id",
            ));
        }
        Ok(Self {
            authority,
            cluster_identity_digest,
            cluster_first_voter_peer_id,
        })
    }

    pub fn authority(&self) -> &PrivateOramActivationAuthorityPublicKeyV1 {
        &self.authority
    }

    pub fn cluster_identity_digest(&self) -> &str {
        &self.cluster_identity_digest
    }

    pub fn cluster_first_voter_peer_id(&self) -> u64 {
        self.cluster_first_voter_peer_id
    }
}

pub enum PrivateOramActivationRegistryExpectationV1<'a> {
    Genesis,
    Anchored {
        registry_generation: u64,
        manifest_digest: &'a str,
    },
    Successor(&'a VerifiedSignedPrivateOramActivationAuthorityManifestV1),
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedSignedPrivateOramActivationAuthorityManifestV1 {
    bundle: PrivateOramActivationAuthorityBundleV1,
    manifest_digest: String,
}

impl Debug for VerifiedSignedPrivateOramActivationAuthorityManifestV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSignedPrivateOramActivationAuthorityManifestV1")
            .field(
                "registry_generation",
                &self.bundle.manifest.registry_generation,
            )
            .field("peer_count", &self.bundle.manifest.peers.len())
            .field("manifest_digest", &"[redacted]")
            .finish()
    }
}

impl VerifiedSignedPrivateOramActivationAuthorityManifestV1 {
    pub fn bundle(&self) -> &PrivateOramActivationAuthorityBundleV1 {
        &self.bundle
    }

    pub fn manifest(&self) -> &PrivateOramActivationAuthorityManifestV1 {
        &self.bundle.manifest
    }

    pub fn signature(&self) -> &PrivateOramActivationAuthoritySignatureV1 {
        &self.bundle.signature
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn peer_pin(&self, peer_id: u64) -> Option<&PrivateOramActivationPeerPinV1> {
        self.bundle
            .manifest
            .peers
            .binary_search_by_key(&peer_id, |peer| peer.peer_id)
            .ok()
            .map(|index| &self.bundle.manifest.peers[index])
    }
}

pub fn private_oram_activation_authority_key_id_v1(public_key: &[u8; 32]) -> String {
    let mut message = Vec::new();
    push_domain_infallible(
        &mut message,
        PRIVATE_ORAM_ACTIVATION_AUTHORITY_KEY_ID_DOMAIN,
    );
    message.extend_from_slice(public_key);
    BASE64URL_NOPAD.encode(&Sha256::digest(message))
}

pub fn private_oram_activation_authority_public_key_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
) -> Result<PrivateOramActivationAuthorityPublicKeyV1, PrivateOramActivationAuthorityError> {
    if key_epoch == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "key_epoch",
        ));
    }
    let public_key: [u8; DIGEST_BYTES] = key_pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("public_key"))?;
    Ok(PrivateOramActivationAuthorityPublicKeyV1 {
        version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_PUBLIC_KEY_VERSION,
        alg: PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: private_oram_activation_authority_key_id_v1(&public_key),
        public_key: BASE64URL_NOPAD.encode(&public_key),
    })
}

pub fn validate_private_oram_activation_authority_public_key_v1(
    public_key: &PrivateOramActivationAuthorityPublicKeyV1,
) -> Result<[u8; DIGEST_BYTES], PrivateOramActivationAuthorityError> {
    if public_key.version != PRIVATE_ORAM_ACTIVATION_AUTHORITY_PUBLIC_KEY_VERSION {
        return Err(PrivateOramActivationAuthorityError::UnsupportedPublicKeyVersion);
    }
    if public_key.alg != PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_ALGORITHM {
        return Err(PrivateOramActivationAuthorityError::InvalidField("alg"));
    }
    if public_key.key_epoch == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "key_epoch",
        ));
    }
    let decoded = decode_canonical::<DIGEST_BYTES>(
        &public_key.public_key,
        BASE64URL_NOPAD_32_BYTE_LEN,
        "public_key",
    )?;
    if public_key.key_id != private_oram_activation_authority_key_id_v1(&decoded) {
        return Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch);
    }
    Ok(decoded)
}

pub fn try_private_oram_activation_cluster_identity_digest_v1(
    cluster_identity_nonce: &str,
    cluster_first_voter_peer_id: u64,
) -> Result<String, PrivateOramActivationAuthorityError> {
    validate_digest(cluster_identity_nonce, "cluster_identity_nonce")?;
    if cluster_first_voter_peer_id == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "cluster_first_voter_peer_id",
        ));
    }
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_ACTIVATION_CLUSTER_IDENTITY_DIGEST_DOMAIN,
    )?;
    push_u16(
        &mut message,
        PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
    );
    push_str(&mut message, cluster_identity_nonce)?;
    push_u64(&mut message, cluster_first_voter_peer_id);
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

/// Hashes canonical URI components extracted by the production Raft URI parser.
pub fn try_private_oram_activation_peer_uri_digest_v1(
    scheme: PrivateOramActivationPeerUriSchemeV1,
    canonical_host: &str,
    port: u16,
) -> Result<String, PrivateOramActivationAuthorityError> {
    // URI parsers present IPv6 literals in bracketed form (`[::1]`); the digest covers the bare
    // canonical address so a pin does not depend on the parser's presentation. Brackets around
    // anything but a canonical IPv6 address are refused.
    let canonical_host = match canonical_host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner)
            if inner
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|address| address.to_string() == inner) =>
        {
            inner
        }
        Some(_) => {
            return Err(PrivateOramActivationAuthorityError::InvalidField(
                "canonical_peer_host",
            ));
        }
        None => canonical_host,
    };
    if !is_canonical_peer_host(canonical_host) {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "canonical_peer_host",
        ));
    }
    if port == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "canonical_peer_port",
        ));
    }
    let mut message = Vec::new();
    push_domain(&mut message, PRIVATE_ORAM_ACTIVATION_PEER_URI_DIGEST_DOMAIN)?;
    message.push(scheme.tag());
    push_str(&mut message, canonical_host)?;
    push_u16(&mut message, port);
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

pub fn validate_private_oram_activation_authority_manifest_v1_shape(
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<(), PrivateOramActivationAuthorityError> {
    if manifest.version != PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION {
        return Err(PrivateOramActivationAuthorityError::UnsupportedManifestVersion);
    }
    validate_digest(&manifest.cluster_identity_nonce, "cluster_identity_nonce")?;
    validate_digest(&manifest.cluster_identity_digest, "cluster_identity_digest")?;
    if manifest.cluster_first_voter_peer_id == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "cluster_first_voter_peer_id",
        ));
    }
    if manifest.registry_generation == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "registry_generation",
        ));
    }
    match (
        manifest.registry_generation,
        &manifest.parent_manifest_digest,
    ) {
        (1, None) => {}
        (1, Some(_)) | (_, None) => {
            return Err(PrivateOramActivationAuthorityError::InvalidManifest);
        }
        (_, Some(parent)) => validate_digest(parent, "parent_manifest_digest")?,
    }
    if manifest.required_capability != PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "required_capability",
        ));
    }
    validate_digest(
        &manifest.required_binary_capability_digest,
        "required_binary_capability_digest",
    )?;
    if manifest.authority_key_epoch == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "authority_key_epoch",
        ));
    }
    validate_digest(&manifest.authority_key_id, "authority_key_id")?;
    let expected_cluster_identity = try_private_oram_activation_cluster_identity_digest_v1(
        &manifest.cluster_identity_nonce,
        manifest.cluster_first_voter_peer_id,
    )?;
    if manifest.cluster_identity_digest != expected_cluster_identity {
        return Err(PrivateOramActivationAuthorityError::InvalidManifest);
    }
    validate_peer_pins(manifest)?;
    Ok(())
}

pub fn try_private_oram_activation_authority_manifest_signature_message_v1(
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<Vec<u8>, PrivateOramActivationAuthorityError> {
    try_manifest_message(
        PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_SIGNATURE_DOMAIN,
        manifest,
    )
}

pub fn private_oram_activation_authority_manifest_digest_v1(
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<String, PrivateOramActivationAuthorityError> {
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(
        try_private_oram_activation_authority_manifest_signature_message_v1(manifest)?,
    )))
}

pub fn sign_private_oram_activation_authority_manifest_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<PrivateOramActivationAuthoritySignatureV1, PrivateOramActivationAuthorityError> {
    let authority = private_oram_activation_authority_public_key_v1(key_pair, key_epoch)?;
    if manifest.authority_key_epoch != authority.key_epoch
        || manifest.authority_key_id != authority.key_id
    {
        return Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch);
    }
    let message = try_private_oram_activation_authority_manifest_signature_message_v1(manifest)?;
    Ok(PrivateOramActivationAuthoritySignatureV1 {
        version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: authority.key_id,
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

pub fn package_private_oram_activation_authority_manifest_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    manifest: PrivateOramActivationAuthorityManifestV1,
) -> Result<PrivateOramActivationAuthorityBundleV1, PrivateOramActivationAuthorityError> {
    let signature =
        sign_private_oram_activation_authority_manifest_v1(key_pair, key_epoch, &manifest)?;
    Ok(PrivateOramActivationAuthorityBundleV1 {
        manifest,
        signature,
    })
}

/// Verifies a bundle against an externally provisioned authority and caller-supplied expectation.
///
/// The result proves signature, shape, trust-anchor, and transition checks only. It does not prove
/// that the supplied expectation came from current durable state.
pub fn validate_private_oram_activation_authority_bundle_v1(
    bundle: &PrivateOramActivationAuthorityBundleV1,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    expectation: PrivateOramActivationRegistryExpectationV1<'_>,
) -> Result<
    VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    PrivateOramActivationAuthorityError,
> {
    let expected_authority = trust_anchor.authority();
    let public_key = validate_private_oram_activation_authority_public_key_v1(expected_authority)?;
    validate_private_oram_activation_authority_manifest_v1_shape(&bundle.manifest)?;
    if bundle.manifest.cluster_identity_digest != trust_anchor.cluster_identity_digest
        || bundle.manifest.cluster_first_voter_peer_id != trust_anchor.cluster_first_voter_peer_id
    {
        return Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch);
    }
    for peer in &bundle.manifest.peers {
        let peer_public_key = decode_canonical::<DIGEST_BYTES>(
            &peer.signer.public_key,
            BASE64URL_NOPAD_32_BYTE_LEN,
            "peer_signer_public_key",
        )?;
        if peer_public_key == public_key {
            return Err(PrivateOramActivationAuthorityError::InvalidManifest);
        }
    }
    validate_private_oram_activation_authority_signature_v1_shape(&bundle.signature)?;
    if bundle.manifest.authority_key_epoch != expected_authority.key_epoch
        || bundle.manifest.authority_key_id != expected_authority.key_id
        || bundle.signature.key_epoch != expected_authority.key_epoch
        || bundle.signature.key_id != expected_authority.key_id
        || bundle.signature.alg != expected_authority.alg
    {
        return Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch);
    }
    let signature = decode_canonical::<SIGNATURE_BYTES>(
        &bundle.signature.sig,
        BASE64URL_NOPAD_64_BYTE_LEN,
        "signature",
    )?;
    let message =
        try_private_oram_activation_authority_manifest_signature_message_v1(&bundle.manifest)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature)
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidSignature)?;
    let manifest_digest = private_oram_activation_authority_manifest_digest_v1(&bundle.manifest)?;
    let verified = VerifiedSignedPrivateOramActivationAuthorityManifestV1 {
        bundle: bundle.clone(),
        manifest_digest,
    };
    match expectation {
        PrivateOramActivationRegistryExpectationV1::Genesis => {
            if verified.manifest().registry_generation != 1
                || verified.manifest().parent_manifest_digest.is_some()
            {
                return Err(PrivateOramActivationAuthorityError::InvalidTransition);
            }
        }
        PrivateOramActivationRegistryExpectationV1::Anchored {
            registry_generation,
            manifest_digest,
        } => {
            if registry_generation == 0 {
                return Err(PrivateOramActivationAuthorityError::InvalidField(
                    "anchored_registry_generation",
                ));
            }
            validate_digest(manifest_digest, "anchored_manifest_digest")?;
            if verified.manifest().registry_generation != registry_generation
                || verified.manifest_digest() != manifest_digest
            {
                return Err(PrivateOramActivationAuthorityError::InvalidTransition);
            }
        }
        PrivateOramActivationRegistryExpectationV1::Successor(previous) => {
            validate_successor(previous, &verified, trust_anchor)?;
        }
    }
    Ok(verified)
}

/// Verifies one signed, consecutive registry transition against the same external trust anchor.
pub fn validate_private_oram_activation_authority_transition_v1(
    previous: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    next_bundle: &PrivateOramActivationAuthorityBundleV1,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
) -> Result<
    VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    PrivateOramActivationAuthorityError,
> {
    validate_private_oram_activation_authority_bundle_v1(
        next_bundle,
        trust_anchor,
        PrivateOramActivationRegistryExpectationV1::Successor(previous),
    )
}

fn validate_successor(
    previous: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    next: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
) -> Result<(), PrivateOramActivationAuthorityError> {
    let previous_manifest = previous.manifest();
    let next_manifest = next.manifest();
    if previous_manifest.authority_key_epoch != trust_anchor.authority.key_epoch
        || previous_manifest.authority_key_id != trust_anchor.authority.key_id
        || previous_manifest.cluster_identity_digest != trust_anchor.cluster_identity_digest
        || previous_manifest.cluster_first_voter_peer_id != trust_anchor.cluster_first_voter_peer_id
        || next_manifest.registry_generation
            != previous_manifest
                .registry_generation
                .checked_add(1)
                .ok_or(PrivateOramActivationAuthorityError::InvalidTransition)?
        || next_manifest.parent_manifest_digest.as_deref() != Some(previous.manifest_digest())
        || next_manifest.cluster_identity_nonce != previous_manifest.cluster_identity_nonce
        || next_manifest.cluster_identity_digest != previous_manifest.cluster_identity_digest
        || next_manifest.cluster_first_voter_peer_id
            != previous_manifest.cluster_first_voter_peer_id
        || next_manifest.authority_key_epoch != previous_manifest.authority_key_epoch
        || next_manifest.authority_key_id != previous_manifest.authority_key_id
    {
        return Err(PrivateOramActivationAuthorityError::InvalidTransition);
    }

    let next_peers = next_manifest
        .peers
        .iter()
        .map(|peer| (peer.peer_id, peer))
        .collect::<BTreeMap<_, _>>();
    for previous_peer in &previous_manifest.peers {
        let Some(next_peer) = next_peers.get(&previous_peer.peer_id) else {
            return Err(PrivateOramActivationAuthorityError::InvalidTransition);
        };
        if next_peer.signer != previous_peer.signer {
            return Err(PrivateOramActivationAuthorityError::InvalidTransition);
        }
    }
    Ok(())
}

/// Resolves the externally authorized signer against a verified signed manifest and challenge.
///
/// This structural resolver does not prove that `authority` is current. A storage-layer current
/// guard must derive `observed_target_uri_digest` from the current Raft URI map and repeat the
/// durable-state, configuration, and URI checks after the RPC before using an acknowledgement.
pub fn private_oram_activation_signer_from_signed_manifest_for_challenge_v1<'a>(
    authority: &'a VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    configuration: &PrivateOramConsensusConfigurationV1,
    observed_target_uri_digest: &str,
    challenge: &PrivateOramPeerActivationChallengeV1,
) -> Result<&'a PrivateOramPeerRecoveryPublicKeyV1, PrivateOramActivationAuthorityError> {
    validate_private_oram_peer_activation_challenge_v1_shape(challenge)
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("challenge"))?;
    validate_digest(observed_target_uri_digest, "observed_target_uri_digest")?;
    let configuration_digest = try_private_oram_consensus_configuration_digest_v1(configuration)
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("configuration"))?;
    let configuration_members =
        private_oram_consensus_configuration_member_ids_v1(configuration)
            .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("configuration"))?;
    let manifest = authority.manifest();
    for (matches, field) in [
        (
            challenge.cluster_identity_digest == manifest.cluster_identity_digest,
            "cluster_identity_digest",
        ),
        (
            challenge.cluster_first_voter_peer_id == manifest.cluster_first_voter_peer_id,
            "cluster_first_voter_peer_id",
        ),
        (
            challenge.pin_registry_generation == manifest.registry_generation,
            "pin_registry_generation",
        ),
        (
            challenge.pin_registry_digest == authority.manifest_digest,
            "pin_registry_digest",
        ),
        (
            challenge.required_capability == manifest.required_capability,
            "required_capability",
        ),
        (
            challenge.required_binary_capability_digest
                == manifest.required_binary_capability_digest,
            "required_binary_capability_digest",
        ),
        (
            challenge.expected_configuration_digest == configuration_digest,
            "expected_configuration_digest",
        ),
        (
            challenge.target_peer_uri_digest == observed_target_uri_digest,
            "observed_target_uri_digest",
        ),
    ] {
        if !matches {
            return Err(PrivateOramActivationAuthorityError::ChallengeContextMismatch(field));
        }
    }
    if configuration_members
        .iter()
        .any(|peer_id| authority.peer_pin(*peer_id).is_none())
        || configuration_members
            .binary_search(&challenge.coordinator_peer_id)
            .is_err()
        || configuration_members
            .binary_search(&challenge.target_peer_id)
            .is_err()
    {
        return Err(
            PrivateOramActivationAuthorityError::ChallengeContextMismatch("configuration_members"),
        );
    }
    let target_pin = authority
        .peer_pin(challenge.target_peer_id)
        .ok_or(PrivateOramActivationAuthorityError::ChallengeContextMismatch("target_peer_id"))?;
    if target_pin.peer_uri_digest != challenge.target_peer_uri_digest {
        return Err(
            PrivateOramActivationAuthorityError::ChallengeContextMismatch("target_peer_uri_digest"),
        );
    }
    Ok(&target_pin.signer)
}

fn validate_peer_pins(
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<(), PrivateOramActivationAuthorityError> {
    if manifest.peers.is_empty() || manifest.peers.len() > MAX_AUTHORIZED_PEERS {
        return Err(PrivateOramActivationAuthorityError::InvalidManifest);
    }
    let mut uri_digests = BTreeSet::new();
    let mut signer_key_ids = BTreeSet::new();
    let mut found_first_voter = false;
    let mut previous_peer_id = None;
    for peer in &manifest.peers {
        if peer.peer_id == 0 || previous_peer_id.is_some_and(|previous| previous >= peer.peer_id) {
            return Err(PrivateOramActivationAuthorityError::InvalidManifest);
        }
        validate_digest(&peer.peer_uri_digest, "peer_uri_digest")?;
        let public_key = validate_private_oram_peer_recovery_public_key_v1(&peer.signer)
            .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("peer_signer"))?;
        if BASE64URL_NOPAD.encode(&public_key) != peer.signer.public_key {
            return Err(PrivateOramActivationAuthorityError::InvalidField(
                "peer_signer_public_key",
            ));
        }
        if !uri_digests.insert(peer.peer_uri_digest.as_str())
            || !signer_key_ids.insert(peer.signer.key_id.as_str())
        {
            return Err(PrivateOramActivationAuthorityError::InvalidManifest);
        }
        found_first_voter |= peer.peer_id == manifest.cluster_first_voter_peer_id;
        previous_peer_id = Some(peer.peer_id);
    }
    if !found_first_voter {
        return Err(PrivateOramActivationAuthorityError::InvalidManifest);
    }
    Ok(())
}

pub fn validate_private_oram_activation_authority_signature_v1_shape(
    signature: &PrivateOramActivationAuthoritySignatureV1,
) -> Result<(), PrivateOramActivationAuthorityError> {
    if signature.version != PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_VERSION {
        return Err(PrivateOramActivationAuthorityError::UnsupportedSignatureVersion);
    }
    if signature.alg != PRIVATE_ORAM_ACTIVATION_AUTHORITY_SIGNATURE_ALGORITHM {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "signature_algorithm",
        ));
    }
    if signature.key_epoch == 0 {
        return Err(PrivateOramActivationAuthorityError::InvalidField(
            "signature_key_epoch",
        ));
    }
    validate_digest(&signature.key_id, "signature_key_id")?;
    decode_canonical::<SIGNATURE_BYTES>(&signature.sig, BASE64URL_NOPAD_64_BYTE_LEN, "signature")?;
    Ok(())
}

fn try_manifest_message(
    domain: &str,
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<Vec<u8>, PrivateOramActivationAuthorityError> {
    validate_private_oram_activation_authority_manifest_v1_shape(manifest)?;
    try_encode_manifest_message_without_shape_validation(domain, manifest)
}

fn try_encode_manifest_message_without_shape_validation(
    domain: &str,
    manifest: &PrivateOramActivationAuthorityManifestV1,
) -> Result<Vec<u8>, PrivateOramActivationAuthorityError> {
    let mut message = Vec::new();
    push_domain(&mut message, domain)?;
    push_u16(&mut message, manifest.version);
    push_str(&mut message, &manifest.cluster_identity_nonce)?;
    push_str(&mut message, &manifest.cluster_identity_digest)?;
    push_u64(&mut message, manifest.cluster_first_voter_peer_id);
    push_u64(&mut message, manifest.registry_generation);
    push_optional_str(&mut message, manifest.parent_manifest_digest.as_deref())?;
    push_str(&mut message, &manifest.required_capability)?;
    push_str(&mut message, &manifest.required_binary_capability_digest)?;
    push_u64(&mut message, manifest.authority_key_epoch);
    push_str(&mut message, &manifest.authority_key_id)?;
    push_u32(
        &mut message,
        u32::try_from(manifest.peers.len())
            .map_err(|_| PrivateOramActivationAuthorityError::InvalidManifest)?,
    );
    for peer in &manifest.peers {
        push_u64(&mut message, peer.peer_id);
        push_str(&mut message, &peer.peer_uri_digest)?;
        push_u16(&mut message, peer.signer.version);
        push_str(&mut message, &peer.signer.alg)?;
        push_u64(&mut message, peer.signer.key_epoch);
        push_str(&mut message, &peer.signer.key_id)?;
        push_str(&mut message, &peer.signer.public_key)?;
    }
    Ok(message)
}

fn is_canonical_peer_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > MAX_CANONICAL_PEER_HOST_BYTES
        || !host.is_ascii()
        || host.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || byte.is_ascii_uppercase()
        })
    {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.to_string() == host;
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || host.starts_with('.')
        || host.ends_with('.')
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramActivationAuthorityError> {
    decode_canonical::<DIGEST_BYTES>(value, BASE64URL_NOPAD_32_BYTE_LEN, field).map(|_| ())
}

fn decode_canonical<const N: usize>(
    value: &str,
    expected_len: usize,
    field: &'static str,
) -> Result<[u8; N], PrivateOramActivationAuthorityError> {
    if value.len() != expected_len {
        return Err(PrivateOramActivationAuthorityError::InvalidField(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField(field))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField(field))?;
    if BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramActivationAuthorityError::InvalidField(field));
    }
    Ok(decoded)
}

fn push_domain(
    message: &mut Vec<u8>,
    domain: &str,
) -> Result<(), PrivateOramActivationAuthorityError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("canonical_message"))?;
    push_u32(message, len);
    message.extend_from_slice(domain.as_bytes());
    Ok(())
}

fn push_domain_infallible(message: &mut Vec<u8>, domain: &str) {
    push_u32(
        message,
        u32::try_from(domain.len()).expect("private ORAM activation domain length fits u32"),
    );
    message.extend_from_slice(domain.as_bytes());
}

fn push_optional_str(
    message: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), PrivateOramActivationAuthorityError> {
    match value {
        Some(value) => {
            message.push(1);
            push_str(message, value)?;
        }
        None => message.push(0),
    }
    Ok(())
}

fn push_str(message: &mut Vec<u8>, value: &str) -> Result<(), PrivateOramActivationAuthorityError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramActivationAuthorityError::InvalidField("canonical_message"))?;
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
    use crate::{
        PrivateOramPeerActivationObservationV1, private_oram_peer_recovery_public_key_v1,
        sign_private_oram_peer_activation_ack_v1,
        validate_private_oram_peer_activation_ack_signature_v1,
    };

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AuthorityKatFixtureV1 {
        trust_anchor_authority: PrivateOramActivationAuthorityPublicKeyV1,
        cluster_identity_digest: String,
        #[serde(with = "super::decimal_u64")]
        cluster_first_voter_peer_id: u64,
        genesis: AuthorityKatVectorV1,
        successor: AuthorityKatVectorV1,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AuthorityKatVectorV1 {
        bundle: PrivateOramActivationAuthorityBundleV1,
        canonical_message_base64url: String,
        manifest_digest: String,
    }

    fn digest(value: u8) -> String {
        BASE64URL_NOPAD.encode(&[value; DIGEST_BYTES])
    }

    fn key_pair(value: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[value; DIGEST_BYTES]).unwrap()
    }

    fn peer(peer_id: u64, key_value: u8, key_epoch: u64) -> PrivateOramActivationPeerPinV1 {
        let host = format!("10.0.0.{peer_id}");
        PrivateOramActivationPeerPinV1 {
            peer_id,
            peer_uri_digest: try_private_oram_activation_peer_uri_digest_v1(
                PrivateOramActivationPeerUriSchemeV1::Http,
                &host,
                6335,
            )
            .unwrap(),
            signer: private_oram_peer_recovery_public_key_v1(&key_pair(key_value), key_epoch)
                .unwrap(),
        }
    }

    fn manifest(
        authority: &PrivateOramActivationAuthorityPublicKeyV1,
    ) -> PrivateOramActivationAuthorityManifestV1 {
        let cluster_identity_nonce = digest(1);
        let cluster_first_voter_peer_id = 11;
        PrivateOramActivationAuthorityManifestV1 {
            version: PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_VERSION,
            cluster_identity_digest: try_private_oram_activation_cluster_identity_digest_v1(
                &cluster_identity_nonce,
                cluster_first_voter_peer_id,
            )
            .unwrap(),
            cluster_identity_nonce,
            cluster_first_voter_peer_id,
            registry_generation: 1,
            parent_manifest_digest: None,
            required_capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
            required_binary_capability_digest: digest(2),
            authority_key_epoch: authority.key_epoch,
            authority_key_id: authority.key_id.clone(),
            peers: vec![peer(11, 21, 1), peer(13, 22, 1)],
        }
    }

    fn verified_genesis() -> (
        Ed25519KeyPair,
        PrivateOramActivationAuthorityTrustAnchorV1,
        VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    ) {
        let key_pair = key_pair(10);
        let authority = private_oram_activation_authority_public_key_v1(&key_pair, 1).unwrap();
        let manifest = manifest(&authority);
        let trust_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                authority,
                manifest.cluster_identity_digest.clone(),
                manifest.cluster_first_voter_peer_id,
            )
            .unwrap();
        let bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, manifest).unwrap();
        let verified = validate_private_oram_activation_authority_bundle_v1(
            &bundle,
            &trust_anchor,
            PrivateOramActivationRegistryExpectationV1::Genesis,
        )
        .unwrap();
        (key_pair, trust_anchor, verified)
    }

    fn configuration() -> PrivateOramConsensusConfigurationV1 {
        PrivateOramConsensusConfigurationV1::from_raft_peer_sets(&[11, 13], &[], &[], &[], false)
            .unwrap()
    }

    fn activation_challenge(
        authority: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
        configuration: &PrivateOramConsensusConfigurationV1,
    ) -> PrivateOramPeerActivationChallengeV1 {
        PrivateOramPeerActivationChallengeV1 {
            protocol_version: crate::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
            activation_id: digest(51),
            activation_generation: 1,
            challenge_nonce: digest(52),
            cluster_identity_digest: authority.manifest().cluster_identity_digest.clone(),
            cluster_first_voter_peer_id: authority.manifest().cluster_first_voter_peer_id,
            coordinator_peer_id: 11,
            target_peer_id: 13,
            target_peer_uri_digest: authority.peer_pin(13).unwrap().peer_uri_digest.clone(),
            membership_generation: 7,
            required_consensus_wire_protocol: crate::PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
            expected_current_term: 5,
            expected_hard_commit: 101,
            expected_last_applied: 101,
            expected_last_log_index: 101,
            expected_pending_conf_index: 0,
            expected_commit_entry_term: 4,
            expected_configuration_digest: try_private_oram_consensus_configuration_digest_v1(
                configuration,
            )
            .unwrap(),
            expected_runtime_capability_fingerprint: digest(53),
            pin_registry_generation: authority.manifest().registry_generation,
            pin_registry_digest: authority.manifest_digest().to_string(),
            required_capability: authority.manifest().required_capability.clone(),
            required_binary_capability_digest: authority
                .manifest()
                .required_binary_capability_digest
                .clone(),
        }
    }

    fn observation(
        challenge: &PrivateOramPeerActivationChallengeV1,
    ) -> PrivateOramPeerActivationObservationV1 {
        PrivateOramPeerActivationObservationV1 {
            responder_peer_id: challenge.target_peer_id,
            process_incarnation: digest(54),
            qdrant_version: "1.17.1-sec.2".to_string(),
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
        }
    }

    fn assert_kat_vector(
        vector: &AuthorityKatVectorV1,
        verified: &VerifiedSignedPrivateOramActivationAuthorityManifestV1,
    ) {
        assert_eq!(&vector.bundle, verified.bundle());
        let message = try_private_oram_activation_authority_manifest_signature_message_v1(
            verified.manifest(),
        )
        .unwrap();
        assert_eq!(
            vector.canonical_message_base64url,
            BASE64URL_NOPAD.encode(&message)
        );
        assert_eq!(vector.manifest_digest, verified.manifest_digest());
        assert_eq!(
            vector.manifest_digest,
            BASE64URL_NOPAD.encode(&Sha256::digest(message))
        );
    }

    #[test]
    fn authority_manifest_and_successor_are_external_known_answers() {
        let fixture: AuthorityKatFixtureV1 = serde_json::from_str(include_str!(
            "../testdata/private_oram_activation_authority_v1.json"
        ))
        .unwrap();
        let trust_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                fixture.trust_anchor_authority.clone(),
                fixture.cluster_identity_digest.clone(),
                fixture.cluster_first_voter_peer_id,
            )
            .unwrap();
        let genesis = validate_private_oram_activation_authority_bundle_v1(
            &fixture.genesis.bundle,
            &trust_anchor,
            PrivateOramActivationRegistryExpectationV1::Genesis,
        )
        .unwrap();
        let successor = validate_private_oram_activation_authority_transition_v1(
            &genesis,
            &fixture.successor.bundle,
            &trust_anchor,
        )
        .unwrap();
        assert_kat_vector(&fixture.genesis, &genesis);
        assert_kat_vector(&fixture.successor, &successor);
        let authority = trust_anchor.authority();
        assert_eq!(
            authority.key_id,
            "zoRruUWVsWrAKTpB7MCZKB4dqcOUv8V1QYDARAchHnQ"
        );
        assert_eq!(
            genesis.manifest().cluster_identity_digest,
            "-QpYc_5vq81TgPRpEwAhHSfN6G4lDg4Pg2FuehJkhZ0"
        );
        assert_eq!(
            genesis.peer_pin(11).unwrap().peer_uri_digest,
            "hodGhKb5WbT3rF5YjBqkq2kQ6PNRqjqWJs8Sjf2M9i8"
        );
        assert_eq!(
            genesis.manifest_digest(),
            "bMnzRlHRHhPtOcHoyUZgsq0WYjjHUD3deL-tJduwrCg"
        );
        assert_eq!(
            genesis.signature().sig,
            "x1FzN01cNZKkP5WW8yEtf_UBKwGCP0wAYAkw4gELbbdx2_QV-Xv3Nrl9paTCds4cQGGADBih69TBRkyaY2VoCw"
        );
        let key_pair = key_pair(10);
        assert_eq!(
            private_oram_activation_authority_public_key_v1(&key_pair, 1).unwrap(),
            *authority
        );
    }

    #[test]
    fn bundle_requires_an_external_authority_pin() {
        let (_, trust_anchor, verified) = verified_genesis();
        let other_key = key_pair(9);
        let other_authority =
            private_oram_activation_authority_public_key_v1(&other_key, 1).unwrap();
        let other_trust_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                other_authority,
                trust_anchor.cluster_identity_digest().to_string(),
                trust_anchor.cluster_first_voter_peer_id(),
            )
            .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_bundle_v1(
                verified.bundle(),
                &other_trust_anchor,
                PrivateOramActivationRegistryExpectationV1::Anchored {
                    registry_generation: verified.manifest().registry_generation,
                    manifest_digest: verified.manifest_digest(),
                },
            ),
            Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch)
        );
        let _ = validate_private_oram_activation_authority_bundle_v1(
            verified.bundle(),
            &trust_anchor,
            PrivateOramActivationRegistryExpectationV1::Anchored {
                registry_generation: verified.manifest().registry_generation,
                manifest_digest: verified.manifest_digest(),
            },
        )
        .unwrap();
    }

    #[test]
    fn attacker_cannot_self_sign_a_replacement_authority_and_peer_pin() {
        let (_, trust_anchor, verified) = verified_genesis();
        let attacker_key = key_pair(9);
        let attacker_authority =
            private_oram_activation_authority_public_key_v1(&attacker_key, 1).unwrap();
        let mut replacement = verified.manifest().clone();
        replacement.authority_key_epoch = attacker_authority.key_epoch;
        replacement.authority_key_id = attacker_authority.key_id;
        replacement.peers[1].signer = peer(13, 99, 1).signer;
        let replacement =
            package_private_oram_activation_authority_manifest_v1(&attacker_key, 1, replacement)
                .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_bundle_v1(
                &replacement,
                &trust_anchor,
                PrivateOramActivationRegistryExpectationV1::Genesis,
            ),
            Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch)
        );
    }

    #[test]
    fn anchored_restart_rejects_stale_or_cross_cluster_bundles() {
        let (key_pair, trust_anchor, genesis) = verified_genesis();
        let mut next_manifest = genesis.manifest().clone();
        next_manifest.registry_generation = 2;
        next_manifest.parent_manifest_digest = Some(genesis.manifest_digest().to_string());
        let next_bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, next_manifest)
                .unwrap();
        let current = validate_private_oram_activation_authority_transition_v1(
            &genesis,
            &next_bundle,
            &trust_anchor,
        )
        .unwrap();

        assert_eq!(
            validate_private_oram_activation_authority_bundle_v1(
                genesis.bundle(),
                &trust_anchor,
                PrivateOramActivationRegistryExpectationV1::Anchored {
                    registry_generation: current.manifest().registry_generation,
                    manifest_digest: current.manifest_digest(),
                },
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );

        let wrong_cluster =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                trust_anchor.authority().clone(),
                digest(61),
                trust_anchor.cluster_first_voter_peer_id(),
            )
            .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_bundle_v1(
                current.bundle(),
                &wrong_cluster,
                PrivateOramActivationRegistryExpectationV1::Anchored {
                    registry_generation: current.manifest().registry_generation,
                    manifest_digest: current.manifest_digest(),
                },
            ),
            Err(PrivateOramActivationAuthorityError::AuthorityKeyMismatch)
        );
    }

    #[test]
    fn bundle_rejects_authority_key_reuse_as_a_peer_signer() {
        let (key_pair, trust_anchor, verified) = verified_genesis();
        let mut manifest = verified.manifest().clone();
        manifest.peers[0].signer = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        let bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, manifest).unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_bundle_v1(
                &bundle,
                &trust_anchor,
                PrivateOramActivationRegistryExpectationV1::Genesis,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );
    }

    #[test]
    fn peer_registry_must_be_canonical_and_unambiguous() {
        let (_, _, verified) = verified_genesis();
        assert!(verified.peer_pin(999).is_none());
        let mut manifest = verified.manifest().clone();
        manifest.peers.reverse();
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.peers[1].peer_uri_digest = manifest.peers[0].peer_uri_digest.clone();
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.peers[1].signer = manifest.peers[0].signer.clone();
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.cluster_first_voter_peer_id = 17;
        manifest.cluster_identity_digest = try_private_oram_activation_cluster_identity_digest_v1(
            &manifest.cluster_identity_nonce,
            manifest.cluster_first_voter_peer_id,
        )
        .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.peers.clear();
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.peers[0].peer_id = 0;
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.peers = vec![manifest.peers[0].clone(); MAX_AUTHORIZED_PEERS + 1];
        assert_eq!(
            validate_private_oram_activation_authority_manifest_v1_shape(&manifest),
            Err(PrivateOramActivationAuthorityError::InvalidManifest)
        );

        let mut manifest = verified.manifest().clone();
        manifest.peers[0].peer_uri_digest = "not-base64".to_string();
        assert!(validate_private_oram_activation_authority_manifest_v1_shape(&manifest).is_err());
    }

    #[test]
    fn transition_requires_a_consecutive_parent_chain() {
        let (key_pair, authority, previous) = verified_genesis();
        let mut next_manifest = previous.manifest().clone();
        next_manifest.registry_generation = 2;
        next_manifest.parent_manifest_digest = Some(previous.manifest_digest().to_string());
        next_manifest.required_binary_capability_digest = digest(4);
        next_manifest.peers.push(peer(17, 23, 1));
        let next_bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, next_manifest)
                .unwrap();
        let next = validate_private_oram_activation_authority_transition_v1(
            &previous,
            &next_bundle,
            &authority,
        )
        .unwrap();
        assert_eq!(next.manifest().registry_generation, 2);

        let mut skipped = next.bundle().clone();
        skipped.manifest.registry_generation = 4;
        skipped.manifest.parent_manifest_digest = Some(next.manifest_digest().to_string());
        skipped.signature =
            sign_private_oram_activation_authority_manifest_v1(&key_pair, 1, &skipped.manifest)
                .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_transition_v1(
                &previous, &skipped, &authority,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );

        let mut wrong_parent = previous.manifest().clone();
        wrong_parent.registry_generation = 2;
        wrong_parent.parent_manifest_digest = Some(digest(69));
        let wrong_parent =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, wrong_parent)
                .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_transition_v1(
                &previous,
                &wrong_parent,
                &authority,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );
    }

    #[test]
    fn transition_rejects_generation_overflow() {
        let (key_pair, authority, genesis) = verified_genesis();
        let mut max_manifest = genesis.manifest().clone();
        max_manifest.registry_generation = u64::MAX;
        max_manifest.parent_manifest_digest = Some(digest(70));
        let max_digest =
            private_oram_activation_authority_manifest_digest_v1(&max_manifest).unwrap();
        let max_bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, max_manifest)
                .unwrap();
        let max_current = validate_private_oram_activation_authority_bundle_v1(
            &max_bundle,
            &authority,
            PrivateOramActivationRegistryExpectationV1::Anchored {
                registry_generation: u64::MAX,
                manifest_digest: &max_digest,
            },
        )
        .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_transition_v1(
                &max_current,
                genesis.bundle(),
                &authority,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );
    }

    #[test]
    fn transition_rejects_peer_removal_or_signer_change() {
        let (key_pair, authority, previous) = verified_genesis();
        let mut next_manifest = previous.manifest().clone();
        next_manifest.registry_generation = 2;
        next_manifest.parent_manifest_digest = Some(previous.manifest_digest().to_string());
        next_manifest.peers[0].signer = peer(11, 31, 1).signer;
        let next_bundle =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, next_manifest)
                .unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_transition_v1(
                &previous,
                &next_bundle,
                &authority,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );

        let mut rotated = previous.manifest().clone();
        rotated.registry_generation = 2;
        rotated.parent_manifest_digest = Some(previous.manifest_digest().to_string());
        rotated.peers[0].signer = peer(11, 31, 2).signer;
        let rotated =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, rotated).unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_transition_v1(
                &previous, &rotated, &authority,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );

        let mut removed = previous.manifest().clone();
        removed.registry_generation = 2;
        removed.parent_manifest_digest = Some(previous.manifest_digest().to_string());
        removed.peers.pop();
        let removed =
            package_private_oram_activation_authority_manifest_v1(&key_pair, 1, removed).unwrap();
        assert_eq!(
            validate_private_oram_activation_authority_transition_v1(
                &previous, &removed, &authority,
            ),
            Err(PrivateOramActivationAuthorityError::InvalidTransition)
        );
    }

    #[test]
    fn challenge_resolver_binds_registry_configuration_and_uri() {
        let (_, _, authority) = verified_genesis();
        let configuration = configuration();
        let challenge = activation_challenge(&authority, &configuration);
        let observed_uri = authority.peer_pin(13).unwrap().peer_uri_digest.clone();
        let signer = private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
            &authority,
            &configuration,
            &observed_uri,
            &challenge,
        )
        .unwrap();
        assert_eq!(signer, &authority.peer_pin(13).unwrap().signer);

        let mut mutations = Vec::new();
        let mut value = challenge.clone();
        value.cluster_first_voter_peer_id = 17;
        mutations.push(value);
        let mut value = challenge.clone();
        value.pin_registry_generation += 1;
        mutations.push(value);
        let mut value = challenge.clone();
        value.pin_registry_digest = digest(62);
        mutations.push(value);
        let mut value = challenge.clone();
        value.required_binary_capability_digest = digest(63);
        mutations.push(value);
        let mut value = challenge.clone();
        value.target_peer_uri_digest = digest(64);
        mutations.push(value);
        let mut value = challenge;
        value.coordinator_peer_id = 17;
        mutations.push(value);
        for mutation in mutations {
            assert!(
                private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
                    &authority,
                    &configuration,
                    &observed_uri,
                    &mutation,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn challenge_resolver_rejects_unpinned_members_and_self_declared_signers() {
        let (_, _, authority) = verified_genesis();
        let configuration = configuration();
        let challenge = activation_challenge(&authority, &configuration);
        let observed_uri = authority.peer_pin(13).unwrap().peer_uri_digest.clone();
        let expected_signer = private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
            &authority,
            &configuration,
            &observed_uri,
            &challenge,
        )
        .unwrap();

        let attacker_ack = sign_private_oram_peer_activation_ack_v1(
            &key_pair(99),
            1,
            &challenge,
            observation(&challenge),
        )
        .unwrap();
        assert!(
            validate_private_oram_peer_activation_ack_signature_v1(
                &challenge,
                &attacker_ack,
                expected_signer,
            )
            .is_err()
        );
        let legitimate_ack = sign_private_oram_peer_activation_ack_v1(
            &key_pair(22),
            1,
            &challenge,
            observation(&challenge),
        )
        .unwrap();
        validate_private_oram_peer_activation_ack_signature_v1(
            &challenge,
            &legitimate_ack,
            expected_signer,
        )
        .unwrap();

        let unpinned_configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &[11, 13, 17],
            &[],
            &[],
            &[],
            false,
        )
        .unwrap();
        let unpinned_challenge = activation_challenge(&authority, &unpinned_configuration);
        assert_eq!(
            private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
                &authority,
                &unpinned_configuration,
                &observed_uri,
                &unpinned_challenge,
            ),
            Err(
                PrivateOramActivationAuthorityError::ChallengeContextMismatch(
                    "configuration_members"
                )
            )
        );

        let without_first_voter =
            PrivateOramConsensusConfigurationV1::from_raft_peer_sets(&[13], &[], &[], &[], false)
                .unwrap();
        let mut without_first_voter_challenge =
            activation_challenge(&authority, &without_first_voter);
        without_first_voter_challenge.coordinator_peer_id = 13;
        private_oram_activation_signer_from_signed_manifest_for_challenge_v1(
            &authority,
            &without_first_voter,
            &observed_uri,
            &without_first_voter_challenge,
        )
        .unwrap();
    }

    #[test]
    fn canonical_message_commits_to_every_manifest_field() {
        let (_, _, verified) = verified_genesis();
        let baseline = try_encode_manifest_message_without_shape_validation(
            PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_SIGNATURE_DOMAIN,
            verified.manifest(),
        )
        .unwrap();
        let mut mutations = Vec::new();

        let mut value = verified.manifest().clone();
        value.version += 1;
        mutations.push(("version", value));
        let mut value = verified.manifest().clone();
        value.cluster_identity_nonce = digest(31);
        mutations.push(("cluster_identity_nonce", value));
        let mut value = verified.manifest().clone();
        value.cluster_identity_digest = digest(32);
        mutations.push(("cluster_identity_digest", value));
        let mut value = verified.manifest().clone();
        value.cluster_first_voter_peer_id += 1;
        mutations.push(("cluster_first_voter_peer_id", value));
        let mut value = verified.manifest().clone();
        value.registry_generation += 1;
        mutations.push(("registry_generation", value));
        let mut value = verified.manifest().clone();
        value.parent_manifest_digest = Some(digest(33));
        mutations.push(("parent_manifest_digest", value));
        let mut value = verified.manifest().clone();
        value.required_capability.push('x');
        mutations.push(("required_capability", value));
        let mut value = verified.manifest().clone();
        value.required_binary_capability_digest = digest(34);
        mutations.push(("required_binary_capability_digest", value));
        let mut value = verified.manifest().clone();
        value.authority_key_epoch += 1;
        mutations.push(("authority_key_epoch", value));
        let mut value = verified.manifest().clone();
        value.authority_key_id = digest(35);
        mutations.push(("authority_key_id", value));
        let mut value = verified.manifest().clone();
        value.peers.push(peer(17, 24, 1));
        mutations.push(("peers_length", value));
        let mut value = verified.manifest().clone();
        value.peers[0].peer_id += 1;
        mutations.push(("peer_id", value));
        let mut value = verified.manifest().clone();
        value.peers[0].peer_uri_digest = digest(36);
        mutations.push(("peer_uri_digest", value));
        let mut value = verified.manifest().clone();
        value.peers[0].signer.version += 1;
        mutations.push(("peer_signer_version", value));
        let mut value = verified.manifest().clone();
        value.peers[0].signer.alg.push('x');
        mutations.push(("peer_signer_alg", value));
        let mut value = verified.manifest().clone();
        value.peers[0].signer.key_epoch += 1;
        mutations.push(("peer_signer_key_epoch", value));
        let mut value = verified.manifest().clone();
        value.peers[0].signer.key_id = digest(37);
        mutations.push(("peer_signer_key_id", value));
        let mut value = verified.manifest().clone();
        value.peers[0].signer.public_key = digest(38);
        mutations.push(("peer_signer_public_key", value));

        for (field, mutation) in mutations {
            let encoded = try_encode_manifest_message_without_shape_validation(
                PRIVATE_ORAM_ACTIVATION_AUTHORITY_MANIFEST_SIGNATURE_DOMAIN,
                &mutation,
            )
            .unwrap();
            assert_ne!(encoded, baseline, "canonical message omitted {field}");
            assert_ne!(
                Sha256::digest(encoded),
                Sha256::digest(&baseline),
                "manifest digest omitted {field}",
            );
        }
    }

    #[test]
    fn signed_u64_json_uses_canonical_decimal_strings() {
        let (_, trust_anchor, verified) = verified_genesis();
        let mut bundle = verified.bundle().clone();
        bundle.manifest.cluster_first_voter_peer_id = u64::MAX;
        bundle.manifest.registry_generation = u64::MAX;
        bundle.manifest.authority_key_epoch = u64::MAX;
        bundle.manifest.peers[0].peer_id = u64::MAX;
        bundle.manifest.peers[0].signer.key_epoch = u64::MAX;
        bundle.signature.key_epoch = u64::MAX;
        let encoded = serde_json::to_value(&bundle).unwrap();
        for pointer in [
            "/manifest/cluster_first_voter_peer_id",
            "/manifest/registry_generation",
            "/manifest/authority_key_epoch",
            "/manifest/peers/0/peer_id",
            "/manifest/peers/0/signer/key_epoch",
            "/signature/key_epoch",
        ] {
            assert_eq!(encoded.pointer(pointer).unwrap(), &u64::MAX.to_string());
        }
        assert_eq!(
            serde_json::from_value::<PrivateOramActivationAuthorityBundleV1>(encoded.clone())
                .unwrap(),
            bundle,
        );
        for pointer in [
            "/manifest/cluster_first_voter_peer_id",
            "/manifest/registry_generation",
            "/manifest/authority_key_epoch",
            "/manifest/peers/0/peer_id",
            "/manifest/peers/0/signer/key_epoch",
            "/signature/key_epoch",
        ] {
            let mut numeric = encoded.clone();
            *numeric.pointer_mut(pointer).unwrap() = serde_json::json!(1);
            assert!(
                serde_json::from_value::<PrivateOramActivationAuthorityBundleV1>(numeric).is_err(),
                "numeric JSON unexpectedly accepted at {pointer}",
            );
        }

        let mut authority_json = serde_json::to_value(trust_anchor.authority()).unwrap();
        assert_eq!(authority_json["key_epoch"], "1");
        authority_json["key_epoch"] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<PrivateOramActivationAuthorityPublicKeyV1>(authority_json)
                .is_err()
        );

        let mut noncanonical = serde_json::to_value(verified.bundle()).unwrap();
        noncanonical["manifest"]["registry_generation"] = serde_json::json!("01");
        assert!(
            serde_json::from_value::<PrivateOramActivationAuthorityBundleV1>(noncanonical).is_err()
        );
    }

    #[test]
    fn authority_base64_rejects_padding_and_noncanonical_tail_bits() {
        let (_, trust_anchor, verified) = verified_genesis();
        let noncanonical_tail = |encoded: &str| {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut bytes = encoded.as_bytes().to_vec();
            let last = bytes.len() - 1;
            let index = ALPHABET
                .iter()
                .position(|value| *value == bytes[last])
                .unwrap();
            bytes[last] = ALPHABET[index + 1];
            String::from_utf8(bytes).unwrap()
        };

        let mut padded_key = trust_anchor.authority().clone();
        padded_key.public_key.push('=');
        assert!(validate_private_oram_activation_authority_public_key_v1(&padded_key).is_err());
        let mut noncanonical_key = trust_anchor.authority().clone();
        noncanonical_key.public_key = noncanonical_tail(&noncanonical_key.public_key);
        assert!(
            validate_private_oram_activation_authority_public_key_v1(&noncanonical_key).is_err()
        );

        let mut padded_signature = verified.bundle().clone();
        padded_signature.signature.sig.push('=');
        assert!(
            validate_private_oram_activation_authority_signature_v1_shape(
                &padded_signature.signature
            )
            .is_err()
        );
        let mut noncanonical_signature = verified.bundle().clone();
        noncanonical_signature.signature.sig =
            noncanonical_tail(&noncanonical_signature.signature.sig);
        assert!(
            validate_private_oram_activation_authority_signature_v1_shape(
                &noncanonical_signature.signature
            )
            .is_err()
        );
    }

    #[test]
    fn stale_signature_rejects_every_manifest_and_signature_field_mutation() {
        let (_, authority, verified) = verified_genesis();
        let mut mutations = Vec::new();
        let mut value = verified.bundle().clone();
        value.manifest.version += 1;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.cluster_identity_nonce = digest(40);
        value.manifest.cluster_identity_digest =
            try_private_oram_activation_cluster_identity_digest_v1(
                &value.manifest.cluster_identity_nonce,
                value.manifest.cluster_first_voter_peer_id,
            )
            .unwrap();
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.cluster_first_voter_peer_id = 13;
        value.manifest.cluster_identity_digest =
            try_private_oram_activation_cluster_identity_digest_v1(
                &value.manifest.cluster_identity_nonce,
                value.manifest.cluster_first_voter_peer_id,
            )
            .unwrap();
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.registry_generation = 2;
        value.manifest.parent_manifest_digest = Some(digest(41));
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.parent_manifest_digest = Some(digest(42));
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.required_capability = "invalid-capability".to_string();
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.required_binary_capability_digest = digest(43);
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.authority_key_epoch += 1;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.authority_key_id = digest(44);
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.peers[1].peer_id = 17;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.peers[0].peer_uri_digest = digest(45);
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.peers[0].signer.key_epoch += 1;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.manifest.peers[0].signer = peer(11, 46, 1).signer;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.signature.version += 1;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.signature.alg = "invalid".to_string();
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.signature.key_epoch += 1;
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.signature.key_id = digest(47);
        mutations.push(value);
        let mut value = verified.bundle().clone();
        value.signature.sig = BASE64URL_NOPAD.encode(&[48; SIGNATURE_BYTES]);
        mutations.push(value);
        for mutation in mutations {
            assert!(
                validate_private_oram_activation_authority_bundle_v1(
                    &mutation,
                    &authority,
                    PrivateOramActivationRegistryExpectationV1::Anchored {
                        registry_generation: verified.manifest().registry_generation,
                        manifest_digest: verified.manifest_digest(),
                    },
                )
                .is_err()
            );
        }
    }

    #[test]
    fn peer_uri_digest_requires_canonical_components() {
        let http = try_private_oram_activation_peer_uri_digest_v1(
            PrivateOramActivationPeerUriSchemeV1::Http,
            "node-1.internal",
            6335,
        )
        .unwrap();
        let https = try_private_oram_activation_peer_uri_digest_v1(
            PrivateOramActivationPeerUriSchemeV1::Https,
            "node-1.internal",
            6335,
        )
        .unwrap();
        let other_port = try_private_oram_activation_peer_uri_digest_v1(
            PrivateOramActivationPeerUriSchemeV1::Http,
            "node-1.internal",
            6336,
        )
        .unwrap();
        assert_ne!(http, https);
        assert_ne!(http, other_port);
        let bare_ipv6 = try_private_oram_activation_peer_uri_digest_v1(
            PrivateOramActivationPeerUriSchemeV1::Https,
            "::1",
            6335,
        )
        .unwrap();
        // `http::Uri::host()` yields the bracketed form; it must pin the same digest.
        assert_eq!(
            try_private_oram_activation_peer_uri_digest_v1(
                PrivateOramActivationPeerUriSchemeV1::Https,
                "[::1]",
                6335,
            )
            .unwrap(),
            bare_ipv6
        );
        for bracketed in [
            "[127.0.0.1]",
            "[::1",
            "::1]",
            "[::01]",
            "[node.internal]",
            "[]",
        ] {
            assert!(
                try_private_oram_activation_peer_uri_digest_v1(
                    PrivateOramActivationPeerUriSchemeV1::Https,
                    bracketed,
                    6335,
                )
                .is_err(),
                "{bracketed}"
            );
        }
        for host in [
            "NODE.internal",
            "node name",
            "127.000.0.1",
            "-node.internal",
            "0:0:0:0:0:0:0:1",
        ] {
            assert!(
                try_private_oram_activation_peer_uri_digest_v1(
                    PrivateOramActivationPeerUriSchemeV1::Https,
                    host,
                    6335,
                )
                .is_err()
            );
        }
        assert!(
            try_private_oram_activation_peer_uri_digest_v1(
                PrivateOramActivationPeerUriSchemeV1::Https,
                "node.internal",
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn debug_and_errors_redact_authority_material() {
        let (_, trust_anchor, verified) = verified_genesis();
        let rendered = format!("{trust_anchor:?} {verified:?} {:?}", verified.bundle());
        assert!(!rendered.contains(&verified.manifest().cluster_identity_nonce));
        assert!(!rendered.contains(trust_anchor.cluster_identity_digest()));
        assert!(!rendered.contains(&verified.signature().sig));
        assert!(
            !format!(
                "{:?}",
                PrivateOramActivationAuthorityError::InvalidSignature
            )
            .contains(&verified.signature().sig)
        );
    }

    #[test]
    fn serde_rejects_unknown_authority_fields() {
        let (_, _, verified) = verified_genesis();
        let mut value = serde_json::to_value(verified.bundle()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<PrivateOramActivationAuthorityBundleV1>(value).is_err());

        let mut value = serde_json::to_value(verified.manifest()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<PrivateOramActivationAuthorityManifestV1>(value).is_err());

        let mut value = serde_json::to_value(verified.peer_pin(11).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<PrivateOramActivationPeerPinV1>(value).is_err());
    }
}
