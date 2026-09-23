use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::aead::{
    AeadCipher, AeadKeyring, EncryptedEnvelope, EncryptionContext, EncryptionError,
    EncryptionPurpose, METADATA_VALUE_KEY_DOMAIN, PAYLOAD_TEXT_KEY_DOMAIN, SecretKey,
    bounded_untrusted_text, validate_encrypted_envelope_metadata, validate_resource_key_id,
};

pub const ENCRYPTED_PAYLOAD_MARKER: &str = "$qdrant_sec";
pub const CLIENT_ENCRYPTED_PAYLOAD_MARKER: &str = "$qdrant_client_aead";
pub const PAYLOAD_TEXT_ENVELOPE_KIND: &str = "payload_text";
pub const METADATA_VALUE_ENVELOPE_KIND: &str = "metadata_value";
const CLIENT_PAYLOAD_ALGORITHM: &str = "AES-256-GCM";
const CLIENT_PAYLOAD_KDF_DOMAIN: &str = "qdrant-sec/client-payload-text/v1";
const CLIENT_PAYLOAD_SIGNATURE_DOMAIN: &str = "qdrant-sec/client-payload-signature/v1";
const CLIENT_PAYLOAD_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_12_BYTE_LEN: usize = 16;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const CLIENT_PAYLOAD_CIPHERTEXT_MAX_BYTES: usize = 1024 * 1024;
const CLIENT_PAYLOAD_CIPHERTEXT_MAX_B64_LEN: usize =
    base64url_nopad_encoded_len(CLIENT_PAYLOAD_CIPHERTEXT_MAX_BYTES);
const SERVER_PAYLOAD_CIPHERTEXT_MAX_BYTES: usize = 1024 * 1024;
const SERVER_PAYLOAD_CIPHERTEXT_MAX_B64_LEN: usize =
    base64url_nopad_encoded_len(SERVER_PAYLOAD_CIPHERTEXT_MAX_BYTES);
const CRYPTO_SCHEMA_VERSION: u16 = 1;
const DEFAULT_ENCRYPTION_EPOCH: u64 = 0;

const fn base64url_nopad_encoded_len(decoded_len: usize) -> usize {
    let full_groups = decoded_len / 3;
    let remainder = decoded_len % 3;
    let base_len = full_groups * 4;
    match remainder {
        0 => base_len,
        1 => base_len + 2,
        _ => base_len + 3,
    }
}

#[derive(Error, PartialEq, Eq)]
pub enum PayloadEncryptionError {
    #[error("payload encryption policy must contain at least one field")]
    EmptyPolicy,
    #[error("payload encryption field path is invalid: {0}")]
    InvalidFieldPath(String),
    #[error("required payload field is missing: {0}")]
    MissingField(String),
    #[error("payload field path expects an object parent: {0}")]
    ExpectedObjectParent(String),
    #[error("payload field {field} must be a string, found {found}")]
    ExpectedString { field: String, found: &'static str },
    #[error(
        "payload field {field} must contain an encrypted qdrant crypto envelope, found {found}"
    )]
    ExpectedEncryptedEnvelope { field: String, found: &'static str },
    #[error("payload field is already encrypted: {0}")]
    AlreadyEncrypted(String),
    #[error("payload field contains a malformed qdrant crypto envelope: {0}")]
    MalformedEnvelope(String),
    #[error("payload field contains unsupported qdrant crypto envelope kind: {0}")]
    UnsupportedEnvelopeKind(String),
    #[error("payload field contains unsupported client envelope algorithm: {0}")]
    UnsupportedClientAlgorithm(String),
    #[error("payload field client envelope AAD does not match expected {0}")]
    ClientEnvelopeAadMismatch(String),
    #[error("payload field client envelope key id is missing")]
    MissingClientKeyId,
    #[error("payload field client envelope key id does not match policy")]
    ClientKeyIdMismatch,
    #[error("payload field client envelope resource key id does not match policy")]
    ClientResourceKeyIdMismatch,
    #[error("payload field client envelope resource key epoch is outside policy")]
    ClientResourceKeyEpochMismatch,
    #[error(
        "payload field client envelope nonce was already used; regenerate the client-side envelope with a fresh nonce before retrying"
    )]
    ClientNonceReplay,
    #[error("client payload nonce replay cache key is malformed")]
    MalformedClientNonceReplayCacheKey,
    #[error("payload field client envelope signature is missing")]
    MissingClientSignature,
    #[error("payload field client envelope signature key id does not match policy")]
    ClientSignatureKeyIdMismatch,
    #[error("payload field contains unsupported client envelope signature algorithm: {0}")]
    UnsupportedClientSignatureAlgorithm(String),
    #[error("payload field client envelope signature verification failed")]
    InvalidClientSignature,
    #[error("payload field client envelope ciphertext exceeds maximum size: {0}")]
    ClientCiphertextTooLarge(String),
    #[error("payload field server envelope ciphertext exceeds maximum size: {0}")]
    ServerCiphertextTooLarge(String),
    #[error("payload field encrypted envelope does not match runtime verification proof")]
    RuntimeEnvelopeProofMismatch,
    #[error("payload field contains unsupported qdrant crypto schema version: {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("payload field encryption epoch does not match active policy")]
    EncryptionEpochMismatch,
    #[error("payload plaintext is not valid UTF-8 after decryption: {0}")]
    InvalidUtf8(String),
    #[error(transparent)]
    Crypto(#[from] EncryptionError),
}

impl Debug for PayloadEncryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPolicy => f.write_str("EmptyPolicy"),
            Self::InvalidFieldPath(_) => f
                .debug_tuple("InvalidFieldPath")
                .field(&"[redacted]")
                .finish(),
            Self::MissingField(_) => f.debug_tuple("MissingField").field(&"[redacted]").finish(),
            Self::ExpectedObjectParent(_) => f
                .debug_tuple("ExpectedObjectParent")
                .field(&"[redacted]")
                .finish(),
            Self::ExpectedString { found, .. } => f
                .debug_struct("ExpectedString")
                .field("field", &"[redacted]")
                .field("found", found)
                .finish(),
            Self::ExpectedEncryptedEnvelope { found, .. } => f
                .debug_struct("ExpectedEncryptedEnvelope")
                .field("field", &"[redacted]")
                .field("found", found)
                .finish(),
            Self::AlreadyEncrypted(_) => f
                .debug_tuple("AlreadyEncrypted")
                .field(&"[redacted]")
                .finish(),
            Self::MalformedEnvelope(_) => f
                .debug_tuple("MalformedEnvelope")
                .field(&"[redacted]")
                .finish(),
            Self::UnsupportedEnvelopeKind(_) => f
                .debug_tuple("UnsupportedEnvelopeKind")
                .field(&"[redacted]")
                .finish(),
            Self::UnsupportedClientAlgorithm(_) => f
                .debug_tuple("UnsupportedClientAlgorithm")
                .field(&"[redacted]")
                .finish(),
            Self::ClientEnvelopeAadMismatch(_) => f
                .debug_tuple("ClientEnvelopeAadMismatch")
                .field(&"[redacted]")
                .finish(),
            Self::MissingClientKeyId => f.write_str("MissingClientKeyId"),
            Self::ClientKeyIdMismatch => f.write_str("ClientKeyIdMismatch"),
            Self::ClientResourceKeyIdMismatch => f.write_str("ClientResourceKeyIdMismatch"),
            Self::ClientResourceKeyEpochMismatch => f.write_str("ClientResourceKeyEpochMismatch"),
            Self::ClientNonceReplay => f.write_str("ClientNonceReplay"),
            Self::MalformedClientNonceReplayCacheKey => {
                f.write_str("MalformedClientNonceReplayCacheKey")
            }
            Self::MissingClientSignature => f.write_str("MissingClientSignature"),
            Self::ClientSignatureKeyIdMismatch => f.write_str("ClientSignatureKeyIdMismatch"),
            Self::UnsupportedClientSignatureAlgorithm(_) => f
                .debug_tuple("UnsupportedClientSignatureAlgorithm")
                .field(&"[redacted]")
                .finish(),
            Self::InvalidClientSignature => f.write_str("InvalidClientSignature"),
            Self::ClientCiphertextTooLarge(_) => f
                .debug_tuple("ClientCiphertextTooLarge")
                .field(&"[redacted]")
                .finish(),
            Self::ServerCiphertextTooLarge(_) => f
                .debug_tuple("ServerCiphertextTooLarge")
                .field(&"[redacted]")
                .finish(),
            Self::RuntimeEnvelopeProofMismatch => f.write_str("RuntimeEnvelopeProofMismatch"),
            Self::UnsupportedSchemaVersion(version) => f
                .debug_tuple("UnsupportedSchemaVersion")
                .field(version)
                .finish(),
            Self::EncryptionEpochMismatch => f.write_str("EncryptionEpochMismatch"),
            Self::InvalidUtf8(_) => f.debug_tuple("InvalidUtf8").field(&"[redacted]").finish(),
            Self::Crypto(_) => f.debug_tuple("Crypto").field(&"[redacted]").finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PayloadEncryptionPolicy {
    fields: Vec<String>,
    strict_missing_fields: bool,
}

impl Debug for PayloadEncryptionPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadEncryptionPolicy")
            .field("field_count", &"[redacted]")
            .field("strict_missing_fields", &self.strict_missing_fields)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingPayloadMode {
    SkipExisting,
    ReencryptIfStale,
    FailIfExisting,
}

impl PayloadEncryptionPolicy {
    pub fn new<I, S>(fields: I) -> Result<Self, PayloadEncryptionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut normalized = Vec::new();

        for field in fields {
            let field = field.into();
            if field.is_empty()
                || field.starts_with('.')
                || field.ends_with('.')
                || field.split('.').any(|part| {
                    part.is_empty()
                        || part == ENCRYPTED_PAYLOAD_MARKER
                        || part == CLIENT_ENCRYPTED_PAYLOAD_MARKER
                        || part == "$qdrant_ciphertext"
                        || part.contains('\0')
                        || part.contains('[')
                        || part.contains(']')
                        || part.contains('*')
                        || part.bytes().all(|byte| byte.is_ascii_digit())
                })
            {
                return Err(PayloadEncryptionError::InvalidFieldPath(field));
            }

            if !normalized.iter().any(|existing| existing == &field) {
                normalized.push(field);
            }
        }

        if normalized.is_empty() {
            return Err(PayloadEncryptionError::EmptyPolicy);
        }

        Ok(Self {
            fields: normalized,
            strict_missing_fields: false,
        })
    }

    pub fn with_strict_missing_fields(mut self, strict: bool) -> Self {
        self.strict_missing_fields = strict;
        self
    }

    pub fn fields(&self) -> &[String] {
        &self.fields
    }
}

pub struct PayloadTextEncryptor {
    collection: String,
    keyring: AeadKeyring,
    key_domain: &'static [u8],
    purpose: EncryptionPurpose,
    envelope_kind: &'static str,
    crypto_schema_version: u16,
    encryption_epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientPayloadValidationContext<'a> {
    pub collection_id: &'a str,
    pub point_id: &'a str,
    pub field_path: &'a str,
    pub expected_key_id: Option<&'a str>,
    pub expected_rk_id: Option<&'a str>,
    pub min_rk_epoch: Option<u64>,
    pub max_rk_epoch: Option<u64>,
    pub key_id_required: bool,
    pub signature_required: bool,
    pub signature_verification: Option<ClientPayloadSignatureVerification<'a>>,
}

impl Debug for ClientPayloadValidationContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadValidationContext")
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("field_path", &"[redacted]")
            .field("expected_key_id", &"[redacted]")
            .field("expected_rk_id", &"[redacted]")
            .field("min_rk_epoch", &self.min_rk_epoch)
            .field("max_rk_epoch", &self.max_rk_epoch)
            .field("key_id_required", &self.key_id_required)
            .field("signature_required", &self.signature_required)
            .field(
                "signature_verification_configured",
                &self.signature_verification.is_some(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClientPayloadSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

impl Debug for ClientPayloadSignatureVerification<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadSignatureVerification")
            .field("expected_key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientPayloadNonceReplayKey {
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    nonce: String,
}

impl Debug for ClientPayloadNonceReplayKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadNonceReplayKey")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("nonce", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientPayloadEnvelopeKey {
    collection_id: String,
    point_id: String,
    field_path: String,
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    nonce: String,
    ciphertext_sha256_b64: String,
    signature_key_id: String,
    signature_sha256_b64: String,
}

impl Debug for ClientPayloadEnvelopeKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadEnvelopeKey")
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("field_path", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("nonce", &"[redacted]")
            .field("ciphertext_sha256_b64", &"[redacted]")
            .field("signature_key_id", &"[redacted]")
            .field("signature_sha256_b64", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServerPayloadEnvelopeKey {
    collection_id: String,
    point_id: String,
    field_path: String,
    key_id: String,
    material_fingerprint: String,
    rk_id: String,
    rk_epoch: Option<u64>,
    schema_version: u16,
    encryption_epoch: u64,
    nonce: String,
    ciphertext_sha256_b64: String,
}

impl Debug for ServerPayloadEnvelopeKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerPayloadEnvelopeKey")
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("field_path", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("material_fingerprint", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("schema_version", &self.schema_version)
            .field("encryption_epoch", &self.encryption_epoch)
            .field("nonce", &"[redacted]")
            .field("ciphertext_sha256_b64", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientPayloadVerifiedEnvelopeKey {
    envelope_key: ClientPayloadEnvelopeKey,
    blind_indexes: Vec<ClientPayloadBlindIndexTokenKey>,
}

impl Debug for ClientPayloadVerifiedEnvelopeKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadVerifiedEnvelopeKey")
            .field("envelope_key", &self.envelope_key)
            .field("blind_index_count", &self.blind_indexes.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServerPayloadVerifiedEnvelopeKey {
    envelope_key: ServerPayloadEnvelopeKey,
}

impl Debug for ServerPayloadVerifiedEnvelopeKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerPayloadVerifiedEnvelopeKey")
            .field("envelope_key", &self.envelope_key)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ClientPayloadBlindIndexTokenKey {
    field_path: String,
    token: String,
}

impl Debug for ClientPayloadBlindIndexTokenKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadBlindIndexTokenKey")
            .field("field_path", &"[redacted]")
            .field("token", &"[redacted]")
            .finish()
    }
}

impl ClientPayloadNonceReplayKey {
    pub fn cache_key(&self) -> String {
        format!(
            "{}\x1f{}\x1f{}\x1f{}",
            self.key_id, self.rk_id, self.rk_epoch, self.nonce,
        )
    }

    pub fn cache_key_for_collection(&self, collection_crypto_id: &str) -> String {
        format!("{}\x1f{}", collection_crypto_id, self.cache_key())
    }

    pub fn validate_cache_key_for_collection(
        cache_key: &str,
    ) -> Result<(), PayloadEncryptionError> {
        let mut parts = cache_key.split('\x1f');
        let Some(collection_crypto_id) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(key_id) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(rk_id) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(rk_epoch) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(nonce) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        if parts.next().is_some()
            || collection_crypto_id.is_empty()
            || key_id.is_empty()
            || rk_id.is_empty()
            || rk_epoch.is_empty()
            || nonce.is_empty()
        {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        }
        validate_resource_key_id(collection_crypto_id)
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        validate_resource_key_id(key_id)
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        validate_resource_key_id(rk_id)
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        rk_epoch
            .parse::<u64>()
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        validate_base64url_nopad_encoded_len(
            nonce,
            BASE64URL_NOPAD_12_BYTE_LEN,
            PayloadEncryptionError::MalformedClientNonceReplayCacheKey,
        )?;
        let nonce = BASE64URL_NOPAD
            .decode(nonce.as_bytes())
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        if nonce.len() != 12 {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        }

        Ok(())
    }
}

impl ClientPayloadVerifiedEnvelopeKey {
    pub fn envelope_key(&self) -> &ClientPayloadEnvelopeKey {
        &self.envelope_key
    }

    pub fn binds_blind_index(
        &self,
        collection_id: &str,
        point_id: &str,
        field_path: &str,
        token: &str,
    ) -> bool {
        self.envelope_key.collection_id == collection_id
            && self.envelope_key.point_id == point_id
            && self.blind_indexes.iter().any(|binding| {
                // Tokens are keyed MACs over plaintext: compare them in constant time so a
                // filter probe cannot learn a stored token byte by byte.
                binding.field_path == field_path
                    && constant_time_eq::constant_time_eq(
                        binding.token.as_bytes(),
                        token.as_bytes(),
                    )
            })
    }
}

impl ServerPayloadVerifiedEnvelopeKey {
    pub fn envelope_key(&self) -> &ServerPayloadEnvelopeKey {
        &self.envelope_key
    }
}

impl ClientPayloadEnvelopeKey {
    pub fn matches_binding(&self, collection_id: &str, point_id: &str, field_path: &str) -> bool {
        self.collection_id == collection_id
            && self.point_id == point_id
            && self.field_path == field_path
    }
}

impl ServerPayloadEnvelopeKey {
    pub fn matches_binding(&self, collection_id: &str, point_id: &str, field_path: &str) -> bool {
        self.collection_id == collection_id
            && self.point_id == point_id
            && self.field_path == field_path
    }
}

impl PayloadTextEncryptor {
    pub fn new_from_resource_key_with_material_fingerprint(
        collection: impl Into<String>,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        Self::new_with_derived_cipher_unchecked(
            collection,
            AeadCipher::new_with_material_fingerprint(
                key_id,
                payload_key,
                material_fingerprint_id,
            )?,
        )
    }

    pub fn new_from_resource_key_with_metadata(
        collection: impl Into<String>,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        let cipher = AeadCipher::new_with_material_fingerprint(
            key_id,
            payload_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;
        Self::new_with_derived_cipher_unchecked(collection, cipher)
    }

    pub fn new_metadata_value_from_resource_key_with_metadata(
        collection: impl Into<String>,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, PayloadEncryptionError> {
        let metadata_key = resource_key.derive_subkey(METADATA_VALUE_KEY_DOMAIN)?;
        let cipher = AeadCipher::new_with_material_fingerprint(
            key_id,
            metadata_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;
        Self::new_with_derived_keyring_for_domain_unchecked(
            collection,
            AeadKeyring::new(cipher),
            METADATA_VALUE_KEY_DOMAIN,
            EncryptionPurpose::MetadataValue,
            METADATA_VALUE_ENVELOPE_KIND,
        )
    }

    /// Builds an encryptor from an already domain-separated AEAD cipher.
    ///
    /// Runtime code that starts from a collection/rule resource key should use
    /// `new_from_resource_key*` so the payload-text HKDF domain is applied in
    /// one place. This constructor is safe Rust because key provenance cannot
    /// be checked by the type system; `unchecked` records the caller's
    /// cryptographic responsibility rather than a memory-safety precondition.
    pub(crate) fn new_with_derived_cipher_unchecked(
        collection: impl Into<String>,
        cipher: AeadCipher,
    ) -> Result<Self, PayloadEncryptionError> {
        Self::new_with_derived_keyring_unchecked(collection, AeadKeyring::new(cipher))
    }

    /// Builds an encryptor from an already domain-separated AEAD keyring.
    ///
    /// Prefer `new_from_resource_key*` for production runtime code. The caller
    /// is still responsible for passing only payload-text domain key material.
    pub(crate) fn new_with_derived_keyring_unchecked(
        collection: impl Into<String>,
        keyring: AeadKeyring,
    ) -> Result<Self, PayloadEncryptionError> {
        Self::new_with_derived_keyring_for_domain_unchecked(
            collection,
            keyring,
            PAYLOAD_TEXT_KEY_DOMAIN,
            EncryptionPurpose::PayloadText,
            PAYLOAD_TEXT_ENVELOPE_KIND,
        )
    }

    fn new_with_derived_keyring_for_domain_unchecked(
        collection: impl Into<String>,
        keyring: AeadKeyring,
        key_domain: &'static [u8],
        purpose: EncryptionPurpose,
        envelope_kind: &'static str,
    ) -> Result<Self, PayloadEncryptionError> {
        let collection = collection.into();
        if collection.is_empty() || collection.contains('\0') {
            return Err(PayloadEncryptionError::InvalidFieldPath(
                "collection".to_string(),
            ));
        }
        Ok(Self {
            collection,
            keyring,
            key_domain,
            purpose,
            envelope_kind,
            crypto_schema_version: CRYPTO_SCHEMA_VERSION,
            encryption_epoch: DEFAULT_ENCRYPTION_EPOCH,
        })
    }

    pub fn with_encryption_epoch(mut self, encryption_epoch: u64) -> Self {
        self.encryption_epoch = encryption_epoch;
        self
    }

    pub fn key_id(&self) -> &str {
        self.keyring.key_id()
    }

    pub const fn crypto_schema_version(&self) -> u16 {
        self.crypto_schema_version
    }

    pub const fn encryption_epoch(&self) -> u64 {
        self.encryption_epoch
    }

    fn context<'a>(&'a self, point_id: &'a str, field: &'a str) -> EncryptionContext<'a> {
        match self.purpose {
            EncryptionPurpose::PayloadText => {
                EncryptionContext::payload_text(&self.collection, point_id, field)
            }
            EncryptionPurpose::MetadataValue => {
                EncryptionContext::metadata_value(&self.collection, point_id, field)
            }
            EncryptionPurpose::CkksVector => {
                unreachable!("payload encryptor never uses the CKKS vector purpose")
            }
        }
    }

    fn ensure_envelope_kind(
        &self,
        envelope: &StoredPayloadEnvelope,
    ) -> Result<(), PayloadEncryptionError> {
        if envelope.kind != self.envelope_kind {
            return Err(PayloadEncryptionError::UnsupportedEnvelopeKind(
                envelope.kind.clone(),
            ));
        }
        Ok(())
    }

    pub fn with_retired_resource_key(
        mut self,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(self.key_domain)?;
        let retired = AeadCipher::new_with_material_fingerprint(
            key_id,
            payload_key,
            material_fingerprint_id,
        )?;
        self.keyring = self.keyring.with_retired(retired);
        Ok(self)
    }

    pub fn with_retired_resource_key_metadata(
        mut self,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(self.key_domain)?;
        let retired = AeadCipher::new_with_material_fingerprint(
            key_id,
            payload_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;
        self.keyring = self.keyring.with_retired(retired);
        Ok(self)
    }

    pub fn encrypt_selected_fields(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
    ) -> Result<usize, PayloadEncryptionError> {
        self.encrypt_selected_fields_with_mode(
            point_id,
            payload,
            policy,
            ExistingPayloadMode::SkipExisting,
        )
    }

    pub fn encrypt_selected_fields_with_mode(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
        existing_mode: ExistingPayloadMode,
    ) -> Result<usize, PayloadEncryptionError> {
        let mut encrypted = 0;

        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                if policy.strict_missing_fields {
                    return Err(PayloadEncryptionError::MissingField(field.clone()));
                }
                continue;
            };

            if let Some(existing_envelope) = extract_envelope(value, field)? {
                self.ensure_envelope_kind(&existing_envelope)?;
                match existing_mode {
                    ExistingPayloadMode::SkipExisting => continue,
                    ExistingPayloadMode::FailIfExisting => {
                        return Err(PayloadEncryptionError::AlreadyEncrypted(field.clone()));
                    }
                    ExistingPayloadMode::ReencryptIfStale => {
                        // Freshness must cover the resource key lineage as well: a pure
                        // resource-key rotation keeps key_id and material fingerprint but
                        // changes rk_id/rk_epoch, and those envelopes must be re-wrapped.
                        if existing_envelope.schema_version == self.crypto_schema_version
                            && existing_envelope.encryption_epoch == self.encryption_epoch
                            && existing_envelope.envelope.key_id == self.keyring.key_id()
                            && existing_envelope.envelope.material_fingerprint
                                == self.keyring.material_fingerprint()
                            && existing_envelope.envelope.rk_id
                                == self.keyring.resource_key_id().unwrap_or_default()
                            && existing_envelope.envelope.rk_epoch
                                == self.keyring.resource_key_epoch()
                        {
                            continue;
                        }

                        let context = self.context(point_id, field);
                        let old_aad_suffix = payload_metadata_aad(
                            &existing_envelope.kind,
                            existing_envelope.schema_version,
                            existing_envelope.encryption_epoch,
                        );
                        let plaintext = Zeroizing::new(self.keyring.decrypt_with_aad_suffix(
                            &existing_envelope.envelope,
                            context,
                            &old_aad_suffix,
                        )?);
                        let new_aad_suffix = payload_metadata_aad(
                            self.envelope_kind,
                            self.crypto_schema_version,
                            self.encryption_epoch,
                        );
                        let envelope = self.keyring.encrypt_with_aad_suffix(
                            &plaintext,
                            context,
                            &new_aad_suffix,
                        )?;
                        *value = stored_envelope_value(
                            envelope,
                            field,
                            self.envelope_kind,
                            self.crypto_schema_version,
                            self.encryption_epoch,
                        )?;
                        encrypted += 1;
                        continue;
                    }
                }
            }

            // Take the plaintext out of the JSON value instead of copying it, so the only
            // heap copy is scrubbed when this iteration ends; the slot is overwritten with the
            // envelope below.
            let plaintext = match value {
                Value::String(plaintext) => Zeroizing::new(std::mem::take(plaintext).into_bytes()),
                other => {
                    return Err(PayloadEncryptionError::ExpectedString {
                        field: field.clone(),
                        found: json_type_name(other),
                    });
                }
            };

            let context = self.context(point_id, field);
            let aad_suffix = payload_metadata_aad(
                self.envelope_kind,
                self.crypto_schema_version,
                self.encryption_epoch,
            );
            let envelope =
                self.keyring
                    .encrypt_with_aad_suffix(&plaintext, context, &aad_suffix)?;
            *value = stored_envelope_value(
                envelope,
                field,
                self.envelope_kind,
                self.crypto_schema_version,
                self.encryption_epoch,
            )?;
            encrypted += 1;
        }

        Ok(encrypted)
    }

    pub fn encrypt_selected_fields_for_runtime(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
        collection_id: &str,
    ) -> Result<(usize, Vec<ServerPayloadVerifiedEnvelopeKey>), PayloadEncryptionError> {
        self.encrypt_selected_fields_with_mode_for_runtime(
            point_id,
            payload,
            policy,
            collection_id,
            ExistingPayloadMode::FailIfExisting,
        )
    }

    pub fn encrypt_selected_fields_with_mode_for_runtime(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
        collection_id: &str,
        existing_mode: ExistingPayloadMode,
    ) -> Result<(usize, Vec<ServerPayloadVerifiedEnvelopeKey>), PayloadEncryptionError> {
        if collection_id != self.collection {
            return Err(PayloadEncryptionError::InvalidFieldPath(
                "collection_id".to_string(),
            ));
        }
        let changed =
            self.encrypt_selected_fields_with_mode(point_id, payload, policy, existing_mode)?;
        let mut verified_envelope_keys = Vec::new();
        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                continue;
            };
            verified_envelope_keys.push(server_payload_verified_envelope_key(
                value,
                collection_id,
                point_id,
                ServerPayloadValidationContext {
                    field_path: field,
                    expected_kind: Some(self.envelope_kind),
                    key_id: Some(self.key_id()),
                    crypto_schema_version: self.crypto_schema_version,
                    encryption_epoch: self.encryption_epoch,
                },
            )?);
        }
        Ok((changed, verified_envelope_keys))
    }

    pub fn decrypt_selected_fields(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
    ) -> Result<usize, PayloadEncryptionError> {
        let mut decrypted = 0;

        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                if policy.strict_missing_fields {
                    return Err(PayloadEncryptionError::MissingField(field.clone()));
                }
                continue;
            };

            let envelope = extract_envelope(value, field)?.ok_or_else(|| {
                PayloadEncryptionError::ExpectedEncryptedEnvelope {
                    field: field.clone(),
                    found: json_type_name(value),
                }
            })?;
            self.ensure_envelope_kind(&envelope)?;
            let context = self.context(point_id, field);
            let aad_suffix = payload_metadata_aad(
                &envelope.kind,
                envelope.schema_version,
                envelope.encryption_epoch,
            );
            // Stale or foreign envelopes are rejected before any plaintext is materialized.
            if envelope.schema_version != self.crypto_schema_version {
                return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
                    envelope.schema_version,
                ));
            }
            if envelope.encryption_epoch != self.encryption_epoch {
                return Err(PayloadEncryptionError::EncryptionEpochMismatch);
            }
            let plaintext = Zeroizing::new(self.keyring.decrypt_with_aad_suffix(
                &envelope.envelope,
                context,
                &aad_suffix,
            )?);
            let plaintext = std::str::from_utf8(&plaintext)
                .map_err(|err| PayloadEncryptionError::InvalidUtf8(err.to_string()))?
                .to_owned();

            *value = Value::String(plaintext);
            decrypted += 1;
        }

        Ok(decrypted)
    }

    pub fn decrypt_selected_fields_if_encrypted(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
    ) -> Result<usize, PayloadEncryptionError> {
        let mut decrypted = 0;

        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                if policy.strict_missing_fields {
                    return Err(PayloadEncryptionError::MissingField(field.clone()));
                }
                continue;
            };

            let Some(envelope) = extract_envelope(value, field)? else {
                continue;
            };
            self.ensure_envelope_kind(&envelope)?;
            let context = self.context(point_id, field);
            let aad_suffix = payload_metadata_aad(
                &envelope.kind,
                envelope.schema_version,
                envelope.encryption_epoch,
            );
            // Stale or foreign envelopes are rejected before any plaintext is materialized.
            if envelope.schema_version != self.crypto_schema_version {
                return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
                    envelope.schema_version,
                ));
            }
            if envelope.encryption_epoch != self.encryption_epoch {
                return Err(PayloadEncryptionError::EncryptionEpochMismatch);
            }
            let plaintext = Zeroizing::new(self.keyring.decrypt_with_aad_suffix(
                &envelope.envelope,
                context,
                &aad_suffix,
            )?);
            let plaintext = std::str::from_utf8(&plaintext)
                .map_err(|err| PayloadEncryptionError::InvalidUtf8(err.to_string()))?
                .to_owned();

            *value = Value::String(plaintext);
            decrypted += 1;
        }

        Ok(decrypted)
    }
}

pub fn is_encrypted_payload_value(value: &Value) -> bool {
    extract_envelope(value, ENCRYPTED_PAYLOAD_MARKER)
        .map(|envelope| envelope.is_some())
        .unwrap_or(false)
}

pub fn is_client_encrypted_payload_value(value: &Value) -> bool {
    extract_client_envelope(value, CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .map(|envelope| envelope.is_some())
        .unwrap_or(false)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ServerPayloadValidationContext<'a> {
    pub field_path: &'a str,
    pub expected_kind: Option<&'a str>,
    pub key_id: Option<&'a str>,
    pub crypto_schema_version: u16,
    pub encryption_epoch: u64,
}

impl Debug for ServerPayloadValidationContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerPayloadValidationContext")
            .field("field_path", &"[redacted]")
            .field("expected_kind", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("crypto_schema_version", &self.crypto_schema_version)
            .field("encryption_epoch", &self.encryption_epoch)
            .finish()
    }
}

pub fn validate_server_payload_value_metadata(
    value: &Value,
    context: ServerPayloadValidationContext<'_>,
) -> Result<(), PayloadEncryptionError> {
    let envelope = extract_envelope(value, context.field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: context.field_path.to_string(),
            found: json_type_name(value),
        }
    })?;

    if envelope.schema_version != context.crypto_schema_version {
        return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
            envelope.schema_version,
        ));
    }
    if envelope.encryption_epoch != context.encryption_epoch {
        return Err(PayloadEncryptionError::EncryptionEpochMismatch);
    }
    if let Some(expected_kind) = context.expected_kind
        && envelope.kind != expected_kind
    {
        return Err(PayloadEncryptionError::UnsupportedEnvelopeKind(
            bounded_untrusted_text(&envelope.kind),
        ));
    }
    if envelope.envelope.ciphertext.len() > SERVER_PAYLOAD_CIPHERTEXT_MAX_B64_LEN {
        return Err(PayloadEncryptionError::ServerCiphertextTooLarge(
            context.field_path.to_string(),
        ));
    }
    validate_encrypted_envelope_metadata(&envelope.envelope)?;
    if let Some(key_id) = context.key_id
        && envelope.envelope.key_id != key_id
    {
        return Err(PayloadEncryptionError::Crypto(EncryptionError::KeyMismatch));
    }

    Ok(())
}

fn server_payload_verified_envelope_key(
    value: &Value,
    collection_id: &str,
    point_id: &str,
    context: ServerPayloadValidationContext<'_>,
) -> Result<ServerPayloadVerifiedEnvelopeKey, PayloadEncryptionError> {
    validate_server_payload_value_metadata(value, context)?;
    let envelope_key =
        server_payload_envelope_key(value, collection_id, point_id, context.field_path)?
            .ok_or_else(|| PayloadEncryptionError::ExpectedEncryptedEnvelope {
                field: context.field_path.to_string(),
                found: json_type_name(value),
            })?;

    Ok(ServerPayloadVerifiedEnvelopeKey { envelope_key })
}

/// Validate a server-side envelope after an ingress runtime plan already
/// encrypted it and passed a matching verified-envelope proof onward.
pub fn validate_server_payload_value_after_runtime_encryption(
    value: &Value,
    collection_id: &str,
    point_id: &str,
    context: ServerPayloadValidationContext<'_>,
    verified_envelope_key: &ServerPayloadVerifiedEnvelopeKey,
) -> Result<(), PayloadEncryptionError> {
    validate_server_payload_value_metadata(value, context)?;
    let envelope_key =
        server_payload_envelope_key(value, collection_id, point_id, context.field_path)?
            .ok_or_else(|| PayloadEncryptionError::ExpectedEncryptedEnvelope {
                field: context.field_path.to_string(),
                found: json_type_name(value),
            })?;
    if verified_envelope_key.envelope_key() != &envelope_key {
        return Err(PayloadEncryptionError::RuntimeEnvelopeProofMismatch);
    }
    Ok(())
}

pub fn validate_client_payload_value(
    value: &Value,
    context: ClientPayloadValidationContext<'_>,
) -> Result<(), PayloadEncryptionError> {
    if context.signature_required && context.signature_verification.is_none() {
        return Err(PayloadEncryptionError::InvalidClientSignature);
    }
    validate_client_payload_value_inner(value, context).map(|_| ())
}

/// Validate a client envelope after an ingress runtime plan already verified its
/// cryptographic signature and passed a matching verified-envelope proof onward.
pub fn validate_client_payload_value_after_runtime_verification(
    value: &Value,
    context: ClientPayloadValidationContext<'_>,
    verified_envelope_key: &ClientPayloadVerifiedEnvelopeKey,
) -> Result<(), PayloadEncryptionError> {
    let validated = validate_client_payload_value_inner(value, context)?;
    // The proof was minted from a verified signature; an equal key below therefore proves that
    // this envelope carries exactly those signature bytes, so no re-verification is needed.
    let envelope_key =
        client_payload_envelope_key_from_validated(validated, false).ok_or_else(|| {
            PayloadEncryptionError::ExpectedEncryptedEnvelope {
                field: context.field_path.to_string(),
                found: json_type_name(value),
            }
        })?;
    if verified_envelope_key.envelope_key() != &envelope_key {
        return Err(PayloadEncryptionError::RuntimeEnvelopeProofMismatch);
    }
    let blind_indexes = client_payload_blind_index_token_keys(value, context.field_path)?;
    if verified_envelope_key.blind_indexes != blind_indexes {
        return Err(PayloadEncryptionError::RuntimeEnvelopeProofMismatch);
    }
    Ok(())
}

fn validate_client_payload_value_inner(
    value: &Value,
    context: ClientPayloadValidationContext<'_>,
) -> Result<ValidatedClientPayloadEnvelope, PayloadEncryptionError> {
    let envelope = extract_client_envelope(value, context.field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: context.field_path.to_string(),
            found: json_type_name(value),
        }
    })?;

    if envelope.version != CRYPTO_SCHEMA_VERSION {
        return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
            envelope.version,
        ));
    }
    if envelope.kind != PAYLOAD_TEXT_ENVELOPE_KIND {
        return Err(PayloadEncryptionError::UnsupportedEnvelopeKind(
            bounded_untrusted_text(&envelope.kind),
        ));
    }
    if envelope.algorithm != CLIENT_PAYLOAD_ALGORITHM {
        return Err(PayloadEncryptionError::UnsupportedClientAlgorithm(
            bounded_untrusted_text(&envelope.algorithm),
        ));
    }
    if context.key_id_required && envelope.key_id.as_deref().is_none_or(str::is_empty) {
        return Err(PayloadEncryptionError::MissingClientKeyId);
    }
    if let Some(key_id) = envelope.key_id.as_deref() {
        validate_resource_key_id(key_id)?;
    }
    if let Some(expected_key_id) = context.expected_key_id
        && envelope.key_id.as_deref() != Some(expected_key_id)
    {
        return Err(PayloadEncryptionError::ClientKeyIdMismatch);
    }
    let rk_id = envelope
        .rk_id
        .as_deref()
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if rk_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    validate_resource_key_id(rk_id)?;
    if let Some(expected_rk_id) = context.expected_rk_id
        && rk_id != expected_rk_id
    {
        return Err(PayloadEncryptionError::ClientResourceKeyIdMismatch);
    }
    let rk_epoch = envelope
        .rk_epoch
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if context
        .min_rk_epoch
        .is_some_and(|min_rk_epoch| rk_epoch < min_rk_epoch)
        || context
            .max_rk_epoch
            .is_some_and(|max_rk_epoch| rk_epoch > max_rk_epoch)
    {
        return Err(PayloadEncryptionError::ClientResourceKeyEpochMismatch);
    }
    if envelope.kdf_domain.as_deref() != Some(CLIENT_PAYLOAD_KDF_DOMAIN) {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    if envelope.aad.collection_id != context.collection_id {
        return Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "collection_id".to_string(),
        ));
    }
    if envelope.aad.point_id != context.point_id {
        return Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "point_id".to_string(),
        ));
    }
    if envelope.aad.field_path != context.field_path {
        return Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "field_path".to_string(),
        ));
    }
    if envelope.aad.schema_version != CRYPTO_SCHEMA_VERSION {
        return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
            envelope.aad.schema_version,
        ));
    }
    validate_base64url_nopad_encoded_len(
        &envelope.nonce,
        BASE64URL_NOPAD_12_BYTE_LEN,
        PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()),
    )?;
    let nonce = BASE64URL_NOPAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if nonce.len() != 12 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    let ciphertext_sha256_b64 =
        client_payload_ciphertext_digest_b64(context.field_path, &envelope.ciphertext)?;
    validate_client_payload_blind_indexes(&envelope)?;
    let (signature_sha256_b64, signature_verified) = validate_client_payload_signature(
        &envelope,
        context.signature_required,
        context.signature_verification,
    )?;

    Ok(ValidatedClientPayloadEnvelope {
        envelope,
        ciphertext_sha256_b64,
        signature_sha256_b64,
        signature_verified,
    })
}

pub fn validate_client_payload_value_for_runtime(
    value: &Value,
    context: ClientPayloadValidationContext<'_>,
) -> Result<ClientPayloadVerifiedEnvelopeKey, PayloadEncryptionError> {
    if context.signature_verification.is_none() {
        return Err(PayloadEncryptionError::InvalidClientSignature);
    }
    let validated = validate_client_payload_value_inner(value, context)?;
    let envelope_key =
        client_payload_envelope_key_from_validated(validated, true).ok_or_else(|| {
            PayloadEncryptionError::ExpectedEncryptedEnvelope {
                field: context.field_path.to_string(),
                found: json_type_name(value),
            }
        })?;
    let blind_indexes = client_payload_blind_index_token_keys(value, context.field_path)?;

    Ok(ClientPayloadVerifiedEnvelopeKey {
        envelope_key,
        blind_indexes,
    })
}

/// Validate a server-side encrypted payload marker replayed by a peer.
///
/// Runtime encryption already authenticated the ciphertext on the origin node.
/// Target peers can still validate all metadata that is available in the
/// forwarded operation and reject plaintext or malformed markers before WAL or
/// segment write.
pub fn validate_server_payload_value_for_peer_replay(
    value: &Value,
    collection_id: &str,
    point_id: &str,
    context: ServerPayloadValidationContext<'_>,
) -> Result<(), PayloadEncryptionError> {
    validate_server_payload_value_metadata(value, context)?;
    server_payload_envelope_key(value, collection_id, point_id, context.field_path)?.ok_or_else(
        || PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: context.field_path.to_string(),
            found: json_type_name(value),
        },
    )?;
    Ok(())
}

pub fn client_payload_envelope_key(
    value: &Value,
    field_path: &str,
) -> Result<Option<ClientPayloadEnvelopeKey>, PayloadEncryptionError> {
    let Some(envelope) = extract_client_envelope(value, field_path)? else {
        return Ok(None);
    };
    let Some(key_id) = envelope.key_id else {
        return Ok(None);
    };
    let Some(rk_id) = envelope.rk_id else {
        return Ok(None);
    };
    let Some(rk_epoch) = envelope.rk_epoch else {
        return Ok(None);
    };
    let Some(signature) = envelope.signature else {
        return Ok(None);
    };
    validate_base64url_nopad_encoded_len(
        &envelope.nonce,
        BASE64URL_NOPAD_12_BYTE_LEN,
        PayloadEncryptionError::MalformedEnvelope(field_path.to_string()),
    )?;
    let ciphertext_sha256_b64 =
        client_payload_ciphertext_digest_b64(field_path, &envelope.ciphertext)?;
    validate_base64url_nopad_encoded_len(
        &signature.sig,
        BASE64URL_NOPAD_64_BYTE_LEN,
        PayloadEncryptionError::MalformedEnvelope(field_path.to_string()),
    )?;
    let signature_sha256_b64 = client_payload_signature_digest_b64(field_path, &signature.sig)?;

    Ok(Some(ClientPayloadEnvelopeKey {
        collection_id: envelope.aad.collection_id,
        point_id: envelope.aad.point_id,
        field_path: envelope.aad.field_path,
        key_id,
        rk_id,
        rk_epoch,
        nonce: envelope.nonce,
        ciphertext_sha256_b64,
        signature_key_id: signature.key_id,
        signature_sha256_b64,
    }))
}

/// Builds the envelope key of a validated envelope.
///
/// With `require_verified_signature` the key is only produced when the signature was verified
/// during validation, which is what a freshly minted verified-envelope proof must guarantee.
/// Without it the key carries the digest of the present signature, which is enough to compare
/// against an existing proof: equal digests mean the same signature bytes that were verified.
fn client_payload_envelope_key_from_validated(
    validated: ValidatedClientPayloadEnvelope,
    require_verified_signature: bool,
) -> Option<ClientPayloadEnvelopeKey> {
    if require_verified_signature && !validated.signature_verified {
        return None;
    }
    let key_id = validated.envelope.key_id?;
    let rk_id = validated.envelope.rk_id?;
    let rk_epoch = validated.envelope.rk_epoch?;
    let signature = validated.envelope.signature?;
    let signature_sha256_b64 = validated.signature_sha256_b64?;

    Some(ClientPayloadEnvelopeKey {
        collection_id: validated.envelope.aad.collection_id,
        point_id: validated.envelope.aad.point_id,
        field_path: validated.envelope.aad.field_path,
        key_id,
        rk_id,
        rk_epoch,
        nonce: validated.envelope.nonce,
        ciphertext_sha256_b64: validated.ciphertext_sha256_b64,
        signature_key_id: signature.key_id,
        signature_sha256_b64,
    })
}

fn client_payload_blind_index_token_keys(
    value: &Value,
    field_path: &str,
) -> Result<Vec<ClientPayloadBlindIndexTokenKey>, PayloadEncryptionError> {
    let Some(envelope) = extract_client_envelope(value, field_path)? else {
        return Ok(Vec::new());
    };
    validate_client_payload_blind_indexes(&envelope)?;
    Ok(envelope
        .blind_indexes
        .into_iter()
        .map(|binding| ClientPayloadBlindIndexTokenKey {
            field_path: binding.field_path,
            token: binding.token,
        })
        .collect())
}

fn validate_client_payload_blind_indexes(
    envelope: &ClientPayloadEnvelope,
) -> Result<(), PayloadEncryptionError> {
    let mut seen = std::collections::HashSet::new();
    for binding in &envelope.blind_indexes {
        if binding.field_path.is_empty() || !seen.insert(binding.field_path.clone()) {
            return Err(PayloadEncryptionError::MalformedEnvelope(
                envelope.aad.field_path.clone(),
            ));
        }
        validate_base64url_nopad_encoded_len(
            &binding.token,
            BASE64URL_NOPAD_32_BYTE_LEN,
            PayloadEncryptionError::MalformedEnvelope(envelope.aad.field_path.clone()),
        )?;
        let token = BASE64URL_NOPAD
            .decode(binding.token.as_bytes())
            .map_err(|_| {
                PayloadEncryptionError::MalformedEnvelope(envelope.aad.field_path.clone())
            })?;
        if token.len() != 32 {
            return Err(PayloadEncryptionError::MalformedEnvelope(
                envelope.aad.field_path.clone(),
            ));
        }
    }
    Ok(())
}

fn client_payload_ciphertext_digest_b64(
    field_path: &str,
    ciphertext_b64: &str,
) -> Result<String, PayloadEncryptionError> {
    if ciphertext_b64.len() > CLIENT_PAYLOAD_CIPHERTEXT_MAX_B64_LEN {
        return Err(PayloadEncryptionError::ClientCiphertextTooLarge(
            field_path.to_string(),
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    if ciphertext.len() < 16 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            field_path.to_string(),
        ));
    }
    if ciphertext.len() > CLIENT_PAYLOAD_CIPHERTEXT_MAX_BYTES {
        return Err(PayloadEncryptionError::ClientCiphertextTooLarge(
            field_path.to_string(),
        ));
    }
    let ciphertext_digest = Sha256::digest(&ciphertext);
    Ok(BASE64URL_NOPAD.encode(ciphertext_digest.as_ref()))
}

fn client_payload_signature_digest_b64(
    field_path: &str,
    signature_b64: &str,
) -> Result<String, PayloadEncryptionError> {
    validate_base64url_nopad_encoded_len(
        signature_b64,
        BASE64URL_NOPAD_64_BYTE_LEN,
        PayloadEncryptionError::MalformedEnvelope(field_path.to_string()),
    )?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature_b64.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    let signature_digest = Sha256::digest(&signature_bytes);
    Ok(BASE64URL_NOPAD.encode(signature_digest.as_ref()))
}

pub fn server_payload_envelope_key(
    value: &Value,
    collection_id: &str,
    point_id: &str,
    field_path: &str,
) -> Result<Option<ServerPayloadEnvelopeKey>, PayloadEncryptionError> {
    let Some(envelope) = extract_envelope(value, field_path)? else {
        return Ok(None);
    };
    // The 1 MiB server cap comes first: the generic metadata validator decodes up to the 16 MiB
    // envelope bound, which would let an oversized marker cost sixteen times its rejection.
    if envelope.envelope.ciphertext.len() > SERVER_PAYLOAD_CIPHERTEXT_MAX_B64_LEN {
        return Err(PayloadEncryptionError::ServerCiphertextTooLarge(
            field_path.to_string(),
        ));
    }
    validate_encrypted_envelope_metadata(&envelope.envelope)?;
    let ciphertext = BASE64URL_NOPAD
        .decode(envelope.envelope.ciphertext.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    if ciphertext.len() > SERVER_PAYLOAD_CIPHERTEXT_MAX_BYTES {
        return Err(PayloadEncryptionError::ServerCiphertextTooLarge(
            field_path.to_string(),
        ));
    }
    let ciphertext_digest = Sha256::digest(&ciphertext);
    let ciphertext_sha256_b64 = BASE64URL_NOPAD.encode(ciphertext_digest.as_ref());

    Ok(Some(ServerPayloadEnvelopeKey {
        collection_id: collection_id.to_string(),
        point_id: point_id.to_string(),
        field_path: field_path.to_string(),
        key_id: envelope.envelope.key_id,
        material_fingerprint: envelope.envelope.material_fingerprint,
        rk_id: envelope.envelope.rk_id,
        rk_epoch: envelope.envelope.rk_epoch,
        schema_version: envelope.schema_version,
        encryption_epoch: envelope.encryption_epoch,
        nonce: envelope.envelope.nonce,
        ciphertext_sha256_b64,
    }))
}

pub fn client_payload_signature_message(
    value: &Value,
    field_path: &str,
) -> Result<Vec<u8>, PayloadEncryptionError> {
    let envelope = extract_client_envelope(value, field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: field_path.to_string(),
            found: json_type_name(value),
        }
    })?;
    if envelope.signature.is_none() {
        return Err(PayloadEncryptionError::MissingClientSignature);
    }
    Ok(client_payload_signature_message_for_envelope(&envelope))
}

pub fn client_payload_signature_key_id(
    value: &Value,
    field_path: &str,
) -> Result<Option<String>, PayloadEncryptionError> {
    let envelope = extract_client_envelope(value, field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: field_path.to_string(),
            found: json_type_name(value),
        }
    })?;
    let Some(signature) = envelope.signature else {
        return Ok(None);
    };
    if signature.key_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            envelope.aad.field_path,
        ));
    }
    validate_resource_key_id(&signature.key_id)?;

    Ok(Some(signature.key_id))
}

pub fn client_payload_nonce_replay_key(
    value: &Value,
    field_path: &str,
) -> Result<Option<ClientPayloadNonceReplayKey>, PayloadEncryptionError> {
    let Some(envelope) = extract_client_envelope(value, field_path)? else {
        return Ok(None);
    };
    let key_id = envelope
        .key_id
        .ok_or(PayloadEncryptionError::MissingClientKeyId)?;
    if key_id.is_empty() {
        return Err(PayloadEncryptionError::MissingClientKeyId);
    }
    validate_resource_key_id(&key_id)?;
    let rk_id = envelope
        .rk_id
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    if rk_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            field_path.to_string(),
        ));
    }
    validate_resource_key_id(&rk_id)?;
    let rk_epoch = envelope
        .rk_epoch
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    validate_base64url_nopad_encoded_len(
        &envelope.nonce,
        BASE64URL_NOPAD_12_BYTE_LEN,
        PayloadEncryptionError::MalformedEnvelope(field_path.to_string()),
    )?;
    let nonce = BASE64URL_NOPAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    if nonce.len() != 12 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            field_path.to_string(),
        ));
    }

    Ok(Some(ClientPayloadNonceReplayKey {
        key_id,
        rk_id,
        rk_epoch,
        nonce: envelope.nonce,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPayloadEnvelope {
    kind: String,
    #[serde(default = "default_crypto_schema_version")]
    schema_version: u16,
    #[serde(default)]
    encryption_epoch: u64,
    envelope: EncryptedEnvelope,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientPayloadEnvelope {
    version: u16,
    kind: String,
    algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rk_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_domain: Option<String>,
    aad: ClientPayloadAad,
    nonce: String,
    ciphertext: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blind_indexes: Vec<ClientPayloadBlindIndexBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<ClientPayloadSignature>,
}

impl Debug for ClientPayloadEnvelope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadEnvelope")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field(
                "kdf_domain",
                &self.kdf_domain.as_ref().map(|_| "[redacted]"),
            )
            .field("aad", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("blind_index_count", &self.blind_indexes.len())
            .field("signature_present", &self.signature.is_some())
            .finish()
    }
}

struct ValidatedClientPayloadEnvelope {
    envelope: ClientPayloadEnvelope,
    ciphertext_sha256_b64: String,
    /// Digest of the well-formed signature carried by the envelope, if any.
    signature_sha256_b64: Option<String>,
    /// Whether that signature was verified against the expected key during this validation.
    signature_verified: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientPayloadAad {
    collection_id: String,
    point_id: String,
    field_path: String,
    #[serde(default = "default_crypto_schema_version")]
    schema_version: u16,
}

impl Debug for ClientPayloadAad {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadAad")
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("field_path", &"[redacted]")
            .field("schema_version", &self.schema_version)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientPayloadBlindIndexBinding {
    field_path: String,
    token: String,
}

impl Debug for ClientPayloadBlindIndexBinding {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadBlindIndexBinding")
            .field("field_path", &"[redacted]")
            .field("token", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientPayloadSignature {
    alg: String,
    key_id: String,
    sig: String,
}

impl Debug for ClientPayloadSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientPayloadSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .field("sig_len", &self.sig.len())
            .finish()
    }
}

/// Checks the envelope signature and returns its digest together with whether it was verified.
///
/// Callers that mint a verified-envelope proof must require the flag; callers that compare an
/// envelope against an existing proof only need the digest, since an equal digest means the
/// very signature bytes that were verified earlier.
fn validate_client_payload_signature(
    envelope: &ClientPayloadEnvelope,
    signature_required: bool,
    signature_verification: Option<ClientPayloadSignatureVerification<'_>>,
) -> Result<(Option<String>, bool), PayloadEncryptionError> {
    let Some(signature) = &envelope.signature else {
        return if signature_required || signature_verification.is_some() {
            Err(PayloadEncryptionError::MissingClientSignature)
        } else {
            Ok((None, false))
        };
    };

    if signature.alg != CLIENT_PAYLOAD_SIGNATURE_ALGORITHM {
        return Err(PayloadEncryptionError::UnsupportedClientSignatureAlgorithm(
            bounded_untrusted_text(&signature.alg),
        ));
    }
    if signature.key_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            envelope.aad.field_path.clone(),
        ));
    }
    validate_resource_key_id(&signature.key_id)?;
    let signature_sha256_b64 =
        client_payload_signature_digest_b64(&envelope.aad.field_path, &signature.sig)?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(envelope.aad.field_path.clone()))?;
    if signature_bytes.len() != 64 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            envelope.aad.field_path.clone(),
        ));
    }

    // A well-formed signature that nothing here can verify is tolerated when signatures are
    // optional; its digest is reported but flagged unverified, so a verified-envelope proof
    // can never be minted from it.
    let Some(verification) = signature_verification else {
        return Ok((Some(signature_sha256_b64), false));
    };
    if signature.key_id != verification.expected_key_id {
        return Err(PayloadEncryptionError::ClientSignatureKeyIdMismatch);
    }
    if verification.public_key.len() != 32 {
        return Err(PayloadEncryptionError::InvalidClientSignature);
    }
    let message = client_payload_signature_message_for_envelope(envelope);
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PayloadEncryptionError::InvalidClientSignature)?;

    Ok((Some(signature_sha256_b64), true))
}

fn client_payload_signature_message_for_envelope(envelope: &ClientPayloadEnvelope) -> Vec<u8> {
    let mut message = Vec::new();
    push_len_prefixed(&mut message, CLIENT_PAYLOAD_SIGNATURE_DOMAIN.as_bytes());
    push_u16(&mut message, envelope.version);
    push_len_prefixed(&mut message, envelope.kind.as_bytes());
    push_len_prefixed(&mut message, envelope.algorithm.as_bytes());
    push_optional_string(&mut message, envelope.key_id.as_deref());
    push_optional_string(&mut message, envelope.rk_id.as_deref());
    push_optional_u64(&mut message, envelope.rk_epoch);
    push_optional_string(&mut message, envelope.kdf_domain.as_deref());
    push_len_prefixed(&mut message, envelope.aad.collection_id.as_bytes());
    push_len_prefixed(&mut message, envelope.aad.point_id.as_bytes());
    push_len_prefixed(&mut message, envelope.aad.field_path.as_bytes());
    push_u16(&mut message, envelope.aad.schema_version);
    let mut blind_indexes = envelope.blind_indexes.iter().collect::<Vec<_>>();
    blind_indexes.sort_by(|left, right| {
        left.field_path
            .cmp(&right.field_path)
            .then_with(|| left.token.cmp(&right.token))
    });
    message.extend_from_slice(&(blind_indexes.len() as u32).to_be_bytes());
    for binding in blind_indexes {
        push_len_prefixed(&mut message, binding.field_path.as_bytes());
        push_len_prefixed(&mut message, binding.token.as_bytes());
    }
    push_len_prefixed(&mut message, envelope.nonce.as_bytes());
    push_len_prefixed(&mut message, envelope.ciphertext.as_bytes());
    if let Some(signature) = &envelope.signature {
        push_len_prefixed(&mut message, signature.alg.as_bytes());
        push_len_prefixed(&mut message, signature.key_id.as_bytes());
    } else {
        push_len_prefixed(&mut message, &[]);
        push_len_prefixed(&mut message, &[]);
    }
    message
}

fn push_len_prefixed(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u32).to_be_bytes());
    message.extend_from_slice(value);
}

fn push_optional_string(message: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            message.push(1);
            push_len_prefixed(message, value.as_bytes());
        }
        None => message.push(0),
    }
}

fn push_optional_u64(message: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&value.to_be_bytes());
        }
        None => message.push(0),
    }
}

fn push_u16(message: &mut Vec<u8>, value: u16) {
    message.extend_from_slice(&value.to_be_bytes());
}

const fn default_crypto_schema_version() -> u16 {
    CRYPTO_SCHEMA_VERSION
}

fn locate_path_mut<'a>(
    payload: &'a mut Map<String, Value>,
    field_path: &str,
) -> Result<Option<&'a mut Value>, PayloadEncryptionError> {
    let mut parts = field_path.split('.');
    let first = parts
        .next()
        .ok_or_else(|| PayloadEncryptionError::InvalidFieldPath(field_path.to_string()))?;
    let Some(mut value) = payload.get_mut(first) else {
        return Ok(None);
    };

    for part in parts {
        match value {
            Value::Object(object) => {
                let Some(next) = object.get_mut(part) else {
                    return Ok(None);
                };
                value = next;
            }
            _ => {
                return Err(PayloadEncryptionError::ExpectedObjectParent(
                    field_path.to_string(),
                ));
            }
        }
    }

    Ok(Some(value))
}

fn stored_envelope_value(
    envelope: EncryptedEnvelope,
    field: &str,
    kind: &str,
    schema_version: u16,
    encryption_epoch: u64,
) -> Result<Value, PayloadEncryptionError> {
    let envelope = StoredPayloadEnvelope {
        kind: kind.to_string(),
        schema_version,
        encryption_epoch,
        envelope,
    };
    let value = serde_json::to_value(envelope)
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field.to_string()))?;
    Ok(Value::Object(Map::from_iter([(
        ENCRYPTED_PAYLOAD_MARKER.to_string(),
        value,
    )])))
}

fn payload_metadata_aad(kind: &str, schema_version: u16, encryption_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::new();
    let kind = kind.as_bytes();
    aad.extend_from_slice(&(kind.len() as u32).to_be_bytes());
    aad.extend_from_slice(kind);
    aad.extend_from_slice(&schema_version.to_be_bytes());
    aad.extend_from_slice(&encryption_epoch.to_be_bytes());
    aad
}

fn validate_base64url_nopad_encoded_len(
    encoded: &str,
    expected_len: usize,
    error: PayloadEncryptionError,
) -> Result<(), PayloadEncryptionError> {
    if encoded.len() != expected_len {
        return Err(error);
    }
    Ok(())
}

fn extract_envelope(
    value: &Value,
    field: &str,
) -> Result<Option<StoredPayloadEnvelope>, PayloadEncryptionError> {
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let Some(envelope) = object.get(ENCRYPTED_PAYLOAD_MARKER) else {
        return Ok(None);
    };
    if object.len() != 1 {
        return Err(PayloadEncryptionError::MalformedEnvelope(field.to_string()));
    }

    let envelope: StoredPayloadEnvelope = serde_json::from_value(envelope.clone())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field.to_string()))?;
    if envelope.kind != PAYLOAD_TEXT_ENVELOPE_KIND && envelope.kind != METADATA_VALUE_ENVELOPE_KIND
    {
        return Err(PayloadEncryptionError::UnsupportedEnvelopeKind(
            bounded_untrusted_text(&envelope.kind),
        ));
    }

    Ok(Some(envelope))
}

fn extract_client_envelope(
    value: &Value,
    field: &str,
) -> Result<Option<ClientPayloadEnvelope>, PayloadEncryptionError> {
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let Some(envelope) = object.get(CLIENT_ENCRYPTED_PAYLOAD_MARKER) else {
        return Ok(None);
    };
    if object.len() != 1 {
        return Err(PayloadEncryptionError::MalformedEnvelope(field.to_string()));
    }

    let envelope: ClientPayloadEnvelope = serde_json::from_value(envelope.clone())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field.to_string()))?;

    Ok(Some(envelope))
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_payload_context() -> ClientPayloadValidationContext<'static> {
        ClientPayloadValidationContext {
            collection_id: "collection-crypto-id",
            point_id: "1",
            field_path: "document.body",
            expected_key_id: Some("tenant-a:client-rk"),
            expected_rk_id: Some("tenant-a:client-rk"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: false,
            signature_verification: None,
        }
    }

    fn valid_client_payload_value() -> Value {
        serde_json::json!({
            CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                "version": 1,
                "kind": PAYLOAD_TEXT_ENVELOPE_KIND,
                "algorithm": CLIENT_PAYLOAD_ALGORITHM,
                "key_id": "tenant-a:client-rk",
                "rk_id": "tenant-a:client-rk",
                "rk_epoch": 3,
                "kdf_domain": CLIENT_PAYLOAD_KDF_DOMAIN,
                "aad": {
                    "collection_id": "collection-crypto-id",
                    "point_id": "1",
                    "field_path": "document.body",
                    "schema_version": 1
                },
                "nonce": BASE64URL_NOPAD.encode(&[1_u8; 12]),
                "ciphertext": BASE64URL_NOPAD.encode(&[2_u8; 16]),
                "signature": {
                    "alg": CLIENT_PAYLOAD_SIGNATURE_ALGORITHM,
                    "key_id": "tenant-a:signing",
                    "sig": BASE64URL_NOPAD.encode(&[3_u8; 64])
                }
            }
        })
    }

    fn sign_client_payload_value(value: &mut Value) -> ring::signature::Ed25519KeyPair {
        use ring::signature::KeyPair as _;

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let envelope = extract_client_envelope(value, "document.body")
            .unwrap()
            .unwrap();
        let message = client_payload_signature_message_for_envelope(&envelope);
        let signature = key_pair.sign(&message);
        value[CLIENT_ENCRYPTED_PAYLOAD_MARKER]["signature"]["sig"] =
            Value::String(BASE64URL_NOPAD.encode(signature.as_ref()));
        assert_eq!(key_pair.public_key().as_ref().len(), 32);
        key_pair
    }

    #[test]
    fn unverifiable_client_signature_is_never_reported_as_verified() {
        use ring::signature::KeyPair as _;

        // Optional signatures without verification material: accepted, digest known, but
        // never flagged verified, so no runtime proof can be minted from them.
        let value = valid_client_payload_value();
        let validated =
            validate_client_payload_value_inner(&value, client_payload_context()).unwrap();
        assert!(!validated.signature_verified);
        assert!(client_payload_envelope_key_from_validated(validated, true).is_none());
        validate_client_payload_value(&value, client_payload_context()).unwrap();

        // Required signatures without verification material fail closed.
        let required = ClientPayloadValidationContext {
            signature_required: true,
            ..client_payload_context()
        };
        assert!(matches!(
            validate_client_payload_value(&value, required),
            Err(PayloadEncryptionError::InvalidClientSignature)
        ));

        // With verification material, only a signature under the expected key yields a digest.
        let mut signed = valid_client_payload_value();
        let key_pair = sign_client_payload_value(&mut signed);
        let verified = ClientPayloadValidationContext {
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a:signing",
                public_key: key_pair.public_key().as_ref(),
            }),
            ..client_payload_context()
        };
        let validated = validate_client_payload_value_inner(&signed, verified).unwrap();
        let digest = validated
            .signature_sha256_b64
            .expect("verified signature digest");
        let signature_b64 = signed[CLIENT_ENCRYPTED_PAYLOAD_MARKER]["signature"]["sig"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            digest,
            client_payload_signature_digest_b64("document.body", &signature_b64).unwrap()
        );
        let runtime_key = validate_client_payload_value_for_runtime(&signed, verified).unwrap();
        assert_eq!(
            runtime_key.envelope_key().signature_sha256_b64,
            digest,
            "runtime envelope keys carry the verified digest"
        );

        // The unsigned fixture signature does not verify under the real key.
        let unsigned = valid_client_payload_value();
        assert!(matches!(
            validate_client_payload_value_inner(&unsigned, verified),
            Err(PayloadEncryptionError::InvalidClientSignature)
        ));
        // Neither does a signature under a different key id.
        let other_key = ClientPayloadValidationContext {
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a:other-signing",
                public_key: key_pair.public_key().as_ref(),
            }),
            ..verified
        };
        assert!(matches!(
            validate_client_payload_value_inner(&signed, other_key),
            Err(PayloadEncryptionError::ClientSignatureKeyIdMismatch)
        ));
    }

    #[test]
    fn blind_index_binding_compares_tokens_exactly() {
        let mut value = valid_client_payload_value();
        value[CLIENT_ENCRYPTED_PAYLOAD_MARKER]["blind_indexes"] = serde_json::json!([
            {
                "field_path": "document.body",
                "token": BASE64URL_NOPAD.encode(&[8_u8; 32]),
            }
        ]);
        let envelope_key = client_payload_envelope_key(&value, "document.body")
            .unwrap()
            .unwrap();
        let blind_indexes = client_payload_blind_index_token_keys(&value, "document.body").unwrap();
        assert!(!blind_indexes.is_empty(), "fixture carries a blind index");
        let field_path = blind_indexes[0].field_path.clone();
        let token = blind_indexes[0].token.clone();
        let verified_key = ClientPayloadVerifiedEnvelopeKey {
            envelope_key,
            blind_indexes,
        };

        assert!(verified_key.binds_blind_index("collection-crypto-id", "1", &field_path, &token));
        let mut truncated = token.clone();
        truncated.pop();
        assert!(!verified_key.binds_blind_index(
            "collection-crypto-id",
            "1",
            &field_path,
            &truncated
        ));
        let mut flipped = token.clone().into_bytes();
        flipped[0] ^= 0x01;
        let flipped = String::from_utf8(flipped).unwrap();
        assert!(!verified_key.binds_blind_index(
            "collection-crypto-id",
            "1",
            &field_path,
            &flipped
        ));
        assert!(!verified_key.binds_blind_index("collection-crypto-id", "2", &field_path, &token));
        assert!(!verified_key.binds_blind_index("other-collection", "1", &field_path, &token));
        assert!(!verified_key.binds_blind_index(
            "collection-crypto-id",
            "1",
            "other.field",
            &token
        ));
    }

    fn server_envelope_kind(value: &Value) -> &str {
        value
            .get(ENCRYPTED_PAYLOAD_MARKER)
            .and_then(Value::as_object)
            .and_then(|envelope| envelope.get("kind"))
            .and_then(Value::as_str)
            .unwrap()
    }

    fn set_server_envelope_kind(value: &mut Value, kind: &str) {
        value
            .get_mut(ENCRYPTED_PAYLOAD_MARKER)
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("kind".to_string(), Value::String(kind.to_string()));
    }

    #[test]
    fn client_payload_debug_redacts_ciphertext_nonce_and_signature() {
        let policy = PayloadEncryptionPolicy::new(["CLIENT-PAYLOAD-POLICY-FIELD-SENTINEL"])
            .unwrap()
            .with_strict_missing_fields(true);
        let policy_debug = format!("{policy:?}");
        assert!(policy_debug.contains("field_count"));
        assert!(policy_debug.contains("strict_missing_fields"));
        assert!(!policy_debug.contains("CLIENT-PAYLOAD-POLICY-FIELD-SENTINEL"));

        let mut value = valid_client_payload_value();
        let marker = value
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .and_then(Value::as_object_mut)
            .unwrap();
        marker.insert(
            "key_id".to_string(),
            Value::String("CLIENT-PAYLOAD-KEY-SENTINEL".to_string()),
        );
        marker.insert(
            "rk_id".to_string(),
            Value::String("CLIENT-PAYLOAD-RK-SENTINEL".to_string()),
        );
        marker.insert(
            "kdf_domain".to_string(),
            Value::String("CLIENT-PAYLOAD-KDF-SENTINEL".to_string()),
        );
        marker.insert(
            "blind_indexes".to_string(),
            serde_json::json!([
                {
                    "field_path": "CLIENT-PAYLOAD-BLIND-FIELD-SENTINEL",
                    "token": BASE64URL_NOPAD.encode(&[8_u8; 32]),
                }
            ]),
        );
        let aad = marker
            .get_mut("aad")
            .and_then(Value::as_object_mut)
            .unwrap();
        aad.insert(
            "collection_id".to_string(),
            Value::String("CLIENT-PAYLOAD-COLLECTION-SENTINEL".to_string()),
        );
        aad.insert(
            "point_id".to_string(),
            Value::String("CLIENT-PAYLOAD-POINT-SENTINEL".to_string()),
        );
        aad.insert(
            "field_path".to_string(),
            Value::String("CLIENT-PAYLOAD-FIELD-SENTINEL".to_string()),
        );

        let envelope = extract_client_envelope(&value, "document.body")
            .unwrap()
            .unwrap();
        let debug = format!("{envelope:?}");

        assert!(debug.contains("ciphertext_len"));
        assert!(debug.contains("signature_present"));
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&[1_u8; 12])));
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&[2_u8; 16])));
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&[3_u8; 64])));
        assert!(!debug.contains("CLIENT-PAYLOAD-KEY-SENTINEL"));
        assert!(!debug.contains("CLIENT-PAYLOAD-RK-SENTINEL"));
        assert!(!debug.contains("CLIENT-PAYLOAD-KDF-SENTINEL"));
        assert!(!debug.contains("CLIENT-PAYLOAD-COLLECTION-SENTINEL"));
        assert!(!debug.contains("CLIENT-PAYLOAD-POINT-SENTINEL"));
        assert!(!debug.contains("CLIENT-PAYLOAD-FIELD-SENTINEL"));

        let aad_debug = format!("{:?}", envelope.aad);
        assert!(aad_debug.contains("schema_version"));
        assert!(!aad_debug.contains("CLIENT-PAYLOAD-COLLECTION-SENTINEL"));
        assert!(!aad_debug.contains("CLIENT-PAYLOAD-POINT-SENTINEL"));
        assert!(!aad_debug.contains("CLIENT-PAYLOAD-FIELD-SENTINEL"));

        let blind_index_debug = format!("{:?}", envelope.blind_indexes.first().unwrap());
        assert!(!blind_index_debug.contains("CLIENT-PAYLOAD-BLIND-FIELD-SENTINEL"));
        assert!(!blind_index_debug.contains(&BASE64URL_NOPAD.encode(&[8_u8; 32])));

        let signature_debug = format!("{:?}", envelope.signature.as_ref().unwrap());
        assert!(signature_debug.contains("sig_len"));
        assert!(!signature_debug.contains("tenant-a:signing"));
        assert!(!signature_debug.contains(&BASE64URL_NOPAD.encode(&[3_u8; 64])));

        let signature_verification = ClientPayloadSignatureVerification {
            expected_key_id: "CLIENT-PAYLOAD-VERIFY-KEY-SENTINEL",
            public_key: &[9_u8; 32],
        };
        let validation_context = ClientPayloadValidationContext {
            collection_id: "CLIENT-PAYLOAD-CONTEXT-COLLECTION-SENTINEL",
            point_id: "CLIENT-PAYLOAD-CONTEXT-POINT-SENTINEL",
            field_path: "CLIENT-PAYLOAD-CONTEXT-FIELD-SENTINEL",
            expected_key_id: Some("CLIENT-PAYLOAD-CONTEXT-KEY-SENTINEL"),
            expected_rk_id: Some("CLIENT-PAYLOAD-CONTEXT-RK-SENTINEL"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(signature_verification),
        };
        for rendered in [
            format!("{signature_verification:?}"),
            format!("{validation_context:?}"),
        ] {
            assert!(rendered.contains("[redacted]"));
            assert!(!rendered.contains("CLIENT-PAYLOAD-VERIFY-KEY-SENTINEL"));
            assert!(!rendered.contains("CLIENT-PAYLOAD-CONTEXT-COLLECTION-SENTINEL"));
            assert!(!rendered.contains("CLIENT-PAYLOAD-CONTEXT-POINT-SENTINEL"));
            assert!(!rendered.contains("CLIENT-PAYLOAD-CONTEXT-FIELD-SENTINEL"));
            assert!(!rendered.contains("CLIENT-PAYLOAD-CONTEXT-KEY-SENTINEL"));
            assert!(!rendered.contains("CLIENT-PAYLOAD-CONTEXT-RK-SENTINEL"));
        }

        let nonce_key = ClientPayloadNonceReplayKey {
            key_id: "CLIENT-PAYLOAD-NONCE-KEY-SENTINEL".to_string(),
            rk_id: "CLIENT-PAYLOAD-NONCE-RK-SENTINEL".to_string(),
            rk_epoch: 3,
            nonce: BASE64URL_NOPAD.encode(&[1_u8; 12]),
        };
        let nonce_key_debug = format!("{nonce_key:?}");
        assert!(!nonce_key_debug.contains("CLIENT-PAYLOAD-NONCE-KEY-SENTINEL"));
        assert!(!nonce_key_debug.contains("CLIENT-PAYLOAD-NONCE-RK-SENTINEL"));
        assert!(!nonce_key_debug.contains(&BASE64URL_NOPAD.encode(&[1_u8; 12])));

        let envelope_key = client_payload_envelope_key(&value, "document.body")
            .unwrap()
            .unwrap();
        let blind_indexes = client_payload_blind_index_token_keys(&value, "document.body").unwrap();
        let verified_key = ClientPayloadVerifiedEnvelopeKey {
            envelope_key,
            blind_indexes,
        };
        let verified_key_debug = format!("{verified_key:?}");
        assert!(verified_key_debug.contains("blind_index_count"));
        assert!(!verified_key_debug.contains("CLIENT-PAYLOAD-KEY-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-PAYLOAD-RK-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-PAYLOAD-COLLECTION-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-PAYLOAD-POINT-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-PAYLOAD-FIELD-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-PAYLOAD-BLIND-FIELD-SENTINEL"));
        assert!(!verified_key_debug.contains(&BASE64URL_NOPAD.encode(&[1_u8; 12])));
        assert!(!verified_key_debug.contains(&BASE64URL_NOPAD.encode(&[2_u8; 16])));
        assert!(!verified_key_debug.contains(&BASE64URL_NOPAD.encode(&[3_u8; 64])));
        assert!(!verified_key_debug.contains(&BASE64URL_NOPAD.encode(&[8_u8; 32])));
    }

    #[test]
    fn server_payload_provenance_debug_redacts_envelope_identifiers() {
        let envelope_key = ServerPayloadEnvelopeKey {
            collection_id: "SERVER-PAYLOAD-COLLECTION-SENTINEL".to_string(),
            point_id: "SERVER-PAYLOAD-POINT-SENTINEL".to_string(),
            field_path: "SERVER-PAYLOAD-FIELD-SENTINEL".to_string(),
            key_id: "SERVER-PAYLOAD-KEY-SENTINEL".to_string(),
            material_fingerprint: "SERVER-PAYLOAD-MATERIAL-FINGERPRINT-SENTINEL".to_string(),
            rk_id: "SERVER-PAYLOAD-RK-SENTINEL".to_string(),
            rk_epoch: Some(3),
            schema_version: 1,
            encryption_epoch: 7,
            nonce: "SERVER-PAYLOAD-NONCE-SENTINEL".to_string(),
            ciphertext_sha256_b64: "SERVER-PAYLOAD-CIPHERTEXT-SHA-SENTINEL".to_string(),
        };
        let verified_key = ServerPayloadVerifiedEnvelopeKey { envelope_key };
        let rendered = format!("{verified_key:?}");

        assert!(rendered.contains("schema_version"));
        assert!(rendered.contains("encryption_epoch"));
        assert!(!rendered.contains("SERVER-PAYLOAD-COLLECTION-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-POINT-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-FIELD-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-KEY-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-MATERIAL-FINGERPRINT-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-RK-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-NONCE-SENTINEL"));
        assert!(!rendered.contains("SERVER-PAYLOAD-CIPHERTEXT-SHA-SENTINEL"));

        let validation_context = ServerPayloadValidationContext {
            field_path: "SERVER-PAYLOAD-CONTEXT-FIELD-SENTINEL",
            expected_kind: Some("SERVER-PAYLOAD-CONTEXT-KIND-SENTINEL"),
            key_id: Some("SERVER-PAYLOAD-CONTEXT-KEY-SENTINEL"),
            crypto_schema_version: 1,
            encryption_epoch: 7,
        };
        let context_debug = format!("{validation_context:?}");
        assert!(context_debug.contains("crypto_schema_version"));
        assert!(context_debug.contains("encryption_epoch"));
        assert!(!context_debug.contains("SERVER-PAYLOAD-CONTEXT-FIELD-SENTINEL"));
        assert!(!context_debug.contains("SERVER-PAYLOAD-CONTEXT-KIND-SENTINEL"));
        assert!(!context_debug.contains("SERVER-PAYLOAD-CONTEXT-KEY-SENTINEL"));
    }

    #[test]
    fn metadata_value_envelope_uses_distinct_kind_and_aad_domain() {
        let resource_key = SecretKey::from_bytes([7_u8; 32]);
        let payload_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "collection-crypto-id",
            "tenant-a:docs",
            &resource_key,
            "tenant-a/payload@v1",
            "tenant-a/payload-rk",
            3,
        )
        .unwrap()
        .with_encryption_epoch(3);
        let metadata_encryptor =
            PayloadTextEncryptor::new_metadata_value_from_resource_key_with_metadata(
                "collection-crypto-id",
                "tenant-a:docs",
                &resource_key,
                "tenant-a/payload@v1",
                "tenant-a/payload-rk",
                3,
            )
            .unwrap()
            .with_encryption_epoch(3);
        let policy = PayloadEncryptionPolicy::new(["field"]).unwrap();

        let mut payload_value = serde_json::json!({ "field": "secret" })
            .as_object()
            .unwrap()
            .clone();
        let mut metadata_value = payload_value.clone();
        payload_encryptor
            .encrypt_selected_fields("1", &mut payload_value, &policy)
            .unwrap();
        metadata_encryptor
            .encrypt_selected_fields("1", &mut metadata_value, &policy)
            .unwrap();

        let payload_marker = payload_value.get("field").unwrap();
        let metadata_marker = metadata_value.get("field").unwrap();
        assert_eq!(
            server_envelope_kind(payload_marker),
            PAYLOAD_TEXT_ENVELOPE_KIND
        );
        assert_eq!(
            server_envelope_kind(metadata_marker),
            METADATA_VALUE_ENVELOPE_KIND,
        );

        assert!(matches!(
            payload_encryptor.decrypt_selected_fields("1", &mut metadata_value.clone(), &policy),
            Err(PayloadEncryptionError::UnsupportedEnvelopeKind(kind))
                if kind == METADATA_VALUE_ENVELOPE_KIND
        ));
        assert!(matches!(
            metadata_encryptor.decrypt_selected_fields("1", &mut payload_value.clone(), &policy),
            Err(PayloadEncryptionError::UnsupportedEnvelopeKind(kind))
                if kind == PAYLOAD_TEXT_ENVELOPE_KIND
        ));

        let mut tampered_metadata = metadata_marker.clone();
        set_server_envelope_kind(&mut tampered_metadata, PAYLOAD_TEXT_ENVELOPE_KIND);
        let mut tampered_payload = Map::from_iter([("field".to_string(), tampered_metadata)]);
        assert!(matches!(
            payload_encryptor.decrypt_selected_fields("1", &mut tampered_payload, &policy),
            Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed))
        ));
    }

    #[test]
    fn resource_key_constructor_does_not_use_raw_resource_key_as_payload_aead_key() {
        let resource_key = SecretKey::from_bytes([71_u8; 32]);
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let encryptor = PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
            "docs",
            "tenant-a:payload",
            &resource_key,
            "tenant-a/payload@v1",
        )
        .unwrap();
        let mut payload = serde_json::json!({ "body": "domain separated" })
            .as_object()
            .unwrap()
            .clone();

        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap();

        let raw_resource_key_encryptor = PayloadTextEncryptor::new_with_derived_cipher_unchecked(
            "docs",
            AeadCipher::new_with_material_fingerprint(
                "tenant-a:payload",
                resource_key,
                "tenant-a/payload@v1",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw_resource_key_encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
            Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
        );
    }

    #[test]
    fn server_payload_validation_rejects_wrong_envelope_kind() {
        let resource_key = SecretKey::from_bytes([8_u8; 32]);
        let metadata_encryptor =
            PayloadTextEncryptor::new_metadata_value_from_resource_key_with_metadata(
                "collection-crypto-id",
                "tenant-a:docs",
                &resource_key,
                "tenant-a/metadata@v1",
                "tenant-a/metadata-rk",
                3,
            )
            .unwrap()
            .with_encryption_epoch(3);
        let policy = PayloadEncryptionPolicy::new(["field"]).unwrap();
        let mut payload = serde_json::json!({ "field": "secret" })
            .as_object()
            .unwrap()
            .clone();
        metadata_encryptor
            .encrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();

        assert_eq!(
            validate_server_payload_value_metadata(
                payload.get("field").unwrap(),
                ServerPayloadValidationContext {
                    field_path: "field",
                    expected_kind: Some(METADATA_VALUE_ENVELOPE_KIND),
                    key_id: Some("tenant-a:docs"),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                },
            ),
            Ok(())
        );
        assert!(matches!(
            validate_server_payload_value_metadata(
                payload.get("field").unwrap(),
                ServerPayloadValidationContext {
                    field_path: "field",
                    expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
                    key_id: Some("tenant-a:docs"),
                    crypto_schema_version: 1,
                    encryption_epoch: 3,
                },
            ),
            Err(PayloadEncryptionError::UnsupportedEnvelopeKind(kind))
                if kind == METADATA_VALUE_ENVELOPE_KIND
        ));
    }

    #[test]
    fn client_payload_rejects_oversized_fixed_base64_fields_before_decode() {
        let mut nonce_value = valid_client_payload_value();
        nonce_value
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("nonce".to_string(), Value::String("A".repeat(1024)));
        assert!(matches!(
            validate_client_payload_value(&nonce_value, client_payload_context()),
            Err(PayloadEncryptionError::MalformedEnvelope(field)) if field == "document.body",
        ));
        assert!(matches!(
            client_payload_nonce_replay_key(&nonce_value, "document.body"),
            Err(PayloadEncryptionError::MalformedEnvelope(field)) if field == "document.body",
        ));

        let mut signature_value = valid_client_payload_value();
        signature_value
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .and_then(Value::as_object_mut)
            .and_then(|envelope| envelope.get_mut("signature"))
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("sig".to_string(), Value::String("A".repeat(1024)));
        assert!(matches!(
            validate_client_payload_value(&signature_value, client_payload_context()),
            Err(PayloadEncryptionError::MalformedEnvelope(field)) if field == "document.body",
        ));
        assert!(matches!(
            client_payload_envelope_key(&signature_value, "document.body"),
            Err(PayloadEncryptionError::MalformedEnvelope(field)) if field == "document.body",
        ));

        let mut ciphertext_value = valid_client_payload_value();
        ciphertext_value
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(
                "ciphertext".to_string(),
                Value::String("A".repeat(CLIENT_PAYLOAD_CIPHERTEXT_MAX_B64_LEN + 1)),
            );
        assert!(matches!(
            validate_client_payload_value(&ciphertext_value, client_payload_context()),
            Err(PayloadEncryptionError::ClientCiphertextTooLarge(field)) if field == "document.body",
        ));
        assert!(matches!(
            client_payload_envelope_key(&ciphertext_value, "document.body"),
            Err(PayloadEncryptionError::ClientCiphertextTooLarge(field)) if field == "document.body",
        ));
    }

    #[test]
    fn server_payload_envelope_key_rejects_oversized_ciphertext_before_decode() {
        let value = serde_json::json!({
            ENCRYPTED_PAYLOAD_MARKER: {
                "kind": PAYLOAD_TEXT_ENVELOPE_KIND,
                "schema_version": 1,
                "encryption_epoch": 0,
                "envelope": {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a:docs",
                    "material_fingerprint": "tenant-a/docs@v1",
                    "rk_id": "tenant-a/docs-rk-v1",
                    "rk_epoch": 0,
                    "nonce": BASE64URL_NOPAD.encode(&[1_u8; 12]),
                    "ciphertext": "A".repeat(SERVER_PAYLOAD_CIPHERTEXT_MAX_B64_LEN + 1),
                },
            },
        });

        assert!(matches!(
            server_payload_envelope_key(&value, "collection-crypto-id", "1", "document.body"),
            Err(PayloadEncryptionError::ServerCiphertextTooLarge(field)) if field == "document.body",
        ));
        assert!(matches!(
            validate_server_payload_value_for_peer_replay(
                &value,
                "collection-crypto-id",
                "1",
                ServerPayloadValidationContext {
                    field_path: "document.body",
                    expected_kind: Some(PAYLOAD_TEXT_ENVELOPE_KIND),
                    key_id: Some("tenant-a:docs"),
                    crypto_schema_version: 1,
                    encryption_epoch: 0,
                },
            ),
            Err(PayloadEncryptionError::ServerCiphertextTooLarge(field)) if field == "document.body",
        ));
    }
}
