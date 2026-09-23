use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 1;
const ALGORITHM: &str = "AES-256-GCM";
pub const RESOURCE_KEY_WRAP_ALGORITHM: &str = "AES-256-GCM";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_KEY_ID_LEN: usize = 128;
const HKDF_SALT: &[u8] = b"qdrant-sec-aead-master-key-v1";
const HKDF_CONTEXT_INFO_DOMAIN: &[u8] = b"qdrant-sec/hkdf-context-info/v1";
const BASE64URL_NOPAD_12_BYTE_LEN: usize = 16;
const ENCRYPTED_ENVELOPE_CIPHERTEXT_MAX_BYTES: usize = 16 * 1024 * 1024;
const ENCRYPTED_ENVELOPE_CIPHERTEXT_MAX_B64_LEN: usize =
    base64url_nopad_encoded_len(ENCRYPTED_ENVELOPE_CIPHERTEXT_MAX_BYTES);
pub const LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_LEN: usize = KEY_LEN + TAG_LEN;
pub const LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_B64_LEN: usize = 64;

pub const PAYLOAD_TEXT_KEY_DOMAIN: &[u8] = b"qdrant-sec/payload-text/v1";
pub const METADATA_VALUE_KEY_DOMAIN: &[u8] = b"qdrant-sec/metadata-value/v1";
pub const CKKS_VECTOR_KEY_DOMAIN: &[u8] = b"qdrant-sec/vector-envelope/v1";

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
pub enum EncryptionError {
    #[error("encryption key must be exactly 32 bytes")]
    InvalidKeyLength,
    #[error("key id must be 1..=128 ASCII characters from [A-Za-z0-9._:-]")]
    InvalidKeyId,
    #[error("material fingerprint id must be 1..=128 ASCII characters from [A-Za-z0-9._:/@-]")]
    InvalidMaterialFingerprintId,
    #[error("resource key id must be 1..=128 ASCII characters from [A-Za-z0-9._:/@-]")]
    InvalidResourceKeyId,
    #[error("failed to obtain cryptographically secure random bytes")]
    RandomFailure,
    #[error("failed to derive encryption subkey")]
    KeyDerivationFailed,
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported envelope algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("envelope key id does not match the active key")]
    KeyMismatch,
    #[error("envelope material fingerprint does not match the active key")]
    MaterialFingerprintMismatch,
    #[error("envelope field is not valid base64url without padding")]
    InvalidEncoding,
    #[error("nonce must decode to 96 bits")]
    InvalidNonceLength,
    #[error("ciphertext is shorter than the authentication tag")]
    InvalidCiphertextLength,
    #[error("encryption failed")]
    SealFailed,
    #[error("decryption authentication failed")]
    OpenFailed,
    #[error("wrapped resource key master key id does not match")]
    MasterKeyMismatch,
    #[error(
        "encryption key reached its AES-GCM random-nonce invocation budget; rotate the resource key"
    )]
    KeyUsageExhausted,
}

impl Debug for EncryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength => f.write_str("InvalidKeyLength"),
            Self::InvalidKeyId => f.write_str("InvalidKeyId"),
            Self::InvalidMaterialFingerprintId => f.write_str("InvalidMaterialFingerprintId"),
            Self::InvalidResourceKeyId => f.write_str("InvalidResourceKeyId"),
            Self::RandomFailure => f.write_str("RandomFailure"),
            Self::KeyDerivationFailed => f.write_str("KeyDerivationFailed"),
            Self::UnsupportedVersion(version) => {
                f.debug_tuple("UnsupportedVersion").field(version).finish()
            }
            Self::UnsupportedAlgorithm(_) => f
                .debug_tuple("UnsupportedAlgorithm")
                .field(&"[redacted]")
                .finish(),
            Self::KeyMismatch => f.write_str("KeyMismatch"),
            Self::MaterialFingerprintMismatch => f.write_str("MaterialFingerprintMismatch"),
            Self::InvalidEncoding => f.write_str("InvalidEncoding"),
            Self::InvalidNonceLength => f.write_str("InvalidNonceLength"),
            Self::InvalidCiphertextLength => f.write_str("InvalidCiphertextLength"),
            Self::SealFailed => f.write_str("SealFailed"),
            Self::OpenFailed => f.write_str("OpenFailed"),
            Self::MasterKeyMismatch => f.write_str("MasterKeyMismatch"),
            Self::KeyUsageExhausted => f.write_str("KeyUsageExhausted"),
        }
    }
}

pub struct SecretKey {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

struct SecretKeyLen;

impl hkdf::KeyType for SecretKeyLen {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

impl SecretKey {
    pub fn generate() -> Result<Self, EncryptionError> {
        let rng = SystemRandom::new();
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill(bytes.as_mut())
            .map_err(|_| EncryptionError::RandomFailure)?;
        Ok(Self { bytes })
    }

    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let key = Self {
            bytes: Zeroizing::new(bytes),
        };
        bytes.zeroize();
        key
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() != KEY_LEN {
            return Err(EncryptionError::InvalidKeyLength);
        }
        let mut owned = Zeroizing::new([0u8; KEY_LEN]);
        owned.copy_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    pub fn derive_subkey(&self, domain: &[u8]) -> Result<Self, EncryptionError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
        let prk = salt.extract(self.as_bytes());
        let info = [domain];
        let okm = prk
            .expand(&info, SecretKeyLen)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;
        // Fill the zeroizing buffer directly: an intermediate stack array would leave an
        // unscrubbed copy of the derived key behind when it is moved into the wrapper.
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        okm.fill(bytes.as_mut())
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;
        Ok(Self { bytes })
    }

    pub fn derive_subkey_with_context(
        &self,
        domain: &[u8],
        context_domain: &[u8],
        context_fields: &[&[u8]],
    ) -> Result<Self, EncryptionError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
        let prk = salt.extract(self.as_bytes());
        let mut info = Zeroizing::new(Vec::new());
        append_hkdf_info_field(&mut info, HKDF_CONTEXT_INFO_DOMAIN);
        append_hkdf_info_field(&mut info, domain);
        append_hkdf_info_field(&mut info, context_domain);
        for field in context_fields {
            append_hkdf_info_field(&mut info, field);
        }
        let info = [&info[..]];
        let okm = prk
            .expand(&info, SecretKeyLen)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;
        // Fill the zeroizing buffer directly: an intermediate stack array would leave an
        // unscrubbed copy of the derived key behind when it is moved into the wrapper.
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        okm.fill(bytes.as_mut())
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

fn append_hkdf_info_field(info: &mut Vec<u8>, field: &[u8]) {
    info.extend_from_slice(&(field.len() as u64).to_be_bytes());
    info.extend_from_slice(field);
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &"[redacted; 32 bytes]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionPurpose {
    PayloadText,
    MetadataValue,
    CkksVector,
}

impl EncryptionPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayloadText => "payload_text",
            Self::MetadataValue => "metadata_value",
            Self::CkksVector => "ckks_vector",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptionContext<'a> {
    pub purpose: EncryptionPurpose,
    pub collection: &'a str,
    pub point_id: Option<&'a str>,
    pub field_path: Option<&'a str>,
    pub vector_name: Option<&'a str>,
}

impl Debug for EncryptionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionContext")
            .field("purpose", &self.purpose)
            .field("collection", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("field_path", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .finish()
    }
}

impl<'a> EncryptionContext<'a> {
    pub const fn payload_text(collection: &'a str, point_id: &'a str, field_path: &'a str) -> Self {
        Self {
            purpose: EncryptionPurpose::PayloadText,
            collection,
            point_id: Some(point_id),
            field_path: Some(field_path),
            vector_name: None,
        }
    }

    pub const fn metadata_value(
        collection: &'a str,
        point_id: &'a str,
        field_path: &'a str,
    ) -> Self {
        Self {
            purpose: EncryptionPurpose::MetadataValue,
            collection,
            point_id: Some(point_id),
            field_path: Some(field_path),
            vector_name: None,
        }
    }

    pub const fn ckks_vector(collection: &'a str, point_id: &'a str, vector_name: &'a str) -> Self {
        Self {
            purpose: EncryptionPurpose::CkksVector,
            collection,
            point_id: Some(point_id),
            field_path: None,
            vector_name: Some(vector_name),
        }
    }

    fn aad_bytes_with_suffix(
        &self,
        envelope_header: &EnvelopeHeader<'_>,
        aad_suffix: &[u8],
    ) -> Vec<u8> {
        let aad_version = if envelope_header.rk_id.is_empty() && envelope_header.rk_epoch.is_none()
        {
            "v1"
        } else {
            "v2"
        };
        let values = [
            "qdrant-sec",
            aad_version,
            self.purpose.as_str(),
            self.collection,
            self.point_id.unwrap_or_default(),
            self.field_path.unwrap_or_default(),
            self.vector_name.unwrap_or_default(),
            envelope_header.algorithm,
            envelope_header.key_id,
            envelope_header.material_fingerprint,
            envelope_header.nonce,
        ];

        let mut aad = Vec::new();
        for value in values {
            let bytes = value.as_bytes();
            aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            aad.extend_from_slice(bytes);
        }
        if aad_version == "v2" {
            let rk_epoch = envelope_header
                .rk_epoch
                .map(|epoch| epoch.to_string())
                .unwrap_or_default();
            for value in [envelope_header.rk_id, rk_epoch.as_str()] {
                let bytes = value.as_bytes();
                aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                aad.extend_from_slice(bytes);
            }
        }
        aad.extend_from_slice(&envelope_header.version.to_be_bytes());
        aad.extend_from_slice(&(aad_suffix.len() as u32).to_be_bytes());
        aad.extend_from_slice(aad_suffix);
        aad
    }
}

struct EnvelopeHeader<'a> {
    version: u8,
    algorithm: &'a str,
    key_id: &'a str,
    material_fingerprint: &'a str,
    rk_id: &'a str,
    rk_epoch: Option<u64>,
    nonce: &'a str,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub material_fingerprint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rk_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rk_epoch: Option<u64>,
    pub nonce: String,
    pub ciphertext: String,
}

impl Debug for EncryptedEnvelope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedEnvelope")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("key_id", &"[redacted]")
            .field("material_fingerprint", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("nonce", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

pub(crate) fn validate_encrypted_envelope_metadata(
    envelope: &EncryptedEnvelope,
) -> Result<(), EncryptionError> {
    if envelope.version != VERSION {
        return Err(EncryptionError::UnsupportedVersion(envelope.version));
    }
    if envelope.algorithm != ALGORITHM {
        return Err(EncryptionError::UnsupportedAlgorithm(
            bounded_untrusted_text(&envelope.algorithm),
        ));
    }
    validate_key_id(&envelope.key_id)?;
    validate_material_fingerprint_id(&envelope.material_fingerprint)?;
    match (!envelope.rk_id.is_empty(), envelope.rk_epoch) {
        (true, Some(_)) => validate_resource_key_id(&envelope.rk_id)?,
        (true, None) | (false, Some(_)) => {
            return Err(EncryptionError::InvalidResourceKeyId);
        }
        (false, None) => {}
    }

    if envelope.nonce.len() != BASE64URL_NOPAD_12_BYTE_LEN {
        return Err(EncryptionError::InvalidNonceLength);
    }
    let nonce = BASE64URL_NOPAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| EncryptionError::InvalidEncoding)?;
    if nonce.len() != NONCE_LEN {
        return Err(EncryptionError::InvalidNonceLength);
    }

    if envelope.ciphertext.len() > ENCRYPTED_ENVELOPE_CIPHERTEXT_MAX_B64_LEN {
        return Err(EncryptionError::InvalidCiphertextLength);
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| EncryptionError::InvalidEncoding)?;
    if ciphertext.len() < TAG_LEN {
        return Err(EncryptionError::InvalidCiphertextLength);
    }
    if ciphertext.len() > ENCRYPTED_ENVELOPE_CIPHERTEXT_MAX_BYTES {
        return Err(EncryptionError::InvalidCiphertextLength);
    }

    Ok(())
}

/// Random 96-bit nonces stay collision-safe for at most 2^32 AES-GCM invocations per key
/// (NIST SP 800-38D, section 8.3). The budget is tracked per key for the lifetime of the process
/// (see [`shared_aead_invocation_budget`]); rotating the resource key starts a fresh budget.
pub const AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT: u64 = 1 << 32;
/// First invocation at which the cipher logs that the key is approaching its budget.
const AES_GCM_RANDOM_NONCE_INVOCATION_WARNING: u64 = AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT / 2;

/// Random-nonce AES-GCM invocation budget of one key.
///
/// [`AeadCipher`] embeds one; keys that are used through free-standing seal functions (the
/// private ORAM bucket and client-state keys) carry their own, so every AES-GCM key in the
/// process observes the same [`AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT`].
pub struct AeadInvocationBudget {
    invocations: AtomicU64,
}

impl AeadInvocationBudget {
    pub const fn new() -> Self {
        Self {
            invocations: AtomicU64::new(0),
        }
    }

    /// Number of invocations reserved so far.
    pub fn invocations(&self) -> u64 {
        self.invocations.load(Ordering::Relaxed)
    }

    /// Reserves one random-nonce invocation, refusing once the per-key budget is spent.
    /// `key_label` names the key in the warning logged when half of the budget is gone.
    pub fn reserve(&self, key_label: &str) -> Result<(), EncryptionError> {
        let previous = self
            .invocations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT).then(|| used + 1)
            })
            .map_err(|_| EncryptionError::KeyUsageExhausted)?;
        if previous + 1 == AES_GCM_RANDOM_NONCE_INVOCATION_WARNING {
            log::warn!(
                "{key_label} used for {previous} AES-GCM invocations in this process; it stops \
                 encrypting at {AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT}, rotate the resource key"
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_for_test(&self, invocations: u64) {
        self.invocations.store(invocations, Ordering::Release);
    }
}

impl Default for AeadInvocationBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for AeadInvocationBudget {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadInvocationBudget")
            .field("invocations", &self.invocations())
            .finish()
    }
}

/// Process-wide random-nonce budgets, one per distinct AES-GCM key.
///
/// The server write paths build a fresh [`AeadCipher`] for every request, so a budget stored in
/// the cipher instance would restart at zero on each request and never enforce the limit. Keys
/// are identified by a domain-separated SHA-256 of the key bytes; the map only ever holds one
/// counter per key the process has used.
static AEAD_INVOCATION_BUDGETS: OnceLock<Mutex<HashMap<[u8; 32], Arc<AeadInvocationBudget>>>> =
    OnceLock::new();
const AEAD_INVOCATION_BUDGET_KEY_DOMAIN: &[u8] = b"qdrant-sec/aead-invocation-budget/v1";

/// The process-wide random-nonce budget of `key`: every cipher built from the same key bytes
/// shares one counter.
pub(crate) fn shared_aead_invocation_budget(key: &SecretKey) -> Arc<AeadInvocationBudget> {
    let mut hasher = Sha256::new();
    hasher.update(AEAD_INVOCATION_BUDGET_KEY_DOMAIN);
    hasher.update(key.as_bytes());
    let key_identity: [u8; 32] = hasher.finalize().into();
    let mut budgets = AEAD_INVOCATION_BUDGETS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Arc::clone(budgets.entry(key_identity).or_default())
}

/// Bounded, printable rendering of an untrusted envelope field for error messages: at most 32
/// characters with control characters escaped, so a stored or submitted envelope cannot inject
/// unbounded or multi-line text into logs and error bodies.
pub(crate) fn bounded_untrusted_text(value: &str) -> String {
    const MAX_CHARS: usize = 32;
    let mut rendered: String = value
        .chars()
        .take(MAX_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if value.chars().count() > MAX_CHARS {
        rendered.push_str("...");
    }
    rendered
}

pub struct AeadCipher {
    key_id: String,
    material_fingerprint: String,
    rk_id: String,
    rk_epoch: Option<u64>,
    key: SecretKey,
    /// Random-nonce budget of `key`, shared with every other cipher built from the same key.
    invocations: Arc<AeadInvocationBudget>,
}

impl Drop for AeadCipher {
    fn drop(&mut self) {
        self.key_id.zeroize();
        self.material_fingerprint.zeroize();
        self.rk_id.zeroize();
    }
}

impl Debug for AeadCipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let rk_id = if self.rk_id.is_empty() {
            "<empty>"
        } else {
            "[redacted]"
        };
        f.debug_struct("AeadCipher")
            .field("key_id", &"[redacted]")
            .field("material_fingerprint", &"[redacted]")
            .field("rk_id", &rk_id)
            .field("rk_epoch", &self.rk_epoch)
            .field("key", &"[redacted; 32 bytes]")
            .finish()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct AeadCipherMetadataKey {
    key_id: String,
    material_fingerprint: String,
    rk_id: String,
    rk_epoch: Option<u64>,
}

impl Debug for AeadCipherMetadataKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadCipherMetadataKey")
            .field("key_id", &"[redacted]")
            .field("material_fingerprint", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .finish()
    }
}

impl Drop for AeadCipherMetadataKey {
    fn drop(&mut self) {
        self.key_id.zeroize();
        self.material_fingerprint.zeroize();
        self.rk_id.zeroize();
    }
}

impl AeadCipherMetadataKey {
    fn from_cipher(cipher: &AeadCipher) -> Self {
        Self {
            key_id: cipher.key_id.clone(),
            material_fingerprint: cipher.material_fingerprint.clone(),
            rk_id: cipher.rk_id.clone(),
            rk_epoch: cipher.rk_epoch,
        }
    }

    fn from_envelope(envelope: &EncryptedEnvelope) -> Self {
        Self {
            key_id: envelope.key_id.clone(),
            material_fingerprint: envelope.material_fingerprint.clone(),
            rk_id: envelope.rk_id.clone(),
            rk_epoch: envelope.rk_epoch,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKeyBlob {
    pub version: u8,
    pub algorithm: String,
    pub mk_id: String,
    pub nonce: String,
    pub wrapped_key: String,
}

impl Debug for WrappedKeyBlob {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedKeyBlob")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("mk_id", &"[redacted]")
            .field("nonce", &"[redacted]")
            .field("wrapped_key_len", &self.wrapped_key.len())
            .finish()
    }
}

pub trait MasterKeyProvider: Send + Sync {
    fn mk_id(&self) -> &str;

    fn wrap_resource_key(
        &self,
        rk_plaintext: &SecretKey,
        aad: &[u8],
    ) -> Result<WrappedKeyBlob, EncryptionError>;

    fn unwrap_resource_key(
        &self,
        wrapped: &WrappedKeyBlob,
        aad: &[u8],
    ) -> Result<SecretKey, EncryptionError>;
}

pub fn rewrap_resource_key(
    old_provider: &dyn MasterKeyProvider,
    new_provider: &dyn MasterKeyProvider,
    wrapped: &WrappedKeyBlob,
    old_aad: &[u8],
    new_aad: &[u8],
) -> Result<WrappedKeyBlob, EncryptionError> {
    let resource_key = old_provider.unwrap_resource_key(wrapped, old_aad)?;
    new_provider.wrap_resource_key(&resource_key, new_aad)
}

pub struct LocalMasterKeyProvider {
    mk_id: String,
    key: SecretKey,
    /// Random-nonce budget of the master key; wrapping is AES-GCM with a random nonce too.
    wraps: Arc<AeadInvocationBudget>,
}

impl Debug for LocalMasterKeyProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalMasterKeyProvider")
            .field("mk_id", &"[redacted]")
            .field("key", &"[redacted; 32 bytes]")
            .finish()
    }
}

impl LocalMasterKeyProvider {
    pub fn new(mk_id: impl Into<String>, key: SecretKey) -> Result<Self, EncryptionError> {
        let mk_id = mk_id.into();
        validate_material_fingerprint_id(&mk_id)?;
        let wraps = shared_aead_invocation_budget(&key);
        Ok(Self { mk_id, key, wraps })
    }
}

impl MasterKeyProvider for LocalMasterKeyProvider {
    fn mk_id(&self) -> &str {
        &self.mk_id
    }

    fn wrap_resource_key(
        &self,
        rk_plaintext: &SecretKey,
        aad: &[u8],
    ) -> Result<WrappedKeyBlob, EncryptionError> {
        self.wraps.reserve("master key")?;
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| EncryptionError::RandomFailure)?;
        let nonce_b64 = BASE64URL_NOPAD.encode(&nonce_bytes);

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::SealFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = Zeroizing::new(rk_plaintext.as_bytes().to_vec());
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), in_out.as_mut_slice())
            .map_err(|_| EncryptionError::SealFailed)?;
        in_out.extend_from_slice(tag.as_ref());

        Ok(WrappedKeyBlob {
            version: VERSION,
            algorithm: RESOURCE_KEY_WRAP_ALGORITHM.to_string(),
            mk_id: self.mk_id.clone(),
            nonce: nonce_b64,
            wrapped_key: BASE64URL_NOPAD.encode(in_out.as_slice()),
        })
    }

    fn unwrap_resource_key(
        &self,
        wrapped: &WrappedKeyBlob,
        aad: &[u8],
    ) -> Result<SecretKey, EncryptionError> {
        if wrapped.version != VERSION {
            return Err(EncryptionError::UnsupportedVersion(wrapped.version));
        }
        if wrapped.algorithm != RESOURCE_KEY_WRAP_ALGORITHM {
            return Err(EncryptionError::UnsupportedAlgorithm(
                bounded_untrusted_text(&wrapped.algorithm),
            ));
        }
        if wrapped.mk_id != self.mk_id {
            return Err(EncryptionError::MasterKeyMismatch);
        }

        if wrapped.nonce.len() != BASE64URL_NOPAD_12_BYTE_LEN {
            return Err(EncryptionError::InvalidNonceLength);
        }
        let nonce_bytes = BASE64URL_NOPAD
            .decode(wrapped.nonce.as_bytes())
            .map_err(|_| EncryptionError::InvalidEncoding)?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidNonceLength)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        if wrapped.wrapped_key.len() != LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_B64_LEN {
            return Err(EncryptionError::InvalidCiphertextLength);
        }
        let mut wrapped_key = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(wrapped.wrapped_key.as_bytes())
                .map_err(|_| EncryptionError::InvalidEncoding)?,
        );
        if wrapped_key.len() != LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_LEN {
            return Err(EncryptionError::InvalidCiphertextLength);
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::OpenFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), wrapped_key.as_mut_slice())
            .map_err(|_| EncryptionError::OpenFailed)?;

        SecretKey::try_from_slice(plaintext)
    }
}

impl AeadCipher {
    pub fn new_with_material_fingerprint(
        key_id: impl Into<String>,
        key: SecretKey,
        material_fingerprint: impl Into<String>,
    ) -> Result<Self, EncryptionError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let material_fingerprint = material_fingerprint.into();
        validate_material_fingerprint_id(&material_fingerprint)?;
        let invocations = shared_aead_invocation_budget(&key);
        Ok(Self {
            key_id,
            material_fingerprint,
            rk_id: String::new(),
            rk_epoch: None,
            key,
            invocations,
        })
    }

    pub fn with_resource_key_metadata(
        mut self,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, EncryptionError> {
        let rk_id = rk_id.into();
        validate_resource_key_id(&rk_id)?;
        self.rk_id = rk_id;
        self.rk_epoch = Some(rk_epoch);
        Ok(self)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn material_fingerprint(&self) -> &str {
        &self.material_fingerprint
    }

    pub fn resource_key_id(&self) -> Option<&str> {
        (!self.rk_id.is_empty()).then_some(self.rk_id.as_str())
    }

    pub fn resource_key_epoch(&self) -> Option<u64> {
        self.rk_epoch
    }

    fn matches_envelope_metadata(
        &self,
        envelope: &EncryptedEnvelope,
    ) -> Result<bool, EncryptionError> {
        if self.key_id != envelope.key_id {
            return Ok(false);
        }
        if self.material_fingerprint != envelope.material_fingerprint {
            return Ok(false);
        }
        if !self.rk_id.is_empty() && (envelope.rk_id.is_empty() || envelope.rk_epoch.is_none()) {
            return Ok(false);
        }
        if !envelope.rk_id.is_empty() {
            validate_resource_key_id(&envelope.rk_id)?;
            if self.rk_id != envelope.rk_id {
                return Ok(false);
            }
        }
        if let Some(rk_epoch) = envelope.rk_epoch
            && self.rk_epoch != Some(rk_epoch)
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.encrypt_with_aad_suffix(plaintext, context, &[])
    }

    /// Number of random-nonce encryptions performed with this cipher's key in this process,
    /// across every cipher built from the same key.
    pub fn invocations(&self) -> u64 {
        self.invocations.invocations()
    }

    /// Reserves one random-nonce invocation, refusing once the per-key budget is spent.
    fn reserve_invocation(&self) -> Result<(), EncryptionError> {
        self.invocations.reserve("encryption key")
    }

    #[cfg(test)]
    pub(crate) fn set_invocations_for_test(&self, invocations: u64) {
        self.invocations.set_for_test(invocations);
    }

    pub(crate) fn encrypt_with_aad_suffix(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.reserve_invocation()?;
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| EncryptionError::RandomFailure)?;
        let nonce_b64 = BASE64URL_NOPAD.encode(&nonce_bytes);

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::SealFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = context.aad_bytes_with_suffix(
            &EnvelopeHeader {
                version: VERSION,
                algorithm: ALGORITHM,
                key_id: &self.key_id,
                material_fingerprint: &self.material_fingerprint,
                rk_id: &self.rk_id,
                rk_epoch: self.rk_epoch,
                nonce: &nonce_b64,
            },
            aad_suffix,
        );
        let mut in_out = plaintext.to_vec();

        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out)
            .map_err(|_| EncryptionError::SealFailed)?;
        in_out.extend_from_slice(tag.as_ref());

        Ok(EncryptedEnvelope {
            version: VERSION,
            algorithm: ALGORITHM.to_string(),
            key_id: self.key_id.clone(),
            material_fingerprint: self.material_fingerprint.clone(),
            rk_id: self.rk_id.clone(),
            rk_epoch: self.rk_epoch,
            nonce: nonce_b64,
            ciphertext: BASE64URL_NOPAD.encode(&in_out),
        })
    }

    pub fn decrypt(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_aad_suffix(envelope, context, &[])
    }

    pub(crate) fn decrypt_with_aad_suffix(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        validate_encrypted_envelope_metadata(envelope)?;
        if envelope.key_id != self.key_id {
            return Err(EncryptionError::KeyMismatch);
        }
        if envelope.material_fingerprint != self.material_fingerprint {
            return Err(EncryptionError::MaterialFingerprintMismatch);
        }
        if !self.rk_id.is_empty() && (envelope.rk_id.is_empty() || envelope.rk_epoch.is_none()) {
            return Err(EncryptionError::KeyMismatch);
        }
        if !envelope.rk_id.is_empty() {
            validate_resource_key_id(&envelope.rk_id)?;
            if envelope.rk_id != self.rk_id {
                return Err(EncryptionError::KeyMismatch);
            }
        }
        if let Some(rk_epoch) = envelope.rk_epoch
            && self.rk_epoch != Some(rk_epoch)
        {
            return Err(EncryptionError::KeyMismatch);
        }

        let nonce_bytes = BASE64URL_NOPAD
            .decode(envelope.nonce.as_bytes())
            .map_err(|_| EncryptionError::InvalidEncoding)?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidNonceLength)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // `open_in_place` turns this buffer into plaintext; scrub it once the caller's copy
        // has been taken instead of leaving the decrypted bytes in freed heap memory.
        let mut ciphertext = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(envelope.ciphertext.as_bytes())
                .map_err(|_| EncryptionError::InvalidEncoding)?,
        );
        if ciphertext.len() < TAG_LEN {
            return Err(EncryptionError::InvalidCiphertextLength);
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::OpenFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let aad = context.aad_bytes_with_suffix(
            &EnvelopeHeader {
                version: envelope.version,
                algorithm: &envelope.algorithm,
                key_id: &envelope.key_id,
                material_fingerprint: &envelope.material_fingerprint,
                rk_id: &envelope.rk_id,
                rk_epoch: envelope.rk_epoch,
                nonce: &envelope.nonce,
            },
            aad_suffix,
        );
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad.as_slice()), ciphertext.as_mut())
            .map_err(|_| EncryptionError::OpenFailed)?;
        Ok(plaintext.to_vec())
    }
}

pub struct AeadKeyring {
    active: AeadCipher,
    retired: Vec<AeadCipher>,
    retired_by_metadata: HashMap<AeadCipherMetadataKey, usize>,
}

impl Debug for AeadKeyring {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadKeyring")
            .field("active", &self.active)
            .field("retired_count", &self.retired.len())
            .field("retired_metadata_count", &self.retired_by_metadata.len())
            .finish()
    }
}

impl AeadKeyring {
    pub fn new(active: AeadCipher) -> Self {
        Self {
            active,
            retired: Vec::new(),
            retired_by_metadata: HashMap::new(),
        }
    }

    pub fn with_retired(mut self, retired: AeadCipher) -> Self {
        let metadata = AeadCipherMetadataKey::from_cipher(&retired);
        self.retired_by_metadata
            .entry(metadata)
            .or_insert(self.retired.len());
        self.retired.push(retired);
        self
    }

    pub fn key_id(&self) -> &str {
        self.active.key_id()
    }

    pub fn material_fingerprint(&self) -> &str {
        self.active.material_fingerprint()
    }

    /// Resource key id bound to the active cipher, if resource key metadata was attached.
    pub fn resource_key_id(&self) -> Option<&str> {
        self.active.resource_key_id()
    }

    /// Resource key epoch bound to the active cipher, if resource key metadata was attached.
    pub fn resource_key_epoch(&self) -> Option<u64> {
        self.active.resource_key_epoch()
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.encrypt_with_aad_suffix(plaintext, context, &[])
    }

    pub(crate) fn encrypt_with_aad_suffix(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.active
            .encrypt_with_aad_suffix(plaintext, context, aad_suffix)
    }

    pub fn decrypt(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_aad_suffix(envelope, context, &[])
    }

    pub(crate) fn decrypt_with_aad_suffix(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        validate_encrypted_envelope_metadata(envelope)?;

        if self.active.matches_envelope_metadata(envelope)? {
            return self
                .active
                .decrypt_with_aad_suffix(envelope, context, aad_suffix);
        }

        let retired_metadata = AeadCipherMetadataKey::from_envelope(envelope);
        if let Some(&retired_index) = self.retired_by_metadata.get(&retired_metadata) {
            return self.retired[retired_index]
                .decrypt_with_aad_suffix(envelope, context, aad_suffix);
        }

        Err(EncryptionError::KeyMismatch)
    }
}

pub(crate) fn validate_key_id(key_id: &str) -> Result<(), EncryptionError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(EncryptionError::InvalidKeyId);
    }

    if key_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(EncryptionError::InvalidKeyId)
    }
}

fn validate_material_fingerprint_id(material_fingerprint: &str) -> Result<(), EncryptionError> {
    if material_fingerprint.is_empty() || material_fingerprint.len() > MAX_KEY_ID_LEN {
        return Err(EncryptionError::InvalidMaterialFingerprintId);
    }

    if material_fingerprint.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
    }) {
        Ok(())
    } else {
        Err(EncryptionError::InvalidMaterialFingerprintId)
    }
}

pub(crate) fn validate_resource_key_id(rk_id: &str) -> Result<(), EncryptionError> {
    if rk_id.is_empty() || rk_id.len() > MAX_KEY_ID_LEN {
        return Err(EncryptionError::InvalidResourceKeyId);
    }

    if rk_id.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
    }) {
        Ok(())
    } else {
        Err(EncryptionError::InvalidResourceKeyId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher(
        key_byte: u8,
        key_id: &str,
        material_fingerprint: &str,
        rk_id: &str,
        rk_epoch: u64,
    ) -> AeadCipher {
        AeadCipher::new_with_material_fingerprint(
            key_id,
            SecretKey::from_bytes([key_byte; KEY_LEN]),
            material_fingerprint,
        )
        .unwrap()
        .with_resource_key_metadata(rk_id, rk_epoch)
        .unwrap()
    }

    #[test]
    fn cipher_refuses_encryption_once_the_random_nonce_budget_is_spent() {
        // The budget is shared by key bytes process-wide, so this test owns key byte 0xE1.
        let cipher = cipher(0xE1, "tenant-a:key", "tenant-a/material", "tenant-a/rk", 7);
        let context = EncryptionContext {
            purpose: EncryptionPurpose::PayloadText,
            collection: "docs",
            point_id: Some("1"),
            field_path: Some("body"),
            vector_name: None,
        };
        assert_eq!(cipher.invocations(), 0);
        cipher.encrypt(b"first", context).unwrap();
        assert_eq!(cipher.invocations(), 1);

        cipher.set_invocations_for_test(AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT - 1);
        let envelope = cipher.encrypt(b"last", context).unwrap();
        assert_eq!(cipher.invocations(), AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT);

        assert!(matches!(
            cipher.encrypt(b"over budget", context),
            Err(EncryptionError::KeyUsageExhausted)
        ));
        // The budget only limits new encryptions; decryption keeps working and the counter
        // never moves past the limit.
        assert_eq!(cipher.decrypt(&envelope, context).unwrap(), b"last");
        assert_eq!(cipher.invocations(), AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT);
    }

    #[test]
    fn ciphers_built_from_the_same_key_share_one_invocation_budget() {
        // Owns key bytes 0xE3 and 0xE5.
        let context = EncryptionContext::payload_text("docs", "1", "body");
        let first = cipher(0xE3, "tenant-a:key", "tenant-a/material", "tenant-a/rk", 1);
        let second = cipher(0xE3, "tenant-b:key", "tenant-b/material", "tenant-b/rk", 9);
        let other_key = cipher(0xE5, "tenant-a:key", "tenant-a/material", "tenant-a/rk", 1);
        assert_eq!(first.invocations(), 0);

        first.encrypt(b"one", context).unwrap();
        second.encrypt(b"two", context).unwrap();
        assert_eq!(
            (first.invocations(), second.invocations()),
            (2, 2),
            "the counter belongs to the key, not to the cipher instance"
        );
        assert_eq!(other_key.invocations(), 0);

        // A fresh instance for an exhausted key is refused too: per-request cipher
        // construction on the server cannot reset the budget.
        first.set_invocations_for_test(AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT);
        let rebuilt = cipher(0xE3, "tenant-c:key", "tenant-c/material", "tenant-c/rk", 3);
        assert!(matches!(
            rebuilt.encrypt(b"three", context),
            Err(EncryptionError::KeyUsageExhausted)
        ));
        other_key.encrypt(b"still fine", context).unwrap();
    }

    #[test]
    fn master_key_wrap_observes_the_random_nonce_budget() {
        // Owns key byte 0xE4.
        let provider =
            LocalMasterKeyProvider::new("mk/local", SecretKey::from_bytes([0xE4; KEY_LEN]))
                .unwrap();
        let resource_key = SecretKey::from_bytes([0x11; KEY_LEN]);
        let wrapped = provider.wrap_resource_key(&resource_key, b"aad").unwrap();
        assert_eq!(provider.wraps.invocations(), 1);

        provider
            .wraps
            .set_for_test(AES_GCM_RANDOM_NONCE_INVOCATION_LIMIT);
        assert!(matches!(
            provider.wrap_resource_key(&resource_key, b"aad"),
            Err(EncryptionError::KeyUsageExhausted)
        ));
        // Unwrapping is unaffected by the encryption budget.
        assert_eq!(
            provider
                .unwrap_resource_key(&wrapped, b"aad")
                .unwrap()
                .as_bytes(),
            resource_key.as_bytes()
        );
    }

    #[test]
    fn bounded_untrusted_text_truncates_and_escapes() {
        assert_eq!(bounded_untrusted_text("AES-256-GCM"), "AES-256-GCM");
        assert_eq!(
            bounded_untrusted_text("line\nbreak\u{7}"),
            "line\\nbreak\\u{7}"
        );
        let long = "a".repeat(100);
        let rendered = bounded_untrusted_text(&long);
        assert_eq!(rendered, format!("{}...", "a".repeat(32)));
        assert!(
            EncryptionError::UnsupportedAlgorithm(bounded_untrusted_text(&"\n".repeat(4096)))
                .to_string()
                .len()
                < 128
        );
    }

    #[test]
    fn secret_key_from_slice_rejects_wrong_lengths_and_keeps_bytes() {
        assert!(matches!(
            SecretKey::try_from_slice(&[7u8; KEY_LEN - 1]),
            Err(EncryptionError::InvalidKeyLength)
        ));
        assert!(matches!(
            SecretKey::try_from_slice(&[7u8; KEY_LEN + 1]),
            Err(EncryptionError::InvalidKeyLength)
        ));
        let key = SecretKey::try_from_slice(&[7u8; KEY_LEN]).unwrap();
        assert_eq!(key.as_bytes(), &[7u8; KEY_LEN]);
        let derived = key.derive_subkey(b"domain").unwrap();
        assert_ne!(derived.as_bytes(), key.as_bytes());
        assert_eq!(
            derived.as_bytes(),
            key.derive_subkey(b"domain").unwrap().as_bytes()
        );
    }

    #[test]
    fn secret_key_debug_redacts_key_material() {
        let key = SecretKey::from_bytes([0x41; KEY_LEN]);

        let rendered = format!("{key:?}");

        assert_eq!(rendered, r#"SecretKey { bytes: "[redacted; 32 bytes]" }"#);
        assert!(!rendered.contains("AAAA"));
        assert!(!rendered.contains("[65"));
    }

    #[test]
    fn cipher_metadata_key_debug_redacts_identifiers() {
        let metadata = AeadCipherMetadataKey {
            key_id: "tenant-a/payload-key-sentinel".to_string(),
            material_fingerprint: "tenant-a/material-fingerprint-sentinel".to_string(),
            rk_id: "tenant-a/resource-key-sentinel".to_string(),
            rk_epoch: Some(7),
        };

        let rendered = format!("{metadata:?}");

        assert!(rendered.contains("AeadCipherMetadataKey"));
        assert!(rendered.contains("rk_epoch"));
        assert!(!rendered.contains("payload-key-sentinel"));
        assert!(!rendered.contains("material-fingerprint-sentinel"));
        assert!(!rendered.contains("resource-key-sentinel"));
    }

    #[test]
    fn cipher_and_keyring_debug_redact_key_metadata() {
        let active = cipher(
            0x41,
            "tenant-a:active-key-sentinel",
            "tenant-a/active-material-sentinel",
            "tenant-a/active-rk-sentinel",
            7,
        );
        let retired = cipher(
            0x42,
            "tenant-a:retired-key-sentinel",
            "tenant-a/retired-material-sentinel",
            "tenant-a/retired-rk-sentinel",
            6,
        );

        let active_debug = format!("{active:?}");
        let keyring_debug = format!("{:?}", AeadKeyring::new(active).with_retired(retired));

        for rendered in [active_debug, keyring_debug] {
            assert!(rendered.contains("[redacted; 32 bytes]"), "{rendered}");
            assert!(!rendered.contains("active-key-sentinel"), "{rendered}");
            assert!(!rendered.contains("active-material-sentinel"), "{rendered}");
            assert!(!rendered.contains("active-rk-sentinel"), "{rendered}");
            assert!(!rendered.contains("retired-key-sentinel"), "{rendered}");
            assert!(
                !rendered.contains("retired-material-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("retired-rk-sentinel"), "{rendered}");
            assert!(!rendered.contains("[65"), "{rendered}");
            assert!(!rendered.contains("[66"), "{rendered}");
        }
    }

    #[test]
    fn wrapped_resource_key_debug_redacts_key_metadata() {
        let provider = LocalMasterKeyProvider::new(
            "tenant-a/local-master-key-sentinel",
            SecretKey::from_bytes([0x51; KEY_LEN]),
        )
        .unwrap();
        let wrapped = provider
            .wrap_resource_key(
                &SecretKey::from_bytes([0x52; KEY_LEN]),
                b"wrapped-resource-key-debug-test",
            )
            .unwrap();

        let wrapped_debug = format!("{wrapped:?}");
        let provider_debug = format!("{provider:?}");

        for rendered in [&wrapped_debug, &provider_debug] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(
                !rendered.contains("local-master-key-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("[81"), "{rendered}");
        }
        assert!(!wrapped_debug.contains(&wrapped.nonce), "{wrapped_debug}");
        assert!(
            !wrapped_debug.contains(&wrapped.wrapped_key),
            "{wrapped_debug}"
        );
    }

    #[test]
    fn encryption_context_debug_redacts_identifiers() {
        let payload_context = EncryptionContext::payload_text(
            "AEAD-CONTEXT-COLLECTION-SENTINEL",
            "AEAD-CONTEXT-POINT-SENTINEL",
            "AEAD-CONTEXT-FIELD-SENTINEL",
        );
        let vector_context = EncryptionContext::ckks_vector(
            "AEAD-CONTEXT-VECTOR-COLLECTION-SENTINEL",
            "AEAD-CONTEXT-VECTOR-POINT-SENTINEL",
            "AEAD-CONTEXT-VECTOR-NAME-SENTINEL",
        );

        for rendered in [
            format!("{payload_context:?}"),
            format!("{vector_context:?}"),
        ] {
            assert!(rendered.contains("purpose"), "{rendered}");
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(!rendered.contains("AEAD-CONTEXT-COLLECTION-SENTINEL"));
            assert!(!rendered.contains("AEAD-CONTEXT-POINT-SENTINEL"));
            assert!(!rendered.contains("AEAD-CONTEXT-FIELD-SENTINEL"));
            assert!(!rendered.contains("AEAD-CONTEXT-VECTOR-COLLECTION-SENTINEL"));
            assert!(!rendered.contains("AEAD-CONTEXT-VECTOR-POINT-SENTINEL"));
            assert!(!rendered.contains("AEAD-CONTEXT-VECTOR-NAME-SENTINEL"));
        }
    }

    #[test]
    fn context_bound_subkey_derivation_binds_all_context_parts() {
        let key = SecretKey::from_bytes([0x41; KEY_LEN]);
        let epoch7 = 7u64.to_be_bytes();
        let epoch8 = 8u64.to_be_bytes();
        let first = key
            .derive_subkey_with_context(
                b"qdrant-sec/test-subkey/v1",
                b"qdrant-sec/test-context/v1",
                &[b"deployment-a", b"collection-a", &epoch7],
            )
            .unwrap();
        let second = key
            .derive_subkey_with_context(
                b"qdrant-sec/test-subkey/v1",
                b"qdrant-sec/test-context/v1",
                &[b"deployment-a", b"collection-a", &epoch7],
            )
            .unwrap();
        let different_collection = key
            .derive_subkey_with_context(
                b"qdrant-sec/test-subkey/v1",
                b"qdrant-sec/test-context/v1",
                &[b"deployment-a", b"collection-b", &epoch7],
            )
            .unwrap();
        let different_epoch = key
            .derive_subkey_with_context(
                b"qdrant-sec/test-subkey/v1",
                b"qdrant-sec/test-context/v1",
                &[b"deployment-a", b"collection-a", &epoch8],
            )
            .unwrap();
        let different_context_domain = key
            .derive_subkey_with_context(
                b"qdrant-sec/test-subkey/v1",
                b"qdrant-sec/other-context/v1",
                &[b"deployment-a", b"collection-a", &epoch7],
            )
            .unwrap();
        let legacy = key.derive_subkey(b"qdrant-sec/test-subkey/v1").unwrap();

        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_ne!(first.as_bytes(), different_collection.as_bytes());
        assert_ne!(first.as_bytes(), different_epoch.as_bytes());
        assert_ne!(first.as_bytes(), different_context_domain.as_bytes());
        assert_ne!(first.as_bytes(), legacy.as_bytes());
    }

    #[test]
    fn keyring_uses_retired_key_only_when_envelope_metadata_matches() {
        let active = cipher(
            1,
            "tenant-a:active",
            "tenant-a/active@v1",
            "tenant-a/active-rk",
            2,
        );
        let retired = cipher(
            2,
            "tenant-a:retired",
            "tenant-a/retired@v1",
            "tenant-a/retired-rk",
            1,
        );
        let context = EncryptionContext::payload_text("collection-1", "point-1", "body");
        let retired_envelope = retired.encrypt(b"retired plaintext", context).unwrap();
        let keyring = AeadKeyring::new(active).with_retired(retired);

        assert_eq!(
            keyring.decrypt(&retired_envelope, context).unwrap(),
            b"retired plaintext"
        );
    }

    #[test]
    fn keyring_does_not_try_retired_keys_after_active_metadata_match_tamper() {
        let active = cipher(
            1,
            "tenant-a:active",
            "tenant-a/shared@v1",
            "tenant-a/active-rk",
            2,
        );
        let retired = cipher(
            2,
            "tenant-a:active",
            "tenant-a/shared@v1",
            "tenant-a/active-rk",
            2,
        );
        let context = EncryptionContext::payload_text("collection-1", "point-1", "body");
        let mut envelope = active.encrypt(b"active plaintext", context).unwrap();
        let mut ciphertext = BASE64URL_NOPAD
            .decode(envelope.ciphertext.as_bytes())
            .unwrap();
        ciphertext[0] ^= 0x01;
        envelope.ciphertext = BASE64URL_NOPAD.encode(&ciphertext);
        let keyring = AeadKeyring::new(active).with_retired(retired);

        assert_eq!(
            keyring.decrypt(&envelope, context),
            Err(EncryptionError::OpenFailed)
        );
    }

    #[test]
    fn local_master_key_provider_rejects_wrong_sized_wrapped_resource_key() {
        let provider =
            LocalMasterKeyProvider::new("tenant-a/mk-v1", SecretKey::from_bytes([91u8; 32]))
                .unwrap();
        let aad = b"resource-key-wrap-test";
        let mut wrapped = provider
            .wrap_resource_key(&SecretKey::from_bytes([92u8; 32]), aad)
            .unwrap();
        assert_eq!(
            wrapped.wrapped_key.len(),
            LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_B64_LEN
        );

        let mut oversized = wrapped.clone();
        oversized.wrapped_key =
            BASE64URL_NOPAD.encode(&[7u8; LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_LEN + 1]);
        assert!(matches!(
            provider.unwrap_resource_key(&oversized, aad),
            Err(EncryptionError::InvalidCiphertextLength),
        ));

        wrapped.nonce.push('A');
        assert!(matches!(
            provider.unwrap_resource_key(&wrapped, aad),
            Err(EncryptionError::InvalidNonceLength),
        ));
    }

    #[test]
    fn envelope_metadata_rejects_oversized_ciphertext_before_decode() {
        let envelope = EncryptedEnvelope {
            version: VERSION,
            algorithm: ALGORITHM.to_string(),
            key_id: "tenant-a:active".to_string(),
            material_fingerprint: "tenant-a/active@v1".to_string(),
            rk_id: "tenant-a/active-rk".to_string(),
            rk_epoch: Some(1),
            nonce: BASE64URL_NOPAD.encode(&[0u8; NONCE_LEN]),
            ciphertext: "A".repeat(ENCRYPTED_ENVELOPE_CIPHERTEXT_MAX_B64_LEN + 1),
        };

        assert_eq!(
            validate_encrypted_envelope_metadata(&envelope),
            Err(EncryptionError::InvalidCiphertextLength)
        );
    }

    #[test]
    fn envelope_metadata_rejects_oversized_nonce_before_decode() {
        let envelope = EncryptedEnvelope {
            version: VERSION,
            algorithm: ALGORITHM.to_string(),
            key_id: "tenant-a:active".to_string(),
            material_fingerprint: "tenant-a/active@v1".to_string(),
            rk_id: "tenant-a/active-rk".to_string(),
            rk_epoch: Some(1),
            nonce: "A".repeat(BASE64URL_NOPAD_12_BYTE_LEN + 1),
            ciphertext: BASE64URL_NOPAD.encode(&[1u8; TAG_LEN]),
        };

        assert_eq!(
            validate_encrypted_envelope_metadata(&envelope),
            Err(EncryptionError::InvalidNonceLength)
        );
    }

    #[test]
    fn keyring_rejects_unknown_envelope_metadata_without_open_attempt() {
        let active = cipher(
            1,
            "tenant-a:active",
            "tenant-a/active@v1",
            "tenant-a/active-rk",
            2,
        );
        let retired = cipher(
            2,
            "tenant-a:retired",
            "tenant-a/retired@v1",
            "tenant-a/retired-rk",
            1,
        );
        let context = EncryptionContext::payload_text("collection-1", "point-1", "body");
        let mut envelope = active.encrypt(b"active plaintext", context).unwrap();
        envelope.key_id = "tenant-a:unknown".to_string();
        let keyring = AeadKeyring::new(active).with_retired(retired);

        assert_eq!(
            keyring.decrypt(&envelope, context),
            Err(EncryptionError::KeyMismatch)
        );
    }
}

#[cfg(test)]
#[path = "aead_concurrency_tests.rs"]
mod concurrency_tests;
