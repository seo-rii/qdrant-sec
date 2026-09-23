use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aead::{
    AeadCipher, AeadKeyring, CKKS_VECTOR_KEY_DOMAIN, EncryptedEnvelope, EncryptionContext,
    EncryptionError, SecretKey, validate_encrypted_envelope_metadata, validate_key_id,
    validate_resource_key_id,
};

pub const CKKS_SCHEME: &str = "openfhe-ckks";
pub const CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50: &str = "ckks-128-n16384-d4-scale50";
pub const CKKS_PUBLIC_MATERIAL_MAX_CRYPTO_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
pub const CKKS_PUBLIC_MATERIAL_MAX_PUBLIC_KEY_BYTES: usize = 4 * 1024 * 1024;
pub const ENCRYPTED_VECTOR_SIDECAR_FIELD: &str = "$qdrant_sec_vectors";
pub const ENCRYPTED_CKKS_VECTOR_MARKER: &str = "$qdrant_sec_ckks_vector";
pub const CLIENT_CKKS_VECTOR_MARKER: &str = "$qdrant_sec_client_ckks_vector";
const VERSION: u8 = 1;
const CRYPTO_SCHEMA_VERSION: u16 = 1;
const DEFAULT_ENCRYPTION_EPOCH: u64 = 0;
const MAX_VECTOR_NAME_LEN: usize = 255;
const SHA256_B64_LEN: usize = 43;
const CKKS_VECTOR_CIPHERTEXT_MAX_BYTES: usize = 16 * 1024 * 1024;
const CKKS_VECTOR_CIPHERTEXT_MAX_B64_LEN: usize = CKKS_VECTOR_CIPHERTEXT_MAX_BYTES.div_ceil(3) * 4;
const CLIENT_CKKS_VECTOR_SIGNATURE_DOMAIN: &str = "qdrant-sec/client-ckks-vector-signature/v1";
const CLIENT_CKKS_VECTOR_SIGNATURE_ALGORITHM: &str = "ed25519";

#[derive(Error, PartialEq, Eq)]
pub enum CkksError {
    #[error("ckks key id is invalid")]
    InvalidKeyId,
    #[error("ckks vector name is invalid")]
    InvalidVectorName,
    #[error("ckks vector sidecar delete target is invalid")]
    InvalidDeleteTarget,
    #[error("ckks context value is invalid: {0}")]
    InvalidContext(String),
    #[error("ckks parameters are invalid: {0}")]
    InvalidParameters(String),
    #[error("ckks vector must contain at least one value")]
    EmptyVector,
    #[error("ckks vector has {len} values but batch size only allows {batch_size}")]
    VectorTooWide { len: usize, batch_size: usize },
    #[error("ckks vector value at index {index} is not finite")]
    NonFiniteValue { index: usize },
    #[error("openfhe backend returned empty ciphertext")]
    EmptyCiphertext,
    #[error("openfhe backend returned {actual} batch ciphertexts for {expected} input vectors")]
    BackendBatchSizeMismatch { expected: usize, actual: usize },
    #[error("ckks vector query has {query_len} values but stored ciphertext has {slots} slots")]
    QueryDimensionMismatch { query_len: usize, slots: usize },
    #[error("unsupported ckks vector envelope version {0}")]
    UnsupportedEnvelopeVersion(u8),
    #[error("unsupported ckks vector scheme {0}")]
    UnsupportedScheme(String),
    #[error("ckks vector envelope is malformed: {0}")]
    MalformedEnvelope(String),
    #[error("unsupported ckks crypto schema version {0}")]
    UnsupportedCryptoSchemaVersion(u16),
    #[error("ckks vector encryption epoch does not match active encryptor")]
    EncryptionEpochMismatch,
    #[error("openfhe backend failed: {0}")]
    Backend(String),
    #[error(transparent)]
    Envelope(#[from] EncryptionError),
}

impl Debug for CkksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyId => f.write_str("InvalidKeyId"),
            Self::InvalidVectorName => f.write_str("InvalidVectorName"),
            Self::InvalidDeleteTarget => f.write_str("InvalidDeleteTarget"),
            Self::InvalidContext(_) => f
                .debug_tuple("InvalidContext")
                .field(&"[redacted]")
                .finish(),
            Self::InvalidParameters(_) => f
                .debug_tuple("InvalidParameters")
                .field(&"[redacted]")
                .finish(),
            Self::EmptyVector => f.write_str("EmptyVector"),
            Self::VectorTooWide { len, batch_size } => f
                .debug_struct("VectorTooWide")
                .field("len", len)
                .field("batch_size", batch_size)
                .finish(),
            Self::NonFiniteValue { index } => f
                .debug_struct("NonFiniteValue")
                .field("index", index)
                .finish(),
            Self::EmptyCiphertext => f.write_str("EmptyCiphertext"),
            Self::BackendBatchSizeMismatch { expected, actual } => f
                .debug_struct("BackendBatchSizeMismatch")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
            Self::QueryDimensionMismatch { query_len, slots } => f
                .debug_struct("QueryDimensionMismatch")
                .field("query_len", query_len)
                .field("slots", slots)
                .finish(),
            Self::UnsupportedEnvelopeVersion(version) => f
                .debug_tuple("UnsupportedEnvelopeVersion")
                .field(version)
                .finish(),
            Self::UnsupportedScheme(_) => f
                .debug_tuple("UnsupportedScheme")
                .field(&"[redacted]")
                .finish(),
            Self::MalformedEnvelope(_) => f
                .debug_tuple("MalformedEnvelope")
                .field(&"[redacted]")
                .finish(),
            Self::UnsupportedCryptoSchemaVersion(version) => f
                .debug_tuple("UnsupportedCryptoSchemaVersion")
                .field(version)
                .finish(),
            Self::EncryptionEpochMismatch => f.write_str("EncryptionEpochMismatch"),
            Self::Backend(_) => f.debug_tuple("Backend").field(&"[redacted]").finish(),
            Self::Envelope(_) => f.debug_tuple("Envelope").field(&"[redacted]").finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CkksParameters {
    pub poly_modulus_degree: u32,
    pub multiplicative_depth: u32,
    pub scaling_mod_size: u32,
    pub first_mod_size: u32,
    pub batch_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CkksParameterProfile {
    pub name: &'static str,
    pub parameters: CkksParameters,
}

const CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50_PARAMETERS: CkksParameters = CkksParameters {
    poly_modulus_degree: 16_384,
    multiplicative_depth: 4,
    scaling_mod_size: 50,
    first_mod_size: 60,
    batch_size: 8_192,
};

pub const CKKS_PARAMETER_PROFILES: &[CkksParameterProfile] = &[CkksParameterProfile {
    name: CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
    parameters: CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50_PARAMETERS,
}];

impl CkksParameters {
    pub const fn openfhe_default_128_bit() -> Self {
        CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50_PARAMETERS
    }

    pub fn from_security_profile(profile: &str) -> Option<Self> {
        CKKS_PARAMETER_PROFILES
            .iter()
            .find(|candidate| candidate.name == profile)
            .map(|candidate| candidate.parameters)
    }

    pub fn security_profile(&self) -> Option<&'static str> {
        CKKS_PARAMETER_PROFILES
            .iter()
            .find(|candidate| candidate.parameters.matches_security_parameters(self))
            .map(|candidate| candidate.name)
    }

    fn matches_security_parameters(&self, other: &Self) -> bool {
        self.poly_modulus_degree == other.poly_modulus_degree
            && self.multiplicative_depth == other.multiplicative_depth
            && self.scaling_mod_size == other.scaling_mod_size
            && self.first_mod_size == other.first_mod_size
    }

    pub fn validate(&self) -> Result<(), CkksError> {
        if self.security_profile().is_none() {
            return Err(CkksError::InvalidParameters(format!(
                "poly_modulus_degree, multiplicative_depth, scaling_mod_size, and first_mod_size must match allowlisted profile {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
            )));
        }

        let max_slots = self.poly_modulus_degree / 2;
        if self.batch_size == 0 || self.batch_size > max_slots {
            return Err(CkksError::InvalidParameters(format!(
                "batch_size must be in 1..={max_slots}",
            )));
        }

        Ok(())
    }
}

impl Default for CkksParameters {
    fn default() -> Self {
        Self::openfhe_default_128_bit()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CkksPublicMaterial {
    crypto_context: Vec<u8>,
    public_key: Vec<u8>,
}

impl Debug for CkksPublicMaterial {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksPublicMaterial")
            .field("crypto_context_len", &self.crypto_context.len())
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

impl CkksPublicMaterial {
    pub fn new(
        crypto_context: impl Into<Vec<u8>>,
        public_key: impl Into<Vec<u8>>,
    ) -> Result<Self, CkksError> {
        let crypto_context = crypto_context.into();
        let public_key = public_key.into();
        if crypto_context.is_empty() {
            return Err(CkksError::InvalidContext(
                "crypto_context must not be empty".to_string(),
            ));
        }
        if crypto_context.len() > CKKS_PUBLIC_MATERIAL_MAX_CRYPTO_CONTEXT_BYTES {
            return Err(CkksError::InvalidContext(format!(
                "crypto_context must be at most {CKKS_PUBLIC_MATERIAL_MAX_CRYPTO_CONTEXT_BYTES} bytes",
            )));
        }
        if public_key.is_empty() {
            return Err(CkksError::InvalidContext(
                "public_key must not be empty".to_string(),
            ));
        }
        if public_key.len() > CKKS_PUBLIC_MATERIAL_MAX_PUBLIC_KEY_BYTES {
            return Err(CkksError::InvalidContext(format!(
                "public_key must be at most {CKKS_PUBLIC_MATERIAL_MAX_PUBLIC_KEY_BYTES} bytes",
            )));
        }

        Ok(Self {
            crypto_context,
            public_key,
        })
    }

    pub fn crypto_context(&self) -> &[u8] {
        &self.crypto_context
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn digest_for(&self, parameters: &CkksParameters) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"qdrant-sec-openfhe-context-v1");
        hasher.update(parameters.poly_modulus_degree.to_be_bytes());
        hasher.update(parameters.multiplicative_depth.to_be_bytes());
        hasher.update(parameters.scaling_mod_size.to_be_bytes());
        hasher.update(parameters.first_mod_size.to_be_bytes());
        hasher.update(parameters.batch_size.to_be_bytes());
        hasher.update((self.crypto_context.len() as u64).to_be_bytes());
        hasher.update(&self.crypto_context);
        hasher.update((self.public_key.len() as u64).to_be_bytes());
        hasher.update(&self.public_key);
        BASE64URL_NOPAD.encode(&hasher.finalize())
    }
}

#[derive(Clone)]
pub struct CkksEncryptionInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub point_id: &'a str,
    pub vector_name: &'a str,
    pub values: &'a [f64],
}

impl Debug for CkksEncryptionInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksEncryptionInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("values_len", &self.values.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct CkksVectorBatchItem<'a> {
    pub point_id: &'a str,
    pub values: &'a [f64],
}

impl Debug for CkksVectorBatchItem<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksVectorBatchItem")
            .field("point_id", &"[redacted]")
            .field("values_len", &self.values.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksBatchEncryptionInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub vector_name: &'a str,
    pub items: &'a [CkksVectorBatchItem<'a>],
}

impl Debug for CkksBatchEncryptionInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksBatchEncryptionInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("items", &self.items)
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksPlaintextQueryScoreInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub point_id: &'a str,
    pub vector_name: &'a str,
    pub distance: &'a str,
    pub query_values: &'a [f64],
    pub ciphertext: &'a [u8],
}

impl Debug for CkksPlaintextQueryScoreInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksPlaintextQueryScoreInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("distance", &self.distance)
            .field("query_values_len", &self.query_values.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct CkksPlaintextQueryScoreBatchItem<'a> {
    pub point_id: &'a str,
    pub ciphertext: &'a [u8],
}

impl Debug for CkksPlaintextQueryScoreBatchItem<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksPlaintextQueryScoreBatchItem")
            .field("point_id", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksPlaintextQueryScoreBatchInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub vector_name: &'a str,
    pub distance: &'a str,
    pub query_values: &'a [f64],
    pub items: &'a [CkksPlaintextQueryScoreBatchItem<'a>],
}

impl Debug for CkksPlaintextQueryScoreBatchInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksPlaintextQueryScoreBatchInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("distance", &self.distance)
            .field("query_values_len", &self.query_values.len())
            .field("items", &self.items)
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksQueryEncryptionInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub vector_name: &'a str,
    pub values: &'a [f64],
}

impl Debug for CkksQueryEncryptionInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksQueryEncryptionInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("values_len", &self.values.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksEncryptedQueryScoreInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub point_id: &'a str,
    pub vector_name: &'a str,
    pub distance: &'a str,
    pub encrypted_query: &'a [u8],
    pub ciphertext: &'a [u8],
}

impl Debug for CkksEncryptedQueryScoreInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksEncryptedQueryScoreInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("distance", &self.distance)
            .field("encrypted_query_len", &self.encrypted_query.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct CkksEncryptedQueryScoreBatchItem<'a> {
    pub point_id: &'a str,
    pub ciphertext: &'a [u8],
}

impl Debug for CkksEncryptedQueryScoreBatchItem<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksEncryptedQueryScoreBatchItem")
            .field("point_id", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksEncryptedQueryScoreBatchInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub vector_name: &'a str,
    pub distance: &'a str,
    pub encrypted_query: &'a [u8],
    pub items: &'a [CkksEncryptedQueryScoreBatchItem<'a>],
}

impl Debug for CkksEncryptedQueryScoreBatchInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksEncryptedQueryScoreBatchInput")
            .field("parameters", self.parameters)
            .field("public_material", self.public_material)
            .field("collection", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("distance", &self.distance)
            .field("encrypted_query_len", &self.encrypted_query.len())
            .field("items", &self.items)
            .finish()
    }
}

pub trait CkksVectorBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError>;

    fn encrypt_batch(
        &self,
        input: CkksBatchEncryptionInput<'_>,
    ) -> Result<Vec<Vec<u8>>, CkksError> {
        input
            .items
            .iter()
            .map(|item| {
                self.encrypt(CkksEncryptionInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    values: item.values,
                })
            })
            .collect()
    }

    fn encrypt_query(&self, input: CkksQueryEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        self.encrypt(CkksEncryptionInput {
            parameters: input.parameters,
            public_material: input.public_material,
            collection: input.collection,
            point_id: "__ckks_query__",
            vector_name: input.vector_name,
            values: input.values,
        })
    }

    fn score_plaintext_query(
        &self,
        _input: CkksPlaintextQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        Err(CkksError::Backend(
            "OpenFHE backend does not support plaintext-query CKKS scoring".to_string(),
        ))
    }

    fn score_plaintext_query_batch(
        &self,
        input: CkksPlaintextQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        input
            .items
            .iter()
            .map(|item| {
                self.score_plaintext_query(CkksPlaintextQueryScoreInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    distance: input.distance,
                    query_values: input.query_values,
                    ciphertext: item.ciphertext,
                })
            })
            .collect()
    }

    fn score_encrypted_query(
        &self,
        _input: CkksEncryptedQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        Err(CkksError::Backend(
            "OpenFHE backend does not support encrypted-query CKKS scoring".to_string(),
        ))
    }

    fn score_encrypted_query_batch(
        &self,
        input: CkksEncryptedQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        input
            .items
            .iter()
            .map(|item| {
                self.score_encrypted_query(CkksEncryptedQueryScoreInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    distance: input.distance,
                    encrypted_query: input.encrypted_query,
                    ciphertext: item.ciphertext,
                })
            })
            .collect()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct EncryptedCkksVector {
    pub version: u8,
    pub scheme: String,
    pub envelope: EncryptedEnvelope,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CkksVectorSidecarEnvelopeKey {
    collection_id: String,
    point_id: String,
    vector_name: String,
    envelope_version: u8,
    envelope_algorithm: String,
    key_id: String,
    material_fingerprint: String,
    rk_id: String,
    rk_epoch: Option<u64>,
    nonce: String,
    ciphertext_sha256_b64: String,
}

impl Debug for CkksVectorSidecarEnvelopeKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksVectorSidecarEnvelopeKey")
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("envelope_version", &self.envelope_version)
            .field("envelope_algorithm", &self.envelope_algorithm)
            .field("key_id", &"[redacted]")
            .field("material_fingerprint", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("nonce", &"[redacted]")
            .field("ciphertext_sha256_b64", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CkksVectorVerifiedSidecarKey {
    envelope_key: CkksVectorSidecarEnvelopeKey,
}

impl Debug for CkksVectorVerifiedSidecarKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksVectorVerifiedSidecarKey")
            .field("envelope_key", &self.envelope_key)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientCkksVectorSidecarEnvelopeKey {
    collection_id: String,
    point_id: String,
    vector_name: String,
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    context_digest: String,
    slots: usize,
    ciphertext_sha256_b64: String,
    signature_key_id: String,
    signature_sha256_b64: String,
}

impl Debug for ClientCkksVectorSidecarEnvelopeKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCkksVectorSidecarEnvelopeKey")
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("context_digest", &"[redacted]")
            .field("slots", &self.slots)
            .field("ciphertext_sha256_b64", &"[redacted]")
            .field("signature_key_id", &"[redacted]")
            .field("signature_sha256_b64", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientCkksVectorVerifiedSidecarKey {
    envelope_key: ClientCkksVectorSidecarEnvelopeKey,
}

impl Debug for ClientCkksVectorVerifiedSidecarKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCkksVectorVerifiedSidecarKey")
            .field("envelope_key", &self.envelope_key)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CkksVectorVerifiedSidecarDeleteKey {
    collection_id: String,
    vector_name: String,
    target: CkksVectorSidecarDeleteTarget,
}

impl Debug for CkksVectorVerifiedSidecarDeleteKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksVectorVerifiedSidecarDeleteKey")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("target", &self.target)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CkksVectorSidecarDeleteTarget {
    PointIds { digest_b64: String },
    Filter { digest_b64: String },
}

impl Debug for CkksVectorSidecarDeleteTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PointIds { .. } => f
                .debug_struct("PointIds")
                .field("digest_b64", &"[redacted]")
                .finish(),
            Self::Filter { .. } => f
                .debug_struct("Filter")
                .field("digest_b64", &"[redacted]")
                .finish(),
        }
    }
}

impl CkksVectorVerifiedSidecarKey {
    pub fn envelope_key(&self) -> &CkksVectorSidecarEnvelopeKey {
        &self.envelope_key
    }
}

impl ClientCkksVectorVerifiedSidecarKey {
    pub fn envelope_key(&self) -> &ClientCkksVectorSidecarEnvelopeKey {
        &self.envelope_key
    }
}

impl ClientCkksVectorSidecarEnvelopeKey {
    pub fn matches_binding(&self, collection_id: &str, point_id: &str, vector_name: &str) -> bool {
        self.collection_id == collection_id
            && self.point_id == point_id
            && self.vector_name == vector_name
    }

    pub fn signature_key_id(&self) -> &str {
        &self.signature_key_id
    }
}

impl CkksVectorVerifiedSidecarDeleteKey {
    pub fn matches_binding(
        &self,
        collection_id: &str,
        vector_name: &str,
        target: &CkksVectorSidecarDeleteTarget,
    ) -> bool {
        self.collection_id == collection_id
            && self.vector_name == vector_name
            && &self.target == target
    }
}

impl CkksVectorSidecarEnvelopeKey {
    pub fn matches_binding(&self, collection_id: &str, point_id: &str, vector_name: &str) -> bool {
        self.collection_id == collection_id
            && self.point_id == point_id
            && self.vector_name == vector_name
    }
}

pub fn ckks_vector_verified_sidecar_delete_key(
    collection_id: &str,
    vector_name: impl Into<String>,
    target: CkksVectorSidecarDeleteTarget,
) -> Result<CkksVectorVerifiedSidecarDeleteKey, CkksError> {
    let vector_name = validate_vector_name(vector_name)?;
    validate_delete_target(&target)?;
    Ok(CkksVectorVerifiedSidecarDeleteKey {
        collection_id: collection_id.to_string(),
        vector_name,
        target,
    })
}

fn validate_delete_target(target: &CkksVectorSidecarDeleteTarget) -> Result<(), CkksError> {
    let digest_b64 = match target {
        CkksVectorSidecarDeleteTarget::PointIds { digest_b64 }
        | CkksVectorSidecarDeleteTarget::Filter { digest_b64 } => digest_b64,
    };
    if digest_b64.len() != SHA256_B64_LEN {
        return Err(CkksError::InvalidDeleteTarget);
    }
    if BASE64URL_NOPAD
        .decode(digest_b64.as_bytes())
        .ok()
        .is_none_or(|digest| digest.len() != 32)
    {
        return Err(CkksError::InvalidDeleteTarget);
    }
    Ok(())
}

fn validate_vector_name(vector_name: impl Into<String>) -> Result<String, CkksError> {
    let vector_name = vector_name.into();
    if vector_name.len() > MAX_VECTOR_NAME_LEN || vector_name.contains('\0') {
        return Err(CkksError::InvalidVectorName);
    }
    Ok(vector_name)
}

fn validate_raw_ciphertext_size(ciphertext: &[u8]) -> Result<(), CkksError> {
    if ciphertext.len() > CKKS_VECTOR_CIPHERTEXT_MAX_BYTES {
        return Err(CkksError::MalformedEnvelope(
            "stored ciphertext exceeds maximum size".to_string(),
        ));
    }
    Ok(())
}

fn validate_stored_ciphertext_encoded_size(ciphertext_b64: &str) -> Result<(), CkksError> {
    if ciphertext_b64.len() > CKKS_VECTOR_CIPHERTEXT_MAX_B64_LEN {
        return Err(CkksError::MalformedEnvelope(
            "stored ciphertext exceeds maximum size".to_string(),
        ));
    }
    Ok(())
}

fn decode_stored_ciphertext(ciphertext_b64: &str) -> Result<Vec<u8>, CkksError> {
    validate_stored_ciphertext_encoded_size(ciphertext_b64)?;
    let ciphertext = BASE64URL_NOPAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| CkksError::MalformedEnvelope("stored ciphertext is invalid".to_string()))?;
    if ciphertext.is_empty() {
        return Err(CkksError::MalformedEnvelope(
            "stored ciphertext is empty".to_string(),
        ));
    }
    validate_raw_ciphertext_size(&ciphertext)?;
    Ok(ciphertext)
}

pub fn encrypted_ckks_vector_payload_value(
    encrypted: &EncryptedCkksVector,
) -> Result<Value, CkksError> {
    Ok(json!({
        ENCRYPTED_CKKS_VECTOR_MARKER: serde_json::to_value(encrypted)
            .map_err(|err| CkksError::MalformedEnvelope(err.to_string()))?,
    }))
}

pub fn is_encrypted_ckks_vector_payload_value(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == 1 && object.contains_key(ENCRYPTED_CKKS_VECTOR_MARKER)
    })
}

pub fn is_client_ckks_vector_payload_value(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.contains_key(CLIENT_CKKS_VECTOR_MARKER))
}

pub fn ckks_vector_sidecar_envelope_key(
    value: &Value,
    collection_id: &str,
    point_id: &str,
    vector_name: &str,
) -> Result<Option<CkksVectorSidecarEnvelopeKey>, CkksError> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(marker) = object.get(ENCRYPTED_CKKS_VECTOR_MARKER) else {
        return Ok(None);
    };
    if object.len() != 1 {
        return Err(CkksError::MalformedEnvelope(
            "encrypted CKKS vector marker must be the only key of the sidecar value".to_string(),
        ));
    }
    let encrypted: EncryptedCkksVector = serde_json::from_value(marker.clone()).map_err(|_| {
        CkksError::MalformedEnvelope("CKKS sidecar marker is malformed".to_string())
    })?;
    if encrypted.version != VERSION {
        return Err(CkksError::UnsupportedEnvelopeVersion(encrypted.version));
    }
    if encrypted.scheme != CKKS_SCHEME {
        return Err(CkksError::UnsupportedScheme(encrypted.scheme));
    }
    validate_stored_ciphertext_encoded_size(&encrypted.envelope.ciphertext)?;
    validate_encrypted_envelope_metadata(&encrypted.envelope)?;
    let ciphertext = decode_stored_ciphertext(&encrypted.envelope.ciphertext)?;
    let ciphertext_sha256_b64 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());

    Ok(Some(CkksVectorSidecarEnvelopeKey {
        collection_id: collection_id.to_string(),
        point_id: point_id.to_string(),
        vector_name: vector_name.to_string(),
        envelope_version: encrypted.envelope.version,
        envelope_algorithm: encrypted.envelope.algorithm,
        key_id: encrypted.envelope.key_id,
        material_fingerprint: encrypted.envelope.material_fingerprint,
        rk_id: encrypted.envelope.rk_id,
        rk_epoch: encrypted.envelope.rk_epoch,
        nonce: encrypted.envelope.nonce,
        ciphertext_sha256_b64,
    }))
}

fn ckks_vector_verified_sidecar_key(
    value: &Value,
    collection_id: &str,
    point_id: &str,
    vector_name: &str,
) -> Result<CkksVectorVerifiedSidecarKey, CkksError> {
    let envelope_key =
        ckks_vector_sidecar_envelope_key(value, collection_id, point_id, vector_name)?.ok_or_else(
            || CkksError::MalformedEnvelope("missing CKKS vector marker".to_string()),
        )?;
    Ok(CkksVectorVerifiedSidecarKey { envelope_key })
}

#[derive(Clone, Copy)]
pub struct ClientCkksVectorSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct ClientCkksVectorValidationContext<'a> {
    pub collection_id: &'a str,
    pub point_id: &'a str,
    pub vector_name: &'a str,
    pub expected_key_id: &'a str,
    pub expected_rk_id: &'a str,
    pub min_rk_epoch: u64,
    pub max_rk_epoch: u64,
    pub expected_context_digest: &'a str,
    pub max_slots: usize,
    pub signature_verification: ClientCkksVectorSignatureVerification<'a>,
}

pub fn client_ckks_vector_signature_message(value: &Value) -> Result<Vec<u8>, CkksError> {
    let envelope = client_ckks_vector_envelope(value)?;
    Ok(client_ckks_vector_signature_message_for_envelope(&envelope))
}

pub fn client_ckks_vector_sidecar_envelope_key(
    value: &Value,
    vector_name: &str,
) -> Result<Option<ClientCkksVectorSidecarEnvelopeKey>, CkksError> {
    let Some(envelope) = optional_client_ckks_vector_envelope(value)? else {
        return Ok(None);
    };
    let signature = envelope.signature.as_ref().ok_or_else(|| {
        CkksError::MalformedEnvelope("client CKKS vector signature is missing".to_string())
    })?;
    validate_client_ckks_vector_common(&envelope, vector_name)?;
    let ciphertext = decode_stored_ciphertext(&envelope.ciphertext)?;
    let ciphertext_sha256_b64 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
    if ciphertext_sha256_b64 != envelope.ciphertext_sha256 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector ciphertext hash does not match ciphertext".to_string(),
        ));
    }
    let signature_bytes = decode_client_ckks_vector_signature(signature)?;
    let signature_sha256_b64 = BASE64URL_NOPAD.encode(Sha256::digest(&signature_bytes).as_ref());

    Ok(Some(ClientCkksVectorSidecarEnvelopeKey {
        collection_id: envelope.collection_id,
        point_id: envelope.point_id,
        vector_name: envelope.vector_name,
        key_id: envelope.key_id,
        rk_id: envelope.rk_id,
        rk_epoch: envelope.rk_epoch,
        context_digest: envelope.context_digest,
        slots: envelope.slots,
        ciphertext_sha256_b64,
        signature_key_id: signature.key_id.clone(),
        signature_sha256_b64,
    }))
}

pub fn validate_client_ckks_vector_payload_value_for_runtime(
    value: &Value,
    context: ClientCkksVectorValidationContext<'_>,
) -> Result<ClientCkksVectorVerifiedSidecarKey, CkksError> {
    let envelope = client_ckks_vector_envelope(value)?;
    validate_client_ckks_vector_common(&envelope, context.vector_name)?;
    if envelope.collection_id != context.collection_id {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector collection_id does not match collection".to_string(),
        ));
    }
    if envelope.point_id != context.point_id {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector point_id does not match point".to_string(),
        ));
    }
    if envelope.vector_name != context.vector_name {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector vector_name does not match sidecar path".to_string(),
        ));
    }
    if envelope.key_id != context.expected_key_id {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector key_id does not match active vector rule".to_string(),
        ));
    }
    if envelope.rk_id != context.expected_rk_id {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector rk_id does not match active vector rule".to_string(),
        ));
    }
    if envelope.rk_epoch < context.min_rk_epoch || envelope.rk_epoch > context.max_rk_epoch {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector rk_epoch is outside active policy".to_string(),
        ));
    }
    if envelope.context_digest != context.expected_context_digest {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector context_digest does not match active public material".to_string(),
        ));
    }
    if envelope.slots == 0 || envelope.slots > context.max_slots {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector slots are outside active CKKS profile".to_string(),
        ));
    }
    let signature = envelope.signature.as_ref().ok_or_else(|| {
        CkksError::MalformedEnvelope("client CKKS vector signature is missing".to_string())
    })?;
    if signature.key_id != context.signature_verification.expected_key_id {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector signature key_id does not match verifier".to_string(),
        ));
    }
    if context.signature_verification.public_key.len() != 32 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector signature public key must be 32 bytes".to_string(),
        ));
    }
    let signature_bytes = decode_client_ckks_vector_signature(signature)?;
    let message = client_ckks_vector_signature_message_for_envelope(&envelope);
    UnparsedPublicKey::new(&ED25519, context.signature_verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| {
            CkksError::MalformedEnvelope("client CKKS vector signature is invalid".to_string())
        })?;

    let Some(envelope_key) = client_ckks_vector_sidecar_envelope_key(value, context.vector_name)?
    else {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector marker is missing".to_string(),
        ));
    };
    Ok(ClientCkksVectorVerifiedSidecarKey { envelope_key })
}

fn optional_client_ckks_vector_envelope(
    value: &Value,
) -> Result<Option<ClientCkksVectorEnvelope>, CkksError> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(marker) = object.get(CLIENT_CKKS_VECTOR_MARKER) else {
        return Ok(None);
    };
    // The marker must be the only key: sibling keys next to the marker would let a caller
    // smuggle plaintext or shadow fields past the sidecar policy checks.
    if object.len() != 1 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector marker must be the only key of the sidecar value".to_string(),
        ));
    }
    serde_json::from_value(marker.clone())
        .map(Some)
        .map_err(|_| CkksError::MalformedEnvelope("CKKS sidecar marker is malformed".to_string()))
}

fn client_ckks_vector_envelope(value: &Value) -> Result<ClientCkksVectorEnvelope, CkksError> {
    optional_client_ckks_vector_envelope(value)?.ok_or_else(|| {
        CkksError::MalformedEnvelope("client CKKS vector marker is missing".to_string())
    })
}

fn validate_client_ckks_vector_common(
    envelope: &ClientCkksVectorEnvelope,
    vector_name: &str,
) -> Result<(), CkksError> {
    if envelope.version != VERSION {
        return Err(CkksError::UnsupportedEnvelopeVersion(envelope.version));
    }
    if envelope.scheme != CKKS_SCHEME {
        return Err(CkksError::UnsupportedScheme(envelope.scheme.clone()));
    }
    if envelope.security_profile != CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector security_profile is not allowlisted".to_string(),
        ));
    }
    validate_vector_name(&envelope.vector_name)?;
    if envelope.vector_name != vector_name {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector vector_name does not match sidecar key".to_string(),
        ));
    }
    if envelope.collection_id.is_empty()
        || envelope.point_id.is_empty()
        || envelope.collection_id.contains('\0')
        || envelope.point_id.contains('\0')
    {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector AAD identifiers are invalid".to_string(),
        ));
    }
    validate_resource_key_id(&envelope.collection_id).map_err(|_| {
        CkksError::MalformedEnvelope("client CKKS vector collection_id is invalid".to_string())
    })?;
    validate_key_id(&envelope.key_id).map_err(|_| {
        CkksError::MalformedEnvelope("client CKKS vector key_id is invalid".to_string())
    })?;
    validate_resource_key_id(&envelope.rk_id).map_err(|_| {
        CkksError::MalformedEnvelope("client CKKS vector rk_id is invalid".to_string())
    })?;
    if envelope.context_digest.len() != SHA256_B64_LEN {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector context_digest has invalid length".to_string(),
        ));
    }
    let digest = BASE64URL_NOPAD
        .decode(envelope.context_digest.as_bytes())
        .map_err(|_| {
            CkksError::MalformedEnvelope("client CKKS vector context_digest is invalid".to_string())
        })?;
    if digest.len() != 32 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector context_digest must decode to 32 bytes".to_string(),
        ));
    }
    if envelope.ciphertext_sha256.len() != SHA256_B64_LEN {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector ciphertext_sha256 has invalid length".to_string(),
        ));
    }
    let digest = BASE64URL_NOPAD
        .decode(envelope.ciphertext_sha256.as_bytes())
        .map_err(|_| {
            CkksError::MalformedEnvelope(
                "client CKKS vector ciphertext_sha256 is invalid".to_string(),
            )
        })?;
    if digest.len() != 32 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector ciphertext_sha256 must decode to 32 bytes".to_string(),
        ));
    }
    decode_stored_ciphertext(&envelope.ciphertext)?;
    Ok(())
}

fn decode_client_ckks_vector_signature(
    signature: &ClientCkksVectorSignature,
) -> Result<Vec<u8>, CkksError> {
    if signature.alg != CLIENT_CKKS_VECTOR_SIGNATURE_ALGORITHM {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector signature algorithm is unsupported".to_string(),
        ));
    }
    validate_resource_key_id(&signature.key_id).map_err(|_| {
        CkksError::MalformedEnvelope("client CKKS vector signature key_id is invalid".to_string())
    })?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| {
            CkksError::MalformedEnvelope(
                "client CKKS vector signature is invalid base64url".to_string(),
            )
        })?;
    if signature_bytes.len() != 64 {
        return Err(CkksError::MalformedEnvelope(
            "client CKKS vector signature must decode to 64 bytes".to_string(),
        ));
    }
    Ok(signature_bytes)
}

fn client_ckks_vector_signature_message_for_envelope(
    envelope: &ClientCkksVectorEnvelope,
) -> Vec<u8> {
    let mut message = Vec::new();
    let push_len_prefixed = |message: &mut Vec<u8>, value: &[u8]| {
        message.extend_from_slice(&(value.len() as u32).to_be_bytes());
        message.extend_from_slice(value);
    };
    push_len_prefixed(&mut message, CLIENT_CKKS_VECTOR_SIGNATURE_DOMAIN.as_bytes());
    message.push(envelope.version);
    push_len_prefixed(&mut message, envelope.scheme.as_bytes());
    push_len_prefixed(&mut message, envelope.security_profile.as_bytes());
    push_len_prefixed(&mut message, envelope.collection_id.as_bytes());
    push_len_prefixed(&mut message, envelope.point_id.as_bytes());
    push_len_prefixed(&mut message, envelope.vector_name.as_bytes());
    push_len_prefixed(&mut message, envelope.key_id.as_bytes());
    push_len_prefixed(&mut message, envelope.rk_id.as_bytes());
    message.extend_from_slice(&envelope.rk_epoch.to_be_bytes());
    push_len_prefixed(&mut message, envelope.context_digest.as_bytes());
    message.extend_from_slice(&(envelope.slots as u64).to_be_bytes());
    push_len_prefixed(&mut message, envelope.ciphertext_sha256.as_bytes());
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

impl Debug for EncryptedCkksVector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedCkksVector")
            .field("version", &self.version)
            .field("scheme", &self.scheme)
            .field("envelope", &self.envelope)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct ClientCkksVectorEnvelope {
    version: u8,
    scheme: String,
    security_profile: String,
    collection_id: String,
    point_id: String,
    vector_name: String,
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    context_digest: String,
    slots: usize,
    ciphertext_sha256: String,
    ciphertext: String,
    signature: Option<ClientCkksVectorSignature>,
}

impl Debug for ClientCkksVectorEnvelope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCkksVectorEnvelope")
            .field("version", &self.version)
            .field("scheme", &self.scheme)
            .field("security_profile", &self.security_profile)
            .field("collection_id", &"[redacted]")
            .field("point_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("context_digest", &"[redacted]")
            .field("slots", &self.slots)
            .field("ciphertext_sha256", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
struct ClientCkksVectorSignature {
    alg: String,
    key_id: String,
    sig: String,
}

impl Debug for ClientCkksVectorSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCkksVectorSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .field("sig_len", &self.sig.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct VerifiedCkksVector {
    #[serde(default = "default_crypto_schema_version")]
    pub crypto_schema_version: u16,
    #[serde(default)]
    pub encryption_epoch: u64,
    pub key_id: String,
    pub vector_name: String,
    pub slots: usize,
    pub context_digest: String,
    pub ciphertext: String,
}

impl Debug for VerifiedCkksVector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCkksVector")
            .field("crypto_schema_version", &self.crypto_schema_version)
            .field("encryption_epoch", &self.encryption_epoch)
            .field("key_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("slots", &self.slots)
            .field("context_digest", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

pub struct CkksVectorEncryptor<B> {
    metadata_keyring: AeadKeyring,
    vector_name: String,
    collection_identity: Option<String>,
    parameters: CkksParameters,
    crypto_schema_version: u16,
    encryption_epoch: u64,
    backend: B,
}

const fn default_crypto_schema_version() -> u16 {
    CRYPTO_SCHEMA_VERSION
}

impl<B> CkksVectorEncryptor<B>
where
    B: CkksVectorBackend,
{
    pub fn new_from_resource_key_with_material_fingerprint(
        key_id: impl Into<String>,
        vector_name: impl Into<String>,
        parameters: CkksParameters,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        backend: B,
    ) -> Result<Self, CkksError> {
        let key_id = key_id.into();
        let vector_name = Self::validate_constructor_inputs(&key_id, vector_name, &parameters)?;
        let metadata_key = resource_key.derive_subkey(CKKS_VECTOR_KEY_DOMAIN)?;

        Self::new_with_metadata_cipher(
            vector_name,
            parameters,
            AeadCipher::new_with_material_fingerprint(
                key_id,
                metadata_key,
                material_fingerprint_id,
            )?,
            backend,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_from_resource_key_with_metadata(
        key_id: impl Into<String>,
        vector_name: impl Into<String>,
        parameters: CkksParameters,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
        backend: B,
    ) -> Result<Self, CkksError> {
        let key_id = key_id.into();
        let vector_name = Self::validate_constructor_inputs(&key_id, vector_name, &parameters)?;
        let metadata_key = resource_key.derive_subkey(CKKS_VECTOR_KEY_DOMAIN)?;
        let metadata_cipher = AeadCipher::new_with_material_fingerprint(
            key_id,
            metadata_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;

        Self::new_with_metadata_cipher(vector_name, parameters, metadata_cipher, backend)
    }

    fn validate_constructor_inputs(
        key_id: &str,
        vector_name: impl Into<String>,
        parameters: &CkksParameters,
    ) -> Result<String, CkksError> {
        validate_key_id(key_id).map_err(|_| CkksError::InvalidKeyId)?;

        let vector_name = validate_vector_name(vector_name)?;

        parameters.validate()?;
        Ok(vector_name)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn new_with_metadata_cipher(
        vector_name: String,
        parameters: CkksParameters,
        metadata_cipher: AeadCipher,
        backend: B,
    ) -> Result<Self, CkksError> {
        Ok(Self {
            metadata_keyring: AeadKeyring::new(metadata_cipher),
            vector_name,
            collection_identity: None,
            parameters,
            crypto_schema_version: CRYPTO_SCHEMA_VERSION,
            encryption_epoch: DEFAULT_ENCRYPTION_EPOCH,
            backend,
        })
    }

    pub fn with_encryption_epoch(mut self, encryption_epoch: u64) -> Self {
        self.encryption_epoch = encryption_epoch;
        self
    }

    pub fn with_collection_identity(
        mut self,
        collection_identity: impl Into<String>,
    ) -> Result<Self, CkksError> {
        let collection_identity = collection_identity.into();
        Self::validate_context_value("collection identity", &collection_identity)?;
        self.collection_identity = Some(collection_identity);
        Ok(self)
    }

    fn collection_context<'a>(&'a self, collection: &'a str) -> Result<&'a str, CkksError> {
        Self::validate_context_value("collection", collection)?;
        Ok(self.collection_identity.as_deref().unwrap_or(collection))
    }

    fn validate_context_value(label: &str, value: &str) -> Result<(), CkksError> {
        if value.is_empty() || value.contains('\0') {
            return Err(CkksError::InvalidContext(format!(
                "{label} must be non-empty and must not contain NUL",
            )));
        }
        Ok(())
    }

    pub fn with_retired_metadata_resource_key(
        mut self,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, CkksError> {
        let key_id = key_id.into();
        validate_key_id(&key_id).map_err(|_| CkksError::InvalidKeyId)?;
        let metadata_key = resource_key.derive_subkey(CKKS_VECTOR_KEY_DOMAIN)?;
        let retired = AeadCipher::new_with_material_fingerprint(
            key_id,
            metadata_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;
        self.metadata_keyring = self.metadata_keyring.with_retired(retired);
        Ok(self)
    }

    pub fn with_retired_metadata_key_with_material_fingerprint(
        mut self,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
    ) -> Result<Self, CkksError> {
        let key_id = key_id.into();
        validate_key_id(&key_id).map_err(|_| CkksError::InvalidKeyId)?;
        let metadata_key = resource_key.derive_subkey(CKKS_VECTOR_KEY_DOMAIN)?;
        let retired = AeadCipher::new_with_material_fingerprint(
            key_id,
            metadata_key,
            material_fingerprint_id,
        )?;
        self.metadata_keyring = self.metadata_keyring.with_retired(retired);
        Ok(self)
    }

    fn validate_vector_values(&self, point_id: &str, values: &[f64]) -> Result<(), CkksError> {
        Self::validate_context_value("point_id", point_id)?;
        if values.is_empty() {
            return Err(CkksError::EmptyVector);
        }
        if values.len() > self.parameters.batch_size as usize {
            return Err(CkksError::VectorTooWide {
                len: values.len(),
                batch_size: self.parameters.batch_size as usize,
            });
        }
        if let Some((index, _)) = values
            .iter()
            .enumerate()
            .find(|(_, value)| !value.is_finite())
        {
            return Err(CkksError::NonFiniteValue { index });
        }

        Ok(())
    }

    fn seal_ciphertext(
        &self,
        collection_context: &str,
        point_id: &str,
        public_material: &CkksPublicMaterial,
        slots: usize,
        ciphertext: &[u8],
    ) -> Result<EncryptedCkksVector, CkksError> {
        if ciphertext.is_empty() {
            return Err(CkksError::EmptyCiphertext);
        }
        validate_raw_ciphertext_size(ciphertext)?;

        let envelope = self.metadata_keyring.encrypt_with_aad_suffix(
            serde_json::to_vec(&VerifiedCkksVector {
                crypto_schema_version: self.crypto_schema_version,
                encryption_epoch: self.encryption_epoch,
                key_id: self.metadata_keyring.key_id().to_string(),
                vector_name: self.vector_name.clone(),
                slots,
                context_digest: public_material.digest_for(&self.parameters),
                ciphertext: BASE64URL_NOPAD.encode(ciphertext),
            })
            .map_err(|err| CkksError::MalformedEnvelope(err.to_string()))?
            .as_slice(),
            EncryptionContext::ckks_vector(collection_context, point_id, &self.vector_name),
            &vector_metadata_aad(VERSION, CKKS_SCHEME),
        )?;

        Ok(EncryptedCkksVector {
            version: VERSION,
            scheme: CKKS_SCHEME.to_string(),
            envelope,
        })
    }

    pub fn encrypt(
        &self,
        collection: &str,
        point_id: &str,
        public_material: &CkksPublicMaterial,
        values: &[f64],
    ) -> Result<EncryptedCkksVector, CkksError> {
        let collection_context = self.collection_context(collection)?;
        self.validate_vector_values(point_id, values)?;

        let ciphertext = self.backend.encrypt(CkksEncryptionInput {
            parameters: &self.parameters,
            public_material,
            collection: collection_context,
            point_id,
            vector_name: &self.vector_name,
            values,
        })?;
        self.seal_ciphertext(
            collection_context,
            point_id,
            public_material,
            values.len(),
            &ciphertext,
        )
    }

    pub fn encrypt_sidecar_payload_value(
        &self,
        collection: &str,
        point_id: &str,
        public_material: &CkksPublicMaterial,
        values: &[f64],
    ) -> Result<(Value, CkksVectorVerifiedSidecarKey), CkksError> {
        let collection_context = self.collection_context(collection)?;
        let encrypted = self.encrypt(collection, point_id, public_material, values)?;
        let value = encrypted_ckks_vector_payload_value(&encrypted)?;
        let verified_sidecar_key = ckks_vector_verified_sidecar_key(
            &value,
            collection_context,
            point_id,
            &self.vector_name,
        )?;
        Ok((value, verified_sidecar_key))
    }

    /// Authenticates a stored sidecar payload value produced by this encryptor and returns its
    /// verified sidecar key, so a runtime that has to rewrite the full sidecar of a point (for
    /// example because a sibling vector was updated) can carry an untouched entry forward.
    pub fn verify_stored_sidecar_payload_value(
        &self,
        collection: &str,
        point_id: &str,
        public_material: &CkksPublicMaterial,
        value: &Value,
    ) -> Result<Option<CkksVectorVerifiedSidecarKey>, CkksError> {
        let Some(object) = value.as_object() else {
            return Ok(None);
        };
        let Some(marker) = object.get(ENCRYPTED_CKKS_VECTOR_MARKER) else {
            return Ok(None);
        };
        if object.len() != 1 {
            return Err(CkksError::MalformedEnvelope(
                "encrypted CKKS vector marker must be the only key of the sidecar value"
                    .to_string(),
            ));
        }
        let encrypted: EncryptedCkksVector =
            serde_json::from_value(marker.clone()).map_err(|_| {
                CkksError::MalformedEnvelope("CKKS sidecar marker is malformed".to_string())
            })?;
        self.open(collection, point_id, public_material, &encrypted)?;
        let collection_context = self.collection_context(collection)?;
        ckks_vector_verified_sidecar_key(value, collection_context, point_id, &self.vector_name)
            .map(Some)
    }

    pub fn encrypt_batch(
        &self,
        collection: &str,
        public_material: &CkksPublicMaterial,
        items: &[CkksVectorBatchItem<'_>],
    ) -> Result<Vec<EncryptedCkksVector>, CkksError> {
        let collection_context = self.collection_context(collection)?;
        for item in items {
            self.validate_vector_values(item.point_id, item.values)?;
        }

        let ciphertexts = self.backend.encrypt_batch(CkksBatchEncryptionInput {
            parameters: &self.parameters,
            public_material,
            collection: collection_context,
            vector_name: &self.vector_name,
            items,
        })?;
        if ciphertexts.len() != items.len() {
            return Err(CkksError::BackendBatchSizeMismatch {
                expected: items.len(),
                actual: ciphertexts.len(),
            });
        }

        items
            .iter()
            .zip(ciphertexts)
            .map(|(item, ciphertext)| {
                self.seal_ciphertext(
                    collection_context,
                    item.point_id,
                    public_material,
                    item.values.len(),
                    &ciphertext,
                )
            })
            .collect()
    }

    pub fn open(
        &self,
        collection: &str,
        point_id: &str,
        expected_public_material: &CkksPublicMaterial,
        encrypted: &EncryptedCkksVector,
    ) -> Result<VerifiedCkksVector, CkksError> {
        if encrypted.version != VERSION {
            return Err(CkksError::UnsupportedEnvelopeVersion(encrypted.version));
        }
        if encrypted.scheme != CKKS_SCHEME {
            return Err(CkksError::UnsupportedScheme(encrypted.scheme.clone()));
        }
        let collection_context = self.collection_context(collection)?;
        Self::validate_context_value("point_id", point_id)?;

        let verified: VerifiedCkksVector =
            serde_json::from_slice(&self.metadata_keyring.decrypt_with_aad_suffix(
                &encrypted.envelope,
                EncryptionContext::ckks_vector(collection_context, point_id, &self.vector_name),
                &vector_metadata_aad(encrypted.version, &encrypted.scheme),
            )?)
            .map_err(|err| CkksError::MalformedEnvelope(err.to_string()))?;

        if verified.key_id != encrypted.envelope.key_id {
            return Err(CkksError::MalformedEnvelope(
                "stored key id does not match envelope key id".to_string(),
            ));
        }
        if verified.crypto_schema_version != self.crypto_schema_version {
            return Err(CkksError::UnsupportedCryptoSchemaVersion(
                verified.crypto_schema_version,
            ));
        }
        if verified.encryption_epoch != self.encryption_epoch {
            return Err(CkksError::EncryptionEpochMismatch);
        }
        if verified.vector_name != self.vector_name {
            return Err(CkksError::MalformedEnvelope(
                "stored vector name does not match encryptor".to_string(),
            ));
        }
        if verified.slots == 0 || verified.slots > self.parameters.batch_size as usize {
            return Err(CkksError::MalformedEnvelope(
                "stored slot count is out of range".to_string(),
            ));
        }
        let digest = BASE64URL_NOPAD
            .decode(verified.context_digest.as_bytes())
            .map_err(|_| {
                CkksError::MalformedEnvelope("stored context digest is invalid".to_string())
            })?;
        if digest.len() != 32 {
            return Err(CkksError::MalformedEnvelope(
                "stored context digest has unexpected length".to_string(),
            ));
        }
        if verified.context_digest != expected_public_material.digest_for(&self.parameters) {
            return Err(CkksError::MalformedEnvelope(
                "stored context digest does not match active context".to_string(),
            ));
        }
        Self::decode_verified_ciphertext(&verified)?;

        Ok(verified)
    }

    fn decode_verified_ciphertext(verified: &VerifiedCkksVector) -> Result<Vec<u8>, CkksError> {
        decode_stored_ciphertext(&verified.ciphertext)
    }

    pub fn score_plaintext_query(
        &self,
        collection: &str,
        point_id: &str,
        expected_public_material: &CkksPublicMaterial,
        encrypted: &EncryptedCkksVector,
        distance: &str,
        query_values: &[f64],
    ) -> Result<f64, CkksError> {
        self.validate_vector_values(point_id, query_values)?;
        let collection_context = self.collection_context(collection)?;
        let verified = self.open(collection, point_id, expected_public_material, encrypted)?;
        if verified.slots != query_values.len() {
            return Err(CkksError::QueryDimensionMismatch {
                query_len: query_values.len(),
                slots: verified.slots,
            });
        }
        let ciphertext = Self::decode_verified_ciphertext(&verified)?;
        let score = self
            .backend
            .score_plaintext_query(CkksPlaintextQueryScoreInput {
                parameters: &self.parameters,
                public_material: expected_public_material,
                collection: collection_context,
                point_id,
                vector_name: &self.vector_name,
                distance,
                query_values,
                ciphertext: &ciphertext,
            })?;
        if !score.is_finite() {
            return Err(CkksError::Backend(
                "OpenFHE backend returned non-finite score".to_string(),
            ));
        }

        Ok(score)
    }

    pub fn score_plaintext_query_batch(
        &self,
        collection: &str,
        expected_public_material: &CkksPublicMaterial,
        encrypted_items: &[(&str, &EncryptedCkksVector)],
        distance: &str,
        query_values: &[f64],
    ) -> Result<Vec<f64>, CkksError> {
        if encrypted_items.is_empty() {
            return Ok(Vec::new());
        }

        self.validate_vector_values(encrypted_items[0].0, query_values)?;
        let collection_context = self.collection_context(collection)?;
        let mut ciphertexts = Vec::with_capacity(encrypted_items.len());

        for (point_id, encrypted) in encrypted_items {
            let verified = self.open(collection, point_id, expected_public_material, encrypted)?;
            if verified.slots != query_values.len() {
                return Err(CkksError::QueryDimensionMismatch {
                    query_len: query_values.len(),
                    slots: verified.slots,
                });
            }
            ciphertexts.push((*point_id, Self::decode_verified_ciphertext(&verified)?));
        }

        let items = ciphertexts
            .iter()
            .map(|(point_id, ciphertext)| CkksPlaintextQueryScoreBatchItem {
                point_id,
                ciphertext,
            })
            .collect::<Vec<_>>();
        let scores =
            self.backend
                .score_plaintext_query_batch(CkksPlaintextQueryScoreBatchInput {
                    parameters: &self.parameters,
                    public_material: expected_public_material,
                    collection: collection_context,
                    vector_name: &self.vector_name,
                    distance,
                    query_values,
                    items: &items,
                })?;
        if scores.len() != encrypted_items.len() {
            return Err(CkksError::Backend(format!(
                "OpenFHE backend returned {} scores for {} encrypted vectors",
                scores.len(),
                encrypted_items.len(),
            )));
        }
        if scores.iter().any(|score| !score.is_finite()) {
            return Err(CkksError::Backend(
                "OpenFHE backend returned non-finite score".to_string(),
            ));
        }

        Ok(scores)
    }

    pub fn encrypt_query(
        &self,
        collection: &str,
        expected_public_material: &CkksPublicMaterial,
        query_values: &[f64],
    ) -> Result<Vec<u8>, CkksError> {
        self.validate_vector_values("__ckks_query__", query_values)?;
        let collection_context = self.collection_context(collection)?;
        let ciphertext = self.backend.encrypt_query(CkksQueryEncryptionInput {
            parameters: &self.parameters,
            public_material: expected_public_material,
            collection: collection_context,
            vector_name: &self.vector_name,
            values: query_values,
        })?;
        if ciphertext.is_empty() {
            return Err(CkksError::EmptyCiphertext);
        }
        validate_raw_ciphertext_size(&ciphertext)?;

        Ok(ciphertext)
    }

    pub fn context_digest_for(&self, public_material: &CkksPublicMaterial) -> String {
        public_material.digest_for(&self.parameters)
    }

    pub fn validate_pre_encrypted_query_input(
        &self,
        encrypted_query: &[u8],
        slots: usize,
    ) -> Result<(), CkksError> {
        if encrypted_query.is_empty() {
            return Err(CkksError::EmptyCiphertext);
        }
        validate_raw_ciphertext_size(encrypted_query)?;
        if slots == 0 {
            return Err(CkksError::EmptyVector);
        }
        if slots > self.parameters.batch_size as usize {
            return Err(CkksError::VectorTooWide {
                len: slots,
                batch_size: self.parameters.batch_size as usize,
            });
        }

        Ok(())
    }

    pub fn score_encrypted_query_batch(
        &self,
        collection: &str,
        expected_public_material: &CkksPublicMaterial,
        encrypted_items: &[(&str, &EncryptedCkksVector)],
        distance: &str,
        query_values: &[f64],
    ) -> Result<Vec<f64>, CkksError> {
        if encrypted_items.is_empty() {
            return Ok(Vec::new());
        }

        let encrypted_query =
            self.encrypt_query(collection, expected_public_material, query_values)?;
        let collection_context = self.collection_context(collection)?;
        let mut ciphertexts = Vec::with_capacity(encrypted_items.len());

        for (point_id, encrypted) in encrypted_items {
            let verified = self.open(collection, point_id, expected_public_material, encrypted)?;
            if verified.slots != query_values.len() {
                return Err(CkksError::QueryDimensionMismatch {
                    query_len: query_values.len(),
                    slots: verified.slots,
                });
            }
            ciphertexts.push((*point_id, Self::decode_verified_ciphertext(&verified)?));
        }

        let items = ciphertexts
            .iter()
            .map(|(point_id, ciphertext)| CkksEncryptedQueryScoreBatchItem {
                point_id,
                ciphertext,
            })
            .collect::<Vec<_>>();
        let scores =
            self.backend
                .score_encrypted_query_batch(CkksEncryptedQueryScoreBatchInput {
                    parameters: &self.parameters,
                    public_material: expected_public_material,
                    collection: collection_context,
                    vector_name: &self.vector_name,
                    distance,
                    encrypted_query: &encrypted_query,
                    items: &items,
                })?;
        if scores.len() != encrypted_items.len() {
            return Err(CkksError::Backend(format!(
                "OpenFHE backend returned {} scores for {} encrypted vectors",
                scores.len(),
                encrypted_items.len(),
            )));
        }
        if scores.iter().any(|score| !score.is_finite()) {
            return Err(CkksError::Backend(
                "OpenFHE backend returned non-finite score".to_string(),
            ));
        }

        Ok(scores)
    }

    pub fn score_pre_encrypted_query_batch(
        &self,
        collection: &str,
        expected_public_material: &CkksPublicMaterial,
        encrypted_query: &[u8],
        slots: usize,
        encrypted_items: &[(&str, &EncryptedCkksVector)],
        distance: &str,
    ) -> Result<Vec<f64>, CkksError> {
        self.validate_pre_encrypted_query_input(encrypted_query, slots)?;
        if encrypted_items.is_empty() {
            return Ok(Vec::new());
        }

        let collection_context = self.collection_context(collection)?;
        let mut ciphertexts = Vec::with_capacity(encrypted_items.len());

        for (point_id, encrypted) in encrypted_items {
            let verified = self.open(collection, point_id, expected_public_material, encrypted)?;
            if verified.slots != slots {
                return Err(CkksError::QueryDimensionMismatch {
                    query_len: slots,
                    slots: verified.slots,
                });
            }
            ciphertexts.push((*point_id, Self::decode_verified_ciphertext(&verified)?));
        }

        let items = ciphertexts
            .iter()
            .map(|(point_id, ciphertext)| CkksEncryptedQueryScoreBatchItem {
                point_id,
                ciphertext,
            })
            .collect::<Vec<_>>();
        let scores =
            self.backend
                .score_encrypted_query_batch(CkksEncryptedQueryScoreBatchInput {
                    parameters: &self.parameters,
                    public_material: expected_public_material,
                    collection: collection_context,
                    vector_name: &self.vector_name,
                    distance,
                    encrypted_query,
                    items: &items,
                })?;
        if scores.len() != encrypted_items.len() {
            return Err(CkksError::Backend(format!(
                "OpenFHE backend returned {} scores for {} encrypted vectors",
                scores.len(),
                encrypted_items.len(),
            )));
        }
        if scores.iter().any(|score| !score.is_finite()) {
            return Err(CkksError::Backend(
                "OpenFHE backend returned non-finite score".to_string(),
            ));
        }

        Ok(scores)
    }

    pub fn score_stored_query_batch(
        &self,
        collection: &str,
        expected_public_material: &CkksPublicMaterial,
        query_point_id: &str,
        query_encrypted: &EncryptedCkksVector,
        encrypted_items: &[(&str, &EncryptedCkksVector)],
        distance: &str,
    ) -> Result<Vec<f64>, CkksError> {
        if encrypted_items.is_empty() {
            return Ok(Vec::new());
        }

        let query_verified = self.open(
            collection,
            query_point_id,
            expected_public_material,
            query_encrypted,
        )?;
        let encrypted_query = Self::decode_verified_ciphertext(&query_verified)?;
        let collection_context = self.collection_context(collection)?;
        let mut ciphertexts = Vec::with_capacity(encrypted_items.len());

        for (point_id, encrypted) in encrypted_items {
            let verified = self.open(collection, point_id, expected_public_material, encrypted)?;
            if verified.slots != query_verified.slots {
                return Err(CkksError::QueryDimensionMismatch {
                    query_len: query_verified.slots,
                    slots: verified.slots,
                });
            }
            ciphertexts.push((*point_id, Self::decode_verified_ciphertext(&verified)?));
        }

        let items = ciphertexts
            .iter()
            .map(|(point_id, ciphertext)| CkksEncryptedQueryScoreBatchItem {
                point_id,
                ciphertext,
            })
            .collect::<Vec<_>>();
        let scores =
            self.backend
                .score_encrypted_query_batch(CkksEncryptedQueryScoreBatchInput {
                    parameters: &self.parameters,
                    public_material: expected_public_material,
                    collection: collection_context,
                    vector_name: &self.vector_name,
                    distance,
                    encrypted_query: &encrypted_query,
                    items: &items,
                })?;
        if scores.len() != encrypted_items.len() {
            return Err(CkksError::Backend(format!(
                "OpenFHE backend returned {} scores for {} encrypted vectors",
                scores.len(),
                encrypted_items.len(),
            )));
        }
        if scores.iter().any(|score| !score.is_finite()) {
            return Err(CkksError::Backend(
                "OpenFHE backend returned non-finite score".to_string(),
            ));
        }

        Ok(scores)
    }
}

fn vector_metadata_aad(version: u8, scheme: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&(scheme.len() as u32).to_be_bytes());
    aad.extend_from_slice(scheme.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ckks_parameter_profile_registry_roundtrips_current_profile() {
        let parameters =
            CkksParameters::from_security_profile(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50)
                .expect("current OpenFHE profile must be registered");
        assert_eq!(parameters, CkksParameters::openfhe_default_128_bit());
        assert_eq!(
            parameters.security_profile(),
            Some(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50),
        );

        let mut smaller_batch = parameters;
        smaller_batch.batch_size = 128;
        assert_eq!(
            smaller_batch.security_profile(),
            Some(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50),
        );
        smaller_batch.validate().unwrap();

        assert!(CkksParameters::from_security_profile("ckks-raw-unsafe").is_none());
    }

    #[test]
    fn ckks_backend_input_debug_redacts_identifiers() {
        let parameters = CkksParameters::default();
        let public_material = CkksPublicMaterial::new(
            b"CKKS-BACKEND-CONTEXT-SENTINEL".to_vec(),
            b"CKKS-BACKEND-PUBLIC-KEY-SENTINEL".to_vec(),
        )
        .unwrap();
        let values = [1.25, 2.5];
        let query_values = [3.75, 4.5];
        let ciphertext = b"CKKS-BACKEND-CIPHERTEXT-SENTINEL";
        let encrypted_query = b"CKKS-BACKEND-QUERY-SENTINEL";
        let vector_items = [CkksVectorBatchItem {
            point_id: "CKKS-BACKEND-BATCH-POINT-SENTINEL",
            values: &values,
        }];
        let plaintext_items = [CkksPlaintextQueryScoreBatchItem {
            point_id: "CKKS-BACKEND-PLAINTEXT-BATCH-POINT-SENTINEL",
            ciphertext,
        }];
        let encrypted_items = [CkksEncryptedQueryScoreBatchItem {
            point_id: "CKKS-BACKEND-ENCRYPTED-BATCH-POINT-SENTINEL",
            ciphertext,
        }];
        let verified = VerifiedCkksVector {
            crypto_schema_version: 1,
            encryption_epoch: 7,
            key_id: "CKKS-BACKEND-VERIFIED-KEY-SENTINEL".to_string(),
            vector_name: "CKKS-BACKEND-VERIFIED-VECTOR-SENTINEL".to_string(),
            slots: 2,
            context_digest: "CKKS-BACKEND-VERIFIED-CONTEXT-SENTINEL".to_string(),
            ciphertext: "CKKS-BACKEND-VERIFIED-CIPHERTEXT-SENTINEL".to_string(),
        };

        let rendered = [
            format!(
                "{:?}",
                CkksEncryptionInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-COLLECTION-SENTINEL",
                    point_id: "CKKS-BACKEND-POINT-SENTINEL",
                    vector_name: "CKKS-BACKEND-VECTOR-SENTINEL",
                    values: &values,
                }
            ),
            format!("{:?}", vector_items[0]),
            format!(
                "{:?}",
                CkksBatchEncryptionInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-BATCH-COLLECTION-SENTINEL",
                    vector_name: "CKKS-BACKEND-BATCH-VECTOR-SENTINEL",
                    items: &vector_items,
                }
            ),
            format!(
                "{:?}",
                CkksPlaintextQueryScoreInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-PLAINTEXT-COLLECTION-SENTINEL",
                    point_id: "CKKS-BACKEND-PLAINTEXT-POINT-SENTINEL",
                    vector_name: "CKKS-BACKEND-PLAINTEXT-VECTOR-SENTINEL",
                    distance: "cosine",
                    query_values: &query_values,
                    ciphertext,
                }
            ),
            format!("{:?}", plaintext_items[0]),
            format!(
                "{:?}",
                CkksPlaintextQueryScoreBatchInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-PLAINTEXT-BATCH-COLLECTION-SENTINEL",
                    vector_name: "CKKS-BACKEND-PLAINTEXT-BATCH-VECTOR-SENTINEL",
                    distance: "cosine",
                    query_values: &query_values,
                    items: &plaintext_items,
                }
            ),
            format!(
                "{:?}",
                CkksQueryEncryptionInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-QUERY-COLLECTION-SENTINEL",
                    vector_name: "CKKS-BACKEND-QUERY-VECTOR-SENTINEL",
                    values: &query_values,
                }
            ),
            format!(
                "{:?}",
                CkksEncryptedQueryScoreInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-ENCRYPTED-COLLECTION-SENTINEL",
                    point_id: "CKKS-BACKEND-ENCRYPTED-POINT-SENTINEL",
                    vector_name: "CKKS-BACKEND-ENCRYPTED-VECTOR-SENTINEL",
                    distance: "cosine",
                    encrypted_query,
                    ciphertext,
                }
            ),
            format!("{:?}", encrypted_items[0]),
            format!(
                "{:?}",
                CkksEncryptedQueryScoreBatchInput {
                    parameters: &parameters,
                    public_material: &public_material,
                    collection: "CKKS-BACKEND-ENCRYPTED-BATCH-COLLECTION-SENTINEL",
                    vector_name: "CKKS-BACKEND-ENCRYPTED-BATCH-VECTOR-SENTINEL",
                    distance: "cosine",
                    encrypted_query,
                    items: &encrypted_items,
                }
            ),
            format!("{verified:?}"),
        ]
        .join("\n");

        for leaked in [
            "CKKS-BACKEND-CONTEXT-SENTINEL",
            "CKKS-BACKEND-PUBLIC-KEY-SENTINEL",
            "CKKS-BACKEND-COLLECTION-SENTINEL",
            "CKKS-BACKEND-POINT-SENTINEL",
            "CKKS-BACKEND-VECTOR-SENTINEL",
            "CKKS-BACKEND-BATCH-POINT-SENTINEL",
            "CKKS-BACKEND-BATCH-COLLECTION-SENTINEL",
            "CKKS-BACKEND-BATCH-VECTOR-SENTINEL",
            "CKKS-BACKEND-PLAINTEXT-COLLECTION-SENTINEL",
            "CKKS-BACKEND-PLAINTEXT-POINT-SENTINEL",
            "CKKS-BACKEND-PLAINTEXT-VECTOR-SENTINEL",
            "CKKS-BACKEND-PLAINTEXT-BATCH-POINT-SENTINEL",
            "CKKS-BACKEND-PLAINTEXT-BATCH-COLLECTION-SENTINEL",
            "CKKS-BACKEND-PLAINTEXT-BATCH-VECTOR-SENTINEL",
            "CKKS-BACKEND-QUERY-COLLECTION-SENTINEL",
            "CKKS-BACKEND-QUERY-VECTOR-SENTINEL",
            "CKKS-BACKEND-ENCRYPTED-COLLECTION-SENTINEL",
            "CKKS-BACKEND-ENCRYPTED-POINT-SENTINEL",
            "CKKS-BACKEND-ENCRYPTED-VECTOR-SENTINEL",
            "CKKS-BACKEND-ENCRYPTED-BATCH-POINT-SENTINEL",
            "CKKS-BACKEND-ENCRYPTED-BATCH-COLLECTION-SENTINEL",
            "CKKS-BACKEND-ENCRYPTED-BATCH-VECTOR-SENTINEL",
            "CKKS-BACKEND-CIPHERTEXT-SENTINEL",
            "CKKS-BACKEND-QUERY-SENTINEL",
            "CKKS-BACKEND-VERIFIED-KEY-SENTINEL",
            "CKKS-BACKEND-VERIFIED-VECTOR-SENTINEL",
            "CKKS-BACKEND-VERIFIED-CONTEXT-SENTINEL",
            "CKKS-BACKEND-VERIFIED-CIPHERTEXT-SENTINEL",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
    }

    #[test]
    fn client_ckks_vector_debug_redacts_envelope_and_sidecar_identifiers() {
        let signature = ClientCkksVectorSignature {
            alg: "ed25519".to_string(),
            key_id: "CLIENT-CKKS-SIGNING-KEY-SENTINEL".to_string(),
            sig: "CLIENT-CKKS-SIGNATURE-SENTINEL".to_string(),
        };
        let rendered = format!("{signature:?}");

        assert!(rendered.contains("sig_len"));
        assert!(!rendered.contains("CLIENT-CKKS-SIGNING-KEY-SENTINEL"));
        assert!(!rendered.contains("CLIENT-CKKS-SIGNATURE-SENTINEL"));

        let envelope = ClientCkksVectorEnvelope {
            version: VERSION,
            scheme: CKKS_SCHEME.to_string(),
            security_profile: CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50.to_string(),
            collection_id: "CLIENT-CKKS-COLLECTION-SENTINEL".to_string(),
            point_id: "CLIENT-CKKS-POINT-SENTINEL".to_string(),
            vector_name: "CLIENT-CKKS-VECTOR-SENTINEL".to_string(),
            key_id: "CLIENT-CKKS-KEY-SENTINEL".to_string(),
            rk_id: "CLIENT-CKKS-RK-SENTINEL".to_string(),
            rk_epoch: 7,
            context_digest: "CLIENT-CKKS-CONTEXT-SENTINEL".to_string(),
            slots: 4,
            ciphertext_sha256: "CLIENT-CKKS-SHA-SENTINEL".to_string(),
            ciphertext: "CLIENT-CKKS-CIPHERTEXT-SENTINEL".to_string(),
            signature: Some(signature),
        };
        let envelope_debug = format!("{envelope:?}");
        assert!(envelope_debug.contains("ciphertext_len"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-COLLECTION-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-POINT-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-VECTOR-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-KEY-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-RK-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-CONTEXT-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-SHA-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-CIPHERTEXT-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-SIGNING-KEY-SENTINEL"));
        assert!(!envelope_debug.contains("CLIENT-CKKS-SIGNATURE-SENTINEL"));

        let sidecar_key = ClientCkksVectorSidecarEnvelopeKey {
            collection_id: "CLIENT-CKKS-COLLECTION-SENTINEL".to_string(),
            point_id: "CLIENT-CKKS-POINT-SENTINEL".to_string(),
            vector_name: "CLIENT-CKKS-VECTOR-SENTINEL".to_string(),
            key_id: "CLIENT-CKKS-KEY-SENTINEL".to_string(),
            rk_id: "CLIENT-CKKS-RK-SENTINEL".to_string(),
            rk_epoch: 7,
            context_digest: "CLIENT-CKKS-CONTEXT-SENTINEL".to_string(),
            slots: 4,
            ciphertext_sha256_b64: "CLIENT-CKKS-SHA-SENTINEL".to_string(),
            signature_key_id: "CLIENT-CKKS-SIGNING-KEY-SENTINEL".to_string(),
            signature_sha256_b64: "CLIENT-CKKS-SIGNATURE-SHA-SENTINEL".to_string(),
        };
        let verified_key = ClientCkksVectorVerifiedSidecarKey {
            envelope_key: sidecar_key,
        };
        let verified_key_debug = format!("{verified_key:?}");
        assert!(verified_key_debug.contains("slots"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-COLLECTION-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-POINT-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-VECTOR-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-KEY-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-RK-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-CONTEXT-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-SHA-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-SIGNING-KEY-SENTINEL"));
        assert!(!verified_key_debug.contains("CLIENT-CKKS-SIGNATURE-SHA-SENTINEL"));

        let server_sidecar_key = CkksVectorSidecarEnvelopeKey {
            collection_id: "SERVER-CKKS-COLLECTION-SENTINEL".to_string(),
            point_id: "SERVER-CKKS-POINT-SENTINEL".to_string(),
            vector_name: "SERVER-CKKS-VECTOR-SENTINEL".to_string(),
            envelope_version: VERSION,
            envelope_algorithm: "AES-256-GCM".to_string(),
            key_id: "SERVER-CKKS-KEY-SENTINEL".to_string(),
            material_fingerprint: "SERVER-CKKS-MATERIAL-FINGERPRINT-SENTINEL".to_string(),
            rk_id: "SERVER-CKKS-RK-SENTINEL".to_string(),
            rk_epoch: Some(7),
            nonce: "SERVER-CKKS-NONCE-SENTINEL".to_string(),
            ciphertext_sha256_b64: "SERVER-CKKS-CIPHERTEXT-SHA-SENTINEL".to_string(),
        };
        let server_verified_key = CkksVectorVerifiedSidecarKey {
            envelope_key: server_sidecar_key,
        };
        let server_verified_debug = format!("{server_verified_key:?}");
        assert!(server_verified_debug.contains("envelope_version"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-COLLECTION-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-POINT-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-VECTOR-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-KEY-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-MATERIAL-FINGERPRINT-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-RK-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-NONCE-SENTINEL"));
        assert!(!server_verified_debug.contains("SERVER-CKKS-CIPHERTEXT-SHA-SENTINEL"));

        let delete_key = CkksVectorVerifiedSidecarDeleteKey {
            collection_id: "SERVER-CKKS-DELETE-COLLECTION-SENTINEL".to_string(),
            vector_name: "SERVER-CKKS-DELETE-VECTOR-SENTINEL".to_string(),
            target: CkksVectorSidecarDeleteTarget::PointIds {
                digest_b64: "SERVER-CKKS-DELETE-DIGEST-SENTINEL".to_string(),
            },
        };
        let delete_debug = format!("{delete_key:?}");
        assert!(!delete_debug.contains("SERVER-CKKS-DELETE-COLLECTION-SENTINEL"));
        assert!(!delete_debug.contains("SERVER-CKKS-DELETE-VECTOR-SENTINEL"));
        assert!(!delete_debug.contains("SERVER-CKKS-DELETE-DIGEST-SENTINEL"));
    }
}
