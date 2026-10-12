use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::aead::{AeadInvocationBudget, EncryptionError, SecretKey, validate_resource_key_id};
use crate::control_plane::{PRIVATE_HNSW_ORAM_BINDING, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER};
use crate::private_hnsw_oram::{
    DistanceKind, FixedBudgetParams, OramParams, PrivateHnswManifestValidationContext,
    PrivateHnswOramBucket, PrivateHnswOramCommitBucketRef, PrivateHnswOramCommitSignatureInput,
    PrivateHnswOramManifest, PrivateHnswOramReadPathsSignatureInput, PrivateHnswOramSignature,
    PrivateHnswParams, ResultPrivacyMode, private_hnsw_oram_bucket_ciphertext_bytes,
    try_private_hnsw_oram_commit_signature_message,
    try_private_hnsw_oram_manifest_signature_message,
    try_private_hnsw_oram_read_paths_signature_message, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_manifest_shape, validate_private_hnsw_oram_manifest_signature_shape,
};
use crate::private_result_oram::{
    PrivateResultOramPayloadBlockPlaintext, PrivateResultOramTokenFetchResult,
};

pub const PRIVATE_HNSW_NODE_AEAD_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-node-aead/v1";
pub const PRIVATE_HNSW_BUCKET_AEAD_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-bucket-aead/v1";
pub const PRIVATE_HNSW_POSITION_MAP_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-position-map/v1";
pub const PRIVATE_HNSW_PAYLOAD_TOKEN_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-payload-token/v1";
pub const PRIVATE_HNSW_BLIND_RESULT_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-blind-result/v1";
const PRIVATE_HNSW_CLIENT_KDF_CONTEXT_DOMAIN: &[u8] =
    b"qdrant-sec/private-hnsw-client-kdf-context/v1";

const NODE_BLOCK_MAGIC: &[u8; 4] = b"QPHO";
pub const PRIVATE_HNSW_NODE_BLOCK_VERSION: u16 = 1;
const NODE_BLOCK_VERSION: u16 = PRIVATE_HNSW_NODE_BLOCK_VERSION;
const BUCKET_PLAINTEXT_MAGIC: &[u8; 4] = b"QPHB";
const BUCKET_PLAINTEXT_VERSION: u16 = 1;
const BUCKET_AEAD_VERSION: u8 = 1;
const BUCKET_AEAD_NONCE_LEN: usize = 12;
const BUCKET_AEAD_TAG_LEN: usize = 16;
const PRIVATE_HNSW_BUCKET_AEAD_CONTEXT_DOMAIN: &str = "qdrant-sec/private-hnsw-oram-bucket-aead/v1";
const PRIVATE_HNSW_BUCKET_COMMITMENT_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-bucket-commitment/v1";
const PRIVATE_HNSW_CLIENT_STATE_AEAD_CONTEXT_DOMAIN: &str =
    "qdrant-sec/private-hnsw-client-state-aead/v1";
const PRIVATE_HNSW_LEVEL_ASSIGNMENT_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-level-assignment/v1";
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_8_BYTE_LEN: usize = 11;
const PRIVATE_HNSW_BUCKET_CIPHERTEXT_OPEN_MAX_BYTES: usize = 64 * 1024 * 1024;
const PRIVATE_HNSW_CLIENT_STATE_CIPHERTEXT_MAX_BYTES: usize = 256 * 1024 * 1024;
const PRIVATE_HNSW_MERKLE_PROOF_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;
const CLIENT_STATE_SNAPSHOT_VERSION: u16 = 1;
const CLIENT_STATE_AEAD_VERSION: u16 = 1;
pub const PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";

#[derive(Error, PartialEq, Eq)]
pub enum PrivateHnswClientError {
    #[error("private HNSW client encryption failed")]
    Encryption(EncryptionError),
    #[error("private HNSW node block has invalid neighbor shape")]
    InvalidNeighborShape,
    #[error("private HNSW node block has too many neighbors")]
    TooManyNeighbors { actual: usize, limit: usize },
    #[error("private HNSW node block vector is too large")]
    VectorTooLarge,
    #[error("private HNSW node block fixed neighbor slot count is too large")]
    FixedNeighborSlotsTooLarge,
    #[error("private HNSW node block does not fit in configured block size")]
    EncodedBlockOversized,
    #[error("private HNSW node block encoding is malformed")]
    InvalidBlockEncoding,
    #[error("private HNSW node block uses unsupported version")]
    UnsupportedBlockVersion(u16),
    #[error("private HNSW node block uses unsupported vector encoding")]
    UnsupportedVectorEncoding(u8),
    #[error("private HNSW node block padding is invalid")]
    InvalidBlockPadding,
    #[error("private HNSW bucket context is invalid")]
    InvalidBucketContext(&'static str),
    #[error("private HNSW bucket ciphertext is not base64url")]
    InvalidBucketCiphertextEncoding,
    #[error("private HNSW bucket ciphertext length does not match expected fixed length")]
    BucketCiphertextSizeMismatch {
        bucket_id: u64,
        expected_bytes: usize,
        actual_bytes: usize,
    },
    #[error("private HNSW bucket ciphertext hash is invalid")]
    InvalidBucketCiphertextHash,
    #[error("private HNSW bucket commitment is invalid")]
    InvalidBucketCommitment,
    #[error("private HNSW bucket metadata does not match the decrypt context")]
    BucketMetadataMismatch,
    #[error("private HNSW bucket uses unsupported ciphertext version")]
    UnsupportedBucketCiphertextVersion(u8),
    #[error("private HNSW bucket ciphertext authentication failed")]
    BucketOpenFailed,
    #[error("private HNSW ORAM tree_height must be between 1 and 62 for Path ORAM path decoding")]
    InvalidTreeHeight,
    #[error("private HNSW ORAM leaf label is outside ORAM tree range")]
    LeafOutOfRange,
    #[error("private HNSW ORAM leaf label is not base64url")]
    InvalidLeafLabelEncoding,
    #[error("private HNSW ORAM leaf label must encode an 8-byte u64")]
    InvalidLeafLabelLength,
    #[error("private HNSW ORAM bucket_count does not match tree_height")]
    BucketCountMismatch,
    #[error("private HNSW ORAM client config is invalid")]
    InvalidOramClientConfig(&'static str),
    #[error("private HNSW ORAM bucket plaintext is malformed")]
    InvalidBucketPlaintext,
    #[error("private HNSW ORAM bucket plaintext metadata does not match config")]
    BucketPlaintextMetadataMismatch,
    #[error("private HNSW ORAM bucket plaintext slot count does not match config")]
    BucketPlaintextSlotCountMismatch,
    #[error("private HNSW ORAM path buckets do not match the requested leaf path")]
    PathBucketMismatch,
    #[error("private HNSW ORAM client position map is missing a node")]
    MissingPosition,
    #[error("private HNSW ORAM path did not contain the requested node")]
    MissingBlock,
    #[error("private HNSW ORAM append rewrite changed immutable block fields")]
    InvalidAppendRewrite,
    #[error("private HNSW ORAM path contains duplicate node blocks")]
    DuplicateBlock,
    #[error("private HNSW ORAM path contains duplicate point tokens")]
    DuplicatePointToken,
    #[error("private HNSW ORAM path contains duplicate payload fetch tokens")]
    DuplicatePayloadFetchToken,
    #[error("private HNSW ORAM build config is invalid")]
    InvalidBuildConfig(&'static str),
    #[error("private HNSW ORAM initial placement overflowed path")]
    OramInitialPlacementOverflow { leaf: u64 },
    #[error("private HNSW ORAM client state snapshot uses unsupported version")]
    UnsupportedClientStateSnapshotVersion(u16),
    #[error("private HNSW ORAM client state snapshot is malformed")]
    InvalidClientStateSnapshot,
    #[error("private HNSW ORAM client state context is invalid")]
    InvalidClientStateContext(&'static str),
    #[error("private HNSW ORAM client state ciphertext is not base64url")]
    InvalidClientStateCiphertextEncoding,
    #[error("private HNSW ORAM client state ciphertext hash is invalid")]
    InvalidClientStateCiphertextHash,
    #[error("private HNSW ORAM client state uses unsupported ciphertext version")]
    UnsupportedClientStateCiphertextVersion(u16),
    #[error("private HNSW ORAM client state decryption authentication failed")]
    ClientStateOpenFailed,
    #[error("private HNSW search config is invalid")]
    InvalidSearchConfig(&'static str),
    #[error("private HNSW search currently requires f32_le node vectors")]
    UnsupportedSearchVectorEncoding,
    #[error("private HNSW search f32 vector bytes are malformed")]
    InvalidF32VectorLength,
    #[error("private HNSW search query and node vector dimensions differ")]
    VectorDimensionMismatch,
    #[error("private HNSW search distance is not finite")]
    NonFiniteDistance,
    #[error("private HNSW search did not exhaust the fixed access budget")]
    FixedBudgetNotExhausted {
        completed_steps: usize,
        fixed_steps: usize,
    },
    #[error("private HNSW private result mode requires every hit to carry a payload fetch token")]
    MissingPayloadFetchToken,
    #[error("private HNSW ORAM Merkle tree must contain at least one leaf")]
    EmptyMerkleTree,
    #[error("private HNSW ORAM Merkle root is invalid")]
    InvalidMerkleRoot,
    #[error("private HNSW ORAM Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("private HNSW ORAM commit new_epoch must be exactly old_epoch + 1")]
    InvalidCommitEpoch,
    #[error("private HNSW ORAM commit must update at least one bucket")]
    EmptyCommit,
    #[error("private HNSW ORAM commit bucket is out of range")]
    BucketOutOfRange { bucket_id: u64, bucket_count: u64 },
    #[error("private HNSW ORAM upload contains duplicate bucket")]
    DuplicateBucket { bucket_id: u64 },
    #[error("private HNSW ORAM upload is missing a configured bucket")]
    MissingBucket { bucket_id: u64 },
    #[error("private HNSW ORAM commit bucket appears more than once")]
    DuplicateUpdatedBucket { bucket_id: u64 },
    #[error("private HNSW ORAM commit bucket has stale epoch")]
    StaleBucketEpoch {
        bucket_id: u64,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    #[error("private HNSW ORAM bucket uses unsupported version")]
    UnsupportedBucketVersion(u16),
    #[error("private HNSW ORAM commit signature context is invalid")]
    InvalidCommitSignatureContext(&'static str),
    #[error("private HNSW ORAM manifest signature context is invalid")]
    InvalidManifestSignatureContext(&'static str),
    #[error("private HNSW ORAM manifest epoch/root does not match commit old epoch/root")]
    ManifestCommitMismatch,
    #[error("private HNSW ORAM Merkle proof is malformed")]
    InvalidMerkleProof,
    #[error("private HNSW ORAM Merkle proof JSON is malformed")]
    InvalidMerkleProofJson,
    #[error("private HNSW ORAM Merkle proof does not match buckets/root")]
    MerkleProofMismatch,
}

impl Debug for PrivateHnswClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateHnswClientError")
            .field(&self.to_string())
            .finish()
    }
}

impl From<EncryptionError> for PrivateHnswClientError {
    fn from(error: EncryptionError) -> Self {
        Self::Encryption(error)
    }
}

pub struct PrivateHnswClientKeys {
    node_aead: SecretKey,
    bucket_aead: SecretKey,
    position_map: SecretKey,
    payload_token: SecretKey,
    blind_result: SecretKey,
    /// AES-GCM invocations spent on `bucket_aead` by this instance.
    bucket_seals: AeadInvocationBudget,
    /// AES-GCM invocations spent on `position_map` (the client-state key) by this instance.
    client_state_seals: AeadInvocationBudget,
}

impl PrivateHnswClientKeys {
    /// Legacy domain-only derivation kept for existing fixtures and clients.
    ///
    /// New private HNSW indexes should use `derive_from_resource_key_for_manifest`
    /// or `derive_from_resource_key_with_context` so the derived client keys are
    /// bound to the collection/vector/resource-key epoch boundary.
    #[deprecated(
        note = "use derive_from_resource_key_for_manifest or derive_from_resource_key_with_context"
    )]
    pub fn derive_from_resource_key(resource_key: &SecretKey) -> Result<Self, EncryptionError> {
        Ok(Self {
            node_aead: resource_key.derive_subkey(PRIVATE_HNSW_NODE_AEAD_DOMAIN)?,
            bucket_aead: resource_key.derive_subkey(PRIVATE_HNSW_BUCKET_AEAD_DOMAIN)?,
            position_map: resource_key.derive_subkey(PRIVATE_HNSW_POSITION_MAP_DOMAIN)?,
            payload_token: resource_key.derive_subkey(PRIVATE_HNSW_PAYLOAD_TOKEN_DOMAIN)?,
            blind_result: resource_key.derive_subkey(PRIVATE_HNSW_BLIND_RESULT_DOMAIN)?,
            bucket_seals: AeadInvocationBudget::new(),
            client_state_seals: AeadInvocationBudget::new(),
        })
    }

    pub fn derive_from_resource_key_for_manifest(
        resource_key: &SecretKey,
        manifest: &PrivateHnswOramManifest,
    ) -> Result<Self, EncryptionError> {
        Self::derive_from_resource_key_with_context(
            resource_key,
            &manifest.collection_id,
            &manifest.vector_name,
            &manifest.rk_id,
            manifest.rk_epoch,
        )
    }

    pub fn derive_from_resource_key_with_context(
        resource_key: &SecretKey,
        collection_id: &str,
        vector_name: &str,
        rk_id: &str,
        rk_epoch: u64,
    ) -> Result<Self, EncryptionError> {
        let node_aead = derive_private_hnsw_context_subkey(
            resource_key,
            PRIVATE_HNSW_NODE_AEAD_DOMAIN,
            collection_id,
            vector_name,
            rk_id,
            rk_epoch,
        )?;
        let bucket_aead = derive_private_hnsw_context_subkey(
            resource_key,
            PRIVATE_HNSW_BUCKET_AEAD_DOMAIN,
            collection_id,
            vector_name,
            rk_id,
            rk_epoch,
        )?;
        let position_map = derive_private_hnsw_context_subkey(
            resource_key,
            PRIVATE_HNSW_POSITION_MAP_DOMAIN,
            collection_id,
            vector_name,
            rk_id,
            rk_epoch,
        )?;
        let payload_token = derive_private_hnsw_context_subkey(
            resource_key,
            PRIVATE_HNSW_PAYLOAD_TOKEN_DOMAIN,
            collection_id,
            vector_name,
            rk_id,
            rk_epoch,
        )?;
        let blind_result = derive_private_hnsw_context_subkey(
            resource_key,
            PRIVATE_HNSW_BLIND_RESULT_DOMAIN,
            collection_id,
            vector_name,
            rk_id,
            rk_epoch,
        )?;

        Ok(Self {
            node_aead,
            bucket_aead,
            position_map,
            payload_token,
            blind_result,
            bucket_seals: AeadInvocationBudget::new(),
            client_state_seals: AeadInvocationBudget::new(),
        })
    }

    pub fn node_aead_key(&self) -> &SecretKey {
        &self.node_aead
    }

    pub fn bucket_aead_key(&self) -> &SecretKey {
        &self.bucket_aead
    }

    pub fn position_map_key(&self) -> &SecretKey {
        &self.position_map
    }

    pub fn payload_token_key(&self) -> &SecretKey {
        &self.payload_token
    }

    pub fn blind_result_key(&self) -> &SecretKey {
        &self.blind_result
    }

    /// AES-GCM seals performed with the bucket key by this instance.
    pub fn bucket_seal_invocations(&self) -> u64 {
        self.bucket_seals.invocations()
    }

    /// AES-GCM seals performed with the client-state key by this instance.
    pub fn client_state_seal_invocations(&self) -> u64 {
        self.client_state_seals.invocations()
    }
}

fn derive_private_hnsw_context_subkey(
    resource_key: &SecretKey,
    domain: &[u8],
    collection_id: &str,
    vector_name: &str,
    rk_id: &str,
    rk_epoch: u64,
) -> Result<SecretKey, EncryptionError> {
    let rk_epoch = rk_epoch.to_be_bytes();
    resource_key.derive_subkey_with_context(
        domain,
        PRIVATE_HNSW_CLIENT_KDF_CONTEXT_DOMAIN,
        &[
            collection_id.as_bytes(),
            vector_name.as_bytes(),
            rk_id.as_bytes(),
            &rk_epoch,
        ],
    )
}

impl Debug for PrivateHnswClientKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientKeys")
            .field("node_aead", &"[redacted; 32 bytes]")
            .field("bucket_aead", &"[redacted; 32 bytes]")
            .field("position_map", &"[redacted; 32 bytes]")
            .field("payload_token", &"[redacted; 32 bytes]")
            .field("blind_result", &"[redacted; 32 bytes]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateHnswVectorEncoding {
    F32Le,
    I8Quantized,
    PqCode,
    BinaryQuantized,
}

impl PrivateHnswVectorEncoding {
    fn tag(self) -> u8 {
        match self {
            Self::F32Le => 1,
            Self::I8Quantized => 2,
            Self::PqCode => 3,
            Self::BinaryQuantized => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, PrivateHnswClientError> {
        match tag {
            1 => Ok(Self::F32Le),
            2 => Ok(Self::I8Quantized),
            3 => Ok(Self::PqCode),
            4 => Ok(Self::BinaryQuantized),
            _ => Err(PrivateHnswClientError::UnsupportedVectorEncoding(tag)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswNodeBlockPlaintext {
    pub version: u16,
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub level_mask: u64,
    pub vector_encoding: PrivateHnswVectorEncoding,
    pub vector: Vec<u8>,
    pub neighbors: Vec<[u8; 32]>,
    pub neighbor_levels: Vec<u8>,
    pub deleted: bool,
    pub generation: u64,
    pub payload_fetch_token: Option<[u8; 32]>,
}

impl Debug for PrivateHnswNodeBlockPlaintext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswNodeBlockPlaintext")
            .field("version", &self.version)
            .field("node_id", &"[redacted; 32 bytes]")
            .field("point_token", &"[redacted; 32 bytes]")
            .field("level_mask", &"[redacted]")
            .field("vector_encoding", &self.vector_encoding)
            .field("vector_len", &"[redacted]")
            .field("neighbor_count", &"[redacted]")
            .field("neighbor_levels_len", &"[redacted]")
            .field("deleted", &"[redacted]")
            .field("generation", &"[redacted]")
            .field("payload_fetch_token", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswBucketAeadContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub bucket_id: u64,
    pub index_epoch: u64,
}

impl Debug for PrivateHnswBucketAeadContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswBucketAeadContext")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("bucket_id", &"[redacted]")
            .field("index_epoch", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswBucketAeadBaseContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
}

impl Debug for PrivateHnswBucketAeadBaseContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswBucketAeadBaseContext")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswClientStateAeadContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub index_epoch: u64,
    pub root_hash: &'a str,
}

impl Debug for PrivateHnswClientStateAeadContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientStateAeadContext")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .finish()
    }
}

impl<'a> PrivateHnswBucketAeadBaseContext<'a> {
    pub fn for_bucket(self, bucket_id: u64, index_epoch: u64) -> PrivateHnswBucketAeadContext<'a> {
        PrivateHnswBucketAeadContext {
            collection_id: self.collection_id,
            vector_name: self.vector_name,
            key_id: self.key_id,
            rk_id: self.rk_id,
            rk_epoch: self.rk_epoch,
            bucket_id,
            index_epoch,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramClientConfig {
    pub tree_height: u32,
    pub bucket_size: usize,
    pub block_size_bytes: usize,
    pub fixed_neighbor_slots: usize,
}

impl Debug for PrivateHnswOramClientConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramClientConfig")
            .field("tree_height", &"[redacted]")
            .field("bucket_size", &"[redacted]")
            .field("block_size_bytes", &"[redacted]")
            .field("fixed_neighbor_slots", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswOramPlaintextBucket {
    pub bucket_id: u64,
    pub blocks: Vec<Option<PrivateHnswNodeBlockPlaintext>>,
}

impl Debug for PrivateHnswOramPlaintextBucket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramPlaintextBucket")
            .field("bucket_id", &"[redacted]")
            .field("blocks_len", &"[redacted]")
            .field("occupied_blocks", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramClientStateSnapshot {
    pub version: u16,
    pub tree_height: u32,
    pub positions: Vec<PrivateHnswPositionMapSnapshotEntry>,
    pub stash: Vec<PrivateHnswNodeBlockPlaintext>,
}

impl Debug for PrivateHnswOramClientStateSnapshot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramClientStateSnapshot")
            .field("version", &self.version)
            .field("tree_height", &"[redacted]")
            .field("position_count", &"[redacted]")
            .field("stash_len", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswEncryptedClientStateSnapshot {
    pub version: u16,
    pub index_epoch: u64,
    pub root_hash: String,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

impl Debug for PrivateHnswEncryptedClientStateSnapshot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswEncryptedClientStateSnapshot")
            .field("version", &self.version)
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .field("ciphertext_len", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswPositionMapSnapshotEntry {
    pub node_id: String,
    pub leaf_label: String,
}

impl Debug for PrivateHnswPositionMapSnapshotEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPositionMapSnapshotEntry")
            .field("node_id", &"[redacted]")
            .field("leaf_label", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleProof {
    pub kind: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub leaves: Vec<PrivateHnswOramMerkleProofLeaf>,
}

impl Debug for PrivateHnswOramMerkleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleProof")
            .field("kind", &self.kind)
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("leaf_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleProofLeaf {
    pub bucket_id: u64,
    pub leaf_hash: String,
    pub siblings: Vec<PrivateHnswOramMerkleSibling>,
}

impl Debug for PrivateHnswOramMerkleProofLeaf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleProofLeaf")
            .field("bucket_id", &"[redacted]")
            .field("leaf_hash", &"[redacted]")
            .field("sibling_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleSibling {
    pub level: u32,
    pub position: PrivateHnswMerkleSiblingPosition,
    pub hash: String,
}

impl Debug for PrivateHnswOramMerkleSibling {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleSibling")
            .field("level", &self.level)
            .field("position", &self.position)
            .field("hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateHnswMerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswEncryptedPathBatch {
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub proof_value: String,
    pub buckets: Vec<PrivateHnswOramBucket>,
}

impl Debug for PrivateHnswEncryptedPathBatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswEncryptedPathBatch")
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("proof_value", &"[redacted]")
            .field("returned_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswOramAccessResult {
    pub old_leaf: u64,
    pub new_leaf: u64,
    pub old_leaf_label: String,
    pub block: PrivateHnswNodeBlockPlaintext,
    pub writeback_buckets: Vec<PrivateHnswOramPlaintextBucket>,
}

impl Debug for PrivateHnswOramAccessResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramAccessResult")
            .field("old_leaf", &"[redacted]")
            .field("new_leaf", &"[redacted]")
            .field("old_leaf_label", &"[redacted]")
            .field("block", &"[redacted]")
            .field("writeback_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswOramEvictionResult {
    pub leaf: u64,
    pub leaf_label: String,
    pub writeback_buckets: Vec<PrivateHnswOramPlaintextBucket>,
}

impl Debug for PrivateHnswOramEvictionResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramEvictionResult")
            .field("leaf", &"[redacted]")
            .field("leaf_label", &"[redacted]")
            .field("writeback_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswSearchParams {
    pub entry_node_id: [u8; 32],
    pub k: usize,
    pub ef: usize,
    pub fixed_steps: usize,
    pub distance: DistanceKind,
    pub padding_node_id: Option<[u8; 32]>,
}

impl Debug for PrivateHnswSearchParams {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSearchParams")
            .field("entry_node_id", &"[redacted; 32 bytes]")
            .field("k", &"[redacted]")
            .field("ef", &"[redacted]")
            .field("fixed_steps", &"[redacted]")
            .field("distance", &self.distance)
            .field("has_padding_node_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateHnswSearchHit {
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub payload_fetch_token: Option<[u8; 32]>,
    pub distance: f32,
}

impl Debug for PrivateHnswSearchHit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSearchHit")
            .field("node_id", &"[redacted; 32 bytes]")
            .field("point_token", &"[redacted; 32 bytes]")
            .field("has_payload_fetch_token", &"[redacted]")
            .field("distance", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateHnswSearchResult {
    pub hits: Vec<PrivateHnswSearchHit>,
    pub accessed_leaf_labels: Vec<String>,
    pub completed_steps: usize,
}

impl Debug for PrivateHnswSearchResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSearchResult")
            .field("hit_count", &"[redacted]")
            .field("accessed_leaf_label_count", &"[redacted]")
            .field("completed_steps", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswPrivateResultFetchPlan {
    pub payload_fetch_tokens: Vec<[u8; 32]>,
    pub real_result_count: usize,
    pub fixed_result_k: usize,
}

impl Debug for PrivateHnswPrivateResultFetchPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPrivateResultFetchPlan")
            .field("payload_fetch_token_count", &"[redacted]")
            .field("real_result_count", &"[redacted]")
            .field("fixed_result_k", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateHnswPrivateResultPayload {
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub payload_fetch_token: [u8; 32],
    pub distance: f32,
    pub payload: Vec<u8>,
    pub payload_generation: u64,
}

impl Debug for PrivateHnswPrivateResultPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPrivateResultPayload")
            .field("node_id", &"[redacted; 32 bytes]")
            .field("point_token", &"[redacted; 32 bytes]")
            .field("payload_fetch_token", &"[redacted; 32 bytes]")
            .field("distance", &"[redacted]")
            .field("payload_len", &"[redacted]")
            .field("payload_generation", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateHnswPrivateResultPayloadFetch {
    pub results: Vec<PrivateHnswPrivateResultPayload>,
    pub real_result_count: usize,
    pub fixed_result_k: usize,
    pub fetched_token_count: usize,
}

impl Debug for PrivateHnswPrivateResultPayloadFetch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPrivateResultPayloadFetch")
            .field("result_count", &"[redacted]")
            .field("real_result_count", &"[redacted]")
            .field("fixed_result_k", &"[redacted]")
            .field("fetched_token_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswSearchAccessMetrics {
    pub path_accesses: usize,
    pub unique_leaf_labels: usize,
    pub fixed_steps: usize,
    pub exhausted_fixed_budget: bool,
}

impl Debug for PrivateHnswSearchAccessMetrics {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSearchAccessMetrics")
            .field("path_accesses", &"[redacted]")
            .field("unique_leaf_labels", &"[redacted]")
            .field("fixed_steps", &"[redacted]")
            .field("exhausted_fixed_budget", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswSearchResult {
    pub fn access_metrics(
        &self,
        params: &PrivateHnswSearchParams,
    ) -> PrivateHnswSearchAccessMetrics {
        let has_canonical_leaf_labels = self
            .accessed_leaf_labels
            .iter()
            .all(|label| decode_private_hnsw_oram_leaf_label_shape(label).is_ok());
        PrivateHnswSearchAccessMetrics {
            path_accesses: self.accessed_leaf_labels.len(),
            unique_leaf_labels: self
                .accessed_leaf_labels
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            fixed_steps: params.fixed_steps,
            exhausted_fixed_budget: params.fixed_steps > 0
                && has_canonical_leaf_labels
                && self.completed_steps == params.fixed_steps
                && self.accessed_leaf_labels.len() == params.fixed_steps,
        }
    }
}

pub fn validate_private_hnsw_search_result_privacy(
    result_privacy: ResultPrivacyMode,
    result: &PrivateHnswSearchResult,
) -> Result<(), PrivateHnswClientError> {
    match result_privacy {
        ResultPrivacyMode::IdsVisible => Ok(()),
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if result
                .hits
                .iter()
                .all(|hit| hit.payload_fetch_token.is_some())
            {
                Ok(())
            } else {
                Err(PrivateHnswClientError::MissingPayloadFetchToken)
            }
        }
    }
}

pub fn validate_private_hnsw_search_fixed_budget(
    params: &PrivateHnswSearchParams,
    result: &PrivateHnswSearchResult,
) -> Result<(), PrivateHnswClientError> {
    if params.fixed_steps == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig("fixed_steps"));
    }
    for leaf_label in &result.accessed_leaf_labels {
        decode_private_hnsw_oram_leaf_label_shape(leaf_label)?;
    }
    if result.completed_steps == params.fixed_steps
        && result.accessed_leaf_labels.len() == params.fixed_steps
    {
        return Ok(());
    }

    Err(PrivateHnswClientError::FixedBudgetNotExhausted {
        completed_steps: result.completed_steps,
        fixed_steps: params.fixed_steps,
    })
}

pub fn validate_private_hnsw_strict_search_result(
    result_privacy: ResultPrivacyMode,
    params: &PrivateHnswSearchParams,
    result: &PrivateHnswSearchResult,
) -> Result<(), PrivateHnswClientError> {
    validate_private_hnsw_search_fixed_budget(params, result)?;
    validate_private_hnsw_search_hits(result)?;
    validate_private_hnsw_search_result_privacy(result_privacy, result)
}

pub fn plan_private_hnsw_private_result_fetch_tokens(
    result_privacy: ResultPrivacyMode,
    result: &PrivateHnswSearchResult,
    fixed_result_k: usize,
    dummy_payload_fetch_tokens: &[[u8; 32]],
) -> Result<Option<PrivateHnswPrivateResultFetchPlan>, PrivateHnswClientError> {
    match result_privacy {
        ResultPrivacyMode::IdsVisible => Ok(None),
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            validate_private_hnsw_search_hits(result)?;
            if fixed_result_k == 0 || result.hits.len() > fixed_result_k {
                return Err(PrivateHnswClientError::InvalidSearchConfig(
                    "fixed_result_k",
                ));
            }
            let padding_count = fixed_result_k - result.hits.len();
            if dummy_payload_fetch_tokens.len() < padding_count {
                return Err(PrivateHnswClientError::InvalidSearchConfig(
                    "dummy_payload_fetch_tokens",
                ));
            }
            let mut dummy_seen = BTreeSet::new();
            if !dummy_payload_fetch_tokens
                .iter()
                .all(|token| dummy_seen.insert(*token))
            {
                return Err(PrivateHnswClientError::InvalidSearchConfig(
                    "payload_fetch_tokens",
                ));
            }
            validate_private_hnsw_search_result_privacy(result_privacy, result)?;
            let mut payload_fetch_tokens = result
                .hits
                .iter()
                .map(|hit| {
                    hit.payload_fetch_token
                        .ok_or(PrivateHnswClientError::MissingPayloadFetchToken)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut seen = BTreeSet::new();
            if !payload_fetch_tokens.iter().all(|token| seen.insert(*token))
                || dummy_payload_fetch_tokens
                    .iter()
                    .any(|token| seen.contains(token))
            {
                return Err(PrivateHnswClientError::InvalidSearchConfig(
                    "payload_fetch_tokens",
                ));
            }
            payload_fetch_tokens.extend_from_slice(&dummy_payload_fetch_tokens[..padding_count]);
            Ok(Some(PrivateHnswPrivateResultFetchPlan {
                payload_fetch_tokens,
                real_result_count: result.hits.len(),
                fixed_result_k,
            }))
        }
    }
}

pub fn finalize_private_hnsw_private_result_fetch(
    result: &PrivateHnswSearchResult,
    fetch_plan: &PrivateHnswPrivateResultFetchPlan,
    token_fetch_result: &PrivateResultOramTokenFetchResult,
) -> Result<PrivateHnswPrivateResultPayloadFetch, PrivateHnswClientError> {
    validate_private_hnsw_search_result_privacy(
        ResultPrivacyMode::PrivatePayloadOramRequired,
        result,
    )?;
    validate_private_hnsw_search_hits(result)?;
    if fetch_plan.fixed_result_k == 0
        || fetch_plan.real_result_count != result.hits.len()
        || fetch_plan.real_result_count > fetch_plan.fixed_result_k
        || fetch_plan.fixed_result_k != fetch_plan.payload_fetch_tokens.len()
        || token_fetch_result.accesses.len() != fetch_plan.payload_fetch_tokens.len()
    {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "result_fetch_plan",
        ));
    }

    let mut seen_tokens = BTreeSet::new();
    if !fetch_plan
        .payload_fetch_tokens
        .iter()
        .all(|token| seen_tokens.insert(*token))
    {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "payload_fetch_tokens",
        ));
    }

    let mut fetched_by_token = BTreeMap::new();
    for access in &token_fetch_result.accesses {
        if access.block.payload_fetch_token != access.payload_fetch_token
            || fetched_by_token
                .insert(access.payload_fetch_token, access)
                .is_some()
        {
            return Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens",
            ));
        }
    }
    for expected_token in &fetch_plan.payload_fetch_tokens {
        if !fetched_by_token.contains_key(expected_token) {
            return Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens",
            ));
        }
    }

    let mut results = Vec::with_capacity(fetch_plan.real_result_count);
    for hit in result.hits.iter().take(fetch_plan.real_result_count) {
        let payload_fetch_token = hit
            .payload_fetch_token
            .ok_or(PrivateHnswClientError::MissingPayloadFetchToken)?;
        let access = fetched_by_token.get(&payload_fetch_token).ok_or(
            PrivateHnswClientError::InvalidSearchConfig("payload_fetch_tokens"),
        )?;
        validate_private_hnsw_result_payload_block(hit, payload_fetch_token, &access.block)?;
        results.push(PrivateHnswPrivateResultPayload {
            node_id: hit.node_id,
            point_token: hit.point_token,
            payload_fetch_token,
            distance: hit.distance,
            payload: access.block.payload.clone(),
            payload_generation: access.block.generation,
        });
    }

    Ok(PrivateHnswPrivateResultPayloadFetch {
        results,
        real_result_count: fetch_plan.real_result_count,
        fixed_result_k: fetch_plan.fixed_result_k,
        fetched_token_count: token_fetch_result.accesses.len(),
    })
}

fn validate_private_hnsw_search_hits(
    result: &PrivateHnswSearchResult,
) -> Result<(), PrivateHnswClientError> {
    let mut node_ids = BTreeSet::new();
    let mut point_tokens = BTreeSet::new();
    for hit in &result.hits {
        if !hit.distance.is_finite() {
            return Err(PrivateHnswClientError::NonFiniteDistance);
        }
        if !node_ids.insert(hit.node_id) || !point_tokens.insert(hit.point_token) {
            return Err(PrivateHnswClientError::InvalidSearchConfig("search_hits"));
        }
    }
    Ok(())
}

fn validate_private_hnsw_result_payload_block(
    hit: &PrivateHnswSearchHit,
    payload_fetch_token: [u8; 32],
    block: &PrivateResultOramPayloadBlockPlaintext,
) -> Result<(), PrivateHnswClientError> {
    if block.deleted {
        return Err(PrivateHnswClientError::InvalidSearchConfig("payload_block"));
    }
    if block.payload_fetch_token != payload_fetch_token {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "payload_fetch_tokens",
        ));
    }
    if block.point_token != hit.point_token {
        return Err(PrivateHnswClientError::InvalidSearchConfig("point_token"));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswSpeculativePrefetchPlan {
    pub leaf_labels: Vec<String>,
    pub real_path_count: usize,
}

impl Debug for PrivateHnswSpeculativePrefetchPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSpeculativePrefetchPlan")
            .field("leaf_label_count", &"[redacted]")
            .field("real_path_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswGraphTraversalPathBatchPlan {
    pub leaf_labels: Vec<String>,
    pub real_path_count: usize,
    pub retained_neighbor_count: usize,
}

impl Debug for PrivateHnswGraphTraversalPathBatchPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswGraphTraversalPathBatchPlan")
            .field("leaf_label_count", &"[redacted]")
            .field("real_path_count", &"[redacted]")
            .field("retained_neighbor_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswDirectionalNeighborFilterPlan {
    pub node_ids: Vec<[u8; 32]>,
    pub retained_count: usize,
}

impl Debug for PrivateHnswDirectionalNeighborFilterPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswDirectionalNeighborFilterPlan")
            .field("node_id_count", &"[redacted]")
            .field("retained_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateHnswBuildPoint {
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub vector: Vec<f32>,
    pub payload_fetch_token: Option<[u8; 32]>,
}

impl Debug for PrivateHnswBuildPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswBuildPoint")
            .field("node_id", &"[redacted; 32 bytes]")
            .field("point_token", &"[redacted; 32 bytes]")
            .field("vector_len", &"[redacted]")
            .field("has_payload_fetch_token", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswPlaintextIndexBuild {
    pub entry_node_id: [u8; 32],
    pub state: PrivateHnswOramClientState,
    pub buckets: Vec<PrivateHnswOramPlaintextBucket>,
    pub logical_node_count: u64,
    pub dummy_node_count: u64,
}

impl Debug for PrivateHnswPlaintextIndexBuild {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPlaintextIndexBuild")
            .field("entry_node_id", &"[redacted; 32 bytes]")
            .field("state", &self.state)
            .field("bucket_count", &"[redacted]")
            .field("logical_node_count", &"[redacted]")
            .field("dummy_node_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswEncryptedIndexBuild {
    pub index_epoch: u64,
    pub entry_node_id: [u8; 32],
    pub root_hash: String,
    pub bucket_count: u64,
    pub logical_node_count: u64,
    pub dummy_node_count: u64,
    pub buckets: Vec<PrivateHnswOramBucket>,
}

impl Debug for PrivateHnswEncryptedIndexBuild {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswEncryptedIndexBuild")
            .field("index_epoch", &"[redacted]")
            .field("entry_node_id", &"[redacted; 32 bytes]")
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("logical_node_count", &"[redacted]")
            .field("dummy_node_count", &"[redacted]")
            .field("returned_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct PrivateHnswClientNodeCache {
    nodes: BTreeMap<[u8; 32], PrivateHnswNodeBlockPlaintext>,
}

impl Debug for PrivateHnswClientNodeCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientNodeCache")
            .field("node_count", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswClientNodeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn contains(&self, node_id: &[u8; 32]) -> bool {
        self.nodes.contains_key(node_id)
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&PrivateHnswNodeBlockPlaintext> {
        self.nodes.get(node_id)
    }

    pub fn insert(
        &mut self,
        block: PrivateHnswNodeBlockPlaintext,
    ) -> Option<PrivateHnswNodeBlockPlaintext> {
        self.nodes.insert(block.node_id, block)
    }

    pub fn insert_if_reaches_level(
        &mut self,
        block: PrivateHnswNodeBlockPlaintext,
        min_level: u8,
    ) -> bool {
        if !private_hnsw_node_reaches_level(&block, min_level) {
            return false;
        }
        self.nodes.insert(block.node_id, block).is_none()
    }

    pub fn extend_upper_layers_from_plaintext_build(
        &mut self,
        build: &PrivateHnswPlaintextIndexBuild,
        min_level: u8,
    ) -> usize {
        let mut inserted = 0;
        for block in build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
        {
            if self.insert_if_reaches_level(block.clone(), min_level) {
                inserted += 1;
            }
        }
        inserted
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramUploadBundle {
    pub manifest: PrivateHnswOramManifest,
    pub manifest_signature: PrivateHnswOramSignature,
    pub buckets: Vec<PrivateHnswOramBucket>,
}

impl Debug for PrivateHnswOramUploadBundle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramUploadBundle")
            .field("manifest", &self.manifest)
            .field("manifest_signature", &self.manifest_signature)
            .field("bucket_count", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswOramUploadBundle {
    pub fn index_epoch(&self) -> u64 {
        self.manifest.index_epoch
    }

    pub fn root_hash(&self) -> &str {
        &self.manifest.root_hash
    }

    pub fn bucket_count(&self) -> u64 {
        self.manifest.bucket_count
    }

    pub fn bucket_commitments(&self) -> Vec<String> {
        self.buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect()
    }

    pub fn validate_initial_upload_contract(&self) -> Result<Vec<String>, PrivateHnswClientError> {
        validate_private_hnsw_oram_upload_bundle(self)
    }

    pub fn validate_initial_upload_contract_with_signature(
        &self,
        validation_context: PrivateHnswManifestValidationContext<'_>,
    ) -> Result<Vec<String>, PrivateHnswClientError> {
        validate_private_hnsw_oram_upload_bundle_with_signature(self, validation_context)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswManifestBuildContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub dim: u32,
    pub distance: DistanceKind,
    pub hnsw: PrivateHnswParams,
    pub oram: OramParams,
    pub fixed_budget: FixedBudgetParams,
    pub result_privacy: ResultPrivacyMode,
    pub owner_signing_key_id: &'a str,
    pub created_at_unix: u64,
}

impl Debug for PrivateHnswManifestBuildContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswManifestBuildContext")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("dim", &self.dim)
            .field("distance", &self.distance)
            .field("hnsw", &"[redacted]")
            .field("oram", &"[redacted]")
            .field("fixed_budget", &"[redacted]")
            .field("result_privacy", &self.result_privacy)
            .field("owner_signing_key_id", &"[redacted]")
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswClientCommitBucketRef {
    pub bucket_id: u64,
    pub ciphertext_sha256: String,
}

impl Debug for PrivateHnswClientCommitBucketRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientCommitBucketRef")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswClientCommitPlan {
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub leaf_commitments: Vec<String>,
    pub updated_buckets: Vec<PrivateHnswClientCommitBucketRef>,
}

impl Debug for PrivateHnswClientCommitPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientCommitPlan")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("leaf_commitment_count", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswClientCommitPlan {
    pub fn signature_bucket_refs(&self) -> Vec<PrivateHnswOramCommitBucketRef<'_>> {
        self.updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswCommitSignatureContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub signing_key_id: &'a str,
}

impl Debug for PrivateHnswCommitSignatureContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswCommitSignatureContext")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("signing_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct PrivateHnswOramClientState {
    position_map: BTreeMap<[u8; 32], u64>,
    stash: BTreeMap<[u8; 32], PrivateHnswNodeBlockPlaintext>,
}

impl Debug for PrivateHnswOramClientState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramClientState")
            .field("position_map_len", &"[redacted]")
            .field("stash_len", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswOramClientState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_position_map(
        position_map: impl IntoIterator<Item = ([u8; 32], u64)>,
        tree_height: u32,
    ) -> Result<Self, PrivateHnswClientError> {
        let mut state = Self::new();
        for (node_id, leaf) in position_map {
            validate_private_hnsw_oram_leaf(leaf, tree_height)?;
            if state.position_map.insert(node_id, leaf).is_some() {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
        }
        Ok(state)
    }

    pub fn insert_position(
        &mut self,
        node_id: [u8; 32],
        leaf: u64,
        tree_height: u32,
    ) -> Result<(), PrivateHnswClientError> {
        validate_private_hnsw_oram_leaf(leaf, tree_height)?;
        self.position_map.insert(node_id, leaf);
        Ok(())
    }

    pub fn insert_position_if_absent(
        &mut self,
        node_id: [u8; 32],
        leaf: u64,
        tree_height: u32,
    ) -> Result<(), PrivateHnswClientError> {
        validate_private_hnsw_oram_leaf(leaf, tree_height)?;
        if self.position_map.contains_key(&node_id) {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        self.position_map.insert(node_id, leaf);
        Ok(())
    }

    pub fn insert_new_stash_block(
        &mut self,
        block: PrivateHnswNodeBlockPlaintext,
        leaf: u64,
        config: PrivateHnswOramClientConfig,
    ) -> Result<(), PrivateHnswClientError> {
        validate_oram_client_config(config)?;
        validate_private_hnsw_oram_leaf(leaf, config.tree_height)?;
        encode_private_hnsw_node_block(
            &block,
            config.block_size_bytes,
            config.fixed_neighbor_slots,
        )?;
        if self.position_map.contains_key(&block.node_id) || self.stash.contains_key(&block.node_id)
        {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        if self
            .stash
            .values()
            .any(|existing| existing.point_token == block.point_token)
        {
            return Err(PrivateHnswClientError::DuplicatePointToken);
        }
        if block
            .payload_fetch_token
            .is_some_and(|payload_fetch_token| {
                self.stash
                    .values()
                    .any(|existing| existing.payload_fetch_token == Some(payload_fetch_token))
            })
        {
            return Err(PrivateHnswClientError::DuplicatePayloadFetchToken);
        }

        self.position_map.insert(block.node_id, leaf);
        self.stash.insert(block.node_id, block);
        Ok(())
    }

    pub fn position(&self, node_id: &[u8; 32]) -> Option<u64> {
        self.position_map.get(node_id).copied()
    }

    pub fn to_snapshot(
        &self,
        tree_height: u32,
    ) -> Result<PrivateHnswOramClientStateSnapshot, PrivateHnswClientError> {
        private_hnsw_oram_leaf_count(tree_height)?;
        let positions = self
            .position_map
            .iter()
            .map(|(node_id, leaf)| {
                Ok(PrivateHnswPositionMapSnapshotEntry {
                    node_id: BASE64URL_NOPAD.encode(node_id),
                    leaf_label: encode_private_hnsw_oram_leaf_label(*leaf, tree_height)?,
                })
            })
            .collect::<Result<Vec<_>, PrivateHnswClientError>>()?;
        let mut stash_point_tokens = BTreeSet::new();
        let mut stash_payload_fetch_tokens = BTreeSet::new();
        for (node_id, block) in &self.stash {
            if block.node_id != *node_id {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
            if !self.position_map.contains_key(node_id) {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
            validate_private_hnsw_client_state_stash_block(block)?;
            if !stash_point_tokens.insert(block.point_token) {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
            if let Some(payload_fetch_token) = block.payload_fetch_token
                && !stash_payload_fetch_tokens.insert(payload_fetch_token)
            {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
        }

        Ok(PrivateHnswOramClientStateSnapshot {
            version: CLIENT_STATE_SNAPSHOT_VERSION,
            tree_height,
            positions,
            stash: self.stash.values().cloned().collect(),
        })
    }

    pub fn from_snapshot(
        snapshot: &PrivateHnswOramClientStateSnapshot,
    ) -> Result<Self, PrivateHnswClientError> {
        if snapshot.version != CLIENT_STATE_SNAPSHOT_VERSION {
            return Err(
                PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(snapshot.version),
            );
        }
        private_hnsw_oram_leaf_count(snapshot.tree_height)?;

        let mut position_map = BTreeMap::new();
        for entry in &snapshot.positions {
            let node_id = decode_client_state_snapshot_node_id(&entry.node_id)?;
            let leaf = decode_private_hnsw_oram_leaf_label(&entry.leaf_label, snapshot.tree_height)
                .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)?;
            if position_map.insert(node_id, leaf).is_some() {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
        }

        let mut stash = BTreeMap::new();
        let mut stash_point_tokens = BTreeSet::new();
        let mut stash_payload_fetch_tokens = BTreeSet::new();
        for block in &snapshot.stash {
            validate_private_hnsw_client_state_stash_block(block)?;
            if !position_map.contains_key(&block.node_id) {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
            if !stash_point_tokens.insert(block.point_token) {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
            if let Some(payload_fetch_token) = block.payload_fetch_token
                && !stash_payload_fetch_tokens.insert(payload_fetch_token)
            {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
            if stash.insert(block.node_id, block.clone()).is_some() {
                return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
            }
        }

        Ok(Self {
            position_map,
            stash,
        })
    }

    pub fn stash_len(&self) -> usize {
        self.stash.len()
    }

    pub fn stash_contains(&self, node_id: &[u8; 32]) -> bool {
        self.stash.contains_key(node_id)
    }
}

fn validate_private_hnsw_client_state_stash_block(
    block: &PrivateHnswNodeBlockPlaintext,
) -> Result<(), PrivateHnswClientError> {
    if block.version != NODE_BLOCK_VERSION {
        return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
    }
    validate_private_hnsw_node_neighbor_shape(
        block.node_id,
        block.level_mask,
        &block.neighbors,
        &block.neighbor_levels,
    )
    .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)?;
    validate_private_hnsw_vector_shape(block.vector_encoding, &block.vector)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)
}

pub fn seal_private_hnsw_oram_client_state_snapshot(
    keys: &PrivateHnswClientKeys,
    context: PrivateHnswClientStateAeadContext<'_>,
    snapshot: &PrivateHnswOramClientStateSnapshot,
) -> Result<PrivateHnswEncryptedClientStateSnapshot, PrivateHnswClientError> {
    validate_client_state_context(context)?;
    PrivateHnswOramClientState::from_snapshot(snapshot)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(snapshot)
            .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)?,
    );
    keys.client_state_seals
        .reserve("private HNSW ORAM client state key")?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; BUCKET_AEAD_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::RandomFailure)?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.position_map_key().as_bytes())
        .map_err(|_| EncryptionError::SealFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = private_hnsw_client_state_aead(context)?;
    let mut in_out = plaintext;
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out[..])
        .map_err(|_| EncryptionError::SealFailed)?;

    let mut raw_ciphertext =
        Vec::with_capacity(2 + BUCKET_AEAD_NONCE_LEN + in_out.len() + tag.as_ref().len());
    raw_ciphertext.extend_from_slice(&CLIENT_STATE_AEAD_VERSION.to_be_bytes());
    raw_ciphertext.extend_from_slice(&nonce_bytes);
    raw_ciphertext.extend_from_slice(&in_out[..]);
    raw_ciphertext.extend_from_slice(tag.as_ref());

    Ok(PrivateHnswEncryptedClientStateSnapshot {
        version: CLIENT_STATE_AEAD_VERSION,
        index_epoch: context.index_epoch,
        root_hash: context.root_hash.to_string(),
        ciphertext: BASE64URL_NOPAD.encode(&raw_ciphertext),
        ciphertext_sha256: base64url_sha256(&raw_ciphertext),
    })
}

pub fn open_private_hnsw_oram_client_state_snapshot(
    keys: &PrivateHnswClientKeys,
    context: PrivateHnswClientStateAeadContext<'_>,
    encrypted: &PrivateHnswEncryptedClientStateSnapshot,
) -> Result<PrivateHnswOramClientStateSnapshot, PrivateHnswClientError> {
    validate_client_state_context(context)?;
    if encrypted.version != CLIENT_STATE_AEAD_VERSION {
        return Err(
            PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(encrypted.version),
        );
    }
    if encrypted.index_epoch != context.index_epoch || encrypted.root_hash != context.root_hash {
        return Err(PrivateHnswClientError::ClientStateOpenFailed);
    }
    if encrypted.ciphertext_sha256.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidClientStateCiphertextHash);
    }
    validate_private_hnsw_client_state_ciphertext_encoded_len(encrypted.ciphertext.len())?;

    let raw_ciphertext = BASE64URL_NOPAD
        .decode(encrypted.ciphertext.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidClientStateCiphertextEncoding)?;
    if raw_ciphertext.len() < 2 + BUCKET_AEAD_NONCE_LEN + BUCKET_AEAD_TAG_LEN {
        return Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding);
    }
    if base64url_sha256(&raw_ciphertext) != encrypted.ciphertext_sha256 {
        return Err(PrivateHnswClientError::InvalidClientStateCiphertextHash);
    }
    let encoded_version = u16::from_be_bytes(
        raw_ciphertext[0..2]
            .try_into()
            .map_err(|_| PrivateHnswClientError::InvalidClientStateCiphertextEncoding)?,
    );
    if encoded_version != CLIENT_STATE_AEAD_VERSION {
        return Err(
            PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(encoded_version),
        );
    }

    let nonce_bytes: [u8; BUCKET_AEAD_NONCE_LEN] = raw_ciphertext[2..2 + BUCKET_AEAD_NONCE_LEN]
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidClientStateCiphertextEncoding)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = Zeroizing::new(raw_ciphertext[2 + BUCKET_AEAD_NONCE_LEN..].to_vec());
    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.position_map_key().as_bytes())
        .map_err(|_| EncryptionError::OpenFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let aad = private_hnsw_client_state_aead(context)?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext[..])
        .map_err(|_| PrivateHnswClientError::ClientStateOpenFailed)?;
    let snapshot = serde_json::from_slice::<PrivateHnswOramClientStateSnapshot>(plaintext)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)?;
    PrivateHnswOramClientState::from_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub fn private_hnsw_oram_leaf_count(tree_height: u32) -> Result<u64, PrivateHnswClientError> {
    if tree_height == 0 || tree_height >= 63 {
        return Err(PrivateHnswClientError::InvalidTreeHeight);
    }
    Ok(1u64 << tree_height)
}

pub fn private_hnsw_oram_bucket_count(tree_height: u32) -> Result<u64, PrivateHnswClientError> {
    private_hnsw_oram_leaf_count(tree_height)?
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(PrivateHnswClientError::InvalidTreeHeight)
}

fn private_hnsw_oram_path_len(tree_height: u32) -> Result<usize, PrivateHnswClientError> {
    private_hnsw_oram_leaf_count(tree_height)?;
    usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or(PrivateHnswClientError::InvalidTreeHeight)
}

pub fn private_hnsw_oram_fixed_writeback_bucket_budget(
    oram: &OramParams,
) -> Result<usize, PrivateHnswClientError> {
    let path_len = private_hnsw_oram_path_len(oram.tree_height)?;
    let path_batch_size = usize::try_from(oram.path_batch_size)
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("path_batch_size"))?;
    if path_batch_size == 0 {
        return Err(PrivateHnswClientError::InvalidOramClientConfig(
            "path_batch_size",
        ));
    }
    path_len.checked_mul(path_batch_size).ok_or(
        PrivateHnswClientError::InvalidCommitSignatureContext("updated_buckets"),
    )
}

/// Client-side mirror of the server's session writeback budget: one path worth of buckets per
/// path read in the session, never below one fixed read round, capped by the tree.
pub fn private_hnsw_oram_session_writeback_bucket_budget(
    oram: &OramParams,
    read_path_count: usize,
) -> Result<usize, PrivateHnswClientError> {
    let path_len = private_hnsw_oram_path_len(oram.tree_height)?;
    let round_budget = private_hnsw_oram_fixed_writeback_bucket_budget(oram)?;
    let bucket_count = usize::try_from(private_hnsw_oram_bucket_count(oram.tree_height)?)
        .map_err(|_| PrivateHnswClientError::InvalidTreeHeight)?;
    Ok(round_budget
        .max(path_len.saturating_mul(read_path_count))
        .min(bucket_count))
}

/// Draws a uniformly random value in `0..leaf_count` from `rng` using rejection sampling.
pub(crate) fn sample_uniform_leaf(rng: &dyn SecureRandom, leaf_count: u64) -> Option<u64> {
    if leaf_count == 0 {
        return None;
    }
    // Largest multiple of `leaf_count` that fits in u64; values at or above it are rejected so
    // the modulo reduction is exact for every leaf count, not only powers of two.
    let zone = u64::MAX - (u64::MAX % leaf_count);
    loop {
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes).ok()?;
        let value = u64::from_be_bytes(bytes);
        if value < zone {
            return Some(value % leaf_count);
        }
    }
}

/// Samples a uniformly random Path ORAM leaf for a remap, padding, or dummy access.
///
/// Every remap leaf handed to [`access_private_hnsw_oram_path`] and every padding/dummy leaf
/// fed into a fixed-budget plan MUST be an independent uniform sample such as this one. The
/// server observes the sequence of accessed paths, so a predictable schedule (for example a
/// counter, or reusing the previous leaf) lets it link consecutive accesses and defeats the
/// ORAM obliviousness guarantee.
pub fn sample_private_hnsw_oram_leaf(tree_height: u32) -> Result<u64, PrivateHnswClientError> {
    let leaf_count = private_hnsw_oram_leaf_count(tree_height)?;
    sample_uniform_leaf(&SystemRandom::new(), leaf_count)
        .ok_or_else(|| EncryptionError::RandomFailure.into())
}

pub fn encode_private_hnsw_oram_leaf_label(
    leaf: u64,
    tree_height: u32,
) -> Result<String, PrivateHnswClientError> {
    validate_private_hnsw_oram_leaf(leaf, tree_height)?;
    Ok(BASE64URL_NOPAD.encode(&leaf.to_be_bytes()))
}

pub fn decode_private_hnsw_oram_leaf_label(
    label: &str,
    tree_height: u32,
) -> Result<u64, PrivateHnswClientError> {
    let bytes = decode_private_hnsw_oram_leaf_label_shape(label)?;
    let leaf = u64::from_be_bytes(bytes);
    validate_private_hnsw_oram_leaf(leaf, tree_height)?;
    Ok(leaf)
}

fn decode_client_state_snapshot_node_id(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidClientStateSnapshot);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidClientStateSnapshot)
}

pub fn private_hnsw_oram_bucket_ids_for_leaf(
    leaf: u64,
    tree_height: u32,
) -> Result<Vec<u64>, PrivateHnswClientError> {
    validate_private_hnsw_oram_leaf(leaf, tree_height)?;
    let mut bucket_ids = Vec::with_capacity(private_hnsw_oram_path_len(tree_height)?);
    for level in 0..=tree_height {
        let level_start = (1u64 << level) - 1;
        let prefix = if level == 0 {
            0
        } else {
            leaf >> (tree_height - level)
        };
        bucket_ids.push(level_start + prefix);
    }
    Ok(bucket_ids)
}

pub fn private_hnsw_oram_bucket_ids_for_leaf_labels<'a>(
    leaf_labels: impl IntoIterator<Item = &'a str>,
    tree_height: u32,
    bucket_count: u64,
) -> Result<Vec<u64>, PrivateHnswClientError> {
    if bucket_count != private_hnsw_oram_bucket_count(tree_height)? {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    let mut bucket_ids = Vec::new();
    let mut seen_leaf_labels = BTreeSet::new();
    for label in leaf_labels {
        let leaf = decode_private_hnsw_oram_leaf_label(label, tree_height)?;
        if !seen_leaf_labels.insert(label) {
            return Err(PrivateHnswClientError::InvalidSearchConfig("leaf_labels"));
        }
        bucket_ids.extend(private_hnsw_oram_bucket_ids_for_leaf(leaf, tree_height)?);
    }
    if bucket_ids.is_empty() {
        return Err(PrivateHnswClientError::InvalidSearchConfig("leaf_labels"));
    }
    Ok(bucket_ids)
}

pub fn empty_private_hnsw_oram_plaintext_bucket(
    bucket_id: u64,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramPlaintextBucket, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    Ok(PrivateHnswOramPlaintextBucket {
        bucket_id,
        blocks: vec![None; config.bucket_size],
    })
}

pub fn build_private_hnsw_oram_plaintext_index_from_blocks(
    config: PrivateHnswOramClientConfig,
    blocks: &[PrivateHnswNodeBlockPlaintext],
    leaves: &[u64],
) -> Result<PrivateHnswPlaintextIndexBuild, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if blocks.is_empty() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("blocks"));
    }
    if blocks.len() != leaves.len() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("leaves"));
    }

    let bucket_count = private_hnsw_oram_bucket_count(config.tree_height)?;
    let bucket_count_usize: usize = bucket_count
        .try_into()
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    let mut buckets = Vec::with_capacity(bucket_count_usize);
    for bucket_id in 0..bucket_count {
        buckets.push(empty_private_hnsw_oram_plaintext_bucket(bucket_id, config)?);
    }

    let mut state = PrivateHnswOramClientState::new();
    let mut seen_nodes = BTreeSet::new();
    let mut seen_point_tokens = BTreeSet::new();
    let mut seen_payload_fetch_tokens = BTreeSet::new();
    for (block, leaf) in blocks.iter().zip(leaves) {
        if !seen_nodes.insert(block.node_id) {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        if !seen_point_tokens.insert(block.point_token) {
            return Err(PrivateHnswClientError::InvalidBuildConfig("point_token"));
        }
        if let Some(payload_fetch_token) = block.payload_fetch_token
            && !seen_payload_fetch_tokens.insert(payload_fetch_token)
        {
            return Err(PrivateHnswClientError::InvalidBuildConfig(
                "payload_fetch_token",
            ));
        }
        validate_private_hnsw_oram_leaf(*leaf, config.tree_height)?;
        encode_private_hnsw_node_block(
            block,
            config.block_size_bytes,
            config.fixed_neighbor_slots,
        )?;
        state.insert_position(block.node_id, *leaf, config.tree_height)?;

        let mut placed = false;
        for bucket_id in private_hnsw_oram_bucket_ids_for_leaf(*leaf, config.tree_height)?
            .into_iter()
            .rev()
        {
            let bucket_index: usize =
                bucket_id
                    .try_into()
                    .map_err(|_| PrivateHnswClientError::BucketOutOfRange {
                        bucket_id,
                        bucket_count,
                    })?;
            let bucket =
                buckets
                    .get_mut(bucket_index)
                    .ok_or(PrivateHnswClientError::BucketOutOfRange {
                        bucket_id,
                        bucket_count,
                    })?;
            if let Some(slot) = bucket.blocks.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(block.clone());
                placed = true;
                break;
            }
        }
        if !placed {
            return Err(PrivateHnswClientError::OramInitialPlacementOverflow { leaf: *leaf });
        }
    }

    let logical_node_count: u64 = blocks
        .len()
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBuildConfig("blocks"))?;
    let bucket_size: u64 = config
        .bucket_size
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("bucket_size"))?;
    let capacity = bucket_count
        .checked_mul(bucket_size)
        .ok_or(PrivateHnswClientError::BucketCountMismatch)?;
    let dummy_node_count = capacity
        .checked_sub(logical_node_count)
        .ok_or(PrivateHnswClientError::BucketCountMismatch)?;

    Ok(PrivateHnswPlaintextIndexBuild {
        entry_node_id: blocks[0].node_id,
        state,
        buckets,
        logical_node_count,
        dummy_node_count,
    })
}

/// Reserves `reserved_physical_slots` empty slots of a plaintext build as free headroom
/// instead of counting them as dummy nodes. Sealing counts every empty slot as a dummy, which
/// leaves an index at full occupancy; an index that will enroll into private ORAM mutation V2
/// must keep the immutable manifest's reserved physical slots free (the sealed bytes do not
/// change, only the declared occupancy).
pub fn reserve_private_hnsw_oram_physical_slots(
    build: &mut PrivateHnswPlaintextIndexBuild,
    reserved_physical_slots: u64,
) -> Result<(), PrivateHnswClientError> {
    if reserved_physical_slots == 0 || reserved_physical_slots > build.dummy_node_count {
        return Err(PrivateHnswClientError::InvalidBuildConfig(
            "reserved_physical_slots",
        ));
    }
    build.dummy_node_count -= reserved_physical_slots;
    Ok(())
}

pub fn build_private_hnsw_oram_plaintext_index_from_f32_points(
    config: PrivateHnswOramClientConfig,
    distance: DistanceKind,
    neighbor_count: usize,
    points: &[PrivateHnswBuildPoint],
    leaves: &[u64],
) -> Result<PrivateHnswPlaintextIndexBuild, PrivateHnswClientError> {
    let levels = vec![0; points.len()];
    build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
        config,
        distance,
        neighbor_count,
        0,
        points,
        &levels,
        leaves,
    )
}

pub fn build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
    config: PrivateHnswOramClientConfig,
    distance: DistanceKind,
    base_neighbor_count: usize,
    upper_neighbor_count: usize,
    max_level: u8,
    points: &[PrivateHnswBuildPoint],
    leaves: &[u64],
) -> Result<PrivateHnswPlaintextIndexBuild, PrivateHnswClientError> {
    if max_level >= 64 {
        return Err(PrivateHnswClientError::InvalidBuildConfig("max_level"));
    }
    let levels = points
        .iter()
        .map(|point| private_hnsw_level_from_node_id(point.node_id, max_level))
        .collect::<Result<Vec<_>, _>>()?;
    build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
        config,
        distance,
        base_neighbor_count,
        upper_neighbor_count,
        points,
        &levels,
        leaves,
    )
}

pub fn private_hnsw_level_from_node_id(
    node_id: [u8; 32],
    max_level: u8,
) -> Result<u8, PrivateHnswClientError> {
    if max_level >= 64 {
        return Err(PrivateHnswClientError::InvalidBuildConfig("max_level"));
    }
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_HNSW_LEVEL_ASSIGNMENT_DOMAIN);
    hasher.update(node_id);
    let digest = hasher.finalize();

    let mut level = 0u8;
    for byte in digest {
        let trailing_zeros = byte.trailing_zeros() as u8;
        level = level
            .checked_add(trailing_zeros)
            .ok_or(PrivateHnswClientError::InvalidBuildConfig("max_level"))?;
        if level >= max_level {
            return Ok(max_level);
        }
        if trailing_zeros < 8 {
            break;
        }
    }
    Ok(level)
}

pub fn private_hnsw_node_reaches_level(block: &PrivateHnswNodeBlockPlaintext, level: u8) -> bool {
    if level >= 64 {
        return false;
    }
    block.level_mask & (1u64 << level) != 0
}

fn private_hnsw_level_mask(point_level: u8) -> Result<u64, PrivateHnswClientError> {
    if point_level >= 64 {
        return Err(PrivateHnswClientError::InvalidBuildConfig("levels"));
    }
    if point_level == 63 {
        return Ok(u64::MAX);
    }
    Ok((1u64 << (u32::from(point_level) + 1)) - 1)
}

/// Assigns leaves by BFS rank from the entry node, which places neighbors on adjacent paths.
///
/// That is a benchmark convenience only: Path ORAM's access-pattern guarantee needs uniformly
/// random, independent initial positions, and a tree built from these leaves reveals each
/// node's BFS rank (hence the traversal) on its first access. Production builds draw leaves
/// with [`sample_private_hnsw_oram_leaf`].
#[doc(hidden)]
pub fn plan_private_hnsw_oram_neighbor_clustered_leaves_for_benchmarks(
    config: PrivateHnswOramClientConfig,
    blocks: &[PrivateHnswNodeBlockPlaintext],
    entry_node_id: [u8; 32],
) -> Result<Vec<u64>, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if blocks.is_empty() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("blocks"));
    }
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height)?;

    let mut index_by_node = BTreeMap::new();
    for (index, block) in blocks.iter().enumerate() {
        if index_by_node.insert(block.node_id, index).is_some() {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
    }

    if !index_by_node.contains_key(&entry_node_id) {
        return Err(PrivateHnswClientError::InvalidBuildConfig("entry_node_id"));
    }
    let seed_node_id = entry_node_id;
    let mut queue = VecDeque::from([seed_node_id]);
    let mut queued = BTreeSet::from([seed_node_id]);
    let mut visited = BTreeSet::new();
    let mut clustered_indexes = Vec::with_capacity(blocks.len());

    while let Some(node_id) = queue.pop_front() {
        queued.remove(&node_id);
        if !visited.insert(node_id) {
            continue;
        }
        let Some(index) = index_by_node.get(&node_id).copied() else {
            continue;
        };
        clustered_indexes.push(index);
        for neighbor_id in &blocks[index].neighbors {
            if index_by_node.contains_key(neighbor_id)
                && !visited.contains(neighbor_id)
                && queued.insert(*neighbor_id)
            {
                queue.push_back(*neighbor_id);
            }
        }
    }

    for (index, block) in blocks.iter().enumerate() {
        if !visited.contains(&block.node_id) {
            clustered_indexes.push(index);
        }
    }

    let mut leaves = vec![0; blocks.len()];
    for (rank, index) in clustered_indexes.into_iter().enumerate() {
        let rank = u64::try_from(rank)
            .map_err(|_| PrivateHnswClientError::InvalidBuildConfig("points"))?;
        leaves[index] = rank % leaf_count;
    }
    Ok(leaves)
}

pub fn plan_private_hnsw_oram_directional_neighbor_filter(
    current_block: &PrivateHnswNodeBlockPlaintext,
    neighbor_blocks: &[PrivateHnswNodeBlockPlaintext],
    query: &[f32],
    distance: DistanceKind,
    max_neighbors: usize,
) -> Result<PrivateHnswDirectionalNeighborFilterPlan, PrivateHnswClientError> {
    if max_neighbors == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig("max_neighbors"));
    }
    if query.is_empty() {
        return Err(PrivateHnswClientError::InvalidSearchConfig("query"));
    }
    if query.iter().any(|value| !value.is_finite()) {
        return Err(PrivateHnswClientError::NonFiniteDistance);
    }

    let current_vector = decode_private_hnsw_f32_vector(current_block)?;
    if current_vector.len() != query.len() {
        return Err(PrivateHnswClientError::VectorDimensionMismatch);
    }

    let allowed_neighbors = current_block
        .neighbors
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut seen_neighbors = BTreeSet::new();
    let mut candidates = Vec::new();
    for block in neighbor_blocks {
        if !allowed_neighbors.contains(&block.node_id) {
            continue;
        }
        if !seen_neighbors.insert(block.node_id) {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        if block.deleted {
            continue;
        }

        let vector = decode_private_hnsw_f32_vector(block)?;
        if vector.len() != query.len() {
            return Err(PrivateHnswClientError::VectorDimensionMismatch);
        }
        let direction_score = directional_neighbor_score(&current_vector, &vector, query)?;
        if direction_score <= 0.0 {
            continue;
        }
        let query_distance = private_hnsw_f32_distance(query, &vector, distance)?;
        candidates.push((block.node_id, query_distance, direction_score));
    }

    candidates.sort_by(|lhs, rhs| {
        lhs.1
            .total_cmp(&rhs.1)
            .then_with(|| rhs.2.total_cmp(&lhs.2))
            .then_with(|| lhs.0.cmp(&rhs.0))
    });

    let node_ids = candidates
        .into_iter()
        .take(max_neighbors)
        .map(|candidate| candidate.0)
        .collect::<Vec<_>>();
    Ok(PrivateHnswDirectionalNeighborFilterPlan {
        retained_count: node_ids.len(),
        node_ids,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_private_hnsw_oram_graph_traversal_path_batch(
    state: &PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    current_block: &PrivateHnswNodeBlockPlaintext,
    neighbor_blocks: &[PrivateHnswNodeBlockPlaintext],
    query: &[f32],
    distance: DistanceKind,
    fixed_path_count: usize,
    next_padding_leaf: impl FnMut() -> Result<u64, PrivateHnswClientError>,
) -> Result<PrivateHnswSpeculativePrefetchPlan, PrivateHnswClientError> {
    let plan = plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
        state,
        config,
        current_block,
        neighbor_blocks,
        query,
        distance,
        fixed_path_count,
        next_padding_leaf,
    )?;
    Ok(PrivateHnswSpeculativePrefetchPlan {
        leaf_labels: plan.leaf_labels,
        real_path_count: plan.real_path_count,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
    state: &PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    current_block: &PrivateHnswNodeBlockPlaintext,
    neighbor_blocks: &[PrivateHnswNodeBlockPlaintext],
    query: &[f32],
    distance: DistanceKind,
    fixed_path_count: usize,
    next_padding_leaf: impl FnMut() -> Result<u64, PrivateHnswClientError>,
) -> Result<PrivateHnswGraphTraversalPathBatchPlan, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if fixed_path_count == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "fixed_path_count",
        ));
    }
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height)?;
    if u64::try_from(fixed_path_count)
        .map_err(|_| PrivateHnswClientError::InvalidSearchConfig("fixed_path_count"))?
        > leaf_count
    {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "fixed_path_count",
        ));
    }

    let directional_plan = plan_private_hnsw_oram_directional_neighbor_filter(
        current_block,
        neighbor_blocks,
        query,
        distance,
        fixed_path_count,
    )?;
    let prefetch_plan = plan_private_hnsw_oram_speculative_prefetch(
        state,
        config,
        &directional_plan.node_ids,
        fixed_path_count,
        next_padding_leaf,
    )?;
    Ok(PrivateHnswGraphTraversalPathBatchPlan {
        leaf_labels: prefetch_plan.leaf_labels,
        real_path_count: prefetch_plan.real_path_count,
        retained_neighbor_count: directional_plan.retained_count,
    })
}

pub fn build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
    config: PrivateHnswOramClientConfig,
    distance: DistanceKind,
    base_neighbor_count: usize,
    upper_neighbor_count: usize,
    points: &[PrivateHnswBuildPoint],
    levels: &[u8],
    leaves: &[u64],
) -> Result<PrivateHnswPlaintextIndexBuild, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if points.is_empty() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("points"));
    }
    if points.len() != leaves.len() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("leaves"));
    }
    if points.len() != levels.len() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("levels"));
    }
    if base_neighbor_count > config.fixed_neighbor_slots {
        return Err(PrivateHnswClientError::TooManyNeighbors {
            actual: base_neighbor_count,
            limit: config.fixed_neighbor_slots,
        });
    }
    if upper_neighbor_count > config.fixed_neighbor_slots {
        return Err(PrivateHnswClientError::TooManyNeighbors {
            actual: upper_neighbor_count,
            limit: config.fixed_neighbor_slots,
        });
    }

    let dim = points[0].vector.len();
    if dim == 0 {
        return Err(PrivateHnswClientError::InvalidBuildConfig("vector"));
    }
    let mut seen_nodes = BTreeSet::new();
    for point in points {
        if !seen_nodes.insert(point.node_id) {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        if point.vector.len() != dim {
            return Err(PrivateHnswClientError::VectorDimensionMismatch);
        }
        if point.vector.iter().any(|value| !value.is_finite()) {
            return Err(PrivateHnswClientError::NonFiniteDistance);
        }
    }
    if levels.iter().any(|level| *level >= 64) {
        return Err(PrivateHnswClientError::InvalidBuildConfig("levels"));
    }

    let mut blocks = Vec::with_capacity(points.len());
    for (index, point) in points.iter().enumerate() {
        let point_level = levels[index];
        let mut neighbors = Vec::new();
        let mut neighbor_levels = Vec::new();
        for level in (0..=point_level).rev() {
            let neighbor_count = if level == 0 {
                base_neighbor_count
            } else {
                upper_neighbor_count
            };
            for node_id in select_private_hnsw_layer_neighbors(
                points,
                levels,
                index,
                level,
                distance,
                neighbor_count,
            )? {
                neighbors.push(node_id);
                neighbor_levels.push(level);
            }
        }
        if neighbors.len() > config.fixed_neighbor_slots {
            return Err(PrivateHnswClientError::TooManyNeighbors {
                actual: neighbors.len(),
                limit: config.fixed_neighbor_slots,
            });
        }
        let vector = point
            .vector
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        blocks.push(PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: point.node_id,
            point_token: point.point_token,
            level_mask: private_hnsw_level_mask(point_level)?,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector,
            neighbor_levels,
            neighbors,
            deleted: false,
            generation: 1,
            payload_fetch_token: point.payload_fetch_token,
        });
    }

    build_private_hnsw_oram_plaintext_index_from_blocks(config, &blocks, leaves)
}

fn select_private_hnsw_layer_neighbors(
    points: &[PrivateHnswBuildPoint],
    levels: &[u8],
    source_index: usize,
    level: u8,
    distance: DistanceKind,
    neighbor_count: usize,
) -> Result<Vec<[u8; 32]>, PrivateHnswClientError> {
    if points.is_empty() || source_index >= points.len() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("points"));
    }
    if points.len() != levels.len() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("levels"));
    }
    if neighbor_count == 0 {
        return Ok(Vec::new());
    }
    let source = points
        .get(source_index)
        .ok_or(PrivateHnswClientError::InvalidBuildConfig("points"))?;
    let candidate_capacity = points
        .len()
        .checked_sub(1)
        .ok_or(PrivateHnswClientError::InvalidBuildConfig("points"))?;
    let mut candidates = Vec::with_capacity(candidate_capacity);
    for (candidate_index, candidate) in points.iter().enumerate() {
        if candidate_index == source_index || levels[candidate_index] < level {
            continue;
        }
        candidates.push((
            private_hnsw_f32_distance(&source.vector, &candidate.vector, distance)?,
            candidate.node_id,
            candidate_index,
        ));
    }
    candidates.sort_by(|lhs, rhs| lhs.0.total_cmp(&rhs.0).then_with(|| lhs.1.cmp(&rhs.1)));

    let mut selected = Vec::new();
    let mut selected_indices: Vec<usize> = Vec::new();
    for (source_distance, node_id, candidate_index) in candidates {
        let mut redundant = false;
        for selected_index in &selected_indices {
            let selected_distance = private_hnsw_f32_distance(
                &points[candidate_index].vector,
                &points[*selected_index].vector,
                distance,
            )?;
            if selected_distance < source_distance {
                redundant = true;
                break;
            }
        }
        if redundant {
            continue;
        }
        selected.push(node_id);
        selected_indices.push(candidate_index);
        if selected.len() == neighbor_count {
            break;
        }
    }

    Ok(selected)
}

pub fn encode_private_hnsw_oram_bucket_plaintext(
    bucket: &PrivateHnswOramPlaintextBucket,
    config: PrivateHnswOramClientConfig,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if bucket.blocks.len() != config.bucket_size {
        return Err(PrivateHnswClientError::BucketPlaintextSlotCountMismatch);
    }
    validate_private_hnsw_plaintext_bucket_tokens(&bucket.blocks)?;
    let bucket_size_u32: u32 = config
        .bucket_size
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("bucket_size"))?;
    let block_size_u32: u32 = config
        .block_size_bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("block_size_bytes"))?;

    let mut encoded = Vec::with_capacity(private_hnsw_bucket_plaintext_len(config)?);
    encoded.extend_from_slice(BUCKET_PLAINTEXT_MAGIC);
    push_u16(&mut encoded, BUCKET_PLAINTEXT_VERSION);
    push_u32(&mut encoded, bucket_size_u32);
    push_u32(&mut encoded, block_size_u32);

    for slot in &bucket.blocks {
        match slot {
            Some(block) => {
                encoded.push(1);
                encoded.extend_from_slice(&encode_private_hnsw_node_block(
                    block,
                    config.block_size_bytes,
                    config.fixed_neighbor_slots,
                )?);
            }
            None => {
                encoded.push(0);
                let next_len = encoded.len().checked_add(config.block_size_bytes).ok_or(
                    PrivateHnswClientError::InvalidOramClientConfig("block_size_bytes"),
                )?;
                encoded.resize(next_len, 0);
            }
        }
    }
    Ok(encoded)
}

pub fn decode_private_hnsw_oram_bucket_plaintext(
    bucket_id: u64,
    encoded: &[u8],
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramPlaintextBucket, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    let expected_len = private_hnsw_bucket_plaintext_len(config)?;
    if encoded.len() != expected_len {
        return Err(PrivateHnswClientError::InvalidBucketPlaintext);
    }

    let mut cursor = 0;
    let magic = read_exact(encoded, &mut cursor, BUCKET_PLAINTEXT_MAGIC.len())?;
    if magic != BUCKET_PLAINTEXT_MAGIC {
        return Err(PrivateHnswClientError::InvalidBucketPlaintext);
    }
    let version = read_u16(encoded, &mut cursor)?;
    if version != BUCKET_PLAINTEXT_VERSION {
        return Err(PrivateHnswClientError::InvalidBucketPlaintext);
    }
    let encoded_bucket_size = read_u32_usize(encoded, &mut cursor)?;
    let encoded_block_size = read_u32_usize(encoded, &mut cursor)?;
    if encoded_bucket_size != config.bucket_size || encoded_block_size != config.block_size_bytes {
        return Err(PrivateHnswClientError::BucketPlaintextMetadataMismatch);
    }

    let mut blocks = Vec::with_capacity(config.bucket_size);
    for _ in 0..config.bucket_size {
        let occupied = read_u8(encoded, &mut cursor)?;
        let block_bytes = read_exact(encoded, &mut cursor, config.block_size_bytes)?;
        match occupied {
            0 => {
                if block_bytes.iter().any(|byte| *byte != 0) {
                    return Err(PrivateHnswClientError::InvalidBucketPlaintext);
                }
                blocks.push(None);
            }
            1 => blocks.push(Some(decode_private_hnsw_node_block(block_bytes)?)),
            _ => return Err(PrivateHnswClientError::InvalidBucketPlaintext),
        }
    }

    validate_private_hnsw_plaintext_bucket_tokens(&blocks)?;
    Ok(PrivateHnswOramPlaintextBucket { bucket_id, blocks })
}

fn validate_private_hnsw_plaintext_bucket_tokens(
    blocks: &[Option<PrivateHnswNodeBlockPlaintext>],
) -> Result<(), PrivateHnswClientError> {
    let mut node_ids = BTreeSet::new();
    let mut point_tokens = BTreeSet::new();
    let mut payload_fetch_tokens = BTreeSet::new();
    for block in blocks.iter().flatten() {
        if !node_ids.insert(block.node_id) {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        if !point_tokens.insert(block.point_token) {
            return Err(PrivateHnswClientError::DuplicatePointToken);
        }
        if let Some(payload_fetch_token) = block.payload_fetch_token
            && !payload_fetch_tokens.insert(payload_fetch_token)
        {
            return Err(PrivateHnswClientError::DuplicatePayloadFetchToken);
        }
    }
    Ok(())
}

pub fn open_private_hnsw_oram_plaintext_bucket(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    bucket: &PrivateHnswOramBucket,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramPlaintextBucket, PrivateHnswClientError> {
    let plaintext = open_private_hnsw_oram_bucket(
        keys,
        base_context.for_bucket(bucket.bucket_id, bucket.index_epoch),
        bucket,
    )?;
    decode_private_hnsw_oram_bucket_plaintext(bucket.bucket_id, &plaintext, config)
}

#[allow(clippy::too_many_arguments)]
pub fn open_private_hnsw_oram_verified_path_batch(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    config: PrivateHnswOramClientConfig,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    proof_value: &str,
    buckets: &[PrivateHnswOramBucket],
) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError> {
    verify_private_hnsw_oram_merkle_proof_json(
        proof_value,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )?;
    buckets
        .iter()
        .map(|bucket| open_private_hnsw_oram_plaintext_bucket(keys, base_context, bucket, config))
        .collect()
}

pub fn seal_private_hnsw_oram_plaintext_bucket(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    index_epoch: u64,
    bucket: &PrivateHnswOramPlaintextBucket,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramBucket, PrivateHnswClientError> {
    let plaintext = encode_private_hnsw_oram_bucket_plaintext(bucket, config)?;
    seal_private_hnsw_oram_bucket(
        keys,
        base_context.for_bucket(bucket.bucket_id, index_epoch),
        &plaintext,
    )
}

pub fn seal_private_hnsw_oram_plaintext_index(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    index_epoch: u64,
    build: &PrivateHnswPlaintextIndexBuild,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswEncryptedIndexBuild, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    let bucket_count = private_hnsw_oram_bucket_count(config.tree_height)?;
    let bucket_count_usize: usize = bucket_count
        .try_into()
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    if build.buckets.len() != bucket_count_usize {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }

    let mut buckets = Vec::with_capacity(build.buckets.len());
    for (expected_bucket_id, bucket) in build.buckets.iter().enumerate() {
        let expected_bucket_id = u64::try_from(expected_bucket_id)
            .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
        if bucket.bucket_id != expected_bucket_id {
            return Err(PrivateHnswClientError::PathBucketMismatch);
        }
        buckets.push(seal_private_hnsw_oram_plaintext_bucket(
            keys,
            base_context,
            index_epoch,
            bucket,
            config,
        )?);
    }
    let root_hash = private_hnsw_oram_merkle_root_for_commitments(
        &buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>(),
    )?;

    Ok(PrivateHnswEncryptedIndexBuild {
        index_epoch,
        entry_node_id: build.entry_node_id,
        root_hash,
        bucket_count,
        logical_node_count: build.logical_node_count,
        dummy_node_count: build.dummy_node_count,
        buckets,
    })
}

pub fn build_private_hnsw_oram_manifest_from_encrypted_index(
    context: PrivateHnswManifestBuildContext<'_>,
    build: &PrivateHnswEncryptedIndexBuild,
) -> Result<PrivateHnswOramManifest, PrivateHnswClientError> {
    validate_manifest_build_context(&context)?;
    if build.bucket_count != private_hnsw_oram_bucket_count(context.oram.tree_height)? {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    decode_merkle_root(&build.root_hash)?;

    Ok(PrivateHnswOramManifest {
        version: 1,
        provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
        collection_id: context.collection_id.to_string(),
        vector_name: context.vector_name.to_string(),
        key_id: context.key_id.to_string(),
        rk_id: context.rk_id.to_string(),
        rk_epoch: context.rk_epoch,
        dim: context.dim,
        distance: context.distance,
        hnsw: context.hnsw,
        oram: context.oram,
        fixed_budget: context.fixed_budget,
        index_epoch: build.index_epoch,
        root_hash: build.root_hash.clone(),
        bucket_count: build.bucket_count,
        logical_node_count: build.logical_node_count,
        dummy_node_count: build.dummy_node_count,
        result_privacy: context.result_privacy,
        owner_signing_key_id: context.owner_signing_key_id.to_string(),
        created_at_unix: context.created_at_unix,
    })
}

pub fn package_private_hnsw_oram_upload_bundle(
    key_pair: &Ed25519KeyPair,
    context: PrivateHnswManifestBuildContext<'_>,
    build: &PrivateHnswEncryptedIndexBuild,
) -> Result<PrivateHnswOramUploadBundle, PrivateHnswClientError> {
    let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(context, build)?;
    let manifest_signature = sign_private_hnsw_oram_manifest(key_pair, &manifest)?;
    let bundle = PrivateHnswOramUploadBundle {
        manifest,
        manifest_signature,
        buckets: build.buckets.clone(),
    };
    validate_private_hnsw_oram_upload_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_private_hnsw_oram_upload_bundle(
    bundle: &PrivateHnswOramUploadBundle,
) -> Result<Vec<String>, PrivateHnswClientError> {
    let manifest = &bundle.manifest;
    validate_private_hnsw_oram_manifest_shape(manifest)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest"))?;
    validate_private_hnsw_oram_manifest_signature_shape(&bundle.manifest_signature).map_err(
        |_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest_signature"),
    )?;
    if bundle.manifest_signature.key_id != manifest.owner_signing_key_id {
        return Err(PrivateHnswClientError::InvalidManifestSignatureContext(
            "owner_signing_key_id",
        ));
    }
    let expected_bucket_count = private_hnsw_oram_bucket_count(manifest.oram.tree_height)?;
    if manifest.bucket_count != expected_bucket_count {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    let bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    // The bundle must carry exactly one bucket per tree slot before anything is sized from the
    // manifest's tree height, as the server-side validator already requires.
    if bundle.buckets.len() != bucket_count {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    decode_merkle_root(&manifest.root_hash)?;
    let expected_ciphertext_bytes = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("oram"))?;

    let base_context = PrivateHnswBucketAeadBaseContext {
        collection_id: &manifest.collection_id,
        vector_name: &manifest.vector_name,
        key_id: &manifest.key_id,
        rk_id: &manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
    };
    let mut commitments = vec![None; bucket_count];
    for bucket in &bundle.buckets {
        validate_private_hnsw_upload_bucket(
            base_context,
            bucket,
            manifest.index_epoch,
            manifest.bucket_count,
            expected_ciphertext_bytes,
        )?;
        let bucket_index = usize::try_from(bucket.bucket_id)
            .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
        if commitments[bucket_index]
            .replace(bucket.bucket_commitment.clone())
            .is_some()
        {
            return Err(PrivateHnswClientError::DuplicateBucket {
                bucket_id: bucket.bucket_id,
            });
        }
    }
    let commitments = commitments
        .into_iter()
        .enumerate()
        .map(|(bucket_id, commitment)| {
            let bucket_id = u64::try_from(bucket_id)
                .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
            commitment.ok_or(PrivateHnswClientError::MissingBucket { bucket_id })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if private_hnsw_oram_merkle_root_for_commitments(&commitments)? != manifest.root_hash {
        return Err(PrivateHnswClientError::MerkleRootMismatch);
    }
    Ok(commitments)
}

pub fn validate_private_hnsw_oram_upload_bundle_with_signature(
    bundle: &PrivateHnswOramUploadBundle,
    validation_context: PrivateHnswManifestValidationContext<'_>,
) -> Result<Vec<String>, PrivateHnswClientError> {
    let commitments = validate_private_hnsw_oram_upload_bundle(bundle)?;
    validate_private_hnsw_oram_manifest(
        &bundle.manifest,
        Some(&bundle.manifest_signature),
        validation_context,
    )
    .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest_signature"))?;
    Ok(commitments)
}

pub(crate) fn validate_private_hnsw_upload_bucket(
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    bucket: &PrivateHnswOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    expected_ciphertext_bytes: usize,
) -> Result<(), PrivateHnswClientError> {
    if bucket.version != 1 {
        return Err(PrivateHnswClientError::UnsupportedBucketVersion(
            bucket.version,
        ));
    }
    if bucket.index_epoch != expected_epoch {
        return Err(PrivateHnswClientError::StaleBucketEpoch {
            bucket_id: bucket.bucket_id,
            expected_epoch,
            actual_epoch: bucket.index_epoch,
        });
    }
    if bucket.bucket_id >= bucket_count {
        return Err(PrivateHnswClientError::BucketOutOfRange {
            bucket_id: bucket.bucket_id,
            bucket_count,
        });
    }

    let Some(decoded_len) = base64url_nopad_decoded_len(bucket.ciphertext.len()) else {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
    };
    if decoded_len != expected_ciphertext_bytes {
        return Err(PrivateHnswClientError::BucketCiphertextSizeMismatch {
            bucket_id: bucket.bucket_id,
            expected_bytes: expected_ciphertext_bytes,
            actual_bytes: decoded_len,
        });
    }
    let raw_ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
    if raw_ciphertext.len() < 1 + BUCKET_AEAD_NONCE_LEN + BUCKET_AEAD_TAG_LEN {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
    }
    if raw_ciphertext[0] != BUCKET_AEAD_VERSION {
        return Err(PrivateHnswClientError::UnsupportedBucketCiphertextVersion(
            raw_ciphertext[0],
        ));
    }
    if base64url_sha256(&raw_ciphertext) != bucket.ciphertext_sha256 {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextHash);
    }
    let expected_commitment = private_hnsw_bucket_commitment(
        base_context.for_bucket(bucket.bucket_id, bucket.index_epoch),
        &bucket.ciphertext_sha256,
    )?;
    if expected_commitment != bucket.bucket_commitment {
        return Err(PrivateHnswClientError::InvalidBucketCommitment);
    }
    Ok(())
}

pub fn refresh_private_hnsw_oram_manifest_for_commit(
    manifest: &PrivateHnswOramManifest,
    plan: &PrivateHnswClientCommitPlan,
) -> Result<PrivateHnswOramManifest, PrivateHnswClientError> {
    validate_private_hnsw_oram_manifest_shape(manifest)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest"))?;
    if manifest.index_epoch != plan.old_epoch || manifest.root_hash != plan.old_root_hash {
        return Err(PrivateHnswClientError::ManifestCommitMismatch);
    }
    if Some(plan.new_epoch) != plan.old_epoch.checked_add(1) {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    decode_merkle_root(&plan.new_root_hash)?;

    let mut refreshed = manifest.clone();
    refreshed.index_epoch = plan.new_epoch;
    refreshed.root_hash = plan.new_root_hash.clone();
    Ok(refreshed)
}

pub fn sign_private_hnsw_oram_manifest_refresh(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
    plan: &PrivateHnswClientCommitPlan,
) -> Result<(PrivateHnswOramManifest, PrivateHnswOramSignature), PrivateHnswClientError> {
    let refreshed = refresh_private_hnsw_oram_manifest_for_commit(manifest, plan)?;
    let signature = sign_private_hnsw_oram_manifest(key_pair, &refreshed)?;
    Ok((refreshed, signature))
}

/// Reads the target node's current path into the stash, remaps the node to `remap_leaf`, and
/// evicts the loaded path.
///
/// `remap_leaf` MUST be a fresh, uniformly random leaf (see [`sample_private_hnsw_oram_leaf`]).
/// Only the range is validated here; the obliviousness of the ORAM depends entirely on the
/// caller never using a predictable remap schedule.
pub fn access_private_hnsw_oram_path(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    target_node_id: [u8; 32],
    path_buckets: &[PrivateHnswOramPlaintextBucket],
    remap_leaf: u64,
) -> Result<PrivateHnswOramAccessResult, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    let old_leaf = state
        .position(&target_node_id)
        .ok_or(PrivateHnswClientError::MissingPosition)?;
    validate_private_hnsw_oram_leaf(remap_leaf, config.tree_height)?;
    let expected_bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(old_leaf, config.tree_height)?;
    load_private_hnsw_oram_path_into_stash(
        state,
        config,
        &expected_bucket_ids,
        path_buckets,
        std::slice::from_ref(&target_node_id),
    )?;

    let block = state
        .stash
        .get(&target_node_id)
        .cloned()
        .ok_or(PrivateHnswClientError::MissingBlock)?;
    state.position_map.insert(target_node_id, remap_leaf);
    let writeback_buckets = evict_private_hnsw_loaded_path(state, config, &expected_bucket_ids)?;

    Ok(PrivateHnswOramAccessResult {
        old_leaf,
        new_leaf: remap_leaf,
        old_leaf_label: encode_private_hnsw_oram_leaf_label(old_leaf, config.tree_height)?,
        block,
        writeback_buckets,
    })
}

pub fn access_private_hnsw_oram_path_with_append_rewrite<Rewrite>(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    target_node_id: [u8; 32],
    path_buckets: &[PrivateHnswOramPlaintextBucket],
    remap_leaf: u64,
    rewrite: Rewrite,
) -> Result<PrivateHnswOramAccessResult, PrivateHnswClientError>
where
    Rewrite: FnOnce(
        &PrivateHnswNodeBlockPlaintext,
    ) -> Result<PrivateHnswNodeBlockPlaintext, PrivateHnswClientError>,
{
    validate_oram_client_config(config)?;
    let mut working_state = state.clone();
    let old_leaf = working_state
        .position(&target_node_id)
        .ok_or(PrivateHnswClientError::MissingPosition)?;
    validate_private_hnsw_oram_leaf(remap_leaf, config.tree_height)?;
    let expected_bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(old_leaf, config.tree_height)?;
    load_private_hnsw_oram_path_into_stash(
        &mut working_state,
        config,
        &expected_bucket_ids,
        path_buckets,
        std::slice::from_ref(&target_node_id),
    )?;

    let previous = working_state
        .stash
        .get(&target_node_id)
        .cloned()
        .ok_or(PrivateHnswClientError::MissingBlock)?;
    let replacement = rewrite(&previous)?;
    validate_private_hnsw_append_rewrite(&previous, &replacement, config)?;
    working_state
        .stash
        .insert(target_node_id, replacement.clone());
    working_state
        .position_map
        .insert(target_node_id, remap_leaf);
    let writeback_buckets =
        evict_private_hnsw_loaded_path(&mut working_state, config, &expected_bucket_ids)?;

    *state = working_state;
    Ok(PrivateHnswOramAccessResult {
        old_leaf,
        new_leaf: remap_leaf,
        old_leaf_label: encode_private_hnsw_oram_leaf_label(old_leaf, config.tree_height)?,
        block: replacement,
        writeback_buckets,
    })
}

pub fn evict_private_hnsw_oram_path(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    leaf: u64,
    path_buckets: &[PrivateHnswOramPlaintextBucket],
) -> Result<PrivateHnswOramEvictionResult, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    validate_private_hnsw_oram_leaf(leaf, config.tree_height)?;
    let mut working_state = state.clone();
    let expected_bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
    load_private_hnsw_oram_path_into_stash(
        &mut working_state,
        config,
        &expected_bucket_ids,
        path_buckets,
        &[],
    )?;
    let writeback_buckets =
        evict_private_hnsw_loaded_path(&mut working_state, config, &expected_bucket_ids)?;
    *state = working_state;
    Ok(PrivateHnswOramEvictionResult {
        leaf,
        leaf_label: encode_private_hnsw_oram_leaf_label(leaf, config.tree_height)?,
        writeback_buckets,
    })
}

/// Loads the served path for `leaf` into the stash for an append window slot.
///
/// A slot may carry several accesses whose blocks all sit on this path (their secret positions
/// coincide), so every node in `required_node_ids` must be stashed or on the path before any
/// block is moved. Returns the path's bucket ids, root first, for the matching eviction.
pub(crate) fn load_private_hnsw_oram_path_for_append(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    leaf: u64,
    path_buckets: &[PrivateHnswOramPlaintextBucket],
    required_node_ids: &[[u8; 32]],
) -> Result<Vec<u64>, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    validate_private_hnsw_oram_leaf(leaf, config.tree_height)?;
    let expected_bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
    load_private_hnsw_oram_path_into_stash(
        state,
        config,
        &expected_bucket_ids,
        path_buckets,
        required_node_ids,
    )?;
    Ok(expected_bucket_ids)
}

/// Moves a stashed block to `remap_leaf` and returns it; the block must already be loaded.
pub(crate) fn remap_private_hnsw_oram_stash_block(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    node_id: [u8; 32],
    remap_leaf: u64,
) -> Result<PrivateHnswNodeBlockPlaintext, PrivateHnswClientError> {
    validate_private_hnsw_oram_leaf(remap_leaf, config.tree_height)?;
    let block = state
        .stash
        .get(&node_id)
        .cloned()
        .ok_or(PrivateHnswClientError::MissingBlock)?;
    state.position_map.insert(node_id, remap_leaf);
    Ok(block)
}

/// Replaces a stashed block through an append rewrite and moves it to `remap_leaf`.
pub(crate) fn rewrite_private_hnsw_oram_stash_block<Rewrite>(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    node_id: [u8; 32],
    remap_leaf: u64,
    rewrite: Rewrite,
) -> Result<PrivateHnswNodeBlockPlaintext, PrivateHnswClientError>
where
    Rewrite: FnOnce(
        &PrivateHnswNodeBlockPlaintext,
    ) -> Result<PrivateHnswNodeBlockPlaintext, PrivateHnswClientError>,
{
    validate_private_hnsw_oram_leaf(remap_leaf, config.tree_height)?;
    let previous = state
        .stash
        .get(&node_id)
        .cloned()
        .ok_or(PrivateHnswClientError::MissingBlock)?;
    let replacement = rewrite(&previous)?;
    validate_private_hnsw_append_rewrite(&previous, &replacement, config)?;
    state.stash.insert(node_id, replacement.clone());
    state.position_map.insert(node_id, remap_leaf);
    Ok(replacement)
}

/// Evicts the stash along a path loaded by [`load_private_hnsw_oram_path_for_append`].
pub(crate) fn evict_private_hnsw_oram_loaded_path(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    expected_bucket_ids: &[u64],
) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    evict_private_hnsw_loaded_path(state, config, expected_bucket_ids)
}

/// Validates a served path and moves its blocks into the stash.
///
/// Every check runs before the first block is stashed: a path rejected here leaves the client
/// state untouched. `required_node_ids` are the blocks the accesses need; failing on them after
/// the load would strand the other path blocks in the stash while the server still stores them,
/// and the next read of an overlapping path would then be rejected as a duplicate.
fn load_private_hnsw_oram_path_into_stash(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    expected_bucket_ids: &[u64],
    path_buckets: &[PrivateHnswOramPlaintextBucket],
    required_node_ids: &[[u8; 32]],
) -> Result<(), PrivateHnswClientError> {
    if path_buckets.len() != expected_bucket_ids.len()
        || path_buckets
            .iter()
            .zip(expected_bucket_ids)
            .any(|(bucket, expected_id)| bucket.bucket_id != *expected_id)
    {
        return Err(PrivateHnswClientError::PathBucketMismatch);
    }

    let mut path_node_ids = BTreeSet::new();
    let mut path_point_tokens = state
        .stash
        .values()
        .map(|block| block.point_token)
        .collect::<BTreeSet<_>>();
    let mut path_payload_fetch_tokens = state
        .stash
        .values()
        .filter_map(|block| block.payload_fetch_token)
        .collect::<BTreeSet<_>>();
    for bucket in path_buckets {
        if bucket.blocks.len() != config.bucket_size {
            return Err(PrivateHnswClientError::BucketPlaintextSlotCountMismatch);
        }
        for block in bucket.blocks.iter().flatten() {
            if state.stash.contains_key(&block.node_id) || !path_node_ids.insert(block.node_id) {
                return Err(PrivateHnswClientError::DuplicateBlock);
            }
            if !path_point_tokens.insert(block.point_token) {
                return Err(PrivateHnswClientError::DuplicatePointToken);
            }
            if let Some(payload_fetch_token) = block.payload_fetch_token
                && !path_payload_fetch_tokens.insert(payload_fetch_token)
            {
                return Err(PrivateHnswClientError::DuplicatePayloadFetchToken);
            }
        }
    }
    if required_node_ids
        .iter()
        .any(|required| !state.stash.contains_key(required) && !path_node_ids.contains(required))
    {
        return Err(PrivateHnswClientError::MissingBlock);
    }
    for block in path_buckets
        .iter()
        .flat_map(|bucket| bucket.blocks.iter().flatten())
    {
        state.stash.insert(block.node_id, block.clone());
    }
    Ok(())
}

fn evict_private_hnsw_loaded_path(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    expected_bucket_ids: &[u64],
) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError> {
    let mut writeback_by_bucket = BTreeMap::new();
    for bucket_id in expected_bucket_ids.iter().rev() {
        let mut blocks = Vec::with_capacity(config.bucket_size);
        while blocks.len() < config.bucket_size {
            let candidate_node_id = state.stash.keys().copied().find(|node_id| {
                let Some(leaf) = state.position_map.get(node_id) else {
                    return false;
                };
                private_hnsw_oram_bucket_ids_for_leaf(*leaf, config.tree_height)
                    .map(|path| path.contains(bucket_id))
                    .unwrap_or(false)
            });
            let Some(candidate_node_id) = candidate_node_id else {
                break;
            };
            let block = state
                .stash
                .remove(&candidate_node_id)
                .ok_or(PrivateHnswClientError::MissingBlock)?;
            blocks.push(Some(block));
        }
        blocks.resize(config.bucket_size, None);
        writeback_by_bucket.insert(
            *bucket_id,
            PrivateHnswOramPlaintextBucket {
                bucket_id: *bucket_id,
                blocks,
            },
        );
    }

    expected_bucket_ids
        .iter()
        .map(|bucket_id| {
            writeback_by_bucket
                .remove(bucket_id)
                .ok_or(PrivateHnswClientError::PathBucketMismatch)
        })
        .collect()
}

fn validate_private_hnsw_append_rewrite(
    previous: &PrivateHnswNodeBlockPlaintext,
    replacement: &PrivateHnswNodeBlockPlaintext,
    config: PrivateHnswOramClientConfig,
) -> Result<(), PrivateHnswClientError> {
    let expected_generation = previous
        .generation
        .checked_add(1)
        .ok_or(PrivateHnswClientError::InvalidAppendRewrite)?;
    let previous_upper_neighbors = previous
        .neighbors
        .iter()
        .zip(&previous.neighbor_levels)
        .filter(|(_, level)| **level > 0)
        .collect::<Vec<_>>();
    let replacement_upper_neighbors = replacement
        .neighbors
        .iter()
        .zip(&replacement.neighbor_levels)
        .filter(|(_, level)| **level > 0)
        .collect::<Vec<_>>();
    if replacement.node_id != previous.node_id
        || replacement.point_token != previous.point_token
        || replacement.level_mask != previous.level_mask
        || replacement.vector_encoding != previous.vector_encoding
        || replacement.vector != previous.vector
        || replacement.deleted != previous.deleted
        || replacement.payload_fetch_token != previous.payload_fetch_token
        || replacement.generation != expected_generation
        || replacement_upper_neighbors != previous_upper_neighbors
    {
        return Err(PrivateHnswClientError::InvalidAppendRewrite);
    }
    encode_private_hnsw_node_block(
        replacement,
        config.block_size_bytes,
        config.fixed_neighbor_slots,
    )?;
    Ok(())
}

/// Plans a fixed-size prefetch batch: the current positions of `candidate_node_ids` padded
/// with dummy paths up to `fixed_path_count`.
///
/// `next_padding_leaf` MUST return independent uniform samples (see
/// [`sample_private_hnsw_oram_leaf`]); the batch is emitted in canonical leaf order so neither
/// the padding values nor their position in the batch reveal how many paths are real.
pub fn plan_private_hnsw_oram_speculative_prefetch(
    state: &PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    candidate_node_ids: &[[u8; 32]],
    fixed_path_count: usize,
    mut next_padding_leaf: impl FnMut() -> Result<u64, PrivateHnswClientError>,
) -> Result<PrivateHnswSpeculativePrefetchPlan, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if fixed_path_count == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "fixed_path_count",
        ));
    }
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height)?;
    if u64::try_from(fixed_path_count)
        .map_err(|_| PrivateHnswClientError::InvalidSearchConfig("fixed_path_count"))?
        > leaf_count
    {
        return Err(PrivateHnswClientError::InvalidSearchConfig(
            "fixed_path_count",
        ));
    }

    let mut leaves = Vec::with_capacity(fixed_path_count);
    let mut seen_leaves = BTreeSet::new();
    for node_id in candidate_node_ids {
        if leaves.len() == fixed_path_count {
            break;
        }
        let Some(leaf) = state.position(node_id) else {
            continue;
        };
        if seen_leaves.insert(leaf) {
            leaves.push(leaf);
        }
    }
    let real_path_count = leaves.len();
    let max_padding_attempts = leaf_count.saturating_mul(8).saturating_add(64);
    let mut padding_attempts = 0u64;
    while leaves.len() < fixed_path_count {
        let leaf = next_padding_leaf()?;
        validate_private_hnsw_oram_leaf(leaf, config.tree_height)?;
        padding_attempts += 1;
        if seen_leaves.insert(leaf) {
            leaves.push(leaf);
        } else if padding_attempts > max_padding_attempts {
            // A padding source that keeps repeating leaves is broken, not unlucky.
            return Err(PrivateHnswClientError::InvalidSearchConfig("padding_leaf"));
        }
    }
    // Canonical order: the server must not learn from the batch layout which entries are real.
    leaves.sort_unstable();

    let leaf_labels = leaves
        .into_iter()
        .map(|leaf| encode_private_hnsw_oram_leaf_label(leaf, config.tree_height))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrivateHnswSpeculativePrefetchPlan {
        leaf_labels,
        real_path_count,
    })
}

pub fn search_private_hnsw_oram_plaintext<ReadPath, WriteBack, NextLeaf>(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramPlaintextBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    let mut working_state = state.clone();
    let pending_writebacks = RefCell::new(BTreeMap::new());
    let result = search_private_hnsw_oram_plaintext_inner(
        &mut working_state,
        config,
        query,
        params,
        None,
        |leaf| {
            let mut buckets = read_path(leaf)?;
            apply_private_hnsw_pending_writebacks(&mut buckets, &pending_writebacks.borrow());
            Ok(buckets)
        },
        |writeback_buckets| {
            record_private_hnsw_pending_writebacks(
                &mut pending_writebacks.borrow_mut(),
                writeback_buckets,
            );
            Ok(())
        },
        next_remap_leaf,
    )?;
    let updated_buckets = private_hnsw_pending_writeback_values(pending_writebacks.into_inner());
    if !updated_buckets.is_empty() {
        writeback(&updated_buckets)?;
    }
    *state = working_state;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub fn search_private_hnsw_oram_plaintext_with_cache<ReadPath, WriteBack, NextLeaf>(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    node_cache: &PrivateHnswClientNodeCache,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramPlaintextBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    let mut working_state = state.clone();
    let pending_writebacks = RefCell::new(BTreeMap::new());
    let result = search_private_hnsw_oram_plaintext_inner(
        &mut working_state,
        config,
        query,
        params,
        Some(node_cache),
        |leaf| {
            let mut buckets = read_path(leaf)?;
            apply_private_hnsw_pending_writebacks(&mut buckets, &pending_writebacks.borrow());
            Ok(buckets)
        },
        |writeback_buckets| {
            record_private_hnsw_pending_writebacks(
                &mut pending_writebacks.borrow_mut(),
                writeback_buckets,
            );
            Ok(())
        },
        next_remap_leaf,
    )?;
    let updated_buckets = private_hnsw_pending_writeback_values(pending_writebacks.into_inner());
    if !updated_buckets.is_empty() {
        writeback(&updated_buckets)?;
    }
    *state = working_state;
    Ok(result)
}

fn apply_private_hnsw_pending_writebacks(
    buckets: &mut [PrivateHnswOramPlaintextBucket],
    pending_writebacks: &BTreeMap<u64, PrivateHnswOramPlaintextBucket>,
) {
    for bucket in buckets {
        if let Some(pending_bucket) = pending_writebacks.get(&bucket.bucket_id) {
            *bucket = pending_bucket.clone();
        }
    }
}

fn record_private_hnsw_pending_writebacks(
    pending_writebacks: &mut BTreeMap<u64, PrivateHnswOramPlaintextBucket>,
    writeback_buckets: &[PrivateHnswOramPlaintextBucket],
) {
    for bucket in writeback_buckets {
        pending_writebacks.insert(bucket.bucket_id, bucket.clone());
    }
}

fn private_hnsw_pending_writeback_values(
    pending_writebacks: BTreeMap<u64, PrivateHnswOramPlaintextBucket>,
) -> Vec<PrivateHnswOramPlaintextBucket> {
    pending_writebacks.into_values().collect()
}

#[allow(clippy::too_many_arguments)]
fn search_private_hnsw_oram_plaintext_inner<ReadPath, WriteBack, NextLeaf>(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    node_cache: Option<&PrivateHnswClientNodeCache>,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    mut next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramPlaintextBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    validate_oram_client_config(config)?;
    validate_search_params(query, params)?;
    // Configuration faults surface before the first read: a padding node without a position
    // or an uncached padding node would otherwise abort at a query-dependent step, which the
    // server can observe.
    match params.padding_node_id {
        Some(padding_node_id) if state.position(&padding_node_id).is_none() => {
            return Err(PrivateHnswClientError::MissingPosition);
        }
        None if node_cache.is_some_and(|cache| !cache.is_empty()) => {
            return Err(PrivateHnswClientError::InvalidSearchConfig(
                "padding_node_id",
            ));
        }
        _ => {}
    }

    let mut pending = VecDeque::from([params.entry_node_id]);
    let mut queued = BTreeSet::from([params.entry_node_id]);
    let mut visited = BTreeSet::new();
    let mut expansion_frontier: Vec<(f32, [u8; 32], Vec<[u8; 32]>)> = Vec::new();
    let mut hits: Vec<PrivateHnswSearchHit> = Vec::new();
    let mut accessed_leaf_labels = Vec::new();

    'search: for _ in 0..params.fixed_steps {
        let (node_id, padding_access) = loop {
            if let Some(candidate_node_id) = pending.pop_front() {
                queued.remove(&candidate_node_id);
                if visited.insert(candidate_node_id) {
                    break (candidate_node_id, false);
                }
                continue;
            }

            // Neighbor distances are unknown until their ORAM blocks are fetched, so choose the
            // nearest expansion only after the current adjacency batch has been evaluated.
            let next_frontier_index = expansion_frontier
                .iter()
                .enumerate()
                .min_by(|(_, lhs), (_, rhs)| {
                    lhs.0.total_cmp(&rhs.0).then_with(|| lhs.1.cmp(&rhs.1))
                })
                .map(|(index, _)| index);
            if let Some(frontier_index) = next_frontier_index {
                let (candidate_distance, _, neighbor_ids) =
                    expansion_frontier.swap_remove(frontier_index);
                // Fixed-budget searches spend the remaining accesses on padding anyway, so only
                // variable-cost searches use the HNSW early-stop heuristic.
                if params.padding_node_id.is_none()
                    && hits.len() >= params.ef
                    && hits
                        .last()
                        .is_some_and(|worst_hit| candidate_distance > worst_hit.distance)
                {
                    expansion_frontier.clear();
                    continue;
                }
                for neighbor_id in neighbor_ids {
                    if !visited.contains(&neighbor_id)
                        && (state.position(&neighbor_id).is_some()
                            || node_cache.is_some_and(|cache| cache.contains(&neighbor_id)))
                        && queued.insert(neighbor_id)
                    {
                        pending.push_back(neighbor_id);
                    }
                }
                continue;
            }

            let Some(padding_node_id) = params.padding_node_id else {
                break 'search;
            };
            break (padding_node_id, true);
        };

        let cached_block = if padding_access {
            None
        } else {
            node_cache.and_then(|cache| cache.get(&node_id)).cloned()
        };
        let access_node_id = if cached_block.is_some() {
            params
                .padding_node_id
                .ok_or(PrivateHnswClientError::InvalidSearchConfig(
                    "padding_node_id",
                ))?
        } else {
            node_id
        };

        let old_leaf = state
            .position(&access_node_id)
            .ok_or(PrivateHnswClientError::MissingPosition)?;
        let path_buckets = read_path(old_leaf)?;
        let access = access_private_hnsw_oram_path(
            state,
            config,
            access_node_id,
            &path_buckets,
            next_remap_leaf()?,
        )?;
        writeback(&access.writeback_buckets)?;
        accessed_leaf_labels.push(access.old_leaf_label);
        let block = cached_block.unwrap_or(access.block);

        if padding_access || block.deleted {
            continue;
        }

        let vector = decode_private_hnsw_f32_vector(&block)?;
        let distance = private_hnsw_f32_distance(query, &vector, params.distance)?;
        hits.push(PrivateHnswSearchHit {
            node_id: block.node_id,
            point_token: block.point_token,
            payload_fetch_token: block.payload_fetch_token,
            distance,
        });
        expansion_frontier.push((distance, block.node_id, block.neighbors.clone()));
        sort_hits(&mut hits);
        hits.truncate(params.ef);
    }

    sort_hits(&mut hits);
    hits.truncate(params.k);
    let completed_steps = accessed_leaf_labels.len();

    Ok(PrivateHnswSearchResult {
        hits,
        accessed_leaf_labels,
        completed_steps,
    })
}

/// Searches without a Merkle proof: served buckets are pinned only to the requested path and
/// to epochs before `writeback_epoch`, not to the signed root. Production callers use the
/// `_verified` variants; this one exists for benchmarks and recall tests.
#[allow(clippy::too_many_arguments)]
pub fn search_private_hnsw_oram_encrypted<ReadPath, WriteBack, NextLeaf>(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    writeback_epoch: u64,
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    let mut working_state = state.clone();
    let result = search_private_hnsw_oram_plaintext(
        &mut working_state,
        config,
        query,
        params,
        |leaf| {
            // Without a Merkle proof the only bounds are the requested path and the current
            // epoch: a served bucket must be the one asked for and must not predate the state
            // this search started from, or a replayed old bucket could resurrect blocks and
            // make the search abort on a stash collision the server can observe.
            let expected_bucket_ids =
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
            let buckets = read_path(leaf)?;
            if buckets.len() != expected_bucket_ids.len()
                || buckets
                    .iter()
                    .zip(&expected_bucket_ids)
                    .any(|(bucket, expected_bucket_id)| {
                        bucket.bucket_id != *expected_bucket_id
                            || bucket.index_epoch >= writeback_epoch
                    })
            {
                return Err(PrivateHnswClientError::PathBucketMismatch);
            }
            buckets
                .into_iter()
                .map(|bucket| {
                    open_private_hnsw_oram_plaintext_bucket(keys, base_context, &bucket, config)
                })
                .collect()
        },
        |writeback_buckets| {
            let encrypted_buckets = writeback_buckets
                .iter()
                .map(|bucket| {
                    seal_private_hnsw_oram_plaintext_bucket(
                        keys,
                        base_context,
                        writeback_epoch,
                        bucket,
                        config,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            writeback(&encrypted_buckets)
        },
        next_remap_leaf,
    )?;
    *state = working_state;
    Ok(result)
}

/// The cached form of [`search_private_hnsw_oram_encrypted`]; the same caveat applies.
#[allow(clippy::too_many_arguments)]
pub fn search_private_hnsw_oram_encrypted_with_cache<ReadPath, WriteBack, NextLeaf>(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    writeback_epoch: u64,
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    node_cache: &PrivateHnswClientNodeCache,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    let mut working_state = state.clone();
    let result = search_private_hnsw_oram_plaintext_with_cache(
        &mut working_state,
        config,
        query,
        params,
        node_cache,
        |leaf| {
            // Without a Merkle proof the only bounds are the requested path and the current
            // epoch: a served bucket must be the one asked for and must not predate the state
            // this search started from, or a replayed old bucket could resurrect blocks and
            // make the search abort on a stash collision the server can observe.
            let expected_bucket_ids =
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
            let buckets = read_path(leaf)?;
            if buckets.len() != expected_bucket_ids.len()
                || buckets
                    .iter()
                    .zip(&expected_bucket_ids)
                    .any(|(bucket, expected_bucket_id)| {
                        bucket.bucket_id != *expected_bucket_id
                            || bucket.index_epoch >= writeback_epoch
                    })
            {
                return Err(PrivateHnswClientError::PathBucketMismatch);
            }
            buckets
                .into_iter()
                .map(|bucket| {
                    open_private_hnsw_oram_plaintext_bucket(keys, base_context, &bucket, config)
                })
                .collect()
        },
        |writeback_buckets| {
            let encrypted_buckets = writeback_buckets
                .iter()
                .map(|bucket| {
                    seal_private_hnsw_oram_plaintext_bucket(
                        keys,
                        base_context,
                        writeback_epoch,
                        bucket,
                        config,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            writeback(&encrypted_buckets)
        },
        next_remap_leaf,
    )?;
    *state = working_state;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub fn search_private_hnsw_oram_encrypted_verified<ReadPath, WriteBack, NextLeaf>(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    writeback_epoch: u64,
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<PrivateHnswEncryptedPathBatch, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    if Some(writeback_epoch) != expected_epoch.checked_add(1) {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    validate_verified_hnsw_search_context(config, expected_root_hash, expected_bucket_count)?;

    let mut working_state = state.clone();
    let result = search_private_hnsw_oram_plaintext(
        &mut working_state,
        config,
        query,
        params,
        |leaf| {
            let batch = read_path(leaf)?;
            if batch.index_epoch != expected_epoch
                || batch.root_hash != expected_root_hash
                || batch.bucket_count != expected_bucket_count
            {
                return Err(PrivateHnswClientError::MerkleProofMismatch);
            }
            open_private_hnsw_oram_verified_path_batch(
                keys,
                base_context,
                config,
                expected_epoch,
                expected_root_hash,
                expected_bucket_count,
                &batch.proof_value,
                &batch.buckets,
            )
        },
        |writeback_buckets| {
            let encrypted_buckets = writeback_buckets
                .iter()
                .map(|bucket| {
                    seal_private_hnsw_oram_plaintext_bucket(
                        keys,
                        base_context,
                        writeback_epoch,
                        bucket,
                        config,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            writeback(&encrypted_buckets)
        },
        next_remap_leaf,
    )?;
    *state = working_state;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub fn search_private_hnsw_oram_encrypted_verified_with_cache<ReadPath, WriteBack, NextLeaf>(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    writeback_epoch: u64,
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    node_cache: &PrivateHnswClientNodeCache,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<PrivateHnswEncryptedPathBatch, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    if Some(writeback_epoch) != expected_epoch.checked_add(1) {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    validate_verified_hnsw_search_context(config, expected_root_hash, expected_bucket_count)?;

    let mut working_state = state.clone();
    let result = search_private_hnsw_oram_plaintext_with_cache(
        &mut working_state,
        config,
        query,
        params,
        node_cache,
        |leaf| {
            let batch = read_path(leaf)?;
            if batch.index_epoch != expected_epoch
                || batch.root_hash != expected_root_hash
                || batch.bucket_count != expected_bucket_count
            {
                return Err(PrivateHnswClientError::MerkleProofMismatch);
            }
            verify_private_hnsw_oram_merkle_proof_json(
                &batch.proof_value,
                expected_epoch,
                expected_root_hash,
                expected_bucket_count,
                &batch.buckets,
            )?;
            batch
                .buckets
                .into_iter()
                .map(|bucket| {
                    open_private_hnsw_oram_plaintext_bucket(keys, base_context, &bucket, config)
                })
                .collect()
        },
        |writeback_buckets| {
            let encrypted_buckets = writeback_buckets
                .iter()
                .map(|bucket| {
                    seal_private_hnsw_oram_plaintext_bucket(
                        keys,
                        base_context,
                        writeback_epoch,
                        bucket,
                        config,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            writeback(&encrypted_buckets)
        },
        next_remap_leaf,
    )?;
    *state = working_state;
    Ok(result)
}

fn validate_verified_hnsw_search_context(
    config: PrivateHnswOramClientConfig,
    expected_root_hash: &str,
    expected_bucket_count: u64,
) -> Result<(), PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    decode_merkle_root(expected_root_hash)?;
    if expected_bucket_count != private_hnsw_oram_bucket_count(config.tree_height)? {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    Ok(())
}

pub fn private_hnsw_oram_merkle_root_for_commitments(
    commitments: &[String],
) -> Result<String, PrivateHnswClientError> {
    let levels = private_hnsw_oram_merkle_levels(commitments)?;
    let root = levels
        .last()
        .and_then(|level| level.first())
        .ok_or(PrivateHnswClientError::EmptyMerkleTree)?;
    Ok(BASE64URL_NOPAD.encode(root))
}

pub fn verify_private_hnsw_oram_merkle_proof_json(
    proof_value: &str,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateHnswOramBucket],
) -> Result<(), PrivateHnswClientError> {
    if proof_value.len() > PRIVATE_HNSW_MERKLE_PROOF_JSON_MAX_BYTES {
        return Err(PrivateHnswClientError::InvalidMerkleProofJson);
    }
    let proof: PrivateHnswOramMerkleProof = serde_json::from_str(proof_value)
        .map_err(|_| PrivateHnswClientError::InvalidMerkleProofJson)?;
    verify_private_hnsw_oram_merkle_proof(
        &proof,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )
}

pub fn verify_private_hnsw_oram_merkle_proof(
    proof: &PrivateHnswOramMerkleProof,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateHnswOramBucket],
) -> Result<(), PrivateHnswClientError> {
    if expected_bucket_count == 0
        || proof.kind != PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND
        || proof.index_epoch != expected_epoch
        || proof.bucket_count != expected_bucket_count
        || buckets.is_empty()
        || proof.leaves.len() != buckets.len()
    {
        return Err(PrivateHnswClientError::InvalidMerkleProof);
    }

    let expected_root = decode_merkle_root(expected_root_hash)?;
    let proof_root = decode_merkle_root(&proof.root_hash)?;
    if proof_root != expected_root {
        return Err(PrivateHnswClientError::MerkleProofMismatch);
    }

    let mut buckets_by_id = BTreeMap::new();
    for bucket in buckets {
        if bucket.version != 1
            || bucket.index_epoch > expected_epoch
            || bucket.bucket_id >= expected_bucket_count
        {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        }
        // Cap the decode before it allocates: the opener enforces the same bound later, but
        // the proof check runs first on every served bucket.
        if base64url_nopad_decoded_len(bucket.ciphertext.len())
            .is_none_or(|decoded_len| decoded_len > PRIVATE_HNSW_BUCKET_CIPHERTEXT_OPEN_MAX_BYTES)
        {
            return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
        }
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
        if base64url_sha256(&raw_ciphertext) != bucket.ciphertext_sha256 {
            return Err(PrivateHnswClientError::InvalidBucketCiphertextHash);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;
        if let Some(existing) = buckets_by_id.insert(bucket.bucket_id, bucket)
            && existing != bucket
        {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        }
    }

    // Every leaf sits at the same depth of the padded tree; a proof with fewer or more
    // siblings is malformed even when its hashes happen to chain.
    let expected_depth = expected_bucket_count
        .checked_next_power_of_two()
        .map(|padded| padded.trailing_zeros())
        .and_then(|depth| usize::try_from(depth).ok())
        .ok_or(PrivateHnswClientError::InvalidMerkleProof)?;
    let mut leaves_by_id = BTreeMap::new();
    for leaf in &proof.leaves {
        if leaf.bucket_id >= expected_bucket_count || leaf.siblings.len() != expected_depth {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        }
        if let Some(existing) = leaves_by_id.insert(leaf.bucket_id, leaf) {
            if existing != leaf {
                return Err(PrivateHnswClientError::InvalidMerkleProof);
            }
            continue;
        }
        let Some(bucket) = buckets_by_id.get(&leaf.bucket_id) else {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        };
        if bucket.bucket_commitment != leaf.leaf_hash {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        }

        let mut node_hash = decode_merkle_proof_hash(&leaf.leaf_hash)?;
        let mut index = leaf.bucket_id;
        for (expected_level, sibling) in leaf.siblings.iter().enumerate() {
            let expected_level = u32::try_from(expected_level)
                .map_err(|_| PrivateHnswClientError::InvalidMerkleProof)?;
            if sibling.level != expected_level {
                return Err(PrivateHnswClientError::InvalidMerkleProof);
            }
            let sibling_hash = decode_merkle_proof_hash(&sibling.hash)?;
            let expected_position = if index % 2 == 0 {
                PrivateHnswMerkleSiblingPosition::Right
            } else {
                PrivateHnswMerkleSiblingPosition::Left
            };
            if sibling.position != expected_position {
                return Err(PrivateHnswClientError::InvalidMerkleProof);
            }
            node_hash = match sibling.position {
                PrivateHnswMerkleSiblingPosition::Left => {
                    private_hnsw_oram_merkle_parent_hash(&sibling_hash, &node_hash)
                }
                PrivateHnswMerkleSiblingPosition::Right => {
                    private_hnsw_oram_merkle_parent_hash(&node_hash, &sibling_hash)
                }
            };
            index /= 2;
        }
        if node_hash != expected_root {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        }
    }
    for bucket_id in buckets_by_id.keys() {
        if !leaves_by_id.contains_key(bucket_id) {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        }
    }

    Ok(())
}

pub fn plan_private_hnsw_oram_commit(
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
) -> Result<PrivateHnswClientCommitPlan, PrivateHnswClientError> {
    if Some(new_epoch) != old_epoch.checked_add(1) {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    if updated_buckets.is_empty() {
        return Err(PrivateHnswClientError::EmptyCommit);
    }
    decode_merkle_root(old_root_hash)?;
    let computed_old_root =
        private_hnsw_oram_merkle_root_for_commitments(current_leaf_commitments)?;
    if computed_old_root != old_root_hash {
        return Err(PrivateHnswClientError::MerkleRootMismatch);
    }

    let bucket_count = u64::try_from(current_leaf_commitments.len())
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    let mut next_leaf_commitments = current_leaf_commitments.to_vec();
    let mut seen_bucket_ids = BTreeSet::new();
    let mut commit_bucket_refs = Vec::with_capacity(updated_buckets.len());

    for bucket in updated_buckets {
        if bucket.version != 1 {
            return Err(PrivateHnswClientError::UnsupportedBucketVersion(
                bucket.version,
            ));
        }
        if bucket.index_epoch != new_epoch {
            return Err(PrivateHnswClientError::StaleBucketEpoch {
                bucket_id: bucket.bucket_id,
                expected_epoch: new_epoch,
                actual_epoch: bucket.index_epoch,
            });
        }
        if bucket.bucket_id >= bucket_count {
            return Err(PrivateHnswClientError::BucketOutOfRange {
                bucket_id: bucket.bucket_id,
                bucket_count,
            });
        }
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateHnswClientError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_bucket_ciphertext_hash(&bucket.ciphertext_sha256)?;
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
        if base64url_sha256(&raw_ciphertext) != bucket.ciphertext_sha256 {
            return Err(PrivateHnswClientError::InvalidBucketCiphertextHash);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;

        let bucket_index = usize::try_from(bucket.bucket_id)
            .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
        next_leaf_commitments[bucket_index] = bucket.bucket_commitment.clone();
        commit_bucket_refs.push(PrivateHnswClientCommitBucketRef {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        });
    }

    let new_root_hash = private_hnsw_oram_merkle_root_for_commitments(&next_leaf_commitments)?;
    Ok(PrivateHnswClientCommitPlan {
        old_epoch,
        new_epoch,
        old_root_hash: old_root_hash.to_string(),
        new_root_hash,
        leaf_commitments: next_leaf_commitments,
        updated_buckets: commit_bucket_refs,
    })
}

pub fn plan_private_hnsw_oram_commit_for_manifest(
    manifest: &PrivateHnswOramManifest,
    new_epoch: u64,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
) -> Result<PrivateHnswClientCommitPlan, PrivateHnswClientError> {
    plan_private_hnsw_oram_commit_for_manifest_context(
        manifest,
        manifest.index_epoch,
        new_epoch,
        &manifest.root_hash,
        current_leaf_commitments,
        updated_buckets,
    )
}

/// Plans a commit whose writeback budget covers one full fixed-budget search (all upper- and
/// base-layer steps of the manifest). Use
/// [`plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths`] with the actual
/// number of paths read (for example `PrivateHnswSearchResult::completed_steps`) otherwise.
pub fn plan_private_hnsw_oram_commit_for_manifest_context(
    manifest: &PrivateHnswOramManifest,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
) -> Result<PrivateHnswClientCommitPlan, PrivateHnswClientError> {
    let read_path_count =
        crate::private_hnsw_oram::private_hnsw_oram_fixed_search_read_path_count(manifest)
            .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest"))?;
    plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths(
        manifest,
        old_epoch,
        new_epoch,
        old_root_hash,
        current_leaf_commitments,
        updated_buckets,
        read_path_count,
    )
}

/// Plans a commit for a session that read `read_path_count` paths; the writeback must fit
/// [`private_hnsw_oram_session_writeback_bucket_budget`], which is what the server enforces.
pub fn plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths(
    manifest: &PrivateHnswOramManifest,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
    read_path_count: usize,
) -> Result<PrivateHnswClientCommitPlan, PrivateHnswClientError> {
    validate_private_hnsw_oram_manifest_shape(manifest)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest"))?;
    let manifest_bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    if current_leaf_commitments.len() != manifest_bucket_count {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    if Some(new_epoch) != old_epoch.checked_add(1) {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    if updated_buckets.is_empty() {
        return Err(PrivateHnswClientError::EmptyCommit);
    }
    let max_updated_buckets =
        private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, read_path_count)?;
    if updated_buckets.len() > max_updated_buckets {
        return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
            "updated_buckets",
        ));
    }
    if private_hnsw_oram_merkle_root_for_commitments(current_leaf_commitments)? != old_root_hash {
        return Err(PrivateHnswClientError::MerkleRootMismatch);
    }
    let base_context = PrivateHnswBucketAeadBaseContext {
        collection_id: &manifest.collection_id,
        vector_name: &manifest.vector_name,
        key_id: &manifest.key_id,
        rk_id: &manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
    };
    let expected_ciphertext_bytes = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("oram"))?;
    for bucket in updated_buckets {
        validate_private_hnsw_upload_bucket(
            base_context,
            bucket,
            new_epoch,
            manifest.bucket_count,
            expected_ciphertext_bytes,
        )?;
    }
    let plan = plan_private_hnsw_oram_commit(
        old_epoch,
        new_epoch,
        old_root_hash,
        current_leaf_commitments,
        updated_buckets,
    )?;
    Ok(plan)
}

pub fn sign_private_hnsw_oram_commit(
    key_pair: &Ed25519KeyPair,
    context: PrivateHnswCommitSignatureContext<'_>,
    plan: &PrivateHnswClientCommitPlan,
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    validate_commit_signature_context(context)?;
    if plan.updated_buckets.is_empty() {
        return Err(PrivateHnswClientError::EmptyCommit);
    }
    if u32::try_from(plan.updated_buckets.len()).is_err() {
        return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
            "updated_buckets",
        ));
    }
    if Some(plan.new_epoch) != plan.old_epoch.checked_add(1) {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    decode_merkle_root(&plan.old_root_hash)?;
    decode_merkle_root(&plan.new_root_hash)?;
    let mut seen_bucket_ids = BTreeSet::new();
    for bucket in &plan.updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateHnswClientError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_bucket_ciphertext_hash(&bucket.ciphertext_sha256)?;
    }
    let bucket_refs = plan.signature_bucket_refs();
    let input = PrivateHnswOramCommitSignatureInput {
        collection_id: context.collection_id,
        vector_name: context.vector_name,
        key_id: context.key_id,
        rk_id: context.rk_id,
        rk_epoch: context.rk_epoch,
        old_epoch: plan.old_epoch,
        new_epoch: plan.new_epoch,
        old_root_hash: &plan.old_root_hash,
        new_root_hash: &plan.new_root_hash,
        updated_buckets: &bucket_refs,
        signature_alg: "ed25519",
        signature_key_id: context.signing_key_id,
    };
    let message = try_private_hnsw_oram_commit_signature_message(input)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("signature_message"))?;
    let signature = key_pair.sign(&message);
    Ok(PrivateHnswOramSignature {
        alg: "ed25519".to_string(),
        key_id: context.signing_key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_hnsw_oram_read_paths(
    key_pair: &Ed25519KeyPair,
    context: PrivateHnswCommitSignatureContext<'_>,
    index_epoch: u64,
    root_hash: &str,
    paths: &[String],
    requested_paths: u32,
    dummy_paths_included: bool,
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    validate_commit_signature_context(context)?;
    decode_merkle_root(root_hash)?;
    let requested_paths_len: usize = requested_paths
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("requested_paths"))?;
    if paths.is_empty()
        || requested_paths == 0
        || u32::try_from(paths.len()).is_err()
        || requested_paths_len != paths.len()
    {
        return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
            "requested_paths",
        ));
    }
    if !dummy_paths_included {
        return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
            "dummy_paths_included",
        ));
    }
    let mut seen_paths = BTreeSet::new();
    for path in paths {
        decode_private_hnsw_oram_leaf_label_shape(path)?;
        if !seen_paths.insert(path.as_str()) {
            return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "paths",
            ));
        }
    }
    let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
    let input = PrivateHnswOramReadPathsSignatureInput {
        collection_id: context.collection_id,
        vector_name: context.vector_name,
        key_id: context.key_id,
        rk_id: context.rk_id,
        rk_epoch: context.rk_epoch,
        index_epoch,
        root_hash,
        paths: &path_refs,
        requested_paths,
        dummy_paths_included,
        signature_alg: "ed25519",
        signature_key_id: context.signing_key_id,
    };
    let message = try_private_hnsw_oram_read_paths_signature_message(input)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("signature_message"))?;
    let signature = key_pair.sign(&message);
    Ok(PrivateHnswOramSignature {
        alg: "ed25519".to_string(),
        key_id: context.signing_key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_hnsw_oram_read_paths_for_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
    paths: &[String],
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    sign_private_hnsw_oram_read_paths_for_manifest_context(
        key_pair,
        manifest,
        manifest.index_epoch,
        &manifest.root_hash,
        paths,
    )
}

pub fn sign_private_hnsw_oram_read_paths_for_manifest_context(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    root_hash: &str,
    paths: &[String],
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    validate_private_hnsw_oram_manifest_shape(manifest)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest"))?;
    let mut seen_paths = BTreeSet::new();
    for path in paths {
        decode_private_hnsw_oram_leaf_label(path, manifest.oram.tree_height)?;
        if !seen_paths.insert(path) {
            return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "paths",
            ));
        }
    }
    sign_private_hnsw_oram_read_paths(
        key_pair,
        PrivateHnswCommitSignatureContext {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            signing_key_id: &manifest.owner_signing_key_id,
        },
        index_epoch,
        root_hash,
        paths,
        manifest.oram.path_batch_size,
        true,
    )
}

pub fn sign_private_hnsw_oram_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    validate_resource_key_id(&manifest.owner_signing_key_id).map_err(|_| {
        PrivateHnswClientError::InvalidManifestSignatureContext("owner_signing_key_id")
    })?;
    validate_private_hnsw_oram_manifest_shape(manifest)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("manifest"))?;
    let message = try_private_hnsw_oram_manifest_signature_message(manifest).map_err(|_| {
        PrivateHnswClientError::InvalidManifestSignatureContext("signature_message")
    })?;
    let signature = key_pair.sign(&message);
    Ok(PrivateHnswOramSignature {
        alg: "ed25519".to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn encode_private_hnsw_node_block(
    block: &PrivateHnswNodeBlockPlaintext,
    block_size_bytes: usize,
    fixed_neighbor_slots: usize,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_private_hnsw_node_neighbor_shape(
        block.node_id,
        block.level_mask,
        &block.neighbors,
        &block.neighbor_levels,
    )?;
    validate_private_hnsw_vector_shape(block.vector_encoding, &block.vector)?;
    if block.neighbors.len() > fixed_neighbor_slots {
        return Err(PrivateHnswClientError::TooManyNeighbors {
            actual: block.neighbors.len(),
            limit: fixed_neighbor_slots,
        });
    }
    let vector_len: u32 = block
        .vector
        .len()
        .try_into()
        .map_err(|_| PrivateHnswClientError::VectorTooLarge)?;
    let neighbor_count: u32 = block
        .neighbors
        .len()
        .try_into()
        .map_err(|_| PrivateHnswClientError::FixedNeighborSlotsTooLarge)?;
    let fixed_neighbor_slots_u32: u32 = fixed_neighbor_slots
        .try_into()
        .map_err(|_| PrivateHnswClientError::FixedNeighborSlotsTooLarge)?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(NODE_BLOCK_MAGIC);
    push_u16(&mut encoded, NODE_BLOCK_VERSION);
    encoded.extend_from_slice(&block.node_id);
    encoded.extend_from_slice(&block.point_token);
    push_u64(&mut encoded, block.level_mask);
    encoded.push(block.vector_encoding.tag());
    encoded.push(u8::from(block.deleted));
    push_u64(&mut encoded, block.generation);
    match block.payload_fetch_token {
        Some(token) => {
            encoded.push(1);
            encoded.extend_from_slice(&token);
        }
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 32]);
        }
    }
    push_u32(&mut encoded, neighbor_count);
    push_u32(&mut encoded, fixed_neighbor_slots_u32);
    push_u32(&mut encoded, vector_len);
    encoded.extend_from_slice(&block.vector);

    for (neighbor, level) in block.neighbors.iter().zip(&block.neighbor_levels) {
        encoded.extend_from_slice(neighbor);
        encoded.push(*level);
    }
    for _ in block.neighbors.len()..fixed_neighbor_slots {
        encoded.extend_from_slice(&[0; 32]);
        encoded.push(0);
    }

    if encoded.len() > block_size_bytes {
        return Err(PrivateHnswClientError::EncodedBlockOversized);
    }
    encoded.resize(block_size_bytes, 0);
    Ok(encoded)
}

pub fn decode_private_hnsw_node_block(
    encoded: &[u8],
) -> Result<PrivateHnswNodeBlockPlaintext, PrivateHnswClientError> {
    let mut cursor = 0;
    let magic = read_exact(encoded, &mut cursor, NODE_BLOCK_MAGIC.len())?;
    if magic != NODE_BLOCK_MAGIC {
        return Err(PrivateHnswClientError::InvalidBlockEncoding);
    }
    let version = read_u16(encoded, &mut cursor)?;
    if version != NODE_BLOCK_VERSION {
        return Err(PrivateHnswClientError::UnsupportedBlockVersion(version));
    }
    let node_id = read_array_32(encoded, &mut cursor)?;
    let point_token = read_array_32(encoded, &mut cursor)?;
    let level_mask = read_u64(encoded, &mut cursor)?;
    let vector_encoding = PrivateHnswVectorEncoding::from_tag(read_u8(encoded, &mut cursor)?)?;
    let deleted = match read_u8(encoded, &mut cursor)? {
        0 => false,
        1 => true,
        _ => return Err(PrivateHnswClientError::InvalidBlockEncoding),
    };
    let generation = read_u64(encoded, &mut cursor)?;
    let payload_present = read_u8(encoded, &mut cursor)?;
    let payload_token = read_array_32(encoded, &mut cursor)?;
    let payload_fetch_token = match payload_present {
        0 => {
            if payload_token != [0; 32] {
                return Err(PrivateHnswClientError::InvalidBlockPadding);
            }
            None
        }
        1 => Some(payload_token),
        _ => return Err(PrivateHnswClientError::InvalidBlockEncoding),
    };

    let neighbor_count = read_u32_usize(encoded, &mut cursor)?;
    let fixed_neighbor_slots = read_u32_usize(encoded, &mut cursor)?;
    if neighbor_count > fixed_neighbor_slots {
        return Err(PrivateHnswClientError::TooManyNeighbors {
            actual: neighbor_count,
            limit: fixed_neighbor_slots,
        });
    }
    // Every slot is serialized in full, so the counters can never exceed what the block still
    // holds; checking here keeps the allocations below from being sized by an attacker.
    let slot_len = 32 + 1;
    if fixed_neighbor_slots > encoded.len().saturating_sub(cursor) / slot_len {
        return Err(PrivateHnswClientError::InvalidBlockEncoding);
    }
    let vector_len = read_u32_usize(encoded, &mut cursor)?;
    let vector = read_exact(encoded, &mut cursor, vector_len)?.to_vec();
    validate_private_hnsw_vector_shape(vector_encoding, &vector)?;

    let mut neighbors = Vec::with_capacity(neighbor_count);
    let mut neighbor_levels = Vec::with_capacity(neighbor_count);
    for slot in 0..fixed_neighbor_slots {
        let neighbor = read_array_32(encoded, &mut cursor)?;
        let level = read_u8(encoded, &mut cursor)?;
        if slot < neighbor_count {
            neighbors.push(neighbor);
            neighbor_levels.push(level);
        } else if neighbor != [0; 32] || level != 0 {
            return Err(PrivateHnswClientError::InvalidBlockPadding);
        }
    }

    if encoded[cursor..].iter().any(|byte| *byte != 0) {
        return Err(PrivateHnswClientError::InvalidBlockPadding);
    }
    validate_private_hnsw_node_neighbor_shape(node_id, level_mask, &neighbors, &neighbor_levels)?;

    Ok(PrivateHnswNodeBlockPlaintext {
        version,
        node_id,
        point_token,
        level_mask,
        vector_encoding,
        vector,
        neighbors,
        neighbor_levels,
        deleted,
        generation,
        payload_fetch_token,
    })
}

fn validate_private_hnsw_node_neighbor_shape(
    node_id: [u8; 32],
    level_mask: u64,
    neighbors: &[[u8; 32]],
    neighbor_levels: &[u8],
) -> Result<(), PrivateHnswClientError> {
    if neighbors.len() != neighbor_levels.len() {
        return Err(PrivateHnswClientError::InvalidNeighborShape);
    }
    validate_private_hnsw_level_mask_shape(level_mask)?;
    let mut seen_neighbor_levels = BTreeSet::new();
    for (neighbor, level) in neighbors.iter().zip(neighbor_levels) {
        if *level >= 64
            || level_mask & (1u64 << u32::from(*level)) == 0
            || *neighbor == node_id
            || !seen_neighbor_levels.insert((*neighbor, *level))
        {
            return Err(PrivateHnswClientError::InvalidNeighborShape);
        }
    }
    Ok(())
}

fn validate_private_hnsw_level_mask_shape(level_mask: u64) -> Result<(), PrivateHnswClientError> {
    if level_mask == 0 {
        return Err(PrivateHnswClientError::InvalidNeighborShape);
    }
    if level_mask != u64::MAX && (level_mask & level_mask.saturating_add(1)) != 0 {
        return Err(PrivateHnswClientError::InvalidNeighborShape);
    }
    Ok(())
}

fn validate_private_hnsw_vector_shape(
    vector_encoding: PrivateHnswVectorEncoding,
    vector_bytes: &[u8],
) -> Result<(), PrivateHnswClientError> {
    if vector_encoding != PrivateHnswVectorEncoding::F32Le {
        return Ok(());
    }
    let (chunks, remainder) = vector_bytes.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err(PrivateHnswClientError::InvalidF32VectorLength);
    }
    let vector = chunks
        .iter()
        .map(|chunk| Ok(f32::from_le_bytes(*chunk)))
        .collect::<Result<Vec<_>, PrivateHnswClientError>>()?;
    if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
        return Err(PrivateHnswClientError::NonFiniteDistance);
    }
    Ok(())
}

pub fn seal_private_hnsw_oram_bucket(
    keys: &PrivateHnswClientKeys,
    context: PrivateHnswBucketAeadContext<'_>,
    plaintext: &[u8],
) -> Result<PrivateHnswOramBucket, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    keys.bucket_seals.reserve("private HNSW ORAM bucket key")?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; BUCKET_AEAD_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::RandomFailure)?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.bucket_aead_key().as_bytes())
        .map_err(|_| EncryptionError::SealFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = private_hnsw_bucket_aead(context)?;
    let mut in_out = Zeroizing::new(plaintext.to_vec());
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out[..])
        .map_err(|_| EncryptionError::SealFailed)?;

    let mut raw_ciphertext =
        Vec::with_capacity(1 + BUCKET_AEAD_NONCE_LEN + in_out.len() + tag.as_ref().len());
    raw_ciphertext.push(BUCKET_AEAD_VERSION);
    raw_ciphertext.extend_from_slice(&nonce_bytes);
    raw_ciphertext.extend_from_slice(&in_out[..]);
    raw_ciphertext.extend_from_slice(tag.as_ref());

    let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
    let bucket_commitment = private_hnsw_bucket_commitment(context, &ciphertext_sha256)?;

    Ok(PrivateHnswOramBucket {
        version: 1,
        bucket_id: context.bucket_id,
        index_epoch: context.index_epoch,
        ciphertext: BASE64URL_NOPAD.encode(&raw_ciphertext),
        ciphertext_sha256,
        bucket_commitment,
    })
}

pub fn open_private_hnsw_oram_bucket(
    keys: &PrivateHnswClientKeys,
    context: PrivateHnswBucketAeadContext<'_>,
    bucket: &PrivateHnswOramBucket,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    if bucket.version != 1
        || bucket.bucket_id != context.bucket_id
        || bucket.index_epoch != context.index_epoch
    {
        return Err(PrivateHnswClientError::BucketMetadataMismatch);
    }

    let Some(decoded_len) = base64url_nopad_decoded_len(bucket.ciphertext.len()) else {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
    };
    if decoded_len > PRIVATE_HNSW_BUCKET_CIPHERTEXT_OPEN_MAX_BYTES {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
    }
    let raw_ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
    if raw_ciphertext.len() < 1 + BUCKET_AEAD_NONCE_LEN + BUCKET_AEAD_TAG_LEN {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
    }
    let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
    if ciphertext_sha256 != bucket.ciphertext_sha256 {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextHash);
    }
    let expected_commitment = private_hnsw_bucket_commitment(context, &bucket.ciphertext_sha256)?;
    if expected_commitment != bucket.bucket_commitment {
        return Err(PrivateHnswClientError::InvalidBucketCommitment);
    }
    if raw_ciphertext[0] != BUCKET_AEAD_VERSION {
        return Err(PrivateHnswClientError::UnsupportedBucketCiphertextVersion(
            raw_ciphertext[0],
        ));
    }

    let nonce_bytes: [u8; BUCKET_AEAD_NONCE_LEN] = raw_ciphertext[1..1 + BUCKET_AEAD_NONCE_LEN]
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = Zeroizing::new(raw_ciphertext[1 + BUCKET_AEAD_NONCE_LEN..].to_vec());

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.bucket_aead_key().as_bytes())
        .map_err(|_| EncryptionError::OpenFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let aad = private_hnsw_bucket_aead(context)?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext[..])
        .map_err(|_| PrivateHnswClientError::BucketOpenFailed)?;
    Ok(plaintext.to_vec())
}

pub fn private_hnsw_bucket_commitment(
    context: PrivateHnswBucketAeadContext<'_>,
    ciphertext_sha256: &str,
) -> Result<String, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    let ciphertext_sha256_bytes = decode_bucket_ciphertext_hash(ciphertext_sha256)?;

    let mut message = Vec::new();
    append_bucket_len_prefixed(
        &mut message,
        PRIVATE_HNSW_BUCKET_COMMITMENT_DOMAIN.as_bytes(),
    )?;
    append_bucket_len_prefixed(&mut message, context.collection_id.as_bytes())?;
    append_bucket_len_prefixed(&mut message, context.vector_name.as_bytes())?;
    append_bucket_len_prefixed(&mut message, context.key_id.as_bytes())?;
    append_bucket_len_prefixed(&mut message, context.rk_id.as_bytes())?;
    message.extend_from_slice(&context.rk_epoch.to_be_bytes());
    message.extend_from_slice(&context.bucket_id.to_be_bytes());
    message.extend_from_slice(&context.index_epoch.to_be_bytes());
    message.extend_from_slice(&ciphertext_sha256_bytes);

    Ok(base64url_sha256(&message))
}

fn private_hnsw_bucket_aead(
    context: PrivateHnswBucketAeadContext<'_>,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    let mut aad = Vec::new();
    append_bucket_len_prefixed(&mut aad, PRIVATE_HNSW_BUCKET_AEAD_CONTEXT_DOMAIN.as_bytes())?;
    append_bucket_len_prefixed(&mut aad, context.collection_id.as_bytes())?;
    append_bucket_len_prefixed(&mut aad, context.vector_name.as_bytes())?;
    append_bucket_len_prefixed(&mut aad, context.key_id.as_bytes())?;
    append_bucket_len_prefixed(&mut aad, context.rk_id.as_bytes())?;
    aad.extend_from_slice(&context.rk_epoch.to_be_bytes());
    aad.extend_from_slice(&context.bucket_id.to_be_bytes());
    aad.extend_from_slice(&context.index_epoch.to_be_bytes());
    Ok(aad)
}

fn private_hnsw_client_state_aead(
    context: PrivateHnswClientStateAeadContext<'_>,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_client_state_context(context)?;
    let root_hash = decode_merkle_root(context.root_hash)?;
    let mut aad = Vec::new();
    append_client_state_len_prefixed(
        &mut aad,
        PRIVATE_HNSW_CLIENT_STATE_AEAD_CONTEXT_DOMAIN.as_bytes(),
    )?;
    append_client_state_len_prefixed(&mut aad, context.collection_id.as_bytes())?;
    append_client_state_len_prefixed(&mut aad, context.vector_name.as_bytes())?;
    append_client_state_len_prefixed(&mut aad, context.key_id.as_bytes())?;
    append_client_state_len_prefixed(&mut aad, context.rk_id.as_bytes())?;
    aad.extend_from_slice(&context.rk_epoch.to_be_bytes());
    aad.extend_from_slice(&context.index_epoch.to_be_bytes());
    aad.extend_from_slice(&root_hash);
    Ok(aad)
}

fn validate_bucket_context(
    context: PrivateHnswBucketAeadContext<'_>,
) -> Result<(), PrivateHnswClientError> {
    if context.collection_id.is_empty() {
        return Err(PrivateHnswClientError::InvalidBucketContext(
            "collection_id",
        ));
    }
    validate_hnsw_context_vector_name(context.vector_name)
        .map_err(|_| PrivateHnswClientError::InvalidBucketContext("vector_name"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswClientError::InvalidBucketContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswClientError::InvalidBucketContext("rk_id"))?;
    Ok(())
}

fn validate_client_state_context(
    context: PrivateHnswClientStateAeadContext<'_>,
) -> Result<(), PrivateHnswClientError> {
    validate_client_state_context_id(context.collection_id)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateContext("collection_id"))?;
    validate_hnsw_context_vector_name(context.vector_name)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateContext("vector_name"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateContext("rk_id"))?;
    decode_merkle_root(context.root_hash)
        .map_err(|_| PrivateHnswClientError::InvalidClientStateContext("root_hash"))?;
    Ok(())
}

fn validate_client_state_context_id(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 255
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(());
    }
    Ok(())
}

fn validate_hnsw_context_vector_name(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || hnsw_context_vector_name_is_client_owned_alias(value)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(());
    }
    Ok(())
}

fn hnsw_context_vector_name_is_client_owned_alias(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let compact_value = value.replace(['_', '-', '.'], "");
    if compact_hnsw_context_vector_name_is_client_owned_alias(&compact_value) {
        return true;
    }
    let Some((stem, _extension)) = value.rsplit_once('.') else {
        return false;
    };
    compact_hnsw_context_vector_name_is_client_owned_alias(&stem.replace(['_', '-', '.'], ""))
}

fn compact_hnsw_context_vector_name_is_client_owned_alias(value: &str) -> bool {
    matches!(
        value,
        "clientstate"
            | "clientstates"
            | "clientstatebackup"
            | "clientstatebackups"
            | "clientstatesnapshot"
            | "clientstatesnapshots"
            | "clientstateciphertext"
            | "clientstateciphertexts"
            | "clientstateciphertexthash"
            | "clientstateciphertexthashes"
            | "clientstateciphertextsha256"
            | "clientstateciphertextssha256"
            | "encryptedclientstate"
            | "encryptedclientstates"
            | "encryptedclientstatebackup"
            | "encryptedclientstatebackups"
            | "encryptedclientstatesnapshot"
            | "encryptedclientstatesnapshots"
            | "encryptedclientstateciphertext"
            | "encryptedclientstateciphertexts"
            | "encryptedclientstateciphertexthash"
            | "encryptedclientstateciphertexthashes"
            | "encryptedclientstateciphertextsha256"
            | "encryptedclientstateciphertextssha256"
            | "stateciphertext"
            | "stateciphertexts"
            | "stateciphertexthash"
            | "stateciphertexthashes"
            | "stateciphertextsha256"
            | "stateciphertextssha256"
            | "payloadfetchtoken"
            | "payloadfetchtokens"
            | "positionmap"
            | "positionmapbackup"
            | "positionmapbackups"
            | "positionmaps"
            | "positionmapsnapshot"
            | "positionmapsnapshots"
            | "orampositionmap"
            | "orampositionmapbackup"
            | "orampositionmapbackups"
            | "orampositionmaps"
            | "orampositionmapsnapshot"
            | "orampositionmapsnapshots"
            | "tokenmap"
            | "tokenmapbackup"
            | "tokenmapbackups"
            | "tokenmaps"
            | "tokenmapsnapshot"
            | "tokenmapsnapshots"
            | "tokenpositionmap"
            | "tokenpositionmapbackup"
            | "tokenpositionmapbackups"
            | "tokenpositionmaps"
            | "tokenpositionmapsnapshot"
            | "tokenpositionmapsnapshots"
            | "stash"
            | "stashbackup"
            | "stashbackups"
            | "stashsnapshot"
            | "stashsnapshots"
    )
}

fn validate_manifest_build_context(
    context: &PrivateHnswManifestBuildContext<'_>,
) -> Result<(), PrivateHnswClientError> {
    validate_client_state_context_id(context.collection_id)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("collection_id"))?;
    validate_hnsw_context_vector_name(context.vector_name)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("vector_name"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswClientError::InvalidManifestSignatureContext("rk_id"))?;
    validate_resource_key_id(context.owner_signing_key_id).map_err(|_| {
        PrivateHnswClientError::InvalidManifestSignatureContext("owner_signing_key_id")
    })?;
    if context.dim == 0 {
        return Err(PrivateHnswClientError::InvalidManifestSignatureContext(
            "dim",
        ));
    }
    Ok(())
}

fn validate_commit_signature_context(
    context: PrivateHnswCommitSignatureContext<'_>,
) -> Result<(), PrivateHnswClientError> {
    validate_client_state_context_id(context.collection_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("collection_id"))?;
    validate_hnsw_context_vector_name(context.vector_name)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("vector_name"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("rk_id"))?;
    validate_resource_key_id(context.signing_key_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("signing_key_id"))?;
    Ok(())
}

fn validate_oram_client_config(
    config: PrivateHnswOramClientConfig,
) -> Result<(), PrivateHnswClientError> {
    private_hnsw_oram_bucket_count(config.tree_height)?;
    if config.bucket_size == 0 {
        return Err(PrivateHnswClientError::InvalidOramClientConfig(
            "bucket_size",
        ));
    }
    if config.block_size_bytes == 0 {
        return Err(PrivateHnswClientError::InvalidOramClientConfig(
            "block_size_bytes",
        ));
    }
    private_hnsw_bucket_plaintext_slots_len(config)?;
    Ok(())
}

fn private_hnsw_bucket_plaintext_slots_len(
    config: PrivateHnswOramClientConfig,
) -> Result<usize, PrivateHnswClientError> {
    let slot_len = config.block_size_bytes.checked_add(1).ok_or(
        PrivateHnswClientError::InvalidOramClientConfig("block_size_bytes"),
    )?;
    config
        .bucket_size
        .checked_mul(slot_len)
        .ok_or(PrivateHnswClientError::InvalidOramClientConfig(
            "bucket_size",
        ))
}

fn private_hnsw_bucket_plaintext_len(
    config: PrivateHnswOramClientConfig,
) -> Result<usize, PrivateHnswClientError> {
    let slots_len = private_hnsw_bucket_plaintext_slots_len(config)?;
    BUCKET_PLAINTEXT_MAGIC
        .len()
        .checked_add(2)
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(slots_len))
        .ok_or(PrivateHnswClientError::InvalidOramClientConfig(
            "bucket_size",
        ))
}

fn validate_search_params(
    query: &[f32],
    params: PrivateHnswSearchParams,
) -> Result<(), PrivateHnswClientError> {
    if query.is_empty() {
        return Err(PrivateHnswClientError::InvalidSearchConfig("query"));
    }
    if query.iter().any(|value| !value.is_finite()) {
        return Err(PrivateHnswClientError::NonFiniteDistance);
    }
    if params.k == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig("k"));
    }
    if params.ef < params.k {
        return Err(PrivateHnswClientError::InvalidSearchConfig("ef"));
    }
    if params.fixed_steps == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig("fixed_steps"));
    }
    Ok(())
}

fn validate_private_hnsw_oram_leaf(
    leaf: u64,
    tree_height: u32,
) -> Result<(), PrivateHnswClientError> {
    if leaf >= private_hnsw_oram_leaf_count(tree_height)? {
        return Err(PrivateHnswClientError::LeafOutOfRange);
    }
    Ok(())
}

fn decode_private_hnsw_oram_leaf_label_shape(
    label: &str,
) -> Result<[u8; 8], PrivateHnswClientError> {
    if label.len() != BASE64URL_NOPAD_8_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidLeafLabelLength);
    }
    let bytes = BASE64URL_NOPAD
        .decode(label.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidLeafLabelEncoding)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidLeafLabelLength)
}

pub fn decode_private_hnsw_f32_vector(
    block: &PrivateHnswNodeBlockPlaintext,
) -> Result<Vec<f32>, PrivateHnswClientError> {
    if block.vector_encoding != PrivateHnswVectorEncoding::F32Le {
        return Err(PrivateHnswClientError::UnsupportedSearchVectorEncoding);
    }
    let (chunks, remainder) = block.vector.as_chunks::<4>();
    if !remainder.is_empty() {
        return Err(PrivateHnswClientError::InvalidF32VectorLength);
    }
    chunks
        .iter()
        .map(|chunk| Ok(f32::from_le_bytes(*chunk)))
        .collect()
}

pub fn private_hnsw_f32_distance(
    query: &[f32],
    vector: &[f32],
    distance: DistanceKind,
) -> Result<f32, PrivateHnswClientError> {
    if query.len() != vector.len() {
        return Err(PrivateHnswClientError::VectorDimensionMismatch);
    }
    let value = match distance {
        DistanceKind::Euclid => query
            .iter()
            .zip(vector)
            .map(|(lhs, rhs)| {
                let delta = lhs - rhs;
                delta * delta
            })
            .sum(),
        DistanceKind::Manhattan => query
            .iter()
            .zip(vector)
            .map(|(lhs, rhs)| (lhs - rhs).abs())
            .sum(),
        DistanceKind::Dot => -query
            .iter()
            .zip(vector)
            .map(|(lhs, rhs)| lhs * rhs)
            .sum::<f32>(),
        DistanceKind::Cosine => {
            let dot = query
                .iter()
                .zip(vector)
                .map(|(lhs, rhs)| lhs * rhs)
                .sum::<f32>();
            let query_norm = query.iter().map(|value| value * value).sum::<f32>().sqrt();
            let vector_norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
            if query_norm == 0.0 || vector_norm == 0.0 {
                return Err(PrivateHnswClientError::NonFiniteDistance);
            }
            1.0 - dot / (query_norm * vector_norm)
        }
    };
    if value.is_finite() {
        Ok(value)
    } else {
        Err(PrivateHnswClientError::NonFiniteDistance)
    }
}

fn directional_neighbor_score(
    current_vector: &[f32],
    neighbor_vector: &[f32],
    query: &[f32],
) -> Result<f32, PrivateHnswClientError> {
    if current_vector.len() != neighbor_vector.len() || current_vector.len() != query.len() {
        return Err(PrivateHnswClientError::VectorDimensionMismatch);
    }
    let score = current_vector
        .iter()
        .zip(neighbor_vector)
        .zip(query)
        .map(|((current, neighbor), query)| (neighbor - current) * (query - current))
        .sum::<f32>();
    if score.is_finite() {
        Ok(score)
    } else {
        Err(PrivateHnswClientError::NonFiniteDistance)
    }
}

fn sort_hits(hits: &mut [PrivateHnswSearchHit]) {
    hits.sort_by(|lhs, rhs| {
        lhs.distance
            .total_cmp(&rhs.distance)
            .then_with(|| lhs.node_id.cmp(&rhs.node_id))
    });
}

fn decode_bucket_ciphertext_hash(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextHash);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextHash)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextHash)
}

fn decode_bucket_commitment(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidBucketCommitment);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCommitment)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBucketCommitment)
}

fn decode_merkle_root(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidMerkleRoot);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidMerkleRoot)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidMerkleRoot)
}

fn base64url_nopad_decoded_len(encoded_len: usize) -> Option<usize> {
    let full_quads = encoded_len / 4;
    let base_len = full_quads.checked_mul(3)?;
    match encoded_len % 4 {
        0 => Some(base_len),
        2 => base_len.checked_add(1),
        3 => base_len.checked_add(2),
        _ => None,
    }
}

fn validate_private_hnsw_client_state_ciphertext_encoded_len(
    encoded_len: usize,
) -> Result<usize, PrivateHnswClientError> {
    let Some(decoded_len) = base64url_nopad_decoded_len(encoded_len) else {
        return Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding);
    };
    if decoded_len > PRIVATE_HNSW_CLIENT_STATE_CIPHERTEXT_MAX_BYTES {
        return Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding);
    }
    Ok(decoded_len)
}

fn decode_merkle_proof_hash(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswClientError::InvalidMerkleProof);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidMerkleProof)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidMerkleProof)
}

fn private_hnsw_oram_merkle_levels(
    commitments: &[String],
) -> Result<Vec<Vec<[u8; 32]>>, PrivateHnswClientError> {
    if commitments.is_empty() {
        return Err(PrivateHnswClientError::EmptyMerkleTree);
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_bucket_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let padded_len = leaves
        .len()
        .checked_next_power_of_two()
        .ok_or(PrivateHnswClientError::BucketCountMismatch)?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let Some(previous) = levels.last() else {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        };
        let mut next = Vec::with_capacity(previous.len() / 2);
        for [left, right] in previous.as_chunks::<2>().0 {
            next.push(private_hnsw_oram_merkle_parent_hash(left, right));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn private_hnsw_oram_merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn base64url_sha256(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref())
}

fn append_bucket_len_prefixed(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), PrivateHnswClientError> {
    append_len_prefixed(out, bytes)
        .map_err(|()| PrivateHnswClientError::InvalidBucketContext("context_length"))
}

fn append_client_state_len_prefixed(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), PrivateHnswClientError> {
    append_len_prefixed(out, bytes)
        .map_err(|()| PrivateHnswClientError::InvalidClientStateContext("context_length"))
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ()> {
    let len: u32 = bytes.len().try_into().map_err(|_| ())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], PrivateHnswClientError> {
    let end = cursor
        .checked_add(len)
        .ok_or(PrivateHnswClientError::InvalidBlockEncoding)?;
    if end > bytes.len() {
        return Err(PrivateHnswClientError::InvalidBlockEncoding);
    }
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, PrivateHnswClientError> {
    Ok(read_exact(bytes, cursor, 1)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, PrivateHnswClientError> {
    let value: [u8; 2] = read_exact(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, PrivateHnswClientError> {
    let value: [u8; 4] = read_exact(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u32_usize(bytes: &[u8], cursor: &mut usize) -> Result<usize, PrivateHnswClientError> {
    usize::try_from(read_u32(bytes, cursor)?)
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, PrivateHnswClientError> {
    let value: [u8; 8] = read_exact(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)?;
    Ok(u64::from_be_bytes(value))
}

fn read_array_32(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], PrivateHnswClientError> {
    read_exact(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OramKind;
    use crate::control_plane::{PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING};
    use crate::private_result_oram::{
        PrivateResultOramFetchTokenPosition, PrivateResultOramManifest,
        PrivateResultOramTokenFetchAccess,
        plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens,
        private_result_oram_bucket_count,
    };

    /// Deterministic padding source for plan tests: consecutive leaves from `start`.
    fn padding_from(
        start: u64,
        tree_height: u32,
    ) -> impl FnMut() -> Result<u64, PrivateHnswClientError> {
        let leaf_count = private_hnsw_oram_leaf_count(tree_height).unwrap();
        let mut next = start;
        move || {
            let leaf = next;
            next = (next + 1) % leaf_count;
            Ok(leaf)
        }
    }

    #[test]
    fn private_hnsw_client_error_display_does_not_reflect_structured_values() {
        let cases = [
            PrivateHnswClientError::Encryption(EncryptionError::UnsupportedAlgorithm(
                "aead-alg-sentinel".to_string(),
            ))
            .to_string(),
            PrivateHnswClientError::TooManyNeighbors {
                actual: 77,
                limit: 55,
            }
            .to_string(),
            PrivateHnswClientError::UnsupportedBlockVersion(99).to_string(),
            PrivateHnswClientError::UnsupportedVectorEncoding(88).to_string(),
            PrivateHnswClientError::InvalidBucketContext("bucket-context-sentinel").to_string(),
            PrivateHnswClientError::BucketCiphertextSizeMismatch {
                bucket_id: 123,
                expected_bytes: 4096,
                actual_bytes: 2048,
            }
            .to_string(),
            PrivateHnswClientError::InvalidOramClientConfig("client-config-sentinel").to_string(),
            PrivateHnswClientError::InvalidBuildConfig("build-config-sentinel").to_string(),
            PrivateHnswClientError::UnsupportedBucketCiphertextVersion(66).to_string(),
            PrivateHnswClientError::OramInitialPlacementOverflow { leaf: 777 }.to_string(),
            PrivateHnswClientError::InvalidClientStateContext("client-state-context-sentinel")
                .to_string(),
            PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(44).to_string(),
            PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(33).to_string(),
            PrivateHnswClientError::InvalidSearchConfig("search-config-sentinel").to_string(),
            PrivateHnswClientError::InvalidSearchConfig("payload_fetch_tokens").to_string(),
            PrivateHnswClientError::InvalidSearchConfig("payloadFetchTokens").to_string(),
            PrivateHnswClientError::InvalidSearchConfig("payload.fetch.token").to_string(),
            PrivateHnswClientError::InvalidBuildConfig("payload_fetch_token").to_string(),
            PrivateHnswClientError::InvalidBuildConfig("payloadFetchToken").to_string(),
            PrivateHnswClientError::InvalidBuildConfig("payload.fetch.token").to_string(),
            PrivateHnswClientError::InvalidClientStateContext("payload_fetch_tokens").to_string(),
            PrivateHnswClientError::InvalidClientStateContext("payloadFetchTokens").to_string(),
            PrivateHnswClientError::InvalidClientStateContext("payload.fetch.token").to_string(),
            PrivateHnswClientError::FixedBudgetNotExhausted {
                completed_steps: 314,
                fixed_steps: 271,
            }
            .to_string(),
            PrivateHnswClientError::DuplicatePointToken.to_string(),
            PrivateHnswClientError::DuplicatePayloadFetchToken.to_string(),
            PrivateHnswClientError::BucketOutOfRange {
                bucket_id: 123,
                bucket_count: 456,
            }
            .to_string(),
            PrivateHnswClientError::DuplicateBucket { bucket_id: 123 }.to_string(),
            PrivateHnswClientError::MissingBucket { bucket_id: 123 }.to_string(),
            PrivateHnswClientError::DuplicateUpdatedBucket { bucket_id: 123 }.to_string(),
            PrivateHnswClientError::StaleBucketEpoch {
                bucket_id: 123,
                expected_epoch: 42,
                actual_epoch: 43,
            }
            .to_string(),
            PrivateHnswClientError::UnsupportedBucketVersion(22).to_string(),
            PrivateHnswClientError::InvalidCommitSignatureContext(
                "commit-signature-context-sentinel",
            )
            .to_string(),
            PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest-signature-context-sentinel",
            )
            .to_string(),
        ];

        for rendered in cases {
            assert!(!rendered.contains("aead-alg-sentinel"), "{rendered}");
            for leaked in [
                "bucket-context-sentinel",
                "client-config-sentinel",
                "build-config-sentinel",
                "client-state-context-sentinel",
                "search-config-sentinel",
                "commit-signature-context-sentinel",
                "manifest-signature-context-sentinel",
                "payload_fetch_token",
                "payload_fetch_tokens",
                "payloadFetchToken",
                "payloadFetchTokens",
                "payload.fetch.token",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
            for leaked in [
                "77", "55", "99", "88", "123", "4096", "2048", "66", "777", "44", "33", "456",
                "42", "43", "22", "314", "271",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
        }
    }

    #[test]
    fn private_hnsw_client_error_debug_does_not_reflect_structured_values() {
        let cases = [
            format!(
                "{:?}",
                PrivateHnswClientError::Encryption(EncryptionError::UnsupportedAlgorithm(
                    "aead-alg-sentinel".to_string(),
                ))
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::TooManyNeighbors {
                    actual: 77,
                    limit: 55,
                }
            ),
            format!("{:?}", PrivateHnswClientError::UnsupportedBlockVersion(99)),
            format!(
                "{:?}",
                PrivateHnswClientError::UnsupportedVectorEncoding(88)
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidBucketContext("bucket-context-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::BucketCiphertextSizeMismatch {
                    bucket_id: 123,
                    expected_bytes: 4096,
                    actual_bytes: 2048,
                }
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidOramClientConfig("client-config-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidBuildConfig("build-config-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::UnsupportedBucketCiphertextVersion(66)
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::OramInitialPlacementOverflow { leaf: 777 }
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidClientStateContext("client-state-context-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(44)
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(33)
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidSearchConfig("search-config-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidSearchConfig("payload_fetch_tokens")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidSearchConfig("payloadFetchTokens")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidSearchConfig("payload.fetch.token")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidBuildConfig("payload_fetch_token")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidBuildConfig("payloadFetchToken")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidBuildConfig("payload.fetch.token")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidClientStateContext("payload_fetch_tokens")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidClientStateContext("payloadFetchTokens")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidClientStateContext("payload.fetch.token")
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::FixedBudgetNotExhausted {
                    completed_steps: 314,
                    fixed_steps: 271,
                }
            ),
            format!("{:?}", PrivateHnswClientError::DuplicatePointToken),
            format!("{:?}", PrivateHnswClientError::DuplicatePayloadFetchToken),
            format!(
                "{:?}",
                PrivateHnswClientError::BucketOutOfRange {
                    bucket_id: 123,
                    bucket_count: 456,
                }
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::DuplicateBucket { bucket_id: 123 }
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::MissingBucket { bucket_id: 123 }
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::DuplicateUpdatedBucket { bucket_id: 123 }
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::StaleBucketEpoch {
                    bucket_id: 123,
                    expected_epoch: 42,
                    actual_epoch: 43,
                }
            ),
            format!("{:?}", PrivateHnswClientError::UnsupportedBucketVersion(22)),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidCommitSignatureContext(
                    "commit-signature-context-sentinel"
                )
            ),
            format!(
                "{:?}",
                PrivateHnswClientError::InvalidManifestSignatureContext(
                    "manifest-signature-context-sentinel"
                )
            ),
        ];

        for rendered in cases {
            assert!(!rendered.contains("aead-alg-sentinel"), "{rendered}");
            for leaked in [
                "bucket-context-sentinel",
                "client-config-sentinel",
                "build-config-sentinel",
                "client-state-context-sentinel",
                "search-config-sentinel",
                "commit-signature-context-sentinel",
                "manifest-signature-context-sentinel",
                "payload_fetch_token",
                "payload_fetch_tokens",
                "payloadFetchToken",
                "payloadFetchTokens",
                "payload.fetch.token",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
            for leaked in [
                "77", "55", "99", "88", "123", "4096", "2048", "66", "777", "44", "33", "456",
                "314", "271", "42", "43", "22",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
        }
    }

    #[test]
    fn private_hnsw_client_encryption_wrapper_does_not_expose_source_error() {
        let err = PrivateHnswClientError::Encryption(EncryptionError::UnsupportedAlgorithm(
            "aead-source-sentinel".to_string(),
        ));

        assert!(std::error::Error::source(&err).is_none());
        assert!(!err.to_string().contains("aead-source-sentinel"));
        assert!(!format!("{err:?}").contains("aead-source-sentinel"));
    }

    fn test_keys() -> PrivateHnswClientKeys {
        let resource_key = SecretKey::from_bytes([7; 32]);
        PrivateHnswClientKeys::derive_from_resource_key_with_context(
            &resource_key,
            "collection-uuid-1",
            "text",
            "tenant-a/vector-private-rk",
            7,
        )
        .unwrap()
    }

    fn bucket_context(bucket_id: u64) -> PrivateHnswBucketAeadContext<'static> {
        bucket_base_context().for_bucket(bucket_id, 42)
    }

    fn bucket_base_context() -> PrivateHnswBucketAeadBaseContext<'static> {
        PrivateHnswBucketAeadBaseContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
        }
    }

    fn commitment(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn fixture_commit_bucket(
        bucket_id: u64,
        index_epoch: u64,
        commitment_byte: u8,
        hash_byte: u8,
    ) -> PrivateHnswOramBucket {
        let ciphertext = [hash_byte; 48];
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: base64url_sha256(&ciphertext),
            bucket_commitment: commitment(commitment_byte),
        }
    }

    fn fixture_context_commit_bucket(
        bucket_id: u64,
        index_epoch: u64,
        hash_byte: u8,
        manifest: &PrivateHnswOramManifest,
    ) -> PrivateHnswOramBucket {
        let mut raw_ciphertext =
            vec![hash_byte; private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap()];
        raw_ciphertext[0] = BUCKET_AEAD_VERSION;
        let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&raw_ciphertext),
            bucket_commitment: private_hnsw_bucket_commitment(
                bucket_base_context().for_bucket(bucket_id, index_epoch),
                &ciphertext_sha256,
            )
            .unwrap(),
            ciphertext_sha256,
        }
    }

    fn proof_sibling(
        level: u32,
        position: PrivateHnswMerkleSiblingPosition,
        hash: String,
    ) -> PrivateHnswOramMerkleSibling {
        PrivateHnswOramMerkleSibling {
            level,
            position,
            hash,
        }
    }

    fn proof_for_bucket_ids(
        bucket_ids: &[u64],
        index_epoch: u64,
        root_hash: String,
        commitments: &[String],
    ) -> PrivateHnswOramMerkleProof {
        let levels = private_hnsw_oram_merkle_levels(commitments).unwrap();
        let leaves = bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = *bucket_id as usize;
                let siblings = levels
                    .iter()
                    .enumerate()
                    .take(levels.len().saturating_sub(1))
                    .map(|(level, level_hashes)| {
                        let sibling_index = if index.is_multiple_of(2) {
                            index + 1
                        } else {
                            index - 1
                        };
                        let position = if index.is_multiple_of(2) {
                            PrivateHnswMerkleSiblingPosition::Right
                        } else {
                            PrivateHnswMerkleSiblingPosition::Left
                        };
                        index /= 2;
                        proof_sibling(
                            level as u32,
                            position,
                            BASE64URL_NOPAD.encode(&level_hashes[sibling_index]),
                        )
                    })
                    .collect();
                PrivateHnswOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[*bucket_id as usize].clone(),
                    siblings,
                }
            })
            .collect();

        PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch,
            root_hash,
            bucket_count: commitments.len() as u64,
            leaves,
        }
    }

    fn fixture_manifest() -> crate::private_hnsw_oram::PrivateHnswOramManifest {
        use crate::control_plane::{PRIVATE_HNSW_ORAM_BINDING, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER};
        use crate::private_hnsw_oram::{
            FixedBudgetParams, OramKind, OramParams, PrivateHnswOramManifest, PrivateHnswParams,
            ResultPrivacyMode,
        };

        PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 1536,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 32,
                ef_construction: 128,
                max_layers: 16,
                fixed_neighbor_slots: 64,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 16384,
                tree_height: 24,
                path_batch_size: 8,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 32,
                base_layer_steps: 256,
                paths_per_round: 8,
                fixed_result_k: 10,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: (1 << 25) - 1,
            logical_node_count: 500_000,
            dummy_node_count: 24_288,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn result_oram_fetch_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            key_id: "tenant-a/payload-private-rk".to_string(),
            rk_id: "tenant-a/payload-private-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 256,
                tree_height: 2,
                path_batch_size: 2,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: private_result_oram_bucket_count(2).unwrap(),
            logical_result_count: 2,
            dummy_result_count: 2,
            owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn node_block() -> PrivateHnswNodeBlockPlaintext {
        PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: [1; 32],
            point_token: [2; 32],
            level_mask: 0b111,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vec![0, 0, 128, 63, 0, 0, 0, 64],
            neighbors: vec![[3; 32], [4; 32]],
            neighbor_levels: vec![1, 0],
            deleted: false,
            generation: 9,
            payload_fetch_token: Some([5; 32]),
        }
    }

    fn node_block_with_id(id: u8) -> PrivateHnswNodeBlockPlaintext {
        let mut block = node_block();
        block.node_id = [id; 32];
        block.point_token = [id.wrapping_add(20); 32];
        block.payload_fetch_token = None;
        block
    }

    fn node_block_with_vector(
        id: u8,
        vector: &[f32],
        neighbors: Vec<[u8; 32]>,
    ) -> PrivateHnswNodeBlockPlaintext {
        PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: [id; 32],
            point_token: [id.wrapping_add(20); 32],
            level_mask: 1,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vector
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect(),
            neighbor_levels: vec![0; neighbors.len()],
            neighbors,
            deleted: false,
            generation: 1,
            payload_fetch_token: None,
        }
    }

    fn result_token_access(
        payload_fetch_token: [u8; 32],
        point_token: [u8; 32],
        payload: Vec<u8>,
    ) -> PrivateResultOramTokenFetchAccess {
        PrivateResultOramTokenFetchAccess {
            payload_fetch_token,
            old_leaf: 0,
            new_leaf: 1,
            block: PrivateResultOramPayloadBlockPlaintext {
                version: 1,
                payload_fetch_token,
                point_token,
                payload,
                deleted: false,
                generation: 7,
            },
        }
    }

    fn oram_config() -> PrivateHnswOramClientConfig {
        PrivateHnswOramClientConfig {
            tree_height: 2,
            bucket_size: 1,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        }
    }

    #[test]
    fn path_oram_leaf_labels_and_bucket_paths_are_canonical() {
        assert_eq!(private_hnsw_oram_leaf_count(3).unwrap(), 8);
        assert_eq!(private_hnsw_oram_bucket_count(3).unwrap(), 15);
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf(5, 3).unwrap(),
            vec![0, 2, 5, 12]
        );

        let left = encode_private_hnsw_oram_leaf_label(4, 3).unwrap();
        let right = encode_private_hnsw_oram_leaf_label(5, 3).unwrap();
        assert_eq!(decode_private_hnsw_oram_leaf_label(&right, 3).unwrap(), 5);
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels([left.as_str(), right.as_str()], 3, 15)
                .unwrap(),
            vec![0, 2, 5, 11, 0, 2, 5, 12]
        );
    }

    #[test]
    fn path_oram_helpers_reject_invalid_tree_and_leaf_labels() {
        assert!(
            PrivateHnswClientError::InvalidTreeHeight
                .to_string()
                .contains("between 1 and 62")
        );
        assert_eq!(
            private_hnsw_oram_leaf_count(0),
            Err(PrivateHnswClientError::InvalidTreeHeight)
        );
        assert_eq!(
            private_hnsw_oram_leaf_count(63),
            Err(PrivateHnswClientError::InvalidTreeHeight)
        );
        assert_eq!(
            encode_private_hnsw_oram_leaf_label(8, 3),
            Err(PrivateHnswClientError::LeafOutOfRange)
        );
        assert_eq!(
            decode_private_hnsw_oram_leaf_label("not-base64", 3),
            Err(PrivateHnswClientError::InvalidLeafLabelLength)
        );
        assert_eq!(
            decode_private_hnsw_oram_leaf_label("!!!!!!!!!!!", 3),
            Err(PrivateHnswClientError::InvalidLeafLabelEncoding)
        );
        let label = BASE64URL_NOPAD.encode(&7u64.to_be_bytes());
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels([label.as_str()], 3, 14),
            Err(PrivateHnswClientError::BucketCountMismatch)
        );
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels([], 3, 15),
            Err(PrivateHnswClientError::InvalidSearchConfig("leaf_labels"))
        );
        let duplicate_label = BASE64URL_NOPAD.encode(&7u64.to_be_bytes());
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels(
                [duplicate_label.as_str(), duplicate_label.as_str()],
                3,
                15,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("leaf_labels"))
        );
        let out_of_range_label = BASE64URL_NOPAD.encode(&8u64.to_be_bytes());
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels([out_of_range_label.as_str()], 3, 15),
            Err(PrivateHnswClientError::LeafOutOfRange)
        );
    }

    #[test]
    fn remap_leaf_sampler_stays_in_range_and_is_not_a_fixed_schedule() {
        let leaf_count = private_hnsw_oram_leaf_count(10).unwrap();
        let samples = (0..256)
            .map(|_| sample_private_hnsw_oram_leaf(10).unwrap())
            .collect::<Vec<_>>();
        assert!(samples.iter().all(|leaf| *leaf < leaf_count));
        assert!(samples.iter().collect::<BTreeSet<_>>().len() > 16);
        assert!(
            samples
                .windows(2)
                .any(|pair| pair[1] != (pair[0] + 1) % leaf_count)
        );
        assert_eq!(sample_uniform_leaf(&SystemRandom::new(), 0), None);
        assert_eq!(sample_uniform_leaf(&SystemRandom::new(), 1), Some(0));
        assert_eq!(
            sample_private_hnsw_oram_leaf(0),
            Err(PrivateHnswClientError::InvalidTreeHeight)
        );
        assert!(sample_private_hnsw_oram_leaf(1).unwrap() < 2);
    }

    #[test]
    fn speculative_prefetch_plan_deduplicates_positions_and_pads_paths() {
        let config = oram_config();
        let state = PrivateHnswOramClientState::with_position_map(
            [([1; 32], 0), ([2; 32], 1), ([3; 32], 1)],
            config.tree_height,
        )
        .unwrap();

        let plan = plan_private_hnsw_oram_speculative_prefetch(
            &state,
            config,
            &[[1; 32], [2; 32], [3; 32], [4; 32]],
            4,
            padding_from(3, config.tree_height),
        )
        .unwrap();
        let leaves = plan
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(plan.real_path_count, 2);
        assert_eq!(leaves, vec![0, 1, 2, 3]);
        assert_eq!(leaves.iter().collect::<BTreeSet<_>>().len(), leaves.len());
        let colliding_padding = plan_private_hnsw_oram_speculative_prefetch(
            &state,
            config,
            &[[1; 32], [2; 32]],
            3,
            padding_from(1, config.tree_height),
        )
        .unwrap();
        let colliding_padding_leaves = colliding_padding
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(colliding_padding.real_path_count, 2);
        assert_eq!(colliding_padding_leaves, vec![0, 1, 2]);
        let all_dummy_padding = plan_private_hnsw_oram_speculative_prefetch(
            &state,
            config,
            &[],
            3,
            padding_from(2, config.tree_height),
        )
        .unwrap();
        let all_dummy_leaves = all_dummy_padding
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(all_dummy_padding.real_path_count, 0);
        assert_eq!(all_dummy_leaves, vec![0, 2, 3]);
        assert_eq!(
            all_dummy_leaves.iter().collect::<BTreeSet<_>>().len(),
            all_dummy_leaves.len()
        );
        assert_eq!(
            plan_private_hnsw_oram_speculative_prefetch(
                &state,
                config,
                &[[1; 32]],
                0,
                padding_from(3, config.tree_height)
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "fixed_path_count"
            ))
        );
        assert_eq!(
            plan_private_hnsw_oram_speculative_prefetch(
                &state,
                config,
                &[],
                5,
                padding_from(3, config.tree_height)
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "fixed_path_count"
            ))
        );
    }

    #[test]
    fn directional_neighbor_filter_keeps_query_aligned_neighbors() {
        let current =
            node_block_with_vector(1, &[0.0, 0.0], vec![[2; 32], [3; 32], [4; 32], [5; 32]]);
        let forward_far = node_block_with_vector(2, &[2.0, 0.0], vec![]);
        let backward = node_block_with_vector(3, &[-2.0, 0.0], vec![]);
        let sideways = node_block_with_vector(4, &[0.0, 2.0], vec![]);
        let forward_near = node_block_with_vector(5, &[4.0, 0.0], vec![]);
        let unrelated = node_block_with_vector(6, &[9.0, 0.0], vec![]);

        let plan = plan_private_hnsw_oram_directional_neighbor_filter(
            &current,
            &[
                forward_far.clone(),
                backward,
                sideways,
                forward_near.clone(),
                unrelated,
            ],
            &[10.0, 0.0],
            DistanceKind::Euclid,
            2,
        )
        .unwrap();

        assert_eq!(plan.retained_count, 2);
        assert_eq!(
            plan.node_ids,
            vec![forward_near.node_id, forward_far.node_id]
        );
        assert_eq!(
            plan_private_hnsw_oram_directional_neighbor_filter(
                &current,
                &[forward_far.clone(), forward_far],
                &[10.0, 0.0],
                DistanceKind::Euclid,
                2,
            ),
            Err(PrivateHnswClientError::DuplicateBlock)
        );
        assert_eq!(
            plan_private_hnsw_oram_directional_neighbor_filter(
                &current,
                &[forward_near],
                &[10.0, 0.0],
                DistanceKind::Euclid,
                0,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("max_neighbors"))
        );
    }

    #[test]
    fn graph_traversal_path_batch_filters_neighbors_then_pads_paths() {
        let config = PrivateHnswOramClientConfig {
            tree_height: 3,
            ..oram_config()
        };
        let current =
            node_block_with_vector(1, &[0.0, 0.0], vec![[2; 32], [3; 32], [4; 32], [5; 32]]);
        let forward_far = node_block_with_vector(2, &[2.0, 0.0], vec![]);
        let backward = node_block_with_vector(3, &[-2.0, 0.0], vec![]);
        let sideways = node_block_with_vector(4, &[0.0, 2.0], vec![]);
        let forward_near = node_block_with_vector(5, &[4.0, 0.0], vec![]);
        let state = PrivateHnswOramClientState::with_position_map(
            [(forward_far.node_id, 1), (forward_near.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let plan = plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
            &state,
            config,
            &current,
            &[
                forward_far.clone(),
                backward.clone(),
                sideways.clone(),
                forward_near.clone(),
            ],
            &[10.0, 0.0],
            DistanceKind::Euclid,
            3,
            padding_from(7, config.tree_height),
        )
        .unwrap();
        let leaves = plan
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(plan.retained_neighbor_count, 2);
        assert_eq!(plan.real_path_count, 2);
        assert_eq!(leaves, vec![1, 2, 7]);

        let compatibility_plan = plan_private_hnsw_oram_graph_traversal_path_batch(
            &state,
            config,
            &current,
            &[
                forward_far.clone(),
                backward.clone(),
                sideways.clone(),
                forward_near.clone(),
            ],
            &[10.0, 0.0],
            DistanceKind::Euclid,
            3,
            padding_from(7, config.tree_height),
        )
        .unwrap();
        assert_eq!(compatibility_plan.leaf_labels, plan.leaf_labels);
        assert_eq!(compatibility_plan.real_path_count, plan.real_path_count);

        let sparse_state = PrivateHnswOramClientState::with_position_map(
            [(forward_near.node_id, 2)],
            config.tree_height,
        )
        .unwrap();
        let sparse_plan = plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
            &sparse_state,
            config,
            &current,
            &[
                forward_far.clone(),
                backward.clone(),
                sideways.clone(),
                forward_near.clone(),
            ],
            &[10.0, 0.0],
            DistanceKind::Euclid,
            3,
            padding_from(7, config.tree_height),
        )
        .unwrap();
        let sparse_leaves = sparse_plan
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(sparse_plan.retained_neighbor_count, 2);
        assert_eq!(sparse_plan.real_path_count, 1);
        assert_eq!(sparse_leaves, vec![0, 2, 7]);
        assert_eq!(
            sparse_leaves.iter().collect::<BTreeSet<_>>().len(),
            sparse_leaves.len()
        );
        let all_filtered_plan = plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
            &state,
            config,
            &current,
            &[backward.clone(), sideways.clone()],
            &[10.0, 0.0],
            DistanceKind::Euclid,
            3,
            padding_from(6, config.tree_height),
        )
        .unwrap();
        let all_filtered_leaves = all_filtered_plan
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(all_filtered_plan.retained_neighbor_count, 0);
        assert_eq!(all_filtered_plan.real_path_count, 0);
        assert_eq!(all_filtered_leaves, vec![0, 6, 7]);
        assert_eq!(
            all_filtered_leaves.iter().collect::<BTreeSet<_>>().len(),
            all_filtered_leaves.len()
        );
        assert_eq!(
            plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
                &state,
                config,
                &current,
                &[
                    forward_far.clone(),
                    backward.clone(),
                    sideways.clone(),
                    forward_near.clone(),
                ],
                &[10.0, 0.0],
                DistanceKind::Euclid,
                0,
                padding_from(7, config.tree_height)
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "fixed_path_count"
            ))
        );
        assert_eq!(
            plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
                &state,
                config,
                &current,
                &[
                    forward_far.clone(),
                    backward.clone(),
                    sideways.clone(),
                    forward_near.clone(),
                ],
                &[10.0, 0.0],
                DistanceKind::Euclid,
                9,
                padding_from(7, config.tree_height)
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "fixed_path_count"
            ))
        );
        assert_eq!(
            plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
                &state,
                config,
                &current,
                &[
                    forward_far.clone(),
                    backward.clone(),
                    sideways.clone(),
                    forward_near.clone(),
                ],
                &[10.0, 0.0],
                DistanceKind::Euclid,
                3,
                padding_from(8, config.tree_height)
            ),
            Err(PrivateHnswClientError::LeafOutOfRange)
        );

        let duplicate_position_state = PrivateHnswOramClientState::with_position_map(
            [(forward_near.node_id, 2), (forward_far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();
        let duplicate_position_plan = plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
            &duplicate_position_state,
            config,
            &current,
            &[forward_far, backward, sideways, forward_near],
            &[10.0, 0.0],
            DistanceKind::Euclid,
            3,
            padding_from(7, config.tree_height),
        )
        .unwrap();
        let duplicate_position_leaves = duplicate_position_plan
            .leaf_labels
            .iter()
            .map(|label| decode_private_hnsw_oram_leaf_label(label, config.tree_height).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(duplicate_position_plan.retained_neighbor_count, 2);
        assert_eq!(duplicate_position_plan.real_path_count, 1);
        assert_eq!(duplicate_position_leaves, vec![0, 2, 7]);
        assert_eq!(
            duplicate_position_leaves
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            duplicate_position_leaves.len()
        );
    }

    #[test]
    #[allow(deprecated)]
    fn client_key_derivation_is_domain_separated_and_deterministic() {
        let resource_key = SecretKey::from_bytes([7; 32]);
        let first = PrivateHnswClientKeys::derive_from_resource_key(&resource_key).unwrap();
        let second = PrivateHnswClientKeys::derive_from_resource_key(&resource_key).unwrap();

        assert_eq!(
            first.bucket_aead_key().as_bytes(),
            second.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.node_aead_key().as_bytes(),
            first.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.position_map_key().as_bytes(),
            first.payload_token_key().as_bytes()
        );
        assert_ne!(
            first.payload_token_key().as_bytes(),
            first.blind_result_key().as_bytes()
        );

        let debug = format!("{first:?}");
        assert!(debug.contains("[redacted; 32 bytes]"));
        for secret in [
            first.node_aead_key(),
            first.bucket_aead_key(),
            first.position_map_key(),
            first.payload_token_key(),
            first.blind_result_key(),
        ] {
            assert!(!debug.contains(&BASE64URL_NOPAD.encode(secret.as_bytes())));
        }
    }

    #[test]
    #[allow(deprecated)]
    fn client_key_derivation_binds_manifest_context() {
        let resource_key = SecretKey::from_bytes([7; 32]);
        let manifest = fixture_manifest();
        let first =
            PrivateHnswClientKeys::derive_from_resource_key_for_manifest(&resource_key, &manifest)
                .unwrap();
        let second =
            PrivateHnswClientKeys::derive_from_resource_key_for_manifest(&resource_key, &manifest)
                .unwrap();
        let legacy = PrivateHnswClientKeys::derive_from_resource_key(&resource_key).unwrap();
        let mut other_vector = manifest.clone();
        other_vector.vector_name = "title".to_string();
        let other_vector_keys = PrivateHnswClientKeys::derive_from_resource_key_for_manifest(
            &resource_key,
            &other_vector,
        )
        .unwrap();
        let mut other_epoch = manifest;
        other_epoch.rk_epoch += 1;
        let other_epoch_keys = PrivateHnswClientKeys::derive_from_resource_key_for_manifest(
            &resource_key,
            &other_epoch,
        )
        .unwrap();

        assert_eq!(
            first.bucket_aead_key().as_bytes(),
            second.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.bucket_aead_key().as_bytes(),
            legacy.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.bucket_aead_key().as_bytes(),
            other_vector_keys.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.bucket_aead_key().as_bytes(),
            other_epoch_keys.bucket_aead_key().as_bytes()
        );
    }

    #[test]
    fn hnsw_debug_redacts_plaintext_and_access_pattern_values() {
        let mut block = node_block_with_vector(44, &[1.25, 2.5], vec![[45; 32]]);
        block.payload_fetch_token = Some([46; 32]);
        let bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 123_456,
            blocks: vec![Some(block.clone()), None],
        };
        let access = PrivateHnswOramAccessResult {
            old_leaf: 654_321,
            new_leaf: 654_322,
            old_leaf_label: "leaf-label-sentinel".to_string(),
            block: block.clone(),
            writeback_buckets: vec![bucket.clone()],
        };
        let params = PrivateHnswSearchParams {
            entry_node_id: block.node_id,
            k: 1,
            ef: 4,
            fixed_steps: 8,
            distance: DistanceKind::Cosine,
            padding_node_id: Some([47; 32]),
        };
        let client_config = PrivateHnswOramClientConfig {
            tree_height: 3,
            bucket_size: 4,
            block_size_bytes: 512,
            fixed_neighbor_slots: 2,
        };
        let hit = PrivateHnswSearchHit {
            node_id: block.node_id,
            point_token: block.point_token,
            payload_fetch_token: block.payload_fetch_token,
            distance: 0.125,
        };
        let result = PrivateHnswSearchResult {
            hits: vec![hit.clone()],
            accessed_leaf_labels: vec!["leaf-label-sentinel".to_string()],
            completed_steps: 8,
        };
        let access_metrics = PrivateHnswSearchAccessMetrics {
            path_accesses: 5,
            unique_leaf_labels: 3,
            fixed_steps: 8,
            exhausted_fixed_budget: true,
        };
        let fetch_plan = PrivateHnswPrivateResultFetchPlan {
            payload_fetch_tokens: vec![[46; 32], [47; 32]],
            real_result_count: 1,
            fixed_result_k: 2,
        };
        let payload = PrivateHnswPrivateResultPayload {
            node_id: hit.node_id,
            point_token: hit.point_token,
            payload_fetch_token: [46; 32],
            distance: hit.distance,
            payload: b"HNSW-PRIVATE-PAYLOAD-RAW".to_vec(),
            payload_generation: 9,
        };
        let payload_debug = format!("{payload:?}");
        let payload_fetch = PrivateHnswPrivateResultPayloadFetch {
            results: vec![payload],
            real_result_count: 1,
            fixed_result_k: 2,
            fetched_token_count: 2,
        };
        let speculative = PrivateHnswSpeculativePrefetchPlan {
            leaf_labels: vec!["leaf-label-sentinel".to_string()],
            real_path_count: 1,
        };
        let traversal = PrivateHnswGraphTraversalPathBatchPlan {
            leaf_labels: vec!["leaf-label-sentinel".to_string()],
            real_path_count: 1,
            retained_neighbor_count: 1,
        };
        let directional = PrivateHnswDirectionalNeighborFilterPlan {
            node_ids: vec![block.node_id],
            retained_count: 1,
        };
        let build_point = PrivateHnswBuildPoint {
            node_id: block.node_id,
            point_token: block.point_token,
            vector: vec![1.25, 2.5],
            payload_fetch_token: block.payload_fetch_token,
        };
        let mut node_cache = PrivateHnswClientNodeCache::new();
        node_cache.insert(block.clone());
        let encrypted_bucket = PrivateHnswOramBucket {
            version: 1,
            bucket_id: 123_456,
            index_epoch: 42,
            ciphertext: "HNSW-CIPHERTEXT-SENTINEL".to_string(),
            ciphertext_sha256: "HNSW-SHA-SENTINEL".to_string(),
            bucket_commitment: "HNSW-COMMITMENT-SENTINEL".to_string(),
        };
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: "HNSW-SIGNATURE-SENTINEL".to_string(),
        };
        let state_snapshot = PrivateHnswOramClientStateSnapshot {
            version: 1,
            tree_height: 3,
            positions: vec![PrivateHnswPositionMapSnapshotEntry {
                node_id: BASE64URL_NOPAD.encode(&[44; 32]),
                leaf_label: "leaf-label-sentinel".to_string(),
            }],
            stash: vec![block.clone()],
        };
        let encrypted_state_snapshot = PrivateHnswEncryptedClientStateSnapshot {
            version: 1,
            index_epoch: 42,
            root_hash: "HNSW-ROOT-SENTINEL".to_string(),
            ciphertext: "HNSW-STATE-CIPHERTEXT-SENTINEL".to_string(),
            ciphertext_sha256: "HNSW-STATE-SHA-SENTINEL".to_string(),
        };
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: "HNSW-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 123_456,
                leaf_hash: "HNSW-LEAF-HASH-SENTINEL".to_string(),
                siblings: vec![PrivateHnswOramMerkleSibling {
                    level: 0,
                    position: PrivateHnswMerkleSiblingPosition::Left,
                    hash: "HNSW-SIBLING-HASH-SENTINEL".to_string(),
                }],
            }],
        };
        let encrypted_batch = PrivateHnswEncryptedPathBatch {
            index_epoch: 42,
            root_hash: "HNSW-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            proof_value: "HNSW-PROOF-VALUE-SENTINEL".to_string(),
            buckets: vec![encrypted_bucket.clone()],
        };
        let encrypted_index = PrivateHnswEncryptedIndexBuild {
            index_epoch: 42,
            entry_node_id: block.node_id,
            root_hash: "HNSW-ROOT-SENTINEL".to_string(),
            bucket_count: 1,
            logical_node_count: 1,
            dummy_node_count: 0,
            buckets: vec![encrypted_bucket.clone()],
        };
        let mut manifest = fixture_manifest();
        manifest.collection_id = "HNSW-CLIENT-MANIFEST-COLLECTION-ID-SENTINEL".to_string();
        manifest.vector_name = "HNSW-CLIENT-MANIFEST-VECTOR-NAME-SENTINEL".to_string();
        manifest.root_hash = "HNSW-MANIFEST-ROOT-SENTINEL".to_string();
        let upload_bundle = PrivateHnswOramUploadBundle {
            manifest: manifest.clone(),
            manifest_signature: signature.clone(),
            buckets: vec![encrypted_bucket.clone()],
        };
        let leaf_commitment = encrypted_bucket.bucket_commitment.clone();
        let commit_plan = PrivateHnswClientCommitPlan {
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: "HNSW-OLD-ROOT-SENTINEL".to_string(),
            new_root_hash: "HNSW-NEW-ROOT-SENTINEL".to_string(),
            leaf_commitments: vec![leaf_commitment],
            updated_buckets: vec![PrivateHnswClientCommitBucketRef {
                bucket_id: 123_456,
                ciphertext_sha256: "HNSW-SHA-SENTINEL".to_string(),
            }],
        };
        let commit_refs = commit_plan.signature_bucket_refs();
        let client_commit_ref = PrivateHnswClientCommitBucketRef {
            bucket_id: 123_456,
            ciphertext_sha256: "HNSW-CLIENT-COMMIT-REF-SHA-SENTINEL".to_string(),
        };
        let oram_commit_ref = PrivateHnswOramCommitBucketRef {
            bucket_id: 123_456,
            ciphertext_sha256: "HNSW-ORAM-COMMIT-REF-SHA-SENTINEL",
        };
        let commit_signature_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "HNSW-CLIENT-COMMIT-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-COMMIT-VECTOR-NAME-SENTINEL",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: "HNSW-OLD-ROOT-SENTINEL",
            new_root_hash: "HNSW-NEW-ROOT-SENTINEL",
            updated_buckets: &commit_refs,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let read_path_labels = ["leaf-label-sentinel", "leaf-label-sentinel-2"];
        let read_signature_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "HNSW-CLIENT-READ-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-READ-VECTOR-NAME-SENTINEL",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: "HNSW-ROOT-SENTINEL",
            paths: &read_path_labels,
            requested_paths: 8,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let bucket_aead_context = PrivateHnswBucketAeadContext {
            collection_id: "HNSW-CLIENT-AEAD-BUCKET-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-AEAD-BUCKET-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-AEAD-BUCKET-KEY-SENTINEL",
            rk_id: "HNSW-AEAD-BUCKET-RK-SENTINEL",
            rk_epoch: 7,
            bucket_id: 888_123,
            index_epoch: 777_123,
        };
        let bucket_aead_base_context = PrivateHnswBucketAeadBaseContext {
            collection_id: "HNSW-CLIENT-AEAD-BASE-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-AEAD-BASE-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-AEAD-BASE-KEY-SENTINEL",
            rk_id: "HNSW-AEAD-BASE-RK-SENTINEL",
            rk_epoch: 7,
        };
        let client_state_aead_context = PrivateHnswClientStateAeadContext {
            collection_id: "HNSW-CLIENT-AEAD-STATE-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-AEAD-STATE-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-AEAD-STATE-KEY-SENTINEL",
            rk_id: "HNSW-AEAD-STATE-RK-SENTINEL",
            rk_epoch: 7,
            index_epoch: 777_124,
            root_hash: "HNSW-AEAD-STATE-ROOT-SENTINEL",
        };
        let commit_signature_context = PrivateHnswCommitSignatureContext {
            collection_id: "HNSW-CLIENT-SIGN-CONTEXT-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-SIGN-CONTEXT-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-SIGN-CONTEXT-KEY-SENTINEL",
            rk_id: "HNSW-SIGN-CONTEXT-RK-SENTINEL",
            rk_epoch: 7,
            signing_key_id: "HNSW-SIGN-CONTEXT-SIGNING-KEY-SENTINEL",
        };
        let manifest_build_context = PrivateHnswManifestBuildContext {
            collection_id: "HNSW-CLIENT-MANIFEST-BUILD-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-CLIENT-MANIFEST-BUILD-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-MANIFEST-BUILD-KEY-SENTINEL",
            rk_id: "HNSW-MANIFEST-BUILD-RK-SENTINEL",
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 1,
                ef_construction: 2,
                max_layers: 1,
                fixed_neighbor_slots: 2,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 2,
                block_size_bytes: 512,
                tree_height: 3,
                path_batch_size: 2,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 2,
                paths_per_round: 2,
                fixed_result_k: 1,
            },
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "HNSW-MANIFEST-BUILD-OWNER-SIGNING-SENTINEL",
            created_at_unix: 1_770_000_000,
        };

        let rendered = [
            format!("{block:?}"),
            format!("{bucket:?}"),
            format!("{access:?}"),
            format!("{params:?}"),
            format!("{client_config:?}"),
            format!("{hit:?}"),
            format!("{result:?}"),
            format!("{access_metrics:?}"),
            format!("{fetch_plan:?}"),
            payload_debug.clone(),
            format!("{payload_fetch:?}"),
            format!("{speculative:?}"),
            format!("{traversal:?}"),
            format!("{directional:?}"),
            format!("{build_point:?}"),
            format!("{node_cache:?}"),
            format!("{encrypted_bucket:?}"),
            format!("{signature:?}"),
            format!("{state_snapshot:?}"),
            format!("{encrypted_state_snapshot:?}"),
            format!("{proof:?}"),
            format!("{:?}", proof.leaves[0]),
            format!("{:?}", proof.leaves[0].siblings[0]),
            format!("{encrypted_batch:?}"),
            format!("{encrypted_index:?}"),
            format!("{manifest:?}"),
            format!("{upload_bundle:?}"),
            format!("{commit_plan:?}"),
            format!("{client_commit_ref:?}"),
            format!("{oram_commit_ref:?}"),
            format!("{commit_signature_input:?}"),
            format!("{read_signature_input:?}"),
            format!("{bucket_aead_context:?}"),
            format!("{bucket_aead_base_context:?}"),
            format!("{client_state_aead_context:?}"),
            format!("{commit_signature_context:?}"),
            format!("{manifest_build_context:?}"),
        ]
        .join("\n");
        for epoch_redacted in [
            format!("{encrypted_state_snapshot:?}"),
            format!("{proof:?}"),
            format!("{encrypted_batch:?}"),
            format!("{encrypted_index:?}"),
        ] {
            assert!(!epoch_redacted.contains("42"), "{epoch_redacted}");
        }
        let encrypted_state_snapshot_rendered = format!("{encrypted_state_snapshot:?}");
        assert!(
            !encrypted_state_snapshot_rendered
                .contains(&encrypted_state_snapshot.ciphertext.len().to_string()),
            "{encrypted_state_snapshot_rendered}"
        );
        for leaked in [
            BASE64URL_NOPAD.encode(&[44; 32]),
            BASE64URL_NOPAD.encode(&[45; 32]),
            BASE64URL_NOPAD.encode(&[46; 32]),
            BASE64URL_NOPAD.encode(&[47; 32]),
            format!("{:?}", [44u8; 32]),
            format!("{:?}", [45u8; 32]),
            format!("{:?}", [46u8; 32]),
            format!("{:?}", [47u8; 32]),
            serde_json::to_string(&block.vector).unwrap(),
            "leaf-label-sentinel".to_string(),
            "leaf-label-sentinel-2".to_string(),
            "123456".to_string(),
            "654321".to_string(),
            "HNSW-PRIVATE-PAYLOAD-RAW".to_string(),
            "HNSW-CIPHERTEXT-SENTINEL".to_string(),
            "HNSW-SHA-SENTINEL".to_string(),
            "HNSW-CLIENT-COMMIT-REF-SHA-SENTINEL".to_string(),
            "HNSW-ORAM-COMMIT-REF-SHA-SENTINEL".to_string(),
            "HNSW-COMMITMENT-SENTINEL".to_string(),
            "HNSW-SIGNATURE-SENTINEL".to_string(),
            "HNSW-ROOT-SENTINEL".to_string(),
            "HNSW-STATE-CIPHERTEXT-SENTINEL".to_string(),
            "HNSW-STATE-SHA-SENTINEL".to_string(),
            "HNSW-LEAF-HASH-SENTINEL".to_string(),
            "HNSW-SIBLING-HASH-SENTINEL".to_string(),
            "HNSW-PROOF-VALUE-SENTINEL".to_string(),
            "HNSW-OLD-ROOT-SENTINEL".to_string(),
            "HNSW-NEW-ROOT-SENTINEL".to_string(),
            "HNSW-CLIENT-MANIFEST-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-MANIFEST-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-MANIFEST-ROOT-SENTINEL".to_string(),
            "HNSW-CLIENT-COMMIT-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-COMMIT-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-CLIENT-READ-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-READ-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-CLIENT-AEAD-BUCKET-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-AEAD-BUCKET-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-AEAD-BUCKET-KEY-SENTINEL".to_string(),
            "HNSW-AEAD-BUCKET-RK-SENTINEL".to_string(),
            "888123".to_string(),
            "777123".to_string(),
            "HNSW-CLIENT-AEAD-BASE-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-AEAD-BASE-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-AEAD-BASE-KEY-SENTINEL".to_string(),
            "HNSW-AEAD-BASE-RK-SENTINEL".to_string(),
            "HNSW-CLIENT-AEAD-STATE-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-AEAD-STATE-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-AEAD-STATE-KEY-SENTINEL".to_string(),
            "HNSW-AEAD-STATE-RK-SENTINEL".to_string(),
            "777124".to_string(),
            "HNSW-AEAD-STATE-ROOT-SENTINEL".to_string(),
            "HNSW-CLIENT-SIGN-CONTEXT-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-SIGN-CONTEXT-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-SIGN-CONTEXT-KEY-SENTINEL".to_string(),
            "HNSW-SIGN-CONTEXT-RK-SENTINEL".to_string(),
            "HNSW-SIGN-CONTEXT-SIGNING-KEY-SENTINEL".to_string(),
            "HNSW-CLIENT-MANIFEST-BUILD-COLLECTION-ID-SENTINEL".to_string(),
            "HNSW-CLIENT-MANIFEST-BUILD-VECTOR-NAME-SENTINEL".to_string(),
            "HNSW-MANIFEST-BUILD-KEY-SENTINEL".to_string(),
            "HNSW-MANIFEST-BUILD-RK-SENTINEL".to_string(),
            "HNSW-MANIFEST-BUILD-OWNER-SIGNING-SENTINEL".to_string(),
        ] {
            assert!(!rendered.contains(&leaked), "{rendered}");
        }
        for (debug_rendered, redacted_count) in [
            (format!("{block:?}"), "vector_len: 8"),
            (format!("{block:?}"), "neighbor_count: 1"),
            (format!("{block:?}"), "neighbor_levels_len: 1"),
            (format!("{block:?}"), "deleted: false"),
            (format!("{block:?}"), "generation: 1"),
            (format!("{block:?}"), "payload_fetch_token: Some"),
            (format!("{bucket:?}"), "blocks_len: 2"),
            (format!("{bucket:?}"), "occupied_blocks: 1"),
            (format!("{state_snapshot:?}"), "tree_height: 3"),
            (format!("{state_snapshot:?}"), "position_count: 1"),
            (format!("{state_snapshot:?}"), "stash_len: 1"),
            (format!("{proof:?}"), "bucket_count: 8"),
            (format!("{proof:?}"), "leaf_count: 1"),
            (format!("{:?}", proof.leaves[0]), "sibling_count: 1"),
            (format!("{encrypted_batch:?}"), "bucket_count: 8"),
            (format!("{encrypted_batch:?}"), "returned_bucket_count: 1"),
            (format!("{encrypted_index:?}"), "bucket_count: 1"),
            (format!("{access:?}"), "writeback_bucket_count: 1"),
            (format!("{params:?}"), "k: 1"),
            (format!("{params:?}"), "ef: 4"),
            (format!("{params:?}"), "fixed_steps: 8"),
            (format!("{params:?}"), "has_padding_node_id: true"),
            (format!("{client_config:?}"), "tree_height: 3"),
            (format!("{client_config:?}"), "bucket_size: 4"),
            (format!("{client_config:?}"), "block_size_bytes: 512"),
            (format!("{client_config:?}"), "fixed_neighbor_slots: 2"),
            (format!("{manifest_build_context:?}"), "ef_construction: 2"),
            (
                format!("{manifest_build_context:?}"),
                "block_size_bytes: 512",
            ),
            (format!("{manifest_build_context:?}"), "fixed_result_k: 1"),
            (format!("{hit:?}"), "has_payload_fetch_token: true"),
            (format!("{result:?}"), "hit_count: 1"),
            (format!("{result:?}"), "accessed_leaf_label_count: 1"),
            (format!("{result:?}"), "completed_steps: 8"),
            (format!("{access_metrics:?}"), "path_accesses: 5"),
            (format!("{access_metrics:?}"), "unique_leaf_labels: 3"),
            (format!("{access_metrics:?}"), "fixed_steps: 8"),
            (
                format!("{access_metrics:?}"),
                "exhausted_fixed_budget: true",
            ),
            (format!("{fetch_plan:?}"), "payload_fetch_token_count: 2"),
            (format!("{fetch_plan:?}"), "real_result_count: 1"),
            (format!("{fetch_plan:?}"), "fixed_result_k: 2"),
            (payload_debug.clone(), "payload_generation: 9"),
            (format!("{payload_fetch:?}"), "result_count: 1"),
            (format!("{payload_fetch:?}"), "fetched_token_count: 2"),
            (format!("{speculative:?}"), "real_path_count: 1"),
            (format!("{traversal:?}"), "real_path_count: 1"),
            (format!("{traversal:?}"), "retained_neighbor_count: 1"),
            (format!("{directional:?}"), "node_id_count: 1"),
            (format!("{directional:?}"), "retained_count: 1"),
            (format!("{build_point:?}"), "vector_len: 2"),
            (format!("{build_point:?}"), "has_payload_fetch_token: true"),
            (format!("{node_cache:?}"), "node_count: 1"),
            (format!("{upload_bundle:?}"), "bucket_count: 1"),
            (format!("{commit_plan:?}"), "leaf_commitment_count: 1"),
            (format!("{commit_plan:?}"), "updated_bucket_count: 1"),
            (format!("{read_signature_input:?}"), "path_count: 2"),
            (format!("{read_signature_input:?}"), "requested_paths: 8"),
        ] {
            assert!(
                !debug_rendered.contains(redacted_count),
                "leaked {redacted_count} in {debug_rendered}"
            );
        }
    }

    #[test]
    fn node_block_codec_pads_to_fixed_size_and_roundtrips() {
        let block = node_block();
        let encoded = encode_private_hnsw_node_block(&block, 512, 4).unwrap();
        assert_eq!(encoded.len(), 512);

        let decoded = decode_private_hnsw_node_block(&encoded).unwrap();
        assert_eq!(decoded, block);
    }

    #[test]
    fn node_block_codec_rejects_shape_and_padding_tamper() {
        let mut block = node_block();
        block.neighbor_levels.pop();
        assert_eq!(
            encode_private_hnsw_node_block(&block, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let block = node_block();
        assert_eq!(
            encode_private_hnsw_node_block(&block, 512, 1),
            Err(PrivateHnswClientError::TooManyNeighbors {
                actual: 2,
                limit: 1
            })
        );

        let mut encoded = encode_private_hnsw_node_block(&block, 512, 4).unwrap();
        let last = encoded.len() - 1;
        encoded[last] = 1;
        assert_eq!(
            decode_private_hnsw_node_block(&encoded),
            Err(PrivateHnswClientError::InvalidBlockPadding)
        );
    }

    #[test]
    fn node_block_codec_rejects_duplicate_level_and_self_neighbors() {
        let mut duplicate_level = node_block();
        duplicate_level.neighbors = vec![[3; 32], [3; 32]];
        duplicate_level.neighbor_levels = vec![0, 0];
        assert_eq!(
            encode_private_hnsw_node_block(&duplicate_level, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let mut duplicate_level_valid_shape = node_block();
        duplicate_level_valid_shape.neighbors = vec![[3; 32], [3; 32]];
        duplicate_level_valid_shape.neighbor_levels = vec![0, 1];
        let mut valid_duplicate_level =
            encode_private_hnsw_node_block(&duplicate_level_valid_shape, 512, 4)
                .expect("same neighbor on different levels is valid");
        assert_eq!(
            decode_private_hnsw_node_block(&valid_duplicate_level)
                .expect("same neighbor on different levels should decode"),
            duplicate_level_valid_shape
        );
        let first_neighbor_offset = 4 + 2 + 32 + 32 + 8 + 1 + 1 + 8 + 1 + 32 + 4 + 4 + 4 + 8;
        let second_neighbor_level_offset = first_neighbor_offset + 33 + 32;
        valid_duplicate_level[second_neighbor_level_offset] = 0;
        assert_eq!(
            decode_private_hnsw_node_block(&valid_duplicate_level),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let mut self_neighbor = node_block();
        self_neighbor.neighbors = vec![self_neighbor.node_id];
        self_neighbor.neighbor_levels = vec![0];
        assert_eq!(
            encode_private_hnsw_node_block(&self_neighbor, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );
    }

    #[test]
    fn node_block_codec_rejects_malformed_level_masks() {
        let mut zero_mask = node_block();
        zero_mask.level_mask = 0;
        assert_eq!(
            encode_private_hnsw_node_block(&zero_mask, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let mut non_contiguous_mask = node_block();
        non_contiguous_mask.level_mask = 0b101;
        assert_eq!(
            encode_private_hnsw_node_block(&non_contiguous_mask, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let mut missing_neighbor_level = node_block();
        missing_neighbor_level.level_mask = 0b1;
        assert_eq!(
            encode_private_hnsw_node_block(&missing_neighbor_level, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let mut encoded = encode_private_hnsw_node_block(&node_block(), 512, 4)
            .expect("fixture block should encode");
        let first_neighbor_level_offset =
            4 + 2 + 32 + 32 + 8 + 1 + 1 + 8 + 1 + 32 + 4 + 4 + 4 + 8 + 32;
        encoded[first_neighbor_level_offset] = 64;
        assert_eq!(
            decode_private_hnsw_node_block(&encoded),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );
    }

    #[test]
    fn node_block_codec_rejects_malformed_f32_vectors() {
        let mut bad_len = node_block();
        bad_len.vector.push(1);
        assert_eq!(
            encode_private_hnsw_node_block(&bad_len, 512, 4),
            Err(PrivateHnswClientError::InvalidF32VectorLength)
        );

        let mut non_finite = node_block();
        non_finite.vector = f32::NAN.to_le_bytes().to_vec();
        assert_eq!(
            encode_private_hnsw_node_block(&non_finite, 512, 4),
            Err(PrivateHnswClientError::NonFiniteDistance)
        );

        let mut empty = node_block();
        empty.vector.clear();
        assert_eq!(
            encode_private_hnsw_node_block(&empty, 512, 4),
            Err(PrivateHnswClientError::NonFiniteDistance)
        );

        let mut encoded = encode_private_hnsw_node_block(&node_block(), 512, 4)
            .expect("fixture block should encode");
        let vector_len_offset = 4 + 2 + 32 + 32 + 8 + 1 + 1 + 8 + 1 + 32 + 4 + 4;
        encoded[vector_len_offset + 3] = 9;
        assert_eq!(
            decode_private_hnsw_node_block(&encoded),
            Err(PrivateHnswClientError::InvalidF32VectorLength)
        );

        let mut encoded = encode_private_hnsw_node_block(&node_block(), 512, 4)
            .expect("fixture block should encode");
        let vector_offset = vector_len_offset + 4;
        encoded[vector_offset..vector_offset + 4].copy_from_slice(&f32::INFINITY.to_le_bytes());
        assert_eq!(
            decode_private_hnsw_node_block(&encoded),
            Err(PrivateHnswClientError::NonFiniteDistance)
        );
    }

    #[test]
    fn bucket_plaintext_codec_roundtrips_fixed_slots_and_rejects_tamper() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(node_block_with_id(8)), None],
        };
        let encoded = encode_private_hnsw_oram_bucket_plaintext(&bucket, config).unwrap();
        assert_eq!(
            encoded.len(),
            private_hnsw_bucket_plaintext_len(config).unwrap()
        );
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(3, &encoded, config).unwrap(),
            bucket
        );

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] = 1;
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(3, &tampered, config),
            Err(PrivateHnswClientError::InvalidBucketPlaintext)
        );

        let duplicate_point_a = node_block_with_id(9);
        let mut duplicate_point_b = node_block_with_id(10);
        duplicate_point_b.point_token = duplicate_point_a.point_token;
        let duplicate_point_bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![
                Some(duplicate_point_a.clone()),
                Some(duplicate_point_b.clone()),
            ],
        };
        assert_eq!(
            encode_private_hnsw_oram_bucket_plaintext(&duplicate_point_bucket, config),
            Err(PrivateHnswClientError::DuplicatePointToken)
        );

        let mut duplicate_point_encoded =
            Vec::with_capacity(private_hnsw_bucket_plaintext_len(config).unwrap());
        duplicate_point_encoded.extend_from_slice(BUCKET_PLAINTEXT_MAGIC);
        push_u16(&mut duplicate_point_encoded, BUCKET_PLAINTEXT_VERSION);
        push_u32(&mut duplicate_point_encoded, config.bucket_size as u32);
        push_u32(&mut duplicate_point_encoded, config.block_size_bytes as u32);
        for block in [duplicate_point_a, duplicate_point_b] {
            duplicate_point_encoded.push(1);
            duplicate_point_encoded.extend_from_slice(
                &encode_private_hnsw_node_block(
                    &block,
                    config.block_size_bytes,
                    config.fixed_neighbor_slots,
                )
                .unwrap(),
            );
        }
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(3, &duplicate_point_encoded, config),
            Err(PrivateHnswClientError::DuplicatePointToken)
        );

        let mut duplicate_payload_a = node_block_with_id(11);
        duplicate_payload_a.payload_fetch_token = Some([77; 32]);
        let mut duplicate_payload_b = node_block_with_id(12);
        duplicate_payload_b.payload_fetch_token = Some([77; 32]);
        let duplicate_payload_bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(duplicate_payload_a), Some(duplicate_payload_b)],
        };
        assert_eq!(
            encode_private_hnsw_oram_bucket_plaintext(&duplicate_payload_bucket, config),
            Err(PrivateHnswClientError::DuplicatePayloadFetchToken)
        );
    }

    #[test]
    fn bucket_plaintext_codec_rejects_overflowing_shape_config() {
        let block_size_overflow = PrivateHnswOramClientConfig {
            block_size_bytes: usize::MAX,
            ..oram_config()
        };
        let bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 3,
            blocks: Vec::new(),
        };
        assert_eq!(
            encode_private_hnsw_oram_bucket_plaintext(&bucket, block_size_overflow),
            Err(PrivateHnswClientError::InvalidOramClientConfig(
                "block_size_bytes"
            ))
        );

        let bucket_size_overflow = PrivateHnswOramClientConfig {
            bucket_size: usize::MAX,
            block_size_bytes: 2,
            ..oram_config()
        };
        assert_eq!(
            empty_private_hnsw_oram_plaintext_bucket(3, bucket_size_overflow),
            Err(PrivateHnswClientError::InvalidOramClientConfig(
                "bucket_size"
            ))
        );
    }

    #[test]
    fn path_oram_access_absorbs_path_remaps_and_writes_back() {
        let config = oram_config();
        let node_a = node_block_with_id(10);
        let node_b = node_block_with_id(11);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2), (node_b.node_id, 3)],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            PrivateHnswOramPlaintextBucket {
                bucket_id: 0,
                blocks: vec![None],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 2,
                blocks: vec![Some(node_b.clone())],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 5,
                blocks: vec![Some(node_a.clone())],
            },
        ];

        let access =
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &path, 0).unwrap();

        assert_eq!(access.old_leaf, 2);
        assert_eq!(access.new_leaf, 0);
        assert_eq!(
            access.old_leaf_label,
            encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap()
        );
        assert_eq!(access.block, node_a);
        assert_eq!(state.position(&[10; 32]), Some(0));
        assert_eq!(state.position(&[11; 32]), Some(3));
        assert_eq!(state.stash_len(), 0);
        assert_eq!(
            access
                .writeback_buckets
                .iter()
                .map(|bucket| bucket.bucket_id)
                .collect::<Vec<_>>(),
            vec![0, 2, 5]
        );
        assert_eq!(
            access.writeback_buckets[0].blocks[0]
                .as_ref()
                .map(|block| block.node_id),
            Some([10; 32])
        );
        assert_eq!(
            access.writeback_buckets[1].blocks[0]
                .as_ref()
                .map(|block| block.node_id),
            Some([11; 32])
        );
        assert!(access.writeback_buckets[2].blocks[0].is_none());
    }

    #[test]
    fn path_oram_access_rejects_wrong_path_and_missing_target() {
        let config = oram_config();
        let node_a = node_block_with_id(10);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2)],
            config.tree_height,
        )
        .unwrap();
        let wrong_path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(3, config).unwrap(),
        ];
        assert_eq!(
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &wrong_path, 0),
            Err(PrivateHnswClientError::PathBucketMismatch)
        );

        let path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(2, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(5, config).unwrap(),
        ];
        assert_eq!(
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &path, 0),
            Err(PrivateHnswClientError::MissingBlock)
        );
    }

    #[test]
    fn path_oram_access_rejects_duplicate_point_and_payload_tokens() {
        let config = oram_config();
        let node_a = node_block_with_id(10);
        let mut duplicate_point_node = node_block_with_id(11);
        duplicate_point_node.point_token = node_a.point_token;
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2), (duplicate_point_node.node_id, 3)],
            config.tree_height,
        )
        .unwrap();
        let duplicate_point_path = vec![
            PrivateHnswOramPlaintextBucket {
                bucket_id: 0,
                blocks: vec![None],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 2,
                blocks: vec![Some(duplicate_point_node)],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 5,
                blocks: vec![Some(node_a.clone())],
            },
        ];
        assert_eq!(
            access_private_hnsw_oram_path(
                &mut state,
                config,
                node_a.node_id,
                &duplicate_point_path,
                0
            ),
            Err(PrivateHnswClientError::DuplicatePointToken)
        );
        assert_eq!(state.stash_len(), 0);
        assert_eq!(state.position(&node_a.node_id), Some(2));

        let mut node_with_payload = node_block_with_id(12);
        node_with_payload.payload_fetch_token = Some([77; 32]);
        let mut duplicate_payload_node = node_block_with_id(13);
        duplicate_payload_node.payload_fetch_token = Some([77; 32]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [
                (node_with_payload.node_id, 2),
                (duplicate_payload_node.node_id, 3),
            ],
            config.tree_height,
        )
        .unwrap();
        let duplicate_payload_path = vec![
            PrivateHnswOramPlaintextBucket {
                bucket_id: 0,
                blocks: vec![None],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 2,
                blocks: vec![Some(duplicate_payload_node)],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 5,
                blocks: vec![Some(node_with_payload.clone())],
            },
        ];
        assert_eq!(
            access_private_hnsw_oram_path(
                &mut state,
                config,
                node_with_payload.node_id,
                &duplicate_payload_path,
                0
            ),
            Err(PrivateHnswClientError::DuplicatePayloadFetchToken)
        );
        assert_eq!(state.stash_len(), 0);
        assert_eq!(state.position(&node_with_payload.node_id), Some(2));
    }

    #[test]
    fn path_oram_writeback_buckets_can_be_encoded_sealed_and_reopened() {
        let config = oram_config();
        let keys = test_keys();
        let node_a = node_block_with_id(10);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2)],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(2, config).unwrap(),
            PrivateHnswOramPlaintextBucket {
                bucket_id: 5,
                blocks: vec![Some(node_a.clone())],
            },
        ];

        let access =
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &path, 0).unwrap();
        let root_writeback = &access.writeback_buckets[0];
        let plaintext = encode_private_hnsw_oram_bucket_plaintext(root_writeback, config).unwrap();
        let sealed = seal_private_hnsw_oram_bucket(
            &keys,
            bucket_context(root_writeback.bucket_id),
            &plaintext,
        )
        .unwrap();
        let reopened =
            open_private_hnsw_oram_bucket(&keys, bucket_context(root_writeback.bucket_id), &sealed)
                .unwrap();
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(root_writeback.bucket_id, &reopened, config)
                .unwrap(),
            *root_writeback
        );
    }

    #[test]
    fn verified_path_batch_opens_buckets_only_after_merkle_proof_check() {
        let config = oram_config();
        let keys = test_keys();
        let plaintext_bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 0,
            blocks: vec![Some(node_block_with_id(8))],
        };
        let bucket = seal_private_hnsw_oram_plaintext_bucket(
            &keys,
            bucket_base_context(),
            42,
            &plaintext_bucket,
            config,
        )
        .unwrap();
        let root_hash = bucket.bucket_commitment.clone();
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count: 1,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 0,
                leaf_hash: bucket.bucket_commitment.clone(),
                siblings: vec![],
            }],
        };
        let proof_json = serde_json::to_string(&proof).unwrap();

        let opened = open_private_hnsw_oram_verified_path_batch(
            &keys,
            bucket_base_context(),
            config,
            42,
            &root_hash,
            1,
            &proof_json,
            std::slice::from_ref(&bucket),
        )
        .unwrap();
        assert_eq!(opened, vec![plaintext_bucket.clone()]);

        let carried_forward_proof = PrivateHnswOramMerkleProof {
            index_epoch: 43,
            ..proof.clone()
        };
        let carried_forward_json = serde_json::to_string(&carried_forward_proof).unwrap();
        let carried_forward = open_private_hnsw_oram_verified_path_batch(
            &keys,
            bucket_base_context(),
            config,
            43,
            &root_hash,
            1,
            &carried_forward_json,
            std::slice::from_ref(&bucket),
        )
        .unwrap();
        assert_eq!(carried_forward, vec![plaintext_bucket]);

        let mut tampered = proof;
        tampered.root_hash = commitment(9);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        assert_eq!(
            open_private_hnsw_oram_verified_path_batch(
                &keys,
                bucket_base_context(),
                config,
                42,
                &root_hash,
                1,
                &tampered_json,
                &[bucket],
            ),
            Err(PrivateHnswClientError::MerkleProofMismatch)
        );
    }

    #[test]
    fn verified_path_batch_accepts_identical_duplicate_buckets_for_fixed_size_paths() {
        let config = oram_config();
        let keys = test_keys();
        let plaintext_bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 0,
            blocks: vec![Some(node_block_with_id(8))],
        };
        let bucket = seal_private_hnsw_oram_plaintext_bucket(
            &keys,
            bucket_base_context(),
            42,
            &plaintext_bucket,
            config,
        )
        .unwrap();
        let root_hash = bucket.bucket_commitment.clone();
        let leaf = PrivateHnswOramMerkleProofLeaf {
            bucket_id: 0,
            leaf_hash: bucket.bucket_commitment.clone(),
            siblings: vec![],
        };
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count: 1,
            leaves: vec![leaf.clone(), leaf],
        };
        let proof_json = serde_json::to_string(&proof).unwrap();
        let duplicated_buckets = vec![bucket.clone(), bucket.clone()];

        let opened = open_private_hnsw_oram_verified_path_batch(
            &keys,
            bucket_base_context(),
            config,
            42,
            &root_hash,
            1,
            &proof_json,
            &duplicated_buckets,
        )
        .unwrap();
        assert_eq!(opened, vec![plaintext_bucket.clone(), plaintext_bucket]);

        let mut future_epoch_bucket = bucket.clone();
        future_epoch_bucket.index_epoch = 43;
        assert_eq!(
            open_private_hnsw_oram_verified_path_batch(
                &keys,
                bucket_base_context(),
                config,
                42,
                &root_hash,
                1,
                &proof_json,
                &[future_epoch_bucket],
            ),
            Err(PrivateHnswClientError::InvalidMerkleProof)
        );

        let mut mismatched_duplicate = bucket.clone();
        let mismatched_ciphertext = b"different ciphertext";
        mismatched_duplicate.ciphertext = BASE64URL_NOPAD.encode(mismatched_ciphertext);
        mismatched_duplicate.ciphertext_sha256 = base64url_sha256(mismatched_ciphertext);
        assert_eq!(
            open_private_hnsw_oram_verified_path_batch(
                &keys,
                bucket_base_context(),
                config,
                42,
                &root_hash,
                1,
                &proof_json,
                &[bucket, mismatched_duplicate],
            ),
            Err(PrivateHnswClientError::InvalidMerkleProof)
        );

        let mut conflicting_leaf = proof.leaves[0].clone();
        conflicting_leaf.leaf_hash = commitment(9);
        let conflicting_proof = PrivateHnswOramMerkleProof {
            leaves: vec![proof.leaves[0].clone(), conflicting_leaf],
            ..proof
        };
        let conflicting_proof_json = serde_json::to_string(&conflicting_proof).unwrap();
        assert_eq!(
            open_private_hnsw_oram_verified_path_batch(
                &keys,
                bucket_base_context(),
                config,
                42,
                &root_hash,
                1,
                &conflicting_proof_json,
                &duplicated_buckets,
            ),
            Err(PrivateHnswClientError::InvalidMerkleProof)
        );
    }

    #[test]
    fn commit_plan_updates_merkle_root_and_signature_refs() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9, 10);

        let plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        assert_eq!(plan.old_epoch, 42);
        assert_eq!(plan.new_epoch, 43);
        assert_eq!(plan.old_root_hash, old_root);
        assert_ne!(plan.new_root_hash, plan.old_root_hash);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);
        assert_eq!(
            plan.updated_buckets,
            vec![PrivateHnswClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }]
        );
        assert_eq!(
            plan.signature_bucket_refs(),
            vec![PrivateHnswOramCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.as_str(),
            }]
        );
    }

    #[test]
    fn commit_plan_for_manifest_rejects_bucket_commitment_context_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.oram.path_batch_size = 2;
        manifest.fixed_budget.paths_per_round = 2;
        manifest.bucket_count = leaf_commitments.len() as u64;
        manifest.logical_node_count = 2;
        manifest.dummy_node_count = 0;
        manifest.root_hash = old_root.clone();
        let updated_bucket = fixture_context_commit_bucket(2, 43, 9, &manifest);

        let plan = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();
        assert_eq!(plan.old_epoch, manifest.index_epoch);
        assert_eq!(plan.old_root_hash, old_root);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);

        let mut wrong_commitment = updated_bucket.clone();
        wrong_commitment.bucket_commitment = commitment(99);
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateHnswClientError::InvalidBucketCommitment)
        );

        let mut wrong_provider = manifest.clone();
        wrong_provider.provider = "vector/wrong-hnsw-oram@v1".to_string();
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &wrong_provider,
                43,
                &leaf_commitments,
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest"
            ))
        );

        let mut short_ciphertext = updated_bucket.clone();
        let short_raw = [BUCKET_AEAD_VERSION, 1, 2, 3];
        short_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&short_raw);
        short_ciphertext.ciphertext_sha256 = base64url_sha256(&short_raw);
        short_ciphertext.bucket_commitment = private_hnsw_bucket_commitment(
            bucket_base_context()
                .for_bucket(short_ciphertext.bucket_id, short_ciphertext.index_epoch),
            &short_ciphertext.ciphertext_sha256,
        )
        .unwrap();
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&short_ciphertext),
            ),
            Err(PrivateHnswClientError::BucketCiphertextSizeMismatch {
                bucket_id: short_ciphertext.bucket_id,
                expected_bytes: private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
                actual_bytes: short_raw.len(),
            })
        );

        let mut long_ciphertext = updated_bucket.clone();
        let expected_bytes = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let long_raw = vec![BUCKET_AEAD_VERSION; expected_bytes + 1];
        long_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&long_raw);
        long_ciphertext.ciphertext_sha256 = base64url_sha256(&long_raw);
        long_ciphertext.bucket_commitment = private_hnsw_bucket_commitment(
            bucket_base_context()
                .for_bucket(long_ciphertext.bucket_id, long_ciphertext.index_epoch),
            &long_ciphertext.ciphertext_sha256,
        )
        .unwrap();
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&long_ciphertext),
            ),
            Err(PrivateHnswClientError::BucketCiphertextSizeMismatch {
                bucket_id: long_ciphertext.bucket_id,
                expected_bytes,
                actual_bytes: expected_bytes + 1,
            })
        );

        let wrong_bucket_count = PrivateHnswOramManifest {
            bucket_count: 2,
            ..manifest
        };
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &wrong_bucket_count,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest"
            ))
        );
    }

    #[test]
    fn commit_plan_for_manifest_context_allows_live_epoch_after_commit() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.oram.path_batch_size = 2;
        manifest.fixed_budget.paths_per_round = 2;
        manifest.bucket_count = leaf_commitments.len() as u64;
        manifest.logical_node_count = 2;
        manifest.dummy_node_count = 0;
        manifest.root_hash = old_root;

        let first_bucket = fixture_context_commit_bucket(2, 43, 9, &manifest);
        let first_plan = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&first_bucket),
        )
        .unwrap();

        let second_bucket = fixture_context_commit_bucket(1, 44, 10, &manifest);
        // The signed manifest still pins the pre-commit root, so planning against it fails on
        // the root even with the correct next epoch.
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &manifest,
                43,
                &first_plan.leaf_commitments,
                std::slice::from_ref(&second_bucket),
            ),
            Err(PrivateHnswClientError::MerkleRootMismatch)
        );

        let second_plan = plan_private_hnsw_oram_commit_for_manifest_context(
            &manifest,
            first_plan.new_epoch,
            44,
            &first_plan.new_root_hash,
            &first_plan.leaf_commitments,
            std::slice::from_ref(&second_bucket),
        )
        .unwrap();
        assert_eq!(second_plan.old_epoch, first_plan.new_epoch);
        assert_eq!(second_plan.old_root_hash, first_plan.new_root_hash);
        assert_eq!(
            second_plan.leaf_commitments[1],
            second_bucket.bucket_commitment
        );

        let mut wrong_commitment = second_bucket;
        wrong_commitment.bucket_commitment = commitment(99);
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest_context(
                &manifest,
                first_plan.new_epoch,
                44,
                &first_plan.new_root_hash,
                &first_plan.leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateHnswClientError::InvalidBucketCommitment)
        );
    }

    #[test]
    fn commit_plan_matches_core_private_hnsw_oram_planner() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.oram.path_batch_size = 2;
        manifest.fixed_budget.paths_per_round = 2;
        manifest.bucket_count = leaf_commitments.len() as u64;
        manifest.logical_node_count = 2;
        manifest.dummy_node_count = 0;
        manifest.root_hash = old_root;
        let updated_bucket = fixture_context_commit_bucket(2, 43, 9, &manifest);

        let client_plan = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();
        let core_plan = crate::private_hnsw_oram::plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        assert_eq!(client_plan.old_epoch, core_plan.old_epoch);
        assert_eq!(client_plan.new_epoch, core_plan.new_epoch);
        assert_eq!(client_plan.old_root_hash, core_plan.old_root_hash);
        assert_eq!(client_plan.new_root_hash, core_plan.new_root_hash);
        assert_eq!(client_plan.leaf_commitments, core_plan.leaf_commitments);
        assert_eq!(
            client_plan
                .signature_bucket_refs()
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket.ciphertext_sha256.to_string()))
                .collect::<Vec<_>>(),
            core_plan
                .signature_bucket_refs()
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket.ciphertext_sha256.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn commit_plan_for_manifest_rejects_oversized_fixed_writeback() {
        let leaf_commitments = (0..7).map(commitment).collect::<Vec<_>>();
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut manifest = PrivateHnswOramManifest {
            root_hash: old_root,
            bucket_count: leaf_commitments.len() as u64,
            ..fixture_manifest()
        };
        manifest.oram.bucket_size = 2;
        manifest.oram.block_size_bytes = 16384;
        manifest.oram.tree_height = 2;
        manifest.oram.path_batch_size = 1;
        manifest.fixed_budget.paths_per_round = 1;
        manifest.logical_node_count = 4;
        manifest.dummy_node_count = 0;
        let fixed_writeback_budget =
            private_hnsw_oram_fixed_writeback_bucket_budget(&manifest.oram).unwrap();
        assert_eq!(fixed_writeback_budget, 3);
        assert_eq!(
            private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, 1).unwrap(),
            3
        );
        assert_eq!(
            private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, 2).unwrap(),
            6
        );
        assert_eq!(
            private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, 9).unwrap(),
            7
        );

        let updated_buckets = (0..=fixed_writeback_budget)
            .map(|bucket_id| {
                fixture_context_commit_bucket(bucket_id as u64, 43, bucket_id as u8, &manifest)
            })
            .collect::<Vec<_>>();
        assert!(updated_buckets.len() <= leaf_commitments.len());

        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths(
                &manifest,
                manifest.index_epoch,
                43,
                &manifest.root_hash,
                &leaf_commitments,
                &updated_buckets,
                1,
            ),
            Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "updated_buckets",
            ))
        );

        let plan = plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths(
            &manifest,
            manifest.index_epoch,
            43,
            &manifest.root_hash,
            &leaf_commitments,
            &updated_buckets[..fixed_writeback_budget],
            1,
        )
        .unwrap();
        assert_eq!(plan.updated_buckets.len(), fixed_writeback_budget);

        // A whole fixed-budget search (upper + base steps, here 3 paths) fits the default budget.
        let whole_search = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            &updated_buckets,
        )
        .unwrap();
        assert_eq!(whole_search.updated_buckets.len(), updated_buckets.len());
    }

    #[test]
    fn commit_plan_can_be_signed_and_verified_by_server_validator() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswOramCommitSignatureInput, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_commit_signature,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9, 10);
        let plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        let context = PrivateHnswCommitSignatureContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            signing_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let signature = sign_private_hnsw_oram_commit(&key_pair, context, &plan).unwrap();
        for malformed_context in [
            PrivateHnswCommitSignatureContext {
                collection_id: "collection\nuuid",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "text/vector",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "client.state",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "client.state.snapshot",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "clientStateCiphertexts.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "encrypted.client.state",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "encrypted.client.state.snapshot",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "encrypted_client_state_ciphertexts.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "stateCiphertexts.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "payload_fetch_token",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "payloadFetchTokens",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "payload.fetch.token",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "positionMapSnapshots.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "oram_position_map_backups.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "tokenMapBackups.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "token.map.backup",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "token.map.backups",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "tokenPositionMapSnapshots.json",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "token.position.map.backup",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "token.position.map.backups",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "stash_snapshots.json",
                ..context
            },
        ] {
            let field = if malformed_context.collection_id.contains('\n') {
                "collection_id"
            } else {
                "vector_name"
            };
            assert_eq!(
                sign_private_hnsw_oram_commit(&key_pair, malformed_context, &plan),
                Err(PrivateHnswClientError::InvalidCommitSignatureContext(field))
            );
        }
        for malformed_context in [
            PrivateHnswCommitSignatureContext {
                key_id: "tenant-a/vector\nprivate-rk",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                rk_id: "tenant-a/vector\nprivate-rk",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                signing_key_id: "tenant-a/private\nhnsw-signing-v1",
                ..context
            },
        ] {
            let field = if malformed_context.key_id.contains('\n') {
                "key_id"
            } else if malformed_context.rk_id.contains('\n') {
                "rk_id"
            } else {
                "signing_key_id"
            };
            assert_eq!(
                sign_private_hnsw_oram_commit(&key_pair, malformed_context, &plan),
                Err(PrivateHnswClientError::InvalidCommitSignatureContext(field))
            );
        }

        let bucket_refs = plan.signature_bucket_refs();
        validate_private_hnsw_oram_commit_signature(
            PrivateHnswOramCommitSignatureInput {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                old_epoch: plan.old_epoch,
                new_epoch: plan.new_epoch,
                old_root_hash: &plan.old_root_hash,
                new_root_hash: &plan.new_root_hash,
                updated_buckets: &bucket_refs,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: "tenant-a/private-hnsw-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();

        let mut empty_plan = plan.clone();
        empty_plan.updated_buckets.clear();
        assert_eq!(
            sign_private_hnsw_oram_commit(&key_pair, context, &empty_plan),
            Err(PrivateHnswClientError::EmptyCommit)
        );

        let mut malformed_root_plan = plan.clone();
        malformed_root_plan.old_root_hash = "AAAA".to_string();
        assert_eq!(
            sign_private_hnsw_oram_commit(&key_pair, context, &malformed_root_plan),
            Err(PrivateHnswClientError::InvalidMerkleRoot)
        );

        let mut malformed_hash_plan = plan.clone();
        malformed_hash_plan.updated_buckets[0].ciphertext_sha256 = "AAAA".to_string();
        assert_eq!(
            sign_private_hnsw_oram_commit(&key_pair, context, &malformed_hash_plan),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );

        let mut duplicate_bucket_plan = plan.clone();
        duplicate_bucket_plan
            .updated_buckets
            .push(duplicate_bucket_plan.updated_buckets[0].clone());
        assert_eq!(
            sign_private_hnsw_oram_commit(&key_pair, context, &duplicate_bucket_plan),
            Err(PrivateHnswClientError::DuplicateUpdatedBucket { bucket_id: 2 })
        );
    }

    #[test]
    fn read_paths_signature_signer_rejects_malformed_request_shape() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswOramReadPathsSignatureInput, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_read_paths_signature,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let context = PrivateHnswCommitSignatureContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            signing_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let root_hash = commitment(42);
        let paths = vec![BASE64URL_NOPAD.encode(&0u64.to_be_bytes())];
        let signature =
            sign_private_hnsw_oram_read_paths(&key_pair, context, 42, &root_hash, &paths, 1, true)
                .unwrap();
        let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
        validate_private_hnsw_oram_read_paths_signature(
            PrivateHnswOramReadPathsSignatureInput {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                index_epoch: 42,
                root_hash: &root_hash,
                paths: &path_refs,
                requested_paths: 1,
                dummy_paths_included: true,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: "tenant-a/private-hnsw-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();
        for malformed_context in [
            PrivateHnswCommitSignatureContext {
                collection_id: "collection\nuuid",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "text/vector",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                vector_name: "client.state",
                ..context
            },
        ] {
            let field = if malformed_context.collection_id.contains('\n') {
                "collection_id"
            } else {
                "vector_name"
            };
            assert_eq!(
                sign_private_hnsw_oram_read_paths(
                    &key_pair,
                    malformed_context,
                    42,
                    &root_hash,
                    &paths,
                    1,
                    true,
                ),
                Err(PrivateHnswClientError::InvalidCommitSignatureContext(field))
            );
        }
        for malformed_context in [
            PrivateHnswCommitSignatureContext {
                key_id: "tenant-a/vector\nprivate-rk",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                rk_id: "tenant-a/vector\nprivate-rk",
                ..context
            },
            PrivateHnswCommitSignatureContext {
                signing_key_id: "tenant-a/private\nhnsw-signing-v1",
                ..context
            },
        ] {
            let field = if malformed_context.key_id.contains('\n') {
                "key_id"
            } else if malformed_context.rk_id.contains('\n') {
                "rk_id"
            } else {
                "signing_key_id"
            };
            assert_eq!(
                sign_private_hnsw_oram_read_paths(
                    &key_pair,
                    malformed_context,
                    42,
                    &root_hash,
                    &paths,
                    1,
                    true,
                ),
                Err(PrivateHnswClientError::InvalidCommitSignatureContext(field))
            );
        }

        let duplicate_paths = vec![paths[0].clone(), paths[0].clone()];
        assert_eq!(
            sign_private_hnsw_oram_read_paths(
                &key_pair,
                context,
                42,
                &root_hash,
                &duplicate_paths,
                2,
                true,
            ),
            Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "paths"
            ))
        );
        assert_eq!(
            sign_private_hnsw_oram_read_paths(&key_pair, context, 42, &root_hash, &paths, 2, true,),
            Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "requested_paths"
            ))
        );
        assert_eq!(
            sign_private_hnsw_oram_read_paths(&key_pair, context, 42, &root_hash, &paths, 1, false,),
            Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "dummy_paths_included"
            ))
        );
        assert_eq!(
            sign_private_hnsw_oram_read_paths(&key_pair, context, 42, "AAAA", &paths, 1, true),
            Err(PrivateHnswClientError::InvalidMerkleRoot)
        );

        let malformed_length_paths = vec!["AAAA".to_string()];
        assert_eq!(
            sign_private_hnsw_oram_read_paths(
                &key_pair,
                context,
                42,
                &root_hash,
                &malformed_length_paths,
                1,
                true,
            ),
            Err(PrivateHnswClientError::InvalidLeafLabelLength)
        );

        let malformed_encoding_paths = vec!["!!!!!!!!!!!".to_string()];
        assert_eq!(
            sign_private_hnsw_oram_read_paths(
                &key_pair,
                context,
                42,
                &root_hash,
                &malformed_encoding_paths,
                1,
                true,
            ),
            Err(PrivateHnswClientError::InvalidLeafLabelEncoding)
        );
    }

    #[test]
    fn read_paths_manifest_signer_enforces_fixed_batch_context() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswOramReadPathsSignatureInput, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_read_paths_signature,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let mut manifest = fixture_manifest();
        manifest.oram.path_batch_size = 2;
        manifest.fixed_budget.paths_per_round = 2;
        let paths = vec![
            encode_private_hnsw_oram_leaf_label(0, manifest.oram.tree_height).unwrap(),
            encode_private_hnsw_oram_leaf_label(1, manifest.oram.tree_height).unwrap(),
        ];

        let signature =
            sign_private_hnsw_oram_read_paths_for_manifest(&key_pair, &manifest, &paths).unwrap();
        let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
        validate_private_hnsw_oram_read_paths_signature(
            PrivateHnswOramReadPathsSignatureInput {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                index_epoch: manifest.index_epoch,
                root_hash: &manifest.root_hash,
                paths: &path_refs,
                requested_paths: manifest.oram.path_batch_size,
                dummy_paths_included: true,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: &manifest.owner_signing_key_id,
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();

        assert_eq!(signature.key_id, manifest.owner_signing_key_id);
        let live_root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let live_signature = sign_private_hnsw_oram_read_paths_for_manifest_context(
            &key_pair,
            &manifest,
            manifest.index_epoch + 1,
            &live_root_hash,
            &paths,
        )
        .unwrap();
        validate_private_hnsw_oram_read_paths_signature(
            PrivateHnswOramReadPathsSignatureInput {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                index_epoch: manifest.index_epoch + 1,
                root_hash: &live_root_hash,
                paths: &path_refs,
                requested_paths: manifest.oram.path_batch_size,
                dummy_paths_included: true,
                signature_alg: &live_signature.alg,
                signature_key_id: &live_signature.key_id,
            },
            &live_signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: &manifest.owner_signing_key_id,
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();
        assert_eq!(
            sign_private_hnsw_oram_read_paths_for_manifest(&key_pair, &manifest, &paths[..1]),
            Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "requested_paths",
            ))
        );
        assert_eq!(
            sign_private_hnsw_oram_read_paths_for_manifest(
                &key_pair,
                &manifest,
                &[paths[0].clone(), paths[0].clone()],
            ),
            Err(PrivateHnswClientError::InvalidCommitSignatureContext(
                "paths",
            ))
        );

        let mut out_of_range_paths = paths.clone();
        out_of_range_paths[1] =
            BASE64URL_NOPAD.encode(&(1u64 << manifest.oram.tree_height).to_be_bytes());
        assert_eq!(
            sign_private_hnsw_oram_read_paths_for_manifest(
                &key_pair,
                &manifest,
                &out_of_range_paths,
            ),
            Err(PrivateHnswClientError::LeafOutOfRange)
        );
    }

    #[test]
    fn manifest_can_be_signed_and_verified_by_server_validator() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswManifestValidationContext, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_manifest,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let manifest = fixture_manifest();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest).unwrap();

        let epoch = validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                expected_collection_id: "collection-uuid-1",
                expected_vector_name: "text",
                expected_key_id: "tenant-a/vector-private-rk",
                expected_rk_id: "tenant-a/vector-private-rk",
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 1536,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap();

        assert_eq!(signature.alg, "ed25519");
        assert_eq!(signature.key_id, manifest.owner_signing_key_id);
        assert_eq!(epoch.epoch, manifest.index_epoch);
        assert_eq!(epoch.root_hash, [42; 32]);

        let mut malformed = manifest;
        malformed.root_hash = "AAAA".to_string();
        assert_eq!(
            sign_private_hnsw_oram_manifest(&key_pair, &malformed),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest"
            ))
        );
    }

    #[test]
    fn manifest_refresh_for_commit_advances_epoch_root_and_resigns() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswManifestValidationContext, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_manifest,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let manifest = fixture_manifest();
        let plan = PrivateHnswClientCommitPlan {
            old_epoch: manifest.index_epoch,
            new_epoch: manifest.index_epoch + 1,
            old_root_hash: manifest.root_hash.clone(),
            new_root_hash: commitment(43),
            leaf_commitments: vec![commitment(1), commitment(2)],
            updated_buckets: vec![PrivateHnswClientCommitBucketRef {
                bucket_id: 1,
                ciphertext_sha256: commitment(9),
            }],
        };

        let refreshed = refresh_private_hnsw_oram_manifest_for_commit(&manifest, &plan).unwrap();
        assert_eq!(refreshed.index_epoch, plan.new_epoch);
        assert_eq!(refreshed.root_hash, plan.new_root_hash);
        assert_eq!(refreshed.collection_id, manifest.collection_id);
        assert_eq!(refreshed.vector_name, manifest.vector_name);
        assert_eq!(refreshed.bucket_count, manifest.bucket_count);
        assert_eq!(refreshed.fixed_budget, manifest.fixed_budget);

        let (signed_manifest, signature) =
            sign_private_hnsw_oram_manifest_refresh(&key_pair, &manifest, &plan).unwrap();
        assert_eq!(signed_manifest, refreshed);
        assert_eq!(signature.key_id, signed_manifest.owner_signing_key_id);

        let epoch = validate_private_hnsw_oram_manifest(
            &signed_manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                expected_collection_id: "collection-uuid-1",
                expected_vector_name: "text",
                expected_key_id: "tenant-a/vector-private-rk",
                expected_rk_id: "tenant-a/vector-private-rk",
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 1536,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap();
        assert_eq!(epoch.epoch, 43);
        assert_eq!(epoch.root_hash, [43; 32]);

        let mut wrong_provider = manifest.clone();
        wrong_provider.provider = "vector/wrong-hnsw-oram@v1".to_string();
        assert_eq!(
            refresh_private_hnsw_oram_manifest_for_commit(&wrong_provider, &plan),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest"
            ))
        );

        let mut stale_plan = plan.clone();
        stale_plan.old_root_hash = commitment(99);
        assert_eq!(
            refresh_private_hnsw_oram_manifest_for_commit(&manifest, &stale_plan),
            Err(PrivateHnswClientError::ManifestCommitMismatch)
        );
    }

    #[test]
    fn commit_plan_rejects_stale_duplicate_out_of_range_and_root_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9, 10);

        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &commitment(99),
                &leaf_commitments,
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateHnswClientError::MerkleRootMismatch)
        );

        let stale_bucket = fixture_commit_bucket(2, 42, 9, 10);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&stale_bucket),
            ),
            Err(PrivateHnswClientError::StaleBucketEpoch {
                bucket_id: 2,
                expected_epoch: 43,
                actual_epoch: 42,
            })
        );

        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                &[updated_bucket.clone(), updated_bucket.clone()],
            ),
            Err(PrivateHnswClientError::DuplicateUpdatedBucket { bucket_id: 2 })
        );

        let out_of_range = fixture_commit_bucket(4, 43, 9, 10);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&out_of_range),
            ),
            Err(PrivateHnswClientError::BucketOutOfRange {
                bucket_id: 4,
                bucket_count: 4,
            })
        );

        let mut hash_mismatch = updated_bucket.clone();
        hash_mismatch.ciphertext_sha256 = commitment(8);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&hash_mismatch),
            ),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );
    }

    #[test]
    fn merkle_proof_verifier_accepts_server_path_batch_proof_json() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let parent_01 = private_hnsw_oram_merkle_parent_hash(
            &decode_bucket_commitment(&leaf_commitments[0]).unwrap(),
            &decode_bucket_commitment(&leaf_commitments[1]).unwrap(),
        );
        let bucket = fixture_commit_bucket(2, 42, 3, 10);
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 4,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 2,
                leaf_hash: leaf_commitments[2].clone(),
                siblings: vec![
                    proof_sibling(0, PrivateHnswMerkleSiblingPosition::Right, commitment(4)),
                    proof_sibling(
                        1,
                        PrivateHnswMerkleSiblingPosition::Left,
                        BASE64URL_NOPAD.encode(&parent_01),
                    ),
                ],
            }],
        };
        let proof_json = serde_json::to_string(&proof).unwrap();

        let empty_proof = PrivateHnswOramMerkleProof {
            leaves: Vec::new(),
            ..proof.clone()
        };
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(&empty_proof, 42, &root, 4, &[]),
            Err(PrivateHnswClientError::InvalidMerkleProof)
        );

        verify_private_hnsw_oram_merkle_proof_json(
            &proof_json,
            42,
            &root,
            4,
            std::slice::from_ref(&bucket),
        )
        .unwrap();
        verify_private_hnsw_oram_merkle_proof(&proof, 42, &root, 4, std::slice::from_ref(&bucket))
            .unwrap();

        let mut hash_mismatch_bucket = bucket.clone();
        hash_mismatch_bucket.ciphertext_sha256 = commitment(8);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(
                &proof,
                42,
                &root,
                4,
                std::slice::from_ref(&hash_mismatch_bucket),
            ),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );

        let duplicate_proof = PrivateHnswOramMerkleProof {
            leaves: vec![proof.leaves[0].clone(), proof.leaves[0].clone()],
            ..proof.clone()
        };
        verify_private_hnsw_oram_merkle_proof(
            &duplicate_proof,
            42,
            &root,
            4,
            &[bucket.clone(), bucket.clone()],
        )
        .unwrap();
        verify_private_hnsw_oram_merkle_proof_json(
            &serde_json::to_string(&duplicate_proof).unwrap(),
            42,
            &root,
            4,
            &[bucket.clone(), bucket.clone()],
        )
        .unwrap();

        let mut conflicting_duplicate_bucket = bucket.clone();
        let conflicting_raw = b"conflicting duplicate HNSW bucket";
        conflicting_duplicate_bucket.ciphertext = BASE64URL_NOPAD.encode(conflicting_raw);
        conflicting_duplicate_bucket.ciphertext_sha256 = base64url_sha256(conflicting_raw);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(
                &duplicate_proof,
                42,
                &root,
                4,
                &[bucket.clone(), conflicting_duplicate_bucket],
            ),
            Err(PrivateHnswClientError::InvalidMerkleProof)
        );

        let mut conflicting_duplicate_proof = duplicate_proof;
        conflicting_duplicate_proof.leaves[1].leaf_hash = commitment(9);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(
                &conflicting_duplicate_proof,
                42,
                &root,
                4,
                &[bucket.clone(), bucket],
            ),
            Err(PrivateHnswClientError::InvalidMerkleProof)
        );

        let oversized_proof_json = " ".repeat(PRIVATE_HNSW_MERKLE_PROOF_JSON_MAX_BYTES + 1);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof_json(&oversized_proof_json, 42, &root, 4, &[]),
            Err(PrivateHnswClientError::InvalidMerkleProofJson)
        );
    }

    #[test]
    fn merkle_proof_verifier_rejects_tampered_leaf_and_sibling() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let parent_01 = private_hnsw_oram_merkle_parent_hash(
            &decode_bucket_commitment(&leaf_commitments[0]).unwrap(),
            &decode_bucket_commitment(&leaf_commitments[1]).unwrap(),
        );
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 4,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 2,
                leaf_hash: leaf_commitments[2].clone(),
                siblings: vec![
                    proof_sibling(0, PrivateHnswMerkleSiblingPosition::Right, commitment(4)),
                    proof_sibling(
                        1,
                        PrivateHnswMerkleSiblingPosition::Left,
                        BASE64URL_NOPAD.encode(&parent_01),
                    ),
                ],
            }],
        };

        let wrong_bucket = fixture_commit_bucket(2, 42, 9, 10);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(
                &proof,
                42,
                &root,
                4,
                std::slice::from_ref(&wrong_bucket),
            ),
            Err(PrivateHnswClientError::MerkleProofMismatch)
        );

        let mut tampered = proof;
        tampered.leaves[0].siblings[0].hash = commitment(9);
        let bucket = fixture_commit_bucket(2, 42, 3, 10);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(&tampered, 42, &root, 4, &[bucket]),
            Err(PrivateHnswClientError::MerkleProofMismatch)
        );
    }

    #[test]
    fn plaintext_oram_bulk_build_places_blocks_on_paths_and_searches() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let mut near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        near.payload_fetch_token = Some([55; 32]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let build = build_private_hnsw_oram_plaintext_index_from_blocks(
            config,
            &[entry.clone(), near.clone(), far.clone()],
            &[0, 1, 2],
        )
        .unwrap();

        assert_eq!(build.entry_node_id, entry.node_id);
        assert_eq!(build.logical_node_count, 3);
        assert_eq!(
            build.dummy_node_count,
            private_hnsw_oram_bucket_count(config.tree_height).unwrap() * config.bucket_size as u64
                - 3
        );
        assert_eq!(build.state.position(&near.node_id), Some(1));

        let full = build.dummy_node_count;
        let mut reserved = build.clone();
        reserve_private_hnsw_oram_physical_slots(&mut reserved, 2).unwrap();
        assert_eq!(reserved.dummy_node_count, full - 2);
        assert!(reserve_private_hnsw_oram_physical_slots(&mut reserved.clone(), 0).is_err());
        assert!(reserve_private_hnsw_oram_physical_slots(&mut reserved.clone(), full - 1).is_err());

        let store = RefCell::new(
            build
                .buckets
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket))
                .collect::<BTreeMap<_, _>>(),
        );
        let mut state = build.state;
        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.hits[0].payload_fetch_token, Some([55; 32]));
        validate_private_hnsw_search_result_privacy(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
        )
        .unwrap();
    }

    #[test]
    fn private_result_search_privacy_requires_payload_fetch_tokens() {
        let result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [2; 32],
                payload_fetch_token: None,
                distance: 0.0,
            }],
            accessed_leaf_labels: vec![],
            completed_steps: 1,
        };

        validate_private_hnsw_search_result_privacy(ResultPrivacyMode::IdsVisible, &result)
            .unwrap();
        assert_eq!(
            validate_private_hnsw_search_result_privacy(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &result,
            ),
            Err(PrivateHnswClientError::MissingPayloadFetchToken)
        );
    }

    #[test]
    fn strict_search_result_requires_fixed_budget_exhaustion() {
        let params = PrivateHnswSearchParams {
            entry_node_id: [9; 32],
            k: 1,
            ef: 1,
            fixed_steps: 3,
            distance: DistanceKind::Euclid,
            padding_node_id: Some([10; 32]),
        };
        let short_result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [2; 32],
                payload_fetch_token: Some([3; 32]),
                distance: 0.0,
            }],
            accessed_leaf_labels: vec!["AAAAAAAAAAA".to_string()],
            completed_steps: 1,
        };

        assert_eq!(
            validate_private_hnsw_search_fixed_budget(&params, &short_result),
            Err(PrivateHnswClientError::FixedBudgetNotExhausted {
                completed_steps: 1,
                fixed_steps: 3,
            })
        );
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &params,
                &short_result,
            ),
            Err(PrivateHnswClientError::FixedBudgetNotExhausted {
                completed_steps: 1,
                fixed_steps: 3,
            })
        );
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::IdsVisible,
                &params,
                &short_result,
            ),
            Err(PrivateHnswClientError::FixedBudgetNotExhausted {
                completed_steps: 1,
                fixed_steps: 3,
            })
        );

        let padded_result = PrivateHnswSearchResult {
            accessed_leaf_labels: vec![
                "AAAAAAAAAAA".to_string(),
                "AAAAAAAAAAE".to_string(),
                "AAAAAAAAAAI".to_string(),
            ],
            completed_steps: 3,
            ..short_result
        };

        validate_private_hnsw_search_fixed_budget(&params, &padded_result).unwrap();
        validate_private_hnsw_strict_search_result(
            ResultPrivacyMode::IdsVisible,
            &params,
            &padded_result,
        )
        .unwrap();
        validate_private_hnsw_strict_search_result(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &params,
            &padded_result,
        )
        .unwrap();

        let malformed_label_result = PrivateHnswSearchResult {
            accessed_leaf_labels: vec![
                "AAAAAAAAAAA".to_string(),
                "not-base64!".to_string(),
                "AAAAAAAAAAI".to_string(),
            ],
            completed_steps: 3,
            ..padded_result.clone()
        };
        assert_eq!(
            validate_private_hnsw_search_fixed_budget(&params, &malformed_label_result),
            Err(PrivateHnswClientError::InvalidLeafLabelEncoding)
        );
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::IdsVisible,
                &params,
                &malformed_label_result,
            ),
            Err(PrivateHnswClientError::InvalidLeafLabelEncoding)
        );

        let non_finite_result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [2; 32],
                payload_fetch_token: Some([3; 32]),
                distance: f32::NAN,
            }],
            ..padded_result.clone()
        };
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::IdsVisible,
                &params,
                &non_finite_result,
            ),
            Err(PrivateHnswClientError::NonFiniteDistance)
        );

        let duplicate_node_result = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([3; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [4; 32],
                    payload_fetch_token: Some([5; 32]),
                    distance: 1.0,
                },
            ],
            ..padded_result.clone()
        };
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::IdsVisible,
                &params,
                &duplicate_node_result,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("search_hits"))
        );

        let duplicate_point_result = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([3; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [4; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([5; 32]),
                    distance: 1.0,
                },
            ],
            ..padded_result.clone()
        };
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::IdsVisible,
                &params,
                &duplicate_point_result,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("search_hits"))
        );

        let zero_step_params = PrivateHnswSearchParams {
            fixed_steps: 0,
            ..params
        };
        assert_eq!(
            validate_private_hnsw_search_fixed_budget(&zero_step_params, &padded_result),
            Err(PrivateHnswClientError::InvalidSearchConfig("fixed_steps"))
        );
        assert_eq!(
            validate_private_hnsw_strict_search_result(
                ResultPrivacyMode::IdsVisible,
                &zero_step_params,
                &padded_result,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("fixed_steps"))
        );
    }

    #[test]
    fn search_access_metrics_requires_matching_path_count_for_budget_exhaustion() {
        let params = PrivateHnswSearchParams {
            entry_node_id: [9; 32],
            k: 1,
            ef: 1,
            fixed_steps: 3,
            distance: DistanceKind::Euclid,
            padding_node_id: Some([10; 32]),
        };
        let inconsistent_result = PrivateHnswSearchResult {
            hits: Vec::new(),
            accessed_leaf_labels: vec!["AAAAAAAAAAA".to_string()],
            completed_steps: 3,
        };

        assert_eq!(
            inconsistent_result.access_metrics(&params),
            PrivateHnswSearchAccessMetrics {
                path_accesses: 1,
                unique_leaf_labels: 1,
                fixed_steps: 3,
                exhausted_fixed_budget: false,
            }
        );

        let malformed_label_result = PrivateHnswSearchResult {
            hits: Vec::new(),
            accessed_leaf_labels: vec![
                "AAAAAAAAAAA".to_string(),
                "not-base64!".to_string(),
                "AAAAAAAAAAI".to_string(),
            ],
            completed_steps: 3,
        };
        assert_eq!(
            malformed_label_result.access_metrics(&params),
            PrivateHnswSearchAccessMetrics {
                path_accesses: 3,
                unique_leaf_labels: 3,
                fixed_steps: 3,
                exhausted_fixed_budget: false,
            }
        );

        let zero_step_params = PrivateHnswSearchParams {
            fixed_steps: 0,
            ..params
        };
        let empty_result = PrivateHnswSearchResult {
            hits: Vec::new(),
            accessed_leaf_labels: Vec::new(),
            completed_steps: 0,
        };
        assert_eq!(
            empty_result.access_metrics(&zero_step_params),
            PrivateHnswSearchAccessMetrics {
                path_accesses: 0,
                unique_leaf_labels: 0,
                fixed_steps: 0,
                exhausted_fixed_budget: false,
            }
        );
    }

    #[test]
    fn private_result_fetch_plan_pads_hit_tokens_to_fixed_result_k() {
        let empty_result = PrivateHnswSearchResult {
            hits: vec![],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        let empty_plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &empty_result,
            3,
            &[[97; 32], [98; 32], [99; 32]],
        )
        .unwrap()
        .unwrap();
        assert_eq!(empty_plan.real_result_count, 0);
        assert_eq!(empty_plan.fixed_result_k, 3);
        assert_eq!(
            empty_plan.payload_fetch_tokens,
            vec![[97; 32], [98; 32], [99; 32]]
        );

        let result = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [3; 32],
                    point_token: [4; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 1.0,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };

        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::IdsVisible,
                &result,
                4,
                &[],
            )
            .unwrap(),
            None
        );

        let plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
            4,
            &[[99; 32], [100; 32]],
        )
        .unwrap()
        .unwrap();

        assert_eq!(plan.real_result_count, 2);
        assert_eq!(plan.fixed_result_k, 4);
        assert_eq!(
            plan.payload_fetch_tokens,
            vec![[11; 32], [12; 32], [99; 32], [100; 32]]
        );
    }

    #[test]
    fn private_result_fetch_plan_feeds_ordered_result_oram_read_plan_and_finalizer() {
        let result = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [21; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.25,
                },
                PrivateHnswSearchHit {
                    node_id: [2; 32],
                    point_token: [22; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 0.5,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        let fetch_plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
            4,
            &[[99; 32], [100; 32]],
        )
        .unwrap()
        .unwrap();
        let token_positions = [
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [11; 32],
                leaf: 2,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [12; 32],
                leaf: 2,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [99; 32],
                leaf: 1,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [100; 32],
                leaf: 3,
            },
        ];
        let ordered = plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(
            &result_oram_fetch_manifest(),
            &fetch_plan.payload_fetch_tokens,
            &token_positions,
            || Ok(0),
        )
        .unwrap();

        assert_ne!(
            ordered.payload_fetch_tokens,
            fetch_plan.payload_fetch_tokens
        );
        assert_eq!(ordered.read_plan.token_count, fetch_plan.fixed_result_k);
        assert_eq!(ordered.read_plan.path_batch_size, 2);
        assert_eq!(ordered.read_plan.batches.len(), 2);
        let token_leaves = token_positions
            .iter()
            .map(|position| (position.payload_fetch_token, position.leaf))
            .collect::<BTreeMap<_, _>>();
        for token_batch in ordered
            .payload_fetch_tokens
            .chunks(ordered.read_plan.path_batch_size)
        {
            let batch_leaves = token_batch
                .iter()
                .map(|token| token_leaves[token])
                .collect::<BTreeSet<_>>();
            assert_eq!(batch_leaves.len(), token_batch.len());
        }
        for batch in &ordered.read_plan.batches {
            assert_eq!(batch.token_count, 2);
            assert_eq!(batch.bucket_ids.len(), 6);
        }

        let token_fetch = PrivateResultOramTokenFetchResult {
            accesses: ordered
                .payload_fetch_tokens
                .iter()
                .map(|token| match token[0] {
                    11 => result_token_access(*token, [21; 32], vec![1, 2, 3]),
                    12 => result_token_access(*token, [22; 32], vec![4, 5, 6]),
                    99 => result_token_access(*token, [199; 32], vec![9]),
                    100 => result_token_access(*token, [200; 32], vec![10]),
                    _ => unreachable!("unexpected fixture token"),
                })
                .collect(),
            updated_buckets: Vec::new(),
        };
        let payloads =
            finalize_private_hnsw_private_result_fetch(&result, &fetch_plan, &token_fetch).unwrap();

        assert_eq!(payloads.real_result_count, 2);
        assert_eq!(payloads.fixed_result_k, 4);
        assert_eq!(payloads.fetched_token_count, 4);
        assert_eq!(payloads.results.len(), 2);
        assert_eq!(payloads.results[0].payload_fetch_token, [11; 32]);
        assert_eq!(payloads.results[0].payload, vec![1, 2, 3]);
        assert_eq!(payloads.results[1].payload_fetch_token, [12; 32]);
        assert_eq!(payloads.results[1].payload, vec![4, 5, 6]);
    }

    #[test]
    fn private_result_fetch_plan_rejects_missing_oversized_or_duplicate_token_batch() {
        let missing_token = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [2; 32],
                payload_fetch_token: None,
                distance: 0.0,
            }],
            accessed_leaf_labels: vec![],
            completed_steps: 1,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &missing_token,
                1,
                &[],
            ),
            Err(PrivateHnswClientError::MissingPayloadFetchToken)
        );

        let one_hit = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [2; 32],
                payload_fetch_token: Some([11; 32]),
                distance: 0.0,
            }],
            accessed_leaf_labels: vec![],
            completed_steps: 1,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &one_hit,
                0,
                &[],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "fixed_result_k"
            ))
        );
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &one_hit,
                3,
                &[[99; 32]],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "dummy_payload_fetch_tokens"
            ))
        );
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &one_hit,
                3,
                &[[99; 32], [99; 32]],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &one_hit,
                1,
                &[[99; 32], [99; 32]],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &one_hit,
                1,
                &[[11; 32], [99; 32]],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );

        let duplicate_real_tokens = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [3; 32],
                    point_token: [4; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 1.0,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &duplicate_real_tokens,
                2,
                &[],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );

        let duplicate_node_hits = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [4; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 1.0,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &duplicate_node_hits,
                2,
                &[],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("search_hits"))
        );

        let duplicate_point_hits = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [3; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 1.0,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &duplicate_point_hits,
                2,
                &[],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig("search_hits"))
        );

        let too_many_hits = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [2; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.0,
                },
                PrivateHnswSearchHit {
                    node_id: [3; 32],
                    point_token: [4; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 1.0,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &too_many_hits,
                1,
                &[],
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "fixed_result_k"
            ))
        );

        let non_finite_result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [2; 32],
                payload_fetch_token: Some([11; 32]),
                distance: f32::NAN,
            }],
            accessed_leaf_labels: vec![],
            completed_steps: 1,
        };
        assert_eq!(
            plan_private_hnsw_private_result_fetch_tokens(
                ResultPrivacyMode::PrivatePayloadOramRequired,
                &non_finite_result,
                1,
                &[],
            ),
            Err(PrivateHnswClientError::NonFiniteDistance)
        );
    }

    #[test]
    fn private_result_fetch_finalizer_maps_real_payloads_and_ignores_dummies() {
        let result = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [21; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.25,
                },
                PrivateHnswSearchHit {
                    node_id: [2; 32],
                    point_token: [22; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 0.5,
                },
            ],
            accessed_leaf_labels: vec![],
            completed_steps: 2,
        };
        let plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
            4,
            &[[99; 32], [100; 32]],
        )
        .unwrap()
        .unwrap();
        let token_fetch = PrivateResultOramTokenFetchResult {
            accesses: vec![
                result_token_access([11; 32], [21; 32], vec![1, 2, 3]),
                result_token_access([12; 32], [22; 32], vec![4, 5, 6]),
                result_token_access([99; 32], [199; 32], vec![9]),
                result_token_access([100; 32], [200; 32], vec![10]),
            ],
            updated_buckets: Vec::new(),
        };

        let payloads =
            finalize_private_hnsw_private_result_fetch(&result, &plan, &token_fetch).unwrap();
        assert_eq!(payloads.real_result_count, 2);
        assert_eq!(payloads.fixed_result_k, 4);
        assert_eq!(payloads.fetched_token_count, 4);
        assert_eq!(payloads.results.len(), 2);
        assert_eq!(payloads.results[0].node_id, [1; 32]);
        assert_eq!(payloads.results[0].point_token, [21; 32]);
        assert_eq!(payloads.results[0].payload_fetch_token, [11; 32]);
        assert_eq!(payloads.results[0].distance, 0.25);
        assert_eq!(payloads.results[0].payload, vec![1, 2, 3]);
        assert_eq!(payloads.results[1].node_id, [2; 32]);
        assert_eq!(payloads.results[1].payload, vec![4, 5, 6]);

        let shuffled_token_fetch = PrivateResultOramTokenFetchResult {
            accesses: vec![
                result_token_access([99; 32], [199; 32], vec![9]),
                result_token_access([12; 32], [22; 32], vec![4, 5, 6]),
                result_token_access([100; 32], [200; 32], vec![10]),
                result_token_access([11; 32], [21; 32], vec![1, 2, 3]),
            ],
            updated_buckets: Vec::new(),
        };
        let shuffled_payloads =
            finalize_private_hnsw_private_result_fetch(&result, &plan, &shuffled_token_fetch)
                .unwrap();
        assert_eq!(shuffled_payloads.results.len(), 2);
        assert_eq!(shuffled_payloads.results[0].payload_fetch_token, [11; 32]);
        assert_eq!(shuffled_payloads.results[0].payload, vec![1, 2, 3]);
        assert_eq!(shuffled_payloads.results[1].payload_fetch_token, [12; 32]);
        assert_eq!(shuffled_payloads.results[1].payload, vec![4, 5, 6]);
    }

    #[test]
    fn private_result_fetch_debug_redacts_tokens_and_payload_bytes() {
        let payload = vec![101, 102, 103];
        let result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [41; 32],
                point_token: [42; 32],
                payload_fetch_token: Some([43; 32]),
                distance: 0.25,
            }],
            accessed_leaf_labels: vec![],
            completed_steps: 1,
        };
        let plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
            1,
            &[],
        )
        .unwrap()
        .unwrap();
        let token_fetch = PrivateResultOramTokenFetchResult {
            accesses: vec![result_token_access([43; 32], [42; 32], payload.clone())],
            updated_buckets: Vec::new(),
        };
        let payloads =
            finalize_private_hnsw_private_result_fetch(&result, &plan, &token_fetch).unwrap();

        let debug_values = [
            format!("{:?}", result.hits[0]),
            format!("{result:?}"),
            format!("{plan:?}"),
            format!("{:?}", token_fetch.accesses[0]),
            format!("{token_fetch:?}"),
            format!("{:?}", payloads.results[0]),
            format!("{payloads:?}"),
        ];
        let secret_values = [
            BASE64URL_NOPAD.encode(&[41; 32]),
            BASE64URL_NOPAD.encode(&[42; 32]),
            BASE64URL_NOPAD.encode(&[43; 32]),
            format!("{:?}", [41u8; 32]),
            format!("{:?}", [42u8; 32]),
            format!("{:?}", [43u8; 32]),
            format!("{payload:?}"),
        ];

        for debug in debug_values {
            for secret in &secret_values {
                assert!(!debug.contains(secret), "{debug}");
            }
        }
    }

    #[test]
    fn private_result_fetch_finalizer_rejects_mismatched_or_deleted_payloads() {
        let result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [21; 32],
                payload_fetch_token: Some([11; 32]),
                distance: 0.25,
            }],
            accessed_leaf_labels: vec![],
            completed_steps: 1,
        };
        let plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
            1,
            &[],
        )
        .unwrap()
        .unwrap();

        let wrong_point_token = PrivateResultOramTokenFetchResult {
            accesses: vec![result_token_access([11; 32], [99; 32], vec![1])],
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(&result, &plan, &wrong_point_token),
            Err(PrivateHnswClientError::InvalidSearchConfig("point_token"))
        );

        let mut deleted_access = result_token_access([11; 32], [21; 32], vec![1]);
        deleted_access.block.deleted = true;
        let deleted_payload = PrivateResultOramTokenFetchResult {
            accesses: vec![deleted_access],
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(&result, &plan, &deleted_payload),
            Err(PrivateHnswClientError::InvalidSearchConfig("payload_block"))
        );

        let wrong_token = PrivateResultOramTokenFetchResult {
            accesses: vec![result_token_access([12; 32], [21; 32], vec![1])],
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(&result, &plan, &wrong_token),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );

        let padded_plan = plan_private_hnsw_private_result_fetch_tokens(
            ResultPrivacyMode::PrivatePayloadOramRequired,
            &result,
            2,
            &[[99; 32]],
        )
        .unwrap()
        .unwrap();
        let wrong_dummy_token = PrivateResultOramTokenFetchResult {
            accesses: vec![
                result_token_access([11; 32], [21; 32], vec![1]),
                result_token_access([100; 32], [199; 32], vec![2]),
            ],
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(&result, &padded_plan, &wrong_dummy_token),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );

        let non_finite_result = PrivateHnswSearchResult {
            hits: vec![PrivateHnswSearchHit {
                node_id: [1; 32],
                point_token: [21; 32],
                payload_fetch_token: Some([11; 32]),
                distance: f32::INFINITY,
            }],
            ..result.clone()
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(
                &non_finite_result,
                &plan,
                &PrivateResultOramTokenFetchResult {
                    accesses: vec![result_token_access([11; 32], [21; 32], vec![1])],
                    updated_buckets: Vec::new(),
                },
            ),
            Err(PrivateHnswClientError::NonFiniteDistance)
        );

        let mut wrong_real_result_count = plan.clone();
        wrong_real_result_count.real_result_count = 0;
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(
                &result,
                &wrong_real_result_count,
                &wrong_point_token,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "result_fetch_plan"
            ))
        );

        let empty_result = PrivateHnswSearchResult {
            hits: Vec::new(),
            accessed_leaf_labels: Vec::new(),
            completed_steps: 1,
        };
        let zero_budget_plan = PrivateHnswPrivateResultFetchPlan {
            payload_fetch_tokens: Vec::new(),
            real_result_count: 0,
            fixed_result_k: 0,
        };
        let empty_token_fetch = PrivateResultOramTokenFetchResult {
            accesses: Vec::new(),
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(
                &empty_result,
                &zero_budget_plan,
                &empty_token_fetch,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "result_fetch_plan"
            ))
        );

        let oversized_real_result = PrivateHnswSearchResult {
            hits: vec![
                PrivateHnswSearchHit {
                    node_id: [1; 32],
                    point_token: [21; 32],
                    payload_fetch_token: Some([11; 32]),
                    distance: 0.25,
                },
                PrivateHnswSearchHit {
                    node_id: [2; 32],
                    point_token: [22; 32],
                    payload_fetch_token: Some([12; 32]),
                    distance: 0.5,
                },
            ],
            accessed_leaf_labels: Vec::new(),
            completed_steps: 1,
        };
        let undersized_fetch_plan = PrivateHnswPrivateResultFetchPlan {
            payload_fetch_tokens: vec![[11; 32]],
            real_result_count: 2,
            fixed_result_k: 1,
        };
        let undersized_token_fetch = PrivateResultOramTokenFetchResult {
            accesses: vec![result_token_access([11; 32], [21; 32], vec![1])],
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(
                &oversized_real_result,
                &undersized_fetch_plan,
                &undersized_token_fetch,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "result_fetch_plan"
            ))
        );

        let mut duplicate_fetch_plan = plan.clone();
        duplicate_fetch_plan.fixed_result_k = 2;
        duplicate_fetch_plan.payload_fetch_tokens = vec![[11; 32], [11; 32]];
        let duplicate_token_fetch = PrivateResultOramTokenFetchResult {
            accesses: vec![
                result_token_access([11; 32], [21; 32], vec![1]),
                result_token_access([11; 32], [21; 32], vec![2]),
            ],
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            finalize_private_hnsw_private_result_fetch(
                &result,
                &duplicate_fetch_plan,
                &duplicate_token_fetch,
            ),
            Err(PrivateHnswClientError::InvalidSearchConfig(
                "payload_fetch_tokens"
            ))
        );
    }

    #[test]
    fn plaintext_index_build_rejects_duplicate_result_tokens() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let first = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let second = node_block_with_vector(2, &[2.0, 0.0], vec![]);

        let mut duplicate_point = second.clone();
        duplicate_point.point_token = first.point_token;
        assert_eq!(
            build_private_hnsw_oram_plaintext_index_from_blocks(
                config,
                &[first.clone(), duplicate_point],
                &[0, 1],
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig("point_token"))
        );

        let mut first_payload = first.clone();
        first_payload.payload_fetch_token = Some([77; 32]);
        let mut duplicate_payload = second;
        duplicate_payload.payload_fetch_token = Some([77; 32]);
        assert_eq!(
            build_private_hnsw_oram_plaintext_index_from_blocks(
                config,
                &[first_payload, duplicate_payload],
                &[0, 1],
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig(
                "payload_fetch_token"
            ))
        );
    }

    #[test]
    fn plaintext_search_uses_cached_upper_layer_node_with_padded_oram_access() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let mut entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32]]);
        entry.level_mask = 0b11;
        entry.neighbor_levels = vec![1];
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let padding = node_block_with_vector(3, &[99.0, 0.0], vec![]);
        let build = build_private_hnsw_oram_plaintext_index_from_blocks(
            config,
            &[entry.clone(), near.clone(), padding.clone()],
            &[0, 1, 2],
        )
        .unwrap();

        let mut cache = PrivateHnswClientNodeCache::new();
        assert_eq!(cache.extend_upper_layers_from_plaintext_build(&build, 1), 1);
        assert!(cache.contains(&entry.node_id));
        assert!(!cache.contains(&near.node_id));
        assert!(private_hnsw_node_reaches_level(&entry, 1));
        assert!(!private_hnsw_node_reaches_level(&near, 1));

        let store = RefCell::new(
            build
                .buckets
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket))
                .collect::<BTreeMap<_, _>>(),
        );
        let mut state = build.state;
        let read_leaves = RefCell::new(Vec::new());
        let mut remaps = [3, 3].into_iter();
        let params = PrivateHnswSearchParams {
            entry_node_id: entry.node_id,
            k: 1,
            ef: 2,
            fixed_steps: 2,
            distance: DistanceKind::Euclid,
            padding_node_id: Some(padding.node_id),
        };
        let result = search_private_hnsw_oram_plaintext_with_cache(
            &mut state,
            config,
            &[1.0, 0.0],
            params,
            &cache,
            |leaf| {
                read_leaves.borrow_mut().push(leaf);
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.completed_steps, 2);
        assert_eq!(*read_leaves.borrow(), vec![2, 1]);
        assert_eq!(
            result.access_metrics(&params),
            PrivateHnswSearchAccessMetrics {
                path_accesses: 2,
                unique_leaf_labels: 2,
                fixed_steps: 2,
                exhausted_fixed_budget: true,
            }
        );
        assert_eq!(
            result.accessed_leaf_labels,
            vec![
                encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap(),
            ]
        );
    }

    #[test]
    fn neighbor_clustered_leaf_plan_follows_graph_order() {
        let config = PrivateHnswOramClientConfig {
            tree_height: 3,
            ..oram_config()
        };
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![[3; 32]]);
        let leaves = plan_private_hnsw_oram_neighbor_clustered_leaves_for_benchmarks(
            config,
            &[far.clone(), entry.clone(), near.clone()],
            entry.node_id,
        )
        .unwrap();

        assert_eq!(leaves, vec![2, 0, 1]);
        assert_eq!(
            plan_private_hnsw_oram_neighbor_clustered_leaves_for_benchmarks(
                config,
                &[],
                entry.node_id
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig("blocks"))
        );
        assert_eq!(
            plan_private_hnsw_oram_neighbor_clustered_leaves_for_benchmarks(
                config,
                std::slice::from_ref(&entry),
                [9; 32],
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig("entry_node_id"))
        );
        assert_eq!(
            plan_private_hnsw_oram_neighbor_clustered_leaves_for_benchmarks(
                config,
                &[entry.clone(), entry],
                [1; 32],
            ),
            Err(PrivateHnswClientError::DuplicateBlock)
        );
    }

    #[test]
    fn neighbor_clustered_leaf_plan_deduplicates_cycles_and_appends_disconnected_tail() {
        let config = PrivateHnswOramClientConfig {
            tree_height: 3,
            ..oram_config()
        };
        let clustered_tail = node_block_with_vector(4, &[4.0, 0.0], vec![[2; 32]]);
        let disconnected = node_block_with_vector(5, &[5.0, 0.0], vec![]);
        let second_neighbor = node_block_with_vector(3, &[3.0, 0.0], vec![[4; 32]]);
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![[2; 32], [2; 32], [3; 32]]);
        let first_neighbor = node_block_with_vector(2, &[2.0, 0.0], vec![[1; 32], [4; 32]]);

        let leaves = plan_private_hnsw_oram_neighbor_clustered_leaves_for_benchmarks(
            config,
            &[
                clustered_tail,
                disconnected,
                second_neighbor,
                entry.clone(),
                first_neighbor,
            ],
            entry.node_id,
        )
        .unwrap();

        assert_eq!(leaves, vec![3, 4, 2, 0, 1]);
    }

    #[test]
    fn f32_reference_bulk_build_constructs_searchable_neighbor_graph() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry_id = [1; 32];
        let near_id = [2; 32];
        let far_id = [3; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: entry_id,
                point_token: [11; 32],
                vector: vec![10.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: near_id,
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: far_id,
                point_token: [33; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ];
        let build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            2,
            &points,
            &[0, 1, 2],
        )
        .unwrap();

        let store = RefCell::new(
            build
                .buckets
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket))
                .collect::<BTreeMap<_, _>>(),
        );
        let mut state = build.state;
        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near_id);
        assert_eq!(result.hits[0].point_token, [22; 32]);
    }

    #[test]
    fn layered_f32_bulk_build_constructs_level_masks_and_neighbor_levels() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            fixed_neighbor_slots: 6,
            ..oram_config()
        };
        let entry_id = [1; 32];
        let upper_id = [2; 32];
        let middle_id = [3; 32];
        let base_id = [4; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: entry_id,
                point_token: [11; 32],
                vector: vec![0.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: upper_id,
                point_token: [22; 32],
                vector: vec![8.0, 8.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: middle_id,
                point_token: [33; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: base_id,
                point_token: [44; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
        ];

        let build = build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            1,
            &points,
            &[2, 2, 1, 0],
            &[0, 1, 2, 3],
        )
        .unwrap();
        let blocks = build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .map(|block| (block.node_id, block.clone()))
            .collect::<BTreeMap<_, _>>();
        let entry = blocks.get(&entry_id).unwrap();
        assert_eq!(entry.level_mask, 0b111);
        assert_eq!(entry.neighbor_levels, vec![2, 1, 0]);
        assert_eq!(entry.neighbors[0], upper_id);
        assert_eq!(entry.neighbors[1], middle_id);
        assert!(entry.neighbors[2] == middle_id || entry.neighbors[2] == base_id);

        let base = blocks.get(&base_id).unwrap();
        assert_eq!(base.level_mask, 1);
        assert!(base.neighbor_levels.iter().all(|level| *level == 0));
    }

    #[test]
    fn layered_f32_bulk_build_handles_max_u64_level_mask_without_overflow() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            fixed_neighbor_slots: 1,
            ..oram_config()
        };
        let point = PrivateHnswBuildPoint {
            node_id: [1; 32],
            point_token: [2; 32],
            vector: vec![0.0, 1.0],
            payload_fetch_token: None,
        };

        let build = build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
            config,
            DistanceKind::Euclid,
            0,
            0,
            std::slice::from_ref(&point),
            &[63],
            &[0],
        )
        .unwrap();
        let block = build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .find(|block| block.node_id == point.node_id)
            .unwrap();
        assert_eq!(block.level_mask, u64::MAX);
        assert!(private_hnsw_node_reaches_level(block, 63));
        assert!(!private_hnsw_node_reaches_level(block, 64));

        assert_eq!(
            build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
                config,
                DistanceKind::Euclid,
                0,
                0,
                &[point],
                &[64],
                &[0],
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig("levels"))
        );
    }

    #[test]
    fn layer_neighbor_selection_rejects_malformed_shape_without_panic() {
        let point = PrivateHnswBuildPoint {
            node_id: [1; 32],
            point_token: [2; 32],
            vector: vec![0.0, 1.0],
            payload_fetch_token: None,
        };

        assert_eq!(
            select_private_hnsw_layer_neighbors(&[], &[], 0, 0, DistanceKind::Euclid, 1),
            Err(PrivateHnswClientError::InvalidBuildConfig("points"))
        );
        assert_eq!(
            select_private_hnsw_layer_neighbors(
                std::slice::from_ref(&point),
                &[0],
                1,
                0,
                DistanceKind::Euclid,
                1,
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig("points"))
        );
        assert_eq!(
            select_private_hnsw_layer_neighbors(
                std::slice::from_ref(&point),
                &[],
                0,
                0,
                DistanceKind::Euclid,
                1,
            ),
            Err(PrivateHnswClientError::InvalidBuildConfig("levels"))
        );
    }

    #[test]
    fn layered_f32_bulk_build_prunes_redundant_neighbors_with_hnsw_heuristic() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            fixed_neighbor_slots: 4,
            ..oram_config()
        };
        let entry_id = [1; 32];
        let near_id = [2; 32];
        let redundant_id = [3; 32];
        let diverse_id = [4; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: entry_id,
                point_token: [11; 32],
                vector: vec![0.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: near_id,
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: redundant_id,
                point_token: [33; 32],
                vector: vec![2.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: diverse_id,
                point_token: [44; 32],
                vector: vec![0.0, 2.0],
                payload_fetch_token: None,
            },
        ];

        let build = build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
            config,
            DistanceKind::Euclid,
            2,
            0,
            &points,
            &[0, 0, 0, 0],
            &[0, 1, 2, 3],
        )
        .unwrap();
        let blocks = build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .map(|block| (block.node_id, block.clone()))
            .collect::<BTreeMap<_, _>>();
        let entry = blocks.get(&entry_id).unwrap();
        assert_eq!(entry.neighbors, vec![near_id, diverse_id]);
        assert!(!entry.neighbors.contains(&redundant_id));
    }

    #[test]
    fn deterministic_level_assignment_drives_auto_layered_builder() {
        assert_eq!(private_hnsw_level_from_node_id([1; 32], 6).unwrap(), 0);
        assert_eq!(private_hnsw_level_from_node_id([255; 32], 6).unwrap(), 3);
        assert_eq!(private_hnsw_level_from_node_id([0; 32], 3).unwrap(), 3);
        assert_eq!(
            private_hnsw_level_from_node_id([0; 32], 64).unwrap_err(),
            PrivateHnswClientError::InvalidBuildConfig("max_level"),
        );

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            fixed_neighbor_slots: 6,
            ..oram_config()
        };
        let low_id = [1; 32];
        let high_id = [255; 32];
        let capped_id = [0; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: low_id,
                point_token: [11; 32],
                vector: vec![0.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: high_id,
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: capped_id,
                point_token: [33; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ];

        let build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            1,
            3,
            &points,
            &[0, 1, 2],
        )
        .unwrap();
        let blocks = build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .map(|block| (block.node_id, block.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(blocks.get(&low_id).unwrap().level_mask, 0b1);
        assert_eq!(blocks.get(&high_id).unwrap().level_mask, 0b1111);
        assert_eq!(blocks.get(&capped_id).unwrap().level_mask, 0b1111);
    }

    #[test]
    fn encrypted_index_build_seals_buckets_and_root_for_upload() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry_id = [1; 32];
        let near_id = [2; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: entry_id,
                point_token: [11; 32],
                vector: vec![10.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: near_id,
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            &points,
            &[0, 1],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            base_context,
            42,
            &plaintext_build,
            config,
        )
        .unwrap();

        assert_eq!(encrypted_build.index_epoch, 42);
        assert_eq!(encrypted_build.entry_node_id, entry_id);
        assert_eq!(encrypted_build.logical_node_count, 2);
        assert_eq!(
            encrypted_build.bucket_count,
            private_hnsw_oram_bucket_count(config.tree_height).unwrap()
        );
        assert!(
            encrypted_build
                .buckets
                .iter()
                .all(|bucket| bucket.index_epoch == 42)
        );
        assert_eq!(
            encrypted_build.root_hash,
            private_hnsw_oram_merkle_root_for_commitments(
                &encrypted_build
                    .buckets
                    .iter()
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .collect::<Vec<_>>()
            )
            .unwrap()
        );

        let commitments = encrypted_build
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let encrypted_store = RefCell::new(
            encrypted_build
                .buckets
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket))
                .collect::<BTreeMap<_, _>>(),
        );
        let writebacks = RefCell::new(Vec::new());
        let mut state = plaintext_build.state;
        let mut remaps = [2, 2].into_iter();
        let result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &encrypted_build.root_hash,
            encrypted_build.bucket_count,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry_id,
                k: 1,
                ef: 2,
                fixed_steps: 2,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proof = proof_for_bucket_ids(
                    &bucket_ids,
                    42,
                    encrypted_build.root_hash.clone(),
                    &commitments,
                );
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: encrypted_build.root_hash.clone(),
                    bucket_count: encrypted_build.bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                writebacks.borrow_mut().extend_from_slice(writeback_buckets);
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near_id);
        assert!(
            writebacks
                .borrow()
                .iter()
                .all(|bucket| bucket.index_epoch == 43)
        );
    }

    #[test]
    fn encrypted_index_build_produces_manifest_ready_for_signing() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            FixedBudgetParams, OramKind, OramParams, PrivateHnswManifestValidationContext,
            PrivateHnswParams, PrivateHnswSignatureVerification, ResultPrivacyMode,
            validate_private_hnsw_oram_manifest,
        };

        let keys = test_keys();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![10.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [2; 32],
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            &points,
            &[0, 1],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            bucket_base_context(),
            42,
            &plaintext_build,
            config,
        )
        .unwrap();

        let build_context = PrivateHnswManifestBuildContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Euclid,
            hnsw: PrivateHnswParams {
                m: 1,
                ef_construction: 2,
                max_layers: 1,
                fixed_neighbor_slots: config.fixed_neighbor_slots as u32,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: config.bucket_size as u32,
                block_size_bytes: config.block_size_bytes as u32,
                tree_height: config.tree_height,
                path_batch_size: 2,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 2,
                paths_per_round: 2,
                fixed_result_k: 1,
            },
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1",
            created_at_unix: 1_770_000_000,
        };
        let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
            build_context.clone(),
            &encrypted_build,
        )
        .unwrap();
        for malformed_context in [
            PrivateHnswManifestBuildContext {
                collection_id: "collection\nuuid",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "text/vector",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "client.state",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "client.state.snapshot",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "clientStateCiphertexts.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "encrypted.client.state",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "encrypted.client.state.snapshot",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "encrypted_client_state_ciphertexts.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "stateCiphertexts.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "payload_fetch_token",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "payloadFetchTokens",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "payload.fetch.token",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "positionMapSnapshots.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "oram_position_map_backups.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "tokenMapBackups.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "token.map.backup",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "token.map.backups",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "tokenPositionMapSnapshots.json",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "token.position.map.backup",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "token.position.map.backups",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                vector_name: "stash_snapshots.json",
                ..build_context.clone()
            },
        ] {
            let field = if malformed_context.collection_id.contains('\n') {
                "collection_id"
            } else {
                "vector_name"
            };
            assert_eq!(
                build_private_hnsw_oram_manifest_from_encrypted_index(
                    malformed_context,
                    &encrypted_build
                ),
                Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                    field
                ))
            );
        }
        for malformed_context in [
            PrivateHnswManifestBuildContext {
                key_id: "tenant-a/vector\nprivate-rk",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                rk_id: "tenant-a/vector\nprivate-rk",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                owner_signing_key_id: "tenant-a/private\nhnsw-signing-v1",
                ..build_context
            },
        ] {
            let field = if malformed_context.key_id.contains('\n') {
                "key_id"
            } else if malformed_context.rk_id.contains('\n') {
                "rk_id"
            } else {
                "owner_signing_key_id"
            };
            assert_eq!(
                build_private_hnsw_oram_manifest_from_encrypted_index(
                    malformed_context,
                    &encrypted_build
                ),
                Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                    field
                ))
            );
        }

        assert_eq!(manifest.root_hash, encrypted_build.root_hash);
        assert_eq!(manifest.bucket_count, encrypted_build.bucket_count);
        assert_eq!(manifest.logical_node_count, 2);
        assert_eq!(manifest.dummy_node_count, encrypted_build.dummy_node_count);

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest).unwrap();
        let epoch = validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                expected_collection_id: "collection-uuid-1",
                expected_vector_name: "text",
                expected_key_id: "tenant-a/vector-private-rk",
                expected_rk_id: "tenant-a/vector-private-rk",
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Euclid,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap();

        assert_eq!(epoch.epoch, 42);
        assert_eq!(
            epoch.root_hash,
            decode_merkle_root(&encrypted_build.root_hash).unwrap()
        );
    }

    #[test]
    fn upload_bundle_packages_signed_manifest_and_buckets() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            FixedBudgetParams, OramKind, OramParams, PrivateHnswManifestValidationContext,
            PrivateHnswParams, PrivateHnswSignatureVerification, ResultPrivacyMode,
            validate_private_hnsw_oram_manifest,
        };

        let keys = test_keys();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![10.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [2; 32],
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            &points,
            &[0, 1],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            bucket_base_context(),
            42,
            &plaintext_build,
            config,
        )
        .unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let build_context = PrivateHnswManifestBuildContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Euclid,
            hnsw: PrivateHnswParams {
                m: 1,
                ef_construction: 2,
                max_layers: 1,
                fixed_neighbor_slots: config.fixed_neighbor_slots as u32,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: config.bucket_size as u32,
                block_size_bytes: config.block_size_bytes as u32,
                tree_height: config.tree_height,
                path_batch_size: 2,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 2,
                paths_per_round: 2,
                fixed_result_k: 1,
            },
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1",
            created_at_unix: 1_770_000_000,
        };

        let bundle = package_private_hnsw_oram_upload_bundle(
            &key_pair,
            build_context.clone(),
            &encrypted_build,
        )
        .unwrap();

        assert_eq!(bundle.index_epoch(), 42);
        assert_eq!(bundle.root_hash(), encrypted_build.root_hash.as_str());
        assert_eq!(bundle.bucket_count(), encrypted_build.bucket_count);
        assert_eq!(bundle.buckets, encrypted_build.buckets);
        assert_eq!(
            private_hnsw_oram_merkle_root_for_commitments(&bundle.bucket_commitments()).unwrap(),
            encrypted_build.root_hash
        );
        let ordered_commitments = bundle.validate_initial_upload_contract().unwrap();
        assert_eq!(ordered_commitments, bundle.bucket_commitments());

        let encoded = serde_json::to_string(&bundle).unwrap();
        let decoded: PrivateHnswOramUploadBundle = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&decoded).unwrap(),
            ordered_commitments
        );
        let core_decoded: crate::private_hnsw_oram::PrivateHnswOramUploadBundle =
            serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            crate::private_hnsw_oram::validate_private_hnsw_oram_upload_bundle(&core_decoded)
                .unwrap(),
            ordered_commitments
        );
        for malformed_context in [
            PrivateHnswManifestBuildContext {
                collection_id: "collection\nuuid",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                key_id: "tenant-a/vector\nprivate-rk",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                rk_id: "tenant-a/vector\nprivate-rk",
                ..build_context.clone()
            },
            PrivateHnswManifestBuildContext {
                owner_signing_key_id: "tenant-a/private\nhnsw-signing-v1",
                ..build_context
            },
        ] {
            let field = if malformed_context.collection_id.contains('\n') {
                "collection_id"
            } else if malformed_context.key_id.contains('\n') {
                "key_id"
            } else if malformed_context.rk_id.contains('\n') {
                "rk_id"
            } else {
                "owner_signing_key_id"
            };
            assert_eq!(
                package_private_hnsw_oram_upload_bundle(
                    &key_pair,
                    malformed_context,
                    &encrypted_build,
                ),
                Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                    field
                ))
            );
        }

        let mut malformed_signature = decoded.clone();
        malformed_signature.manifest_signature.alg = "ed25519-sentinel".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&malformed_signature),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest_signature"
            ))
        );

        let mut wrong_signature_key = decoded.clone();
        wrong_signature_key.manifest_signature.key_id =
            "tenant-a/private-hnsw-signing-v2".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_signature_key),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "owner_signing_key_id"
            ))
        );

        let validation_context = || PrivateHnswManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_vector_name: "text",
            expected_key_id: "tenant-a/vector-private-rk",
            expected_rk_id: "tenant-a/vector-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            expected_dim: 2,
            expected_distance: DistanceKind::Euclid,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: "tenant-a/private-hnsw-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
        };

        let epoch = validate_private_hnsw_oram_manifest(
            &decoded.manifest,
            Some(&decoded.manifest_signature),
            validation_context(),
        )
        .unwrap();

        assert_eq!(epoch.epoch, 42);
        assert_eq!(
            epoch.root_hash,
            decode_merkle_root(&encrypted_build.root_hash).unwrap()
        );

        assert_eq!(
            validate_private_hnsw_oram_upload_bundle_with_signature(&decoded, validation_context())
                .unwrap(),
            ordered_commitments
        );
        assert_eq!(
            crate::private_hnsw_oram::validate_private_hnsw_oram_upload_bundle_with_signature(
                &core_decoded,
                validation_context()
            )
            .unwrap(),
            ordered_commitments
        );
        assert_eq!(
            decoded
                .validate_initial_upload_contract_with_signature(validation_context())
                .unwrap(),
            ordered_commitments
        );

        let mut tampered_signature = decoded.clone();
        tampered_signature.manifest_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle_with_signature(
                &tampered_signature,
                validation_context()
            ),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest_signature"
            ))
        );

        let wrong_context = validate_private_hnsw_oram_upload_bundle_with_signature(
            &decoded,
            PrivateHnswManifestValidationContext {
                expected_collection_id: "collection-uuid-1",
                expected_vector_name: "text",
                expected_key_id: "tenant-a/vector-private-rk-v2",
                expected_rk_id: "tenant-a/vector-private-rk",
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Euclid,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap_err();
        assert_eq!(
            wrong_context,
            PrivateHnswClientError::InvalidManifestSignatureContext("manifest_signature")
        );

        // A bundle with fewer buckets than tree slots is refused on its count, before any
        // table is sized from the manifest, like the server-side validator.
        let mut incomplete = decoded.clone();
        incomplete.buckets.pop();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&incomplete),
            Err(PrivateHnswClientError::BucketCountMismatch)
        );

        let mut duplicate = decoded.clone();
        duplicate.buckets[1] = duplicate.buckets[0].clone();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&duplicate),
            Err(PrivateHnswClientError::DuplicateBucket { bucket_id: 0 })
        );

        let mut wrong_hash = decoded.clone();
        wrong_hash.buckets[0].ciphertext_sha256 = commitment(99);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_hash),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );

        let mut malformed_hash = decoded.clone();
        malformed_hash.buckets[0].ciphertext_sha256 = "AAAA".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&malformed_hash),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );

        let mut wrong_commitment = decoded.clone();
        wrong_commitment.buckets[0].bucket_commitment = commitment(99);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_commitment),
            Err(PrivateHnswClientError::InvalidBucketCommitment)
        );

        let mut malformed_commitment = decoded.clone();
        malformed_commitment.buckets[0].bucket_commitment = "AAAA".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&malformed_commitment),
            Err(PrivateHnswClientError::InvalidBucketCommitment)
        );

        let mut wrong_size = decoded.clone();
        let mut wrong_size_raw = BASE64URL_NOPAD
            .decode(wrong_size.buckets[0].ciphertext.as_bytes())
            .unwrap();
        let expected_bytes = wrong_size_raw.len();
        wrong_size_raw.pop();
        let wrong_size_hash = base64url_sha256(&wrong_size_raw);
        let wrong_size_context = PrivateHnswBucketAeadBaseContext {
            collection_id: &wrong_size.manifest.collection_id,
            vector_name: &wrong_size.manifest.vector_name,
            key_id: &wrong_size.manifest.key_id,
            rk_id: &wrong_size.manifest.rk_id,
            rk_epoch: wrong_size.manifest.rk_epoch,
        };
        let wrong_size_bucket = &mut wrong_size.buckets[0];
        wrong_size_bucket.ciphertext = BASE64URL_NOPAD.encode(&wrong_size_raw);
        wrong_size_bucket.ciphertext_sha256 = wrong_size_hash;
        wrong_size_bucket.bucket_commitment = private_hnsw_bucket_commitment(
            wrong_size_context
                .for_bucket(wrong_size_bucket.bucket_id, wrong_size_bucket.index_epoch),
            &wrong_size_bucket.ciphertext_sha256,
        )
        .unwrap();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_size),
            Err(PrivateHnswClientError::BucketCiphertextSizeMismatch {
                bucket_id: 0,
                expected_bytes,
                actual_bytes: expected_bytes - 1
            })
        );

        let mut malformed_ciphertext_len = decoded.clone();
        malformed_ciphertext_len.buckets[0].ciphertext = "A".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&malformed_ciphertext_len),
            Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding)
        );

        let mut oversized_ciphertext = decoded.clone();
        let oversized_raw = vec![0; expected_bytes + 1];
        oversized_ciphertext.buckets[0].ciphertext = BASE64URL_NOPAD.encode(&oversized_raw);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&oversized_ciphertext),
            Err(PrivateHnswClientError::BucketCiphertextSizeMismatch {
                bucket_id: 0,
                expected_bytes,
                actual_bytes: expected_bytes + 1
            })
        );

        let mut malformed_root = decoded.clone();
        malformed_root.manifest.root_hash = "AAAA".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&malformed_root),
            Err(PrivateHnswClientError::InvalidManifestSignatureContext(
                "manifest"
            ))
        );

        let mut wrong_root = decoded;
        wrong_root.manifest.root_hash = commitment(99);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_root),
            Err(PrivateHnswClientError::MerkleRootMismatch)
        );
    }

    #[test]
    fn client_state_snapshot_roundtrips_position_map_and_stash() {
        let config = oram_config();
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let stash = node_block_with_vector(2, &[2.0, 0.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (stash.node_id, 1)],
            config.tree_height,
        )
        .unwrap();
        state.stash.insert(stash.node_id, stash.clone());
        let debug = format!("{state:?}");
        assert!(!debug.contains("position_map_len: 2"), "{debug}");
        assert!(!debug.contains("stash_len: 1"), "{debug}");
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&entry.node_id)));
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&stash.node_id)));
        assert!(!debug.contains(&serde_json::to_string(&stash.vector).unwrap()));

        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.tree_height, config.tree_height);
        assert_eq!(snapshot.positions.len(), 2);
        assert_eq!(snapshot.stash, vec![stash.clone()]);
        let mut malformed_state = state.clone();
        malformed_state
            .stash
            .get_mut(&stash.node_id)
            .unwrap()
            .vector
            .push(1);
        assert_eq!(
            malformed_state.to_snapshot(config.tree_height),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
        let mut mismatched_stash_key_state = state.clone();
        mismatched_stash_key_state
            .stash
            .get_mut(&stash.node_id)
            .unwrap()
            .node_id = [99; 32];
        assert_eq!(
            mismatched_stash_key_state.to_snapshot(config.tree_height),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
        let mut duplicate_stash_point_state = state.clone();
        let mut duplicate_stash_point = node_block_with_vector(3, &[3.0, 0.0], vec![]);
        duplicate_stash_point.point_token = stash.point_token;
        duplicate_stash_point_state
            .position_map
            .insert(duplicate_stash_point.node_id, 2);
        duplicate_stash_point_state
            .stash
            .insert(duplicate_stash_point.node_id, duplicate_stash_point);
        assert_eq!(
            duplicate_stash_point_state.to_snapshot(config.tree_height),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
        let mut duplicate_stash_payload_state = state.clone();
        duplicate_stash_payload_state
            .stash
            .get_mut(&stash.node_id)
            .unwrap()
            .payload_fetch_token = Some([77; 32]);
        let mut duplicate_stash_payload = node_block_with_vector(4, &[4.0, 0.0], vec![]);
        duplicate_stash_payload.payload_fetch_token = Some([77; 32]);
        duplicate_stash_payload_state
            .position_map
            .insert(duplicate_stash_payload.node_id, 3);
        duplicate_stash_payload_state
            .stash
            .insert(duplicate_stash_payload.node_id, duplicate_stash_payload);
        assert_eq!(
            duplicate_stash_payload_state.to_snapshot(config.tree_height),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: PrivateHnswOramClientStateSnapshot = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&decoded).unwrap(),
            state
        );

        let mut bad_version = decoded.clone();
        bad_version.version = 2;
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&bad_version),
            Err(PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(2))
        );

        let mut bad_node_id = decoded.clone();
        bad_node_id.positions[0].node_id = "AAAA".to_string();
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&bad_node_id),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let mut bad_leaf_label = decoded.clone();
        bad_leaf_label.positions[0].leaf_label = "AAAA".to_string();
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&bad_leaf_label),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let mut duplicate_position = decoded.clone();
        duplicate_position
            .positions
            .push(duplicate_position.positions[0].clone());
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&duplicate_position),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let mut bad_stash_vector = decoded.clone();
        bad_stash_vector.stash[0].vector.push(1);
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&bad_stash_vector),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
        let mut bad_stash_level_mask = decoded.clone();
        bad_stash_level_mask.stash[0].level_mask = 0b101;
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&bad_stash_level_mask),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let mut bad_stash = decoded;
        bad_stash.stash[0].node_id = [9; 32];
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&bad_stash),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
        let mut duplicate_point_stash = snapshot.clone();
        let mut duplicate_point_block = node_block_with_vector(3, &[3.0, 0.0], vec![]);
        duplicate_point_block.point_token = duplicate_point_stash.stash[0].point_token;
        duplicate_point_stash
            .positions
            .push(PrivateHnswPositionMapSnapshotEntry {
                node_id: BASE64URL_NOPAD.encode(&duplicate_point_block.node_id),
                leaf_label: encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap(),
            });
        duplicate_point_stash.stash.push(duplicate_point_block);
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&duplicate_point_stash),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let mut duplicate_payload_stash = snapshot.clone();
        duplicate_payload_stash.stash[0].payload_fetch_token = Some([77; 32]);
        let mut duplicate_payload_block = node_block_with_vector(4, &[4.0, 0.0], vec![]);
        duplicate_payload_block.payload_fetch_token = Some([77; 32]);
        duplicate_payload_stash
            .positions
            .push(PrivateHnswPositionMapSnapshotEntry {
                node_id: BASE64URL_NOPAD.encode(&duplicate_payload_block.node_id),
                leaf_label: encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap(),
            });
        duplicate_payload_stash.stash.push(duplicate_payload_block);
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&duplicate_payload_stash),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let mut duplicate_stash = snapshot.clone();
        duplicate_stash.stash.push(stash);
        assert_eq!(
            PrivateHnswOramClientState::from_snapshot(&duplicate_stash),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
        assert_eq!(
            PrivateHnswOramClientState::with_position_map(
                [(entry.node_id, 0), (entry.node_id, 1)],
                config.tree_height,
            ),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );
    }

    #[test]
    fn client_state_snapshot_seal_open_binds_epoch_and_root_context() {
        let keys = test_keys();
        let config = oram_config();
        let state =
            PrivateHnswOramClientState::with_position_map([([1; 32], 0)], config.tree_height)
                .unwrap();
        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        let context = PrivateHnswClientStateAeadContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
        };

        let encrypted =
            seal_private_hnsw_oram_client_state_snapshot(&keys, context, &snapshot).unwrap();

        assert_eq!(encrypted.version, 1);
        assert_eq!(encrypted.index_epoch, 42);
        assert_eq!(encrypted.root_hash, context.root_hash);
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &encrypted).unwrap(),
            snapshot
        );

        let mut wrong_epoch = encrypted.clone();
        wrong_epoch.index_epoch = 43;
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &wrong_epoch),
            Err(PrivateHnswClientError::ClientStateOpenFailed)
        );

        let mut wrong_version = encrypted.clone();
        wrong_version.version = 2;
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &wrong_version),
            Err(PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(2))
        );

        let mut malformed_ciphertext = encrypted.clone();
        malformed_ciphertext.ciphertext = "client-state-ciphertext!sentinel".to_string();
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &malformed_ciphertext),
            Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding)
        );

        let mut short_ciphertext = encrypted.clone();
        short_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&[0, 1, 2, 3]);
        short_ciphertext.ciphertext_sha256 = base64url_sha256(&[0, 1, 2, 3]);
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &short_ciphertext),
            Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding)
        );

        let mut wrong_encoded_version = encrypted.clone();
        let mut wrong_version_raw = BASE64URL_NOPAD
            .decode(wrong_encoded_version.ciphertext.as_bytes())
            .unwrap();
        wrong_version_raw[0..2].copy_from_slice(&2u16.to_be_bytes());
        wrong_encoded_version.ciphertext = BASE64URL_NOPAD.encode(&wrong_version_raw);
        wrong_encoded_version.ciphertext_sha256 = base64url_sha256(&wrong_version_raw);
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &wrong_encoded_version),
            Err(PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(2))
        );

        let mut malformed_snapshot = snapshot.clone();
        malformed_snapshot.stash.push(node_block_with_id(9));
        assert_eq!(
            seal_private_hnsw_oram_client_state_snapshot(&keys, context, &malformed_snapshot),
            Err(PrivateHnswClientError::InvalidClientStateSnapshot)
        );

        let wrong_context = PrivateHnswClientStateAeadContext {
            root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            ..context
        };
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, wrong_context, &encrypted),
            Err(PrivateHnswClientError::ClientStateOpenFailed)
        );

        for wrong_context in [
            PrivateHnswClientStateAeadContext {
                collection_id: "collection-uuid-2",
                ..context
            },
            PrivateHnswClientStateAeadContext {
                vector_name: "body",
                ..context
            },
            PrivateHnswClientStateAeadContext {
                key_id: "tenant-a/vector-private-rk-v2",
                ..context
            },
            PrivateHnswClientStateAeadContext {
                rk_id: "tenant-a/vector-private-rk-v2",
                ..context
            },
            PrivateHnswClientStateAeadContext {
                rk_epoch: 8,
                ..context
            },
        ] {
            assert_eq!(
                open_private_hnsw_oram_client_state_snapshot(&keys, wrong_context, &encrypted),
                Err(PrivateHnswClientError::ClientStateOpenFailed)
            );
        }
        for (malformed_context, field) in [
            (
                PrivateHnswClientStateAeadContext {
                    collection_id: "collection\nuuid",
                    ..context
                },
                "collection_id",
            ),
            (
                PrivateHnswClientStateAeadContext {
                    vector_name: "text\nvector",
                    ..context
                },
                "vector_name",
            ),
            (
                PrivateHnswClientStateAeadContext {
                    vector_name: "text/vector",
                    ..context
                },
                "vector_name",
            ),
            (
                PrivateHnswClientStateAeadContext {
                    vector_name: "client.state",
                    ..context
                },
                "vector_name",
            ),
        ] {
            assert_eq!(
                seal_private_hnsw_oram_client_state_snapshot(&keys, malformed_context, &snapshot),
                Err(PrivateHnswClientError::InvalidClientStateContext(field))
            );
        }

        let mut tampered_hash = encrypted.clone();
        tampered_hash.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[9; 32]);
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &tampered_hash),
            Err(PrivateHnswClientError::InvalidClientStateCiphertextHash)
        );

        let mut malformed_hash = encrypted.clone();
        malformed_hash.ciphertext_sha256 = "AAAA".to_string();
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &malformed_hash),
            Err(PrivateHnswClientError::InvalidClientStateCiphertextHash)
        );

        let mut tampered_ciphertext = encrypted;
        let mut raw = BASE64URL_NOPAD
            .decode(tampered_ciphertext.ciphertext.as_bytes())
            .unwrap();
        let last = raw.last_mut().unwrap();
        *last ^= 0x80;
        tampered_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&raw);
        tampered_ciphertext.ciphertext_sha256 = base64url_sha256(&raw);
        assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &tampered_ciphertext),
            Err(PrivateHnswClientError::ClientStateOpenFailed)
        );
    }

    #[test]
    fn client_state_snapshot_ciphertext_does_not_expose_position_map_or_stash() {
        fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty()
                && haystack
                    .windows(needle.len())
                    .any(|window| window == needle)
        }

        let keys = test_keys();
        let config = oram_config();
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let mut stash = node_block_with_vector(2, &[2.0, 0.0], vec![[1; 32]]);
        stash.point_token = [66; 32];
        stash.vector = [3.25_f32, 4.5_f32]
            .into_iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        stash.level_mask = 0b11;
        stash.neighbors = vec![[88; 32], [99; 32]];
        stash.neighbor_levels = vec![1, 0];
        stash.payload_fetch_token = Some([77; 32]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (stash.node_id, 1)],
            config.tree_height,
        )
        .unwrap();
        state.stash.insert(stash.node_id, stash.clone());
        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        let plaintext_json = serde_json::to_string(&snapshot).unwrap();
        let context = PrivateHnswClientStateAeadContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
        };

        assert!(plaintext_json.contains("positions"));
        assert!(plaintext_json.contains("stash"));
        assert!(plaintext_json.contains("payload_fetch_token"));
        let sensitive_stash_values = [
            serde_json::to_string(&stash.node_id).unwrap(),
            serde_json::to_string(&stash.point_token).unwrap(),
            serde_json::to_string(&stash.vector).unwrap(),
            serde_json::to_string(&stash.neighbors).unwrap(),
            serde_json::to_string(&stash.payload_fetch_token).unwrap(),
        ];
        for sensitive_value in &sensitive_stash_values {
            assert!(plaintext_json.contains(sensitive_value));
        }
        for position in &snapshot.positions {
            assert!(plaintext_json.contains(&position.node_id));
            assert!(plaintext_json.contains(&position.leaf_label));
        }

        let encrypted =
            seal_private_hnsw_oram_client_state_snapshot(&keys, context, &snapshot).unwrap();
        let encrypted_json = serde_json::to_string(&encrypted).unwrap();
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(encrypted.ciphertext.as_bytes())
            .unwrap();

        for plaintext_marker in [
            "positions",
            "stash",
            "node_id",
            "leaf_label",
            "point_token",
            "vector",
            "neighbors",
            "payload_fetch_token",
        ] {
            assert!(!encrypted_json.contains(plaintext_marker));
            assert!(!contains_bytes(
                &raw_ciphertext,
                plaintext_marker.as_bytes()
            ));
        }
        for position in &snapshot.positions {
            assert!(!encrypted_json.contains(&position.node_id));
            assert!(!encrypted_json.contains(&position.leaf_label));
            assert!(!contains_bytes(
                &raw_ciphertext,
                position.node_id.as_bytes()
            ));
            assert!(!contains_bytes(
                &raw_ciphertext,
                position.leaf_label.as_bytes()
            ));
        }
        for sensitive_value in &sensitive_stash_values {
            assert!(!encrypted_json.contains(sensitive_value));
            assert!(!contains_bytes(&raw_ciphertext, sensitive_value.as_bytes()));
        }
        for sensitive_bytes in [
            stash.node_id.as_slice(),
            stash.point_token.as_slice(),
            stash.vector.as_slice(),
            stash.payload_fetch_token.as_ref().unwrap().as_slice(),
        ] {
            assert!(!contains_bytes(&raw_ciphertext, sensitive_bytes));
        }
        for neighbor in &stash.neighbors {
            assert!(!contains_bytes(&raw_ciphertext, neighbor.as_slice()));
        }
    }

    #[test]
    fn plaintext_oram_hnsw_search_walks_graph_and_ranks_top_k() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (near.node_id, 1), (far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, near.clone()), (2, far.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.completed_steps, 3);
        assert_eq!(
            result.accessed_leaf_labels,
            vec![
                encode_private_hnsw_oram_leaf_label(0, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap(),
            ]
        );
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
        assert_eq!(state.position(&entry.node_id), Some(3));
        assert_eq!(state.position(&near.node_id), Some(3));
        assert_eq!(state.position(&far.node_id), Some(3));
    }

    #[test]
    fn plaintext_oram_hnsw_search_expands_nearest_frontier_within_fixed_budget() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            tree_height: 3,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 2,
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let distractor = node_block_with_vector(2, &[9.0, 0.0], vec![[4; 32]]);
        let gateway = node_block_with_vector(3, &[1.0, 0.0], vec![[5; 32]]);
        let distractor_tail = node_block_with_vector(4, &[8.0, 0.0], vec![]);
        let target = node_block_with_vector(5, &[0.0, 0.0], vec![]);
        let blocks = [
            entry.clone(),
            distractor,
            gateway,
            distractor_tail,
            target.clone(),
        ];
        let mut state = PrivateHnswOramClientState::with_position_map(
            blocks
                .iter()
                .enumerate()
                .map(|(leaf, block)| (block.node_id, leaf as u64)),
            config.tree_height,
        )
        .unwrap();

        let store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in blocks.into_iter().enumerate() {
            let leaf_bucket_id =
                *private_hnsw_oram_bucket_ids_for_leaf(leaf as u64, config.tree_height)
                    .unwrap()
                    .last()
                    .unwrap();
            store.borrow_mut().get_mut(&leaf_bucket_id).unwrap().blocks[0] = Some(block);
        }

        let mut remaps = [5, 6, 7, 0].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[0.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 4,
                fixed_steps: 4,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store = store.borrow_mut();
                for bucket in writeback_buckets {
                    store.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.completed_steps, 4);
        assert_eq!(result.hits[0].node_id, target.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
        assert_eq!(
            result.accessed_leaf_labels,
            [0, 1, 2, 4]
                .into_iter()
                .map(|leaf| encode_private_hnsw_oram_leaf_label(leaf, config.tree_height).unwrap())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn strict_fixed_budget_search_crosses_worse_bridge_instead_of_padding_early() {
        let entry = node_block_with_vector(1, &[100.0, 0.0], vec![[2; 32], [3; 32], [4; 32]]);
        let near_dead_end = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let second_dead_end = node_block_with_vector(3, &[2.0, 0.0], vec![]);
        let bridge = node_block_with_vector(4, &[3.0, 0.0], vec![[5; 32]]);
        let target = node_block_with_vector(5, &[0.0, 0.0], vec![]);
        let mut padding = node_block_with_vector(6, &[200.0, 0.0], vec![]);
        padding.deleted = true;
        let result = run_fixed_budget_graph_search(
            &[
                entry.clone(),
                near_dead_end,
                second_dead_end,
                bridge,
                target.clone(),
                padding.clone(),
            ],
            &[0.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 2,
                fixed_steps: 6,
                distance: DistanceKind::Euclid,
                padding_node_id: Some(padding.node_id),
            },
        );

        assert_eq!(result.completed_steps, 6);
        assert_eq!(result.hits[0].node_id, target.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
    }

    #[test]
    fn fixed_budget_search_does_not_prune_equal_distance_bridge_by_node_id() {
        let entry = node_block_with_vector(1, &[100.0, 0.0], vec![[2; 32], [3; 32]]);
        let lower_id_dead_end = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let equal_distance_bridge = node_block_with_vector(3, &[-1.0, 0.0], vec![[4; 32]]);
        let target = node_block_with_vector(4, &[0.0, 0.0], vec![]);
        let mut padding = node_block_with_vector(5, &[200.0, 0.0], vec![]);
        padding.deleted = true;
        let result = run_fixed_budget_graph_search(
            &[
                entry.clone(),
                lower_id_dead_end,
                equal_distance_bridge,
                target.clone(),
                padding.clone(),
            ],
            &[0.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 1,
                fixed_steps: 5,
                distance: DistanceKind::Euclid,
                padding_node_id: Some(padding.node_id),
            },
        );

        assert_eq!(result.completed_steps, 5);
        assert_eq!(result.hits[0].node_id, target.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
    }

    fn run_fixed_budget_graph_search(
        blocks: &[PrivateHnswNodeBlockPlaintext],
        query: &[f32],
        params: PrivateHnswSearchParams,
    ) -> PrivateHnswSearchResult {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            tree_height: 3,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: blocks
                .iter()
                .map(|block| block.neighbors.len())
                .max()
                .unwrap_or(0),
        };
        let mut state = PrivateHnswOramClientState::with_position_map(
            blocks
                .iter()
                .enumerate()
                .map(|(leaf, block)| (block.node_id, leaf as u64)),
            config.tree_height,
        )
        .unwrap();
        let store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in blocks.iter().cloned().enumerate() {
            let leaf_bucket_id =
                *private_hnsw_oram_bucket_ids_for_leaf(leaf as u64, config.tree_height)
                    .unwrap()
                    .last()
                    .unwrap();
            store.borrow_mut().get_mut(&leaf_bucket_id).unwrap().blocks[0] = Some(block);
        }

        let leaf_count = private_hnsw_oram_leaf_count(config.tree_height).unwrap();
        let mut next_leaf = 0;
        search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            query,
            params,
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store = store.borrow_mut();
                for bucket in writeback_buckets {
                    store.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || {
                let leaf = next_leaf;
                next_leaf = (next_leaf + 1) % leaf_count;
                Ok(leaf)
            },
        )
        .unwrap()
    }

    #[test]
    fn plaintext_oram_hnsw_search_keeps_state_when_final_writeback_fails() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let mut state =
            PrivateHnswOramClientState::with_position_map([(entry.node_id, 0)], config.tree_height)
                .unwrap();
        let original_state = state.clone();
        let mut entry_bucket = empty_private_hnsw_oram_plaintext_bucket(3, config).unwrap();
        entry_bucket.blocks[0] = Some(entry);
        let path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap(),
            entry_bucket,
        ];

        let err = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: [1; 32],
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |_| Ok(path.clone()),
            |writeback_buckets| {
                assert!(!writeback_buckets.is_empty());
                Err(PrivateHnswClientError::InvalidSearchConfig("writeback"))
            },
            || Ok(2),
        )
        .unwrap_err();

        assert_eq!(
            err,
            PrivateHnswClientError::InvalidSearchConfig("writeback")
        );
        assert_eq!(state, original_state);
    }

    #[test]
    fn plaintext_oram_hnsw_search_pads_to_fixed_steps_with_dummy_node() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let mut dummy = node_block_with_vector(99, &[0.0, 0.0], vec![]);
        dummy.deleted = true;
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (dummy.node_id, 1)],
            config.tree_height,
        )
        .unwrap();

        let store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, dummy.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let params = PrivateHnswSearchParams {
            entry_node_id: entry.node_id,
            k: 1,
            ef: 1,
            fixed_steps: 3,
            distance: DistanceKind::Euclid,
            padding_node_id: Some(dummy.node_id),
        };
        let mut remaps = [2, 3, 0].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            params,
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.completed_steps, 3);
        assert_eq!(
            result.access_metrics(&params),
            PrivateHnswSearchAccessMetrics {
                path_accesses: 3,
                unique_leaf_labels: 3,
                fixed_steps: 3,
                exhausted_fixed_budget: true,
            }
        );
        assert_eq!(
            result.accessed_leaf_labels,
            vec![
                encode_private_hnsw_oram_leaf_label(0, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(3, config.tree_height).unwrap(),
            ]
        );
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, entry.node_id);
        assert_eq!(state.position(&entry.node_id), Some(2));
        assert_eq!(state.position(&dummy.node_id), Some(0));
    }

    #[test]
    fn encrypted_oram_hnsw_search_opens_and_reseals_writeback_buckets() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (near.node_id, 1), (far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let plaintext_store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            plaintext_store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, near.clone()), (2, far.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = plaintext_store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let encrypted_store = RefCell::new(BTreeMap::new());
        for bucket in plaintext_store.borrow().values() {
            let encrypted =
                seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 42, bucket, config)
                    .unwrap();
            encrypted_store
                .borrow_mut()
                .insert(bucket.bucket_id, encrypted);
        }

        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_encrypted(
            &keys,
            base_context,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = encrypted_store.borrow_mut();
                for bucket in writeback_buckets {
                    assert_eq!(bucket.index_epoch, 43);
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
        assert_eq!(result.completed_steps, 3);
        assert!(
            encrypted_store
                .borrow()
                .values()
                .any(|bucket| bucket.index_epoch == 43)
        );

        let root = encrypted_store.borrow().get(&0).cloned().unwrap();
        let root_plaintext =
            open_private_hnsw_oram_plaintext_bucket(&keys, base_context, &root, config).unwrap();
        assert_eq!(root_plaintext.bucket_id, 0);
        assert!(root_plaintext.blocks.iter().any(|slot| slot.is_some()));
    }

    #[test]
    fn encrypted_oram_hnsw_search_keeps_state_when_final_reseal_fails() {
        use std::cell::{Cell, RefCell};

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let mut oversized_stash_block = node_block_with_vector(99, &[99.0, 0.0], vec![]);
        oversized_stash_block.vector = vec![99; config.block_size_bytes];
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (oversized_stash_block.node_id, 0)],
            config.tree_height,
        )
        .unwrap();
        state
            .stash
            .insert(oversized_stash_block.node_id, oversized_stash_block);
        let original_state = state.clone();

        let plaintext_store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            plaintext_store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(0, config.tree_height)
            .unwrap()
            .last()
            .unwrap();
        plaintext_store
            .borrow_mut()
            .get_mut(&leaf_bucket_id)
            .unwrap()
            .blocks[0] = Some(entry.clone());

        let encrypted_store = RefCell::new(BTreeMap::new());
        for bucket in plaintext_store.borrow().values() {
            let encrypted =
                seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 42, bucket, config)
                    .unwrap();
            encrypted_store
                .borrow_mut()
                .insert(bucket.bucket_id, encrypted);
        }
        let writeback_called = Cell::new(false);

        let err = search_private_hnsw_oram_encrypted(
            &keys,
            base_context,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |_| {
                writeback_called.set(true);
                Ok(())
            },
            || Ok(0),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::EncodedBlockOversized);
        assert!(!writeback_called.get());
        assert_eq!(state, original_state);
    }

    #[test]
    fn verified_encrypted_oram_hnsw_search_rejects_non_advancing_writeback_epoch_before_read() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let mut state =
            PrivateHnswOramClientState::with_position_map([([1; 32], 0)], config.tree_height)
                .unwrap();
        let params = PrivateHnswSearchParams {
            entry_node_id: [1; 32],
            k: 1,
            ef: 1,
            fixed_steps: 1,
            distance: DistanceKind::Euclid,
            padding_node_id: None,
        };
        let read_called = RefCell::new(false);
        let writeback_called = RefCell::new(false);

        let err = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            private_hnsw_oram_bucket_count(config.tree_height).unwrap(),
            42,
            &mut state,
            config,
            &[1.0, 0.0],
            params,
            |_| {
                *read_called.borrow_mut() = true;
                Err(PrivateHnswClientError::PathBucketMismatch)
            },
            |_| {
                *writeback_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(0),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::InvalidCommitEpoch);
        assert!(!*read_called.borrow());
        assert!(!*writeback_called.borrow());
        assert_eq!(state.position(&[1; 32]), Some(0));

        let mut cached_state = state.clone();
        let read_with_cache_called = RefCell::new(false);
        let writeback_with_cache_called = RefCell::new(false);
        let err = search_private_hnsw_oram_encrypted_verified_with_cache(
            &keys,
            base_context,
            42,
            &root_hash,
            private_hnsw_oram_bucket_count(config.tree_height).unwrap(),
            42,
            &mut cached_state,
            config,
            &[1.0, 0.0],
            params,
            &PrivateHnswClientNodeCache::new(),
            |_| {
                *read_with_cache_called.borrow_mut() = true;
                Err(PrivateHnswClientError::PathBucketMismatch)
            },
            |_| {
                *writeback_with_cache_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(0),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::InvalidCommitEpoch);
        assert!(!*read_with_cache_called.borrow());
        assert!(!*writeback_with_cache_called.borrow());
        assert_eq!(cached_state.position(&[1; 32]), Some(0));
    }

    #[test]
    fn verified_encrypted_oram_hnsw_search_rejects_bad_context_before_read() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let bucket_count = private_hnsw_oram_bucket_count(config.tree_height).unwrap();
        let params = PrivateHnswSearchParams {
            entry_node_id: [1; 32],
            k: 1,
            ef: 1,
            fixed_steps: 1,
            distance: DistanceKind::Euclid,
            padding_node_id: None,
        };
        let mut state =
            PrivateHnswOramClientState::with_position_map([([1; 32], 0)], config.tree_height)
                .unwrap();
        let read_called = RefCell::new(false);
        let writeback_called = RefCell::new(false);

        let err = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count - 1,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            params,
            |_| {
                *read_called.borrow_mut() = true;
                Err(PrivateHnswClientError::PathBucketMismatch)
            },
            |_| {
                *writeback_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(0),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::BucketCountMismatch);
        assert!(!*read_called.borrow());
        assert!(!*writeback_called.borrow());
        assert_eq!(state.position(&[1; 32]), Some(0));

        let mut cached_state = state.clone();
        let read_with_cache_called = RefCell::new(false);
        let writeback_with_cache_called = RefCell::new(false);
        let err = search_private_hnsw_oram_encrypted_verified_with_cache(
            &keys,
            base_context,
            42,
            "AAAA",
            bucket_count,
            43,
            &mut cached_state,
            config,
            &[1.0, 0.0],
            params,
            &PrivateHnswClientNodeCache::new(),
            |_| {
                *read_with_cache_called.borrow_mut() = true;
                Err(PrivateHnswClientError::PathBucketMismatch)
            },
            |_| {
                *writeback_with_cache_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(0),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::InvalidMerkleRoot);
        assert!(!*read_with_cache_called.borrow());
        assert!(!*writeback_with_cache_called.borrow());
        assert_eq!(cached_state.position(&[1; 32]), Some(0));
    }

    #[test]
    fn verified_encrypted_oram_hnsw_search_checks_merkle_proofs_before_opening() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let bucket_count = private_hnsw_oram_bucket_count(config.tree_height).unwrap();
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (near.node_id, 1), (far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let plaintext_store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..bucket_count {
            plaintext_store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, near.clone()), (2, far.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = plaintext_store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let encrypted_store = RefCell::new(BTreeMap::new());
        for bucket in plaintext_store.borrow().values() {
            let encrypted =
                seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 42, bucket, config)
                    .unwrap();
            encrypted_store
                .borrow_mut()
                .insert(bucket.bucket_id, encrypted);
        }
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .borrow()
                    .get(&bucket_id)
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .ok_or(PrivateHnswClientError::PathBucketMismatch)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let root_hash = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
        let writebacks = RefCell::new(Vec::new());

        let mut partial_failure_state = state.clone();
        let original_partial_failure_state = partial_failure_state.clone();
        let partial_failure_reads = RefCell::new(0usize);
        let partial_failure_writebacks = RefCell::new(0usize);
        let mut partial_failure_remaps = [3].into_iter();
        let err = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut partial_failure_state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 1,
                fixed_steps: 2,
                distance: DistanceKind::Euclid,
                padding_node_id: Some(far.node_id),
            },
            |leaf| {
                let mut reads = partial_failure_reads.borrow_mut();
                let read_index = *reads;
                *reads += 1;

                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proof = proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: if read_index == 0 {
                        root_hash.clone()
                    } else {
                        BASE64URL_NOPAD.encode(&[99; 32])
                    },
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                assert!(!writeback_buckets.is_empty());
                *partial_failure_writebacks.borrow_mut() += 1;
                Ok(())
            },
            || {
                partial_failure_remaps
                    .next()
                    .ok_or(PrivateHnswClientError::LeafOutOfRange)
            },
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::MerkleProofMismatch);
        assert_eq!(*partial_failure_reads.borrow(), 2);
        assert_eq!(*partial_failure_writebacks.borrow(), 0);
        assert_eq!(partial_failure_state, original_partial_failure_state);

        let mut bad_state = state.clone();
        let bad_writeback_called = RefCell::new(false);
        let err = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut bad_state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let mut buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // Keep the ciphertext hash valid but make bucket open fail if it runs before proof verification.
                let mut tampered_raw_ciphertext = BASE64URL_NOPAD
                    .decode(buckets[0].ciphertext.as_bytes())
                    .unwrap();
                *tampered_raw_ciphertext.last_mut().unwrap() ^= 0x01;
                buckets[0].ciphertext = BASE64URL_NOPAD.encode(&tampered_raw_ciphertext);
                buckets[0].ciphertext_sha256 = base64url_sha256(&tampered_raw_ciphertext);
                let mut proof =
                    proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                proof.leaves[0].leaf_hash = commitment(99);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                assert!(!writeback_buckets.is_empty());
                *bad_writeback_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(3),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::MerkleProofMismatch);
        assert!(!*bad_writeback_called.borrow());
        assert_eq!(bad_state.position(&entry.node_id), Some(0));

        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proof = proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                writebacks.borrow_mut().extend_from_slice(writeback_buckets);
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.completed_steps, 3);
        assert!(
            writebacks
                .borrow()
                .iter()
                .all(|bucket| bucket.index_epoch == 43)
        );
    }

    #[test]
    fn verified_encrypted_oram_hnsw_search_with_cache_checks_merkle_proofs_before_writeback() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let bucket_count = private_hnsw_oram_bucket_count(config.tree_height).unwrap();
        let mut entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32]]);
        entry.level_mask = 0b11;
        entry.neighbor_levels = vec![1];
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let padding = node_block_with_vector(3, &[99.0, 0.0], vec![]);
        let build = build_private_hnsw_oram_plaintext_index_from_blocks(
            config,
            &[entry.clone(), near.clone(), padding.clone()],
            &[0, 1, 2],
        )
        .unwrap();

        let mut cache = PrivateHnswClientNodeCache::new();
        assert_eq!(cache.extend_upper_layers_from_plaintext_build(&build, 1), 1);
        assert!(cache.contains(&entry.node_id));

        let encrypted_store = RefCell::new(BTreeMap::new());
        for bucket in &build.buckets {
            let encrypted =
                seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 42, bucket, config)
                    .unwrap();
            encrypted_store
                .borrow_mut()
                .insert(bucket.bucket_id, encrypted);
        }
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .borrow()
                    .get(&bucket_id)
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .ok_or(PrivateHnswClientError::PathBucketMismatch)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let root_hash = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();

        let mut bad_state = build.state.clone();
        let read_leaves = RefCell::new(Vec::new());
        let bad_writeback_called = RefCell::new(false);
        let err = search_private_hnsw_oram_encrypted_verified_with_cache(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut bad_state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 2,
                fixed_steps: 2,
                distance: DistanceKind::Euclid,
                padding_node_id: Some(padding.node_id),
            },
            &cache,
            |leaf| {
                read_leaves.borrow_mut().push(leaf);
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let mut buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // Keep the ciphertext hash valid but make bucket open fail if it runs before proof verification.
                let mut tampered_raw_ciphertext = BASE64URL_NOPAD
                    .decode(buckets[0].ciphertext.as_bytes())
                    .unwrap();
                *tampered_raw_ciphertext.last_mut().unwrap() ^= 0x01;
                buckets[0].ciphertext = BASE64URL_NOPAD.encode(&tampered_raw_ciphertext);
                buckets[0].ciphertext_sha256 = base64url_sha256(&tampered_raw_ciphertext);
                let mut proof =
                    proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                proof.leaves[0].leaf_hash = commitment(99);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                assert!(!writeback_buckets.is_empty());
                *bad_writeback_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(3),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::MerkleProofMismatch);
        assert_eq!(*read_leaves.borrow(), vec![2]);
        assert!(!*bad_writeback_called.borrow());
        assert_eq!(bad_state.position(&entry.node_id), Some(0));
        assert_eq!(bad_state.position(&near.node_id), Some(1));
        assert_eq!(bad_state.position(&padding.node_id), Some(2));

        let mut state = build.state.clone();
        let read_leaves = RefCell::new(Vec::new());
        let writebacks = RefCell::new(Vec::new());
        let mut remaps = [3, 3].into_iter();
        let params = PrivateHnswSearchParams {
            entry_node_id: entry.node_id,
            k: 1,
            ef: 2,
            fixed_steps: 2,
            distance: DistanceKind::Euclid,
            padding_node_id: Some(padding.node_id),
        };
        let result = search_private_hnsw_oram_encrypted_verified_with_cache(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            params,
            &cache,
            |leaf| {
                read_leaves.borrow_mut().push(leaf);
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proof = proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                writebacks.borrow_mut().extend_from_slice(writeback_buckets);
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.completed_steps, 2);
        assert_eq!(*read_leaves.borrow(), vec![2, 1]);
        assert_eq!(
            result.accessed_leaf_labels,
            vec![
                encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap(),
            ]
        );
        assert_eq!(
            result.access_metrics(&params),
            PrivateHnswSearchAccessMetrics {
                path_accesses: 2,
                unique_leaf_labels: 2,
                fixed_steps: 2,
                exhausted_fixed_budget: true,
            }
        );
        assert!(
            writebacks
                .borrow()
                .iter()
                .all(|bucket| bucket.index_epoch == 43)
        );
    }

    #[test]
    fn plaintext_oram_hnsw_search_rejects_bad_vector_shapes() {
        use std::cell::RefCell;

        let config = oram_config();
        let mut state =
            PrivateHnswOramClientState::with_position_map([([1; 32], 0)], config.tree_height)
                .unwrap();
        let original_state = state.clone();
        let writeback_called = RefCell::new(false);
        let bad_vector = PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: [1; 32],
            point_token: [2; 32],
            level_mask: 1,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vec![1, 2, 3],
            neighbors: vec![],
            neighbor_levels: vec![],
            deleted: false,
            generation: 1,
            payload_fetch_token: None,
        };
        let path = [
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap(),
            PrivateHnswOramPlaintextBucket {
                bucket_id: 3,
                blocks: vec![Some(bad_vector)],
            },
        ];

        let err = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0],
            PrivateHnswSearchParams {
                entry_node_id: [1; 32],
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |_| Ok(path.to_vec()),
            |_| {
                *writeback_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(0),
        )
        .unwrap_err();
        assert_eq!(err, PrivateHnswClientError::InvalidF32VectorLength);
        assert_eq!(state, original_state);
        assert!(!*writeback_called.borrow());
    }

    #[test]
    fn bucket_seal_open_roundtrips_and_populates_integrity_fields() {
        let keys = test_keys();
        let context = bucket_context(3);
        let plaintext = vec![11; 256];
        let bucket = seal_private_hnsw_oram_bucket(&keys, context, &plaintext).unwrap();

        assert_eq!(bucket.version, 1);
        assert_eq!(bucket.bucket_id, 3);
        assert_eq!(bucket.index_epoch, 42);
        decode_bucket_ciphertext_hash(&bucket.ciphertext_sha256).unwrap();
        decode_bucket_commitment(&bucket.bucket_commitment).unwrap();
        assert_eq!(
            private_hnsw_bucket_commitment(context, &bucket.ciphertext_sha256).unwrap(),
            bucket.bucket_commitment
        );
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &bucket).unwrap(),
            plaintext
        );
    }

    #[test]
    fn bucket_open_rejects_wrong_context_hash_and_ciphertext_tamper() {
        let keys = test_keys();
        let context = bucket_context(3);
        let bucket = seal_private_hnsw_oram_bucket(&keys, context, &[9; 64]).unwrap();

        let mut wrong_context = context;
        wrong_context.bucket_id = 4;
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, wrong_context, &bucket),
            Err(PrivateHnswClientError::BucketMetadataMismatch)
        );

        for wrong_context in [
            PrivateHnswBucketAeadContext {
                collection_id: "collection-uuid-2",
                ..context
            },
            PrivateHnswBucketAeadContext {
                vector_name: "body",
                ..context
            },
            PrivateHnswBucketAeadContext {
                key_id: "tenant-a/vector-private-rk-v2",
                ..context
            },
            PrivateHnswBucketAeadContext {
                rk_id: "tenant-a/vector-private-rk-v2",
                ..context
            },
            PrivateHnswBucketAeadContext {
                rk_epoch: 8,
                ..context
            },
        ] {
            let mut wrong_context_bucket = bucket.clone();
            wrong_context_bucket.bucket_commitment = private_hnsw_bucket_commitment(
                wrong_context,
                &wrong_context_bucket.ciphertext_sha256,
            )
            .unwrap();
            assert_eq!(
                open_private_hnsw_oram_bucket(&keys, wrong_context, &wrong_context_bucket),
                Err(PrivateHnswClientError::BucketOpenFailed)
            );
        }
        for malformed_context in [
            PrivateHnswBucketAeadContext {
                vector_name: "text/vector",
                ..context
            },
            PrivateHnswBucketAeadContext {
                vector_name: "client.state",
                ..context
            },
        ] {
            assert_eq!(
                seal_private_hnsw_oram_bucket(&keys, malformed_context, &[9; 64]),
                Err(PrivateHnswClientError::InvalidBucketContext("vector_name"))
            );
        }

        let mut wrong_hash = bucket.clone();
        wrong_hash.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[8; 32]);
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &wrong_hash),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );

        let mut malformed_ciphertext = bucket.clone();
        malformed_ciphertext.ciphertext = "A".to_string();
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &malformed_ciphertext),
            Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding)
        );

        let mut wrong_ciphertext = bucket;
        let mut raw = BASE64URL_NOPAD
            .decode(wrong_ciphertext.ciphertext.as_bytes())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        wrong_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&raw);
        wrong_ciphertext.ciphertext_sha256 = base64url_sha256(&raw);
        wrong_ciphertext.bucket_commitment =
            private_hnsw_bucket_commitment(context, &wrong_ciphertext.ciphertext_sha256).unwrap();
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &wrong_ciphertext),
            Err(PrivateHnswClientError::BucketOpenFailed)
        );
    }

    #[test]
    fn base64url_nopad_decoded_len_rejects_impossible_shapes() {
        fn base64url_nopad_encoded_len(decoded_len: usize) -> usize {
            let full_triples = decoded_len / 3;
            let base_len = full_triples * 4;
            match decoded_len % 3 {
                0 => base_len,
                1 => base_len + 2,
                2 => base_len + 3,
                _ => unreachable!(),
            }
        }

        assert_eq!(base64url_nopad_decoded_len(0), Some(0));
        assert_eq!(base64url_nopad_decoded_len(2), Some(1));
        assert_eq!(base64url_nopad_decoded_len(3), Some(2));
        assert_eq!(base64url_nopad_decoded_len(4), Some(3));
        assert_eq!(base64url_nopad_decoded_len(1), None);
        assert_eq!(base64url_nopad_decoded_len(5), None);

        let max_encoded =
            base64url_nopad_encoded_len(PRIVATE_HNSW_CLIENT_STATE_CIPHERTEXT_MAX_BYTES);
        assert_eq!(
            validate_private_hnsw_client_state_ciphertext_encoded_len(max_encoded).unwrap(),
            PRIVATE_HNSW_CLIENT_STATE_CIPHERTEXT_MAX_BYTES
        );
        let oversized_encoded =
            base64url_nopad_encoded_len(PRIVATE_HNSW_CLIENT_STATE_CIPHERTEXT_MAX_BYTES + 1);
        assert_eq!(
            validate_private_hnsw_client_state_ciphertext_encoded_len(oversized_encoded),
            Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding)
        );
        assert_eq!(
            validate_private_hnsw_client_state_ciphertext_encoded_len(5),
            Err(PrivateHnswClientError::InvalidClientStateCiphertextEncoding)
        );
    }
}

#[cfg(test)]
#[path = "private_hnsw_client_budget_tests.rs"]
mod budget_tests;
