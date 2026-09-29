use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aead::validate_resource_key_id;
use crate::control_plane::{PRIVATE_HNSW_ORAM_BINDING, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER};

pub const PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-manifest-signature/v1";
pub const PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-commit-signature/v1";
pub const PRIVATE_HNSW_ORAM_READ_PATHS_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-read-paths-signature/v1";
pub const PRIVATE_HNSW_ORAM_BUCKET_COMMITMENT_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-bucket-commitment/v1";

const PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_8_BYTE_LEN: usize = 11;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const PRIVATE_HNSW_ORAM_MANIFEST_VERSION: u16 = 1;
const PRIVATE_HNSW_ORAM_BUCKET_VERSION: u16 = 1;
const PRIVATE_HNSW_NODE_BLOCK_FIXED_BYTES: u64 = 133;
const PRIVATE_HNSW_NODE_BLOCK_F32_ELEMENT_BYTES: u64 = 4;
const PRIVATE_HNSW_NODE_BLOCK_NEIGHBOR_SLOT_BYTES: u64 = 33;
const PRIVATE_HNSW_ORAM_BUCKET_PLAINTEXT_HEADER_BYTES: usize = 4 + 2 + 4 + 4;
const PRIVATE_HNSW_ORAM_BUCKET_AEAD_OVERHEAD_BYTES: usize = 1 + 12 + 16;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateHnswOramError {
    #[error("private HNSW ORAM manifest uses unsupported version")]
    UnsupportedManifestVersion(u16),
    #[error("private HNSW ORAM manifest provider is invalid")]
    InvalidProvider,
    #[error("private HNSW ORAM manifest binding is invalid")]
    InvalidBinding,
    #[error("private HNSW ORAM manifest field is invalid")]
    InvalidManifestField(&'static str),
    #[error("private HNSW ORAM manifest field does not match runtime context")]
    ManifestContextMismatch(&'static str),
    #[error("private HNSW ORAM manifest signature is missing")]
    MissingManifestSignature,
    #[error("private HNSW ORAM manifest signature uses unsupported algorithm")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private HNSW ORAM manifest signature key id does not match runtime context")]
    SignatureKeyIdMismatch,
    #[error("private HNSW ORAM manifest signature is malformed")]
    MalformedSignature,
    #[error("private HNSW ORAM manifest signature verification failed")]
    InvalidManifestSignature,
    #[error("private HNSW ORAM commit signature verification failed")]
    InvalidCommitSignature,
    #[error("private HNSW ORAM commit must update at least one bucket")]
    EmptyCommit,
    #[error("private HNSW ORAM read_paths signature verification failed")]
    InvalidReadPathsSignature,
    #[error("private HNSW ORAM resource key id is invalid")]
    InvalidResourceKeyId,
    #[error("private HNSW ORAM bucket uses unsupported version")]
    UnsupportedBucketVersion(u16),
    #[error("private HNSW ORAM bucket id is out of range")]
    BucketOutOfRange { bucket_id: u64, bucket_count: u64 },
    #[error("private HNSW ORAM bucket epoch is stale")]
    StaleBucketEpoch {
        bucket_id: u64,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    #[error("private HNSW ORAM commit updates the same bucket more than once")]
    DuplicateUpdatedBucket { bucket_id: u64 },
    #[error("private HNSW ORAM bucket field is invalid")]
    InvalidBucketField(&'static str),
    #[error("private HNSW ORAM bucket ciphertext is oversized")]
    BucketOversized,
    #[error("private HNSW ORAM bucket ciphertext hash is invalid")]
    InvalidBucketHash,
    #[error("private HNSW ORAM bucket commitment is invalid")]
    InvalidBucketCommitment,
    #[error("private HNSW ORAM bucket context is invalid")]
    InvalidBucketContext(&'static str),
    #[error("private HNSW ORAM fetch/commit plan field is invalid")]
    InvalidFetchPlanField(&'static str),
    #[error("private HNSW ORAM Merkle tree is empty")]
    EmptyMerkleTree,
    #[error("private HNSW ORAM Merkle root does not match bucket commitments")]
    MerkleRootMismatch,
    #[error("private HNSW ORAM manifest does not match commit plan")]
    ManifestCommitMismatch,
}

impl Debug for PrivateHnswOramError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateHnswOramError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistanceKind {
    Cosine,
    Dot,
    Euclid,
    Manhattan,
}

impl DistanceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cosine => "cosine",
            Self::Dot => "dot",
            Self::Euclid => "euclid",
            Self::Manhattan => "manhattan",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultPrivacyMode {
    IdsVisible,
    PrivatePayloadOramRequired,
}

impl ResultPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdsVisible => "ids_visible",
            Self::PrivatePayloadOramRequired => "private_payload_oram_required",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OramKind {
    PathOram,
}

impl OramKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PathOram => "path_oram",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswParams {
    pub m: u32,
    pub ef_construction: u32,
    pub max_layers: u32,
    pub fixed_neighbor_slots: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OramParams {
    pub kind: OramKind,
    pub bucket_size: u32,
    pub block_size_bytes: u32,
    pub tree_height: u32,
    pub path_batch_size: u32,
}

pub fn private_hnsw_oram_bucket_ciphertext_bytes(
    oram: &OramParams,
) -> Result<usize, PrivateHnswOramError> {
    let bucket_size = usize::try_from(oram.bucket_size)
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("oram.bucket_size"))?;
    let block_size_bytes = usize::try_from(oram.block_size_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("oram.block_size_bytes"))?;
    let slot_bytes =
        1usize
            .checked_add(block_size_bytes)
            .ok_or(PrivateHnswOramError::InvalidManifestField(
                "oram.block_size_bytes",
            ))?;
    let bucket_payload_bytes =
        bucket_size
            .checked_mul(slot_bytes)
            .ok_or(PrivateHnswOramError::InvalidManifestField(
                "oram.bucket_size",
            ))?;
    let plaintext_bytes = PRIVATE_HNSW_ORAM_BUCKET_PLAINTEXT_HEADER_BYTES
        .checked_add(bucket_payload_bytes)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    PRIVATE_HNSW_ORAM_BUCKET_AEAD_OVERHEAD_BYTES
        .checked_add(plaintext_bytes)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedBudgetParams {
    pub enabled: bool,
    pub upper_layer_steps: u32,
    pub base_layer_steps: u32,
    pub paths_per_round: u32,
    pub fixed_result_k: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramManifest {
    pub version: u16,
    pub provider: String,
    pub binding: String,
    pub collection_id: String,
    pub vector_name: String,
    pub key_id: String,
    pub rk_id: String,
    pub rk_epoch: u64,
    pub dim: u32,
    pub distance: DistanceKind,
    pub hnsw: PrivateHnswParams,
    pub oram: OramParams,
    pub fixed_budget: FixedBudgetParams,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub logical_node_count: u64,
    pub dummy_node_count: u64,
    pub result_privacy: ResultPrivacyMode,
    pub owner_signing_key_id: String,
    pub created_at_unix: u64,
}

impl Debug for PrivateHnswOramManifest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramManifest")
            .field("version", &self.version)
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("dim", &self.dim)
            .field("distance", &self.distance)
            .field("hnsw", &self.hnsw)
            .field("oram", &self.oram)
            .field("fixed_budget", &self.fixed_budget)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.bucket_count)
            .field("logical_node_count", &self.logical_node_count)
            .field("dummy_node_count", &self.dummy_node_count)
            .field("result_privacy", &self.result_privacy)
            .field("owner_signing_key_id", &"[redacted]")
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramBucket {
    pub version: u16,
    pub bucket_id: u64,
    pub index_epoch: u64,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub bucket_commitment: String,
}

impl Debug for PrivateHnswOramBucket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramBucket")
            .field("version", &self.version)
            .field("bucket_id", &"[redacted]")
            .field("index_epoch", &"[redacted]")
            .field("ciphertext_len", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .field("bucket_commitment", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramBucketValidationContext {
    pub bucket_count: u64,
    pub expected_index_epoch: u64,
    pub max_ciphertext_bytes: usize,
}

impl Debug for PrivateHnswOramBucketValidationContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramBucketValidationContext")
            .field("bucket_count", &"[redacted]")
            .field("expected_index_epoch", &"[redacted]")
            .field("max_ciphertext_bytes", &self.max_ciphertext_bytes)
            .finish()
    }
}

impl PrivateHnswOramBucketValidationContext {
    pub fn from_manifest(manifest: &PrivateHnswOramManifest, max_ciphertext_bytes: usize) -> Self {
        Self {
            bucket_count: manifest.bucket_count,
            expected_index_epoch: manifest.index_epoch,
            max_ciphertext_bytes,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramBucketCommitmentContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub bucket_id: u64,
    pub index_epoch: u64,
}

impl Debug for PrivateHnswOramBucketCommitmentContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramBucketCommitmentContext")
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateHnswOramSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
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

    pub fn validate_initial_upload_contract(&self) -> Result<Vec<String>, PrivateHnswOramError> {
        validate_private_hnsw_oram_upload_bundle(self)
    }

    pub fn validate_initial_upload_contract_with_signature(
        &self,
        validation_context: PrivateHnswManifestValidationContext<'_>,
    ) -> Result<Vec<String>, PrivateHnswOramError> {
        validate_private_hnsw_oram_upload_bundle_with_signature(self, validation_context)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

impl Debug for PrivateHnswSignatureVerification<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSignatureVerification")
            .field("expected_key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswManifestValidationContext<'a> {
    pub expected_collection_id: &'a str,
    pub expected_vector_name: &'a str,
    pub expected_key_id: &'a str,
    pub expected_rk_id: &'a str,
    pub min_rk_epoch: u64,
    pub max_rk_epoch: u64,
    pub expected_dim: u32,
    pub expected_distance: DistanceKind,
    pub signature_verification: PrivateHnswSignatureVerification<'a>,
}

impl Debug for PrivateHnswManifestValidationContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswManifestValidationContext")
            .field("expected_collection_id", &"[redacted]")
            .field("expected_vector_name", &"[redacted]")
            .field("expected_key_id", &"[redacted]")
            .field("expected_rk_id", &"[redacted]")
            .field("min_rk_epoch", &self.min_rk_epoch)
            .field("max_rk_epoch", &self.max_rk_epoch)
            .field("expected_dim", &self.expected_dim)
            .field("expected_distance", &self.expected_distance)
            .field("signature_verification", &self.signature_verification)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswEpoch {
    pub epoch: u64,
    pub root_hash: [u8; 32],
}

impl Debug for PrivateHnswEpoch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswEpoch")
            .field("epoch", &self.epoch)
            .field("root_hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswOramCommitPlan {
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub leaf_commitments: Vec<String>,
    pub updated_buckets: Vec<PrivateHnswOramClientCommitBucketRef>,
}

impl Debug for PrivateHnswOramCommitPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramCommitPlan")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("leaf_commitment_count", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswOramCommitPlan {
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

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswOramClientCommitBucketRef {
    pub bucket_id: u64,
    pub ciphertext_sha256: String,
}

impl Debug for PrivateHnswOramClientCommitBucketRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramClientCommitBucketRef")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramCommitBucketRef<'a> {
    pub bucket_id: u64,
    pub ciphertext_sha256: &'a str,
}

impl Debug for PrivateHnswOramCommitBucketRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramCommitBucketRef")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramCommitSignatureInput<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub updated_buckets: &'a [PrivateHnswOramCommitBucketRef<'a>],
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

impl Debug for PrivateHnswOramCommitSignatureInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramCommitSignatureInput")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .field("signature_alg", &self.signature_alg)
            .field("signature_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramReadPathsSignatureInput<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub index_epoch: u64,
    pub root_hash: &'a str,
    pub paths: &'a [&'a str],
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

impl Debug for PrivateHnswOramReadPathsSignatureInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramReadPathsSignatureInput")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("path_count", &"[redacted]")
            .field("requested_paths", &"[redacted]")
            .field("dummy_paths_included", &"[redacted]")
            .field("signature_alg", &self.signature_alg)
            .field("signature_key_id", &"[redacted]")
            .finish()
    }
}

pub fn validate_private_hnsw_oram_manifest(
    manifest: &PrivateHnswOramManifest,
    signature: Option<&PrivateHnswOramSignature>,
    context: PrivateHnswManifestValidationContext<'_>,
) -> Result<PrivateHnswEpoch, PrivateHnswOramError> {
    validate_manifest_shape(manifest)?;
    validate_manifest_context(manifest, context)?;
    validate_private_hnsw_oram_manifest_signature(
        manifest,
        signature,
        context.signature_verification,
    )?;

    let root_hash = decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(PrivateHnswEpoch {
        epoch: manifest.index_epoch,
        root_hash,
    })
}

pub fn validate_private_hnsw_oram_manifest_shape(
    manifest: &PrivateHnswOramManifest,
) -> Result<(), PrivateHnswOramError> {
    validate_manifest_shape(manifest)
}

pub fn validate_private_hnsw_oram_manifest_signature_shape(
    signature: &PrivateHnswOramSignature,
) -> Result<(), PrivateHnswOramError> {
    if signature.alg != PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    validate_resource_id(&signature.key_id)?;
    decode_base64url_64(&signature.sig)?;
    Ok(())
}

pub fn validate_private_hnsw_oram_manifest_signature(
    manifest: &PrivateHnswOramManifest,
    signature: Option<&PrivateHnswOramSignature>,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    let signature = signature.ok_or(PrivateHnswOramError::MissingManifestSignature)?;
    validate_manifest_shape(manifest)?;
    validate_signature_header(
        signature,
        manifest.owner_signing_key_id.as_str(),
        verification,
    )?;
    let signature_bytes = decode_base64url_64(&signature.sig)?;
    let message = try_private_hnsw_oram_manifest_signature_message(manifest)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidManifestSignature)
}

pub fn validate_private_hnsw_oram_commit_signature(
    input: PrivateHnswOramCommitSignatureInput<'_>,
    signature: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    validate_private_hnsw_oram_commit_signature_shape(input)?;
    let signature_bytes = decode_base64url_64(signature)?;
    let message = try_private_hnsw_oram_commit_signature_message(input)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidCommitSignature)
}

pub fn validate_private_hnsw_oram_read_paths_signature(
    input: PrivateHnswOramReadPathsSignatureInput<'_>,
    signature: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    validate_private_hnsw_oram_read_paths_signature_shape(input)?;
    let signature_bytes = decode_base64url_64(signature)?;
    let message = try_private_hnsw_oram_read_paths_signature_message(input)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)
}

pub fn private_hnsw_min_f32_node_block_bytes(dim: u32, fixed_neighbor_slots: u32) -> Option<u64> {
    let vector_bytes = u64::from(dim).checked_mul(PRIVATE_HNSW_NODE_BLOCK_F32_ELEMENT_BYTES)?;
    let neighbor_bytes =
        u64::from(fixed_neighbor_slots).checked_mul(PRIVATE_HNSW_NODE_BLOCK_NEIGHBOR_SLOT_BYTES)?;
    PRIVATE_HNSW_NODE_BLOCK_FIXED_BYTES
        .checked_add(vector_bytes)?
        .checked_add(neighbor_bytes)
}

pub fn sign_private_hnsw_oram_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
) -> Result<PrivateHnswOramSignature, PrivateHnswOramError> {
    let message = try_private_hnsw_oram_manifest_signature_message(manifest)?;
    Ok(PrivateHnswOramSignature {
        alg: PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

pub fn package_private_hnsw_oram_upload_bundle(
    key_pair: &Ed25519KeyPair,
    manifest: PrivateHnswOramManifest,
    buckets: Vec<PrivateHnswOramBucket>,
) -> Result<PrivateHnswOramUploadBundle, PrivateHnswOramError> {
    let manifest_signature = sign_private_hnsw_oram_manifest(key_pair, &manifest)?;
    let bundle = PrivateHnswOramUploadBundle {
        manifest,
        manifest_signature,
        buckets,
    };
    validate_private_hnsw_oram_upload_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_private_hnsw_oram_upload_bundle(
    bundle: &PrivateHnswOramUploadBundle,
) -> Result<Vec<String>, PrivateHnswOramError> {
    let manifest = &bundle.manifest;
    validate_private_hnsw_oram_manifest_shape(manifest)?;
    validate_private_hnsw_oram_manifest_signature_shape(&bundle.manifest_signature)?;
    if bundle.manifest_signature.key_id != manifest.owner_signing_key_id {
        return Err(PrivateHnswOramError::SignatureKeyIdMismatch);
    }
    let bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
    if bundle.buckets.len() != bucket_count {
        return Err(PrivateHnswOramError::InvalidManifestField("bucket_count"));
    }

    let max_ciphertext_bytes = private_hnsw_oram_upload_max_ciphertext_bytes(manifest)?;
    let expected_ciphertext_bytes = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)?;
    let validation_context =
        PrivateHnswOramBucketValidationContext::from_manifest(manifest, max_ciphertext_bytes);
    let mut commitments = Vec::with_capacity(bundle.buckets.len());
    for (expected_bucket_id, bucket) in bundle.buckets.iter().enumerate() {
        let expected_bucket_id = u64::try_from(expected_bucket_id)
            .map_err(|_| PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
        if bucket.bucket_id != expected_bucket_id {
            return Err(PrivateHnswOramError::InvalidBucketField("bucket_id"));
        }
        validate_private_hnsw_oram_bucket_shape(bucket, validation_context)?;
        validate_private_hnsw_oram_bucket_ciphertext_fixed_size(bucket, expected_ciphertext_bytes)?;
        let expected_commitment = private_hnsw_oram_bucket_commitment(
            PrivateHnswOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: manifest.index_epoch,
            },
            &bucket.ciphertext_sha256,
        )?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(PrivateHnswOramError::InvalidBucketCommitment);
        }
        commitments.push(bucket.bucket_commitment.clone());
    }
    if private_hnsw_oram_merkle_root_for_commitments(&commitments)? != manifest.root_hash {
        return Err(PrivateHnswOramError::MerkleRootMismatch);
    }
    Ok(commitments)
}

pub fn validate_private_hnsw_oram_upload_bundle_with_signature(
    bundle: &PrivateHnswOramUploadBundle,
    validation_context: PrivateHnswManifestValidationContext<'_>,
) -> Result<Vec<String>, PrivateHnswOramError> {
    let commitments = validate_private_hnsw_oram_upload_bundle(bundle)?;
    validate_private_hnsw_oram_manifest(
        &bundle.manifest,
        Some(&bundle.manifest_signature),
        validation_context,
    )?;
    Ok(commitments)
}

pub fn plan_private_hnsw_oram_commit(
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
) -> Result<PrivateHnswOramCommitPlan, PrivateHnswOramError> {
    if Some(new_epoch) != old_epoch.checked_add(1) {
        return Err(PrivateHnswOramError::InvalidManifestField("new_epoch"));
    }
    if updated_buckets.is_empty() {
        return Err(PrivateHnswOramError::EmptyCommit);
    }
    if private_hnsw_oram_merkle_root_for_commitments(current_leaf_commitments)? != old_root_hash {
        return Err(PrivateHnswOramError::MerkleRootMismatch);
    }

    let bucket_count = u64::try_from(current_leaf_commitments.len())
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
    let mut next_leaf_commitments = current_leaf_commitments.to_vec();
    let mut seen_bucket_ids = BTreeSet::new();
    let mut commit_bucket_refs = Vec::with_capacity(updated_buckets.len());

    for bucket in updated_buckets {
        if bucket.version != PRIVATE_HNSW_ORAM_BUCKET_VERSION {
            return Err(PrivateHnswOramError::UnsupportedBucketVersion(
                bucket.version,
            ));
        }
        if bucket.index_epoch != new_epoch {
            return Err(PrivateHnswOramError::StaleBucketEpoch {
                bucket_id: bucket.bucket_id,
                expected_epoch: new_epoch,
                actual_epoch: bucket.index_epoch,
            });
        }
        if bucket.bucket_id >= bucket_count {
            return Err(PrivateHnswOramError::BucketOutOfRange {
                bucket_id: bucket.bucket_id,
                bucket_count,
            });
        }
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateHnswOramError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
            .map_err(|_| PrivateHnswOramError::InvalidBucketField("ciphertext_sha256"))?;
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .map_err(|_| PrivateHnswOramError::InvalidBucketField("ciphertext"))?;
        if base64url_sha256(&raw_ciphertext) != bucket.ciphertext_sha256 {
            return Err(PrivateHnswOramError::InvalidBucketHash);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;

        let bucket_index = usize::try_from(bucket.bucket_id)
            .map_err(|_| PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
        next_leaf_commitments[bucket_index] = bucket.bucket_commitment.clone();
        commit_bucket_refs.push(PrivateHnswOramClientCommitBucketRef {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        });
    }

    let new_root_hash = private_hnsw_oram_merkle_root_for_commitments(&next_leaf_commitments)?;
    Ok(PrivateHnswOramCommitPlan {
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
) -> Result<PrivateHnswOramCommitPlan, PrivateHnswOramError> {
    plan_private_hnsw_oram_commit_for_manifest_context(
        manifest,
        manifest.index_epoch,
        new_epoch,
        &manifest.root_hash,
        current_leaf_commitments,
        updated_buckets,
    )
}

/// Plans a commit whose writeback budget is derived from the manifest's fixed search budget
/// (one full fixed-budget search per commit). Use
/// [`plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths`] when the session read
/// a different number of paths.
pub fn plan_private_hnsw_oram_commit_for_manifest_context(
    manifest: &PrivateHnswOramManifest,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
) -> Result<PrivateHnswOramCommitPlan, PrivateHnswOramError> {
    validate_private_hnsw_oram_manifest_shape(manifest)?;
    let read_path_count = private_hnsw_oram_fixed_search_read_path_count(manifest)?;
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
/// [`private_hnsw_oram_session_writeback_bucket_budget`].
pub fn plan_private_hnsw_oram_commit_for_manifest_context_with_read_paths(
    manifest: &PrivateHnswOramManifest,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
    read_path_count: usize,
) -> Result<PrivateHnswOramCommitPlan, PrivateHnswOramError> {
    validate_private_hnsw_oram_manifest_shape(manifest)?;
    let manifest_bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
    if current_leaf_commitments.len() != manifest_bucket_count {
        return Err(PrivateHnswOramError::InvalidManifestField("bucket_count"));
    }
    if Some(new_epoch) != old_epoch.checked_add(1) {
        return Err(PrivateHnswOramError::InvalidManifestField("new_epoch"));
    }
    if updated_buckets.is_empty() {
        return Err(PrivateHnswOramError::EmptyCommit);
    }
    let max_updated_buckets =
        private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, read_path_count)?;
    if updated_buckets.len() > max_updated_buckets {
        return Err(PrivateHnswOramError::InvalidFetchPlanField(
            "updated_buckets",
        ));
    }
    if private_hnsw_oram_merkle_root_for_commitments(current_leaf_commitments)? != old_root_hash {
        return Err(PrivateHnswOramError::MerkleRootMismatch);
    }

    let max_ciphertext_bytes = private_hnsw_oram_upload_max_ciphertext_bytes(manifest)?;
    let expected_ciphertext_bytes = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)?;
    for bucket in updated_buckets {
        validate_private_hnsw_oram_bucket_ciphertext_fixed_size(bucket, expected_ciphertext_bytes)?;
        validate_private_hnsw_oram_bucket_shape(
            bucket,
            PrivateHnswOramBucketValidationContext {
                expected_index_epoch: new_epoch,
                bucket_count: manifest.bucket_count,
                max_ciphertext_bytes,
            },
        )?;
        let expected_commitment = private_hnsw_oram_bucket_commitment(
            PrivateHnswOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: new_epoch,
            },
            &bucket.ciphertext_sha256,
        )?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(PrivateHnswOramError::InvalidBucketCommitment);
        }
    }
    plan_private_hnsw_oram_commit(
        old_epoch,
        new_epoch,
        old_root_hash,
        current_leaf_commitments,
        updated_buckets,
    )
}

pub fn refresh_private_hnsw_oram_manifest_for_commit(
    manifest: &PrivateHnswOramManifest,
    plan: &PrivateHnswOramCommitPlan,
) -> Result<PrivateHnswOramManifest, PrivateHnswOramError> {
    validate_private_hnsw_oram_manifest_shape(manifest)?;
    if manifest.index_epoch != plan.old_epoch || manifest.root_hash != plan.old_root_hash {
        return Err(PrivateHnswOramError::ManifestCommitMismatch);
    }
    if Some(plan.new_epoch) != plan.old_epoch.checked_add(1) {
        return Err(PrivateHnswOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(&plan.new_root_hash, "root_hash")?;

    let mut refreshed = manifest.clone();
    refreshed.index_epoch = plan.new_epoch;
    refreshed.root_hash = plan.new_root_hash.clone();
    Ok(refreshed)
}

pub fn sign_private_hnsw_oram_manifest_refresh(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
    plan: &PrivateHnswOramCommitPlan,
) -> Result<(PrivateHnswOramManifest, PrivateHnswOramSignature), PrivateHnswOramError> {
    let refreshed = refresh_private_hnsw_oram_manifest_for_commit(manifest, plan)?;
    let signature = sign_private_hnsw_oram_manifest(key_pair, &refreshed)?;
    Ok((refreshed, signature))
}

pub fn try_private_hnsw_oram_manifest_signature_message(
    manifest: &PrivateHnswOramManifest,
) -> Result<Vec<u8>, PrivateHnswOramError> {
    validate_manifest_shape(manifest)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidManifestField("signature_message"),
    )?;
    push_u16(&mut message, manifest.version);
    try_push_str(&mut message, &manifest.provider, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.binding, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.collection_id, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.vector_name, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.key_id, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.rk_id, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u64(&mut message, manifest.rk_epoch);
    push_u32(&mut message, manifest.dim);
    try_push_str(&mut message, manifest.distance.as_str(), || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u32(&mut message, manifest.hnsw.m);
    push_u32(&mut message, manifest.hnsw.ef_construction);
    push_u32(&mut message, manifest.hnsw.max_layers);
    push_u32(&mut message, manifest.hnsw.fixed_neighbor_slots);
    try_push_str(&mut message, manifest.oram.kind.as_str(), || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u32(&mut message, manifest.oram.bucket_size);
    push_u32(&mut message, manifest.oram.block_size_bytes);
    push_u32(&mut message, manifest.oram.tree_height);
    push_u32(&mut message, manifest.oram.path_batch_size);
    push_bool(&mut message, manifest.fixed_budget.enabled);
    push_u32(&mut message, manifest.fixed_budget.upper_layer_steps);
    push_u32(&mut message, manifest.fixed_budget.base_layer_steps);
    push_u32(&mut message, manifest.fixed_budget.paths_per_round);
    push_u32(&mut message, manifest.fixed_budget.fixed_result_k);
    push_u64(&mut message, manifest.index_epoch);
    try_push_str(&mut message, &manifest.root_hash, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u64(&mut message, manifest.bucket_count);
    push_u64(&mut message, manifest.logical_node_count);
    push_u64(&mut message, manifest.dummy_node_count);
    try_push_str(&mut message, manifest.result_privacy.as_str(), || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    Ok(message)
}

pub fn try_private_hnsw_oram_read_paths_signature_message(
    input: PrivateHnswOramReadPathsSignatureInput<'_>,
) -> Result<Vec<u8>, PrivateHnswOramError> {
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    validate_private_hnsw_oram_read_paths_signature_shape(input)?;
    validate_signature_message_header_shape(input.signature_alg, input.signature_key_id)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_READ_PATHS_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidReadPathsSignature,
    )?;
    try_push_str(&mut message, input.collection_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.vector_name, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.key_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.rk_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.index_epoch);
    try_push_str(&mut message, input.root_hash, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    let path_count = u32::try_from(input.paths.len())
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    push_u32(&mut message, path_count);
    for path in input.paths {
        try_push_str(&mut message, path, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })?;
    }
    push_u32(&mut message, input.requested_paths);
    push_bool(&mut message, input.dummy_paths_included);
    try_push_str(&mut message, input.signature_alg, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.signature_key_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    Ok(message)
}

fn validate_private_hnsw_oram_read_paths_signature_shape(
    input: PrivateHnswOramReadPathsSignatureInput<'_>,
) -> Result<(), PrivateHnswOramError> {
    decode_base64url_32(input.root_hash, "root_hash")?;
    let requested_paths_len: usize = input
        .requested_paths
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    if input.paths.is_empty()
        || input.requested_paths == 0
        || u32::try_from(input.paths.len()).is_err()
        || requested_paths_len != input.paths.len()
        || !input.dummy_paths_included
    {
        return Err(PrivateHnswOramError::InvalidReadPathsSignature);
    }
    let mut seen_paths = BTreeSet::new();
    for path in input.paths {
        decode_base64url_8(path).map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
        if !seen_paths.insert(*path) {
            return Err(PrivateHnswOramError::InvalidReadPathsSignature);
        }
    }
    Ok(())
}

pub fn try_private_hnsw_oram_commit_signature_message(
    input: PrivateHnswOramCommitSignatureInput<'_>,
) -> Result<Vec<u8>, PrivateHnswOramError> {
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    validate_private_hnsw_oram_commit_signature_shape(input)?;
    validate_signature_message_header_shape(input.signature_alg, input.signature_key_id)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidCommitSignature,
    )?;
    try_push_str(&mut message, input.collection_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.vector_name, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.key_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.rk_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.old_epoch);
    push_u64(&mut message, input.new_epoch);
    try_push_str(&mut message, input.old_root_hash, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.new_root_hash, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    let updated_bucket_count = u32::try_from(input.updated_buckets.len())
        .map_err(|_| PrivateHnswOramError::InvalidCommitSignature)?;
    push_u32(&mut message, updated_bucket_count);
    for bucket in input.updated_buckets {
        push_u64(&mut message, bucket.bucket_id);
        try_push_str(&mut message, bucket.ciphertext_sha256, || {
            PrivateHnswOramError::InvalidCommitSignature
        })?;
    }
    try_push_str(&mut message, input.signature_alg, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.signature_key_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    Ok(message)
}

pub fn private_hnsw_oram_writeback_digest(
    input: PrivateHnswOramCommitSignatureInput<'_>,
) -> Result<String, PrivateHnswOramError> {
    let message = try_private_hnsw_oram_commit_signature_message(input)?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn validate_private_hnsw_oram_commit_signature_shape(
    input: PrivateHnswOramCommitSignatureInput<'_>,
) -> Result<(), PrivateHnswOramError> {
    if input.updated_buckets.is_empty() {
        return Err(PrivateHnswOramError::EmptyCommit);
    }
    if u32::try_from(input.updated_buckets.len()).is_err() {
        return Err(PrivateHnswOramError::InvalidCommitSignature);
    }
    if Some(input.new_epoch) != input.old_epoch.checked_add(1) {
        return Err(PrivateHnswOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(input.old_root_hash, "old_root_hash")?;
    decode_base64url_32(input.new_root_hash, "new_root_hash")?;
    let mut seen_bucket_ids = BTreeSet::new();
    for bucket in input.updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateHnswOramError::InvalidCommitSignature);
        }
        decode_base64url_32(bucket.ciphertext_sha256, "ciphertext_sha256")?;
    }
    Ok(())
}

pub fn validate_private_hnsw_oram_bucket_shape(
    bucket: &PrivateHnswOramBucket,
    context: PrivateHnswOramBucketValidationContext,
) -> Result<(), PrivateHnswOramError> {
    if bucket.version != PRIVATE_HNSW_ORAM_BUCKET_VERSION {
        return Err(PrivateHnswOramError::UnsupportedBucketVersion(
            bucket.version,
        ));
    }
    if bucket.bucket_id >= context.bucket_count {
        return Err(PrivateHnswOramError::BucketOutOfRange {
            bucket_id: bucket.bucket_id,
            bucket_count: context.bucket_count,
        });
    }
    if bucket.index_epoch != context.expected_index_epoch {
        return Err(PrivateHnswOramError::InvalidBucketField("index_epoch"));
    }
    let max_ciphertext_b64_len = max_base64url_nopad_encoded_len(context.max_ciphertext_bytes)
        .ok_or(PrivateHnswOramError::InvalidBucketField(
            "max_ciphertext_bytes",
        ))?;
    if bucket.ciphertext.len() > max_ciphertext_b64_len {
        return Err(PrivateHnswOramError::BucketOversized);
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateHnswOramError::InvalidBucketField("ciphertext"))?;
    if ciphertext.len() > context.max_ciphertext_bytes {
        return Err(PrivateHnswOramError::BucketOversized);
    }
    let ciphertext_hash = decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
        .map_err(|_| PrivateHnswOramError::InvalidBucketField("ciphertext_sha256"))?;
    let computed_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    if computed_hash != ciphertext_hash {
        return Err(PrivateHnswOramError::InvalidBucketHash);
    }
    decode_bucket_commitment(&bucket.bucket_commitment)?;
    Ok(())
}

fn validate_private_hnsw_oram_bucket_ciphertext_fixed_size(
    bucket: &PrivateHnswOramBucket,
    expected_ciphertext_bytes: usize,
) -> Result<(), PrivateHnswOramError> {
    let Some(expected_encoded_len) = max_base64url_nopad_encoded_len(expected_ciphertext_bytes)
    else {
        return Err(PrivateHnswOramError::InvalidBucketField("ciphertext"));
    };
    if bucket.ciphertext.len() != expected_encoded_len {
        return Err(PrivateHnswOramError::InvalidBucketField("ciphertext"));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateHnswOramError::InvalidBucketField("ciphertext"))?;
    if ciphertext.len() != expected_ciphertext_bytes {
        return Err(PrivateHnswOramError::InvalidBucketField("ciphertext"));
    }
    Ok(())
}

/// Pre-decode ceiling for uploaded and written-back bucket ciphertexts. Every bucket must have
/// exactly the fixed size, so the ceiling is that size: the former `bucket_size * block_size +
/// 4096` heuristic fell below the fixed size for `bucket_size > 4053` and rejected every
/// well-formed bucket of such a layout.
fn private_hnsw_oram_upload_max_ciphertext_bytes(
    manifest: &PrivateHnswOramManifest,
) -> Result<usize, PrivateHnswOramError> {
    private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
}

pub fn private_hnsw_oram_bucket_commitment(
    context: PrivateHnswOramBucketCommitmentContext<'_>,
    ciphertext_sha256: &str,
) -> Result<String, PrivateHnswOramError> {
    validate_id(context.collection_id, "collection_id")
        .map_err(|_| PrivateHnswOramError::InvalidBucketContext("collection_id"))?;
    validate_vector_name(context.vector_name)
        .map_err(|_| PrivateHnswOramError::InvalidBucketContext("vector_name"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswOramError::InvalidBucketContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswOramError::InvalidBucketContext("rk_id"))?;
    let ciphertext_sha256 = decode_base64url_32(ciphertext_sha256, "ciphertext_sha256")
        .map_err(|_| PrivateHnswOramError::InvalidBucketField("ciphertext_sha256"))?;

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_BUCKET_COMMITMENT_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidBucketContext("context_length"),
    )?;
    push_bucket_context_str(&mut message, context.collection_id)?;
    push_bucket_context_str(&mut message, context.vector_name)?;
    push_bucket_context_str(&mut message, context.key_id)?;
    push_bucket_context_str(&mut message, context.rk_id)?;
    push_u64(&mut message, context.rk_epoch);
    push_u64(&mut message, context.bucket_id);
    push_u64(&mut message, context.index_epoch);
    message.extend_from_slice(&ciphertext_sha256);
    Ok(BASE64URL_NOPAD.encode(Sha256::digest(&message).as_ref()))
}

pub fn private_hnsw_oram_fixed_writeback_bucket_budget(
    oram: &OramParams,
) -> Result<usize, PrivateHnswOramError> {
    let path_len = private_hnsw_oram_path_len(oram.tree_height)?;
    let path_batch_size = usize::try_from(oram.path_batch_size)
        .map_err(|_| PrivateHnswOramError::InvalidFetchPlanField("path_batch_size"))?;
    if path_batch_size == 0 {
        return Err(PrivateHnswOramError::InvalidFetchPlanField(
            "path_batch_size",
        ));
    }
    path_len
        .checked_mul(path_batch_size)
        .ok_or(PrivateHnswOramError::InvalidFetchPlanField(
            "updated_buckets",
        ))
}

/// Writeback budget for a session that has read `read_path_count` ORAM paths.
///
/// A client can only legitimately rewrite buckets that lie on paths it read during the session,
/// so the bound is one path worth of buckets per read path. It never drops below a single fixed
/// read round (`path_batch_size` paths) and never exceeds the tree itself.
pub fn private_hnsw_oram_session_writeback_bucket_budget(
    oram: &OramParams,
    read_path_count: usize,
) -> Result<usize, PrivateHnswOramError> {
    let path_len = private_hnsw_oram_path_len(oram.tree_height)?;
    let round_budget = private_hnsw_oram_fixed_writeback_bucket_budget(oram)?;
    let bucket_count = path_oram_bucket_count(oram.tree_height)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    let session_budget = path_len.saturating_mul(read_path_count);
    Ok(round_budget.max(session_budget).min(bucket_count))
}

/// Number of ORAM paths a fixed-budget search reads: every upper- and base-layer step accesses
/// exactly one path, and the whole search is written back in a single commit.
pub fn private_hnsw_oram_fixed_search_read_path_count(
    manifest: &PrivateHnswOramManifest,
) -> Result<usize, PrivateHnswOramError> {
    manifest
        .fixed_budget
        .upper_layer_steps
        .checked_add(manifest.fixed_budget.base_layer_steps)
        .and_then(|steps| usize::try_from(steps).ok())
        .ok_or(PrivateHnswOramError::InvalidManifestField("fixed_budget"))
}

pub fn private_hnsw_oram_merkle_root_for_commitments(
    commitments: &[String],
) -> Result<String, PrivateHnswOramError> {
    let levels = private_hnsw_oram_merkle_levels(commitments)?;
    let root = levels
        .last()
        .and_then(|level| level.first())
        .ok_or(PrivateHnswOramError::EmptyMerkleTree)?;
    Ok(BASE64URL_NOPAD.encode(root))
}

fn validate_manifest_shape(manifest: &PrivateHnswOramManifest) -> Result<(), PrivateHnswOramError> {
    if manifest.version != PRIVATE_HNSW_ORAM_MANIFEST_VERSION {
        return Err(PrivateHnswOramError::UnsupportedManifestVersion(
            manifest.version,
        ));
    }
    if manifest.provider != VECTOR_PRIVATE_HNSW_ORAM_PROVIDER {
        return Err(PrivateHnswOramError::InvalidProvider);
    }
    if manifest.binding != PRIVATE_HNSW_ORAM_BINDING {
        return Err(PrivateHnswOramError::InvalidBinding);
    }
    validate_id(&manifest.collection_id, "collection_id")?;
    validate_vector_name(&manifest.vector_name)?;
    validate_resource_id(&manifest.key_id)?;
    validate_resource_id(&manifest.rk_id)?;
    validate_resource_id(&manifest.owner_signing_key_id)?;
    if manifest.dim == 0 {
        return Err(PrivateHnswOramError::InvalidManifestField("dim"));
    }
    if manifest.hnsw.m == 0
        || manifest.hnsw.ef_construction == 0
        || manifest.hnsw.max_layers == 0
        || manifest.hnsw.fixed_neighbor_slots < manifest.hnsw.m
    {
        return Err(PrivateHnswOramError::InvalidManifestField("hnsw"));
    }
    if manifest.oram.bucket_size == 0
        || manifest.oram.block_size_bytes == 0
        || manifest.oram.tree_height == 0
        || manifest.oram.path_batch_size == 0
    {
        return Err(PrivateHnswOramError::InvalidManifestField("oram"));
    }
    let min_node_block_bytes =
        private_hnsw_min_f32_node_block_bytes(manifest.dim, manifest.hnsw.fixed_neighbor_slots)
            .ok_or(PrivateHnswOramError::InvalidManifestField(
                "oram.block_size_bytes",
            ))?;
    if u64::from(manifest.oram.block_size_bytes) < min_node_block_bytes {
        return Err(PrivateHnswOramError::InvalidManifestField(
            "oram.block_size_bytes",
        ));
    }
    if !manifest.fixed_budget.enabled
        || manifest.fixed_budget.upper_layer_steps == 0
        || manifest.fixed_budget.base_layer_steps == 0
        || manifest.fixed_budget.paths_per_round == 0
        || manifest.fixed_budget.fixed_result_k == 0
    {
        return Err(PrivateHnswOramError::InvalidManifestField("fixed_budget"));
    }
    if manifest.bucket_count == 0 {
        return Err(PrivateHnswOramError::InvalidManifestField("bucket_count"));
    }
    let leaf_count = path_oram_leaf_count(manifest.oram.tree_height)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    if u64::from(manifest.oram.path_batch_size) > leaf_count {
        return Err(PrivateHnswOramError::InvalidManifestField(
            "oram.path_batch_size",
        ));
    }
    if manifest.fixed_budget.paths_per_round != manifest.oram.path_batch_size {
        return Err(PrivateHnswOramError::InvalidManifestField(
            "fixed_budget.paths_per_round",
        ));
    }
    let expected_bucket_count = path_oram_bucket_count(manifest.oram.tree_height)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    if manifest.bucket_count != expected_bucket_count {
        return Err(PrivateHnswOramError::InvalidManifestField("bucket_count"));
    }
    let capacity = manifest
        .bucket_count
        .checked_mul(u64::from(manifest.oram.bucket_size))
        .ok_or(PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
    let node_count = manifest
        .logical_node_count
        .checked_add(manifest.dummy_node_count)
        .ok_or(PrivateHnswOramError::InvalidManifestField("node_count"))?;
    if node_count > capacity {
        return Err(PrivateHnswOramError::InvalidManifestField("node_count"));
    }
    decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(())
}

fn path_oram_bucket_count(tree_height: u32) -> Option<u64> {
    path_oram_leaf_count(tree_height)?
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
}

fn path_oram_leaf_count(tree_height: u32) -> Option<u64> {
    if tree_height >= 63 {
        return None;
    }
    Some(1u64 << tree_height)
}

fn private_hnsw_oram_path_len(tree_height: u32) -> Result<usize, PrivateHnswOramError> {
    path_oram_leaf_count(tree_height)
        .filter(|_| tree_height > 0)
        .ok_or(PrivateHnswOramError::InvalidFetchPlanField("tree_height"))?;
    usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or(PrivateHnswOramError::InvalidFetchPlanField("tree_height"))
}

fn validate_manifest_context(
    manifest: &PrivateHnswOramManifest,
    context: PrivateHnswManifestValidationContext<'_>,
) -> Result<(), PrivateHnswOramError> {
    if manifest.collection_id != context.expected_collection_id {
        return Err(PrivateHnswOramError::ManifestContextMismatch(
            "collection_id",
        ));
    }
    if manifest.vector_name != context.expected_vector_name {
        return Err(PrivateHnswOramError::ManifestContextMismatch("vector_name"));
    }
    if manifest.key_id != context.expected_key_id {
        return Err(PrivateHnswOramError::ManifestContextMismatch("key_id"));
    }
    if manifest.rk_id != context.expected_rk_id {
        return Err(PrivateHnswOramError::ManifestContextMismatch("rk_id"));
    }
    if manifest.rk_epoch < context.min_rk_epoch || manifest.rk_epoch > context.max_rk_epoch {
        return Err(PrivateHnswOramError::ManifestContextMismatch("rk_epoch"));
    }
    if manifest.dim != context.expected_dim {
        return Err(PrivateHnswOramError::ManifestContextMismatch("dim"));
    }
    if manifest.distance != context.expected_distance {
        return Err(PrivateHnswOramError::ManifestContextMismatch("distance"));
    }
    Ok(())
}

fn validate_signature_header(
    signature: &PrivateHnswOramSignature,
    expected_owner_key_id: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_fields(&signature.alg, &signature.key_id, verification)?;
    if signature.key_id != expected_owner_key_id {
        return Err(PrivateHnswOramError::SignatureKeyIdMismatch);
    }
    Ok(())
}

fn validate_signature_fields(
    alg: &str,
    key_id: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_message_header_shape(alg, key_id)?;
    if key_id != verification.expected_key_id {
        return Err(PrivateHnswOramError::SignatureKeyIdMismatch);
    }
    if verification.public_key.len() != 32 {
        return Err(PrivateHnswOramError::MalformedSignature);
    }
    Ok(())
}

fn validate_signature_message_header_shape(
    alg: &str,
    key_id: &str,
) -> Result<(), PrivateHnswOramError> {
    if alg != PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
            alg.to_string(),
        ));
    }
    validate_resource_id(key_id)
}

fn validate_signature_input_context(
    collection_id: &str,
    vector_name: Option<&str>,
    key_id: &str,
    rk_id: &str,
) -> Result<(), PrivateHnswOramError> {
    validate_id(collection_id, "collection_id")?;
    if let Some(vector_name) = vector_name {
        validate_vector_name(vector_name)?;
    }
    validate_resource_id(key_id)?;
    validate_resource_id(rk_id)?;
    Ok(())
}

fn validate_id(value: &str, field: &'static str) -> Result<(), PrivateHnswOramError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(PrivateHnswOramError::InvalidManifestField(field));
    }
    Ok(())
}

fn validate_vector_name(value: &str) -> Result<(), PrivateHnswOramError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || vector_name_is_client_owned_oram_state_alias(value)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(PrivateHnswOramError::InvalidManifestField("vector_name"));
    }
    Ok(())
}

fn vector_name_is_client_owned_oram_state_alias(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let compact_value = value.replace(['_', '-', '.'], "");
    if compact_vector_name_is_client_owned_oram_state_alias(&compact_value) {
        return true;
    }
    let Some((stem, _extension)) = value.rsplit_once('.') else {
        return false;
    };
    compact_vector_name_is_client_owned_oram_state_alias(&stem.replace(['_', '-', '.'], ""))
}

fn compact_vector_name_is_client_owned_oram_state_alias(value: &str) -> bool {
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
            | "positionmaps"
            | "positionmapbackup"
            | "positionmapbackups"
            | "positionmapsnapshot"
            | "positionmapsnapshots"
            | "orampositionmap"
            | "orampositionmaps"
            | "orampositionmapbackup"
            | "orampositionmapbackups"
            | "orampositionmapsnapshot"
            | "orampositionmapsnapshots"
            | "tokenmap"
            | "tokenmaps"
            | "tokenmapbackup"
            | "tokenmapbackups"
            | "tokenmapsnapshot"
            | "tokenmapsnapshots"
            | "tokenpositionmap"
            | "tokenpositionmaps"
            | "tokenpositionmapbackup"
            | "tokenpositionmapbackups"
            | "tokenpositionmapsnapshot"
            | "tokenpositionmapsnapshots"
            | "stash"
            | "stashbackup"
            | "stashbackups"
            | "stashsnapshot"
            | "stashsnapshots"
    )
}

fn validate_resource_id(value: &str) -> Result<(), PrivateHnswOramError> {
    validate_resource_key_id(value).map_err(|_| PrivateHnswOramError::InvalidResourceKeyId)
}

fn decode_base64url_32(value: &str, field: &'static str) -> Result<[u8; 32], PrivateHnswOramError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswOramError::InvalidManifestField(field));
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswOramError::InvalidManifestField(field))?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidManifestField(field))
}

fn decode_base64url_8(value: &str) -> Result<[u8; 8], PrivateHnswOramError> {
    if value.len() != BASE64URL_NOPAD_8_BYTE_LEN {
        return Err(PrivateHnswOramError::InvalidReadPathsSignature);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)
}

fn decode_base64url_64(value: &str) -> Result<[u8; 64], PrivateHnswOramError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateHnswOramError::MalformedSignature);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswOramError::MalformedSignature)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswOramError::MalformedSignature)
}

fn decode_bucket_commitment(value: &str) -> Result<[u8; 32], PrivateHnswOramError> {
    decode_base64url_32(value, "bucket_commitment")
        .map_err(|_| PrivateHnswOramError::InvalidBucketField("bucket_commitment"))
}

fn max_base64url_nopad_encoded_len(byte_len: usize) -> Option<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => unreachable!(),
    };
    full_chunks.checked_mul(4)?.checked_add(tail_len)
}

fn private_hnsw_oram_merkle_levels(
    commitments: &[String],
) -> Result<Vec<Vec<[u8; 32]>>, PrivateHnswOramError> {
    if commitments.is_empty() {
        return Err(PrivateHnswOramError::EmptyMerkleTree);
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_bucket_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let padded_len = leaves
        .len()
        .checked_next_power_of_two()
        .ok_or(PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let current = levels.last().expect("level must exist");
        let mut next = Vec::with_capacity(current.len() / 2);
        for [left, right] in current.as_chunks::<2>().0 {
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

fn push_bucket_context_str(message: &mut Vec<u8>, value: &str) -> Result<(), PrivateHnswOramError> {
    let len: u32 = value
        .len()
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidBucketContext("context_length"))?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn try_push_domain(
    message: &mut Vec<u8>,
    value: &[u8],
    error: impl FnOnce() -> PrivateHnswOramError,
) -> Result<(), PrivateHnswOramError> {
    let len: u32 = value.len().try_into().map_err(|_| error())?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn try_push_str(
    message: &mut Vec<u8>,
    value: &str,
    error: impl FnOnce() -> PrivateHnswOramError,
) -> Result<(), PrivateHnswOramError> {
    let len: u64 = value.len().try_into().map_err(|_| error())?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_bool(message: &mut Vec<u8>, value: bool) {
    message.push(u8::from(value));
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
    use data_encoding::BASE64URL_NOPAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn private_hnsw_oram_error_display_does_not_reflect_structured_values() {
        let cases = [
            PrivateHnswOramError::UnsupportedManifestVersion(99).to_string(),
            PrivateHnswOramError::InvalidProvider.to_string(),
            PrivateHnswOramError::InvalidBinding.to_string(),
            PrivateHnswOramError::InvalidManifestField("manifest-field-sentinel").to_string(),
            PrivateHnswOramError::ManifestContextMismatch("manifest-context-sentinel").to_string(),
            PrivateHnswOramError::MissingManifestSignature.to_string(),
            PrivateHnswOramError::UnsupportedSignatureAlgorithm("rsa-pss-sentinel".to_string())
                .to_string(),
            PrivateHnswOramError::SignatureKeyIdMismatch.to_string(),
            PrivateHnswOramError::MalformedSignature.to_string(),
            PrivateHnswOramError::InvalidManifestSignature.to_string(),
            PrivateHnswOramError::InvalidCommitSignature.to_string(),
            PrivateHnswOramError::EmptyCommit.to_string(),
            PrivateHnswOramError::InvalidReadPathsSignature.to_string(),
            PrivateHnswOramError::InvalidResourceKeyId.to_string(),
            PrivateHnswOramError::UnsupportedBucketVersion(88).to_string(),
            PrivateHnswOramError::BucketOutOfRange {
                bucket_id: 123,
                bucket_count: 456,
            }
            .to_string(),
            PrivateHnswOramError::StaleBucketEpoch {
                bucket_id: 123,
                expected_epoch: 88,
                actual_epoch: 77,
            }
            .to_string(),
            PrivateHnswOramError::DuplicateUpdatedBucket { bucket_id: 123 }.to_string(),
            PrivateHnswOramError::InvalidBucketField("bucket-field-sentinel").to_string(),
            PrivateHnswOramError::BucketOversized.to_string(),
            PrivateHnswOramError::InvalidBucketHash.to_string(),
            PrivateHnswOramError::InvalidBucketCommitment.to_string(),
            PrivateHnswOramError::InvalidBucketContext("bucket-context-sentinel").to_string(),
            PrivateHnswOramError::InvalidFetchPlanField("fetch-plan-field-sentinel").to_string(),
            PrivateHnswOramError::EmptyMerkleTree.to_string(),
            PrivateHnswOramError::MerkleRootMismatch.to_string(),
            PrivateHnswOramError::ManifestCommitMismatch.to_string(),
        ];

        for rendered in cases {
            assert!(!rendered.contains("rsa-pss-sentinel"), "{rendered}");
            assert!(!rendered.contains("manifest-field-sentinel"), "{rendered}");
            assert!(!rendered.contains("bucket-field-sentinel"), "{rendered}");
            assert!(!rendered.contains("bucket-context-sentinel"), "{rendered}");
            assert!(
                !rendered.contains("fetch-plan-field-sentinel"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("manifest-context-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("99"), "{rendered}");
            assert!(!rendered.contains("88"), "{rendered}");
            assert!(!rendered.contains("77"), "{rendered}");
            assert!(!rendered.contains("123"), "{rendered}");
            assert!(!rendered.contains("456"), "{rendered}");
        }
    }

    #[test]
    fn private_hnsw_oram_error_debug_does_not_reflect_structured_values() {
        let cases = [
            format!("{:?}", PrivateHnswOramError::UnsupportedManifestVersion(99)),
            format!("{:?}", PrivateHnswOramError::InvalidProvider),
            format!("{:?}", PrivateHnswOramError::InvalidBinding),
            format!(
                "{:?}",
                PrivateHnswOramError::InvalidManifestField("manifest-field-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswOramError::ManifestContextMismatch("manifest-context-sentinel")
            ),
            format!("{:?}", PrivateHnswOramError::MissingManifestSignature),
            format!(
                "{:?}",
                PrivateHnswOramError::UnsupportedSignatureAlgorithm("rsa-pss-sentinel".to_string())
            ),
            format!("{:?}", PrivateHnswOramError::SignatureKeyIdMismatch),
            format!("{:?}", PrivateHnswOramError::MalformedSignature),
            format!("{:?}", PrivateHnswOramError::InvalidManifestSignature),
            format!("{:?}", PrivateHnswOramError::InvalidCommitSignature),
            format!("{:?}", PrivateHnswOramError::EmptyCommit),
            format!("{:?}", PrivateHnswOramError::InvalidReadPathsSignature),
            format!("{:?}", PrivateHnswOramError::InvalidResourceKeyId),
            format!("{:?}", PrivateHnswOramError::UnsupportedBucketVersion(88)),
            format!(
                "{:?}",
                PrivateHnswOramError::BucketOutOfRange {
                    bucket_id: 123,
                    bucket_count: 456,
                }
            ),
            format!(
                "{:?}",
                PrivateHnswOramError::StaleBucketEpoch {
                    bucket_id: 123,
                    expected_epoch: 88,
                    actual_epoch: 77,
                }
            ),
            format!(
                "{:?}",
                PrivateHnswOramError::DuplicateUpdatedBucket { bucket_id: 123 }
            ),
            format!(
                "{:?}",
                PrivateHnswOramError::InvalidBucketField("bucket-field-sentinel")
            ),
            format!("{:?}", PrivateHnswOramError::BucketOversized),
            format!("{:?}", PrivateHnswOramError::InvalidBucketHash),
            format!("{:?}", PrivateHnswOramError::InvalidBucketCommitment),
            format!(
                "{:?}",
                PrivateHnswOramError::InvalidBucketContext("bucket-context-sentinel")
            ),
            format!(
                "{:?}",
                PrivateHnswOramError::InvalidFetchPlanField("fetch-plan-field-sentinel")
            ),
            format!("{:?}", PrivateHnswOramError::EmptyMerkleTree),
            format!("{:?}", PrivateHnswOramError::MerkleRootMismatch),
            format!("{:?}", PrivateHnswOramError::ManifestCommitMismatch),
        ];

        for rendered in cases {
            assert!(!rendered.contains("rsa-pss-sentinel"), "{rendered}");
            assert!(!rendered.contains("manifest-field-sentinel"), "{rendered}");
            assert!(!rendered.contains("bucket-field-sentinel"), "{rendered}");
            assert!(!rendered.contains("bucket-context-sentinel"), "{rendered}");
            assert!(
                !rendered.contains("fetch-plan-field-sentinel"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("manifest-context-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("99"), "{rendered}");
            assert!(!rendered.contains("88"), "{rendered}");
            assert!(!rendered.contains("77"), "{rendered}");
            assert!(!rendered.contains("123"), "{rendered}");
            assert!(!rendered.contains("456"), "{rendered}");
        }
    }

    #[test]
    fn private_hnsw_debug_redacts_ciphertext_and_access_pattern_values() {
        let encrypted_bucket = PrivateHnswOramBucket {
            version: 1,
            bucket_id: 987_654,
            index_epoch: 42,
            ciphertext: "HNSW-CIPHERTEXT-SENTINEL".to_string(),
            ciphertext_sha256: "HNSW-SHA-SENTINEL".to_string(),
            bucket_commitment: "HNSW-COMMITMENT-SENTINEL".to_string(),
        };
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "HNSW-SIGNATURE-KEY-SENTINEL".to_string(),
            sig: "HNSW-SIGNATURE-SENTINEL".to_string(),
        };
        let mut manifest = fixture_manifest();
        manifest.collection_id = "HNSW-MANIFEST-COLLECTION-ID-SENTINEL".to_string();
        manifest.vector_name = "HNSW-MANIFEST-VECTOR-NAME-SENTINEL".to_string();
        manifest.key_id = "HNSW-MANIFEST-KEY-SENTINEL".to_string();
        manifest.rk_id = "HNSW-MANIFEST-RK-SENTINEL".to_string();
        manifest.owner_signing_key_id = "HNSW-MANIFEST-OWNER-SIGNING-KEY-SENTINEL".to_string();
        manifest.root_hash = "HNSW-MANIFEST-ROOT-SENTINEL".to_string();
        let updated_bucket = PrivateHnswOramCommitBucketRef {
            bucket_id: 987_654,
            ciphertext_sha256: "HNSW-SHA-SENTINEL",
        };
        let commit_refs = [updated_bucket];
        let commit_signature_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "HNSW-COMMIT-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-COMMIT-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-COMMIT-KEY-SENTINEL",
            rk_id: "HNSW-COMMIT-RK-SENTINEL",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: "HNSW-OLD-ROOT-SENTINEL",
            new_root_hash: "HNSW-NEW-ROOT-SENTINEL",
            updated_buckets: &commit_refs,
            signature_alg: "ed25519",
            signature_key_id: "HNSW-COMMIT-SIGNATURE-KEY-SENTINEL",
        };
        let paths = ["HNSW-PATH-LABEL-SENTINEL", "HNSW-PATH-LABEL-SENTINEL-2"];
        let read_paths_signature_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "HNSW-READ-COLLECTION-ID-SENTINEL",
            vector_name: "HNSW-READ-VECTOR-NAME-SENTINEL",
            key_id: "HNSW-READ-KEY-SENTINEL",
            rk_id: "HNSW-READ-RK-SENTINEL",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: "HNSW-ROOT-SENTINEL",
            paths: &paths,
            requested_paths: 77,
            dummy_paths_included: false,
            signature_alg: "ed25519",
            signature_key_id: "HNSW-READ-SIGNATURE-KEY-SENTINEL",
        };
        let validation_context = PrivateHnswManifestValidationContext {
            expected_collection_id: "HNSW-CONTEXT-COLLECTION-ID-SENTINEL",
            expected_vector_name: "HNSW-CONTEXT-VECTOR-NAME-SENTINEL",
            expected_key_id: "HNSW-CONTEXT-KEY-SENTINEL",
            expected_rk_id: "HNSW-CONTEXT-RK-SENTINEL",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            expected_dim: 1536,
            expected_distance: DistanceKind::Cosine,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: "HNSW-CONTEXT-SIGNATURE-KEY-SENTINEL",
                public_key: &[99; 32],
            },
        };
        let epoch = PrivateHnswEpoch {
            epoch: 42,
            root_hash: [77; 32],
        };

        let rendered = [
            format!("{encrypted_bucket:?}"),
            format!("{signature:?}"),
            format!("{manifest:?}"),
            format!("{:?}", commit_refs[0]),
            format!("{commit_signature_input:?}"),
            format!("{read_paths_signature_input:?}"),
            format!("{validation_context:?}"),
            format!("{epoch:?}"),
        ]
        .join("\n");
        let encrypted_bucket_rendered = format!("{encrypted_bucket:?}");
        assert!(!encrypted_bucket_rendered.contains("987654"));
        assert!(!encrypted_bucket_rendered.contains("42"));
        assert!(
            !encrypted_bucket_rendered.contains(&encrypted_bucket.ciphertext.len().to_string()),
            "{encrypted_bucket_rendered}"
        );
        for leaked in [
            "987654",
            "HNSW-CIPHERTEXT-SENTINEL",
            "HNSW-SHA-SENTINEL",
            "HNSW-COMMITMENT-SENTINEL",
            "HNSW-MANIFEST-COLLECTION-ID-SENTINEL",
            "HNSW-MANIFEST-VECTOR-NAME-SENTINEL",
            "HNSW-SIGNATURE-KEY-SENTINEL",
            "HNSW-SIGNATURE-SENTINEL",
            "HNSW-COMMIT-COLLECTION-ID-SENTINEL",
            "HNSW-COMMIT-VECTOR-NAME-SENTINEL",
            "HNSW-COMMIT-KEY-SENTINEL",
            "HNSW-COMMIT-RK-SENTINEL",
            "HNSW-COMMIT-SIGNATURE-KEY-SENTINEL",
            "HNSW-READ-COLLECTION-ID-SENTINEL",
            "HNSW-READ-VECTOR-NAME-SENTINEL",
            "HNSW-READ-KEY-SENTINEL",
            "HNSW-READ-RK-SENTINEL",
            "HNSW-READ-SIGNATURE-KEY-SENTINEL",
            "HNSW-CONTEXT-COLLECTION-ID-SENTINEL",
            "HNSW-CONTEXT-VECTOR-NAME-SENTINEL",
            "HNSW-CONTEXT-KEY-SENTINEL",
            "HNSW-CONTEXT-RK-SENTINEL",
            "HNSW-CONTEXT-SIGNATURE-KEY-SENTINEL",
            "[99, 99, 99",
            "[77, 77, 77",
            "HNSW-MANIFEST-KEY-SENTINEL",
            "HNSW-MANIFEST-RK-SENTINEL",
            "HNSW-MANIFEST-OWNER-SIGNING-KEY-SENTINEL",
            "HNSW-MANIFEST-ROOT-SENTINEL",
            "HNSW-OLD-ROOT-SENTINEL",
            "HNSW-NEW-ROOT-SENTINEL",
            "HNSW-ROOT-SENTINEL",
            "HNSW-PATH-LABEL-SENTINEL",
            "HNSW-PATH-LABEL-SENTINEL-2",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
        assert!(!rendered.contains("requested_paths: 77"), "{rendered}");
        assert!(
            !rendered.contains("dummy_paths_included: false"),
            "{rendered}"
        );
        assert!(!rendered.contains("updated_bucket_count: 1"), "{rendered}");
        assert!(!rendered.contains("path_count: 2"), "{rendered}");
    }

    fn fixture_manifest() -> PrivateHnswOramManifest {
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

    #[test]
    fn bucket_ciphertext_size_matches_path_oram_encoding_contract() {
        let mut manifest = fixture_manifest();
        manifest.oram.bucket_size = 4;
        manifest.oram.block_size_bytes = 8192;

        assert_eq!(
            private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            1 + 12 + 16 + 4 + 2 + 4 + 4 + 4 * (1 + 8192)
        );
    }

    #[test]
    fn upload_ciphertext_ceiling_is_the_fixed_bucket_size_for_every_layout() {
        let mut manifest = fixture_manifest();
        for bucket_size in [1u32, 4, 4053, 4054, 8192] {
            manifest.oram.bucket_size = bucket_size;
            let fixed = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
            assert_eq!(
                private_hnsw_oram_upload_max_ciphertext_bytes(&manifest).unwrap(),
                fixed,
                "bucket_size {bucket_size}"
            );
        }
        // The former heuristic (`bucket_size * block_size + 4096`) undercut the fixed size for
        // wide buckets and rejected every well-formed bucket of such a layout.
        manifest.oram.bucket_size = 4054;
        let fixed = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        assert!(fixed > 4054 * manifest.oram.block_size_bytes as usize + 4096);
    }

    #[test]
    fn upload_bundle_packages_signed_manifest_and_buckets() {
        let key_pair = deterministic_key_pair();
        let (manifest, buckets) = small_upload_bundle_fixture();
        let bundle =
            package_private_hnsw_oram_upload_bundle(&key_pair, manifest.clone(), buckets.clone())
                .unwrap();

        assert_eq!(bundle.index_epoch(), manifest.index_epoch);
        assert_eq!(bundle.root_hash(), manifest.root_hash);
        assert_eq!(bundle.bucket_count(), manifest.bucket_count);
        assert_eq!(bundle.bucket_commitments().len(), buckets.len());
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&bundle).unwrap(),
            bundle.bucket_commitments()
        );
        validate_private_hnsw_oram_upload_bundle_with_signature(
            &bundle,
            fixture_context(
                key_pair.public_key().as_ref(),
                &bundle.manifest_signature.key_id,
            ),
        )
        .unwrap();

        let mut wrong_signature_key = bundle.clone();
        wrong_signature_key.manifest_signature.key_id =
            "tenant-a/private-hnsw-signing-v2".to_string();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_signature_key),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );

        let mut incomplete = bundle.clone();
        incomplete.buckets.pop();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&incomplete),
            Err(PrivateHnswOramError::InvalidManifestField("bucket_count"))
        );

        let mut unordered = bundle.clone();
        unordered.buckets.swap(0, 1);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&unordered),
            Err(PrivateHnswOramError::InvalidBucketField("bucket_id"))
        );

        let mut wrong_hash = bundle.clone();
        wrong_hash.buckets[0].ciphertext_sha256 = BASE64URL_NOPAD.encode(&[9; 32]);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_hash),
            Err(PrivateHnswOramError::InvalidBucketHash)
        );

        let mut wrong_commitment = bundle.clone();
        wrong_commitment.buckets[0].bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&wrong_commitment),
            Err(PrivateHnswOramError::InvalidBucketCommitment)
        );

        let mut short_ciphertext = bundle.clone();
        short_ciphertext.buckets[0].ciphertext = BASE64URL_NOPAD.encode(&[7; 32]);
        short_ciphertext.buckets[0].ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest([7; 32]).as_ref());
        short_ciphertext.buckets[0].bucket_commitment = private_hnsw_oram_bucket_commitment(
            PrivateHnswOramBucketCommitmentContext {
                collection_id: &short_ciphertext.manifest.collection_id,
                vector_name: &short_ciphertext.manifest.vector_name,
                key_id: &short_ciphertext.manifest.key_id,
                rk_id: &short_ciphertext.manifest.rk_id,
                rk_epoch: short_ciphertext.manifest.rk_epoch,
                bucket_id: 0,
                index_epoch: short_ciphertext.manifest.index_epoch,
            },
            &short_ciphertext.buckets[0].ciphertext_sha256,
        )
        .unwrap();
        assert_eq!(
            validate_private_hnsw_oram_upload_bundle(&short_ciphertext),
            Err(PrivateHnswOramError::InvalidBucketField("ciphertext"))
        );

        let mut wrong_root = manifest;
        wrong_root.root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        assert_eq!(
            package_private_hnsw_oram_upload_bundle(&key_pair, wrong_root, buckets),
            Err(PrivateHnswOramError::MerkleRootMismatch)
        );
    }

    #[test]
    fn commit_plan_for_manifest_updates_root_and_resigns_manifest() {
        let key_pair = deterministic_key_pair();
        let (manifest, buckets) = small_upload_bundle_fixture();
        let leaf_commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let updated_bucket = fixture_upload_bucket(&manifest, 2, 43, 9);

        let plan = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        assert_eq!(plan.old_epoch, manifest.index_epoch);
        assert_eq!(plan.new_epoch, 43);
        assert_eq!(plan.old_root_hash, manifest.root_hash);
        assert_ne!(plan.new_root_hash, plan.old_root_hash);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);
        assert_eq!(
            plan.updated_buckets,
            vec![PrivateHnswOramClientCommitBucketRef {
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

        let refreshed = refresh_private_hnsw_oram_manifest_for_commit(&manifest, &plan).unwrap();
        assert_eq!(refreshed.index_epoch, plan.new_epoch);
        assert_eq!(refreshed.root_hash, plan.new_root_hash);
        assert_eq!(refreshed.collection_id, manifest.collection_id);
        assert_eq!(refreshed.vector_name, manifest.vector_name);
        assert_eq!(refreshed.bucket_count, manifest.bucket_count);

        let (signed_manifest, signature) =
            sign_private_hnsw_oram_manifest_refresh(&key_pair, &manifest, &plan).unwrap();
        assert_eq!(signed_manifest, refreshed);
        assert_eq!(signature.key_id, signed_manifest.owner_signing_key_id);
        let epoch = validate_private_hnsw_oram_manifest(
            &signed_manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: signed_manifest.dim,
                expected_distance: signed_manifest.distance,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: &signature.key_id,
                    public_key: key_pair.public_key().as_ref(),
                },
                expected_collection_id: &signed_manifest.collection_id,
                expected_vector_name: &signed_manifest.vector_name,
                expected_key_id: &signed_manifest.key_id,
                expected_rk_id: &signed_manifest.rk_id,
            },
        )
        .unwrap();
        assert_eq!(epoch.epoch, 43);
        assert_eq!(
            BASE64URL_NOPAD.encode(&epoch.root_hash),
            signed_manifest.root_hash
        );
    }

    #[test]
    fn commit_plan_rejects_stale_duplicate_out_of_range_and_context_mismatch() {
        let (manifest, buckets) = small_upload_bundle_fixture();
        let leaf_commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let updated_bucket = fixture_upload_bucket(&manifest, 2, 43, 9);

        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(&manifest, 43, &leaf_commitments, &[]),
            Err(PrivateHnswOramError::EmptyCommit)
        );

        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &manifest,
                43,
                &[BASE64URL_NOPAD.encode(&[99; 32])],
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateHnswOramError::InvalidManifestField("bucket_count"))
        );

        let stale_bucket = fixture_upload_bucket(&manifest, 2, 42, 9);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &manifest.root_hash,
                &leaf_commitments,
                std::slice::from_ref(&stale_bucket),
            ),
            Err(PrivateHnswOramError::StaleBucketEpoch {
                bucket_id: 2,
                expected_epoch: 43,
                actual_epoch: 42,
            })
        );

        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &manifest.root_hash,
                &leaf_commitments,
                &[updated_bucket.clone(), updated_bucket.clone()],
            ),
            Err(PrivateHnswOramError::DuplicateUpdatedBucket { bucket_id: 2 })
        );

        let out_of_range = fixture_upload_bucket(&manifest, 3, 43, 9);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &manifest.root_hash,
                &leaf_commitments,
                std::slice::from_ref(&out_of_range),
            ),
            Err(PrivateHnswOramError::BucketOutOfRange {
                bucket_id: 3,
                bucket_count: 3,
            })
        );

        let mut wrong_commitment = updated_bucket.clone();
        wrong_commitment.bucket_commitment = BASE64URL_NOPAD.encode(&[88; 32]);
        assert_eq!(
            plan_private_hnsw_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateHnswOramError::InvalidBucketCommitment)
        );

        let mut short_ciphertext = updated_bucket.clone();
        short_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&[7; 32]);
        short_ciphertext.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest([7; 32]).as_ref());
        short_ciphertext.bucket_commitment = private_hnsw_oram_bucket_commitment(
            PrivateHnswOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: short_ciphertext.bucket_id,
                index_epoch: short_ciphertext.index_epoch,
            },
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
            Err(PrivateHnswOramError::InvalidBucketField("ciphertext"))
        );

        let mut stale_plan = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();
        stale_plan.old_root_hash = BASE64URL_NOPAD.encode(&[77; 32]);
        assert_eq!(
            refresh_private_hnsw_oram_manifest_for_commit(&manifest, &stale_plan),
            Err(PrivateHnswOramError::ManifestCommitMismatch)
        );
    }

    #[test]
    fn commit_plan_for_manifest_rejects_oversized_fixed_writeback() {
        let mut manifest = small_upload_manifest();
        manifest.oram.tree_height = 2;
        manifest.oram.path_batch_size = 1;
        manifest.fixed_budget.paths_per_round = 1;
        manifest.bucket_count = 7;
        manifest.logical_node_count = 4;
        manifest.dummy_node_count = 0;
        let buckets = (0..manifest.bucket_count)
            .map(|bucket_id| {
                fixture_upload_bucket(
                    &manifest,
                    bucket_id,
                    manifest.index_epoch,
                    bucket_id as u8 + 1,
                )
            })
            .collect::<Vec<_>>();
        let leaf_commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        manifest.root_hash =
            private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let fixed_writeback_budget =
            private_hnsw_oram_fixed_writeback_bucket_budget(&manifest.oram).unwrap();
        assert_eq!(fixed_writeback_budget, 3);
        // One read round never buys more than a round, two rounds buy two paths, and the
        // budget is capped by the tree.
        assert_eq!(
            private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, 0).unwrap(),
            3
        );
        assert_eq!(
            private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, 2).unwrap(),
            6
        );
        assert_eq!(
            private_hnsw_oram_session_writeback_bucket_budget(&manifest.oram, 100).unwrap(),
            7
        );

        let updated_buckets = (0..=fixed_writeback_budget)
            .map(|bucket_id| {
                fixture_upload_bucket(&manifest, bucket_id as u64, 43, bucket_id as u8 + 9)
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
            Err(PrivateHnswOramError::InvalidFetchPlanField(
                "updated_buckets"
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

        // The manifest-derived planner budgets a whole fixed-budget search (all steps).
        let search_paths = private_hnsw_oram_fixed_search_read_path_count(&manifest).unwrap();
        assert_eq!(
            search_paths,
            (manifest.fixed_budget.upper_layer_steps + manifest.fixed_budget.base_layer_steps)
                as usize
        );
        assert!(search_paths > 1);
        let whole_search = plan_private_hnsw_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            &updated_buckets,
        )
        .unwrap();
        assert_eq!(whole_search.updated_buckets.len(), updated_buckets.len());
    }

    fn fixture_context<'a>(
        public_key: &'a [u8],
        key_id: &'a str,
    ) -> PrivateHnswManifestValidationContext<'a> {
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
                expected_key_id: key_id,
                public_key,
            },
        }
    }

    fn deterministic_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    fn sign_b64(key_pair: &Ed25519KeyPair, message: &[u8]) -> String {
        BASE64URL_NOPAD.encode(key_pair.sign(message).as_ref())
    }

    fn small_upload_manifest() -> PrivateHnswOramManifest {
        PrivateHnswOramManifest {
            oram: OramParams {
                tree_height: 1,
                path_batch_size: 2,
                ..fixture_manifest().oram
            },
            fixed_budget: FixedBudgetParams {
                paths_per_round: 2,
                ..fixture_manifest().fixed_budget
            },
            bucket_count: 3,
            logical_node_count: 3,
            dummy_node_count: 0,
            ..fixture_manifest()
        }
    }

    fn fixture_upload_bucket(
        manifest: &PrivateHnswOramManifest,
        bucket_id: u64,
        index_epoch: u64,
        byte: u8,
    ) -> PrivateHnswOramBucket {
        let ciphertext_len = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let ciphertext = vec![byte; ciphertext_len];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: private_hnsw_oram_bucket_commitment(
                PrivateHnswOramBucketCommitmentContext {
                    collection_id: &manifest.collection_id,
                    vector_name: &manifest.vector_name,
                    key_id: &manifest.key_id,
                    rk_id: &manifest.rk_id,
                    rk_epoch: manifest.rk_epoch,
                    bucket_id,
                    index_epoch,
                },
                &ciphertext_sha256,
            )
            .unwrap(),
        }
    }

    fn small_upload_bundle_fixture() -> (PrivateHnswOramManifest, Vec<PrivateHnswOramBucket>) {
        let mut manifest = small_upload_manifest();
        let buckets = (0..manifest.bucket_count)
            .map(|bucket_id| {
                fixture_upload_bucket(
                    &manifest,
                    bucket_id,
                    manifest.index_epoch,
                    bucket_id as u8 + 1,
                )
            })
            .collect::<Vec<_>>();
        manifest.root_hash = private_hnsw_oram_merkle_root_for_commitments(
            &buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        (manifest, buckets)
    }

    fn checked_manifest_signature_message(manifest: &PrivateHnswOramManifest) -> Vec<u8> {
        try_private_hnsw_oram_manifest_signature_message(manifest).unwrap()
    }

    fn checked_commit_signature_message(input: PrivateHnswOramCommitSignatureInput<'_>) -> Vec<u8> {
        try_private_hnsw_oram_commit_signature_message(input).unwrap()
    }

    fn unchecked_commit_signature_message(
        input: PrivateHnswOramCommitSignatureInput<'_>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        try_push_domain(
            &mut message,
            PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
            || PrivateHnswOramError::InvalidCommitSignature,
        )
        .unwrap();
        try_push_str(&mut message, input.collection_id, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.vector_name, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.key_id, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.rk_id, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        push_u64(&mut message, input.rk_epoch);
        push_u64(&mut message, input.old_epoch);
        push_u64(&mut message, input.new_epoch);
        try_push_str(&mut message, input.old_root_hash, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.new_root_hash, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        push_u32(
            &mut message,
            u32::try_from(input.updated_buckets.len()).unwrap(),
        );
        for bucket in input.updated_buckets {
            push_u64(&mut message, bucket.bucket_id);
            try_push_str(&mut message, bucket.ciphertext_sha256, || {
                PrivateHnswOramError::InvalidCommitSignature
            })
            .unwrap();
        }
        try_push_str(&mut message, input.signature_alg, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.signature_key_id, || {
            PrivateHnswOramError::InvalidCommitSignature
        })
        .unwrap();
        message
    }

    fn checked_read_paths_signature_message(
        input: PrivateHnswOramReadPathsSignatureInput<'_>,
    ) -> Vec<u8> {
        try_private_hnsw_oram_read_paths_signature_message(input).unwrap()
    }

    fn unchecked_read_paths_signature_message(
        input: PrivateHnswOramReadPathsSignatureInput<'_>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        try_push_domain(
            &mut message,
            PRIVATE_HNSW_ORAM_READ_PATHS_SIGNATURE_DOMAIN.as_bytes(),
            || PrivateHnswOramError::InvalidReadPathsSignature,
        )
        .unwrap();
        try_push_str(&mut message, input.collection_id, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.vector_name, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.key_id, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.rk_id, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        push_u64(&mut message, input.rk_epoch);
        push_u64(&mut message, input.index_epoch);
        try_push_str(&mut message, input.root_hash, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        push_u32(&mut message, u32::try_from(input.paths.len()).unwrap());
        for path in input.paths {
            try_push_str(&mut message, path, || {
                PrivateHnswOramError::InvalidReadPathsSignature
            })
            .unwrap();
        }
        push_u32(&mut message, input.requested_paths);
        push_bool(&mut message, input.dummy_paths_included);
        try_push_str(&mut message, input.signature_alg, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.signature_key_id, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })
        .unwrap();
        message
    }

    #[test]
    fn manifest_signature_message_is_stable() {
        let manifest = fixture_manifest();
        let digest = Sha256::digest(checked_manifest_signature_message(&manifest));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "1hzG6sGJ3RkYa_N_fB91X83CT5gF19sXnVxGdo2hiOQ"
        );
    }

    #[test]
    fn commit_signature_message_is_stable() {
        let buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };

        let digest = Sha256::digest(checked_commit_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "K7D-QZtqOp7EBdqB0idlNYPSzjPMcg_Uripj067shYQ"
        );
        assert_eq!(
            private_hnsw_oram_writeback_digest(input).unwrap(),
            "K7D-QZtqOp7EBdqB0idlNYPSzjPMcg_Uripj067shYQ"
        );
    }

    #[test]
    fn read_paths_signature_message_is_stable() {
        let paths = ["AAAAAAAAAAA", "AAAAAAAAAAE"];
        let input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 2,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };

        let digest = Sha256::digest(checked_read_paths_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "n_ChN7eT7j4hxnccWt9L4u65CYHUnOMr5K3f80SJTaA"
        );
    }

    #[test]
    fn signature_known_answer_vectors_are_stable() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        assert_eq!(
            sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
            "L9Q5eSm8eDGxINlvhFUYSsBiRrhqkc0eEcqbyqv9rnsAuqYCEv9k4ZWUL0RiWi-ft49oq-JBu9yX_xrtkXG_Bw"
        );

        let buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let commit_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        assert_eq!(
            sign_b64(&key_pair, &checked_commit_signature_message(commit_input)),
            "wRomyqNMlHx22E4hNCitBRnqk06QhZ2Y_SwWnCrKhteedbtrxIslkFfUTiPWgl03hfFiKWJbzhi8jZVVb9u_Ag"
        );

        let paths = ["AAAAAAAAAAA", "AAAAAAAAAAE"];
        let read_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 2,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        assert_eq!(
            sign_b64(&key_pair, &checked_read_paths_signature_message(read_input)),
            "xoxnYq-yulLq8ufkyv_wLANeEpsC2lYdbwWPr8KvjRgPc-3st2HrbKDwE_wQZTPiByEp_W5F3lVS84TWgbVcCw"
        );
    }

    fn assert_signature_fixture(
        fixture: &serde_json::Value,
        case_name: &str,
        expected_domain: &str,
        message: &[u8],
        signature: &str,
    ) {
        let case = fixture["cases"]
            .as_array()
            .and_then(|cases| {
                cases
                    .iter()
                    .find(|case| case["name"].as_str() == Some(case_name))
            })
            .unwrap_or_else(|| panic!("test vector case {case_name} must exist"));
        let get = |key: &str| {
            case[key]
                .as_str()
                .unwrap_or_else(|| panic!("test vector case {case_name} must define {key}"))
        };

        assert_eq!(get("domain"), expected_domain);
        assert_eq!(get("signature_alg"), "ed25519");
        assert_eq!(
            message.len() as u64,
            case["signature_message_len"]
                .as_u64()
                .unwrap_or_else(|| panic!("test vector case {case_name} must define message len"))
        );
        assert_eq!(
            BASE64URL_NOPAD.encode(message),
            get("signature_message_b64")
        );
        assert_eq!(
            BASE64URL_NOPAD.encode(Sha256::digest(message).as_ref()),
            get("signature_message_sha256_b64")
        );
        assert_eq!(signature, get("signature_b64"));
    }

    #[test]
    fn signature_messages_match_sdk_test_vector() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/qdrant-sec-private-hnsw-oram-signature-test-vector.json"
        ))
        .expect("private HNSW ORAM signature test vector must be valid JSON");
        assert_eq!(
            fixture["provider"].as_str(),
            Some(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
        );
        assert_eq!(fixture["binding"].as_str(), Some(PRIVATE_HNSW_ORAM_BINDING));
        assert_eq!(
            fixture["deterministic_seed_hex"].as_str(),
            Some("0707070707070707070707070707070707070707070707070707070707070707")
        );

        let key_pair = deterministic_key_pair();
        let manifest_message = checked_manifest_signature_message(&fixture_manifest());
        let manifest_signature = sign_b64(&key_pair, &manifest_message);
        assert_signature_fixture(
            &fixture,
            "manifest",
            PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN,
            &manifest_message,
            &manifest_signature,
        );

        let buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let commit_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let commit_message = checked_commit_signature_message(commit_input);
        let commit_signature = sign_b64(&key_pair, &commit_message);
        assert_signature_fixture(
            &fixture,
            "commit",
            PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN,
            &commit_message,
            &commit_signature,
        );

        let paths = ["AAAAAAAAAAA", "AAAAAAAAAAE"];
        let read_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 2,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let read_message = checked_read_paths_signature_message(read_input);
        let read_signature = sign_b64(&key_pair, &read_message);
        assert_signature_fixture(
            &fixture,
            "read_paths",
            PRIVATE_HNSW_ORAM_READ_PATHS_SIGNATURE_DOMAIN,
            &read_message,
            &read_signature,
        );
    }

    #[test]
    fn signature_message_builders_reject_client_state_vector_aliases() {
        let paths = ["AAAAAAAAAAA"];
        let buckets = [PrivateHnswOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];

        for vector_alias in [
            "client.state",
            "client.state.snapshot",
            "client_states.json",
            "clientStateCiphertexts.json",
            "encryptedClientStates.json",
            "encrypted.client.state",
            "encrypted.client.state.snapshot",
            "encrypted_client_state_ciphertexts.json",
            "stateCiphertexts.json",
            "positionMapSnapshots.json",
            "oram_position_map_backups.json",
            "tokenMap.json",
            "tokenMaps.json",
            "tokenMapBackup.json",
            "tokenMapBackups.json",
            "token.map.backup",
            "token.map.backup.json",
            "token.map.backups",
            "token.map.backups.json",
            "tokenMapSnapshot.json",
            "tokenMapSnapshots.json",
            "token_map.json",
            "token_maps.json",
            "token_map_backup.json",
            "token_map_backups.json",
            "token_map_snapshot.json",
            "token_map_snapshots.json",
            "tokenPositionMapSnapshots.json",
            "token.position.map.backup",
            "token.position.map.backup.json",
            "token.position.map.backups",
            "token.position.map.backups.json",
            "stash_snapshots.json",
            "payload_fetch_token",
            "payload_fetch_tokens",
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload.fetch.token",
        ] {
            let mut manifest = fixture_manifest();
            manifest.vector_name = vector_alias.to_string();
            assert_eq!(
                try_private_hnsw_oram_manifest_signature_message(&manifest),
                Err(PrivateHnswOramError::InvalidManifestField("vector_name")),
                "manifest accepted private ORAM client-state vector alias {vector_alias}",
            );

            let read_paths_input = PrivateHnswOramReadPathsSignatureInput {
                collection_id: "collection-uuid-1",
                vector_name: vector_alias,
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                index_epoch: 42,
                root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
                paths: &paths,
                requested_paths: 1,
                dummy_paths_included: true,
                signature_alg: "ed25519",
                signature_key_id: "tenant-a/private-hnsw-signing-v1",
            };
            assert_eq!(
                try_private_hnsw_oram_read_paths_signature_message(read_paths_input),
                Err(PrivateHnswOramError::InvalidManifestField("vector_name")),
                "read_paths accepted private ORAM client-state vector alias {vector_alias}",
            );

            let commit_input = PrivateHnswOramCommitSignatureInput {
                collection_id: "collection-uuid-1",
                vector_name: vector_alias,
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                old_epoch: 42,
                new_epoch: 43,
                old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
                new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
                updated_buckets: &buckets,
                signature_alg: "ed25519",
                signature_key_id: "tenant-a/private-hnsw-signing-v1",
            };
            assert_eq!(
                try_private_hnsw_oram_commit_signature_message(commit_input),
                Err(PrivateHnswOramError::InvalidManifestField("vector_name")),
                "commit accepted private ORAM client-state vector alias {vector_alias}",
            );
        }

        let valid_read_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 1,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let unsupported_read_alg = PrivateHnswOramReadPathsSignatureInput {
            signature_alg: "rsa-pss-sentinel",
            ..valid_read_input
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(unsupported_read_alg),
            Err(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
                "rsa-pss-sentinel".to_string()
            ))
        );
        let malformed_read_key = PrivateHnswOramReadPathsSignatureInput {
            signature_key_id: "bad key id",
            ..valid_read_input
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(malformed_read_key),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );
        for malformed_read_context in [
            PrivateHnswOramReadPathsSignatureInput {
                key_id: "tenant-a/vector private-rk",
                ..valid_read_input
            },
            PrivateHnswOramReadPathsSignatureInput {
                rk_id: "tenant-a/vector private-rk",
                ..valid_read_input
            },
        ] {
            assert_eq!(
                try_private_hnsw_oram_read_paths_signature_message(malformed_read_context),
                Err(PrivateHnswOramError::InvalidResourceKeyId)
            );
        }

        let valid_commit_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let unsupported_commit_alg = PrivateHnswOramCommitSignatureInput {
            signature_alg: "rsa-pss-sentinel",
            ..valid_commit_input
        };
        assert_eq!(
            try_private_hnsw_oram_commit_signature_message(unsupported_commit_alg),
            Err(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
                "rsa-pss-sentinel".to_string()
            ))
        );
        let malformed_commit_key = PrivateHnswOramCommitSignatureInput {
            signature_key_id: "bad key id",
            ..valid_commit_input
        };
        assert_eq!(
            try_private_hnsw_oram_commit_signature_message(malformed_commit_key),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );
        for malformed_commit_context in [
            PrivateHnswOramCommitSignatureInput {
                key_id: "tenant-a/vector private-rk",
                ..valid_commit_input
            },
            PrivateHnswOramCommitSignatureInput {
                rk_id: "tenant-a/vector private-rk",
                ..valid_commit_input
            },
        ] {
            assert_eq!(
                try_private_hnsw_oram_commit_signature_message(malformed_commit_context),
                Err(PrivateHnswOramError::InvalidResourceKeyId)
            );
        }
    }

    #[test]
    fn read_paths_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let paths = ["AAAAAAAAAAA"];
        let input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 1,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let signature = sign_b64(&key_pair, &checked_read_paths_signature_message(input));
        let verification = PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_hnsw_oram_read_paths_signature(input, &signature, verification).unwrap();

        let invalid_collection_context = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                invalid_collection_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("collection_id"))
        );

        let invalid_context = PrivateHnswOramReadPathsSignatureInput {
            vector_name: "",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                invalid_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let unsafe_vector_context = PrivateHnswOramReadPathsSignatureInput {
            vector_name: "text/private",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                unsafe_vector_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let client_state_alias_context = PrivateHnswOramReadPathsSignatureInput {
            vector_name: "client.state",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                client_state_alias_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        for invalid_context in [
            PrivateHnswOramReadPathsSignatureInput {
                key_id: "bad key id",
                ..input
            },
            PrivateHnswOramReadPathsSignatureInput {
                rk_id: "bad rk id",
                ..input
            },
        ] {
            assert_eq!(
                validate_private_hnsw_oram_read_paths_signature(
                    invalid_context,
                    "malformed-signature",
                    verification,
                ),
                Err(PrivateHnswOramError::InvalidResourceKeyId)
            );
        }
        let malformed_signature_key_input = PrivateHnswOramReadPathsSignatureInput {
            signature_key_id: "tenant-a/private\nhnsw-signing-v1",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                malformed_signature_key_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );

        let malformed_root = PrivateHnswOramReadPathsSignatureInput {
            root_hash: "AAAA",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                malformed_root,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("root_hash"))
        );

        let empty_paths = PrivateHnswOramReadPathsSignatureInput {
            paths: &[],
            ..input
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(empty_paths),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                empty_paths,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let zero_requested_paths = PrivateHnswOramReadPathsSignatureInput {
            requested_paths: 0,
            ..input
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(zero_requested_paths),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                zero_requested_paths,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let malformed_paths = ["AAAA"];
        let malformed_path = PrivateHnswOramReadPathsSignatureInput {
            paths: &malformed_paths,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                malformed_path,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let duplicate_paths = ["AAAAAAAAAAA", "AAAAAAAAAAA"];
        let duplicate_path_input = PrivateHnswOramReadPathsSignatureInput {
            paths: &duplicate_paths,
            requested_paths: 2,
            ..input
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(duplicate_path_input),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        let duplicate_path_signature = sign_b64(
            &key_pair,
            &unchecked_read_paths_signature_message(duplicate_path_input),
        );
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                duplicate_path_input,
                &duplicate_path_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let tampered = PrivateHnswOramReadPathsSignatureInput {
            requested_paths: 2,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(tampered, &signature, verification),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let tampered_padding = PrivateHnswOramReadPathsSignatureInput {
            dummy_paths_included: false,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                tampered_padding,
                &signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(tampered_padding),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        let tampered_padding_signature = sign_b64(
            &key_pair,
            &unchecked_read_paths_signature_message(tampered_padding),
        );
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                tampered_padding,
                &tampered_padding_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let mismatched = PrivateHnswOramReadPathsSignatureInput {
            requested_paths: 2,
            ..input
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(mismatched),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        let mismatched_signature = sign_b64(
            &key_pair,
            &unchecked_read_paths_signature_message(mismatched),
        );
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                mismatched,
                &mismatched_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
    }

    #[test]
    fn manifest_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };
        let context = fixture_context(key_pair.public_key().as_ref(), &signature.key_id);

        let epoch =
            validate_private_hnsw_oram_manifest(&manifest, Some(&signature), context).unwrap();
        assert_eq!(epoch.epoch, 42);
        assert_eq!(epoch.root_hash, [42; 32]);

        let mut tampered = manifest;
        tampered.root_hash = BASE64URL_NOPAD.encode(&[43; 32]);
        assert_eq!(
            validate_private_hnsw_oram_manifest(&tampered, Some(&signature), context),
            Err(PrivateHnswOramError::InvalidManifestSignature)
        );

        let mut malformed = fixture_manifest();
        malformed.root_hash = "AAAA".to_string();
        assert_eq!(
            validate_private_hnsw_oram_manifest_signature(
                &malformed,
                Some(&signature),
                context.signature_verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("root_hash"))
        );
    }

    #[test]
    fn manifest_signature_requires_owner_and_runtime_key_id_match() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };

        let mut wrong_owner_signature = signature.clone();
        wrong_owner_signature.key_id = "tenant-a/private-hnsw-signing-v2".to_string();
        assert_eq!(
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&wrong_owner_signature),
                fixture_context(
                    key_pair.public_key().as_ref(),
                    &wrong_owner_signature.key_id
                ),
            ),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );

        assert_eq!(
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&signature),
                fixture_context(
                    key_pair.public_key().as_ref(),
                    "tenant-a/private-hnsw-wrong"
                ),
            ),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );
    }

    #[test]
    fn manifest_shape_rejects_node_count_over_capacity() {
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.bucket_size = 1;
        manifest.oram.path_batch_size = 2;
        manifest.fixed_budget.paths_per_round = 2;
        manifest.logical_node_count = 4;
        manifest.dummy_node_count = 0;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField("node_count"))
        );
    }

    #[test]
    fn manifest_shape_rejects_path_oram_bucket_count_mismatch() {
        let mut manifest = fixture_manifest();
        manifest.bucket_count -= 1;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField("bucket_count"))
        );
    }

    #[test]
    fn manifest_shape_rejects_vector_name_not_safe_for_store_path() {
        for vector_name in [
            "text/private",
            "text:private",
            ".",
            "stash",
            "stash.snapshot",
            "client.state",
            "client_state.json",
            "position-map",
            "position.map",
            "oram.position.map",
            "token.position-map",
        ] {
            let mut manifest = fixture_manifest();
            manifest.vector_name = vector_name.to_string();
            assert_eq!(
                validate_private_hnsw_oram_manifest_shape(&manifest),
                Err(PrivateHnswOramError::InvalidManifestField("vector_name")),
                "vector_name {vector_name:?} should be rejected",
            );
        }
    }

    #[test]
    fn manifest_shape_rejects_malformed_context_ids() {
        for manifest in [
            PrivateHnswOramManifest {
                collection_id: "collection\nuuid".to_string(),
                ..fixture_manifest()
            },
            PrivateHnswOramManifest {
                key_id: "tenant-a/vector\nprivate-rk".to_string(),
                ..fixture_manifest()
            },
            PrivateHnswOramManifest {
                rk_id: "tenant-a/vector\nprivate-rk".to_string(),
                ..fixture_manifest()
            },
            PrivateHnswOramManifest {
                owner_signing_key_id: "tenant-a/private\nhnsw-signing-v1".to_string(),
                ..fixture_manifest()
            },
        ] {
            let expected = if manifest.collection_id.contains('\n') {
                PrivateHnswOramError::InvalidManifestField("collection_id")
            } else {
                PrivateHnswOramError::InvalidResourceKeyId
            };
            assert_eq!(
                validate_private_hnsw_oram_manifest_shape(&manifest),
                Err(expected)
            );
        }
    }

    #[test]
    fn manifest_shape_rejects_impossible_path_batch_budget() {
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.path_batch_size = 3;
        manifest.fixed_budget.paths_per_round = 3;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField(
                "oram.path_batch_size"
            ))
        );

        manifest = fixture_manifest();
        manifest.fixed_budget.paths_per_round = manifest.oram.path_batch_size + 1;
        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField(
                "fixed_budget.paths_per_round"
            ))
        );
    }

    #[test]
    fn manifest_shape_rejects_impossible_node_block_budget() {
        let mut manifest = fixture_manifest();
        manifest.oram.block_size_bytes = 8192;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField(
                "oram.block_size_bytes"
            ))
        );
    }

    #[test]
    fn manifest_context_mismatch_and_malformed_signature_reject() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };
        let mut wrong_context = fixture_context(key_pair.public_key().as_ref(), &signature.key_id);
        wrong_context.expected_vector_name = "body";
        assert_eq!(
            validate_private_hnsw_oram_manifest(&manifest, Some(&signature), wrong_context),
            Err(PrivateHnswOramError::ManifestContextMismatch("vector_name"))
        );
        validate_private_hnsw_oram_manifest_shape(&manifest).unwrap();

        let bad_signature = PrivateHnswOramSignature {
            sig: "not-base64url".to_string(),
            ..signature.clone()
        };
        assert_eq!(
            validate_private_hnsw_oram_manifest_signature_shape(&bad_signature),
            Err(PrivateHnswOramError::MalformedSignature)
        );
        assert_eq!(
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&bad_signature),
                fixture_context(key_pair.public_key().as_ref(), &bad_signature.key_id)
            ),
            Err(PrivateHnswOramError::MalformedSignature)
        );
        let malformed_key_signature = PrivateHnswOramSignature {
            key_id: "tenant-a/private\nhnsw-signing-v1".to_string(),
            ..signature
        };
        assert_eq!(
            validate_private_hnsw_oram_manifest_signature_shape(&malformed_key_signature),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );
    }

    #[test]
    fn commit_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let buckets = [PrivateHnswOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];
        let input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let signature = sign_b64(&key_pair, &checked_commit_signature_message(input));
        let verification = PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_hnsw_oram_commit_signature(input, &signature, verification).unwrap();

        let stale_epoch_input = PrivateHnswOramCommitSignatureInput {
            new_epoch: input.old_epoch,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                stale_epoch_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("new_epoch"))
        );

        let invalid_context = PrivateHnswOramCommitSignatureInput {
            collection_id: "",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("collection_id"))
        );

        let invalid_vector_context = PrivateHnswOramCommitSignatureInput {
            vector_name: "text:private",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_vector_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let client_state_alias_context = PrivateHnswOramCommitSignatureInput {
            vector_name: "client.state",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                client_state_alias_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let invalid_key_context = PrivateHnswOramCommitSignatureInput {
            key_id: "bad key id",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_key_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );
        let invalid_rk_context = PrivateHnswOramCommitSignatureInput {
            rk_id: "bad rk id",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_rk_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );

        let empty_input = PrivateHnswOramCommitSignatureInput {
            updated_buckets: &[],
            ..input
        };
        assert_eq!(
            try_private_hnsw_oram_commit_signature_message(empty_input),
            Err(PrivateHnswOramError::EmptyCommit)
        );
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                empty_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::EmptyCommit)
        );

        let malformed_root_input = PrivateHnswOramCommitSignatureInput {
            old_root_hash: "AAAA",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                malformed_root_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("old_root_hash"))
        );

        let malformed_hash_buckets = [PrivateHnswOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: "AAAA",
        }];
        let malformed_hash_input = PrivateHnswOramCommitSignatureInput {
            updated_buckets: &malformed_hash_buckets,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                malformed_hash_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField(
                "ciphertext_sha256"
            ))
        );

        let duplicate_buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[10; 32]),
            },
        ];
        let duplicate_input = PrivateHnswOramCommitSignatureInput {
            updated_buckets: &duplicate_buckets,
            ..input
        };
        assert_eq!(
            try_private_hnsw_oram_commit_signature_message(duplicate_input),
            Err(PrivateHnswOramError::InvalidCommitSignature)
        );
        let duplicate_signature = sign_b64(
            &key_pair,
            &unchecked_commit_signature_message(duplicate_input),
        );
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                duplicate_input,
                &duplicate_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidCommitSignature)
        );

        let wrong_signature_key_input = PrivateHnswOramCommitSignatureInput {
            signature_key_id: "tenant-a/private-hnsw-signing-v2",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                wrong_signature_key_input,
                &signature,
                verification,
            ),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );
        let malformed_signature_key_input = PrivateHnswOramCommitSignatureInput {
            signature_key_id: "tenant-a/private\nhnsw-signing-v1",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                malformed_signature_key_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );

        let tampered = PrivateHnswOramCommitSignatureInput {
            old_epoch: 43,
            new_epoch: 44,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(tampered, &signature, verification),
            Err(PrivateHnswOramError::InvalidCommitSignature)
        );
    }

    #[test]
    fn generated_key_pair_manifest_signature_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };

        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();
    }
}
