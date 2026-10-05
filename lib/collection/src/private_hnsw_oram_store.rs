#![allow(
    dead_code,
    reason = "D3-B3-B2 owner store tokens remain dormant until the paired adapter is wired"
)]

use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::marker::PhantomData;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateHnswBucketAeadContext, PrivateHnswManifestValidationContext, PrivateHnswOramBucket,
    PrivateHnswOramCommitBucketRef, PrivateHnswOramCommitSignatureInput, PrivateHnswOramManifest,
    PrivateHnswOramSignature, PrivateHnswOramUploadBundle, PrivateHnswSignatureVerification,
    PrivateOramAppendBucketRefV1, PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2,
    PrivateOramImmutableManifestV2, PrivateOramIndexKindV2, PrivateOramIndexStateV2,
    private_hnsw_bucket_commitment, private_hnsw_oram_bucket_ciphertext_bytes,
    private_hnsw_oram_bucket_count, private_hnsw_oram_writeback_digest,
    private_oram_immutable_manifest_v2_digest, try_private_hnsw_oram_manifest_signature_message,
    validate_private_hnsw_oram_commit_signature, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_manifest_shape, validate_private_hnsw_oram_upload_bundle,
    validate_private_hnsw_oram_upload_bundle_with_signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::operations::types::{CollectionError, CollectionResult};
use crate::private_oram_owner_store_adapter::PrivateOramOwnerIndexStoreInspectionAuthorityV1;

pub const PRIVATE_HNSW_ORAM_DIR: &str = "private_hnsw_oram";
const MANIFEST_FILE: &str = "manifest.json";
const MANIFEST_SIGNATURE_FILE: &str = "manifest.sig";
const BUCKETS_DIR: &str = "buckets";
const EPOCHS_DIR: &str = "epochs";
const MERKLE_DIR: &str = "merkle";
const TEMP_DIR: &str = "temp";
const PENDING_WRITEBACK_FILE: &str = "pending-writeback.json";
const CURRENT_EPOCH_FILE: &str = "current.json";
const MERKLE_NODES_FILE: &str = "nodes.dat";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_EPOCH_BYTES: u64 = 16 * 1024;
const MAX_MERKLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PENDING_WRITEBACK_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(not(test))]
const MAX_OWNER_EPOCH_DIRECTORY_ENTRIES: usize = 4_096;
#[cfg(test)]
const MAX_OWNER_EPOCH_DIRECTORY_ENTRIES: usize = 16;
/// Epoch commit records retained behind the current epoch. Owner verification hashes every
/// commit file and refuses directories above `MAX_OWNER_EPOCH_DIRECTORY_ENTRIES`, so an
/// unbounded history made every v2 owner verification of a long-lived index fail for good.
#[cfg(not(test))]
const EPOCH_COMMIT_HISTORY_KEEP: u64 = 1_024;
#[cfg(test)]
const EPOCH_COMMIT_HISTORY_KEEP: u64 = 4;
const BUCKET_JSON_OVERHEAD_BYTES: usize = 32 * 1024;
pub const PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";
const OWNER_EXACT_OLD_STORE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-hnsw-store-exact-old/v1";
const OWNER_EXACT_NEW_STORE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-hnsw-store-exact-new/v1";
const OWNER_EPOCH_DIRECTORY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-hnsw-epoch-directory/v1";

#[derive(Clone)]
pub struct PrivateHnswOramStore {
    root: PathBuf,
}

impl Debug for PrivateHnswOramStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramStore")
            .field("root", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramEpochState {
    pub index_epoch: u64,
    pub root_hash: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramLiveReplicationBundle {
    pub manifest: PrivateHnswOramManifest,
    pub manifest_signature: PrivateHnswOramSignature,
    pub current: PrivateHnswOramEpochState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writeback_digest: Option<String>,
    pub buckets: Vec<PrivateHnswOramBucket>,
}

impl Debug for PrivateHnswOramLiveReplicationBundle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramLiveReplicationBundle")
            .field("manifest", &"[redacted]")
            .field("manifest_signature", &"[redacted]")
            .field("current_epoch", &self.current.index_epoch)
            .field("current_root_hash", &"[redacted]")
            .field("has_writeback_digest", &self.writeback_digest.is_some())
            .field("bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateHnswOramEpochCommit {
    index_epoch: u64,
    root_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writeback_digest: Option<String>,
}

impl Debug for PrivateHnswOramEpochCommit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramEpochCommit")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("has_writeback_digest", &self.writeback_digest.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateHnswOramConsensusWriteback {
    pub old: PrivateHnswOramEpochState,
    pub new: PrivateHnswOramEpochState,
    pub writeback_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramWritebackBatch {
    pub version: u16,
    pub old: PrivateHnswOramEpochState,
    pub new: PrivateHnswOramEpochState,
    pub bucket_count: u64,
    pub updated_buckets: Vec<PrivateHnswOramBucket>,
    pub commit_signature: PrivateHnswOramSignature,
}

impl Debug for PrivateHnswOramWritebackBatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramWritebackBatch")
            .field("version", &self.version)
            .field("old_epoch", &self.old.index_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_epoch", &self.new.index_epoch)
            .field("new_root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .field("commit_signature", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateHnswOramConsensusWriteback {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramConsensusWriteback")
            .field("old_epoch", &self.old.index_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_epoch", &self.new.index_epoch)
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateHnswOramEpochState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramEpochState")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
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
            .field("index_epoch", &self.index_epoch)
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
    pub position: MerkleSiblingPosition,
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
pub enum MerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateHnswOramMerkleTree {
    version: u16,
    index_epoch: u64,
    root_hash: String,
    bucket_count: u64,
    leaf_hashes: Vec<String>,
}

impl Debug for PrivateHnswOramMerkleTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleTree")
            .field("version", &self.version)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("leaf_hash_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitialEpochStatus {
    Absent,
    Matching,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateHnswPendingWriteback {
    version: u16,
    old: PrivateHnswOramEpochState,
    new: PrivateHnswOramEpochState,
    bucket_count: u64,
    updated_buckets: Vec<PrivateHnswOramBucket>,
    merkle_tree: PrivateHnswOramMerkleTree,
    commit_signature: PrivateHnswOramSignature,
}

// Dormant D3-B3-B2 primitive: this binds canonical logical state plus the
// mutation-affected bucket bodies. It does not prove unrelated bucket
// availability. Keep the minting path module-private until the paired typed
// authority and every V2 writer share the same pinned namespace and lock.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateHnswOwnerStoreVerificationContextV1<'a> {
    journal_descriptor_digest: &'a str,
    prepared_state_digest: &'a str,
    immutable_manifest_digest: &'a str,
    immutable_manifest: &'a PrivateOramImmutableManifestV2,
    immutable_index: &'a PrivateOramImmutableIndexV2,
    index_name: &'a str,
    old_state: &'a PrivateOramIndexStateV2,
    new_state: &'a PrivateOramIndexStateV2,
    final_bucket_refs: &'a [PrivateOramAppendBucketRefV1],
    final_buckets: &'a [PrivateHnswOramBucket],
    max_ciphertext_bytes: usize,
    manifest_validation: PrivateHnswManifestValidationContext<'a>,
}

impl Debug for PrivateHnswOwnerStoreVerificationContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOwnerStoreVerificationContextV1")
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("immutable_manifest_digest", &"[redacted]")
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_state.index_epoch)
            .field("new_epoch", &self.new_state.index_epoch)
            .field("final_bucket_count", &self.final_buckets.len())
            .field("max_ciphertext_bytes", &self.max_ciphertext_bytes)
            .field("manifest_validation", &self.manifest_validation)
            .finish()
    }
}

pub(crate) struct PrivateHnswOwnerExactOldStoreTokenV1<'lock> {
    index_name: String,
    canonical_state_digest: String,
    _lock: PhantomData<&'lock File>,
}

impl Debug for PrivateHnswOwnerExactOldStoreTokenV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOwnerExactOldStoreTokenV1")
            .field("index_name", &"[redacted]")
            .field("canonical_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswOwnerExactOldStoreTokenV1<'_> {
    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn canonical_state_digest(&self) -> &str {
        &self.canonical_state_digest
    }
}

pub(crate) struct PrivateHnswOwnerExactNewStoreTokenV1<'lock> {
    index_name: String,
    canonical_state_digest: String,
    _lock: PhantomData<&'lock File>,
}

impl Debug for PrivateHnswOwnerExactNewStoreTokenV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOwnerExactNewStoreTokenV1")
            .field("index_name", &"[redacted]")
            .field("canonical_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswOwnerExactNewStoreTokenV1<'_> {
    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn canonical_state_digest(&self) -> &str {
        &self.canonical_state_digest
    }
}

pub(crate) enum PrivateHnswOwnerStoreObservationV1<'lock> {
    Old(PrivateHnswOwnerExactOldStoreTokenV1<'lock>),
    New(PrivateHnswOwnerExactNewStoreTokenV1<'lock>),
    Third,
}

impl Debug for PrivateHnswOwnerStoreObservationV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Old(_) => "PrivateHnswOwnerStoreObservationV1::Old([redacted])",
            Self::New(_) => "PrivateHnswOwnerStoreObservationV1::New([redacted])",
            Self::Third => "PrivateHnswOwnerStoreObservationV1::Third",
        })
    }
}

// Dormant V2 recovery states. S1 includes the full-prefix crash window before
// the Merkle tree is published; no other bucket ordering is recoverable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateHnswOwnerRecoveryPhaseV1 {
    S0,
    S1 { written_bucket_count: usize },
    S2,
    S3,
    S4,
}

struct PrivateHnswOwnerRecoveryEvidenceV1 {
    phase: PrivateHnswOwnerRecoveryPhaseV1,
    manifest: PrivateHnswOramManifest,
    manifest_signature: PrivateHnswOramSignature,
    observed_merkle_tree: PrivateHnswOramMerkleTree,
    old_commit_kind: OwnerStoreCommitKind,
    new_merkle_tree: PrivateHnswOramMerkleTree,
}

impl Debug for PrivateHnswOwnerRecoveryEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOwnerRecoveryEvidenceV1")
            .field("phase", &self.phase)
            .field("manifest", &"[redacted]")
            .field("manifest_signature", &"[redacted]")
            .field("observed_merkle_tree", &self.observed_merkle_tree)
            .field("old_commit_kind", &self.old_commit_kind)
            .field("new_merkle_tree", &self.new_merkle_tree)
            .finish()
    }
}

pub(crate) struct PrivateHnswOwnerStoreLockV1<'a> {
    store: &'a PrivateHnswOramStore,
    directory: File,
}

struct PrivateHnswCanonicalWriterLockV1<'a> {
    store: &'a PrivateHnswOramStore,
    owner_lock: PrivateHnswOwnerStoreLockV1<'a>,
}

impl Debug for PrivateHnswCanonicalWriterLockV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswCanonicalWriterLockV1")
            .field("store", &self.store)
            .field("owner_lock", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateHnswOwnerStoreLockV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOwnerStoreLockV1")
            .field("store", &self.store)
            .field("directory", &"[redacted]")
            .finish()
    }
}

impl Drop for PrivateHnswOwnerStoreLockV1<'_> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        let _ = unsafe { nix::libc::flock(self.directory.as_raw_fd(), nix::libc::LOCK_UN) };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerStorePhase {
    ExactOld,
    ExactNew,
}

impl OwnerStorePhase {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::ExactOld => OWNER_EXACT_OLD_STORE_DOMAIN,
            Self::ExactNew => OWNER_EXACT_NEW_STORE_DOMAIN,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::ExactOld => 1,
            Self::ExactNew => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerStoreCommitKind {
    InitialAnchor,
    DigestBound,
}

impl OwnerStoreCommitKind {
    const fn tag(self) -> u8 {
        match self {
            Self::InitialAnchor => 1,
            Self::DigestBound => 2,
        }
    }
}

struct OwnerStoreEvidence {
    canonical_state_digest: String,
}

impl Debug for PrivateHnswPendingWriteback {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPendingWriteback")
            .field("version", &self.version)
            .field("old_epoch", &self.old.index_epoch)
            .field("new_epoch", &self.new.index_epoch)
            .field("bucket_count", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .field("merkle_tree", &self.merkle_tree)
            .field("commit_signature", &"[redacted]")
            .finish()
    }
}

impl PrivateHnswOramStore {
    pub fn new(collection_path: impl AsRef<Path>, vector_name: &str) -> CollectionResult<Self> {
        validate_path_component(vector_name, "vector name")?;
        Ok(Self {
            root: collection_path
                .as_ref()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join(vector_name),
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    fn lock_owner_store_v1(&self) -> CollectionResult<PrivateHnswOwnerStoreLockV1<'_>> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(CollectionError::service_error(
                "private HNSW ORAM owner store verification is unsupported on this platform",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            validate_private_dir(&self.root)?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(&self.root)
                .map_err(|_| {
                    CollectionError::service_error(
                        "failed to open private HNSW ORAM owner store root",
                    )
                })?;
            validate_owner_store_directory_identity(&directory, &self.root)?;
            let result = unsafe {
                nix::libc::flock(
                    directory.as_raw_fd(),
                    nix::libc::LOCK_EX | nix::libc::LOCK_NB,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                return if matches!(error.raw_os_error(), Some(nix::libc::EAGAIN)) {
                    Err(CollectionError::bad_request(
                        "another private HNSW ORAM owner store operation is active",
                    ))
                } else {
                    Err(CollectionError::service_error(
                        "failed to lock private HNSW ORAM owner store",
                    ))
                };
            }
            if let Err(error) = validate_owner_store_directory_identity(&directory, &self.root) {
                let _ = unsafe { nix::libc::flock(directory.as_raw_fd(), nix::libc::LOCK_UN) };
                return Err(error);
            }
            Ok(PrivateHnswOwnerStoreLockV1 {
                store: self,
                directory,
            })
        }
    }

    pub(crate) fn with_owner_store_lock_v1<R>(
        &self,
        action: impl for<'lock> FnOnce(&'lock PrivateHnswOwnerStoreLockV1<'_>) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        let lock = self.lock_owner_store_v1()?;
        let output = action(&lock);
        validate_owner_store_directory_identity(&lock.directory, &self.root)?;
        output
    }

    fn with_canonical_writer_lock_v1<R>(
        &self,
        action: impl for<'lock> FnOnce(
            &'lock PrivateHnswCanonicalWriterLockV1<'_>,
        ) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = action;
            return Err(CollectionError::service_error(
                "private HNSW ORAM canonical writes are unsupported on this platform",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            self.bootstrap_owner_store_root_v1()?;
            let owner_lock = self.lock_owner_store_v1()?;
            let lock = PrivateHnswCanonicalWriterLockV1 {
                store: self,
                owner_lock,
            };
            self.ensure_layout_under_owner_lock(&lock)?;
            let output = action(&lock);
            validate_owner_store_directory_identity(&lock.owner_lock.directory, &self.root)?;
            output
        }
    }

    fn bootstrap_owner_store_root_v1(&self) -> CollectionResult<()> {
        let private_hnsw_dir = self.root.parent().ok_or_else(|| {
            CollectionError::service_error("private HNSW ORAM store path is invalid")
        })?;
        create_private_dir(private_hnsw_dir)?;
        create_private_dir(&self.root)
    }

    fn ensure_layout_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        create_private_dir(&self.buckets_dir())?;
        create_private_dir(&self.epochs_dir())?;
        create_private_dir(&self.merkle_dir())?;
        create_private_dir(&self.temp_dir())
    }

    fn validate_canonical_writer_lock_v1(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
    ) -> CollectionResult<()> {
        if !std::ptr::eq(self, lock.store) {
            return Err(CollectionError::service_error(
                "private HNSW ORAM canonical writer lock does not match store",
            ));
        }
        validate_owner_store_directory_identity(&lock.owner_lock.directory, &self.root)?;
        Ok(())
    }

    pub(crate) fn with_owner_exact_old_store_v1<R>(
        &self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
        action: impl for<'lock> FnOnce(
            PrivateHnswOwnerExactOldStoreTokenV1<'lock>,
        ) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        let final_buckets = authority
            .hnsw_final_buckets()
            .ok_or_else(owner_store_state_mismatch)?;
        self.with_owner_store_lock_v1(|lock| {
            let token = lock.verify_exact_old(PrivateHnswOwnerStoreVerificationContextV1 {
                journal_descriptor_digest: authority.journal_descriptor_digest(),
                prepared_state_digest: authority.prepared_state_digest(),
                immutable_manifest_digest: authority.immutable_manifest_digest(),
                immutable_manifest: authority.immutable_manifest(),
                immutable_index: authority.immutable_index(),
                index_name: authority.index_name(),
                old_state: authority.old_state(),
                new_state: authority.new_state(),
                final_bucket_refs: authority.final_bucket_refs(),
                final_buckets,
                max_ciphertext_bytes,
                manifest_validation,
            })?;
            action(token)
        })
    }

    pub(crate) fn with_owner_exact_new_store_v1<R>(
        &self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
        action: impl for<'lock> FnOnce(
            PrivateHnswOwnerExactNewStoreTokenV1<'lock>,
        ) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        let final_buckets = authority
            .hnsw_final_buckets()
            .ok_or_else(owner_store_state_mismatch)?;
        self.with_owner_store_lock_v1(|lock| {
            let token = lock.verify_exact_new(PrivateHnswOwnerStoreVerificationContextV1 {
                journal_descriptor_digest: authority.journal_descriptor_digest(),
                prepared_state_digest: authority.prepared_state_digest(),
                immutable_manifest_digest: authority.immutable_manifest_digest(),
                immutable_manifest: authority.immutable_manifest(),
                immutable_index: authority.immutable_index(),
                index_name: authority.index_name(),
                old_state: authority.old_state(),
                new_state: authority.new_state(),
                final_bucket_refs: authority.final_bucket_refs(),
                final_buckets,
                max_ciphertext_bytes,
                manifest_validation,
            })?;
            action(token)
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn apply_owner_exact_new_test_fixture_v1(
        &self,
        old: &PrivateOramIndexStateV2,
        new: &PrivateOramIndexStateV2,
        final_buckets: &[PrivateHnswOramBucket],
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            let old_epoch = PrivateHnswOramEpochState {
                index_epoch: old.index_epoch,
                root_hash: old.root_hash.clone(),
            };
            let new_epoch = PrivateHnswOramEpochState {
                index_epoch: new.index_epoch,
                root_hash: new.root_hash.clone(),
            };
            let tree = self.prepare_merkle_commit_under_owner_lock(
                lock,
                old.index_epoch,
                &old.root_hash,
                new.index_epoch,
                &new.root_hash,
                bucket_count,
                final_buckets,
            )?;
            for bucket in final_buckets {
                self.write_bucket_under_owner_lock(
                    lock,
                    bucket,
                    new.index_epoch,
                    bucket_count,
                    max_ciphertext_bytes,
                )?;
            }
            self.write_merkle_tree_under_owner_lock(lock, &tree)?;
            self.compare_and_swap_epoch_with_writeback_digest_under_owner_lock(
                lock,
                &old_epoch,
                &new_epoch,
                Some(&new.last_writeback_digest),
            )
        })
    }

    pub fn ensure_layout(&self) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|_| Ok(()))
    }

    pub fn write_manifest(
        &self,
        manifest: &PrivateHnswOramManifest,
        signature: &PrivateHnswOramSignature,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_manifest_under_owner_lock(lock, manifest, signature)
        })
    }

    fn write_manifest_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        manifest: &PrivateHnswOramManifest,
        signature: &PrivateHnswOramSignature,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.manifest_path(),
            manifest,
        )?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.manifest_signature_path(),
            signature,
        )
    }

    pub fn read_manifest(
        &self,
    ) -> CollectionResult<(PrivateHnswOramManifest, PrivateHnswOramSignature)> {
        validate_private_dir(&self.root)?;
        let manifest = read_json_private_file(&self.manifest_path(), MAX_MANIFEST_BYTES)?;
        let signature =
            read_json_private_file(&self.manifest_signature_path(), MAX_SIGNATURE_BYTES)?;
        Ok((manifest, signature))
    }

    pub fn write_initial_upload_bundle(
        &self,
        bundle: &PrivateHnswOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        let leaf_commitments = validate_upload_bundle(bundle, max_ciphertext_bytes)?;
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_initial_upload_bundle_under_owner_lock(
                lock,
                bundle,
                max_ciphertext_bytes,
                leaf_commitments,
            )
        })
    }

    fn write_initial_upload_bundle_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        bundle: &PrivateHnswOramUploadBundle,
        max_ciphertext_bytes: usize,
        leaf_commitments: Vec<String>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.validate_canonical_writer_lock_v1(lock)?;
        self.ensure_no_pending_initial_replication()?;
        let epoch = PrivateHnswOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };

        match self.initial_epoch_status(&epoch)? {
            InitialEpochStatus::Absent => {}
            InitialEpochStatus::Matching => {
                self.validate_existing_initial_upload_bundle(
                    bundle,
                    &leaf_commitments,
                    max_ciphertext_bytes,
                )?;
                return Ok(epoch);
            }
        }
        self.write_manifest_under_owner_lock(lock, &bundle.manifest, &bundle.manifest_signature)?;
        self.write_merkle_tree_from_commitments_under_owner_lock(
            lock,
            bundle.manifest.index_epoch,
            bundle.manifest.root_hash.clone(),
            leaf_commitments,
        )?;
        for bucket in &bundle.buckets {
            self.write_bucket_under_owner_lock(
                lock,
                bucket,
                bundle.manifest.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_initial_epoch_if_absent_or_matching_under_owner_lock(lock, &epoch)?;
        Ok(epoch)
    }

    pub fn write_initial_upload_bundle_with_signature(
        &self,
        bundle: &PrivateHnswOramUploadBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        let leaf_commitments = validate_upload_bundle_with_signature(
            bundle,
            max_ciphertext_bytes,
            validation_context,
        )?;
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_initial_upload_bundle_under_owner_lock(
                lock,
                bundle,
                max_ciphertext_bytes,
                leaf_commitments,
            )
        })
    }

    pub fn read_initial_upload_bundle(
        &self,
        max_ciphertext_bytes: usize,
        max_bundle_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramUploadBundle> {
        let (manifest, manifest_signature) = self.read_manifest()?;
        self.ensure_no_pending_initial_replication()?;
        let expected_bucket_count = private_hnsw_oram_bucket_count(manifest.oram.tree_height)
            .map_err(private_hnsw_client_error)?;
        if manifest.bucket_count != expected_bucket_count || expected_bucket_count == 0 {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial replication manifest bucket_count is invalid",
            ));
        }
        let expected_epoch = PrivateHnswOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };
        if self.read_current_epoch()? != expected_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial replication requires the manifest epoch",
            ));
        }
        let first = self.read_bucket(
            0,
            manifest.index_epoch,
            manifest.bucket_count,
            max_ciphertext_bytes,
        )?;
        validate_initial_replication_bundle_budget(
            manifest.bucket_count,
            initial_replication_bucket_estimated_bytes(
                first.ciphertext.len(),
                first.ciphertext_sha256.len(),
                first.bucket_commitment.len(),
            )?,
            max_bundle_bytes,
            "private HNSW ORAM initial replication bundle is oversized",
        )?;
        let capacity = usize::try_from(manifest.bucket_count).map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM initial replication bucket_count is invalid",
            )
        })?;
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(capacity).map_err(|_| {
            CollectionError::service_error(
                "private HNSW ORAM initial replication allocation failed",
            )
        })?;
        buckets.push(first);
        for bucket_id in 1..manifest.bucket_count {
            buckets.push(self.read_bucket(
                bucket_id,
                manifest.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )?);
        }
        let bundle = PrivateHnswOramUploadBundle {
            manifest,
            manifest_signature,
            buckets,
        };
        let commitments = validate_upload_bundle(&bundle, max_ciphertext_bytes)?;
        let tree = self.read_merkle_tree()?;
        if tree.leaf_hashes != commitments {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial replication Merkle state does not match",
            ));
        }
        Ok(bundle)
    }

    pub fn read_live_replication_bundle(
        &self,
        max_ciphertext_bytes: usize,
        max_bundle_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramLiveReplicationBundle> {
        let (manifest, manifest_signature) = self.read_manifest()?;
        validate_private_hnsw_oram_manifest_shape(&manifest).map_err(private_hnsw_oram_error)?;
        self.ensure_no_pending_live_replication()?;
        let current = self.read_current_epoch()?;
        let writeback_digest = self.live_writeback_digest(&manifest, &current)?;
        let buckets = self.read_live_replication_buckets(
            &manifest,
            &current,
            max_ciphertext_bytes,
            max_bundle_bytes,
        )?;
        let bundle = PrivateHnswOramLiveReplicationBundle {
            manifest,
            manifest_signature,
            current,
            writeback_digest,
            buckets,
        };
        let commitments = validate_live_replication_bundle(&bundle, max_ciphertext_bytes)?;
        let tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(
            &tree,
            bundle.current.index_epoch,
            &bundle.current.root_hash,
            bundle.manifest.bucket_count,
        )?;
        if tree.leaf_hashes != commitments {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication Merkle state does not match",
            ));
        }
        Ok(bundle)
    }

    pub fn write_live_replication_bundle_with_signature(
        &self,
        bundle: &PrivateHnswOramLiveReplicationBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateHnswManifestValidationContext<'_>,
        expected_current: &PrivateHnswOramEpochState,
        expected_writeback_digest: Option<&str>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        validate_private_hnsw_oram_manifest(
            &bundle.manifest,
            Some(&bundle.manifest_signature),
            validation_context,
        )
        .map_err(private_hnsw_oram_error)?;
        if bundle.current != *expected_current
            || bundle.writeback_digest.as_deref() != expected_writeback_digest
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication bundle does not match consensus",
            ));
        }
        let commitments = validate_live_replication_bundle(bundle, max_ciphertext_bytes)?;
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_live_replication_bundle_under_owner_lock(
                lock,
                bundle,
                max_ciphertext_bytes,
                expected_current,
                expected_writeback_digest,
                commitments,
            )
        })
    }

    fn write_live_replication_bundle_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        bundle: &PrivateHnswOramLiveReplicationBundle,
        max_ciphertext_bytes: usize,
        expected_current: &PrivateHnswOramEpochState,
        expected_writeback_digest: Option<&str>,
        commitments: Vec<String>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.validate_canonical_writer_lock_v1(lock)?;
        if bundle.current != *expected_current
            || bundle.writeback_digest.as_deref() != expected_writeback_digest
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication bundle does not match consensus",
            ));
        }
        self.ensure_no_pending_live_replication()?;

        match self.read_current_epoch() {
            Ok(current) if current == bundle.current => {
                let stored = self.read_live_replication_bundle(max_ciphertext_bytes, usize::MAX)?;
                if stored != *bundle {
                    return Err(CollectionError::bad_request(
                        "private HNSW ORAM live replication bundle does not match existing store",
                    ));
                }
                return Ok(current);
            }
            Ok(_) => {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM live replication cannot replace current state",
                ));
            }
            Err(CollectionError::NotFound { .. }) => {}
            Err(err) => return Err(err),
        }

        self.write_manifest_under_owner_lock(lock, &bundle.manifest, &bundle.manifest_signature)?;
        self.write_merkle_tree_from_commitments_under_owner_lock(
            lock,
            bundle.current.index_epoch,
            bundle.current.root_hash.clone(),
            commitments,
        )?;
        for bucket in &bundle.buckets {
            self.write_bucket_under_owner_lock(
                lock,
                bucket,
                bucket.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_live_epoch_under_owner_lock(
            lock,
            &bundle.current,
            bundle.writeback_digest.as_deref(),
        )?;

        let stored = self.read_live_replication_bundle(max_ciphertext_bytes, usize::MAX)?;
        if stored != *bundle {
            return Err(CollectionError::service_error(
                "private HNSW ORAM live replication final state validation failed",
            ));
        }
        Ok(bundle.current.clone())
    }

    fn ensure_no_pending_live_replication(&self) -> CollectionResult<()> {
        if self.pending_writeback_exists()? {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication requires no pending writeback",
            ));
        }
        Ok(())
    }

    fn live_writeback_digest(
        &self,
        manifest: &PrivateHnswOramManifest,
        current: &PrivateHnswOramEpochState,
    ) -> CollectionResult<Option<String>> {
        match self.read_epoch_commit(current.index_epoch) {
            Ok(commit) if commit.root_hash == current.root_hash => commit
                .writeback_digest
                .ok_or_else(|| {
                    CollectionError::bad_request(
                        "private HNSW ORAM live replication current commit has no consensus digest",
                    )
                })
                .map(Some),
            Ok(_) => Err(CollectionError::bad_request(
                "private HNSW ORAM live replication commit does not match current state",
            )),
            Err(CollectionError::NotFound { .. })
                if current.index_epoch == manifest.index_epoch
                    && current.root_hash == manifest.root_hash =>
            {
                Ok(None)
            }
            Err(CollectionError::NotFound { .. }) => Err(CollectionError::bad_request(
                "private HNSW ORAM live replication current commit is missing",
            )),
            Err(err) => Err(err),
        }
    }

    fn read_live_replication_buckets(
        &self,
        manifest: &PrivateHnswOramManifest,
        current: &PrivateHnswOramEpochState,
        max_ciphertext_bytes: usize,
        max_bundle_bytes: usize,
    ) -> CollectionResult<Vec<PrivateHnswOramBucket>> {
        if manifest.bucket_count == 0 {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication bucket_count is invalid",
            ));
        }
        let first = self.read_bucket(
            0,
            current.index_epoch,
            manifest.bucket_count,
            max_ciphertext_bytes,
        )?;
        validate_initial_replication_bundle_budget(
            manifest.bucket_count,
            initial_replication_bucket_estimated_bytes(
                first.ciphertext.len(),
                first.ciphertext_sha256.len(),
                first.bucket_commitment.len(),
            )?,
            max_bundle_bytes,
            "private HNSW ORAM live replication bundle is oversized",
        )?;
        let capacity = usize::try_from(manifest.bucket_count).map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM live replication bucket_count is invalid",
            )
        })?;
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(capacity).map_err(|_| {
            CollectionError::service_error("private HNSW ORAM live replication allocation failed")
        })?;
        buckets.push(first);
        for bucket_id in 1..manifest.bucket_count {
            buckets.push(self.read_bucket(
                bucket_id,
                current.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )?);
        }
        Ok(buckets)
    }

    fn write_live_epoch_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        current: &PrivateHnswOramEpochState,
        writeback_digest: Option<&str>,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_epoch_state(current)?;
        if let Some(writeback_digest) = writeback_digest {
            validate_writeback_digest(writeback_digest)?;
            write_json_atomic(
                &self.root,
                &self.temp_dir(),
                &self.commit_epoch_path(current.index_epoch),
                &PrivateHnswOramEpochCommit {
                    index_epoch: current.index_epoch,
                    root_hash: current.root_hash.clone(),
                    writeback_digest: Some(writeback_digest.to_string()),
                },
            )?;
        }
        self.write_initial_epoch_under_owner_lock(lock, current)
    }

    fn ensure_no_pending_initial_replication(&self) -> CollectionResult<()> {
        if self.pending_writeback_exists()? {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial replication requires no pending writeback",
            ));
        }
        Ok(())
    }

    fn initial_epoch_status(
        &self,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<InitialEpochStatus> {
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(InitialEpochStatus::Matching),
            Ok(_) => Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch/root does not match initial epoch",
            )),
            Err(CollectionError::NotFound { .. }) => Ok(InitialEpochStatus::Absent),
            Err(err) => Err(err),
        }
    }

    fn validate_existing_initial_upload_bundle(
        &self,
        bundle: &PrivateHnswOramUploadBundle,
        leaf_commitments: &[String],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        let (stored_manifest, stored_signature) = self.read_manifest()?;
        if stored_manifest != bundle.manifest || stored_signature != bundle.manifest_signature {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial upload bundle does not match existing manifest",
            ));
        }

        let stored_tree = self.read_merkle_tree()?;
        if stored_tree.index_epoch != bundle.manifest.index_epoch
            || stored_tree.root_hash != bundle.manifest.root_hash
            || stored_tree.bucket_count != bundle.manifest.bucket_count
            || stored_tree.leaf_hashes.as_slice() != leaf_commitments
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial upload bundle does not match existing Merkle tree",
            ));
        }

        for bucket in &bundle.buckets {
            let stored_bucket = self.read_bucket(
                bucket.bucket_id,
                bundle.manifest.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
            if stored_bucket != *bucket {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM initial upload bundle does not match existing bucket set",
                ));
            }
        }
        Ok(())
    }

    pub fn write_bucket(
        &self,
        bucket: &PrivateHnswOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_bucket_under_owner_lock(
                lock,
                bucket,
                expected_epoch,
                bucket_count,
                max_ciphertext_bytes,
            )
        })
    }

    pub fn write_initial_bucket_set(
        &self,
        expected: &PrivateHnswOramEpochState,
        buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            let tree = self.validate_initial_bucket_set_under_owner_lock(
                lock,
                expected,
                buckets,
                max_ciphertext_bytes,
            )?;
            for bucket in buckets {
                self.write_bucket_under_owner_lock(
                    lock,
                    bucket,
                    expected.index_epoch,
                    tree.bucket_count,
                    max_ciphertext_bytes,
                )?;
            }
            self.write_merkle_tree_under_owner_lock(lock, &tree)
        })
    }

    fn validate_initial_bucket_set_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        expected: &PrivateHnswOramEpochState,
        buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramMerkleTree> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_epoch_state(expected)?;
        self.ensure_current_epoch_matches(expected)?;

        let (manifest, _) = self.read_manifest()?;
        if manifest.index_epoch != expected.index_epoch || manifest.root_hash != expected.root_hash
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket upload epoch/root does not match manifest",
            ));
        }
        let bucket_count = usize::try_from(manifest.bucket_count).map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM bucket upload bucket_count exceeds supported range",
            )
        })?;
        if bucket_count == 0 || buckets.len() != bucket_count {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket upload must include the configured bucket count",
            ));
        }

        let mut leaf_hashes = Vec::new();
        leaf_hashes.try_reserve_exact(bucket_count).map_err(|_| {
            CollectionError::service_error(
                "private HNSW ORAM bucket upload commitment allocation failed",
            )
        })?;
        for (bucket_id, bucket) in buckets.iter().enumerate() {
            let expected_bucket_id = u64::try_from(bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private HNSW ORAM bucket upload bucket id exceeds supported range",
                )
            })?;
            if bucket.bucket_id != expected_bucket_id {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM bucket upload buckets must be complete and ordered",
                ));
            }
            validate_bucket(
                bucket,
                expected.index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
            validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
            leaf_hashes.push(bucket.bucket_commitment.clone());
        }
        validate_bucket_commitment_context(&manifest, expected.index_epoch, buckets)?;
        if Self::merkle_root_for_commitments(&leaf_hashes)? != expected.root_hash {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket upload Merkle root mismatch",
            ));
        }

        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch: expected.index_epoch,
            root_hash: expected.root_hash.clone(),
            bucket_count: manifest.bucket_count,
            leaf_hashes,
        };
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    fn write_bucket_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        bucket: &PrivateHnswOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_bucket(bucket, expected_epoch, bucket_count, max_ciphertext_bytes)?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.bucket_path(bucket.bucket_id),
            bucket,
        )
    }

    pub fn validate_bucket_for_write(
        &self,
        bucket: &PrivateHnswOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        validate_bucket(bucket, expected_epoch, bucket_count, max_ciphertext_bytes)
    }

    pub fn read_bucket(
        &self,
        bucket_id: u64,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramBucket> {
        validate_private_dir(&self.buckets_dir())?;
        let max_bucket_file_bytes = max_bucket_file_bytes(max_ciphertext_bytes)?;
        let bucket: PrivateHnswOramBucket =
            read_json_private_file(&self.bucket_path(bucket_id), max_bucket_file_bytes)?;
        if bucket.bucket_id != bucket_id {
            return Err(CollectionError::service_error(
                "private HNSW ORAM bucket file id mismatch",
            ));
        }
        validate_bucket_for_read(&bucket, expected_epoch, bucket_count, max_ciphertext_bytes)?;
        Ok(bucket)
    }

    pub fn write_initial_epoch(&self, epoch: &PrivateHnswOramEpochState) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_initial_epoch_under_owner_lock(lock, epoch)
        })
    }

    fn write_initial_epoch_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_epoch_state(epoch)?;
        let current_path = self.current_epoch_path();
        if current_path.exists() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch already exists",
            ));
        }
        write_json_atomic(&self.root, &self.temp_dir(), &current_path, epoch)
    }

    pub fn write_initial_epoch_if_absent_or_matching(
        &self,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_initial_epoch_if_absent_or_matching_under_owner_lock(lock, epoch)
        })
    }

    fn write_initial_epoch_if_absent_or_matching_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(()),
            Ok(_) => Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => {
                self.write_initial_epoch_under_owner_lock(lock, epoch)
            }
            Err(err) => Err(err),
        }
    }

    pub fn write_manifest_with_initial_epoch_if_absent_or_matching(
        &self,
        manifest: &PrivateHnswOramManifest,
        signature: &PrivateHnswOramSignature,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_manifest_with_initial_epoch_if_absent_or_matching_under_owner_lock(
                lock, manifest, signature, epoch,
            )
        })
    }

    fn write_manifest_with_initial_epoch_if_absent_or_matching_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        manifest: &PrivateHnswOramManifest,
        signature: &PrivateHnswOramSignature,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => match self.read_manifest() {
                Ok((stored_manifest, stored_signature))
                    if stored_manifest.index_epoch == current.index_epoch
                        && stored_manifest.root_hash == current.root_hash =>
                {
                    if stored_manifest != *manifest {
                        return Err(CollectionError::bad_request(
                            "private HNSW ORAM manifest upload does not match existing current manifest",
                        ));
                    }
                    if stored_signature != *signature {
                        // The manifest and its signature are two renames; a crash between them
                        // leaves the refreshed manifest beside the previous signature. The
                        // upload path verifies `signature` over `manifest` against the pinned
                        // owner key before calling here, so republishing it repairs the pair.
                        return self.write_manifest_under_owner_lock(lock, manifest, signature);
                    }
                    Ok(())
                }
                Ok((stored_manifest, _)) => {
                    // A post-commit refresh may only move the fields a commit legitimately
                    // changes; everything else (identifiers, key metadata including rk_epoch,
                    // layout, bucket count) is the commitment context of every stored bucket.
                    if !manifest_refresh_preserves_immutable_fields(&stored_manifest, manifest) {
                        return Err(CollectionError::bad_request(
                            "private HNSW ORAM manifest refresh changes fields other than epoch, root and node counts",
                        ));
                    }
                    self.write_manifest_under_owner_lock(lock, manifest, signature)
                }
                Err(CollectionError::NotFound { .. }) => {
                    self.write_manifest_under_owner_lock(lock, manifest, signature)
                }
                Err(err) => Err(err),
            },
            Ok(_) => Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => {
                self.write_manifest_under_owner_lock(lock, manifest, signature)?;
                self.write_initial_epoch_under_owner_lock(lock, epoch)
            }
            Err(err) => Err(err),
        }
    }

    pub fn read_current_epoch(&self) -> CollectionResult<PrivateHnswOramEpochState> {
        validate_private_dir(&self.epochs_dir())?;
        let epoch = read_json_private_file(&self.current_epoch_path(), MAX_EPOCH_BYTES)?;
        validate_epoch_state(&epoch)?;
        Ok(epoch)
    }

    pub fn compare_and_swap_epoch(
        &self,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.compare_and_swap_epoch_with_writeback_digest_under_owner_lock(lock, old, new, None)
        })
    }

    fn compare_and_swap_epoch_with_writeback_digest_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        writeback_digest: Option<&str>,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_epoch_state(old)?;
        validate_epoch_state(new)?;
        if let Some(writeback_digest) = writeback_digest {
            validate_writeback_digest(writeback_digest)?;
        }
        if Some(new.index_epoch) != old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM new epoch must be exactly old epoch + 1",
            ));
        }

        let current = self.read_current_epoch()?;
        if &current != old {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
        }

        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.commit_epoch_path(new.index_epoch),
            &PrivateHnswOramEpochCommit {
                index_epoch: new.index_epoch,
                root_hash: new.root_hash.clone(),
                writeback_digest: writeback_digest.map(str::to_string),
            },
        )?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.current_epoch_path(),
            new,
        )?;
        self.prune_epoch_commit_history(new.index_epoch);
        Ok(())
    }

    /// Drops epoch commit records older than the retained window. Pruning only runs here, when
    /// the epoch advances under the owner lock, so the epoch-directory digest a verifier sees
    /// for a given epoch never changes underneath it. Failures are logged: the commit is
    /// already durable and the next advance retries.
    fn prune_epoch_commit_history(&self, current_epoch: u64) {
        let Some(floor) = current_epoch.checked_sub(EPOCH_COMMIT_HISTORY_KEEP) else {
            return;
        };
        let epochs_dir = self.epochs_dir();
        let Ok(entries) = fs_err::read_dir(&epochs_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(epoch) = name
                .strip_suffix(".commit")
                .and_then(|encoded| encoded.parse::<u64>().ok())
            else {
                continue;
            };
            if epoch >= floor || name != format!("{epoch:08}.commit") {
                continue;
            }
            if let Err(error) = remove_private_file(&entry.path(), &epochs_dir, MAX_EPOCH_BYTES) {
                log::warn!("failed to prune private HNSW ORAM epoch commit history: {error}");
                return;
            }
        }
    }

    pub fn commit_writeback(
        &self,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.commit_writeback_under_owner_lock(
                lock,
                old,
                new,
                bucket_count,
                updated_buckets,
                max_ciphertext_bytes,
            )
        })
    }

    fn commit_writeback_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.validate_canonical_writer_lock_v1(lock)?;
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit must update at least one bucket",
            ));
        }
        if Some(new.index_epoch) != old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit new epoch must be exactly old epoch + 1",
            ));
        }
        self.ensure_current_epoch_matches(old)?;
        let (manifest, _) = self.read_manifest()?;
        validate_commit_manifest_context(&manifest, old, bucket_count)?;
        validate_fixed_writeback_budget(&manifest, updated_buckets.len())?;
        for bucket in updated_buckets {
            validate_bucket(bucket, new.index_epoch, bucket_count, max_ciphertext_bytes)?;
            validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
        }
        validate_bucket_commitment_context(&manifest, new.index_epoch, updated_buckets)?;
        let merkle_tree = self.prepare_merkle_commit_under_owner_lock(
            lock,
            old.index_epoch,
            &old.root_hash,
            new.index_epoch,
            &new.root_hash,
            bucket_count,
            updated_buckets,
        )?;
        for bucket in updated_buckets {
            self.write_bucket_under_owner_lock(
                lock,
                bucket,
                new.index_epoch,
                bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_merkle_tree_under_owner_lock(lock, &merkle_tree)?;
        self.compare_and_swap_epoch_with_writeback_digest_under_owner_lock(lock, old, new, None)?;
        Ok(new.clone())
    }

    pub fn commit_writeback_with_signature(
        &self,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateHnswOramSignature,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        let PrivateHnswSignatureVerification {
            expected_key_id,
            public_key,
        } = signature_verification;
        self.with_canonical_writer_lock_v1(|lock| {
            self.prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                old,
                new,
                bucket_count,
                updated_buckets,
                max_ciphertext_bytes,
                commit_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id,
                    public_key,
                },
                None,
            )?;
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                max_ciphertext_bytes,
                PrivateHnswSignatureVerification {
                    expected_key_id,
                    public_key,
                },
                None,
            )
        })
    }

    pub fn prepare_durable_writeback_with_signature(
        &self,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateHnswOramSignature,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramConsensusWriteback> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                old,
                new,
                bucket_count,
                updated_buckets,
                max_ciphertext_bytes,
                commit_signature,
                signature_verification,
                None,
            )
        })
    }

    fn prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateHnswOramSignature,
        signature_verification: PrivateHnswSignatureVerification<'_>,
        expected_consensus_writeback: Option<&PrivateHnswOramConsensusWriteback>,
    ) -> CollectionResult<PrivateHnswOramConsensusWriteback> {
        self.validate_canonical_writer_lock_v1(lock)?;
        let pending_path = self.pending_writeback_path();
        if pending_path.exists() {
            let pending: PrivateHnswPendingWriteback =
                read_json_private_file(&pending_path, MAX_PENDING_WRITEBACK_BYTES)?;
            let consensus_writeback = self.validate_pending_writeback(
                &pending,
                max_ciphertext_bytes,
                signature_verification,
            )?;
            if pending.old != *old
                || pending.new != *new
                || pending.bucket_count != bucket_count
                || pending.updated_buckets.as_slice() != updated_buckets
                || pending.commit_signature != *commit_signature
            {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM pending writeback does not match requested commit",
                ));
            }
            if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback)
            {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM replicated writeback does not match consensus",
                ));
            }
            return Ok(consensus_writeback);
        }

        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit must update at least one bucket",
            ));
        }
        if Some(new.index_epoch) != old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit new epoch must be exactly old epoch + 1",
            ));
        }
        let (manifest, _) = self.read_manifest()?;
        validate_fixed_writeback_budget(&manifest, updated_buckets.len())?;
        let updated_bucket_refs = updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        let signature_input = PrivateHnswOramCommitSignatureInput {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            old_epoch: old.index_epoch,
            new_epoch: new.index_epoch,
            old_root_hash: &old.root_hash,
            new_root_hash: &new.root_hash,
            updated_buckets: &updated_bucket_refs,
            signature_alg: &commit_signature.alg,
            signature_key_id: &commit_signature.key_id,
        };
        validate_private_hnsw_oram_commit_signature(
            signature_input,
            &commit_signature.sig,
            signature_verification,
        )
        .map_err(private_hnsw_oram_error)?;
        let writeback_digest =
            private_hnsw_oram_writeback_digest(signature_input).map_err(private_hnsw_oram_error)?;
        let consensus_writeback = PrivateHnswOramConsensusWriteback {
            old: old.clone(),
            new: new.clone(),
            writeback_digest,
        };
        if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM replicated writeback does not match consensus",
            ));
        }
        validate_commit_manifest_context(&manifest, old, bucket_count)?;
        for bucket in updated_buckets {
            validate_bucket(bucket, new.index_epoch, bucket_count, max_ciphertext_bytes)?;
            validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
        }
        validate_bucket_commitment_context(&manifest, new.index_epoch, updated_buckets)?;
        let current = self.read_current_epoch()?;
        if current == *new {
            let merkle_tree = self.read_merkle_tree()?;
            validate_merkle_tree_context(
                &merkle_tree,
                new.index_epoch,
                &new.root_hash,
                bucket_count,
            )?;
            for expected_bucket in updated_buckets {
                let stored_bucket = self.read_bucket(
                    expected_bucket.bucket_id,
                    new.index_epoch,
                    bucket_count,
                    max_ciphertext_bytes,
                )?;
                if stored_bucket != *expected_bucket {
                    return Err(CollectionError::bad_request(
                        "private HNSW ORAM applied replicated writeback does not match",
                    ));
                }
            }
            return Ok(consensus_writeback);
        }
        if current != *old {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch/root does not match expected state",
            ));
        }
        let merkle_tree = self.prepare_merkle_commit_under_owner_lock(
            lock,
            old.index_epoch,
            &old.root_hash,
            new.index_epoch,
            &new.root_hash,
            bucket_count,
            updated_buckets,
        )?;
        let pending = PrivateHnswPendingWriteback {
            version: 1,
            old: old.clone(),
            new: new.clone(),
            bucket_count,
            updated_buckets: updated_buckets.to_vec(),
            merkle_tree,
            commit_signature: commit_signature.clone(),
        };
        write_json_atomic_with_limit(
            &self.root,
            &self.temp_dir(),
            &pending_path,
            &pending,
            MAX_PENDING_WRITEBACK_BYTES,
        )?;
        Ok(consensus_writeback)
    }

    pub fn commit_prepared_writeback_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                max_ciphertext_bytes,
                signature_verification,
                None,
            )
        })
    }

    pub fn commit_replica_writeback_with_signature(
        &self,
        expected_consensus_writeback: &PrivateHnswOramConsensusWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                max_ciphertext_bytes,
                signature_verification,
                Some(expected_consensus_writeback),
            )
        })
    }

    fn commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
        expected_consensus_writeback: Option<&PrivateHnswOramConsensusWriteback>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        self.validate_canonical_writer_lock_v1(lock)?;
        let pending: PrivateHnswPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        let consensus_writeback = self.validate_pending_writeback(
            &pending,
            max_ciphertext_bytes,
            signature_verification,
        )?;
        if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM pending writeback consensus transition does not match",
            ));
        }

        let current = self.read_current_epoch()?;
        if current != pending.old && current != pending.new {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM pending writeback epoch/root does not match current state",
            ));
        }
        for bucket in &pending.updated_buckets {
            self.write_bucket_under_owner_lock(
                lock,
                bucket,
                pending.new.index_epoch,
                pending.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_merkle_tree_under_owner_lock(lock, &pending.merkle_tree)?;
        if current == pending.old {
            self.compare_and_swap_epoch_with_writeback_digest_under_owner_lock(
                lock,
                &pending.old,
                &pending.new,
                Some(&consensus_writeback.writeback_digest),
            )?;
        }

        if self.read_current_epoch()? != pending.new
            || self.read_merkle_tree()? != pending.merkle_tree
        {
            return Err(CollectionError::service_error(
                "private HNSW ORAM pending writeback final state validation failed",
            ));
        }
        for expected_bucket in &pending.updated_buckets {
            let stored_bucket = self.read_bucket(
                expected_bucket.bucket_id,
                pending.new.index_epoch,
                pending.bucket_count,
                max_ciphertext_bytes,
            )?;
            if stored_bucket != *expected_bucket {
                return Err(CollectionError::service_error(
                    "private HNSW ORAM pending writeback final state validation failed",
                ));
            }
        }
        self.write_completed_writeback_record_under_owner_lock(lock, &consensus_writeback)?;
        self.remove_pending_writeback_record_under_owner_lock(lock)?;
        Ok(pending.new)
    }

    pub fn completed_replica_writeback_matches(
        &self,
        expected: &PrivateHnswOramConsensusWriteback,
    ) -> CollectionResult<bool> {
        validate_writeback_digest(&expected.writeback_digest)?;
        if self.pending_writeback_exists()? || self.read_current_epoch()? != expected.new {
            return Ok(false);
        }
        let tree = self.read_merkle_tree()?;
        if tree.index_epoch != expected.new.index_epoch || tree.root_hash != expected.new.root_hash
        {
            return Ok(false);
        }
        let commit = self.read_epoch_commit(expected.new.index_epoch)?;
        Ok(commit.index_epoch == expected.new.index_epoch
            && commit.root_hash == expected.new.root_hash
            && commit.writeback_digest.as_deref() == Some(&expected.writeback_digest))
    }

    fn write_completed_writeback_record_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        expected: &PrivateHnswOramConsensusWriteback,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_writeback_digest(&expected.writeback_digest)?;
        let completed = PrivateHnswOramEpochCommit {
            index_epoch: expected.new.index_epoch,
            root_hash: expected.new.root_hash.clone(),
            writeback_digest: Some(expected.writeback_digest.clone()),
        };
        match self.read_epoch_commit(expected.new.index_epoch) {
            Ok(existing) if existing == completed => return Ok(()),
            Ok(existing)
                if existing.index_epoch == completed.index_epoch
                    && existing.root_hash == completed.root_hash
                    && existing.writeback_digest.is_none() => {}
            Ok(_) => {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM completed writeback record does not match",
                ));
            }
            Err(CollectionError::NotFound { .. }) => {}
            Err(err) => return Err(err),
        }
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.commit_epoch_path(completed.index_epoch),
            &completed,
        )
    }

    fn remove_pending_writeback_record_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        remove_private_file(
            &self.pending_writeback_path(),
            &self.temp_dir(),
            MAX_PENDING_WRITEBACK_BYTES,
        )
    }

    fn read_epoch_commit(&self, epoch: u64) -> CollectionResult<PrivateHnswOramEpochCommit> {
        validate_private_dir(&self.epochs_dir())?;
        let commit = read_json_private_file(&self.commit_epoch_path(epoch), MAX_EPOCH_BYTES)?;
        validate_epoch_commit(&commit, epoch)?;
        Ok(commit)
    }

    pub fn pending_writeback_exists(&self) -> CollectionResult<bool> {
        match fs::symlink_metadata(self.pending_writeback_path()) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(CollectionError::service_error(
                "failed to inspect private HNSW ORAM pending writeback",
            )),
        }
    }

    pub fn pending_writeback_consensus_transition_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<Option<PrivateHnswOramConsensusWriteback>> {
        if !self.pending_writeback_exists()? {
            return Ok(None);
        }
        let pending: PrivateHnswPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        self.validate_pending_writeback(&pending, max_ciphertext_bytes, signature_verification)
            .map(Some)
    }

    pub fn pending_writeback_replication_batch_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<
        Option<(
            PrivateHnswOramWritebackBatch,
            PrivateHnswOramConsensusWriteback,
        )>,
    > {
        if !self.pending_writeback_exists()? {
            return Ok(None);
        }
        let pending: PrivateHnswPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        let consensus_writeback = self.validate_pending_writeback(
            &pending,
            max_ciphertext_bytes,
            signature_verification,
        )?;
        Ok(Some((
            PrivateHnswOramWritebackBatch {
                version: pending.version,
                old: pending.old,
                new: pending.new,
                bucket_count: pending.bucket_count,
                updated_buckets: pending.updated_buckets,
                commit_signature: pending.commit_signature,
            },
            consensus_writeback,
        )))
    }

    pub fn prepare_replica_writeback_with_signature(
        &self,
        batch: &PrivateHnswOramWritebackBatch,
        expected_consensus_writeback: &PrivateHnswOramConsensusWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramConsensusWriteback> {
        if batch.version != 1 {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM replicated writeback is invalid",
            ));
        }
        self.with_canonical_writer_lock_v1(|lock| {
            self.prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                &batch.old,
                &batch.new,
                batch.bucket_count,
                &batch.updated_buckets,
                max_ciphertext_bytes,
                &batch.commit_signature,
                signature_verification,
                Some(expected_consensus_writeback),
            )
        })
    }

    pub fn recover_pending_writeback_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<Option<PrivateHnswOramEpochState>> {
        self.with_canonical_writer_lock_v1(|lock| {
            if !self.pending_writeback_exists()? {
                return Ok(None);
            }
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                max_ciphertext_bytes,
                signature_verification,
                None,
            )
            .map(Some)
        })
    }

    pub fn abort_pending_writeback_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<bool> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.abort_pending_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                max_ciphertext_bytes,
                signature_verification,
                None,
            )
        })
    }

    pub fn abort_replica_writeback_with_signature(
        &self,
        expected_consensus_writeback: &PrivateHnswOramConsensusWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<bool> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.abort_pending_writeback_with_signature_and_consensus_under_owner_lock(
                lock,
                max_ciphertext_bytes,
                signature_verification,
                Some(expected_consensus_writeback),
            )
        })
    }

    fn abort_pending_writeback_with_signature_and_consensus_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
        expected_consensus_writeback: Option<&PrivateHnswOramConsensusWriteback>,
    ) -> CollectionResult<bool> {
        self.validate_canonical_writer_lock_v1(lock)?;
        if !self.pending_writeback_exists()? {
            return Ok(false);
        }
        let pending: PrivateHnswPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        let consensus_writeback = self.validate_pending_writeback(
            &pending,
            max_ciphertext_bytes,
            signature_verification,
        )?;
        if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM pending writeback consensus transition does not match",
            ));
        }
        self.ensure_current_epoch_matches(&pending.old)?;
        let old_tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(
            &old_tree,
            pending.old.index_epoch,
            &pending.old.root_hash,
            pending.bucket_count,
        )?;
        for updated_bucket in &pending.updated_buckets {
            let stored_bucket = self.read_bucket(
                updated_bucket.bucket_id,
                pending.old.index_epoch,
                pending.bucket_count,
                max_ciphertext_bytes,
            )?;
            let bucket_index = usize::try_from(updated_bucket.bucket_id).map_err(|_| {
                CollectionError::bad_request("private HNSW ORAM pending writeback is invalid")
            })?;
            if old_tree.leaf_hashes.get(bucket_index) != Some(&stored_bucket.bucket_commitment) {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM pending writeback abort state is invalid",
                ));
            }
        }
        self.remove_pending_writeback_record_under_owner_lock(lock)?;
        Ok(true)
    }

    fn validate_pending_writeback(
        &self,
        pending: &PrivateHnswPendingWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramConsensusWriteback> {
        if pending.version != 1 || pending.updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM pending writeback is invalid",
            ));
        }
        validate_epoch_state(&pending.old)?;
        validate_epoch_state(&pending.new)?;
        if Some(pending.new.index_epoch) != pending.old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM pending writeback is invalid",
            ));
        }

        let (manifest, _) = self.read_manifest()?;
        validate_commit_manifest_context(&manifest, &pending.old, pending.bucket_count)?;
        validate_fixed_writeback_budget(&manifest, pending.updated_buckets.len())?;
        let mut seen_bucket_ids = BTreeSet::new();
        for bucket in &pending.updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM pending writeback is invalid",
                ));
            }
            validate_bucket(
                bucket,
                pending.new.index_epoch,
                pending.bucket_count,
                max_ciphertext_bytes,
            )?;
            validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
        }
        validate_bucket_commitment_context(
            &manifest,
            pending.new.index_epoch,
            &pending.updated_buckets,
        )?;
        validate_merkle_tree_context(
            &pending.merkle_tree,
            pending.new.index_epoch,
            &pending.new.root_hash,
            pending.bucket_count,
        )?;
        for bucket in &pending.updated_buckets {
            let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
                CollectionError::bad_request("private HNSW ORAM pending writeback is invalid")
            })?;
            if pending.merkle_tree.leaf_hashes.get(bucket_index) != Some(&bucket.bucket_commitment)
            {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM pending writeback is invalid",
                ));
            }
        }

        let updated_bucket_refs = pending
            .updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        let signature_input = PrivateHnswOramCommitSignatureInput {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            old_epoch: pending.old.index_epoch,
            new_epoch: pending.new.index_epoch,
            old_root_hash: &pending.old.root_hash,
            new_root_hash: &pending.new.root_hash,
            updated_buckets: &updated_bucket_refs,
            signature_alg: &pending.commit_signature.alg,
            signature_key_id: &pending.commit_signature.key_id,
        };
        validate_private_hnsw_oram_commit_signature(
            signature_input,
            &pending.commit_signature.sig,
            signature_verification,
        )
        .map_err(private_hnsw_oram_error)?;
        let writeback_digest =
            private_hnsw_oram_writeback_digest(signature_input).map_err(private_hnsw_oram_error)?;
        Ok(PrivateHnswOramConsensusWriteback {
            old: pending.old.clone(),
            new: pending.new.clone(),
            writeback_digest,
        })
    }

    pub fn merkle_root_for_commitments(commitments: &[String]) -> CollectionResult<String> {
        let levels = merkle_levels(commitments)?;
        let root = levels
            .last()
            .and_then(|level| level.first())
            .ok_or_else(|| {
                CollectionError::bad_request("private HNSW ORAM Merkle tree is empty")
            })?;
        Ok(BASE64URL_NOPAD.encode(root))
    }

    pub fn write_merkle_tree_from_commitments(
        &self,
        index_epoch: u64,
        root_hash: String,
        leaf_hashes: Vec<String>,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            self.write_merkle_tree_from_commitments_under_owner_lock(
                lock,
                index_epoch,
                root_hash,
                leaf_hashes,
            )
        })
    }

    fn write_merkle_tree_from_commitments_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        index_epoch: u64,
        root_hash: String,
        leaf_hashes: Vec<String>,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        let bucket_count = u64::try_from(leaf_hashes.len()).map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM Merkle tree bucket_count exceeds u64")
        })?;
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch,
            root_hash,
            bucket_count,
            leaf_hashes,
        };
        validate_merkle_tree(&tree)?;
        self.write_merkle_tree_under_owner_lock(lock, &tree)
    }

    pub fn read_merkle_path_batch(
        &self,
        bucket_ids: &[u64],
        expected_epoch: u64,
        expected_root_hash: &str,
        expected_bucket_count: u64,
    ) -> CollectionResult<PrivateHnswOramMerkleProof> {
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle proof bucket batch is empty",
            ));
        }
        let tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(
            &tree,
            expected_epoch,
            expected_root_hash,
            expected_bucket_count,
        )?;
        let levels = merkle_levels(&tree.leaf_hashes)?;
        let mut leaves = Vec::with_capacity(bucket_ids.len());
        for &bucket_id in bucket_ids {
            if bucket_id >= tree.bucket_count {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle proof bucket is out of range",
                ));
            }
            let bucket_index = usize::try_from(bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private HNSW ORAM Merkle proof bucket id exceeds usize",
                )
            })?;
            leaves.push(PrivateHnswOramMerkleProofLeaf {
                bucket_id,
                leaf_hash: tree.leaf_hashes[bucket_index].clone(),
                siblings: merkle_siblings_for_bucket(&levels, bucket_index)?,
            });
        }

        Ok(PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: tree.index_epoch,
            root_hash: tree.root_hash,
            bucket_count: tree.bucket_count,
            leaves,
        })
    }

    pub fn read_bucket_batch_with_proof(
        &self,
        bucket_ids: &[u64],
        expected_epoch: u64,
        expected_root_hash: &str,
        expected_bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<(Vec<PrivateHnswOramBucket>, PrivateHnswOramMerkleProof)> {
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket batch is empty",
            ));
        }
        let expected = PrivateHnswOramEpochState {
            index_epoch: expected_epoch,
            root_hash: expected_root_hash.to_string(),
        };
        self.ensure_current_epoch_matches(&expected)?;
        let proof = self.read_merkle_path_batch(
            bucket_ids,
            expected_epoch,
            expected_root_hash,
            expected_bucket_count,
        )?;
        let mut buckets = Vec::with_capacity(bucket_ids.len());
        for &bucket_id in bucket_ids {
            buckets.push(self.read_bucket(
                bucket_id,
                expected_epoch,
                expected_bucket_count,
                max_ciphertext_bytes,
            )?);
        }
        ensure_read_proof_matches_buckets(&proof, &buckets)?;
        Ok((buckets, proof))
    }

    pub fn write_merkle_commit(
        &self,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|lock| {
            let tree = self.prepare_merkle_commit_under_owner_lock(
                lock,
                old_epoch,
                old_root_hash,
                new_epoch,
                new_root_hash,
                bucket_count,
                updated_buckets,
            )?;
            self.write_merkle_tree_under_owner_lock(lock, &tree)
        })
    }

    fn prepare_merkle_commit_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
    ) -> CollectionResult<PrivateHnswOramMerkleTree> {
        self.validate_canonical_writer_lock_v1(lock)?;
        if new_epoch <= old_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit new epoch must be exactly old epoch + 1",
            ));
        }
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit must update at least one bucket",
            ));
        }
        let mut tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(&tree, old_epoch, old_root_hash, bucket_count)?;
        let mut seen_bucket_ids = BTreeSet::new();
        for bucket in updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit repeats a bucket",
                ));
            }
            if bucket.index_epoch != new_epoch {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit bucket has stale epoch",
                ));
            }
            if bucket.bucket_id >= bucket_count {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit bucket is out of range",
                ));
            }
            decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
            let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit bucket id exceeds usize",
                )
            })?;
            tree.leaf_hashes[bucket_index] = bucket.bucket_commitment.clone();
        }
        let computed_root = Self::merkle_root_for_commitments(&tree.leaf_hashes)?;
        if computed_root != new_root_hash {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit new_root_hash mismatch",
            ));
        }
        tree.index_epoch = new_epoch;
        tree.root_hash = new_root_hash.to_string();
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    fn read_merkle_tree(&self) -> CollectionResult<PrivateHnswOramMerkleTree> {
        validate_private_dir(&self.merkle_dir())?;
        let tree = read_json_private_file(&self.merkle_nodes_path(), MAX_MERKLE_BYTES)?;
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    fn write_merkle_tree_under_owner_lock(
        &self,
        lock: &PrivateHnswCanonicalWriterLockV1<'_>,
        tree: &PrivateHnswOramMerkleTree,
    ) -> CollectionResult<()> {
        self.validate_canonical_writer_lock_v1(lock)?;
        validate_merkle_tree(tree)?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.merkle_nodes_path(),
            tree,
        )
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE)
    }

    fn manifest_signature_path(&self) -> PathBuf {
        self.root.join(MANIFEST_SIGNATURE_FILE)
    }

    fn buckets_dir(&self) -> PathBuf {
        self.root.join(BUCKETS_DIR)
    }

    fn epochs_dir(&self) -> PathBuf {
        self.root.join(EPOCHS_DIR)
    }

    fn merkle_dir(&self) -> PathBuf {
        self.root.join(MERKLE_DIR)
    }

    fn temp_dir(&self) -> PathBuf {
        self.root.join(TEMP_DIR)
    }

    fn pending_writeback_path(&self) -> PathBuf {
        self.temp_dir().join(PENDING_WRITEBACK_FILE)
    }

    fn current_epoch_path(&self) -> PathBuf {
        self.epochs_dir().join(CURRENT_EPOCH_FILE)
    }

    fn merkle_nodes_path(&self) -> PathBuf {
        self.merkle_dir().join(MERKLE_NODES_FILE)
    }

    fn commit_epoch_path(&self, epoch: u64) -> PathBuf {
        self.epochs_dir().join(format!("{epoch:08}.commit"))
    }

    fn bucket_path(&self, bucket_id: u64) -> PathBuf {
        self.buckets_dir().join(format!("{bucket_id:08}.bucket"))
    }

    fn ensure_current_epoch_matches(
        &self,
        expected: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        let current = self.read_current_epoch()?;
        if &current != expected {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
        }
        Ok(())
    }
}

impl PrivateHnswOwnerStoreLockV1<'_> {
    pub(crate) fn classify_owner_state_v1<'lock>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOwnerStoreObservationV1<'lock>> {
        let final_buckets = authority
            .hnsw_final_buckets()
            .ok_or_else(owner_store_state_mismatch)?;
        let context = PrivateHnswOwnerStoreVerificationContextV1 {
            journal_descriptor_digest: authority.journal_descriptor_digest(),
            prepared_state_digest: authority.prepared_state_digest(),
            immutable_manifest_digest: authority.immutable_manifest_digest(),
            immutable_manifest: authority.immutable_manifest(),
            immutable_index: authority.immutable_index(),
            index_name: authority.index_name(),
            old_state: authority.old_state(),
            new_state: authority.new_state(),
            final_bucket_refs: authority.final_bucket_refs(),
            final_buckets,
            max_ciphertext_bytes,
            manifest_validation,
        };
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;
        let current = self.store.read_current_epoch()?;
        let old = PrivateHnswOramEpochState {
            index_epoch: context.old_state.index_epoch,
            root_hash: context.old_state.root_hash.clone(),
        };
        let new = PrivateHnswOramEpochState {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
        };
        if current == old {
            return self
                .verify_exact_old(context)
                .map(PrivateHnswOwnerStoreObservationV1::Old);
        }
        if current == new {
            return self
                .verify_exact_new(context)
                .map(PrivateHnswOwnerStoreObservationV1::New);
        }
        ensure_owner_store_has_no_legacy_pending(self.store)?;
        if self.store.read_current_epoch()? != current {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(PrivateHnswOwnerStoreObservationV1::Third)
    }

    pub(crate) fn classify_owner_recovery_phase_v1(
        &self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOwnerRecoveryPhaseV1> {
        let context = owner_store_verification_context_from_authority(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        Ok(self.classify_owner_recovery_state_v1(context)?.phase)
    }

    pub(crate) fn verify_owner_exact_old_v1<'lock>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOwnerExactOldStoreTokenV1<'lock>> {
        let context = owner_store_verification_context_from_authority(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        self.verify_exact_old(context)
    }

    pub(crate) fn verify_owner_exact_new_v1<'lock>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOwnerExactNewStoreTokenV1<'lock>> {
        let context = owner_store_verification_context_from_authority(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        self.verify_exact_new(context)
    }

    pub(crate) fn resume_owner_recovery_to_exact_new_v1<'lock>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOwnerExactNewStoreTokenV1<'lock>> {
        let context = owner_store_verification_context_from_authority(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        self.resume_owner_recovery_context_to_exact_new_v1(context)
    }

    fn resume_owner_recovery_context_to_exact_new_v1<'lock>(
        &'lock self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateHnswOwnerExactNewStoreTokenV1<'lock>> {
        let mut evidence = self.classify_owner_recovery_state_v1(context)?;
        let written_bucket_count = match evidence.phase {
            PrivateHnswOwnerRecoveryPhaseV1::S0 => 0,
            PrivateHnswOwnerRecoveryPhaseV1::S1 {
                written_bucket_count,
            } => written_bucket_count,
            PrivateHnswOwnerRecoveryPhaseV1::S2
            | PrivateHnswOwnerRecoveryPhaseV1::S3
            | PrivateHnswOwnerRecoveryPhaseV1::S4 => context.final_buckets.len(),
        };

        if written_bucket_count < context.final_buckets.len() {
            for (offset, bucket) in context.final_buckets[written_bucket_count..]
                .iter()
                .enumerate()
            {
                let expected_written_bucket_count = written_bucket_count
                    .checked_add(offset)
                    .ok_or_else(owner_store_state_mismatch)?;
                self.write_owner_recovery_bucket_v1(
                    context,
                    expected_written_bucket_count,
                    bucket,
                    &evidence,
                )?;
            }
            evidence = self.classify_owner_recovery_state_v1(context)?;
        }

        if evidence.phase
            == (PrivateHnswOwnerRecoveryPhaseV1::S1 {
                written_bucket_count: context.final_buckets.len(),
            })
        {
            self.write_owner_recovery_merkle_tree_v1(context)?;
            evidence = self.classify_owner_recovery_state_v1(context)?;
        }

        if evidence.phase == PrivateHnswOwnerRecoveryPhaseV1::S2 {
            self.publish_owner_recovery_commit_v1(context)?;
            evidence = self.classify_owner_recovery_state_v1(context)?;
        }

        if evidence.phase == PrivateHnswOwnerRecoveryPhaseV1::S3 {
            self.publish_owner_recovery_current_v1(context)?;
            evidence = self.classify_owner_recovery_state_v1(context)?;
        }

        if evidence.phase != PrivateHnswOwnerRecoveryPhaseV1::S4 {
            return Err(owner_store_state_mismatch());
        }
        self.verify_exact_new(context)
    }

    fn classify_owner_recovery_state_v1(
        &self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateHnswOwnerRecoveryEvidenceV1> {
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;

        let (manifest, signature) = self.store.read_manifest()?;
        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            context.manifest_validation,
        )
        .map_err(private_hnsw_oram_error)?;
        validate_owner_store_context(&manifest, context, OwnerStorePhase::ExactOld)?;

        let old = PrivateHnswOramEpochState {
            index_epoch: context.old_state.index_epoch,
            root_hash: context.old_state.root_hash.clone(),
        };
        let new = PrivateHnswOramEpochState {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
        };
        let current = self.store.read_current_epoch()?;
        if current != old && current != new {
            return Err(owner_store_state_mismatch());
        }

        let tree = self.store.read_merkle_tree()?;
        let tree_is_old = validate_merkle_tree_context(
            &tree,
            old.index_epoch,
            &old.root_hash,
            manifest.bucket_count,
        )
        .is_ok();
        let tree_is_new = validate_merkle_tree_context(
            &tree,
            new.index_epoch,
            &new.root_hash,
            manifest.bucket_count,
        )
        .is_ok();
        if tree_is_old == tree_is_new {
            return Err(owner_store_state_mismatch());
        }

        let epoch_directory_digest =
            validate_owner_store_epoch_directory(self.store, new.index_epoch)?;
        let old_commit_kind = validate_owner_store_old_commit(self.store, &manifest, context)?;
        let new_commit_exists = validate_owner_store_new_commit_if_present(self.store, context)?;

        let (written_bucket_count, new_merkle_tree) = if tree_is_old {
            let written_bucket_count =
                classify_owner_recovery_bucket_prefix(self.store, &manifest, &tree, context)?;
            let new_tree = owner_recovery_new_merkle_tree(&tree, context)?;
            (written_bucket_count, new_tree)
        } else {
            read_owner_store_buckets(
                self.store,
                &manifest,
                &tree,
                context,
                OwnerStorePhase::ExactNew,
            )?;
            (context.final_buckets.len(), tree.clone())
        };

        let phase = if current == old && tree_is_old && !new_commit_exists {
            if written_bucket_count == 0 {
                PrivateHnswOwnerRecoveryPhaseV1::S0
            } else {
                PrivateHnswOwnerRecoveryPhaseV1::S1 {
                    written_bucket_count,
                }
            }
        } else if current == old && tree_is_new && !new_commit_exists {
            PrivateHnswOwnerRecoveryPhaseV1::S2
        } else if current == old && tree_is_new && new_commit_exists {
            PrivateHnswOwnerRecoveryPhaseV1::S3
        } else if current == new && tree_is_new && new_commit_exists {
            PrivateHnswOwnerRecoveryPhaseV1::S4
        } else {
            return Err(owner_store_state_mismatch());
        };

        ensure_owner_store_has_no_legacy_pending(self.store)?;
        if self.store.read_manifest()? != (manifest.clone(), signature.clone())
            || self.store.read_current_epoch()? != current
            || self.store.read_merkle_tree()? != tree
            || validate_owner_store_old_commit(self.store, &manifest, context)? != old_commit_kind
            || validate_owner_store_new_commit_if_present(self.store, context)? != new_commit_exists
        {
            return Err(owner_store_state_mismatch());
        }
        if validate_owner_store_epoch_directory(self.store, new.index_epoch)?
            != epoch_directory_digest
        {
            return Err(owner_store_state_mismatch());
        }
        if tree_is_old {
            if classify_owner_recovery_bucket_prefix(self.store, &manifest, &tree, context)?
                != written_bucket_count
            {
                return Err(owner_store_state_mismatch());
            }
        } else {
            read_owner_store_buckets(
                self.store,
                &manifest,
                &tree,
                context,
                OwnerStorePhase::ExactNew,
            )?;
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(PrivateHnswOwnerRecoveryEvidenceV1 {
            phase,
            manifest,
            manifest_signature: signature,
            observed_merkle_tree: tree,
            old_commit_kind,
            new_merkle_tree,
        })
    }

    fn write_owner_recovery_bucket_v1(
        &self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
        expected_written_bucket_count: usize,
        bucket: &PrivateHnswOramBucket,
        evidence: &PrivateHnswOwnerRecoveryEvidenceV1,
    ) -> CollectionResult<()> {
        let initial_written_bucket_count = match evidence.phase {
            PrivateHnswOwnerRecoveryPhaseV1::S0 => 0,
            PrivateHnswOwnerRecoveryPhaseV1::S1 {
                written_bucket_count,
            } => written_bucket_count,
            _ => return Err(owner_store_state_mismatch()),
        };
        if expected_written_bucket_count < initial_written_bucket_count
            || context.final_buckets.get(expected_written_bucket_count) != Some(bucket)
            || context
                .final_bucket_refs
                .get(expected_written_bucket_count)
                .is_none_or(|bucket_ref| bucket_ref.bucket_id != bucket.bucket_id)
        {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;
        if self.store.read_manifest()?
            != (
                evidence.manifest.clone(),
                evidence.manifest_signature.clone(),
            )
        {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_context(&evidence.manifest, context, OwnerStorePhase::ExactOld)?;
        let expected_old = PrivateHnswOramEpochState {
            index_epoch: context.old_state.index_epoch,
            root_hash: context.old_state.root_hash.clone(),
        };
        if self.store.read_current_epoch()? != expected_old
            || self.store.read_merkle_tree()? != evidence.observed_merkle_tree
            || validate_owner_store_old_commit(self.store, &evidence.manifest, context)?
                != evidence.old_commit_kind
            || validate_owner_store_new_commit_if_present(self.store, context)?
        {
            return Err(owner_store_state_mismatch());
        }
        validate_merkle_tree_context(
            &evidence.observed_merkle_tree,
            context.old_state.index_epoch,
            &context.old_state.root_hash,
            evidence.manifest.bucket_count,
        )?;

        let max_bucket_file_bytes = max_bucket_file_bytes(context.max_ciphertext_bytes)?;
        let old_bucket: PrivateHnswOramBucket = read_json_private_file(
            &self.store.bucket_path(bucket.bucket_id),
            max_bucket_file_bytes,
        )?;
        if old_bucket.bucket_id != bucket.bucket_id || old_bucket == *bucket {
            return Err(owner_store_state_mismatch());
        }
        validate_bucket_for_read(
            &old_bucket,
            context.old_state.index_epoch,
            evidence.manifest.bucket_count,
            context.max_ciphertext_bytes,
        )?;
        validate_bucket_ciphertext_fixed_size(&old_bucket, &evidence.manifest)?;
        validate_bucket_commitment_context(
            &evidence.manifest,
            old_bucket.index_epoch,
            std::slice::from_ref(&old_bucket),
        )?;
        let old_bucket_index =
            usize::try_from(old_bucket.bucket_id).map_err(|_| owner_store_state_mismatch())?;
        if evidence
            .observed_merkle_tree
            .leaf_hashes
            .get(old_bucket_index)
            != Some(&old_bucket.bucket_commitment)
        {
            return Err(owner_store_state_mismatch());
        }
        if let Some(previous_index) = expected_written_bucket_count.checked_sub(1) {
            let previous = context
                .final_buckets
                .get(previous_index)
                .ok_or_else(owner_store_state_mismatch)?;
            let observed_previous: PrivateHnswOramBucket = read_json_private_file(
                &self.store.bucket_path(previous.bucket_id),
                max_bucket_file_bytes,
            )?;
            if observed_previous != *previous {
                return Err(owner_store_state_mismatch());
            }
        }

        validate_bucket(
            bucket,
            context.new_state.index_epoch,
            evidence.manifest.bucket_count,
            context.max_ciphertext_bytes,
        )?;
        validate_bucket_ciphertext_fixed_size(bucket, &evidence.manifest)?;
        validate_bucket_commitment_context(
            &evidence.manifest,
            context.new_state.index_epoch,
            std::slice::from_ref(bucket),
        )?;
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.bucket_path(bucket.bucket_id),
            bucket,
        )?;
        let observed_bucket: PrivateHnswOramBucket = read_json_private_file(
            &self.store.bucket_path(bucket.bucket_id),
            max_bucket_file_bytes,
        )?;
        if observed_bucket != *bucket
            || self.store.read_manifest()?
                != (
                    evidence.manifest.clone(),
                    evidence.manifest_signature.clone(),
                )
            || self.store.read_current_epoch()? != expected_old
            || self.store.read_merkle_tree()? != evidence.observed_merkle_tree
            || validate_owner_store_old_commit(self.store, &evidence.manifest, context)?
                != evidence.old_commit_kind
            || validate_owner_store_new_commit_if_present(self.store, context)?
        {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(())
    }

    fn write_owner_recovery_merkle_tree_v1(
        &self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<()> {
        let evidence = self.classify_owner_recovery_state_v1(context)?;
        if evidence.phase
            != (PrivateHnswOwnerRecoveryPhaseV1::S1 {
                written_bucket_count: context.final_buckets.len(),
            })
        {
            return Err(owner_store_state_mismatch());
        }
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.merkle_nodes_path(),
            &evidence.new_merkle_tree,
        )?;
        if self.classify_owner_recovery_state_v1(context)?.phase
            != PrivateHnswOwnerRecoveryPhaseV1::S2
        {
            return Err(owner_store_state_mismatch());
        }
        Ok(())
    }

    fn publish_owner_recovery_commit_v1(
        &self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<()> {
        if self.classify_owner_recovery_state_v1(context)?.phase
            != PrivateHnswOwnerRecoveryPhaseV1::S2
        {
            return Err(owner_store_state_mismatch());
        }
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.commit_epoch_path(context.new_state.index_epoch),
            &PrivateHnswOramEpochCommit {
                index_epoch: context.new_state.index_epoch,
                root_hash: context.new_state.root_hash.clone(),
                writeback_digest: Some(context.new_state.last_writeback_digest.clone()),
            },
        )?;
        if self.classify_owner_recovery_state_v1(context)?.phase
            != PrivateHnswOwnerRecoveryPhaseV1::S3
        {
            return Err(owner_store_state_mismatch());
        }
        Ok(())
    }

    fn publish_owner_recovery_current_v1(
        &self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<()> {
        if self.classify_owner_recovery_state_v1(context)?.phase
            != PrivateHnswOwnerRecoveryPhaseV1::S3
        {
            return Err(owner_store_state_mismatch());
        }
        let new = PrivateHnswOramEpochState {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
        };
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.current_epoch_path(),
            &new,
        )?;
        if self.classify_owner_recovery_state_v1(context)?.phase
            != PrivateHnswOwnerRecoveryPhaseV1::S4
        {
            return Err(owner_store_state_mismatch());
        }
        Ok(())
    }

    fn verify_exact_old<'lock>(
        &'lock self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateHnswOwnerExactOldStoreTokenV1<'lock>> {
        let evidence = self.verify_exact_state(context, OwnerStorePhase::ExactOld)?;
        Ok(PrivateHnswOwnerExactOldStoreTokenV1 {
            index_name: context.index_name.to_string(),
            canonical_state_digest: evidence.canonical_state_digest,
            _lock: PhantomData,
        })
    }

    fn verify_exact_new<'lock>(
        &'lock self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateHnswOwnerExactNewStoreTokenV1<'lock>> {
        let evidence = self.verify_exact_state(context, OwnerStorePhase::ExactNew)?;
        Ok(PrivateHnswOwnerExactNewStoreTokenV1 {
            index_name: context.index_name.to_string(),
            canonical_state_digest: evidence.canonical_state_digest,
            _lock: PhantomData,
        })
    }

    fn verify_exact_state(
        &self,
        context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
        phase: OwnerStorePhase,
    ) -> CollectionResult<OwnerStoreEvidence> {
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;

        let (manifest, signature) = self.store.read_manifest()?;
        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            context.manifest_validation,
        )
        .map_err(private_hnsw_oram_error)?;
        validate_owner_store_context(&manifest, context, phase)?;
        let store_manifest_digest = digest_bytes(
            &try_private_hnsw_oram_manifest_signature_message(&manifest)
                .map_err(private_hnsw_oram_error)?,
        );

        let target = match phase {
            OwnerStorePhase::ExactOld => context.old_state,
            OwnerStorePhase::ExactNew => context.new_state,
        };
        let expected_epoch = PrivateHnswOramEpochState {
            index_epoch: target.index_epoch,
            root_hash: target.root_hash.clone(),
        };
        if self.store.read_current_epoch()? != expected_epoch {
            return Err(owner_store_state_mismatch());
        }

        let tree = self.store.read_merkle_tree()?;
        validate_merkle_tree_context(
            &tree,
            target.index_epoch,
            &target.root_hash,
            manifest.bucket_count,
        )?;
        let epoch_directory_digest =
            validate_owner_store_epoch_directory(self.store, target.index_epoch)?;
        let commit_kind =
            validate_owner_store_epoch_commits(self.store, &manifest, context, phase)?;
        let buckets = read_owner_store_buckets(self.store, &manifest, &tree, context, phase)?;

        ensure_owner_store_has_no_legacy_pending(self.store)?;
        if validate_owner_store_epoch_directory(self.store, target.index_epoch)?
            != epoch_directory_digest
        {
            return Err(owner_store_state_mismatch());
        }
        if self.store.read_manifest()? != (manifest.clone(), signature) {
            return Err(owner_store_state_mismatch());
        }
        if self.store.read_current_epoch()? != expected_epoch
            || self.store.read_merkle_tree()? != tree
            || validate_owner_store_epoch_commits(self.store, &manifest, context, phase)?
                != commit_kind
            || read_owner_store_buckets(self.store, &manifest, &tree, context, phase)? != buckets
        {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;

        Ok(OwnerStoreEvidence {
            canonical_state_digest: owner_store_canonical_state_digest(
                context,
                phase,
                &store_manifest_digest,
                &tree,
                commit_kind,
                &epoch_directory_digest,
                &buckets,
            ),
        })
    }
}

fn owner_store_verification_context_from_authority<'a>(
    authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a>,
    max_ciphertext_bytes: usize,
    manifest_validation: PrivateHnswManifestValidationContext<'a>,
) -> CollectionResult<PrivateHnswOwnerStoreVerificationContextV1<'a>> {
    let final_buckets = authority
        .hnsw_final_buckets()
        .ok_or_else(owner_store_state_mismatch)?;
    Ok(PrivateHnswOwnerStoreVerificationContextV1 {
        journal_descriptor_digest: authority.journal_descriptor_digest(),
        prepared_state_digest: authority.prepared_state_digest(),
        immutable_manifest_digest: authority.immutable_manifest_digest(),
        immutable_manifest: authority.immutable_manifest(),
        immutable_index: authority.immutable_index(),
        index_name: authority.index_name(),
        old_state: authority.old_state(),
        new_state: authority.new_state(),
        final_bucket_refs: authority.final_bucket_refs(),
        final_buckets,
        max_ciphertext_bytes,
        manifest_validation,
    })
}

fn classify_owner_recovery_bucket_prefix(
    store: &PrivateHnswOramStore,
    manifest: &PrivateHnswOramManifest,
    old_tree: &PrivateHnswOramMerkleTree,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<usize> {
    let max_bucket_file_bytes = max_bucket_file_bytes(context.max_ciphertext_bytes)?;
    let mut written_bucket_count = 0;
    let mut observed_old = false;
    for (bucket_ref, final_bucket) in context.final_bucket_refs.iter().zip(context.final_buckets) {
        let bucket: PrivateHnswOramBucket = read_json_private_file(
            &store.bucket_path(bucket_ref.bucket_id),
            max_bucket_file_bytes,
        )?;
        if bucket.bucket_id != bucket_ref.bucket_id {
            return Err(owner_store_state_mismatch());
        }
        if bucket == *final_bucket {
            if observed_old {
                return Err(owner_store_state_mismatch());
            }
            validate_bucket(
                &bucket,
                context.new_state.index_epoch,
                manifest.bucket_count,
                context.max_ciphertext_bytes,
            )?;
            validate_bucket_ciphertext_fixed_size(&bucket, manifest)?;
            validate_bucket_commitment_context(
                manifest,
                context.new_state.index_epoch,
                std::slice::from_ref(&bucket),
            )?;
            written_bucket_count += 1;
            continue;
        }

        observed_old = true;
        validate_bucket_for_read(
            &bucket,
            context.old_state.index_epoch,
            manifest.bucket_count,
            context.max_ciphertext_bytes,
        )?;
        validate_bucket_ciphertext_fixed_size(&bucket, manifest)?;
        validate_bucket_commitment_context(
            manifest,
            bucket.index_epoch,
            std::slice::from_ref(&bucket),
        )?;
        let bucket_index =
            usize::try_from(bucket.bucket_id).map_err(|_| owner_store_state_mismatch())?;
        if old_tree.leaf_hashes.get(bucket_index) != Some(&bucket.bucket_commitment) {
            return Err(owner_store_state_mismatch());
        }
    }
    Ok(written_bucket_count)
}

fn owner_recovery_new_merkle_tree(
    old_tree: &PrivateHnswOramMerkleTree,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<PrivateHnswOramMerkleTree> {
    let mut tree = old_tree.clone();
    for bucket in context.final_buckets {
        let bucket_index =
            usize::try_from(bucket.bucket_id).map_err(|_| owner_store_state_mismatch())?;
        let leaf = tree
            .leaf_hashes
            .get_mut(bucket_index)
            .ok_or_else(owner_store_state_mismatch)?;
        *leaf = bucket.bucket_commitment.clone();
    }
    tree.index_epoch = context.new_state.index_epoch;
    tree.root_hash = context.new_state.root_hash.clone();
    validate_merkle_tree(&tree)?;
    Ok(tree)
}

fn validate_owner_store_old_commit(
    store: &PrivateHnswOramStore,
    manifest: &PrivateHnswOramManifest,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<OwnerStoreCommitKind> {
    match store.read_epoch_commit(context.old_state.index_epoch) {
        Ok(commit)
            if commit.root_hash == context.old_state.root_hash
                && commit.writeback_digest.as_deref()
                    == Some(context.old_state.last_writeback_digest.as_str()) =>
        {
            Ok(OwnerStoreCommitKind::DigestBound)
        }
        Err(CollectionError::NotFound { .. })
            if manifest.index_epoch == context.old_state.index_epoch
                && manifest.root_hash == context.old_state.root_hash =>
        {
            Ok(OwnerStoreCommitKind::InitialAnchor)
        }
        Ok(_) | Err(CollectionError::NotFound { .. }) => Err(owner_store_state_mismatch()),
        Err(error) => Err(error),
    }
}

fn validate_owner_store_new_commit_if_present(
    store: &PrivateHnswOramStore,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<bool> {
    match store.read_epoch_commit(context.new_state.index_epoch) {
        Ok(commit)
            if commit.root_hash == context.new_state.root_hash
                && commit.writeback_digest.as_deref()
                    == Some(context.new_state.last_writeback_digest.as_str()) =>
        {
            Ok(true)
        }
        Err(CollectionError::NotFound { .. }) => Ok(false),
        Ok(_) => Err(owner_store_state_mismatch()),
        Err(error) => Err(error),
    }
}

fn validate_owner_store_context(
    manifest: &PrivateHnswOramManifest,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
) -> CollectionResult<()> {
    validate_owner_store_immutable_manifest(manifest, context)?;
    for (value, field) in [
        (
            context.journal_descriptor_digest,
            "journal_descriptor_digest",
        ),
        (context.prepared_state_digest, "prepared_state_digest"),
        (
            context.immutable_manifest_digest,
            "immutable_manifest_digest",
        ),
        (
            context.old_state.last_writeback_digest.as_str(),
            "old_writeback_digest",
        ),
        (
            context.new_state.last_writeback_digest.as_str(),
            "new_writeback_digest",
        ),
    ] {
        decode_base64url_32(value, field)?;
    }
    decode_base64url_32(&context.old_state.root_hash, "old_root_hash")?;
    decode_base64url_32(&context.new_state.root_hash, "new_root_hash")?;
    validate_path_component(context.index_name, "owner index name")?;

    let old = context.old_state;
    let new = context.new_state;
    let expected_new_epoch = old.index_epoch.checked_add(1).ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM owner store transition is invalid")
    })?;
    let expected_new_logical = old.logical_count.checked_add(1).ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM owner store transition is invalid")
    })?;
    let old_occupancy = old
        .logical_count
        .checked_add(old.dummy_count)
        .ok_or_else(owner_store_state_mismatch)?;
    let new_occupancy = new
        .logical_count
        .checked_add(new.dummy_count)
        .ok_or_else(owner_store_state_mismatch)?;
    let manifest_occupancy = manifest
        .logical_node_count
        .checked_add(manifest.dummy_node_count)
        .ok_or_else(owner_store_state_mismatch)?;
    if context.index_name != manifest.vector_name
        || old.kind != PrivateOramIndexKindV2::Hnsw
        || new.kind != PrivateOramIndexKindV2::Hnsw
        || old.index_name != context.index_name
        || new.index_name != context.index_name
        || new.index_epoch != expected_new_epoch
        || new.root_hash == old.root_hash
        || new.logical_count != expected_new_logical
        || old.dummy_count == 0
        || new.dummy_count != old.dummy_count - 1
        || new.last_writeback_digest == old.last_writeback_digest
        || old_occupancy != new_occupancy
        || old_occupancy != manifest_occupancy
    {
        return Err(owner_store_state_mismatch());
    }

    let target = match phase {
        OwnerStorePhase::ExactOld => old,
        OwnerStorePhase::ExactNew => new,
    };
    if manifest.index_epoch > target.index_epoch {
        return Err(owner_store_state_mismatch());
    }
    if manifest.index_epoch == target.index_epoch
        && (manifest.root_hash != target.root_hash
            || manifest.logical_node_count != target.logical_count
            || manifest.dummy_node_count != target.dummy_count)
    {
        return Err(owner_store_state_mismatch());
    }

    if context.final_bucket_refs.is_empty()
        || context.final_bucket_refs.len() != context.final_buckets.len()
        || context
            .final_bucket_refs
            .windows(2)
            .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
    {
        return Err(owner_store_state_mismatch());
    }
    for (bucket_ref, bucket) in context.final_bucket_refs.iter().zip(context.final_buckets) {
        decode_base64url_32(&bucket_ref.ciphertext_sha256, "ciphertext_sha256")?;
        decode_base64url_32(&bucket_ref.bucket_commitment, "bucket_commitment")?;
        if bucket_ref.bucket_id != bucket.bucket_id
            || bucket_ref.ciphertext_sha256 != bucket.ciphertext_sha256
            || bucket_ref.bucket_commitment != bucket.bucket_commitment
        {
            return Err(owner_store_state_mismatch());
        }
        validate_bucket(
            bucket,
            new.index_epoch,
            manifest.bucket_count,
            context.max_ciphertext_bytes,
        )?;
        validate_bucket_ciphertext_fixed_size(bucket, manifest)?;
        validate_bucket_commitment_context(
            manifest,
            bucket.index_epoch,
            std::slice::from_ref(bucket),
        )?;
    }
    Ok(())
}

fn validate_owner_store_immutable_manifest(
    manifest: &PrivateHnswOramManifest,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<()> {
    let immutable_digest = private_oram_immutable_manifest_v2_digest(context.immutable_manifest)
        .map_err(|_| owner_store_state_mismatch())?;
    let occupancy = manifest
        .logical_node_count
        .checked_add(manifest.dummy_node_count)
        .ok_or_else(owner_store_state_mismatch)?;
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        key_id,
        rk_id,
        rk_epoch,
        dim,
        distance,
        hnsw,
        oram,
        fixed_search_budget,
        ..
    } = &context.immutable_index.params
    else {
        return Err(owner_store_state_mismatch());
    };
    if immutable_digest != context.immutable_manifest_digest
        || !context
            .immutable_manifest
            .indexes
            .iter()
            .any(|index| index == context.immutable_index)
        || context.immutable_manifest.collection_id != manifest.collection_id
        || context.immutable_manifest.result_privacy != manifest.result_privacy
        || context.immutable_manifest.owner_signing_key_id != manifest.owner_signing_key_id
        || context.immutable_manifest.created_at_unix != manifest.created_at_unix
        || context.immutable_index.index_name != context.index_name
        || manifest.vector_name != context.index_name
        || key_id != &manifest.key_id
        || rk_id != &manifest.rk_id
        || *rk_epoch != manifest.rk_epoch
        || *dim != manifest.dim
        || distance != &manifest.distance
        || hnsw != &manifest.hnsw
        || oram != &manifest.oram
        || fixed_search_budget != &manifest.fixed_budget
        || context.immutable_index.capacity.bucket_count != manifest.bucket_count
        || context.immutable_index.capacity.logical_capacity != occupancy
    {
        return Err(owner_store_state_mismatch());
    }
    Ok(())
}

fn validate_owner_store_epoch_commits(
    store: &PrivateHnswOramStore,
    manifest: &PrivateHnswOramManifest,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
) -> CollectionResult<OwnerStoreCommitKind> {
    match phase {
        OwnerStorePhase::ExactOld => {
            if validate_owner_store_new_commit_if_present(store, context)? {
                return Err(owner_store_state_mismatch());
            }
            validate_owner_store_old_commit(store, manifest, context)
        }
        OwnerStorePhase::ExactNew => {
            if validate_owner_store_new_commit_if_present(store, context)? {
                Ok(OwnerStoreCommitKind::DigestBound)
            } else {
                Err(owner_store_state_mismatch())
            }
        }
    }
}

fn validate_owner_store_epoch_directory(
    store: &PrivateHnswOramStore,
    current_epoch: u64,
) -> CollectionResult<String> {
    validate_private_dir(&store.epochs_dir())?;
    let entries = fs_err::read_dir(store.epochs_dir()).map_err(|_| {
        CollectionError::service_error("failed to inspect private HNSW ORAM owner epoch state")
    })?;
    let mut entry_count = 0_usize;
    let mut commits = Vec::new();
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(owner_store_state_mismatch)?;
        if entry_count > MAX_OWNER_EPOCH_DIRECTORY_ENTRIES {
            return Err(owner_store_state_mismatch());
        }
        let entry = entry.map_err(|_| {
            CollectionError::service_error("failed to inspect private HNSW ORAM owner epoch state")
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(owner_store_state_mismatch());
        };
        if name == CURRENT_EPOCH_FILE {
            continue;
        }
        let Some(encoded_epoch) = name.strip_suffix(".commit") else {
            return Err(owner_store_state_mismatch());
        };
        let epoch = encoded_epoch
            .parse::<u64>()
            .map_err(|_| owner_store_state_mismatch())?;
        if name != format!("{epoch:08}.commit") || epoch > current_epoch {
            return Err(owner_store_state_mismatch());
        }
        commits.push((epoch, store.read_epoch_commit(epoch)?));
    }
    commits.sort_unstable_by_key(|(epoch, _)| *epoch);
    let mut hasher = Sha256::new();
    hash_len_prefixed(&mut hasher, OWNER_EPOCH_DIRECTORY_DOMAIN);
    hasher.update((commits.len() as u64).to_be_bytes());
    for (epoch, commit) in commits {
        hasher.update(epoch.to_be_bytes());
        hash_len_prefixed(&mut hasher, commit.root_hash.as_bytes());
        match commit.writeback_digest {
            Some(writeback_digest) => {
                hasher.update([1]);
                hash_len_prefixed(&mut hasher, writeback_digest.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn read_owner_store_buckets(
    store: &PrivateHnswOramStore,
    manifest: &PrivateHnswOramManifest,
    tree: &PrivateHnswOramMerkleTree,
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
) -> CollectionResult<Vec<PrivateHnswOramBucket>> {
    let expected_epoch = match phase {
        OwnerStorePhase::ExactOld => context.old_state.index_epoch,
        OwnerStorePhase::ExactNew => context.new_state.index_epoch,
    };
    let mut buckets = Vec::with_capacity(context.final_bucket_refs.len());
    for (offset, bucket_ref) in context.final_bucket_refs.iter().enumerate() {
        let bucket = store.read_bucket(
            bucket_ref.bucket_id,
            expected_epoch,
            manifest.bucket_count,
            context.max_ciphertext_bytes,
        )?;
        validate_bucket_ciphertext_fixed_size(&bucket, manifest)?;
        validate_bucket_commitment_context(
            manifest,
            bucket.index_epoch,
            std::slice::from_ref(&bucket),
        )?;
        let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM owner store bucket id is invalid")
        })?;
        if tree.leaf_hashes.get(bucket_index) != Some(&bucket.bucket_commitment)
            || (phase == OwnerStorePhase::ExactNew
                && context.final_buckets.get(offset) != Some(&bucket))
        {
            return Err(owner_store_state_mismatch());
        }
        buckets.push(bucket);
    }
    Ok(buckets)
}

fn ensure_owner_store_has_no_legacy_pending(store: &PrivateHnswOramStore) -> CollectionResult<()> {
    if store.pending_writeback_exists()? {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM V2 owner verification rejects legacy pending writeback state",
        ));
    }
    Ok(())
}

fn owner_store_canonical_state_digest(
    context: PrivateHnswOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
    store_manifest_digest: &str,
    tree: &PrivateHnswOramMerkleTree,
    commit_kind: OwnerStoreCommitKind,
    epoch_directory_digest: &str,
    buckets: &[PrivateHnswOramBucket],
) -> String {
    let mut hasher = Sha256::new();
    hash_len_prefixed(&mut hasher, phase.domain());
    hash_len_prefixed(&mut hasher, context.journal_descriptor_digest.as_bytes());
    hash_len_prefixed(&mut hasher, context.prepared_state_digest.as_bytes());
    hash_len_prefixed(&mut hasher, context.immutable_manifest_digest.as_bytes());
    hasher.update([1, phase.tag()]);
    hash_len_prefixed(&mut hasher, context.index_name.as_bytes());
    hash_len_prefixed(&mut hasher, store_manifest_digest.as_bytes());
    hash_owner_index_state(&mut hasher, context.old_state);
    hash_owner_index_state(&mut hasher, context.new_state);
    hasher.update(tree.bucket_count.to_be_bytes());
    hash_len_prefixed(&mut hasher, tree.root_hash.as_bytes());
    hash_len_prefixed(
        &mut hasher,
        owner_store_merkle_leaves_digest(tree).as_bytes(),
    );
    hasher.update([commit_kind.tag()]);
    hash_len_prefixed(&mut hasher, epoch_directory_digest.as_bytes());
    hasher.update((context.final_bucket_refs.len() as u64).to_be_bytes());
    for bucket_ref in context.final_bucket_refs {
        hasher.update(bucket_ref.bucket_id.to_be_bytes());
        hash_len_prefixed(&mut hasher, bucket_ref.ciphertext_sha256.as_bytes());
        hash_len_prefixed(&mut hasher, bucket_ref.bucket_commitment.as_bytes());
    }
    hasher.update((buckets.len() as u64).to_be_bytes());
    for bucket in buckets {
        hasher.update(bucket.bucket_id.to_be_bytes());
        hasher.update(bucket.index_epoch.to_be_bytes());
        hash_len_prefixed(&mut hasher, bucket.ciphertext_sha256.as_bytes());
        hash_len_prefixed(&mut hasher, bucket.bucket_commitment.as_bytes());
    }
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn hash_owner_index_state(hasher: &mut Sha256, state: &PrivateOramIndexStateV2) {
    hasher.update([match state.kind {
        PrivateOramIndexKindV2::Hnsw => 1,
        PrivateOramIndexKindV2::Result => 2,
    }]);
    hash_len_prefixed(hasher, state.index_name.as_bytes());
    hasher.update(state.index_epoch.to_be_bytes());
    hash_len_prefixed(hasher, state.root_hash.as_bytes());
    hasher.update(state.logical_count.to_be_bytes());
    hasher.update(state.dummy_count.to_be_bytes());
    hash_len_prefixed(hasher, state.last_writeback_digest.as_bytes());
}

fn owner_store_merkle_leaves_digest(tree: &PrivateHnswOramMerkleTree) -> String {
    let mut hasher = Sha256::new();
    hasher.update((tree.leaf_hashes.len() as u64).to_be_bytes());
    for leaf in &tree.leaf_hashes {
        hash_len_prefixed(&mut hasher, leaf.as_bytes());
    }
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn digest_bytes(value: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(value))
}

fn owner_store_state_mismatch() -> CollectionError {
    CollectionError::bad_request("private HNSW ORAM owner canonical store state does not match")
}

fn ensure_read_proof_matches_buckets(
    proof: &PrivateHnswOramMerkleProof,
    buckets: &[PrivateHnswOramBucket],
) -> CollectionResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

fn validate_merkle_tree(tree: &PrivateHnswOramMerkleTree) -> CollectionResult<()> {
    if tree.version != 1 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree has unsupported version",
        ));
    }
    if tree.bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree bucket_count must be non-zero",
        ));
    }
    let leaf_hash_count = u64::try_from(tree.leaf_hashes.len()).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM Merkle tree leaf count exceeds u64")
    })?;
    if leaf_hash_count != tree.bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree leaf count does not match bucket_count",
        ));
    }
    let computed_root = PrivateHnswOramStore::merkle_root_for_commitments(&tree.leaf_hashes)?;
    if computed_root != tree.root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree root_hash mismatch",
        ));
    }
    Ok(())
}

fn validate_merkle_tree_context(
    tree: &PrivateHnswOramMerkleTree,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
) -> CollectionResult<()> {
    validate_merkle_tree(tree)?;
    if tree.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree epoch mismatch",
        ));
    }
    if tree.root_hash != expected_root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree root_hash mismatch",
        ));
    }
    if tree.bucket_count != expected_bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree bucket_count mismatch",
        ));
    }
    Ok(())
}

fn merkle_levels(commitments: &[String]) -> CollectionResult<Vec<Vec<[u8; 32]>>> {
    if commitments.is_empty() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree must contain at least one leaf",
        ));
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_base64url_32(commitment, "bucket_commitment"))
        .collect::<CollectionResult<Vec<_>>>()?;
    let padded_len = leaves.len().checked_next_power_of_two().ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM Merkle tree is too large")
    })?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let Some(previous) = levels.last() else {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle tree is invalid",
            ));
        };
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(merkle_parent_hash(&pair[0], &pair[1]));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn merkle_siblings_for_bucket(
    levels: &[Vec<[u8; 32]>],
    mut index: usize,
) -> CollectionResult<Vec<PrivateHnswOramMerkleSibling>> {
    if levels.is_empty() || index >= levels[0].len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle proof bucket index is out of range",
        ));
    }
    let sibling_level_count = levels.len().checked_sub(1).ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM Merkle proof levels are invalid")
    })?;
    let mut siblings = Vec::with_capacity(sibling_level_count);
    for (level_index, level) in levels.iter().enumerate().take(sibling_level_count) {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let position = if index % 2 == 0 {
            MerkleSiblingPosition::Right
        } else {
            MerkleSiblingPosition::Left
        };
        let sibling = level.get(sibling_index).ok_or_else(|| {
            CollectionError::bad_request("private HNSW ORAM Merkle proof sibling is missing")
        })?;
        siblings.push(PrivateHnswOramMerkleSibling {
            level: u32::try_from(level_index).map_err(|_| {
                CollectionError::bad_request("private HNSW ORAM Merkle proof level exceeds u32")
            })?,
            position,
            hash: BASE64URL_NOPAD.encode(sibling),
        });
        index /= 2;
    }
    Ok(siblings)
}

fn validate_bucket(
    bucket: &PrivateHnswOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket has stale epoch",
        ));
    }
    Ok(())
}

fn validate_commit_manifest_context(
    manifest: &PrivateHnswOramManifest,
    _old: &PrivateHnswOramEpochState,
    bucket_count: u64,
) -> CollectionResult<()> {
    if manifest.bucket_count != bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM manifest bucket_count does not match commit bucket_count",
        ));
    }
    Ok(())
}

fn initial_replication_bucket_estimated_bytes(
    ciphertext_bytes: usize,
    ciphertext_hash_bytes: usize,
    commitment_bytes: usize,
) -> CollectionResult<usize> {
    std::mem::size_of::<PrivateHnswOramBucket>()
        .checked_add(ciphertext_bytes)
        .and_then(|size| size.checked_add(ciphertext_hash_bytes))
        .and_then(|size| size.checked_add(commitment_bytes))
        .ok_or_else(|| {
            CollectionError::bad_request(
                "private HNSW ORAM initial replication bundle size is invalid",
            )
        })
}

fn validate_initial_replication_bundle_budget(
    bucket_count: u64,
    estimated_bucket_bytes: usize,
    max_bundle_bytes: usize,
    error_message: &'static str,
) -> CollectionResult<()> {
    let bucket_count =
        usize::try_from(bucket_count).map_err(|_| CollectionError::bad_request(error_message))?;
    let estimated_total = estimated_bucket_bytes
        .checked_mul(bucket_count)
        .ok_or_else(|| CollectionError::bad_request(error_message))?;
    if max_bundle_bytes == 0 || estimated_total > max_bundle_bytes {
        return Err(CollectionError::bad_request(error_message));
    }
    Ok(())
}

/// The exact writeback budget is session-scoped (one path per path read in the session) and
/// enforced by the API session layer on the writer; the store can only bound a replicated or
/// replayed writeback by the tree itself.
fn validate_fixed_writeback_budget(
    manifest: &PrivateHnswOramManifest,
    updated_bucket_count: usize,
) -> CollectionResult<()> {
    let max_updated_buckets = usize::try_from(manifest.bucket_count)
        .map_err(|_| CollectionError::bad_request("private HNSW ORAM bucket count overflows"))?;
    if updated_bucket_count > max_updated_buckets {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM commit exceeds fixed writeback budget",
        ));
    }
    Ok(())
}

fn validate_bucket_commitment_context(
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    buckets: &[PrivateHnswOramBucket],
) -> CollectionResult<()> {
    for bucket in buckets {
        let expected_commitment = private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch,
            },
            &bucket.ciphertext_sha256,
        )
        .map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM commit bucket commitment context mismatch",
            )
        })?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit bucket commitment context mismatch",
            ));
        }
    }
    Ok(())
}

fn validate_bucket_ciphertext_fixed_size(
    bucket: &PrivateHnswOramBucket,
    manifest: &PrivateHnswOramManifest,
) -> CollectionResult<()> {
    let expected = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_hnsw_oram_error)?;
    let expected_b64_len = max_base64url_nopad_encoded_len(expected)?;
    if bucket.ciphertext.len() != expected_b64_len {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() != expected {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    Ok(())
}

fn validate_bucket_for_read(
    bucket: &PrivateHnswOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch > expected_epoch {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket is newer than requested epoch",
        ));
    }
    Ok(())
}

fn validate_bucket_shape(
    bucket: &PrivateHnswOramBucket,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    if bucket.version != 1 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket version is unsupported",
        ));
    }
    if bucket.bucket_id >= bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket is out of range",
        ));
    }
    let max_ciphertext_b64_len = max_base64url_nopad_encoded_len(max_ciphertext_bytes)?;
    if bucket.ciphertext.len() > max_ciphertext_b64_len {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext exceeds maximum size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() > max_ciphertext_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext exceeds maximum size",
        ));
    }
    let sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
    if sha256 != bucket.ciphertext_sha256 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext_sha256 mismatch",
        ));
    }
    decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
    Ok(())
}

fn validate_upload_bundle(
    bundle: &PrivateHnswOramUploadBundle,
    max_ciphertext_bytes: usize,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_hnsw_oram_upload_bundle(bundle).map_err(private_hnsw_client_error)?;
    for bucket in &bundle.buckets {
        validate_bucket(
            bucket,
            bundle.manifest.index_epoch,
            bundle.manifest.bucket_count,
            max_ciphertext_bytes,
        )?;
    }
    Ok(leaf_commitments)
}

fn validate_upload_bundle_with_signature(
    bundle: &PrivateHnswOramUploadBundle,
    max_ciphertext_bytes: usize,
    validation_context: PrivateHnswManifestValidationContext<'_>,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_hnsw_oram_upload_bundle_with_signature(bundle, validation_context)
            .map_err(private_hnsw_client_error)?;
    for bucket in &bundle.buckets {
        validate_bucket(
            bucket,
            bundle.manifest.index_epoch,
            bundle.manifest.bucket_count,
            max_ciphertext_bytes,
        )?;
    }
    Ok(leaf_commitments)
}

fn validate_live_replication_bundle(
    bundle: &PrivateHnswOramLiveReplicationBundle,
    max_ciphertext_bytes: usize,
) -> CollectionResult<Vec<String>> {
    validate_private_hnsw_oram_manifest_shape(&bundle.manifest).map_err(private_hnsw_oram_error)?;
    validate_epoch_state(&bundle.current)?;
    if bundle.current.index_epoch < bundle.manifest.index_epoch {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM live replication epoch precedes manifest anchor",
        ));
    }
    if bundle.current.index_epoch == bundle.manifest.index_epoch {
        if bundle.current.root_hash != bundle.manifest.root_hash {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication initial state is invalid",
            ));
        }
        if let Some(writeback_digest) = bundle.writeback_digest.as_deref() {
            validate_writeback_digest(writeback_digest)?;
        }
    } else if let Some(writeback_digest) = bundle.writeback_digest.as_deref() {
        validate_writeback_digest(writeback_digest)?;
    } else {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM live replication advanced state requires consensus digest",
        ));
    }
    let bucket_count = usize::try_from(bundle.manifest.bucket_count).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM live replication bucket_count is invalid")
    })?;
    if bundle.buckets.len() != bucket_count || bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM live replication bucket set is incomplete",
        ));
    }
    let mut commitments = Vec::new();
    commitments.try_reserve_exact(bucket_count).map_err(|_| {
        CollectionError::service_error("private HNSW ORAM live replication allocation failed")
    })?;
    for (bucket_id, bucket) in bundle.buckets.iter().enumerate() {
        let expected_bucket_id = u64::try_from(bucket_id).map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM live replication bucket id is invalid")
        })?;
        if bucket.bucket_id != expected_bucket_id || bucket.index_epoch > bundle.current.index_epoch
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM live replication bucket context is invalid",
            ));
        }
        validate_bucket_shape(bucket, bundle.manifest.bucket_count, max_ciphertext_bytes)?;
        validate_bucket_ciphertext_fixed_size(bucket, &bundle.manifest)?;
        validate_bucket_commitment_context(
            &bundle.manifest,
            bucket.index_epoch,
            std::slice::from_ref(bucket),
        )?;
        commitments.push(bucket.bucket_commitment.clone());
    }
    let computed_root = PrivateHnswOramStore::merkle_root_for_commitments(&commitments)?;
    if computed_root != bundle.current.root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM live replication root hash mismatch",
        ));
    }
    Ok(commitments)
}

fn private_hnsw_client_error(err: qdrant_sec::PrivateHnswClientError) -> CollectionError {
    use qdrant_sec::PrivateHnswClientError;

    let message = match err {
        PrivateHnswClientError::Encryption(_) => "private HNSW client encryption failed",
        PrivateHnswClientError::InvalidNeighborShape => {
            "private HNSW node block has invalid neighbor shape"
        }
        PrivateHnswClientError::TooManyNeighbors { .. } => {
            "private HNSW node block has too many neighbors"
        }
        PrivateHnswClientError::VectorTooLarge => "private HNSW node block vector is too large",
        PrivateHnswClientError::FixedNeighborSlotsTooLarge => {
            "private HNSW node block fixed neighbor slot count is too large"
        }
        PrivateHnswClientError::EncodedBlockOversized => {
            "private HNSW node block does not fit in configured block size"
        }
        PrivateHnswClientError::InvalidBlockEncoding => {
            "private HNSW node block encoding is malformed"
        }
        PrivateHnswClientError::UnsupportedBlockVersion(_) => {
            "private HNSW node block uses unsupported version"
        }
        PrivateHnswClientError::UnsupportedVectorEncoding(_) => {
            "private HNSW node block uses unsupported vector encoding"
        }
        PrivateHnswClientError::InvalidBlockPadding => "private HNSW node block padding is invalid",
        PrivateHnswClientError::InvalidBucketContext(_) => "private HNSW bucket context is invalid",
        PrivateHnswClientError::InvalidBucketCiphertextEncoding => {
            "private HNSW bucket ciphertext is not base64url"
        }
        PrivateHnswClientError::BucketCiphertextSizeMismatch { .. } => {
            "private HNSW bucket ciphertext length does not match expected fixed length"
        }
        PrivateHnswClientError::InvalidBucketCiphertextHash => {
            "private HNSW bucket ciphertext hash is invalid"
        }
        PrivateHnswClientError::InvalidBucketCommitment => {
            "private HNSW bucket commitment is invalid"
        }
        PrivateHnswClientError::BucketMetadataMismatch => {
            "private HNSW bucket metadata does not match the decrypt context"
        }
        PrivateHnswClientError::UnsupportedBucketCiphertextVersion(_) => {
            "private HNSW bucket uses unsupported ciphertext version"
        }
        PrivateHnswClientError::BucketOpenFailed => {
            "private HNSW bucket ciphertext authentication failed"
        }
        PrivateHnswClientError::InvalidTreeHeight => "private HNSW ORAM tree_height is invalid",
        PrivateHnswClientError::LeafOutOfRange => {
            "private HNSW ORAM leaf label is outside tree range"
        }
        PrivateHnswClientError::InvalidLeafLabelEncoding => {
            "private HNSW ORAM leaf label is not base64url"
        }
        PrivateHnswClientError::InvalidLeafLabelLength => {
            "private HNSW ORAM leaf label has invalid length"
        }
        PrivateHnswClientError::BucketCountMismatch => {
            "private HNSW ORAM bucket_count does not match tree_height"
        }
        PrivateHnswClientError::InvalidOramClientConfig(_) => {
            "private HNSW ORAM client config is invalid"
        }
        PrivateHnswClientError::InvalidBucketPlaintext => {
            "private HNSW ORAM bucket plaintext is malformed"
        }
        PrivateHnswClientError::BucketPlaintextMetadataMismatch => {
            "private HNSW ORAM bucket plaintext metadata does not match config"
        }
        PrivateHnswClientError::BucketPlaintextSlotCountMismatch => {
            "private HNSW ORAM bucket plaintext slot count does not match config"
        }
        PrivateHnswClientError::PathBucketMismatch => {
            "private HNSW ORAM path buckets do not match requested leaf"
        }
        PrivateHnswClientError::MissingPosition => {
            "private HNSW ORAM client position map is missing a node"
        }
        PrivateHnswClientError::MissingBlock => {
            "private HNSW ORAM path did not contain requested node"
        }
        PrivateHnswClientError::InvalidAppendRewrite => {
            "private HNSW ORAM append rewrite is invalid"
        }
        PrivateHnswClientError::DuplicateBlock => {
            "private HNSW ORAM path contains duplicate node blocks"
        }
        PrivateHnswClientError::DuplicatePointToken => {
            "private HNSW ORAM path contains duplicate point tokens"
        }
        PrivateHnswClientError::DuplicatePayloadFetchToken => {
            "private HNSW ORAM path contains duplicate payload fetch tokens"
        }
        PrivateHnswClientError::InvalidBuildConfig(_) => {
            "private HNSW ORAM build config is invalid"
        }
        PrivateHnswClientError::OramInitialPlacementOverflow { .. } => {
            "private HNSW ORAM initial placement overflowed path"
        }
        PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(_) => {
            "private HNSW ORAM client state snapshot uses unsupported version"
        }
        PrivateHnswClientError::InvalidClientStateSnapshot => {
            "private HNSW ORAM client state snapshot is malformed"
        }
        PrivateHnswClientError::InvalidClientStateContext(_) => {
            "private HNSW ORAM client state context is invalid"
        }
        PrivateHnswClientError::InvalidClientStateCiphertextEncoding => {
            "private HNSW ORAM client state ciphertext is not base64url"
        }
        PrivateHnswClientError::InvalidClientStateCiphertextHash => {
            "private HNSW ORAM client state ciphertext hash is invalid"
        }
        PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(_) => {
            "private HNSW ORAM client state uses unsupported ciphertext version"
        }
        PrivateHnswClientError::ClientStateOpenFailed => {
            "private HNSW ORAM client state decryption authentication failed"
        }
        PrivateHnswClientError::InvalidSearchConfig(_) => "private HNSW search config is invalid",
        PrivateHnswClientError::UnsupportedSearchVectorEncoding => {
            "private HNSW search currently requires f32_le node vectors"
        }
        PrivateHnswClientError::InvalidF32VectorLength => {
            "private HNSW search f32 vector bytes are malformed"
        }
        PrivateHnswClientError::VectorDimensionMismatch => {
            "private HNSW search query and node vector dimensions differ"
        }
        PrivateHnswClientError::NonFiniteDistance => "private HNSW search distance is not finite",
        PrivateHnswClientError::FixedBudgetNotExhausted { .. } => {
            "private HNSW search did not exhaust the fixed access budget"
        }
        PrivateHnswClientError::MissingPayloadFetchToken => {
            "private HNSW private result mode requires payload fetch tokens"
        }
        PrivateHnswClientError::EmptyMerkleTree => {
            "private HNSW ORAM Merkle tree must contain at least one leaf"
        }
        PrivateHnswClientError::InvalidMerkleRoot => "private HNSW ORAM Merkle root is invalid",
        PrivateHnswClientError::MerkleRootMismatch => "private HNSW ORAM Merkle root mismatch",
        PrivateHnswClientError::InvalidCommitEpoch => {
            "private HNSW ORAM commit new_epoch must be exactly old_epoch + 1"
        }
        PrivateHnswClientError::EmptyCommit => {
            "private HNSW ORAM commit must update at least one bucket"
        }
        PrivateHnswClientError::BucketOutOfRange { .. } => {
            "private HNSW ORAM bucket is out of range"
        }
        PrivateHnswClientError::DuplicateBucket { .. } => {
            "private HNSW ORAM upload contains duplicate bucket"
        }
        PrivateHnswClientError::MissingBucket { .. } => {
            "private HNSW ORAM upload is missing a configured bucket"
        }
        PrivateHnswClientError::DuplicateUpdatedBucket { .. } => {
            "private HNSW ORAM commit bucket appears more than once"
        }
        PrivateHnswClientError::StaleBucketEpoch { .. } => {
            "private HNSW ORAM commit bucket has stale epoch"
        }
        PrivateHnswClientError::UnsupportedBucketVersion(_) => {
            "private HNSW ORAM bucket uses unsupported version"
        }
        PrivateHnswClientError::InvalidCommitSignatureContext(_) => {
            "private HNSW ORAM commit signature context is invalid"
        }
        PrivateHnswClientError::InvalidManifestSignatureContext(_) => {
            "private HNSW ORAM manifest signature context is invalid"
        }
        PrivateHnswClientError::ManifestCommitMismatch => {
            "private HNSW ORAM manifest epoch/root does not match commit old epoch/root"
        }
        PrivateHnswClientError::InvalidMerkleProof => "private HNSW ORAM Merkle proof is malformed",
        PrivateHnswClientError::InvalidMerkleProofJson => {
            "private HNSW ORAM Merkle proof JSON is malformed"
        }
        PrivateHnswClientError::MerkleProofMismatch => {
            "private HNSW ORAM Merkle proof does not match buckets/root"
        }
    };
    CollectionError::bad_request(message)
}

fn private_hnsw_oram_error(err: qdrant_sec::PrivateHnswOramError) -> CollectionError {
    use qdrant_sec::PrivateHnswOramError;

    let message = match err {
        PrivateHnswOramError::UnsupportedManifestVersion(_) => {
            "private HNSW ORAM manifest version is unsupported"
        }
        PrivateHnswOramError::UnsupportedSignatureAlgorithm(_) => {
            "private HNSW ORAM signature algorithm must be ed25519"
        }
        PrivateHnswOramError::InvalidCommitSignature => {
            "private HNSW ORAM commit signature verification failed"
        }
        PrivateHnswOramError::MalformedSignature => "private HNSW ORAM signature is malformed",
        PrivateHnswOramError::InvalidProvider => "private HNSW ORAM manifest provider is invalid",
        PrivateHnswOramError::InvalidBinding => "private HNSW ORAM manifest binding is invalid",
        PrivateHnswOramError::InvalidManifestField(_) => {
            "private HNSW ORAM manifest field is invalid"
        }
        PrivateHnswOramError::ManifestContextMismatch(_) => {
            "private HNSW ORAM manifest field does not match runtime context"
        }
        PrivateHnswOramError::MissingManifestSignature => {
            "private HNSW ORAM manifest signature is missing"
        }
        PrivateHnswOramError::SignatureKeyIdMismatch => {
            "private HNSW ORAM manifest signature key id does not match runtime context"
        }
        PrivateHnswOramError::InvalidManifestSignature => {
            "private HNSW ORAM manifest signature verification failed"
        }
        PrivateHnswOramError::EmptyCommit => {
            "private HNSW ORAM commit must update at least one bucket"
        }
        PrivateHnswOramError::InvalidReadPathsSignature => {
            "private HNSW ORAM read_paths signature verification failed"
        }
        PrivateHnswOramError::InvalidResourceKeyId => {
            "private HNSW ORAM resource key id is invalid"
        }
        PrivateHnswOramError::UnsupportedBucketVersion(_) => {
            "private HNSW ORAM bucket version is unsupported"
        }
        PrivateHnswOramError::BucketOutOfRange { .. } => "private HNSW ORAM bucket is out of range",
        PrivateHnswOramError::StaleBucketEpoch { .. } => {
            "private HNSW ORAM bucket epoch does not match expected epoch"
        }
        PrivateHnswOramError::DuplicateUpdatedBucket { .. } => {
            "private HNSW ORAM commit repeats a bucket"
        }
        PrivateHnswOramError::InvalidBucketField(_) => "private HNSW ORAM bucket field is invalid",
        PrivateHnswOramError::BucketOversized => {
            "private HNSW ORAM bucket ciphertext exceeds maximum size"
        }
        PrivateHnswOramError::InvalidBucketHash => {
            "private HNSW ORAM bucket ciphertext_sha256 mismatch"
        }
        PrivateHnswOramError::InvalidBucketCommitment => {
            "private HNSW ORAM bucket commitment context mismatch"
        }
        PrivateHnswOramError::InvalidBucketContext(_) => {
            "private HNSW ORAM bucket context is invalid"
        }
        PrivateHnswOramError::InvalidFetchPlanField(_) => {
            "private HNSW ORAM fetch or commit plan field is invalid"
        }
        PrivateHnswOramError::EmptyMerkleTree => "private HNSW ORAM Merkle tree is empty",
        PrivateHnswOramError::MerkleRootMismatch => {
            "private HNSW ORAM Merkle root does not match bucket commitments"
        }
        PrivateHnswOramError::ManifestCommitMismatch => {
            "private HNSW ORAM manifest epoch/root does not match commit old epoch/root"
        }
    };
    CollectionError::bad_request(message)
}

fn max_base64url_nopad_encoded_len(byte_len: usize) -> CollectionResult<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket ciphertext size overflows",
            ));
        }
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
        .ok_or_else(|| {
            CollectionError::bad_request("private HNSW ORAM bucket ciphertext size overflows")
        })
}

fn max_bucket_file_bytes(max_ciphertext_bytes: usize) -> CollectionResult<u64> {
    let encoded_len = max_base64url_nopad_encoded_len(max_ciphertext_bytes)?;
    let file_len = encoded_len
        .checked_add(BUCKET_JSON_OVERHEAD_BYTES)
        .ok_or_else(|| {
            CollectionError::bad_request("private HNSW ORAM bucket file size overflows")
        })?;
    u64::try_from(file_len)
        .map_err(|_| CollectionError::bad_request("private HNSW ORAM bucket file size overflows"))
}

fn validate_epoch_state(epoch: &PrivateHnswOramEpochState) -> CollectionResult<()> {
    decode_base64url_32(&epoch.root_hash, "root_hash")?;
    Ok(())
}

fn validate_epoch_commit(
    commit: &PrivateHnswOramEpochCommit,
    expected_epoch: u64,
) -> CollectionResult<()> {
    if commit.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM completed writeback epoch does not match",
        ));
    }
    decode_base64url_32(&commit.root_hash, "root_hash")?;
    if let Some(writeback_digest) = commit.writeback_digest.as_deref() {
        validate_writeback_digest(writeback_digest)?;
    }
    Ok(())
}

fn validate_writeback_digest(writeback_digest: &str) -> CollectionResult<()> {
    decode_base64url_32(writeback_digest, "writeback_digest").map(|_| ())
}

fn decode_base64url_32(value: &str, field: &str) -> CollectionResult<[u8; 32]> {
    if value.len() != 43 {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM {field} must encode 32 bytes",
        )));
    }
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        CollectionError::bad_request(format!("private HNSW ORAM {field} is not base64url"))
    })?;
    bytes.try_into().map_err(|_| {
        CollectionError::bad_request(format!("private HNSW ORAM {field} must encode 32 bytes"))
    })
}

fn validate_path_component(value: &str, label: &str) -> CollectionResult<()> {
    if !private_hnsw_oram_vector_name_is_safe_store_component(value) {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM {label} is not a safe store path component",
        )));
    }
    Ok(())
}

pub fn private_hnsw_oram_vector_name_is_safe_store_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !private_oram_path_component_is_client_owned_state_alias(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
}

pub fn private_oram_path_component_is_client_owned_state_alias(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let compact_value = value.replace(['_', '-', '.'], "");
    if compact_path_component_is_client_owned_oram_state_alias(&compact_value) {
        return true;
    }
    let Some((stem, _extension)) = value.rsplit_once('.') else {
        return false;
    };
    compact_path_component_is_client_owned_oram_state_alias(&stem.replace(['_', '-', '.'], ""))
}

fn compact_path_component_is_client_owned_oram_state_alias(value: &str) -> bool {
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

fn create_private_dir(path: &Path) -> CollectionResult<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(CollectionError::service_error(
                "private HNSW ORAM path must be a non-symlink directory",
            ));
        }
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| {
                CollectionError::service_error("failed to create private HNSW ORAM directory")
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|_| {
                CollectionError::service_error("failed to inspect private HNSW ORAM directory")
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(CollectionError::service_error(
                    "private HNSW ORAM path must be a non-symlink directory",
                ));
            }
            true
        }
        Err(_) => {
            return Err(CollectionError::service_error(
                "failed to inspect private HNSW ORAM directory",
            ));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                CollectionError::service_error("failed to harden private HNSW ORAM directory")
            })?;
        }
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> CollectionResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found("private HNSW ORAM directory");
        }
        CollectionError::service_error("failed to inspect private HNSW ORAM directory")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::service_error(
            "private HNSW ORAM path must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(
                "private HNSW ORAM directory must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private HNSW ORAM directory must not be group/world accessible",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_store_directory_identity(directory: &File, path: &Path) -> CollectionResult<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let opened = directory.metadata().map_err(|_| {
        CollectionError::service_error("failed to inspect private HNSW ORAM owner store root")
    })?;
    let current = fs::symlink_metadata(path).map_err(|_| {
        CollectionError::service_error("failed to inspect private HNSW ORAM owner store root")
    })?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !opened.file_type().is_dir()
        || current.file_type().is_symlink()
        || !current.file_type().is_dir()
        || opened.uid() != effective_uid
        || current.uid() != effective_uid
        || opened.permissions().mode() & 0o077 != 0
        || current.permissions().mode() & 0o077 != 0
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(CollectionError::service_error(
            "private HNSW ORAM owner store root identity is invalid",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_owner_store_directory_identity(
    _directory: &File,
    _path: &Path,
) -> CollectionResult<()> {
    Err(CollectionError::service_error(
        "private HNSW ORAM owner store verification is unsupported on this platform",
    ))
}

fn read_json_private_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> CollectionResult<T> {
    let mut file = open_private_file_for_read(path, max_bytes)?;
    let mut bytes = Vec::new();
    let read_limit = max_bytes.saturating_add(1);
    (&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| CollectionError::service_error("failed to read private HNSW ORAM file"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM file exceeds maximum size",
        ));
    }
    validate_opened_private_file_at_path(&file, path, max_bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| CollectionError::bad_request("private HNSW ORAM file contains invalid JSON"))
}

fn write_json_atomic<T: Serialize>(
    root: &Path,
    temp_dir: &Path,
    target: &Path,
    value: &T,
) -> CollectionResult<()> {
    write_json_atomic_with_limit(root, temp_dir, target, value, u64::MAX)
}

/// Writes `value` atomically, refusing before any file is created when the serialized form
/// exceeds `max_bytes`: every reader enforces a size cap, so a record larger than its reader's
/// cap would be written once and then never be readable again (a pending write-back record
/// that outgrows its cap wedges the index until the file is removed by hand).
fn write_json_atomic_with_limit<T: Serialize>(
    root: &Path,
    temp_dir: &Path,
    target: &Path,
    value: &T,
    max_bytes: u64,
) -> CollectionResult<()> {
    validate_target_under_root(root, target)?;
    validate_private_dir(temp_dir)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| {
        CollectionError::service_error("failed to serialize private HNSW ORAM file")
    })?;
    if u64::try_from(bytes.len()).is_ok_and(|len| len > max_bytes) {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM record exceeds its maximum size",
        ));
    }
    let temp_path = unique_temp_path(temp_dir);
    let written = (|| -> CollectionResult<()> {
        let mut file = open_private_file_for_write(&temp_path)?;
        file.write_all(&bytes).map_err(|_| {
            CollectionError::service_error("failed to write private HNSW ORAM temp file")
        })?;
        file.flush().map_err(|_| {
            CollectionError::service_error("failed to flush private HNSW ORAM temp file")
        })?;
        file.sync_all().map_err(|_| {
            CollectionError::service_error("failed to sync private HNSW ORAM temp file")
        })?;
        drop(file);
        sync_dir(temp_dir)?;
        fs::rename(&temp_path, target)
            .map_err(|_| CollectionError::service_error("failed to replace private HNSW ORAM file"))
    })();
    if let Err(err) = written {
        // Nothing sweeps `temp/`, so a failed write (ENOSPC, a crash-free error) must not leave
        // its partial file behind.
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Some(parent) = target.parent() {
        sync_dir(parent)?;
    }
    if target.parent() != Some(temp_dir) {
        sync_dir(temp_dir)?;
    }
    Ok(())
}

/// A post-commit manifest refresh may change only `index_epoch`, `root_hash`, the node counts
/// and `created_at_unix`; every other field is part of each stored bucket's commitment context
/// or of the runtime policy pinned at upload.
fn manifest_refresh_preserves_immutable_fields(
    stored: &PrivateHnswOramManifest,
    refreshed: &PrivateHnswOramManifest,
) -> bool {
    let mut expected = stored.clone();
    expected.index_epoch = refreshed.index_epoch;
    expected.root_hash = refreshed.root_hash.clone();
    expected.logical_node_count = refreshed.logical_node_count;
    expected.dummy_node_count = refreshed.dummy_node_count;
    expected.created_at_unix = refreshed.created_at_unix;
    expected == *refreshed
}

fn remove_private_file(path: &Path, parent: &Path, max_bytes: u64) -> CollectionResult<()> {
    validate_private_dir(parent)?;
    let file = open_private_file_for_read(path, max_bytes)?;
    drop(file);
    fs::remove_file(path)
        .map_err(|_| CollectionError::service_error("failed to remove private HNSW ORAM file"))?;
    sync_dir(parent)
}

fn validate_target_under_root(root: &Path, target: &Path) -> CollectionResult<()> {
    if !target.starts_with(root) {
        return Err(CollectionError::service_error(
            "private HNSW ORAM target escapes root",
        ));
    }
    if let Some(parent) = target.parent() {
        validate_private_dir(parent)?;
    }
    Ok(())
}

fn open_private_file_for_read(path: &Path, max_bytes: u64) -> CollectionResult<File> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found("private HNSW ORAM file");
        }
        CollectionError::service_error("failed to inspect private HNSW ORAM file")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM file exceeds maximum size",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(
                "private HNSW ORAM file must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private HNSW ORAM file must not be group/world accessible",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(CollectionError::service_error(
                "private HNSW ORAM file must not be hard-linked",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| CollectionError::service_error("failed to open private HNSW ORAM file"))?;
        validate_opened_private_file_for_read(&file, max_bytes)?;
        let opened = file.metadata().map_err(|_| {
            CollectionError::service_error("failed to inspect opened private HNSW ORAM file")
        })?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(CollectionError::service_error(
                "private HNSW ORAM file identity changed while opening",
            ));
        }
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        File::open(path)
            .map_err(|_| CollectionError::service_error("failed to open private HNSW ORAM file"))
    }
}

#[cfg(unix)]
fn validate_opened_private_file_for_read(file: &File, max_bytes: u64) -> CollectionResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata().map_err(|_| {
        CollectionError::service_error("failed to inspect opened private HNSW ORAM file")
    })?;
    if !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM file exceeds maximum size",
        ));
    }
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != effective_uid {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file must be owned by the current user",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file must not be group/world accessible",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file must not be hard-linked",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_opened_private_file_at_path(
    file: &File,
    path: &Path,
    max_bytes: u64,
) -> CollectionResult<()> {
    use std::os::unix::fs::MetadataExt as _;

    validate_opened_private_file_for_read(file, max_bytes)?;
    let opened = file.metadata().map_err(|_| {
        CollectionError::service_error("failed to inspect opened private HNSW ORAM file")
    })?;
    let current = fs::symlink_metadata(path).map_err(|_| {
        CollectionError::service_error("failed to re-inspect private HNSW ORAM file")
    })?;
    if current.file_type().is_symlink()
        || !current.file_type().is_file()
        || current.nlink() != 1
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file identity changed while reading",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_opened_private_file_at_path(
    _file: &File,
    _path: &Path,
    _max_bytes: u64,
) -> CollectionResult<()> {
    Ok(())
}

fn open_private_file_for_write(path: &Path) -> CollectionResult<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| CollectionError::service_error("failed to create private HNSW ORAM temp file"))
}

fn unique_temp_path(temp_dir: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    temp_dir.join(format!(
        "private-hnsw-oram-{}-{timestamp}-{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4(),
    ))
}

fn sync_dir(path: &Path) -> CollectionResult<()> {
    let file = File::open(path).map_err(|_| {
        CollectionError::service_error("failed to open private HNSW ORAM directory for sync")
    })?;
    file.sync_all()
        .map_err(|_| CollectionError::service_error("failed to sync private HNSW ORAM directory"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use qdrant_sec::{
        DistanceKind, EncryptionError, FixedBudgetParams, OramKind, OramParams,
        PRIVATE_HNSW_ORAM_BINDING, PRIVATE_HNSW_ORAM_V2_BINDING,
        PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION, PrivateHnswBucketAeadBaseContext,
        PrivateHnswBucketAeadContext, PrivateHnswBuildPoint, PrivateHnswClientCommitBucketRef,
        PrivateHnswClientCommitPlan, PrivateHnswClientError, PrivateHnswClientKeys,
        PrivateHnswCommitSignatureContext, PrivateHnswEncryptedPathBatch,
        PrivateHnswManifestBuildContext, PrivateHnswManifestValidationContext,
        PrivateHnswNodeBlockPlaintext, PrivateHnswOramClientConfig, PrivateHnswOramError,
        PrivateHnswOramPlaintextBucket, PrivateHnswParams, PrivateHnswSearchParams,
        PrivateHnswSignatureVerification, PrivateHnswVectorEncoding,
        PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2,
        PrivateOramImmutableManifestV2, PrivateOramIndexCapacityV2, ResultPrivacyMode, SecretKey,
        VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER,
        build_private_hnsw_oram_manifest_from_encrypted_index,
        build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
        decode_private_hnsw_oram_bucket_plaintext, empty_private_hnsw_oram_plaintext_bucket,
        encode_private_hnsw_oram_bucket_plaintext, open_private_hnsw_oram_bucket,
        package_private_hnsw_oram_upload_bundle, plan_private_hnsw_oram_commit,
        private_hnsw_oram_bucket_ids_for_leaf, private_hnsw_oram_merkle_root_for_commitments,
        seal_private_hnsw_oram_bucket, seal_private_hnsw_oram_plaintext_index,
        search_private_hnsw_oram_encrypted_verified, sign_private_hnsw_oram_commit,
        sign_private_hnsw_oram_manifest, verify_private_hnsw_oram_merkle_proof_json,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    use super::*;

    fn root_hash(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    #[test]
    fn private_hnsw_store_debug_redacts_paths_and_hashes() {
        let store = PrivateHnswOramStore::new("/tmp/hnsw-store-debug-sentinel", "text").unwrap();
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: "HNSW-STORE-ROOT-SENTINEL".to_string(),
        };
        let leaf_commitment = "HNSW-STORE-LEAF-COMMITMENT-SENTINEL".to_string();
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: "HNSW-STORE-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 123_456,
                leaf_hash: leaf_commitment.clone(),
                siblings: vec![PrivateHnswOramMerkleSibling {
                    level: 0,
                    position: MerkleSiblingPosition::Left,
                    hash: "HNSW-STORE-SIBLING-SENTINEL".to_string(),
                }],
            }],
        };
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: "HNSW-STORE-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaf_hashes: vec![leaf_commitment.clone()],
        };
        let rendered = [
            format!("{store:?}"),
            format!("{epoch:?}"),
            format!("{proof:?}"),
            format!("{:?}", proof.leaves[0]),
            format!("{:?}", proof.leaves[0].siblings[0]),
            format!("{tree:?}"),
        ]
        .join("\n");
        for leaked in [
            "/tmp/hnsw-store-debug-sentinel",
            "HNSW-STORE-ROOT-SENTINEL",
            leaf_commitment.as_str(),
            "HNSW-STORE-SIBLING-SENTINEL",
            "123456",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
        for (debug_rendered, redacted_count) in [
            (format!("{proof:?}"), "bucket_count: 8"),
            (format!("{proof:?}"), "leaf_count: 1"),
            (format!("{:?}", proof.leaves[0]), "sibling_count: 1"),
            (format!("{tree:?}"), "bucket_count: 8"),
            (format!("{tree:?}"), "leaf_hash_count: 1"),
        ] {
            assert!(
                !debug_rendered.contains(redacted_count),
                "leaked {redacted_count} in {debug_rendered}"
            );
        }
    }

    #[test]
    fn private_hnsw_temp_paths_include_random_suffix() {
        let temp = TempDir::new().unwrap();
        let first = unique_temp_path(temp.path());
        let second = unique_temp_path(temp.path());

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(temp.path()));
        assert_eq!(second.parent(), Some(temp.path()));
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("private-hnsw-oram-")
        );
    }

    #[test]
    fn private_hnsw_store_rejects_unsafe_vector_path_components_without_reflecting_value() {
        for vector_name in [
            "../secret-vector-sentinel",
            "/tmp/secret-vector-sentinel",
            "tenant/secret-vector-sentinel",
            "secret vector sentinel",
            "client_state",
            "client_states",
            "clientState",
            "clientStates",
            "client-state",
            "client.state",
            "client_state.json",
            "client_state_backup",
            "client_state_backups",
            "clientStateBackup.json",
            "clientStateBackups.json",
            "client_state_snapshot",
            "client_state_snapshot.json",
            "client_state_snapshots",
            "client_state_snapshots.json",
            "client.state.snapshots.json",
            "clientStateSnapshot.json",
            "clientStateSnapshots.json",
            "client.state.snapshot",
            "client.state.snapshot.json",
            "client_state_ciphertext",
            "clientStateCiphertext.json",
            "client_state_ciphertexts",
            "clientStateCiphertexts.json",
            "client_state_ciphertext_hash",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_hashes",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "clientStateCiphertextHashes.json",
            "client_state_ciphertext_sha256",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "clientStateCiphertextSha256.json",
            "client_state_ciphertexts_sha256",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "clientStateCiphertextsSha256.json",
            "encrypted_client_state",
            "encrypted.client.state",
            "encrypted.client.state.json",
            "encryptedClientState.json",
            "encrypted_client_states",
            "encryptedClientStates.json",
            "encrypted_client_state_backup",
            "encrypted_client_state_backups",
            "encryptedClientStateBackup.json",
            "encryptedClientStateBackups.json",
            "encrypted_client_state_snapshot",
            "encrypted.client.state.snapshot",
            "encrypted.client.state.snapshot.json",
            "encrypted_client_state_snapshot.json",
            "encrypted_client_state_snapshots",
            "encrypted_client_state_snapshots.json",
            "encrypted.client.state.snapshots.json",
            "encryptedClientStateSnapshot.json",
            "encryptedClientStateSnapshots.json",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertext.json",
            "encrypted_client_state_ciphertexts",
            "encryptedClientStateCiphertexts.json",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_hashes",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encryptedClientStateCiphertextHashes.json",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encryptedClientStateCiphertextSha256.json",
            "encrypted_client_state_ciphertexts_sha256",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "encryptedClientStateCiphertextsSha256.json",
            "state_ciphertext",
            "stateCiphertext.json",
            "state_ciphertexts",
            "stateCiphertexts.json",
            "state_ciphertext_hash",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_sha256",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "stateCiphertextSha256.json",
            "state_ciphertexts_sha256",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "stateCiphertextsSha256.json",
            "payload_fetch_token",
            "payload_fetch_token.json",
            "payload_fetch_tokens",
            "payload_fetch_tokens.json",
            "payloadFetchToken",
            "payloadFetchToken.json",
            "payloadFetchTokens",
            "payloadFetchTokens.json",
            "payload.fetch.token",
            "position_map",
            "position_maps",
            "positionMaps.json",
            "position_map_backup",
            "position_map_backups",
            "positionMapBackup.json",
            "positionMapBackups.json",
            "position_map_snapshot",
            "positionMapSnapshot.json",
            "position_map_snapshots",
            "positionMapSnapshots.json",
            "position.map",
            "oram-position-map",
            "oram_position_map",
            "oram_position_maps",
            "oramPositionMap.json",
            "oramPositionMaps.json",
            "oramPositionMapBackup",
            "oram_position_map_backup",
            "oram_position_map_backups",
            "oramPositionMapBackups.json",
            "oram_position_map_snapshot",
            "oramPositionMapSnapshot.json",
            "oram_position_map_snapshots",
            "oramPositionMapSnapshots.json",
            "token.position.map",
            "token_map",
            "token_maps",
            "tokenMap.json",
            "tokenMaps.json",
            "token_map_backup",
            "token.map.backup",
            "token.map.backup.json",
            "token.map.backups",
            "token.map.backups.json",
            "token_map_backups",
            "tokenMapBackup.json",
            "tokenMapBackups.json",
            "token_map_snapshot",
            "tokenMapSnapshot.json",
            "token_map_snapshots",
            "tokenMapSnapshots.json",
            "token_position_map",
            "token_position_maps",
            "tokenPositionMap.json",
            "tokenPositionMaps.json",
            "token_position_map_backup",
            "token.position.map.backup",
            "token.position.map.backup.json",
            "token.position.map.backups",
            "token.position.map.backups.json",
            "token_position_map_backups",
            "tokenPositionMapBackup.json",
            "tokenPositionMapBackups.json",
            "token_position_map_snapshot",
            "tokenPositionMapSnapshot.json",
            "token_position_map_snapshots",
            "tokenPositionMapSnapshots.json",
            "stash",
            "stash_backup",
            "stash_backups",
            "stashBackup.json",
            "stashBackups.json",
            "stash.snapshot",
            "stash_snapshot",
            "stashSnapshot.json",
            "stash_snapshots",
            "stashSnapshots.json",
            &"x".repeat(129),
        ] {
            let err = PrivateHnswOramStore::new("/tmp/hnsw-safe-path-test", vector_name)
                .expect_err("unsafe vector name must not become a filesystem path component");
            let rendered = err.to_string();
            assert!(rendered.contains("safe store path component"), "{rendered}");
            assert!(!rendered.contains(vector_name), "{rendered}");
        }

        for vector_name in ["text", "text_v1", "tenant-a@text.1"] {
            let store = PrivateHnswOramStore::new("/tmp/hnsw-safe-path-test", vector_name)
                .expect("safe vector name should be accepted");
            assert!(store.root_path().ends_with(vector_name));
        }
    }

    fn bucket_ciphertext(bytes: &[u8]) -> (String, String) {
        (
            BASE64URL_NOPAD.encode(bytes),
            BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref()),
        )
    }

    #[test]
    fn private_hnsw_client_error_mapping_redacts_structured_values() {
        let client_state_alias_needles = [
            "client_state",
            "clientState",
            "client_states",
            "clientStates",
            "client_state_ciphertext",
            "clientStateCiphertext",
            "client_state_ciphertexts",
            "clientStateCiphertexts",
            "client_state_ciphertext_hash",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "clientStateCiphertextHash",
            "client_state_ciphertext_hashes",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "clientStateCiphertextHashes",
            "client_state_ciphertext_sha256",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "clientStateCiphertextSha256",
            "client_state_ciphertexts_sha256",
            "client_state_ciphertexts_sha256.bin",
            "client_state_ciphertexts_sha256.json",
            "clientStateCiphertextsSha256",
            "client_state_backup",
            "clientStateBackup",
            "client_state_snapshot",
            "client.state.snapshot",
            "client.state.snapshot.json",
            "clientStateSnapshot",
            "client_state_snapshots",
            "clientStateSnapshots",
            "encrypted_client_states",
            "encryptedClientStates",
            "encrypted_client_state_backup",
            "encrypted_client_state",
            "encrypted.client.state",
            "encrypted.client.state.json",
            "encryptedClientState",
            "encryptedClientStateBackup",
            "encrypted_client_state_backups",
            "encrypted_client_state_snapshot",
            "encrypted.client.state.snapshot",
            "encrypted.client.state.snapshot.json",
            "encryptedClientStateSnapshot",
            "encrypted_client_state_snapshots",
            "encryptedClientStateSnapshots",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertext",
            "encrypted_client_state_ciphertexts",
            "encryptedClientStateCiphertexts",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encryptedClientStateCiphertextHash",
            "encrypted_client_state_ciphertext_hashes",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encryptedClientStateCiphertextHashes",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "encryptedClientStateCiphertextSha256",
            "encrypted_client_state_ciphertexts_sha256",
            "encrypted_client_state_ciphertexts_sha256.bin",
            "encrypted_client_state_ciphertexts_sha256.json",
            "encryptedClientStateCiphertextsSha256",
            "oram_position_map_backup",
            "oram_position_map_backups",
            "oram_position_map",
            "oram_position_maps",
            "oramPositionMap",
            "oramPositionMaps",
            "oramPositionMapBackup",
            "oramPositionMapBackups",
            "oram_position_map_snapshot",
            "oram_position_map_snapshots",
            "oramPositionMapSnapshot",
            "oramPositionMapSnapshots",
            "position_map",
            "position_maps",
            "positionMap",
            "positionMaps",
            "position_map_backup",
            "position_map_backups",
            "positionMapBackup",
            "positionMapBackups",
            "position_map_snapshot",
            "position_map_snapshots",
            "positionMapSnapshot",
            "positionMapSnapshots",
            "state_ciphertext",
            "stateCiphertext",
            "state_ciphertexts",
            "stateCiphertexts",
            "state_ciphertext_hash",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "stateCiphertextHash",
            "state_ciphertext_hashes",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "stateCiphertextHashes",
            "state_ciphertext_sha256",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
            "stateCiphertextSha256",
            "state_ciphertexts_sha256",
            "state_ciphertexts_sha256.bin",
            "state_ciphertexts_sha256.json",
            "stateCiphertextsSha256",
            "payload_fetch_token",
            "payload_fetch_tokens",
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload.fetch.token",
            "token_map",
            "token_maps",
            "tokenMap",
            "tokenMaps",
            "token_map_backup",
            "token.map.backup",
            "token.map.backup.json",
            "token.map.backups",
            "token.map.backups.json",
            "token_map_backups",
            "tokenMapBackup",
            "tokenMapBackups",
            "token_map_snapshot",
            "token_map_snapshots",
            "tokenMapSnapshot",
            "tokenMapSnapshots",
            "token_position_map",
            "token_position_maps",
            "tokenPositionMap",
            "tokenPositionMaps",
            "token_position_map_backup",
            "token.position.map.backup",
            "token.position.map.backup.json",
            "token.position.map.backups",
            "token.position.map.backups.json",
            "token_position_map_backups",
            "tokenPositionMapBackup",
            "tokenPositionMapBackups",
            "token_position_map_snapshot",
            "token_position_map_snapshots",
            "tokenPositionMapSnapshot",
            "tokenPositionMapSnapshots",
            "stash",
            "stashBackup",
            "stashBackups",
            "stash_backup",
            "stash_backups",
            "stash_snapshot",
            "stash_snapshots",
            "stashSnapshot",
            "stashSnapshots",
        ];
        let cases = [
            (
                private_hnsw_client_error(PrivateHnswClientError::Encryption(
                    EncryptionError::UnsupportedAlgorithm("aead-alg-777777".to_string()),
                )),
                vec!["aead-alg-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::TooManyNeighbors {
                    actual: 777_777,
                    limit: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::UnsupportedBlockVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::UnsupportedVectorEncoding(77)),
                vec!["77"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidBucketContext(
                    "bucket-context-777777",
                )),
                vec!["bucket-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::BucketCiphertextSizeMismatch {
                    bucket_id: 777_777,
                    expected_bytes: 888_888,
                    actual_bytes: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_hnsw_client_error(
                    PrivateHnswClientError::UnsupportedBucketCiphertextVersion(77),
                ),
                vec!["77"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidOramClientConfig(
                    "client-config-777777",
                )),
                vec!["client-config-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidBuildConfig(
                    "build-config-777777",
                )),
                vec!["build-config-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::OramInitialPlacementOverflow {
                    leaf: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(
                    PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidClientStateContext(
                    "client-state-context-777777",
                )),
                vec!["client-state-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(
                    PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidSearchConfig(
                    "search-config-777777",
                )),
                vec!["search-config-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::BucketOutOfRange {
                    bucket_id: 777_777,
                    bucket_count: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::DuplicateBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::MissingBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::DuplicateUpdatedBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::StaleBucketEpoch {
                    bucket_id: 777_777,
                    expected_epoch: 888_888,
                    actual_epoch: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::FixedBudgetNotExhausted {
                    completed_steps: 777_777,
                    fixed_steps: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::DuplicatePointToken),
                vec![],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::DuplicatePayloadFetchToken),
                vec![],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidAppendRewrite),
                vec![],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::UnsupportedBucketVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidCommitSignatureContext(
                    "commit-signature-context-777777",
                )),
                vec!["commit-signature-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidManifestSignatureContext(
                    "manifest-signature-context-777777",
                )),
                vec!["manifest-signature-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidMerkleProof),
                vec![],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidMerkleProofJson),
                vec![],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::MerkleProofMismatch),
                vec![],
            ),
        ];

        for (err, needles) in cases {
            let rendered = err.to_string();
            for needle in needles {
                assert!(!rendered.contains(needle), "{rendered}");
            }
            for needle in client_state_alias_needles.iter().copied() {
                assert!(!rendered.contains(needle), "{rendered}");
            }
        }
    }

    #[test]
    fn private_hnsw_oram_error_mapping_redacts_structured_values() {
        let cases = [
            (
                private_hnsw_oram_error(PrivateHnswOramError::UnsupportedManifestVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
                    "rsa-pss-777777".to_string(),
                )),
                vec!["rsa-pss-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::InvalidManifestField(
                    "manifest-field-777777",
                )),
                vec!["manifest-field-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::ManifestContextMismatch(
                    "manifest-context-777777",
                )),
                vec!["manifest-context-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::UnsupportedBucketVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::BucketOutOfRange {
                    bucket_id: 777_777,
                    bucket_count: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::StaleBucketEpoch {
                    bucket_id: 777_777,
                    expected_epoch: 888_888,
                    actual_epoch: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::DuplicateUpdatedBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::InvalidBucketField(
                    "bucket-field-777777",
                )),
                vec!["bucket-field-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::InvalidBucketContext(
                    "bucket-context-777777",
                )),
                vec!["bucket-context-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::InvalidFetchPlanField(
                    "fetch-plan-field-777777",
                )),
                vec!["fetch-plan-field-777777", "777777"],
            ),
        ];

        for (err, needles) in cases {
            let rendered = err.to_string();
            for needle in needles {
                assert!(!rendered.contains(needle), "{rendered}");
            }
        }
    }

    #[test]
    fn private_hnsw_oram_error_mapping_redacts_client_state_alias_fields() {
        let sensitive_fields = [
            "client_state_ciphertext_hash.bin",
            "clientStateCiphertextHash",
            "encrypted_client_state_ciphertext_sha256.json",
            "encryptedClientStateCiphertextSha256",
            "oram_position_map_snapshot",
            "positionMapBackup",
            "state_ciphertexts_sha256.json",
            "token_position_map_backup",
            "payload_fetch_tokens",
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload.fetch.token",
            "stashSnapshot",
        ];

        for field in sensitive_fields {
            let cases = [
                private_hnsw_oram_error(PrivateHnswOramError::InvalidManifestField(field)),
                private_hnsw_oram_error(PrivateHnswOramError::ManifestContextMismatch(field)),
                private_hnsw_oram_error(PrivateHnswOramError::InvalidBucketField(field)),
                private_hnsw_oram_error(PrivateHnswOramError::InvalidBucketContext(field)),
                private_hnsw_oram_error(PrivateHnswOramError::InvalidFetchPlanField(field)),
            ];

            for err in cases {
                let rendered = err.to_string();
                assert!(!rendered.contains(field), "{rendered}");
                assert!(!rendered.contains("client_state"), "{rendered}");
                assert!(!rendered.contains("ClientState"), "{rendered}");
                assert!(!rendered.contains("position_map"), "{rendered}");
                assert!(!rendered.contains("PositionMap"), "{rendered}");
                assert!(!rendered.contains("payload_fetch_tokens"), "{rendered}");
                assert!(!rendered.contains("payloadFetchToken"), "{rendered}");
                assert!(!rendered.contains("payloadFetchTokens"), "{rendered}");
                assert!(!rendered.contains("payload.fetch.token"), "{rendered}");
                assert!(!rendered.contains("stash"), "{rendered}");
            }
        }
    }

    fn fixture_store(temp: &TempDir) -> PrivateHnswOramStore {
        PrivateHnswOramStore::new(temp.path(), "text").unwrap()
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
            root_hash: root_hash(42),
            bucket_count: 16,
            logical_node_count: 10,
            dummy_node_count: 6,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn fixture_signature() -> PrivateHnswOramSignature {
        PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_bucket(bucket_id: u64, epoch: u64, plaintext: &[u8]) -> PrivateHnswOramBucket {
        let (ciphertext, ciphertext_sha256) = bucket_ciphertext(plaintext);
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment: root_hash(99),
        }
    }

    fn fixture_bucket_commitment(
        manifest: &PrivateHnswOramManifest,
        bucket_id: u64,
        index_epoch: u64,
        ciphertext_sha256: &str,
    ) -> String {
        private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch,
            },
            ciphertext_sha256,
        )
        .unwrap()
    }

    fn client_bucket_context(bucket_id: u64) -> PrivateHnswBucketAeadContext<'static> {
        client_bucket_base_context().for_bucket(bucket_id, 42)
    }

    fn client_bucket_base_context() -> PrivateHnswBucketAeadBaseContext<'static> {
        PrivateHnswBucketAeadBaseContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
        }
    }

    fn fixture_client_keys() -> PrivateHnswClientKeys {
        PrivateHnswClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes([13; 32]),
            "collection-uuid-1",
            "text",
            "tenant-a/vector-private-rk",
            7,
        )
        .unwrap()
    }

    fn client_oram_config() -> PrivateHnswOramClientConfig {
        PrivateHnswOramClientConfig {
            tree_height: 1,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        }
    }

    fn fixture_upload_bundle(key_pair: &Ed25519KeyPair) -> PrivateHnswOramUploadBundle {
        let keys = fixture_client_keys();
        let config = client_oram_config();
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [2; 32],
                point_token: [22; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            1,
            1,
            &points,
            &[0, 1],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            client_bucket_base_context(),
            42,
            &plaintext_build,
            config,
        )
        .unwrap();

        package_private_hnsw_oram_upload_bundle(
            key_pair,
            PrivateHnswManifestBuildContext {
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
            },
            &encrypted_build,
        )
        .unwrap()
    }

    fn fixture_signed_commit_update(
        key_pair: &Ed25519KeyPair,
    ) -> (
        PrivateHnswOramUploadBundle,
        PrivateHnswOramBucket,
        PrivateHnswOramEpochState,
        PrivateHnswOramSignature,
    ) {
        let bundle = fixture_upload_bundle(key_pair);
        let keys = fixture_client_keys();
        let config = client_oram_config();
        let plaintext_bucket = empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap();
        let encoded_bucket =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket, config).unwrap();
        let updated_bucket = seal_private_hnsw_oram_bucket(
            &keys,
            client_bucket_base_context().for_bucket(0, 43),
            &encoded_bucket,
        )
        .unwrap();

        let mut next_commitments = bundle.bucket_commitments();
        let bucket_index = usize::try_from(updated_bucket.bucket_id).unwrap();
        next_commitments[bucket_index] = updated_bucket.bucket_commitment.clone();
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let plan = PrivateHnswClientCommitPlan {
            old_epoch: bundle.manifest.index_epoch,
            new_epoch: new_epoch.index_epoch,
            old_root_hash: bundle.manifest.root_hash.clone(),
            new_root_hash: new_epoch.root_hash.clone(),
            leaf_commitments: next_commitments,
            updated_buckets: vec![PrivateHnswClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let signature = sign_private_hnsw_oram_commit(
            key_pair,
            PrivateHnswCommitSignatureContext {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-hnsw-signing-v1",
            },
            &plan,
        )
        .unwrap();
        (bundle, updated_bucket, new_epoch, signature)
    }

    fn fixture_owner_signed_commit_update(
        key_pair: &Ed25519KeyPair,
    ) -> (
        PrivateHnswOramUploadBundle,
        PrivateHnswOramBucket,
        PrivateHnswOramEpochState,
        PrivateHnswOramSignature,
    ) {
        let (mut bundle, updated_bucket, new_epoch, signature) =
            fixture_signed_commit_update(key_pair);
        bundle.manifest.dummy_node_count -= 1;
        bundle.manifest_signature =
            sign_private_hnsw_oram_manifest(key_pair, &bundle.manifest).unwrap();
        (bundle, updated_bucket, new_epoch, signature)
    }

    fn fixture_validation_context<'a>(
        public_key: &'a [u8],
    ) -> PrivateHnswManifestValidationContext<'a> {
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
                public_key,
            },
        }
    }

    fn fixture_owner_states(
        manifest: &PrivateHnswOramManifest,
        new_epoch: &PrivateHnswOramEpochState,
    ) -> (PrivateOramIndexStateV2, PrivateOramIndexStateV2) {
        let old = PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: manifest.vector_name.clone(),
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
            logical_count: manifest.logical_node_count,
            dummy_count: manifest.dummy_node_count,
            last_writeback_digest: root_hash(70),
        };
        let new = PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: manifest.vector_name.clone(),
            index_epoch: new_epoch.index_epoch,
            root_hash: new_epoch.root_hash.clone(),
            logical_count: manifest.logical_node_count + 1,
            dummy_count: manifest.dummy_node_count - 1,
            last_writeback_digest: root_hash(71),
        };
        (old, new)
    }

    fn fixture_owner_immutable_manifest(
        manifest: &PrivateHnswOramManifest,
    ) -> PrivateOramImmutableManifestV2 {
        let logical_capacity = manifest.logical_node_count + manifest.dummy_node_count;
        let physical_slots = manifest.bucket_count * u64::from(manifest.oram.bucket_size);
        assert!(logical_capacity < physical_slots);
        let fixed_append_read_path_count = manifest.oram.path_batch_size * 2;
        PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: manifest.collection_id.clone(),
            manifest_nonce: root_hash(69),
            indexes: vec![PrivateOramImmutableIndexV2 {
                index_name: manifest.vector_name.clone(),
                params: PrivateOramImmutableIndexParamsV2::Hnsw {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                    key_id: manifest.key_id.clone(),
                    rk_id: manifest.rk_id.clone(),
                    rk_epoch: manifest.rk_epoch,
                    dim: manifest.dim,
                    vector_encoding: PrivateHnswVectorEncoding::F32Le,
                    distance: manifest.distance,
                    hnsw: manifest.hnsw.clone(),
                    oram: manifest.oram.clone(),
                    fixed_search_budget: manifest.fixed_budget.clone(),
                    max_neighbor_rewrites: 1,
                },
                capacity: PrivateOramIndexCapacityV2 {
                    bucket_count: manifest.bucket_count,
                    logical_capacity,
                    reserved_physical_slots: physical_slots - logical_capacity,
                    max_client_stash_blocks: 1,
                    fixed_append_read_path_count,
                    fixed_append_write_bucket_count: fixed_append_read_path_count
                        * (manifest.oram.tree_height + 1),
                },
            }],
            result_privacy: manifest.result_privacy,
            owner_signing_key_id: manifest.owner_signing_key_id.clone(),
            created_at_unix: manifest.created_at_unix,
        }
    }

    fn fixture_owner_bucket_refs(
        buckets: &[PrivateHnswOramBucket],
    ) -> Vec<PrivateOramAppendBucketRefV1> {
        buckets
            .iter()
            .map(|bucket| PrivateOramAppendBucketRefV1 {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect()
    }

    fn fixture_owner_store_context<'a>(
        journal_descriptor_digest: &'a str,
        prepared_state_digest: &'a str,
        immutable_manifest_digest: &'a str,
        immutable_manifest: &'a PrivateOramImmutableManifestV2,
        old_state: &'a PrivateOramIndexStateV2,
        new_state: &'a PrivateOramIndexStateV2,
        final_bucket_refs: &'a [PrivateOramAppendBucketRefV1],
        final_buckets: &'a [PrivateHnswOramBucket],
        public_key: &'a [u8],
    ) -> PrivateHnswOwnerStoreVerificationContextV1<'a> {
        PrivateHnswOwnerStoreVerificationContextV1 {
            journal_descriptor_digest,
            prepared_state_digest,
            immutable_manifest_digest,
            immutable_manifest,
            immutable_index: &immutable_manifest.indexes[0],
            index_name: "text",
            old_state,
            new_state,
            final_bucket_refs,
            final_buckets,
            max_ciphertext_bytes: 4096,
            manifest_validation: fixture_validation_context(public_key),
        }
    }

    struct OwnerRecoveryFixture {
        store: PrivateHnswOramStore,
        manifest: PrivateHnswOramManifest,
        old_state: PrivateOramIndexStateV2,
        new_state: PrivateOramIndexStateV2,
        final_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
        final_buckets: Vec<PrivateHnswOramBucket>,
        journal_descriptor_digest: String,
        prepared_state_digest: String,
        immutable_manifest_digest: String,
        immutable_manifest: PrivateOramImmutableManifestV2,
        public_key: Vec<u8>,
    }

    impl OwnerRecoveryFixture {
        fn new(temp: &TempDir) -> Self {
            let key_pair = Ed25519KeyPair::from_seed_unchecked(&[61; 32]).unwrap();
            let public_key = key_pair.public_key().as_ref().to_vec();
            let (bundle, first_bucket, _, _) = fixture_owner_signed_commit_update(&key_pair);
            let keys = fixture_client_keys();
            let config = client_oram_config();
            let plaintext_bucket = empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap();
            let encoded_bucket =
                encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket, config).unwrap();
            let second_bucket = seal_private_hnsw_oram_bucket(
                &keys,
                client_bucket_base_context().for_bucket(1, 43),
                &encoded_bucket,
            )
            .unwrap();
            let final_buckets = vec![first_bucket, second_bucket];
            let mut commitments = bundle.bucket_commitments();
            for bucket in &final_buckets {
                commitments[usize::try_from(bucket.bucket_id).unwrap()] =
                    bucket.bucket_commitment.clone();
            }
            let new_epoch = PrivateHnswOramEpochState {
                index_epoch: 43,
                root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&commitments).unwrap(),
            };
            let store = fixture_store(temp);
            store
                .write_initial_upload_bundle_with_signature(
                    &bundle,
                    4096,
                    fixture_validation_context(&public_key),
                )
                .unwrap();
            let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch);
            let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
            let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest);
            let immutable_manifest_digest =
                private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
            Self {
                store,
                manifest: bundle.manifest,
                old_state,
                new_state,
                final_bucket_refs,
                final_buckets,
                journal_descriptor_digest: root_hash(72),
                prepared_state_digest: root_hash(73),
                immutable_manifest_digest,
                immutable_manifest,
                public_key,
            }
        }

        fn context(&self) -> PrivateHnswOwnerStoreVerificationContextV1<'_> {
            fixture_owner_store_context(
                &self.journal_descriptor_digest,
                &self.prepared_state_digest,
                &self.immutable_manifest_digest,
                &self.immutable_manifest,
                &self.old_state,
                &self.new_state,
                &self.final_bucket_refs,
                &self.final_buckets,
                &self.public_key,
            )
        }

        fn seed_phase(&self, phase: PrivateHnswOwnerRecoveryPhaseV1) {
            let written_bucket_count = match phase {
                PrivateHnswOwnerRecoveryPhaseV1::S0 => 0,
                PrivateHnswOwnerRecoveryPhaseV1::S1 {
                    written_bucket_count,
                } => written_bucket_count,
                PrivateHnswOwnerRecoveryPhaseV1::S2
                | PrivateHnswOwnerRecoveryPhaseV1::S3
                | PrivateHnswOwnerRecoveryPhaseV1::S4 => self.final_buckets.len(),
            };
            for bucket in &self.final_buckets[..written_bucket_count] {
                self.store
                    .write_bucket(
                        bucket,
                        self.new_state.index_epoch,
                        self.manifest.bucket_count,
                        4096,
                    )
                    .unwrap();
            }
            if matches!(
                phase,
                PrivateHnswOwnerRecoveryPhaseV1::S2
                    | PrivateHnswOwnerRecoveryPhaseV1::S3
                    | PrivateHnswOwnerRecoveryPhaseV1::S4
            ) {
                self.store
                    .write_merkle_commit(
                        self.old_state.index_epoch,
                        &self.old_state.root_hash,
                        self.new_state.index_epoch,
                        &self.new_state.root_hash,
                        self.manifest.bucket_count,
                        &self.final_buckets,
                    )
                    .unwrap();
            }
            if matches!(
                phase,
                PrivateHnswOwnerRecoveryPhaseV1::S3 | PrivateHnswOwnerRecoveryPhaseV1::S4
            ) {
                self.write_new_commit(PrivateHnswOramEpochCommit {
                    index_epoch: self.new_state.index_epoch,
                    root_hash: self.new_state.root_hash.clone(),
                    writeback_digest: Some(self.new_state.last_writeback_digest.clone()),
                });
            }
            if phase == PrivateHnswOwnerRecoveryPhaseV1::S4 {
                self.write_current(&PrivateHnswOramEpochState {
                    index_epoch: self.new_state.index_epoch,
                    root_hash: self.new_state.root_hash.clone(),
                });
            }
        }

        fn write_new_commit(&self, commit: PrivateHnswOramEpochCommit) {
            write_json_atomic(
                &self.store.root,
                &self.store.temp_dir(),
                &self.store.commit_epoch_path(self.new_state.index_epoch),
                &commit,
            )
            .unwrap();
        }

        fn write_current(&self, current: &PrivateHnswOramEpochState) {
            write_json_atomic(
                &self.store.root,
                &self.store.temp_dir(),
                &self.store.current_epoch_path(),
                current,
            )
            .unwrap();
        }
    }

    fn assert_owner_recovery_resumes_from_phase(expected: PrivateHnswOwnerRecoveryPhaseV1) {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        fixture.seed_phase(expected);
        let lock = fixture.store.lock_owner_store_v1().unwrap();
        assert_eq!(
            lock.classify_owner_recovery_state_v1(fixture.context())
                .unwrap()
                .phase,
            expected
        );
        let token = lock
            .resume_owner_recovery_context_to_exact_new_v1(fixture.context())
            .unwrap();
        assert_eq!(token.index_name(), "text");
        assert_eq!(token.canonical_state_digest().len(), 43);
        assert_eq!(
            lock.classify_owner_recovery_state_v1(fixture.context())
                .unwrap()
                .phase,
            PrivateHnswOwnerRecoveryPhaseV1::S4
        );
    }

    fn client_node_block() -> PrivateHnswNodeBlockPlaintext {
        PrivateHnswNodeBlockPlaintext {
            version: 1,
            node_id: [21; 32],
            point_token: [22; 32],
            level_mask: 1,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vec![0, 0, 128, 63],
            neighbors: vec![[23; 32]],
            neighbor_levels: vec![0],
            deleted: false,
            generation: 1,
            payload_fetch_token: None,
        }
    }

    #[test]
    fn initial_upload_bundle_with_signature_verifies_manifest_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);

        let mut bad_alg_bundle = bundle.clone();
        let signature_alg_sentinel = "private-hnsw-signature-alg-sentinel";
        bad_alg_bundle.manifest_signature.alg = signature_alg_sentinel.to_string();
        let rendered = store
            .write_initial_upload_bundle(&bad_alg_bundle, 4096)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest signature context"));
        assert!(!rendered.contains(signature_alg_sentinel), "{rendered}");
        assert!(
            !rendered.contains(&bad_alg_bundle.manifest_signature.key_id),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.manifest_signature.sig),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.manifest.root_hash),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.buckets[0].ciphertext),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.buckets[0].ciphertext_sha256),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.buckets[0].bucket_commitment),
            "{rendered}"
        );
        assert!(
            !store.root_path().exists(),
            "invalid unsigned upload must not create private HNSW ORAM layout"
        );

        let epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                4096,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap();
        assert_eq!(epoch.index_epoch, bundle.manifest.index_epoch);
        assert_eq!(epoch.root_hash, bundle.manifest.root_hash);
        assert_eq!(
            store.read_manifest().unwrap(),
            (bundle.manifest.clone(), bundle.manifest_signature.clone()),
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(
            store.write_initial_upload_bundle(&bundle, 4096).unwrap(),
            epoch
        );
        assert_eq!(
            store
                .read_initial_upload_bundle(4096, 16 * 1024 * 1024)
                .unwrap(),
            bundle,
        );
        let oversized = store
            .read_initial_upload_bundle(4096, 1)
            .unwrap_err()
            .to_string();
        assert!(oversized.contains("initial replication bundle is oversized"));
        assert!(!oversized.contains(&epoch.root_hash));

        let mut mismatched_signature = bundle.clone();
        mismatched_signature.manifest_signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        let rendered = store
            .write_initial_upload_bundle(&mismatched_signature, 4096)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("does not match existing manifest"));
        assert!(!rendered.contains(&mismatched_signature.manifest_signature.sig));
        assert!(!rendered.contains(&mismatched_signature.manifest.root_hash));
        assert!(!rendered.contains(&mismatched_signature.buckets[0].ciphertext));
        assert!(!rendered.contains(&mismatched_signature.buckets[0].ciphertext_sha256));
        assert!(!rendered.contains(&mismatched_signature.buckets[0].bucket_commitment));

        let mut tampered = bundle.clone();
        tampered.manifest_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let rendered = store
            .write_initial_upload_bundle_with_signature(
                &tampered,
                4096,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest signature context"));
        assert!(!rendered.contains(&tampered.manifest_signature.sig));
        assert!(!rendered.contains(&tampered.manifest_signature.key_id));
        assert!(!rendered.contains(&tampered.manifest.root_hash));
        assert!(!rendered.contains(&tampered.buckets[0].ciphertext));
        assert!(!rendered.contains(&tampered.buckets[0].ciphertext_sha256));
        assert!(!rendered.contains(&tampered.buckets[0].bucket_commitment));
        assert!(
            !store.root_path().exists(),
            "invalid signed upload must not create private HNSW ORAM layout"
        );
        assert!(matches!(
            store.read_current_epoch(),
            Err(CollectionError::NotFound { .. })
        ));
    }

    #[test]
    fn initial_upload_bundle_rejects_root_mismatch() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[18; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let mut bundle = fixture_upload_bundle(&key_pair);
        let computed_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&bundle.bucket_commitments())
                .unwrap();
        bundle.manifest.root_hash = root_hash(99);
        assert_ne!(computed_root, bundle.manifest.root_hash);

        let err = store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("Merkle root mismatch"));
        assert!(!rendered.contains(&computed_root), "{rendered}");
        assert!(
            !store.root_path().exists(),
            "invalid initial upload must not create private HNSW ORAM layout"
        );
    }

    #[test]
    fn initial_upload_bundle_preflights_existing_epoch_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[18; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut replacement = original.clone();
        let config = client_oram_config();
        let plaintext_bucket = empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap();
        let encoded_bucket =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket, config).unwrap();
        let replacement_bucket = seal_private_hnsw_oram_bucket(
            &fixture_client_keys(),
            client_bucket_base_context().for_bucket(0, replacement.manifest.index_epoch),
            &encoded_bucket,
        )
        .unwrap();
        replacement.buckets[0] = replacement_bucket;
        replacement.manifest.root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&replacement.bucket_commitments())
                .unwrap();
        assert_ne!(replacement.manifest.root_hash, original.manifest.root_hash);

        let err = store
            .write_initial_upload_bundle(&replacement, 4096)
            .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("current epoch/root"), "{rendered}");
        assert!(!rendered.contains("upload bundle"), "{rendered}");
        assert_eq!(store.read_manifest().unwrap().0, original.manifest);
        assert_eq!(
            store
                .read_bucket(
                    0,
                    original.manifest.index_epoch,
                    original.manifest.bucket_count,
                    4096,
                )
                .unwrap(),
            original.buckets[0],
        );
        let proof = store
            .read_merkle_path_batch(
                &[0],
                original.manifest.index_epoch,
                &original.manifest.root_hash,
                original.manifest.bucket_count,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            original.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_files_to_match() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut replacement = original.buckets[0].clone();
        let mut replacement_raw = BASE64URL_NOPAD
            .decode(replacement.ciphertext.as_bytes())
            .unwrap();
        replacement_raw[0] ^= 0x55;
        replacement.ciphertext = BASE64URL_NOPAD.encode(&replacement_raw);
        replacement.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&replacement_raw).as_ref());
        assert_ne!(replacement, original.buckets[0]);
        store
            .write_bucket(
                &replacement,
                original.manifest.index_epoch,
                original.manifest.bucket_count,
                4096,
            )
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 4096)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("existing bucket set"));
        assert!(!rendered.contains(&replacement.ciphertext));
        assert!(!rendered.contains(&replacement.ciphertext_sha256));
        assert!(!rendered.contains(&replacement.bucket_commitment));
        assert!(!rendered.contains(&original.buckets[0].ciphertext));
        assert!(!rendered.contains(&original.buckets[0].ciphertext_sha256));
        assert_eq!(
            store
                .read_bucket(
                    0,
                    original.manifest.index_epoch,
                    original.manifest.bucket_count,
                    4096,
                )
                .unwrap(),
            replacement
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_manifest_to_match() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[20; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut tampered_signature = original.manifest_signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        store
            .write_manifest(&original.manifest, &tampered_signature)
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 4096)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("existing manifest"));
        assert!(!rendered.contains(&tampered_signature.sig));
        assert!(!rendered.contains(&original.manifest_signature.sig));
        assert!(!rendered.contains(&original.manifest.root_hash));
        assert!(!rendered.contains(&original.buckets[0].ciphertext));
        assert!(!rendered.contains(&original.buckets[0].ciphertext_sha256));
        assert!(!rendered.contains(&original.buckets[0].bucket_commitment));
        assert_eq!(store.read_manifest().unwrap().1, tampered_signature);
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_merkle_tree_to_match() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[21; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut tampered_commitments = original.bucket_commitments();
        tampered_commitments[1] = root_hash(88);
        let tampered_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&tampered_commitments).unwrap();
        assert_ne!(tampered_root, original.manifest.root_hash);
        store
            .write_merkle_tree_from_commitments(
                original.manifest.index_epoch,
                tampered_root.clone(),
                tampered_commitments,
            )
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 4096)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("existing Merkle tree"));
        assert!(!rendered.contains(&tampered_root));
        assert!(!rendered.contains(&original.manifest.root_hash));
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
        assert_eq!(store.read_merkle_tree().unwrap().root_hash, tampered_root);
    }

    #[test]
    fn missing_layout_reads_fail_as_not_found() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);

        let err = store.read_manifest().unwrap_err();
        assert!(matches!(err, CollectionError::NotFound { .. }));

        let err = store.read_current_epoch().unwrap_err();
        assert!(matches!(err, CollectionError::NotFound { .. }));
    }

    #[test]
    fn manifest_roundtrip_writes_private_files() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();

        store.write_manifest(&manifest, &signature).unwrap();
        let (stored_manifest, stored_signature) = store.read_manifest().unwrap();
        assert_eq!(stored_manifest, manifest);
        assert_eq!(stored_signature, signature);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let manifest_mode = fs::metadata(store.root_path().join(MANIFEST_FILE))
                .unwrap()
                .permissions()
                .mode();
            let root_mode = fs::metadata(store.root_path())
                .unwrap()
                .permissions()
                .mode();
            let parent_mode = fs::metadata(store.root_path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(manifest_mode & 0o077, 0);
            assert_eq!(root_mode & 0o077, 0);
            assert_eq!(parent_mode & 0o077, 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_writer_lock_contention_rejects_leaf_writer_before_mutation() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let bucket = fixture_bucket(0, 42, b"contended bucket");
        let bucket_path = store.bucket_path(bucket.bucket_id);
        let owner_lock = store.lock_owner_store_v1().unwrap();

        let error = store.write_bucket(&bucket, 42, 2, 64).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("another private HNSW ORAM owner store operation")
        );
        assert!(!bucket_path.exists());
        drop(owner_lock);
        store.write_bucket(&bucket, 42, 2, 64).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_writer_lock_contention_rejects_aggregate_writer_before_mutation() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let owner_lock = store.lock_owner_store_v1().unwrap();

        let error = store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("another private HNSW ORAM owner store operation")
        );
        for path in [
            store.manifest_path(),
            store.manifest_signature_path(),
            store.merkle_nodes_path(),
            store.current_epoch_path(),
            store.bucket_path(0),
        ] {
            assert!(!path.exists());
        }
        drop(owner_lock);
        store.write_initial_upload_bundle(&bundle, 4096).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initial_bucket_set_lock_contention_rejects_before_mutation() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);
        let expected = PrivateHnswOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store
            .write_manifest(&bundle.manifest, &bundle.manifest_signature)
            .unwrap();
        store.write_initial_epoch(&expected).unwrap();
        let owner_lock = store.lock_owner_store_v1().unwrap();

        let error = store
            .write_initial_bucket_set(&expected, &bundle.buckets, 4096)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("another private HNSW ORAM owner store operation")
        );
        assert!(!store.bucket_path(0).exists());
        assert!(!store.merkle_nodes_path().exists());
        drop(owner_lock);
        store
            .write_initial_bucket_set(&expected, &bundle.buckets, 4096)
            .unwrap();
    }

    #[test]
    fn initial_bucket_set_validates_entire_bundle_before_writes_and_does_not_self_deadlock() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);
        let expected = PrivateHnswOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store
            .write_manifest(&bundle.manifest, &bundle.manifest_signature)
            .unwrap();
        store.write_initial_epoch(&expected).unwrap();

        let mut invalid_hash = bundle.buckets.clone();
        invalid_hash.last_mut().unwrap().ciphertext_sha256 = root_hash(91);
        let error = store
            .write_initial_bucket_set(&expected, &invalid_hash, 4096)
            .unwrap_err();
        assert!(error.to_string().contains("ciphertext_sha256 mismatch"));
        assert!(!store.bucket_path(0).exists());
        assert!(!store.merkle_nodes_path().exists());

        let mut unordered = bundle.buckets.clone();
        unordered.swap(0, 1);
        let error = store
            .write_initial_bucket_set(&expected, &unordered, 4096)
            .unwrap_err();
        assert!(error.to_string().contains("complete and ordered"));
        assert!(!store.bucket_path(0).exists());
        assert!(!store.bucket_path(1).exists());
        assert!(!store.merkle_nodes_path().exists());

        store
            .write_bucket(
                &bundle.buckets[0],
                expected.index_epoch,
                bundle.manifest.bucket_count,
                4096,
            )
            .unwrap();
        assert!(!store.merkle_nodes_path().exists());
        store
            .write_initial_bucket_set(&expected, &bundle.buckets, 4096)
            .unwrap();
        assert_eq!(
            store
                .read_bucket(0, expected.index_epoch, bundle.manifest.bucket_count, 4096,)
                .unwrap(),
            bundle.buckets[0]
        );
        let proof = store
            .read_merkle_path_batch(
                &[0],
                expected.index_epoch,
                &expected.root_hash,
                bundle.manifest.bucket_count,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_store_lock_revalidates_root_identity_after_callback() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let displaced_root = temp.path().join("displaced-private-hnsw-root");

        let error = store
            .with_owner_store_lock_v1(|_| {
                fs::rename(&store.root, &displaced_root).unwrap();
                create_private_dir(&store.root).unwrap();
                Ok(())
            })
            .unwrap_err();

        assert!(error.to_string().contains("root identity is invalid"));
        fs::remove_dir(&store.root).unwrap();
        fs::rename(displaced_root, &store.root).unwrap();
        store.ensure_layout().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn canonical_writer_aggregate_operations_do_not_self_deadlock() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);

        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let committed = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            updated_bucket
        );
    }

    #[test]
    fn initial_epoch_if_absent_creates_private_layout() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };

        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();

        assert_eq!(store.read_current_epoch().unwrap(), epoch);
    }

    #[test]
    fn initial_epoch_reupload_is_idempotent_and_conflict_preserves_current() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let conflicting_epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(43),
        };

        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();
        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), epoch);

        let err = store
            .write_initial_epoch_if_absent_or_matching(&conflicting_epoch)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("current epoch/root does not match uploaded manifest"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains(&epoch.root_hash), "{rendered}");
        assert!(
            !rendered.contains(&conflicting_epoch.root_hash),
            "{rendered}"
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
    }

    #[test]
    fn current_manifest_reupload_requires_existing_manifest_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();
        let epoch = PrivateHnswOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap();
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap();

        let mut replacement = manifest.clone();
        replacement.logical_node_count += 1;
        replacement.dummy_node_count -= 1;
        let replacement_signature = PrivateHnswOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..signature.clone()
        };
        let rendered = store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &replacement,
                &replacement_signature,
                &epoch,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("manifest upload does not match existing current manifest"));
        assert!(!rendered.contains(&replacement_signature.sig));
        assert!(!rendered.contains(&signature.sig));
        assert!(!rendered.contains(&manifest.root_hash));
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(store.read_manifest().unwrap(), (manifest, signature));
    }

    #[test]
    fn current_manifest_reupload_repairs_a_torn_signature() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let stale_signature = fixture_signature();
        let epoch = PrivateHnswOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &manifest,
                &stale_signature,
                &epoch,
            )
            .unwrap();

        // A crash between the manifest and signature renames leaves the current manifest beside
        // another signature; re-uploading the verified pair must repair it, not wedge it.
        let signature = PrivateHnswOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..stale_signature.clone()
        };
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap();
        assert_eq!(
            store.read_manifest().unwrap(),
            (manifest.clone(), signature.clone())
        );
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap();
        assert_eq!(store.read_manifest().unwrap(), (manifest, signature));
    }

    #[test]
    fn post_commit_manifest_refresh_allows_current_epoch_ahead_of_stored_manifest() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let mut new_manifest = old_manifest.clone();
        new_manifest.index_epoch = old_manifest.index_epoch + 1;
        new_manifest.root_hash = root_hash(43);
        let new_signature = PrivateHnswOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..old_signature.clone()
        };
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: new_manifest.index_epoch,
            root_hash: new_manifest.root_hash.clone(),
        };

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &old_manifest,
                &old_signature,
                &old_epoch,
            )
            .unwrap();
        store
            .compare_and_swap_epoch(&old_epoch, &new_epoch)
            .unwrap();
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &new_manifest,
                &new_signature,
                &new_epoch,
            )
            .unwrap();

        assert_eq!(store.read_current_epoch().unwrap(), new_epoch);
        assert_eq!(
            store.read_manifest().unwrap(),
            (new_manifest, new_signature)
        );
    }

    #[test]
    fn post_commit_manifest_refresh_rejects_stale_epoch_without_overwriting() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: old_manifest.index_epoch + 1,
            root_hash: root_hash(43),
        };

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &old_manifest,
                &old_signature,
                &old_epoch,
            )
            .unwrap();
        store
            .compare_and_swap_epoch(&old_epoch, &new_epoch)
            .unwrap();

        let rendered = store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &old_manifest,
                &old_signature,
                &old_epoch,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("current epoch/root does not match uploaded manifest"));
        assert!(!rendered.contains(&old_signature.sig), "{rendered}");
        assert!(!rendered.contains(&old_epoch.root_hash), "{rendered}");
        assert!(!rendered.contains(&new_epoch.root_hash), "{rendered}");
        assert_eq!(store.read_current_epoch().unwrap(), new_epoch);
        assert_eq!(
            store.read_manifest().unwrap(),
            (old_manifest, old_signature)
        );
    }

    #[test]
    fn manifest_initial_epoch_publish_requires_manifest_write_success() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();
        let epoch = PrivateHnswOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };
        store.ensure_layout().unwrap();
        fs::create_dir(store.root_path().join(MANIFEST_SIGNATURE_FILE)).unwrap();

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap_err();

        assert!(
            matches!(
                store.read_current_epoch().unwrap_err(),
                CollectionError::NotFound { .. }
            ),
            "failed initial manifest upload must not publish current epoch"
        );
    }

    #[test]
    fn bucket_write_rejects_hash_mismatch_and_oversize() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted bucket");

        store
            .validate_bucket_for_write(&bucket, 42, 16, 64)
            .unwrap();
        store.write_bucket(&bucket, 42, 16, 64).unwrap();
        assert_eq!(store.read_bucket(3, 42, 16, 64).unwrap(), bucket);

        let large_max_ciphertext_bytes = 2 * 65_536 + 4_096;
        let large_bucket = fixture_bucket(6, 42, &vec![7; large_max_ciphertext_bytes]);
        store
            .write_bucket(&large_bucket, 42, 16, large_max_ciphertext_bytes)
            .unwrap();
        assert_eq!(
            store
                .read_bucket(6, 42, 16, large_max_ciphertext_bytes)
                .unwrap(),
            large_bucket
        );

        let mut bad_hash = bucket.clone();
        bad_hash.ciphertext_sha256 = root_hash(1);
        let err = store
            .validate_bucket_for_write(&bad_hash, 42, 16, 64)
            .unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));
        let err = store.write_bucket(&bad_hash, 42, 16, 64).unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));

        let oversized = fixture_bucket(4, 42, &[8; 65]);
        let err = store
            .validate_bucket_for_write(&oversized, 42, 16, 64)
            .unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));
        let err = store.write_bucket(&oversized, 42, 16, 64).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));

        let mut encoded_oversized = bucket.clone();
        encoded_oversized.bucket_id = 5;
        encoded_oversized.ciphertext = "A".repeat(max_base64url_nopad_encoded_len(64).unwrap() + 1);
        encoded_oversized.ciphertext_sha256 = root_hash(2);
        let err = store
            .validate_bucket_for_write(&encoded_oversized, 42, 16, 64)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("exceeds maximum size"));
        assert!(!rendered.contains("ciphertext_sha256 mismatch"));
        assert!(!rendered.contains(&encoded_oversized.ciphertext));

        let out_of_range = fixture_bucket(99, 42, b"out of range private hnsw bucket");
        let err = store
            .validate_bucket_for_write(&out_of_range, 42, 16, 64)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("99"), "{rendered}");
        assert!(!rendered.contains("16"), "{rendered}");
        let err = store.write_bucket(&out_of_range, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("99"), "{rendered}");
        assert!(!rendered.contains("16"), "{rendered}");
    }

    #[test]
    fn bucket_read_rejects_file_id_mismatch_without_ciphertext_leak() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let mut mismatched_bucket = fixture_bucket(1, 42, b"encrypted bucket mismatch");
        mismatched_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"private-hnsw-bucket-ciphertext-sentinel");
        write_json_atomic(
            store.root_path(),
            &store.temp_dir(),
            &store.root_path().join(BUCKETS_DIR).join("00000000.bucket"),
            &mismatched_bucket,
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 2, 128).unwrap_err();
        let err = err.to_string();

        assert!(err.contains("bucket file id mismatch"));
        assert!(!err.contains("requested"));
        assert!(!err.contains("found"));
        assert!(!err.contains("private-hnsw-bucket-ciphertext-sentinel"));
        assert!(!err.contains(&mismatched_bucket.ciphertext));
    }

    #[test]
    fn store_accepts_client_sealed_buckets_and_merkle_root_roundtrips() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let keys = fixture_client_keys();

        let config = client_oram_config();
        let plaintext_bucket0 = PrivateHnswOramPlaintextBucket {
            bucket_id: 0,
            blocks: vec![Some(client_node_block()), None],
        };
        let plaintext_bucket1 = empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap();
        let bucket0_plaintext =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket0, config).unwrap();
        let bucket1_plaintext =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket1, config).unwrap();
        let bucket0 =
            seal_private_hnsw_oram_bucket(&keys, client_bucket_context(0), &bucket0_plaintext)
                .unwrap();
        let bucket1 =
            seal_private_hnsw_oram_bucket(&keys, client_bucket_context(1), &bucket1_plaintext)
                .unwrap();
        let commitments = vec![
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&commitments).unwrap();
        assert_eq!(
            private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap(),
            root
        );

        store
            .write_merkle_tree_from_commitments(42, root.clone(), commitments.clone())
            .unwrap();
        store.write_bucket(&bucket0, 42, 2, 2048).unwrap();
        store.write_bucket(&bucket1, 42, 2, 2048).unwrap();

        let stored_bucket0 = store.read_bucket(0, 42, 2, 2048).unwrap();
        let reopened_bucket0 =
            open_private_hnsw_oram_bucket(&keys, client_bucket_context(0), &stored_bucket0)
                .unwrap();
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(0, &reopened_bucket0, config).unwrap(),
            plaintext_bucket0
        );

        let proof = store.read_merkle_path_batch(&[0, 1], 42, &root, 2).unwrap();
        assert_eq!(proof.root_hash, root);
        assert_eq!(proof.leaves[0].leaf_hash, commitments[0]);
        assert_eq!(proof.leaves[1].leaf_hash, commitments[1]);
    }

    #[test]
    fn client_commit_plan_matches_store_merkle_commit_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated bucket");
        let plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        store
            .write_merkle_commit(
                42,
                &old_root,
                43,
                &plan.new_root_hash,
                4,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap();
        assert_eq!(
            store
                .read_merkle_path_batch(&[2], 43, &plan.new_root_hash, 4)
                .unwrap()
                .leaves[0]
                .leaf_hash,
            updated_bucket.bucket_commitment
        );
    }

    #[test]
    fn bucket_read_accepts_unchanged_bucket_from_prior_committed_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let unchanged_bucket = fixture_bucket(0, 42, b"unchanged bucket");
        let replaced_bucket = fixture_bucket(1, 42, b"old bucket");
        let leaf_commitments = vec![
            unchanged_bucket.bucket_commitment.clone(),
            replaced_bucket.bucket_commitment.clone(),
        ];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();

        store.write_bucket(&unchanged_bucket, 42, 2, 64).unwrap();
        store.write_bucket(&replaced_bucket, 42, 2, 64).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(1, 43, b"new bucket");
        let mut updated_commitments = leaf_commitments;
        updated_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&updated_commitments).unwrap();
        store
            .write_merkle_commit(
                42,
                &old_root,
                43,
                &new_root,
                2,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap();
        store.write_bucket(&updated_bucket, 43, 2, 64).unwrap();

        assert_eq!(store.read_bucket(0, 43, 2, 64).unwrap(), unchanged_bucket);
        assert_eq!(store.read_bucket(1, 43, 2, 64).unwrap(), updated_bucket);
        let err = store.read_bucket(1, 42, 2, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("1"), "{rendered}");
    }

    #[test]
    fn writeback_commit_rejects_non_advancing_epoch_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let original_bucket = bundle.buckets[0].clone();
        let updated_bucket =
            fixture_bucket(0, old.index_epoch, b"private-hnsw-non-advancing-sentinel");
        let non_advancing_new = PrivateHnswOramEpochState {
            index_epoch: old.index_epoch,
            root_hash: root_hash(99),
        };

        let err = store
            .commit_writeback(
                &old,
                &non_advancing_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("new epoch must be exactly old epoch + 1"));
        assert!(!err.contains("private-hnsw-non-advancing-sentinel"));
        assert!(!err.contains(&updated_bucket.ciphertext), "{err}");
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            original_bucket
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
    }

    #[test]
    fn writeback_commit_preflights_stale_current_epoch_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let stale_current = PrivateHnswOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: root_hash(77),
        };
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("RootHashMismatch"));
        assert!(!err.contains("42"), "{err}");
        assert!(!err.contains("43"), "{err}");
        assert!(!err.contains(&old.root_hash), "{err}");
        assert!(!err.contains(&stale_current.root_hash), "{err}");
        assert_eq!(store.read_current_epoch().unwrap(), stale_current);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0]
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_rejects_invalid_bucket_and_wrong_root_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let original_bucket = bundle.buckets[0].clone();
        let assert_writeback_target_unchanged = || {
            assert_eq!(store.read_current_epoch().unwrap(), old);
            assert_eq!(
                store
                    .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                    .unwrap(),
                original_bucket
            );
            let proof = store
                .read_merkle_path_batch(
                    &[0],
                    old.index_epoch,
                    &old.root_hash,
                    bundle.bucket_count(),
                )
                .unwrap();
            assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
        };

        let mut hash_mismatch_bucket = updated_bucket.clone();
        let mut hash_mismatch_raw = BASE64URL_NOPAD
            .decode(hash_mismatch_bucket.ciphertext.as_bytes())
            .unwrap();
        hash_mismatch_raw[0] ^= 0xff;
        hash_mismatch_bucket.ciphertext = BASE64URL_NOPAD.encode(&hash_mismatch_raw);
        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&hash_mismatch_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("ciphertext_sha256 mismatch"));
        assert!(!err.contains(&hash_mismatch_bucket.ciphertext), "{err}");
        assert!(
            !err.contains(&hash_mismatch_bucket.ciphertext_sha256),
            "{err}"
        );
        assert!(
            !err.contains(&hash_mismatch_bucket.bucket_commitment),
            "{err}"
        );
        assert_writeback_target_unchanged();

        let mut short_ciphertext_bucket = updated_bucket.clone();
        let short_raw = b"short-hnsw-commit";
        let short_hash = BASE64URL_NOPAD.encode(Sha256::digest(short_raw).as_ref());
        short_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(short_raw);
        short_ciphertext_bucket.ciphertext_sha256 = short_hash.clone();
        short_ciphertext_bucket.bucket_commitment = fixture_bucket_commitment(
            &bundle.manifest,
            short_ciphertext_bucket.bucket_id,
            short_ciphertext_bucket.index_epoch,
            &short_hash,
        );
        let mut short_commitments = bundle.bucket_commitments();
        short_commitments[0] = short_ciphertext_bucket.bucket_commitment.clone();
        let short_new = PrivateHnswOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&short_commitments)
                .unwrap(),
        };
        let err = store
            .commit_writeback(
                &old,
                &short_new,
                bundle.bucket_count(),
                std::slice::from_ref(&short_ciphertext_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains("short-hnsw-commit"));
        assert!(!err.contains(&short_ciphertext_bucket.ciphertext), "{err}");
        assert!(
            !err.contains(&short_ciphertext_bucket.ciphertext_sha256),
            "{err}"
        );
        assert!(
            !err.contains(&short_ciphertext_bucket.bucket_commitment),
            "{err}"
        );
        assert_writeback_target_unchanged();

        let expected_bytes =
            private_hnsw_oram_bucket_ciphertext_bytes(&bundle.manifest.oram).unwrap();
        let mut oversized_bucket = updated_bucket.clone();
        let oversized_raw = vec![7; expected_bytes + 1];
        oversized_bucket.ciphertext = BASE64URL_NOPAD.encode(&oversized_raw);
        oversized_bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&oversized_raw).as_ref());

        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&oversized_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains(&oversized_bucket.ciphertext));
        assert!(!err.contains(&oversized_bucket.ciphertext_sha256));
        assert_writeback_target_unchanged();

        let wrong_root_new = PrivateHnswOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: root_hash(99),
        };
        let err = store
            .commit_writeback(
                &old,
                &wrong_root_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("new_root_hash mismatch"));
        assert!(!err.contains(&wrong_root_new.root_hash), "{err}");
        assert!(!err.contains(&updated_bucket.ciphertext), "{err}");
        assert!(!err.contains(&updated_bucket.ciphertext_sha256), "{err}");
        assert!(!err.contains(&updated_bucket.bucket_commitment), "{err}");
        assert_writeback_target_unchanged();
    }

    #[test]
    fn writeback_commit_with_signature_verifies_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let committed = store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            updated_bucket,
        );
        let proof = store
            .read_merkle_path_batch(&[0], new.index_epoch, &new.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, updated_bucket.bucket_commitment);

        let second_updated_bucket = seal_private_hnsw_oram_bucket(
            &fixture_client_keys(),
            client_bucket_base_context().for_bucket(1, 44),
            &encode_private_hnsw_oram_bucket_plaintext(
                &empty_private_hnsw_oram_plaintext_bucket(1, client_oram_config()).unwrap(),
                client_oram_config(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut second_commitments = bundle.bucket_commitments();
        second_commitments[0] = updated_bucket.bucket_commitment.clone();
        second_commitments[1] = second_updated_bucket.bucket_commitment.clone();
        let second_new = PrivateHnswOramEpochState {
            index_epoch: 44,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&second_commitments)
                .unwrap(),
        };
        let second_plan = PrivateHnswClientCommitPlan {
            old_epoch: new.index_epoch,
            new_epoch: second_new.index_epoch,
            old_root_hash: new.root_hash.clone(),
            new_root_hash: second_new.root_hash.clone(),
            leaf_commitments: second_commitments,
            updated_buckets: vec![PrivateHnswClientCommitBucketRef {
                bucket_id: second_updated_bucket.bucket_id,
                ciphertext_sha256: second_updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let second_signature = sign_private_hnsw_oram_commit(
            &key_pair,
            PrivateHnswCommitSignatureContext {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-hnsw-signing-v1",
            },
            &second_plan,
        )
        .unwrap();
        let second_committed = store
            .commit_writeback_with_signature(
                &new,
                &second_new,
                bundle.bucket_count(),
                std::slice::from_ref(&second_updated_bucket),
                4096,
                &second_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap();

        assert_eq!(second_committed, second_new);
        assert_eq!(store.read_current_epoch().unwrap(), second_new);
        assert_eq!(store.read_manifest().unwrap().0, bundle.manifest);
        assert_eq!(
            store
                .read_bucket(1, second_new.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            second_updated_bucket,
        );
        let proof = store
            .read_merkle_path_batch(
                &[1],
                second_new.index_epoch,
                &second_new.root_hash,
                bundle.bucket_count(),
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            second_updated_bucket.bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let tampered_store = fixture_store(&temp);
        let old = tampered_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        let mut tampered_signature = signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let rendered = tampered_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &tampered_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("commit signature verification failed"));
        assert!(!rendered.contains(&tampered_signature.sig), "{rendered}");
        assert_eq!(tampered_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            tampered_store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = tampered_store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let unsupported_alg_store = fixture_store(&temp);
        let old = unsupported_alg_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        let mut unsupported_alg_signature = signature.clone();
        unsupported_alg_signature.alg = "rsa-pss-hnsw-sentinel".to_string();
        let rendered = unsupported_alg_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &unsupported_alg_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("signature algorithm must be ed25519"));
        assert!(
            !rendered.contains(&unsupported_alg_signature.alg),
            "{rendered}"
        );
        for sentinel in [
            unsupported_alg_signature.key_id.as_str(),
            unsupported_alg_signature.sig.as_str(),
            old.root_hash.as_str(),
            new.root_hash.as_str(),
            updated_bucket.ciphertext.as_str(),
            updated_bucket.ciphertext_sha256.as_str(),
            updated_bucket.bucket_commitment.as_str(),
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
        assert_eq!(unsupported_alg_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            unsupported_alg_store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = unsupported_alg_store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let wrong_key_store = fixture_store(&temp);
        let old = wrong_key_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        let mut wrong_key_signature = signature.clone();
        wrong_key_signature.key_id = "tenant-a/private-hnsw-signing-v2".to_string();
        let rendered = wrong_key_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &wrong_key_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("signature key id does not match runtime context"));
        assert!(
            !rendered.contains(&wrong_key_signature.key_id),
            "{rendered}"
        );
        assert_eq!(wrong_key_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            wrong_key_store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = wrong_key_store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn durable_signed_writeback_resumes_across_finalize_crash_windows() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);

        for crash_window in 0..3 {
            let temp = TempDir::new().unwrap();
            let store = fixture_store(&temp);
            let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
            let signature_verification = || PrivateHnswSignatureVerification {
                expected_key_id: "tenant-a/private-hnsw-signing-v1",
                public_key: public_key.as_ref(),
            };

            let consensus_writeback = store
                .prepare_durable_writeback_with_signature(
                    &old,
                    &new,
                    bundle.bucket_count(),
                    std::slice::from_ref(&updated_bucket),
                    4096,
                    &signature,
                    signature_verification(),
                )
                .unwrap();
            assert_eq!(consensus_writeback.old, old);
            assert_eq!(consensus_writeback.new, new);
            assert_eq!(
                BASE64URL_NOPAD
                    .decode(consensus_writeback.writeback_digest.as_bytes())
                    .unwrap()
                    .len(),
                32,
            );
            assert_eq!(
                store
                    .pending_writeback_consensus_transition_with_signature(
                        4096,
                        signature_verification(),
                    )
                    .unwrap(),
                Some(consensus_writeback.clone()),
            );
            assert_eq!(
                store
                    .prepare_durable_writeback_with_signature(
                        &old,
                        &new,
                        bundle.bucket_count(),
                        std::slice::from_ref(&updated_bucket),
                        4096,
                        &signature,
                        signature_verification(),
                    )
                    .unwrap(),
                consensus_writeback,
            );
            let rendered = format!("{consensus_writeback:?}");
            for sentinel in [
                old.root_hash.as_str(),
                new.root_hash.as_str(),
                consensus_writeback.writeback_digest.as_str(),
                updated_bucket.ciphertext.as_str(),
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
            assert_eq!(store.read_current_epoch().unwrap(), old);
            assert!(store.pending_writeback_path().exists());

            let pending: PrivateHnswPendingWriteback = read_json_private_file(
                &store.pending_writeback_path(),
                MAX_PENDING_WRITEBACK_BYTES,
            )
            .unwrap();
            if crash_window >= 1 {
                store
                    .write_bucket(
                        &updated_bucket,
                        new.index_epoch,
                        bundle.bucket_count(),
                        4096,
                    )
                    .unwrap();
                write_json_atomic(
                    &store.root,
                    &store.temp_dir(),
                    &store.merkle_nodes_path(),
                    &pending.merkle_tree,
                )
                .unwrap();
            }
            if crash_window >= 2 {
                store.compare_and_swap_epoch(&old, &new).unwrap();
            }

            let committed = if crash_window == 0 {
                store
                    .commit_writeback_with_signature(
                        &old,
                        &new,
                        bundle.bucket_count(),
                        std::slice::from_ref(&updated_bucket),
                        4096,
                        &signature,
                        signature_verification(),
                    )
                    .unwrap()
            } else {
                store
                    .recover_pending_writeback_with_signature(4096, signature_verification())
                    .unwrap()
                    .unwrap()
            };

            assert_eq!(committed, new);
            assert_eq!(store.read_current_epoch().unwrap(), new);
            assert_eq!(
                store
                    .read_bucket(0, new.index_epoch, bundle.bucket_count(), 4096)
                    .unwrap(),
                updated_bucket,
            );
            let proof = store
                .read_merkle_path_batch(
                    &[0],
                    new.index_epoch,
                    &new.root_hash,
                    bundle.bucket_count(),
                )
                .unwrap();
            assert_eq!(proof.leaves[0].leaf_hash, updated_bucket.bucket_commitment);
            assert!(!store.pending_writeback_path().exists());
            assert!(!store.pending_writeback_exists().unwrap());
            assert!(
                store
                    .completed_replica_writeback_matches(&consensus_writeback)
                    .unwrap()
            );
            assert_eq!(
                store
                    .pending_writeback_consensus_transition_with_signature(
                        4096,
                        signature_verification(),
                    )
                    .unwrap(),
                None,
            );
        }
    }

    #[test]
    fn replicated_signed_writeback_is_bound_to_consensus_before_prepare() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[35; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);
        let source_temp = TempDir::new().unwrap();
        let replica_temp = TempDir::new().unwrap();
        let source = fixture_store(&source_temp);
        let replica = fixture_store(&replica_temp);
        let old = source.write_initial_upload_bundle(&bundle, 4096).unwrap();
        assert_eq!(
            replica.write_initial_upload_bundle(&bundle, 4096).unwrap(),
            old,
        );
        let signature_verification = || PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: public_key.as_ref(),
        };

        let prepared = source
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                signature_verification(),
            )
            .unwrap();
        let (batch, exported) = source
            .pending_writeback_replication_batch_with_signature(4096, signature_verification())
            .unwrap()
            .unwrap();
        assert_eq!(exported, prepared);

        for pending_initial_replication in [
            source
                .read_initial_upload_bundle(4096, 16 * 1024 * 1024)
                .unwrap_err(),
            source
                .write_initial_upload_bundle(&bundle, 4096)
                .unwrap_err(),
        ] {
            let rendered = pending_initial_replication.to_string();
            assert!(rendered.contains("requires no pending writeback"));
            for sentinel in [
                old.root_hash.as_str(),
                new.root_hash.as_str(),
                exported.writeback_digest.as_str(),
                updated_bucket.ciphertext.as_str(),
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }

        let rendered = format!("{batch:?}");
        for sentinel in [
            old.root_hash.as_str(),
            new.root_hash.as_str(),
            updated_bucket.ciphertext.as_str(),
            signature.sig.as_str(),
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }

        let mut oversized_batch = batch.clone();
        let tree_bound = usize::try_from(bundle.manifest.bucket_count).unwrap();
        oversized_batch.updated_buckets =
            vec![updated_bucket.clone(); tree_bound.saturating_add(1)];
        let oversized = replica
            .prepare_replica_writeback_with_signature(
                &oversized_batch,
                &exported,
                4096,
                signature_verification(),
            )
            .unwrap_err()
            .to_string();
        assert!(oversized.contains("exceeds fixed writeback budget"));
        assert!(!oversized.contains(&updated_bucket.ciphertext));
        assert!(!replica.pending_writeback_exists().unwrap());

        let mut conflicting_consensus = exported.clone();
        conflicting_consensus.writeback_digest = BASE64URL_NOPAD.encode(&[99; 32]);
        let mismatch = replica
            .prepare_replica_writeback_with_signature(
                &batch,
                &conflicting_consensus,
                4096,
                signature_verification(),
            )
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("does not match consensus"));
        assert!(!mismatch.contains(&conflicting_consensus.writeback_digest));
        assert!(!replica.pending_writeback_exists().unwrap());
        assert_eq!(replica.read_current_epoch().unwrap(), old);

        let replicated = replica
            .prepare_replica_writeback_with_signature(
                &batch,
                &exported,
                4096,
                signature_verification(),
            )
            .unwrap();
        assert_eq!(replicated, exported);
        assert_eq!(replica.read_current_epoch().unwrap(), old);
        assert!(replica.pending_writeback_exists().unwrap());

        for mismatch in [
            replica
                .commit_replica_writeback_with_signature(
                    &conflicting_consensus,
                    4096,
                    signature_verification(),
                )
                .unwrap_err(),
            replica
                .abort_replica_writeback_with_signature(
                    &conflicting_consensus,
                    4096,
                    signature_verification(),
                )
                .unwrap_err(),
        ] {
            let mismatch = mismatch.to_string();
            assert!(mismatch.contains("consensus transition does not match"));
            assert!(!mismatch.contains(&conflicting_consensus.writeback_digest));
        }
        assert_eq!(replica.read_current_epoch().unwrap(), old);
        assert!(replica.pending_writeback_exists().unwrap());

        assert_eq!(
            replica
                .commit_replica_writeback_with_signature(&exported, 4096, signature_verification(),)
                .unwrap(),
            new,
        );
        assert_eq!(
            replica
                .prepare_replica_writeback_with_signature(
                    &batch,
                    &exported,
                    4096,
                    signature_verification(),
                )
                .unwrap(),
            exported,
        );
        assert!(!replica.pending_writeback_exists().unwrap());
        assert!(
            replica
                .completed_replica_writeback_matches(&exported)
                .unwrap()
        );
        assert!(
            !replica
                .completed_replica_writeback_matches(&conflicting_consensus)
                .unwrap()
        );
        assert_eq!(
            replica
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            updated_bucket,
        );
        let advanced = replica
            .read_initial_upload_bundle(4096, 16 * 1024 * 1024)
            .unwrap_err()
            .to_string();
        assert!(advanced.contains("requires the manifest epoch"));
        assert!(!advanced.contains(&new.root_hash));
    }

    #[test]
    fn live_replication_bundle_installs_advanced_signed_state() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[53; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);
        let source_temp = TempDir::new().unwrap();
        let target_temp = TempDir::new().unwrap();
        let source = fixture_store(&source_temp);
        let target = fixture_store(&target_temp);
        let old = source.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let verification = || PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: public_key.as_ref(),
        };

        source
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                verification(),
            )
            .unwrap();
        let unrefreshed = source
            .read_live_replication_bundle(4096, 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(unrefreshed.manifest.index_epoch, old.index_epoch);
        let mut refreshed_manifest = unrefreshed.manifest.clone();
        refreshed_manifest.index_epoch = new.index_epoch;
        refreshed_manifest.root_hash = new.root_hash.clone();
        let refreshed_signature =
            sign_private_hnsw_oram_manifest(&key_pair, &refreshed_manifest).unwrap();
        source
            .write_manifest(&refreshed_manifest, &refreshed_signature)
            .unwrap();
        let exported = source
            .read_live_replication_bundle(4096, 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(exported.current, new);
        assert_eq!(exported.manifest.index_epoch, new.index_epoch);
        assert!(exported.writeback_digest.is_some());
        assert_eq!(exported.buckets[0], updated_bucket);
        assert!(
            exported
                .buckets
                .iter()
                .skip(1)
                .all(|bucket| bucket.index_epoch == old.index_epoch)
        );

        let installed = target
            .write_live_replication_bundle_with_signature(
                &exported,
                4096,
                fixture_validation_context(public_key.as_ref()),
                &new,
                exported.writeback_digest.as_deref(),
            )
            .unwrap();
        assert_eq!(installed, new);
        assert_eq!(
            target
                .read_live_replication_bundle(4096, 16 * 1024 * 1024)
                .unwrap(),
            exported,
        );
        assert_eq!(
            target
                .write_live_replication_bundle_with_signature(
                    &exported,
                    4096,
                    fixture_validation_context(public_key.as_ref()),
                    &new,
                    exported.writeback_digest.as_deref(),
                )
                .unwrap(),
            new,
        );

        let mismatch_temp = TempDir::new().unwrap();
        let mismatch_target = fixture_store(&mismatch_temp);
        let mismatched_consensus = PrivateHnswOramEpochState {
            root_hash: root_hash(98),
            ..new.clone()
        };
        let rendered = mismatch_target
            .write_live_replication_bundle_with_signature(
                &exported,
                4096,
                fixture_validation_context(public_key.as_ref()),
                &mismatched_consensus,
                exported.writeback_digest.as_deref(),
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("does not match consensus"));
        assert!(!rendered.contains(&new.root_hash));
        assert!(!mismatch_target.root_path().exists());

        let rendered = format!("{exported:?}");
        for sentinel in [
            exported.current.root_hash.as_str(),
            exported.buckets[0].ciphertext.as_str(),
            exported.manifest_signature.sig.as_str(),
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
    }

    #[test]
    fn durable_signed_writeback_rejects_tampered_journal_before_finalize() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let signature_verification = || PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: public_key.as_ref(),
        };

        store
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                signature_verification(),
            )
            .unwrap();
        let mut pending: PrivateHnswPendingWriteback =
            read_json_private_file(&store.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)
                .unwrap();
        pending.commit_signature.sig = BASE64URL_NOPAD.encode(&[41; 64]);
        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.pending_writeback_path(),
            &pending,
        )
        .unwrap();

        let rendered = store
            .commit_prepared_writeback_with_signature(4096, signature_verification())
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("commit signature verification failed"));
        for sentinel in [
            pending.commit_signature.sig.as_str(),
            old.root_hash.as_str(),
            new.root_hash.as_str(),
            updated_bucket.ciphertext.as_str(),
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        assert!(store.pending_writeback_path().exists());
    }

    #[test]
    fn durable_signed_writeback_abort_requires_unmodified_old_view() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[43; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);
        let signature_verification = || PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: public_key.as_ref(),
        };

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        store
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                signature_verification(),
            )
            .unwrap();
        assert!(
            store
                .abort_pending_writeback_with_signature(4096, signature_verification())
                .unwrap()
        );
        assert!(!store.pending_writeback_exists().unwrap());
        assert_eq!(store.read_current_epoch().unwrap(), old);

        let temp = TempDir::new().unwrap();
        let partially_written_store = fixture_store(&temp);
        let old = partially_written_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        partially_written_store
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                signature_verification(),
            )
            .unwrap();
        partially_written_store
            .write_bucket(
                &updated_bucket,
                new.index_epoch,
                bundle.bucket_count(),
                4096,
            )
            .unwrap();
        let rendered = partially_written_store
            .abort_pending_writeback_with_signature(4096, signature_verification())
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains(&updated_bucket.ciphertext));
        assert!(partially_written_store.pending_writeback_exists().unwrap());
        assert_eq!(partially_written_store.read_current_epoch().unwrap(), old);
    }

    #[test]
    fn writeback_commit_rejects_bucket_commitment_context_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
        let (bundle, updated_bucket, _, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();

        let mut tampered_bucket = updated_bucket.clone();
        tampered_bucket.bucket_commitment = root_hash(88);
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[0] = tampered_bucket.bucket_commitment.clone();
        let tampered_new = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let rendered = store
            .commit_writeback(
                &old,
                &tampered_new,
                bundle.bucket_count(),
                std::slice::from_ref(&tampered_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("commit bucket commitment context mismatch"));
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_allows_manifest_epoch_root_to_remain_at_upload_anchor() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.root_hash = root_hash(99);
        assert_ne!(tampered_manifest.root_hash, old.root_hash);
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let committed = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            updated_bucket,
        );
        assert_eq!(store.read_manifest().unwrap().0, tampered_manifest);
    }

    #[test]
    fn writeback_commit_preflights_manifest_bucket_count_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.bucket_count += 1;
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let rendered = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("manifest bucket_count"));
        assert!(
            !rendered.contains(&tampered_manifest.bucket_count.to_string()),
            "{rendered}"
        );
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(
            !rendered.contains(&bundle.manifest_signature.sig),
            "{rendered}"
        );
        assert!(!rendered.contains(&updated_bucket.ciphertext), "{rendered}");
        assert!(
            !rendered.contains(&updated_bucket.bucket_commitment),
            "{rendered}"
        );
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0]
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn sdk_upload_search_fixture_roundtrips_store_read_paths_and_commit() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let keys = fixture_client_keys();
        let base_context = client_bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            tree_height: 2,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        };
        let entry_id = [1; 32];
        let neighbor_id = [2; 32];
        let far_id = [3; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: entry_id,
                point_token: [11; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: neighbor_id,
                point_token: [22; 32],
                vector: vec![2.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: far_id,
                point_token: [33; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            2,
            1,
            2,
            &points,
            &[0, 1, 2],
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
        let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
            PrivateHnswManifestBuildContext {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                dim: 2,
                distance: DistanceKind::Euclid,
                hnsw: PrivateHnswParams {
                    m: 2,
                    ef_construction: 4,
                    max_layers: 3,
                    fixed_neighbor_slots: config.fixed_neighbor_slots as u32,
                },
                oram: OramParams {
                    kind: OramKind::PathOram,
                    bucket_size: config.bucket_size as u32,
                    block_size_bytes: config.block_size_bytes as u32,
                    tree_height: config.tree_height,
                    path_batch_size: 1,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 3,
                    paths_per_round: 1,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: "tenant-a/private-hnsw-signing-v1",
                created_at_unix: 1_770_000_000,
            },
            &encrypted_build,
        )
        .unwrap();
        assert_eq!(manifest.root_hash, encrypted_build.root_hash);

        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: encrypted_build.index_epoch,
            root_hash: encrypted_build.root_hash.clone(),
        };
        let leaf_commitments = encrypted_build
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        store
            .write_manifest(&manifest, &fixture_signature())
            .unwrap();
        store.write_initial_epoch(&old_epoch).unwrap();
        store
            .write_merkle_tree_from_commitments(
                encrypted_build.index_epoch,
                encrypted_build.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for bucket in &encrypted_build.buckets {
            store
                .write_bucket(
                    bucket,
                    encrypted_build.index_epoch,
                    encrypted_build.bucket_count,
                    4096,
                )
                .unwrap();
        }

        let updated_by_bucket = std::cell::RefCell::new(BTreeMap::new());
        let mut state = plaintext_build.state.clone();
        let mut remaps = [3].into_iter();
        let result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            encrypted_build.index_epoch,
            &encrypted_build.root_hash,
            encrypted_build.bucket_count,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: encrypted_build.entry_node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let mut buckets = Vec::with_capacity(bucket_ids.len());
                for bucket_id in &bucket_ids {
                    let overlay_bucket = updated_by_bucket.borrow().get(bucket_id).cloned();
                    let bucket = match overlay_bucket {
                        Some(bucket) => bucket,
                        None => store
                            .read_bucket(
                                *bucket_id,
                                encrypted_build.index_epoch,
                                encrypted_build.bucket_count,
                                4096,
                            )
                            .map_err(|_| PrivateHnswClientError::PathBucketMismatch)?,
                    };
                    buckets.push(bucket);
                }
                let proof = store
                    .read_merkle_path_batch(
                        &bucket_ids,
                        encrypted_build.index_epoch,
                        &encrypted_build.root_hash,
                        encrypted_build.bucket_count,
                    )
                    .map_err(|_| PrivateHnswClientError::MerkleProofMismatch)?;
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: encrypted_build.index_epoch,
                    root_hash: encrypted_build.root_hash.clone(),
                    bucket_count: encrypted_build.bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                let mut updated = updated_by_bucket.borrow_mut();
                for bucket in writeback_buckets {
                    updated.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();
        assert_eq!(result.hits[0].node_id, entry_id);

        let updated_buckets = updated_by_bucket
            .into_inner()
            .into_values()
            .collect::<Vec<_>>();
        let commit_plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &encrypted_build.root_hash,
            &leaf_commitments,
            &updated_buckets,
        )
        .unwrap();
        store
            .write_merkle_commit(
                42,
                &encrypted_build.root_hash,
                43,
                &commit_plan.new_root_hash,
                encrypted_build.bucket_count,
                &updated_buckets,
            )
            .unwrap();
        for bucket in &updated_buckets {
            store
                .write_bucket(bucket, 43, encrypted_build.bucket_count, 4096)
                .unwrap();
        }
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: commit_plan.new_root_hash.clone(),
        };
        store
            .compare_and_swap_epoch(&old_epoch, &new_epoch)
            .unwrap();

        let mut post_commit_remaps = [3].into_iter();
        let post_commit_updates = std::cell::RefCell::new(BTreeMap::new());
        let post_commit_result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            43,
            &commit_plan.new_root_hash,
            encrypted_build.bucket_count,
            44,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: encrypted_build.entry_node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let mut buckets = Vec::with_capacity(bucket_ids.len());
                for bucket_id in &bucket_ids {
                    let overlay_bucket = post_commit_updates.borrow().get(bucket_id).cloned();
                    let bucket = match overlay_bucket {
                        Some(bucket) => bucket,
                        None => store
                            .read_bucket(*bucket_id, 43, encrypted_build.bucket_count, 4096)
                            .map_err(|_| PrivateHnswClientError::PathBucketMismatch)?,
                    };
                    buckets.push(bucket);
                }
                let proof = store
                    .read_merkle_path_batch(
                        &bucket_ids,
                        43,
                        &commit_plan.new_root_hash,
                        encrypted_build.bucket_count,
                    )
                    .map_err(|_| PrivateHnswClientError::MerkleProofMismatch)?;
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 43,
                    root_hash: commit_plan.new_root_hash.clone(),
                    bucket_count: encrypted_build.bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                let mut updated = post_commit_updates.borrow_mut();
                for bucket in writeback_buckets {
                    updated.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || {
                post_commit_remaps
                    .next()
                    .ok_or(PrivateHnswClientError::LeafOutOfRange)
            },
        )
        .unwrap();
        assert_eq!(post_commit_result.hits[0].node_id, entry_id);
        assert!(
            post_commit_updates
                .borrow()
                .values()
                .all(|bucket| bucket.index_epoch == 44)
        );
    }

    #[test]
    fn epoch_compare_and_swap_rejects_stale_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let new = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };
        store.write_initial_epoch(&old).unwrap();
        store
            .write_initial_epoch_if_absent_or_matching(&old)
            .unwrap();
        store.compare_and_swap_epoch(&old, &new).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), new);

        // A well-formed old+1 transition from the superseded state must hit the root check
        // (an epoch gap is refused earlier by the exact old+1 rule).
        let newer = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(44),
        };
        let err = store.compare_and_swap_epoch(&old, &newer).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("RootHashMismatch"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains("44"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&new.root_hash), "{rendered}");
        assert!(!rendered.contains(&newer.root_hash), "{rendered}");
    }

    #[test]
    fn crash_window_before_epoch_cas_fails_closed_instead_of_serving_mixed_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_bucket = fixture_bucket(0, 42, b"old bucket");
        let other_bucket = fixture_bucket(1, 42, b"other bucket");
        let old_commitments = vec![
            old_bucket.bucket_commitment.clone(),
            other_bucket.bucket_commitment.clone(),
        ];
        let old_root = PrivateHnswOramStore::merkle_root_for_commitments(&old_commitments).unwrap();
        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: old_root.clone(),
        };

        store.write_initial_epoch(&old_epoch).unwrap();
        store.write_bucket(&old_bucket, 42, 2, 64).unwrap();
        store.write_bucket(&other_bucket, 42, 2, 64).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), old_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(0, 43, b"new bucket");
        store.write_bucket(&updated_bucket, 43, 2, 64).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), old_epoch);
        let err = store.read_bucket(0, 42, 2, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("0"), "{rendered}");

        let mut new_commitments = old_commitments;
        new_commitments[0] = updated_bucket.bucket_commitment.clone();
        let new_root = PrivateHnswOramStore::merkle_root_for_commitments(&new_commitments).unwrap();
        store
            .write_merkle_commit(
                42,
                &old_root,
                43,
                &new_root,
                2,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), old_epoch);
        let err = store
            .read_merkle_path_batch(&[0], 42, &old_root, 2)
            .unwrap_err();
        assert!(err.to_string().contains("epoch mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn bucket_symlink_rejects() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside = temp.path().join("outside.bucket");
        let bucket = fixture_bucket(3, 42, b"symlink target hnsw bucket");
        fs::write(&outside, serde_json::to_vec_pretty(&bucket).unwrap()).unwrap();
        symlink(
            outside,
            store.root_path().join(BUCKETS_DIR).join("00000003.bucket"),
        )
        .unwrap();

        let err = store.read_bucket(3, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"));
        assert!(!rendered.contains("outside.bucket"), "{rendered}");
        assert!(!rendered.contains("00000003.bucket"), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn bucket_hardlink_rejects_without_path_or_body_leak() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside = temp.path().join("outside-hardlink.bucket");
        let bucket = fixture_bucket(3, 42, b"hard-linked hnsw bucket");
        fs::write(&outside, serde_json::to_vec_pretty(&bucket).unwrap()).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&outside, store.bucket_path(3)).unwrap();

        let error = store.read_bucket(3, 42, 16, 64).unwrap_err().to_string();
        assert!(error.contains("must not be hard-linked"));
        assert!(!error.contains("outside-hardlink"));
        assert!(!error.contains("00000003.bucket"));
        assert!(!error.contains(&bucket.ciphertext));
        assert!(!error.contains(&bucket.ciphertext_sha256));
        assert!(!error.contains(&bucket.bucket_commitment));
    }

    #[cfg(unix)]
    #[test]
    fn current_epoch_symlink_rejects_without_path_or_target_leak() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside = temp.path().join("outside-current-epoch.json");
        fs::write(&outside, br#"{"index_epoch":42,"root_hash":"bad"}"#).unwrap();
        symlink(outside, store.current_epoch_path()).unwrap();

        let err = store.read_current_epoch().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"), "{rendered}");
        assert!(!rendered.contains("outside-current-epoch"), "{rendered}");
        assert!(!rendered.contains(CURRENT_EPOCH_FILE), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn current_epoch_group_world_accessible_rejects_without_epoch_or_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        store.write_initial_epoch(&epoch).unwrap();
        fs::set_permissions(
            store.current_epoch_path(),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = store.read_current_epoch().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains(&epoch.root_hash), "{rendered}");
        assert!(!rendered.contains(CURRENT_EPOCH_FILE), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_rejects_root_symlink_without_chmod_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let outside_dir = temp.path().join("outside-private-hnsw");
        fs::create_dir(&outside_dir).unwrap();
        fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let private_hnsw_root = temp.path().join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_hnsw_root).unwrap();
        fs::set_permissions(&private_hnsw_root, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside_dir, private_hnsw_root.join("text")).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains("outside-private-hnsw"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        let outside_mode = fs::metadata(&outside_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn parent_directory_group_world_accessible_rejects_without_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let private_hnsw_root = temp.path().join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_hnsw_root).unwrap();
        fs::set_permissions(&private_hnsw_root, fs::Permissions::from_mode(0o755)).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(
            !store.root_path().exists(),
            "weak parent must fail before creating vector store root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn temp_directory_symlink_rejects_without_path_or_temp_name_leak() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside_temp = temp.path().join("outside-private-hnsw-temp");
        fs::create_dir(&outside_temp).unwrap();
        fs::set_permissions(&outside_temp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir(store.root_path().join(TEMP_DIR)).unwrap();
        symlink(&outside_temp, store.root_path().join(TEMP_DIR)).unwrap();

        let err = store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(
            !rendered.contains("outside-private-hnsw-temp"),
            "{rendered}"
        );
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains("private-hnsw-oram-"), "{rendered}");
        let outside_mode = fs::metadata(&outside_temp).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn temp_directory_group_world_accessible_rejects_without_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        fs::set_permissions(
            store.root_path().join(TEMP_DIR),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let err = store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains("private-hnsw-oram-"), "{rendered}");
        assert!(matches!(
            store.read_current_epoch(),
            Err(CollectionError::NotFound { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bucket_directory_group_world_accessible_rejects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        fs::set_permissions(
            store.root_path().join(BUCKETS_DIR),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let err = store.read_bucket(3, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn bucket_file_group_world_accessible_rejects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted bucket");
        store.write_bucket(&bucket, 42, 16, 64).unwrap();
        fs::set_permissions(
            store.root_path().join(BUCKETS_DIR).join("00000003.bucket"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = store.read_bucket(3, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("00000003.bucket"), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
    }

    #[test]
    fn merkle_tree_roundtrip_returns_batch_proof_for_requested_buckets() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut bucket1 = fixture_bucket(1, 42, b"encrypted hnsw bucket 1");
        bucket1.bucket_commitment = leaf_commitments[1].clone();
        let mut bucket3 = fixture_bucket(3, 42, b"encrypted hnsw bucket 3");
        bucket3.bucket_commitment = leaf_commitments[3].clone();

        store
            .write_merkle_tree_from_commitments(42, root.clone(), leaf_commitments.clone())
            .unwrap();
        let proof = store.read_merkle_path_batch(&[1, 3], 42, &root, 4).unwrap();

        assert_eq!(proof.kind, "merkle_path_batch/v1");
        assert_eq!(proof.index_epoch, 42);
        assert_eq!(proof.root_hash, root);
        assert_eq!(proof.bucket_count, 4);
        assert_eq!(proof.leaves.len(), 2);
        assert_eq!(proof.leaves[0].bucket_id, 1);
        assert_eq!(proof.leaves[0].leaf_hash, leaf_commitments[1]);
        assert_eq!(proof.leaves[1].bucket_id, 3);
        assert_eq!(proof.leaves[1].leaf_hash, leaf_commitments[3]);
        assert_eq!(proof.leaves[0].siblings.len(), 2);

        let duplicate_proof = store
            .read_merkle_path_batch(&[1, 3, 1], 42, &root, 4)
            .unwrap();
        assert_eq!(duplicate_proof.leaves.len(), 3);
        assert_eq!(duplicate_proof.leaves[0], duplicate_proof.leaves[2]);
        let duplicate_proof_json = serde_json::to_string(&duplicate_proof).unwrap();
        verify_private_hnsw_oram_merkle_proof_json(
            &duplicate_proof_json,
            42,
            &root,
            4,
            &[bucket1.clone(), bucket3, bucket1],
        )
        .unwrap();

        let err = store.read_merkle_path_batch(&[], 42, &root, 4).unwrap_err();
        assert!(err.to_string().contains("bucket batch is empty"));
        let err = store
            .read_merkle_path_batch(&[4], 42, &root, 4)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("4"), "{rendered}");

        let sentinel_bucket_id = 987_654_321_u64;
        let err = store
            .read_merkle_path_batch(&[sentinel_bucket_id], 42, &root, 4)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(
            !rendered.contains(&sentinel_bucket_id.to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn read_bucket_batch_with_proof_checks_current_epoch_and_commitments() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket0 = fixture_bucket(0, 42, b"encrypted hnsw bucket 0");
        let bucket1 = fixture_bucket(1, 42, b"encrypted hnsw bucket 1");
        let leaf_commitments = vec![
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        let current = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root.clone(),
        };

        store.write_initial_epoch(&current).unwrap();
        store
            .write_merkle_tree_from_commitments(42, root.clone(), leaf_commitments)
            .unwrap();
        store.write_bucket(&bucket0, 42, 2, 128).unwrap();
        store.write_bucket(&bucket1, 42, 2, 128).unwrap();

        let (buckets, proof) = store
            .read_bucket_batch_with_proof(&[0, 1, 0], 42, &root, 2, 128)
            .unwrap();
        assert_eq!(
            buckets,
            vec![bucket0.clone(), bucket1.clone(), bucket0.clone()]
        );
        assert_eq!(proof.leaves.len(), buckets.len());
        assert_eq!(proof.leaves[0], proof.leaves[2]);

        let mut replacement = fixture_bucket(1, 42, b"private-hnsw-read-bucket-mismatch-sentinel");
        replacement.bucket_commitment = root_hash(88);
        assert_ne!(replacement.bucket_commitment, bucket1.bucket_commitment);
        store.write_bucket(&replacement, 42, 2, 128).unwrap();

        let rendered = store
            .read_bucket_batch_with_proof(&[1], 42, &root, 2, 128)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("encrypted bucket/proof consistency validation failed"));
        assert!(!rendered.contains("private-hnsw-read-bucket-mismatch-sentinel"));
        assert!(!rendered.contains(&replacement.ciphertext));
        assert!(!rendered.contains(&replacement.ciphertext_sha256));
        assert!(!rendered.contains(&replacement.bucket_commitment));

        let rendered = store
            .read_bucket_batch_with_proof(&[], 42, &root, 2, 128)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket batch is empty"));
    }

    #[test]
    fn read_bucket_batch_with_proof_preflights_stale_current_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let stale_current = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };

        store.write_initial_epoch(&old).unwrap();
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let rendered = store
            .read_bucket_batch_with_proof(&[1], old.index_epoch, &old.root_hash, 2, 128)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale_current.root_hash), "{rendered}");
    }

    #[test]
    fn merkle_tree_validation_rejects_root_mismatch_without_computed_root() {
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: root_hash(99),
            bucket_count: 2,
            leaf_hashes: vec![root_hash(1), root_hash(2)],
        };
        let computed_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&tree.leaf_hashes).unwrap();
        assert_ne!(computed_root, tree.root_hash);

        let err = validate_merkle_tree(&tree).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("root_hash mismatch"));
        assert!(!rendered.contains(&computed_root), "{rendered}");
        assert!(!rendered.contains(&tree.root_hash), "{rendered}");
    }

    #[test]
    fn merkle_commit_updates_root_and_rejects_wrong_new_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated bucket");
        let mut updated_commitments = leaf_commitments;
        updated_commitments[2] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&updated_commitments).unwrap();

        let err = store
            .write_merkle_commit(42, &old_root, 43, &old_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));

        let wrong_new_root = root_hash(99);
        assert_ne!(wrong_new_root, new_root);
        let err = store
            .write_merkle_commit(
                42,
                &old_root,
                43,
                &wrong_new_root,
                4,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("new_root_hash mismatch"));
        assert!(!rendered.contains(&wrong_new_root), "{rendered}");
        assert!(!rendered.contains(&new_root), "{rendered}");

        store
            .write_merkle_commit(42, &old_root, 43, &new_root, 4, &[updated_bucket])
            .unwrap();
        let proof = store
            .read_merkle_path_batch(&[2], 43, &new_root, 4)
            .unwrap();
        assert_eq!(proof.root_hash, new_root);
        assert_eq!(proof.leaves[0].leaf_hash, updated_commitments[2]);

        let err = store
            .write_merkle_commit(42, &old_root, 43, &new_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));
    }

    #[test]
    fn merkle_commit_rejects_duplicate_updated_bucket() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated bucket");
        let mut updated_commitments = leaf_commitments;
        updated_commitments[2] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&updated_commitments).unwrap();

        let err = store
            .write_merkle_commit(
                42,
                &old_root,
                43,
                &new_root,
                4,
                &[updated_bucket.clone(), updated_bucket],
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("repeats a bucket"));
        assert!(!rendered.contains("2"), "{rendered}");
    }

    #[test]
    fn owner_recovery_resumes_from_s0() {
        assert_owner_recovery_resumes_from_phase(PrivateHnswOwnerRecoveryPhaseV1::S0);
    }

    #[test]
    fn owner_recovery_resumes_from_s1_partial_prefix() {
        assert_owner_recovery_resumes_from_phase(PrivateHnswOwnerRecoveryPhaseV1::S1 {
            written_bucket_count: 1,
        });
    }

    #[test]
    fn owner_recovery_resumes_from_s1_full_prefix_before_merkle_publish() {
        assert_owner_recovery_resumes_from_phase(PrivateHnswOwnerRecoveryPhaseV1::S1 {
            written_bucket_count: 2,
        });
    }

    #[test]
    fn owner_recovery_resumes_from_s2() {
        assert_owner_recovery_resumes_from_phase(PrivateHnswOwnerRecoveryPhaseV1::S2);
    }

    #[test]
    fn owner_recovery_resumes_from_s3() {
        assert_owner_recovery_resumes_from_phase(PrivateHnswOwnerRecoveryPhaseV1::S3);
    }

    #[test]
    fn owner_recovery_resumes_idempotently_from_s4() {
        assert_owner_recovery_resumes_from_phase(PrivateHnswOwnerRecoveryPhaseV1::S4);
    }

    #[test]
    fn owner_recovery_publish_steps_require_exact_source_phase() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        let old_tree = fixture.store.read_merkle_tree().unwrap();
        let lock = fixture.store.lock_owner_store_v1().unwrap();
        lock.write_owner_recovery_merkle_tree_v1(fixture.context())
            .unwrap_err();
        assert_eq!(fixture.store.read_merkle_tree().unwrap(), old_tree);

        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        fixture.seed_phase(PrivateHnswOwnerRecoveryPhaseV1::S1 {
            written_bucket_count: fixture.final_buckets.len(),
        });
        let lock = fixture.store.lock_owner_store_v1().unwrap();
        lock.publish_owner_recovery_commit_v1(fixture.context())
            .unwrap_err();
        assert!(matches!(
            fixture
                .store
                .read_epoch_commit(fixture.new_state.index_epoch),
            Err(CollectionError::NotFound { .. })
        ));

        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        fixture.seed_phase(PrivateHnswOwnerRecoveryPhaseV1::S2);
        let old = fixture.store.read_current_epoch().unwrap();
        let lock = fixture.store.lock_owner_store_v1().unwrap();
        lock.publish_owner_recovery_current_v1(fixture.context())
            .unwrap_err();
        assert_eq!(fixture.store.read_current_epoch().unwrap(), old);
    }

    #[test]
    fn owner_recovery_rejects_non_prefix_bucket_progress() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        let second = &fixture.final_buckets[1];
        fixture
            .store
            .write_bucket(
                second,
                fixture.new_state.index_epoch,
                fixture.manifest.bucket_count,
                4096,
            )
            .unwrap();

        let error = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .classify_owner_recovery_state_v1(fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical store state does not match"));
        assert!(!error.contains(&second.ciphertext));
    }

    #[test]
    fn owner_recovery_rejects_wrong_bucket_body_hash_and_commitment() {
        for mutation in 0..3 {
            let temp = TempDir::new().unwrap();
            let fixture = OwnerRecoveryFixture::new(&temp);
            let mut bucket = fixture.final_buckets[0].clone();
            match mutation {
                0 => bucket.ciphertext = fixture.final_buckets[1].ciphertext.clone(),
                1 => bucket.ciphertext_sha256 = root_hash(89),
                2 => bucket.bucket_commitment = root_hash(90),
                _ => unreachable!(),
            }
            write_json_atomic(
                &fixture.store.root,
                &fixture.store.temp_dir(),
                &fixture.store.bucket_path(bucket.bucket_id),
                &bucket,
            )
            .unwrap();

            let error = fixture
                .store
                .lock_owner_store_v1()
                .unwrap()
                .classify_owner_recovery_state_v1(fixture.context())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("ciphertext_sha256 mismatch")
                    || error.contains("commitment context mismatch")
                    || error.contains("newer than requested epoch")
                    || error.contains("canonical store state does not match")
            );
            assert!(!error.contains(&bucket.ciphertext));
            assert!(!error.contains(&bucket.ciphertext_sha256));
            assert!(!error.contains(&bucket.bucket_commitment));
        }
    }

    #[test]
    fn owner_recovery_rejects_wrong_merkle_state() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        fixture.seed_phase(PrivateHnswOwnerRecoveryPhaseV1::S1 {
            written_bucket_count: fixture.final_buckets.len(),
        });
        let mut tree = fixture.store.read_merkle_tree().unwrap();
        tree.index_epoch = fixture.new_state.index_epoch;
        tree.root_hash = fixture.new_state.root_hash.clone();
        write_json_atomic(
            &fixture.store.root,
            &fixture.store.temp_dir(),
            &fixture.store.merkle_nodes_path(),
            &tree,
        )
        .unwrap();

        let error = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .classify_owner_recovery_state_v1(fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("Merkle tree root_hash mismatch"));
        assert!(!error.contains(&fixture.new_state.root_hash));
    }

    #[test]
    fn owner_recovery_rejects_wrong_commit_state() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        fixture.seed_phase(PrivateHnswOwnerRecoveryPhaseV1::S2);
        fixture.write_new_commit(PrivateHnswOramEpochCommit {
            index_epoch: fixture.new_state.index_epoch,
            root_hash: fixture.new_state.root_hash.clone(),
            writeback_digest: Some(root_hash(91)),
        });

        let error = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .classify_owner_recovery_state_v1(fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical store state does not match"));
        assert!(!error.contains(&fixture.new_state.root_hash));
    }

    #[test]
    fn owner_recovery_rejects_invalid_current_transition() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        fixture.seed_phase(PrivateHnswOwnerRecoveryPhaseV1::S2);
        fixture.write_current(&PrivateHnswOramEpochState {
            index_epoch: fixture.new_state.index_epoch,
            root_hash: fixture.new_state.root_hash.clone(),
        });

        let error = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .classify_owner_recovery_state_v1(fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical store state does not match"));
        assert!(!error.contains(&fixture.new_state.root_hash));
    }

    #[test]
    fn owner_recovery_rejects_legacy_pending_writeback() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        write_json_atomic(
            &fixture.store.root,
            &fixture.store.temp_dir(),
            &fixture.store.pending_writeback_path(),
            &serde_json::json!({"legacy": true}),
        )
        .unwrap();

        let error = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .classify_owner_recovery_state_v1(fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("rejects legacy pending writeback"));
    }

    #[test]
    fn owner_store_canonical_digest_binds_historical_epoch_commits() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        let before = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_old(fixture.context())
            .unwrap()
            .canonical_state_digest()
            .to_string();
        let historical_epoch = fixture.old_state.index_epoch - 1;
        write_json_atomic(
            &fixture.store.root,
            &fixture.store.temp_dir(),
            &fixture.store.commit_epoch_path(historical_epoch),
            &PrivateHnswOramEpochCommit {
                index_epoch: historical_epoch,
                root_hash: root_hash(111),
                writeback_digest: Some(root_hash(112)),
            },
        )
        .unwrap();
        let first_history = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_old(fixture.context())
            .unwrap()
            .canonical_state_digest()
            .to_string();
        assert_ne!(before, first_history);

        write_json_atomic(
            &fixture.store.root,
            &fixture.store.temp_dir(),
            &fixture.store.commit_epoch_path(historical_epoch),
            &PrivateHnswOramEpochCommit {
                index_epoch: historical_epoch,
                root_hash: root_hash(113),
                writeback_digest: Some(root_hash(114)),
            },
        )
        .unwrap();
        let replaced_history = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_old(fixture.context())
            .unwrap()
            .canonical_state_digest()
            .to_string();
        assert_ne!(first_history, replaced_history);
    }

    #[test]
    fn owner_store_rejects_excessive_epoch_directory_entries() {
        let temp = TempDir::new().unwrap();
        let fixture = OwnerRecoveryFixture::new(&temp);
        for epoch in 0..MAX_OWNER_EPOCH_DIRECTORY_ENTRIES as u64 {
            write_json_atomic(
                &fixture.store.root,
                &fixture.store.temp_dir(),
                &fixture.store.commit_epoch_path(epoch),
                &PrivateHnswOramEpochCommit {
                    index_epoch: epoch,
                    root_hash: root_hash(120_u8.wrapping_add(epoch as u8)),
                    writeback_digest: Some(root_hash(140_u8.wrapping_add(epoch as u8))),
                },
            )
            .unwrap();
        }

        let error = fixture
            .store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_old(fixture.context())
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical store state does not match"));
    }

    #[test]
    fn owner_store_tokens_require_exact_old_or_exact_new_canonical_state() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new_epoch, _) = fixture_owner_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                4096,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch);
        let final_buckets = vec![updated_bucket.clone()];
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(72);
        let prepared_state_digest = root_hash(73);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );

        let lock = store.lock_owner_store_v1().unwrap();
        let old_token = lock.verify_exact_old(context).unwrap();
        assert_eq!(old_token.index_name(), "text");
        assert_eq!(old_token.canonical_state_digest().len(), 43);
        let old_debug = format!("{old_token:?}");
        assert!(!old_debug.contains("text"));
        assert!(!old_debug.contains(old_token.canonical_state_digest()));
        let old_token_digest = old_token.canonical_state_digest().to_string();
        drop(old_token);
        drop(lock);

        store
            .apply_owner_exact_new_test_fixture_v1(
                &old_state,
                &new_state,
                &final_buckets,
                bundle.bucket_count(),
                4096,
            )
            .unwrap();

        let lock = store.lock_owner_store_v1().unwrap();
        let new_token = lock.verify_exact_new(context).unwrap();
        assert_eq!(new_token.index_name(), "text");
        assert_eq!(new_token.canonical_state_digest().len(), 43);
        assert_ne!(old_token_digest, new_token.canonical_state_digest());
        let new_debug = format!("{new_token:?}");
        assert!(!new_debug.contains("text"));
        assert!(!new_debug.contains(new_token.canonical_state_digest()));
    }

    #[test]
    fn owner_store_exact_old_rejects_legacy_pending_and_concurrent_verifier() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new_epoch, _) = fixture_owner_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                4096,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch);
        let final_buckets = vec![updated_bucket];
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(72);
        let prepared_state_digest = root_hash(73);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );

        let lock = store.lock_owner_store_v1().unwrap();
        let error = store.lock_owner_store_v1().unwrap_err().to_string();
        assert!(error.contains("another private HNSW ORAM owner store operation"));
        drop(lock);

        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.pending_writeback_path(),
            &serde_json::json!({"legacy": true}),
        )
        .unwrap();
        let error = store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_old(context)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rejects legacy pending writeback"));
        assert!(!error.contains(&new_state.root_hash));
        assert!(!error.contains(&final_buckets[0].ciphertext));

        fs::remove_file(store.pending_writeback_path()).unwrap();
        sync_dir(&store.temp_dir()).unwrap();
        let future_root = root_hash(76);
        let future_digest = root_hash(77);
        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.commit_epoch_path(new_state.index_epoch + 1),
            &PrivateHnswOramEpochCommit {
                index_epoch: new_state.index_epoch + 1,
                root_hash: future_root.clone(),
                writeback_digest: Some(future_digest.clone()),
            },
        )
        .unwrap();
        let error = store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_old(context)
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical store state does not match"));
        assert!(!error.contains(&future_root));
        assert!(!error.contains(&future_digest));
    }

    #[test]
    fn owner_store_exact_new_rejects_missing_digest_commit_and_bucket_mismatch() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new_epoch, _) = fixture_owner_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                4096,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch);
        let final_buckets = vec![updated_bucket.clone()];
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(72);
        let prepared_state_digest = root_hash(73);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );

        store
            .write_merkle_commit(
                old_epoch.index_epoch,
                &old_epoch.root_hash,
                new_epoch.index_epoch,
                &new_epoch.root_hash,
                bundle.bucket_count(),
                &final_buckets,
            )
            .unwrap();
        store
            .write_bucket(
                &updated_bucket,
                new_epoch.index_epoch,
                bundle.bucket_count(),
                4096,
            )
            .unwrap();
        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.current_epoch_path(),
            &new_epoch,
        )
        .unwrap();

        let error = store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_new(context)
            .unwrap_err()
            .to_string();
        assert!(error.contains("canonical store state does not match"));

        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.commit_epoch_path(new_epoch.index_epoch),
            &PrivateHnswOramEpochCommit {
                index_epoch: new_epoch.index_epoch,
                root_hash: new_epoch.root_hash.clone(),
                writeback_digest: Some(new_state.last_writeback_digest.clone()),
            },
        )
        .unwrap();
        let mut mismatched_bucket = updated_bucket;
        mismatched_bucket.ciphertext_sha256 = root_hash(75);
        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.bucket_path(mismatched_bucket.bucket_id),
            &mismatched_bucket,
        )
        .unwrap();
        let error = store
            .lock_owner_store_v1()
            .unwrap()
            .verify_exact_new(context)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("ciphertext_sha256 mismatch")
                || error.contains("canonical store state does not match")
        );
        assert!(!error.contains(&final_buckets[0].ciphertext));
        assert!(!error.contains(&final_buckets[0].ciphertext_sha256));
    }
}
