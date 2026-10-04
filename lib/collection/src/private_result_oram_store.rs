#![allow(
    dead_code,
    reason = "D3-B3-B2 owner store tokens remain dormant until the paired adapter is wired"
)]

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
    PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateOramAppendBucketRefV1,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2, PrivateOramImmutableManifestV2,
    PrivateOramIndexKindV2, PrivateOramIndexStateV2, PrivateResultOramBucket,
    PrivateResultOramBucketCommitmentContext, PrivateResultOramBucketValidationContext,
    PrivateResultOramCommitBucketRef, PrivateResultOramCommitSignatureInput,
    PrivateResultOramManifest, PrivateResultOramManifestValidationContext,
    PrivateResultOramMerkleProof, PrivateResultOramMerkleProofLeaf, PrivateResultOramMerkleSibling,
    PrivateResultOramMerkleSiblingPosition, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, PrivateResultOramUploadBundle,
    private_oram_immutable_manifest_v2_digest, private_result_oram_bucket_ciphertext_bytes,
    private_result_oram_bucket_commitment, private_result_oram_bucket_count,
    private_result_oram_writeback_digest, try_private_result_oram_manifest_signature_message,
    validate_private_result_oram_bucket_shape, validate_private_result_oram_commit_signature,
    validate_private_result_oram_manifest, validate_private_result_oram_manifest_shape,
    validate_private_result_oram_upload_bundle,
    validate_private_result_oram_upload_bundle_with_signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::operations::types::{CollectionError, CollectionResult};
use crate::private_oram_owner_store_adapter::PrivateOramOwnerIndexStoreInspectionAuthorityV1;

pub const PRIVATE_RESULT_ORAM_DIR: &str = "private_result_oram";
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
const OWNER_EXACT_OLD_STORE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-result-store-exact-old/v1";
const OWNER_EXACT_NEW_STORE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-result-store-exact-new/v1";
const OWNER_EPOCH_DIRECTORY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-result-epoch-directory/v1";

#[derive(Clone)]
pub struct PrivateResultOramStore {
    root: PathBuf,
}

impl Debug for PrivateResultOramStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramStore")
            .field("root", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramEpochState {
    pub index_epoch: u64,
    pub root_hash: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramLiveReplicationBundle {
    pub manifest: PrivateResultOramManifest,
    pub manifest_signature: PrivateResultOramSignature,
    pub current: PrivateResultOramEpochState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writeback_digest: Option<String>,
    pub buckets: Vec<PrivateResultOramBucket>,
}

impl Debug for PrivateResultOramLiveReplicationBundle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramLiveReplicationBundle")
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
struct PrivateResultOramEpochCommit {
    index_epoch: u64,
    root_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writeback_digest: Option<String>,
}

impl Debug for PrivateResultOramEpochCommit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramEpochCommit")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("has_writeback_digest", &self.writeback_digest.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramConsensusWriteback {
    pub old: PrivateResultOramEpochState,
    pub new: PrivateResultOramEpochState,
    pub writeback_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramWritebackBatch {
    pub version: u16,
    pub old: PrivateResultOramEpochState,
    pub new: PrivateResultOramEpochState,
    pub bucket_count: u64,
    pub updated_buckets: Vec<PrivateResultOramBucket>,
    pub commit_signature: PrivateResultOramSignature,
}

impl Debug for PrivateResultOramWritebackBatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramWritebackBatch")
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

impl Debug for PrivateResultOramConsensusWriteback {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramConsensusWriteback")
            .field("old_epoch", &self.old.index_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_epoch", &self.new.index_epoch)
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateResultOramEpochState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramEpochState")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateResultOramMerkleTree {
    version: u16,
    index_epoch: u64,
    root_hash: String,
    bucket_count: u64,
    leaf_hashes: Vec<String>,
}

impl Debug for PrivateResultOramMerkleTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramMerkleTree")
            .field("version", &self.version)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("leaf_hash_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateResultPendingWriteback {
    version: u16,
    old: PrivateResultOramEpochState,
    new: PrivateResultOramEpochState,
    bucket_count: u64,
    updated_buckets: Vec<PrivateResultOramBucket>,
    merkle_tree: PrivateResultOramMerkleTree,
    commit_signature: PrivateResultOramSignature,
}

impl Debug for PrivateResultPendingWriteback {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultPendingWriteback")
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

// Dormant D3-B3-B2 primitive: this binds canonical logical state plus the
// mutation-affected bucket bodies. It does not prove unrelated bucket
// availability. Keep the minting path module-private until the paired typed
// authority and every V2 writer share the same pinned namespace and lock.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateResultOwnerStoreVerificationContextV1<'a> {
    journal_descriptor_digest: &'a str,
    prepared_state_digest: &'a str,
    immutable_manifest_digest: &'a str,
    immutable_manifest: &'a PrivateOramImmutableManifestV2,
    immutable_index: &'a PrivateOramImmutableIndexV2,
    index_name: &'a str,
    old_state: &'a PrivateOramIndexStateV2,
    new_state: &'a PrivateOramIndexStateV2,
    final_bucket_refs: &'a [PrivateOramAppendBucketRefV1],
    final_buckets: &'a [PrivateResultOramBucket],
    max_ciphertext_bytes: usize,
    manifest_validation: PrivateResultOramManifestValidationContext<'a>,
}

impl Debug for PrivateResultOwnerStoreVerificationContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOwnerStoreVerificationContextV1")
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

pub(crate) struct PrivateResultOwnerExactOldStoreTokenV1<'lock> {
    index_name: String,
    canonical_state_digest: String,
    _lock: PhantomData<&'lock File>,
}

impl Debug for PrivateResultOwnerExactOldStoreTokenV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOwnerExactOldStoreTokenV1")
            .field("index_name", &"[redacted]")
            .field("canonical_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateResultOwnerExactOldStoreTokenV1<'_> {
    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn canonical_state_digest(&self) -> &str {
        &self.canonical_state_digest
    }
}

pub(crate) struct PrivateResultOwnerExactNewStoreTokenV1<'lock> {
    index_name: String,
    canonical_state_digest: String,
    _lock: PhantomData<&'lock File>,
}

impl Debug for PrivateResultOwnerExactNewStoreTokenV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOwnerExactNewStoreTokenV1")
            .field("index_name", &"[redacted]")
            .field("canonical_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateResultOwnerExactNewStoreTokenV1<'_> {
    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn canonical_state_digest(&self) -> &str {
        &self.canonical_state_digest
    }
}

pub(crate) enum PrivateResultOwnerStoreObservationV1<'lock> {
    Old(PrivateResultOwnerExactOldStoreTokenV1<'lock>),
    New(PrivateResultOwnerExactNewStoreTokenV1<'lock>),
    Third,
}

impl Debug for PrivateResultOwnerStoreObservationV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Old(_) => "PrivateResultOwnerStoreObservationV1::Old([redacted])",
            Self::New(_) => "PrivateResultOwnerStoreObservationV1::New([redacted])",
            Self::Third => "PrivateResultOwnerStoreObservationV1::Third",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateResultOwnerRecoveryProgressV1 {
    S0,
    S1 { written_prefix: usize },
    S2,
    S3,
    S4,
}

#[derive(Clone, PartialEq, Eq)]
struct PrivateResultOwnerRecoverySnapshotV1 {
    progress: PrivateResultOwnerRecoveryProgressV1,
    manifest: PrivateResultOramManifest,
    manifest_signature: PrivateResultOramSignature,
    store_manifest_digest: String,
    epoch_directory_digest: String,
    tree: PrivateResultOramMerkleTree,
    old_commit_kind: OwnerStoreCommitKind,
    affected_buckets: Vec<PrivateResultOramBucket>,
}

impl Debug for PrivateResultOwnerRecoverySnapshotV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOwnerRecoverySnapshotV1")
            .field("progress", &self.progress)
            .field("manifest", &"[redacted]")
            .field("manifest_signature", &"[redacted]")
            .field("store_manifest_digest", &"[redacted]")
            .field("epoch_directory_digest", &"[redacted]")
            .field("tree", &self.tree)
            .field("old_commit_kind", &self.old_commit_kind)
            .field("affected_bucket_count", &self.affected_buckets.len())
            .finish()
    }
}

pub(crate) struct PrivateResultOwnerStoreLockV1<'a> {
    store: &'a PrivateResultOramStore,
    directory: File,
}

struct PrivateResultOwnerStoreWriteTokenV1<'a> {
    store: &'a PrivateResultOramStore,
    lock: PrivateResultOwnerStoreLockV1<'a>,
}

impl PrivateResultOwnerStoreWriteTokenV1<'_> {
    fn validate_pinned_root_identity(&self) -> CollectionResult<()> {
        validate_owner_store_directory_identity(&self.lock.directory, &self.store.root)
    }
}

impl Debug for PrivateResultOwnerStoreLockV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOwnerStoreLockV1")
            .field("store", &self.store)
            .field("directory", &"[redacted]")
            .finish()
    }
}

impl Drop for PrivateResultOwnerStoreLockV1<'_> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitialEpochStatus {
    Absent,
    Matching,
}

impl PrivateResultOramStore {
    pub fn new(collection_path: impl AsRef<Path>) -> Self {
        Self {
            root: collection_path.as_ref().join(PRIVATE_RESULT_ORAM_DIR),
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    fn lock_owner_store_v1(&self) -> CollectionResult<PrivateResultOwnerStoreLockV1<'_>> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(CollectionError::service_error(
                "private result ORAM owner store verification is unsupported on this platform",
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
                        "failed to open private result ORAM owner store root",
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
                        "another private result ORAM owner store operation is active",
                    ))
                } else {
                    Err(CollectionError::service_error(
                        "failed to lock private result ORAM owner store",
                    ))
                };
            }
            if let Err(error) = validate_owner_store_directory_identity(&directory, &self.root) {
                let _ = unsafe { nix::libc::flock(directory.as_raw_fd(), nix::libc::LOCK_UN) };
                return Err(error);
            }
            Ok(PrivateResultOwnerStoreLockV1 {
                store: self,
                directory,
            })
        }
    }

    pub(crate) fn with_owner_store_lock_v1<R>(
        &self,
        action: impl for<'lock> FnOnce(&'lock PrivateResultOwnerStoreLockV1<'_>) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        let lock = self.lock_owner_store_v1()?;
        let output = action(&lock);
        validate_owner_store_directory_identity(&lock.directory, &self.root)?;
        output
    }

    fn with_canonical_writer_lock_v1<R>(
        &self,
        action: impl for<'lock> FnOnce(
            &'lock PrivateResultOwnerStoreWriteTokenV1<'_>,
        ) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = action;
            return Err(CollectionError::service_error(
                "private result ORAM canonical writes are unsupported on this platform",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            // The root is the lock inode. Its idempotent bootstrap must happen before
            // opening and pinning that inode; every mutation after bootstrap is locked.
            create_private_dir(&self.root)?;
            let token = PrivateResultOwnerStoreWriteTokenV1 {
                store: self,
                lock: self.lock_owner_store_v1()?,
            };

            let output = action(&token);
            token.validate_pinned_root_identity()?;
            output
        }
    }

    pub(crate) fn with_owner_exact_old_store_v1<R>(
        &self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateResultOramManifestValidationContext<'_>,
        action: impl for<'lock> FnOnce(
            PrivateResultOwnerExactOldStoreTokenV1<'lock>,
        ) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        let final_buckets = authority
            .result_final_buckets()
            .ok_or_else(owner_store_state_mismatch)?;
        self.with_owner_store_lock_v1(|lock| {
            let token = lock.verify_exact_old(PrivateResultOwnerStoreVerificationContextV1 {
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
        manifest_validation: PrivateResultOramManifestValidationContext<'_>,
        action: impl for<'lock> FnOnce(
            PrivateResultOwnerExactNewStoreTokenV1<'lock>,
        ) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        let final_buckets = authority
            .result_final_buckets()
            .ok_or_else(owner_store_state_mismatch)?;
        self.with_owner_store_lock_v1(|lock| {
            let token = lock.verify_exact_new(PrivateResultOwnerStoreVerificationContextV1 {
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
        final_buckets: &[PrivateResultOramBucket],
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        let old_epoch = PrivateResultOramEpochState {
            index_epoch: old.index_epoch,
            root_hash: old.root_hash.clone(),
        };
        let new_epoch = PrivateResultOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: new.root_hash.clone(),
        };
        self.with_canonical_writer_lock_v1(|token| {
            let tree = self.prepare_merkle_tree_under_owner_lock(
                token,
                old.index_epoch,
                &old.root_hash,
                new.index_epoch,
                &new.root_hash,
                bucket_count,
                final_buckets,
            )?;
            for bucket in final_buckets {
                self.write_bucket_under_owner_lock(
                    token,
                    bucket,
                    new.index_epoch,
                    bucket_count,
                    max_ciphertext_bytes,
                )?;
            }
            self.write_merkle_tree_under_owner_lock(token, &tree)?;
            self.compare_and_swap_epoch_under_owner_lock(
                token,
                &old_epoch,
                &new_epoch,
                Some(&new.last_writeback_digest),
            )
        })
    }

    pub fn ensure_layout(&self) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| self.ensure_layout_under_owner_lock(token))
    }

    fn ensure_layout_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
    ) -> CollectionResult<()> {
        if !std::ptr::eq(self, token.store) {
            return Err(CollectionError::service_error(
                "private result ORAM owner store writer token mismatch",
            ));
        }
        create_private_dir(&self.buckets_dir())?;
        create_private_dir(&self.epochs_dir())?;
        create_private_dir(&self.merkle_dir())?;
        create_private_dir(&self.temp_dir())?;
        Ok(())
    }

    pub fn write_manifest(
        &self,
        manifest: &PrivateResultOramManifest,
        signature: &PrivateResultOramSignature,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_manifest_under_owner_lock(token, manifest, signature)
        })
    }

    fn write_manifest_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        manifest: &PrivateResultOramManifest,
        signature: &PrivateResultOramSignature,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        write_json_atomic_with_limit(
            &self.root,
            &self.temp_dir(),
            &self.manifest_path(),
            manifest,
            MAX_MANIFEST_BYTES,
        )?;
        write_json_atomic_with_limit(
            &self.root,
            &self.temp_dir(),
            &self.manifest_signature_path(),
            signature,
            MAX_SIGNATURE_BYTES,
        )
    }

    pub fn read_manifest(
        &self,
    ) -> CollectionResult<(PrivateResultOramManifest, PrivateResultOramSignature)> {
        validate_private_dir(&self.root)?;
        let manifest = read_json_private_file(&self.manifest_path(), MAX_MANIFEST_BYTES)?;
        let signature =
            read_json_private_file(&self.manifest_signature_path(), MAX_SIGNATURE_BYTES)?;
        Ok((manifest, signature))
    }

    pub fn write_initial_upload_bundle(
        &self,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        validate_upload_bundle(bundle, max_ciphertext_bytes)?;
        self.with_canonical_writer_lock_v1(|token| {
            self.write_initial_upload_bundle_under_owner_lock(token, bundle, max_ciphertext_bytes)
        })
    }

    fn write_initial_upload_bundle_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.ensure_layout_under_owner_lock(token)?;
        let leaf_commitments = validate_upload_bundle(bundle, max_ciphertext_bytes)?;
        self.ensure_no_pending_initial_replication()?;
        let epoch = PrivateResultOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };

        match self.initial_epoch_status_under_owner_lock(token, &epoch)? {
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
        self.write_manifest_under_owner_lock(token, &bundle.manifest, &bundle.manifest_signature)?;
        self.write_merkle_tree_from_commitments_under_owner_lock(
            token,
            bundle.manifest.index_epoch,
            bundle.manifest.root_hash.clone(),
            leaf_commitments,
        )?;
        for bucket in &bundle.buckets {
            self.write_bucket_under_owner_lock(
                token,
                bucket,
                bundle.manifest.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_initial_epoch_if_absent_or_matching_under_owner_lock(token, &epoch)?;
        Ok(epoch)
    }

    pub fn write_initial_upload_bundle_with_signature(
        &self,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateResultOramManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        validate_upload_bundle_with_signature(bundle, max_ciphertext_bytes, validation_context)?;
        self.with_canonical_writer_lock_v1(|token| {
            self.write_initial_upload_bundle_under_owner_lock(token, bundle, max_ciphertext_bytes)
        })
    }

    pub fn read_initial_upload_bundle(
        &self,
        max_ciphertext_bytes: usize,
        max_bundle_bytes: usize,
    ) -> CollectionResult<PrivateResultOramUploadBundle> {
        let (manifest, manifest_signature) = self.read_manifest()?;
        self.ensure_no_pending_initial_replication()?;
        let expected_bucket_count = private_result_oram_bucket_count(manifest.oram.tree_height)
            .map_err(private_result_oram_error)?;
        if manifest.bucket_count != expected_bucket_count || expected_bucket_count == 0 {
            return Err(CollectionError::bad_request(
                "private result ORAM initial replication manifest bucket_count is invalid",
            ));
        }
        let expected_epoch = PrivateResultOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };
        if self.read_current_epoch()? != expected_epoch {
            return Err(CollectionError::bad_request(
                "private result ORAM initial replication requires the manifest epoch",
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
            "private result ORAM initial replication bundle is oversized",
        )?;
        let capacity = usize::try_from(manifest.bucket_count).map_err(|_| {
            CollectionError::bad_request(
                "private result ORAM initial replication bucket_count is invalid",
            )
        })?;
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(capacity).map_err(|_| {
            CollectionError::service_error(
                "private result ORAM initial replication allocation failed",
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
        let bundle = PrivateResultOramUploadBundle {
            manifest,
            manifest_signature,
            buckets,
        };
        let commitments = validate_upload_bundle(&bundle, max_ciphertext_bytes)?;
        let tree = self.read_merkle_tree()?;
        if tree.leaf_hashes != commitments {
            return Err(CollectionError::bad_request(
                "private result ORAM initial replication Merkle state does not match",
            ));
        }
        Ok(bundle)
    }

    pub fn read_live_replication_bundle(
        &self,
        max_ciphertext_bytes: usize,
        max_bundle_bytes: usize,
    ) -> CollectionResult<PrivateResultOramLiveReplicationBundle> {
        let (manifest, manifest_signature) = self.read_manifest()?;
        validate_private_result_oram_manifest_shape(&manifest)
            .map_err(private_result_oram_error)?;
        self.ensure_no_pending_live_replication()?;
        let current = self.read_current_epoch()?;
        let writeback_digest = self.live_writeback_digest(&manifest, &current)?;
        let buckets = self.read_live_replication_buckets(
            &manifest,
            &current,
            max_ciphertext_bytes,
            max_bundle_bytes,
        )?;
        let bundle = PrivateResultOramLiveReplicationBundle {
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
                "private result ORAM live replication Merkle state does not match",
            ));
        }
        Ok(bundle)
    }

    pub fn write_live_replication_bundle_with_signature(
        &self,
        bundle: &PrivateResultOramLiveReplicationBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateResultOramManifestValidationContext<'_>,
        expected_current: &PrivateResultOramEpochState,
        expected_writeback_digest: Option<&str>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        validate_private_result_oram_manifest(
            &bundle.manifest,
            Some(&bundle.manifest_signature),
            validation_context,
        )
        .map_err(private_result_oram_error)?;
        if bundle.current != *expected_current
            || bundle.writeback_digest.as_deref() != expected_writeback_digest
        {
            return Err(CollectionError::bad_request(
                "private result ORAM live replication bundle does not match consensus",
            ));
        }
        validate_live_replication_bundle(bundle, max_ciphertext_bytes)?;
        self.with_canonical_writer_lock_v1(|token| {
            self.write_live_replication_bundle_with_signature_under_owner_lock(
                token,
                bundle,
                max_ciphertext_bytes,
                validation_context,
                expected_current,
                expected_writeback_digest,
            )
        })
    }

    fn write_live_replication_bundle_with_signature_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        bundle: &PrivateResultOramLiveReplicationBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateResultOramManifestValidationContext<'_>,
        expected_current: &PrivateResultOramEpochState,
        expected_writeback_digest: Option<&str>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.ensure_layout_under_owner_lock(token)?;
        validate_private_result_oram_manifest(
            &bundle.manifest,
            Some(&bundle.manifest_signature),
            validation_context,
        )
        .map_err(private_result_oram_error)?;
        if bundle.current != *expected_current
            || bundle.writeback_digest.as_deref() != expected_writeback_digest
        {
            return Err(CollectionError::bad_request(
                "private result ORAM live replication bundle does not match consensus",
            ));
        }
        let commitments = validate_live_replication_bundle(bundle, max_ciphertext_bytes)?;
        self.ensure_no_pending_live_replication()?;

        match self.read_current_epoch() {
            Ok(current) if current == bundle.current => {
                let stored = self.read_live_replication_bundle(max_ciphertext_bytes, usize::MAX)?;
                if stored != *bundle {
                    return Err(CollectionError::bad_request(
                        "private result ORAM live replication bundle does not match existing store",
                    ));
                }
                return Ok(current);
            }
            Ok(_) => {
                return Err(CollectionError::bad_request(
                    "private result ORAM live replication cannot replace current state",
                ));
            }
            Err(CollectionError::NotFound { .. }) => {}
            Err(err) => return Err(err),
        }

        self.write_manifest_under_owner_lock(token, &bundle.manifest, &bundle.manifest_signature)?;
        self.write_merkle_tree_from_commitments_under_owner_lock(
            token,
            bundle.current.index_epoch,
            bundle.current.root_hash.clone(),
            commitments,
        )?;
        for bucket in &bundle.buckets {
            self.write_bucket_under_owner_lock(
                token,
                bucket,
                bucket.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_live_epoch_under_owner_lock(
            token,
            &bundle.current,
            bundle.writeback_digest.as_deref(),
        )?;

        let stored = self.read_live_replication_bundle(max_ciphertext_bytes, usize::MAX)?;
        if stored != *bundle {
            return Err(CollectionError::service_error(
                "private result ORAM live replication final state validation failed",
            ));
        }
        Ok(bundle.current.clone())
    }

    fn ensure_no_pending_live_replication(&self) -> CollectionResult<()> {
        if self.pending_writeback_exists()? {
            return Err(CollectionError::bad_request(
                "private result ORAM live replication requires no pending writeback",
            ));
        }
        Ok(())
    }

    fn live_writeback_digest(
        &self,
        manifest: &PrivateResultOramManifest,
        current: &PrivateResultOramEpochState,
    ) -> CollectionResult<Option<String>> {
        match self.read_epoch_commit(current.index_epoch) {
            Ok(commit) if commit.root_hash == current.root_hash => commit
                .writeback_digest
                .ok_or_else(|| {
                    CollectionError::bad_request(
                        "private result ORAM live replication current commit has no consensus digest",
                    )
                })
                .map(Some),
            Ok(_) => Err(CollectionError::bad_request(
                "private result ORAM live replication commit does not match current state",
            )),
            Err(CollectionError::NotFound { .. })
                if current.index_epoch == manifest.index_epoch
                    && current.root_hash == manifest.root_hash =>
            {
                Ok(None)
            }
            Err(CollectionError::NotFound { .. }) => Err(CollectionError::bad_request(
                "private result ORAM live replication current commit is missing",
            )),
            Err(err) => Err(err),
        }
    }

    fn read_live_replication_buckets(
        &self,
        manifest: &PrivateResultOramManifest,
        current: &PrivateResultOramEpochState,
        max_ciphertext_bytes: usize,
        max_bundle_bytes: usize,
    ) -> CollectionResult<Vec<PrivateResultOramBucket>> {
        if manifest.bucket_count == 0 {
            return Err(CollectionError::bad_request(
                "private result ORAM live replication bucket_count is invalid",
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
            "private result ORAM live replication bundle is oversized",
        )?;
        let capacity = usize::try_from(manifest.bucket_count).map_err(|_| {
            CollectionError::bad_request(
                "private result ORAM live replication bucket_count is invalid",
            )
        })?;
        let mut buckets = Vec::new();
        buckets.try_reserve_exact(capacity).map_err(|_| {
            CollectionError::service_error("private result ORAM live replication allocation failed")
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
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        current: &PrivateResultOramEpochState,
        writeback_digest: Option<&str>,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        validate_epoch_state(current)?;
        if let Some(writeback_digest) = writeback_digest {
            validate_writeback_digest(writeback_digest)?;
            write_json_atomic(
                &self.root,
                &self.temp_dir(),
                &self.commit_epoch_path(current.index_epoch),
                &PrivateResultOramEpochCommit {
                    index_epoch: current.index_epoch,
                    root_hash: current.root_hash.clone(),
                    writeback_digest: Some(writeback_digest.to_string()),
                },
            )?;
        }
        self.write_initial_epoch_under_owner_lock(token, current)
    }

    fn ensure_no_pending_initial_replication(&self) -> CollectionResult<()> {
        if self.pending_writeback_exists()? {
            return Err(CollectionError::bad_request(
                "private result ORAM initial replication requires no pending writeback",
            ));
        }
        Ok(())
    }

    fn initial_epoch_status_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<InitialEpochStatus> {
        self.ensure_layout_under_owner_lock(token)?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(InitialEpochStatus::Matching),
            Ok(_) => Err(CollectionError::bad_request(
                "private result ORAM current epoch/root does not match initial epoch",
            )),
            Err(CollectionError::NotFound { .. }) => Ok(InitialEpochStatus::Absent),
            Err(err) => Err(err),
        }
    }

    fn validate_existing_initial_upload_bundle(
        &self,
        bundle: &PrivateResultOramUploadBundle,
        leaf_commitments: &[String],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        let (stored_manifest, stored_signature) = self.read_manifest()?;
        if stored_manifest != bundle.manifest || stored_signature != bundle.manifest_signature {
            return Err(CollectionError::bad_request(
                "private result ORAM initial upload bundle does not match existing manifest",
            ));
        }

        let stored_tree = self.read_merkle_tree()?;
        if stored_tree.index_epoch != bundle.manifest.index_epoch
            || stored_tree.root_hash != bundle.manifest.root_hash
            || stored_tree.bucket_count != bundle.manifest.bucket_count
            || stored_tree.leaf_hashes.as_slice() != leaf_commitments
        {
            return Err(CollectionError::bad_request(
                "private result ORAM initial upload bundle does not match existing Merkle tree",
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
                    "private result ORAM initial upload bundle does not match existing bucket set",
                ));
            }
        }
        Ok(())
    }

    pub fn write_bucket(
        &self,
        bucket: &PrivateResultOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_bucket_under_owner_lock(
                token,
                bucket,
                expected_epoch,
                bucket_count,
                max_ciphertext_bytes,
            )
        })
    }

    fn write_bucket_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        bucket: &PrivateResultOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
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
        bucket: &PrivateResultOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        validate_bucket(bucket, expected_epoch, bucket_count, max_ciphertext_bytes)
    }

    pub fn write_bucket_upload_bundle(
        &self,
        expected_current: &PrivateResultOramEpochState,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_bucket_upload_bundle_under_owner_lock(
                token,
                expected_current,
                bundle,
                max_ciphertext_bytes,
            )
        })
    }

    fn write_bucket_upload_bundle_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        expected_current: &PrivateResultOramEpochState,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        validate_epoch_state(expected_current)?;
        if self.read_current_epoch()? != *expected_current {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket upload epoch/root does not match current manifest epoch",
            ));
        }

        let (stored_manifest, stored_signature) = self.read_manifest()?;
        if stored_manifest != bundle.manifest || stored_signature != bundle.manifest_signature {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket upload does not match current manifest",
            ));
        }
        if bundle.manifest.index_epoch != expected_current.index_epoch
            || bundle.manifest.root_hash != expected_current.root_hash
        {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket upload epoch/root does not match current manifest epoch",
            ));
        }

        // Complete preflight happens before the first canonical write. The bundle
        // validator enforces exact bucket count, ascending IDs, hashes, fixed
        // ciphertext size, commitments, and the final Merkle root.
        let leaf_commitments = validate_upload_bundle(bundle, max_ciphertext_bytes)?;
        for bucket in &bundle.buckets {
            validate_bucket_ciphertext_fixed_size(bucket, &bundle.manifest)?;
        }
        validate_bucket_commitment_context(
            &bundle.manifest,
            expected_current.index_epoch,
            &bundle.buckets,
        )?;
        let tree = PrivateResultOramMerkleTree {
            version: 1,
            index_epoch: expected_current.index_epoch,
            root_hash: expected_current.root_hash.clone(),
            bucket_count: bundle.manifest.bucket_count,
            leaf_hashes: leaf_commitments,
        };
        validate_merkle_tree_context(
            &tree,
            expected_current.index_epoch,
            &expected_current.root_hash,
            bundle.manifest.bucket_count,
        )?;

        self.ensure_layout_under_owner_lock(token)?;
        for bucket in &bundle.buckets {
            self.write_bucket_under_owner_lock(
                token,
                bucket,
                expected_current.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_merkle_tree_under_owner_lock(token, &tree)?;
        Ok(expected_current.clone())
    }

    pub fn read_bucket(
        &self,
        bucket_id: u64,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramBucket> {
        validate_private_dir(&self.buckets_dir())?;
        let max_bucket_file_bytes = max_bucket_file_bytes(max_ciphertext_bytes)?;
        let bucket: PrivateResultOramBucket =
            read_json_private_file(&self.bucket_path(bucket_id), max_bucket_file_bytes)?;
        if bucket.bucket_id != bucket_id {
            return Err(CollectionError::service_error(
                "private result ORAM bucket file id mismatch",
            ));
        }
        validate_bucket_for_read(&bucket, expected_epoch, bucket_count, max_ciphertext_bytes)?;
        Ok(bucket)
    }

    pub fn write_initial_epoch(&self, epoch: &PrivateResultOramEpochState) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_initial_epoch_under_owner_lock(token, epoch)
        })
    }

    fn write_initial_epoch_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        validate_epoch_state(epoch)?;
        let current_path = self.current_epoch_path();
        if current_path.exists() {
            return Err(CollectionError::bad_request(
                "private result ORAM current epoch already exists",
            ));
        }
        write_json_atomic(&self.root, &self.temp_dir(), &current_path, epoch)
    }

    pub fn write_initial_epoch_if_absent_or_matching(
        &self,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_initial_epoch_if_absent_or_matching_under_owner_lock(token, epoch)
        })
    }

    fn write_initial_epoch_if_absent_or_matching_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(()),
            Ok(_) => Err(CollectionError::bad_request(
                "private result ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => {
                self.write_initial_epoch_under_owner_lock(token, epoch)
            }
            Err(err) => Err(err),
        }
    }

    pub fn write_manifest_with_initial_epoch_if_absent_or_matching(
        &self,
        manifest: &PrivateResultOramManifest,
        signature: &PrivateResultOramSignature,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_manifest_with_initial_epoch_if_absent_or_matching_under_owner_lock(
                token, manifest, signature, epoch,
            )
        })
    }

    fn write_manifest_with_initial_epoch_if_absent_or_matching_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        manifest: &PrivateResultOramManifest,
        signature: &PrivateResultOramSignature,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => match self.read_manifest() {
                Ok((stored_manifest, stored_signature))
                    if stored_manifest.index_epoch == current.index_epoch
                        && stored_manifest.root_hash == current.root_hash =>
                {
                    if stored_manifest != *manifest || stored_signature != *signature {
                        return Err(CollectionError::bad_request(
                            "private result ORAM manifest upload does not match existing current manifest",
                        ));
                    }
                    Ok(())
                }
                Ok((stored_manifest, _)) => {
                    // A post-commit refresh may only move the fields a commit legitimately
                    // changes; everything else (identifiers, key metadata including rk_epoch,
                    // layout, bucket count) is the commitment context of every stored bucket.
                    if !manifest_refresh_preserves_immutable_fields(&stored_manifest, manifest) {
                        return Err(CollectionError::bad_request(
                            "private result ORAM manifest refresh changes fields other than epoch, root and result counts",
                        ));
                    }
                    self.write_manifest_under_owner_lock(token, manifest, signature)
                }
                Err(CollectionError::NotFound { .. }) => {
                    self.write_manifest_under_owner_lock(token, manifest, signature)
                }
                Err(err) => Err(err),
            },
            Ok(_) => Err(CollectionError::bad_request(
                "private result ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => {
                self.write_manifest_under_owner_lock(token, manifest, signature)?;
                self.write_initial_epoch_under_owner_lock(token, epoch)
            }
            Err(err) => Err(err),
        }
    }

    pub fn read_current_epoch(&self) -> CollectionResult<PrivateResultOramEpochState> {
        validate_private_dir(&self.epochs_dir())?;
        let epoch = read_json_private_file(&self.current_epoch_path(), MAX_EPOCH_BYTES)?;
        validate_epoch_state(&epoch)?;
        Ok(epoch)
    }

    pub fn compare_and_swap_epoch(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.compare_and_swap_epoch_under_owner_lock(token, old, new, None)
        })
    }

    fn compare_and_swap_epoch_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        writeback_digest: Option<&str>,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        validate_epoch_state(old)?;
        validate_epoch_state(new)?;
        if let Some(writeback_digest) = writeback_digest {
            validate_writeback_digest(writeback_digest)?;
        }
        if Some(new.index_epoch) != old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private result ORAM new epoch must be exactly old epoch + 1",
            ));
        }

        let current = self.read_current_epoch()?;
        if &current != old {
            return Err(CollectionError::bad_request(
                "private result ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
        }

        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.commit_epoch_path(new.index_epoch),
            &PrivateResultOramEpochCommit {
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
                log::warn!("failed to prune private result ORAM epoch commit history: {error}");
                return;
            }
        }
    }

    pub fn commit_writeback(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.with_canonical_writer_lock_v1(|token| {
            self.commit_writeback_under_owner_lock(
                token,
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
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.ensure_layout_under_owner_lock(token)?;
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM commit must update at least one bucket",
            ));
        }
        if Some(new.index_epoch) != old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private result ORAM commit new epoch must be exactly old epoch + 1",
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
        let merkle_tree = self.prepare_merkle_tree_under_owner_lock(
            token,
            old.index_epoch,
            &old.root_hash,
            new.index_epoch,
            &new.root_hash,
            bucket_count,
            updated_buckets,
        )?;
        for bucket in updated_buckets {
            self.write_bucket_under_owner_lock(
                token,
                bucket,
                new.index_epoch,
                bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_merkle_tree_under_owner_lock(token, &merkle_tree)?;
        self.compare_and_swap_epoch_under_owner_lock(token, old, new, None)?;
        Ok(new.clone())
    }

    pub fn commit_writeback_with_signature(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateResultOramSignature,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        let PrivateResultOramSignatureVerification {
            expected_key_id,
            public_key,
        } = signature_verification;
        self.with_canonical_writer_lock_v1(|token| {
            self.prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
                token,
                old,
                new,
                bucket_count,
                updated_buckets,
                max_ciphertext_bytes,
                commit_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id,
                    public_key,
                },
                None,
            )?;
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                token,
                max_ciphertext_bytes,
                PrivateResultOramSignatureVerification {
                    expected_key_id,
                    public_key,
                },
                None,
            )
        })
    }

    pub fn prepare_durable_writeback_with_signature(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateResultOramSignature,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramConsensusWriteback> {
        self.with_canonical_writer_lock_v1(|token| {
            self.prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
                token,
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
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateResultOramSignature,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
        expected_consensus_writeback: Option<&PrivateResultOramConsensusWriteback>,
    ) -> CollectionResult<PrivateResultOramConsensusWriteback> {
        self.ensure_layout_under_owner_lock(token)?;
        let pending_path = self.pending_writeback_path();
        if pending_path.exists() {
            let pending: PrivateResultPendingWriteback =
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
                    "private result ORAM pending writeback does not match requested commit",
                ));
            }
            if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback)
            {
                return Err(CollectionError::bad_request(
                    "private result ORAM replicated writeback does not match consensus",
                ));
            }
            return Ok(consensus_writeback);
        }

        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM commit must update at least one bucket",
            ));
        }
        if Some(new.index_epoch) != old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private result ORAM commit new epoch must be exactly old epoch + 1",
            ));
        }
        let (manifest, _) = self.read_manifest()?;
        validate_fixed_writeback_budget(&manifest, updated_buckets.len())?;
        let updated_bucket_refs = updated_buckets
            .iter()
            .map(|bucket| PrivateResultOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        let signature_input = PrivateResultOramCommitSignatureInput {
            collection_id: &manifest.collection_id,
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
        validate_private_result_oram_commit_signature(
            signature_input,
            &commit_signature.sig,
            signature_verification,
        )
        .map_err(private_result_oram_error)?;
        let writeback_digest = private_result_oram_writeback_digest(signature_input)
            .map_err(private_result_oram_error)?;
        let consensus_writeback = PrivateResultOramConsensusWriteback {
            old: old.clone(),
            new: new.clone(),
            writeback_digest,
        };
        if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback) {
            return Err(CollectionError::bad_request(
                "private result ORAM replicated writeback does not match consensus",
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
                        "private result ORAM applied replicated writeback does not match",
                    ));
                }
            }
            return Ok(consensus_writeback);
        }
        if current != *old {
            return Err(CollectionError::bad_request(
                "private result ORAM current epoch/root does not match expected state",
            ));
        }
        let merkle_tree = self.prepare_merkle_tree_under_owner_lock(
            token,
            old.index_epoch,
            &old.root_hash,
            new.index_epoch,
            &new.root_hash,
            bucket_count,
            updated_buckets,
        )?;
        let pending = PrivateResultPendingWriteback {
            version: 1,
            old: old.clone(),
            new: new.clone(),
            bucket_count,
            updated_buckets: updated_buckets.to_vec(),
            merkle_tree,
            commit_signature: commit_signature.clone(),
        };
        // Every reader of the pending record enforces this cap; writing a larger one would
        // leave a prepared write-back that commit, recover and abort can no longer read.
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
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.with_canonical_writer_lock_v1(|token| {
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                token,
                max_ciphertext_bytes,
                signature_verification,
                None,
            )
        })
    }

    pub fn commit_replica_writeback_with_signature(
        &self,
        expected_consensus_writeback: &PrivateResultOramConsensusWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.with_canonical_writer_lock_v1(|token| {
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                token,
                max_ciphertext_bytes,
                signature_verification,
                Some(expected_consensus_writeback),
            )
        })
    }

    fn commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
        expected_consensus_writeback: Option<&PrivateResultOramConsensusWriteback>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.ensure_layout_under_owner_lock(token)?;
        let pending: PrivateResultPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        let consensus_writeback = self.validate_pending_writeback(
            &pending,
            max_ciphertext_bytes,
            signature_verification,
        )?;
        if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback) {
            return Err(CollectionError::bad_request(
                "private result ORAM pending writeback consensus transition does not match",
            ));
        }

        let current = self.read_current_epoch()?;
        if current != pending.old && current != pending.new {
            return Err(CollectionError::bad_request(
                "private result ORAM pending writeback epoch/root does not match current state",
            ));
        }
        for bucket in &pending.updated_buckets {
            self.write_bucket_under_owner_lock(
                token,
                bucket,
                pending.new.index_epoch,
                pending.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_merkle_tree_under_owner_lock(token, &pending.merkle_tree)?;
        if current == pending.old {
            self.compare_and_swap_epoch_under_owner_lock(
                token,
                &pending.old,
                &pending.new,
                Some(&consensus_writeback.writeback_digest),
            )?;
        }

        if self.read_current_epoch()? != pending.new
            || self.read_merkle_tree()? != pending.merkle_tree
        {
            return Err(CollectionError::service_error(
                "private result ORAM pending writeback final state validation failed",
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
                    "private result ORAM pending writeback final state validation failed",
                ));
            }
        }
        self.write_completed_writeback_record_under_owner_lock(token, &consensus_writeback)?;
        self.remove_pending_writeback_record_under_owner_lock(token)?;
        Ok(pending.new)
    }

    pub fn completed_replica_writeback_matches(
        &self,
        expected: &PrivateResultOramConsensusWriteback,
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
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        expected: &PrivateResultOramConsensusWriteback,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        validate_writeback_digest(&expected.writeback_digest)?;
        let completed = PrivateResultOramEpochCommit {
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
                    "private result ORAM completed writeback record does not match",
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
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        remove_private_file(
            &self.pending_writeback_path(),
            &self.temp_dir(),
            MAX_PENDING_WRITEBACK_BYTES,
        )
    }

    fn read_epoch_commit(&self, epoch: u64) -> CollectionResult<PrivateResultOramEpochCommit> {
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
                "failed to inspect private result ORAM pending writeback",
            )),
        }
    }

    pub fn pending_writeback_consensus_transition_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<Option<PrivateResultOramConsensusWriteback>> {
        if !self.pending_writeback_exists()? {
            return Ok(None);
        }
        let pending: PrivateResultPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        self.validate_pending_writeback(&pending, max_ciphertext_bytes, signature_verification)
            .map(Some)
    }

    pub fn pending_writeback_replication_batch_with_signature(
        &self,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<
        Option<(
            PrivateResultOramWritebackBatch,
            PrivateResultOramConsensusWriteback,
        )>,
    > {
        if !self.pending_writeback_exists()? {
            return Ok(None);
        }
        let pending: PrivateResultPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        let consensus_writeback = self.validate_pending_writeback(
            &pending,
            max_ciphertext_bytes,
            signature_verification,
        )?;
        Ok(Some((
            PrivateResultOramWritebackBatch {
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
        batch: &PrivateResultOramWritebackBatch,
        expected_consensus_writeback: &PrivateResultOramConsensusWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramConsensusWriteback> {
        if batch.version != 1 {
            return Err(CollectionError::bad_request(
                "private result ORAM replicated writeback is invalid",
            ));
        }
        self.with_canonical_writer_lock_v1(|token| {
            self.prepare_durable_writeback_with_signature_and_consensus_under_owner_lock(
                token,
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
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<Option<PrivateResultOramEpochState>> {
        self.with_canonical_writer_lock_v1(|token| {
            if !self.pending_writeback_exists()? {
                return Ok(None);
            }
            self.commit_prepared_writeback_with_signature_and_consensus_under_owner_lock(
                token,
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
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<bool> {
        self.with_canonical_writer_lock_v1(|token| {
            self.abort_pending_writeback_with_signature_and_consensus_under_owner_lock(
                token,
                max_ciphertext_bytes,
                signature_verification,
                None,
            )
        })
    }

    pub fn abort_replica_writeback_with_signature(
        &self,
        expected_consensus_writeback: &PrivateResultOramConsensusWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<bool> {
        self.with_canonical_writer_lock_v1(|token| {
            self.abort_pending_writeback_with_signature_and_consensus_under_owner_lock(
                token,
                max_ciphertext_bytes,
                signature_verification,
                Some(expected_consensus_writeback),
            )
        })
    }

    fn abort_pending_writeback_with_signature_and_consensus_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
        expected_consensus_writeback: Option<&PrivateResultOramConsensusWriteback>,
    ) -> CollectionResult<bool> {
        self.ensure_layout_under_owner_lock(token)?;
        if !self.pending_writeback_exists()? {
            return Ok(false);
        }
        let pending: PrivateResultPendingWriteback =
            read_json_private_file(&self.pending_writeback_path(), MAX_PENDING_WRITEBACK_BYTES)?;
        let consensus_writeback = self.validate_pending_writeback(
            &pending,
            max_ciphertext_bytes,
            signature_verification,
        )?;
        if expected_consensus_writeback.is_some_and(|expected| expected != &consensus_writeback) {
            return Err(CollectionError::bad_request(
                "private result ORAM pending writeback consensus transition does not match",
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
                CollectionError::bad_request("private result ORAM pending writeback is invalid")
            })?;
            if old_tree.leaf_hashes.get(bucket_index) != Some(&stored_bucket.bucket_commitment) {
                return Err(CollectionError::bad_request(
                    "private result ORAM pending writeback abort state is invalid",
                ));
            }
        }
        self.remove_pending_writeback_record_under_owner_lock(token)?;
        Ok(true)
    }

    fn validate_pending_writeback(
        &self,
        pending: &PrivateResultPendingWriteback,
        max_ciphertext_bytes: usize,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramConsensusWriteback> {
        if pending.version != 1 || pending.updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM pending writeback is invalid",
            ));
        }
        validate_epoch_state(&pending.old)?;
        validate_epoch_state(&pending.new)?;
        if Some(pending.new.index_epoch) != pending.old.index_epoch.checked_add(1) {
            return Err(CollectionError::bad_request(
                "private result ORAM pending writeback is invalid",
            ));
        }

        let (manifest, _) = self.read_manifest()?;
        validate_commit_manifest_context(&manifest, &pending.old, pending.bucket_count)?;
        validate_fixed_writeback_budget(&manifest, pending.updated_buckets.len())?;
        let mut seen_bucket_ids = std::collections::BTreeSet::new();
        for bucket in &pending.updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(
                    "private result ORAM pending writeback is invalid",
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
                CollectionError::bad_request("private result ORAM pending writeback is invalid")
            })?;
            if pending.merkle_tree.leaf_hashes.get(bucket_index) != Some(&bucket.bucket_commitment)
            {
                return Err(CollectionError::bad_request(
                    "private result ORAM pending writeback is invalid",
                ));
            }
        }

        let updated_bucket_refs = pending
            .updated_buckets
            .iter()
            .map(|bucket| PrivateResultOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        let signature_input = PrivateResultOramCommitSignatureInput {
            collection_id: &manifest.collection_id,
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
        validate_private_result_oram_commit_signature(
            signature_input,
            &pending.commit_signature.sig,
            signature_verification,
        )
        .map_err(private_result_oram_error)?;
        let writeback_digest = private_result_oram_writeback_digest(signature_input)
            .map_err(private_result_oram_error)?;
        Ok(PrivateResultOramConsensusWriteback {
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
                CollectionError::bad_request("private result ORAM Merkle tree is empty")
            })?;
        Ok(BASE64URL_NOPAD.encode(root))
    }

    pub fn write_merkle_tree_from_commitments(
        &self,
        index_epoch: u64,
        root_hash: String,
        leaf_hashes: Vec<String>,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_merkle_tree_from_commitments_under_owner_lock(
                token,
                index_epoch,
                root_hash,
                leaf_hashes,
            )
        })
    }

    fn write_merkle_tree_from_commitments_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        index_epoch: u64,
        root_hash: String,
        leaf_hashes: Vec<String>,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        let bucket_count = u64::try_from(leaf_hashes.len()).map_err(|_| {
            CollectionError::bad_request("private result ORAM Merkle tree bucket_count exceeds u64")
        })?;
        let tree = PrivateResultOramMerkleTree {
            version: 1,
            index_epoch,
            root_hash,
            bucket_count,
            leaf_hashes,
        };
        validate_merkle_tree(&tree)?;
        self.write_merkle_tree_under_owner_lock(token, &tree)
    }

    pub fn read_merkle_path_batch(
        &self,
        bucket_ids: &[u64],
        expected_epoch: u64,
        expected_root_hash: &str,
        expected_bucket_count: u64,
    ) -> CollectionResult<PrivateResultOramMerkleProof> {
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle proof bucket batch is empty",
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
                    "private result ORAM Merkle proof bucket is out of range",
                ));
            }
            let bucket_index = usize::try_from(bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private result ORAM Merkle proof bucket id exceeds usize",
                )
            })?;
            leaves.push(PrivateResultOramMerkleProofLeaf {
                bucket_id,
                leaf_hash: tree.leaf_hashes[bucket_index].clone(),
                siblings: merkle_siblings_for_bucket(&levels, bucket_index)?,
            });
        }

        Ok(PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
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
    ) -> CollectionResult<(Vec<PrivateResultOramBucket>, PrivateResultOramMerkleProof)> {
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket batch is empty",
            ));
        }
        let expected = PrivateResultOramEpochState {
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

    fn prepare_merkle_tree_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
    ) -> CollectionResult<PrivateResultOramMerkleTree> {
        if !std::ptr::eq(self, token.store) {
            return Err(CollectionError::service_error(
                "private result ORAM owner store writer token mismatch",
            ));
        }
        if new_epoch <= old_epoch {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle commit new epoch must be exactly old epoch + 1",
            ));
        }
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle commit must update at least one bucket",
            ));
        }
        let mut tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(&tree, old_epoch, old_root_hash, bucket_count)?;
        let mut seen_bucket_ids = std::collections::BTreeSet::new();
        for bucket in updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle commit repeats a bucket",
                ));
            }
            if bucket.index_epoch != new_epoch {
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle commit bucket has stale epoch",
                ));
            }
            if bucket.bucket_id >= bucket_count {
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle commit bucket is out of range",
                ));
            }
            decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
            let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private result ORAM Merkle commit bucket id exceeds usize",
                )
            })?;
            tree.leaf_hashes[bucket_index] = bucket.bucket_commitment.clone();
        }
        let computed_root = Self::merkle_root_for_commitments(&tree.leaf_hashes)?;
        if computed_root != new_root_hash {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle commit new_root_hash mismatch",
            ));
        }
        tree.index_epoch = new_epoch;
        tree.root_hash = new_root_hash.to_string();
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    #[cfg(test)]
    fn write_merkle_commit_for_offline_corruption_test(
        &self,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            let tree = self.prepare_merkle_tree_under_owner_lock(
                token,
                old_epoch,
                old_root_hash,
                new_epoch,
                new_root_hash,
                bucket_count,
                updated_buckets,
            )?;
            self.write_merkle_tree_under_owner_lock(token, &tree)
        })
    }

    #[cfg(test)]
    fn write_merkle_tree_for_offline_corruption_test(
        &self,
        tree: &PrivateResultOramMerkleTree,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.write_merkle_tree_under_owner_lock(token, tree)
        })
    }

    #[cfg(test)]
    fn compare_and_swap_epoch_with_writeback_digest_for_offline_corruption_test(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        writeback_digest: Option<&str>,
    ) -> CollectionResult<()> {
        self.with_canonical_writer_lock_v1(|token| {
            self.compare_and_swap_epoch_under_owner_lock(token, old, new, writeback_digest)
        })
    }

    fn read_merkle_tree(&self) -> CollectionResult<PrivateResultOramMerkleTree> {
        validate_private_dir(&self.merkle_dir())?;
        let tree = read_json_private_file(&self.merkle_nodes_path(), MAX_MERKLE_BYTES)?;
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    fn write_merkle_tree_under_owner_lock(
        &self,
        token: &PrivateResultOwnerStoreWriteTokenV1<'_>,
        tree: &PrivateResultOramMerkleTree,
    ) -> CollectionResult<()> {
        self.ensure_layout_under_owner_lock(token)?;
        validate_merkle_tree(tree)?;
        write_json_atomic_with_limit(
            &self.root,
            &self.temp_dir(),
            &self.merkle_nodes_path(),
            tree,
            MAX_MERKLE_BYTES,
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
        expected: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        let current = self.read_current_epoch()?;
        if &current != expected {
            return Err(CollectionError::bad_request(
                "private result ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
        }
        Ok(())
    }
}

impl PrivateResultOwnerStoreLockV1<'_> {
    pub(crate) fn classify_owner_recovery_progress_v1<'context>(
        &self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'context>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateResultOramManifestValidationContext<'context>,
    ) -> CollectionResult<PrivateResultOwnerRecoveryProgressV1> {
        let context = private_result_owner_recovery_context_v1(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        Ok(self
            .revalidated_owner_recovery_snapshot_v1(context)?
            .progress)
    }

    pub(crate) fn verify_owner_exact_old_v1<'lock, 'context>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'context>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateResultOramManifestValidationContext<'context>,
    ) -> CollectionResult<PrivateResultOwnerExactOldStoreTokenV1<'lock>> {
        let context = private_result_owner_recovery_context_v1(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        self.verify_exact_old(context)
    }

    pub(crate) fn verify_owner_exact_new_v1<'lock, 'context>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'context>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateResultOramManifestValidationContext<'context>,
    ) -> CollectionResult<PrivateResultOwnerExactNewStoreTokenV1<'lock>> {
        let context = private_result_owner_recovery_context_v1(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        self.verify_exact_new(context)
    }

    pub(crate) fn resume_owner_recovery_to_exact_new_v1<'lock, 'context>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'context>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateResultOramManifestValidationContext<'context>,
    ) -> CollectionResult<PrivateResultOwnerExactNewStoreTokenV1<'lock>> {
        let context = private_result_owner_recovery_context_v1(
            authority,
            max_ciphertext_bytes,
            manifest_validation,
        )?;
        self.resume_owner_recovery_context_to_exact_new_v1(context)
    }

    fn resume_owner_recovery_context_to_exact_new_v1<'lock>(
        &'lock self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateResultOwnerExactNewStoreTokenV1<'lock>> {
        let mut snapshot = self.revalidated_owner_recovery_snapshot_v1(context)?;
        let written_prefix = match snapshot.progress {
            PrivateResultOwnerRecoveryProgressV1::S0 => 0,
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix } => written_prefix,
            PrivateResultOwnerRecoveryProgressV1::S2
            | PrivateResultOwnerRecoveryProgressV1::S3
            | PrivateResultOwnerRecoveryProgressV1::S4 => context.final_buckets.len(),
        };
        if written_prefix < context.final_buckets.len() {
            for next_prefix in written_prefix..context.final_buckets.len() {
                self.write_owner_recovery_next_bucket_v1(context, next_prefix, &snapshot)?;
            }
            snapshot = self.revalidated_owner_recovery_snapshot_v1(context)?;
        }

        if snapshot.progress
            == (PrivateResultOwnerRecoveryProgressV1::S1 {
                written_prefix: context.final_buckets.len(),
            })
        {
            self.publish_owner_recovery_merkle_v1(context)?;
            snapshot = self.revalidated_owner_recovery_snapshot_v1(context)?;
        }
        if snapshot.progress == PrivateResultOwnerRecoveryProgressV1::S2 {
            self.publish_owner_recovery_commit_v1(context)?;
            snapshot = self.revalidated_owner_recovery_snapshot_v1(context)?;
        }
        if snapshot.progress == PrivateResultOwnerRecoveryProgressV1::S3 {
            self.publish_owner_recovery_current_v1(context)?;
            snapshot = self.revalidated_owner_recovery_snapshot_v1(context)?;
        }
        if snapshot.progress != PrivateResultOwnerRecoveryProgressV1::S4 {
            return Err(CollectionError::service_error(
                "private result ORAM owner recovery did not reach exact new state",
            ));
        }
        self.verify_exact_new(context)
    }

    fn write_owner_recovery_next_bucket_v1(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
        written_prefix: usize,
        snapshot: &PrivateResultOwnerRecoverySnapshotV1,
    ) -> CollectionResult<()> {
        let expected = if written_prefix == 0 {
            PrivateResultOwnerRecoveryProgressV1::S0
        } else {
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix }
        };
        let initial_prefix = match snapshot.progress {
            PrivateResultOwnerRecoveryProgressV1::S0 => 0,
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix } => written_prefix,
            _ => return Err(owner_store_state_mismatch()),
        };
        if written_prefix < initial_prefix
            || (written_prefix == initial_prefix && snapshot.progress != expected)
        {
            return Err(owner_store_state_mismatch());
        }
        let bucket = context
            .final_buckets
            .get(written_prefix)
            .ok_or_else(owner_store_state_mismatch)?;
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;
        if self.store.read_manifest()?
            != (
                snapshot.manifest.clone(),
                snapshot.manifest_signature.clone(),
            )
        {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_context(&snapshot.manifest, context, OwnerStorePhase::ExactOld)?;
        let expected_old = PrivateResultOramEpochState {
            index_epoch: context.old_state.index_epoch,
            root_hash: context.old_state.root_hash.clone(),
        };
        if self.store.read_current_epoch()? != expected_old
            || self.store.read_merkle_tree()? != snapshot.tree
            || validate_owner_recovery_old_commit(self.store, &snapshot.manifest, context)?
                != snapshot.old_commit_kind
            || owner_recovery_new_commit_is_exact_or_absent(self.store, context)?
        {
            return Err(owner_store_state_mismatch());
        }
        validate_merkle_tree_context(
            &snapshot.tree,
            context.old_state.index_epoch,
            &context.old_state.root_hash,
            snapshot.manifest.bucket_count,
        )?;

        let max_file_bytes = max_bucket_file_bytes(context.max_ciphertext_bytes)?;
        let observed_old: PrivateResultOramBucket =
            read_json_private_file(&self.store.bucket_path(bucket.bucket_id), max_file_bytes)?;
        let expected_old_bucket = snapshot
            .affected_buckets
            .get(written_prefix)
            .ok_or_else(owner_store_state_mismatch)?;
        if &observed_old != expected_old_bucket || observed_old == *bucket {
            return Err(owner_store_state_mismatch());
        }
        if let Some(previous_index) = written_prefix.checked_sub(1) {
            let previous = context
                .final_buckets
                .get(previous_index)
                .ok_or_else(owner_store_state_mismatch)?;
            let observed_previous: PrivateResultOramBucket = read_json_private_file(
                &self.store.bucket_path(previous.bucket_id),
                max_file_bytes,
            )?;
            if observed_previous != *previous {
                return Err(owner_store_state_mismatch());
            }
        }
        validate_bucket(
            bucket,
            context.new_state.index_epoch,
            snapshot.manifest.bucket_count,
            context.max_ciphertext_bytes,
        )?;
        validate_bucket_ciphertext_fixed_size(bucket, &snapshot.manifest)?;
        validate_bucket_commitment_context(
            &snapshot.manifest,
            context.new_state.index_epoch,
            std::slice::from_ref(bucket),
        )?;
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.bucket_path(bucket.bucket_id),
            bucket,
        )?;
        let observed_new: PrivateResultOramBucket =
            read_json_private_file(&self.store.bucket_path(bucket.bucket_id), max_file_bytes)?;
        if observed_new != *bucket
            || self.store.read_manifest()?
                != (
                    snapshot.manifest.clone(),
                    snapshot.manifest_signature.clone(),
                )
            || self.store.read_current_epoch()? != expected_old
            || self.store.read_merkle_tree()? != snapshot.tree
            || validate_owner_recovery_old_commit(self.store, &snapshot.manifest, context)?
                != snapshot.old_commit_kind
            || owner_recovery_new_commit_is_exact_or_absent(self.store, context)?
        {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(())
    }

    fn publish_owner_recovery_merkle_v1(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<()> {
        let snapshot = self.revalidated_owner_recovery_snapshot_v1(context)?;
        if snapshot.progress
            != (PrivateResultOwnerRecoveryProgressV1::S1 {
                written_prefix: context.final_buckets.len(),
            })
        {
            return Err(owner_store_state_mismatch());
        }
        let tree = owner_recovery_new_tree_from_old(&snapshot.tree, context)?;
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.merkle_nodes_path(),
            &tree,
        )?;
        if self
            .revalidated_owner_recovery_snapshot_v1(context)?
            .progress
            != PrivateResultOwnerRecoveryProgressV1::S2
        {
            return Err(owner_store_state_mismatch());
        }
        Ok(())
    }

    fn publish_owner_recovery_commit_v1(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<()> {
        if self
            .revalidated_owner_recovery_snapshot_v1(context)?
            .progress
            != PrivateResultOwnerRecoveryProgressV1::S2
        {
            return Err(owner_store_state_mismatch());
        }
        let commit = PrivateResultOramEpochCommit {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
            writeback_digest: Some(context.new_state.last_writeback_digest.clone()),
        };
        validate_epoch_commit(&commit, context.new_state.index_epoch)?;
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.commit_epoch_path(context.new_state.index_epoch),
            &commit,
        )?;
        if self
            .revalidated_owner_recovery_snapshot_v1(context)?
            .progress
            != PrivateResultOwnerRecoveryProgressV1::S3
        {
            return Err(owner_store_state_mismatch());
        }
        Ok(())
    }

    fn publish_owner_recovery_current_v1(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<()> {
        if self
            .revalidated_owner_recovery_snapshot_v1(context)?
            .progress
            != PrivateResultOwnerRecoveryProgressV1::S3
        {
            return Err(owner_store_state_mismatch());
        }
        let current = PrivateResultOramEpochState {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
        };
        validate_epoch_state(&current)?;
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        write_json_atomic(
            &self.store.root,
            &self.store.temp_dir(),
            &self.store.current_epoch_path(),
            &current,
        )?;
        if self
            .revalidated_owner_recovery_snapshot_v1(context)?
            .progress
            != PrivateResultOwnerRecoveryProgressV1::S4
        {
            return Err(owner_store_state_mismatch());
        }
        Ok(())
    }

    fn revalidated_owner_recovery_snapshot_v1(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateResultOwnerRecoverySnapshotV1> {
        let first = self.classify_owner_recovery_snapshot_once_v1(context)?;
        let second = self.classify_owner_recovery_snapshot_once_v1(context)?;
        if first != second {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(second)
    }

    fn classify_owner_recovery_snapshot_once_v1(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateResultOwnerRecoverySnapshotV1> {
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;

        let (manifest, signature) = self.store.read_manifest()?;
        validate_private_result_oram_manifest(
            &manifest,
            Some(&signature),
            context.manifest_validation,
        )
        .map_err(private_result_oram_error)?;
        let current = self.store.read_current_epoch()?;
        let old = PrivateResultOramEpochState {
            index_epoch: context.old_state.index_epoch,
            root_hash: context.old_state.root_hash.clone(),
        };
        let new = PrivateResultOramEpochState {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
        };
        let context_phase = if current == old {
            OwnerStorePhase::ExactOld
        } else if current == new {
            OwnerStorePhase::ExactNew
        } else {
            return Err(owner_store_state_mismatch());
        };
        validate_owner_store_context(&manifest, context, context_phase)?;
        let store_manifest_digest = digest_bytes(
            &try_private_result_oram_manifest_signature_message(&manifest)
                .map_err(private_result_oram_error)?,
        );
        let old_commit_kind = validate_owner_recovery_old_commit(self.store, &manifest, context)?;
        let new_commit_present = owner_recovery_new_commit_is_exact_or_absent(self.store, context)?;
        let epoch_directory_digest = validate_owner_recovery_epoch_directory(
            self.store,
            context.old_state.index_epoch,
            context.new_state.index_epoch,
            new_commit_present,
        )?;

        let tree = self.store.read_merkle_tree()?;
        let tree_is_old = validate_merkle_tree_context(
            &tree,
            context.old_state.index_epoch,
            &context.old_state.root_hash,
            manifest.bucket_count,
        )
        .is_ok();
        let tree_is_new = validate_merkle_tree_context(
            &tree,
            context.new_state.index_epoch,
            &context.new_state.root_hash,
            manifest.bucket_count,
        )
        .is_ok();
        if tree_is_old == tree_is_new {
            return Err(owner_store_state_mismatch());
        }

        let (written_prefix, affected_buckets) =
            read_owner_recovery_bucket_prefix(self.store, &manifest, &tree, tree_is_old, context)?;
        let all_new = written_prefix == context.final_buckets.len();
        let progress = if current == old && tree_is_old && !new_commit_present {
            if written_prefix == 0 {
                PrivateResultOwnerRecoveryProgressV1::S0
            } else {
                PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix }
            }
        } else if current == old && tree_is_new && all_new && !new_commit_present {
            PrivateResultOwnerRecoveryProgressV1::S2
        } else if current == old && tree_is_new && all_new && new_commit_present {
            PrivateResultOwnerRecoveryProgressV1::S3
        } else if current == new && tree_is_new && all_new && new_commit_present {
            PrivateResultOwnerRecoveryProgressV1::S4
        } else {
            return Err(owner_store_state_mismatch());
        };
        ensure_owner_store_has_no_legacy_pending(self.store)?;
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(PrivateResultOwnerRecoverySnapshotV1 {
            progress,
            manifest,
            manifest_signature: signature,
            store_manifest_digest,
            epoch_directory_digest,
            tree,
            old_commit_kind,
            affected_buckets,
        })
    }

    pub(crate) fn classify_owner_state_v1<'lock>(
        &'lock self,
        authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_>,
        max_ciphertext_bytes: usize,
        manifest_validation: PrivateResultOramManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateResultOwnerStoreObservationV1<'lock>> {
        let final_buckets = authority
            .result_final_buckets()
            .ok_or_else(owner_store_state_mismatch)?;
        let context = PrivateResultOwnerStoreVerificationContextV1 {
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
        let old = PrivateResultOramEpochState {
            index_epoch: context.old_state.index_epoch,
            root_hash: context.old_state.root_hash.clone(),
        };
        let new = PrivateResultOramEpochState {
            index_epoch: context.new_state.index_epoch,
            root_hash: context.new_state.root_hash.clone(),
        };
        if current == old {
            return self
                .verify_exact_old(context)
                .map(PrivateResultOwnerStoreObservationV1::Old);
        }
        if current == new {
            return self
                .verify_exact_new(context)
                .map(PrivateResultOwnerStoreObservationV1::New);
        }
        ensure_owner_store_has_no_legacy_pending(self.store)?;
        if self.store.read_current_epoch()? != current {
            return Err(owner_store_state_mismatch());
        }
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        Ok(PrivateResultOwnerStoreObservationV1::Third)
    }

    fn verify_exact_old<'lock>(
        &'lock self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateResultOwnerExactOldStoreTokenV1<'lock>> {
        let evidence = self.verify_exact_state(context, OwnerStorePhase::ExactOld)?;
        Ok(PrivateResultOwnerExactOldStoreTokenV1 {
            index_name: context.index_name.to_string(),
            canonical_state_digest: evidence.canonical_state_digest,
            _lock: PhantomData,
        })
    }

    fn verify_exact_new<'lock>(
        &'lock self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    ) -> CollectionResult<PrivateResultOwnerExactNewStoreTokenV1<'lock>> {
        let evidence = self.verify_exact_state(context, OwnerStorePhase::ExactNew)?;
        Ok(PrivateResultOwnerExactNewStoreTokenV1 {
            index_name: context.index_name.to_string(),
            canonical_state_digest: evidence.canonical_state_digest,
            _lock: PhantomData,
        })
    }

    fn verify_exact_state(
        &self,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
        phase: OwnerStorePhase,
    ) -> CollectionResult<OwnerStoreEvidence> {
        validate_owner_store_directory_identity(&self.directory, &self.store.root)?;
        ensure_owner_store_has_no_legacy_pending(self.store)?;

        let (manifest, signature) = self.store.read_manifest()?;
        validate_private_result_oram_manifest(
            &manifest,
            Some(&signature),
            context.manifest_validation,
        )
        .map_err(private_result_oram_error)?;
        validate_owner_store_context(&manifest, context, phase)?;
        let store_manifest_digest = digest_bytes(
            &try_private_result_oram_manifest_signature_message(&manifest)
                .map_err(private_result_oram_error)?,
        );

        let target = match phase {
            OwnerStorePhase::ExactOld => context.old_state,
            OwnerStorePhase::ExactNew => context.new_state,
        };
        let expected_epoch = PrivateResultOramEpochState {
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

fn private_result_owner_recovery_context_v1<'a>(
    authority: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a>,
    max_ciphertext_bytes: usize,
    manifest_validation: PrivateResultOramManifestValidationContext<'a>,
) -> CollectionResult<PrivateResultOwnerStoreVerificationContextV1<'a>> {
    let final_buckets = authority
        .result_final_buckets()
        .ok_or_else(owner_store_state_mismatch)?;
    Ok(PrivateResultOwnerStoreVerificationContextV1 {
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

fn validate_owner_recovery_old_commit(
    store: &PrivateResultOramStore,
    manifest: &PrivateResultOramManifest,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
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

fn owner_recovery_new_commit_is_exact_or_absent(
    store: &PrivateResultOramStore,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
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

fn validate_owner_recovery_epoch_directory(
    store: &PrivateResultOramStore,
    old_epoch: u64,
    new_epoch: u64,
    new_commit_present: bool,
) -> CollectionResult<String> {
    let entries = read_owner_epoch_directory_entries(store, new_epoch)?;
    let mut observed_new_commit = false;
    for (epoch, _) in &entries {
        if *epoch == new_epoch {
            if !new_commit_present || observed_new_commit {
                return Err(owner_store_state_mismatch());
            }
            observed_new_commit = true;
        } else if *epoch > old_epoch {
            return Err(owner_store_state_mismatch());
        }
    }
    if observed_new_commit != new_commit_present {
        return Err(owner_store_state_mismatch());
    }
    Ok(owner_epoch_directory_digest(&entries))
}

fn read_owner_recovery_bucket_prefix(
    store: &PrivateResultOramStore,
    manifest: &PrivateResultOramManifest,
    tree: &PrivateResultOramMerkleTree,
    tree_is_old: bool,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<(usize, Vec<PrivateResultOramBucket>)> {
    let mut written_prefix = 0_usize;
    let mut observed_old = false;
    let mut buckets = Vec::with_capacity(context.final_buckets.len());
    for (bucket_ref, final_bucket) in context.final_bucket_refs.iter().zip(context.final_buckets) {
        let max_file_bytes = max_bucket_file_bytes(context.max_ciphertext_bytes)?;
        let bucket: PrivateResultOramBucket =
            read_json_private_file(&store.bucket_path(bucket_ref.bucket_id), max_file_bytes)?;
        if bucket.bucket_id != bucket_ref.bucket_id {
            return Err(owner_store_state_mismatch());
        }
        let bucket_index =
            usize::try_from(bucket.bucket_id).map_err(|_| owner_store_state_mismatch())?;
        let tree_commitment = tree
            .leaf_hashes
            .get(bucket_index)
            .ok_or_else(owner_store_state_mismatch)?;
        if bucket == *final_bucket {
            if observed_old {
                return Err(owner_store_state_mismatch());
            }
            validate_bucket(
                &bucket,
                context.new_state.index_epoch,
                manifest.bucket_count,
                context.max_ciphertext_bytes,
            )
            .map_err(|_| owner_store_state_mismatch())?;
            validate_bucket_ciphertext_fixed_size(&bucket, manifest)
                .map_err(|_| owner_store_state_mismatch())?;
            validate_bucket_commitment_context(
                manifest,
                context.new_state.index_epoch,
                std::slice::from_ref(&bucket),
            )
            .map_err(|_| owner_store_state_mismatch())?;
            if !tree_is_old && tree_commitment != &bucket.bucket_commitment {
                return Err(owner_store_state_mismatch());
            }
            written_prefix = written_prefix
                .checked_add(1)
                .ok_or_else(owner_store_state_mismatch)?;
        } else {
            if !tree_is_old {
                return Err(owner_store_state_mismatch());
            }
            observed_old = true;
            validate_bucket_for_read(
                &bucket,
                context.old_state.index_epoch,
                manifest.bucket_count,
                context.max_ciphertext_bytes,
            )
            .map_err(|_| owner_store_state_mismatch())?;
            validate_bucket_ciphertext_fixed_size(&bucket, manifest)
                .map_err(|_| owner_store_state_mismatch())?;
            validate_bucket_commitment_context(
                manifest,
                bucket.index_epoch,
                std::slice::from_ref(&bucket),
            )
            .map_err(|_| owner_store_state_mismatch())?;
            if tree_commitment != &bucket.bucket_commitment {
                return Err(owner_store_state_mismatch());
            }
        }
        buckets.push(bucket);
    }
    Ok((written_prefix, buckets))
}

fn owner_recovery_new_tree_from_old(
    old_tree: &PrivateResultOramMerkleTree,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<PrivateResultOramMerkleTree> {
    validate_merkle_tree_context(
        old_tree,
        context.old_state.index_epoch,
        &context.old_state.root_hash,
        old_tree.bucket_count,
    )
    .map_err(|_| owner_store_state_mismatch())?;
    let mut tree = old_tree.clone();
    for bucket_ref in context.final_bucket_refs {
        let bucket_index =
            usize::try_from(bucket_ref.bucket_id).map_err(|_| owner_store_state_mismatch())?;
        let leaf = tree
            .leaf_hashes
            .get_mut(bucket_index)
            .ok_or_else(owner_store_state_mismatch)?;
        *leaf = bucket_ref.bucket_commitment.clone();
    }
    tree.index_epoch = context.new_state.index_epoch;
    tree.root_hash = context.new_state.root_hash.clone();
    validate_merkle_tree(&tree).map_err(|_| owner_store_state_mismatch())?;
    Ok(tree)
}

fn validate_owner_store_context(
    manifest: &PrivateResultOramManifest,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
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
    validate_owner_index_name(context.index_name)?;

    let old = context.old_state;
    let new = context.new_state;
    let expected_new_epoch = old.index_epoch.checked_add(1).ok_or_else(|| {
        CollectionError::bad_request("private result ORAM owner store transition is invalid")
    })?;
    let expected_new_logical = old.logical_count.checked_add(1).ok_or_else(|| {
        CollectionError::bad_request("private result ORAM owner store transition is invalid")
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
        .logical_result_count
        .checked_add(manifest.dummy_result_count)
        .ok_or_else(owner_store_state_mismatch)?;
    if old.kind != PrivateOramIndexKindV2::Result
        || new.kind != PrivateOramIndexKindV2::Result
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
            || manifest.logical_result_count != target.logical_count
            || manifest.dummy_result_count != target.dummy_count)
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
    manifest: &PrivateResultOramManifest,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
) -> CollectionResult<()> {
    let immutable_digest = private_oram_immutable_manifest_v2_digest(context.immutable_manifest)
        .map_err(|_| owner_store_state_mismatch())?;
    let occupancy = manifest
        .logical_result_count
        .checked_add(manifest.dummy_result_count)
        .ok_or_else(owner_store_state_mismatch)?;
    let PrivateOramImmutableIndexParamsV2::Result {
        key_id,
        rk_id,
        rk_epoch,
        oram,
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
        || context.immutable_manifest.owner_signing_key_id != manifest.owner_signing_key_id
        || context.immutable_manifest.created_at_unix != manifest.created_at_unix
        || context.immutable_index.index_name != context.index_name
        || key_id != &manifest.key_id
        || rk_id != &manifest.rk_id
        || *rk_epoch != manifest.rk_epoch
        || oram != &manifest.oram
        || context.immutable_index.capacity.bucket_count != manifest.bucket_count
        || context.immutable_index.capacity.logical_capacity != occupancy
    {
        return Err(owner_store_state_mismatch());
    }
    Ok(())
}

fn validate_owner_store_epoch_commits(
    store: &PrivateResultOramStore,
    manifest: &PrivateResultOramManifest,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
) -> CollectionResult<OwnerStoreCommitKind> {
    match phase {
        OwnerStorePhase::ExactOld => {
            match store.read_epoch_commit(context.new_state.index_epoch) {
                Err(CollectionError::NotFound { .. }) => {}
                Ok(_) => return Err(owner_store_state_mismatch()),
                Err(error) => return Err(error),
            }
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
        OwnerStorePhase::ExactNew => match store.read_epoch_commit(context.new_state.index_epoch) {
            Ok(commit)
                if commit.root_hash == context.new_state.root_hash
                    && commit.writeback_digest.as_deref()
                        == Some(context.new_state.last_writeback_digest.as_str()) =>
            {
                Ok(OwnerStoreCommitKind::DigestBound)
            }
            Ok(_) | Err(CollectionError::NotFound { .. }) => Err(owner_store_state_mismatch()),
            Err(error) => Err(error),
        },
    }
}

fn validate_owner_store_epoch_directory(
    store: &PrivateResultOramStore,
    current_epoch: u64,
) -> CollectionResult<String> {
    let entries = read_owner_epoch_directory_entries(store, current_epoch)?;
    Ok(owner_epoch_directory_digest(&entries))
}

fn read_owner_epoch_directory_entries(
    store: &PrivateResultOramStore,
    current_epoch: u64,
) -> CollectionResult<Vec<(u64, PrivateResultOramEpochCommit)>> {
    validate_private_dir(&store.epochs_dir())?;
    let entries = fs_err::read_dir(store.epochs_dir()).map_err(|_| {
        CollectionError::service_error("failed to inspect private result ORAM owner epoch state")
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
            CollectionError::service_error(
                "failed to inspect private result ORAM owner epoch state",
            )
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
    Ok(commits)
}

fn owner_epoch_directory_digest(entries: &[(u64, PrivateResultOramEpochCommit)]) -> String {
    let mut hasher = Sha256::new();
    hash_len_prefixed(&mut hasher, OWNER_EPOCH_DIRECTORY_DOMAIN);
    hasher.update((entries.len() as u64).to_be_bytes());
    for (epoch, commit) in entries {
        hasher.update(epoch.to_be_bytes());
        hash_len_prefixed(&mut hasher, commit.root_hash.as_bytes());
        match &commit.writeback_digest {
            Some(writeback_digest) => {
                hasher.update([1]);
                hash_len_prefixed(&mut hasher, writeback_digest.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn read_owner_store_buckets(
    store: &PrivateResultOramStore,
    manifest: &PrivateResultOramManifest,
    tree: &PrivateResultOramMerkleTree,
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
) -> CollectionResult<Vec<PrivateResultOramBucket>> {
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
            CollectionError::bad_request("private result ORAM owner store bucket id is invalid")
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

fn ensure_owner_store_has_no_legacy_pending(
    store: &PrivateResultOramStore,
) -> CollectionResult<()> {
    if store.pending_writeback_exists()? {
        return Err(CollectionError::bad_request(
            "private result ORAM V2 owner verification rejects legacy pending writeback state",
        ));
    }
    Ok(())
}

fn owner_store_canonical_state_digest(
    context: PrivateResultOwnerStoreVerificationContextV1<'_>,
    phase: OwnerStorePhase,
    store_manifest_digest: &str,
    tree: &PrivateResultOramMerkleTree,
    commit_kind: OwnerStoreCommitKind,
    epoch_directory_digest: &str,
    buckets: &[PrivateResultOramBucket],
) -> String {
    let mut hasher = Sha256::new();
    hash_len_prefixed(&mut hasher, phase.domain());
    hash_len_prefixed(&mut hasher, context.journal_descriptor_digest.as_bytes());
    hash_len_prefixed(&mut hasher, context.prepared_state_digest.as_bytes());
    hash_len_prefixed(&mut hasher, context.immutable_manifest_digest.as_bytes());
    hasher.update([2, phase.tag()]);
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

fn owner_store_merkle_leaves_digest(tree: &PrivateResultOramMerkleTree) -> String {
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
    CollectionError::bad_request("private result ORAM owner canonical store state does not match")
}

fn validate_owner_index_name(index_name: &str) -> CollectionResult<()> {
    if index_name.is_empty()
        || index_name.len() > 256
        || index_name
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(CollectionError::bad_request(
            "private result ORAM owner index name is invalid",
        ));
    }
    Ok(())
}

fn ensure_read_proof_matches_buckets(
    proof: &PrivateResultOramMerkleProof,
    buckets: &[PrivateResultOramBucket],
) -> CollectionResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(CollectionError::bad_request(
            "private result ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private result ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

fn validate_merkle_tree(tree: &PrivateResultOramMerkleTree) -> CollectionResult<()> {
    if tree.version != 1 {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree has unsupported version",
        ));
    }
    if tree.bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree bucket_count must be non-zero",
        ));
    }
    let leaf_hash_count = u64::try_from(tree.leaf_hashes.len()).map_err(|_| {
        CollectionError::bad_request("private result ORAM Merkle tree leaf count exceeds u64")
    })?;
    if leaf_hash_count != tree.bucket_count {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree leaf count does not match bucket_count",
        ));
    }
    let computed_root = PrivateResultOramStore::merkle_root_for_commitments(&tree.leaf_hashes)?;
    if computed_root != tree.root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree root_hash mismatch",
        ));
    }
    Ok(())
}

fn validate_merkle_tree_context(
    tree: &PrivateResultOramMerkleTree,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
) -> CollectionResult<()> {
    validate_merkle_tree(tree)?;
    if tree.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree epoch mismatch",
        ));
    }
    if tree.root_hash != expected_root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree root_hash mismatch",
        ));
    }
    if tree.bucket_count != expected_bucket_count {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree bucket_count mismatch",
        ));
    }
    Ok(())
}

fn merkle_levels(commitments: &[String]) -> CollectionResult<Vec<Vec<[u8; 32]>>> {
    if commitments.is_empty() {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree must contain at least one leaf",
        ));
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_base64url_32(commitment, "bucket_commitment"))
        .collect::<CollectionResult<Vec<_>>>()?;
    let padded_len = leaves.len().checked_next_power_of_two().ok_or_else(|| {
        CollectionError::bad_request("private result ORAM Merkle tree is too large")
    })?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let Some(previous) = levels.last() else {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle tree is invalid",
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
) -> CollectionResult<Vec<PrivateResultOramMerkleSibling>> {
    if levels.is_empty() || index >= levels[0].len() {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle proof bucket index is out of range",
        ));
    }
    let sibling_level_count = levels.len().checked_sub(1).ok_or_else(|| {
        CollectionError::bad_request("private result ORAM Merkle proof levels are invalid")
    })?;
    let mut siblings = Vec::with_capacity(sibling_level_count);
    for (level_index, level) in levels.iter().enumerate().take(sibling_level_count) {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let position = if index % 2 == 0 {
            PrivateResultOramMerkleSiblingPosition::Right
        } else {
            PrivateResultOramMerkleSiblingPosition::Left
        };
        let sibling = level.get(sibling_index).ok_or_else(|| {
            CollectionError::bad_request("private result ORAM Merkle proof sibling is missing")
        })?;
        siblings.push(PrivateResultOramMerkleSibling {
            level: u32::try_from(level_index).map_err(|_| {
                CollectionError::bad_request("private result ORAM Merkle proof level exceeds u32")
            })?,
            position,
            hash: BASE64URL_NOPAD.encode(sibling),
        });
        index /= 2;
    }
    Ok(siblings)
}

fn validate_bucket(
    bucket: &PrivateResultOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(
            "private result ORAM bucket has stale epoch",
        ));
    }
    Ok(())
}

fn validate_commit_manifest_context(
    manifest: &PrivateResultOramManifest,
    _old: &PrivateResultOramEpochState,
    bucket_count: u64,
) -> CollectionResult<()> {
    if manifest.bucket_count != bucket_count {
        return Err(CollectionError::bad_request(
            "private result ORAM manifest bucket_count does not match commit bucket_count",
        ));
    }
    Ok(())
}

fn initial_replication_bucket_estimated_bytes(
    ciphertext_bytes: usize,
    ciphertext_hash_bytes: usize,
    commitment_bytes: usize,
) -> CollectionResult<usize> {
    std::mem::size_of::<PrivateResultOramBucket>()
        .checked_add(ciphertext_bytes)
        .and_then(|size| size.checked_add(ciphertext_hash_bytes))
        .and_then(|size| size.checked_add(commitment_bytes))
        .ok_or_else(|| {
            CollectionError::bad_request(
                "private result ORAM initial replication bundle size is invalid",
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
    manifest: &PrivateResultOramManifest,
    updated_bucket_count: usize,
) -> CollectionResult<()> {
    let max_updated_buckets = usize::try_from(manifest.bucket_count)
        .map_err(|_| CollectionError::bad_request("private result ORAM bucket count overflows"))?;
    if updated_bucket_count > max_updated_buckets {
        return Err(CollectionError::bad_request(
            "private result ORAM commit exceeds fixed writeback budget",
        ));
    }
    Ok(())
}

fn validate_bucket_commitment_context(
    manifest: &PrivateResultOramManifest,
    index_epoch: u64,
    buckets: &[PrivateResultOramBucket],
) -> CollectionResult<()> {
    for bucket in buckets {
        let expected_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
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
                "private result ORAM commit bucket commitment context mismatch",
            )
        })?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private result ORAM commit bucket commitment context mismatch",
            ));
        }
    }
    Ok(())
}

fn validate_bucket_ciphertext_fixed_size(
    bucket: &PrivateResultOramBucket,
    manifest: &PrivateResultOramManifest,
) -> CollectionResult<()> {
    let expected = private_result_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_result_oram_error)?;
    let expected_b64_len = base64url_nopad_encoded_len(expected)?;
    if bucket.ciphertext.len() != expected_b64_len {
        return Err(CollectionError::bad_request(
            "private result ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request("private result ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() != expected {
        return Err(CollectionError::bad_request(
            "private result ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    Ok(())
}

fn validate_bucket_for_read(
    bucket: &PrivateResultOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch > expected_epoch {
        return Err(CollectionError::bad_request(
            "private result ORAM bucket is newer than requested epoch",
        ));
    }
    Ok(())
}

fn validate_bucket_shape(
    bucket: &PrivateResultOramBucket,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_private_result_oram_bucket_shape(
        bucket,
        PrivateResultOramBucketValidationContext {
            expected_index_epoch: bucket.index_epoch,
            bucket_count,
            max_ciphertext_bytes,
        },
    )
    .map_err(private_result_oram_error)
}

fn validate_upload_bundle(
    bundle: &PrivateResultOramUploadBundle,
    max_ciphertext_bytes: usize,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_result_oram_upload_bundle(bundle).map_err(private_result_oram_error)?;
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
    bundle: &PrivateResultOramUploadBundle,
    max_ciphertext_bytes: usize,
    validation_context: PrivateResultOramManifestValidationContext<'_>,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_result_oram_upload_bundle_with_signature(bundle, validation_context)
            .map_err(private_result_oram_error)?;
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
    bundle: &PrivateResultOramLiveReplicationBundle,
    max_ciphertext_bytes: usize,
) -> CollectionResult<Vec<String>> {
    validate_private_result_oram_manifest_shape(&bundle.manifest)
        .map_err(private_result_oram_error)?;
    validate_epoch_state(&bundle.current)?;
    if bundle.current.index_epoch < bundle.manifest.index_epoch {
        return Err(CollectionError::bad_request(
            "private result ORAM live replication epoch precedes manifest anchor",
        ));
    }
    if bundle.current.index_epoch == bundle.manifest.index_epoch {
        if bundle.current.root_hash != bundle.manifest.root_hash {
            return Err(CollectionError::bad_request(
                "private result ORAM live replication initial state is invalid",
            ));
        }
        if let Some(writeback_digest) = bundle.writeback_digest.as_deref() {
            validate_writeback_digest(writeback_digest)?;
        }
    } else if let Some(writeback_digest) = bundle.writeback_digest.as_deref() {
        validate_writeback_digest(writeback_digest)?;
    } else {
        return Err(CollectionError::bad_request(
            "private result ORAM live replication advanced state requires consensus digest",
        ));
    }
    let bucket_count = usize::try_from(bundle.manifest.bucket_count).map_err(|_| {
        CollectionError::bad_request("private result ORAM live replication bucket_count is invalid")
    })?;
    if bundle.buckets.len() != bucket_count || bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private result ORAM live replication bucket set is incomplete",
        ));
    }
    let mut commitments = Vec::new();
    commitments.try_reserve_exact(bucket_count).map_err(|_| {
        CollectionError::service_error("private result ORAM live replication allocation failed")
    })?;
    for (bucket_id, bucket) in bundle.buckets.iter().enumerate() {
        let expected_bucket_id = u64::try_from(bucket_id).map_err(|_| {
            CollectionError::bad_request(
                "private result ORAM live replication bucket id is invalid",
            )
        })?;
        if bucket.bucket_id != expected_bucket_id || bucket.index_epoch > bundle.current.index_epoch
        {
            return Err(CollectionError::bad_request(
                "private result ORAM live replication bucket context is invalid",
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
    let computed_root = PrivateResultOramStore::merkle_root_for_commitments(&commitments)?;
    if computed_root != bundle.current.root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM live replication root hash mismatch",
        ));
    }
    Ok(commitments)
}

fn validate_epoch_state(epoch: &PrivateResultOramEpochState) -> CollectionResult<()> {
    decode_base64url_32(&epoch.root_hash, "root_hash")?;
    Ok(())
}

fn validate_epoch_commit(
    commit: &PrivateResultOramEpochCommit,
    expected_epoch: u64,
) -> CollectionResult<()> {
    if commit.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(
            "private result ORAM completed writeback epoch does not match",
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

fn base64url_nopad_encoded_len(byte_len: usize) -> CollectionResult<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket ciphertext size overflows",
            ));
        }
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
        .ok_or_else(|| {
            CollectionError::bad_request("private result ORAM bucket ciphertext size overflows")
        })
}

fn max_bucket_file_bytes(max_ciphertext_bytes: usize) -> CollectionResult<u64> {
    let encoded_len = base64url_nopad_encoded_len(max_ciphertext_bytes)?;
    let file_len = encoded_len
        .checked_add(BUCKET_JSON_OVERHEAD_BYTES)
        .ok_or_else(|| {
            CollectionError::bad_request("private result ORAM bucket file size overflows")
        })?;
    u64::try_from(file_len)
        .map_err(|_| CollectionError::bad_request("private result ORAM bucket file size overflows"))
}

fn private_result_oram_error(err: qdrant_sec::PrivateResultOramError) -> CollectionError {
    use qdrant_sec::PrivateResultOramError;

    let message = match err {
        PrivateResultOramError::Encryption(_) => "private result ORAM client encryption failed",
        PrivateResultOramError::UnsupportedManifestVersion(_) => {
            "private result ORAM manifest version is unsupported"
        }
        PrivateResultOramError::InvalidProvider => {
            "private result ORAM manifest provider is invalid"
        }
        PrivateResultOramError::InvalidBinding => "private result ORAM manifest binding is invalid",
        PrivateResultOramError::InvalidManifestField(_) => {
            "private result ORAM manifest field is invalid"
        }
        PrivateResultOramError::ManifestContextMismatch(_) => {
            "private result ORAM manifest field does not match runtime context"
        }
        PrivateResultOramError::MissingManifestSignature => {
            "private result ORAM manifest signature is missing"
        }
        PrivateResultOramError::UnsupportedSignatureAlgorithm(_) => {
            "private result ORAM signature algorithm must be ed25519"
        }
        PrivateResultOramError::SignatureKeyIdMismatch => {
            "private result ORAM signature key id does not match runtime context"
        }
        PrivateResultOramError::MalformedSignature => "private result ORAM signature is malformed",
        PrivateResultOramError::InvalidManifestSignature => {
            "private result ORAM manifest signature verification failed"
        }
        PrivateResultOramError::InvalidCommitSignature => {
            "private result ORAM commit signature verification failed"
        }
        PrivateResultOramError::InvalidReadBucketsSignature => {
            "private result ORAM read_buckets signature verification failed"
        }
        PrivateResultOramError::InvalidResourceKeyId => {
            "private result ORAM resource key id is invalid"
        }
        PrivateResultOramError::UnsupportedBucketVersion(_) => {
            "private result ORAM bucket version is unsupported"
        }
        PrivateResultOramError::UnsupportedBucketCiphertextVersion(_) => {
            "private result ORAM bucket ciphertext uses unsupported version"
        }
        PrivateResultOramError::UnsupportedPayloadBlockVersion(_) => {
            "private result ORAM payload block uses unsupported version"
        }
        PrivateResultOramError::UnsupportedClientStateSnapshotVersion(_) => {
            "private result ORAM client state snapshot uses unsupported version"
        }
        PrivateResultOramError::UnsupportedClientStateCiphertextVersion(_) => {
            "private result ORAM client state uses unsupported ciphertext version"
        }
        PrivateResultOramError::BucketOutOfRange { .. } => {
            "private result ORAM bucket is out of range"
        }
        PrivateResultOramError::InvalidBucketField(_) => {
            "private result ORAM bucket field is invalid"
        }
        PrivateResultOramError::BucketOversized => {
            "private result ORAM bucket ciphertext exceeds maximum size"
        }
        PrivateResultOramError::InvalidBucketHash => {
            "private result ORAM bucket ciphertext_sha256 mismatch"
        }
        PrivateResultOramError::InvalidBucketCiphertextEncoding => {
            "private result ORAM bucket ciphertext is malformed"
        }
        PrivateResultOramError::InvalidBucketCiphertextHash => {
            "private result ORAM bucket ciphertext hash mismatch"
        }
        PrivateResultOramError::BucketOpenFailed => {
            "private result ORAM bucket decryption authentication failed"
        }
        PrivateResultOramError::BucketMetadataMismatch => {
            "private result ORAM bucket metadata does not match context"
        }
        PrivateResultOramError::InvalidBucketContext(_) => {
            "private result ORAM bucket context is invalid"
        }
        PrivateResultOramError::InvalidBucketCommitment => {
            "private result ORAM bucket commitment context mismatch"
        }
        PrivateResultOramError::EmptyMerkleTree => "private result ORAM Merkle tree is empty",
        PrivateResultOramError::MerkleRootMismatch => {
            "private result ORAM Merkle root does not match current commitments"
        }
        PrivateResultOramError::ManifestCommitMismatch => {
            "private result ORAM manifest epoch/root does not match commit old epoch/root"
        }
        PrivateResultOramError::StaleBucketEpoch { .. } => {
            "private result ORAM bucket epoch does not match expected epoch"
        }
        PrivateResultOramError::DuplicateUpdatedBucket { .. } => {
            "private result ORAM commit repeats a bucket"
        }
        PrivateResultOramError::EmptyCommit => {
            "private result ORAM commit must update at least one bucket"
        }
        PrivateResultOramError::InvalidMerkleProof => {
            "private result ORAM Merkle proof is malformed"
        }
        PrivateResultOramError::InvalidMerkleProofJson => {
            "private result ORAM Merkle proof JSON is malformed"
        }
        PrivateResultOramError::MerkleProofMismatch => {
            "private result ORAM Merkle proof does not match bucket commitments"
        }
        PrivateResultOramError::InvalidFetchPlanField(_) => {
            "private result ORAM fetch plan field is invalid"
        }
        PrivateResultOramError::MissingPayloadFetchTokenPosition => {
            "private result ORAM fetch token position is missing"
        }
        PrivateResultOramError::DuplicatePayloadFetchToken => {
            "private result ORAM fetch token appears more than once"
        }
        PrivateResultOramError::DuplicatePointToken => {
            "private result ORAM point token appears more than once"
        }
        PrivateResultOramError::DuplicatePayloadFetchTokenPosition => {
            "private result ORAM fetch token position appears more than once"
        }
        PrivateResultOramError::InvalidClientConfig(_) => {
            "private result ORAM client config is invalid"
        }
        PrivateResultOramError::InvalidPayloadBlock => {
            "private result ORAM payload block is malformed"
        }
        PrivateResultOramError::InvalidPayloadBlockPadding => {
            "private result ORAM payload block padding is invalid"
        }
        PrivateResultOramError::PayloadBlockOversized => {
            "private result ORAM payload block exceeds configured size"
        }
        PrivateResultOramError::InvalidBucketPlaintext => {
            "private result ORAM bucket plaintext is malformed"
        }
        PrivateResultOramError::BucketPlaintextSlotCountMismatch => {
            "private result ORAM bucket plaintext slot count does not match config"
        }
        PrivateResultOramError::MissingPosition => {
            "private result ORAM client position map is missing a token"
        }
        PrivateResultOramError::MissingBlock => {
            "private result ORAM path did not contain requested block"
        }
        PrivateResultOramError::PathBucketMismatch => {
            "private result ORAM path buckets do not match requested leaf"
        }
        PrivateResultOramError::InvalidClientStateSnapshot => {
            "private result ORAM client state snapshot is malformed"
        }
        PrivateResultOramError::InvalidClientStateContext(_) => {
            "private result ORAM client state context is invalid"
        }
        PrivateResultOramError::InvalidClientStateCiphertextEncoding => {
            "private result ORAM client state ciphertext is not base64url"
        }
        PrivateResultOramError::InvalidClientStateCiphertextHash => {
            "private result ORAM client state ciphertext hash is invalid"
        }
        PrivateResultOramError::ClientStateOpenFailed => {
            "private result ORAM client state decryption authentication failed"
        }
    };
    CollectionError::bad_request(message)
}

fn decode_base64url_32(value: &str, field: &str) -> CollectionResult<[u8; 32]> {
    if value.len() != 43 {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM {field} must encode 32 bytes",
        )));
    }
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        CollectionError::bad_request(format!("private result ORAM {field} is not base64url"))
    })?;
    bytes.try_into().map_err(|_| {
        CollectionError::bad_request(format!("private result ORAM {field} must encode 32 bytes"))
    })
}

fn create_private_dir(path: &Path) -> CollectionResult<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(CollectionError::service_error(
                "private result ORAM path must be a non-symlink directory",
            ));
        }
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| {
                CollectionError::service_error("failed to create private result ORAM directory")
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|_| {
                CollectionError::service_error("failed to inspect private result ORAM directory")
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(CollectionError::service_error(
                    "private result ORAM path must be a non-symlink directory",
                ));
            }
            true
        }
        Err(_) => {
            return Err(CollectionError::service_error(
                "failed to inspect private result ORAM directory",
            ));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                CollectionError::service_error("failed to harden private result ORAM directory")
            })?;
        }
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> CollectionResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found("private result ORAM directory");
        }
        CollectionError::service_error("failed to inspect private result ORAM directory")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::service_error(
            "private result ORAM path must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(
                "private result ORAM directory must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private result ORAM directory must not be group/world accessible",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_store_directory_identity(directory: &File, path: &Path) -> CollectionResult<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let opened = directory.metadata().map_err(|_| {
        CollectionError::service_error("failed to inspect private result ORAM owner store root")
    })?;
    let current = fs::symlink_metadata(path).map_err(|_| {
        CollectionError::service_error("failed to inspect private result ORAM owner store root")
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
            "private result ORAM owner store root identity is invalid",
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
        "private result ORAM owner store verification is unsupported on this platform",
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
        .map_err(|_| CollectionError::service_error("failed to read private result ORAM file"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(CollectionError::bad_request(
            "private result ORAM file exceeds maximum size",
        ));
    }
    validate_opened_private_file_at_path(&file, path, max_bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| CollectionError::bad_request("private result ORAM file contains invalid JSON"))
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
/// exceeds `max_bytes` (the cap its reader enforces), and removing the temp file on any error.
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
        CollectionError::service_error("failed to serialize private result ORAM file")
    })?;
    if u64::try_from(bytes.len()).is_ok_and(|len| len > max_bytes) {
        return Err(CollectionError::bad_request(
            "private result ORAM record exceeds its maximum size",
        ));
    }
    let temp_path = unique_temp_path(temp_dir);
    let written = (|| -> CollectionResult<()> {
        let mut file = open_private_file_for_write(&temp_path)?;
        file.write_all(&bytes).map_err(|_| {
            CollectionError::service_error("failed to write private result ORAM temp file")
        })?;
        file.flush().map_err(|_| {
            CollectionError::service_error("failed to flush private result ORAM temp file")
        })?;
        file.sync_all().map_err(|_| {
            CollectionError::service_error("failed to sync private result ORAM temp file")
        })?;
        drop(file);
        sync_dir(temp_dir)?;
        fs::rename(&temp_path, target).map_err(|_| {
            CollectionError::service_error("failed to replace private result ORAM file")
        })
    })();
    if let Err(err) = written {
        // Nothing sweeps `temp/`, so a failed write must not leave its partial file behind.
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

/// A post-commit manifest refresh may change only `index_epoch`, `root_hash`, the result counts
/// and `created_at_unix`; every other field is part of each stored bucket's commitment context
/// or of the runtime policy pinned at upload.
fn manifest_refresh_preserves_immutable_fields(
    stored: &PrivateResultOramManifest,
    refreshed: &PrivateResultOramManifest,
) -> bool {
    let mut expected = stored.clone();
    expected.index_epoch = refreshed.index_epoch;
    expected.root_hash = refreshed.root_hash.clone();
    expected.logical_result_count = refreshed.logical_result_count;
    expected.dummy_result_count = refreshed.dummy_result_count;
    expected.created_at_unix = refreshed.created_at_unix;
    expected == *refreshed
}

fn remove_private_file(path: &Path, parent: &Path, max_bytes: u64) -> CollectionResult<()> {
    validate_private_dir(parent)?;
    let file = open_private_file_for_read(path, max_bytes)?;
    drop(file);
    fs::remove_file(path)
        .map_err(|_| CollectionError::service_error("failed to remove private result ORAM file"))?;
    sync_dir(parent)
}

fn validate_target_under_root(root: &Path, target: &Path) -> CollectionResult<()> {
    if !target.starts_with(root) {
        return Err(CollectionError::service_error(
            "private result ORAM target escapes root",
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
            return CollectionError::not_found("private result ORAM file");
        }
        CollectionError::service_error("failed to inspect private result ORAM file")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(
            "private result ORAM file must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(
            "private result ORAM file exceeds maximum size",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(
                "private result ORAM file must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private result ORAM file must not be group/world accessible",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(CollectionError::service_error(
                "private result ORAM file must not be hard-linked",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| {
                CollectionError::service_error("failed to open private result ORAM file")
            })?;
        validate_opened_private_file_for_read(&file, max_bytes)?;
        let opened = file.metadata().map_err(|_| {
            CollectionError::service_error("failed to inspect opened private result ORAM file")
        })?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(CollectionError::service_error(
                "private result ORAM file identity changed while opening",
            ));
        }
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        File::open(path)
            .map_err(|_| CollectionError::service_error("failed to open private result ORAM file"))
    }
}

#[cfg(unix)]
fn validate_opened_private_file_for_read(file: &File, max_bytes: u64) -> CollectionResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata().map_err(|_| {
        CollectionError::service_error("failed to inspect opened private result ORAM file")
    })?;
    if !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(
            "private result ORAM file must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(
            "private result ORAM file exceeds maximum size",
        ));
    }
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != effective_uid {
        return Err(CollectionError::service_error(
            "private result ORAM file must be owned by the current user",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CollectionError::service_error(
            "private result ORAM file must not be group/world accessible",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(CollectionError::service_error(
            "private result ORAM file must not be hard-linked",
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
        CollectionError::service_error("failed to inspect opened private result ORAM file")
    })?;
    let current = fs::symlink_metadata(path).map_err(|_| {
        CollectionError::service_error("failed to re-inspect private result ORAM file")
    })?;
    if current.file_type().is_symlink()
        || !current.file_type().is_file()
        || current.nlink() != 1
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(CollectionError::service_error(
            "private result ORAM file identity changed while reading",
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
    options.open(path).map_err(|_| {
        CollectionError::service_error("failed to create private result ORAM temp file")
    })
}

fn unique_temp_path(temp_dir: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    temp_dir.join(format!(
        "private-result-oram-{}-{timestamp}-{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4(),
    ))
}

fn sync_dir(path: &Path) -> CollectionResult<()> {
    let file = File::open(path).map_err(|_| {
        CollectionError::service_error("failed to open private result ORAM directory for sync")
    })?;
    file.sync_all()
        .map_err(|_| CollectionError::service_error("failed to sync private result ORAM directory"))
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        DistanceKind, EncryptionError, FixedBudgetParams, OramKind, OramParams,
        PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER,
        PRIVATE_HNSW_ORAM_V2_BINDING, PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        PRIVATE_RESULT_ORAM_BINDING, PRIVATE_RESULT_ORAM_V2_BINDING, PrivateHnswParams,
        PrivateHnswVectorEncoding, PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2,
        PrivateOramImmutableManifestV2, PrivateOramIndexCapacityV2,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
        PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
        PrivateResultOramError, PrivateResultOramSignatureVerification, ResultPrivacyMode,
        VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, private_result_oram_bucket_commitment,
        private_result_oram_merkle_root_for_commitments, sign_private_result_oram_commit,
        sign_private_result_oram_manifest, verify_private_result_oram_merkle_proof,
        verify_private_result_oram_merkle_proof_json,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    use super::*;

    fn root_hash(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    #[test]
    fn private_result_oram_store_debug_redacts_paths_and_hashes() {
        let store = PrivateResultOramStore::new("/tmp/result-oram-store-debug-sentinel");
        let epoch = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: "RESULT-STORE-ROOT-SENTINEL".to_string(),
        };
        let leaf_commitment = "RESULT-STORE-LEAF-COMMITMENT-SENTINEL".to_string();
        let tree = PrivateResultOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: "RESULT-STORE-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaf_hashes: vec![leaf_commitment.clone()],
        };
        let rendered = [
            format!("{store:?}"),
            format!("{epoch:?}"),
            format!("{tree:?}"),
        ]
        .join("\n");
        for leaked in [
            "/tmp/result-oram-store-debug-sentinel",
            "RESULT-STORE-ROOT-SENTINEL",
            leaf_commitment.as_str(),
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
        assert!(
            !format!("{tree:?}").contains("leaf_hash_count: 1"),
            "{tree:?}"
        );
        assert!(!format!("{tree:?}").contains("bucket_count: 8"), "{tree:?}");
    }

    #[test]
    fn private_result_oram_temp_paths_include_random_suffix() {
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
                .starts_with("private-result-oram-")
        );
    }

    fn bucket_ciphertext(bytes: &[u8]) -> (String, String) {
        let expected =
            qdrant_sec::private_result_oram_bucket_ciphertext_bytes(&fixture_manifest().oram)
                .unwrap();
        assert!(bytes.len() <= expected);
        let mut ciphertext = vec![0; expected];
        ciphertext[..bytes.len()].copy_from_slice(bytes);
        (
            BASE64URL_NOPAD.encode(&ciphertext),
            BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref()),
        )
    }

    fn max_base64url_nopad_encoded_len_for_test(byte_len: usize) -> usize {
        let full_chunks = byte_len / 3;
        let remainder = byte_len % 3;
        full_chunks * 4
            + match remainder {
                0 => 0,
                1 => 2,
                2 => 3,
                _ => unreachable!("remainder modulo 3"),
            }
    }

    #[test]
    fn private_result_oram_error_mapping_redacts_structured_values() {
        let client_state_alias_needles = [
            "client_state",
            "client_state.json",
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
            "client.state.snapshots",
            "clientStateSnapshots",
            "encrypted_client_states",
            "encryptedClientStates",
            "encrypted_client_state_backup",
            "encrypted_client_state",
            "encrypted.client.state",
            "encrypted.client.state.json",
            "encrypted_client_state.json",
            "encryptedClientState",
            "encryptedClientStateBackup",
            "encrypted_client_state_backups",
            "encrypted_client_state_snapshot",
            "encrypted.client.state.snapshot",
            "encrypted.client.state.snapshot.json",
            "encrypted_client_state_snapshot.json",
            "encryptedClientStateSnapshot",
            "encrypted_client_state_snapshots",
            "encrypted.client.state.snapshots",
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
            "state_ciphertext_hashes.json",
            "state_ciphertext_hashes.bin",
            "stateCiphertextHashes",
            "state_ciphertext_sha256",
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
            "token.position.map",
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
            "stashBackup.json",
            "stashBackups",
            "stashBackups.json",
            "stash_backup",
            "stash_backups",
            "stash_snapshot",
            "stash_snapshots",
            "stashSnapshot",
            "stashSnapshots",
        ];
        let cases = [
            (
                private_result_oram_error(PrivateResultOramError::Encryption(
                    EncryptionError::UnsupportedAlgorithm("aead-alg-777777".to_string()),
                )),
                vec!["aead-alg-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedManifestVersion(
                    65_000,
                )),
                vec!["65000"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                    "rsa-pss-777777".to_string(),
                )),
                vec!["rsa-pss-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidManifestField(
                    "manifest-field-777777",
                )),
                vec!["manifest-field-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::ManifestContextMismatch(
                    "manifest-context-777777",
                )),
                vec!["manifest-context-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedBucketVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidBucketField(
                    "bucket-field-777777",
                )),
                vec!["bucket-field-777777", "777777"],
            ),
            (
                private_result_oram_error(
                    PrivateResultOramError::UnsupportedBucketCiphertextVersion(77),
                ),
                vec!["77"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidBucketContext(
                    "bucket-context-777777",
                )),
                vec!["bucket-context-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidFetchPlanField(
                    "fetch-plan-field-777777",
                )),
                vec!["fetch-plan-field-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidClientConfig(
                    "client-config-777777",
                )),
                vec!["client-config-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidClientStateContext(
                    "client-state-context-777777",
                )),
                vec!["client-state-context-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedPayloadBlockVersion(
                    65_000,
                )),
                vec!["65000"],
            ),
            (
                private_result_oram_error(
                    PrivateResultOramError::UnsupportedClientStateSnapshotVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_result_oram_error(
                    PrivateResultOramError::UnsupportedClientStateCiphertextVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::BucketOutOfRange {
                    bucket_id: 777_777,
                    bucket_count: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::StaleBucketEpoch {
                    bucket_id: 777_777,
                    expected_epoch: 888_888,
                    actual_epoch: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::DuplicateUpdatedBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::DuplicatePointToken),
                vec![],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidMerkleProof),
                vec![],
            ),
            (
                private_result_oram_error(PrivateResultOramError::InvalidMerkleProofJson),
                vec![],
            ),
            (
                private_result_oram_error(PrivateResultOramError::MerkleProofMismatch),
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

    fn fixture_store(temp: &TempDir) -> PrivateResultOramStore {
        PrivateResultOramStore::new(temp.path())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_root_lock_rejects_leaf_writer_before_mutation() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let bucket = fixture_bucket(0, 42, b"owner-lock-leaf-writer");

        let lock = store.lock_owner_store_v1().unwrap();
        let error = store.write_bucket(&bucket, 42, 1, 128).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another private result ORAM owner store operation")
        );
        assert!(!store.bucket_path(bucket.bucket_id).exists());
        drop(lock);

        store.write_bucket(&bucket, 42, 1, 128).unwrap();
        assert!(store.bucket_path(bucket.bucket_id).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_root_lock_rejects_initial_install_before_mutation() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let bundle = fixture_upload_bundle();

        let lock = store.lock_owner_store_v1().unwrap();
        let error = store.write_initial_upload_bundle(&bundle, 128).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another private result ORAM owner store operation")
        );
        assert!(!store.manifest_path().exists());
        assert!(!store.current_epoch_path().exists());
        assert!(!store.merkle_nodes_path().exists());
        assert!(!store.bucket_path(0).exists());
        drop(lock);

        assert_eq!(
            store.write_initial_upload_bundle(&bundle, 128).unwrap(),
            PrivateResultOramEpochState {
                index_epoch: bundle.manifest.index_epoch,
                root_hash: bundle.manifest.root_hash.clone(),
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bucket_upload_bundle_uses_one_lock_and_preflights_before_mutation() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let expected = PrivateResultOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };
        store
            .write_manifest(&bundle.manifest, &bundle.manifest_signature)
            .unwrap();
        store.write_initial_epoch(&expected).unwrap();

        let lock = store.lock_owner_store_v1().unwrap();
        let error = store
            .write_bucket_upload_bundle(&expected, &bundle, 128)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another private result ORAM owner store operation")
        );
        for bucket in &bundle.buckets {
            assert!(!store.bucket_path(bucket.bucket_id).exists());
        }
        assert!(!store.merkle_nodes_path().exists());
        drop(lock);

        let stale = PrivateResultOramEpochState {
            index_epoch: expected.index_epoch,
            root_hash: root_hash(98),
        };
        let error = store
            .write_bucket_upload_bundle(&stale, &bundle, 128)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bucket upload epoch/root does not match current manifest epoch")
        );
        for bucket in &bundle.buckets {
            assert!(!store.bucket_path(bucket.bucket_id).exists());
        }
        assert!(!store.merkle_nodes_path().exists());

        let mut invalid = bundle.clone();
        let last = invalid.buckets.last_mut().unwrap();
        last.ciphertext_sha256 = root_hash(99);
        let _error = store
            .write_bucket_upload_bundle(&expected, &invalid, 128)
            .unwrap_err();
        for bucket in &bundle.buckets {
            assert!(!store.bucket_path(bucket.bucket_id).exists());
        }
        assert!(!store.merkle_nodes_path().exists());

        assert_eq!(
            store
                .write_bucket_upload_bundle(&expected, &bundle, 128)
                .unwrap(),
            expected
        );
        for bucket in &bundle.buckets {
            assert_eq!(
                store
                    .read_bucket(
                        bucket.bucket_id,
                        expected.index_epoch,
                        bundle.manifest.bucket_count,
                        128,
                    )
                    .unwrap(),
                *bucket
            );
        }
        assert_eq!(
            store.read_merkle_tree().unwrap().root_hash,
            expected.root_hash
        );
        assert_eq!(
            store
                .write_bucket_upload_bundle(&expected, &bundle, 128)
                .unwrap(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owner_store_callback_revalidates_pinned_root_identity() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let displaced = temp.path().join("displaced-private-result-oram");

        let error = store
            .with_owner_store_lock_v1(|_| {
                fs::rename(&store.root, &displaced).unwrap();
                create_private_dir(&store.root).unwrap();
                Ok(())
            })
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("owner store root identity is invalid")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn canonical_writers_fail_closed_without_owner_lock_support() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);

        let error = store.ensure_layout().unwrap_err();

        assert!(error.to_string().contains("unsupported on this platform"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn aggregate_writers_acquire_owner_root_lock_once_without_self_deadlock() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let updated_bucket = fixture_bucket(1, 43, b"single-lock-aggregate-writeback");
        let mut commitments = bundle.bucket_commitments();
        commitments[1] = updated_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&commitments).unwrap(),
        };

        assert_eq!(
            store
                .commit_writeback(
                    &old,
                    &new,
                    bundle.bucket_count(),
                    std::slice::from_ref(&updated_bucket),
                    128,
                )
                .unwrap(),
            new
        );
        assert_eq!(store.read_current_epoch().unwrap(), new);
    }

    fn fixture_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            key_id: "tenant-a/result-private-rk".to_string(),
            rk_id: "tenant-a/result-private-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 8,
                tree_height: 1,
                path_batch_size: 2,
            },
            index_epoch: 42,
            root_hash: root_hash(42),
            bucket_count: 3,
            logical_result_count: 2,
            dummy_result_count: 1,
            owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn fixture_signature() -> PrivateResultOramSignature {
        PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-result-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_bucket(bucket_id: u64, epoch: u64, plaintext: &[u8]) -> PrivateResultOramBucket {
        let (ciphertext, ciphertext_sha256) = bucket_ciphertext(plaintext);
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(bucket_id, epoch, &ciphertext_sha256),
        }
    }

    fn fixture_bucket_commitment(bucket_id: u64, epoch: u64, ciphertext_sha256: &str) -> String {
        private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/result-private-rk",
                rk_id: "tenant-a/result-private-rk",
                rk_epoch: 7,
                bucket_id,
                index_epoch: epoch,
            },
            ciphertext_sha256,
        )
        .unwrap()
    }

    fn fixture_upload_bundle() -> PrivateResultOramUploadBundle {
        let buckets = vec![
            fixture_bucket(0, 42, b"encrypted result bucket 0"),
            fixture_bucket(1, 42, b"encrypted result bucket 1"),
            fixture_bucket(2, 42, b"encrypted result bucket 2"),
        ];
        let commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let mut manifest = fixture_manifest();
        manifest.bucket_count = buckets.len() as u64;
        manifest.logical_result_count = 2;
        manifest.dummy_result_count = 1;
        manifest.root_hash =
            PrivateResultOramStore::merkle_root_for_commitments(&commitments).unwrap();
        PrivateResultOramUploadBundle {
            manifest,
            manifest_signature: fixture_signature(),
            buckets,
        }
    }

    fn signed_fixture_upload_bundle(key_pair: &Ed25519KeyPair) -> PrivateResultOramUploadBundle {
        let mut bundle = fixture_upload_bundle();
        bundle.manifest_signature =
            sign_private_result_oram_manifest(key_pair, &bundle.manifest).unwrap();
        bundle
    }

    fn fixture_signed_commit_update(
        key_pair: &Ed25519KeyPair,
    ) -> (
        PrivateResultOramUploadBundle,
        PrivateResultOramBucket,
        PrivateResultOramEpochState,
        PrivateResultOramSignature,
    ) {
        let bundle = fixture_upload_bundle();
        let updated_bucket = fixture_bucket(1, 43, b"updated signed result bucket 1");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new_epoch = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let plan = PrivateResultOramCommitPlan {
            old_epoch: bundle.manifest.index_epoch,
            new_epoch: new_epoch.index_epoch,
            old_root_hash: bundle.manifest.root_hash.clone(),
            new_root_hash: new_epoch.root_hash.clone(),
            leaf_commitments: next_commitments,
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let signature = sign_private_result_oram_commit(
            key_pair,
            PrivateResultOramCommitSignatureContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/result-private-rk",
                rk_id: "tenant-a/result-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-result-signing-v1",
            },
            &plan,
        )
        .unwrap();
        (bundle, updated_bucket, new_epoch, signature)
    }

    fn fixture_validation_context<'a>(
        public_key: &'a [u8],
    ) -> PrivateResultOramManifestValidationContext<'a> {
        PrivateResultOramManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_key_id: "tenant-a/result-private-rk",
            expected_rk_id: "tenant-a/result-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/private-result-signing-v1",
                public_key,
            },
        }
    }

    fn fixture_owner_states(
        manifest: &PrivateResultOramManifest,
        new_epoch: &PrivateResultOramEpochState,
        index_name: &str,
    ) -> (PrivateOramIndexStateV2, PrivateOramIndexStateV2) {
        let old = PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: index_name.to_string(),
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
            logical_count: manifest.logical_result_count,
            dummy_count: manifest.dummy_result_count,
            last_writeback_digest: root_hash(70),
        };
        let new = PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: index_name.to_string(),
            index_epoch: new_epoch.index_epoch,
            root_hash: new_epoch.root_hash.clone(),
            logical_count: manifest.logical_result_count + 1,
            dummy_count: manifest.dummy_result_count - 1,
            last_writeback_digest: root_hash(71),
        };
        (old, new)
    }

    fn fixture_owner_immutable_manifest(
        manifest: &PrivateResultOramManifest,
        result_index_name: &str,
    ) -> PrivateOramImmutableManifestV2 {
        let logical_capacity = manifest.logical_result_count + manifest.dummy_result_count;
        let result_physical_slots = manifest.bucket_count * u64::from(manifest.oram.bucket_size);
        assert!(logical_capacity < result_physical_slots);
        let fixed_append_read_path_count = manifest.oram.path_batch_size * 2;
        let capacity = |bucket_count: u64, bucket_size: u32, tree_height: u32| {
            let physical_slots = bucket_count * u64::from(bucket_size);
            assert!(logical_capacity < physical_slots);
            PrivateOramIndexCapacityV2 {
                bucket_count,
                logical_capacity,
                reserved_physical_slots: physical_slots - logical_capacity,
                max_client_stash_blocks: 1,
                fixed_append_read_path_count,
                fixed_append_write_bucket_count: fixed_append_read_path_count * (tree_height + 1),
            }
        };
        let hnsw_oram = OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 2,
        };
        PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: manifest.collection_id.clone(),
            manifest_nonce: root_hash(69),
            indexes: vec![
                PrivateOramImmutableIndexV2 {
                    index_name: "text".to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Hnsw {
                        provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                        key_id: "tenant-a/vector-private-rk".to_string(),
                        rk_id: "tenant-a/vector-private-rk".to_string(),
                        rk_epoch: manifest.rk_epoch,
                        dim: 2,
                        vector_encoding: PrivateHnswVectorEncoding::F32Le,
                        distance: DistanceKind::Euclid,
                        hnsw: PrivateHnswParams {
                            m: 1,
                            ef_construction: 2,
                            max_layers: 1,
                            fixed_neighbor_slots: 4,
                        },
                        oram: hnsw_oram.clone(),
                        fixed_search_budget: FixedBudgetParams {
                            enabled: true,
                            upper_layer_steps: 1,
                            base_layer_steps: 2,
                            paths_per_round: 2,
                            fixed_result_k: 1,
                        },
                        max_neighbor_rewrites: 1,
                    },
                    capacity: capacity(3, hnsw_oram.bucket_size, hnsw_oram.tree_height),
                },
                PrivateOramImmutableIndexV2 {
                    index_name: result_index_name.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Result {
                        provider: PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                        key_id: manifest.key_id.clone(),
                        rk_id: manifest.rk_id.clone(),
                        rk_epoch: manifest.rk_epoch,
                        oram: manifest.oram.clone(),
                    },
                    capacity: capacity(
                        manifest.bucket_count,
                        manifest.oram.bucket_size,
                        manifest.oram.tree_height,
                    ),
                },
            ],
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: manifest.owner_signing_key_id.clone(),
            created_at_unix: manifest.created_at_unix,
        }
    }

    fn fixture_owner_bucket_refs(
        buckets: &[PrivateResultOramBucket],
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
        index_name: &'a str,
        old_state: &'a PrivateOramIndexStateV2,
        new_state: &'a PrivateOramIndexStateV2,
        final_bucket_refs: &'a [PrivateOramAppendBucketRefV1],
        final_buckets: &'a [PrivateResultOramBucket],
        public_key: &'a [u8],
    ) -> PrivateResultOwnerStoreVerificationContextV1<'a> {
        PrivateResultOwnerStoreVerificationContextV1 {
            journal_descriptor_digest,
            prepared_state_digest,
            immutable_manifest_digest,
            immutable_manifest,
            immutable_index: &immutable_manifest.indexes[1],
            index_name,
            old_state,
            new_state,
            final_bucket_refs,
            final_buckets,
            max_ciphertext_bytes: 128,
            manifest_validation: fixture_validation_context(public_key),
        }
    }

    fn with_owner_recovery_fixture(
        action: impl for<'a> FnOnce(
            &'a PrivateResultOramStore,
            PrivateResultOwnerStoreVerificationContextV1<'a>,
        ),
    ) {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
        let public_key = key_pair.public_key();
        let mut bundle = fixture_upload_bundle();
        bundle.manifest_signature =
            sign_private_result_oram_manifest(&key_pair, &bundle.manifest).unwrap();
        let final_buckets = vec![
            fixture_bucket(0, 43, b"owner recovery result bucket 0"),
            fixture_bucket(2, 43, b"owner recovery result bucket 2"),
        ];
        let mut commitments = bundle.bucket_commitments();
        for bucket in &final_buckets {
            commitments[usize::try_from(bucket.bucket_id).unwrap()] =
                bucket.bucket_commitment.clone();
        }
        let new_epoch = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&commitments).unwrap(),
        };
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                128,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let index_name = "private-result-index";
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch, index_name);
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(80);
        let prepared_state_digest = root_hash(81);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest, index_name);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            index_name,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );
        action(&store, context);
    }

    fn advance_owner_recovery_fixture_to(
        lock: &PrivateResultOwnerStoreLockV1<'_>,
        context: PrivateResultOwnerStoreVerificationContextV1<'_>,
        target: PrivateResultOwnerRecoveryProgressV1,
    ) {
        let target_prefix = match target {
            PrivateResultOwnerRecoveryProgressV1::S0 => 0,
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix } => written_prefix,
            PrivateResultOwnerRecoveryProgressV1::S2
            | PrivateResultOwnerRecoveryProgressV1::S3
            | PrivateResultOwnerRecoveryProgressV1::S4 => context.final_buckets.len(),
        };
        let snapshot = lock
            .revalidated_owner_recovery_snapshot_v1(context)
            .unwrap();
        for written_prefix in 0..target_prefix {
            lock.write_owner_recovery_next_bucket_v1(context, written_prefix, &snapshot)
                .unwrap();
        }
        if matches!(
            target,
            PrivateResultOwnerRecoveryProgressV1::S2
                | PrivateResultOwnerRecoveryProgressV1::S3
                | PrivateResultOwnerRecoveryProgressV1::S4
        ) {
            lock.publish_owner_recovery_merkle_v1(context).unwrap();
        }
        if matches!(
            target,
            PrivateResultOwnerRecoveryProgressV1::S3 | PrivateResultOwnerRecoveryProgressV1::S4
        ) {
            lock.publish_owner_recovery_commit_v1(context).unwrap();
        }
        if target == PrivateResultOwnerRecoveryProgressV1::S4 {
            lock.publish_owner_recovery_current_v1(context).unwrap();
        }
        assert_eq!(
            lock.revalidated_owner_recovery_snapshot_v1(context)
                .unwrap()
                .progress,
            target,
        );
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
            assert_eq!(manifest_mode & 0o077, 0);
            assert_eq!(root_mode & 0o077, 0);
        }
    }

    #[test]
    fn initial_epoch_if_absent_creates_private_layout() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateResultOramEpochState {
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
        let epoch = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let conflicting_epoch = PrivateResultOramEpochState {
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
        let epoch = PrivateResultOramEpochState {
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
        replacement.logical_result_count += 1;
        replacement.dummy_result_count -= 1;
        let replacement_signature = PrivateResultOramSignature {
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
    fn post_commit_manifest_refresh_allows_current_epoch_ahead_of_stored_manifest() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateResultOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let mut new_manifest = old_manifest.clone();
        new_manifest.index_epoch = old_manifest.index_epoch + 1;
        new_manifest.root_hash = root_hash(43);
        let new_signature = PrivateResultOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..old_signature.clone()
        };
        let new_epoch = PrivateResultOramEpochState {
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
    fn post_commit_manifest_refresh_cannot_change_bucket_commitment_context() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateResultOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let new_epoch = PrivateResultOramEpochState {
            index_epoch: old_manifest.index_epoch + 1,
            root_hash: root_hash(43),
        };
        let new_signature = PrivateResultOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..old_signature.clone()
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

        let mut refreshed = old_manifest.clone();
        refreshed.index_epoch = new_epoch.index_epoch;
        refreshed.root_hash = new_epoch.root_hash.clone();
        let mut changed_rk_epoch = refreshed.clone();
        changed_rk_epoch.rk_epoch += 1;
        let mut changed_bucket_count = refreshed.clone();
        changed_bucket_count.bucket_count += 1;
        let mut changed_signer = refreshed.clone();
        changed_signer.owner_signing_key_id.push('x');
        for tampered in [changed_rk_epoch, changed_bucket_count, changed_signer] {
            let rendered = store
                .write_manifest_with_initial_epoch_if_absent_or_matching(
                    &tampered,
                    &new_signature,
                    &new_epoch,
                )
                .unwrap_err()
                .to_string();
            assert!(
                rendered.contains("manifest refresh changes fields"),
                "{rendered}"
            );
            assert_eq!(
                store.read_manifest().unwrap(),
                (old_manifest.clone(), old_signature.clone())
            );
        }

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &refreshed,
                &new_signature,
                &new_epoch,
            )
            .unwrap();
        assert_eq!(store.read_manifest().unwrap(), (refreshed, new_signature));
    }

    #[test]
    fn post_commit_manifest_refresh_rejects_stale_epoch_without_overwriting() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateResultOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let new_epoch = PrivateResultOramEpochState {
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
        let epoch = PrivateResultOramEpochState {
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
            "failed initial manifest upload must not publish current epoch",
        );
    }

    #[test]
    fn bucket_write_rejects_hash_mismatch_and_oversize() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted result bucket");

        store
            .validate_bucket_for_write(&bucket, 42, 16, 128)
            .unwrap();
        store.write_bucket(&bucket, 42, 16, 128).unwrap();
        assert_eq!(store.read_bucket(3, 42, 16, 128).unwrap(), bucket);

        let large_max_ciphertext_bytes = 2 * 65_536 + 4_096;
        let large_ciphertext = vec![7; large_max_ciphertext_bytes];
        let large_ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&large_ciphertext).as_ref());
        let large_bucket = PrivateResultOramBucket {
            version: 1,
            bucket_id: 6,
            index_epoch: 42,
            ciphertext: BASE64URL_NOPAD.encode(&large_ciphertext),
            ciphertext_sha256: large_ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(6, 42, &large_ciphertext_sha256),
        };
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
            .validate_bucket_for_write(&bad_hash, 42, 16, 128)
            .unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));
        let err = store.write_bucket(&bad_hash, 42, 16, 128).unwrap_err();
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
        encoded_oversized.ciphertext = "A".repeat(max_base64url_nopad_encoded_len_for_test(64) + 1);
        encoded_oversized.ciphertext_sha256 = root_hash(2);
        let err = store
            .validate_bucket_for_write(&encoded_oversized, 42, 16, 64)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("exceeds maximum size"));
        assert!(!rendered.contains("ciphertext_sha256 mismatch"));
        assert!(!rendered.contains(&encoded_oversized.ciphertext));

        let out_of_range = fixture_bucket(99, 42, b"out of range result bucket");
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
        let mut mismatched_bucket = fixture_bucket(1, 42, b"encrypted result bucket mismatch");
        mismatched_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"private-result-bucket-ciphertext-sentinel");
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
        assert!(!err.contains("private-result-bucket-ciphertext-sentinel"));
        assert!(!err.contains(&mismatched_bucket.ciphertext));
    }

    #[cfg(unix)]
    #[test]
    fn bucket_read_rejects_symlink_file() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside_bucket = temp.path().join("outside.bucket");
        let bucket = fixture_bucket(0, 42, b"symlink target result bucket");
        std::fs::write(&outside_bucket, serde_json::to_vec_pretty(&bucket).unwrap()).unwrap();
        std::os::unix::fs::symlink(
            &outside_bucket,
            store.root_path().join(BUCKETS_DIR).join("00000000.bucket"),
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 1, 128).unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"));
        assert!(!rendered.contains("outside.bucket"), "{rendered}");
        assert!(!rendered.contains("00000000.bucket"), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
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
        let outside = temp.path().join("outside-result-hardlink.bucket");
        let bucket = fixture_bucket(0, 42, b"hard-linked result bucket");
        fs::write(&outside, serde_json::to_vec_pretty(&bucket).unwrap()).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&outside, store.bucket_path(0)).unwrap();

        let error = store.read_bucket(0, 42, 1, 128).unwrap_err().to_string();
        assert!(error.contains("must not be hard-linked"));
        assert!(!error.contains("outside-result-hardlink"));
        assert!(!error.contains("00000000.bucket"));
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
        let outside = temp.path().join("outside-result-current-epoch.json");
        fs::write(&outside, br#"{"index_epoch":42,"root_hash":"bad"}"#).unwrap();
        symlink(outside, store.current_epoch_path()).unwrap();

        let err = store.read_current_epoch().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"), "{rendered}");
        assert!(
            !rendered.contains("outside-result-current-epoch"),
            "{rendered}"
        );
        assert!(!rendered.contains(CURRENT_EPOCH_FILE), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn current_epoch_group_world_accessible_rejects_without_epoch_or_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateResultOramEpochState {
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
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_rejects_root_symlink_without_chmod_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let outside_dir = temp.path().join("outside-private-result");
        fs::create_dir(&outside_dir).unwrap();
        fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside_dir, temp.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains("outside-private-result"), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        let outside_mode = fs::metadata(&outside_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn root_directory_group_world_accessible_rejects_without_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join(PRIVATE_RESULT_ORAM_DIR);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(
            !store.root_path().join(BUCKETS_DIR).exists(),
            "weak result ORAM root must fail before creating bucket directory"
        );
        let root_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn temp_directory_symlink_rejects_without_path_or_temp_name_leak() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside_temp = temp.path().join("outside-private-result-temp");
        fs::create_dir(&outside_temp).unwrap();
        fs::set_permissions(&outside_temp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir(store.root_path().join(TEMP_DIR)).unwrap();
        symlink(&outside_temp, store.root_path().join(TEMP_DIR)).unwrap();

        let err = store
            .write_initial_epoch(&PrivateResultOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(
            !rendered.contains("outside-private-result-temp"),
            "{rendered}"
        );
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains("private-result-oram-"), "{rendered}");
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
            .write_initial_epoch(&PrivateResultOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains("private-result-oram-"), "{rendered}");
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

        let err = store.read_bucket(0, 42, 1, 128).unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn bucket_file_group_world_accessible_rejects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(0, 42, b"encrypted result bucket");
        store.write_bucket(&bucket, 42, 1, 128).unwrap();
        fs::set_permissions(
            store.root_path().join(BUCKETS_DIR).join("00000000.bucket"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 1, 128).unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("00000000.bucket"), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext_sha256), "{rendered}");
        assert!(!rendered.contains(&bucket.bucket_commitment), "{rendered}");
    }

    #[test]
    fn initial_upload_bundle_writes_manifest_buckets_merkle_and_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();

        let mut bad_alg_bundle = bundle.clone();
        let signature_alg_sentinel = "private-result-signature-alg-sentinel";
        bad_alg_bundle.manifest_signature.alg = signature_alg_sentinel.to_string();
        let err = store
            .write_initial_upload_bundle(&bad_alg_bundle, 128)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature algorithm must be ed25519"));
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
            "invalid unsigned upload must not create private result ORAM layout"
        );

        let epoch = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        assert_eq!(
            epoch,
            PrivateResultOramEpochState {
                index_epoch: bundle.manifest.index_epoch,
                root_hash: bundle.manifest.root_hash.clone(),
            }
        );
        assert_eq!(
            store.read_manifest().unwrap(),
            (bundle.manifest.clone(), bundle.manifest_signature.clone()),
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(
            store
                .read_bucket(1, bundle.manifest.index_epoch, 3, 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = store
            .read_merkle_path_batch(
                &[1],
                bundle.manifest.index_epoch,
                &bundle.manifest.root_hash,
                3,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );
        verify_private_result_oram_merkle_proof(
            &proof,
            bundle.manifest.index_epoch,
            &bundle.manifest.root_hash,
            bundle.manifest.bucket_count,
            &[bundle.buckets[1].clone()],
        )
        .unwrap();
        assert_eq!(
            store
                .read_initial_upload_bundle(128, 16 * 1024 * 1024)
                .unwrap(),
            bundle,
        );
        let oversized = store
            .read_initial_upload_bundle(128, 1)
            .unwrap_err()
            .to_string();
        assert!(oversized.contains("initial replication bundle is oversized"));
        assert!(!oversized.contains(&epoch.root_hash));
    }

    #[test]
    fn initial_upload_bundle_with_signature_verifies_manifest_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
        let bundle = signed_fixture_upload_bundle(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                128,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap();
        assert_eq!(epoch.index_epoch, bundle.manifest.index_epoch);
        assert_eq!(
            store.read_manifest().unwrap(),
            (bundle.manifest.clone(), bundle.manifest_signature.clone()),
        );

        let mut tampered = bundle.clone();
        tampered.manifest_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let rendered = store
            .write_initial_upload_bundle_with_signature(
                &tampered,
                128,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest signature verification failed"));
        assert!(!rendered.contains(&tampered.manifest_signature.sig));
        assert!(!rendered.contains(&tampered.manifest_signature.key_id));
        assert!(!rendered.contains(&tampered.manifest.root_hash));
        assert!(!rendered.contains(&tampered.buckets[0].ciphertext));
        assert!(!rendered.contains(&tampered.buckets[0].ciphertext_sha256));
        assert!(!rendered.contains(&tampered.buckets[0].bucket_commitment));
        assert!(
            !store.root_path().exists(),
            "invalid signed upload must not create private result ORAM layout"
        );
        assert!(matches!(
            store.read_current_epoch(),
            Err(CollectionError::NotFound { .. })
        ));
    }

    #[test]
    fn initial_upload_bundle_rejects_root_mismatch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let mut bundle = fixture_upload_bundle();
        let computed_root = PrivateResultOramStore::merkle_root_for_commitments(
            &bundle
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        bundle.manifest.root_hash = root_hash(99);
        assert_ne!(computed_root, bundle.manifest.root_hash);

        let err = store.write_initial_upload_bundle(&bundle, 128).unwrap_err();

        assert!(err.to_string().contains("Merkle root does not match"));
        assert!(!err.to_string().contains(&computed_root));
    }

    #[test]
    fn initial_upload_bundle_preflights_existing_epoch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let mut replacement = fixture_upload_bundle();
        replacement.buckets[0] = fixture_bucket(0, 42, b"replacement encrypted result bucket");
        let replacement_commitments = replacement
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        replacement.manifest.root_hash =
            PrivateResultOramStore::merkle_root_for_commitments(&replacement_commitments).unwrap();

        let err = store
            .write_initial_upload_bundle(&replacement, 128)
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("current epoch/root"));
        assert!(!rendered.contains("upload bundle"), "{rendered}");
        assert_eq!(store.read_manifest().unwrap().0, original.manifest);
        assert_eq!(
            store
                .read_bucket(0, original.manifest.index_epoch, 3, 128)
                .unwrap(),
            original.buckets[0],
        );
        let proof = store
            .read_merkle_path_batch(
                &[0],
                original.manifest.index_epoch,
                &original.manifest.root_hash,
                3,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            original.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_files_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let replacement = fixture_bucket(
            0,
            original.manifest.index_epoch,
            b"same root different encrypted result bucket",
        );
        assert_ne!(replacement, original.buckets[0]);
        store
            .write_bucket(&replacement, original.manifest.index_epoch, 3, 128)
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 128)
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
                .read_bucket(0, original.manifest.index_epoch, 3, 128)
                .unwrap(),
            replacement,
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_manifest_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let mut tampered_signature = original.manifest_signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        store
            .write_manifest(&original.manifest, &tampered_signature)
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 128)
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
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let tampered_bucket = fixture_bucket(
            1,
            original.manifest.index_epoch,
            b"tampered result bucket for merkle tree",
        );
        let mut tampered_commitments = original.bucket_commitments();
        tampered_commitments[1] = tampered_bucket.bucket_commitment.clone();
        let tampered_root =
            PrivateResultOramStore::merkle_root_for_commitments(&tampered_commitments).unwrap();
        assert_ne!(tampered_root, original.manifest.root_hash);
        store
            .write_merkle_tree_from_commitments(
                original.manifest.index_epoch,
                tampered_root.clone(),
                tampered_commitments,
            )
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 128)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("existing Merkle tree"));
        assert!(!rendered.contains(&tampered_root));
        assert!(!rendered.contains(&tampered_bucket.bucket_commitment));
        assert!(!rendered.contains(&original.manifest.root_hash));
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
        assert_eq!(store.read_merkle_tree().unwrap().root_hash, tampered_root);
    }

    #[test]
    fn writeback_commit_updates_bucket_merkle_and_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let updated_bucket = fixture_bucket(1, 43, b"updated result bucket 1");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let empty_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: old.root_hash.clone(),
        };
        let err = store
            .commit_writeback(&old, &empty_new, bundle.bucket_count(), &[], 128)
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));

        let committed = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                &[updated_bucket.clone()],
                128,
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(1, new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            updated_bucket,
        );
        assert_eq!(
            store
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[0],
        );
        let err = store
            .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains("1"), "{rendered}");
        let proof = store
            .read_merkle_path_batch(&[1], new.index_epoch, &new.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, updated_bucket.bucket_commitment);

        let err = store
            .commit_writeback(&old, &new, bundle.bucket_count(), &[], 128)
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));
    }

    #[test]
    fn writeback_commit_with_signature_verifies_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle();
        let updated_bucket = fixture_bucket(1, 43, b"updated signed result bucket 1");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let plan = PrivateResultOramCommitPlan {
            old_epoch: bundle.manifest.index_epoch,
            new_epoch: new.index_epoch,
            old_root_hash: bundle.manifest.root_hash.clone(),
            new_root_hash: new.root_hash.clone(),
            leaf_commitments: next_commitments,
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let signature = sign_private_result_oram_commit(
            &key_pair,
            PrivateResultOramCommitSignatureContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/result-private-rk",
                rk_id: "tenant-a/result-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-result-signing-v1",
            },
            &plan,
        )
        .unwrap();

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let committed = store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(1, new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            updated_bucket,
        );

        let second_updated_bucket = fixture_bucket(2, 44, b"updated signed result bucket 2");
        let mut second_commitments = bundle.bucket_commitments();
        second_commitments[1] = updated_bucket.bucket_commitment.clone();
        second_commitments[2] = second_updated_bucket.bucket_commitment.clone();
        let second_new = PrivateResultOramEpochState {
            index_epoch: 44,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&second_commitments)
                .unwrap(),
        };
        let second_plan = PrivateResultOramCommitPlan {
            old_epoch: new.index_epoch,
            new_epoch: second_new.index_epoch,
            old_root_hash: new.root_hash.clone(),
            new_root_hash: second_new.root_hash.clone(),
            leaf_commitments: second_commitments,
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: second_updated_bucket.bucket_id,
                ciphertext_sha256: second_updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let second_signature = sign_private_result_oram_commit(
            &key_pair,
            PrivateResultOramCommitSignatureContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/result-private-rk",
                rk_id: "tenant-a/result-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-result-signing-v1",
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
                128,
                &second_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap();

        assert_eq!(second_committed, second_new);
        assert_eq!(store.read_current_epoch().unwrap(), second_new);
        assert_eq!(store.read_manifest().unwrap().0, bundle.manifest);
        assert_eq!(
            store
                .read_bucket(2, second_new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            second_updated_bucket,
        );
        let proof = store
            .read_merkle_path_batch(
                &[2],
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
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        let mut tampered_signature = signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let rendered = tampered_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &tampered_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
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
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = tampered_store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let unsupported_alg_store = fixture_store(&temp);
        let old = unsupported_alg_store
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        let mut unsupported_alg_signature = signature.clone();
        unsupported_alg_signature.alg = "rsa-pss-result-sentinel".to_string();
        let rendered = unsupported_alg_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &unsupported_alg_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
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
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = unsupported_alg_store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let wrong_key_store = fixture_store(&temp);
        let old = wrong_key_store
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        let mut wrong_key_signature = signature.clone();
        wrong_key_signature.key_id = "tenant-a/private-result-signing-v2".to_string();
        let rendered = wrong_key_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &wrong_key_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
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
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = wrong_key_store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
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
            let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
            let signature_verification = || PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/private-result-signing-v1",
                public_key: public_key.as_ref(),
            };

            let consensus_writeback = store
                .prepare_durable_writeback_with_signature(
                    &old,
                    &new,
                    bundle.bucket_count(),
                    std::slice::from_ref(&updated_bucket),
                    128,
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
                        128,
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
                        128,
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

            let pending: PrivateResultPendingWriteback = read_json_private_file(
                &store.pending_writeback_path(),
                MAX_PENDING_WRITEBACK_BYTES,
            )
            .unwrap();
            if crash_window >= 1 {
                store
                    .write_bucket(&updated_bucket, new.index_epoch, bundle.bucket_count(), 128)
                    .unwrap();
                store
                    .write_merkle_tree_for_offline_corruption_test(&pending.merkle_tree)
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
                        128,
                        &signature,
                        signature_verification(),
                    )
                    .unwrap()
            } else {
                store
                    .recover_pending_writeback_with_signature(128, signature_verification())
                    .unwrap()
                    .unwrap()
            };

            assert_eq!(committed, new);
            assert_eq!(store.read_current_epoch().unwrap(), new);
            assert_eq!(
                store
                    .read_bucket(1, new.index_epoch, bundle.bucket_count(), 128)
                    .unwrap(),
                updated_bucket,
            );
            let proof = store
                .read_merkle_path_batch(
                    &[1],
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
                        128,
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
        let old = source.write_initial_upload_bundle(&bundle, 128).unwrap();
        assert_eq!(
            replica.write_initial_upload_bundle(&bundle, 128).unwrap(),
            old,
        );
        let signature_verification = || PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: public_key.as_ref(),
        };

        let prepared = source
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                signature_verification(),
            )
            .unwrap();
        let (batch, exported) = source
            .pending_writeback_replication_batch_with_signature(128, signature_verification())
            .unwrap()
            .unwrap();
        assert_eq!(exported, prepared);

        for pending_initial_replication in [
            source
                .read_initial_upload_bundle(128, 16 * 1024 * 1024)
                .unwrap_err(),
            source
                .write_initial_upload_bundle(&bundle, 128)
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
                128,
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
                128,
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
                128,
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
                    128,
                    signature_verification(),
                )
                .unwrap_err(),
            replica
                .abort_replica_writeback_with_signature(
                    &conflicting_consensus,
                    128,
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
                .commit_replica_writeback_with_signature(&exported, 128, signature_verification(),)
                .unwrap(),
            new,
        );
        assert_eq!(
            replica
                .prepare_replica_writeback_with_signature(
                    &batch,
                    &exported,
                    128,
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
                .read_bucket(1, new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            updated_bucket,
        );
        let advanced = replica
            .read_initial_upload_bundle(128, 16 * 1024 * 1024)
            .unwrap_err()
            .to_string();
        assert!(advanced.contains("requires the manifest epoch"));
        assert!(!advanced.contains(&new.root_hash));
    }

    #[test]
    fn live_replication_bundle_installs_advanced_signed_state() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[53; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (mut bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);
        bundle.manifest_signature =
            sign_private_result_oram_manifest(&key_pair, &bundle.manifest).unwrap();
        let source_temp = TempDir::new().unwrap();
        let target_temp = TempDir::new().unwrap();
        let source = fixture_store(&source_temp);
        let target = fixture_store(&target_temp);
        let old = source.write_initial_upload_bundle(&bundle, 128).unwrap();
        let verification = || PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: public_key.as_ref(),
        };

        source
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                verification(),
            )
            .unwrap();
        let unrefreshed = source
            .read_live_replication_bundle(128, 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(unrefreshed.manifest.index_epoch, old.index_epoch);
        let mut refreshed_manifest = unrefreshed.manifest.clone();
        refreshed_manifest.index_epoch = new.index_epoch;
        refreshed_manifest.root_hash = new.root_hash.clone();
        let refreshed_signature =
            sign_private_result_oram_manifest(&key_pair, &refreshed_manifest).unwrap();
        source
            .write_manifest(&refreshed_manifest, &refreshed_signature)
            .unwrap();
        let exported = source
            .read_live_replication_bundle(128, 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(exported.current, new);
        assert_eq!(exported.manifest.index_epoch, new.index_epoch);
        assert!(exported.writeback_digest.is_some());
        assert_eq!(exported.buckets[1], updated_bucket);
        assert_eq!(exported.buckets[0].index_epoch, old.index_epoch);
        assert_eq!(exported.buckets[2].index_epoch, old.index_epoch);

        let installed = target
            .write_live_replication_bundle_with_signature(
                &exported,
                128,
                fixture_validation_context(public_key.as_ref()),
                &new,
                exported.writeback_digest.as_deref(),
            )
            .unwrap();
        assert_eq!(installed, new);
        assert_eq!(
            target
                .read_live_replication_bundle(128, 16 * 1024 * 1024)
                .unwrap(),
            exported,
        );
        assert_eq!(
            target
                .write_live_replication_bundle_with_signature(
                    &exported,
                    128,
                    fixture_validation_context(public_key.as_ref()),
                    &new,
                    exported.writeback_digest.as_deref(),
                )
                .unwrap(),
            new,
        );

        let mismatch_temp = TempDir::new().unwrap();
        let mismatch_target = fixture_store(&mismatch_temp);
        let mismatched_consensus = PrivateResultOramEpochState {
            root_hash: root_hash(98),
            ..new.clone()
        };
        let rendered = mismatch_target
            .write_live_replication_bundle_with_signature(
                &exported,
                128,
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
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let signature_verification = || PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: public_key.as_ref(),
        };

        store
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                signature_verification(),
            )
            .unwrap();
        let mut pending: PrivateResultPendingWriteback =
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
            .commit_prepared_writeback_with_signature(128, signature_verification())
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
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        assert!(store.pending_writeback_path().exists());
    }

    #[test]
    fn durable_signed_writeback_abort_requires_unmodified_old_view() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[43; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);
        let signature_verification = || PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: public_key.as_ref(),
        };

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        store
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                signature_verification(),
            )
            .unwrap();
        assert!(
            store
                .abort_pending_writeback_with_signature(128, signature_verification())
                .unwrap()
        );
        assert!(!store.pending_writeback_exists().unwrap());
        assert_eq!(store.read_current_epoch().unwrap(), old);

        let temp = TempDir::new().unwrap();
        let partially_written_store = fixture_store(&temp);
        let old = partially_written_store
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        partially_written_store
            .prepare_durable_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                signature_verification(),
            )
            .unwrap();
        partially_written_store
            .write_bucket(&updated_bucket, new.index_epoch, bundle.bucket_count(), 128)
            .unwrap();
        let rendered = partially_written_store
            .abort_pending_writeback_with_signature(128, signature_verification())
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains(&updated_bucket.ciphertext));
        assert!(partially_written_store.pending_writeback_exists().unwrap());
        assert_eq!(partially_written_store.read_current_epoch().unwrap(), old);
    }

    #[test]
    fn writeback_commit_preflights_stale_current_epoch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let stale_current = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let updated_bucket = fixture_bucket(0, 43, b"stale writeback bucket");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[0] = updated_bucket.bucket_commitment.clone();
        let attempted_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &attempted_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale_current.root_hash), "{rendered}");
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 128)
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
    fn writeback_commit_rejects_non_advancing_epoch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let original_bucket = bundle.buckets[0].clone();
        let updated_bucket =
            fixture_bucket(0, old.index_epoch, b"private-result-non-advancing-sentinel");
        let non_advancing_new = PrivateResultOramEpochState {
            index_epoch: old.index_epoch,
            root_hash: root_hash(99),
        };

        let err = store
            .commit_writeback(
                &old,
                &non_advancing_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();

        assert!(err.contains("new epoch must be exactly old epoch + 1"));
        assert!(!err.contains("private-result-non-advancing-sentinel"));
        assert!(!err.contains(&updated_bucket.ciphertext));
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            original_bucket
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
    }

    #[test]
    fn writeback_commit_rejects_bucket_commitment_context_mismatch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let valid_bucket = fixture_bucket(1, 43, b"updated result bucket 1");
        let mut invalid_bucket = valid_bucket.clone();
        invalid_bucket.bucket_commitment = root_hash(88);
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = invalid_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&invalid_bucket),
                128,
            )
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("commit bucket commitment context mismatch")
        );
        assert_eq!(
            store
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1]
        );
        let proof = store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_rejects_invalid_bucket_and_root_mismatch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let original_bucket = bundle.buckets[1].clone();
        let assert_writeback_target_unchanged = || {
            assert_eq!(store.read_current_epoch().unwrap(), old);
            assert_eq!(
                store
                    .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                    .unwrap(),
                original_bucket
            );
            let proof = store
                .read_merkle_path_batch(
                    &[1],
                    old.index_epoch,
                    &old.root_hash,
                    bundle.bucket_count(),
                )
                .unwrap();
            assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
        };

        let mut hash_mismatch_bucket = fixture_bucket(1, 43, b"hash mismatch result bucket");
        hash_mismatch_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"private-result-writeback-ciphertext-sentinel");
        let mut hash_mismatch_commitments = bundle.bucket_commitments();
        hash_mismatch_commitments[1] = hash_mismatch_bucket.bucket_commitment.clone();
        let hash_mismatch_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(
                &hash_mismatch_commitments,
            )
            .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &hash_mismatch_new,
                bundle.bucket_count(),
                std::slice::from_ref(&hash_mismatch_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("ciphertext_sha256 mismatch"));
        assert!(!err.contains("private-result-writeback-ciphertext-sentinel"));
        assert!(!err.contains(&hash_mismatch_bucket.ciphertext));
        assert!(!err.contains(&hash_mismatch_bucket.ciphertext_sha256));
        assert!(!err.contains(&hash_mismatch_bucket.bucket_commitment));
        assert_writeback_target_unchanged();

        let mut short_ciphertext_bucket =
            fixture_bucket(1, 43, b"valid hash with short result bucket");
        let short_raw = b"short-result-commit";
        let short_hash = BASE64URL_NOPAD.encode(Sha256::digest(short_raw).as_ref());
        short_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(short_raw);
        short_ciphertext_bucket.ciphertext_sha256 = short_hash.clone();
        short_ciphertext_bucket.bucket_commitment = fixture_bucket_commitment(1, 43, &short_hash);
        let mut short_ciphertext_commitments = bundle.bucket_commitments();
        short_ciphertext_commitments[1] = short_ciphertext_bucket.bucket_commitment.clone();
        let short_ciphertext_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(
                &short_ciphertext_commitments,
            )
            .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &short_ciphertext_new,
                bundle.bucket_count(),
                std::slice::from_ref(&short_ciphertext_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains("short-result-commit"));
        assert!(!err.contains(&short_ciphertext_bucket.ciphertext));
        assert!(!err.contains(&short_ciphertext_bucket.ciphertext_sha256));
        assert!(!err.contains(&short_ciphertext_bucket.bucket_commitment));
        assert_writeback_target_unchanged();

        let expected_bytes =
            private_result_oram_bucket_ciphertext_bytes(&bundle.manifest.oram).unwrap();
        let mut long_ciphertext_bucket =
            fixture_bucket(1, 43, b"valid hash with long result bucket");
        let long_raw = vec![7; expected_bytes + 1];
        let long_hash = BASE64URL_NOPAD.encode(Sha256::digest(&long_raw).as_ref());
        long_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(&long_raw);
        long_ciphertext_bucket.ciphertext_sha256 = long_hash.clone();
        long_ciphertext_bucket.bucket_commitment = fixture_bucket_commitment(1, 43, &long_hash);
        let mut long_ciphertext_commitments = bundle.bucket_commitments();
        long_ciphertext_commitments[1] = long_ciphertext_bucket.bucket_commitment.clone();
        let long_ciphertext_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(
                &long_ciphertext_commitments,
            )
            .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &long_ciphertext_new,
                bundle.bucket_count(),
                std::slice::from_ref(&long_ciphertext_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains(&long_ciphertext_bucket.ciphertext));
        assert!(!err.contains(&long_ciphertext_bucket.ciphertext_sha256));
        assert!(!err.contains(&long_ciphertext_bucket.bucket_commitment));
        assert_writeback_target_unchanged();

        let valid_bucket = fixture_bucket(1, 43, b"valid result bucket with wrong root");
        let wrong_root_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(99),
        };

        let err = store
            .commit_writeback(
                &old,
                &wrong_root_new,
                bundle.bucket_count(),
                std::slice::from_ref(&valid_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("new_root_hash mismatch"));
        assert!(!err.contains(&wrong_root_new.root_hash), "{err}");
        assert!(!err.contains(&valid_bucket.ciphertext), "{err}");
        assert!(!err.contains(&valid_bucket.ciphertext_sha256), "{err}");
        assert!(!err.contains(&valid_bucket.bucket_commitment), "{err}");
        assert_writeback_target_unchanged();
    }

    #[test]
    fn writeback_commit_allows_manifest_epoch_root_to_remain_at_upload_anchor() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.root_hash = root_hash(99);
        assert_ne!(tampered_manifest.root_hash, old.root_hash);
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let updated_bucket = fixture_bucket(1, 43, b"manifest drift result bucket");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let attempted_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let committed = store
            .commit_writeback(
                &old,
                &attempted_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap();

        assert_eq!(committed, attempted_new);
        assert_eq!(store.read_current_epoch().unwrap(), attempted_new);
        assert_eq!(
            store
                .read_bucket(1, attempted_new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            updated_bucket,
        );
        assert_eq!(store.read_manifest().unwrap().0, tampered_manifest);
    }

    #[test]
    fn writeback_commit_preflights_manifest_bucket_count_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.bucket_count += 1;
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"manifest bucket count drift");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[2] = updated_bucket.bucket_commitment.clone();
        let attempted_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &attempted_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();

        assert!(err.to_string().contains("manifest bucket_count"));
        let rendered = err.to_string();
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
                .read_bucket(2, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[2]
        );
        let proof = store
            .read_merkle_path_batch(&[2], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[2].bucket_commitment
        );
    }

    #[test]
    fn merkle_commit_updates_root_consistently() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap(),
            old_root,
        );
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated result bucket");
        let mut next_commitments = leaf_commitments;
        next_commitments[2] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateResultOramStore::merkle_root_for_commitments(&next_commitments).unwrap();

        let wrong_new_root = root_hash(99);
        assert_ne!(wrong_new_root, new_root);
        let err = store
            .write_merkle_commit_for_offline_corruption_test(42, &old_root, 43, &old_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));

        let err = store
            .write_merkle_commit_for_offline_corruption_test(
                42,
                &old_root,
                43,
                &wrong_new_root,
                4,
                &[updated_bucket.clone()],
            )
            .unwrap_err();
        assert!(err.to_string().contains("new_root_hash mismatch"));
        assert!(!err.to_string().contains(&new_root));

        store
            .write_merkle_commit_for_offline_corruption_test(
                42,
                &old_root,
                43,
                &new_root,
                4,
                &[updated_bucket],
            )
            .unwrap();

        let err = store
            .write_merkle_commit_for_offline_corruption_test(42, &old_root, 43, &new_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));
    }

    #[test]
    fn merkle_commit_rejects_duplicate_bucket_updates() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2)];
        let old_root =
            PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments)
            .unwrap();

        let first = fixture_bucket(1, 43, b"first update");
        let second = fixture_bucket(1, 43, b"second update");

        let err = store
            .write_merkle_commit_for_offline_corruption_test(
                42,
                &old_root,
                43,
                &root_hash(43),
                2,
                &[first, second],
            )
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("repeats a bucket"));
        assert!(!rendered.contains("1"), "{rendered}");
    }

    #[test]
    fn merkle_path_batch_returns_leaf_hashes_and_siblings() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket0 = fixture_bucket(0, 42, b"encrypted result bucket 0");
        let bucket1 = fixture_bucket(1, 42, b"encrypted result bucket 1");
        let bucket2 = fixture_bucket(2, 42, b"encrypted result bucket 2");
        let leaf_commitments = vec![
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
            bucket2.bucket_commitment.clone(),
        ];
        let root = PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, root.clone(), leaf_commitments.clone())
            .unwrap();

        let proof = store.read_merkle_path_batch(&[0, 2], 42, &root, 3).unwrap();
        assert_eq!(proof.kind, PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND);
        assert_eq!(proof.index_epoch, 42);
        assert_eq!(proof.root_hash, root);
        assert_eq!(proof.bucket_count, 3);
        assert_eq!(proof.leaves[0].bucket_id, 0);
        assert_eq!(proof.leaves[0].leaf_hash, leaf_commitments[0]);
        assert_eq!(proof.leaves[1].bucket_id, 2);
        assert_eq!(proof.leaves[1].leaf_hash, leaf_commitments[2]);
        assert_eq!(
            proof.leaves[0].siblings[0].position,
            PrivateResultOramMerkleSiblingPosition::Right
        );
        assert_eq!(
            proof.leaves[1].siblings[0].position,
            PrivateResultOramMerkleSiblingPosition::Right
        );

        let duplicate_proof = store
            .read_merkle_path_batch(&[0, 2, 0], 42, &root, 3)
            .unwrap();
        assert_eq!(duplicate_proof.leaves.len(), 3);
        assert_eq!(duplicate_proof.leaves[0], duplicate_proof.leaves[2]);
        verify_private_result_oram_merkle_proof(
            &duplicate_proof,
            42,
            &root,
            3,
            &[bucket0.clone(), bucket2.clone(), bucket0.clone()],
        )
        .unwrap();
        let duplicate_proof_json = serde_json::to_string(&duplicate_proof).unwrap();
        verify_private_result_oram_merkle_proof_json(
            &duplicate_proof_json,
            42,
            &root,
            3,
            &[bucket0.clone(), bucket2, bucket0],
        )
        .unwrap();

        let err = store.read_merkle_path_batch(&[], 42, &root, 3).unwrap_err();
        assert!(err.to_string().contains("bucket batch is empty"));

        let err = store
            .read_merkle_path_batch(&[3], 42, &root, 3)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("3"), "{rendered}");

        let sentinel_bucket_id = 987_654_321_u64;
        let err = store
            .read_merkle_path_batch(&[sentinel_bucket_id], 42, &root, 3)
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
        let bundle = fixture_upload_bundle();
        let current = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let (buckets, proof) = store
            .read_bucket_batch_with_proof(
                &[0, 2, 0],
                current.index_epoch,
                &current.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap();

        assert_eq!(
            buckets,
            vec![
                bundle.buckets[0].clone(),
                bundle.buckets[2].clone(),
                bundle.buckets[0].clone(),
            ]
        );
        assert_eq!(proof.leaves.len(), buckets.len());
        assert_eq!(proof.leaves[0], proof.leaves[2]);
        verify_private_result_oram_merkle_proof(
            &proof,
            current.index_epoch,
            &current.root_hash,
            bundle.bucket_count(),
            &buckets,
        )
        .unwrap();

        let replacement = fixture_bucket(
            2,
            current.index_epoch,
            b"private-result-read-bucket-mismatch-sentinel",
        );
        assert_ne!(
            replacement.bucket_commitment,
            bundle.buckets[2].bucket_commitment
        );
        store
            .write_bucket(
                &replacement,
                current.index_epoch,
                bundle.bucket_count(),
                128,
            )
            .unwrap();
        let rendered = store
            .read_bucket_batch_with_proof(
                &[2],
                current.index_epoch,
                &current.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("encrypted bucket/proof consistency validation failed"));
        assert!(!rendered.contains("private-result-read-bucket-mismatch-sentinel"));
        assert!(!rendered.contains(&replacement.ciphertext));
        assert!(!rendered.contains(&replacement.ciphertext_sha256));
        assert!(!rendered.contains(&replacement.bucket_commitment));

        let rendered = store
            .read_bucket_batch_with_proof(
                &[],
                current.index_epoch,
                &current.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket batch is empty"));
    }

    #[test]
    fn read_bucket_batch_with_proof_preflights_stale_current_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let stale_current = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let rendered = store
            .read_bucket_batch_with_proof(
                &[1],
                old.index_epoch,
                &old.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale_current.root_hash), "{rendered}");
        assert_eq!(
            store
                .read_bucket(1, stale_current.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
    }

    #[test]
    fn crash_window_before_epoch_cas_fails_closed_instead_of_serving_mixed_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_bucket = fixture_bucket(0, 42, b"old result bucket");
        let other_bucket = fixture_bucket(1, 42, b"other result bucket");
        let old_commitments = vec![
            old_bucket.bucket_commitment.clone(),
            other_bucket.bucket_commitment.clone(),
        ];
        let old_root =
            PrivateResultOramStore::merkle_root_for_commitments(&old_commitments).unwrap();
        let old_epoch = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: old_root.clone(),
        };

        store.write_initial_epoch(&old_epoch).unwrap();
        store.write_bucket(&old_bucket, 42, 2, 128).unwrap();
        store.write_bucket(&other_bucket, 42, 2, 128).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), old_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(0, 43, b"new result bucket");
        store.write_bucket(&updated_bucket, 43, 2, 128).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), old_epoch);
        let rendered = store.read_bucket(0, 42, 2, 128).unwrap_err().to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("0"), "{rendered}");

        let mut new_commitments = old_commitments;
        new_commitments[0] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateResultOramStore::merkle_root_for_commitments(&new_commitments).unwrap();
        store
            .write_merkle_commit_for_offline_corruption_test(
                42,
                &old_root,
                43,
                &new_root,
                2,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), old_epoch);
        let rendered = store
            .read_merkle_path_batch(&[0], 42, &old_root, 2)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("epoch mismatch"));
    }

    #[test]
    fn merkle_tree_validation_rejects_root_mismatch_without_computed_root() {
        let tree = PrivateResultOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: root_hash(99),
            bucket_count: 2,
            leaf_hashes: vec![root_hash(1), root_hash(2)],
        };
        let computed_root =
            PrivateResultOramStore::merkle_root_for_commitments(&tree.leaf_hashes).unwrap();
        assert_ne!(computed_root, tree.root_hash);

        let err = validate_merkle_tree(&tree).unwrap_err();

        assert!(err.to_string().contains("root_hash mismatch"));
        assert!(!err.to_string().contains(&computed_root));
    }

    #[test]
    fn epoch_cas_rejects_stale_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let stale = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(41),
        };
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };

        store.write_initial_epoch(&old).unwrap();
        let err = store.compare_and_swap_epoch(&stale, &new).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("41"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale.root_hash), "{rendered}");
        assert!(!rendered.contains(&new.root_hash), "{rendered}");

        store.compare_and_swap_epoch(&old, &new).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), new);
    }

    #[test]
    fn owner_store_tokens_require_exact_canonical_state_and_bind_result_index_name() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (mut bundle, updated_bucket, new_epoch, _) = fixture_signed_commit_update(&key_pair);
        bundle.manifest_signature =
            sign_private_result_oram_manifest(&key_pair, &bundle.manifest).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                128,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let index_name = "private-result-index";
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch, index_name);
        let final_buckets = vec![updated_bucket.clone()];
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(72);
        let prepared_state_digest = root_hash(73);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest, index_name);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            index_name,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );

        let context_debug = format!("{context:?}");
        for secret in [
            journal_descriptor_digest.as_str(),
            prepared_state_digest.as_str(),
            immutable_manifest_digest.as_str(),
            index_name,
            final_buckets[0].ciphertext.as_str(),
        ] {
            assert!(!context_debug.contains(secret), "{context_debug}");
        }

        let lock = store.lock_owner_store_v1().unwrap();
        let initial_old_token = lock.verify_exact_old(context).unwrap();
        assert_eq!(initial_old_token.index_name(), index_name);
        assert_eq!(initial_old_token.canonical_state_digest().len(), 43);
        let old_debug = format!("{initial_old_token:?}");
        assert!(!old_debug.contains(index_name));
        assert!(!old_debug.contains(initial_old_token.canonical_state_digest()));

        let alternate_index_name = "private-result-index-shadow";
        let (alternate_old_state, alternate_new_state) =
            fixture_owner_states(&bundle.manifest, &new_epoch, alternate_index_name);
        let alternate_immutable_manifest =
            fixture_owner_immutable_manifest(&bundle.manifest, alternate_index_name);
        let alternate_immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&alternate_immutable_manifest).unwrap();
        let alternate_context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &alternate_immutable_manifest_digest,
            &alternate_immutable_manifest,
            alternate_index_name,
            &alternate_old_state,
            &alternate_new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );
        let alternate_token = lock.verify_exact_old(alternate_context).unwrap();
        assert_ne!(
            initial_old_token.canonical_state_digest(),
            alternate_token.canonical_state_digest()
        );
        let initial_old_digest = initial_old_token.canonical_state_digest().to_string();
        drop(alternate_token);
        drop(initial_old_token);
        drop(lock);

        write_json_atomic(
            &store.root,
            &store.temp_dir(),
            &store.commit_epoch_path(old_state.index_epoch),
            &PrivateResultOramEpochCommit {
                index_epoch: old_state.index_epoch,
                root_hash: old_state.root_hash.clone(),
                writeback_digest: Some(old_state.last_writeback_digest.clone()),
            },
        )
        .unwrap();
        let lock = store.lock_owner_store_v1().unwrap();
        let digest_bound_old_token = lock.verify_exact_old(context).unwrap();
        assert_ne!(
            initial_old_digest,
            digest_bound_old_token.canonical_state_digest()
        );
        let digest_bound_old_digest = digest_bound_old_token.canonical_state_digest().to_string();
        drop(digest_bound_old_token);
        drop(lock);

        store
            .write_bucket(
                &updated_bucket,
                new_epoch.index_epoch,
                bundle.bucket_count(),
                128,
            )
            .unwrap();
        store
            .write_merkle_commit_for_offline_corruption_test(
                old_epoch.index_epoch,
                &old_epoch.root_hash,
                new_epoch.index_epoch,
                &new_epoch.root_hash,
                bundle.bucket_count(),
                &final_buckets,
            )
            .unwrap();
        store
            .compare_and_swap_epoch_with_writeback_digest_for_offline_corruption_test(
                &old_epoch,
                &new_epoch,
                Some(&new_state.last_writeback_digest),
            )
            .unwrap();

        let lock = store.lock_owner_store_v1().unwrap();
        let new_token = lock.verify_exact_new(context).unwrap();
        assert_eq!(new_token.index_name(), index_name);
        assert_eq!(new_token.canonical_state_digest().len(), 43);
        assert_ne!(digest_bound_old_digest, new_token.canonical_state_digest());
        let new_debug = format!("{new_token:?}");
        assert!(!new_debug.contains(index_name));
        assert!(!new_debug.contains(new_token.canonical_state_digest()));
    }

    #[test]
    fn owner_store_exact_old_rejects_legacy_pending_and_concurrent_verifier() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (mut bundle, updated_bucket, new_epoch, _) = fixture_signed_commit_update(&key_pair);
        bundle.manifest_signature =
            sign_private_result_oram_manifest(&key_pair, &bundle.manifest).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                128,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let index_name = "private-result-index";
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch, index_name);
        let final_buckets = vec![updated_bucket];
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(72);
        let prepared_state_digest = root_hash(73);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest, index_name);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            index_name,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );

        let lock = store.lock_owner_store_v1().unwrap();
        let error = store.lock_owner_store_v1().unwrap_err().to_string();
        assert!(error.contains("another private result ORAM owner store operation"));
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
            &PrivateResultOramEpochCommit {
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
    fn owner_store_exact_new_rejects_missing_digest_commit_and_bucket_body_mismatch() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public_key = key_pair.public_key();
        let (mut bundle, updated_bucket, new_epoch, _) = fixture_signed_commit_update(&key_pair);
        bundle.manifest_signature =
            sign_private_result_oram_manifest(&key_pair, &bundle.manifest).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                128,
                fixture_validation_context(public_key.as_ref()),
            )
            .unwrap();
        let index_name = "private-result-index";
        let (old_state, new_state) = fixture_owner_states(&bundle.manifest, &new_epoch, index_name);
        let final_buckets = vec![updated_bucket.clone()];
        let final_bucket_refs = fixture_owner_bucket_refs(&final_buckets);
        let journal_descriptor_digest = root_hash(72);
        let prepared_state_digest = root_hash(73);
        let immutable_manifest = fixture_owner_immutable_manifest(&bundle.manifest, index_name);
        let immutable_manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let context = fixture_owner_store_context(
            &journal_descriptor_digest,
            &prepared_state_digest,
            &immutable_manifest_digest,
            &immutable_manifest,
            index_name,
            &old_state,
            &new_state,
            &final_bucket_refs,
            &final_buckets,
            public_key.as_ref(),
        );

        store
            .write_bucket(
                &updated_bucket,
                new_epoch.index_epoch,
                bundle.bucket_count(),
                128,
            )
            .unwrap();
        store
            .write_merkle_commit_for_offline_corruption_test(
                old_epoch.index_epoch,
                &old_epoch.root_hash,
                new_epoch.index_epoch,
                &new_epoch.root_hash,
                bundle.bucket_count(),
                &final_buckets,
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
            &PrivateResultOramEpochCommit {
                index_epoch: new_epoch.index_epoch,
                root_hash: new_epoch.root_hash.clone(),
                writeback_digest: Some(new_state.last_writeback_digest.clone()),
            },
        )
        .unwrap();
        let replacement = fixture_bucket(
            updated_bucket.bucket_id,
            updated_bucket.index_epoch,
            b"mismatched owner result bucket body",
        );
        let mut mismatched_bucket = updated_bucket;
        mismatched_bucket.ciphertext = replacement.ciphertext.clone();
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
                || error.contains("ciphertext hash mismatch")
                || error.contains("canonical store state does not match")
        );
        assert!(!error.contains(&final_buckets[0].ciphertext));
        assert!(!error.contains(&final_buckets[0].ciphertext_sha256));
        assert!(!error.contains(&replacement.ciphertext));
    }

    #[test]
    fn owner_recovery_resumes_every_s0_through_s4_crash_prefix_to_exact_new() {
        let states = [
            PrivateResultOwnerRecoveryProgressV1::S0,
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix: 1 },
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix: 2 },
            PrivateResultOwnerRecoveryProgressV1::S2,
            PrivateResultOwnerRecoveryProgressV1::S3,
            PrivateResultOwnerRecoveryProgressV1::S4,
        ];
        for target in states {
            with_owner_recovery_fixture(move |store, context| {
                let lock = store.lock_owner_store_v1().unwrap();
                advance_owner_recovery_fixture_to(&lock, context, target);

                let token = lock
                    .resume_owner_recovery_context_to_exact_new_v1(context)
                    .unwrap();
                assert_eq!(token.index_name(), context.index_name);
                assert_eq!(token.canonical_state_digest().len(), 43);
                drop(token);
                assert_eq!(
                    lock.revalidated_owner_recovery_snapshot_v1(context)
                        .unwrap()
                        .progress,
                    PrivateResultOwnerRecoveryProgressV1::S4,
                );

                let replay = lock
                    .resume_owner_recovery_context_to_exact_new_v1(context)
                    .unwrap();
                assert_eq!(replay.index_name(), context.index_name);
            });
        }
    }

    #[test]
    fn owner_recovery_accepts_affected_bucket_older_than_old_epoch() {
        with_owner_recovery_fixture(|store, context| {
            let older_epoch = context.old_state.index_epoch.checked_sub(1).unwrap();
            let mut manifest = store.read_manifest().unwrap().0;
            manifest.index_epoch = older_epoch;
            let key_pair = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
            let signature = sign_private_result_oram_manifest(&key_pair, &manifest).unwrap();
            store.write_manifest(&manifest, &signature).unwrap();

            let older_bucket = fixture_bucket(
                context.final_buckets[0].bucket_id,
                older_epoch,
                b"encrypted result bucket 0",
            );
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.bucket_path(older_bucket.bucket_id),
                &older_bucket,
            )
            .unwrap();

            let mut old_tree = store.read_merkle_tree().unwrap();
            old_tree.leaf_hashes[usize::try_from(older_bucket.bucket_id).unwrap()] =
                older_bucket.bucket_commitment.clone();
            old_tree.root_hash =
                PrivateResultOramStore::merkle_root_for_commitments(&old_tree.leaf_hashes).unwrap();
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.merkle_nodes_path(),
                &old_tree,
            )
            .unwrap();

            let mut old_state = context.old_state.clone();
            old_state.root_hash = old_tree.root_hash.clone();
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.commit_epoch_path(old_state.index_epoch),
                &PrivateResultOramEpochCommit {
                    index_epoch: old_state.index_epoch,
                    root_hash: old_state.root_hash.clone(),
                    writeback_digest: Some(old_state.last_writeback_digest.clone()),
                },
            )
            .unwrap();
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.current_epoch_path(),
                &PrivateResultOramEpochState {
                    index_epoch: old_state.index_epoch,
                    root_hash: old_state.root_hash.clone(),
                },
            )
            .unwrap();

            let context = PrivateResultOwnerStoreVerificationContextV1 {
                old_state: &old_state,
                ..context
            };
            let lock = store.lock_owner_store_v1().unwrap();
            lock.verify_exact_old(context).unwrap();
            assert_eq!(
                lock.revalidated_owner_recovery_snapshot_v1(context)
                    .unwrap()
                    .progress,
                PrivateResultOwnerRecoveryProgressV1::S0,
            );
            lock.resume_owner_recovery_context_to_exact_new_v1(context)
                .unwrap();
        });
    }

    #[test]
    fn owner_recovery_rejects_non_prefix_bucket_progress() {
        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            let second = &context.final_buckets[1];
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.bucket_path(second.bucket_id),
                second,
            )
            .unwrap();

            let error = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(error.contains("canonical store state does not match"));
            assert!(!error.contains(&second.ciphertext));
            assert!(!error.contains(&second.ciphertext_sha256));
        });
    }

    #[test]
    fn owner_recovery_rejects_wrong_commit_and_current_combinations() {
        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            advance_owner_recovery_fixture_to(
                &lock,
                context,
                PrivateResultOwnerRecoveryProgressV1::S2,
            );
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.commit_epoch_path(context.new_state.index_epoch),
                &PrivateResultOramEpochCommit {
                    index_epoch: context.new_state.index_epoch,
                    root_hash: root_hash(91),
                    writeback_digest: Some(context.new_state.last_writeback_digest.clone()),
                },
            )
            .unwrap();

            let error = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(error.contains("canonical store state does not match"));
            assert!(!error.contains(&context.new_state.root_hash));
            assert!(!error.contains(&context.new_state.last_writeback_digest));
        });

        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            let new_current = PrivateResultOramEpochState {
                index_epoch: context.new_state.index_epoch,
                root_hash: context.new_state.root_hash.clone(),
            };
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.current_epoch_path(),
                &new_current,
            )
            .unwrap();

            let error = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(error.contains("canonical store state does not match"));
            assert!(!error.contains(&context.new_state.root_hash));
        });
    }

    #[test]
    fn owner_recovery_rejects_wrong_bucket_merkle_and_legacy_pending_state() {
        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            let mut wrong_body = context.final_buckets[0].clone();
            wrong_body.ciphertext = context.final_buckets[1].ciphertext.clone();
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.bucket_path(wrong_body.bucket_id),
                &wrong_body,
            )
            .unwrap();

            let rendered = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(!rendered.contains(&wrong_body.ciphertext));
            assert!(!rendered.contains(&wrong_body.ciphertext_sha256));
        });

        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            let mut wrong_hash = context.final_buckets[0].clone();
            wrong_hash.ciphertext_sha256 = root_hash(92);
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.bucket_path(wrong_hash.bucket_id),
                &wrong_hash,
            )
            .unwrap();

            let rendered = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(!rendered.contains(&wrong_hash.ciphertext));
            assert!(!rendered.contains(&wrong_hash.ciphertext_sha256));
        });

        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            let mut wrong_commitment = context.final_buckets[0].clone();
            wrong_commitment.bucket_commitment = root_hash(93);
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.bucket_path(wrong_commitment.bucket_id),
                &wrong_commitment,
            )
            .unwrap();

            let rendered = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(!rendered.contains(&wrong_commitment.ciphertext));
            assert!(!rendered.contains(&wrong_commitment.bucket_commitment));
        });

        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            advance_owner_recovery_fixture_to(
                &lock,
                context,
                PrivateResultOwnerRecoveryProgressV1::S1 {
                    written_prefix: context.final_buckets.len(),
                },
            );
            let mut wrong_tree = store.read_merkle_tree().unwrap();
            let first = &context.final_bucket_refs[0];
            wrong_tree.leaf_hashes[usize::try_from(first.bucket_id).unwrap()] =
                first.bucket_commitment.clone();
            wrong_tree.index_epoch = context.new_state.index_epoch;
            wrong_tree.root_hash =
                PrivateResultOramStore::merkle_root_for_commitments(&wrong_tree.leaf_hashes)
                    .unwrap();
            assert_ne!(wrong_tree.root_hash, context.new_state.root_hash);
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.merkle_nodes_path(),
                &wrong_tree,
            )
            .unwrap();

            let error = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(error.contains("canonical store state does not match"));
            assert!(!error.contains(&wrong_tree.root_hash));
        });

        with_owner_recovery_fixture(|store, context| {
            let lock = store.lock_owner_store_v1().unwrap();
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.pending_writeback_path(),
                &serde_json::json!({"legacy": true}),
            )
            .unwrap();

            let error = lock
                .revalidated_owner_recovery_snapshot_v1(context)
                .unwrap_err()
                .to_string();
            assert!(error.contains("rejects legacy pending writeback"));
        });
    }

    #[test]
    fn owner_store_canonical_digest_binds_historical_epoch_commits() {
        with_owner_recovery_fixture(|store, context| {
            let before = store
                .lock_owner_store_v1()
                .unwrap()
                .verify_exact_old(context)
                .unwrap()
                .canonical_state_digest()
                .to_string();
            let historical_epoch = context.old_state.index_epoch - 1;
            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.commit_epoch_path(historical_epoch),
                &PrivateResultOramEpochCommit {
                    index_epoch: historical_epoch,
                    root_hash: root_hash(101),
                    writeback_digest: Some(root_hash(102)),
                },
            )
            .unwrap();
            let first_history = store
                .lock_owner_store_v1()
                .unwrap()
                .verify_exact_old(context)
                .unwrap()
                .canonical_state_digest()
                .to_string();
            assert_ne!(before, first_history);

            write_json_atomic(
                &store.root,
                &store.temp_dir(),
                &store.commit_epoch_path(historical_epoch),
                &PrivateResultOramEpochCommit {
                    index_epoch: historical_epoch,
                    root_hash: root_hash(103),
                    writeback_digest: Some(root_hash(104)),
                },
            )
            .unwrap();
            let replaced_history = store
                .lock_owner_store_v1()
                .unwrap()
                .verify_exact_old(context)
                .unwrap()
                .canonical_state_digest()
                .to_string();
            assert_ne!(first_history, replaced_history);
        });
    }

    #[test]
    fn owner_store_rejects_excessive_epoch_directory_entries() {
        with_owner_recovery_fixture(|store, context| {
            for epoch in 0..MAX_OWNER_EPOCH_DIRECTORY_ENTRIES as u64 {
                write_json_atomic(
                    &store.root,
                    &store.temp_dir(),
                    &store.commit_epoch_path(epoch),
                    &PrivateResultOramEpochCommit {
                        index_epoch: epoch,
                        root_hash: root_hash(120_u8.wrapping_add(epoch as u8)),
                        writeback_digest: Some(root_hash(140_u8.wrapping_add(epoch as u8))),
                    },
                )
                .unwrap();
            }

            let error = store
                .lock_owner_store_v1()
                .unwrap()
                .verify_exact_old(context)
                .unwrap_err()
                .to_string();
            assert!(error.contains("canonical store state does not match"));
        });
    }
}
