#![allow(
    dead_code,
    reason = "D3-B2-B is a dormant staging primitive until D3-B3 admission wiring"
)]

//! Prepared-only durable staging for a visible point record bound to a private ORAM mutation.
//!
//! The canonical frame can contain a visible point ID and payload, so confidentiality relies on
//! the owner-only host filesystem boundary. Private vector bytes are rejected. Publication also
//! requires Linux `renameat2(RENAME_NOREPLACE)` on a local filesystem with durable directory fsync.

use std::collections::BTreeSet;
use std::ffi::{CString, OsStr};
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use fs4::fs_std::FileExt;
use qdrant_sec::{
    PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES, PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
    PrivateOramAppendMutationBundleV1, PrivateOramStagedInsertFrameV1,
    decode_private_oram_staged_insert_frame_v1, encode_private_oram_staged_insert_frame_v1,
    private_oram_append_mutation_v1_digest, private_oram_staged_insert_frame_v1_digest,
    private_oram_staged_point_id_canonical_string, private_oram_staged_point_semantic_v1_digest,
    validate_private_oram_staged_insert_frame_v1_against_mutation_bundle,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::private_oram_mutation_journal::{
    PrivateOramValidatedPointStageParentV1, create_private_directory, path_entry_exists,
    private_oram_point_id_digest, set_private_directory_permissions,
};

pub const PRIVATE_ORAM_POINT_STAGING_DIR: &str = "private_oram_point_staging";
pub const PRIVATE_ORAM_POINT_STAGE_DESCRIPTOR_VERSION: u16 = 1;
pub const PRIVATE_ORAM_POINT_STAGE_STATE_VERSION: u16 = 1;

const ACTIVE_DIR: &str = "active";
const ACTIVE_TEMP_DIR: &str = "temp";
const LOCK_FILE: &str = "stage.lock";
const DESCRIPTOR_FILE: &str = "descriptor.bin";
const FRAME_FILE: &str = "frame.bin";
const STATE_FILE: &str = "state.bin";
const CANDIDATE_PREFIX: &str = ".candidate-";
const PREPARED_PHASE_TAG: u8 = 1;
const MAX_DESCRIPTOR_BYTES: u64 = 4 * 1024;
const MAX_STATE_BYTES: u64 = 1024;
const DIGEST_BYTES: usize = 32;

const DESCRIPTOR_DOMAIN: &[u8] = b"qdrant-sec/private-oram-point-stage-descriptor/v1";
const STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-point-stage-state/v1";

#[derive(Error, Clone, Copy, PartialEq, Eq)]
pub enum PrivateOramPointStagingError {
    #[error("private ORAM point staging is unsupported on this platform or filesystem")]
    Unsupported,
    #[error("private ORAM point staging input is invalid")]
    InvalidInput(&'static str),
    #[error("private ORAM point staging frame is invalid")]
    InvalidFrame,
    #[error("private ORAM point staging requires a point without server vectors")]
    ServerVectorsForbidden,
    #[error("private ORAM point staging parent binding is invalid")]
    ParentMismatch,
    #[error("another private ORAM point stage is active")]
    ConcurrentStage,
    #[error("private ORAM point staging contains corrupt or inconsistent state")]
    Corrupt,
    #[error("private ORAM point staging I/O failed before publication")]
    Io,
    #[error("private ORAM point staging publication outcome is indeterminate")]
    Indeterminate,
}

impl Debug for PrivateOramPointStagingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Unsupported"),
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::InvalidFrame => f.write_str("InvalidFrame([redacted])"),
            Self::ServerVectorsForbidden => f.write_str("ServerVectorsForbidden"),
            Self::ParentMismatch => f.write_str("ParentMismatch([redacted])"),
            Self::ConcurrentStage => f.write_str("ConcurrentStage"),
            Self::Corrupt => f.write_str("Corrupt([redacted])"),
            Self::Io => f.write_str("Io([redacted])"),
            Self::Indeterminate => f.write_str("Indeterminate([redacted])"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramPointStageDescriptorV1 {
    pub version: u16,
    pub parent_descriptor_digest: String,
    pub parent_owners_prepared_record_digest: String,
    pub signed_mutation_digest: String,
    pub frame_codec_version: u16,
    pub frame_length: u64,
    pub frame_sha256: String,
    pub point_operation_digest: String,
    pub canonical_point_id_digest: String,
    pub descriptor_digest: String,
}

impl Debug for PrivateOramPointStageDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPointStageDescriptorV1")
            .field("version", &self.version)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_owners_prepared_record_digest", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("frame_codec_version", &self.frame_codec_version)
            .field("frame_length", &self.frame_length)
            .field("frame_sha256", &"[redacted]")
            .field("point_operation_digest", &"[redacted]")
            .field("canonical_point_id_digest", &"[redacted]")
            .field("descriptor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramPointStageStateV1 {
    pub version: u16,
    pub descriptor_digest: String,
    pub state_digest: String,
}

impl PrivateOramPointStageStateV1 {
    pub const fn is_prepared(&self) -> bool {
        true
    }
}

impl Debug for PrivateOramPointStageStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPointStageStateV1")
            .field("version", &self.version)
            .field("phase", &"Prepared")
            .field("descriptor_digest", &"[redacted]")
            .field("state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateOramPointStageSnapshotV1 {
    pub descriptor: PrivateOramPointStageDescriptorV1,
    pub state: PrivateOramPointStageStateV1,
    pub frame: PrivateOramStagedInsertFrameV1,
}

impl Debug for PrivateOramPointStageSnapshotV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPointStageSnapshotV1")
            .field("descriptor", &self.descriptor)
            .field("state", &self.state)
            .field("frame", &"[redacted]")
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct PrivateOramDurablePointStageTokenV1 {
    point_id: String,
    frame_sha256: String,
    canonical_point_id_digest: String,
    point_semantic_digest: String,
    target_shard_ids: Vec<u32>,
    child_descriptor_digest: String,
    parent_descriptor_digest: String,
    parent_owners_prepared_record_digest: String,
}

/// Callback-scoped evidence that the exact staged frame remains installed under the held root
/// lock. It is intentionally impossible to move this authority outside `with_live_stage`.
pub(super) struct PrivateOramLivePointStageV1<'lock> {
    stage: &'lock ValidatedPointStage,
    durable: &'lock PrivateOramDurablePointStageTokenV1,
    _lock: &'lock PrivateOramPointStageLock,
}

impl Debug for PrivateOramLivePointStageV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramLivePointStageV1")
            .field("frame", &"[redacted]")
            .field("durable", &self.durable)
            .field("lock", &"[held]")
            .finish()
    }
}

impl PrivateOramLivePointStageV1<'_> {
    pub(super) fn frame(&self) -> &PrivateOramStagedInsertFrameV1 {
        &self.stage.frame
    }

    pub(super) fn durable(&self) -> &PrivateOramDurablePointStageTokenV1 {
        self.durable
    }
}

impl Debug for PrivateOramDurablePointStageTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurablePointStageTokenV1")
            .field("point_id", &"[redacted]")
            .field("frame_sha256", &"[redacted]")
            .field("canonical_point_id_digest", &"[redacted]")
            .field("point_semantic_digest", &"[redacted]")
            .field("target_shard_count", &self.target_shard_ids.len())
            .field("child_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_owners_prepared_record_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramDurablePointStageTokenV1 {
    fn from_validated_stage(
        descriptor: &PrivateOramPointStageDescriptorV1,
        frame: &PrivateOramStagedInsertFrameV1,
        point_semantic_digest: String,
        point_id: String,
    ) -> Self {
        Self {
            point_id,
            frame_sha256: descriptor.frame_sha256.clone(),
            canonical_point_id_digest: descriptor.canonical_point_id_digest.clone(),
            point_semantic_digest,
            target_shard_ids: frame.target_shard_ids.clone(),
            child_descriptor_digest: descriptor.descriptor_digest.clone(),
            parent_descriptor_digest: descriptor.parent_descriptor_digest.clone(),
            parent_owners_prepared_record_digest: descriptor
                .parent_owners_prepared_record_digest
                .clone(),
        }
    }

    pub(super) fn point_id(&self) -> &str {
        &self.point_id
    }

    pub(super) fn frame_sha256(&self) -> &str {
        &self.frame_sha256
    }

    pub(super) fn canonical_point_id_digest(&self) -> &str {
        &self.canonical_point_id_digest
    }

    pub(super) fn point_semantic_digest(&self) -> &str {
        &self.point_semantic_digest
    }

    pub(super) fn target_shard_ids(&self) -> &[u32] {
        &self.target_shard_ids
    }

    pub(super) fn child_descriptor_digest(&self) -> &str {
        &self.child_descriptor_digest
    }

    pub(super) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(super) fn parent_owners_prepared_record_digest(&self) -> &str {
        &self.parent_owners_prepared_record_digest
    }
}

#[derive(Clone)]
pub struct PrivateOramPointStagingStore {
    root: PathBuf,
}

impl Debug for PrivateOramPointStagingStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPointStagingStore")
            .field("root", &"[redacted]")
            .finish()
    }
}

impl PrivateOramPointStagingStore {
    pub fn new(collection_path: &Path) -> Self {
        Self {
            root: collection_path.join(PRIVATE_ORAM_POINT_STAGING_DIR),
        }
    }

    pub(super) fn belongs_to_collection(&self, collection_path: &Path) -> bool {
        self.root == collection_path.join(PRIVATE_ORAM_POINT_STAGING_DIR)
    }

    pub(super) fn prepare(
        &self,
        canonical_frame_bytes: &[u8],
        parent: &PrivateOramValidatedPointStageParentV1,
    ) -> Result<
        (
            PrivateOramPointStageSnapshotV1,
            PrivateOramDurablePointStageTokenV1,
        ),
        PrivateOramPointStagingError,
    > {
        let parent = PointStageParentBinding::from_validated_parent(parent);
        self.prepare_bound(canonical_frame_bytes, &parent)
    }

    pub(super) fn load(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
    ) -> Result<
        Option<(
            PrivateOramPointStageSnapshotV1,
            PrivateOramDurablePointStageTokenV1,
        )>,
        PrivateOramPointStagingError,
    > {
        let parent = PointStageParentBinding::from_validated_parent(parent);
        self.load_bound(&parent)
    }

    pub(super) fn with_live_stage<R>(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
        action: impl for<'lock> FnOnce(&PrivateOramLivePointStageV1<'lock>) -> R,
    ) -> Result<R, PrivateOramPointStagingError> {
        let parent = PointStageParentBinding::from_validated_parent(parent);
        self.with_live_stage_bound(&parent, action)
    }

    /// Runs a terminal parent transition while the exact staged child remains locked.
    ///
    /// The child is disposable after a successful terminal transition, so this consuming form
    /// validates the canonical root immediately before the callback and deliberately does not
    /// turn later child cleanup or tampering into an error after the parent commit is durable.
    #[cfg(test)]
    pub(super) fn with_consumed_live_stage<R>(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
        action: impl for<'lock> FnOnce(&PrivateOramLivePointStageV1<'lock>) -> R,
    ) -> Result<R, PrivateOramPointStagingError> {
        let parent = PointStageParentBinding::from_validated_parent(parent);
        self.with_consumed_live_stage_bound(&parent, action)
    }

    #[cfg(test)]
    fn with_consumed_live_stage_bound<R>(
        &self,
        parent: &PointStageParentBinding,
        action: impl for<'lock> FnOnce(&PrivateOramLivePointStageV1<'lock>) -> R,
    ) -> Result<R, PrivateOramPointStagingError> {
        if !path_entry_exists(&self.root).map_err(|_| PrivateOramPointStagingError::Io)? {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        validate_private_directory_exact(&self.root)?;
        let lock = self.acquire_lock()?;
        let root = lock.pinned_root_path();
        if Self::stable_root_entry_at(&root)? != StableRootEntry::Active {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        let stage = Self::load_active_structural_at(&root)?;
        stage.validate_parent(parent)?;
        let durable = stage.durable_token();
        lock.validate_root_identity()?;
        Ok(action(&PrivateOramLivePointStageV1 {
            stage: &stage,
            durable: &durable,
            _lock: &lock,
        }))
    }

    fn with_live_stage_bound<R>(
        &self,
        parent: &PointStageParentBinding,
        action: impl for<'lock> FnOnce(&PrivateOramLivePointStageV1<'lock>) -> R,
    ) -> Result<R, PrivateOramPointStagingError> {
        if !path_entry_exists(&self.root).map_err(|_| PrivateOramPointStagingError::Io)? {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        validate_private_directory_exact(&self.root)?;
        let lock = self.acquire_lock()?;
        let root = lock.pinned_root_path();
        if Self::stable_root_entry_at(&root)? != StableRootEntry::Active {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        let stage = Self::load_active_structural_at(&root)?;
        stage.validate_parent(parent)?;
        let durable = stage.durable_token();
        let output = action(&PrivateOramLivePointStageV1 {
            stage: &stage,
            durable: &durable,
            _lock: &lock,
        });
        let reloaded = Self::load_active_structural_at(&root)?;
        if !reloaded.exactly_matches(&stage) {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        reloaded.validate_parent(parent)?;
        lock.validate_root_identity()?;
        Ok(output)
    }

    fn prepare_bound(
        &self,
        canonical_frame_bytes: &[u8],
        parent: &PointStageParentBinding,
    ) -> Result<
        (
            PrivateOramPointStageSnapshotV1,
            PrivateOramDurablePointStageTokenV1,
        ),
        PrivateOramPointStagingError,
    > {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        let desired = ValidatedPointStage::build(canonical_frame_bytes, parent)?;
        self.ensure_root()?;
        let lock = self.acquire_lock()?;
        let root = lock.pinned_root_path();
        let root_entry = Self::stable_root_entry_at(&root)?;
        if root_entry == StableRootEntry::Active {
            let existing = Self::load_active_structural_at(&root)?;
            if !existing.exactly_matches(&desired) {
                return Err(PrivateOramPointStagingError::ConcurrentStage);
            }
            existing.validate_parent(parent)?;
            sync_private_directory(&root)
                .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
            lock.validate_root_identity()
                .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
            return Ok(existing.into_output());
        }
        if !parent.permits_new_child_install {
            return Err(PrivateOramPointStagingError::ParentMismatch);
        }

        let candidate = tempfile::Builder::new()
            .prefix(CANDIDATE_PREFIX)
            .tempdir_in(&root)
            .map_err(|_| PrivateOramPointStagingError::Io)?;
        set_private_directory_permissions(candidate.path())
            .map_err(|_| PrivateOramPointStagingError::Io)?;
        validate_private_directory_exact(candidate.path())?;

        write_new_private_file(
            &candidate.path().join(DESCRIPTOR_FILE),
            &desired.descriptor_bytes,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(FRAME_FILE),
            &desired.frame_bytes,
            PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES as u64,
        )?;
        write_new_private_file(
            &candidate.path().join(STATE_FILE),
            &desired.state_bytes,
            MAX_STATE_BYTES,
        )?;
        let candidate_temp = candidate.path().join(ACTIVE_TEMP_DIR);
        fs::create_dir(&candidate_temp).map_err(|_| PrivateOramPointStagingError::Io)?;
        set_private_directory_permissions(&candidate_temp)
            .map_err(|_| PrivateOramPointStagingError::Io)?;
        validate_private_directory_exact(&candidate_temp)?;
        validate_directory_is_empty(&candidate_temp)?;
        validate_active_entry_set(candidate.path())?;
        sync_private_directory(&candidate_temp).map_err(|_| PrivateOramPointStagingError::Io)?;
        sync_private_directory(candidate.path()).map_err(|_| PrivateOramPointStagingError::Io)?;

        let root_file = open_private_directory(&root)?;
        let candidate_name = candidate
            .path()
            .file_name()
            .ok_or(PrivateOramPointStagingError::Corrupt)?;
        match rename_directory_noreplace(&root_file, candidate_name, OsStr::new(ACTIVE_DIR)) {
            Ok(()) => {
                sync_open_directory(&root_file)
                    .and_then(|()| validate_open_directory_at_path(&root_file, &root))
                    .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
                let installed = Self::load_active_structural_at(&root)
                    .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
                if !installed.exactly_matches(&desired) {
                    return Err(PrivateOramPointStagingError::Indeterminate);
                }
                installed.validate_parent(parent)?;
                lock.validate_root_identity()
                    .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
                Ok(installed.into_output())
            }
            Err(PrivateOramPointStagingError::ConcurrentStage) => {
                sync_open_directory(&root_file)
                    .and_then(|()| validate_open_directory_at_path(&root_file, &root))
                    .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
                let existing = Self::load_active_structural_at(&root)?;
                if !existing.exactly_matches(&desired) {
                    return Err(PrivateOramPointStagingError::ConcurrentStage);
                }
                existing.validate_parent(parent)?;
                lock.validate_root_identity()
                    .map_err(|_| PrivateOramPointStagingError::Indeterminate)?;
                Ok(existing.into_output())
            }
            Err(error) => Err(error),
        }
    }

    fn load_bound(
        &self,
        parent: &PointStageParentBinding,
    ) -> Result<
        Option<(
            PrivateOramPointStageSnapshotV1,
            PrivateOramDurablePointStageTokenV1,
        )>,
        PrivateOramPointStagingError,
    > {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root).map_err(|_| PrivateOramPointStagingError::Io)? {
            return if parent.expected_child_descriptor_digest.is_some() {
                Err(PrivateOramPointStagingError::Corrupt)
            } else {
                Ok(None)
            };
        }
        validate_private_directory_exact(&self.root)?;
        let lock = self.acquire_lock()?;
        let root = lock.pinned_root_path();
        let result = match Self::stable_root_entry_at(&root)? {
            StableRootEntry::Empty => {
                if parent.expected_child_descriptor_digest.is_some() {
                    Err(PrivateOramPointStagingError::Corrupt)
                } else {
                    Ok(None)
                }
            }
            StableRootEntry::Active => {
                let loaded = Self::load_active_structural_at(&root)?;
                loaded.validate_parent(parent)?;
                Ok(Some(loaded.into_output()))
            }
        }?;
        lock.validate_root_identity()?;
        Ok(result)
    }

    fn ensure_root(&self) -> Result<(), PrivateOramPointStagingError> {
        create_private_directory(&self.root).map_err(|_| PrivateOramPointStagingError::Io)?;
        validate_private_directory_exact(&self.root)
    }

    fn acquire_lock(&self) -> Result<PrivateOramPointStageLock, PrivateOramPointStagingError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        let root = open_pinned_point_stage_directory(&self.root)?;
        let lock_path = root.pinned_path(&self.root).join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        }
        let file = options
            .open(&lock_path)
            .map_err(|_| PrivateOramPointStagingError::Io)?;
        validate_lock_file_metadata(
            &file
                .metadata()
                .map_err(|_| PrivateOramPointStagingError::Io)?,
        )?;
        FileExt::lock_exclusive(file.file()).map_err(|_| PrivateOramPointStagingError::Io)?;
        let current =
            fs::symlink_metadata(&lock_path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        validate_lock_file_metadata(&current)?;
        ensure_same_inode(
            &file
                .metadata()
                .map_err(|_| PrivateOramPointStagingError::Corrupt)?,
            &current,
        )?;
        file.sync_all()
            .map_err(|_| PrivateOramPointStagingError::Io)?;
        root.validate_at_path(&self.root)?;
        sync_open_directory(&root.directory)?;
        Ok(PrivateOramPointStageLock {
            _file: file,
            root,
            root_path: self.root.clone(),
        })
    }

    fn stable_root_entry_at(root: &Path) -> Result<StableRootEntry, PrivateOramPointStagingError> {
        validate_private_directory_exact(root)?;
        let names = directory_entry_names(root)?;
        let mut has_active = false;
        for name in names {
            if name == OsStr::new(ACTIVE_DIR) {
                if has_active {
                    return Err(PrivateOramPointStagingError::Corrupt);
                }
                has_active = true;
            } else if is_candidate_name(&name) {
                // A process crash can strand an unpublished sibling candidate. It is never
                // adopted or removed here; only the non-replacing `active` install is canonical.
                validate_private_directory_exact(&root.join(name))?;
            } else if name == OsStr::new(LOCK_FILE) {
                let metadata = fs::symlink_metadata(root.join(name))
                    .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
                validate_lock_file_metadata(&metadata)?;
            } else {
                return Err(PrivateOramPointStagingError::Corrupt);
            }
        }
        Ok(if has_active {
            StableRootEntry::Active
        } else {
            StableRootEntry::Empty
        })
    }

    fn load_active_structural_at(
        root: &Path,
    ) -> Result<ValidatedPointStage, PrivateOramPointStagingError> {
        let active = root.join(ACTIVE_DIR);
        let active_before = private_directory_identity(&active)?;
        validate_active_entry_set(&active)?;
        let temp = active.join(ACTIVE_TEMP_DIR);
        validate_private_directory_exact(&temp)?;
        validate_directory_is_empty(&temp)?;

        let descriptor_bytes =
            read_private_file(&active.join(DESCRIPTOR_FILE), MAX_DESCRIPTOR_BYTES)?;
        let frame_bytes = read_private_file(
            &active.join(FRAME_FILE),
            PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES as u64,
        )?;
        let state_bytes = read_private_file(&active.join(STATE_FILE), MAX_STATE_BYTES)?;

        validate_active_entry_set(&active)?;
        validate_directory_is_empty(&temp)?;
        let active_after = private_directory_identity(&active)?;
        if active_before != active_after {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        ValidatedPointStage::decode(descriptor_bytes, frame_bytes, state_bytes)
    }
}

#[derive(Clone)]
struct PointStageParentBinding {
    descriptor_digest: String,
    owners_prepared_record_digest: String,
    permits_new_child_install: bool,
    expected_child_descriptor_digest: Option<String>,
    signed_mutation_digest: String,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
}

impl PointStageParentBinding {
    fn from_validated_parent(parent: &PrivateOramValidatedPointStageParentV1) -> Self {
        let descriptor = parent.descriptor();
        Self {
            descriptor_digest: descriptor.descriptor_digest.clone(),
            owners_prepared_record_digest: parent.owners_prepared_record_digest().to_string(),
            permits_new_child_install: parent.permits_new_child_install(),
            expected_child_descriptor_digest: parent
                .expected_child_descriptor_digest()
                .map(str::to_string),
            signed_mutation_digest: descriptor.mutation_digest.clone(),
            mutation_bundle: descriptor.mutation_bundle.clone(),
        }
    }
}

#[derive(Clone)]
struct ValidatedPointStage {
    descriptor: PrivateOramPointStageDescriptorV1,
    descriptor_bytes: Vec<u8>,
    frame: PrivateOramStagedInsertFrameV1,
    frame_bytes: Vec<u8>,
    state: PrivateOramPointStageStateV1,
    state_bytes: Vec<u8>,
    point_id: String,
    point_semantic_digest: String,
}

impl ValidatedPointStage {
    fn build(
        frame_bytes: &[u8],
        parent: &PointStageParentBinding,
    ) -> Result<Self, PrivateOramPointStagingError> {
        if frame_bytes.is_empty()
            || frame_bytes.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES
        {
            return Err(PrivateOramPointStagingError::InvalidInput("frame_bytes"));
        }
        let frame = decode_private_oram_staged_insert_frame_v1(frame_bytes)
            .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        let reencoded = encode_private_oram_staged_insert_frame_v1(&frame)
            .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        if reencoded.as_slice() != frame_bytes {
            return Err(PrivateOramPointStagingError::InvalidFrame);
        }
        validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
            &frame,
            &parent.mutation_bundle,
        )
        .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        if !frame.point.vectors.is_empty() {
            return Err(PrivateOramPointStagingError::ServerVectorsForbidden);
        }
        let point_id = private_oram_staged_point_id_canonical_string(&frame.point.id)
            .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        let point_semantic_digest = private_oram_staged_point_semantic_v1_digest(&frame.point)
            .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        let frame_sha256 = private_oram_staged_insert_frame_v1_digest(&frame)
            .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        if frame_sha256 != digest_string(frame_bytes) {
            return Err(PrivateOramPointStagingError::InvalidFrame);
        }
        let canonical_point_id_digest = private_oram_point_id_digest(&point_id)
            .map_err(|_| PrivateOramPointStagingError::InvalidFrame)?;
        let recomputed_mutation_digest =
            private_oram_append_mutation_v1_digest(&parent.mutation_bundle.mutation)
                .map_err(|_| PrivateOramPointStagingError::ParentMismatch)?;
        if recomputed_mutation_digest != parent.signed_mutation_digest {
            return Err(PrivateOramPointStagingError::ParentMismatch);
        }

        let mut descriptor = PrivateOramPointStageDescriptorV1 {
            version: PRIVATE_ORAM_POINT_STAGE_DESCRIPTOR_VERSION,
            parent_descriptor_digest: parent.descriptor_digest.clone(),
            parent_owners_prepared_record_digest: parent.owners_prepared_record_digest.clone(),
            signed_mutation_digest: parent.signed_mutation_digest.clone(),
            frame_codec_version: frame.version,
            frame_length: u64::try_from(frame_bytes.len())
                .map_err(|_| PrivateOramPointStagingError::InvalidInput("frame_length"))?,
            frame_sha256,
            point_operation_digest: parent
                .mutation_bundle
                .mutation
                .point_operation_digest
                .clone(),
            canonical_point_id_digest,
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        validate_parent_admission(&descriptor, parent)?;
        let descriptor_bytes = encode_descriptor(&descriptor)?;

        let mut state = PrivateOramPointStageStateV1 {
            version: PRIVATE_ORAM_POINT_STAGE_STATE_VERSION,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state)?;
        let state_bytes = encode_state(&state)?;
        Ok(Self {
            descriptor,
            descriptor_bytes,
            frame,
            frame_bytes: frame_bytes.to_vec(),
            state,
            state_bytes,
            point_id,
            point_semantic_digest,
        })
    }

    fn decode(
        descriptor_bytes: Vec<u8>,
        frame_bytes: Vec<u8>,
        state_bytes: Vec<u8>,
    ) -> Result<Self, PrivateOramPointStagingError> {
        let descriptor = decode_descriptor(&descriptor_bytes)?;
        let state = decode_state(&state_bytes)?;
        if state.descriptor_digest != descriptor.descriptor_digest
            || descriptor.frame_length
                != u64::try_from(frame_bytes.len())
                    .map_err(|_| PrivateOramPointStagingError::Corrupt)?
            || descriptor.frame_sha256 != digest_string(&frame_bytes)
        {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        let frame = decode_private_oram_staged_insert_frame_v1(&frame_bytes)
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        if encode_private_oram_staged_insert_frame_v1(&frame)
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?
            != frame_bytes
            || frame.version != descriptor.frame_codec_version
            || frame.version != PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION
            || !frame.point.vectors.is_empty()
        {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        let point_id = private_oram_staged_point_id_canonical_string(&frame.point.id)
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        let point_semantic_digest = private_oram_staged_point_semantic_v1_digest(&frame.point)
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        if private_oram_point_id_digest(&point_id)
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?
            != descriptor.canonical_point_id_digest
        {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        Ok(Self {
            descriptor,
            descriptor_bytes,
            frame,
            frame_bytes,
            state,
            state_bytes,
            point_id,
            point_semantic_digest,
        })
    }

    fn validate_parent(
        &self,
        parent: &PointStageParentBinding,
    ) -> Result<(), PrivateOramPointStagingError> {
        validate_parent_admission(&self.descriptor, parent)?;
        validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
            &self.frame,
            &parent.mutation_bundle,
        )
        .map_err(|_| PrivateOramPointStagingError::ParentMismatch)?;
        let mutation_digest =
            private_oram_append_mutation_v1_digest(&parent.mutation_bundle.mutation)
                .map_err(|_| PrivateOramPointStagingError::ParentMismatch)?;
        if mutation_digest != self.descriptor.signed_mutation_digest
            || self.descriptor.point_operation_digest
                != parent.mutation_bundle.mutation.point_operation_digest
        {
            return Err(PrivateOramPointStagingError::ParentMismatch);
        }
        Ok(())
    }

    fn exactly_matches(&self, other: &Self) -> bool {
        self.descriptor_bytes == other.descriptor_bytes
            && self.frame_bytes == other.frame_bytes
            && self.state_bytes == other.state_bytes
    }

    fn into_output(
        self,
    ) -> (
        PrivateOramPointStageSnapshotV1,
        PrivateOramDurablePointStageTokenV1,
    ) {
        let token = self.durable_token();
        let snapshot = PrivateOramPointStageSnapshotV1 {
            descriptor: self.descriptor,
            state: self.state,
            frame: self.frame,
        };
        (snapshot, token)
    }

    fn durable_token(&self) -> PrivateOramDurablePointStageTokenV1 {
        PrivateOramDurablePointStageTokenV1::from_validated_stage(
            &self.descriptor,
            &self.frame,
            self.point_semantic_digest.clone(),
            self.point_id.clone(),
        )
    }
}

fn validate_parent_admission(
    descriptor: &PrivateOramPointStageDescriptorV1,
    parent: &PointStageParentBinding,
) -> Result<(), PrivateOramPointStagingError> {
    if descriptor.parent_descriptor_digest != parent.descriptor_digest
        || descriptor.parent_owners_prepared_record_digest != parent.owners_prepared_record_digest
        || descriptor.signed_mutation_digest != parent.signed_mutation_digest
    {
        return Err(PrivateOramPointStagingError::ParentMismatch);
    }
    match parent.expected_child_descriptor_digest.as_deref() {
        Some(expected) if expected == descriptor.descriptor_digest => Ok(()),
        Some(_) => Err(PrivateOramPointStagingError::ParentMismatch),
        None if parent.permits_new_child_install => Ok(()),
        None => Err(PrivateOramPointStagingError::ParentMismatch),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StableRootEntry {
    Empty,
    Active,
}

fn encode_descriptor(
    descriptor: &PrivateOramPointStageDescriptorV1,
) -> Result<Vec<u8>, PrivateOramPointStagingError> {
    if descriptor.version != PRIVATE_ORAM_POINT_STAGE_DESCRIPTOR_VERSION
        || descriptor.frame_codec_version != PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION
        || descriptor.frame_length == 0
        || descriptor.frame_length > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES as u64
    {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let mut bytes = descriptor_body(descriptor)?;
    let actual_digest = digest_string(&bytes);
    if descriptor.descriptor_digest != actual_digest {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    bytes.extend_from_slice(&decode_digest(
        &descriptor.descriptor_digest,
        "descriptor_digest",
    )?);
    if bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    Ok(bytes)
}

fn decode_descriptor(
    bytes: &[u8],
) -> Result<PrivateOramPointStageDescriptorV1, PrivateOramPointStagingError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(DESCRIPTOR_DOMAIN)?;
    let version = decoder.read_u16()?;
    let parent_descriptor_digest = decoder.read_digest()?;
    let parent_owners_prepared_record_digest = decoder.read_digest()?;
    let signed_mutation_digest = decoder.read_digest()?;
    let frame_codec_version = decoder.read_u16()?;
    let frame_length = decoder.read_u64()?;
    let frame_sha256 = decoder.read_digest()?;
    let point_operation_digest = decoder.read_digest()?;
    let canonical_point_id_digest = decoder.read_digest()?;
    let descriptor_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let descriptor = PrivateOramPointStageDescriptorV1 {
        version,
        parent_descriptor_digest,
        parent_owners_prepared_record_digest,
        signed_mutation_digest,
        frame_codec_version,
        frame_length,
        frame_sha256,
        point_operation_digest,
        canonical_point_id_digest,
        descriptor_digest,
    };
    if encode_descriptor(&descriptor)? != bytes {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    Ok(descriptor)
}

fn descriptor_body(
    descriptor: &PrivateOramPointStageDescriptorV1,
) -> Result<Vec<u8>, PrivateOramPointStagingError> {
    let mut bytes = Vec::with_capacity(512);
    push_domain(&mut bytes, DESCRIPTOR_DOMAIN)?;
    bytes.extend_from_slice(&descriptor.version.to_be_bytes());
    push_digest(
        &mut bytes,
        &descriptor.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.parent_owners_prepared_record_digest,
        "parent_owners_prepared_record_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.signed_mutation_digest,
        "signed_mutation_digest",
    )?;
    bytes.extend_from_slice(&descriptor.frame_codec_version.to_be_bytes());
    bytes.extend_from_slice(&descriptor.frame_length.to_be_bytes());
    push_digest(&mut bytes, &descriptor.frame_sha256, "frame_sha256")?;
    push_digest(
        &mut bytes,
        &descriptor.point_operation_digest,
        "point_operation_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.canonical_point_id_digest,
        "canonical_point_id_digest",
    )?;
    Ok(bytes)
}

fn descriptor_digest(
    descriptor: &PrivateOramPointStageDescriptorV1,
) -> Result<String, PrivateOramPointStagingError> {
    Ok(digest_string(&descriptor_body(descriptor)?))
}

fn encode_state(
    state: &PrivateOramPointStageStateV1,
) -> Result<Vec<u8>, PrivateOramPointStagingError> {
    if state.version != PRIVATE_ORAM_POINT_STAGE_STATE_VERSION {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let mut bytes = state_body(state)?;
    let actual_digest = digest_string(&bytes);
    if state.state_digest != actual_digest {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    bytes.extend_from_slice(&decode_digest(&state.state_digest, "state_digest")?);
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    Ok(bytes)
}

fn decode_state(
    bytes: &[u8],
) -> Result<PrivateOramPointStageStateV1, PrivateOramPointStagingError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(STATE_DOMAIN)?;
    let version = decoder.read_u16()?;
    if decoder.read_u8()? != PREPARED_PHASE_TAG {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let descriptor_digest = decoder.read_digest()?;
    let state_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let state = PrivateOramPointStageStateV1 {
        version,
        descriptor_digest,
        state_digest,
    };
    if encode_state(&state)? != bytes {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    Ok(state)
}

fn state_body(
    state: &PrivateOramPointStageStateV1,
) -> Result<Vec<u8>, PrivateOramPointStagingError> {
    let mut bytes = Vec::with_capacity(160);
    push_domain(&mut bytes, STATE_DOMAIN)?;
    bytes.extend_from_slice(&state.version.to_be_bytes());
    bytes.push(PREPARED_PHASE_TAG);
    push_digest(&mut bytes, &state.descriptor_digest, "descriptor_digest")?;
    Ok(bytes)
}

fn state_digest(
    state: &PrivateOramPointStageStateV1,
) -> Result<String, PrivateOramPointStagingError> {
    Ok(digest_string(&state_body(state)?))
}

fn push_domain(bytes: &mut Vec<u8>, domain: &[u8]) -> Result<(), PrivateOramPointStagingError> {
    let length = u32::try_from(domain.len())
        .map_err(|_| PrivateOramPointStagingError::InvalidInput("domain"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(domain);
    Ok(())
}

fn push_digest(
    bytes: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramPointStagingError> {
    bytes.extend_from_slice(&decode_digest(value, field)?);
    Ok(())
}

fn decode_digest(
    value: &str,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], PrivateOramPointStagingError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramPointStagingError::InvalidInput(field))?;
    let digest: [u8; DIGEST_BYTES] = decoded
        .try_into()
        .map_err(|_| PrivateOramPointStagingError::InvalidInput(field))?;
    if BASE64URL_NOPAD.encode(&digest) != value {
        return Err(PrivateOramPointStagingError::InvalidInput(field));
    }
    Ok(digest)
}

fn digest_string(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(bytes))
}

struct BinaryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_domain(&mut self, expected: &[u8]) -> Result<(), PrivateOramPointStagingError> {
        let length = self.read_u32()? as usize;
        if length != expected.len() || self.read_exact(length)? != expected {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, PrivateOramPointStagingError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PrivateOramPointStagingError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, PrivateOramPointStagingError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, PrivateOramPointStagingError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_digest(&mut self) -> Result<String, PrivateOramPointStagingError> {
        Ok(BASE64URL_NOPAD.encode(self.read_exact(DIGEST_BYTES)?))
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PrivateOramPointStagingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PrivateOramPointStagingError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrivateOramPointStagingError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    length: u64,
}

struct PinnedPointStageDirectory {
    directory: File,
}

impl PinnedPointStageDirectory {
    fn pinned_path(&self, fallback: &Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let _ = fallback;
            PathBuf::from("/proc/self/fd")
                .join(self.directory.file().as_raw_fd().to_string())
                .join(".")
        }
        #[cfg(not(target_os = "linux"))]
        {
            fallback.to_path_buf()
        }
    }

    fn validate_at_path(&self, path: &Path) -> Result<(), PrivateOramPointStagingError> {
        let opened = self
            .directory
            .metadata()
            .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        validate_directory_metadata(&opened)?;
        let current =
            fs::symlink_metadata(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        validate_directory_metadata(&current)?;
        ensure_same_inode(&opened, &current)
    }
}

struct PrivateOramPointStageLock {
    _file: File,
    root: PinnedPointStageDirectory,
    root_path: PathBuf,
}

impl PrivateOramPointStageLock {
    fn pinned_root_path(&self) -> PathBuf {
        self.root.pinned_path(&self.root_path)
    }

    fn validate_root_identity(&self) -> Result<(), PrivateOramPointStagingError> {
        self.root.validate_at_path(&self.root_path)
    }
}

fn open_pinned_point_stage_directory(
    path: &Path,
) -> Result<PinnedPointStageDirectory, PrivateOramPointStagingError> {
    Ok(PinnedPointStageDirectory {
        directory: open_private_directory(path)?,
    })
}

fn private_directory_identity(
    path: &Path,
) -> Result<DirectoryIdentity, PrivateOramPointStagingError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_directory_metadata(&before)?;
    let opened = open_private_directory(path)?;
    let after = opened
        .metadata()
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(DirectoryIdentity {
            device: after.dev(),
            inode: after.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(DirectoryIdentity {
            length: after.len(),
        })
    }
}

fn validate_private_directory_exact(path: &Path) -> Result<(), PrivateOramPointStagingError> {
    private_directory_identity(path).map(drop)
}

fn validate_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramPointStagingError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramPointStagingError> {
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
    }
    Ok(())
}

fn validate_lock_file_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramPointStagingError> {
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_same_inode(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramPointStagingError> {
    if before.file_type().is_file() != after.file_type().is_file()
        || before.file_type().is_dir() != after.file_type().is_dir()
        || before.len() != after.len()
    {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
    }
    Ok(())
}

fn open_private_directory(path: &Path) -> Result<File, PrivateOramPointStagingError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramPointStagingError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    let after = file
        .metadata()
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    Ok(file)
}

fn write_new_private_file(
    path: &Path,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<(), PrivateOramPointStagingError> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(PrivateOramPointStagingError::InvalidInput("file_bytes"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramPointStagingError::Unsupported);
    #[allow(unreachable_code)]
    let mut file = options
        .open(path)
        .map_err(|_| PrivateOramPointStagingError::Io)?;
    file.write_all(bytes)
        .map_err(|_| PrivateOramPointStagingError::Io)?;
    file.flush().map_err(|_| PrivateOramPointStagingError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| PrivateOramPointStagingError::Io)?;
    validate_file_metadata(&metadata, max_bytes)?;
    if metadata.len() != bytes.len() as u64 {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    file.sync_all()
        .map_err(|_| PrivateOramPointStagingError::Io)
}

fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PrivateOramPointStagingError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramPointStagingError::Unsupported);
    #[allow(unreachable_code)]
    let mut file = options
        .open(path)
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    let opened = file
        .metadata()
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_file_metadata(&opened, max_bytes)?;
    ensure_same_inode(&before, &opened)?;

    let expected_length =
        usize::try_from(opened.len()).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    if bytes.len() != expected_length {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    let after = file
        .metadata()
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_file_metadata(&after, max_bytes)?;
    ensure_same_inode(&opened, &after)?;
    let path_after =
        fs::symlink_metadata(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_file_metadata(&path_after, max_bytes)?;
    ensure_same_inode(&after, &path_after)?;
    Ok(bytes)
}

fn sync_private_directory(path: &Path) -> Result<(), PrivateOramPointStagingError> {
    sync_open_directory(&open_private_directory(path)?)
}

fn sync_open_directory(directory: &File) -> Result<(), PrivateOramPointStagingError> {
    directory
        .sync_all()
        .map_err(|_| PrivateOramPointStagingError::Io)
}

fn validate_open_directory_at_path(
    directory: &File,
    path: &Path,
) -> Result<(), PrivateOramPointStagingError> {
    let opened = directory
        .metadata()
        .map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_directory_metadata(&opened)?;
    let current = fs::symlink_metadata(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    validate_directory_metadata(&current)?;
    ensure_same_inode(&opened, &current)
}

fn directory_entry_names(
    path: &Path,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramPointStagingError> {
    let mut names = BTreeSet::new();
    let entries = fs::read_dir(path).map_err(|_| PrivateOramPointStagingError::Corrupt)?;
    for entry in entries {
        let entry = entry.map_err(|_| PrivateOramPointStagingError::Corrupt)?;
        if !names.insert(entry.file_name()) {
            return Err(PrivateOramPointStagingError::Corrupt);
        }
    }
    Ok(names)
}

fn validate_active_entry_set(path: &Path) -> Result<(), PrivateOramPointStagingError> {
    validate_private_directory_exact(path)?;
    let actual = directory_entry_names(path)?;
    let expected = [DESCRIPTOR_FILE, FRAME_FILE, STATE_FILE, ACTIVE_TEMP_DIR]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    Ok(())
}

fn validate_directory_is_empty(path: &Path) -> Result<(), PrivateOramPointStagingError> {
    validate_private_directory_exact(path)?;
    if !directory_entry_names(path)?.is_empty() {
        return Err(PrivateOramPointStagingError::Corrupt);
    }
    Ok(())
}

fn is_candidate_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() > CANDIDATE_PREFIX.len() && name.starts_with(CANDIDATE_PREFIX)
    })
}

#[cfg(target_os = "linux")]
fn rename_directory_noreplace(
    root: &File,
    source_name: &OsStr,
    destination_name: &OsStr,
) -> Result<(), PrivateOramPointStagingError> {
    let source = checked_single_component_cstring(source_name)?;
    let destination = checked_single_component_cstring(destination_name)?;
    // SAFETY: both names are validated single-component C strings, and `root` is an opened,
    // no-follow directory descriptor used for both sides of the non-replacing rename.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_renameat2,
            root.as_raw_fd(),
            source.as_ptr(),
            root.as_raw_fd(),
            destination.as_ptr(),
            nix::libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    match errno {
        Some(nix::libc::EEXIST) => Err(PrivateOramPointStagingError::ConcurrentStage),
        Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::EOPNOTSUPP | nix::libc::EXDEV) => {
            Err(PrivateOramPointStagingError::Unsupported)
        }
        _ => Err(PrivateOramPointStagingError::Indeterminate),
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_directory_noreplace(
    _root: &File,
    _source_name: &OsStr,
    _destination_name: &OsStr,
) -> Result<(), PrivateOramPointStagingError> {
    Err(PrivateOramPointStagingError::Unsupported)
}

#[cfg(target_os = "linux")]
fn checked_single_component_cstring(name: &OsStr) -> Result<CString, PrivateOramPointStagingError> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(PrivateOramPointStagingError::InvalidInput(
            "rename_component",
        ));
    }
    CString::new(bytes).map_err(|_| PrivateOramPointStagingError::InvalidInput("rename_component"))
}

#[cfg(not(target_os = "linux"))]
const fn ensure_supported_platform() -> Result<(), PrivateOramPointStagingError> {
    Err(PrivateOramPointStagingError::Unsupported)
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        PrivateOramAppendBucketRefV1, PrivateOramAppendIndexWritebackV1,
        PrivateOramAppendMutationBundleV1, PrivateOramAppendMutationV1,
        PrivateOramAppendWritebackDigestInput, PrivateOramIndexKindV2, PrivateOramIndexStateV2,
        PrivateOramPointOperationKindV1, PrivateOramSignature, PrivateOramSignedStateBundleV2,
        PrivateOramSignedStateV2, PrivateOramStagedNamedVectorV1, PrivateOramStagedPointIdV1,
        PrivateOramStagedPointV1, PrivateOramStagedVectorV1, PrivateOramVisiblePointRecordV1,
        private_oram_append_writeback_v1_digest, private_oram_signed_state_v2_digest,
        private_oram_visible_point_record_v1_digest,
    };
    use serde_json::{Map, Value};
    use tempfile::TempDir;

    use super::*;

    struct StoreFixture {
        _temp: TempDir,
        collection: PathBuf,
        store: PrivateOramPointStagingStore,
        parent: PointStageParentBinding,
        frame_bytes: Vec<u8>,
    }

    fn digest(fill: u8) -> String {
        BASE64URL_NOPAD.encode(&[fill; 32])
    }

    fn signature() -> PrivateOramSignature {
        PrivateOramSignature {
            alg: "ed25519".to_string(),
            key_id: "owner-key".to_string(),
            sig: BASE64URL_NOPAD.encode(&[91; 64]),
        }
    }

    fn state_bundle(
        frame: &PrivateOramStagedInsertFrameV1,
        state_sequence: u64,
        last_mutation_id: Option<String>,
        index_epoch: u64,
        root_hash: String,
        counts: (u64, u64),
        last_writeback_digest: String,
    ) -> PrivateOramSignedStateBundleV2 {
        PrivateOramSignedStateBundleV2 {
            state: PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: frame.collection_id.clone(),
                manifest_digest: frame.manifest_digest.clone(),
                layout_generation: frame.layout_generation,
                layout_digest: frame.layout_digest.clone(),
                state_sequence,
                indexes: vec![PrivateOramIndexStateV2 {
                    kind: PrivateOramIndexKindV2::Hnsw,
                    index_name: "text".to_string(),
                    index_epoch,
                    root_hash,
                    logical_count: counts.0,
                    dummy_count: counts.1,
                    last_writeback_digest,
                }],
                client_state_digest: digest(u8::try_from(state_sequence).unwrap()),
                last_mutation_id,
                owner_signing_key_id: "owner-key".to_string(),
                signed_at_unix: 1_700_000_000 + state_sequence,
            },
            signature: signature(),
        }
    }

    fn bound_parent_and_frame(marker: u8) -> (PointStageParentBinding, Vec<u8>) {
        let mut payload = Map::new();
        payload.insert(
            "secret".to_string(),
            Value::String(format!("payload-secret-{marker}")),
        );
        let mut frame = PrivateOramStagedInsertFrameV1 {
            version: PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
            collection_id: format!("secret-collection-{marker}"),
            manifest_digest: digest(marker),
            mutation_id: digest(marker.wrapping_add(1)),
            old_state_digest: digest(marker.wrapping_add(2)),
            new_state_digest: digest(marker.wrapping_add(3)),
            layout_generation: 7,
            layout_digest: digest(marker.wrapping_add(4)),
            old_state_sequence: 41,
            new_state_sequence: 42,
            writer_lease_digest: digest(marker.wrapping_add(5)),
            writer_fence: 11,
            target_shard_ids: vec![13, 21],
            shard_key: None,
            point: PrivateOramStagedPointV1 {
                id: PrivateOramStagedPointIdV1::Numeric {
                    value: 4_242 + u64::from(marker),
                },
                vectors: Vec::new(),
                payload: Some(payload),
            },
        };
        let old_root_hash = digest(marker.wrapping_add(6));
        let new_root_hash = digest(marker.wrapping_add(7));
        let old_writeback_digest = digest(marker.wrapping_add(8));
        let read_transcript_digest = digest(marker.wrapping_add(9));
        let writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text".to_string(),
            read_path_count: 1,
            read_transcript_digest,
            updated_buckets: vec![PrivateOramAppendBucketRefV1 {
                bucket_id: 0,
                ciphertext_sha256: digest(marker.wrapping_add(10)),
                bucket_commitment: digest(marker.wrapping_add(11)),
            }],
        };
        let new_writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &frame.collection_id,
                manifest_digest: &frame.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &old_root_hash,
                new_root_hash: &new_root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })
            .unwrap();
        let old_state = state_bundle(
            &frame,
            41,
            Some(digest(marker.wrapping_add(12))),
            11,
            old_root_hash,
            (8, 24),
            old_writeback_digest,
        );
        let new_state = state_bundle(
            &frame,
            42,
            Some(frame.mutation_id.clone()),
            12,
            new_root_hash,
            (9, 23),
            new_writeback_digest,
        );
        frame.old_state_digest = private_oram_signed_state_v2_digest(&old_state.state).unwrap();
        frame.new_state_digest = private_oram_signed_state_v2_digest(&new_state.state).unwrap();
        let frame_bytes = encode_private_oram_staged_insert_frame_v1(&frame).unwrap();
        let frame_sha256 = private_oram_staged_insert_frame_v1_digest(&frame).unwrap();
        let point_id = private_oram_staged_point_id_canonical_string(&frame.point.id).unwrap();
        let point_operation_digest = private_oram_visible_point_record_v1_digest(
            &frame.collection_id,
            &frame.manifest_digest,
            &frame.mutation_id,
            PrivateOramVisiblePointRecordV1 {
                point_id: &point_id,
                staged_insert_sha256: &frame_sha256,
            },
        )
        .unwrap();
        let mutation_bundle = PrivateOramAppendMutationBundleV1 {
            mutation: PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: frame.mutation_id.clone(),
                collection_id: frame.collection_id.clone(),
                manifest_digest: frame.manifest_digest.clone(),
                layout_generation: frame.layout_generation,
                writer_lease_digest: frame.writer_lease_digest.clone(),
                writer_fence: frame.writer_fence,
                issued_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_000_600,
                old_state,
                new_state,
                point_operation_kind: PrivateOramPointOperationKindV1::VisiblePointRecord,
                point_operation_digest,
                writebacks: vec![writeback],
                owner_signing_key_id: "owner-key".to_string(),
            },
            signature: signature(),
        };
        let signed_mutation_digest =
            private_oram_append_mutation_v1_digest(&mutation_bundle.mutation).unwrap();
        (
            PointStageParentBinding {
                descriptor_digest: digest(marker.wrapping_add(20)),
                owners_prepared_record_digest: digest(marker.wrapping_add(21)),
                permits_new_child_install: true,
                expected_child_descriptor_digest: None,
                signed_mutation_digest,
                mutation_bundle,
            },
            frame_bytes,
        )
    }

    fn fixture(marker: u8) -> StoreFixture {
        let temp = TempDir::new().unwrap();
        let collection = temp.path().join(format!("collection-secret-{marker}"));
        fs::create_dir(&collection).unwrap();
        let store = PrivateOramPointStagingStore::new(&collection);
        let (parent, frame_bytes) = bound_parent_and_frame(marker);
        StoreFixture {
            _temp: temp,
            collection,
            store,
            parent,
            frame_bytes,
        }
    }

    fn active_path(fixture: &StoreFixture) -> PathBuf {
        fixture.store.root.join(ACTIVE_DIR)
    }

    fn prepare(
        fixture: &StoreFixture,
    ) -> (
        PrivateOramPointStageSnapshotV1,
        PrivateOramDurablePointStageTokenV1,
    ) {
        fixture
            .store
            .prepare_bound(&fixture.frame_bytes, &fixture.parent)
            .unwrap()
    }

    fn rewrite_frame_and_parent(
        frame: &PrivateOramStagedInsertFrameV1,
        parent: &mut PointStageParentBinding,
    ) -> Vec<u8> {
        let frame_bytes = encode_private_oram_staged_insert_frame_v1(frame).unwrap();
        let frame_sha256 = private_oram_staged_insert_frame_v1_digest(frame).unwrap();
        let point_id = private_oram_staged_point_id_canonical_string(&frame.point.id).unwrap();
        parent.mutation_bundle.mutation.point_operation_digest =
            private_oram_visible_point_record_v1_digest(
                &frame.collection_id,
                &frame.manifest_digest,
                &frame.mutation_id,
                PrivateOramVisiblePointRecordV1 {
                    point_id: &point_id,
                    staged_insert_sha256: &frame_sha256,
                },
            )
            .unwrap();
        parent.signed_mutation_digest =
            private_oram_append_mutation_v1_digest(&parent.mutation_bundle.mutation).unwrap();
        frame_bytes
    }

    fn assert_load_corrupt(fixture: &StoreFixture) {
        assert_eq!(
            fixture.store.load_bound(&fixture.parent).unwrap_err(),
            PrivateOramPointStagingError::Corrupt
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_rejects_staging_before_creating_collection_paths() {
        let temp = tempfile::tempdir().unwrap();
        let collection = temp.path().join("missing-collection");
        let store = PrivateOramPointStagingStore::new(&collection);
        let (parent, frame) = bound_parent_and_frame(1);
        assert_eq!(
            store.prepare_bound(&frame, &parent).unwrap_err(),
            PrivateOramPointStagingError::Unsupported
        );
        assert_eq!(
            store.load_bound(&parent).unwrap_err(),
            PrivateOramPointStagingError::Unsupported
        );
        assert!(!store.root.exists());
        assert!(!collection.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn descriptor_state_and_point_id_digests_have_known_answers() {
        let (parent, frame_bytes) = bound_parent_and_frame(1);
        let stage = ValidatedPointStage::build(&frame_bytes, &parent).unwrap();
        assert_eq!(
            (
                stage.descriptor.descriptor_digest.as_str(),
                stage.state.state_digest.as_str(),
                stage.descriptor.canonical_point_id_digest.as_str(),
                digest_string(&stage.descriptor_bytes),
            ),
            (
                "j89dR3JHBa-o13HoAS4vykv0MowVF1NP1HVPUryGklw",
                "02gPY7BZq9SCBqKBw8YoToWveGhYlKa_O90pMEHvZX8",
                "qB7QAdhKddjmZWvIOWXFRyhHwKwuXVxVuwG9V6XsqDI",
                "lUa-ZRjIqPa_qaJpBxivtO7ch46whjNHwyW7m0UzPKk".to_string(),
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_reopen_and_exact_replay_are_idempotent() {
        let fixture = fixture(2);
        let (first, first_token) = prepare(&fixture);
        assert!(first.state.is_prepared());
        assert_eq!(
            first_token.child_descriptor_digest(),
            first.descriptor.descriptor_digest
        );
        assert_eq!(
            directory_entry_names(&fixture.store.root).unwrap(),
            [ACTIVE_DIR, LOCK_FILE]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect()
        );
        assert!(
            directory_entry_names(&active_path(&fixture).join(ACTIVE_TEMP_DIR))
                .unwrap()
                .is_empty()
        );

        let reopened = PrivateOramPointStagingStore::new(&fixture.collection);
        let (loaded, loaded_token) = reopened.load_bound(&fixture.parent).unwrap().unwrap();
        assert_eq!(loaded, first);
        assert_eq!(loaded_token, first_token);
        let (replayed, replayed_token) = reopened
            .prepare_bound(&fixture.frame_bytes, &fixture.parent)
            .unwrap();
        assert_eq!(replayed, first);
        assert_eq!(replayed_token, first_token);

        let mut advanced_parent = fixture.parent.clone();
        advanced_parent.permits_new_child_install = false;
        advanced_parent.expected_child_descriptor_digest =
            Some(first.descriptor.descriptor_digest.clone());
        let (advanced_replay, _) = reopened
            .prepare_bound(&fixture.frame_bytes, &advanced_parent)
            .unwrap();
        assert_eq!(advanced_replay, first);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_stage_is_callback_scoped_and_revalidates_exact_bytes() {
        let fixture = fixture(23);
        let (prepared, durable) = prepare(&fixture);
        let observed = fixture
            .store
            .with_live_stage_bound(&fixture.parent, |live| {
                let rendered = format!("{live:?}");
                assert!(!rendered.contains(&fixture.parent.mutation_bundle.mutation.collection_id));
                assert!(!rendered.contains(&live.frame().mutation_id));
                (
                    live.durable().child_descriptor_digest().to_string(),
                    live.frame().target_shard_ids.clone(),
                )
            })
            .unwrap();
        assert_eq!(observed.0, durable.child_descriptor_digest());
        assert_eq!(observed.0, prepared.descriptor.descriptor_digest);
        assert_eq!(observed.1, durable.target_shard_ids());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_stage_rejects_root_path_replacement_after_callback() {
        let fixture = fixture(24);
        prepare(&fixture);
        let moved = fixture.collection.join("moved-point-staging");
        let result = fixture.store.with_live_stage_bound(&fixture.parent, |_| {
            fs::rename(&fixture.store.root, &moved).unwrap();
            fs::create_dir(&fixture.store.root).unwrap();
            set_private_directory_permissions(&fixture.store.root).unwrap();
        });
        assert_eq!(result.unwrap_err(), PrivateOramPointStagingError::Corrupt);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn consumed_live_stage_does_not_reclassify_a_completed_parent_action() {
        let fixture = fixture(25);
        prepare(&fixture);
        let moved = fixture.collection.join("consumed-point-staging");
        let output = fixture
            .store
            .with_consumed_live_stage_bound(&fixture.parent, |_| {
                fs::rename(&fixture.store.root, &moved).unwrap();
                fs::create_dir(&fixture.store.root).unwrap();
                set_private_directory_permissions(&fixture.store.root).unwrap();
                7_u8
            })
            .unwrap();
        assert_eq!(output, 7);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_crash_candidate_is_ignored_but_preserved() {
        let fixture = fixture(21);
        fixture.store.ensure_root().unwrap();
        let stranded = fixture.store.root.join(".candidate-stranded");
        fs::create_dir(&stranded).unwrap();
        set_private_directory_permissions(&stranded).unwrap();

        let (prepared, _) = prepare(&fixture);
        assert!(stranded.is_dir());
        assert_eq!(
            fixture
                .store
                .load_bound(&fixture.parent)
                .unwrap()
                .unwrap()
                .0,
            prepared
        );
    }

    #[cfg(all(target_os = "linux", unix))]
    #[test]
    fn symlinked_crash_candidate_is_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = fixture(22);
        fixture.store.ensure_root().unwrap();
        let outside = fixture.collection.join("outside-candidate");
        fs::create_dir(&outside).unwrap();
        set_private_directory_permissions(&outside).unwrap();
        symlink(&outside, fixture.store.root.join(".candidate-symlink")).unwrap();

        assert_eq!(
            fixture.store.load_bound(&fixture.parent).unwrap_err(),
            PrivateOramPointStagingError::Corrupt
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn conflicting_stage_is_rejected_without_replacing_active() {
        let fixture = fixture(3);
        prepare(&fixture);
        let descriptor_path = active_path(&fixture).join(DESCRIPTOR_FILE);
        let original = fs::read(&descriptor_path).unwrap();
        let (other_parent, other_frame) = bound_parent_and_frame(4);
        assert_eq!(
            fixture
                .store
                .prepare_bound(&other_frame, &other_parent)
                .unwrap_err(),
            PrivateOramPointStagingError::ConcurrentStage
        );
        assert_eq!(fs::read(descriptor_path).unwrap(), original);
    }

    #[test]
    fn nonempty_server_vector_list_is_rejected_after_exact_binding() {
        let (mut parent, frame_bytes) = bound_parent_and_frame(5);
        let mut frame = decode_private_oram_staged_insert_frame_v1(&frame_bytes).unwrap();
        frame.point.vectors.push(PrivateOramStagedNamedVectorV1 {
            name: "server-vector".to_string(),
            vector: PrivateOramStagedVectorV1::Dense {
                values: vec![1.0, 2.0],
            },
        });
        let frame_bytes = rewrite_frame_and_parent(&frame, &mut parent);
        assert!(matches!(
            ValidatedPointStage::build(&frame_bytes, &parent),
            Err(PrivateOramPointStagingError::ServerVectorsForbidden)
        ));
    }

    #[test]
    fn parent_and_frame_mismatches_fail_closed() {
        let (parent, frame_bytes) = bound_parent_and_frame(6);
        let mut mismatched_bundle = parent.clone();
        mismatched_bundle.mutation_bundle.mutation.collection_id = "other-collection".to_string();
        mismatched_bundle.signed_mutation_digest =
            private_oram_append_mutation_v1_digest(&mismatched_bundle.mutation_bundle.mutation)
                .unwrap();
        assert!(matches!(
            ValidatedPointStage::build(&frame_bytes, &mismatched_bundle),
            Err(PrivateOramPointStagingError::InvalidFrame)
        ));

        let mut wrong_expected_child = parent;
        wrong_expected_child.permits_new_child_install = false;
        wrong_expected_child.expected_child_descriptor_digest = Some(digest(250));
        assert!(matches!(
            ValidatedPointStage::build(&frame_bytes, &wrong_expected_child),
            Err(PrivateOramPointStagingError::ParentMismatch)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tampered_frame_is_rejected() {
        let fixture = fixture(7);
        prepare(&fixture);
        let path = active_path(&fixture).join(FRAME_FILE);
        let mut bytes = fs::read(&path).unwrap();
        let offset = bytes.len() / 2;
        bytes[offset] ^= 0x40;
        fs::write(path, bytes).unwrap();
        assert_load_corrupt(&fixture);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn truncated_descriptor_is_rejected() {
        let fixture = fixture(8);
        prepare(&fixture);
        let file = OpenOptions::new()
            .write(true)
            .open(active_path(&fixture).join(DESCRIPTOR_FILE))
            .unwrap();
        file.set_len(17).unwrap();
        assert_load_corrupt(&fixture);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let fixture = fixture(9);
        prepare(&fixture);
        let file = OpenOptions::new()
            .write(true)
            .open(active_path(&fixture).join(FRAME_FILE))
            .unwrap();
        file.set_len(PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES as u64 + 1)
            .unwrap();
        assert_load_corrupt(&fixture);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trailing_state_bytes_and_future_phase_are_rejected() {
        let trailing = fixture(10);
        prepare(&trailing);
        let state_path = active_path(&trailing).join(STATE_FILE);
        let mut file = OpenOptions::new().append(true).open(&state_path).unwrap();
        file.write_all(&[0]).unwrap();
        file.sync_all().unwrap();
        assert_load_corrupt(&trailing);

        let future = fixture(11);
        prepare(&future);
        let state_path = active_path(&future).join(STATE_FILE);
        let mut state = fs::read(&state_path).unwrap();
        let phase_offset = 4 + STATE_DOMAIN.len() + 2;
        state[phase_offset] = PREPARED_PHASE_TAG + 1;
        fs::write(state_path, state).unwrap();
        assert_load_corrupt(&future);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn extra_active_entry_and_nonempty_temp_are_rejected() {
        let extra = fixture(12);
        prepare(&extra);
        fs::write(active_path(&extra).join("extra.bin"), b"x").unwrap();
        assert_load_corrupt(&extra);

        let nonempty_temp = fixture(13);
        prepare(&nonempty_temp);
        fs::write(
            active_path(&nonempty_temp)
                .join(ACTIVE_TEMP_DIR)
                .join("unexpected"),
            b"x",
        )
        .unwrap();
        assert_load_corrupt(&nonempty_temp);
    }

    #[cfg(all(target_os = "linux", unix))]
    #[test]
    fn symlink_and_fifo_substitution_are_rejected() {
        use std::os::unix::fs::symlink;

        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let symlinked = fixture(14);
        prepare(&symlinked);
        let descriptor = active_path(&symlinked).join(DESCRIPTOR_FILE);
        let outside = symlinked.collection.join("outside.bin");
        fs::write(&outside, b"outside").unwrap();
        fs::remove_file(&descriptor).unwrap();
        symlink(&outside, &descriptor).unwrap();
        assert_load_corrupt(&symlinked);

        let fifo = fixture(15);
        prepare(&fifo);
        let state = active_path(&fifo).join(STATE_FILE);
        fs::remove_file(&state).unwrap();
        mkfifo(&state, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert_load_corrupt(&fifo);
    }

    #[cfg(all(target_os = "linux", unix))]
    #[test]
    fn file_directory_modes_and_hardlinks_are_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let file_mode = fixture(16);
        prepare(&file_mode);
        fs::set_permissions(
            active_path(&file_mode).join(FRAME_FILE),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert_load_corrupt(&file_mode);

        let directory_mode = fixture(17);
        prepare(&directory_mode);
        fs::set_permissions(
            active_path(&directory_mode).join(ACTIVE_TEMP_DIR),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        assert_load_corrupt(&directory_mode);

        let hardlink = fixture(18);
        prepare(&hardlink);
        fs::hard_link(
            active_path(&hardlink).join(DESCRIPTOR_FILE),
            hardlink.collection.join("descriptor-alias"),
        )
        .unwrap();
        assert_load_corrupt(&hardlink);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nonreplace_syscall_preserves_an_existing_active_directory() {
        let fixture = fixture(19);
        prepare(&fixture);
        let descriptor_before = fs::read(active_path(&fixture).join(DESCRIPTOR_FILE)).unwrap();
        let candidate = fixture.store.root.join(".candidate-manual");
        fs::create_dir(&candidate).unwrap();
        set_private_directory_permissions(&candidate).unwrap();
        let root = open_private_directory(&fixture.store.root).unwrap();
        assert_eq!(
            rename_directory_noreplace(
                &root,
                candidate.file_name().unwrap(),
                OsStr::new(ACTIVE_DIR),
            )
            .unwrap_err(),
            PrivateOramPointStagingError::ConcurrentStage
        );
        assert_eq!(
            fs::read(active_path(&fixture).join(DESCRIPTOR_FILE)).unwrap(),
            descriptor_before
        );
        assert!(candidate.is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn debug_output_redacts_paths_payload_ids_and_digests() {
        let fixture = fixture(20);
        let (snapshot, token) = prepare(&fixture);
        let output = format!(
            "{fixture_store:?} {snapshot:?} {token:?} {error:?}",
            fixture_store = fixture.store,
            error = PrivateOramPointStagingError::Corrupt,
        );
        assert!(!output.contains("collection-secret"));
        assert!(!output.contains("payload-secret"));
        assert!(!output.contains(token.point_id()));
        assert!(!output.contains(token.frame_sha256()));
        assert!(!output.contains(&snapshot.descriptor.descriptor_digest));
        assert!(output.contains("[redacted]"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rename_components_must_be_single_components() {
        assert!(checked_single_component_cstring(OsStr::new("active")).is_ok());
        assert_eq!(
            checked_single_component_cstring(OsStr::new("a/b")).unwrap_err(),
            PrivateOramPointStagingError::InvalidInput("rename_component")
        );
        assert_eq!(
            checked_single_component_cstring(OsStr::new("..")).unwrap_err(),
            PrivateOramPointStagingError::InvalidInput("rename_component")
        );
    }
}
