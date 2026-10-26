use std::collections::HashMap;
#[cfg(feature = "staging")]
use std::collections::HashSet;
use std::fmt;
use std::fs::DirBuilder;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "staging")]
use std::sync::{Mutex, OnceLock};

use collection::config::CollectionConfigInternal;
use collection::private_hnsw_oram_store::PRIVATE_HNSW_ORAM_DIR;
use collection::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR;
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use fs_err as fs;
use fs_err::{File, OpenOptions};
use fs4::fs_std::FileExt;
use qdrant_sec::{
    PrivateOramExternalRecoveryCheckpointBundle,
    try_private_oram_external_recovery_checkpoint_signature_message,
    validate_private_oram_external_recovery_checkpoint_shape,
    validate_private_oram_recovery_signature_shape,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StorageError;
#[cfg(test)]
use crate::content_manager::consensus_ops::PrivateOramExternalRecoveryAuthority;
use crate::content_manager::consensus_ops::{
    PrivateOramExternalRecoveryKey, PrivateOramExternalRecoveryLease,
    PrivateOramExternalRecoveryLeasePhase, PrivateOramExternalRecoveryState,
};
use crate::content_manager::private_oram_mutation_journal::PRIVATE_ORAM_MUTATION_JOURNAL_DIR;
use crate::content_manager::toc::COLLECTIONS_DIR;
use crate::types::{
    PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES, PrivateOramExternalRecoveryConfig,
};

pub const PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES: u64 = 8 * 1024 * 1024;

const PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR: &str = "private_oram_external_recovery";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_FILE: &str = "state.json";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_SNAPSHOT_FILE: &str = "snapshot.upload";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_LOCK_FILE: &str = "recovery.lock";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR: &str = "verified_collection";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR: &str = "verified_collection.pending";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MARKER_FILE: &str = "install.json";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BACKUP_DIR: &str = "live_collection.backup";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_VERSION: u16 = 1;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_VERSION: u16 = 5;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_BYTES: u64 = 64 * 1024;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_TREE_DEPTH: usize = 64;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_TREE_ENTRIES: u64 = 10_000_000;
const PRIVATE_ORAM_SHA256_BASE64URL_LEN: usize = 43;
const PRIVATE_ORAM_SHA256_HEX_LEN: usize = 64;
const PRIVATE_ORAM_OPERATION_TOKEN_BYTES: usize = 32;
const PRIVATE_ORAM_OPERATION_TOKEN_LEN: usize = 43;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_COLLECTION_KEY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-staging-key/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_OPERATION_ID_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-operation-id/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-checkpoint-digest/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_TREE_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-tree-digest/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_PRIVATE_STATE_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-private-state-digest/v2";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_CONFIG_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-config-digest/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_INTENT_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-install-intent-digest/v1";
#[cfg(feature = "staging")]
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BULK_SYNC_ENOSPC_ONCE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BULK_SYNC_ENOSPC_ONCE_FILE";
#[cfg(feature = "staging")]
const PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BULK_SYNC_FAULT_MAX_BYTES: usize = 4 * 1024;

#[cfg(feature = "staging")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramExternalRecoveryInstallBulkSyncFault {
    operation_id_hash: String,
    tree: String,
}

#[cfg(feature = "staging")]
fn should_inject_private_oram_external_recovery_install_bulk_sync_enospc(
    operation_id_hash: &str,
    tree: &'static str,
) -> bool {
    let Some(selector_path) =
        std::env::var_os(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BULK_SYNC_ENOSPC_ONCE_FILE_ENV)
    else {
        return false;
    };
    if selector_path.is_empty() {
        return false;
    }
    let Ok(selector_bytes) = fs::read(selector_path) else {
        return false;
    };
    if selector_bytes.len() > PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BULK_SYNC_FAULT_MAX_BYTES {
        return false;
    }
    let Ok(selector) =
        serde_json::from_slice::<PrivateOramExternalRecoveryInstallBulkSyncFault>(&selector_bytes)
    else {
        return false;
    };
    if selector.operation_id_hash != operation_id_hash || selector.tree != tree {
        return false;
    }

    static CONSUMED: OnceLock<Mutex<HashSet<(String, String)>>> = OnceLock::new();
    CONSUMED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .is_ok_and(|mut consumed| {
            consumed.insert((operation_id_hash.to_string(), tree.to_string()))
        })
}

fn bulk_sync_private_oram_external_recovery_install_tree(
    path: &Path,
    _operation_id_hash: &str,
    _tree: &'static str,
) -> std::io::Result<()> {
    #[cfg(feature = "staging")]
    {
        if should_inject_private_oram_external_recovery_install_bulk_sync_enospc(
            _operation_id_hash,
            _tree,
        ) {
            log::warn!(
                "Private ORAM staging external recovery install bulk-sync ENOSPC injected: {_tree}",
            );
            return Err(std::io::Error::from_raw_os_error(nix::libc::ENOSPC));
        }
    }
    common::fs::bulk_sync_dir(path)
}

#[cfg(all(test, unix))]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PrivateOramExternalRecoveryIoFault {
    StateTempFileSync,
    StateParentDirectorySync,
    InstallMarkerTempFileSync,
    InstallMarkerParentDirectorySync,
    VerificationOutputRename,
    VerificationOutputParentDirectorySync,
    InstallTreeRename,
    InstallTreeSourceParentDirectorySync,
    InstallTreeDestinationParentDirectorySync,
}

#[cfg(all(test, unix))]
thread_local! {
    static PRIVATE_ORAM_EXTERNAL_RECOVERY_IO_FAULT: std::cell::Cell<Option<PrivateOramExternalRecoveryIoFault>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, unix))]
struct PrivateOramExternalRecoveryIoFaultGuard;

#[cfg(all(test, unix))]
impl Drop for PrivateOramExternalRecoveryIoFaultGuard {
    fn drop(&mut self) {
        PRIVATE_ORAM_EXTERNAL_RECOVERY_IO_FAULT.with(|fault| fault.set(None));
    }
}

#[cfg(all(test, unix))]
fn inject_private_oram_external_recovery_io_fault(
    point: PrivateOramExternalRecoveryIoFault,
) -> std::io::Result<()> {
    let should_fail = PRIVATE_ORAM_EXTERNAL_RECOVERY_IO_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        return Err(std::io::Error::from_raw_os_error(nix::libc::ENOSPC));
    }
    Ok(())
}

#[cfg(all(test, unix))]
fn set_private_oram_external_recovery_io_fault(
    point: PrivateOramExternalRecoveryIoFault,
) -> PrivateOramExternalRecoveryIoFaultGuard {
    PRIVATE_ORAM_EXTERNAL_RECOVERY_IO_FAULT.with(|fault| {
        assert!(
            fault.replace(Some(point)).is_none(),
            "private ORAM external recovery I/O fault already set",
        );
    });
    PrivateOramExternalRecoveryIoFaultGuard
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramExternalRecoveryStagingPhase {
    Uploading,
    Verified,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct PrivateOramExternalRecoveryStagingStatus {
    pub phase: PrivateOramExternalRecoveryStagingPhase,
    pub backup_generation: u64,
    pub bytes_received: u64,
    pub snapshot_size_bytes: u64,
    pub next_chunk_index: u64,
    pub chunk_size_bytes: u64,
    pub lease_expires_at_unix: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramExternalRecoveryInstallPhase {
    Prepared,
    OldMoved,
    NewPromoted,
    LoadInProgress,
    RollbackInProgress,
    RollbackComplete,
    Loaded,
    ConsensusCommitted,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramExternalRecoveryInstallMarker {
    version: u16,
    phase: PrivateOramExternalRecoveryInstallPhase,
    collection_name: String,
    collection_id: String,
    operation_id_hash: String,
    install_attempt_nonce: String,
    checkpoint_digest: String,
    backup_generation: u64,
    owner_peer_id: u64,
    layout_generation: u64,
    layout_digest: String,
    index_state_digest: String,
    old_tree_digest: String,
    old_config_digest: String,
    old_private_state_digest: String,
    new_tree_digest: String,
    new_config_digest: String,
    new_private_state_digest: String,
}

impl fmt::Debug for PrivateOramExternalRecoveryInstallMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryInstallMarker")
            .field("version", &self.version)
            .field("phase", &self.phase)
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .field("install_attempt_nonce", &"[redacted]")
            .field("checkpoint_digest", &"[redacted]")
            .field("backup_generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("layout_generation", &"[redacted]")
            .field("layout_digest", &"[redacted]")
            .field("index_state_digest", &"[redacted]")
            .field("old_tree_digest", &"[redacted]")
            .field("old_config_digest", &"[redacted]")
            .field("old_private_state_digest", &"[redacted]")
            .field("new_tree_digest", &"[redacted]")
            .field("new_config_digest", &"[redacted]")
            .field("new_private_state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOramExternalRecoveryInstallTreeState {
    OldReady,
    OldMoved,
    NewPromoted,
    Finalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOramExternalRecoveryConsensusInstallState {
    Staging,
    Installing,
    Committed,
    /// Consensus no longer carries this marker's lease (no record, no active lease, or a lease
    /// owned by another peer/operation) and the install was never committed. A marker that
    /// never replaced the live tree is cancelled locally instead of refusing to boot.
    Superseded,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramExternalRecoveryStagingState {
    version: u16,
    operation_id_hash: String,
    checkpoint_digest: String,
    checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
    lease_expires_at_unix: u64,
    bytes_received: u64,
    next_chunk_index: u64,
    phase: PrivateOramExternalRecoveryStagingPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_tree_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_private_state_digest: Option<String>,
}

impl fmt::Debug for PrivateOramExternalRecoveryStagingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryStagingState")
            .field("version", &self.version)
            .field("operation_id_hash", &"[redacted]")
            .field("checkpoint_digest", &"[redacted]")
            .field("checkpoint_bundle", &"[redacted]")
            .field("lease_expires_at_unix", &self.lease_expires_at_unix)
            .field("bytes_received", &self.bytes_received)
            .field("next_chunk_index", &self.next_chunk_index)
            .field("phase", &self.phase)
            .field("verified_tree_digest", &"[redacted]")
            .field("verified_private_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramExternalRecoveryStagingState {
    fn status(&self) -> PrivateOramExternalRecoveryStagingStatus {
        PrivateOramExternalRecoveryStagingStatus {
            phase: self.phase,
            backup_generation: self.checkpoint_bundle.checkpoint.backup_generation,
            bytes_received: self.bytes_received,
            snapshot_size_bytes: self.checkpoint_bundle.checkpoint.snapshot_size_bytes,
            next_chunk_index: self.next_chunk_index,
            chunk_size_bytes: PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES,
            lease_expires_at_unix: self.lease_expires_at_unix,
        }
    }
}

#[derive(Clone)]
pub struct PrivateOramExternalRecoveryStaging {
    storage_path: PathBuf,
    collection_id: String,
    operation_id_hash: String,
}

impl fmt::Debug for PrivateOramExternalRecoveryStaging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryStaging")
            .field("storage_path", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .finish()
    }
}

pub struct PrivateOramExternalRecoveryVerification {
    checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
    snapshot_path: PathBuf,
    verified_collection_path: PathBuf,
    verify_temp_collection_path: PathBuf,
    operation_id_hash: String,
    checkpoint_digest: String,
    archive_identity: FileIdentity,
    _collection_lock: PrivateOramExternalRecoveryLock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateOramExternalRecoveryArchiveResources {
    pub entry_count: u64,
    pub logical_bytes: u64,
}

impl fmt::Debug for PrivateOramExternalRecoveryVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryVerification")
            .field("checkpoint_bundle", &"[redacted]")
            .field("snapshot_path", &"[redacted]")
            .field("verified_collection_path", &"[redacted]")
            .field("verify_temp_collection_path", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .field("checkpoint_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct PrivateOramExternalRecoveryLock {
    _file: std::fs::File,
}

pub struct PrivateOramExternalRecoveryInstallTransaction {
    staging: PrivateOramExternalRecoveryStaging,
    marker: PrivateOramExternalRecoveryInstallMarker,
    _collection_lock: PrivateOramExternalRecoveryLock,
}

impl fmt::Debug for PrivateOramExternalRecoveryInstallTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryInstallTransaction")
            .field("staging", &self.staging)
            .field("phase", &self.marker.phase)
            .finish()
    }
}

impl PrivateOramExternalRecoveryVerification {
    pub fn checkpoint_bundle(&self) -> &PrivateOramExternalRecoveryCheckpointBundle {
        &self.checkpoint_bundle
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub fn verified_collection_path(&self) -> &Path {
        &self.verified_collection_path
    }

    pub fn verify_temp_collection_path(&self) -> &Path {
        &self.verify_temp_collection_path
    }

    pub fn reset_verification_output(&self) -> Result<(), StorageError> {
        remove_secure_directory_if_exists(&self.verify_temp_collection_path)?;
        remove_secure_directory_if_exists(&self.verified_collection_path)?;
        ensure_secure_directory(&self.verify_temp_collection_path)
    }

    pub fn promote_verification_output(&self) -> Result<(), StorageError> {
        validate_secure_directory(&self.verify_temp_collection_path)?;
        match fs::symlink_metadata(&self.verified_collection_path) {
            Ok(_) => return Err(invalid_staging_state()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid_staging_state()),
        }
        #[cfg(all(test, unix))]
        inject_private_oram_external_recovery_io_fault(
            PrivateOramExternalRecoveryIoFault::VerificationOutputRename,
        )
        .map_err(|_| invalid_staging_state())?;
        fs::rename(
            &self.verify_temp_collection_path,
            &self.verified_collection_path,
        )
        .map_err(|_| invalid_staging_state())?;
        #[cfg(all(test, unix))]
        inject_private_oram_external_recovery_io_fault(
            PrivateOramExternalRecoveryIoFault::VerificationOutputParentDirectorySync,
        )
        .map_err(|_| invalid_staging_state())?;
        common::fs::sync_parent_dir(&self.verified_collection_path)
            .map_err(|_| invalid_staging_state())
    }

    pub fn validate_archive_resources(
        &self,
        limits: &PrivateOramExternalRecoveryConfig,
    ) -> Result<PrivateOramExternalRecoveryArchiveResources, StorageError> {
        let file = open_regular_file(
            &self.snapshot_path,
            true,
            Some(PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES),
        )?;
        if file_identity(&file)? != self.archive_identity {
            return Err(invalid_staging_state());
        }

        let mut archive = tar::Archive::new(file);
        let mut entry_count = 0_u64;
        let mut unpacked_bytes = 0_u64;
        for entry in archive.entries().map_err(|_| invalid_staging_request())? {
            let entry = entry.map_err(|_| invalid_staging_request())?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(invalid_staging_request)?;
            if entry_count > PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_TREE_ENTRIES {
                return Err(invalid_staging_request());
            }
            match entry.header().entry_type() {
                tar::EntryType::Directory => {}
                tar::EntryType::Regular | tar::EntryType::GNUSparse => {
                    let size = entry
                        .header()
                        .size()
                        .map_err(|_| invalid_staging_request())?;
                    unpacked_bytes = unpacked_bytes
                        .checked_add(size)
                        .ok_or_else(invalid_staging_request)?;
                    if unpacked_bytes > limits.max_unpacked_bytes {
                        return Err(invalid_staging_request());
                    }
                }
                _ => return Err(invalid_staging_request()),
            }
        }
        ensure_private_oram_external_recovery_free_space(
            &self.snapshot_path,
            unpacked_bytes,
            limits.min_free_space_bytes,
        )?;
        Ok(PrivateOramExternalRecoveryArchiveResources {
            entry_count,
            logical_bytes: unpacked_bytes,
        })
    }
}

pub fn private_oram_external_recovery_reservation_bytes(
    snapshot_size_bytes: u64,
    limits: &PrivateOramExternalRecoveryConfig,
) -> Result<u64, StorageError> {
    if snapshot_size_bytes == 0
        || snapshot_size_bytes > limits.max_snapshot_bytes
        || snapshot_size_bytes > PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES
    {
        return Err(invalid_staging_request());
    }
    snapshot_size_bytes
        .checked_add(limits.max_unpacked_bytes)
        .ok_or_else(invalid_staging_request)
}

pub fn load_private_oram_external_recovery_reservations(
    storage_path: &Path,
    limits: &PrivateOramExternalRecoveryConfig,
) -> Result<HashMap<String, u64>, StorageError> {
    let base_path = storage_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR);
    match fs::symlink_metadata(&base_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HashMap::new());
        }
        Err(_) => return Err(invalid_staging_state()),
        Ok(_) => validate_secure_directory(&base_path)?,
    }

    let mut reservations = HashMap::new();
    for collection_entry in fs::read_dir(&base_path).map_err(|_| invalid_staging_state())? {
        let collection_path = collection_entry
            .map_err(|_| invalid_staging_state())?
            .path();
        validate_secure_directory(&collection_path)?;
        let collection_key = collection_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(invalid_staging_state)?;
        validate_base64url_sha256(collection_key).map_err(|_| invalid_staging_state())?;

        for operation_entry in
            fs::read_dir(&collection_path).map_err(|_| invalid_staging_state())?
        {
            let operation_path = operation_entry.map_err(|_| invalid_staging_state())?.path();
            let entry_name = operation_path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(invalid_staging_state)?;
            if entry_name == PRIVATE_ORAM_EXTERNAL_RECOVERY_LOCK_FILE {
                let metadata =
                    fs::symlink_metadata(&operation_path).map_err(|_| invalid_staging_state())?;
                validate_secure_file_metadata(&metadata, 0)?;
                continue;
            }
            if entry_name == PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MARKER_FILE {
                if read_install_marker(&operation_path)?.is_none() {
                    return Err(invalid_staging_state());
                }
                continue;
            }

            validate_base64url_sha256(entry_name).map_err(|_| invalid_staging_state())?;
            validate_secure_directory(&operation_path)?;
            let state = read_private_oram_external_recovery_state_file(
                &operation_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_FILE),
            )?
            .ok_or_else(invalid_staging_state)?;
            let staging = PrivateOramExternalRecoveryStaging::new(
                storage_path,
                &state.checkpoint_bundle.checkpoint.collection_id,
                entry_name,
            )?;
            if staging.collection_path() != collection_path
                || staging.operation_path() != operation_path
            {
                return Err(invalid_staging_state());
            }
            let reserved = private_oram_external_recovery_reservation_bytes(
                state.checkpoint_bundle.checkpoint.snapshot_size_bytes,
                limits,
            )?;
            if reservations
                .insert(state.operation_id_hash.clone(), reserved)
                .is_some()
            {
                return Err(invalid_staging_state());
            }
        }
    }
    Ok(reservations)
}

impl PrivateOramExternalRecoveryStaging {
    pub fn new(
        storage_path: impl Into<PathBuf>,
        collection_id: &str,
        operation_id_hash: &str,
    ) -> Result<Self, StorageError> {
        if collection_id.is_empty() || collection_id.len() > 1024 {
            return Err(invalid_staging_request());
        }
        validate_base64url_sha256(operation_id_hash)?;
        Ok(Self {
            storage_path: storage_path.into(),
            collection_id: collection_id.to_string(),
            operation_id_hash: operation_id_hash.to_string(),
        })
    }

    pub fn begin(
        &self,
        checkpoint_digest: &str,
        checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
        lease_expires_at_unix: u64,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        validate_base64url_sha256(checkpoint_digest)?;
        validate_private_oram_external_recovery_checkpoint_shape(&checkpoint_bundle.checkpoint)
            .map_err(|_| invalid_staging_request())?;
        validate_private_oram_recovery_signature_shape(&checkpoint_bundle.signature)
            .map_err(|_| invalid_staging_request())?;
        if checkpoint_bundle.checkpoint.collection_id != self.collection_id
            || checkpoint_bundle.checkpoint.snapshot_size_bytes
                > PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES
            || checkpoint_bundle.checkpoint.snapshot_size_bytes == 0
            || lease_expires_at_unix == 0
            || private_oram_external_recovery_checkpoint_digest(&checkpoint_bundle)?
                != checkpoint_digest
        {
            return Err(invalid_staging_request());
        }

        self.ensure_collection_directories()?;
        let _collection_lock = self.acquire_collection_lock(true)?;
        if read_install_marker(&self.install_marker_path())?.is_some() {
            return Err(invalid_install_state());
        }
        ensure_secure_directory(&self.operation_path())?;
        let desired = PrivateOramExternalRecoveryStagingState {
            version: PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_VERSION,
            operation_id_hash: self.operation_id_hash.clone(),
            checkpoint_digest: checkpoint_digest.to_string(),
            checkpoint_bundle,
            lease_expires_at_unix,
            bytes_received: 0,
            next_chunk_index: 0,
            phase: PrivateOramExternalRecoveryStagingPhase::Uploading,
            verified_tree_digest: None,
            verified_private_state_digest: None,
        };
        validate_state(&desired)?;

        if let Some(mut existing) = self.read_state()? {
            let same_recovery = existing.version == desired.version
                && existing.operation_id_hash == desired.operation_id_hash
                && existing.checkpoint_digest == desired.checkpoint_digest
                && existing.checkpoint_bundle == desired.checkpoint_bundle;
            if !same_recovery || lease_expires_at_unix < existing.lease_expires_at_unix {
                return Err(invalid_staging_state());
            }
            self.reconcile_snapshot_file(&existing)?;
            if lease_expires_at_unix > existing.lease_expires_at_unix {
                existing.lease_expires_at_unix = lease_expires_at_unix;
                self.write_state(&existing)?;
            }
            return Ok(existing.status());
        }

        self.create_empty_snapshot_file()?;
        self.write_state(&desired)?;
        Ok(desired.status())
    }

    pub fn begin_with_limits(
        &self,
        checkpoint_digest: &str,
        checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
        lease_expires_at_unix: u64,
        limits: &PrivateOramExternalRecoveryConfig,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        let snapshot_size_bytes = checkpoint_bundle.checkpoint.snapshot_size_bytes;
        private_oram_external_recovery_reservation_bytes(snapshot_size_bytes, limits)?;
        ensure_private_oram_external_recovery_free_space(
            &self.storage_path,
            snapshot_size_bytes,
            limits.min_free_space_bytes,
        )?;
        self.begin(checkpoint_digest, checkpoint_bundle, lease_expires_at_unix)
    }

    pub fn status(&self) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        let _collection_lock = self.acquire_collection_lock(false)?;
        let state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        Ok(state.status())
    }

    pub fn status_for_consensus_lease(
        &self,
        checkpoint_digest: &str,
        backup_generation: u64,
        lease_expires_at_unix: u64,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        validate_base64url_sha256(checkpoint_digest)?;
        let _collection_lock = self.acquire_collection_lock(false)?;
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        if state.checkpoint_digest != checkpoint_digest
            || state.checkpoint_bundle.checkpoint.backup_generation != backup_generation
            || lease_expires_at_unix < state.lease_expires_at_unix
        {
            return Err(invalid_staging_state());
        }
        if lease_expires_at_unix > state.lease_expires_at_unix {
            state.lease_expires_at_unix = lease_expires_at_unix;
            self.write_state(&state)?;
        }
        Ok(state.status())
    }

    pub fn status_and_checkpoint_bundle_for_consensus_lease(
        &self,
        checkpoint_digest: &str,
        backup_generation: u64,
        lease_expires_at_unix: u64,
    ) -> Result<
        (
            PrivateOramExternalRecoveryStagingStatus,
            PrivateOramExternalRecoveryCheckpointBundle,
        ),
        StorageError,
    > {
        validate_base64url_sha256(checkpoint_digest)?;
        let _collection_lock = self.acquire_collection_lock(false)?;
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        if state.checkpoint_digest != checkpoint_digest
            || state.checkpoint_bundle.checkpoint.backup_generation != backup_generation
            || lease_expires_at_unix < state.lease_expires_at_unix
        {
            return Err(invalid_staging_state());
        }
        if lease_expires_at_unix > state.lease_expires_at_unix {
            state.lease_expires_at_unix = lease_expires_at_unix;
            self.write_state(&state)?;
        }
        Ok((state.status(), state.checkpoint_bundle))
    }

    pub fn append_chunk(
        &self,
        chunk_index: u64,
        chunk_path: &Path,
        chunk_sha256: &str,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        validate_lowercase_sha256(chunk_sha256)?;
        let _collection_lock = self.acquire_collection_lock(false)?;
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        let total_size = state.checkpoint_bundle.checkpoint.snapshot_size_bytes;
        let expected_offset = chunk_index
            .checked_mul(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES)
            .ok_or_else(invalid_staging_request)?;
        if expected_offset >= total_size {
            return Err(invalid_staging_request());
        }
        let expected_len =
            (total_size - expected_offset).min(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES);
        let mut chunk = open_regular_file(chunk_path, false, None)?;
        let chunk_identity = file_identity(&chunk)?;
        if chunk_identity.len != expected_len {
            return Err(invalid_staging_request());
        }
        let actual_chunk_sha256 = lowercase_sha256_reader(&mut chunk)?;
        if actual_chunk_sha256 != chunk_sha256 {
            return Err(StorageError::bad_request(
                "private ORAM external recovery chunk hash mismatch",
            ));
        }

        if chunk_index < state.next_chunk_index {
            let mut snapshot = self.open_snapshot_file(false)?;
            snapshot.seek(SeekFrom::Start(expected_offset))?;
            let existing_sha256 = lowercase_sha256_reader_limited(&mut snapshot, expected_len)?;
            if existing_sha256 != chunk_sha256 {
                return Err(StorageError::bad_request(
                    "private ORAM external recovery duplicate chunk does not match",
                ));
            }
            return Ok(state.status());
        }
        if chunk_index != state.next_chunk_index
            || expected_offset != state.bytes_received
            || state.phase != PrivateOramExternalRecoveryStagingPhase::Uploading
        {
            return Err(StorageError::bad_request(
                "private ORAM external recovery chunk is out of order",
            ));
        }

        let mut snapshot = self.open_snapshot_file(true)?;
        let snapshot_identity = file_identity(&snapshot)?;
        if snapshot_identity.len != state.bytes_received {
            return Err(invalid_staging_state());
        }
        snapshot.seek(SeekFrom::Start(state.bytes_received))?;
        chunk.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(&mut chunk.take(expected_len + 1), &mut snapshot)?;
        if copied != expected_len {
            snapshot.set_len(state.bytes_received)?;
            snapshot.sync_all()?;
            return Err(invalid_staging_state());
        }
        snapshot.sync_all()?;

        state.bytes_received = state
            .bytes_received
            .checked_add(expected_len)
            .ok_or_else(invalid_staging_state)?;
        state.next_chunk_index = state
            .next_chunk_index
            .checked_add(1)
            .ok_or_else(invalid_staging_state)?;
        validate_state(&state)?;
        self.write_state(&state)?;
        Ok(state.status())
    }

    pub fn append_chunk_with_limits(
        &self,
        chunk_index: u64,
        chunk_path: &Path,
        chunk_sha256: &str,
        limits: &PrivateOramExternalRecoveryConfig,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        let state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        private_oram_external_recovery_reservation_bytes(
            state.checkpoint_bundle.checkpoint.snapshot_size_bytes,
            limits,
        )?;
        let expected_offset = chunk_index
            .checked_mul(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES)
            .ok_or_else(invalid_staging_request)?;
        let remaining = state
            .checkpoint_bundle
            .checkpoint
            .snapshot_size_bytes
            .checked_sub(expected_offset)
            .ok_or_else(invalid_staging_request)?;
        ensure_private_oram_external_recovery_free_space(
            &self.storage_path,
            remaining.min(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES),
            limits.min_free_space_bytes,
        )?;
        self.append_chunk(chunk_index, chunk_path, chunk_sha256)
    }

    pub fn prepare_verification(
        &self,
    ) -> Result<PrivateOramExternalRecoveryVerification, StorageError> {
        let collection_lock = self.acquire_collection_lock(false)?;
        let state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        if state.bytes_received != state.checkpoint_bundle.checkpoint.snapshot_size_bytes {
            return Err(StorageError::bad_request(
                "private ORAM external recovery upload is incomplete",
            ));
        }
        let snapshot_path = self.snapshot_path();
        let mut snapshot = self.open_snapshot_file(false)?;
        let archive_identity = file_identity(&snapshot)?;
        let snapshot_sha256 = lowercase_sha256_reader(&mut snapshot)?;
        if snapshot_sha256 != state.checkpoint_bundle.checkpoint.snapshot_sha256 {
            return Err(StorageError::bad_request(
                "private ORAM external recovery snapshot hash mismatch",
            ));
        }
        Ok(PrivateOramExternalRecoveryVerification {
            checkpoint_bundle: state.checkpoint_bundle,
            snapshot_path,
            verified_collection_path: self
                .operation_path()
                .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR),
            verify_temp_collection_path: self
                .operation_path()
                .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR),
            operation_id_hash: self.operation_id_hash.clone(),
            checkpoint_digest: state.checkpoint_digest,
            archive_identity,
            _collection_lock: collection_lock,
        })
    }

    pub fn prepare_verification_with_limits(
        &self,
        limits: &PrivateOramExternalRecoveryConfig,
    ) -> Result<
        (
            PrivateOramExternalRecoveryVerification,
            PrivateOramExternalRecoveryArchiveResources,
        ),
        StorageError,
    > {
        let verification = self.prepare_verification()?;
        private_oram_external_recovery_reservation_bytes(
            verification
                .checkpoint_bundle
                .checkpoint
                .snapshot_size_bytes,
            limits,
        )?;
        let archive_resources = verification.validate_archive_resources(limits)?;
        Ok((verification, archive_resources))
    }

    pub fn ensure_install_free_space(
        &self,
        limits: &PrivateOramExternalRecoveryConfig,
    ) -> Result<(), StorageError> {
        ensure_private_oram_external_recovery_free_space(
            &self.storage_path,
            0,
            limits.min_free_space_bytes,
        )
    }

    pub fn mark_verified(
        &self,
        verification: PrivateOramExternalRecoveryVerification,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        if verification.operation_id_hash != self.operation_id_hash {
            return Err(invalid_staging_request());
        }
        if verification.snapshot_path != self.snapshot_path()
            || verification.verified_collection_path
                != self
                    .operation_path()
                    .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR)
            || verification.verify_temp_collection_path
                != self
                    .operation_path()
                    .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR)
        {
            return Err(invalid_staging_request());
        }
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        let mut snapshot = self.open_snapshot_file(false)?;
        let archive_identity = file_identity(&snapshot)?;
        let archive_sha256 = lowercase_sha256_reader(&mut snapshot)?;
        if state.checkpoint_digest != verification.checkpoint_digest
            || state.checkpoint_bundle != verification.checkpoint_bundle
            || archive_identity != verification.archive_identity
            || archive_sha256 != state.checkpoint_bundle.checkpoint.snapshot_sha256
            || !secure_directory_exists(&verification.verified_collection_path)?
        {
            return Err(invalid_staging_state());
        }
        state.verified_tree_digest = Some(
            private_oram_external_recovery_tree_digest(&verification.verified_collection_path)
                .map_err(|_| invalid_staging_state())?,
        );
        state.verified_private_state_digest = Some(
            private_oram_external_recovery_private_state_digest(
                &verification.verified_collection_path,
            )
            .map_err(|_| invalid_staging_state())?,
        );
        state.phase = PrivateOramExternalRecoveryStagingPhase::Verified;
        validate_state(&state)?;
        self.write_state(&state)?;
        Ok(state.status())
    }

    pub fn abort(&self) -> Result<(), StorageError> {
        let _collection_lock = self.acquire_collection_lock(false)?;
        if read_install_marker(&self.install_marker_path())?.is_some() {
            return Err(invalid_install_state());
        }
        let operation_path = self.operation_path();
        match fs::symlink_metadata(&operation_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(invalid_staging_state()),
            Ok(_) => validate_secure_directory(&operation_path)?,
        }
        let state = self.read_state()?.ok_or_else(invalid_staging_state)?;
        if state.operation_id_hash != self.operation_id_hash
            || state.checkpoint_bundle.checkpoint.collection_id != self.collection_id
        {
            return Err(invalid_staging_state());
        }
        fs::remove_dir_all(&operation_path).map_err(|_| invalid_staging_state())?;
        common::fs::sync_parent_dir(&operation_path).map_err(|_| invalid_staging_state())?;
        Ok(())
    }

    pub fn prepare_install(
        &self,
        collection_name: &str,
        lease: &PrivateOramExternalRecoveryLease,
    ) -> Result<PrivateOramExternalRecoveryInstallTransaction, StorageError> {
        validate_install_collection_name(collection_name)?;
        let collection_lock = self.acquire_collection_lock(false)?;
        if let Some(marker) = read_install_marker(&self.install_marker_path())? {
            validate_install_marker_for_staging(&marker, self, collection_name, lease)?;
            return Ok(PrivateOramExternalRecoveryInstallTransaction {
                staging: self.clone(),
                marker,
                _collection_lock: collection_lock,
            });
        }
        if lease.phase != PrivateOramExternalRecoveryLeasePhase::Staging {
            return Err(invalid_install_state());
        }

        let state = self.read_state()?.ok_or_else(invalid_install_state)?;
        self.reconcile_snapshot_file(&state)?;
        let checkpoint = state.checkpoint_bundle.checkpoint.clone();
        if state.phase != PrivateOramExternalRecoveryStagingPhase::Verified
            || state.operation_id_hash != lease.operation_id_hash
            || state.checkpoint_digest != lease.checkpoint_digest
            || checkpoint.collection_id != self.collection_id
            || checkpoint.backup_generation != lease.backup_generation
        {
            return Err(invalid_install_state());
        }

        let verified_path = self.verified_collection_path();
        let live_path = self.live_collection_path(collection_name);
        let backup_path = self.install_backup_path();
        validate_owned_directory(&verified_path, true)?;
        validate_owned_directory(&live_path, false)?;
        validate_install_tree_collection_identity(
            &verified_path,
            collection_name,
            &self.collection_id,
        )?;
        validate_install_tree_collection_identity(
            &live_path,
            collection_name,
            &self.collection_id,
        )?;
        validate_missing_path(&backup_path)?;
        bulk_sync_private_oram_external_recovery_install_tree(
            &verified_path,
            &self.operation_id_hash,
            "verified",
        )
        .map_err(|_| invalid_install_state())?;
        bulk_sync_private_oram_external_recovery_install_tree(
            &live_path,
            &self.operation_id_hash,
            "live",
        )
        .map_err(|_| invalid_install_state())?;

        let verified_tree_digest = state
            .verified_tree_digest
            .clone()
            .ok_or_else(invalid_install_state)?;
        let verified_private_state_digest = state
            .verified_private_state_digest
            .clone()
            .ok_or_else(invalid_install_state)?;
        if private_oram_external_recovery_tree_digest(&verified_path)? != verified_tree_digest
            || private_oram_external_recovery_private_state_digest(&verified_path)?
                != verified_private_state_digest
        {
            return Err(invalid_install_state());
        }

        let marker = PrivateOramExternalRecoveryInstallMarker {
            version: PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_VERSION,
            phase: PrivateOramExternalRecoveryInstallPhase::Prepared,
            collection_name: collection_name.to_string(),
            collection_id: self.collection_id.clone(),
            operation_id_hash: self.operation_id_hash.clone(),
            install_attempt_nonce: BASE64URL_NOPAD.encode(&rand::random::<[u8; 32]>()),
            checkpoint_digest: state.checkpoint_digest,
            backup_generation: checkpoint.backup_generation,
            owner_peer_id: lease.owner_peer_id,
            layout_generation: checkpoint.layout_generation,
            layout_digest: checkpoint.layout_digest.clone(),
            index_state_digest: checkpoint.index_state_digest.clone(),
            old_tree_digest: private_oram_external_recovery_tree_digest(&live_path)?,
            old_config_digest: private_oram_external_recovery_config_digest(&live_path)?,
            old_private_state_digest: private_oram_external_recovery_private_state_digest(
                &live_path,
            )?,
            new_tree_digest: verified_tree_digest,
            new_config_digest: private_oram_external_recovery_config_digest(&verified_path)?,
            new_private_state_digest: verified_private_state_digest,
        };
        validate_install_marker(&marker)?;
        write_install_marker(&self.install_marker_path(), None, &marker)?;

        Ok(PrivateOramExternalRecoveryInstallTransaction {
            staging: self.clone(),
            marker,
            _collection_lock: collection_lock,
        })
    }

    pub fn install_marker_is_present(&self) -> Result<bool, StorageError> {
        Ok(read_install_marker(&self.install_marker_path())?.is_some())
    }

    pub fn resume_committed_install(
        &self,
        collection_name: &str,
        committed: &PrivateOramExternalRecoveryState,
    ) -> Result<PrivateOramExternalRecoveryInstallTransaction, StorageError> {
        validate_install_collection_name(collection_name)?;
        let collection_lock = self.acquire_collection_lock(false)?;
        let marker =
            read_install_marker(&self.install_marker_path())?.ok_or_else(invalid_install_state)?;
        validate_install_marker_staging_binding(&marker, self)?;
        if marker.collection_name != collection_name
            || !matches!(
                marker.phase,
                PrivateOramExternalRecoveryInstallPhase::Loaded
                    | PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted
            )
            || consensus_install_state(&marker, Some(committed))?
                != PrivateOramExternalRecoveryConsensusInstallState::Committed
        {
            return Err(invalid_install_state());
        }
        Ok(PrivateOramExternalRecoveryInstallTransaction {
            staging: self.clone(),
            marker,
            _collection_lock: collection_lock,
        })
    }

    pub fn cancel_prepared_install_if_present(
        &self,
        collection_name: &str,
        lease: &PrivateOramExternalRecoveryLease,
    ) -> Result<(), StorageError> {
        let collection_lock = self.acquire_collection_lock(false)?;
        let Some(marker) = read_install_marker(&self.install_marker_path())? else {
            return Ok(());
        };
        validate_install_marker_for_staging(&marker, self, collection_name, lease)?;
        PrivateOramExternalRecoveryInstallTransaction {
            staging: self.clone(),
            marker,
            _collection_lock: collection_lock,
        }
        .cancel_rolled_back_or_prepared()
    }

    fn ensure_collection_directories(&self) -> Result<(), StorageError> {
        if !self.storage_path.is_dir() {
            return Err(invalid_staging_state());
        }
        ensure_secure_directory(&self.base_path())?;
        ensure_secure_directory(&self.collection_path())
    }

    fn acquire_collection_lock(
        &self,
        create: bool,
    ) -> Result<PrivateOramExternalRecoveryLock, StorageError> {
        let lock_path = self.collection_lock_path();
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            options
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .mode(0o600);
        }
        let file = options.open(&lock_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::not_found("private ORAM external recovery not found")
            } else {
                invalid_staging_state()
            }
        })?;
        let opened = file.metadata().map_err(|_| invalid_staging_state())?;
        validate_secure_file_metadata(&opened, 0)?;
        FileExt::lock_exclusive(&file).map_err(|_| invalid_staging_state())?;
        let current = fs::symlink_metadata(&lock_path).map_err(|_| invalid_staging_state())?;
        ensure_same_file(&opened, &current)?;
        validate_secure_file_metadata(&current, 0)?;
        if create {
            file.sync_all().map_err(|_| invalid_staging_state())?;
            common::fs::sync_parent_dir(&lock_path).map_err(|_| invalid_staging_state())?;
        }
        Ok(PrivateOramExternalRecoveryLock { _file: file })
    }

    fn create_empty_snapshot_file(&self) -> Result<(), StorageError> {
        let snapshot_path = self.snapshot_path();
        match fs::symlink_metadata(&snapshot_path) {
            Ok(_) => {
                let file = self.open_snapshot_file(true)?;
                if file_identity(&file)?.len != 0 {
                    return Err(invalid_staging_state());
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid_staging_state()),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_open_options(&mut options, true);
        let file = options
            .open(&snapshot_path)
            .map_err(|_| invalid_staging_state())?;
        file.sync_all().map_err(|_| invalid_staging_state())?;
        common::fs::sync_parent_dir(&snapshot_path).map_err(|_| invalid_staging_state())
    }

    fn reconcile_snapshot_file(
        &self,
        state: &PrivateOramExternalRecoveryStagingState,
    ) -> Result<(), StorageError> {
        let file = self.open_snapshot_file(true)?;
        let identity = file_identity(&file)?;
        if identity.len < state.bytes_received
            || identity.len > state.checkpoint_bundle.checkpoint.snapshot_size_bytes
        {
            return Err(invalid_staging_state());
        }
        if identity.len > state.bytes_received {
            file.set_len(state.bytes_received)
                .map_err(|_| invalid_staging_state())?;
            file.sync_all().map_err(|_| invalid_staging_state())?;
        }
        Ok(())
    }

    fn read_state(&self) -> Result<Option<PrivateOramExternalRecoveryStagingState>, StorageError> {
        let state = read_private_oram_external_recovery_state_file(&self.state_path())?;
        let Some(state) = state else {
            return Ok(None);
        };
        if state.operation_id_hash != self.operation_id_hash
            || state.checkpoint_bundle.checkpoint.collection_id != self.collection_id
        {
            return Err(invalid_staging_state());
        }
        Ok(Some(state))
    }

    fn write_state(
        &self,
        state: &PrivateOramExternalRecoveryStagingState,
    ) -> Result<(), StorageError> {
        validate_state(state)?;
        let bytes = serde_json::to_vec(state).map_err(|_| invalid_staging_state())?;
        if bytes.is_empty() || bytes.len() as u64 > PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES {
            return Err(invalid_staging_state());
        }
        let temp_path = self
            .operation_path()
            .join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
        let state_path = self.state_path();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_open_options(&mut options, true);
        let result = (|| {
            let mut file = options
                .open(&temp_path)
                .map_err(|_| invalid_staging_state())?;
            file.write_all(&bytes)
                .map_err(|_| invalid_staging_state())?;
            #[cfg(all(test, unix))]
            inject_private_oram_external_recovery_io_fault(
                PrivateOramExternalRecoveryIoFault::StateTempFileSync,
            )
            .map_err(|_| invalid_staging_state())?;
            file.sync_all().map_err(|_| invalid_staging_state())?;
            fs::rename(&temp_path, &state_path).map_err(|_| invalid_staging_state())?;
            #[cfg(all(test, unix))]
            inject_private_oram_external_recovery_io_fault(
                PrivateOramExternalRecoveryIoFault::StateParentDirectorySync,
            )
            .map_err(|_| invalid_staging_state())?;
            common::fs::sync_parent_dir(&state_path).map_err(|_| invalid_staging_state())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn open_snapshot_file(&self, write: bool) -> Result<File, StorageError> {
        open_regular_file(
            &self.snapshot_path(),
            true,
            Some(PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES),
        )
        .and_then(|file| {
            if write {
                let original = file.metadata().map_err(|_| invalid_staging_state())?;
                drop(file);
                let mut options = OpenOptions::new();
                options.read(true).write(true);
                secure_open_options(&mut options, false);
                let reopened = options
                    .open(self.snapshot_path())
                    .map_err(|_| invalid_staging_state())?;
                let reopened_metadata = reopened.metadata().map_err(|_| invalid_staging_state())?;
                ensure_same_file(&original, &reopened_metadata)?;
                validate_secure_file_metadata(
                    &reopened_metadata,
                    PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES,
                )?;
                Ok(reopened)
            } else {
                Ok(file)
            }
        })
    }

    fn base_path(&self) -> PathBuf {
        self.storage_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR)
    }

    fn collection_path(&self) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_COLLECTION_KEY_DOMAIN);
        hasher.update((self.collection_id.len() as u64).to_be_bytes());
        hasher.update(self.collection_id.as_bytes());
        self.base_path()
            .join(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    fn operation_path(&self) -> PathBuf {
        self.collection_path().join(&self.operation_id_hash)
    }

    fn collection_lock_path(&self) -> PathBuf {
        self.collection_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_LOCK_FILE)
    }

    fn state_path(&self) -> PathBuf {
        self.operation_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_FILE)
    }

    fn snapshot_path(&self) -> PathBuf {
        self.operation_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_SNAPSHOT_FILE)
    }

    fn verified_collection_path(&self) -> PathBuf {
        self.operation_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR)
    }

    fn install_backup_path(&self) -> PathBuf {
        self.operation_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_BACKUP_DIR)
    }

    fn install_marker_path(&self) -> PathBuf {
        self.collection_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MARKER_FILE)
    }

    fn live_collection_path(&self, collection_name: &str) -> PathBuf {
        self.storage_path
            .join(COLLECTIONS_DIR)
            .join(collection_name)
    }
}

impl PrivateOramExternalRecoveryInstallTransaction {
    pub fn phase(&self) -> PrivateOramExternalRecoveryInstallPhase {
        self.marker.phase
    }

    pub fn install_intent_digest(&self) -> String {
        private_oram_external_recovery_install_intent_digest(&self.marker)
    }

    pub fn cancel_prepared(self) -> Result<(), StorageError> {
        self.cancel_prepared_marker()
    }

    fn cancel_rolled_back_or_prepared(self) -> Result<(), StorageError> {
        match self.marker.phase {
            PrivateOramExternalRecoveryInstallPhase::Prepared => self.cancel_prepared_marker(),
            PrivateOramExternalRecoveryInstallPhase::RollbackComplete => {
                self.cancel_rolled_back_marker()
            }
            _ => Err(invalid_install_state()),
        }
    }

    fn cancel_prepared_marker(&self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::Prepared)?;
        if self.classify_tree_state()? != PrivateOramExternalRecoveryInstallTreeState::OldReady {
            return Err(invalid_install_state());
        }
        remove_install_marker(&self.staging.install_marker_path(), &self.marker)
    }

    fn cancel_rolled_back_marker(&self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::RollbackComplete)?;
        self.validate_rolled_back_tree_state_relaxed()?;
        remove_install_marker(&self.staging.install_marker_path(), &self.marker)
    }

    pub fn rollback_uncommitted(mut self) -> Result<(), StorageError> {
        self.require_uncommitted_phase()?;
        match self.marker.phase {
            PrivateOramExternalRecoveryInstallPhase::LoadInProgress => {
                return self.rollback_load_in_progress();
            }
            PrivateOramExternalRecoveryInstallPhase::RollbackInProgress => {
                return self.complete_load_rollback();
            }
            PrivateOramExternalRecoveryInstallPhase::RollbackComplete => {
                return self.validate_rolled_back_tree_state_relaxed();
            }
            _ => {}
        }
        match self.classify_tree_state()? {
            PrivateOramExternalRecoveryInstallTreeState::OldReady => {
                self.set_phase(PrivateOramExternalRecoveryInstallPhase::Prepared)
            }
            PrivateOramExternalRecoveryInstallTreeState::OldMoved => self.rollback_old_moved(),
            PrivateOramExternalRecoveryInstallTreeState::NewPromoted => {
                self.rollback_new_promoted()
            }
            PrivateOramExternalRecoveryInstallTreeState::Finalized => Err(invalid_install_state()),
        }
    }

    pub fn finalize_rolled_back(mut self) -> Result<(), StorageError> {
        match self.marker.phase {
            PrivateOramExternalRecoveryInstallPhase::RollbackInProgress => {
                self.complete_load_rollback()?;
            }
            PrivateOramExternalRecoveryInstallPhase::RollbackComplete => {
                self.validate_rolled_back_tree_state_relaxed()?;
            }
            _ => return Err(invalid_install_state()),
        }
        self.cancel_rolled_back_marker()
    }

    fn require_uncommitted_phase(&self) -> Result<(), StorageError> {
        if !matches!(
            self.marker.phase,
            PrivateOramExternalRecoveryInstallPhase::Prepared
                | PrivateOramExternalRecoveryInstallPhase::OldMoved
                | PrivateOramExternalRecoveryInstallPhase::NewPromoted
                | PrivateOramExternalRecoveryInstallPhase::LoadInProgress
                | PrivateOramExternalRecoveryInstallPhase::RollbackInProgress
                | PrivateOramExternalRecoveryInstallPhase::RollbackComplete
        ) {
            return Err(invalid_install_state());
        }
        self.require_phase(self.marker.phase)
    }

    pub fn move_live_to_backup(&mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::Prepared)?;
        if self.classify_tree_state()? != PrivateOramExternalRecoveryInstallTreeState::OldReady {
            return Err(invalid_install_state());
        }
        rename_install_tree(
            &self.live_path(),
            &self.backup_path(),
            &self.marker.old_tree_digest,
            false,
        )?;
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::OldMoved)
    }

    pub fn promote_verified_collection(&mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::OldMoved)?;
        if self.classify_tree_state()? != PrivateOramExternalRecoveryInstallTreeState::OldMoved {
            return Err(invalid_install_state());
        }
        rename_install_tree(
            &self.verified_path(),
            &self.live_path(),
            &self.marker.new_tree_digest,
            true,
        )?;
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::NewPromoted)
    }

    pub fn mark_load_in_progress(&mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::NewPromoted)?;
        if self.classify_tree_state()? != PrivateOramExternalRecoveryInstallTreeState::NewPromoted {
            return Err(invalid_install_state());
        }
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::LoadInProgress)
    }

    pub fn mark_ready_to_commit(&mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::LoadInProgress)?;
        if self.classify_promoted_tree_state_relaxed()?
            != PrivateOramExternalRecoveryInstallTreeState::NewPromoted
        {
            return Err(invalid_install_state());
        }
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::Loaded)
    }

    pub fn mark_consensus_committed(&mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::Loaded)?;
        if self.classify_promoted_tree_state_relaxed()?
            != PrivateOramExternalRecoveryInstallTreeState::NewPromoted
        {
            return Err(invalid_install_state());
        }
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted)
    }

    pub fn finalize_committed(mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted)?;
        self.finalize_committed_files()
    }

    fn require_phase(
        &self,
        expected: PrivateOramExternalRecoveryInstallPhase,
    ) -> Result<(), StorageError> {
        let current = read_install_marker(&self.staging.install_marker_path())?
            .ok_or_else(invalid_install_state)?;
        if self.marker.phase != expected || current != self.marker {
            return Err(invalid_install_state());
        }
        Ok(())
    }

    fn set_phase(
        &mut self,
        phase: PrivateOramExternalRecoveryInstallPhase,
    ) -> Result<(), StorageError> {
        let mut next = self.marker.clone();
        next.phase = phase;
        write_install_marker(
            &self.staging.install_marker_path(),
            Some(&self.marker),
            &next,
        )?;
        self.marker = next;
        Ok(())
    }

    fn live_path(&self) -> PathBuf {
        self.staging
            .live_collection_path(&self.marker.collection_name)
    }

    fn verified_path(&self) -> PathBuf {
        self.staging.verified_collection_path()
    }

    fn backup_path(&self) -> PathBuf {
        self.staging.install_backup_path()
    }

    fn classify_tree_state(
        &self,
    ) -> Result<PrivateOramExternalRecoveryInstallTreeState, StorageError> {
        for path in [self.live_path(), self.verified_path(), self.backup_path()] {
            if path_exists(&path)? {
                validate_install_tree_collection_identity(
                    &path,
                    &self.marker.collection_name,
                    &self.marker.collection_id,
                )?;
            }
        }
        let live = install_tree_digest_if_exists(&self.live_path(), false)?;
        let verified = install_tree_digest_if_exists(&self.verified_path(), true)?;
        let backup = install_tree_digest_if_exists(&self.backup_path(), false)?;
        match (live.as_deref(), verified.as_deref(), backup.as_deref()) {
            (Some(live), Some(verified), None)
                if live == self.marker.old_tree_digest
                    && verified == self.marker.new_tree_digest =>
            {
                Ok(PrivateOramExternalRecoveryInstallTreeState::OldReady)
            }
            (None, Some(verified), Some(backup))
                if verified == self.marker.new_tree_digest
                    && backup == self.marker.old_tree_digest =>
            {
                Ok(PrivateOramExternalRecoveryInstallTreeState::OldMoved)
            }
            (Some(live), None, Some(backup))
                if live == self.marker.new_tree_digest && backup == self.marker.old_tree_digest =>
            {
                Ok(PrivateOramExternalRecoveryInstallTreeState::NewPromoted)
            }
            (Some(live), None, None) if live == self.marker.new_tree_digest => {
                Ok(PrivateOramExternalRecoveryInstallTreeState::Finalized)
            }
            _ => Err(invalid_install_state()),
        }
    }

    fn classify_promoted_tree_state_relaxed(
        &self,
    ) -> Result<PrivateOramExternalRecoveryInstallTreeState, StorageError> {
        if !path_exists(&self.live_path())? || path_exists(&self.verified_path())? {
            return Err(invalid_install_state());
        }
        validate_install_tree_collection_identity(
            &self.live_path(),
            &self.marker.collection_name,
            &self.marker.collection_id,
        )?;
        if private_oram_external_recovery_private_state_digest(&self.live_path())?
            != self.marker.new_private_state_digest
            || private_oram_external_recovery_config_digest(&self.live_path())?
                != self.marker.new_config_digest
        {
            return Err(invalid_install_state());
        }
        if path_exists(&self.backup_path())? {
            validate_install_tree_collection_identity(
                &self.backup_path(),
                &self.marker.collection_name,
                &self.marker.collection_id,
            )?;
            if private_oram_external_recovery_tree_digest(&self.backup_path())?
                != self.marker.old_tree_digest
            {
                return Err(invalid_install_state());
            }
            Ok(PrivateOramExternalRecoveryInstallTreeState::NewPromoted)
        } else {
            Ok(PrivateOramExternalRecoveryInstallTreeState::Finalized)
        }
    }

    fn validate_rolled_back_tree_state_relaxed(&self) -> Result<(), StorageError> {
        if !path_exists(&self.live_path())?
            || path_exists(&self.verified_path())?
            || path_exists(&self.backup_path())?
        {
            return Err(invalid_install_state());
        }
        validate_install_tree_collection_identity(
            &self.live_path(),
            &self.marker.collection_name,
            &self.marker.collection_id,
        )?;
        if private_oram_external_recovery_config_digest(&self.live_path())?
            != self.marker.old_config_digest
            || private_oram_external_recovery_private_state_digest(&self.live_path())?
                != self.marker.old_private_state_digest
        {
            return Err(invalid_install_state());
        }
        Ok(())
    }

    fn rollback_old_moved(&mut self) -> Result<(), StorageError> {
        rename_install_tree(
            &self.backup_path(),
            &self.live_path(),
            &self.marker.old_tree_digest,
            false,
        )?;
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::Prepared)
    }

    fn rollback_new_promoted(&mut self) -> Result<(), StorageError> {
        rename_install_tree(
            &self.live_path(),
            &self.verified_path(),
            &self.marker.new_tree_digest,
            true,
        )?;
        rename_install_tree(
            &self.backup_path(),
            &self.live_path(),
            &self.marker.old_tree_digest,
            false,
        )?;
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::Prepared)
    }

    fn rollback_load_in_progress(&mut self) -> Result<(), StorageError> {
        if self.classify_promoted_tree_state_relaxed()?
            != PrivateOramExternalRecoveryInstallTreeState::NewPromoted
        {
            return Err(invalid_install_state());
        }
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::RollbackInProgress)?;
        self.complete_load_rollback()
    }

    fn complete_load_rollback(&mut self) -> Result<(), StorageError> {
        self.require_phase(PrivateOramExternalRecoveryInstallPhase::RollbackInProgress)?;
        validate_missing_path(&self.verified_path())?;
        if path_exists(&self.backup_path())? {
            validate_install_tree_collection_identity(
                &self.backup_path(),
                &self.marker.collection_name,
                &self.marker.collection_id,
            )?;
            if private_oram_external_recovery_tree_digest(&self.backup_path())?
                != self.marker.old_tree_digest
            {
                return Err(invalid_install_state());
            }
            remove_owned_directory_if_exists(&self.live_path(), false)?;
            rename_install_tree(
                &self.backup_path(),
                &self.live_path(),
                &self.marker.old_tree_digest,
                false,
            )?;
        } else {
            validate_install_tree_collection_identity(
                &self.live_path(),
                &self.marker.collection_name,
                &self.marker.collection_id,
            )?;
            if private_oram_external_recovery_tree_digest(&self.live_path())?
                != self.marker.old_tree_digest
            {
                return Err(invalid_install_state());
            }
        }
        self.set_phase(PrivateOramExternalRecoveryInstallPhase::RollbackComplete)
    }

    fn finalize_committed_files(&mut self) -> Result<(), StorageError> {
        match self.classify_promoted_tree_state_relaxed()? {
            PrivateOramExternalRecoveryInstallTreeState::NewPromoted => {
                remove_owned_directory_if_exists(&self.backup_path(), false)?;
            }
            PrivateOramExternalRecoveryInstallTreeState::Finalized => {}
            PrivateOramExternalRecoveryInstallTreeState::OldReady
            | PrivateOramExternalRecoveryInstallTreeState::OldMoved => {
                return Err(invalid_install_state());
            }
        }
        remove_install_marker(&self.staging.install_marker_path(), &self.marker)?;
        remove_owned_directory_if_exists(&self.staging.operation_path(), true)
    }
}

pub fn reconcile_private_oram_external_recovery_installs(
    storage_path: &Path,
    consensus_state_for: impl FnMut(
        &PrivateOramExternalRecoveryKey,
    ) -> Option<PrivateOramExternalRecoveryState>,
) -> Result<(), StorageError> {
    reconcile_private_oram_external_recovery_installs_inner(
        storage_path,
        consensus_state_for,
        false,
        |_, _, _| Ok(false),
    )
}

pub fn finalize_committed_private_oram_external_recovery_installs(
    storage_path: &Path,
    consensus_state_for: impl FnMut(
        &PrivateOramExternalRecoveryKey,
    ) -> Option<PrivateOramExternalRecoveryState>,
    collection_is_loaded: impl FnMut(&str, &str, &str) -> Result<bool, StorageError>,
) -> Result<(), StorageError> {
    reconcile_private_oram_external_recovery_installs_inner(
        storage_path,
        consensus_state_for,
        true,
        collection_is_loaded,
    )
}

pub fn private_oram_external_recovery_install_is_pending(
    storage_path: &Path,
) -> Result<bool, StorageError> {
    let base_path = storage_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR);
    let metadata = match fs::symlink_metadata(&base_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(invalid_install_state()),
    };
    validate_secure_directory_metadata(&metadata)?;

    for entry in fs::read_dir(&base_path).map_err(|_| invalid_install_state())? {
        let collection_path = entry.map_err(|_| invalid_install_state())?.path();
        validate_secure_directory(&collection_path)?;
        if read_install_marker(
            &collection_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MARKER_FILE),
        )?
        .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn reconcile_private_oram_external_recovery_installs_inner(
    storage_path: &Path,
    mut consensus_state_for: impl FnMut(
        &PrivateOramExternalRecoveryKey,
    ) -> Option<PrivateOramExternalRecoveryState>,
    finalize_committed: bool,
    mut collection_is_loaded: impl FnMut(&str, &str, &str) -> Result<bool, StorageError>,
) -> Result<(), StorageError> {
    let base_path = storage_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR);
    let metadata = match fs::symlink_metadata(&base_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(invalid_install_state()),
    };
    validate_secure_directory_metadata(&metadata)?;

    let mut collection_paths = fs::read_dir(&base_path)
        .map_err(|_| invalid_install_state())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_install_state())?;
    collection_paths.sort();

    for collection_path in collection_paths {
        validate_secure_directory(&collection_path)?;
        let marker_path = collection_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MARKER_FILE);
        let Some(marker) = read_install_marker(&marker_path)? else {
            continue;
        };
        let staging = PrivateOramExternalRecoveryStaging::new(
            storage_path,
            &marker.collection_id,
            &marker.operation_id_hash,
        )?;
        if staging.collection_path() != collection_path
            || staging.install_marker_path() != marker_path
        {
            return Err(invalid_install_state());
        }

        let collection_lock = staging.acquire_collection_lock(false)?;
        let locked_marker = read_install_marker(&marker_path)?.ok_or_else(invalid_install_state)?;
        if locked_marker != marker {
            return Err(invalid_install_state());
        }
        let key = PrivateOramExternalRecoveryKey {
            collection_id: marker.collection_id.clone(),
        };
        let consensus = consensus_install_state(&marker, consensus_state_for(&key).as_ref())?;
        if finalize_committed
            && consensus == PrivateOramExternalRecoveryConsensusInstallState::Committed
            && !collection_is_loaded(
                &marker.collection_name,
                &marker.collection_id,
                &marker.layout_digest,
            )?
        {
            return Err(invalid_install_state());
        }
        let mut transaction = PrivateOramExternalRecoveryInstallTransaction {
            staging,
            marker,
            _collection_lock: collection_lock,
        };
        reconcile_install_transaction(&mut transaction, consensus, finalize_committed)?;
    }
    Ok(())
}

fn reconcile_install_transaction(
    transaction: &mut PrivateOramExternalRecoveryInstallTransaction,
    consensus: PrivateOramExternalRecoveryConsensusInstallState,
    finalize_committed: bool,
) -> Result<(), StorageError> {
    if consensus == PrivateOramExternalRecoveryConsensusInstallState::Committed {
        if !matches!(
            transaction.marker.phase,
            PrivateOramExternalRecoveryInstallPhase::Loaded
                | PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted
        ) {
            return Err(invalid_install_state());
        }
        transaction.classify_promoted_tree_state_relaxed()?;
        if transaction.marker.phase == PrivateOramExternalRecoveryInstallPhase::Loaded {
            transaction.set_phase(PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted)?;
        }
        if finalize_committed {
            return transaction.finalize_committed_files();
        }
        return Ok(());
    }

    if matches!(
        consensus,
        PrivateOramExternalRecoveryConsensusInstallState::Staging
            | PrivateOramExternalRecoveryConsensusInstallState::Superseded
    ) {
        // A superseded marker whose live tree was never replaced (Prepared over an untouched
        // tree, or a completed rollback) is cancelled like a staging-phase attempt. Every other
        // phase still fails closed below.
        return match transaction.marker.phase {
            PrivateOramExternalRecoveryInstallPhase::Prepared
                if transaction.classify_tree_state()?
                    == PrivateOramExternalRecoveryInstallTreeState::OldReady =>
            {
                transaction.cancel_prepared_marker()
            }
            PrivateOramExternalRecoveryInstallPhase::RollbackInProgress => {
                transaction.complete_load_rollback()?;
                transaction.cancel_rolled_back_marker()
            }
            PrivateOramExternalRecoveryInstallPhase::RollbackComplete => {
                transaction.cancel_rolled_back_marker()
            }
            _ => Err(invalid_install_state()),
        };
    }

    if transaction.marker.phase == PrivateOramExternalRecoveryInstallPhase::RollbackInProgress {
        return transaction.complete_load_rollback();
    }
    if transaction.marker.phase == PrivateOramExternalRecoveryInstallPhase::RollbackComplete {
        return transaction.validate_rolled_back_tree_state_relaxed();
    }

    if matches!(
        transaction.marker.phase,
        PrivateOramExternalRecoveryInstallPhase::LoadInProgress
            | PrivateOramExternalRecoveryInstallPhase::Loaded
    ) {
        if transaction.classify_promoted_tree_state_relaxed()?
            != PrivateOramExternalRecoveryInstallTreeState::NewPromoted
        {
            return Err(invalid_install_state());
        }
        return Ok(());
    }

    match transaction.classify_tree_state()? {
        PrivateOramExternalRecoveryInstallTreeState::OldReady => {
            transaction.set_phase(PrivateOramExternalRecoveryInstallPhase::Prepared)?;
            transaction.move_live_to_backup()?;
            transaction.promote_verified_collection()?;
            transaction.mark_load_in_progress()
        }
        PrivateOramExternalRecoveryInstallTreeState::OldMoved => {
            transaction.set_phase(PrivateOramExternalRecoveryInstallPhase::OldMoved)?;
            transaction.promote_verified_collection()?;
            transaction.mark_load_in_progress()
        }
        PrivateOramExternalRecoveryInstallTreeState::NewPromoted => {
            transaction.set_phase(PrivateOramExternalRecoveryInstallPhase::NewPromoted)?;
            transaction.mark_load_in_progress()
        }
        PrivateOramExternalRecoveryInstallTreeState::Finalized => Err(invalid_install_state()),
    }
}

pub fn new_private_oram_external_recovery_operation_token() -> String {
    BASE64URL_NOPAD.encode(&rand::random::<[u8; PRIVATE_ORAM_OPERATION_TOKEN_BYTES]>())
}

pub fn private_oram_external_recovery_operation_id_hash(
    operation_token: &str,
) -> Result<String, StorageError> {
    if operation_token.len() != PRIVATE_ORAM_OPERATION_TOKEN_LEN {
        return Err(invalid_staging_request());
    }
    let decoded = BASE64URL_NOPAD
        .decode(operation_token.as_bytes())
        .map_err(|_| invalid_staging_request())?;
    if decoded.len() != PRIVATE_ORAM_OPERATION_TOKEN_BYTES
        || BASE64URL_NOPAD.encode(&decoded) != operation_token
    {
        return Err(invalid_staging_request());
    }
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_OPERATION_ID_DOMAIN);
    hasher.update((decoded.len() as u64).to_be_bytes());
    hasher.update(decoded);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_external_recovery_checkpoint_digest(
    bundle: &PrivateOramExternalRecoveryCheckpointBundle,
) -> Result<String, StorageError> {
    validate_private_oram_recovery_signature_shape(&bundle.signature)
        .map_err(|_| invalid_staging_request())?;
    let message =
        try_private_oram_external_recovery_checkpoint_signature_message(&bundle.checkpoint)
            .map_err(|_| invalid_staging_request())?;
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_DIGEST_DOMAIN);
    update_length_prefixed(&mut hasher, &message);
    update_length_prefixed(&mut hasher, bundle.signature.alg.as_bytes());
    update_length_prefixed(&mut hasher, bundle.signature.key_id.as_bytes());
    update_length_prefixed(&mut hasher, bundle.signature.sig.as_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_install_marker(
    marker: &PrivateOramExternalRecoveryInstallMarker,
) -> Result<(), StorageError> {
    validate_install_collection_name(&marker.collection_name)?;
    if marker.version != PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_VERSION
        || marker.collection_id.is_empty()
        || marker.collection_id.len() > 1024
        || marker.backup_generation == 0
        || marker.layout_generation == 0
        || validate_base64url_sha256(&marker.operation_id_hash).is_err()
        || validate_base64url_sha256(&marker.install_attempt_nonce).is_err()
        || validate_base64url_sha256(&marker.checkpoint_digest).is_err()
        || validate_base64url_sha256(&marker.layout_digest).is_err()
        || validate_base64url_sha256(&marker.index_state_digest).is_err()
        || validate_base64url_sha256(&marker.old_tree_digest).is_err()
        || validate_base64url_sha256(&marker.old_config_digest).is_err()
        || validate_base64url_sha256(&marker.old_private_state_digest).is_err()
        || validate_base64url_sha256(&marker.new_tree_digest).is_err()
        || validate_base64url_sha256(&marker.new_config_digest).is_err()
        || validate_base64url_sha256(&marker.new_private_state_digest).is_err()
    {
        return Err(invalid_install_state());
    }
    Ok(())
}

fn private_oram_external_recovery_install_intent_digest(
    marker: &PrivateOramExternalRecoveryInstallMarker,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_INTENT_DIGEST_DOMAIN);
    hasher.update(marker.version.to_be_bytes());
    update_length_prefixed(&mut hasher, marker.collection_name.as_bytes());
    update_length_prefixed(&mut hasher, marker.collection_id.as_bytes());
    update_length_prefixed(&mut hasher, marker.operation_id_hash.as_bytes());
    update_length_prefixed(&mut hasher, marker.install_attempt_nonce.as_bytes());
    update_length_prefixed(&mut hasher, marker.checkpoint_digest.as_bytes());
    hasher.update(marker.backup_generation.to_be_bytes());
    hasher.update(marker.owner_peer_id.to_be_bytes());
    hasher.update(marker.layout_generation.to_be_bytes());
    update_length_prefixed(&mut hasher, marker.layout_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.index_state_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.old_tree_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.old_config_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.old_private_state_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.new_tree_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.new_config_digest.as_bytes());
    update_length_prefixed(&mut hasher, marker.new_private_state_digest.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn validate_install_marker_for_staging(
    marker: &PrivateOramExternalRecoveryInstallMarker,
    staging: &PrivateOramExternalRecoveryStaging,
    collection_name: &str,
    lease: &PrivateOramExternalRecoveryLease,
) -> Result<(), StorageError> {
    validate_install_marker_staging_binding(marker, staging)?;
    let install_intent_digest = private_oram_external_recovery_install_intent_digest(marker);
    let lease_matches_phase = match lease.phase {
        PrivateOramExternalRecoveryLeasePhase::Staging => lease.install_intent_digest.is_none(),
        PrivateOramExternalRecoveryLeasePhase::Installing => {
            lease.install_intent_digest.as_deref() == Some(install_intent_digest.as_str())
        }
    };
    if marker.collection_name != collection_name
        || marker.collection_id != staging.collection_id
        || marker.operation_id_hash != staging.operation_id_hash
        || marker.owner_peer_id != lease.owner_peer_id
        || marker.operation_id_hash != lease.operation_id_hash
        || marker.checkpoint_digest != lease.checkpoint_digest
        || marker.backup_generation != lease.backup_generation
        || !lease_matches_phase
    {
        return Err(invalid_install_state());
    }
    Ok(())
}

fn validate_install_marker_staging_binding(
    marker: &PrivateOramExternalRecoveryInstallMarker,
    staging: &PrivateOramExternalRecoveryStaging,
) -> Result<(), StorageError> {
    validate_install_marker(marker)?;
    if marker.collection_id != staging.collection_id
        || marker.operation_id_hash != staging.operation_id_hash
    {
        return Err(invalid_install_state());
    }
    let state = staging.read_state()?.ok_or_else(invalid_install_state)?;
    let checkpoint = &state.checkpoint_bundle.checkpoint;
    if state.phase != PrivateOramExternalRecoveryStagingPhase::Verified
        || state.checkpoint_digest != marker.checkpoint_digest
        || checkpoint.collection_id != marker.collection_id
        || checkpoint.backup_generation != marker.backup_generation
        || checkpoint.layout_generation != marker.layout_generation
        || checkpoint.layout_digest != marker.layout_digest
        || checkpoint.index_state_digest != marker.index_state_digest
        || state.verified_tree_digest.as_deref() != Some(marker.new_tree_digest.as_str())
        || state.verified_private_state_digest.as_deref()
            != Some(marker.new_private_state_digest.as_str())
    {
        return Err(invalid_install_state());
    }
    Ok(())
}

fn validate_install_collection_name(collection_name: &str) -> Result<(), StorageError> {
    if collection_name.is_empty()
        || collection_name.len() > 255
        || common::validation::validate_collection_name(collection_name).is_err()
    {
        return Err(invalid_install_state());
    }
    let mut components = Path::new(collection_name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == collection_name => Ok(()),
        _ => Err(invalid_install_state()),
    }
}

fn read_install_marker(
    marker_path: &Path,
) -> Result<Option<PrivateOramExternalRecoveryInstallMarker>, StorageError> {
    let metadata = match fs::symlink_metadata(marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_install_state()),
    };
    validate_secure_file_metadata(&metadata, PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_BYTES)
        .map_err(|_| invalid_install_state())?;
    if metadata.len() == 0 {
        return Err(invalid_install_state());
    }
    let file = open_regular_file(
        marker_path,
        true,
        Some(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_BYTES),
    )
    .map_err(|_| invalid_install_state())?;
    let opened = file.metadata().map_err(|_| invalid_install_state())?;
    ensure_same_file(&metadata, &opened).map_err(|_| invalid_install_state())?;
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_install_state())?;
    if bytes.len() as u64 != opened.len() {
        return Err(invalid_install_state());
    }
    let marker = serde_json::from_slice(&bytes).map_err(|_| invalid_install_state())?;
    validate_install_marker(&marker)?;
    Ok(Some(marker))
}

fn write_install_marker(
    marker_path: &Path,
    expected: Option<&PrivateOramExternalRecoveryInstallMarker>,
    marker: &PrivateOramExternalRecoveryInstallMarker,
) -> Result<(), StorageError> {
    validate_install_marker(marker)?;
    validate_secure_directory(marker_path.parent().ok_or_else(invalid_install_state)?)?;
    if read_install_marker(marker_path)?.as_ref() != expected {
        return Err(invalid_install_state());
    }
    let bytes = serde_json::to_vec(marker).map_err(|_| invalid_install_state())?;
    if bytes.is_empty() || bytes.len() as u64 > PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_BYTES {
        return Err(invalid_install_state());
    }
    let temp_path = marker_path
        .parent()
        .ok_or_else(invalid_install_state)?
        .join(format!(".install-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    secure_open_options(&mut options, true);
    let result = (|| {
        let mut file = options
            .open(&temp_path)
            .map_err(|_| invalid_install_state())?;
        file.write_all(&bytes)
            .map_err(|_| invalid_install_state())?;
        #[cfg(all(test, unix))]
        inject_private_oram_external_recovery_io_fault(
            PrivateOramExternalRecoveryIoFault::InstallMarkerTempFileSync,
        )
        .map_err(|_| invalid_install_state())?;
        file.sync_all().map_err(|_| invalid_install_state())?;
        fs::rename(&temp_path, marker_path).map_err(|_| invalid_install_state())?;
        #[cfg(all(test, unix))]
        inject_private_oram_external_recovery_io_fault(
            PrivateOramExternalRecoveryIoFault::InstallMarkerParentDirectorySync,
        )
        .map_err(|_| invalid_install_state())?;
        common::fs::sync_parent_dir(marker_path).map_err(|_| invalid_install_state())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn remove_install_marker(
    marker_path: &Path,
    expected: &PrivateOramExternalRecoveryInstallMarker,
) -> Result<(), StorageError> {
    match read_install_marker(marker_path)? {
        Some(marker) if marker == *expected => {}
        None => return Ok(()),
        Some(_) => return Err(invalid_install_state()),
    }
    fs::remove_file(marker_path).map_err(|_| invalid_install_state())?;
    common::fs::sync_parent_dir(marker_path).map_err(|_| invalid_install_state())
}

fn consensus_install_state(
    marker: &PrivateOramExternalRecoveryInstallMarker,
    state: Option<&PrivateOramExternalRecoveryState>,
) -> Result<PrivateOramExternalRecoveryConsensusInstallState, StorageError> {
    let Some(state) = state else {
        return Ok(PrivateOramExternalRecoveryConsensusInstallState::Superseded);
    };
    let install_intent_digest = private_oram_external_recovery_install_intent_digest(marker);
    if state.committed_backup_generation == marker.backup_generation
        && state.committed_checkpoint_digest.as_deref() == Some(&marker.checkpoint_digest)
        && state.committed_install_intent_digest.as_deref() == Some(install_intent_digest.as_str())
    {
        return Ok(PrivateOramExternalRecoveryConsensusInstallState::Committed);
    }
    let Some(lease) = state.active_lease.as_ref() else {
        return Ok(PrivateOramExternalRecoveryConsensusInstallState::Superseded);
    };
    if lease.owner_peer_id != marker.owner_peer_id
        || lease.operation_id_hash != marker.operation_id_hash
        || lease.checkpoint_digest != marker.checkpoint_digest
        || lease.backup_generation != marker.backup_generation
    {
        return Ok(PrivateOramExternalRecoveryConsensusInstallState::Superseded);
    }
    match lease.phase {
        PrivateOramExternalRecoveryLeasePhase::Staging if lease.install_intent_digest.is_none() => {
            Ok(PrivateOramExternalRecoveryConsensusInstallState::Staging)
        }
        PrivateOramExternalRecoveryLeasePhase::Installing
            if lease.install_intent_digest.as_deref() == Some(install_intent_digest.as_str()) =>
        {
            Ok(PrivateOramExternalRecoveryConsensusInstallState::Installing)
        }
        _ => Err(invalid_install_state()),
    }
}

fn rename_install_tree(
    source: &Path,
    destination: &Path,
    expected_digest: &str,
    require_private: bool,
) -> Result<(), StorageError> {
    validate_base64url_sha256(expected_digest).map_err(|_| invalid_install_state())?;
    let source_digest = private_oram_external_recovery_tree_digest(source)?;
    validate_owned_directory(source, require_private)?;
    if source_digest != expected_digest {
        return Err(invalid_install_state());
    }
    validate_missing_path(destination)?;
    #[cfg(all(test, unix))]
    inject_private_oram_external_recovery_io_fault(
        PrivateOramExternalRecoveryIoFault::InstallTreeRename,
    )
    .map_err(|_| invalid_install_state())?;
    fs::rename(source, destination).map_err(|_| invalid_install_state())?;
    #[cfg(all(test, unix))]
    inject_private_oram_external_recovery_io_fault(
        PrivateOramExternalRecoveryIoFault::InstallTreeSourceParentDirectorySync,
    )
    .map_err(|_| invalid_install_state())?;
    common::fs::sync_parent_dir(source).map_err(|_| invalid_install_state())?;
    #[cfg(all(test, unix))]
    inject_private_oram_external_recovery_io_fault(
        PrivateOramExternalRecoveryIoFault::InstallTreeDestinationParentDirectorySync,
    )
    .map_err(|_| invalid_install_state())?;
    common::fs::sync_parent_dir(destination).map_err(|_| invalid_install_state())?;
    validate_owned_directory(destination, require_private)?;
    if private_oram_external_recovery_tree_digest(destination)? != expected_digest {
        return Err(invalid_install_state());
    }
    Ok(())
}

fn install_tree_digest_if_exists(
    path: &Path,
    require_private: bool,
) -> Result<Option<String>, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_owned_directory(path, require_private)?;
            private_oram_external_recovery_tree_digest(path).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(invalid_install_state()),
    }
}

fn private_oram_external_recovery_tree_digest(path: &Path) -> Result<String, StorageError> {
    validate_owned_directory(path, false)?;
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_TREE_DIGEST_DOMAIN);
    let mut entry_count = 0;
    update_install_tree_digest(path, Path::new(""), &mut hasher, &mut entry_count, 0)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn private_oram_external_recovery_private_state_digest(
    collection_path: &Path,
) -> Result<String, StorageError> {
    validate_owned_directory(collection_path, false)?;
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_PRIVATE_STATE_DIGEST_DOMAIN);
    for directory_name in [
        PRIVATE_HNSW_ORAM_DIR,
        PRIVATE_RESULT_ORAM_DIR,
        PRIVATE_ORAM_MUTATION_JOURNAL_DIR,
    ] {
        update_length_prefixed(&mut hasher, directory_name.as_bytes());
        let path = collection_path.join(directory_name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_owned_directory_metadata(&metadata, false)?;
                hasher.update([1]);
                update_length_prefixed(
                    &mut hasher,
                    private_oram_external_recovery_tree_digest(&path)?.as_bytes(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => hasher.update([0]),
            Err(_) => return Err(invalid_install_state()),
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn private_oram_external_recovery_config_digest(
    collection_path: &Path,
) -> Result<String, StorageError> {
    validate_owned_directory(collection_path, false)?;
    let config =
        CollectionConfigInternal::load(collection_path).map_err(|_| invalid_install_state())?;
    let bytes = config.to_bytes().map_err(|_| invalid_install_state())?;
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_CONFIG_DIGEST_DOMAIN);
    update_length_prefixed(&mut hasher, &bytes);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn update_install_tree_digest(
    directory: &Path,
    relative: &Path,
    hasher: &mut Sha256,
    entry_count: &mut u64,
    depth: usize,
) -> Result<(), StorageError> {
    if depth > PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_TREE_DEPTH {
        return Err(invalid_install_state());
    }
    let before = fs::symlink_metadata(directory).map_err(|_| invalid_install_state())?;
    validate_owned_directory_metadata(&before, false)?;
    let mut entries = fs::read_dir(directory)
        .map_err(|_| invalid_install_state())?
        .map(|entry| {
            let entry = entry.map_err(|_| invalid_install_state())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_install_state())?;
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                return Err(invalid_install_state());
            }
            Ok((name, entry.path()))
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    for (name, path) in entries {
        *entry_count = entry_count
            .checked_add(1)
            .ok_or_else(invalid_install_state)?;
        if *entry_count > PRIVATE_ORAM_EXTERNAL_RECOVERY_INSTALL_MAX_TREE_ENTRIES {
            return Err(invalid_install_state());
        }
        let relative_path = relative.join(&name);
        let relative_bytes = relative_path
            .to_str()
            .ok_or_else(invalid_install_state)?
            .as_bytes();
        let metadata = fs::symlink_metadata(&path).map_err(|_| invalid_install_state())?;
        if metadata.file_type().is_dir() {
            validate_owned_directory_metadata(&metadata, false)?;
            hasher.update(b"d");
            update_length_prefixed(hasher, relative_bytes);
            update_install_tree_digest(&path, &relative_path, hasher, entry_count, depth + 1)?;
        } else if metadata.file_type().is_file() {
            validate_owned_file_metadata(&metadata)?;
            hasher.update(b"f");
            update_length_prefixed(hasher, relative_bytes);
            hasher.update(metadata.len().to_be_bytes());
            let mut file =
                open_regular_file(&path, false, None).map_err(|_| invalid_install_state())?;
            let opened = file.metadata().map_err(|_| invalid_install_state())?;
            ensure_same_file(&metadata, &opened).map_err(|_| invalid_install_state())?;
            let mut remaining = metadata.len();
            let mut buffer = [0_u8; 64 * 1024];
            while remaining > 0 {
                let limit = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| invalid_install_state())?;
                let read = file
                    .read(&mut buffer[..limit])
                    .map_err(|_| invalid_install_state())?;
                if read == 0 {
                    return Err(invalid_install_state());
                }
                hasher.update(&buffer[..read]);
                remaining -= read as u64;
            }
            let after = file.metadata().map_err(|_| invalid_install_state())?;
            ensure_same_file(&opened, &after).map_err(|_| invalid_install_state())?;
            if after.len() != metadata.len() {
                return Err(invalid_install_state());
            }
        } else {
            return Err(invalid_install_state());
        }
    }
    let after = fs::symlink_metadata(directory).map_err(|_| invalid_install_state())?;
    ensure_same_file(&before, &after).map_err(|_| invalid_install_state())
}

fn validate_owned_directory(path: &Path, require_private: bool) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_install_state())?;
    validate_owned_directory_metadata(&metadata, require_private)
}

fn validate_secure_directory_metadata(metadata: &std::fs::Metadata) -> Result<(), StorageError> {
    validate_owned_directory_metadata(metadata, true)
}

fn validate_owned_directory_metadata(
    metadata: &std::fs::Metadata,
    require_private: bool,
) -> Result<(), StorageError> {
    if !metadata.file_type().is_dir() {
        return Err(invalid_install_state());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let forbidden_mode = if require_private { 0o077 } else { 0o022 };
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & forbidden_mode != 0
        {
            return Err(invalid_install_state());
        }
    }
    Ok(())
}

fn validate_owned_file_metadata(metadata: &std::fs::Metadata) -> Result<(), StorageError> {
    if !metadata.file_type().is_file() {
        return Err(invalid_install_state());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(invalid_install_state());
        }
    }
    Ok(())
}

fn validate_install_tree_collection_identity(
    path: &Path,
    collection_name: &str,
    collection_id: &str,
) -> Result<(), StorageError> {
    let config = CollectionConfigInternal::load(path).map_err(|_| invalid_install_state())?;
    let stable_id = config
        .stable_crypto_id(collection_name)
        .map_err(|_| invalid_install_state())?;
    if stable_id != collection_id {
        return Err(invalid_install_state());
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(invalid_install_state()),
    }
}

fn validate_missing_path(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(invalid_install_state()),
    }
}

fn remove_owned_directory_if_exists(
    path: &Path,
    require_private: bool,
) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_owned_directory(path, require_private)?;
            fs::remove_dir_all(path).map_err(|_| invalid_install_state())?;
            common::fs::sync_parent_dir(path).map_err(|_| invalid_install_state())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(invalid_install_state()),
    }
}

fn read_private_oram_external_recovery_state_file(
    state_path: &Path,
) -> Result<Option<PrivateOramExternalRecoveryStagingState>, StorageError> {
    let metadata = match fs::symlink_metadata(state_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_staging_state()),
    };
    validate_secure_file_metadata(&metadata, PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES)?;
    let file = open_regular_file(
        state_path,
        true,
        Some(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES),
    )?;
    let opened = file.metadata().map_err(|_| invalid_staging_state())?;
    ensure_same_file(&metadata, &opened)?;
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_staging_state())?;
    if bytes.len() as u64 != opened.len() {
        return Err(invalid_staging_state());
    }
    let state = serde_json::from_slice(&bytes).map_err(|_| invalid_staging_state())?;
    validate_state(&state)?;
    Ok(Some(state))
}

fn validate_state(state: &PrivateOramExternalRecoveryStagingState) -> Result<(), StorageError> {
    validate_private_oram_external_recovery_checkpoint_shape(&state.checkpoint_bundle.checkpoint)
        .map_err(|_| invalid_staging_state())?;
    validate_private_oram_recovery_signature_shape(&state.checkpoint_bundle.signature)
        .map_err(|_| invalid_staging_state())?;
    validate_base64url_sha256(&state.operation_id_hash)?;
    validate_base64url_sha256(&state.checkpoint_digest)?;
    match state.phase {
        PrivateOramExternalRecoveryStagingPhase::Uploading => {
            if state.verified_tree_digest.is_some() || state.verified_private_state_digest.is_some()
            {
                return Err(invalid_staging_state());
            }
        }
        PrivateOramExternalRecoveryStagingPhase::Verified => {
            let verified_tree_digest = state
                .verified_tree_digest
                .as_deref()
                .ok_or_else(invalid_staging_state)?;
            let verified_private_state_digest = state
                .verified_private_state_digest
                .as_deref()
                .ok_or_else(invalid_staging_state)?;
            validate_base64url_sha256(verified_tree_digest).map_err(|_| invalid_staging_state())?;
            validate_base64url_sha256(verified_private_state_digest)
                .map_err(|_| invalid_staging_state())?;
        }
    }
    if state.version != PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_VERSION
        || state.lease_expires_at_unix == 0
        || state.checkpoint_bundle.checkpoint.snapshot_size_bytes == 0
        || state.checkpoint_bundle.checkpoint.snapshot_size_bytes
            > PRIVATE_ORAM_EXTERNAL_RECOVERY_HARD_MAX_SNAPSHOT_BYTES
        || state.bytes_received > state.checkpoint_bundle.checkpoint.snapshot_size_bytes
        || state.bytes_received < state.checkpoint_bundle.checkpoint.snapshot_size_bytes
            && state.bytes_received % PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES != 0
        || state.next_chunk_index
            != state
                .bytes_received
                .div_ceil(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES)
        || state.phase == PrivateOramExternalRecoveryStagingPhase::Verified
            && state.bytes_received != state.checkpoint_bundle.checkpoint.snapshot_size_bytes
        || private_oram_external_recovery_checkpoint_digest(&state.checkpoint_bundle)?
            != state.checkpoint_digest
    {
        return Err(invalid_staging_state());
    }
    Ok(())
}

fn ensure_secure_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_secure_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;

                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(invalid_staging_state()),
            }
            validate_secure_directory(path)?;
            common::fs::sync_parent_dir(path).map_err(|_| invalid_staging_state())
        }
        Err(_) => Err(invalid_staging_state()),
    }
}

fn secure_directory_exists(path: &Path) -> Result<bool, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_secure_directory(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(invalid_staging_state()),
    }
}

fn remove_secure_directory_if_exists(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_secure_directory(path)?;
            fs::remove_dir_all(path).map_err(|_| invalid_staging_state())?;
            common::fs::sync_parent_dir(path).map_err(|_| invalid_staging_state())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(invalid_staging_state()),
    }
}

fn validate_secure_directory(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_staging_state())?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_staging_state());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid_staging_state());
        }
    }
    Ok(())
}

fn open_regular_file(
    path: &Path,
    require_private: bool,
    max_bytes: Option<u64>,
) -> Result<File, StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_staging_state())?;
    if let Some(max_bytes) = max_bytes {
        validate_file_metadata(&metadata, require_private, max_bytes)?;
    } else if !metadata.file_type().is_file() {
        return Err(invalid_staging_state());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    secure_open_options(&mut options, false);
    let file = options.open(path).map_err(|_| invalid_staging_state())?;
    let opened = file.metadata().map_err(|_| invalid_staging_state())?;
    ensure_same_file(&metadata, &opened)?;
    if let Some(max_bytes) = max_bytes {
        validate_file_metadata(&opened, require_private, max_bytes)?;
    }
    Ok(file)
}

fn secure_open_options(options: &mut OpenOptions, create_private: bool) {
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        if create_private {
            options.mode(0o600);
        }
    }
}

fn validate_secure_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), StorageError> {
    validate_file_metadata(metadata, true, max_bytes)
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    require_private: bool,
    max_bytes: u64,
) -> Result<(), StorageError> {
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(invalid_staging_state());
    }
    #[cfg(unix)]
    if require_private {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid_staging_state());
        }
    }
    Ok(())
}

fn ensure_same_file(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), StorageError> {
    if before.len() != after.len() || before.file_type().is_file() != after.file_type().is_file() {
        return Err(invalid_staging_state());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(invalid_staging_state());
        }
    }
    Ok(())
}

fn file_identity(file: &File) -> Result<FileIdentity, StorageError> {
    let metadata = file.metadata().map_err(|_| invalid_staging_state())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        Ok(FileIdentity {
            len: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentity {
            len: metadata.len(),
        })
    }
}

fn lowercase_sha256_reader(reader: &mut impl Read) -> Result<String, StorageError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(HEXLOWER.encode(&hasher.finalize()))
}

fn lowercase_sha256_reader_limited(
    reader: &mut impl Read,
    expected_len: u64,
) -> Result<String, StorageError> {
    let mut limited = reader.take(expected_len);
    let digest = lowercase_sha256_reader(&mut limited)?;
    if limited.limit() != 0 {
        return Err(invalid_staging_state());
    }
    Ok(digest)
}

fn validate_base64url_sha256(value: &str) -> Result<(), StorageError> {
    if value.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(invalid_staging_request());
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| invalid_staging_request())?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(invalid_staging_request());
    }
    Ok(())
}

fn validate_lowercase_sha256(value: &str) -> Result<(), StorageError> {
    if value.len() != PRIVATE_ORAM_SHA256_HEX_LEN {
        return Err(invalid_staging_request());
    }
    let decoded = HEXLOWER
        .decode(value.as_bytes())
        .map_err(|_| invalid_staging_request())?;
    if decoded.len() != 32 || HEXLOWER.encode(&decoded) != value {
        return Err(invalid_staging_request());
    }
    Ok(())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn invalid_staging_request() -> StorageError {
    StorageError::bad_request("private ORAM external recovery request is invalid")
}

fn ensure_private_oram_external_recovery_free_space(
    path: &Path,
    additional_bytes: u64,
    min_free_space_bytes: u64,
) -> Result<(), StorageError> {
    let required = additional_bytes
        .checked_add(min_free_space_bytes)
        .ok_or_else(invalid_staging_request)?;
    let available = fs4::available_space(path).map_err(|_| {
        StorageError::service_error("private ORAM external recovery free-space preflight failed")
    })?;
    if available < required {
        return Err(StorageError::bad_request(
            "private ORAM external recovery has insufficient free storage",
        ));
    }
    Ok(())
}

fn invalid_staging_state() -> StorageError {
    StorageError::service_error("private ORAM external recovery staging state is invalid")
}

fn invalid_install_state() -> StorageError {
    StorageError::service_error("private ORAM external recovery install state is invalid")
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector, WalConfig,
    };
    use collection::optimizers_builder::OptimizersConfig;
    use qdrant_sec::{
        PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_VERSION, PrivateOramExternalRecoveryCheckpoint,
        PrivateOramRecoverySignature,
    };
    use segment::types::HnswConfig;

    use super::*;

    fn resource_limits() -> PrivateOramExternalRecoveryConfig {
        PrivateOramExternalRecoveryConfig {
            min_free_space_bytes: 0,
            ..Default::default()
        }
    }

    fn tar_snapshot(entry_type: tar::EntryType, bytes: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut archive);
            let mut header = tar::Header::new_gnu();
            header.set_path("payload.bin").unwrap();
            header.set_entry_type(entry_type);
            header.set_mode(0o600);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, bytes).unwrap();
            builder.finish().unwrap();
        }
        archive
    }

    fn sparse_tar_snapshot(logical_size: u64, bytes: &[u8]) -> Vec<u8> {
        assert!(logical_size > bytes.len() as u64);
        let mut archive = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut archive);
            let mut header = tar::Header::new_gnu();
            header.set_path("sparse.bin").unwrap();
            header.set_entry_type(tar::EntryType::GNUSparse);
            header.set_mode(0o600);
            header.set_size(bytes.len() as u64);
            let sparse_offset = logical_size - bytes.len() as u64;
            let gnu = header.as_gnu_mut().unwrap();
            gnu.set_real_size(logical_size);
            gnu.sparse[0].set_offset(sparse_offset);
            gnu.sparse[0].set_length(bytes.len() as u64);
            header.set_cksum();
            builder.append(&header, bytes).unwrap();
            builder.finish().unwrap();
        }
        archive
    }

    fn upload_staging_snapshot(
        temp: &tempfile::TempDir,
        snapshot: &[u8],
    ) -> PrivateOramExternalRecoveryStaging {
        let bundle = bundle(snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging
            .begin_with_limits(&checkpoint_digest, bundle, 1_000, &resource_limits())
            .unwrap();
        let chunk_path = temp.path().join(format!("{operation_hash}.chunk"));
        let chunk_hash = chunk_file(&chunk_path, snapshot);
        staging
            .append_chunk_with_limits(0, &chunk_path, &chunk_hash, &resource_limits())
            .unwrap();
        staging
    }

    fn bundle(snapshot: &[u8]) -> PrivateOramExternalRecoveryCheckpointBundle {
        PrivateOramExternalRecoveryCheckpointBundle {
            checkpoint: PrivateOramExternalRecoveryCheckpoint {
                version: PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_VERSION,
                collection_id: "12345678-90ab-cdef-1234-567890abcdef".to_string(),
                backup_generation: 7,
                source_peer_id: 11,
                source_shard_ids: vec![1],
                layout_generation: 3,
                owner_peer_ids: vec![11],
                layout_digest: BASE64URL_NOPAD.encode(&[1; 32]),
                index_state_digest: BASE64URL_NOPAD.encode(&[2; 32]),
                owner_snapshot_authority_digest: BASE64URL_NOPAD.encode(&[5; 32]),
                snapshot_size_bytes: snapshot.len() as u64,
                snapshot_sha256: HEXLOWER.encode(&Sha256::digest(snapshot)),
                client_recovery_state_digest: BASE64URL_NOPAD.encode(&[3; 32]),
                owner_signing_key_id: "owner-key-1".to_string(),
                created_at_unix: 100,
            },
            signature: PrivateOramRecoverySignature {
                alg: "ed25519".to_string(),
                key_id: "owner-key-1".to_string(),
                sig: BASE64URL_NOPAD.encode(&[4; 64]),
            },
        }
    }

    #[test]
    fn external_recovery_reservation_uses_archive_and_bounded_unpack_bytes() {
        let limits = PrivateOramExternalRecoveryConfig {
            max_snapshot_bytes: 10,
            max_total_staged_bytes: 20,
            max_unpacked_bytes: 4,
            min_free_space_bytes: 0,
            ..Default::default()
        };
        assert_eq!(
            private_oram_external_recovery_reservation_bytes(7, &limits).unwrap(),
            11,
        );
        assert!(private_oram_external_recovery_reservation_bytes(11, &limits).is_err());
        assert!(private_oram_external_recovery_reservation_bytes(0, &limits).is_err());
    }

    #[test]
    fn external_recovery_reservations_reload_and_abort_releases_disk_state() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot";
        let bundle = bundle(snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        let limits = PrivateOramExternalRecoveryConfig {
            max_unpacked_bytes: snapshot.len() as u64,
            min_free_space_bytes: 0,
            ..Default::default()
        };
        staging
            .begin_with_limits(&checkpoint_digest, bundle, 1_000, &limits)
            .unwrap();

        let reservations =
            load_private_oram_external_recovery_reservations(temp.path(), &limits).unwrap();
        assert_eq!(
            reservations.get(&operation_hash),
            Some(&(2 * snapshot.len() as u64)),
        );

        staging.abort().unwrap();
        assert!(
            load_private_oram_external_recovery_reservations(temp.path(), &limits)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn external_recovery_begin_limit_failure_has_no_staging_side_effect() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot";
        let bundle = bundle(snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        let limits = PrivateOramExternalRecoveryConfig {
            max_snapshot_bytes: snapshot.len() as u64 - 1,
            min_free_space_bytes: 0,
            ..Default::default()
        };

        assert!(
            staging
                .begin_with_limits(&checkpoint_digest, bundle, 1_000, &limits)
                .is_err()
        );
        assert!(!staging.operation_path().exists());
    }

    #[test]
    fn external_recovery_verify_rejects_expanded_bytes_before_unpack() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = tar_snapshot(tar::EntryType::Regular, &[7_u8; 1024]);
        let staging = upload_staging_snapshot(&temp, &snapshot);
        let limits = PrivateOramExternalRecoveryConfig {
            max_unpacked_bytes: 512,
            min_free_space_bytes: 0,
            ..Default::default()
        };

        assert!(staging.prepare_verification_with_limits(&limits).is_err());
        assert!(!staging.verified_collection_path().exists());
        assert!(
            !staging
                .operation_path()
                .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR)
                .exists()
        );
    }

    #[test]
    fn external_recovery_verify_accepts_bounded_sparse_tar() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = sparse_tar_snapshot(4096, &[9_u8; 64]);
        let staging = upload_staging_snapshot(&temp, &snapshot);
        let limits = PrivateOramExternalRecoveryConfig {
            max_unpacked_bytes: 4096,
            min_free_space_bytes: 0,
            ..Default::default()
        };

        let (verification, resources) = staging.prepare_verification_with_limits(&limits).unwrap();
        assert_eq!(
            verification.validate_archive_resources(&limits).unwrap(),
            PrivateOramExternalRecoveryArchiveResources {
                entry_count: 1,
                logical_bytes: 4096,
            }
        );
        assert_eq!(resources.logical_bytes, 4096);
    }

    #[test]
    fn external_recovery_verify_rejects_sparse_expansion_before_unpack() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = sparse_tar_snapshot(4096, &[9_u8; 64]);
        let staging = upload_staging_snapshot(&temp, &snapshot);
        let limits = PrivateOramExternalRecoveryConfig {
            max_unpacked_bytes: 4095,
            min_free_space_bytes: 0,
            ..Default::default()
        };

        assert!(staging.prepare_verification_with_limits(&limits).is_err());
        assert!(!staging.verified_collection_path().exists());
    }

    fn chunk_file(path: &Path, bytes: &[u8]) -> String {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        HEXLOWER.encode(&Sha256::digest(bytes))
    }

    fn install_collection_config() -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a:docs".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "body_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1_000,
                default_segment_number: 0,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: None,
                indexing_threshold: Some(100_000),
                flush_interval_sec: 60,
                max_optimization_threads: Some(0),
                prevent_unoptimized: None,
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(uuid::Uuid::parse_str("12345678-90ab-cdef-1234-567890abcdef").unwrap()),
            metadata: None,
        }
    }

    fn install_fixture(
        temp: &tempfile::TempDir,
    ) -> (
        PrivateOramExternalRecoveryStaging,
        PrivateOramExternalRecoveryLease,
    ) {
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging
            .begin(&checkpoint_digest, bundle.clone(), 1_000)
            .unwrap();
        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        let verification = staging.prepare_verification().unwrap();
        verification.reset_verification_output().unwrap();
        install_collection_config()
            .save(verification.verify_temp_collection_path())
            .unwrap();
        fs::create_dir(verification.verify_temp_collection_path().join("nested")).unwrap();
        fs::write(
            verification
                .verify_temp_collection_path()
                .join("nested/new"),
            b"new-tree",
        )
        .unwrap();
        let private_state = verification
            .verify_temp_collection_path()
            .join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_state).unwrap();
        fs::write(private_state.join("state"), b"verified-private-state").unwrap();
        let parent_state = verification
            .verify_temp_collection_path()
            .join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR);
        fs::create_dir(&parent_state).unwrap();
        fs::write(parent_state.join("state"), b"verified-parent-state").unwrap();
        verification.promote_verification_output().unwrap();
        staging.mark_verified(verification).unwrap();

        let live_path = temp.path().join(COLLECTIONS_DIR).join("docs");
        fs::create_dir_all(live_path.join("nested")).unwrap();
        install_collection_config().save(&live_path).unwrap();
        fs::write(live_path.join("nested/old"), b"old-tree").unwrap();

        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 11,
            operation_id_hash: operation_hash,
            checkpoint_digest,
            backup_generation: bundle.checkpoint.backup_generation,
            issued_at_unix: 100,
            expires_at_unix: 1_000,
            authority: PrivateOramExternalRecoveryAuthority::LegacyV1,
            install_intent_digest: None,
            phase: PrivateOramExternalRecoveryLeasePhase::Staging,
        };
        (staging, lease)
    }

    #[cfg(unix)]
    fn assert_no_atomic_write_temp_files(directory: &Path, prefix: &str) {
        assert!(fs::read_dir(directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(prefix)
        }),);
    }

    #[cfg(unix)]
    #[test]
    fn staging_state_write_recovers_from_enospc_and_ambiguous_parent_fsync_failure() {
        for (fault, state_is_visible_after_failure) in [
            (PrivateOramExternalRecoveryIoFault::StateTempFileSync, false),
            (
                PrivateOramExternalRecoveryIoFault::StateParentDirectorySync,
                true,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let snapshot = b"snapshot";
            let bundle = bundle(snapshot);
            let checkpoint_digest =
                private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
            let operation_hash = private_oram_external_recovery_operation_id_hash(
                &new_private_oram_external_recovery_operation_token(),
            )
            .unwrap();
            let staging = PrivateOramExternalRecoveryStaging::new(
                temp.path(),
                &bundle.checkpoint.collection_id,
                &operation_hash,
            )
            .unwrap();

            let fault_guard = set_private_oram_external_recovery_io_fault(fault);
            assert!(
                staging
                    .begin(&checkpoint_digest, bundle.clone(), 1_000)
                    .is_err()
            );
            drop(fault_guard);
            assert_eq!(
                staging.state_path().exists(),
                state_is_visible_after_failure
            );
            assert_no_atomic_write_temp_files(&staging.operation_path(), ".state-");

            let retried = staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
            assert_eq!(
                retried.phase,
                PrivateOramExternalRecoveryStagingPhase::Uploading
            );
            assert_eq!(retried.bytes_received, 0);
            assert!(staging.state_path().exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn install_marker_write_recovers_from_enospc_and_ambiguous_parent_fsync_failure() {
        for (fault, marker_is_visible_after_failure) in [
            (
                PrivateOramExternalRecoveryIoFault::InstallMarkerTempFileSync,
                false,
            ),
            (
                PrivateOramExternalRecoveryIoFault::InstallMarkerParentDirectorySync,
                true,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (staging, lease) = install_fixture(&temp);

            let fault_guard = set_private_oram_external_recovery_io_fault(fault);
            assert!(staging.prepare_install("docs", &lease).is_err());
            drop(fault_guard);
            assert_eq!(
                staging.install_marker_path().exists(),
                marker_is_visible_after_failure,
            );
            assert_no_atomic_write_temp_files(&staging.collection_path(), ".install-");

            let retried = staging.prepare_install("docs", &lease).unwrap();
            assert_eq!(
                retried.phase(),
                PrivateOramExternalRecoveryInstallPhase::Prepared,
            );
            retried.cancel_prepared().unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_output_promotion_recovers_from_rename_and_parent_sync_errors() {
        for (fault, pending_is_visible, verified_is_visible) in [
            (
                PrivateOramExternalRecoveryIoFault::VerificationOutputRename,
                true,
                false,
            ),
            (
                PrivateOramExternalRecoveryIoFault::VerificationOutputParentDirectorySync,
                false,
                true,
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let staging = upload_staging_snapshot(&temp, b"snapshot");
            let verification = staging.prepare_verification().unwrap();
            verification.reset_verification_output().unwrap();
            fs::write(
                verification.verify_temp_collection_path().join("marker"),
                b"verified",
            )
            .unwrap();

            let fault_guard = set_private_oram_external_recovery_io_fault(fault);
            assert!(verification.promote_verification_output().is_err());
            drop(fault_guard);
            assert_eq!(
                verification.verify_temp_collection_path().exists(),
                pending_is_visible,
            );
            assert_eq!(
                verification.verified_collection_path().exists(),
                verified_is_visible,
            );

            verification.reset_verification_output().unwrap();
            fs::write(
                verification.verify_temp_collection_path().join("marker"),
                b"verified",
            )
            .unwrap();
            verification.promote_verification_output().unwrap();
            assert_eq!(
                fs::read(verification.verified_collection_path().join("marker")).unwrap(),
                b"verified",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn live_tree_install_rolls_back_rename_and_parent_sync_errors() {
        for fault in [
            PrivateOramExternalRecoveryIoFault::InstallTreeRename,
            PrivateOramExternalRecoveryIoFault::InstallTreeSourceParentDirectorySync,
            PrivateOramExternalRecoveryIoFault::InstallTreeDestinationParentDirectorySync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (staging, lease) = install_fixture(&temp);
            let mut transaction = staging.prepare_install("docs", &lease).unwrap();

            let fault_guard = set_private_oram_external_recovery_io_fault(fault);
            assert!(transaction.move_live_to_backup().is_err());
            drop(fault_guard);
            transaction.rollback_uncommitted().unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
                b"old-tree",
            );
            assert!(!staging.install_backup_path().exists());
            assert_eq!(
                read_install_marker(&staging.install_marker_path())
                    .unwrap()
                    .unwrap()
                    .phase,
                PrivateOramExternalRecoveryInstallPhase::Prepared,
            );

            let mut transaction = staging.prepare_install("docs", &lease).unwrap();
            transaction.move_live_to_backup().unwrap();
            transaction.promote_verified_collection().unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
                b"new-tree",
            );
        }

        for fault in [
            PrivateOramExternalRecoveryIoFault::InstallTreeRename,
            PrivateOramExternalRecoveryIoFault::InstallTreeSourceParentDirectorySync,
            PrivateOramExternalRecoveryIoFault::InstallTreeDestinationParentDirectorySync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (staging, lease) = install_fixture(&temp);
            let mut transaction = staging.prepare_install("docs", &lease).unwrap();
            transaction.move_live_to_backup().unwrap();

            let fault_guard = set_private_oram_external_recovery_io_fault(fault);
            assert!(transaction.promote_verified_collection().is_err());
            drop(fault_guard);
            transaction.rollback_uncommitted().unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
                b"old-tree",
            );
            assert!(!staging.install_backup_path().exists());
            assert_eq!(
                read_install_marker(&staging.install_marker_path())
                    .unwrap()
                    .unwrap()
                    .phase,
                PrivateOramExternalRecoveryInstallPhase::Prepared,
            );

            let mut transaction = staging.prepare_install("docs", &lease).unwrap();
            transaction.move_live_to_backup().unwrap();
            transaction.promote_verified_collection().unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
                b"new-tree",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn live_tree_install_recovers_after_real_parent_permission_revocation() {
        use std::os::unix::fs::PermissionsExt as _;

        // Root can bypass the discretionary write-permission denial this test exercises.
        if nix::unistd::Uid::effective().as_raw() == 0 {
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        let operation_path = staging.operation_path();
        let original_operation_permissions = fs::metadata(&operation_path).unwrap().permissions();
        fs::set_permissions(&operation_path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let move_result = transaction.move_live_to_backup();
        fs::set_permissions(&operation_path, original_operation_permissions).unwrap();
        assert!(move_result.is_err());
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
            b"old-tree",
        );
        assert!(!staging.install_backup_path().exists());

        transaction.move_live_to_backup().unwrap();
        let collections_path = temp.path().join(COLLECTIONS_DIR);
        let original_collection_permissions =
            fs::metadata(&collections_path).unwrap().permissions();
        fs::set_permissions(&collections_path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let promote_result = transaction.promote_verified_collection();
        fs::set_permissions(&collections_path, original_collection_permissions).unwrap();
        assert!(promote_result.is_err());
        assert!(!staging.live_collection_path("docs").exists());
        assert!(staging.verified_collection_path().exists());
        assert!(staging.install_backup_path().exists());

        transaction.promote_verified_collection().unwrap();
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
            b"new-tree",
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux user and mount namespaces"]
    fn archive_extraction_recovers_from_real_tmpfs_enospc() {
        const CHILD_MOUNT_ENV: &str = "QDRANT_PRIVATE_ORAM_ENOSPC_CHILD_MOUNT";
        const TEST_NAME: &str = "content_manager::snapshots::private_oram_external_recovery::tests::archive_extraction_recovers_from_real_tmpfs_enospc";

        let Ok(mount_path) = std::env::var(CHILD_MOUNT_ENV) else {
            let mount_dir = tempfile::Builder::new()
                .prefix("qdrant-private-oram-enospc-mount-")
                .tempdir()
                .unwrap();
            let status = std::process::Command::new("unshare")
                .args(["-Ur", "-m", "--"])
                .arg(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_MOUNT_ENV, mount_dir.path())
                .status()
                .unwrap();
            assert!(status.success(), "private ORAM ENOSPC child failed");
            return;
        };
        let mount_path = PathBuf::from(mount_path);
        struct TmpfsMountGuard(PathBuf);

        impl Drop for TmpfsMountGuard {
            fn drop(&mut self) {
                let _ = std::process::Command::new("umount").arg(&self.0).status();
            }
        }

        let mount_status = std::process::Command::new("mount")
            .args([
                "-t",
                "tmpfs",
                "-o",
                "size=4m,nr_inodes=1024,mode=700",
                "qdrant-private-oram-enospc",
            ])
            .arg(&mount_path)
            .status()
            .unwrap();
        assert!(mount_status.success(), "failed to mount ENOSPC tmpfs");
        let mount_guard = TmpfsMountGuard(mount_path.clone());

        let first_bytes = vec![0x31_u8; 128 * 1024];
        let second_bytes = vec![0x72_u8; 1024 * 1024];
        let mut snapshot = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut snapshot);
            for (path, bytes) in [
                ("first.bin", first_bytes.as_slice()),
                ("second.bin", second_bytes.as_slice()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o600);
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                builder.append(&header, bytes).unwrap();
            }
            builder.finish().unwrap();
        }

        let host_temp = tempfile::tempdir().unwrap();
        let staging = upload_staging_snapshot(&host_temp, &snapshot);
        let mut verification = staging.prepare_verification().unwrap();
        // Only verification output moves to tmpfs; archive identity and staging stay production-bound.
        assert!(!verification.snapshot_path().starts_with(&mount_path));
        verification.verify_temp_collection_path = mount_path.join("verified.pending");
        verification.verified_collection_path = mount_path.join("verified");
        assert_eq!(
            verification.verify_temp_collection_path(),
            mount_path.join("verified.pending"),
        );
        assert_eq!(
            verification.verified_collection_path(),
            mount_path.join("verified"),
        );
        verification.reset_verification_output().unwrap();

        let bytes_to_leave = 512 * 1024_u64;
        let available = fs4::available_space(&mount_path).unwrap();
        assert!(available > bytes_to_leave);
        let filler_path = mount_path.join("filler");
        let mut filler = fs::File::create(&filler_path).unwrap();
        let mut filler_source = std::io::repeat(0xa5).take(available - bytes_to_leave);
        assert_eq!(
            std::io::copy(&mut filler_source, &mut filler).unwrap(),
            available - bytes_to_leave,
        );
        filler.sync_all().unwrap();
        drop(filler);

        let unpack_error = common::tar_unpack::tar_unpack_file(
            verification.snapshot_path(),
            verification.verify_temp_collection_path(),
        )
        .unwrap_err();
        assert_eq!(unpack_error.kind(), std::io::ErrorKind::StorageFull);
        assert_eq!(
            fs::read(verification.verify_temp_collection_path().join("first.bin"),).unwrap(),
            first_bytes,
        );
        let partial_second_len = fs::metadata(
            verification
                .verify_temp_collection_path()
                .join("second.bin"),
        )
        .unwrap()
        .len();
        assert!(partial_second_len < second_bytes.len() as u64);
        assert!(!verification.verified_collection_path().exists());

        fs::remove_file(&filler_path).unwrap();
        verification.reset_verification_output().unwrap();
        assert!(
            fs::read_dir(verification.verify_temp_collection_path())
                .unwrap()
                .next()
                .is_none(),
        );
        common::tar_unpack::tar_unpack_file(
            verification.snapshot_path(),
            verification.verify_temp_collection_path(),
        )
        .unwrap();
        assert_eq!(
            fs::read(verification.verify_temp_collection_path().join("first.bin"),).unwrap(),
            first_bytes,
        );
        assert_eq!(
            fs::read(
                verification
                    .verify_temp_collection_path()
                    .join("second.bin"),
            )
            .unwrap(),
            second_bytes,
        );
        verification.promote_verification_output().unwrap();
        assert!(!verification.verify_temp_collection_path().exists());
        assert!(verification.verified_collection_path().exists());

        drop(verification);
        drop(staging);
        let unmount_status = std::process::Command::new("umount")
            .arg(&mount_path)
            .status()
            .unwrap();
        assert!(unmount_status.success(), "failed to unmount ENOSPC tmpfs");
        std::mem::forget(mount_guard);
    }

    #[cfg(unix)]
    #[test]
    fn unconsumed_io_fault_is_cleared_when_its_guard_drops() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot";
        let bundle = bundle(snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();

        let fault_guard = set_private_oram_external_recovery_io_fault(
            PrivateOramExternalRecoveryIoFault::InstallMarkerTempFileSync,
        );
        drop(fault_guard);

        assert!(staging.begin(&checkpoint_digest, bundle, 1_000).is_ok());
    }

    fn recovery_state(
        staging: &PrivateOramExternalRecoveryStaging,
        lease: &PrivateOramExternalRecoveryLease,
        phase: PrivateOramExternalRecoveryLeasePhase,
    ) -> PrivateOramExternalRecoveryState {
        let install_intent_digest = (phase == PrivateOramExternalRecoveryLeasePhase::Installing)
            .then(|| {
                private_oram_external_recovery_install_intent_digest(
                    &read_install_marker(&staging.install_marker_path())
                        .unwrap()
                        .unwrap(),
                )
            });
        PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(PrivateOramExternalRecoveryLease {
                phase,
                install_intent_digest,
                ..lease.clone()
            }),
        }
    }

    fn committed_recovery_state(
        staging: &PrivateOramExternalRecoveryStaging,
        lease: &PrivateOramExternalRecoveryLease,
    ) -> PrivateOramExternalRecoveryState {
        let install_intent_digest = private_oram_external_recovery_install_intent_digest(
            &read_install_marker(&staging.install_marker_path())
                .unwrap()
                .unwrap(),
        );
        PrivateOramExternalRecoveryState {
            committed_backup_generation: lease.backup_generation,
            committed_checkpoint_digest: Some(lease.checkpoint_digest.clone()),
            committed_install_intent_digest: Some(install_intent_digest),
            active_lease: None,
        }
    }

    fn reconcile_fixture(
        temp: &tempfile::TempDir,
        state: PrivateOramExternalRecoveryState,
    ) -> Result<(), StorageError> {
        reconcile_private_oram_external_recovery_installs(temp.path(), |_| Some(state.clone()))
    }

    fn finalize_fixture(
        temp: &tempfile::TempDir,
        state: PrivateOramExternalRecoveryState,
    ) -> Result<(), StorageError> {
        finalize_committed_private_oram_external_recovery_installs(
            temp.path(),
            |_| Some(state.clone()),
            |_, _, _| Ok(true),
        )
    }

    #[test]
    fn staged_chunks_are_ordered_idempotent_and_verified() {
        let temp = tempfile::tempdir().unwrap();
        let mut snapshot = vec![7_u8; PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES as usize];
        snapshot.extend_from_slice(b"tail");
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let token = new_private_oram_external_recovery_operation_token();
        let operation_hash = private_oram_external_recovery_operation_id_hash(&token).unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();

        let initial = staging
            .begin(&checkpoint_digest, bundle.clone(), 1_000)
            .unwrap();
        assert_eq!(initial.bytes_received, 0);
        assert_eq!(initial.next_chunk_index, 0);
        assert_eq!(
            staging
                .status_for_consensus_lease(&checkpoint_digest, 7, 1_100)
                .unwrap()
                .lease_expires_at_unix,
            1_100
        );
        assert!(
            staging
                .status_for_consensus_lease(&checkpoint_digest, 7, 1_000)
                .is_err()
        );

        let first_path = temp.path().join("first.chunk");
        let first_hash = chunk_file(
            &first_path,
            &snapshot[..PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES as usize],
        );
        let tail_path = temp.path().join("tail.chunk");
        let tail_hash = chunk_file(
            &tail_path,
            &snapshot[PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES as usize..],
        );

        let out_of_order = staging
            .append_chunk(1, &tail_path, &tail_hash)
            .unwrap_err()
            .to_string();
        assert!(out_of_order.contains("out of order"));
        let first = staging.append_chunk(0, &first_path, &first_hash).unwrap();
        assert_eq!(
            first.bytes_received,
            PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES
        );
        assert_eq!(
            staging.append_chunk(0, &first_path, &first_hash).unwrap(),
            first
        );
        let complete = staging.append_chunk(1, &tail_path, &tail_hash).unwrap();
        assert_eq!(complete.bytes_received, snapshot.len() as u64);

        let verification = staging.prepare_verification().unwrap();
        verification.reset_verification_output().unwrap();
        fs::write(
            verification.verify_temp_collection_path().join("marker"),
            b"verified",
        )
        .unwrap();
        verification.promote_verification_output().unwrap();
        assert_eq!(
            fs::read(verification.verified_collection_path().join("marker")).unwrap(),
            b"verified"
        );
        let verified = staging.mark_verified(verification).unwrap();
        assert_eq!(
            verified.phase,
            PrivateOramExternalRecoveryStagingPhase::Verified
        );
        assert_eq!(staging.status().unwrap(), verified);

        staging.abort().unwrap();
        assert!(matches!(
            staging.status(),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn uncommitted_archive_suffix_is_truncated_before_retry() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();

        let mut archive = OpenOptions::new()
            .append(true)
            .open(staging.snapshot_path())
            .unwrap();
        archive.write_all(b"partial").unwrap();
        archive.sync_all().unwrap();
        assert_eq!(fs::metadata(staging.snapshot_path()).unwrap().len(), 7);

        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        assert_eq!(
            fs::read(staging.snapshot_path()).unwrap(),
            snapshot.as_slice()
        );
    }

    #[test]
    fn collection_lock_serializes_staging_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();

        let _first = staging.acquire_collection_lock(false).unwrap();
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(staging.collection_lock_path())
            .unwrap();
        assert!(!FileExt::try_lock_exclusive(&second).unwrap());
    }

    #[test]
    fn mark_verified_rejects_archive_tampering_after_preflight() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        let verification = staging.prepare_verification().unwrap();
        fs::create_dir(&verification.verified_collection_path).unwrap();
        fs::write(&verification.snapshot_path, b"tampered").unwrap();

        assert!(staging.mark_verified(verification).is_err());
        assert_eq!(
            staging.status().unwrap().phase,
            PrivateOramExternalRecoveryStagingPhase::Uploading
        );
    }

    #[test]
    fn mark_verified_rejects_a_substituted_verified_directory() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        let mut verification = staging.prepare_verification().unwrap();
        let substituted = temp.path().join("substituted");
        fs::create_dir(&substituted).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&substituted, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        verification.verified_collection_path = substituted;

        assert!(staging.mark_verified(verification).is_err());
    }

    #[test]
    fn prepare_install_rejects_verified_tree_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);

        fs::write(
            staging.verified_collection_path().join("nested/new"),
            b"substituted-tree",
        )
        .unwrap();

        assert!(staging.prepare_install("docs", &lease).is_err());
        assert!(!staging.install_marker_path().exists());
    }

    #[test]
    fn prepare_install_rejects_verified_private_state_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let private_state = staging
            .verified_collection_path()
            .join(PRIVATE_HNSW_ORAM_DIR);
        fs::write(private_state.join("state"), b"substituted-private-state").unwrap();

        assert!(staging.prepare_install("docs", &lease).is_err());
        assert!(!staging.install_marker_path().exists());
    }

    #[test]
    fn legacy_verified_state_without_digests_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let state_path = staging.state_path();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let state = state.as_object_mut().unwrap();
        state.remove("verified_tree_digest");
        state.remove("verified_private_state_digest");
        fs::write(&state_path, serde_json::to_vec(state).unwrap()).unwrap();

        assert!(staging.status().is_err());
        assert!(staging.prepare_install("docs", &lease).is_err());
        assert!(!staging.install_marker_path().exists());
    }

    #[test]
    fn legacy_uploading_state_without_digests_remains_readable() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();

        let state_path = staging.state_path();
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let state = state.as_object_mut().unwrap();
        state.remove("verified_tree_digest");
        state.remove("verified_private_state_digest");
        fs::write(&state_path, serde_json::to_vec(state).unwrap()).unwrap();

        assert_eq!(
            staging.status().unwrap().phase,
            PrivateOramExternalRecoveryStagingPhase::Uploading,
        );
    }

    #[test]
    fn durable_install_reconciles_every_persisted_phase() {
        for phase in [
            PrivateOramExternalRecoveryInstallPhase::Prepared,
            PrivateOramExternalRecoveryInstallPhase::OldMoved,
            PrivateOramExternalRecoveryInstallPhase::NewPromoted,
            PrivateOramExternalRecoveryInstallPhase::LoadInProgress,
            PrivateOramExternalRecoveryInstallPhase::Loaded,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (staging, lease) = install_fixture(&temp);
            let mut transaction = staging.prepare_install("docs", &lease).unwrap();
            if phase != PrivateOramExternalRecoveryInstallPhase::Prepared {
                transaction.move_live_to_backup().unwrap();
            }
            if matches!(
                phase,
                PrivateOramExternalRecoveryInstallPhase::NewPromoted
                    | PrivateOramExternalRecoveryInstallPhase::LoadInProgress
                    | PrivateOramExternalRecoveryInstallPhase::Loaded
            ) {
                transaction.promote_verified_collection().unwrap();
            }
            if matches!(
                phase,
                PrivateOramExternalRecoveryInstallPhase::LoadInProgress
                    | PrivateOramExternalRecoveryInstallPhase::Loaded
            ) {
                transaction.mark_load_in_progress().unwrap();
            }
            if phase == PrivateOramExternalRecoveryInstallPhase::Loaded {
                transaction.mark_ready_to_commit().unwrap();
            }
            assert_eq!(transaction.phase(), phase);
            drop(transaction);

            reconcile_fixture(
                &temp,
                recovery_state(
                    &staging,
                    &lease,
                    PrivateOramExternalRecoveryLeasePhase::Installing,
                ),
            )
            .unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
                b"new-tree",
            );
            assert!(staging.install_backup_path().exists());
            assert_eq!(
                read_install_marker(&staging.install_marker_path())
                    .unwrap()
                    .unwrap()
                    .phase,
                if phase == PrivateOramExternalRecoveryInstallPhase::Loaded {
                    PrivateOramExternalRecoveryInstallPhase::Loaded
                } else {
                    PrivateOramExternalRecoveryInstallPhase::LoadInProgress
                },
            );
        }
    }

    #[test]
    fn durable_install_reconciles_rename_ahead_of_marker() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let transaction = staging.prepare_install("docs", &lease).unwrap();
        rename_install_tree(
            &transaction.live_path(),
            &transaction.backup_path(),
            &transaction.marker.old_tree_digest,
            false,
        )
        .unwrap();
        drop(transaction);
        reconcile_fixture(
            &temp,
            recovery_state(
                &staging,
                &lease,
                PrivateOramExternalRecoveryLeasePhase::Installing,
            ),
        )
        .unwrap();
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
            b"new-tree",
        );
        assert_eq!(
            read_install_marker(&staging.install_marker_path())
                .unwrap()
                .unwrap()
                .phase,
            PrivateOramExternalRecoveryInstallPhase::LoadInProgress,
        );

        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        rename_install_tree(
            &transaction.verified_path(),
            &transaction.live_path(),
            &transaction.marker.new_tree_digest,
            true,
        )
        .unwrap();
        drop(transaction);
        reconcile_fixture(
            &temp,
            recovery_state(
                &staging,
                &lease,
                PrivateOramExternalRecoveryLeasePhase::Installing,
            ),
        )
        .unwrap();
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
            b"new-tree",
        );
        assert_eq!(
            read_install_marker(&staging.install_marker_path())
                .unwrap()
                .unwrap()
                .phase,
            PrivateOramExternalRecoveryInstallPhase::LoadInProgress,
        );
    }

    #[test]
    fn committed_install_cleanup_is_idempotent() {
        for phase in [
            PrivateOramExternalRecoveryInstallPhase::Loaded,
            PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let (staging, lease) = install_fixture(&temp);
            let mut transaction = staging.prepare_install("docs", &lease).unwrap();
            transaction.move_live_to_backup().unwrap();
            transaction.promote_verified_collection().unwrap();
            if matches!(
                phase,
                PrivateOramExternalRecoveryInstallPhase::Loaded
                    | PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted
            ) {
                transaction.mark_load_in_progress().unwrap();
                transaction.mark_ready_to_commit().unwrap();
            }
            if phase == PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted {
                transaction.mark_consensus_committed().unwrap();
            }
            drop(transaction);

            let committed = committed_recovery_state(&staging, &lease);
            reconcile_fixture(&temp, committed.clone()).unwrap();
            assert!(staging.operation_path().exists());
            assert!(staging.install_marker_path().exists());
            assert!(staging.install_backup_path().exists());
            assert!(
                finalize_committed_private_oram_external_recovery_installs(
                    temp.path(),
                    |_| Some(committed.clone()),
                    |_, _, _| Ok(false),
                )
                .is_err()
            );
            assert!(staging.install_backup_path().exists());
            finalize_fixture(&temp, committed.clone()).unwrap();
            finalize_fixture(&temp, committed).unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/new"),).unwrap(),
                b"new-tree",
            );
            assert!(!staging.operation_path().exists());
            assert!(!staging.install_marker_path().exists());
        }

        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        drop(transaction);
        assert!(reconcile_fixture(&temp, committed_recovery_state(&staging, &lease)).is_err());
    }

    #[test]
    fn committed_install_resumes_only_the_exact_durable_marker() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        transaction.mark_ready_to_commit().unwrap();
        drop(transaction);

        let committed = committed_recovery_state(&staging, &lease);
        let resumed = staging
            .resume_committed_install("docs", &committed)
            .unwrap();
        assert_eq!(
            resumed.phase(),
            PrivateOramExternalRecoveryInstallPhase::Loaded
        );
        drop(resumed);

        let mut wrong = committed;
        wrong.committed_checkpoint_digest = Some(BASE64URL_NOPAD.encode(&[99; 32]));
        assert!(staging.resume_committed_install("docs", &wrong).is_err());
    }

    #[test]
    fn loaded_install_survives_live_tree_mutation_until_commit_is_confirmed() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        transaction.mark_ready_to_commit().unwrap();
        drop(transaction);

        fs::write(
            staging.live_collection_path("docs").join("runtime-state"),
            b"post-load mutation",
        )
        .unwrap();
        reconcile_fixture(
            &temp,
            recovery_state(
                &staging,
                &lease,
                PrivateOramExternalRecoveryLeasePhase::Installing,
            ),
        )
        .unwrap();
        assert!(staging.install_marker_path().exists());
        assert!(staging.install_backup_path().exists());

        finalize_fixture(&temp, committed_recovery_state(&staging, &lease)).unwrap();
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("runtime-state")).unwrap(),
            b"post-load mutation",
        );
        assert!(!staging.operation_path().exists());
        assert!(!staging.install_marker_path().exists());
    }

    #[test]
    fn loaded_install_rejects_private_state_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);

        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        transaction.mark_ready_to_commit().unwrap();
        drop(transaction);

        fs::write(
            staging
                .live_collection_path("docs")
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("state"),
            b"substituted-private-state",
        )
        .unwrap();
        assert!(reconcile_fixture(&temp, committed_recovery_state(&staging, &lease)).is_err());
        assert!(staging.install_marker_path().exists());
        assert!(staging.install_backup_path().exists());
    }

    #[test]
    fn loaded_install_rejects_parent_journal_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);

        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        transaction.mark_ready_to_commit().unwrap();
        drop(transaction);

        fs::write(
            staging
                .live_collection_path("docs")
                .join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR)
                .join("state"),
            b"substituted-parent-state",
        )
        .unwrap();
        assert!(reconcile_fixture(&temp, committed_recovery_state(&staging, &lease)).is_err());
        assert!(staging.install_marker_path().exists());
        assert!(staging.install_backup_path().exists());
    }

    #[test]
    fn rollback_refuses_loaded_marker_after_ambiguous_phase_write() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();

        let mut loaded_marker = transaction.marker.clone();
        loaded_marker.phase = PrivateOramExternalRecoveryInstallPhase::Loaded;
        write_install_marker(
            &staging.install_marker_path(),
            Some(&transaction.marker),
            &loaded_marker,
        )
        .unwrap();

        assert!(transaction.rollback_uncommitted().is_err());
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/new")).unwrap(),
            b"new-tree",
        );
        assert!(staging.install_backup_path().exists());
        assert!(!staging.verified_collection_path().exists());
        assert_eq!(
            read_install_marker(&staging.install_marker_path())
                .unwrap()
                .unwrap()
                .phase,
            PrivateOramExternalRecoveryInstallPhase::Loaded,
        );
    }

    #[test]
    fn durable_install_rejects_substituted_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        fs::write(
            staging.verified_collection_path().join("nested/new"),
            b"substituted",
        )
        .unwrap();
        assert!(transaction.move_live_to_backup().is_err());
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/old"),).unwrap(),
            b"old-tree",
        );

        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        fs::write(
            staging.install_backup_path().join("nested/old"),
            b"substituted",
        )
        .unwrap();
        drop(transaction);
        assert!(
            reconcile_fixture(
                &temp,
                recovery_state(
                    &staging,
                    &lease,
                    PrivateOramExternalRecoveryLeasePhase::Installing,
                ),
            )
            .is_err()
        );
        assert!(!staging.live_collection_path("docs").exists());
    }

    #[test]
    fn durable_install_binds_marker_to_consensus_intent() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let transaction = staging.prepare_install("docs", &lease).unwrap();
        let installing_state = recovery_state(
            &staging,
            &lease,
            PrivateOramExternalRecoveryLeasePhase::Installing,
        );
        let original_marker = transaction.marker.clone();
        drop(transaction);
        let mut wrong_installing_lease = installing_state
            .active_lease
            .clone()
            .expect("installing recovery must have a lease");
        wrong_installing_lease.install_intent_digest = Some(BASE64URL_NOPAD.encode(&[62; 32]));
        assert!(
            staging
                .prepare_install("docs", &wrong_installing_lease)
                .is_err()
        );

        let marker_path = staging.install_marker_path();
        let mut tampered_marker = original_marker.clone();
        tampered_marker.layout_digest = BASE64URL_NOPAD.encode(&[63; 32]);
        write_install_marker(&marker_path, Some(&original_marker), &tampered_marker).unwrap();

        assert!(reconcile_fixture(&temp, installing_state).is_err());
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
            b"old-tree",
        );
    }

    #[test]
    fn prepared_install_must_be_cancelled_before_begin_or_abort() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        drop(staging.prepare_install("docs", &lease).unwrap());
        let state = staging.read_state().unwrap().unwrap();

        assert!(
            staging
                .begin(
                    &state.checkpoint_digest,
                    state.checkpoint_bundle.clone(),
                    state.lease_expires_at_unix,
                )
                .is_err()
        );
        assert!(staging.abort().is_err());

        staging
            .prepare_install("docs", &lease)
            .unwrap()
            .cancel_prepared()
            .unwrap();
        staging.abort().unwrap();
        assert!(!staging.install_marker_path().exists());
        assert!(!staging.operation_path().exists());
    }

    #[test]
    fn repeated_prepare_uses_a_fresh_install_intent() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        assert!(!private_oram_external_recovery_install_is_pending(temp.path()).unwrap());
        let first = staging.prepare_install("docs", &lease).unwrap();
        assert!(private_oram_external_recovery_install_is_pending(temp.path()).unwrap());
        let first_digest = first.install_intent_digest();
        first.cancel_prepared().unwrap();
        assert!(!private_oram_external_recovery_install_is_pending(temp.path()).unwrap());

        let second = staging.prepare_install("docs", &lease).unwrap();
        assert_ne!(second.install_intent_digest(), first_digest);
    }

    #[test]
    fn superseded_lease_reconcile_cancels_an_untouched_prepared_marker() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        drop(staging.prepare_install("docs", &lease).unwrap());
        // Another peer superseded the expired lease with its own operation.
        let mut foreign = recovery_state(
            &staging,
            &lease,
            PrivateOramExternalRecoveryLeasePhase::Staging,
        );
        let foreign_lease = foreign
            .active_lease
            .as_mut()
            .expect("staging recovery must have a lease");
        foreign_lease.owner_peer_id = foreign_lease.owner_peer_id.wrapping_add(1);
        foreign_lease.operation_id_hash = BASE64URL_NOPAD.encode(&[64; 32]);
        reconcile_fixture(&temp, foreign).unwrap();
        assert!(!staging.install_marker_path().exists());
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
            b"old-tree",
        );

        // The consensus record can also be gone entirely after an abort elsewhere.
        drop(staging.prepare_install("docs", &lease).unwrap());
        reconcile_private_oram_external_recovery_installs(temp.path(), |_| None).unwrap();
        assert!(!staging.install_marker_path().exists());

        // A marker that already replaced the live tree still fails closed under a foreign lease.
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        drop(transaction);
        assert!(reconcile_private_oram_external_recovery_installs(temp.path(), |_| None).is_err());
    }

    #[test]
    fn staging_reconcile_discards_a_rolled_back_install_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let first = staging.prepare_install("docs", &lease).unwrap();
        let first_digest = first.install_intent_digest();
        drop(first);

        reconcile_fixture(
            &temp,
            recovery_state(
                &staging,
                &lease,
                PrivateOramExternalRecoveryLeasePhase::Staging,
            ),
        )
        .unwrap();
        assert!(!staging.install_marker_path().exists());

        let second = staging.prepare_install("docs", &lease).unwrap();
        assert_ne!(second.install_intent_digest(), first_digest);
    }

    #[test]
    fn load_in_progress_rollback_discards_mutated_candidate_and_restores_old_tree() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        fs::write(
            staging.live_collection_path("docs").join("runtime-state"),
            b"load mutation",
        )
        .unwrap();

        transaction.rollback_uncommitted().unwrap();
        assert_eq!(
            fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
            b"old-tree",
        );
        assert!(!staging.install_backup_path().exists());
        assert_eq!(
            read_install_marker(&staging.install_marker_path())
                .unwrap()
                .unwrap()
                .phase,
            PrivateOramExternalRecoveryInstallPhase::RollbackComplete,
        );
        reconcile_fixture(
            &temp,
            recovery_state(
                &staging,
                &lease,
                PrivateOramExternalRecoveryLeasePhase::Staging,
            ),
        )
        .unwrap();
        assert!(!staging.install_marker_path().exists());
    }

    #[test]
    fn load_rollback_reconciles_every_destructive_crash_point() {
        for crash_point in 0..3 {
            let temp = tempfile::tempdir().unwrap();
            let (staging, lease) = install_fixture(&temp);
            let mut transaction = staging.prepare_install("docs", &lease).unwrap();
            transaction.move_live_to_backup().unwrap();
            transaction.promote_verified_collection().unwrap();
            transaction.mark_load_in_progress().unwrap();
            fs::write(
                staging.live_collection_path("docs").join("runtime-state"),
                b"load mutation",
            )
            .unwrap();
            transaction
                .set_phase(PrivateOramExternalRecoveryInstallPhase::RollbackInProgress)
                .unwrap();

            if crash_point >= 1 {
                remove_owned_directory_if_exists(&staging.live_collection_path("docs"), false)
                    .unwrap();
            }
            if crash_point == 2 {
                rename_install_tree(
                    &staging.install_backup_path(),
                    &staging.live_collection_path("docs"),
                    &transaction.marker.old_tree_digest,
                    false,
                )
                .unwrap();
            }
            let installing = recovery_state(
                &staging,
                &lease,
                PrivateOramExternalRecoveryLeasePhase::Installing,
            );
            drop(transaction);

            reconcile_fixture(&temp, installing).unwrap();
            assert_eq!(
                fs::read(staging.live_collection_path("docs").join("nested/old")).unwrap(),
                b"old-tree",
            );
            assert!(!staging.install_backup_path().exists());
            assert!(!staging.verified_collection_path().exists());
            assert_eq!(
                read_install_marker(&staging.install_marker_path())
                    .unwrap()
                    .unwrap()
                    .phase,
                PrivateOramExternalRecoveryInstallPhase::RollbackComplete,
            );

            reconcile_fixture(
                &temp,
                recovery_state(
                    &staging,
                    &lease,
                    PrivateOramExternalRecoveryLeasePhase::Staging,
                ),
            )
            .unwrap();
            assert!(!staging.install_marker_path().exists());
        }
    }

    #[test]
    fn loaded_install_rejects_config_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        transaction.mark_ready_to_commit().unwrap();
        drop(transaction);

        let live_path = staging.live_collection_path("docs");
        let mut config = CollectionConfigInternal::load(&live_path).unwrap();
        config.params.read_fan_out_delay_ms = Some(1);
        config.save(&live_path).unwrap();

        assert!(reconcile_fixture(&temp, committed_recovery_state(&staging, &lease)).is_err());
        assert!(staging.install_marker_path().exists());
        assert!(staging.install_backup_path().exists());
    }

    #[test]
    fn committed_cleanup_tolerates_operation_left_after_marker_removal() {
        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        let mut transaction = staging.prepare_install("docs", &lease).unwrap();
        transaction.move_live_to_backup().unwrap();
        transaction.promote_verified_collection().unwrap();
        transaction.mark_load_in_progress().unwrap();
        transaction.mark_ready_to_commit().unwrap();
        transaction.mark_consensus_committed().unwrap();
        let marker = transaction.marker.clone();
        drop(transaction);
        let committed = committed_recovery_state(&staging, &lease);

        remove_owned_directory_if_exists(&staging.install_backup_path(), false).unwrap();
        remove_install_marker(&staging.install_marker_path(), &marker).unwrap();
        assert!(staging.operation_path().exists());
        reconcile_fixture(&temp, committed).unwrap();
        assert!(staging.operation_path().exists());
        assert!(!staging.install_marker_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn install_marker_rejects_symlink_and_malformed_state() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let (staging, lease) = install_fixture(&temp);
        drop(staging.prepare_install("docs", &lease).unwrap());
        let installing_state = recovery_state(
            &staging,
            &lease,
            PrivateOramExternalRecoveryLeasePhase::Installing,
        );
        fs::remove_file(staging.install_marker_path()).unwrap();
        let target = temp.path().join("install-target");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, staging.install_marker_path()).unwrap();
        assert!(reconcile_fixture(&temp, installing_state.clone()).is_err());

        fs::remove_file(staging.install_marker_path()).unwrap();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_open_options(&mut options, true);
        let mut marker = options.open(staging.install_marker_path()).unwrap();
        marker.write_all(b"{}").unwrap();
        marker.sync_all().unwrap();
        assert!(reconcile_fixture(&temp, installing_state).is_err());
    }

    #[test]
    fn staging_debug_and_errors_redact_recovery_values() {
        let temp = tempfile::tempdir().unwrap();
        let collection = "private-oram-recovery-collection-sentinel";
        let operation_hash = BASE64URL_NOPAD.encode(&[9; 32]);
        let staging =
            PrivateOramExternalRecoveryStaging::new(temp.path(), collection, &operation_hash)
                .unwrap();
        let rendered = format!("{staging:?}");
        assert!(!rendered.contains(collection));
        assert!(!rendered.contains(&operation_hash));
        assert!(!rendered.contains(&temp.path().display().to_string()));

        let malformed = staging
            .append_chunk(
                0,
                Path::new("private-oram-recovery-path-sentinel"),
                "private-oram-recovery-hash-sentinel",
            )
            .unwrap_err()
            .to_string();
        assert!(!malformed.contains("private-oram-recovery"));
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_symlinked_state() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
        fs::remove_file(staging.state_path()).unwrap();
        let target = temp.path().join("state-target");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, staging.state_path()).unwrap();

        assert!(staging.status().is_err());
    }
}
