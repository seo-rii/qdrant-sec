//! Snapshot-independent monotonic floor persistence for private-ORAM mutation V2.
//!
//! A transition first publishes a pending intent that binds both the old and new complete Raft
//! state image digests. The caller then publishes the Raft image, promotes the next local floor,
//! and removes the intent. Recovery accepts only the exact old or new image digest.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::format::{
    PrivateOramMutationAuthorityFloorV2, PrivateOramMutationFormatFloorV2,
    plan_private_oram_mutation_authority_floor_transition_v2,
    plan_private_oram_mutation_format_floor_transition_v2,
    validate_private_oram_mutation_authority_floor_v2,
    validate_private_oram_mutation_format_floor_v2,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationJournalError, create_private_directory, ensure_same_file, file_sha256,
    path_entry_exists, read_json_private, secure_open_options, sync_directory,
    validate_private_file_metadata,
};

const FLOOR_STORE_DIRECTORY: &str = "private_oram_mutation_floor_v2";
const STABLE_FLOOR_FILE: &str = "stable.json";
const PENDING_FLOOR_FILE: &str = "pending.json";
const FLOOR_LOCK_FILE: &str = ".lock";
const FLOOR_TEMP_PREFIX: &str = ".floor-";
const LOCAL_FLOOR_CHECKPOINT_VERSION: u16 = 1;
const LOCAL_FLOOR_PENDING_VERSION: u16 = 1;
// A serialized authority floor is roughly 1 KiB (ten base64 digests, its key and field names),
// so the count cap below must be the binding one: at 64 MiB the file cap was reached near 65k
// floors, below the validator's 100k, and every save then failed the same way on every node.
const MAX_LOCAL_FLOOR_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LOCAL_AUTHORITY_FLOORS: usize = 100_000;
const PARENT_SYNC_ATTEMPTS: usize = 3;

const LOCAL_FLOOR_CHECKPOINT_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-local-floor-checkpoint/v2";
const LOCAL_FLOOR_PENDING_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-local-floor-pending/v2";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationLocalFloorCheckpointV2 {
    version: u16,
    generation: u64,
    format_floor: PrivateOramMutationFormatFloorV2,
    authority_floors: BTreeMap<String, PrivateOramMutationAuthorityFloorV2>,
    checkpoint_digest: String,
}

impl Debug for PrivateOramMutationLocalFloorCheckpointV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationLocalFloorCheckpointV2")
            .field("version", &self.version)
            .field("generation", &self.generation)
            .field("format_epoch", &self.format_floor.format_epoch())
            .field(
                "activation_enabled",
                &self.format_floor.activation_enabled(),
            )
            .field("authority_floor_count", &self.authority_floors.len())
            .field("checkpoint_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationLocalFloorCheckpointV2 {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn format_floor(&self) -> &PrivateOramMutationFormatFloorV2 {
        &self.format_floor
    }

    pub(crate) fn authority_floor(
        &self,
        collection_key_digest: &str,
    ) -> Option<&PrivateOramMutationAuthorityFloorV2> {
        self.authority_floors.get(collection_key_digest)
    }

    pub(crate) fn authority_floors(
        &self,
    ) -> &BTreeMap<String, PrivateOramMutationAuthorityFloorV2> {
        &self.authority_floors
    }

    pub(crate) fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationLocalFloorPendingV2 {
    version: u16,
    prior_checkpoint_digest: Option<String>,
    next_checkpoint: PrivateOramMutationLocalFloorCheckpointV2,
    prior_raft_state_digest: String,
    next_raft_state_digest: String,
    pending_digest: String,
}

impl Debug for PrivateOramMutationLocalFloorPendingV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationLocalFloorPendingV2")
            .field("version", &self.version)
            .field(
                "has_prior_checkpoint",
                &self.prior_checkpoint_digest.is_some(),
            )
            .field("next_generation", &self.next_checkpoint.generation)
            .field("prior_checkpoint_digest", &"[redacted]")
            .field("prior_raft_state_digest", &"[redacted]")
            .field("next_raft_state_digest", &"[redacted]")
            .field("pending_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationLocalFloorPendingV2 {
    pub(crate) fn next_checkpoint(&self) -> &PrivateOramMutationLocalFloorCheckpointV2 {
        &self.next_checkpoint
    }
}

pub(crate) fn private_oram_mutation_raft_state_image_digest_v2(encoded: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(encoded))
}

pub(crate) fn plan_private_oram_mutation_local_floor_checkpoint_v2(
    current: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    format_floor: PrivateOramMutationFormatFloorV2,
    authority_floors: BTreeMap<String, PrivateOramMutationAuthorityFloorV2>,
) -> Result<PrivateOramMutationLocalFloorCheckpointV2, PrivateOramMutationJournalError> {
    if let Some(current) = current {
        validate_private_oram_mutation_local_floor_checkpoint_v2(current)?;
        if current.format_floor == format_floor && current.authority_floors == authority_floors {
            return Ok(current.clone());
        }
    }

    let generation = match current {
        Some(current) => current
            .generation
            .checked_add(1)
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?,
        None => 1,
    };
    let mut candidate = PrivateOramMutationLocalFloorCheckpointV2 {
        version: LOCAL_FLOOR_CHECKPOINT_VERSION,
        generation,
        format_floor,
        authority_floors,
        checkpoint_digest: String::new(),
    };
    candidate.checkpoint_digest = local_floor_checkpoint_digest_v2(&candidate)?;
    validate_private_oram_mutation_local_floor_checkpoint_transition_v2(current, &candidate)?;
    Ok(candidate)
}

pub(crate) fn validate_private_oram_mutation_local_floor_checkpoint_v2(
    checkpoint: &PrivateOramMutationLocalFloorCheckpointV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if checkpoint.version != LOCAL_FLOOR_CHECKPOINT_VERSION
        || checkpoint.generation == 0
        || checkpoint.authority_floors.len() > MAX_LOCAL_AUTHORITY_FLOORS
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_private_oram_mutation_format_floor_v2(&checkpoint.format_floor)?;
    for (key, floor) in &checkpoint.authority_floors {
        if key != floor.collection_key_digest() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        validate_private_oram_mutation_authority_floor_v2(floor)?;
        plan_private_oram_mutation_authority_floor_transition_v2(
            None,
            &checkpoint.format_floor,
            floor,
        )?;
    }
    if checkpoint.checkpoint_digest != local_floor_checkpoint_digest_v2(checkpoint)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn validate_private_oram_mutation_local_floor_checkpoint_transition_v2(
    current: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    candidate: &PrivateOramMutationLocalFloorCheckpointV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_local_floor_checkpoint_v2(candidate)?;
    let Some(current) = current else {
        if candidate.generation != 1 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        plan_private_oram_mutation_format_floor_transition_v2(None, &candidate.format_floor)?;
        if !candidate.authority_floors.is_empty() {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(());
    };
    validate_private_oram_mutation_local_floor_checkpoint_v2(current)?;
    if candidate == current {
        return Ok(());
    }
    if candidate.generation
        != current
            .generation
            .checked_add(1)
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    plan_private_oram_mutation_format_floor_transition_v2(
        Some(&current.format_floor),
        &candidate.format_floor,
    )?;
    if current
        .authority_floors
        .keys()
        .any(|key| !candidate.authority_floors.contains_key(key))
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (key, candidate_floor) in &candidate.authority_floors {
        plan_private_oram_mutation_authority_floor_transition_v2(
            current.authority_floors.get(key),
            &candidate.format_floor,
            candidate_floor,
        )?;
    }
    Ok(())
}

pub(crate) fn plan_private_oram_mutation_local_floor_pending_v2(
    current: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    next_checkpoint: &PrivateOramMutationLocalFloorCheckpointV2,
    prior_raft_state_digest: String,
    next_raft_state_digest: String,
) -> Result<PrivateOramMutationLocalFloorPendingV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_local_floor_checkpoint_transition_v2(current, next_checkpoint)?;
    if current == Some(next_checkpoint)
        || prior_raft_state_digest == next_raft_state_digest
        || validate_digest(&prior_raft_state_digest).is_err()
        || validate_digest(&next_raft_state_digest).is_err()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut pending = PrivateOramMutationLocalFloorPendingV2 {
        version: LOCAL_FLOOR_PENDING_VERSION,
        prior_checkpoint_digest: current.map(|checkpoint| checkpoint.checkpoint_digest.clone()),
        next_checkpoint: next_checkpoint.clone(),
        prior_raft_state_digest,
        next_raft_state_digest,
        pending_digest: String::new(),
    };
    pending.pending_digest = local_floor_pending_digest_v2(&pending)?;
    validate_private_oram_mutation_local_floor_pending_v2(&pending)?;
    Ok(pending)
}

pub(crate) fn validate_private_oram_mutation_local_floor_pending_v2(
    pending: &PrivateOramMutationLocalFloorPendingV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if pending.version != LOCAL_FLOOR_PENDING_VERSION
        || pending.prior_raft_state_digest == pending.next_raft_state_digest
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if let Some(digest) = &pending.prior_checkpoint_digest {
        validate_digest(digest)?;
    }
    validate_digest(&pending.prior_raft_state_digest)?;
    validate_digest(&pending.next_raft_state_digest)?;
    validate_private_oram_mutation_local_floor_checkpoint_v2(&pending.next_checkpoint)?;
    if pending.pending_digest != local_floor_pending_digest_v2(pending)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PrivateOramMutationLocalFloorRecoveryActionV2 {
    RemovePendingKeepPrior,
    PromoteNextThenRemovePending,
    RemovePendingKeepNext,
}

fn plan_private_oram_mutation_local_floor_recovery_v2(
    stable: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    pending: &PrivateOramMutationLocalFloorPendingV2,
    observed_raft_state_digest: &str,
) -> Result<PrivateOramMutationLocalFloorRecoveryActionV2, PrivateOramMutationJournalError> {
    if let Some(stable) = stable {
        validate_private_oram_mutation_local_floor_checkpoint_v2(stable)?;
    }
    validate_private_oram_mutation_local_floor_pending_v2(pending)?;
    validate_digest(observed_raft_state_digest)?;

    if stable == Some(&pending.next_checkpoint) {
        return if observed_raft_state_digest == pending.next_raft_state_digest {
            Ok(PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepNext)
        } else {
            Err(PrivateOramMutationJournalError::Corrupt)
        };
    }
    if stable.map(|checkpoint| checkpoint.checkpoint_digest.as_str())
        != pending.prior_checkpoint_digest.as_deref()
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_private_oram_mutation_local_floor_checkpoint_transition_v2(
        stable,
        &pending.next_checkpoint,
    )?;
    if observed_raft_state_digest == pending.prior_raft_state_digest {
        Ok(PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepPrior)
    } else if observed_raft_state_digest == pending.next_raft_state_digest {
        Ok(PrivateOramMutationLocalFloorRecoveryActionV2::PromoteNextThenRemovePending)
    } else {
        Err(PrivateOramMutationJournalError::Corrupt)
    }
}

fn local_floor_checkpoint_digest_v2(
    checkpoint: &PrivateOramMutationLocalFloorCheckpointV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_FLOOR_CHECKPOINT_DIGEST_DOMAIN_V2);
    hasher.update(checkpoint.version.to_be_bytes());
    hasher.update(checkpoint.generation.to_be_bytes());
    hash_digest(&mut hasher, checkpoint.format_floor.floor_digest())?;
    let authority_count = u64::try_from(checkpoint.authority_floors.len())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(authority_count.to_be_bytes());
    for (key, floor) in &checkpoint.authority_floors {
        hash_digest(&mut hasher, key)?;
        hash_digest(&mut hasher, floor.floor_digest())?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn local_floor_pending_digest_v2(
    pending: &PrivateOramMutationLocalFloorPendingV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_FLOOR_PENDING_DIGEST_DOMAIN_V2);
    hasher.update(pending.version.to_be_bytes());
    match &pending.prior_checkpoint_digest {
        Some(digest) => {
            hasher.update([1]);
            hash_digest(&mut hasher, digest)?;
        }
        None => hasher.update([0]),
    }
    hash_digest(&mut hasher, pending.next_checkpoint.checkpoint_digest())?;
    hash_digest(&mut hasher, &pending.prior_raft_state_digest)?;
    hash_digest(&mut hasher, &pending.next_raft_state_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_digest(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(decoded);
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let mut sink = Sha256::new();
    hash_digest(&mut sink, value)
}

#[derive(Clone, Debug)]
pub(crate) struct PrivateOramMutationFloorStoreV2 {
    root: PathBuf,
}

pub(crate) struct PrivateOramMutationFloorTransitionGuardV2 {
    lock: PrivateOramMutationFloorStoreLock,
    pending: PrivateOramMutationLocalFloorPendingV2,
}

impl Debug for PrivateOramMutationFloorTransitionGuardV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationFloorTransitionGuardV2")
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl PrivateOramMutationFloorTransitionGuardV2 {
    pub(crate) fn finalize(
        self,
        observed_raft_state_digest: &str,
    ) -> Result<PrivateOramMutationLocalFloorCheckpointV2, PrivateOramMutationJournalError> {
        let Self { lock, pending } = self;
        cleanup_floor_temp_files(&lock)?;
        let stable = load_stable(&lock)?;
        match plan_private_oram_mutation_local_floor_recovery_v2(
            stable.as_ref(),
            &pending,
            observed_raft_state_digest,
        )? {
            PrivateOramMutationLocalFloorRecoveryActionV2::PromoteNextThenRemovePending => {
                publish_stable(&lock, stable.as_ref(), &pending.next_checkpoint)?;
            }
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepNext => {}
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepPrior => {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        remove_pending(&lock)?;
        lock.validate_root_identity()?;
        Ok(pending.next_checkpoint)
    }
}

impl PrivateOramMutationFloorStoreV2 {
    pub(crate) fn new(storage_path: impl AsRef<Path>) -> Self {
        Self {
            root: storage_path.as_ref().join(FLOOR_STORE_DIRECTORY),
        }
    }

    pub(crate) fn begin_transition(
        &self,
        next_checkpoint: &PrivateOramMutationLocalFloorCheckpointV2,
        prior_raft_state_digest: String,
        next_raft_state_digest: String,
    ) -> Result<PrivateOramMutationLocalFloorPendingV2, PrivateOramMutationJournalError> {
        let lock = self
            .acquire_lock(true)?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        cleanup_floor_temp_files(&lock)?;
        let stable = load_stable(&lock)?;
        if load_pending(&lock)?.is_some() {
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }
        let pending = plan_private_oram_mutation_local_floor_pending_v2(
            stable.as_ref(),
            next_checkpoint,
            prior_raft_state_digest,
            next_raft_state_digest,
        )?;
        write_json_atomic(&lock, PENDING_FLOOR_FILE, &pending, None)?;
        lock.validate_root_identity()?;
        Ok(pending)
    }

    /// Begins a floor transition while retaining the cross-process floor lock through publication
    /// of the complete Raft-state image and stable-floor finalization.
    pub(crate) fn begin_transition_guard(
        &self,
        next_checkpoint: &PrivateOramMutationLocalFloorCheckpointV2,
        prior_raft_state_digest: String,
        next_raft_state_digest: String,
    ) -> Result<PrivateOramMutationFloorTransitionGuardV2, PrivateOramMutationJournalError> {
        let lock = self
            .acquire_lock(true)?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        cleanup_floor_temp_files(&lock)?;
        let stable = load_stable(&lock)?;
        if load_pending(&lock)?.is_some() {
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }
        let pending = plan_private_oram_mutation_local_floor_pending_v2(
            stable.as_ref(),
            next_checkpoint,
            prior_raft_state_digest,
            next_raft_state_digest,
        )?;
        write_json_atomic(&lock, PENDING_FLOOR_FILE, &pending, None)?;
        lock.validate_root_identity()?;
        Ok(PrivateOramMutationFloorTransitionGuardV2 { lock, pending })
    }

    pub(crate) fn finalize_transition(
        &self,
        expected: &PrivateOramMutationLocalFloorPendingV2,
        observed_raft_state_digest: &str,
    ) -> Result<PrivateOramMutationLocalFloorCheckpointV2, PrivateOramMutationJournalError> {
        let lock = self
            .acquire_lock(false)?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        cleanup_floor_temp_files(&lock)?;
        let stable = load_stable(&lock)?;
        let pending = load_pending(&lock)?.ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if &pending != expected {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        match plan_private_oram_mutation_local_floor_recovery_v2(
            stable.as_ref(),
            &pending,
            observed_raft_state_digest,
        )? {
            PrivateOramMutationLocalFloorRecoveryActionV2::PromoteNextThenRemovePending => {
                publish_stable(&lock, stable.as_ref(), &pending.next_checkpoint)?;
            }
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepNext => {}
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepPrior => {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        remove_pending(&lock)?;
        lock.validate_root_identity()?;
        Ok(pending.next_checkpoint)
    }

    pub(crate) fn recover(
        &self,
        observed_raft_state_digest: &str,
    ) -> Result<Option<PrivateOramMutationLocalFloorCheckpointV2>, PrivateOramMutationJournalError>
    {
        validate_digest(observed_raft_state_digest)?;
        let Some(lock) = self.acquire_lock(false)? else {
            return Ok(None);
        };
        cleanup_floor_temp_files(&lock)?;
        let stable = load_stable(&lock)?;
        let Some(pending) = load_pending(&lock)? else {
            lock.validate_root_identity()?;
            return Ok(stable);
        };
        let recovered = match plan_private_oram_mutation_local_floor_recovery_v2(
            stable.as_ref(),
            &pending,
            observed_raft_state_digest,
        )? {
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepPrior => stable,
            PrivateOramMutationLocalFloorRecoveryActionV2::PromoteNextThenRemovePending => {
                publish_stable(&lock, stable.as_ref(), &pending.next_checkpoint)?;
                Some(pending.next_checkpoint.clone())
            }
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepNext => {
                Some(pending.next_checkpoint.clone())
            }
        };
        remove_pending(&lock)?;
        lock.validate_root_identity()?;
        Ok(recovered)
    }

    fn acquire_lock(
        &self,
        create: bool,
    ) -> Result<Option<PrivateOramMutationFloorStoreLock>, PrivateOramMutationJournalError> {
        if create {
            create_private_directory(&self.root)?;
        } else if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        let root = open_pinned_floor_directory(&self.root)?;
        let lock_path = root.entry_path(&self.root, FLOOR_LOCK_FILE)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        secure_open_options(&mut options, true);
        let file = options
            .open(&lock_path)
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_file_metadata(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            0,
        )?;
        FileExt::lock_exclusive(file.file()).map_err(PrivateOramMutationJournalError::Io)?;
        let current =
            fs::symlink_metadata(&lock_path).map_err(PrivateOramMutationJournalError::Io)?;
        ensure_same_file(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &current,
        )?;
        validate_private_file_metadata(&current, 0)?;
        file.sync_all()
            .map_err(PrivateOramMutationJournalError::Io)?;
        root.validate_at_path(&self.root)?;
        sync_directory(&root.pinned_path(&self.root))?;
        Ok(Some(PrivateOramMutationFloorStoreLock {
            _file: file,
            root,
            root_path: self.root.clone(),
        }))
    }
}

fn load_stable(
    lock: &PrivateOramMutationFloorStoreLock,
) -> Result<Option<PrivateOramMutationLocalFloorCheckpointV2>, PrivateOramMutationJournalError> {
    let path = lock.entry_path(STABLE_FLOOR_FILE)?;
    if !path_entry_exists(&path)? {
        return Ok(None);
    }
    let checkpoint = read_json_private(&path, MAX_LOCAL_FLOOR_FILE_BYTES)?;
    validate_private_oram_mutation_local_floor_checkpoint_v2(&checkpoint)?;
    Ok(Some(checkpoint))
}

fn load_pending(
    lock: &PrivateOramMutationFloorStoreLock,
) -> Result<Option<PrivateOramMutationLocalFloorPendingV2>, PrivateOramMutationJournalError> {
    let path = lock.entry_path(PENDING_FLOOR_FILE)?;
    if !path_entry_exists(&path)? {
        return Ok(None);
    }
    let pending = read_json_private(&path, MAX_LOCAL_FLOOR_FILE_BYTES)?;
    validate_private_oram_mutation_local_floor_pending_v2(&pending)?;
    Ok(Some(pending))
}

fn publish_stable(
    lock: &PrivateOramMutationFloorStoreLock,
    previous: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    next: &PrivateOramMutationLocalFloorCheckpointV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_local_floor_checkpoint_transition_v2(previous, next)?;
    let previous_digest = match previous {
        Some(_) => Some(file_sha256(
            &lock.entry_path(STABLE_FLOOR_FILE)?,
            MAX_LOCAL_FLOOR_FILE_BYTES,
        )?),
        None => None,
    };
    write_json_atomic(lock, STABLE_FLOOR_FILE, next, previous_digest)
}

fn remove_pending(
    lock: &PrivateOramMutationFloorStoreLock,
) -> Result<(), PrivateOramMutationJournalError> {
    let path = lock.entry_path(PENDING_FLOOR_FILE)?;
    if !path_entry_exists(&path)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let metadata = fs::symlink_metadata(&path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(&metadata, MAX_LOCAL_FLOOR_FILE_BYTES)?;
    fs::remove_file(&path).map_err(PrivateOramMutationJournalError::Io)?;
    sync_directory(&lock.root.pinned_path(&lock.root_path))?;
    if path_entry_exists(&path)? {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    Ok(())
}

fn write_json_atomic<T: Serialize>(
    lock: &PrivateOramMutationFloorStoreLock,
    destination_name: &str,
    value: &T,
    previous_file_digest: Option<[u8; 32]>,
) -> Result<(), PrivateOramMutationJournalError> {
    let root = lock.root.pinned_path(&lock.root_path);
    let destination = lock.entry_path(destination_name)?;
    let mut candidate = tempfile::Builder::new()
        .prefix(FLOOR_TEMP_PREFIX)
        .tempfile_in(&root)
        .map_err(PrivateOramMutationJournalError::Io)?;
    let mut candidate_hasher = Sha256::new();
    {
        let mut writer = FloorSha256Writer {
            inner: &mut candidate,
            hasher: &mut candidate_hasher,
        };
        serde_json::to_writer(&mut writer, value)
            .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
        writer
            .flush()
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    let candidate_digest: [u8; 32] = candidate_hasher.finalize().into();
    candidate
        .as_file()
        .sync_all()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(
        &candidate
            .as_file()
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        MAX_LOCAL_FLOOR_FILE_BYTES,
    )?;

    if let Err(error) =
        persist_floor_candidate(candidate, &destination, previous_file_digest.is_none())
    {
        let observed = observed_file_digest(&destination)?;
        if observed == Some(candidate_digest) {
            return sync_floor_parent_after_publish(lock, &destination, candidate_digest);
        }
        if observed == previous_file_digest {
            return Err(PrivateOramMutationJournalError::Io(error));
        }
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    if observed_file_digest(&destination)? != Some(candidate_digest) {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    sync_floor_parent_after_publish(lock, &destination, candidate_digest)
}

fn persist_floor_candidate(
    candidate: NamedTempFile,
    destination: &Path,
    require_absent: bool,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        if require_absent {
            candidate
                .persist_noclobber(destination)
                .map(|_| ())
                .map_err(|error| error.error)
        } else {
            candidate
                .persist(destination)
                .map(|_| ())
                .map_err(|error| error.error)
        }
    }
    #[cfg(not(unix))]
    {
        if require_absent && destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "floor destination already exists",
            ));
        }
        atomicwrites::replace_atomic(candidate.path(), destination)
    }
}

fn observed_file_digest(path: &Path) -> Result<Option<[u8; 32]>, PrivateOramMutationJournalError> {
    if !path_entry_exists(path)? {
        return Ok(None);
    }
    file_sha256(path, MAX_LOCAL_FLOOR_FILE_BYTES).map(Some)
}

fn sync_floor_parent_after_publish(
    lock: &PrivateOramMutationFloorStoreLock,
    destination: &Path,
    expected_digest: [u8; 32],
) -> Result<(), PrivateOramMutationJournalError> {
    for _ in 0..PARENT_SYNC_ATTEMPTS {
        if sync_directory(&lock.root.pinned_path(&lock.root_path)).is_ok() {
            return if observed_file_digest(destination)? == Some(expected_digest) {
                lock.validate_root_identity()?;
                Ok(())
            } else {
                Err(PrivateOramMutationJournalError::Indeterminate)
            };
        }
        if observed_file_digest(destination)? != Some(expected_digest) {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
    }
    Err(PrivateOramMutationJournalError::Indeterminate)
}

struct FloorSha256Writer<'a, W> {
    inner: W,
    hasher: &'a mut Sha256,
}

impl<W: Write> Write for FloorSha256Writer<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn cleanup_floor_temp_files(
    lock: &PrivateOramMutationFloorStoreLock,
) -> Result<(), PrivateOramMutationJournalError> {
    let root = lock.root.pinned_path(&lock.root_path);
    let mut removed = false;
    for entry in fs::read_dir(&root).map_err(PrivateOramMutationJournalError::Io)? {
        let entry = entry.map_err(PrivateOramMutationJournalError::Io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if matches!(
            name.as_str(),
            FLOOR_LOCK_FILE | STABLE_FLOOR_FILE | PENDING_FLOOR_FILE
        ) {
            continue;
        }
        if !name.starts_with(FLOOR_TEMP_PREFIX) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_file_metadata(&metadata, MAX_LOCAL_FLOOR_FILE_BYTES)?;
        fs::remove_file(path).map_err(PrivateOramMutationJournalError::Io)?;
        removed = true;
    }
    if removed {
        sync_directory(&root)?;
    }
    lock.validate_root_identity()
}

struct PinnedPrivateOramMutationFloorDirectory {
    directory: File,
}

impl PinnedPrivateOramMutationFloorDirectory {
    fn pinned_path(&self, fallback: &Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let _ = fallback;
            PathBuf::from("/proc/self/fd").join(self.directory.file().as_raw_fd().to_string())
        }
        #[cfg(not(target_os = "linux"))]
        {
            fallback.to_path_buf()
        }
    }

    fn entry_path(
        &self,
        fallback_root: &Path,
        name: &str,
    ) -> Result<PathBuf, PrivateOramMutationJournalError> {
        if name.is_empty()
            || Path::new(name).components().count() != 1
            || matches!(name, "." | "..")
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        Ok(self.pinned_path(fallback_root).join(name))
    }

    fn validate_at_path(&self, path: &Path) -> Result<(), PrivateOramMutationJournalError> {
        let opened = self
            .directory
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_floor_directory_metadata(&opened)?;
        let current = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
        validate_floor_directory_metadata(&current)?;
        ensure_same_floor_directory(&opened, &current)
    }
}

fn open_pinned_floor_directory(
    path: &Path,
) -> Result<PinnedPrivateOramMutationFloorDirectory, PrivateOramMutationJournalError> {
    let before = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_floor_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    let directory = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    let opened = directory
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_floor_directory_metadata(&opened)?;
    ensure_same_floor_directory(&before, &opened)?;
    let pinned = PinnedPrivateOramMutationFloorDirectory { directory };
    pinned.validate_at_path(path)?;
    Ok(pinned)
}

fn validate_floor_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7077 != 0
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_same_floor_directory(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if !before.file_type().is_dir() || !after.file_type().is_dir() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

struct PrivateOramMutationFloorStoreLock {
    _file: File,
    root: PinnedPrivateOramMutationFloorDirectory,
    root_path: PathBuf,
}

impl PrivateOramMutationFloorStoreLock {
    fn entry_path(&self, name: &str) -> Result<PathBuf, PrivateOramMutationJournalError> {
        self.root.entry_path(&self.root_path, name)
    }

    fn validate_root_identity(&self) -> Result<(), PrivateOramMutationJournalError> {
        self.root.validate_at_path(&self.root_path)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::mpsc;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::content_manager::consensus::private_oram_mutation_cleanup::authority::{
        activate_private_oram_mutation_authority_v2,
        private_oram_mutation_activation_context_for_test, private_oram_mutation_authority_key_v2,
        private_oram_mutation_legacy_authority_v2,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::format::{
        PrivateOramMutationFormatFloorTestInputV2,
        plan_private_oram_mutation_authority_floor_acceptance_v2,
        private_oram_mutation_format_floor_for_test,
    };
    use crate::content_manager::consensus_ops::{
        PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION, PrivateOramMutationLeaseSlotV2,
    };

    fn digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn format_floor(
        format_epoch: u64,
        membership_generation: u64,
        activation_enabled: bool,
        index: u64,
    ) -> PrivateOramMutationFormatFloorV2 {
        private_oram_mutation_format_floor_for_test(PrivateOramMutationFormatFloorTestInputV2 {
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            format_epoch,
            minimum_reader_protocol: 2,
            minimum_writer_protocol: 2,
            snapshot_format_epoch: format_epoch,
            membership_generation,
            eligible_peer_set_digest: digest(3_u8.wrapping_add(format_epoch as u8)),
            eligible_process_incarnations_digest: digest(13_u8.wrapping_add(format_epoch as u8)),
            capability_manifest_digest: digest(23_u8.wrapping_add(format_epoch as u8)),
            activation_enabled,
            term: 1,
            index,
        })
        .unwrap()
    }

    fn activated_authority_floor(
        format_floor: &PrivateOramMutationFormatFloorV2,
    ) -> PrivateOramMutationAuthorityFloorV2 {
        let slot = PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        };
        let legacy = private_oram_mutation_legacy_authority_v2(
            private_oram_mutation_authority_key_v2(
                "collection-a",
                digest(1),
                digest(2),
                digest(30),
            )
            .unwrap(),
            slot,
            digest(31),
        )
        .unwrap();
        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            "collection-a",
            private_oram_mutation_activation_context_for_test(
                digest(1),
                digest(2),
                1,
                10,
                2,
                digest(32),
            )
            .unwrap(),
        )
        .unwrap();
        plan_private_oram_mutation_authority_floor_acceptance_v2(None, format_floor, &activated, 10)
            .unwrap()
    }

    fn genesis_checkpoint() -> PrivateOramMutationLocalFloorCheckpointV2 {
        plan_private_oram_mutation_local_floor_checkpoint_v2(
            None,
            format_floor(1, 1, false, 5),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn activated_checkpoint(
        genesis: &PrivateOramMutationLocalFloorCheckpointV2,
    ) -> PrivateOramMutationLocalFloorCheckpointV2 {
        let format_floor = format_floor(2, 2, true, 6);
        let authority_floor = activated_authority_floor(&format_floor);
        let authority_floors = BTreeMap::from([(
            authority_floor.collection_key_digest().to_string(),
            authority_floor,
        )]);
        plan_private_oram_mutation_local_floor_checkpoint_v2(
            Some(genesis),
            format_floor,
            authority_floors,
        )
        .unwrap()
    }

    fn store(temp: &TempDir) -> PrivateOramMutationFloorStoreV2 {
        PrivateOramMutationFloorStoreV2::new(temp.path())
    }

    fn install_genesis(
        store: &PrivateOramMutationFloorStoreV2,
        prior_state: &str,
        next_state: &str,
    ) -> PrivateOramMutationLocalFloorCheckpointV2 {
        let checkpoint = genesis_checkpoint();
        let pending = store
            .begin_transition(&checkpoint, prior_state.to_string(), next_state.to_string())
            .unwrap();
        store.finalize_transition(&pending, next_state).unwrap()
    }

    #[test]
    fn checkpoint_transition_is_immediate_monotonic_and_cannot_drop_authority() {
        let genesis = genesis_checkpoint();
        let activated = activated_checkpoint(&genesis);
        assert_eq!(genesis.generation(), 1);
        assert_eq!(activated.generation(), 2);
        assert!(activated.authority_floor(digest(30).as_str()).is_none());
        assert_eq!(
            plan_private_oram_mutation_local_floor_checkpoint_v2(
                Some(&activated),
                activated.format_floor().clone(),
                activated.authority_floors.clone(),
            )
            .unwrap(),
            activated
        );

        assert!(matches!(
            plan_private_oram_mutation_local_floor_checkpoint_v2(
                Some(&activated),
                activated.format_floor().clone(),
                BTreeMap::new(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut skipped = activated.clone();
        skipped.generation += 1;
        skipped.checkpoint_digest = local_floor_checkpoint_digest_v2(&skipped).unwrap();
        assert!(matches!(
            validate_private_oram_mutation_local_floor_checkpoint_transition_v2(
                Some(&genesis),
                &skipped,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn pending_recovery_accepts_only_exact_old_or_new_state_images() {
        let next = genesis_checkpoint();
        let pending =
            plan_private_oram_mutation_local_floor_pending_v2(None, &next, digest(70), digest(71))
                .unwrap();
        assert_eq!(
            plan_private_oram_mutation_local_floor_recovery_v2(None, &pending, &digest(70))
                .unwrap(),
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepPrior
        );
        assert_eq!(
            plan_private_oram_mutation_local_floor_recovery_v2(None, &pending, &digest(71))
                .unwrap(),
            PrivateOramMutationLocalFloorRecoveryActionV2::PromoteNextThenRemovePending
        );
        assert!(matches!(
            plan_private_oram_mutation_local_floor_recovery_v2(None, &pending, &digest(72)),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        assert_eq!(
            plan_private_oram_mutation_local_floor_recovery_v2(Some(&next), &pending, &digest(71),)
                .unwrap(),
            PrivateOramMutationLocalFloorRecoveryActionV2::RemovePendingKeepNext
        );
    }

    #[test]
    fn store_rolls_back_pending_when_raft_state_is_still_old() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        let checkpoint = genesis_checkpoint();
        store
            .begin_transition(&checkpoint, digest(70), digest(71))
            .unwrap();
        assert!(path_entry_exists(&store.root.join(PENDING_FLOOR_FILE)).unwrap());

        assert_eq!(store.recover(&digest(70)).unwrap(), None);
        assert!(!path_entry_exists(&store.root.join(PENDING_FLOOR_FILE)).unwrap());
        assert!(!path_entry_exists(&store.root.join(STABLE_FLOOR_FILE)).unwrap());
    }

    #[test]
    fn store_rolls_forward_pending_when_raft_state_is_new() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        let checkpoint = genesis_checkpoint();
        store
            .begin_transition(&checkpoint, digest(70), digest(71))
            .unwrap();

        assert_eq!(
            store.recover(&digest(71)).unwrap(),
            Some(checkpoint.clone())
        );
        assert!(!path_entry_exists(&store.root.join(PENDING_FLOOR_FILE)).unwrap());
        assert!(path_entry_exists(&store.root.join(STABLE_FLOOR_FILE)).unwrap());
        assert_eq!(store.recover(&digest(71)).unwrap(), Some(checkpoint));
    }

    #[test]
    fn transition_guard_holds_cross_process_lock_until_publish_outcome_is_known() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        let guard = store
            .begin_transition_guard(&genesis_checkpoint(), digest(70), digest(71))
            .unwrap();
        let contender = store.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx.send(contender.recover(&digest(70))).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());

        drop(guard);
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            None
        );
        worker.join().unwrap();
    }

    #[test]
    fn store_cleans_pending_after_stable_was_already_promoted() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        let checkpoint = genesis_checkpoint();
        store
            .begin_transition(&checkpoint, digest(70), digest(71))
            .unwrap();
        {
            let lock = store.acquire_lock(false).unwrap().unwrap();
            let pending = load_pending(&lock).unwrap().unwrap();
            publish_stable(&lock, None, pending.next_checkpoint()).unwrap();
        }

        assert_eq!(store.recover(&digest(71)).unwrap(), Some(checkpoint));
        assert!(!path_entry_exists(&store.root.join(PENDING_FLOOR_FILE)).unwrap());
    }

    #[test]
    fn store_preserves_intent_and_floor_on_unrelated_state_image() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        let genesis = install_genesis(&store, &digest(70), &digest(71));
        let activated = activated_checkpoint(&genesis);
        store
            .begin_transition(&activated, digest(71), digest(72))
            .unwrap();

        assert!(matches!(
            store.recover(&digest(99)),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        assert!(path_entry_exists(&store.root.join(PENDING_FLOOR_FILE)).unwrap());
        let lock = store.acquire_lock(false).unwrap().unwrap();
        assert_eq!(load_stable(&lock).unwrap(), Some(genesis));
        assert_eq!(
            load_pending(&lock).unwrap().unwrap().next_checkpoint,
            activated
        );
    }

    #[test]
    fn store_rejects_unknown_entries_and_cleans_private_temp_files() {
        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        store
            .begin_transition(&genesis_checkpoint(), digest(70), digest(71))
            .unwrap();
        store.recover(&digest(70)).unwrap();

        let temp_path = store.root.join(format!("{FLOOR_TEMP_PREFIX}orphan"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_open_options(&mut options, true);
        let mut orphan = options.open(&temp_path).unwrap();
        orphan.write_all(b"orphan").unwrap();
        orphan.sync_all().unwrap();
        drop(orphan);
        assert_eq!(store.recover(&digest(70)).unwrap(), None);
        assert!(!path_entry_exists(&temp_path).unwrap());

        fs::write(store.root.join("unexpected"), b"unexpected").unwrap();
        assert!(matches!(
            store.recover(&digest(70)),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_symlinked_floor_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = store(&temp);
        let target = temp.path().join("target");
        create_private_directory(&target).unwrap();
        symlink(&target, &store.root).unwrap();
        assert!(matches!(
            store.recover(&digest(70)),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn floor_store_codecs_and_debug_output_fail_closed() {
        let checkpoint = genesis_checkpoint();
        let mut encoded = serde_json::to_value(&checkpoint).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), serde_json::json!(1));
        assert!(
            serde_json::from_value::<PrivateOramMutationLocalFloorCheckpointV2>(encoded).is_err()
        );

        let mut tampered = checkpoint.clone();
        tampered.checkpoint_digest = digest(99);
        assert!(matches!(
            validate_private_oram_mutation_local_floor_checkpoint_v2(&tampered),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        let pending = plan_private_oram_mutation_local_floor_pending_v2(
            None,
            &checkpoint,
            digest(70),
            digest(71),
        )
        .unwrap();
        let debug = format!("{checkpoint:?} {pending:?}");
        for secret in [digest(1), digest(2), digest(70), digest(71)] {
            assert!(!debug.contains(&secret), "{debug}");
        }
    }

    #[test]
    fn floor_store_digests_match_known_answer_vectors() {
        let checkpoint = genesis_checkpoint();
        assert_eq!(
            checkpoint.checkpoint_digest,
            "OPI2y6J6WsVN_qAy7SL6JGqnIi3YJrXUl67xia72EXU"
        );
        let pending = plan_private_oram_mutation_local_floor_pending_v2(
            None,
            &checkpoint,
            private_oram_mutation_raft_state_image_digest_v2(b"prior-raft-state"),
            private_oram_mutation_raft_state_image_digest_v2(b"next-raft-state"),
        )
        .unwrap();
        assert_eq!(
            pending.pending_digest,
            "Tql5mzZwI9Or7m3mfEjR7rNylI-xlROeRLOk5vlDUNI"
        );
    }
}
