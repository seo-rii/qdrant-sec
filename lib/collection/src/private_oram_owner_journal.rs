#![allow(
    dead_code,
    reason = "D3-B3-B2 is dormant until the private ORAM mutation coordinator is wired"
)]

//! Prepared-first durable owner journal for a paired private ORAM append mutation.
//!
//! The journal lives below the primary HNSW store's existing `temp` directory. A non-empty
//! journal therefore reuses the collection snapshot incomplete-write gate. Publication requires
//! Linux `renameat2(RENAME_NOREPLACE)` and an owner-only local filesystem with durable directory
//! fsync. No canonical HNSW/result bucket, Merkle, epoch, or point file is modified by prepare.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use qdrant_sec::{
    PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS, PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2,
    PrivateHnswOramBucket, PrivateOramAppendBucketRefV1, PrivateOramAppendMutationBundleV1,
    PrivateOramIndexKindV2, PrivateOramOwnerCleanupObservedPrestateV1,
    PrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerCleanupTerminalStateV1, PrivateOramOwnerLifecycleStateV1,
    PrivateOramOwnerPrestagePackageV2, PrivateOramOwnerPrestageRequestV2,
    PrivateOramOwnerReservationPrepareChallengeV1, PrivateOramValidatedOwnerFinalBucketsV1,
    PrivateOramValidatedOwnerPrepareV1, PrivateResultOramBucket,
    SignedPrivateOramOwnerCleanupAuthorizationV1, SignedPrivateOramOwnerCleanupReceiptV1,
    VerifiedPrivateOramOwnerCleanupAuthorizationV1, VerifiedPrivateOramOwnerPrestageRequestV2,
    decode_private_oram_owner_prestage_package_v2, private_oram_append_mutation_v1_digest,
    private_oram_owner_cleanup_receipt_v1, private_oram_owner_lifecycle_genesis_state_v1,
    private_oram_owner_prestage_request_digest_v2, validate_private_oram_owner_lifecycle_state_v1,
    validate_private_oram_owner_prestage_package_for_request_v2,
    validate_private_oram_owner_reservation_prepare_challenge_v1,
    validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1,
    validate_self_consistent_signed_private_oram_owner_cleanup_receipt_v1,
    validate_signed_private_oram_owner_cleanup_receipt_v1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(test)]
thread_local! {
    static FAIL_OWNER_ARCHIVE_AFTER_CANONICAL_RENAME_V1: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static FAIL_OWNER_ARCHIVE_AFTER_RECORD_PUBLISH_V1: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn set_fail_owner_archive_after_canonical_rename_v1(enabled: bool) {
    FAIL_OWNER_ARCHIVE_AFTER_CANONICAL_RENAME_V1.set(enabled);
}

#[cfg(test)]
pub(crate) fn set_fail_owner_archive_after_record_publish_v1(enabled: bool) {
    FAIL_OWNER_ARCHIVE_AFTER_RECORD_PUBLISH_V1.set(enabled);
}

fn fail_owner_archive_after_canonical_rename_v1() -> Result<(), PrivateOramOwnerJournalError> {
    #[cfg(test)]
    if FAIL_OWNER_ARCHIVE_AFTER_CANONICAL_RENAME_V1.get() {
        return Err(PrivateOramOwnerJournalError::Indeterminate);
    }
    Ok(())
}

fn fail_owner_archive_after_record_publish_v1() -> Result<(), PrivateOramOwnerJournalError> {
    #[cfg(test)]
    if FAIL_OWNER_ARCHIVE_AFTER_RECORD_PUBLISH_V1.get() {
        return Err(PrivateOramOwnerJournalError::Indeterminate);
    }
    Ok(())
}

use crate::operations::types::{CollectionError, CollectionResult};
use crate::private_hnsw_oram_store::PRIVATE_HNSW_ORAM_DIR;
use crate::private_oram_owner_store_adapter::PrivateOramOwnerLockedRecoveryTransactionV1;

pub const PRIVATE_ORAM_OWNER_JOURNAL_DIR: &str = "private-oram-owner-v2";
#[doc(hidden)]
pub const PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2: &str = "private-oram-owner-prestage-v2";
pub const PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION: u16 = 1;
pub const PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION: u16 = 1;
pub const PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION: u16 = 1;
#[doc(hidden)]
pub const PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2: &str = "private_oram_mutations";
#[doc(hidden)]
pub const PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2: &str = "terminal_archive_v2.json";
#[doc(hidden)]
pub const PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1: &str =
    "owner_child_archive_grant_v1.json";
#[doc(hidden)]
pub const PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_MAX_BYTES_V2: u64 = 64 * 1024;
#[doc(hidden)]
pub const PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_MAX_BYTES_V1: u64 = 128 * 1024;
const PRIVATE_ORAM_PARENT_DESCRIPTOR_MAX_BYTES_V2: u64 = 512 * 1024 * 1024;
const PRIVATE_ORAM_PARENT_IMMUTABLE_MANIFEST_MAX_BYTES_V2: u64 = 4 * 1024 * 1024;
const PRIVATE_ORAM_PARENT_STATE_MAX_BYTES_V2: u64 = 64 * 1024 * 1024;
const PRIVATE_ORAM_PARENT_FORMAT_MAX_BYTES_V2: u64 = 4 * 1024;
const PRIVATE_ORAM_PARENT_CLEANUP_MAX_BYTES_V2: u64 = 64 * 1024;
const PRIVATE_ORAM_PARENT_STATE_RECORD_COUNT_V2: u64 = 7;

/// Test-only process crash points for the owner journal kill matrix: when the environment
/// names this point, the process aborts there (no unwinding, no destructors), like a kill.
#[cfg(test)]
const PRIVATE_ORAM_OWNER_JOURNAL_CRASH_POINT_ENV: &str =
    "QDRANT_SEC_PRIVATE_ORAM_OWNER_JOURNAL_CRASH_POINT";

#[cfg(test)]
fn private_oram_owner_journal_crash_point(name: &str) {
    if std::env::var(PRIVATE_ORAM_OWNER_JOURNAL_CRASH_POINT_ENV).is_ok_and(|point| point == name) {
        std::process::abort();
    }
}

#[cfg(not(test))]
#[inline(always)]
fn private_oram_owner_journal_crash_point(_name: &str) {}

const OWNER_STORE_TEMP_DIR: &str = "temp";
#[doc(hidden)]
pub const PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2: &str = "journal.lock";
const ACTIVE_DIR: &str = "active";
const ACTIVE_TEMP_DIR: &str = "temp";
const DESCRIPTOR_FILE: &str = "descriptor.bin";
const FINAL_BUCKETS_FILE: &str = "final-buckets.bin";
const STATE_FILE: &str = "state.bin";
const TERMINAL_DIR: &str = "terminal";
const TERMINAL_RECORD_FILE: &str = "record.bin";
const COMPLETED_DIR_PREFIX: &str = "completed-v2-";
const OWNER_TERMINAL_ARCHIVE_FILE: &str = "owner-terminal-archive-v1.json";
const CANDIDATE_PREFIX: &str = ".candidate-";
const TERMINAL_CANDIDATE_PREFIX: &str = ".terminal-candidate-";
const PREPARED_PHASE_TAG: u8 = 1;
const FINALIZED_PHASE_TAG: u8 = 2;
const ABORTED_OLD_PHASE_TAG: u8 = 3;
const HNSW_KIND_TAG: u8 = 1;
const RESULT_KIND_TAG: u8 = 2;
const MAX_DESCRIPTOR_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FINAL_BUCKET_FRAME_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 4 * 1024;
const MAX_TERMINAL_RECORD_BYTES: u64 = 4 * 1024;
const MAX_OWNER_TERMINAL_ARCHIVE_BYTES: u64 = 128 * 1024;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const DIGEST_BYTES: usize = 32;
const MAX_PAIRED_OWNER_INDEXES: usize = 2;
const MAX_OWNER_ADOPTION_CANONICAL_BYTES: usize = 64 * 1024;

const PRESTAGE_ROOT_DIR: &str = PRIVATE_ORAM_OWNER_PRESTAGE_ROOT_DIR_V2;
const PRESTAGE_INTENTS_DIR: &str = "intents";
const PRESTAGE_TEMP_DIR: &str = "temp";
const PRESTAGE_TERMINALS_DIR: &str = "terminals";
const PRESTAGE_RETIRED_DIR: &str = "retired";
const PRESTAGE_QUARANTINE_DIR: &str = "quarantine";
const PRESTAGE_RESERVATION_FENCE_DIR: &str = "reservation-fence";
const PRESTAGE_SUPERBLOCK_FILE: &str = "superblock.json";
const PRESTAGE_PACKAGE_FILE: &str = "package.json";
const PRESTAGE_RECEIPT_FILE: &str = "receipt.json";
const PRESTAGE_INTENT_MARKER_FILE: &str = "intent.json";
const PRESTAGE_ADOPTION_PENDING_MARKER_FILE: &str = "adoption-pending.json";
const PRESTAGE_ADOPTED_MARKER_FILE: &str = "adopted.json";
const PRESTAGE_TERMINAL_RECORD_FILE: &str = "record.json";
const PRESTAGE_RESERVATION_FENCE_FILE: &str = "fence.json";
const PRESTAGE_RESERVATION_RESOLUTION_FILE: &str = "resolution.json";
const PRESTAGE_RESERVATION_ABORT_RELEASE_FILE: &str = "abort-release.json";
const PRESTAGE_RECEIPT_VERSION: u16 = 4;
const PRESTAGE_SUPERBLOCK_VERSION: u16 = 2;
const PRESTAGE_LIFECYCLE_MARKER_VERSION: u16 = 3;
const PRESTAGE_MAX_PACKAGE_BYTES: u64 = PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2 as u64;
const PRESTAGE_MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const PRESTAGE_MAX_SUPERBLOCK_BYTES: u64 = 64 * 1024;
const PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES: u64 = 64 * 1024;
const PRESTAGE_MAX_TERMINAL_RECORDS: usize = 4_096;
const PRESTAGE_RESERVATION_FENCE_VERSION: u16 = 1;
const PRESTAGE_RESERVATION_RESOLUTION_VERSION_V2: u16 = 2;
const PRESTAGE_RESERVATION_RESOLUTION_VERSION: u16 = 3;
const PRESTAGE_RESERVATION_ABORT_RELEASE_VERSION: u16 = 1;
const PRESTAGE_MAX_RESERVATION_FENCE_BYTES: u64 = 128 * 1024;
const PRESTAGE_MAX_RESERVATION_RESOLUTION_BYTES: u64 = 64 * 1024;
const PRESTAGE_MAX_RESERVATION_ABORT_RELEASE_BYTES: u64 = 64 * 1024;
const PRESTAGE_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-prestage-storage-receipt/v3";
const PRESTAGE_SUPERBLOCK_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-prestage-superblock/v2";
const PRESTAGE_OWNER_STORE_INCARNATION_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-store-incarnation/v2";
const PRESTAGE_LIFECYCLE_MARKER_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-prestage-lifecycle-marker/v3";
const PRESTAGE_RESERVATION_FENCE_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-reservation-fence/v1";
const PRESTAGE_RESERVATION_RESOLUTION_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-reservation-resolution/v1";
const PRESTAGE_RESERVATION_ABSENT_FENCE_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-reservation-absent-fence/v1";
const PRESTAGE_RESERVATION_ABORT_RELEASE_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-reservation-abort-release/v1";

const DESCRIPTOR_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-journal-descriptor/v1";
const STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-journal-state/v1";
const FINALIZED_STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-finalized-state/v1";
const ABORTED_OLD_STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-aborted-old-state/v1";
const FINAL_BUCKET_FRAME_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-final-bucket-frame/v1";
const INDEX_PREPARED_EVIDENCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-index-prepared-evidence/v1";
const INDEX_FINALIZED_EVIDENCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-index-finalized-evidence/v1";
const INDEX_ABORTED_OLD_EVIDENCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-index-aborted-old-evidence/v1";
const OWNER_COMMITTED_ARCHIVE_GRANT_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-committed-archive-grant/v1";
const OWNER_SNAPSHOT_AUTHORITY_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-owner-snapshot-authority-digest/v2";
const OWNER_TERMINAL_ARCHIVE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-terminal-archive/v1";
const OWNER_TERMINAL_ARCHIVE_VERSION: u16 = 1;
const OWNER_COMMITTED_ARCHIVE_GRANT_VERSION: u16 = 2;
const OWNER_COMMITTED_ARCHIVE_TERMINAL_FORMAT_V2: &str =
    "private-oram-mutation-terminal-archive/v2";

const fn bool_true() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Error, Clone, Copy, PartialEq, Eq)]
pub enum PrivateOramOwnerJournalError {
    #[error("private ORAM owner journal is unsupported on this platform or filesystem")]
    Unsupported,
    #[error("private ORAM owner journal input is invalid")]
    InvalidInput(&'static str),
    #[error("private ORAM owner journal is not enrolled")]
    NotEnrolled,
    #[error("another private ORAM owner journal is active")]
    ConcurrentMutation,
    #[error("private ORAM owner journal phase transition is invalid")]
    InvalidTransition,
    #[error("private ORAM owner journal contains corrupt or inconsistent state")]
    Corrupt,
    #[error("private ORAM owner journal I/O failed before publication")]
    Io,
    #[error("private ORAM owner journal publication outcome is indeterminate")]
    Indeterminate,
    #[error("private ORAM owner cleanup terminal commit is indeterminate")]
    IndeterminateTerminalCommit,
    #[error("private ORAM owner cleanup requires externally authenticated recovery")]
    ExternalRecoveryRequired,
    #[error("private ORAM owner cleanup terminal capacity is exhausted")]
    TerminalCapacityExceeded,
}

impl Debug for PrivateOramOwnerJournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Unsupported"),
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::NotEnrolled => f.write_str("NotEnrolled"),
            Self::ConcurrentMutation => f.write_str("ConcurrentMutation"),
            Self::InvalidTransition => f.write_str("InvalidTransition"),
            Self::Corrupt => f.write_str("Corrupt([redacted])"),
            Self::Io => f.write_str("Io([redacted])"),
            Self::Indeterminate => f.write_str("Indeterminate([redacted])"),
            Self::IndeterminateTerminalCommit => {
                f.write_str("IndeterminateTerminalCommit([redacted])")
            }
            Self::ExternalRecoveryRequired => f.write_str("ExternalRecoveryRequired([redacted])"),
            Self::TerminalCapacityExceeded => f.write_str("TerminalCapacityExceeded"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerJournalRequirementV1<'a> {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: &'a str,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub writeback_digest: &'a str,
}

impl Debug for PrivateOramOwnerJournalRequirementV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalRequirementV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerJournalPrepareContextV1<'a> {
    pub(crate) parent_descriptor_digest: &'a str,
    pub(crate) parent_lease_acquired_record_digest: &'a str,
    pub(crate) owner_peer_id: u64,
    pub(crate) requirements: &'a [PrivateOramOwnerJournalRequirementV1<'a>],
}

/// Cross-crate input for one owner prepare after the V2 parent journal is durable.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrepareParentV2 {
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    owner_peer_id: u64,
    requirements: Vec<PrivateOramOwnerPrepareRequirementV2>,
}

/// Non-authoritative future-parent projection used to build one inert owner intent.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerPrestagePlanV2 {
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    owner_peer_id: u64,
    requirements: Vec<PrivateOramOwnerPrepareRequirementV2>,
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrepareRequirementV2 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub writeback_digest: String,
}

impl Debug for PrivateOramOwnerPrepareParentV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPrepareParentV2")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("requirement_count", &self.requirements.len())
            .finish()
    }
}

impl Debug for PrivateOramOwnerPrestagePlanV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPrestagePlanV2")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("requirement_count", &self.requirements.len())
            .finish()
    }
}

impl Debug for PrivateOramOwnerPrepareRequirementV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPrepareRequirementV2")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerPrepareParentV2 {
    pub fn try_new(
        parent_descriptor_digest: String,
        parent_lease_acquired_record_digest: String,
        owner_peer_id: u64,
        requirements: Vec<PrivateOramOwnerPrepareRequirementV2>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_owner_prepare_parent_fields(
            &parent_descriptor_digest,
            &parent_lease_acquired_record_digest,
            &requirements,
        )?;
        Ok(Self {
            parent_descriptor_digest,
            parent_lease_acquired_record_digest,
            owner_peer_id,
            requirements,
        })
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub fn requirements(&self) -> &[PrivateOramOwnerPrepareRequirementV2] {
        &self.requirements
    }
}

impl PrivateOramOwnerPrestagePlanV2 {
    pub fn try_new(
        parent_descriptor_digest: String,
        parent_lease_acquired_record_digest: String,
        owner_peer_id: u64,
        requirements: Vec<PrivateOramOwnerPrepareRequirementV2>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_owner_prepare_parent_fields(
            &parent_descriptor_digest,
            &parent_lease_acquired_record_digest,
            &requirements,
        )?;
        Ok(Self {
            parent_descriptor_digest,
            parent_lease_acquired_record_digest,
            owner_peer_id,
            requirements,
        })
    }
}

/// Durable proof that an exact inert owner package and its prepared journal bytes are installed.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrestageReceiptV2 {
    version: u16,
    intent_key: String,
    collection_id: String,
    mutation_id: String,
    mutation_digest: String,
    expected_aggregate_digest: String,
    lease_generation: u64,
    writer_fence: u64,
    owner_peer_id: u64,
    owner_store_incarnation_digest: String,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    owner_roster_digest: String,
    activation_registry_generation: u64,
    activation_manifest_digest: String,
    package_sha256: String,
    package_len: u64,
    owner_request_digest: String,
    owner_journal_descriptor_digest: String,
    prepared_state_digest: String,
    receipt_digest: String,
}

impl Debug for PrivateOramOwnerPrestageReceiptV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPrestageReceiptV3")
            .field("version", &self.version)
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("package_len", &self.package_len)
            .finish_non_exhaustive()
    }
}

impl PrivateOramOwnerPrestageReceiptV2 {
    pub fn intent_key(&self) -> &str {
        &self.intent_key
    }

    pub fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub fn owner_store_incarnation_digest(&self) -> &str {
        &self.owner_store_incarnation_digest
    }

    pub fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    pub fn mutation_digest(&self) -> &str {
        &self.mutation_digest
    }

    pub fn expected_aggregate_digest(&self) -> &str {
        &self.expected_aggregate_digest
    }

    pub fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    pub fn writer_fence(&self) -> u64 {
        self.writer_fence
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub fn owner_roster_digest(&self) -> &str {
        &self.owner_roster_digest
    }

    pub fn activation_registry_generation(&self) -> u64 {
        self.activation_registry_generation
    }

    pub fn activation_manifest_digest(&self) -> &str {
        &self.activation_manifest_digest
    }

    pub fn prepared_state_digest(&self) -> &str {
        &self.prepared_state_digest
    }

    pub fn package_sha256(&self) -> &str {
        &self.package_sha256
    }

    pub fn package_len(&self) -> u64 {
        self.package_len
    }

    pub fn owner_request_digest(&self) -> &str {
        &self.owner_request_digest
    }

    pub fn owner_journal_descriptor_digest(&self) -> &str {
        &self.owner_journal_descriptor_digest
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    #[cfg(feature = "testing")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_for_test(
        intent_key: String,
        collection_id: String,
        mutation_id: String,
        mutation_digest: String,
        expected_aggregate_digest: String,
        lease_generation: u64,
        writer_fence: u64,
        owner_peer_id: u64,
        owner_store_incarnation_digest: String,
        parent_descriptor_digest: String,
        parent_lease_acquired_record_digest: String,
        owner_roster_digest: String,
        activation_registry_generation: u64,
        activation_manifest_digest: String,
        package_sha256: String,
        package_len: u64,
        owner_request_digest: String,
        owner_journal_descriptor_digest: String,
        prepared_state_digest: String,
    ) -> Self {
        let mut receipt = Self {
            version: PRESTAGE_RECEIPT_VERSION,
            intent_key,
            collection_id,
            mutation_id,
            mutation_digest,
            expected_aggregate_digest,
            lease_generation,
            writer_fence,
            owner_peer_id,
            owner_store_incarnation_digest,
            parent_descriptor_digest,
            parent_lease_acquired_record_digest,
            owner_roster_digest,
            activation_registry_generation,
            activation_manifest_digest,
            package_sha256,
            package_len,
            owner_request_digest,
            owner_journal_descriptor_digest,
            prepared_state_digest,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = private_oram_owner_prestage_receipt_digest_v2(&receipt)
            .expect("test prestage receipt must be canonical");
        receipt
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerPrestageSuperblockV2 {
    version: u16,
    owner_store_incarnation_digest: String,
    lifecycle_generation: u64,
    lifecycle_state_root: String,
    minimum_lifecycle_reader_version: u16,
    lifecycle_capability: String,
    superblock_digest: String,
}

impl PrivateOramOwnerPrestageSuperblockV2 {
    fn lifecycle_state(
        &self,
    ) -> Result<PrivateOramOwnerLifecycleStateV1, PrivateOramOwnerJournalError> {
        let state = PrivateOramOwnerLifecycleStateV1 {
            owner_store_incarnation_digest: self.owner_store_incarnation_digest.clone(),
            generation: self.lifecycle_generation,
            state_root: self.lifecycle_state_root.clone(),
            minimum_reader_version: self.minimum_lifecycle_reader_version,
            capability: self.lifecycle_capability.clone(),
        };
        let genesis = private_oram_owner_lifecycle_genesis_state_v1(
            self.owner_store_incarnation_digest.clone(),
        )
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        if self.lifecycle_generation == 0 && state != genesis {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(state)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrivateOramOwnerLifecycleMarkerKindV2 {
    Intent,
    AdoptionPending,
    Adopted,
    TombstonedAbsent,
    Quarantined,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerLifecycleMarkerV2 {
    version: u16,
    kind: PrivateOramOwnerLifecycleMarkerKindV2,
    owner_store_incarnation_digest: String,
    intent_key: String,
    collection_id: String,
    mutation_id: String,
    mutation_digest: String,
    expected_aggregate_digest: String,
    lease_generation: u64,
    writer_fence: u64,
    owner_peer_id: u64,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    package_sha256: String,
    prestage_receipt_digest: Option<String>,
    owner_journal_descriptor_digest: Option<String>,
    terminal_authority_digest: Option<String>,
    cleanup_authority_signer: Option<PrivateOramOwnerCleanupSignerV1>,
    signed_cleanup_authorization: Option<SignedPrivateOramOwnerCleanupAuthorizationV1>,
    signed_cleanup_receipt: Option<SignedPrivateOramOwnerCleanupReceiptV1>,
    marker_digest: String,
}

impl Debug for PrivateOramOwnerLifecycleMarkerV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerLifecycleMarkerV2")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("intent_key", &"[redacted]")
            .field("marker_digest", &"[redacted]")
            .finish()
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramOwnerLocalIntentStateV2 {
    Absent,
    Intent,
    AdoptionPending,
    Adopted,
    TombstonedAbsent,
    Quarantined,
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerLocalIntentStatusV2 {
    state: PrivateOramOwnerLocalIntentStateV2,
    lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    marker_digest: Option<String>,
}

impl Debug for PrivateOramOwnerLocalIntentStatusV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerLocalIntentStatusV2")
            .field("state", &self.state)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("marker_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerLocalIntentStatusV2 {
    pub const fn state(&self) -> PrivateOramOwnerLocalIntentStateV2 {
        self.state
    }

    pub fn owner_store_incarnation_digest(&self) -> &str {
        &self.lifecycle_state.owner_store_incarnation_digest
    }

    pub fn lifecycle_state(&self) -> &PrivateOramOwnerLifecycleStateV1 {
        &self.lifecycle_state
    }

    pub fn marker_digest(&self) -> Option<&str> {
        self.marker_digest.as_deref()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerReservationFenceRecordV1 {
    version: u16,
    challenge: PrivateOramOwnerReservationPrepareChallengeV1,
    lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    terminal_record_count: u64,
    terminal_record_limit: u64,
    fence_record_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerReservationResolutionKindV1 {
    Finalized,
    Cancelled,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerReservationResolutionRecordV1 {
    version: u16,
    kind: PrivateOramOwnerReservationResolutionKindV1,
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    fence_was_present: bool,
    fence_record_digest: String,
    committed_challenge_digest: String,
    reservation_intent_digest: String,
    attempt_id: String,
    challenge_applied_term: u64,
    challenge_applied_index: u64,
    resolution_applied_term: u64,
    resolution_applied_index: u64,
    reserved_terminal_intent_key: String,
    finalized_reservation_digest: Option<String>,
    owner_store_incarnation_digest: String,
    owner_store_binding_digest: String,
    resolution_record_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerReservationAbortReleaseRecordV1 {
    version: u16,
    resolution_record_digest: String,
    fence_record_digest: String,
    abort_release_authority_digest: String,
    owner_store_incarnation_digest: String,
    owner_store_binding_digest: String,
    release_marker_digest: String,
}

impl Debug for PrivateOramOwnerReservationResolutionRecordV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationResolutionRecordV1")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("fence_was_present", &self.fence_was_present)
            .field("challenge_applied_term", &self.challenge_applied_term)
            .field("challenge_applied_index", &self.challenge_applied_index)
            .field("resolution_applied_term", &self.resolution_applied_term)
            .field("resolution_applied_index", &self.resolution_applied_index)
            .field("fence_record_digest", &"[redacted]")
            .field("committed_challenge_digest", &"[redacted]")
            .field("reservation_intent_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("reserved_terminal_intent_key", &"[redacted]")
            .field("finalized_reservation_digest", &"[redacted]")
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("owner_store_binding_digest", &"[redacted]")
            .field("resolution_record_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramOwnerReservationFenceRecordV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationFenceRecordV1")
            .field("version", &self.version)
            .field("challenge", &self.challenge)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("terminal_record_count", &self.terminal_record_count)
            .field("terminal_record_limit", &self.terminal_record_limit)
            .field("fence_record_digest", &"[redacted]")
            .finish()
    }
}

/// Durable owner-local proof created before an owner signs reservation readiness.
#[doc(hidden)]
#[derive(PartialEq, Eq)]
pub struct PrivateOramOwnerDurableReservationFenceV1 {
    record: PrivateOramOwnerReservationFenceRecordV1,
}

impl Debug for PrivateOramOwnerDurableReservationFenceV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerDurableReservationFenceV1")
            .field("record", &"[durable]")
            .finish()
    }
}

impl PrivateOramOwnerDurableReservationFenceV1 {
    pub fn challenge(&self) -> &PrivateOramOwnerReservationPrepareChallengeV1 {
        &self.record.challenge
    }

    pub fn lifecycle_state(&self) -> &PrivateOramOwnerLifecycleStateV1 {
        &self.record.lifecycle_state
    }

    pub fn local_terminal_generation(&self) -> u64 {
        self.record.lifecycle_state.generation
    }

    pub fn fence_record_digest(&self) -> &str {
        &self.record.fence_record_digest
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerReservationResolutionV1 {
    pub kind: PrivateOramOwnerReservationResolutionKindV1,
    pub committed_challenge_digest: String,
    pub reservation_intent_digest: String,
    pub attempt_id: String,
    pub challenge_applied_term: u64,
    pub challenge_applied_index: u64,
    pub resolution_applied_term: u64,
    pub resolution_applied_index: u64,
    pub finalized_reservation_digest: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerDurableReservationResolutionV1 {
    record: PrivateOramOwnerReservationResolutionRecordV1,
    owner_store_incarnation_digest: String,
    owner_store_binding_digest: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerInstalledReservationResolutionV1 {
    durable_resolution: PrivateOramOwnerDurableReservationResolutionV1,
    installed_intent_marker_digest: String,
    installed_prestage_receipt_digest: String,
    installed_package_sha256: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerAbortReleasedReservationResolutionV1 {
    durable_resolution: PrivateOramOwnerDurableReservationResolutionV1,
    abort_release_authority_digest: String,
    abort_release_marker_digest: String,
}

impl Debug for PrivateOramOwnerDurableReservationResolutionV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerDurableReservationResolutionV1")
            .field("kind", &self.record.kind)
            .field(
                "resolution_applied_term",
                &self.record.resolution_applied_term,
            )
            .field(
                "resolution_applied_index",
                &self.record.resolution_applied_index,
            )
            .field("resolution_record_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramOwnerInstalledReservationResolutionV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerInstalledReservationResolutionV1")
            .field("durable_resolution", &self.durable_resolution)
            .field("installed_intent_marker_digest", &"[redacted]")
            .field("installed_prestage_receipt_digest", &"[redacted]")
            .field("installed_package_sha256", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramOwnerAbortReleasedReservationResolutionV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerAbortReleasedReservationResolutionV1")
            .field("durable_resolution", &self.durable_resolution)
            .field("abort_release_authority_digest", &"[redacted]")
            .field("abort_release_marker_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerDurableReservationResolutionV1 {
    pub const fn kind(&self) -> PrivateOramOwnerReservationResolutionKindV1 {
        self.record.kind
    }

    pub fn reserved_terminal_intent_key(&self) -> &str {
        &self.record.reserved_terminal_intent_key
    }

    pub fn resolution_record_digest(&self) -> &str {
        &self.record.resolution_record_digest
    }

    pub fn durable_fence_record_digest(&self) -> &str {
        &self.record.fence_record_digest
    }

    pub fn owner_store_incarnation_digest(&self) -> &str {
        &self.owner_store_incarnation_digest
    }

    pub fn owner_store_binding_digest(&self) -> &str {
        &self.owner_store_binding_digest
    }
}

impl PrivateOramOwnerInstalledReservationResolutionV1 {
    pub fn durable_resolution(&self) -> &PrivateOramOwnerDurableReservationResolutionV1 {
        &self.durable_resolution
    }

    pub fn installed_intent_marker_digest(&self) -> &str {
        &self.installed_intent_marker_digest
    }

    pub fn installed_prestage_receipt_digest(&self) -> &str {
        &self.installed_prestage_receipt_digest
    }

    pub fn installed_package_sha256(&self) -> &str {
        &self.installed_package_sha256
    }
}

impl PrivateOramOwnerAbortReleasedReservationResolutionV1 {
    pub fn durable_resolution(&self) -> &PrivateOramOwnerDurableReservationResolutionV1 {
        &self.durable_resolution
    }

    pub fn abort_release_authority_digest(&self) -> &str {
        &self.abort_release_authority_digest
    }

    pub fn abort_release_marker_digest(&self) -> &str {
        &self.abort_release_marker_digest
    }
}

impl Debug for PrivateOramOwnerReservationResolutionV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationResolutionV1")
            .field("kind", &self.kind)
            .field("challenge_applied_term", &self.challenge_applied_term)
            .field("challenge_applied_index", &self.challenge_applied_index)
            .field("resolution_applied_term", &self.resolution_applied_term)
            .field("resolution_applied_index", &self.resolution_applied_index)
            .field("committed_challenge_digest", &"[redacted]")
            .field("reservation_intent_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("finalized_reservation_digest", &"[redacted]")
            .finish()
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramOwnerCleanupRepairStateV2 {
    Complete,
    NeedsSuperblockReconciliation,
    NeedsPayloadRelocation,
}

/// Owner cleanup evidence constructed only after the exact immutable terminal is durable.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedPrivateOramOwnerCleanupReceiptV2 {
    signed_receipt: SignedPrivateOramOwnerCleanupReceiptV1,
    storage_terminal_marker_digest: String,
    repair_state: PrivateOramOwnerCleanupRepairStateV2,
}

impl Debug for CommittedPrivateOramOwnerCleanupReceiptV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedPrivateOramOwnerCleanupReceiptV2")
            .field("repair_state", &self.repair_state)
            .field("signed_receipt", &"[redacted]")
            .field("storage_terminal_marker_digest", &"[redacted]")
            .finish()
    }
}

impl CommittedPrivateOramOwnerCleanupReceiptV2 {
    pub fn signed_receipt(&self) -> &SignedPrivateOramOwnerCleanupReceiptV1 {
        &self.signed_receipt
    }

    pub fn receipt(&self) -> &PrivateOramOwnerCleanupReceiptV1 {
        &self.signed_receipt.receipt
    }

    pub fn storage_terminal_marker_digest(&self) -> &str {
        &self.storage_terminal_marker_digest
    }

    pub const fn repair_state(&self) -> PrivateOramOwnerCleanupRepairStateV2 {
        self.repair_state
    }
}

/// Multi-entry, insert-only store for pre-admission owner intents.
#[doc(hidden)]
#[derive(Clone)]
pub struct PrivateOramOwnerPrestageStoreV2 {
    primary_hnsw_store_root: PathBuf,
    root: PathBuf,
}

/// Holds the parent, lifecycle, and canonical owner namespaces stable while a V2 snapshot is
/// validated and archived.
#[doc(hidden)]
pub struct PrivateOramOwnerSnapshotGuardV2 {
    store: PrivateOramOwnerPrestageStoreV2,
    expectation: PrivateOramOwnerNewGenerationReadinessExpectationV2,
    parent_journal: Option<PrivateOramPinnedParentSnapshotV2>,
    owner_temp: PrivateOramOwnedSharedDirectoryLockV2,
    lifecycle_root: PrivateOramOwnedSharedDirectoryLockV2,
    canonical_root: Option<PrivateOramOwnedSharedDirectoryLockV2>,
}

impl Debug for PrivateOramOwnerSnapshotGuardV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerSnapshotGuardV2")
            .field("store", &"[redacted]")
            .field("expectation", &self.expectation)
            .field("parent_journal_present", &self.parent_journal.is_some())
            .field("canonical_root_present", &self.canonical_root.is_some())
            .finish()
    }
}

struct PrivateOramPinnedParentSnapshotV2 {
    root: File,
    root_path: PathBuf,
    _lock: PinnedPrivateLockFile,
}

struct PrivateOramOwnedSharedDirectoryLockV2 {
    directory: File,
    path: PathBuf,
}

impl PrivateOramOwnedSharedDirectoryLockV2 {
    fn acquire(path: &Path) -> Result<Self, PrivateOramOwnerJournalError> {
        let directory = open_private_directory(path)?;
        #[cfg(target_os = "linux")]
        {
            // SAFETY: the returned guard owns the validated directory fd for the full lock
            // lifetime and Drop releases this exact lock.
            let result = unsafe {
                nix::libc::flock(
                    directory.as_raw_fd(),
                    nix::libc::LOCK_SH | nix::libc::LOCK_NB,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                return if error.raw_os_error() == Some(nix::libc::EWOULDBLOCK) {
                    Err(PrivateOramOwnerJournalError::ConcurrentMutation)
                } else {
                    Err(PrivateOramOwnerJournalError::Unsupported)
                };
            }
        }
        #[cfg(not(target_os = "linux"))]
        return Err(PrivateOramOwnerJournalError::Unsupported);

        #[allow(unreachable_code)]
        let guard = Self {
            directory,
            path: path.to_path_buf(),
        };
        guard.validate_held()?;
        Ok(guard)
    }

    fn validate_held(&self) -> Result<(), PrivateOramOwnerJournalError> {
        validate_open_directory_at_path(&self.directory, &self.path)
    }
}

#[cfg(target_os = "linux")]
impl Drop for PrivateOramOwnedSharedDirectoryLockV2 {
    fn drop(&mut self) {
        // SAFETY: this guard owns the directory fd and no other guard instance releases it.
        let _ = unsafe { nix::libc::flock(self.directory.as_raw_fd(), nix::libc::LOCK_UN) };
    }
}

impl Debug for PrivateOramOwnerPrestageStoreV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPrestageStoreV2")
            .field("primary_hnsw_store_root", &"[redacted]")
            .field("root", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerSnapshotGuardV2 {
    /// Revalidates every pinned namespace and the exact consensus-qualified archive set while all
    /// snapshot locks remain held. Call this again after archive creation before publishing it.
    #[doc(hidden)]
    pub fn validate_held_v2(&self) -> Result<(), PrivateOramOwnerJournalError> {
        self.owner_temp.validate_held()?;
        self.lifecycle_root.validate_held()?;
        if let Some(canonical_root) = &self.canonical_root {
            canonical_root.validate_held()?;
        }
        if let Some(parent) = &self.parent_journal {
            validate_open_directory_at_path(&parent.root, &parent.root_path)?;
            parent._lock.validate_at_path()?;
        }

        self.store
            .require_ready_for_new_generation_v2(&self.expectation)?;
        validate_private_oram_owner_snapshot_exact_v2(
            &self.store,
            &self.lifecycle_root.directory,
            self.canonical_root.as_ref().map(|guard| &guard.directory),
            &self.expectation,
        )?;
        validate_private_oram_parent_snapshot_exact_v2(
            self.parent_journal.as_ref(),
            &self.expectation,
        )?;

        self.owner_temp.validate_held()?;
        self.lifecycle_root.validate_held()?;
        if let Some(canonical_root) = &self.canonical_root {
            canonical_root.validate_held()?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn expectation(&self) -> &PrivateOramOwnerNewGenerationReadinessExpectationV2 {
        &self.expectation
    }
}

fn validate_private_oram_owner_snapshot_exact_v2(
    store: &PrivateOramOwnerPrestageStoreV2,
    lifecycle_root: &File,
    canonical_root: Option<&File>,
    expectation: &PrivateOramOwnerNewGenerationReadinessExpectationV2,
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_open_directory_at_path(lifecycle_root, &store.root)?;
    validate_private_oram_owner_prestage_root_entries(lifecycle_root)?;

    for name in [
        PRESTAGE_INTENTS_DIR,
        PRESTAGE_TEMP_DIR,
        PRESTAGE_QUARANTINE_DIR,
        PRESTAGE_RESERVATION_FENCE_DIR,
    ] {
        let (path, directory) = store.open_prestage_child_locked(lifecycle_root, name)?;
        if !directory_entry_names_open_bounded(
            &directory,
            PRESTAGE_MAX_TERMINAL_RECORDS,
            PrivateOramOwnerJournalError::TerminalCapacityExceeded,
        )?
        .is_empty()
        {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }
        validate_open_directory_at_path(&directory, &path)?;
    }

    let expected_generations = expectation
        .acknowledged_archives
        .iter()
        .map(|archive| archive.generation)
        .collect::<BTreeSet<_>>();
    match canonical_root {
        Some(canonical_root) => {
            let canonical_path = store
                .owner_temp_path()?
                .join(PRIVATE_ORAM_OWNER_JOURNAL_DIR);
            validate_open_directory_at_path(canonical_root, &canonical_path)?;
            let mut actual_generations = BTreeSet::new();
            for name in directory_entry_names_open_bounded(
                canonical_root,
                PRESTAGE_MAX_TERMINAL_RECORDS
                    .checked_add(1)
                    .ok_or(PrivateOramOwnerJournalError::TerminalCapacityExceeded)?,
                PrivateOramOwnerJournalError::TerminalCapacityExceeded,
            )? {
                let Some(generation) = completed_generation_from_name(&name)? else {
                    return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
                };
                if !actual_generations.insert(generation) {
                    return Err(PrivateOramOwnerJournalError::Corrupt);
                }
            }
            if actual_generations != expected_generations {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
        }
        None if expected_generations.is_empty() => {}
        None => return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired),
    }
    Ok(())
}

fn validate_private_oram_parent_snapshot_exact_v2(
    parent: Option<&PrivateOramPinnedParentSnapshotV2>,
    expectation: &PrivateOramOwnerNewGenerationReadinessExpectationV2,
) -> Result<(), PrivateOramOwnerJournalError> {
    let expected_completed = expectation
        .acknowledged_archives
        .iter()
        .map(|archive| completed_generation_name(archive.generation))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let Some(parent) = parent else {
        return if expected_completed.is_empty() {
            Ok(())
        } else {
            Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired)
        };
    };

    validate_open_directory_at_path(&parent.root, &parent.root_path)?;
    parent._lock.validate_at_path()?;
    let mut expected_root = expected_completed
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<BTreeSet<_>>();
    expected_root.insert(OsStr::new(PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2).to_owned());
    expected_root.insert(OsStr::new("temp").to_owned());
    let actual_root = directory_entry_names_open_bounded(
        &parent.root,
        PRESTAGE_MAX_TERMINAL_RECORDS
            .checked_add(2)
            .ok_or(PrivateOramOwnerJournalError::TerminalCapacityExceeded)?,
        PrivateOramOwnerJournalError::TerminalCapacityExceeded,
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    if actual_root != expected_root {
        return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
    }

    let parent_temp_path = open_directory_entry_path(&parent.root, OsStr::new("temp"))?;
    let parent_temp = open_private_directory(&parent_temp_path)?;
    if !directory_entry_names_open(&parent_temp)?.is_empty() {
        return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
    }

    let expected_completed_entries = BTreeSet::from([
        OsStr::new("temp").to_owned(),
        OsStr::new("state_records").to_owned(),
        OsStr::new("descriptor.json").to_owned(),
        OsStr::new("immutable_manifest.json").to_owned(),
        OsStr::new("state.json").to_owned(),
        OsStr::new("format.json").to_owned(),
        OsStr::new("cleanup_complete_v2.json").to_owned(),
        OsStr::new(PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2).to_owned(),
        OsStr::new(PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1).to_owned(),
    ]);
    for completed_name in expected_completed {
        let completed_path =
            open_directory_entry_path(&parent.root, OsStr::new(completed_name.as_str()))?;
        let completed = open_private_directory(&completed_path)?;
        if directory_entry_names_open(&completed)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            != expected_completed_entries
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }

        let temp_path = open_directory_entry_path(&completed, OsStr::new("temp"))?;
        let temp = open_private_directory(&temp_path)?;
        if !directory_entry_names_open(&temp)?.is_empty() {
            return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
        }

        let records_path = open_directory_entry_path(&completed, OsStr::new("state_records"))?;
        let records = open_private_directory(&records_path)?;
        let expected_records = (1..=PRIVATE_ORAM_PARENT_STATE_RECORD_COUNT_V2)
            .map(|sequence| std::ffi::OsString::from(format!("{sequence:020}.json")))
            .collect::<BTreeSet<_>>();
        if directory_entry_names_open(&records)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            != expected_records
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        for record_name in expected_records {
            let path = open_directory_entry_path(&records, &record_name)?;
            read_private_file_pinned(&path, PRIVATE_ORAM_PARENT_STATE_MAX_BYTES_V2)?;
        }
        for (name, max_bytes) in [
            (
                "descriptor.json",
                PRIVATE_ORAM_PARENT_DESCRIPTOR_MAX_BYTES_V2,
            ),
            (
                "immutable_manifest.json",
                PRIVATE_ORAM_PARENT_IMMUTABLE_MANIFEST_MAX_BYTES_V2,
            ),
            ("state.json", PRIVATE_ORAM_PARENT_STATE_MAX_BYTES_V2),
            ("format.json", PRIVATE_ORAM_PARENT_FORMAT_MAX_BYTES_V2),
            (
                "cleanup_complete_v2.json",
                PRIVATE_ORAM_PARENT_CLEANUP_MAX_BYTES_V2,
            ),
            (
                PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2,
                PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_MAX_BYTES_V2,
            ),
            (
                PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1,
                PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_MAX_BYTES_V1,
            ),
        ] {
            let path = open_directory_entry_path(&completed, OsStr::new(name))?;
            read_private_file_pinned(&path, max_bytes)?;
        }
        validate_open_directory_at_path(&completed, &completed_path)?;
    }
    validate_open_directory_at_path(&parent.root, &parent.root_path)
}

fn validate_owner_prepare_parent_fields(
    parent_descriptor_digest: &str,
    parent_lease_acquired_record_digest: &str,
    requirements: &[PrivateOramOwnerPrepareRequirementV2],
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_digest(parent_descriptor_digest, "parent_descriptor_digest")?;
    validate_digest(
        parent_lease_acquired_record_digest,
        "parent_lease_acquired_record_digest",
    )?;
    if requirements.is_empty()
        || requirements.len() > MAX_PAIRED_OWNER_INDEXES
        || requirements[0].kind != PrivateOramIndexKindV2::Hnsw
        || requirements
            .windows(2)
            .any(|pair| pair[0].kind == pair[1].kind)
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput(
            "owner_requirements",
        ));
    }
    Ok(())
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPreparedEvidenceV2 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    indexes: Vec<PrivateOramOwnerPreparedIndexEvidenceV2>,
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPreparedIndexEvidenceV2 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
}

impl Debug for PrivateOramOwnerPreparedEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPreparedEvidenceV2")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl Debug for PrivateOramOwnerPreparedIndexEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPreparedIndexEvidenceV2")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerPreparedEvidenceV2 {
    pub const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub fn indexes(&self) -> &[PrivateOramOwnerPreparedIndexEvidenceV2] {
        &self.indexes
    }
}

impl PrivateOramOwnerPreparedIndexEvidenceV2 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub fn index_name(&self) -> &str {
        &self.index_name
    }

    pub fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateOramOwnerJournalFinalizeContextV1<'a> {
    expected_journal_descriptor_digest: &'a str,
    parent_descriptor_digest: &'a str,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: &'a str,
    reconciliation_authority_digest: &'a str,
    canonical_index_states: &'a [PrivateOramOwnerJournalTerminalIndexStateV1],
}

impl Debug for PrivateOramOwnerJournalFinalizeContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalFinalizeContextV1")
            .field("expected_journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field(
                "canonical_index_state_count",
                &self.canonical_index_states.len(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateOramOwnerJournalAbortOldContextV1<'a> {
    expected_journal_descriptor_digest: &'a str,
    parent_descriptor_digest: &'a str,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: &'a str,
    reconciliation_authority_digest: &'a str,
    canonical_index_states: &'a [PrivateOramOwnerJournalTerminalIndexStateV1],
}

impl Debug for PrivateOramOwnerJournalAbortOldContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalAbortOldContextV1")
            .field("expected_journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field(
                "canonical_index_state_count",
                &self.canonical_index_states.len(),
            )
            .finish()
    }
}

impl Debug for PrivateOramOwnerJournalPrepareContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalPrepareContextV1")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("requirement_count", &self.requirements.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalIndexDescriptorV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub writeback_digest: String,
    pub read_path_count: u32,
    pub read_transcript_digest: String,
    pub ordered_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
    pub final_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
}

impl Debug for PrivateOramOwnerJournalIndexDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalIndexDescriptorV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("read_path_count", &self.read_path_count)
            .field("read_transcript_digest", &"[redacted]")
            .field("ordered_bucket_count", &self.ordered_bucket_refs.len())
            .field("final_bucket_count", &self.final_bucket_refs.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalDescriptorV1 {
    pub version: u16,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub owner_peer_id: u64,
    pub collection_id: String,
    pub mutation_id: String,
    pub signed_mutation_digest: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub indexes: Vec<PrivateOramOwnerJournalIndexDescriptorV1>,
    pub final_bucket_frame_version: u16,
    pub final_bucket_frame_length: u64,
    pub final_bucket_frame_sha256: String,
    pub descriptor_digest: String,
}

impl Debug for PrivateOramOwnerJournalDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalDescriptorV1")
            .field("version", &self.version)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("indexes", &self.indexes)
            .field(
                "final_bucket_frame_version",
                &self.final_bucket_frame_version,
            )
            .field("final_bucket_frame_length", &self.final_bucket_frame_length)
            .field("final_bucket_frame_sha256", &"[redacted]")
            .field("descriptor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerJournalPhaseV1 {
    Prepared,
    Finalized,
    AbortedOld,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalStateV1 {
    pub version: u16,
    pub sequence: u64,
    pub descriptor_digest: String,
    pub previous_record_digest: Option<String>,
    pub phase: PrivateOramOwnerJournalPhaseV1,
    pub state_digest: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalTerminalIndexStateV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub canonical_state_digest: String,
}

impl Debug for PrivateOramOwnerJournalTerminalIndexStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalTerminalIndexStateV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("canonical_state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalTerminalRecordV1 {
    pub version: u16,
    pub sequence: u64,
    pub descriptor_digest: String,
    pub previous_record_digest: String,
    pub phase: PrivateOramOwnerJournalPhaseV1,
    pub parent_descriptor_digest: String,
    pub authenticated_owner_peer_id: u64,
    pub consensus_authority_record_digest: String,
    pub reconciliation_authority_digest: String,
    pub canonical_index_states: Vec<PrivateOramOwnerJournalTerminalIndexStateV1>,
    pub record_digest: String,
}

/// One acknowledged generation that retained consensus history requires locally.
///
/// This is expectation data, not archive authority. The collection layer compares it with the
/// exact durable child archive while the owner lifecycle and canonical roots are both locked.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerAcknowledgedArchiveExpectationV2 {
    generation: u64,
    owner_peer_id: u64,
    parent_terminal_record_digest: String,
    pending_tombstone_digest: String,
    clear_receipt_digest: String,
}

impl Debug for PrivateOramOwnerAcknowledgedArchiveExpectationV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerAcknowledgedArchiveExpectationV2")
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("archive_binding", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerAcknowledgedArchiveExpectationV2 {
    #[doc(hidden)]
    pub fn try_new(
        generation: u64,
        owner_peer_id: u64,
        parent_terminal_record_digest: String,
        pending_tombstone_digest: String,
        clear_receipt_digest: String,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        if generation == 0 || owner_peer_id == 0 {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        for (field, digest) in [
            (
                "parent_terminal_record_digest",
                parent_terminal_record_digest.as_str(),
            ),
            (
                "pending_tombstone_digest",
                pending_tombstone_digest.as_str(),
            ),
            ("clear_receipt_digest", clear_receipt_digest.as_str()),
        ] {
            validate_digest(digest, field)?;
        }
        Ok(Self {
            generation,
            owner_peer_id,
            parent_terminal_record_digest,
            pending_tombstone_digest,
            clear_receipt_digest,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[doc(hidden)]
    pub fn pending_tombstone_digest(&self) -> &str {
        &self.pending_tombstone_digest
    }
}

/// Consensus-qualified, side-effect-free owner readiness expectation for a new generation.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerNewGenerationReadinessExpectationV2 {
    collection_id: String,
    owner_store_incarnation_digest: String,
    consensus_aggregate_digest: String,
    acknowledged_archives: Vec<PrivateOramOwnerAcknowledgedArchiveExpectationV2>,
}

impl Debug for PrivateOramOwnerNewGenerationReadinessExpectationV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerNewGenerationReadinessExpectationV2")
            .field(
                "acknowledged_archive_count",
                &self.acknowledged_archives.len(),
            )
            .field("collection_id", &"[redacted]")
            .field("owner_store_incarnation", &"[redacted]")
            .field("consensus_aggregate", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerNewGenerationReadinessExpectationV2 {
    #[doc(hidden)]
    pub fn try_new(
        collection_id: String,
        owner_store_incarnation_digest: String,
        consensus_aggregate_digest: String,
        acknowledged_archives: Vec<PrivateOramOwnerAcknowledgedArchiveExpectationV2>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_resource_id(&collection_id, "collection_id")?;
        validate_digest(
            &owner_store_incarnation_digest,
            "owner_store_incarnation_digest",
        )?;
        validate_digest(&consensus_aggregate_digest, "consensus_aggregate_digest")?;
        if acknowledged_archives.len() > PRESTAGE_MAX_TERMINAL_RECORDS {
            return Err(PrivateOramOwnerJournalError::TerminalCapacityExceeded);
        }
        let mut previous_generation = None;
        for archive in &acknowledged_archives {
            if previous_generation.is_some_and(|previous| previous >= archive.generation) {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            previous_generation = Some(archive.generation);
        }
        Ok(Self {
            collection_id,
            owner_store_incarnation_digest,
            consensus_aggregate_digest,
            acknowledged_archives,
        })
    }

    pub fn consensus_aggregate_digest(&self) -> &str {
        &self.consensus_aggregate_digest
    }

    pub fn acknowledged_archives(&self) -> &[PrivateOramOwnerAcknowledgedArchiveExpectationV2] {
        &self.acknowledged_archives
    }

    /// Canonically commits a recovery checkpoint to this exact consensus-qualified owner chain.
    #[doc(hidden)]
    pub fn snapshot_authority_digest_v2(&self) -> Result<String, PrivateOramOwnerJournalError> {
        let mut bytes = Vec::new();
        push_domain(&mut bytes, OWNER_SNAPSHOT_AUTHORITY_DIGEST_DOMAIN_V2)?;
        push_resource_id(&mut bytes, &self.collection_id, "collection_id")?;
        push_digest(
            &mut bytes,
            &self.owner_store_incarnation_digest,
            "owner_store_incarnation_digest",
        )?;
        push_digest(
            &mut bytes,
            &self.consensus_aggregate_digest,
            "consensus_aggregate_digest",
        )?;
        push_len(
            &mut bytes,
            self.acknowledged_archives.len(),
            "acknowledged_archives",
        )?;
        for archive in &self.acknowledged_archives {
            bytes.extend_from_slice(&archive.generation.to_be_bytes());
            bytes.extend_from_slice(&archive.owner_peer_id.to_be_bytes());
            push_digest(
                &mut bytes,
                &archive.parent_terminal_record_digest,
                "parent_terminal_record_digest",
            )?;
            push_digest(
                &mut bytes,
                &archive.pending_tombstone_digest,
                "pending_tombstone_digest",
            )?;
            push_digest(
                &mut bytes,
                &archive.clear_receipt_digest,
                "clear_receipt_digest",
            )?;
        }
        Ok(digest_string(&bytes))
    }
}

/// One index entry in an inert parent-issued child-archive grant.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCommittedArchiveGrantIndexV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
    terminal_state_digest: String,
}

impl Debug for PrivateOramOwnerCommittedArchiveGrantIndexV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerCommittedArchiveGrantIndexV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("terminal_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCommittedArchiveGrantIndexV1 {
    #[doc(hidden)]
    pub fn try_new(
        kind: PrivateOramIndexKindV2,
        index_name: String,
        prepared_journal_digest: String,
        terminal_state_digest: String,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_resource_id(&index_name, "index_name")?;
        validate_digest(&prepared_journal_digest, "prepared_journal_digest")?;
        validate_digest(&terminal_state_digest, "terminal_state_digest")?;
        Ok(Self {
            kind,
            index_name,
            prepared_journal_digest,
            terminal_state_digest,
        })
    }
}

/// Canonical inert record published by the exact parent terminal archive transition.
///
/// Constructing this value is not authority. The child transition accepts only a generation and
/// independently reopens this record from the fixed parent journal namespace.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCommittedArchiveGrantV1 {
    version: u16,
    terminal_archive_format: String,
    terminal_archive_file_len: u64,
    terminal_archive_file_sha256: String,
    generation: u64,
    collection_id: String,
    mutation_id: String,
    vector_name: String,
    owner_peer_id: u64,
    owner_store_incarnation_digest: String,
    writer_fence: u64,
    intent_key: String,
    prestage_receipt_digest: String,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    receipt: PrivateOramOwnerPrestageReceiptV2,
    parent_terminal_record_digest: String,
    parent_archive_record_digest: String,
    pending_tombstone_digest: String,
    clear_receipt_digest: String,
    owner_terminal_record_digest: String,
    decision_authority_record_digest: String,
    reconciliation_authority_digest: String,
    owner_terminal_evidence_digest: String,
    indexes: Vec<PrivateOramOwnerCommittedArchiveGrantIndexV1>,
    grant_digest: String,
}

impl Debug for PrivateOramOwnerCommittedArchiveGrantV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerCommittedArchiveGrantV1")
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .field("grant", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCommittedArchiveGrantV1 {
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        terminal_archive_file_len: u64,
        terminal_archive_file_sha256: String,
        vector_name: String,
        receipt: PrivateOramOwnerPrestageReceiptV2,
        parent_terminal_record_digest: String,
        parent_archive_record_digest: String,
        pending_tombstone_digest: String,
        clear_receipt_digest: String,
        owner_terminal_record_digest: String,
        decision_authority_record_digest: String,
        reconciliation_authority_digest: String,
        owner_terminal_evidence_digest: String,
        indexes: Vec<PrivateOramOwnerCommittedArchiveGrantIndexV1>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_private_oram_owner_prestage_receipt_v2(&receipt)?;
        if terminal_archive_file_len == 0
            || terminal_archive_file_len > PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_MAX_BYTES_V2
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "terminal_archive_file_len",
            ));
        }
        validate_digest(
            &terminal_archive_file_sha256,
            "terminal_archive_file_sha256",
        )?;
        validate_resource_id(&vector_name, "vector_name")?;
        for (field, digest) in [
            (
                "parent_terminal_record_digest",
                &parent_terminal_record_digest,
            ),
            (
                "parent_archive_record_digest",
                &parent_archive_record_digest,
            ),
            ("pending_tombstone_digest", &pending_tombstone_digest),
            ("clear_receipt_digest", &clear_receipt_digest),
            (
                "owner_terminal_record_digest",
                &owner_terminal_record_digest,
            ),
            (
                "decision_authority_record_digest",
                &decision_authority_record_digest,
            ),
            (
                "reconciliation_authority_digest",
                &reconciliation_authority_digest,
            ),
            (
                "owner_terminal_evidence_digest",
                &owner_terminal_evidence_digest,
            ),
        ] {
            validate_digest(digest, field)?;
        }
        validate_committed_archive_grant_indexes_v1(&indexes)?;
        if indexes[0].index_name != vector_name {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "archive_indexes",
            ));
        }
        let mut grant = Self {
            version: OWNER_COMMITTED_ARCHIVE_GRANT_VERSION,
            terminal_archive_format: OWNER_COMMITTED_ARCHIVE_TERMINAL_FORMAT_V2.to_string(),
            terminal_archive_file_len,
            terminal_archive_file_sha256,
            generation: receipt.lease_generation(),
            collection_id: receipt.collection_id().to_string(),
            mutation_id: receipt.mutation_id().to_string(),
            vector_name,
            owner_peer_id: receipt.owner_peer_id(),
            owner_store_incarnation_digest: receipt.owner_store_incarnation_digest().to_string(),
            writer_fence: receipt.writer_fence(),
            intent_key: receipt.intent_key().to_string(),
            prestage_receipt_digest: receipt.receipt_digest().to_string(),
            parent_descriptor_digest: receipt.parent_descriptor_digest().to_string(),
            parent_lease_acquired_record_digest: receipt
                .parent_lease_acquired_record_digest()
                .to_string(),
            receipt,
            parent_terminal_record_digest,
            parent_archive_record_digest,
            pending_tombstone_digest,
            clear_receipt_digest,
            owner_terminal_record_digest,
            decision_authority_record_digest,
            reconciliation_authority_digest,
            owner_terminal_evidence_digest,
            indexes,
            grant_digest: String::new(),
        };
        grant.grant_digest = committed_archive_grant_digest_v1(&grant)?;
        validate_committed_archive_grant_v1(&grant)?;
        Ok(grant)
    }
}

#[doc(hidden)]
pub fn encode_private_oram_owner_committed_archive_grant_v1(
    grant: &PrivateOramOwnerCommittedArchiveGrantV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_committed_archive_grant_v1(grant)?;
    let bytes = serde_json::to_vec(grant).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_MAX_BYTES_V1
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput("archive_grant"));
    }
    Ok(bytes)
}

#[doc(hidden)]
pub fn decode_private_oram_owner_committed_archive_grant_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerCommittedArchiveGrantV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_MAX_BYTES_V1
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput("archive_grant"));
    }
    let grant = serde_json::from_slice::<PrivateOramOwnerCommittedArchiveGrantV1>(bytes)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_committed_archive_grant_v1(&grant)?;
    if encode_private_oram_owner_committed_archive_grant_v1(&grant)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(grant)
}

/// Durable proof that the exact terminal owner generation and its adopted intent are retired.
#[doc(hidden)]
pub struct PrivateOramOwnerArchivedGenerationV1 {
    collection_id: String,
    generation: u64,
    owner_peer_id: u64,
    parent_archive_record_digest: String,
    pending_tombstone_digest: String,
    clear_receipt_digest: String,
    owner_terminal_evidence_digest: String,
    owner_archive_record_digest: String,
    retired_prestage_receipt_digest: String,
}

impl Debug for PrivateOramOwnerArchivedGenerationV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerArchivedGenerationV1")
            .field("generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("archive", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerArchivedGenerationV1 {
    pub fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub fn parent_archive_record_digest(&self) -> &str {
        &self.parent_archive_record_digest
    }

    pub fn pending_tombstone_digest(&self) -> &str {
        &self.pending_tombstone_digest
    }

    pub fn clear_receipt_digest(&self) -> &str {
        &self.clear_receipt_digest
    }

    pub fn owner_terminal_evidence_digest(&self) -> &str {
        &self.owner_terminal_evidence_digest
    }

    pub fn owner_archive_record_digest(&self) -> &str {
        &self.owner_archive_record_digest
    }

    pub fn retired_prestage_receipt_digest(&self) -> &str {
        &self.retired_prestage_receipt_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerTerminalArchiveIndexV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    writeback_digest: String,
    prepared_journal_digest: String,
    terminal_state_digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerTerminalArchiveV1 {
    version: u16,
    generation: u64,
    owner_store_incarnation_digest: String,
    collection_id: String,
    owner_peer_id: u64,
    mutation_id: String,
    signed_mutation_digest: String,
    writer_fence: u64,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    parent_terminal_record_digest: String,
    parent_archive_record_digest: String,
    pending_tombstone_digest: String,
    clear_receipt_digest: String,
    owner_journal_descriptor_digest: String,
    owner_prepared_state_digest: String,
    owner_terminal_record_digest: String,
    owner_terminal_phase: PrivateOramOwnerJournalPhaseV1,
    decision_authority_record_digest: String,
    reconciliation_authority_digest: String,
    owner_terminal_evidence_digest: String,
    intent_key: String,
    prestage_receipt_digest: String,
    prestage_adopted_marker_digest: String,
    indexes: Vec<PrivateOramOwnerTerminalArchiveIndexV1>,
    archive_authority_digest: String,
    archive_record_digest: String,
}

impl Debug for PrivateOramOwnerJournalTerminalRecordV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalTerminalRecordV1")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("descriptor_digest", &"[redacted]")
            .field("previous_record_digest", &"[redacted]")
            .field("phase", &self.phase)
            .field("parent_descriptor_digest", &"[redacted]")
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field(
                "canonical_index_state_count",
                &self.canonical_index_states.len(),
            )
            .field("record_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramOwnerJournalStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalStateV1")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("descriptor_digest", &"[redacted]")
            .field("previous_record_digest", &"[redacted]")
            .field("phase", &self.phase)
            .field("state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PrivateOramOwnerFinalBucketBatchV1 {
    Hnsw(Vec<PrivateHnswOramBucket>),
    Result(Vec<PrivateResultOramBucket>),
}

impl PrivateOramOwnerFinalBucketBatchV1 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        match self {
            Self::Hnsw(_) => PrivateOramIndexKindV2::Hnsw,
            Self::Result(_) => PrivateOramIndexKindV2::Result,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Hnsw(buckets) => buckets.len(),
            Self::Result(buckets) => buckets.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Debug for PrivateOramOwnerFinalBucketBatchV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerFinalBucketBatchV1")
            .field("kind", &self.kind())
            .field("bucket_count", &self.len())
            .field("buckets", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerFinalBucketIndexV1 {
    pub index_name: String,
    pub buckets: PrivateOramOwnerFinalBucketBatchV1,
}

impl Debug for PrivateOramOwnerFinalBucketIndexV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerFinalBucketIndexV1")
            .field("index_name", &"[redacted]")
            .field("buckets", &self.buckets)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalSnapshotV1 {
    pub descriptor: PrivateOramOwnerJournalDescriptorV1,
    pub state: PrivateOramOwnerJournalStateV1,
    pub terminal: Option<PrivateOramOwnerJournalTerminalRecordV1>,
    pub final_buckets: Vec<PrivateOramOwnerFinalBucketIndexV1>,
}

impl Debug for PrivateOramOwnerJournalSnapshotV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalSnapshotV1")
            .field("descriptor", &self.descriptor)
            .field("state", &self.state)
            .field("terminal", &self.terminal)
            .field("final_bucket_index_count", &self.final_buckets.len())
            .field("final_buckets", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerPreparedIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
}

impl Debug for PrivateOramOwnerPreparedIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPreparedIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerPreparedIndexEvidenceV1 {
    pub(crate) const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }
}

/// Untrusted parent projection used to match one owner-journal index during restart recovery.
///
/// Construction validates shape only. This type does not carry parent consensus authority.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryIndexProjectionInputV1<'a> {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: &'a str,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub writeback_digest: &'a str,
    pub prepared_journal_digest: &'a str,
}

impl Debug for PrivateOramOwnerRecoveryIndexProjectionInputV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryIndexProjectionInputV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryIndexProjectionV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    writeback_digest: String,
    prepared_journal_digest: String,
}

impl Debug for PrivateOramOwnerRecoveryIndexProjectionV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryIndexProjectionV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryIndexProjectionV1 {
    pub fn try_from_input(
        input: PrivateOramOwnerRecoveryIndexProjectionInputV1<'_>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_resource_id(input.index_name, "index_name")?;
        validate_digest(input.old_root_hash, "old_root_hash")?;
        validate_digest(input.new_root_hash, "new_root_hash")?;
        validate_digest(input.writeback_digest, "writeback_digest")?;
        validate_digest(input.prepared_journal_digest, "prepared_journal_digest")?;
        if input.new_epoch <= input.old_epoch {
            return Err(PrivateOramOwnerJournalError::InvalidInput("index_epoch"));
        }
        Ok(Self {
            kind: input.kind,
            index_name: input.index_name.to_string(),
            old_epoch: input.old_epoch,
            new_epoch: input.new_epoch,
            old_root_hash: input.old_root_hash.to_string(),
            new_root_hash: input.new_root_hash.to_string(),
            writeback_digest: input.writeback_digest.to_string(),
            prepared_journal_digest: input.prepared_journal_digest.to_string(),
        })
    }
}

/// Untrusted, immutable projection of typed parent recovery evidence.
///
/// The storage coordinator must build this from its validated parent authority. Reopening the
/// child journal below recomputes every Prepared digest; possession of this projection alone does
/// not authorize canonical writes or a terminal transition.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryProjectionV1 {
    expected_owner_peer_id: u64,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    collection_id: String,
    mutation_id: String,
    signed_mutation_digest: String,
    writer_lease_digest: String,
    writer_fence: u64,
    indexes: Vec<PrivateOramOwnerRecoveryIndexProjectionV1>,
}

impl Debug for PrivateOramOwnerRecoveryProjectionV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryProjectionV1")
            .field("expected_owner_peer_id", &self.expected_owner_peer_id)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramOwnerRecoveryProjectionV1 {
    pub fn try_new(
        expected_owner_peer_id: u64,
        parent_descriptor_digest: &str,
        parent_lease_acquired_record_digest: &str,
        mutation_bundle: &PrivateOramAppendMutationBundleV1,
        indexes: Vec<PrivateOramOwnerRecoveryIndexProjectionV1>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_digest(parent_descriptor_digest, "parent_descriptor_digest")?;
        validate_digest(
            parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        )?;
        if indexes.len() != MAX_PAIRED_OWNER_INDEXES
            || indexes[0].kind != PrivateOramIndexKindV2::Hnsw
            || indexes[1].kind != PrivateOramIndexKindV2::Result
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput("indexes"));
        }

        let mutation = &mutation_bundle.mutation;
        validate_resource_id(&mutation.collection_id, "collection_id")?;
        validate_digest(&mutation.mutation_id, "mutation_id")?;
        validate_digest(&mutation.writer_lease_digest, "writer_lease_digest")?;
        let signed_mutation_digest = private_oram_append_mutation_v1_digest(mutation)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("mutation_bundle"))?;
        validate_digest(&signed_mutation_digest, "signed_mutation_digest")?;
        if mutation.old_state.state.indexes.len() != indexes.len()
            || mutation.new_state.state.indexes.len() != indexes.len()
            || mutation.writebacks.len() != indexes.len()
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "mutation_indexes",
            ));
        }
        for (((projection, old), new), writeback) in indexes
            .iter()
            .zip(&mutation.old_state.state.indexes)
            .zip(&mutation.new_state.state.indexes)
            .zip(&mutation.writebacks)
        {
            if projection.kind != old.kind
                || projection.kind != new.kind
                || projection.kind != writeback.kind
                || projection.index_name != old.index_name
                || projection.index_name != new.index_name
                || projection.index_name != writeback.index_name
                || projection.old_epoch != old.index_epoch
                || projection.new_epoch != new.index_epoch
                || projection.old_root_hash != old.root_hash
                || projection.new_root_hash != new.root_hash
                || projection.writeback_digest != new.last_writeback_digest
            {
                return Err(PrivateOramOwnerJournalError::InvalidInput(
                    "mutation_indexes",
                ));
            }
        }

        Ok(Self {
            expected_owner_peer_id,
            parent_descriptor_digest: parent_descriptor_digest.to_string(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.to_string(),
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest,
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            indexes,
        })
    }
}

/// Opaque evidence that a live Prepared child matched an untrusted parent projection while the
/// child journal remained under a shared lock.
///
/// The value is exposed only by reference inside `with_revalidated_recovery_prepared_v1`, so safe
/// callers cannot retain it after the lock is released.
pub(crate) struct PrivateOramOwnerRecoveryPreparedBindingV1<'lock> {
    prepared: PrivateOramDurableOwnerPreparedTokenV1,
    store_binding: PrivateOramOwnerPreparedStoreBindingV1,
    lock_lifetime: PhantomData<&'lock mut ()>,
}

impl Debug for PrivateOramOwnerRecoveryPreparedBindingV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryPreparedBindingV1")
            .field("prepared", &"[redacted]")
            .field("store_binding", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryPreparedBindingV1<'_> {
    /// Returns structural data only. The snapshot is untrusted outside this lock-scoped rebind and
    /// cannot authorize a store write or terminal transition.
    pub(crate) fn untrusted_snapshot_view(&self) -> &PrivateOramOwnerJournalSnapshotV1 {
        self.store_binding.snapshot()
    }
}

/// Opaque recovery binding held under the child journal's exclusive root lock.
///
/// Unlike the read-only Prepared binding, this value may also reopen an exact terminal record so
/// a caller can replay publication after an ambiguous response. The terminal remains untrusted
/// until a phase-specific transition is rebuilt and compared under the same lock.
pub(crate) struct PrivateOramOwnerRecoveryExclusiveBindingV1<'lock> {
    state: PrivateOramOwnerRecoveryExclusiveStateV1,
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    lock_lifetime: RecoveryTransactionBrand<'lock>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl Debug for PrivateOramOwnerRecoveryExclusiveBindingV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryExclusiveBindingV1")
            .field("state", &self.state)
            .field("snapshot", &"[redacted]")
            .finish()
    }
}

impl<'lock> PrivateOramOwnerRecoveryExclusiveBindingV1<'lock> {
    /// Returns structural data only. A terminal record in this view is not authority until exact
    /// phase-specific replay succeeds while this binding still holds the exclusive root lock.
    pub(crate) fn untrusted_snapshot_view(&self) -> &PrivateOramOwnerJournalSnapshotV1 {
        &self.snapshot
    }

    pub(crate) const fn state(&self) -> PrivateOramOwnerRecoveryExclusiveStateV1 {
        self.state
    }

    fn finalize_action(
        &self,
        context: PrivateOramOwnerJournalFinalizeContextV1<'_>,
    ) -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, PrivateOramOwnerJournalError>
    {
        self.terminal_action(TerminalTransition {
            phase: PrivateOramOwnerJournalPhaseV1::Finalized,
            expected_journal_descriptor_digest: context.expected_journal_descriptor_digest,
            parent_descriptor_digest: context.parent_descriptor_digest,
            authenticated_owner_peer_id: context.authenticated_owner_peer_id,
            consensus_authority_record_digest: context.consensus_authority_record_digest,
            reconciliation_authority_digest: context.reconciliation_authority_digest,
            canonical_index_states: context.canonical_index_states,
        })
    }

    fn abort_old_action(
        &self,
        context: PrivateOramOwnerJournalAbortOldContextV1<'_>,
    ) -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, PrivateOramOwnerJournalError>
    {
        self.terminal_action(TerminalTransition {
            phase: PrivateOramOwnerJournalPhaseV1::AbortedOld,
            expected_journal_descriptor_digest: context.expected_journal_descriptor_digest,
            parent_descriptor_digest: context.parent_descriptor_digest,
            authenticated_owner_peer_id: context.authenticated_owner_peer_id,
            consensus_authority_record_digest: context.consensus_authority_record_digest,
            reconciliation_authority_digest: context.reconciliation_authority_digest,
            canonical_index_states: context.canonical_index_states,
        })
    }

    pub(crate) fn finalize_recovery_store_pair_action_v1(
        &self,
        expected_journal_descriptor_digest: &str,
        parent_descriptor_digest: &str,
        authenticated_owner_peer_id: u64,
        consensus_authority_record_digest: &str,
        reconciliation_authority_digest: &str,
        canonical_index_states: &[PrivateOramOwnerJournalTerminalIndexStateV1],
    ) -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, PrivateOramOwnerJournalError>
    {
        self.finalize_action(PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest,
            parent_descriptor_digest,
            authenticated_owner_peer_id,
            consensus_authority_record_digest,
            reconciliation_authority_digest,
            canonical_index_states,
        })
    }

    pub(crate) fn abort_old_recovery_store_pair_action_v1(
        &self,
        expected_journal_descriptor_digest: &str,
        parent_descriptor_digest: &str,
        authenticated_owner_peer_id: u64,
        consensus_authority_record_digest: &str,
        reconciliation_authority_digest: &str,
        canonical_index_states: &[PrivateOramOwnerJournalTerminalIndexStateV1],
    ) -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, PrivateOramOwnerJournalError>
    {
        self.abort_old_action(PrivateOramOwnerJournalAbortOldContextV1 {
            expected_journal_descriptor_digest,
            parent_descriptor_digest,
            authenticated_owner_peer_id,
            consensus_authority_record_digest,
            reconciliation_authority_digest,
            canonical_index_states,
        })
    }

    fn terminal_action(
        &self,
        transition: TerminalTransition<'_>,
    ) -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, PrivateOramOwnerJournalError>
    {
        validate_terminal_transition(transition)?;
        let desired = build_terminal_record(&self.snapshot, transition)?;
        if self
            .snapshot
            .terminal
            .as_ref()
            .is_some_and(|existing| existing != &desired)
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(PrivateOramOwnerRecoveryExclusiveActionV1 {
            terminal: Some(PrivateOramOwnerRecoveryTerminalIntentV1 {
                phase: transition.phase,
                expected_journal_descriptor_digest: transition
                    .expected_journal_descriptor_digest
                    .to_string(),
                parent_descriptor_digest: transition.parent_descriptor_digest.to_string(),
                authenticated_owner_peer_id: transition.authenticated_owner_peer_id,
                consensus_authority_record_digest: transition
                    .consensus_authority_record_digest
                    .to_string(),
                reconciliation_authority_digest: transition
                    .reconciliation_authority_digest
                    .to_string(),
                canonical_index_states: transition.canonical_index_states.to_vec(),
                lock_lifetime: PhantomData,
                not_send_or_sync: PhantomData,
            }),
            lock_lifetime: PhantomData,
            not_send_or_sync: PhantomData,
        })
    }

    pub(crate) const fn no_terminal_action(
        &self,
    ) -> PrivateOramOwnerRecoveryExclusiveActionV1<'lock> {
        let _ = self.state;
        PrivateOramOwnerRecoveryExclusiveActionV1 {
            terminal: None,
            lock_lifetime: PhantomData,
            not_send_or_sync: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateOramOwnerRecoveryExclusiveStateV1 {
    Prepared,
    FinalizedReplay,
    AbortedOldReplay,
}

type RecoveryTransactionBrand<'lock> = PhantomData<fn(&'lock mut ()) -> &'lock mut ()>;

pub(crate) struct PrivateOramOwnerRecoveryExclusiveActionV1<'lock> {
    terminal: Option<PrivateOramOwnerRecoveryTerminalIntentV1<'lock>>,
    lock_lifetime: RecoveryTransactionBrand<'lock>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

struct PrivateOramOwnerRecoveryTerminalIntentV1<'lock> {
    phase: PrivateOramOwnerJournalPhaseV1,
    expected_journal_descriptor_digest: String,
    parent_descriptor_digest: String,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    canonical_index_states: Vec<PrivateOramOwnerJournalTerminalIndexStateV1>,
    lock_lifetime: RecoveryTransactionBrand<'lock>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl PrivateOramOwnerRecoveryTerminalIntentV1<'_> {
    fn transition(&self) -> TerminalTransition<'_> {
        TerminalTransition {
            phase: self.phase,
            expected_journal_descriptor_digest: &self.expected_journal_descriptor_digest,
            parent_descriptor_digest: &self.parent_descriptor_digest,
            authenticated_owner_peer_id: self.authenticated_owner_peer_id,
            consensus_authority_record_digest: &self.consensus_authority_record_digest,
            reconciliation_authority_digest: &self.reconciliation_authority_digest,
            canonical_index_states: &self.canonical_index_states,
        }
    }
}

pub(crate) enum PrivateOramOwnerRecoveryExclusiveOutcomeV1 {
    NoTerminal,
    Finalized(PrivateOramDurableOwnerFinalizedTokenV1),
    AbortedOld(PrivateOramDurableOwnerAbortedOldTokenV1),
}

impl Debug for PrivateOramOwnerRecoveryExclusiveOutcomeV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTerminal => f.write_str("NoTerminal"),
            Self::Finalized(_) => f.write_str("Finalized([redacted])"),
            Self::AbortedOld(_) => f.write_str("AbortedOld([redacted])"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramDurableOwnerPreparedTokenV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    indexes: Vec<PrivateOramOwnerPreparedIndexEvidenceV1>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerPreparedStoreBindingV1 {
    snapshot: PrivateOramOwnerJournalSnapshotV1,
}

impl Debug for PrivateOramOwnerPreparedStoreBindingV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPreparedStoreBindingV1")
            .field("snapshot", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerPreparedStoreBindingV1 {
    pub(crate) fn snapshot(&self) -> &PrivateOramOwnerJournalSnapshotV1 {
        &self.snapshot
    }
}

impl Debug for PrivateOramDurableOwnerPreparedTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurableOwnerPreparedTokenV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramDurableOwnerPreparedTokenV1 {
    pub(crate) const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub(crate) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(crate) fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub(crate) fn indexes(&self) -> &[PrivateOramOwnerPreparedIndexEvidenceV1] {
        &self.indexes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerFinalizedIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
    finalized_state_digest: String,
}

impl Debug for PrivateOramOwnerFinalizedIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerFinalizedIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("finalized_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerFinalizedIndexEvidenceV1 {
    pub(crate) const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }

    pub(crate) fn finalized_state_digest(&self) -> &str {
        &self.finalized_state_digest
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramDurableOwnerFinalizedTokenV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    prepared_state_digest: String,
    terminal_record_digest: String,
    parent_descriptor_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    indexes: Vec<PrivateOramOwnerFinalizedIndexEvidenceV1>,
}

impl Debug for PrivateOramDurableOwnerFinalizedTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurableOwnerFinalizedTokenV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramDurableOwnerFinalizedTokenV1 {
    pub(crate) const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub(crate) fn prepared_state_digest(&self) -> &str {
        &self.prepared_state_digest
    }

    pub(crate) fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }

    pub(crate) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(crate) fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub(crate) fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub(crate) fn indexes(&self) -> &[PrivateOramOwnerFinalizedIndexEvidenceV1] {
        &self.indexes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerAbortedOldIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
    aborted_old_state_digest: String,
}

impl Debug for PrivateOramOwnerAbortedOldIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerAbortedOldIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("aborted_old_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerAbortedOldIndexEvidenceV1 {
    pub(crate) const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }

    pub(crate) fn aborted_old_state_digest(&self) -> &str {
        &self.aborted_old_state_digest
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramDurableOwnerAbortedOldTokenV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    prepared_state_digest: String,
    terminal_record_digest: String,
    parent_descriptor_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    indexes: Vec<PrivateOramOwnerAbortedOldIndexEvidenceV1>,
}

impl Debug for PrivateOramDurableOwnerAbortedOldTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurableOwnerAbortedOldTokenV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramDurableOwnerAbortedOldTokenV1 {
    pub(crate) const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub(crate) fn prepared_state_digest(&self) -> &str {
        &self.prepared_state_digest
    }

    pub(crate) fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }

    pub(crate) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(crate) fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub(crate) fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub(crate) fn indexes(&self) -> &[PrivateOramOwnerAbortedOldIndexEvidenceV1] {
        &self.indexes
    }
}

#[derive(Clone)]
pub struct PrivateOramOwnerJournal {
    root: PathBuf,
}

impl Debug for PrivateOramOwnerJournal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournal")
            .field("root", &"[redacted]")
            .finish()
    }
}

struct LoadedPrivateOramOwnerPrestageIntentV2 {
    package: PrivateOramOwnerPrestagePackageV2,
    package_bytes: Vec<u8>,
    receipt: PrivateOramOwnerPrestageReceiptV2,
    prepared: ValidatedOwnerJournal,
    intent_marker: PrivateOramOwnerLifecycleMarkerV2,
    adoption_pending_marker: Option<PrivateOramOwnerLifecycleMarkerV2>,
    adopted_marker: Option<PrivateOramOwnerLifecycleMarkerV2>,
}

enum PlannedPrivateOramOwnerCleanupV2 {
    Existing(CommittedPrivateOramOwnerCleanupReceiptV2),
    Unsigned(PrivateOramOwnerCleanupReceiptV1),
}

impl LoadedPrivateOramOwnerPrestageIntentV2 {
    fn state(&self) -> PrivateOramOwnerLocalIntentStateV2 {
        if self.adopted_marker.is_some() {
            PrivateOramOwnerLocalIntentStateV2::Adopted
        } else if self.adoption_pending_marker.is_some() {
            PrivateOramOwnerLocalIntentStateV2::AdoptionPending
        } else {
            PrivateOramOwnerLocalIntentStateV2::Intent
        }
    }

    fn current_marker(&self) -> &PrivateOramOwnerLifecycleMarkerV2 {
        self.adopted_marker
            .as_ref()
            .or(self.adoption_pending_marker.as_ref())
            .unwrap_or(&self.intent_marker)
    }
}

fn loaded_prestage_intents_exactly_match_v2(
    left: &LoadedPrivateOramOwnerPrestageIntentV2,
    right: &LoadedPrivateOramOwnerPrestageIntentV2,
) -> bool {
    left.package == right.package
        && left.package_bytes == right.package_bytes
        && left.receipt == right.receipt
        && left.prepared.exactly_matches(&right.prepared)
        && left.intent_marker == right.intent_marker
        && left.adoption_pending_marker == right.adoption_pending_marker
        && left.adopted_marker == right.adopted_marker
}

fn terminalized_journal_matches_prestaged_v1(
    prestaged: &ValidatedOwnerJournal,
    terminalized: &ValidatedOwnerJournal,
) -> bool {
    prestaged.snapshot.terminal.is_none()
        && prestaged.terminal_bytes.is_none()
        && terminalized.snapshot.terminal.is_some()
        && terminalized.terminal_bytes.is_some()
        && prestaged.snapshot.descriptor == terminalized.snapshot.descriptor
        && prestaged.snapshot.state == terminalized.snapshot.state
        && prestaged.snapshot.final_buckets == terminalized.snapshot.final_buckets
        && prestaged.descriptor_bytes == terminalized.descriptor_bytes
        && prestaged.state_bytes == terminalized.state_bytes
        && prestaged.final_bucket_bytes == terminalized.final_bucket_bytes
}

impl PrivateOramOwnerPrestageStoreV2 {
    pub fn new(primary_hnsw_store_root: impl AsRef<Path>) -> Self {
        let primary_hnsw_store_root = primary_hnsw_store_root.as_ref().to_path_buf();
        let root = primary_hnsw_store_root
            .join(OWNER_STORE_TEMP_DIR)
            .join(PRESTAGE_ROOT_DIR);
        Self {
            primary_hnsw_store_root,
            root,
        }
    }

    /// Pins a runtime-provided HNSW root to the current process directory without resolving
    /// symlinks. Snapshot and terminal archive paths use this constructor so later CWD changes
    /// cannot rebind an already validated owner namespace.
    #[doc(hidden)]
    pub fn try_new_pinned_absolute_v2(
        primary_hnsw_store_root: impl AsRef<Path>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        let absolute = std::path::absolute(primary_hnsw_store_root.as_ref())
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                    normalized.push(component.as_os_str());
                }
                Component::CurDir => {}
                Component::ParentDir => return Err(PrivateOramOwnerJournalError::Corrupt),
            }
        }
        validate_absolute_normal_path(&normalized)?;
        Ok(Self::new(normalized))
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Acquires the durable V2 owner snapshot lock hierarchy in writer order and validates the
    /// exact consensus-qualified acknowledged archive chain before returning.
    #[doc(hidden)]
    pub fn acquire_snapshot_guard_v2(
        &self,
        expectation: &PrivateOramOwnerNewGenerationReadinessExpectationV2,
    ) -> Result<PrivateOramOwnerSnapshotGuardV2, PrivateOramOwnerJournalError> {
        let hnsw_root = require_absolute_normal_path(&self.primary_hnsw_store_root)?;
        let hnsw_parent = hnsw_root
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        if hnsw_parent.file_name() != Some(OsStr::new(PRIVATE_HNSW_ORAM_DIR)) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let collection_root_path = hnsw_parent
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        validate_absolute_normal_path(collection_root_path)?;

        // Parent grant publication is rank 0. Holding this lock before lifecycle/canonical locks
        // prevents an archive from being captured between parent and child publication.
        let collection_root = open_owned_ancestry_directory(collection_root_path)?;
        let parent_root_path = collection_root_path.join(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2);
        let parent_journal = if path_entry_exists(&parent_root_path)? {
            let anchored_parent = open_owned_directory_entry_path(
                &collection_root,
                OsStr::new(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2),
            )?;
            let root = open_private_directory(&anchored_parent)?;
            validate_open_directory_at_path(&root, &parent_root_path)?;
            let lock = open_private_lock_file_shared(&open_directory_entry_path(
                &root,
                OsStr::new(PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2),
            )?)?;
            Some(PrivateOramPinnedParentSnapshotV2 {
                root,
                root_path: parent_root_path,
                _lock: lock,
            })
        } else {
            None
        };

        let owner_temp_path = self.owner_temp_path()?.to_path_buf();
        let owner_temp = PrivateOramOwnedSharedDirectoryLockV2::acquire(&owner_temp_path)?;
        let lifecycle_root = PrivateOramOwnedSharedDirectoryLockV2::acquire(&self.root)?;
        let canonical_path = owner_temp_path.join(PRIVATE_ORAM_OWNER_JOURNAL_DIR);
        let canonical_root = if path_entry_exists(&canonical_path)? {
            Some(PrivateOramOwnedSharedDirectoryLockV2::acquire(
                &canonical_path,
            )?)
        } else {
            None
        };

        let guard = PrivateOramOwnerSnapshotGuardV2 {
            store: self.clone(),
            expectation: expectation.clone(),
            parent_journal,
            owner_temp,
            lifecycle_root,
            canonical_root,
        };
        guard.validate_held_v2()?;
        Ok(guard)
    }

    /// Durably installs the consensus-prepared owner incarnation at its genesis lifecycle.
    /// Exact replay is idempotent; a different or already-advanced incarnation fails closed.
    pub fn install_genesis_enrollment_v2(
        &self,
        owner_store_incarnation_digest: &str,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        validate_digest(
            owner_store_incarnation_digest,
            "owner_store_incarnation_digest",
        )?;
        let expected = private_oram_owner_lifecycle_genesis_state_v1(
            owner_store_incarnation_digest.to_string(),
        )
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("owner_lifecycle"))?;
        let installed = self.ensure_layout_inner_v2(true, Some(owner_store_incarnation_digest))?;
        if installed != expected {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(())
    }

    /// Requires an existing durable owner incarnation without creating replacement state.
    pub fn require_enrollment_v2(
        &self,
        owner_store_incarnation_digest: &str,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        validate_digest(
            owner_store_incarnation_digest,
            "owner_store_incarnation_digest",
        )?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let _lock = lock_private_oram_owner_lifecycle_root_shared(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        validate_private_oram_owner_prestage_root_entries(&root)?;
        self.require_no_unreconciled_signed_cleanup_locked(&root)?;
        let installed = self.load_superblock_locked(&root)?.lifecycle_state()?;
        if installed.owner_store_incarnation_digest != owner_store_incarnation_digest {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(())
    }

    /// Consensus-qualified, side-effect-free pre-admission assertion for a new owner generation.
    ///
    /// The lifecycle namespace is locked before the canonical journal namespace, matching every
    /// writer that can adopt or archive a generation. The exact consensus-required generation set
    /// must equal both the completed archive set and the retired adopted-intent set. This rejects
    /// a rollback that removes both members of an otherwise locally consistent pair.
    pub fn require_ready_for_new_generation_v2(
        &self,
        expectation: &PrivateOramOwnerNewGenerationReadinessExpectationV2,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root_shared(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        validate_private_oram_owner_prestage_root_entries(&root)?;
        self.require_no_unreconciled_signed_cleanup_locked(&root)?;
        let superblock = self.load_superblock_locked(&root)?;
        if superblock.owner_store_incarnation_digest != expectation.owner_store_incarnation_digest {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }

        let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        for intent_name in directory_entry_names_open_bounded(
            &intents,
            PRESTAGE_MAX_TERMINAL_RECORDS,
            PrivateOramOwnerJournalError::TerminalCapacityExceeded,
        )? {
            let intent_key = intent_name
                .to_str()
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            let loaded =
                self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?;
            if loaded.state() != PrivateOramOwnerLocalIntentStateV2::Intent {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
        }

        let (_, quarantine) = self.open_prestage_child_locked(&root, PRESTAGE_QUARANTINE_DIR)?;
        if !directory_entry_names_open_bounded(
            &quarantine,
            PRESTAGE_MAX_TERMINAL_RECORDS,
            PrivateOramOwnerJournalError::TerminalCapacityExceeded,
        )?
        .is_empty()
        {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }

        let (_, retired) = self.open_prestage_child_locked(&root, PRESTAGE_RETIRED_DIR)?;
        let retired_intents = directory_entry_names_open_bounded(
            &retired,
            PRESTAGE_MAX_TERMINAL_RECORDS,
            PrivateOramOwnerJournalError::TerminalCapacityExceeded,
        )?
        .into_iter()
        .map(|intent_name| {
            let intent_key = intent_name
                .to_str()
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            self.load_intent_locked(&root, &retired, PRESTAGE_RETIRED_DIR, intent_key)
        })
        .collect::<Result<Vec<_>, _>>()?;

        let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
        let canonical_path =
            open_directory_entry_path(&owner_temp, OsStr::new(PRIVATE_ORAM_OWNER_JOURNAL_DIR))?;
        if path_entry_exists(&canonical_path)? {
            let canonical_root = open_private_directory(&canonical_path)?;
            let canonical_lock = lock_private_journal_root_shared(&canonical_root)?;
            let canonical_names = directory_entry_names_open_bounded(
                &canonical_root,
                PRESTAGE_MAX_TERMINAL_RECORDS
                    .checked_mul(2)
                    .and_then(|limit| limit.checked_add(1))
                    .ok_or(PrivateOramOwnerJournalError::TerminalCapacityExceeded)?,
                PrivateOramOwnerJournalError::TerminalCapacityExceeded,
            )?;
            if canonical_names.contains(OsStr::new(ACTIVE_DIR)) {
                return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
            }

            let mut archived_by_generation = BTreeMap::new();
            for name in canonical_names {
                if let Some(generation) = completed_generation_from_name(&name)? {
                    owner_journal.load_completed_structural_from(
                        &canonical_root,
                        generation,
                        false,
                        None,
                    )?;
                    let archive = owner_journal
                        .load_completed_archive_record_under_lock_v1(&canonical_lock, generation)?
                        .ok_or(PrivateOramOwnerJournalError::ExternalRecoveryRequired)?;
                    if archive.collection_id != expectation.collection_id
                        || archive.owner_store_incarnation_digest
                            != expectation.owner_store_incarnation_digest
                        || archived_by_generation.insert(generation, archive).is_some()
                    {
                        return Err(PrivateOramOwnerJournalError::Corrupt);
                    }
                } else if is_candidate_name(&name) {
                    validate_private_directory_exact(&open_directory_entry_path(
                        &canonical_root,
                        &name,
                    )?)?;
                } else {
                    return Err(PrivateOramOwnerJournalError::Corrupt);
                }
            }

            if archived_by_generation.len() != expectation.acknowledged_archives.len() {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
            for expected in &expectation.acknowledged_archives {
                let Some(archive) = archived_by_generation.get(&expected.generation) else {
                    return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
                };
                let parent = LoadedCanonicalParentArchiveGrantV1::load(
                    &self.primary_hnsw_store_root,
                    expected.generation,
                )
                .map_err(|_| PrivateOramOwnerJournalError::ExternalRecoveryRequired)?;
                let grant = parent.grant();
                if archive.generation != expected.generation
                    || archive.owner_peer_id != expected.owner_peer_id
                    || archive.parent_terminal_record_digest
                        != expected.parent_terminal_record_digest
                    || archive.pending_tombstone_digest != expected.pending_tombstone_digest
                    || archive.clear_receipt_digest != expected.clear_receipt_digest
                    || grant.collection_id != archive.collection_id
                    || grant.generation != archive.generation
                    || grant.owner_peer_id != archive.owner_peer_id
                    || grant.owner_store_incarnation_digest
                        != archive.owner_store_incarnation_digest
                    || grant.owner_store_incarnation_digest
                        != expectation.owner_store_incarnation_digest
                    || grant.prestage_receipt_digest != archive.prestage_receipt_digest
                    || grant.parent_terminal_record_digest != archive.parent_terminal_record_digest
                    || grant.parent_archive_record_digest != archive.parent_archive_record_digest
                    || grant.pending_tombstone_digest != archive.pending_tombstone_digest
                    || grant.clear_receipt_digest != archive.clear_receipt_digest
                    || grant.owner_terminal_evidence_digest
                        != archive.owner_terminal_evidence_digest
                    || grant.grant_digest != archive.archive_authority_digest
                {
                    return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
                }
            }

            let mut retired_archived_receipts = BTreeSet::new();
            for loaded in &retired_intents {
                if loaded.state() == PrivateOramOwnerLocalIntentStateV2::Adopted {
                    if !owner_journal
                        .committed_archive_fences_intent_under_lock_v1(&canonical_lock, loaded)?
                        || !retired_archived_receipts
                            .insert(loaded.receipt.receipt_digest().to_string())
                    {
                        return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
                    }
                }
            }
            let archived_receipts = archived_by_generation
                .values()
                .map(|archive| archive.prestage_receipt_digest.clone())
                .collect::<BTreeSet<_>>();
            if archived_receipts != retired_archived_receipts {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
            validate_open_directory_at_path(&canonical_root, owner_journal.root_path())?;
        } else if !expectation.acknowledged_archives.is_empty()
            || retired_intents
                .iter()
                .any(|loaded| loaded.state() == PrivateOramOwnerLocalIntentStateV2::Adopted)
        {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }

        lifecycle_lock.validate_held()?;
        validate_open_directory_at_path(&root, &self.root)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_exclusive_lifecycle_root_lock_for_test_v2<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        self.ensure_layout()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let guard = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        let output = action();
        guard.require_exclusive()?;
        Ok(output)
    }

    /// Installs one immutable intent. Exact replay returns the same receipt; a conflicting body
    /// under the same intent key fails closed.
    pub fn install_v2(
        &self,
        validated_request: &VerifiedPrivateOramOwnerPrestageRequestV2,
        package: &PrivateOramOwnerPrestagePackageV2,
        package_canonical_json: &[u8],
        validated_prepare: &PrivateOramValidatedOwnerPrepareV1,
        plan: &PrivateOramOwnerPrestagePlanV2,
    ) -> Result<PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerJournalError> {
        self.install_inner_v2(
            validated_request,
            package,
            package_canonical_json,
            validated_prepare,
            plan,
            false,
            false,
        )
    }

    /// V3 install requires a committed finalized reservation handoff. An exact replay may proceed
    /// after the handoff marker was consumed because the immutable intent itself is durable proof.
    pub fn install_v3_reserved(
        &self,
        validated_request: &VerifiedPrivateOramOwnerPrestageRequestV2,
        package: &PrivateOramOwnerPrestagePackageV2,
        package_canonical_json: &[u8],
        validated_prepare: &PrivateOramValidatedOwnerPrepareV1,
        plan: &PrivateOramOwnerPrestagePlanV2,
    ) -> Result<PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerJournalError> {
        self.install_inner_v2(
            validated_request,
            package,
            package_canonical_json,
            validated_prepare,
            plan,
            true,
            true,
        )
    }

    #[cfg(test)]
    pub(crate) fn install_v3_reserved_leave_fence_for_test_v1(
        &self,
        validated_request: &VerifiedPrivateOramOwnerPrestageRequestV2,
        package: &PrivateOramOwnerPrestagePackageV2,
        package_canonical_json: &[u8],
        validated_prepare: &PrivateOramValidatedOwnerPrepareV1,
        plan: &PrivateOramOwnerPrestagePlanV2,
    ) -> Result<PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerJournalError> {
        self.install_inner_v2(
            validated_request,
            package,
            package_canonical_json,
            validated_prepare,
            plan,
            true,
            false,
        )
    }

    fn install_inner_v2(
        &self,
        validated_request: &VerifiedPrivateOramOwnerPrestageRequestV2,
        package: &PrivateOramOwnerPrestagePackageV2,
        package_canonical_json: &[u8],
        validated_prepare: &PrivateOramValidatedOwnerPrepareV1,
        plan: &PrivateOramOwnerPrestagePlanV2,
        require_finalized_reservation_handoff: bool,
        consume_finalized_reservation_handoff: bool,
    ) -> Result<PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        validate_private_oram_owner_prestage_package_for_request_v2(
            validated_request,
            package,
            package_canonical_json,
        )
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("prestage_package"))?;
        let request = validated_request.request();
        if request.owner_peer_id != plan.owner_peer_id
            || request.parent_descriptor_digest != plan.parent_descriptor_digest
            || request.parent_lease_acquired_record_digest
                != plan.parent_lease_acquired_record_digest
            || validated_prepare.mutation_digest() != request.mutation_digest
            || validated_prepare.mutation_bundle() != &package.owner_prepare.mutation_bundle
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "prestage_context",
            ));
        }
        let requirements = plan
            .requirements
            .iter()
            .map(|requirement| PrivateOramOwnerJournalRequirementV1 {
                kind: requirement.kind,
                index_name: &requirement.index_name,
                old_epoch: requirement.old_epoch,
                new_epoch: requirement.new_epoch,
                old_root_hash: &requirement.old_root_hash,
                new_root_hash: &requirement.new_root_hash,
                writeback_digest: &requirement.writeback_digest,
            })
            .collect::<Vec<_>>();
        let desired = ValidatedOwnerJournal::build(
            validated_prepare,
            PrivateOramOwnerJournalPrepareContextV1 {
                parent_descriptor_digest: &plan.parent_descriptor_digest,
                parent_lease_acquired_record_digest: &plan.parent_lease_acquired_record_digest,
                owner_peer_id: plan.owner_peer_id,
                requirements: &requirements,
            },
        )?;
        self.ensure_layout()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let _lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        let reservation_handoff = self.require_install_authorized_by_reservation_fence_locked(
            &root,
            request.intent_key.as_str(),
        )?;
        let superblock = self.load_superblock_locked(&root)?;
        let receipt = private_oram_owner_prestage_receipt_v2(
            request,
            &desired,
            &superblock.owner_store_incarnation_digest,
        )?;
        if let Some(terminal) =
            self.load_terminal_marker_locked(&root, request.intent_key.as_str())?
        {
            if terminal.signed_cleanup_receipt.is_some() {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
            if !private_oram_owner_terminal_matches_receipt_v2(&terminal, &receipt)? {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
            let destination = match terminal.kind {
                PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => PRESTAGE_RETIRED_DIR,
                PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => PRESTAGE_QUARANTINE_DIR,
                _ => return Err(PrivateOramOwnerJournalError::Corrupt),
            };
            self.finish_terminal_payload_move_locked(
                &root,
                &intents,
                request.intent_key.as_str(),
                &terminal,
                destination,
            )?;
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let intent_marker = private_oram_owner_lifecycle_marker_v2(
            PrivateOramOwnerLifecycleMarkerKindV2::Intent,
            &superblock.owner_store_incarnation_digest,
            &receipt,
            None,
        )?;
        let intent_marker_bytes = encode_private_oram_owner_lifecycle_marker_v2(&intent_marker)?;
        let (intents_path, intents) =
            self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let (retired_path, retired) =
            self.open_prestage_child_locked(&root, PRESTAGE_RETIRED_DIR)?;
        let (quarantine_path, _) =
            self.open_prestage_child_locked(&root, PRESTAGE_QUARANTINE_DIR)?;
        let (temp_path, temp) = self.open_prestage_child_locked(&root, PRESTAGE_TEMP_DIR)?;

        let intent_path = intents_path.join(&request.intent_key);
        if path_entry_exists(&intent_path)? {
            let existing = self.load_intent_locked(
                &root,
                &intents,
                PRESTAGE_INTENTS_DIR,
                request.intent_key.as_str(),
            )?;
            if existing.package_bytes != package_canonical_json
                || existing.package != *package
                || existing.receipt != receipt
                || !existing.prepared.exactly_matches(&desired)
                || existing.intent_marker != intent_marker
            {
                return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
            }
            let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
            let canonical_root = owner_journal.ensure_root()?;
            let canonical_lock = lock_private_journal_root(&canonical_root)?;
            if owner_journal.committed_archive_fences_intent_under_exclusive_lock_v1(
                &canonical_lock,
                &existing,
            )? {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            sync_open_directory(&intents)
                .and_then(|()| sync_open_directory(&root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            validate_open_directory_at_path(&root, &self.root)?;
            if reservation_handoff && consume_finalized_reservation_handoff {
                self.consume_finalized_reservation_fence_locked(&root)?;
            }
            return Ok(receipt);
        }
        let retired_intent_path = retired_path.join(&request.intent_key);
        if path_entry_exists(&quarantine_path.join(&request.intent_key))? {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        if path_entry_exists(&retired_intent_path)? {
            let retired_intent = self.load_intent_locked(
                &root,
                &retired,
                PRESTAGE_RETIRED_DIR,
                request.intent_key.as_str(),
            )?;
            if retired_intent.package_bytes != package_canonical_json
                || retired_intent.package != *package
                || retired_intent.receipt != receipt
                || !retired_intent.prepared.exactly_matches(&desired)
                || retired_intent.intent_marker != intent_marker
                || retired_intent.state() != PrivateOramOwnerLocalIntentStateV2::Adopted
            {
                return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
            }
            let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
            let canonical_root = owner_journal.ensure_root()?;
            let canonical_lock = lock_private_journal_root(&canonical_root)?;
            if owner_journal.committed_archive_fences_intent_under_exclusive_lock_v1(
                &canonical_lock,
                &retired_intent,
            )? {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }
        if require_finalized_reservation_handoff && !reservation_handoff {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }

        let candidate = tempfile::Builder::new()
            .prefix("prestage-v2-")
            .tempdir_in(&temp_path)
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
        set_private_directory_permissions(candidate.path())?;
        write_new_private_file(
            &candidate.path().join(PRESTAGE_PACKAGE_FILE),
            package_canonical_json,
            PRESTAGE_MAX_PACKAGE_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(DESCRIPTOR_FILE),
            &desired.descriptor_bytes,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(FINAL_BUCKETS_FILE),
            &desired.final_bucket_bytes,
            MAX_FINAL_BUCKET_FRAME_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(STATE_FILE),
            &desired.state_bytes,
            MAX_STATE_BYTES,
        )?;
        let receipt_bytes = encode_private_oram_owner_prestage_receipt_v2(&receipt)?;
        write_new_private_file(
            &candidate.path().join(PRESTAGE_RECEIPT_FILE),
            &receipt_bytes,
            PRESTAGE_MAX_RECEIPT_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(PRESTAGE_INTENT_MARKER_FILE),
            &intent_marker_bytes,
            PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
        )?;
        validate_private_oram_owner_prestage_intent_entries(candidate.path())?;
        sync_private_directory(candidate.path())?;
        for (name, expected, max_bytes) in [
            (
                PRESTAGE_PACKAGE_FILE,
                package_canonical_json,
                PRESTAGE_MAX_PACKAGE_BYTES,
            ),
            (
                DESCRIPTOR_FILE,
                desired.descriptor_bytes.as_slice(),
                MAX_DESCRIPTOR_BYTES,
            ),
            (
                FINAL_BUCKETS_FILE,
                desired.final_bucket_bytes.as_slice(),
                MAX_FINAL_BUCKET_FRAME_BYTES,
            ),
            (STATE_FILE, desired.state_bytes.as_slice(), MAX_STATE_BYTES),
            (
                PRESTAGE_RECEIPT_FILE,
                receipt_bytes.as_slice(),
                PRESTAGE_MAX_RECEIPT_BYTES,
            ),
            (
                PRESTAGE_INTENT_MARKER_FILE,
                intent_marker_bytes.as_slice(),
                PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
            ),
        ] {
            let (mut pinned, actual) =
                read_private_file_pinned(&candidate.path().join(name), max_bytes)?;
            if actual != expected {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
            pinned.validate_exact_contents(expected)?;
        }
        let candidate_directory = open_private_directory(candidate.path())?;
        let candidate_name = candidate
            .path()
            .file_name()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        sync_open_directory(&temp)?;
        match rename_entry_noreplace(
            &temp,
            candidate_name,
            &intents,
            OsStr::new(&request.intent_key),
        ) {
            Ok(()) => {
                sync_open_directory(&temp)
                    .and_then(|()| sync_open_directory(&intents))
                    .and_then(|()| sync_open_directory(&root))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed_directory = open_private_directory(&intent_path)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                ensure_same_open_inode(&candidate_directory, &installed_directory)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed = self
                    .load_intent_locked(
                        &root,
                        &intents,
                        PRESTAGE_INTENTS_DIR,
                        request.intent_key.as_str(),
                    )
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if installed.package_bytes != package_canonical_json
                    || installed.receipt != receipt
                    || !installed.prepared.exactly_matches(&desired)
                    || installed.intent_marker != intent_marker
                {
                    return Err(PrivateOramOwnerJournalError::Indeterminate);
                }
                validate_open_directory_at_path(&root, &self.root)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if reservation_handoff && consume_finalized_reservation_handoff {
                    self.consume_finalized_reservation_fence_locked(&root)?;
                }
                Ok(receipt)
            }
            Err(PrivateOramOwnerJournalError::ConcurrentMutation) => {
                let existing = self.load_intent_locked(
                    &root,
                    &intents,
                    PRESTAGE_INTENTS_DIR,
                    request.intent_key.as_str(),
                )?;
                if existing.package_bytes != package_canonical_json
                    || existing.receipt != receipt
                    || !existing.prepared.exactly_matches(&desired)
                    || existing.intent_marker != intent_marker
                {
                    return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
                }
                sync_open_directory(&intents)
                    .and_then(|()| sync_open_directory(&root))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if reservation_handoff && consume_finalized_reservation_handoff {
                    self.consume_finalized_reservation_fence_locked(&root)?;
                }
                Ok(receipt)
            }
            Err(error) => Err(error),
        }
    }

    /// Adopts exact pre-staged bytes only after the durable sequence-1 parent exists.
    pub fn adopt_for_parent_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        parent: &PrivateOramOwnerPrepareParentV2,
    ) -> Result<PrivateOramOwnerPreparedEvidenceV2, PrivateOramOwnerJournalError> {
        self.adopt_for_parent_inner_v2(intent_key, expected_package_sha256, parent, false, false)?
            .ok_or(PrivateOramOwnerJournalError::Indeterminate)
    }

    /// Retires one exact committed owner generation authorized by the canonical parent grant.
    /// The lifecycle lock remains held from parent durability validation through adopted-intent
    /// retirement. This operation never creates missing parent or child lifecycle state.
    /// Safe callers control only the requested generation and call timing; no caller-supplied path,
    /// grant bytes, or evidence object participates in authority. The grant digest binds immutable
    /// local state but does not authenticate against arbitrary same-UID filesystem writes, which
    /// are outside this in-process API threat model.
    ///
    /// The removed raw-input authority type must remain unavailable to downstream crates.
    ///
    /// ```compile_fail
    /// use collection::private_oram_owner_journal::PrivateOramOwnerCommittedArchiveInputV1;
    /// ```
    ///
    /// The removed raw index-input authority type must remain unavailable too.
    ///
    /// ```compile_fail
    /// use collection::private_oram_owner_journal::PrivateOramOwnerCommittedArchiveIndexInputV1;
    /// ```
    ///
    /// No downstream unsafe block may recover the former unchecked archive entry point.
    ///
    /// ```compile_fail
    /// use collection::private_oram_owner_journal::PrivateOramOwnerPrestageStoreV2;
    ///
    /// let _ = PrivateOramOwnerPrestageStoreV2::archive_committed_generation_from_parent_unchecked_v1;
    /// ```
    #[doc(hidden)]
    pub fn archive_committed_generation_from_canonical_parent_v1(
        &self,
        generation: u64,
    ) -> Result<PrivateOramOwnerArchivedGenerationV1, PrivateOramOwnerJournalError> {
        let mut parent =
            LoadedCanonicalParentArchiveGrantV1::load(&self.primary_hnsw_store_root, generation)?;
        let authority = parent.grant().clone();
        let Some((owner_temp, root)) =
            parent.open_child_lifecycle_root_namespaces(self.owner_temp_path()?, &self.root)?
        else {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        };
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        lifecycle_lock.require_exclusive()?;
        self.require_no_active_reservation_fence_locked(&root, None)?;
        if self
            .load_terminal_marker_locked(&root, authority.receipt.intent_key())?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let superblock = self.load_superblock_locked(&root)?;
        if superblock.owner_store_incarnation_digest != authority.owner_store_incarnation_digest {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let (intents_path, intents) =
            self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let (retired_path, retired) =
            self.open_prestage_child_locked(&root, PRESTAGE_RETIRED_DIR)?;
        let (quarantine_path, _) =
            self.open_prestage_child_locked(&root, PRESTAGE_QUARANTINE_DIR)?;
        let intent_key = authority.receipt.intent_key();
        let in_intents = path_entry_exists(&intents_path.join(intent_key))?;
        let in_retired = path_entry_exists(&retired_path.join(intent_key))?;
        let in_quarantine = path_entry_exists(&quarantine_path.join(intent_key))?;
        if in_quarantine || in_intents == in_retired {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let loaded = if in_intents {
            self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?
        } else {
            self.load_intent_locked(&root, &retired, PRESTAGE_RETIRED_DIR, intent_key)?
        };
        if loaded.receipt != authority.receipt
            || loaded.state() != PrivateOramOwnerLocalIntentStateV2::Adopted
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        parent.establish_durable()?;

        let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
        let canonical_root = owner_journal.open_existing_root()?;
        let canonical_lock = lock_private_journal_root(&canonical_root)?;
        let expected_archive = owner_journal.archive_committed_directory_under_exclusive_lock_v1(
            &canonical_lock,
            &authority,
            &superblock.owner_store_incarnation_digest,
            &loaded,
        )?;
        parent
            .validate_bindings_and_contents()
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        let archive_name = completed_generation_name(authority.receipt.lease_generation())?;
        let completed_path = open_directory_entry_path(&canonical_root, OsStr::new(&archive_name))?;
        let completed = open_private_directory(&completed_path)?;
        let archive_bytes = encode_owner_terminal_archive_v1(&expected_archive)?;
        self.publish_immutable_file_locked(
            &root,
            &completed,
            &completed_path,
            OWNER_TERMINAL_ARCHIVE_FILE,
            &archive_bytes,
            MAX_OWNER_TERMINAL_ARCHIVE_BYTES,
        )?;
        let installed_archive = owner_journal
            .load_completed_archive_record_under_lock_v1(
                &canonical_lock,
                authority.receipt.lease_generation(),
            )?
            .ok_or(PrivateOramOwnerJournalError::Indeterminate)?;
        if installed_archive != expected_archive {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        parent
            .validate_bindings_and_contents()
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        fail_owner_archive_after_record_publish_v1()?;

        match (in_intents, in_retired) {
            (true, false) => {
                rename_entry_noreplace(
                    &intents,
                    OsStr::new(intent_key),
                    &retired,
                    OsStr::new(intent_key),
                )?;
                sync_open_directory(&intents)
                    .and_then(|()| sync_open_directory(&retired))
                    .and_then(|()| sync_open_directory(&root))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
            (false, true) => {
                sync_open_directory(&intents)
                    .and_then(|()| sync_open_directory(&retired))
                    .and_then(|()| sync_open_directory(&root))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
            (true, true) | (false, false) => {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
        let retired_loaded =
            self.load_intent_locked(&root, &retired, PRESTAGE_RETIRED_DIR, intent_key)?;
        if !loaded_prestage_intents_exactly_match_v2(&loaded, &retired_loaded)
            || path_entry_exists(&intents_path.join(intent_key))?
            || path_entry_exists(&quarantine_path.join(intent_key))?
            || !owner_journal.committed_archive_fences_intent_under_exclusive_lock_v1(
                &canonical_lock,
                &retired_loaded,
            )?
        {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        parent
            .validate_bindings_and_contents()
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        validate_open_directory_at_path(&canonical_root, owner_journal.root_path())?;
        validate_open_directory_at_path(&root, &self.root)?;
        Ok(PrivateOramOwnerArchivedGenerationV1 {
            collection_id: installed_archive.collection_id,
            generation: installed_archive.generation,
            owner_peer_id: installed_archive.owner_peer_id,
            parent_archive_record_digest: installed_archive.parent_archive_record_digest,
            pending_tombstone_digest: installed_archive.pending_tombstone_digest,
            clear_receipt_digest: installed_archive.clear_receipt_digest,
            owner_terminal_evidence_digest: installed_archive.owner_terminal_evidence_digest,
            owner_archive_record_digest: installed_archive.archive_record_digest,
            retired_prestage_receipt_digest: installed_archive.prestage_receipt_digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn leave_adoption_pending_for_test_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        parent: &PrivateOramOwnerPrepareParentV2,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        if self
            .adopt_for_parent_inner_v2(intent_key, expected_package_sha256, parent, true, false)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn leave_adoption_after_canonical_for_test_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        parent: &PrivateOramOwnerPrepareParentV2,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        if self
            .adopt_for_parent_inner_v2(intent_key, expected_package_sha256, parent, false, true)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(())
    }

    fn adopt_for_parent_inner_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        parent: &PrivateOramOwnerPrepareParentV2,
        stop_after_pending: bool,
        stop_after_canonical: bool,
    ) -> Result<Option<PrivateOramOwnerPreparedEvidenceV2>, PrivateOramOwnerJournalError> {
        validate_digest(expected_package_sha256, "package_sha256")?;
        self.ensure_layout()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        // The finalized reservation's resolution record outlives adoption: the coordinator
        // acknowledges the reservation outcome only after point staging and recovery readiness,
        // and that acknowledgement re-proves the installed reservation from this record. Cleanup
        // and the next reservation fence clear it.
        self.require_no_active_reservation_fence_locked(&root, Some(intent_key))?;
        let superblock = self.load_superblock_locked(&root)?;
        if let Some(terminal) = self.load_terminal_marker_locked(&root, intent_key)? {
            if terminal.signed_cleanup_receipt.is_some() {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
            if terminal.package_sha256 != expected_package_sha256
                || terminal.parent_descriptor_digest != parent.parent_descriptor_digest
                || terminal.parent_lease_acquired_record_digest
                    != parent.parent_lease_acquired_record_digest
                || terminal.owner_peer_id != parent.owner_peer_id
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            self.validate_terminal_payload_state_locked(&root, &terminal)?;
            let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
            let destination = match terminal.kind {
                PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => PRESTAGE_RETIRED_DIR,
                PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => PRESTAGE_QUARANTINE_DIR,
                _ => return Err(PrivateOramOwnerJournalError::Corrupt),
            };
            self.finish_terminal_payload_move_locked(
                &root,
                &intents,
                intent_key,
                &terminal,
                destination,
            )?;
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let (intents_path, intents) =
            self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let (retired_path, retired) =
            self.open_prestage_child_locked(&root, PRESTAGE_RETIRED_DIR)?;
        let (quarantine_path, _) =
            self.open_prestage_child_locked(&root, PRESTAGE_QUARANTINE_DIR)?;
        let in_intents = path_entry_exists(&intents_path.join(intent_key))?;
        let in_retired = path_entry_exists(&retired_path.join(intent_key))?;
        let in_quarantine = path_entry_exists(&quarantine_path.join(intent_key))?;
        if in_quarantine || in_intents == in_retired {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let loaded = if in_intents {
            self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?
        } else {
            self.load_intent_locked(&root, &retired, PRESTAGE_RETIRED_DIR, intent_key)?
        };
        if loaded.receipt.package_sha256 != expected_package_sha256
            || loaded.receipt.parent_descriptor_digest != parent.parent_descriptor_digest
            || loaded.receipt.parent_lease_acquired_record_digest
                != parent.parent_lease_acquired_record_digest
            || loaded.receipt.owner_peer_id != parent.owner_peer_id
            || loaded.prepared.snapshot.descriptor.parent_descriptor_digest
                != parent.parent_descriptor_digest
            || loaded
                .prepared
                .snapshot
                .descriptor
                .parent_lease_acquired_record_digest
                != parent.parent_lease_acquired_record_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let expected_requirements = parent
            .requirements
            .iter()
            .map(|requirement| {
                (
                    requirement.kind,
                    requirement.index_name.as_str(),
                    requirement.old_epoch,
                    requirement.new_epoch,
                    requirement.old_root_hash.as_str(),
                    requirement.new_root_hash.as_str(),
                    requirement.writeback_digest.as_str(),
                )
            })
            .collect::<Vec<_>>();
        let actual_requirements = loaded
            .prepared
            .snapshot
            .descriptor
            .indexes
            .iter()
            .map(|index| {
                (
                    index.kind,
                    index.index_name.as_str(),
                    index.old_epoch,
                    index.new_epoch,
                    index.old_root_hash.as_str(),
                    index.new_root_hash.as_str(),
                    index.writeback_digest.as_str(),
                )
            })
            .collect::<Vec<_>>();
        if actual_requirements != expected_requirements {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
        let canonical_root = owner_journal.ensure_root()?;
        let canonical_lock = lock_private_journal_root(&canonical_root)?;
        if owner_journal
            .committed_archive_fences_intent_under_exclusive_lock_v1(&canonical_lock, &loaded)?
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        if in_retired {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let pending_marker = private_oram_owner_lifecycle_marker_v2(
            PrivateOramOwnerLifecycleMarkerKindV2::AdoptionPending,
            &superblock.owner_store_incarnation_digest,
            &loaded.receipt,
            None,
        )?;
        if let Some(existing) = &loaded.adoption_pending_marker {
            if existing != &pending_marker {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        } else {
            self.publish_intent_marker_locked(
                &root,
                &intents,
                intent_key,
                PRESTAGE_ADOPTION_PENDING_MARKER_FILE,
                &pending_marker,
            )?;
        }
        if stop_after_pending && loaded.adopted_marker.is_none() {
            validate_open_directory_at_path(&root, &self.root)?;
            return Ok(None);
        }
        let adopted_marker = private_oram_owner_lifecycle_marker_v2(
            PrivateOramOwnerLifecycleMarkerKindV2::Adopted,
            &superblock.owner_store_incarnation_digest,
            &loaded.receipt,
            None,
        )?;
        if let Some(existing) = &loaded.adopted_marker
            && existing != &adopted_marker
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let prepared = match owner_journal.prepare_validated_with_lifecycle_guard(
            &lifecycle_lock,
            &canonical_lock,
            loaded.prepared.clone(),
        ) {
            Ok(prepared) => prepared,
            Err(error @ PrivateOramOwnerJournalError::ConcurrentMutation) => {
                let quarantine = private_oram_owner_lifecycle_marker_v2(
                    PrivateOramOwnerLifecycleMarkerKindV2::Quarantined,
                    &superblock.owner_store_incarnation_digest,
                    &loaded.receipt,
                    Some(&pending_marker.marker_digest),
                )?;
                self.publish_terminal_then_move_intent_locked(
                    &root,
                    &intents,
                    intent_key,
                    &quarantine,
                    PRESTAGE_QUARANTINE_DIR,
                    true,
                )?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if stop_after_canonical && loaded.adopted_marker.is_none() {
            validate_open_directory_at_path(&canonical_root, owner_journal.root_path())?;
            validate_open_directory_at_path(&root, &self.root)?;
            return Ok(None);
        }
        if loaded.adopted_marker.is_none() {
            self.publish_intent_marker_locked(
                &root,
                &intents,
                intent_key,
                PRESTAGE_ADOPTED_MARKER_FILE,
                &adopted_marker,
            )?;
        }
        let (_, token) = prepared;
        let replayed =
            self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?;
        if replayed.state() != PrivateOramOwnerLocalIntentStateV2::Adopted
            || replayed.current_marker() != &adopted_marker
        {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        validate_open_directory_at_path(&root, &self.root)?;
        Ok(Some(prepared_evidence_v2(token)))
    }

    pub fn inspect_v2(
        &self,
        intent_key: &str,
    ) -> Result<Option<PrivateOramOwnerPrestageReceiptV2>, PrivateOramOwnerJournalError> {
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let _lock = lock_private_oram_owner_lifecycle_root_shared(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        validate_private_oram_owner_prestage_root_entries(&root)?;
        self.require_no_unreconciled_signed_cleanup_locked(&root)?;
        if let Some(terminal) = self.load_terminal_marker_locked(&root, intent_key)? {
            self.validate_terminal_payload_state_locked(&root, &terminal)?;
            return match terminal.kind {
                PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => Ok(None),
                PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => {
                    Err(PrivateOramOwnerJournalError::Corrupt)
                }
                _ => Err(PrivateOramOwnerJournalError::Corrupt),
            };
        }
        let (intents_path, intents) =
            self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let intent_path = intents_path.join(intent_key);
        if !path_entry_exists(&intent_path)? {
            return Ok(None);
        }
        Ok(Some(
            self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?
                .receipt,
        ))
    }

    /// Creates the owner store namespace if needed and returns its lifecycle state. Owner
    /// enrollment (docs/private-oram-v2-enrollment.md) requires the genesis state.
    pub fn ensure_lifecycle_state_v2(
        &self,
    ) -> Result<PrivateOramOwnerLifecycleStateV1, PrivateOramOwnerJournalError> {
        self.ensure_layout()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let _lock = lock_private_oram_owner_lifecycle_root_shared(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        self.load_superblock_locked(&root)?.lifecycle_state()
    }

    pub fn inspect_lifecycle_v2(
        &self,
        intent_key: &str,
    ) -> Result<PrivateOramOwnerLocalIntentStatusV2, PrivateOramOwnerJournalError> {
        validate_digest(intent_key, "intent_key")?;
        self.ensure_layout()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let _lock = lock_private_oram_owner_lifecycle_root_shared(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        let superblock = self.load_superblock_locked(&root)?;
        if let Some(terminal) = self.load_terminal_marker_locked(&root, intent_key)? {
            self.validate_terminal_payload_state_locked(&root, &terminal)?;
            let state = match terminal.kind {
                PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => {
                    PrivateOramOwnerLocalIntentStateV2::TombstonedAbsent
                }
                PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => {
                    PrivateOramOwnerLocalIntentStateV2::Quarantined
                }
                _ => return Err(PrivateOramOwnerJournalError::Corrupt),
            };
            return Ok(PrivateOramOwnerLocalIntentStatusV2 {
                state,
                lifecycle_state: superblock.lifecycle_state()?,
                marker_digest: Some(terminal.marker_digest),
            });
        }
        let (intents_path, intents) =
            self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let intent_path = intents_path.join(intent_key);
        if !path_entry_exists(&intent_path)? {
            return Ok(PrivateOramOwnerLocalIntentStatusV2 {
                state: PrivateOramOwnerLocalIntentStateV2::Absent,
                lifecycle_state: superblock.lifecycle_state()?,
                marker_digest: None,
            });
        }
        let loaded = self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?;
        Ok(PrivateOramOwnerLocalIntentStatusV2 {
            state: loaded.state(),
            lifecycle_state: superblock.lifecycle_state()?,
            marker_digest: Some(loaded.current_marker().marker_digest.clone()),
        })
    }

    /// Persists one exclusive committed-challenge fence before reservation readiness is signed.
    /// Exact replay is idempotent; a different active challenge fails closed.
    pub fn prepare_reservation_fence_v1(
        &self,
        challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
        expected_lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
    ) -> Result<PrivateOramOwnerDurableReservationFenceV1, PrivateOramOwnerJournalError> {
        validate_private_oram_owner_reservation_prepare_challenge_v1(challenge)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("reservation_challenge"))?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        lifecycle_lock.require_exclusive()?;
        validate_private_oram_owner_prestage_root_entries(&root)?;
        self.require_no_unreconciled_signed_cleanup_locked(&root)?;
        let installed_lifecycle = self.load_superblock_locked(&root)?.lifecycle_state()?;
        if &installed_lifecycle != expected_lifecycle_state
            || challenge.owner_store_incarnation_digest
                != installed_lifecycle.owner_store_incarnation_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let (fence_path, fence_dir) =
            self.open_prestage_child_locked(&root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        validate_private_oram_owner_reservation_fence_entries(&fence_dir)?;
        if let Some(existing) = self.load_reservation_fence_locked(&root, &fence_dir)? {
            if existing.challenge != *challenge || existing.lifecycle_state != installed_lifecycle {
                return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
            }
            return Ok(PrivateOramOwnerDurableReservationFenceV1 { record: existing });
        }
        if self
            .load_reservation_resolution_locked(&root, &fence_dir)?
            .as_ref()
            .is_some_and(|record| {
                private_oram_owner_reservation_resolution_matches_challenge_v1(record, challenge)
            })
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        self.remove_reservation_resolution_residual_locked(&root, &fence_dir)?;
        if self
            .load_terminal_marker_locked(&root, &challenge.reserved_terminal_intent_key)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        self.require_terminal_capacity_locked(&root, &challenge.reserved_terminal_intent_key)?;
        let (_, terminals) = self.open_prestage_child_locked(&root, PRESTAGE_TERMINALS_DIR)?;
        let terminal_record_count = u64::try_from(
            directory_entry_names_open_bounded(
                &terminals,
                PRESTAGE_MAX_TERMINAL_RECORDS,
                PrivateOramOwnerJournalError::Corrupt,
            )?
            .len(),
        )
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let mut record = PrivateOramOwnerReservationFenceRecordV1 {
            version: PRESTAGE_RESERVATION_FENCE_VERSION,
            challenge: challenge.clone(),
            lifecycle_state: installed_lifecycle,
            terminal_record_count,
            terminal_record_limit: PRESTAGE_MAX_TERMINAL_RECORDS as u64,
            fence_record_digest: String::new(),
        };
        record.fence_record_digest = private_oram_owner_reservation_fence_digest_v1(&record)?;
        let bytes = encode_private_oram_owner_reservation_fence_v1(&record)?;
        self.publish_immutable_file_locked(
            &root,
            &fence_dir,
            &fence_path,
            PRESTAGE_RESERVATION_FENCE_FILE,
            &bytes,
            PRESTAGE_MAX_RESERVATION_FENCE_BYTES,
        )?;
        sync_open_directory(&fence_dir)
            .and_then(|()| sync_open_directory(&root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        let installed = self
            .load_reservation_fence_locked(&root, &fence_dir)?
            .ok_or(PrivateOramOwnerJournalError::Indeterminate)?;
        if installed != record {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        validate_open_directory_at_path(&root, &self.root)
            .and_then(|()| validate_open_directory_at_path(&fence_dir, &fence_path))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        Ok(PrivateOramOwnerDurableReservationFenceV1 { record })
    }

    /// Durably binds the local fence to an exact committed consensus disposition. A finalized
    /// disposition is consumed only after the reserved intent is installed. Cancellation removes
    /// the fence only after the resolution record itself has reached durable storage.
    pub fn resolve_reservation_fence_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
    ) -> Result<PrivateOramOwnerDurableReservationResolutionV1, PrivateOramOwnerJournalError> {
        self.resolve_reservation_fence_inner_v1(resolution, None)
    }

    /// Resolves an exact committed cancellation even when this owner durably never published the
    /// corresponding fence. The absent case is recorded before returning so response loss and
    /// restart replay the same terminal fact and the cancelled challenge cannot later be prepared.
    pub fn resolve_reservation_fence_or_record_absent_cancellation_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
        challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
        expected_lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
    ) -> Result<PrivateOramOwnerDurableReservationResolutionV1, PrivateOramOwnerJournalError> {
        validate_private_oram_owner_reservation_prepare_challenge_v1(challenge)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("reservation_challenge"))?;
        if !private_oram_owner_reservation_resolution_input_matches_challenge_v1(
            resolution, challenge,
        ) {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        self.resolve_reservation_fence_inner_v1(
            resolution,
            Some((challenge, expected_lifecycle_state)),
        )
    }

    fn resolve_reservation_fence_inner_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
        absent_cancellation_context: Option<(
            &PrivateOramOwnerReservationPrepareChallengeV1,
            &PrivateOramOwnerLifecycleStateV1,
        )>,
    ) -> Result<PrivateOramOwnerDurableReservationResolutionV1, PrivateOramOwnerJournalError> {
        validate_private_oram_owner_reservation_resolution_input_v1(resolution)?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        lifecycle_lock.require_exclusive()?;
        let superblock = self.load_superblock_locked(&root)?;
        let (fence_path, fence_dir) =
            self.open_prestage_child_locked(&root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        let Some(fence) = self.load_reservation_fence_locked(&root, &fence_dir)? else {
            if let Some(existing) = self.load_reservation_resolution_locked(&root, &fence_dir)? {
                if !private_oram_owner_reservation_resolution_matches_input_v1(
                    &existing, resolution,
                ) {
                    return Err(PrivateOramOwnerJournalError::InvalidTransition);
                }
                return Ok(PrivateOramOwnerDurableReservationResolutionV1 {
                    owner_store_incarnation_digest: existing.owner_store_incarnation_digest.clone(),
                    owner_store_binding_digest: existing.owner_store_binding_digest.clone(),
                    record: existing,
                });
            }
            let Some((challenge, expected_lifecycle_state)) = absent_cancellation_context else {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            };
            if resolution.kind != PrivateOramOwnerReservationResolutionKindV1::Cancelled
                || challenge.owner_store_incarnation_digest
                    != superblock.owner_store_incarnation_digest
                || expected_lifecycle_state != &superblock.lifecycle_state()?
                || challenge.owner_store_incarnation_digest
                    != expected_lifecycle_state.owner_store_incarnation_digest
                || self
                    .load_reservation_abort_release_locked(&root, &fence_dir)?
                    .is_some()
                || self
                    .load_terminal_marker_locked(&root, &challenge.reserved_terminal_intent_key)?
                    .is_some()
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            let (intents_path, _) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
            if path_entry_exists(&intents_path.join(&challenge.reserved_terminal_intent_key))? {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            let mut record = PrivateOramOwnerReservationResolutionRecordV1 {
                version: PRESTAGE_RESERVATION_RESOLUTION_VERSION,
                kind: resolution.kind,
                fence_was_present: false,
                fence_record_digest: private_oram_owner_absent_reservation_fence_digest_v1(
                    challenge,
                    expected_lifecycle_state,
                )?,
                committed_challenge_digest: resolution.committed_challenge_digest.clone(),
                reservation_intent_digest: resolution.reservation_intent_digest.clone(),
                attempt_id: resolution.attempt_id.clone(),
                challenge_applied_term: resolution.challenge_applied_term,
                challenge_applied_index: resolution.challenge_applied_index,
                resolution_applied_term: resolution.resolution_applied_term,
                resolution_applied_index: resolution.resolution_applied_index,
                reserved_terminal_intent_key: challenge.reserved_terminal_intent_key.clone(),
                finalized_reservation_digest: None,
                owner_store_incarnation_digest: superblock.owner_store_incarnation_digest.clone(),
                owner_store_binding_digest: challenge.expected_checkpoint_record_digest.clone(),
                resolution_record_digest: String::new(),
            };
            record.resolution_record_digest =
                private_oram_owner_reservation_resolution_digest_v1(&record)?;
            let bytes = encode_private_oram_owner_reservation_resolution_v1(&record)?;
            self.publish_immutable_file_locked(
                &root,
                &fence_dir,
                &fence_path,
                PRESTAGE_RESERVATION_RESOLUTION_FILE,
                &bytes,
                PRESTAGE_MAX_RESERVATION_RESOLUTION_BYTES,
            )?;
            sync_open_directory(&fence_dir)
                .and_then(|()| sync_open_directory(&root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            if self
                .load_reservation_fence_locked(&root, &fence_dir)?
                .is_some()
                || self
                    .load_reservation_resolution_locked(&root, &fence_dir)?
                    .as_ref()
                    != Some(&record)
            {
                return Err(PrivateOramOwnerJournalError::Indeterminate);
            }
            return Ok(PrivateOramOwnerDurableReservationResolutionV1 {
                owner_store_incarnation_digest: record.owner_store_incarnation_digest.clone(),
                owner_store_binding_digest: record.owner_store_binding_digest.clone(),
                record,
            });
        };
        if fence.challenge.committed_challenge_digest != resolution.committed_challenge_digest
            || fence.challenge.reservation_intent_digest != resolution.reservation_intent_digest
            || fence.challenge.attempt_id != resolution.attempt_id
            || fence.challenge.challenge_applied_term != resolution.challenge_applied_term
            || fence.challenge.challenge_applied_index != resolution.challenge_applied_index
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let mut record = PrivateOramOwnerReservationResolutionRecordV1 {
            version: PRESTAGE_RESERVATION_RESOLUTION_VERSION,
            kind: resolution.kind,
            fence_was_present: true,
            fence_record_digest: fence.fence_record_digest.clone(),
            committed_challenge_digest: resolution.committed_challenge_digest.clone(),
            reservation_intent_digest: resolution.reservation_intent_digest.clone(),
            attempt_id: resolution.attempt_id.clone(),
            challenge_applied_term: resolution.challenge_applied_term,
            challenge_applied_index: resolution.challenge_applied_index,
            resolution_applied_term: resolution.resolution_applied_term,
            resolution_applied_index: resolution.resolution_applied_index,
            reserved_terminal_intent_key: fence.challenge.reserved_terminal_intent_key.clone(),
            finalized_reservation_digest: resolution.finalized_reservation_digest.clone(),
            owner_store_incarnation_digest: fence
                .lifecycle_state
                .owner_store_incarnation_digest
                .clone(),
            owner_store_binding_digest: fence.challenge.expected_checkpoint_record_digest.clone(),
            resolution_record_digest: String::new(),
        };
        if record.owner_store_incarnation_digest != superblock.owner_store_incarnation_digest {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        record.resolution_record_digest =
            private_oram_owner_reservation_resolution_digest_v1(&record)?;
        let bytes = encode_private_oram_owner_reservation_resolution_v1(&record)?;
        self.publish_immutable_file_locked(
            &root,
            &fence_dir,
            &fence_path,
            PRESTAGE_RESERVATION_RESOLUTION_FILE,
            &bytes,
            PRESTAGE_MAX_RESERVATION_RESOLUTION_BYTES,
        )?;
        sync_open_directory(&fence_dir)
            .and_then(|()| sync_open_directory(&root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        if resolution.kind == PrivateOramOwnerReservationResolutionKindV1::Cancelled {
            self.remove_reservation_fence_keep_resolution_locked(&root, &fence_dir, &record)?;
        }
        Ok(PrivateOramOwnerDurableReservationResolutionV1 {
            owner_store_incarnation_digest: record.owner_store_incarnation_digest.clone(),
            owner_store_binding_digest: record.owner_store_binding_digest.clone(),
            record,
        })
    }

    /// Confirms that one finalized reservation resolution was consumed by an exact durable owner
    /// intent. The returned evidence is suitable for a completion receipt signed after install.
    pub fn confirm_installed_reservation_resolution_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
    ) -> Result<PrivateOramOwnerInstalledReservationResolutionV1, PrivateOramOwnerJournalError>
    {
        validate_private_oram_owner_reservation_resolution_input_v1(resolution)?;
        if resolution.kind != PrivateOramOwnerReservationResolutionKindV1::Finalized {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        lifecycle_lock.require_exclusive()?;
        let superblock = self.load_superblock_locked(&root)?;
        let (_, fence_dir) =
            self.open_prestage_child_locked(&root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        if self
            .load_reservation_fence_locked(&root, &fence_dir)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }
        let durable_record = self
            .load_reservation_resolution_locked(&root, &fence_dir)?
            .filter(|record| {
                private_oram_owner_reservation_resolution_matches_input_v1(record, resolution)
            })
            .ok_or(PrivateOramOwnerJournalError::ExternalRecoveryRequired)?;
        if durable_record.owner_store_incarnation_digest
            != superblock.owner_store_incarnation_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let installed = self
            .load_intent_locked(
                &root,
                &intents,
                PRESTAGE_INTENTS_DIR,
                &durable_record.reserved_terminal_intent_key,
            )
            .map_err(|error| match error {
                PrivateOramOwnerJournalError::Io => {
                    PrivateOramOwnerJournalError::ExternalRecoveryRequired
                }
                other => other,
            })?;
        if installed.receipt.intent_key() != durable_record.reserved_terminal_intent_key {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let installed_intent_marker_digest = installed.current_marker().marker_digest.clone();
        Ok(PrivateOramOwnerInstalledReservationResolutionV1 {
            durable_resolution: PrivateOramOwnerDurableReservationResolutionV1 {
                owner_store_incarnation_digest: durable_record
                    .owner_store_incarnation_digest
                    .clone(),
                owner_store_binding_digest: durable_record.owner_store_binding_digest.clone(),
                record: durable_record,
            },
            installed_intent_marker_digest,
            installed_prestage_receipt_digest: installed.receipt.receipt_digest().to_string(),
            installed_package_sha256: installed.receipt.package_sha256().to_string(),
        })
    }

    /// Releases one finalized but uninstalled reservation only after a durable consensus abort
    /// outcome is supplied. The abort marker reaches durable storage before the fence is removed.
    pub fn release_finalized_reservation_after_abort_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
        abort_release_authority_digest: &str,
    ) -> Result<PrivateOramOwnerAbortReleasedReservationResolutionV1, PrivateOramOwnerJournalError>
    {
        self.release_finalized_reservation_after_abort_inner_v1(
            resolution,
            abort_release_authority_digest,
            true,
        )
    }

    #[cfg(test)]
    pub(crate) fn release_finalized_reservation_after_abort_leave_fence_for_test_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
        abort_release_authority_digest: &str,
    ) -> Result<PrivateOramOwnerAbortReleasedReservationResolutionV1, PrivateOramOwnerJournalError>
    {
        self.release_finalized_reservation_after_abort_inner_v1(
            resolution,
            abort_release_authority_digest,
            false,
        )
    }

    fn release_finalized_reservation_after_abort_inner_v1(
        &self,
        resolution: &PrivateOramOwnerReservationResolutionV1,
        abort_release_authority_digest: &str,
        consume_finalized_reservation_handoff: bool,
    ) -> Result<PrivateOramOwnerAbortReleasedReservationResolutionV1, PrivateOramOwnerJournalError>
    {
        validate_private_oram_owner_reservation_resolution_input_v1(resolution)?;
        validate_digest(
            abort_release_authority_digest,
            "abort_release_authority_digest",
        )?;
        if resolution.kind != PrivateOramOwnerReservationResolutionKindV1::Finalized {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        lifecycle_lock.require_exclusive()?;
        let superblock = self.load_superblock_locked(&root)?;
        let (fence_path, fence_dir) =
            self.open_prestage_child_locked(&root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        let fence = self.load_reservation_fence_locked(&root, &fence_dir)?;
        let durable_record = self
            .load_reservation_resolution_locked(&root, &fence_dir)?
            .filter(|record| {
                private_oram_owner_reservation_resolution_matches_input_v1(record, resolution)
            })
            .ok_or(PrivateOramOwnerJournalError::ExternalRecoveryRequired)?;
        if durable_record.owner_store_incarnation_digest
            != superblock.owner_store_incarnation_digest
            || fence.as_ref().is_some_and(|record| {
                record.fence_record_digest != durable_record.fence_record_digest
                    || record.challenge.reserved_terminal_intent_key
                        != durable_record.reserved_terminal_intent_key
            })
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let (intents_path, _) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        if path_entry_exists(&intents_path.join(&durable_record.reserved_terminal_intent_key))? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let mut release = PrivateOramOwnerReservationAbortReleaseRecordV1 {
            version: PRESTAGE_RESERVATION_ABORT_RELEASE_VERSION,
            resolution_record_digest: durable_record.resolution_record_digest.clone(),
            fence_record_digest: durable_record.fence_record_digest.clone(),
            abort_release_authority_digest: abort_release_authority_digest.to_string(),
            owner_store_incarnation_digest: durable_record.owner_store_incarnation_digest.clone(),
            owner_store_binding_digest: durable_record.owner_store_binding_digest.clone(),
            release_marker_digest: String::new(),
        };
        release.release_marker_digest =
            private_oram_owner_reservation_abort_release_digest_v1(&release)?;
        let existing_release = self.load_reservation_abort_release_locked(&root, &fence_dir)?;
        if fence.is_none() && existing_release.is_none() {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }
        if existing_release
            .as_ref()
            .is_some_and(|existing| existing != &release)
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        if existing_release.is_none() {
            let bytes = encode_private_oram_owner_reservation_abort_release_v1(&release)?;
            self.publish_immutable_file_locked(
                &root,
                &fence_dir,
                &fence_path,
                PRESTAGE_RESERVATION_ABORT_RELEASE_FILE,
                &bytes,
                PRESTAGE_MAX_RESERVATION_ABORT_RELEASE_BYTES,
            )?;
            sync_open_directory(&fence_dir)
                .and_then(|()| sync_open_directory(&root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }
        if fence.is_some() && consume_finalized_reservation_handoff {
            self.remove_reservation_fence_keep_resolution_locked(
                &root,
                &fence_dir,
                &durable_record,
            )?;
        }
        let retained_fence = self.load_reservation_fence_locked(&root, &fence_dir)?;
        if retained_fence.is_some() == consume_finalized_reservation_handoff
            || self
                .load_reservation_resolution_locked(&root, &fence_dir)?
                .as_ref()
                != Some(&durable_record)
            || self
                .load_reservation_abort_release_locked(&root, &fence_dir)?
                .as_ref()
                != Some(&release)
        {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        Ok(PrivateOramOwnerAbortReleasedReservationResolutionV1 {
            durable_resolution: PrivateOramOwnerDurableReservationResolutionV1 {
                owner_store_incarnation_digest: durable_record
                    .owner_store_incarnation_digest
                    .clone(),
                owner_store_binding_digest: durable_record.owner_store_binding_digest.clone(),
                record: durable_record,
            },
            abort_release_authority_digest: release.abort_release_authority_digest,
            abort_release_marker_digest: release.release_marker_digest,
        })
    }

    /// Applies one consensus-authorized negative admission cleanup. The owner signature callback
    /// runs outside filesystem locks; its result is revalidated against a freshly classified
    /// local state before any terminal marker is published.
    pub fn cleanup_with_authorization_v2<F>(
        &self,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        sign_receipt: F,
    ) -> Result<CommittedPrivateOramOwnerCleanupReceiptV2, PrivateOramOwnerJournalError>
    where
        F: FnOnce(
            &PrivateOramOwnerCleanupReceiptV1,
        )
            -> Result<SignedPrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerJournalError>,
    {
        let unsigned = match self.plan_cleanup_v2(authorization)? {
            PlannedPrivateOramOwnerCleanupV2::Existing(committed) => return Ok(committed),
            PlannedPrivateOramOwnerCleanupV2::Unsigned(unsigned) => unsigned,
        };
        let signed = sign_receipt(&unsigned)?;
        validate_signed_private_oram_owner_cleanup_receipt_v1(&signed, authorization)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("cleanup_receipt"))?;
        self.apply_signed_cleanup_v2(authorization, &signed)
    }

    fn plan_cleanup_v2(
        &self,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
    ) -> Result<PlannedPrivateOramOwnerCleanupV2, PrivateOramOwnerJournalError> {
        self.ensure_layout_for_authenticated_cleanup_v2()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        self.require_no_active_reservation_fence_locked(&root, None)?;
        let superblock = self.load_superblock_locked(&root)?;
        let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
        let canonical_root = owner_journal.ensure_root()?;
        let _canonical_lock = lock_private_journal_root(&canonical_root)?;
        if let Some(terminal) = self.load_terminal_marker_locked(
            &root,
            authorization.authorization().target.intent_key.as_str(),
        )? {
            let committed = self.replay_cleanup_terminal_locked(
                lifecycle_lock.root_lock(),
                authorization,
                &terminal,
                &superblock,
                &owner_journal,
                &canonical_root,
            )?;
            return Ok(PlannedPrivateOramOwnerCleanupV2::Existing(committed));
        }
        self.require_terminal_capacity_locked(
            &root,
            authorization.authorization().target.intent_key.as_str(),
        )?;
        let observed = self.validate_cleanup_prestate_locked(
            &root,
            &superblock,
            authorization,
            &owner_journal,
            &canonical_root,
        )?;
        let receipt = private_oram_owner_cleanup_receipt_v1(authorization, observed)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidTransition)?;
        Ok(PlannedPrivateOramOwnerCleanupV2::Unsigned(receipt))
    }

    fn apply_signed_cleanup_v2(
        &self,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        signed: &SignedPrivateOramOwnerCleanupReceiptV1,
    ) -> Result<CommittedPrivateOramOwnerCleanupReceiptV2, PrivateOramOwnerJournalError> {
        self.apply_signed_cleanup_inner_v2(authorization, signed, false)
    }

    #[cfg(test)]
    pub(crate) fn leave_cleanup_after_terminal_for_test_v2<F>(
        &self,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        sign_receipt: F,
    ) -> Result<SignedPrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerJournalError>
    where
        F: FnOnce(
            &PrivateOramOwnerCleanupReceiptV1,
        )
            -> Result<SignedPrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerJournalError>,
    {
        let unsigned = match self.plan_cleanup_v2(authorization)? {
            PlannedPrivateOramOwnerCleanupV2::Existing(_) => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            PlannedPrivateOramOwnerCleanupV2::Unsigned(unsigned) => unsigned,
        };
        let signed = sign_receipt(&unsigned)?;
        self.apply_signed_cleanup_inner_v2(authorization, &signed, true)
            .map(|committed| committed.signed_receipt)
    }

    fn apply_signed_cleanup_inner_v2(
        &self,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        signed: &SignedPrivateOramOwnerCleanupReceiptV1,
        stop_after_terminal: bool,
    ) -> Result<CommittedPrivateOramOwnerCleanupReceiptV2, PrivateOramOwnerJournalError> {
        validate_signed_private_oram_owner_cleanup_receipt_v1(signed, authorization)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("cleanup_receipt"))?;
        self.ensure_layout_for_authenticated_cleanup_v2()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let lifecycle_lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        self.require_no_active_reservation_fence_locked(&root, None)?;
        let superblock = self.load_superblock_locked(&root)?;
        let intent_key = authorization.authorization().target.intent_key.as_str();
        let owner_journal = PrivateOramOwnerJournal::new(&self.primary_hnsw_store_root);
        let canonical_root = owner_journal.ensure_root()?;
        let _canonical_lock = lock_private_journal_root(&canonical_root)?;
        if let Some(terminal) = self.load_terminal_marker_locked(&root, intent_key)? {
            return self.replay_cleanup_terminal_locked(
                lifecycle_lock.root_lock(),
                authorization,
                &terminal,
                &superblock,
                &owner_journal,
                &canonical_root,
            );
        }
        self.require_terminal_capacity_locked(&root, intent_key)?;
        let observed = self.validate_cleanup_prestate_locked(
            &root,
            &superblock,
            authorization,
            &owner_journal,
            &canonical_root,
        )?;
        let expected = private_oram_owner_cleanup_receipt_v1(authorization, observed)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidTransition)?;
        if signed.receipt != expected {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let terminal = private_oram_owner_cleanup_lifecycle_marker_v2(authorization, signed)?;
        encode_private_oram_owner_lifecycle_marker_v2(&terminal)?;
        let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let destination = match terminal.kind {
            PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => PRESTAGE_RETIRED_DIR,
            PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => PRESTAGE_QUARANTINE_DIR,
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        };
        if let Err(error) = self.publish_terminal_then_move_intent_locked(
            &root,
            &intents,
            intent_key,
            &terminal,
            destination,
            false,
        ) {
            return Err(match error {
                PrivateOramOwnerJournalError::Indeterminate => {
                    PrivateOramOwnerJournalError::IndeterminateTerminalCommit
                }
                error => error,
            });
        }
        if stop_after_terminal {
            return Ok(committed_private_oram_owner_cleanup_receipt_v2(
                signed,
                &terminal,
                PrivateOramOwnerCleanupRepairStateV2::NeedsSuperblockReconciliation,
            ));
        }
        if self
            .replace_superblock_locked(
                lifecycle_lock.root_lock(),
                &superblock,
                &signed.receipt.new_lifecycle_state,
            )
            .is_err()
        {
            return Ok(committed_private_oram_owner_cleanup_receipt_v2(
                signed,
                &terminal,
                PrivateOramOwnerCleanupRepairStateV2::NeedsSuperblockReconciliation,
            ));
        }
        if self
            .finish_terminal_payload_move_locked(
                &root,
                &intents,
                intent_key,
                &terminal,
                destination,
            )
            .is_err()
        {
            return Ok(committed_private_oram_owner_cleanup_receipt_v2(
                signed,
                &terminal,
                PrivateOramOwnerCleanupRepairStateV2::NeedsPayloadRelocation,
            ));
        }
        Ok(committed_private_oram_owner_cleanup_receipt_v2(
            signed,
            &terminal,
            PrivateOramOwnerCleanupRepairStateV2::Complete,
        ))
    }

    fn replay_cleanup_terminal_locked(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        terminal: &PrivateOramOwnerLifecycleMarkerV2,
        superblock: &PrivateOramOwnerPrestageSuperblockV2,
        owner_journal: &PrivateOramOwnerJournal,
        canonical_root: &File,
    ) -> Result<CommittedPrivateOramOwnerCleanupReceiptV2, PrivateOramOwnerJournalError> {
        root_lock.require_exclusive()?;
        let root = root_lock.root;
        let signed = terminal
            .signed_cleanup_receipt
            .as_ref()
            .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
        validate_signed_private_oram_owner_cleanup_receipt_v1(signed, authorization)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidTransition)?;
        if *terminal != private_oram_owner_cleanup_lifecycle_marker_v2(authorization, signed)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        self.validate_cleanup_canonical_absence_locked(
            authorization,
            owner_journal,
            canonical_root,
        )?;
        self.validate_terminal_payload_state_locked(root, terminal)?;
        let installed_state = superblock.lifecycle_state()?;
        if installed_state == signed.receipt.previous_lifecycle_state {
            if self
                .replace_superblock_locked(
                    root_lock,
                    superblock,
                    &signed.receipt.new_lifecycle_state,
                )
                .is_err()
            {
                return Ok(committed_private_oram_owner_cleanup_receipt_v2(
                    signed,
                    terminal,
                    PrivateOramOwnerCleanupRepairStateV2::NeedsSuperblockReconciliation,
                ));
            }
        } else if installed_state != signed.receipt.new_lifecycle_state {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }
        let (_, intents) = self.open_prestage_child_locked(root, PRESTAGE_INTENTS_DIR)?;
        let destination = match terminal.kind {
            PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => PRESTAGE_RETIRED_DIR,
            PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => PRESTAGE_QUARANTINE_DIR,
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        };
        if self
            .finish_terminal_payload_move_locked(
                root,
                &intents,
                &terminal.intent_key,
                terminal,
                destination,
            )
            .is_err()
        {
            return Ok(committed_private_oram_owner_cleanup_receipt_v2(
                signed,
                terminal,
                PrivateOramOwnerCleanupRepairStateV2::NeedsPayloadRelocation,
            ));
        }
        Ok(committed_private_oram_owner_cleanup_receipt_v2(
            signed,
            terminal,
            PrivateOramOwnerCleanupRepairStateV2::Complete,
        ))
    }

    fn validate_cleanup_prestate_locked(
        &self,
        root: &File,
        superblock: &PrivateOramOwnerPrestageSuperblockV2,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        owner_journal: &PrivateOramOwnerJournal,
        canonical_root: &File,
    ) -> Result<PrivateOramOwnerCleanupObservedPrestateV1, PrivateOramOwnerJournalError> {
        if authorization
            .authorization()
            .target
            .expected_lifecycle_state
            != superblock.lifecycle_state()?
            || authorization.authorization().target.owner_peer_id == 0
            || authorization.authorization().target.intent_key.is_empty()
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        self.validate_cleanup_canonical_absence_locked(
            authorization,
            owner_journal,
            canonical_root,
        )?;
        let authorization = authorization.authorization();

        let (intents_path, intents) =
            self.open_prestage_child_locked(root, PRESTAGE_INTENTS_DIR)?;
        let (retired_path, _) = self.open_prestage_child_locked(root, PRESTAGE_RETIRED_DIR)?;
        let (quarantine_path, _) =
            self.open_prestage_child_locked(root, PRESTAGE_QUARANTINE_DIR)?;
        let intent_key = authorization.target.intent_key.as_str();
        let in_intents = path_entry_exists(&intents_path.join(intent_key))?;
        let in_retired = path_entry_exists(&retired_path.join(intent_key))?;
        let in_quarantine = path_entry_exists(&quarantine_path.join(intent_key))?;
        if in_retired || in_quarantine {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        if !in_intents {
            if authorization.target.prestage_receipt_digest.is_some()
                || authorization.target.intent_marker_digest.is_some()
                || authorization
                    .target
                    .owner_journal_descriptor_digest
                    .is_some()
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            return Ok(PrivateOramOwnerCleanupObservedPrestateV1::Absent);
        }
        let loaded = self.load_intent_locked(root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?;
        if loaded.state() != PrivateOramOwnerLocalIntentStateV2::Intent
            || loaded.receipt.collection_id != authorization.authority.collection_id
            || loaded.receipt.mutation_id != authorization.attempt.mutation_id
            || loaded.receipt.mutation_digest != authorization.attempt.mutation_digest
            || loaded.receipt.expected_aggregate_digest
                != authorization.attempt.expected_aggregate_digest
            || loaded.receipt.lease_generation != authorization.attempt.lease_generation
            || loaded.receipt.writer_fence != authorization.attempt.writer_fence
            || loaded.receipt.owner_peer_id != authorization.target.owner_peer_id
            || loaded.receipt.parent_descriptor_digest
                != authorization.target.parent_descriptor_digest
            || loaded.receipt.parent_lease_acquired_record_digest
                != authorization.target.parent_lease_acquired_record_digest
            || loaded.receipt.owner_roster_digest != authorization.authority.owner_roster_digest
            || loaded.receipt.activation_registry_generation
                != authorization.authority.activation_registry_generation
            || loaded.receipt.activation_manifest_digest
                != authorization.authority.activation_manifest_digest
            || loaded.receipt.package_sha256 != authorization.target.package_sha256
            || loaded.receipt.package_len != authorization.target.package_len
            || loaded.package_bytes.len() as u64 != authorization.target.package_len
            || loaded.receipt.owner_request_digest != authorization.target.owner_request_digest
            || authorization.target.prestage_receipt_digest.as_deref()
                != Some(loaded.receipt.receipt_digest.as_str())
            || authorization.target.intent_marker_digest.as_deref()
                != Some(loaded.intent_marker.marker_digest.as_str())
            || authorization
                .target
                .owner_journal_descriptor_digest
                .as_deref()
                != Some(loaded.receipt.owner_journal_descriptor_digest.as_str())
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(PrivateOramOwnerCleanupObservedPrestateV1::Intent)
    }

    fn validate_cleanup_canonical_absence_locked(
        &self,
        authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
        owner_journal: &PrivateOramOwnerJournal,
        canonical_root: &File,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let authorization = authorization.authorization();
        if PrivateOramOwnerJournal::stable_root_entry_from(canonical_root)?
            == StableRootEntry::Active
        {
            let canonical = owner_journal
                .load_active_structural_from(canonical_root, false, None)?
                .snapshot;
            let descriptor = &canonical.descriptor;
            let exact_descriptor = authorization
                .target
                .owner_journal_descriptor_digest
                .as_deref()
                == Some(descriptor.descriptor_digest.as_str());
            let same_attempt = descriptor.collection_id == authorization.authority.collection_id
                && descriptor.mutation_id == authorization.attempt.mutation_id
                && descriptor.signed_mutation_digest == authorization.attempt.mutation_digest
                && descriptor.parent_descriptor_digest
                    == authorization.target.parent_descriptor_digest
                && descriptor.parent_lease_acquired_record_digest
                    == authorization.target.parent_lease_acquired_record_digest
                && descriptor.owner_peer_id == authorization.target.owner_peer_id
                && descriptor.writer_fence == authorization.attempt.writer_fence;
            if exact_descriptor || same_attempt {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn quarantine_intent_for_test_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        terminal_authority_digest: &str,
    ) -> Result<PrivateOramOwnerLocalIntentStatusV2, PrivateOramOwnerJournalError> {
        self.quarantine_intent_inner_for_test_v2(
            intent_key,
            expected_package_sha256,
            terminal_authority_digest,
            true,
        )
    }

    #[cfg(test)]
    pub(crate) fn leave_quarantine_before_payload_move_for_test_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        terminal_authority_digest: &str,
    ) -> Result<PrivateOramOwnerLocalIntentStatusV2, PrivateOramOwnerJournalError> {
        self.quarantine_intent_inner_for_test_v2(
            intent_key,
            expected_package_sha256,
            terminal_authority_digest,
            false,
        )
    }

    #[cfg(test)]
    fn quarantine_intent_inner_for_test_v2(
        &self,
        intent_key: &str,
        expected_package_sha256: &str,
        terminal_authority_digest: &str,
        move_payload: bool,
    ) -> Result<PrivateOramOwnerLocalIntentStatusV2, PrivateOramOwnerJournalError> {
        validate_digest(expected_package_sha256, "package_sha256")?;
        validate_digest(terminal_authority_digest, "terminal_authority_digest")?;
        self.ensure_layout()?;
        let (owner_temp, root) = self.open_lifecycle_root_namespaces()?;
        let _lock = lock_private_oram_owner_lifecycle_root(
            &owner_temp,
            self.owner_temp_path()?,
            &root,
            &self.root,
        )?;
        let superblock = self.load_superblock_locked(&root)?;
        if let Some(existing) = self.load_terminal_marker_locked(&root, intent_key)? {
            if existing.kind != PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
                || existing.terminal_authority_digest.as_deref() != Some(terminal_authority_digest)
                || existing.package_sha256 != expected_package_sha256
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            self.validate_terminal_payload_state_locked(&root, &existing)?;
            let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
            if move_payload {
                self.finish_terminal_payload_move_locked(
                    &root,
                    &intents,
                    intent_key,
                    &existing,
                    PRESTAGE_QUARANTINE_DIR,
                )?;
            }
            return Ok(PrivateOramOwnerLocalIntentStatusV2 {
                state: PrivateOramOwnerLocalIntentStateV2::Quarantined,
                lifecycle_state: superblock.lifecycle_state()?,
                marker_digest: Some(existing.marker_digest),
            });
        }
        let (_, intents) = self.open_prestage_child_locked(&root, PRESTAGE_INTENTS_DIR)?;
        let loaded = self.load_intent_locked(&root, &intents, PRESTAGE_INTENTS_DIR, intent_key)?;
        if loaded.state() != PrivateOramOwnerLocalIntentStateV2::Intent
            || loaded.receipt.package_sha256 != expected_package_sha256
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let terminal = private_oram_owner_lifecycle_marker_v2(
            PrivateOramOwnerLifecycleMarkerKindV2::Quarantined,
            &superblock.owner_store_incarnation_digest,
            &loaded.receipt,
            Some(terminal_authority_digest),
        )?;
        self.publish_terminal_then_move_intent_locked(
            &root,
            &intents,
            intent_key,
            &terminal,
            PRESTAGE_QUARANTINE_DIR,
            move_payload,
        )?;
        Ok(PrivateOramOwnerLocalIntentStatusV2 {
            state: PrivateOramOwnerLocalIntentStateV2::Quarantined,
            lifecycle_state: superblock.lifecycle_state()?,
            marker_digest: Some(terminal.marker_digest),
        })
    }

    fn ensure_superblock_locked(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        expected_owner_store_incarnation_digest: Option<&str>,
    ) -> Result<PrivateOramOwnerPrestageSuperblockV2, PrivateOramOwnerJournalError> {
        root_lock.require_exclusive()?;
        let root = root_lock.root;
        let superblock_path =
            open_directory_entry_path(root, OsStr::new(PRESTAGE_SUPERBLOCK_FILE))?;
        if path_entry_exists(&superblock_path)? {
            let installed = self.load_superblock_locked(root)?;
            if expected_owner_store_incarnation_digest
                .is_some_and(|expected| installed.owner_store_incarnation_digest != expected)
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            return Ok(installed);
        }
        let owner_store_incarnation_digest = match expected_owner_store_incarnation_digest {
            Some(expected) => {
                validate_digest(expected, "owner_store_incarnation_digest")?;
                expected.to_string()
            }
            None => {
                let mut incarnation_hasher = Sha256::new();
                incarnation_hasher.update(PRESTAGE_OWNER_STORE_INCARNATION_DOMAIN);
                incarnation_hasher.update(uuid::Uuid::new_v4().as_bytes());
                BASE64URL_NOPAD.encode(&incarnation_hasher.finalize())
            }
        };
        let lifecycle =
            private_oram_owner_lifecycle_genesis_state_v1(owner_store_incarnation_digest.clone())
                .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let mut superblock = PrivateOramOwnerPrestageSuperblockV2 {
            version: PRESTAGE_SUPERBLOCK_VERSION,
            owner_store_incarnation_digest,
            lifecycle_generation: lifecycle.generation,
            lifecycle_state_root: lifecycle.state_root,
            minimum_lifecycle_reader_version: lifecycle.minimum_reader_version,
            lifecycle_capability: lifecycle.capability,
            superblock_digest: String::new(),
        };
        superblock.superblock_digest =
            private_oram_owner_prestage_superblock_digest_v2(&superblock)?;
        let bytes = encode_private_oram_owner_prestage_superblock_v2(&superblock)?;
        self.publish_immutable_file_locked(
            root,
            root,
            &self.root,
            PRESTAGE_SUPERBLOCK_FILE,
            &bytes,
            PRESTAGE_MAX_SUPERBLOCK_BYTES,
        )?;
        let installed = self.load_superblock_locked(root)?;
        if installed != superblock {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        Ok(installed)
    }

    fn load_superblock_locked(
        &self,
        root: &File,
    ) -> Result<PrivateOramOwnerPrestageSuperblockV2, PrivateOramOwnerJournalError> {
        validate_open_directory_at_path(root, &self.root)?;
        let superblock_path =
            open_directory_entry_path(root, OsStr::new(PRESTAGE_SUPERBLOCK_FILE))?;
        let (mut pinned, bytes) =
            read_private_file_pinned(&superblock_path, PRESTAGE_MAX_SUPERBLOCK_BYTES)?;
        let superblock = decode_private_oram_owner_prestage_superblock_v2(&bytes)?;
        pinned.validate_exact_contents(&bytes)?;
        Ok(superblock)
    }

    fn require_no_unreconciled_signed_cleanup_locked(
        &self,
        root: &File,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let installed = self.load_superblock_locked(root)?.lifecycle_state()?;
        let mut transitions = BTreeMap::new();
        let (terminals_path, terminals) =
            self.open_prestage_child_locked(root, PRESTAGE_TERMINALS_DIR)?;
        let terminal_names = directory_entry_names_open_bounded(
            &terminals,
            PRESTAGE_MAX_TERMINAL_RECORDS,
            PrivateOramOwnerJournalError::Corrupt,
        )?;
        for terminal_name in terminal_names {
            let intent_key = terminal_name
                .to_str()
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            validate_digest(intent_key, "intent_key")?;
            let terminal = self
                .load_terminal_marker_locked(root, intent_key)?
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            let Some(signed) = terminal.signed_cleanup_receipt else {
                continue;
            };
            let previous = signed.receipt.previous_lifecycle_state;
            let next = &signed.receipt.new_lifecycle_state;
            if next.generation > installed.generation
                || (next.generation == installed.generation && next != &installed)
            {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
            if transitions
                .insert(next.generation, (previous, next.clone()))
                .is_some()
            {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
        }

        let mut reconstructed = private_oram_owner_lifecycle_genesis_state_v1(
            installed.owner_store_incarnation_digest.clone(),
        )
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        for generation in 1..=installed.generation {
            let (previous, next) = transitions
                .get(&generation)
                .ok_or(PrivateOramOwnerJournalError::ExternalRecoveryRequired)?;
            if previous != &reconstructed || next.generation != generation {
                return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
            }
            reconstructed = next.clone();
        }
        if reconstructed != installed {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        }
        validate_open_directory_at_path(&terminals, &terminals_path)?;
        Ok(())
    }

    fn require_terminal_capacity_locked(
        &self,
        root: &File,
        intent_key: &str,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        validate_digest(intent_key, "intent_key")?;
        let (terminals_path, terminals) =
            self.open_prestage_child_locked(root, PRESTAGE_TERMINALS_DIR)?;
        let terminal_names = directory_entry_names_open_bounded(
            &terminals,
            PRESTAGE_MAX_TERMINAL_RECORDS,
            PrivateOramOwnerJournalError::Corrupt,
        )?;
        if terminal_names.len() == PRESTAGE_MAX_TERMINAL_RECORDS
            && !terminal_names.contains(OsStr::new(intent_key))
        {
            return Err(PrivateOramOwnerJournalError::TerminalCapacityExceeded);
        }
        validate_open_directory_at_path(&terminals, &terminals_path)?;
        Ok(())
    }

    fn replace_superblock_locked(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        expected: &PrivateOramOwnerPrestageSuperblockV2,
        lifecycle: &PrivateOramOwnerLifecycleStateV1,
    ) -> Result<PrivateOramOwnerPrestageSuperblockV2, PrivateOramOwnerJournalError> {
        root_lock.require_exclusive()?;
        let root = root_lock.root;
        if self.load_superblock_locked(root)? != *expected
            || lifecycle.owner_store_incarnation_digest != expected.owner_store_incarnation_digest
            || lifecycle.generation <= expected.lifecycle_generation
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let mut replacement = PrivateOramOwnerPrestageSuperblockV2 {
            version: PRESTAGE_SUPERBLOCK_VERSION,
            owner_store_incarnation_digest: lifecycle.owner_store_incarnation_digest.clone(),
            lifecycle_generation: lifecycle.generation,
            lifecycle_state_root: lifecycle.state_root.clone(),
            minimum_lifecycle_reader_version: lifecycle.minimum_reader_version,
            lifecycle_capability: lifecycle.capability.clone(),
            superblock_digest: String::new(),
        };
        replacement.superblock_digest =
            private_oram_owner_prestage_superblock_digest_v2(&replacement)?;
        let bytes = encode_private_oram_owner_prestage_superblock_v2(&replacement)?;
        let (temp_path, temp) = self.open_prestage_child_locked(root, PRESTAGE_TEMP_DIR)?;
        let candidate_name = format!(".superblock-v2-{}", uuid::Uuid::new_v4().simple());
        let candidate_name = OsStr::new(&candidate_name);
        let candidate_path = open_directory_entry_path(&temp, candidate_name)?;
        write_new_private_file(&candidate_path, &bytes, PRESTAGE_MAX_SUPERBLOCK_BYTES)?;
        sync_open_directory(&temp)?;
        validate_open_directory_at_path(root, &self.root)?;
        validate_open_directory_at_path(&temp, &temp_path)?;
        rename_entry_replace(
            &temp,
            candidate_name,
            root,
            OsStr::new(PRESTAGE_SUPERBLOCK_FILE),
        )?;
        sync_open_directory(root)
            .and_then(|()| sync_open_directory(&temp))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        let installed = self
            .load_superblock_locked(root)
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        if installed != replacement {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        validate_open_directory_at_path(root, &self.root)
            .and_then(|()| validate_open_directory_at_path(&temp, &temp_path))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        Ok(installed)
    }

    fn publish_intent_marker_locked(
        &self,
        root: &File,
        intents: &File,
        intent_key: &str,
        marker_file: &str,
        marker: &PrivateOramOwnerLifecycleMarkerV2,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        validate_open_directory_at_path(root, &self.root)?;
        validate_open_directory_at_path(intents, &self.root.join(PRESTAGE_INTENTS_DIR))?;
        if marker.intent_key != intent_key
            || !matches!(
                (marker_file, marker.kind),
                (
                    PRESTAGE_ADOPTION_PENDING_MARKER_FILE,
                    PrivateOramOwnerLifecycleMarkerKindV2::AdoptionPending
                ) | (
                    PRESTAGE_ADOPTED_MARKER_FILE,
                    PrivateOramOwnerLifecycleMarkerKindV2::Adopted
                )
            )
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "lifecycle_marker",
            ));
        }
        let intent_path = open_directory_entry_path(intents, OsStr::new(intent_key))?;
        let intent = open_private_directory(&intent_path)?;
        let bytes = encode_private_oram_owner_lifecycle_marker_v2(marker)?;
        self.publish_immutable_file_locked(
            root,
            &intent,
            &intent_path,
            marker_file,
            &bytes,
            PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
        )?;
        sync_open_directory(intents)
            .and_then(|()| sync_open_directory(root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        Ok(())
    }

    fn publish_immutable_file_locked(
        &self,
        root: &File,
        destination: &File,
        destination_path: &Path,
        file_name: &str,
        bytes: &[u8],
        max_bytes: u64,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        validate_open_directory_at_path(root, &self.root)?;
        validate_open_directory_at_path(destination, destination_path)?;
        let final_path = open_directory_entry_path(destination, OsStr::new(file_name))?;
        if path_entry_exists(&final_path)? {
            let (mut existing, existing_bytes) = read_private_file_pinned(&final_path, max_bytes)?;
            if existing_bytes != bytes {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            existing.validate_exact_contents(bytes)?;
            sync_open_directory(destination)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            return Ok(());
        }
        let (temp_path, temp) = self.open_prestage_child_locked(root, PRESTAGE_TEMP_DIR)?;
        let candidate = tempfile::Builder::new()
            .prefix("lifecycle-file-v2-")
            .tempdir_in(&temp_path)
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
        set_private_directory_permissions(candidate.path())?;
        write_new_private_file(&candidate.path().join(file_name), bytes, max_bytes)?;
        sync_private_directory(candidate.path())?;
        let candidate_directory = open_private_directory(candidate.path())?;
        let installed_candidate = match rename_entry_noreplace(
            &candidate_directory,
            OsStr::new(file_name),
            destination,
            OsStr::new(file_name),
        ) {
            Ok(()) => true,
            Err(PrivateOramOwnerJournalError::ConcurrentMutation) => false,
            Err(error) => return Err(error),
        };
        if installed_candidate {
            sync_open_directory(&candidate_directory)
                .and_then(|()| sync_open_directory(destination))
                .and_then(|()| sync_open_directory(&temp))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        } else {
            sync_open_directory(destination)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }
        let (mut installed, installed_bytes) = read_private_file_pinned(&final_path, max_bytes)
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        if installed_bytes != bytes {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        installed
            .validate_exact_contents(bytes)
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        Ok(())
    }

    fn load_terminal_marker_locked(
        &self,
        root: &File,
        intent_key: &str,
    ) -> Result<Option<PrivateOramOwnerLifecycleMarkerV2>, PrivateOramOwnerJournalError> {
        validate_digest(intent_key, "intent_key")?;
        validate_open_directory_at_path(root, &self.root)?;
        let (terminals_path, terminals) =
            self.open_prestage_child_locked(root, PRESTAGE_TERMINALS_DIR)?;
        let terminal_path = terminals_path.join(intent_key);
        if !path_entry_exists(&terminal_path)? {
            return Ok(None);
        }
        let terminal = open_private_directory(&terminal_path)?;
        let names = directory_entry_names_open(&terminal)?;
        if names != BTreeSet::from([OsStr::new(PRESTAGE_TERMINAL_RECORD_FILE).to_owned()]) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let (mut pinned, bytes) = read_private_file_pinned(
            &terminal_path.join(PRESTAGE_TERMINAL_RECORD_FILE),
            PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
        )?;
        let marker = decode_private_oram_owner_lifecycle_marker_v2(&bytes)?;
        let superblock = self.load_superblock_locked(root)?;
        if marker.intent_key != intent_key
            || marker.owner_store_incarnation_digest != superblock.owner_store_incarnation_digest
            || !matches!(
                marker.kind,
                PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent
                    | PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
            )
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        pinned.validate_exact_contents(&bytes)?;
        validate_open_directory_at_path(&terminal, &terminal_path)?;
        validate_open_directory_at_path(&terminals, &terminals_path)?;
        Ok(Some(marker))
    }

    fn load_reservation_fence_locked(
        &self,
        root: &File,
        fence_dir: &File,
    ) -> Result<Option<PrivateOramOwnerReservationFenceRecordV1>, PrivateOramOwnerJournalError>
    {
        validate_open_directory_at_path(root, &self.root)?;
        let fence_path = self.root.join(PRESTAGE_RESERVATION_FENCE_DIR);
        validate_open_directory_at_path(fence_dir, &fence_path)?;
        validate_private_oram_owner_reservation_fence_entries(fence_dir)?;
        let record_path =
            open_directory_entry_path(fence_dir, OsStr::new(PRESTAGE_RESERVATION_FENCE_FILE))?;
        if !path_entry_exists(&record_path)? {
            return Ok(None);
        }
        let (mut pinned, bytes) =
            read_private_file_pinned(&record_path, PRESTAGE_MAX_RESERVATION_FENCE_BYTES)?;
        let record = decode_private_oram_owner_reservation_fence_v1(&bytes)?;
        pinned.validate_exact_contents(&bytes)?;
        Ok(Some(record))
    }

    fn load_reservation_resolution_locked(
        &self,
        root: &File,
        fence_dir: &File,
    ) -> Result<Option<PrivateOramOwnerReservationResolutionRecordV1>, PrivateOramOwnerJournalError>
    {
        validate_open_directory_at_path(root, &self.root)?;
        let fence_path = self.root.join(PRESTAGE_RESERVATION_FENCE_DIR);
        validate_open_directory_at_path(fence_dir, &fence_path)?;
        validate_private_oram_owner_reservation_fence_entries(fence_dir)?;
        let record_path =
            open_directory_entry_path(fence_dir, OsStr::new(PRESTAGE_RESERVATION_RESOLUTION_FILE))?;
        if !path_entry_exists(&record_path)? {
            return Ok(None);
        }
        let (mut pinned, bytes) =
            read_private_file_pinned(&record_path, PRESTAGE_MAX_RESERVATION_RESOLUTION_BYTES)?;
        let record = decode_private_oram_owner_reservation_resolution_v1(&bytes)?;
        pinned.validate_exact_contents(&bytes)?;
        Ok(Some(record))
    }

    fn load_reservation_abort_release_locked(
        &self,
        root: &File,
        fence_dir: &File,
    ) -> Result<Option<PrivateOramOwnerReservationAbortReleaseRecordV1>, PrivateOramOwnerJournalError>
    {
        validate_open_directory_at_path(root, &self.root)?;
        let fence_path = self.root.join(PRESTAGE_RESERVATION_FENCE_DIR);
        validate_open_directory_at_path(fence_dir, &fence_path)?;
        validate_private_oram_owner_reservation_fence_entries(fence_dir)?;
        let record_path = open_directory_entry_path(
            fence_dir,
            OsStr::new(PRESTAGE_RESERVATION_ABORT_RELEASE_FILE),
        )?;
        if !path_entry_exists(&record_path)? {
            return Ok(None);
        }
        let (mut pinned, bytes) =
            read_private_file_pinned(&record_path, PRESTAGE_MAX_RESERVATION_ABORT_RELEASE_BYTES)?;
        let record = decode_private_oram_owner_reservation_abort_release_v1(&bytes)?;
        pinned.validate_exact_contents(&bytes)?;
        Ok(Some(record))
    }

    fn require_install_authorized_by_reservation_fence_locked(
        &self,
        root: &File,
        intent_key: &str,
    ) -> Result<bool, PrivateOramOwnerJournalError> {
        let (_, fence_dir) =
            self.open_prestage_child_locked(root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        if self
            .load_reservation_abort_release_locked(root, &fence_dir)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let Some(fence) = self.load_reservation_fence_locked(root, &fence_dir)? else {
            if self
                .load_reservation_resolution_locked(root, &fence_dir)?
                .as_ref()
                .is_some_and(|resolution| {
                    resolution.kind == PrivateOramOwnerReservationResolutionKindV1::Cancelled
                })
            {
                self.remove_reservation_resolution_residual_locked(root, &fence_dir)?;
            }
            return Ok(false);
        };
        let resolution = self
            .load_reservation_resolution_locked(root, &fence_dir)?
            .ok_or(PrivateOramOwnerJournalError::ConcurrentMutation)?;
        if resolution.kind != PrivateOramOwnerReservationResolutionKindV1::Finalized
            || resolution.fence_record_digest != fence.fence_record_digest
            || resolution.reserved_terminal_intent_key != intent_key
            || fence.challenge.reserved_terminal_intent_key != intent_key
        {
            return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
        }
        Ok(true)
    }

    fn consume_finalized_reservation_fence_locked(
        &self,
        root: &File,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let (_, fence_dir) =
            self.open_prestage_child_locked(root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        let resolution = self
            .load_reservation_resolution_locked(root, &fence_dir)?
            .ok_or(PrivateOramOwnerJournalError::Indeterminate)?;
        if resolution.kind != PrivateOramOwnerReservationResolutionKindV1::Finalized {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        self.remove_reservation_fence_keep_resolution_locked(root, &fence_dir, &resolution)
    }

    fn remove_reservation_fence_keep_resolution_locked(
        &self,
        root: &File,
        fence_dir: &File,
        resolution: &PrivateOramOwnerReservationResolutionRecordV1,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let fence_path =
            open_directory_entry_path(&fence_dir, OsStr::new(PRESTAGE_RESERVATION_FENCE_FILE))?;
        fs::remove_file(&fence_path).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        sync_open_directory(&fence_dir)
            .and_then(|()| sync_open_directory(root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        if self
            .load_reservation_fence_locked(root, &fence_dir)?
            .is_some()
            || self
                .load_reservation_resolution_locked(root, &fence_dir)?
                .as_ref()
                != Some(resolution)
        {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        Ok(())
    }

    fn remove_reservation_resolution_residual_locked(
        &self,
        root: &File,
        fence_dir: &File,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        if self
            .load_reservation_fence_locked(root, fence_dir)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
        }
        let release_path = open_directory_entry_path(
            fence_dir,
            OsStr::new(PRESTAGE_RESERVATION_ABORT_RELEASE_FILE),
        )?;
        if path_entry_exists(&release_path)? {
            let _ = self
                .load_reservation_abort_release_locked(root, fence_dir)?
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            fs::remove_file(&release_path)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }
        let resolution_path =
            open_directory_entry_path(fence_dir, OsStr::new(PRESTAGE_RESERVATION_RESOLUTION_FILE))?;
        if path_entry_exists(&resolution_path)? {
            let _ = self
                .load_reservation_resolution_locked(root, fence_dir)?
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            fs::remove_file(&resolution_path)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }
        sync_open_directory(fence_dir)
            .and_then(|()| sync_open_directory(root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        Ok(())
    }

    fn require_no_active_reservation_fence_locked(
        &self,
        root: &File,
        retain_finalized_resolution_for_intent: Option<&str>,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let (_, fence_dir) =
            self.open_prestage_child_locked(root, PRESTAGE_RESERVATION_FENCE_DIR)?;
        if self
            .load_reservation_fence_locked(root, &fence_dir)?
            .is_some()
        {
            return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
        }
        if let Some(intent_key) = retain_finalized_resolution_for_intent {
            let retained_resolution = self.load_reservation_resolution_locked(root, &fence_dir)?;
            if retained_resolution.as_ref().is_some_and(|resolution| {
                resolution.kind == PrivateOramOwnerReservationResolutionKindV1::Finalized
                    && resolution.reserved_terminal_intent_key == intent_key
            }) {
                if self
                    .load_reservation_abort_release_locked(root, &fence_dir)?
                    .is_some()
                {
                    return Err(PrivateOramOwnerJournalError::InvalidTransition);
                }
                return Ok(());
            }
        }
        self.remove_reservation_resolution_residual_locked(root, &fence_dir)?;
        Ok(())
    }

    fn validate_terminal_payload_state_locked(
        &self,
        root: &File,
        terminal: &PrivateOramOwnerLifecycleMarkerV2,
    ) -> Result<Option<LoadedPrivateOramOwnerPrestageIntentV2>, PrivateOramOwnerJournalError> {
        validate_open_directory_at_path(root, &self.root)?;
        let (intents_path, intents) =
            self.open_prestage_child_locked(root, PRESTAGE_INTENTS_DIR)?;
        let (retired_path, retired) =
            self.open_prestage_child_locked(root, PRESTAGE_RETIRED_DIR)?;
        let (quarantine_path, quarantine) =
            self.open_prestage_child_locked(root, PRESTAGE_QUARANTINE_DIR)?;
        let in_intents = path_entry_exists(&intents_path.join(&terminal.intent_key))?;
        let in_retired = path_entry_exists(&retired_path.join(&terminal.intent_key))?;
        let in_quarantine = path_entry_exists(&quarantine_path.join(&terminal.intent_key))?;
        if terminal
            .signed_cleanup_receipt
            .as_ref()
            .is_some_and(|signed| {
                signed.receipt.terminal_state
                    == PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent
            })
        {
            if in_intents || in_retired || in_quarantine {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
            validate_open_directory_at_path(&intents, &intents_path)?;
            validate_open_directory_at_path(&retired, &retired_path)?;
            validate_open_directory_at_path(&quarantine, &quarantine_path)?;
            validate_open_directory_at_path(root, &self.root)?;
            return Ok(None);
        }
        let (parent, parent_name) = match (terminal.kind, in_intents, in_retired, in_quarantine) {
            (PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent, true, false, false) => {
                (&intents, PRESTAGE_INTENTS_DIR)
            }
            (PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent, false, true, false) => {
                (&retired, PRESTAGE_RETIRED_DIR)
            }
            (PrivateOramOwnerLifecycleMarkerKindV2::Quarantined, true, false, false) => {
                (&intents, PRESTAGE_INTENTS_DIR)
            }
            (PrivateOramOwnerLifecycleMarkerKindV2::Quarantined, false, false, true) => {
                (&quarantine, PRESTAGE_QUARANTINE_DIR)
            }
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        };
        let loaded = self.load_intent_locked(root, parent, parent_name, &terminal.intent_key)?;
        let payload_state_matches = loaded.state() == PrivateOramOwnerLocalIntentStateV2::Intent
            || (terminal.kind == PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
                && terminal.signed_cleanup_receipt.is_none()
                && loaded.state() == PrivateOramOwnerLocalIntentStateV2::AdoptionPending
                && terminal.terminal_authority_digest.as_deref()
                    == Some(loaded.current_marker().marker_digest.as_str()));
        if !payload_state_matches
            || !private_oram_owner_terminal_matches_receipt_v2(terminal, &loaded.receipt)?
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        validate_open_directory_at_path(&intents, &intents_path)?;
        validate_open_directory_at_path(&retired, &retired_path)?;
        validate_open_directory_at_path(&quarantine, &quarantine_path)?;
        validate_open_directory_at_path(root, &self.root)?;
        Ok(Some(loaded))
    }

    fn publish_terminal_then_move_intent_locked(
        &self,
        root: &File,
        intents: &File,
        intent_key: &str,
        terminal: &PrivateOramOwnerLifecycleMarkerV2,
        destination_name: &str,
        move_payload: bool,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        if terminal.intent_key != intent_key
            || !matches!(
                (terminal.kind, destination_name),
                (
                    PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent,
                    PRESTAGE_RETIRED_DIR
                ) | (
                    PrivateOramOwnerLifecycleMarkerKindV2::Quarantined,
                    PRESTAGE_QUARANTINE_DIR
                )
            )
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput("terminal"));
        }
        validate_open_directory_at_path(root, &self.root)?;
        let (terminals_path, terminals) =
            self.open_prestage_child_locked(root, PRESTAGE_TERMINALS_DIR)?;
        let terminal_path = terminals_path.join(intent_key);
        if let Some(existing) = self.load_terminal_marker_locked(root, intent_key)? {
            if existing != *terminal {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            sync_open_directory(&terminals)
                .and_then(|()| sync_open_directory(root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        } else {
            self.require_terminal_capacity_locked(root, intent_key)?;
            let (temp_path, temp) = self.open_prestage_child_locked(root, PRESTAGE_TEMP_DIR)?;
            let candidate = tempfile::Builder::new()
                .prefix("terminal-v2-")
                .tempdir_in(&temp_path)
                .map_err(|_| PrivateOramOwnerJournalError::Io)?;
            set_private_directory_permissions(candidate.path())?;
            let bytes = encode_private_oram_owner_lifecycle_marker_v2(terminal)?;
            write_new_private_file(
                &candidate.path().join(PRESTAGE_TERMINAL_RECORD_FILE),
                &bytes,
                PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
            )?;
            sync_private_directory(candidate.path())?;
            let candidate_directory = open_private_directory(candidate.path())?;
            let candidate_name = candidate
                .path()
                .file_name()
                .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
            let installed_candidate = match rename_entry_noreplace(
                &temp,
                candidate_name,
                &terminals,
                OsStr::new(intent_key),
            ) {
                Ok(()) => true,
                Err(PrivateOramOwnerJournalError::ConcurrentMutation) => false,
                Err(error) => return Err(error),
            };
            sync_open_directory(&temp)
                .and_then(|()| sync_open_directory(&terminals))
                .and_then(|()| sync_open_directory(root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            let installed = self
                .load_terminal_marker_locked(root, intent_key)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?
                .ok_or(PrivateOramOwnerJournalError::Indeterminate)?;
            if installed != *terminal {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            if installed_candidate {
                let installed_directory = open_private_directory(&terminal_path)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                ensure_same_open_inode(&candidate_directory, &installed_directory)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
        }
        if move_payload {
            self.finish_terminal_payload_move_locked(
                root,
                intents,
                intent_key,
                terminal,
                destination_name,
            )?;
        } else {
            self.validate_terminal_payload_state_locked(root, terminal)?;
        }
        validate_open_directory_at_path(&terminals, &terminals_path)
            .and_then(|()| validate_open_directory_at_path(root, &self.root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        let _ = terminal_path;
        Ok(())
    }

    fn finish_terminal_payload_move_locked(
        &self,
        root: &File,
        intents: &File,
        intent_key: &str,
        terminal: &PrivateOramOwnerLifecycleMarkerV2,
        destination_name: &str,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        if terminal.intent_key != intent_key
            || !matches!(
                (terminal.kind, destination_name),
                (
                    PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent,
                    PRESTAGE_RETIRED_DIR
                ) | (
                    PrivateOramOwnerLifecycleMarkerKindV2::Quarantined,
                    PRESTAGE_QUARANTINE_DIR
                )
            )
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput("terminal"));
        }
        if terminal
            .signed_cleanup_receipt
            .as_ref()
            .is_some_and(|signed| {
                signed.receipt.terminal_state
                    == PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent
            })
        {
            self.validate_terminal_payload_state_locked(root, terminal)?;
            return Ok(());
        }
        self.validate_terminal_payload_state_locked(root, terminal)?;
        let (destination_path, destination) =
            self.open_prestage_child_locked(root, destination_name)?;
        let source_path = open_directory_entry_path(intents, OsStr::new(intent_key))?;
        let moved_path = destination_path.join(intent_key);
        let source_exists = path_entry_exists(&source_path)?;
        let moved_exists = path_entry_exists(&moved_path)?;
        match (source_exists, moved_exists) {
            (true, false) => {
                rename_entry_noreplace(
                    intents,
                    OsStr::new(intent_key),
                    &destination,
                    OsStr::new(intent_key),
                )?;
                sync_open_directory(intents)
                    .and_then(|()| sync_open_directory(&destination))
                    .and_then(|()| sync_open_directory(root))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
            (false, true) => {
                sync_open_directory(intents)
                    .and_then(|()| sync_open_directory(&destination))
                    .and_then(|()| sync_open_directory(root))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
            (true, true) | (false, false) => {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
        self.validate_terminal_payload_state_locked(root, terminal)?;
        Ok(())
    }

    fn open_prestage_child_locked(
        &self,
        root: &File,
        name: &str,
    ) -> Result<(PathBuf, File), PrivateOramOwnerJournalError> {
        if !matches!(
            name,
            PRESTAGE_INTENTS_DIR
                | PRESTAGE_TEMP_DIR
                | PRESTAGE_TERMINALS_DIR
                | PRESTAGE_RETIRED_DIR
                | PRESTAGE_QUARANTINE_DIR
                | PRESTAGE_RESERVATION_FENCE_DIR
        ) {
            return Err(PrivateOramOwnerJournalError::InvalidInput("prestage_child"));
        }
        validate_open_directory_at_path(root, &self.root)?;
        let anchored = open_directory_entry_path(root, OsStr::new(name))?;
        let child = open_private_directory(&anchored)?;
        validate_open_directory_at_path(&child, &self.root.join(name))?;
        Ok((anchored, child))
    }

    fn owner_temp_path(&self) -> Result<&Path, PrivateOramOwnerJournalError> {
        self.root
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)
    }

    fn open_lifecycle_root_namespaces(&self) -> Result<(File, File), PrivateOramOwnerJournalError> {
        let owner_temp_path = self.owner_temp_path()?;
        let owner_temp = open_private_directory(owner_temp_path)?;
        let anchored_root = open_directory_entry_path(&owner_temp, OsStr::new(PRESTAGE_ROOT_DIR))?;
        let root = open_private_directory(&anchored_root)?;
        validate_open_directory_at_path(&owner_temp, owner_temp_path)?;
        validate_open_directory_at_path(&root, &self.root)?;
        Ok((owner_temp, root))
    }

    fn ensure_layout(&self) -> Result<(), PrivateOramOwnerJournalError> {
        self.ensure_layout_inner_v2(true, None).map(drop)
    }

    fn ensure_layout_for_authenticated_cleanup_v2(
        &self,
    ) -> Result<(), PrivateOramOwnerJournalError> {
        self.ensure_layout_inner_v2(false, None).map(drop)
    }

    fn ensure_layout_inner_v2(
        &self,
        reject_unreconciled_cleanup: bool,
        expected_owner_store_incarnation_digest: Option<&str>,
    ) -> Result<PrivateOramOwnerLifecycleStateV1, PrivateOramOwnerJournalError> {
        let owner_temp = self.owner_temp_path()?;
        let owner_temp_file = open_private_directory(owner_temp)?;
        let parent_lock = lock_private_journal_root(&owner_temp_file)?;
        let anchored_root =
            open_directory_entry_path(&owner_temp_file, OsStr::new(PRESTAGE_ROOT_DIR))?;
        create_private_directory(&anchored_root)?;
        sync_open_directory(&owner_temp_file)?;
        validate_open_directory_at_path(&owner_temp_file, owner_temp)?;
        let root = open_private_directory(&anchored_root)?;
        validate_open_directory_at_path(&root, &self.root)?;
        for name in [
            PRESTAGE_INTENTS_DIR,
            PRESTAGE_TEMP_DIR,
            PRESTAGE_TERMINALS_DIR,
            PRESTAGE_RETIRED_DIR,
            PRESTAGE_QUARANTINE_DIR,
            PRESTAGE_RESERVATION_FENCE_DIR,
        ] {
            let child_path = open_directory_entry_path(&root, OsStr::new(name))?;
            create_private_directory(&child_path)?;
            sync_private_directory(&child_path)?;
        }
        sync_open_directory(&root)?;
        validate_open_directory_at_path(&root, &self.root)?;
        let root_lock = lock_private_journal_root(&root)?;
        let lifecycle_lock = PrivateOramOwnerLifecycleRootLock {
            root_lock,
            parent_lock,
            expected_parent: owner_temp,
            expected_root: &self.root,
        };
        lifecycle_lock.require_exclusive()?;
        let superblock = self.ensure_superblock_locked(
            lifecycle_lock.root_lock(),
            expected_owner_store_incarnation_digest,
        )?;
        if reject_unreconciled_cleanup {
            self.require_no_unreconciled_signed_cleanup_locked(&root)?;
        }
        validate_private_oram_owner_prestage_root_entries(&root)?;
        superblock.lifecycle_state()
    }

    fn load_intent_locked(
        &self,
        root: &File,
        parent: &File,
        parent_name: &str,
        intent_key: &str,
    ) -> Result<LoadedPrivateOramOwnerPrestageIntentV2, PrivateOramOwnerJournalError> {
        validate_digest(intent_key, "intent_key")?;
        if !matches!(
            parent_name,
            PRESTAGE_INTENTS_DIR | PRESTAGE_RETIRED_DIR | PRESTAGE_QUARANTINE_DIR
        ) {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "prestage_parent",
            ));
        }
        validate_open_directory_at_path(root, &self.root)?;
        validate_open_directory_at_path(parent, &self.root.join(parent_name))?;
        let intent_path = open_directory_entry_path(parent, OsStr::new(intent_key))?;
        let intent = open_private_directory(&intent_path)?;
        validate_open_directory_at_path(&intent, &intent_path)?;
        validate_private_oram_owner_prestage_intent_entries(&intent_path)?;
        let (mut package_file, package_bytes) = read_private_file_pinned(
            &intent_path.join(PRESTAGE_PACKAGE_FILE),
            PRESTAGE_MAX_PACKAGE_BYTES,
        )?;
        let (mut descriptor_file, descriptor_bytes) =
            read_private_file_pinned(&intent_path.join(DESCRIPTOR_FILE), MAX_DESCRIPTOR_BYTES)?;
        let (mut final_bucket_file, final_bucket_bytes) = read_private_file_pinned(
            &intent_path.join(FINAL_BUCKETS_FILE),
            MAX_FINAL_BUCKET_FRAME_BYTES,
        )?;
        let (mut state_file, state_bytes) =
            read_private_file_pinned(&intent_path.join(STATE_FILE), MAX_STATE_BYTES)?;
        let (mut receipt_file, receipt_bytes) = read_private_file_pinned(
            &intent_path.join(PRESTAGE_RECEIPT_FILE),
            PRESTAGE_MAX_RECEIPT_BYTES,
        )?;
        let (mut intent_marker_file, intent_marker_bytes) = read_private_file_pinned(
            &intent_path.join(PRESTAGE_INTENT_MARKER_FILE),
            PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
        )?;
        let mut pending_marker_file = None;
        let mut pending_marker_bytes = None;
        if path_entry_exists(&intent_path.join(PRESTAGE_ADOPTION_PENDING_MARKER_FILE))? {
            let (file, bytes) = read_private_file_pinned(
                &intent_path.join(PRESTAGE_ADOPTION_PENDING_MARKER_FILE),
                PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
            )?;
            pending_marker_file = Some(file);
            pending_marker_bytes = Some(bytes);
        }
        let mut adopted_marker_file = None;
        let mut adopted_marker_bytes = None;
        if path_entry_exists(&intent_path.join(PRESTAGE_ADOPTED_MARKER_FILE))? {
            let (file, bytes) = read_private_file_pinned(
                &intent_path.join(PRESTAGE_ADOPTED_MARKER_FILE),
                PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES,
            )?;
            adopted_marker_file = Some(file);
            adopted_marker_bytes = Some(bytes);
        }
        let package = decode_private_oram_owner_prestage_package_v2(&package_bytes)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let receipt = decode_private_oram_owner_prestage_receipt_v2(&receipt_bytes)?;
        let prepared =
            ValidatedOwnerJournal::decode(descriptor_bytes, final_bucket_bytes, state_bytes, None)?;
        let superblock = self.load_superblock_locked(root)?;
        let intent_marker = decode_private_oram_owner_lifecycle_marker_v2(&intent_marker_bytes)?;
        let expected_intent_marker = private_oram_owner_lifecycle_marker_v2(
            PrivateOramOwnerLifecycleMarkerKindV2::Intent,
            &superblock.owner_store_incarnation_digest,
            &receipt,
            None,
        )?;
        let adoption_pending_marker = pending_marker_bytes
            .as_deref()
            .map(decode_private_oram_owner_lifecycle_marker_v2)
            .transpose()?;
        let adopted_marker = adopted_marker_bytes
            .as_deref()
            .map(decode_private_oram_owner_lifecycle_marker_v2)
            .transpose()?;
        if receipt.intent_key != intent_key
            || receipt.package_sha256 != digest_string(&package_bytes)
            || usize::try_from(receipt.package_len).ok() != Some(package_bytes.len())
            || receipt.collection_id != package.collection_id
            || receipt.mutation_id != package.mutation_id
            || receipt.mutation_digest != package.mutation_digest
            || receipt.expected_aggregate_digest != package.expected_aggregate_digest
            || receipt.lease_generation != package.lease_generation
            || receipt.writer_fence != package.writer_fence
            || receipt.owner_peer_id != package.owner_peer_id
            || receipt.parent_descriptor_digest != package.parent_descriptor_digest
            || receipt.parent_lease_acquired_record_digest
                != package.parent_lease_acquired_record_digest
            || receipt.owner_roster_digest != package.owner_roster_digest
            || receipt.activation_registry_generation != package.activation_registry_generation
            || receipt.activation_manifest_digest != package.activation_manifest_digest
            || receipt.owner_journal_descriptor_digest
                != prepared.snapshot.descriptor.descriptor_digest
            || receipt.prepared_state_digest != prepared.snapshot.state.state_digest
            || intent_marker != expected_intent_marker
            || adoption_pending_marker.as_ref().is_some_and(|marker| {
                private_oram_owner_lifecycle_marker_v2(
                    PrivateOramOwnerLifecycleMarkerKindV2::AdoptionPending,
                    &superblock.owner_store_incarnation_digest,
                    &receipt,
                    None,
                )
                .map_or(true, |expected| marker != &expected)
            })
            || adopted_marker.as_ref().is_some_and(|marker| {
                private_oram_owner_lifecycle_marker_v2(
                    PrivateOramOwnerLifecycleMarkerKindV2::Adopted,
                    &superblock.owner_store_incarnation_digest,
                    &receipt,
                    None,
                )
                .map_or(true, |expected| marker != &expected)
            })
            || (adopted_marker.is_some() && adoption_pending_marker.is_none())
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        package_file.validate_exact_contents(&package_bytes)?;
        descriptor_file.validate_exact_contents(&prepared.descriptor_bytes)?;
        final_bucket_file.validate_exact_contents(&prepared.final_bucket_bytes)?;
        state_file.validate_exact_contents(&prepared.state_bytes)?;
        receipt_file.validate_exact_contents(&receipt_bytes)?;
        intent_marker_file.validate_exact_contents(&intent_marker_bytes)?;
        if let (Some(mut file), Some(bytes)) =
            (pending_marker_file, pending_marker_bytes.as_deref())
        {
            file.validate_exact_contents(bytes)?;
        }
        if let (Some(mut file), Some(bytes)) =
            (adopted_marker_file, adopted_marker_bytes.as_deref())
        {
            file.validate_exact_contents(bytes)?;
        }
        validate_open_directory_at_path(&intent, &intent_path)?;
        Ok(LoadedPrivateOramOwnerPrestageIntentV2 {
            package,
            package_bytes,
            receipt,
            prepared,
            intent_marker,
            adoption_pending_marker,
            adopted_marker,
        })
    }
}

fn prepared_evidence_v2(
    token: PrivateOramDurableOwnerPreparedTokenV1,
) -> PrivateOramOwnerPreparedEvidenceV2 {
    PrivateOramOwnerPreparedEvidenceV2 {
        owner_peer_id: token.owner_peer_id,
        journal_descriptor_digest: token.journal_descriptor_digest,
        parent_descriptor_digest: token.parent_descriptor_digest,
        parent_lease_acquired_record_digest: token.parent_lease_acquired_record_digest,
        indexes: token
            .indexes
            .into_iter()
            .map(|index| PrivateOramOwnerPreparedIndexEvidenceV2 {
                kind: index.kind,
                index_name: index.index_name,
                prepared_journal_digest: index.prepared_journal_digest,
            })
            .collect(),
    }
}

fn private_oram_owner_prestage_receipt_v2(
    request: &PrivateOramOwnerPrestageRequestV2,
    prepared: &ValidatedOwnerJournal,
    owner_store_incarnation_digest: &str,
) -> Result<PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerJournalError> {
    validate_digest(
        owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    let mut receipt = PrivateOramOwnerPrestageReceiptV2 {
        version: PRESTAGE_RECEIPT_VERSION,
        intent_key: request.intent_key.clone(),
        collection_id: request.collection_id.clone(),
        mutation_id: request.mutation_id.clone(),
        mutation_digest: request.mutation_digest.clone(),
        expected_aggregate_digest: request.expected_aggregate_digest.clone(),
        lease_generation: request.lease_generation,
        writer_fence: request.writer_fence,
        owner_peer_id: request.owner_peer_id,
        owner_store_incarnation_digest: owner_store_incarnation_digest.to_string(),
        parent_descriptor_digest: request.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: request.parent_lease_acquired_record_digest.clone(),
        owner_roster_digest: request.owner_roster_digest.clone(),
        activation_registry_generation: request.activation_registry_generation,
        activation_manifest_digest: request.activation_manifest_digest.clone(),
        package_sha256: request.package_sha256.clone(),
        package_len: request.package_len,
        owner_request_digest: private_oram_owner_prestage_request_digest_v2(request)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("prestage_request"))?,
        owner_journal_descriptor_digest: prepared.snapshot.descriptor.descriptor_digest.clone(),
        prepared_state_digest: prepared.snapshot.state.state_digest.clone(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = private_oram_owner_prestage_receipt_digest_v2(&receipt)?;
    validate_private_oram_owner_prestage_receipt_v2(&receipt)?;
    Ok(receipt)
}

#[doc(hidden)]
pub fn encode_private_oram_owner_prestage_receipt_v2(
    receipt: &PrivateOramOwnerPrestageReceiptV2,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_prestage_receipt_v2(receipt)?;
    let encoded = serde_json::to_vec(receipt).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() as u64 > PRESTAGE_MAX_RECEIPT_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(encoded)
}

#[doc(hidden)]
pub fn decode_private_oram_owner_prestage_receipt_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerJournalError> {
    if encoded.is_empty() || encoded.len() as u64 > PRESTAGE_MAX_RECEIPT_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let receipt: PrivateOramOwnerPrestageReceiptV2 =
        serde_json::from_slice(encoded).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_private_oram_owner_prestage_receipt_v2(&receipt)?;
    if serde_json::to_vec(&receipt).map_err(|_| PrivateOramOwnerJournalError::Corrupt)? != encoded {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(receipt)
}

#[doc(hidden)]
pub fn encode_private_oram_owner_prepare_parent_v2(
    parent: &PrivateOramOwnerPrepareParentV2,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_owner_prepare_parent_fields(
        parent.parent_descriptor_digest(),
        parent.parent_lease_acquired_record_digest(),
        parent.requirements(),
    )?;
    if parent.owner_peer_id() == 0 {
        return Err(PrivateOramOwnerJournalError::InvalidInput("owner_peer_id"));
    }
    encode_owner_adoption_canonical(parent)
}

#[doc(hidden)]
pub fn decode_private_oram_owner_prepare_parent_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerPrepareParentV2, PrivateOramOwnerJournalError> {
    let parent: PrivateOramOwnerPrepareParentV2 = decode_owner_adoption_canonical(encoded)?;
    validate_owner_prepare_parent_fields(
        parent.parent_descriptor_digest(),
        parent.parent_lease_acquired_record_digest(),
        parent.requirements(),
    )?;
    if parent.owner_peer_id() == 0 {
        return Err(PrivateOramOwnerJournalError::InvalidInput("owner_peer_id"));
    }
    Ok(parent)
}

#[doc(hidden)]
pub fn encode_private_oram_owner_prepared_evidence_v2(
    evidence: &PrivateOramOwnerPreparedEvidenceV2,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_prepared_evidence_v2(evidence)?;
    encode_owner_adoption_canonical(evidence)
}

#[doc(hidden)]
pub fn decode_private_oram_owner_prepared_evidence_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerPreparedEvidenceV2, PrivateOramOwnerJournalError> {
    let evidence: PrivateOramOwnerPreparedEvidenceV2 = decode_owner_adoption_canonical(encoded)?;
    validate_private_oram_owner_prepared_evidence_v2(&evidence)?;
    Ok(evidence)
}

fn validate_private_oram_owner_prepared_evidence_v2(
    evidence: &PrivateOramOwnerPreparedEvidenceV2,
) -> Result<(), PrivateOramOwnerJournalError> {
    if evidence.owner_peer_id == 0
        || evidence.indexes.is_empty()
        || evidence.indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || evidence.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || evidence
            .indexes
            .windows(2)
            .any(|pair| pair[0].kind == pair[1].kind)
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    for digest in [
        &evidence.journal_descriptor_digest,
        &evidence.parent_descriptor_digest,
        &evidence.parent_lease_acquired_record_digest,
    ] {
        validate_digest(digest, "owner_prepared_evidence")?;
    }
    for index in &evidence.indexes {
        validate_resource_id(&index.index_name, "index_name")?;
        validate_digest(&index.prepared_journal_digest, "prepared_journal_digest")?;
    }
    Ok(())
}

fn encode_owner_adoption_canonical<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let encoded = serde_json::to_vec(value).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > MAX_OWNER_ADOPTION_CANONICAL_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(encoded)
}

fn decode_owner_adoption_canonical<T>(encoded: &[u8]) -> Result<T, PrivateOramOwnerJournalError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if encoded.is_empty() || encoded.len() > MAX_OWNER_ADOPTION_CANONICAL_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let value =
        serde_json::from_slice(encoded).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if serde_json::to_vec(&value).map_err(|_| PrivateOramOwnerJournalError::Corrupt)? != encoded {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(value)
}

#[doc(hidden)]
pub fn validate_private_oram_owner_prestage_receipt_v2(
    receipt: &PrivateOramOwnerPrestageReceiptV2,
) -> Result<(), PrivateOramOwnerJournalError> {
    if receipt.version != PRESTAGE_RECEIPT_VERSION
        || receipt.lease_generation == 0
        || receipt.writer_fence == 0
        || receipt.activation_registry_generation == 0
        || receipt.package_len == 0
        || receipt.package_len > PRESTAGE_MAX_PACKAGE_BYTES
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    for value in [
        &receipt.intent_key,
        &receipt.mutation_id,
        &receipt.mutation_digest,
        &receipt.expected_aggregate_digest,
        &receipt.owner_store_incarnation_digest,
        &receipt.parent_descriptor_digest,
        &receipt.parent_lease_acquired_record_digest,
        &receipt.owner_roster_digest,
        &receipt.activation_manifest_digest,
        &receipt.package_sha256,
        &receipt.owner_request_digest,
        &receipt.owner_journal_descriptor_digest,
        &receipt.prepared_state_digest,
        &receipt.receipt_digest,
    ] {
        validate_digest(value, "prestage_receipt")?;
    }
    if receipt.collection_id.is_empty()
        || receipt.collection_id.len() > MAX_RESOURCE_ID_BYTES
        || receipt.receipt_digest != private_oram_owner_prestage_receipt_digest_v2(receipt)?
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn private_oram_owner_prestage_receipt_digest_v2(
    receipt: &PrivateOramOwnerPrestageReceiptV2,
) -> Result<String, PrivateOramOwnerJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_RECEIPT_DIGEST_DOMAIN);
    hasher.update(receipt.version.to_be_bytes());
    for value in [
        &receipt.intent_key,
        &receipt.collection_id,
        &receipt.mutation_id,
        &receipt.mutation_digest,
        &receipt.expected_aggregate_digest,
        &receipt.owner_store_incarnation_digest,
        &receipt.parent_descriptor_digest,
        &receipt.parent_lease_acquired_record_digest,
        &receipt.owner_roster_digest,
        &receipt.activation_manifest_digest,
        &receipt.package_sha256,
        &receipt.owner_request_digest,
        &receipt.owner_journal_descriptor_digest,
        &receipt.prepared_state_digest,
    ] {
        hasher.update(
            u64::try_from(value.len())
                .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
                .to_be_bytes(),
        );
        hasher.update(value.as_bytes());
    }
    hasher.update(receipt.lease_generation.to_be_bytes());
    hasher.update(receipt.writer_fence.to_be_bytes());
    hasher.update(receipt.owner_peer_id.to_be_bytes());
    hasher.update(receipt.activation_registry_generation.to_be_bytes());
    hasher.update(receipt.package_len.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn private_oram_owner_prestage_superblock_digest_v2(
    superblock: &PrivateOramOwnerPrestageSuperblockV2,
) -> Result<String, PrivateOramOwnerJournalError> {
    validate_digest(
        &superblock.owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    validate_digest(&superblock.lifecycle_state_root, "lifecycle_state_root")?;
    superblock.lifecycle_state()?;
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_SUPERBLOCK_DIGEST_DOMAIN);
    hasher.update(superblock.version.to_be_bytes());
    lifecycle_hash_string(&mut hasher, &superblock.owner_store_incarnation_digest)?;
    hasher.update(superblock.lifecycle_generation.to_be_bytes());
    lifecycle_hash_string(&mut hasher, &superblock.lifecycle_state_root)?;
    hasher.update(superblock.minimum_lifecycle_reader_version.to_be_bytes());
    lifecycle_hash_string(&mut hasher, &superblock.lifecycle_capability)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn encode_private_oram_owner_prestage_superblock_v2(
    superblock: &PrivateOramOwnerPrestageSuperblockV2,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if superblock.version != PRESTAGE_SUPERBLOCK_VERSION
        || superblock.superblock_digest
            != private_oram_owner_prestage_superblock_digest_v2(superblock)?
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let bytes =
        serde_json::to_vec(superblock).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_SUPERBLOCK_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn decode_private_oram_owner_prestage_superblock_v2(
    bytes: &[u8],
) -> Result<PrivateOramOwnerPrestageSuperblockV2, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_SUPERBLOCK_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let superblock: PrivateOramOwnerPrestageSuperblockV2 =
        serde_json::from_slice(bytes).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encode_private_oram_owner_prestage_superblock_v2(&superblock)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(superblock)
}

fn private_oram_owner_reservation_fence_digest_v1(
    record: &PrivateOramOwnerReservationFenceRecordV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_reservation_prepare_challenge_v1(&record.challenge)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_private_oram_owner_lifecycle_state_v1(&record.lifecycle_state)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if record.version != PRESTAGE_RESERVATION_FENCE_VERSION
        || record.challenge.owner_store_incarnation_digest
            != record.lifecycle_state.owner_store_incarnation_digest
        || record.terminal_record_limit != PRESTAGE_MAX_TERMINAL_RECORDS as u64
        || record.terminal_record_count >= record.terminal_record_limit
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let challenge_bytes =
        serde_json::to_vec(&record.challenge).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let lifecycle_bytes = serde_json::to_vec(&record.lifecycle_state)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_RESERVATION_FENCE_DIGEST_DOMAIN);
    hasher.update(record.version.to_be_bytes());
    hasher.update(
        u64::try_from(challenge_bytes.len())
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(challenge_bytes);
    hasher.update(
        u64::try_from(lifecycle_bytes.len())
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(lifecycle_bytes);
    hasher.update(record.terminal_record_count.to_be_bytes());
    hasher.update(record.terminal_record_limit.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn encode_private_oram_owner_reservation_fence_v1(
    record: &PrivateOramOwnerReservationFenceRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_digest(&record.fence_record_digest, "fence_record_digest")?;
    if record.fence_record_digest != private_oram_owner_reservation_fence_digest_v1(record)? {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let bytes = serde_json::to_vec(record).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_RESERVATION_FENCE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn decode_private_oram_owner_reservation_fence_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerReservationFenceRecordV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_RESERVATION_FENCE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let record: PrivateOramOwnerReservationFenceRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encode_private_oram_owner_reservation_fence_v1(&record)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(record)
}

fn validate_private_oram_owner_reservation_resolution_input_v1(
    resolution: &PrivateOramOwnerReservationResolutionV1,
) -> Result<(), PrivateOramOwnerJournalError> {
    for (value, field) in [
        (
            &resolution.committed_challenge_digest,
            "committed_challenge_digest",
        ),
        (
            &resolution.reservation_intent_digest,
            "reservation_intent_digest",
        ),
        (&resolution.attempt_id, "attempt_id"),
    ] {
        validate_digest(value, field)?;
    }
    if resolution.challenge_applied_term == 0
        || resolution.challenge_applied_index == 0
        || resolution.resolution_applied_term == 0
        || resolution.resolution_applied_index <= resolution.challenge_applied_index
        || resolution.resolution_applied_term < resolution.challenge_applied_term
        || matches!(
            resolution.kind,
            PrivateOramOwnerReservationResolutionKindV1::Finalized
        ) != resolution.finalized_reservation_digest.is_some()
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput(
            "reservation_resolution",
        ));
    }
    if let Some(digest) = resolution.finalized_reservation_digest.as_deref() {
        validate_digest(digest, "finalized_reservation_digest")?;
    }
    Ok(())
}

fn private_oram_owner_reservation_resolution_matches_input_v1(
    record: &PrivateOramOwnerReservationResolutionRecordV1,
    resolution: &PrivateOramOwnerReservationResolutionV1,
) -> bool {
    record.kind == resolution.kind
        && record.committed_challenge_digest == resolution.committed_challenge_digest
        && record.reservation_intent_digest == resolution.reservation_intent_digest
        && record.attempt_id == resolution.attempt_id
        && record.challenge_applied_term == resolution.challenge_applied_term
        && record.challenge_applied_index == resolution.challenge_applied_index
        && record.resolution_applied_term == resolution.resolution_applied_term
        && record.resolution_applied_index == resolution.resolution_applied_index
        && record.finalized_reservation_digest == resolution.finalized_reservation_digest
}

fn private_oram_owner_reservation_resolution_input_matches_challenge_v1(
    resolution: &PrivateOramOwnerReservationResolutionV1,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> bool {
    resolution.committed_challenge_digest == challenge.committed_challenge_digest
        && resolution.reservation_intent_digest == challenge.reservation_intent_digest
        && resolution.attempt_id == challenge.attempt_id
        && resolution.challenge_applied_term == challenge.challenge_applied_term
        && resolution.challenge_applied_index == challenge.challenge_applied_index
}

fn private_oram_owner_reservation_resolution_matches_challenge_v1(
    record: &PrivateOramOwnerReservationResolutionRecordV1,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> bool {
    record.committed_challenge_digest == challenge.committed_challenge_digest
        && record.reservation_intent_digest == challenge.reservation_intent_digest
        && record.attempt_id == challenge.attempt_id
        && record.challenge_applied_term == challenge.challenge_applied_term
        && record.challenge_applied_index == challenge.challenge_applied_index
        && record.reserved_terminal_intent_key == challenge.reserved_terminal_intent_key
        && record.owner_store_incarnation_digest == challenge.owner_store_incarnation_digest
        && record.owner_store_binding_digest == challenge.expected_checkpoint_record_digest
}

fn private_oram_owner_absent_reservation_fence_digest_v1(
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_reservation_prepare_challenge_v1(challenge)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_private_oram_owner_lifecycle_state_v1(lifecycle_state)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if challenge.owner_store_incarnation_digest != lifecycle_state.owner_store_incarnation_digest {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_RESERVATION_ABSENT_FENCE_DIGEST_DOMAIN);
    for digest in [
        challenge.committed_challenge_digest.as_str(),
        challenge.reservation_intent_digest.as_str(),
        challenge.attempt_id.as_str(),
        challenge.expected_checkpoint_record_digest.as_str(),
        challenge.reserved_terminal_intent_key.as_str(),
        lifecycle_state.owner_store_incarnation_digest.as_str(),
        lifecycle_state.state_root.as_str(),
    ] {
        validate_digest(digest, "absent_fence_binding")?;
        hasher.update((digest.len() as u64).to_be_bytes());
        hasher.update(digest.as_bytes());
    }
    hasher.update(challenge.challenge_applied_term.to_be_bytes());
    hasher.update(challenge.challenge_applied_index.to_be_bytes());
    hasher.update(lifecycle_state.generation.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn private_oram_owner_reservation_resolution_digest_v1(
    record: &PrivateOramOwnerReservationResolutionRecordV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    validate_digest(&record.fence_record_digest, "fence_record_digest")?;
    validate_digest(
        &record.committed_challenge_digest,
        "committed_challenge_digest",
    )?;
    validate_digest(
        &record.reservation_intent_digest,
        "reservation_intent_digest",
    )?;
    validate_digest(&record.attempt_id, "attempt_id")?;
    validate_digest(
        &record.reserved_terminal_intent_key,
        "reserved_terminal_intent_key",
    )?;
    validate_digest(
        &record.owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    validate_digest(
        &record.owner_store_binding_digest,
        "owner_store_binding_digest",
    )?;
    if !matches!(
        record.version,
        PRESTAGE_RESERVATION_RESOLUTION_VERSION_V2 | PRESTAGE_RESERVATION_RESOLUTION_VERSION
    ) || (record.version == PRESTAGE_RESERVATION_RESOLUTION_VERSION_V2
        && !record.fence_was_present)
        || (record.kind == PrivateOramOwnerReservationResolutionKindV1::Finalized
            && !record.fence_was_present)
        || record.challenge_applied_term == 0
        || record.challenge_applied_index == 0
        || record.resolution_applied_term == 0
        || record.resolution_applied_index <= record.challenge_applied_index
        || record.resolution_applied_term < record.challenge_applied_term
        || matches!(
            record.kind,
            PrivateOramOwnerReservationResolutionKindV1::Finalized
        ) != record.finalized_reservation_digest.is_some()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    if let Some(digest) = record.finalized_reservation_digest.as_deref() {
        validate_digest(digest, "finalized_reservation_digest")?;
    }
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_RESERVATION_RESOLUTION_DIGEST_DOMAIN);
    hasher.update(record.version.to_be_bytes());
    hasher.update([match record.kind {
        PrivateOramOwnerReservationResolutionKindV1::Finalized => 1,
        PrivateOramOwnerReservationResolutionKindV1::Cancelled => 2,
    }]);
    if record.version >= PRESTAGE_RESERVATION_RESOLUTION_VERSION {
        hasher.update([u8::from(record.fence_was_present)]);
    }
    for value in [
        record.fence_record_digest.as_str(),
        record.committed_challenge_digest.as_str(),
        record.reservation_intent_digest.as_str(),
        record.attempt_id.as_str(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(record.challenge_applied_term.to_be_bytes());
    hasher.update(record.challenge_applied_index.to_be_bytes());
    hasher.update(record.resolution_applied_term.to_be_bytes());
    hasher.update(record.resolution_applied_index.to_be_bytes());
    hasher.update((record.reserved_terminal_intent_key.len() as u64).to_be_bytes());
    hasher.update(record.reserved_terminal_intent_key.as_bytes());
    if let Some(digest) = record.finalized_reservation_digest.as_deref() {
        hasher.update([1]);
        hasher.update((digest.len() as u64).to_be_bytes());
        hasher.update(digest.as_bytes());
    } else {
        hasher.update([0]);
    }
    for digest in [
        record.owner_store_incarnation_digest.as_str(),
        record.owner_store_binding_digest.as_str(),
    ] {
        hasher.update((digest.len() as u64).to_be_bytes());
        hasher.update(digest.as_bytes());
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn encode_private_oram_owner_reservation_resolution_v1(
    record: &PrivateOramOwnerReservationResolutionRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_digest(&record.resolution_record_digest, "resolution_record_digest")?;
    if record.resolution_record_digest
        != private_oram_owner_reservation_resolution_digest_v1(record)?
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let bytes = serde_json::to_vec(record).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_RESERVATION_RESOLUTION_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn decode_private_oram_owner_reservation_resolution_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerReservationResolutionRecordV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_RESERVATION_RESOLUTION_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let record: PrivateOramOwnerReservationResolutionRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encode_private_oram_owner_reservation_resolution_v1(&record)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(record)
}

fn private_oram_owner_reservation_abort_release_digest_v1(
    record: &PrivateOramOwnerReservationAbortReleaseRecordV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    if record.version != PRESTAGE_RESERVATION_ABORT_RELEASE_VERSION {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    for (value, field) in [
        (
            record.resolution_record_digest.as_str(),
            "resolution_record_digest",
        ),
        (record.fence_record_digest.as_str(), "fence_record_digest"),
        (
            record.abort_release_authority_digest.as_str(),
            "abort_release_authority_digest",
        ),
        (
            record.owner_store_incarnation_digest.as_str(),
            "owner_store_incarnation_digest",
        ),
        (
            record.owner_store_binding_digest.as_str(),
            "owner_store_binding_digest",
        ),
    ] {
        validate_digest(value, field)?;
    }
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_RESERVATION_ABORT_RELEASE_DIGEST_DOMAIN);
    hasher.update(record.version.to_be_bytes());
    for value in [
        record.resolution_record_digest.as_str(),
        record.fence_record_digest.as_str(),
        record.abort_release_authority_digest.as_str(),
        record.owner_store_incarnation_digest.as_str(),
        record.owner_store_binding_digest.as_str(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn encode_private_oram_owner_reservation_abort_release_v1(
    record: &PrivateOramOwnerReservationAbortReleaseRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_digest(&record.release_marker_digest, "release_marker_digest")?;
    if record.release_marker_digest
        != private_oram_owner_reservation_abort_release_digest_v1(record)?
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let bytes = serde_json::to_vec(record).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_RESERVATION_ABORT_RELEASE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn decode_private_oram_owner_reservation_abort_release_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerReservationAbortReleaseRecordV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_RESERVATION_ABORT_RELEASE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let record: PrivateOramOwnerReservationAbortReleaseRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encode_private_oram_owner_reservation_abort_release_v1(&record)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(record)
}

fn private_oram_owner_lifecycle_marker_v2(
    kind: PrivateOramOwnerLifecycleMarkerKindV2,
    owner_store_incarnation_digest: &str,
    receipt: &PrivateOramOwnerPrestageReceiptV2,
    terminal_authority_digest: Option<&str>,
) -> Result<PrivateOramOwnerLifecycleMarkerV2, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_prestage_receipt_v2(receipt)?;
    if receipt.owner_store_incarnation_digest != owner_store_incarnation_digest {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    let mut marker = PrivateOramOwnerLifecycleMarkerV2 {
        version: PRESTAGE_LIFECYCLE_MARKER_VERSION,
        kind,
        owner_store_incarnation_digest: owner_store_incarnation_digest.to_string(),
        intent_key: receipt.intent_key.clone(),
        collection_id: receipt.collection_id.clone(),
        mutation_id: receipt.mutation_id.clone(),
        mutation_digest: receipt.mutation_digest.clone(),
        expected_aggregate_digest: receipt.expected_aggregate_digest.clone(),
        lease_generation: receipt.lease_generation,
        writer_fence: receipt.writer_fence,
        owner_peer_id: receipt.owner_peer_id,
        parent_descriptor_digest: receipt.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: receipt.parent_lease_acquired_record_digest.clone(),
        package_sha256: receipt.package_sha256.clone(),
        prestage_receipt_digest: Some(receipt.receipt_digest.clone()),
        owner_journal_descriptor_digest: Some(receipt.owner_journal_descriptor_digest.clone()),
        terminal_authority_digest: terminal_authority_digest.map(ToOwned::to_owned),
        cleanup_authority_signer: None,
        signed_cleanup_authorization: None,
        signed_cleanup_receipt: None,
        marker_digest: String::new(),
    };
    marker.marker_digest = private_oram_owner_lifecycle_marker_digest_v2(&marker)?;
    validate_private_oram_owner_lifecycle_marker_v2(&marker)?;
    Ok(marker)
}

fn private_oram_owner_cleanup_lifecycle_marker_v2(
    verified_authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
    signed_receipt: &SignedPrivateOramOwnerCleanupReceiptV1,
) -> Result<PrivateOramOwnerLifecycleMarkerV2, PrivateOramOwnerJournalError> {
    validate_signed_private_oram_owner_cleanup_receipt_v1(signed_receipt, verified_authorization)
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("cleanup_receipt"))?;
    let authorization = verified_authorization.authorization();
    let receipt = &signed_receipt.receipt;
    let kind = match receipt.terminal_state {
        PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent => {
            PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent
        }
        PrivateOramOwnerCleanupTerminalStateV1::Quarantined => {
            PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
        }
    };
    let mut marker = PrivateOramOwnerLifecycleMarkerV2 {
        version: PRESTAGE_LIFECYCLE_MARKER_VERSION,
        kind,
        owner_store_incarnation_digest: receipt
            .previous_lifecycle_state
            .owner_store_incarnation_digest
            .clone(),
        intent_key: authorization.target.intent_key.clone(),
        collection_id: authorization.authority.collection_id.clone(),
        mutation_id: authorization.attempt.mutation_id.clone(),
        mutation_digest: authorization.attempt.mutation_digest.clone(),
        expected_aggregate_digest: authorization.attempt.expected_aggregate_digest.clone(),
        lease_generation: authorization.attempt.lease_generation,
        writer_fence: authorization.attempt.writer_fence,
        owner_peer_id: authorization.target.owner_peer_id,
        parent_descriptor_digest: authorization.target.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: authorization
            .target
            .parent_lease_acquired_record_digest
            .clone(),
        package_sha256: authorization.target.package_sha256.clone(),
        prestage_receipt_digest: authorization.target.prestage_receipt_digest.clone(),
        owner_journal_descriptor_digest: authorization
            .target
            .owner_journal_descriptor_digest
            .clone(),
        terminal_authority_digest: Some(authorization.authorization_digest.clone()),
        cleanup_authority_signer: Some(verified_authorization.authority_signer().clone()),
        signed_cleanup_authorization: Some(verified_authorization.signed().clone()),
        signed_cleanup_receipt: Some(signed_receipt.clone()),
        marker_digest: String::new(),
    };
    marker.marker_digest = private_oram_owner_lifecycle_marker_digest_v2(&marker)?;
    validate_private_oram_owner_lifecycle_marker_v2(&marker)?;
    Ok(marker)
}

fn committed_private_oram_owner_cleanup_receipt_v2(
    signed_receipt: &SignedPrivateOramOwnerCleanupReceiptV1,
    terminal: &PrivateOramOwnerLifecycleMarkerV2,
    repair_state: PrivateOramOwnerCleanupRepairStateV2,
) -> CommittedPrivateOramOwnerCleanupReceiptV2 {
    CommittedPrivateOramOwnerCleanupReceiptV2 {
        signed_receipt: signed_receipt.clone(),
        storage_terminal_marker_digest: terminal.marker_digest.clone(),
        repair_state,
    }
}

fn private_oram_owner_terminal_matches_receipt_v2(
    terminal: &PrivateOramOwnerLifecycleMarkerV2,
    receipt: &PrivateOramOwnerPrestageReceiptV2,
) -> Result<bool, PrivateOramOwnerJournalError> {
    if !matches!(
        terminal.kind,
        PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent
            | PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
    ) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    if let (Some(authority_signer), Some(signed_authorization), Some(signed_receipt)) = (
        &terminal.cleanup_authority_signer,
        &terminal.signed_cleanup_authorization,
        &terminal.signed_cleanup_receipt,
    ) {
        validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
            signed_authorization,
            authority_signer,
        )
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_self_consistent_signed_private_oram_owner_cleanup_receipt_v1(
            signed_receipt,
            &signed_authorization.authorization,
        )
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let authorization = &signed_authorization.authorization;
        let expected_intent_marker = private_oram_owner_lifecycle_marker_v2(
            PrivateOramOwnerLifecycleMarkerKindV2::Intent,
            &terminal.owner_store_incarnation_digest,
            receipt,
            None,
        )?;
        return Ok(receipt.intent_key == authorization.target.intent_key
            && receipt.collection_id == authorization.authority.collection_id
            && receipt.mutation_id == authorization.attempt.mutation_id
            && receipt.mutation_digest == authorization.attempt.mutation_digest
            && receipt.expected_aggregate_digest
                == authorization.attempt.expected_aggregate_digest
            && receipt.lease_generation == authorization.attempt.lease_generation
            && receipt.writer_fence == authorization.attempt.writer_fence
            && receipt.owner_peer_id == authorization.target.owner_peer_id
            && receipt.parent_descriptor_digest == authorization.target.parent_descriptor_digest
            && receipt.parent_lease_acquired_record_digest
                == authorization.target.parent_lease_acquired_record_digest
            && receipt.owner_roster_digest == authorization.authority.owner_roster_digest
            && receipt.activation_registry_generation
                == authorization.authority.activation_registry_generation
            && receipt.activation_manifest_digest
                == authorization.authority.activation_manifest_digest
            && receipt.package_sha256 == authorization.target.package_sha256
            && receipt.package_len == authorization.target.package_len
            && receipt.owner_request_digest == authorization.target.owner_request_digest
            && authorization.target.prestage_receipt_digest.as_deref()
                == Some(receipt.receipt_digest.as_str())
            && authorization.target.intent_marker_digest.as_deref()
                == Some(expected_intent_marker.marker_digest.as_str())
            && authorization
                .target
                .owner_journal_descriptor_digest
                .as_deref()
                == Some(receipt.owner_journal_descriptor_digest.as_str()));
    }
    Ok(*terminal
        == private_oram_owner_lifecycle_marker_v2(
            terminal.kind,
            &terminal.owner_store_incarnation_digest,
            receipt,
            terminal.terminal_authority_digest.as_deref(),
        )?)
}

fn validate_private_oram_owner_lifecycle_marker_v2(
    marker: &PrivateOramOwnerLifecycleMarkerV2,
) -> Result<(), PrivateOramOwnerJournalError> {
    let terminal = matches!(
        marker.kind,
        PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent
            | PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
    );
    if marker.version != PRESTAGE_LIFECYCLE_MARKER_VERSION
        || marker.collection_id.is_empty()
        || marker.collection_id.len() > MAX_RESOURCE_ID_BYTES
        || marker.lease_generation == 0
        || marker.writer_fence == 0
        || marker.owner_peer_id == 0
        || terminal != marker.terminal_authority_digest.is_some()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    for digest in [
        &marker.owner_store_incarnation_digest,
        &marker.intent_key,
        &marker.mutation_id,
        &marker.mutation_digest,
        &marker.expected_aggregate_digest,
        &marker.parent_descriptor_digest,
        &marker.parent_lease_acquired_record_digest,
        &marker.package_sha256,
        &marker.marker_digest,
    ] {
        validate_digest(digest, "lifecycle_marker")?;
    }
    if let Some(digest) = &marker.terminal_authority_digest {
        validate_digest(digest, "terminal_authority_digest")?;
    }
    if let Some(digest) = &marker.prestage_receipt_digest {
        validate_digest(digest, "prestage_receipt_digest")?;
    }
    if let Some(digest) = &marker.owner_journal_descriptor_digest {
        validate_digest(digest, "owner_journal_descriptor_digest")?;
    }
    match (
        &marker.cleanup_authority_signer,
        &marker.signed_cleanup_authorization,
        &marker.signed_cleanup_receipt,
    ) {
        (Some(authority_signer), Some(signed_authorization), Some(signed_receipt)) => {
            validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
                signed_authorization,
                authority_signer,
            )
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
            validate_self_consistent_signed_private_oram_owner_cleanup_receipt_v1(
                signed_receipt,
                &signed_authorization.authorization,
            )
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
            let authorization = &signed_authorization.authorization;
            let receipt = &signed_receipt.receipt;
            let expected_kind = match receipt.terminal_state {
                PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent => {
                    PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent
                }
                PrivateOramOwnerCleanupTerminalStateV1::Quarantined => {
                    PrivateOramOwnerLifecycleMarkerKindV2::Quarantined
                }
            };
            if marker.kind != expected_kind
                || marker.terminal_authority_digest.as_deref()
                    != Some(authorization.authorization_digest.as_str())
                || marker.owner_store_incarnation_digest
                    != authorization
                        .target
                        .expected_lifecycle_state
                        .owner_store_incarnation_digest
                || marker.intent_key != authorization.target.intent_key
                || marker.collection_id != authorization.authority.collection_id
                || marker.mutation_id != authorization.attempt.mutation_id
                || marker.mutation_digest != authorization.attempt.mutation_digest
                || marker.expected_aggregate_digest
                    != authorization.attempt.expected_aggregate_digest
                || marker.lease_generation != authorization.attempt.lease_generation
                || marker.writer_fence != authorization.attempt.writer_fence
                || marker.owner_peer_id != authorization.target.owner_peer_id
                || marker.parent_descriptor_digest != authorization.target.parent_descriptor_digest
                || marker.parent_lease_acquired_record_digest
                    != authorization.target.parent_lease_acquired_record_digest
                || marker.package_sha256 != authorization.target.package_sha256
                || marker.prestage_receipt_digest != authorization.target.prestage_receipt_digest
                || marker.owner_journal_descriptor_digest
                    != authorization.target.owner_journal_descriptor_digest
                || receipt.previous_lifecycle_state != authorization.target.expected_lifecycle_state
            {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
        (None, None, None) if marker.prestage_receipt_digest.is_some() => {}
        _ => {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    if marker.marker_digest != private_oram_owner_lifecycle_marker_digest_v2(marker)? {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn private_oram_owner_lifecycle_marker_digest_v2(
    marker: &PrivateOramOwnerLifecycleMarkerV2,
) -> Result<String, PrivateOramOwnerJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PRESTAGE_LIFECYCLE_MARKER_DIGEST_DOMAIN);
    hasher.update(marker.version.to_be_bytes());
    hasher.update([match marker.kind {
        PrivateOramOwnerLifecycleMarkerKindV2::Intent => 1,
        PrivateOramOwnerLifecycleMarkerKindV2::AdoptionPending => 2,
        PrivateOramOwnerLifecycleMarkerKindV2::Adopted => 3,
        PrivateOramOwnerLifecycleMarkerKindV2::TombstonedAbsent => 4,
        PrivateOramOwnerLifecycleMarkerKindV2::Quarantined => 5,
    }]);
    for value in [
        &marker.owner_store_incarnation_digest,
        &marker.intent_key,
        &marker.collection_id,
        &marker.mutation_id,
        &marker.mutation_digest,
        &marker.expected_aggregate_digest,
        &marker.parent_descriptor_digest,
        &marker.parent_lease_acquired_record_digest,
        &marker.package_sha256,
    ] {
        lifecycle_hash_string(&mut hasher, value)?;
    }
    hasher.update(marker.lease_generation.to_be_bytes());
    hasher.update(marker.writer_fence.to_be_bytes());
    hasher.update(marker.owner_peer_id.to_be_bytes());
    match &marker.prestage_receipt_digest {
        Some(digest) => {
            hasher.update([1]);
            lifecycle_hash_string(&mut hasher, digest)?;
        }
        None => hasher.update([0]),
    }
    match &marker.owner_journal_descriptor_digest {
        Some(digest) => {
            hasher.update([1]);
            lifecycle_hash_string(&mut hasher, digest)?;
        }
        None => hasher.update([0]),
    }
    match &marker.terminal_authority_digest {
        Some(digest) => {
            hasher.update([1]);
            lifecycle_hash_string(&mut hasher, digest)?;
        }
        None => hasher.update([0]),
    }
    lifecycle_hash_optional_json(&mut hasher, marker.cleanup_authority_signer.as_ref())?;
    lifecycle_hash_optional_json(&mut hasher, marker.signed_cleanup_authorization.as_ref())?;
    lifecycle_hash_optional_json(&mut hasher, marker.signed_cleanup_receipt.as_ref())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn lifecycle_hash_optional_json<T: Serialize>(
    hasher: &mut Sha256,
    value: Option<&T>,
) -> Result<(), PrivateOramOwnerJournalError> {
    match value {
        Some(value) => {
            hasher.update([1]);
            let bytes =
                serde_json::to_vec(value).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
            hasher.update(
                u64::try_from(bytes.len())
                    .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
                    .to_be_bytes(),
            );
            hasher.update(bytes);
        }
        None => hasher.update([0]),
    }
    Ok(())
}

fn encode_private_oram_owner_lifecycle_marker_v2(
    marker: &PrivateOramOwnerLifecycleMarkerV2,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_lifecycle_marker_v2(marker)?;
    let bytes = serde_json::to_vec(marker).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn decode_private_oram_owner_lifecycle_marker_v2(
    bytes: &[u8],
) -> Result<PrivateOramOwnerLifecycleMarkerV2, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > PRESTAGE_MAX_LIFECYCLE_MARKER_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let marker: PrivateOramOwnerLifecycleMarkerV2 =
        serde_json::from_slice(bytes).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if encode_private_oram_owner_lifecycle_marker_v2(&marker)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(marker)
}

fn lifecycle_hash_string(
    hasher: &mut Sha256,
    value: &str,
) -> Result<(), PrivateOramOwnerJournalError> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(value.as_bytes());
    Ok(())
}

fn validate_private_oram_owner_prestage_root_entries(
    root: &File,
) -> Result<(), PrivateOramOwnerJournalError> {
    let names = directory_entry_names_open(root)?;
    let expected = BTreeSet::from([
        OsStr::new(PRESTAGE_INTENTS_DIR).to_owned(),
        OsStr::new(PRESTAGE_TEMP_DIR).to_owned(),
        OsStr::new(PRESTAGE_TERMINALS_DIR).to_owned(),
        OsStr::new(PRESTAGE_RETIRED_DIR).to_owned(),
        OsStr::new(PRESTAGE_QUARANTINE_DIR).to_owned(),
        OsStr::new(PRESTAGE_RESERVATION_FENCE_DIR).to_owned(),
        OsStr::new(PRESTAGE_SUPERBLOCK_FILE).to_owned(),
    ]);
    if names.into_iter().collect::<BTreeSet<_>>() != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_private_oram_owner_reservation_fence_entries(
    fence_dir: &File,
) -> Result<(), PrivateOramOwnerJournalError> {
    let names = directory_entry_names_open(fence_dir)?;
    let allowed = BTreeSet::from([
        OsStr::new(PRESTAGE_RESERVATION_FENCE_FILE).to_owned(),
        OsStr::new(PRESTAGE_RESERVATION_RESOLUTION_FILE).to_owned(),
        OsStr::new(PRESTAGE_RESERVATION_ABORT_RELEASE_FILE).to_owned(),
    ]);
    if !names.is_subset(&allowed) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_private_oram_owner_prestage_intent_entries(
    intent_path: &Path,
) -> Result<(), PrivateOramOwnerJournalError> {
    let intent = open_private_directory(intent_path)?;
    let names = directory_entry_names_open(&intent)?;
    let required = BTreeSet::from([
        OsStr::new(PRESTAGE_PACKAGE_FILE).to_owned(),
        OsStr::new(PRESTAGE_RECEIPT_FILE).to_owned(),
        OsStr::new(PRESTAGE_INTENT_MARKER_FILE).to_owned(),
        OsStr::new(DESCRIPTOR_FILE).to_owned(),
        OsStr::new(FINAL_BUCKETS_FILE).to_owned(),
        OsStr::new(STATE_FILE).to_owned(),
    ]);
    let names = names.into_iter().collect::<BTreeSet<_>>();
    let allowed = required
        .iter()
        .cloned()
        .chain([
            OsStr::new(PRESTAGE_ADOPTION_PENDING_MARKER_FILE).to_owned(),
            OsStr::new(PRESTAGE_ADOPTED_MARKER_FILE).to_owned(),
        ])
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&names)
        || !names.is_subset(&allowed)
        || (names.contains(OsStr::new(PRESTAGE_ADOPTED_MARKER_FILE))
            && !names.contains(OsStr::new(PRESTAGE_ADOPTION_PENDING_MARKER_FILE)))
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

impl PrivateOramOwnerJournal {
    /// Creates a paired owner journal below the primary HNSW store root.
    pub fn new(primary_hnsw_store_root: impl AsRef<Path>) -> Self {
        Self {
            root: primary_hnsw_store_root
                .as_ref()
                .join(OWNER_STORE_TEMP_DIR)
                .join(PRIVATE_ORAM_OWNER_JOURNAL_DIR),
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    fn archive_committed_directory_under_exclusive_lock_v1(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        authority: &PrivateOramOwnerCommittedArchiveGrantV1,
        owner_store_incarnation_digest: &str,
        loaded_intent: &LoadedPrivateOramOwnerPrestageIntentV2,
    ) -> Result<PrivateOramOwnerTerminalArchiveV1, PrivateOramOwnerJournalError> {
        root_lock.require_exclusive()?;
        let root = root_lock.root;
        validate_open_directory_at_path(root, &self.root)?;
        let archive_name = completed_generation_name(authority.receipt.lease_generation())?;
        let entries = directory_entry_names_open(root)?;
        let active_exists = entries.contains(OsStr::new(ACTIVE_DIR));
        let archive_exists = entries.contains(OsStr::new(&archive_name));
        if active_exists && archive_exists {
            return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
        }

        let moved_source = if active_exists {
            let active = self.load_active_structural_from(root, true, None)?;
            let expected = build_owner_terminal_archive_v1(
                authority,
                owner_store_incarnation_digest,
                loaded_intent,
                &active,
            )?;
            let active_path = open_directory_entry_path(root, OsStr::new(ACTIVE_DIR))?;
            let pinned_active = open_private_directory(&active_path)?;
            rename_directory_noreplace(root, OsStr::new(ACTIVE_DIR), OsStr::new(&archive_name))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            sync_open_directory(root).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            fail_owner_archive_after_canonical_rename_v1()?;
            Some((pinned_active, expected))
        } else if archive_exists {
            None
        } else {
            return Err(PrivateOramOwnerJournalError::ExternalRecoveryRequired);
        };

        let archive_path = open_directory_entry_path(root, OsStr::new(&archive_name))?;
        let completed = open_private_directory(&archive_path)?;
        if let Some((pinned_active, _)) = moved_source.as_ref() {
            ensure_same_open_inode(pinned_active, &completed)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }
        if path_entry_exists(&open_directory_entry_path(root, OsStr::new(ACTIVE_DIR))?)? {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        let archived = self.load_completed_structural_from(
            root,
            authority.receipt.lease_generation(),
            true,
            Some(&completed),
        )?;
        let expected = build_owner_terminal_archive_v1(
            authority,
            owner_store_incarnation_digest,
            loaded_intent,
            &archived,
        )?;
        if moved_source
            .as_ref()
            .is_some_and(|(_, before)| before != &expected)
        {
            return Err(PrivateOramOwnerJournalError::Indeterminate);
        }
        validate_open_directory_at_path(&completed, &archive_path)?;
        validate_open_directory_at_path(root, &self.root)?;
        Ok(expected)
    }

    fn load_completed_archive_record_under_lock_v1(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        generation: u64,
    ) -> Result<Option<PrivateOramOwnerTerminalArchiveV1>, PrivateOramOwnerJournalError> {
        let root = root_lock.root;
        validate_open_directory_at_path(root, &self.root)?;
        let archive_name = completed_generation_name(generation)?;
        let archive_path = open_directory_entry_path(root, OsStr::new(&archive_name))?;
        if !path_entry_exists(&archive_path)? {
            return Ok(None);
        }
        let completed = open_private_directory(&archive_path)?;
        let (_, has_archive_record) = validate_completed_entry_set_open(&completed)?;
        if !has_archive_record {
            return Ok(None);
        }
        let record_path =
            open_directory_entry_path(&completed, OsStr::new(OWNER_TERMINAL_ARCHIVE_FILE))?;
        let (mut pinned, bytes) =
            read_private_file_pinned(&record_path, MAX_OWNER_TERMINAL_ARCHIVE_BYTES)?;
        let archive = decode_owner_terminal_archive_v1(&bytes)?;
        if archive.generation != generation {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        pinned.validate_exact_contents(&bytes)?;
        pinned.validate_at_path()?;
        validate_open_directory_at_path(&completed, &archive_path)?;
        validate_open_directory_at_path(root, &self.root)?;
        Ok(Some(archive))
    }

    fn committed_archive_fences_intent_under_exclusive_lock_v1(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        loaded: &LoadedPrivateOramOwnerPrestageIntentV2,
    ) -> Result<bool, PrivateOramOwnerJournalError> {
        root_lock.require_exclusive()?;
        self.committed_archive_fences_intent_under_lock_v1(root_lock, loaded)
    }

    fn committed_archive_fences_intent_under_lock_v1(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        loaded: &LoadedPrivateOramOwnerPrestageIntentV2,
    ) -> Result<bool, PrivateOramOwnerJournalError> {
        let root = root_lock.root;
        let archive_name = completed_generation_name(loaded.receipt.lease_generation())?;
        let entries = directory_entry_names_open(root)?;
        if !entries.contains(OsStr::new(&archive_name)) {
            return Ok(false);
        }
        if entries.contains(OsStr::new(ACTIVE_DIR)) {
            return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
        }
        let archived = self.load_completed_structural_from(
            root,
            loaded.receipt.lease_generation(),
            false,
            None,
        )?;
        if !terminalized_journal_matches_prestaged_v1(&loaded.prepared, &archived) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let record = self
            .load_completed_archive_record_under_lock_v1(
                root_lock,
                loaded.receipt.lease_generation(),
            )?
            .ok_or(PrivateOramOwnerJournalError::ExternalRecoveryRequired)?;
        let adopted_marker = loaded
            .adopted_marker
            .as_ref()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        if record.collection_id != loaded.receipt.collection_id()
            || record.owner_peer_id != loaded.receipt.owner_peer_id()
            || record.mutation_id != loaded.receipt.mutation_id()
            || record.signed_mutation_digest != loaded.receipt.mutation_digest()
            || record.writer_fence != loaded.receipt.writer_fence()
            || record.parent_descriptor_digest != loaded.receipt.parent_descriptor_digest()
            || record.parent_lease_acquired_record_digest
                != loaded.receipt.parent_lease_acquired_record_digest()
            || record.owner_journal_descriptor_digest
                != loaded.receipt.owner_journal_descriptor_digest()
            || record.owner_prepared_state_digest != loaded.receipt.prepared_state_digest()
            || record.intent_key != loaded.receipt.intent_key()
            || record.prestage_receipt_digest != loaded.receipt.receipt_digest()
            || record.prestage_adopted_marker_digest != adopted_marker.marker_digest
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(true)
    }

    pub(crate) fn prepare(
        &self,
        validated: &PrivateOramValidatedOwnerPrepareV1,
        context: PrivateOramOwnerJournalPrepareContextV1<'_>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let desired = ValidatedOwnerJournal::build(validated, context)?;
        self.prepare_validated(desired)
    }

    /// Test-only direct canonical prepare. Production prestaged adoption must use the lifecycle
    /// transaction so the prestage lock is always acquired before the canonical lock.
    #[cfg(test)]
    pub(crate) fn prepare_for_parent_v2(
        &self,
        validated: &PrivateOramValidatedOwnerPrepareV1,
        parent: &PrivateOramOwnerPrepareParentV2,
    ) -> Result<PrivateOramOwnerPreparedEvidenceV2, PrivateOramOwnerJournalError> {
        let requirements = parent
            .requirements
            .iter()
            .map(|requirement| PrivateOramOwnerJournalRequirementV1 {
                kind: requirement.kind,
                index_name: &requirement.index_name,
                old_epoch: requirement.old_epoch,
                new_epoch: requirement.new_epoch,
                old_root_hash: &requirement.old_root_hash,
                new_root_hash: &requirement.new_root_hash,
                writeback_digest: &requirement.writeback_digest,
            })
            .collect::<Vec<_>>();
        let (_, token) = self.prepare(
            validated,
            PrivateOramOwnerJournalPrepareContextV1 {
                parent_descriptor_digest: &parent.parent_descriptor_digest,
                parent_lease_acquired_record_digest: &parent.parent_lease_acquired_record_digest,
                owner_peer_id: parent.owner_peer_id,
                requirements: &requirements,
            },
        )?;
        Ok(PrivateOramOwnerPreparedEvidenceV2 {
            owner_peer_id: token.owner_peer_id,
            journal_descriptor_digest: token.journal_descriptor_digest,
            parent_descriptor_digest: token.parent_descriptor_digest,
            parent_lease_acquired_record_digest: token.parent_lease_acquired_record_digest,
            indexes: token
                .indexes
                .into_iter()
                .map(|index| PrivateOramOwnerPreparedIndexEvidenceV2 {
                    kind: index.kind,
                    index_name: index.index_name,
                    prepared_journal_digest: index.prepared_journal_digest,
                })
                .collect(),
        })
    }

    /// Loads a self-consistent but untrusted snapshot without minting durable owner evidence.
    ///
    /// The snapshot may contain only the Prepared record or an append-only terminal record.
    /// Recovery must bind it to typed parent state, the signed mutation, manifests, and canonical
    /// index state before it can produce new evidence.
    pub fn inspect_structural(
        &self,
    ) -> Result<Option<PrivateOramOwnerJournalSnapshotV1>, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        let root_file = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root_shared(&root_file)?;
        let output = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => None,
            StableRootEntry::Active => Some(
                self.load_active_structural_from(&root_file, false, None)?
                    .snapshot,
            ),
        };
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    pub(crate) fn bind_live_prepared_store_adapter_v1(
        &self,
        prepared: &PrivateOramDurableOwnerPreparedTokenV1,
    ) -> Result<PrivateOramOwnerPreparedStoreBindingV1, PrivateOramOwnerJournalError> {
        let snapshot = self
            .inspect_structural()?
            .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
        prepared_store_binding(snapshot, prepared)
    }

    pub(crate) fn with_live_prepared_store_binding_v1<R>(
        &self,
        prepared: &PrivateOramDurableOwnerPreparedTokenV1,
        action: impl FnOnce(&PrivateOramOwnerPreparedStoreBindingV1) -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let root_file = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root_shared(&root_file)?;
        let snapshot = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            StableRootEntry::Active => {
                self.load_active_structural_from(&root_file, false, None)?
                    .snapshot
            }
        };
        let binding = prepared_store_binding(snapshot, prepared)?;
        let output = action(&binding);
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    /// Reopens and revalidates the exact paired child Prepared evidence under one shared lock.
    ///
    /// The projection is deliberately not authority-bearing. A storage-layer caller must retain
    /// its typed parent recovery authority while consuming the callback-scoped binding.
    pub(crate) fn with_revalidated_recovery_prepared_v1<R>(
        &self,
        projection: &PrivateOramOwnerRecoveryProjectionV1,
        action: impl for<'lock> FnOnce(&PrivateOramOwnerRecoveryPreparedBindingV1<'lock>) -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let root_file = open_private_directory(&self.root)?;
        let root_lock = lock_private_journal_root_shared(&root_file)?;
        let snapshot = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            StableRootEntry::Active => {
                self.load_active_structural_from(&root_file, false, None)?
                    .snapshot
            }
        };
        let binding = recovery_prepared_binding(snapshot, projection, &root_lock)?;
        let output = action(&binding);
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    /// Reopens the exact paired child under an exclusive lock for roll-forward or terminal replay.
    ///
    /// An already installed terminal is accepted structurally so an exact phase-specific replay
    /// can resolve a crash after publication. The callback must not treat that terminal as
    /// authority before the locked recorder compares the complete desired record.
    pub(crate) fn recover_revalidated_store_pair_exclusive_v1(
        &self,
        projection: &PrivateOramOwnerRecoveryProjectionV1,
        transaction: PrivateOramOwnerLockedRecoveryTransactionV1<'_, '_, '_, '_>,
    ) -> CollectionResult<PrivateOramOwnerRecoveryExclusiveOutcomeV1> {
        self.recover_revalidated_store_pair_exclusive_then_v1(projection, transaction, Ok)
    }

    pub(crate) fn recover_revalidated_store_pair_exclusive_then_v1<R>(
        &self,
        projection: &PrivateOramOwnerRecoveryProjectionV1,
        transaction: PrivateOramOwnerLockedRecoveryTransactionV1<'_, '_, '_, '_>,
        continuation: impl FnOnce(PrivateOramOwnerRecoveryExclusiveOutcomeV1) -> CollectionResult<R>,
    ) -> CollectionResult<R> {
        self.with_revalidated_recovery_exclusive_then_v1(
            projection,
            |binding| transaction.recover_under_child_exclusive_v1(binding),
            continuation,
        )
        .map_err(|_| {
            CollectionError::bad_request("private ORAM owner recovery child authority is invalid")
        })?
    }

    fn with_revalidated_recovery_exclusive_v1<E>(
        &self,
        projection: &PrivateOramOwnerRecoveryProjectionV1,
        action: impl for<'lock> FnOnce(
            &PrivateOramOwnerRecoveryExclusiveBindingV1<'lock>,
        )
            -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, E>,
    ) -> Result<Result<PrivateOramOwnerRecoveryExclusiveOutcomeV1, E>, PrivateOramOwnerJournalError>
    {
        self.with_revalidated_recovery_exclusive_then_v1(projection, action, Ok)
    }

    fn with_revalidated_recovery_exclusive_then_v1<E, R>(
        &self,
        projection: &PrivateOramOwnerRecoveryProjectionV1,
        action: impl for<'lock> FnOnce(
            &PrivateOramOwnerRecoveryExclusiveBindingV1<'lock>,
        )
            -> Result<PrivateOramOwnerRecoveryExclusiveActionV1<'lock>, E>,
        continuation: impl FnOnce(PrivateOramOwnerRecoveryExclusiveOutcomeV1) -> Result<R, E>,
    ) -> Result<Result<R, E>, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let root_file = open_private_directory(&self.root)?;
        let root_lock = lock_private_journal_root(&root_file)?;
        let snapshot = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            StableRootEntry::Active => {
                self.load_active_structural_from(&root_file, true, None)?
                    .snapshot
            }
        };
        let binding = recovery_exclusive_binding(snapshot, projection, &root_lock)?;
        let action = match action(&binding) {
            Ok(action) => action,
            Err(error) => {
                validate_open_directory_at_path(&root_file, &self.root)?;
                return Ok(Err(error));
            }
        };
        validate_open_directory_at_path(&root_file, &self.root)?;
        let terminal = match action.terminal {
            Some(intent) => {
                let phase = intent.phase;
                let journal =
                    self.record_terminal_under_exclusive_lock(&root_lock, intent.transition())?;
                Some((phase, journal))
            }
            None => None,
        };
        validate_open_directory_at_path(&root_file, &self.root)?;
        let outcome = match terminal {
            Some((PrivateOramOwnerJournalPhaseV1::Finalized, journal)) => {
                PrivateOramOwnerRecoveryExclusiveOutcomeV1::Finalized(finalized_token(
                    &journal.snapshot,
                )?)
            }
            Some((PrivateOramOwnerJournalPhaseV1::AbortedOld, journal)) => {
                PrivateOramOwnerRecoveryExclusiveOutcomeV1::AbortedOld(aborted_old_token(
                    &journal.snapshot,
                )?)
            }
            Some((PrivateOramOwnerJournalPhaseV1::Prepared, _)) => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            None => PrivateOramOwnerRecoveryExclusiveOutcomeV1::NoTerminal,
        };
        let output = continuation(outcome);
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    #[cfg(test)]
    pub(crate) fn with_exclusive_root_lock_test_v1<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        let root_file = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root(&root_file)?;
        let output = action();
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn prepare_store_adapter_test_fixture_v1(
        &self,
        mutation_bundle: &qdrant_sec::PrivateOramAppendMutationBundleV1,
        owner_peer_id: u64,
        parent_descriptor_digest: &str,
        parent_lease_acquired_record_digest: &str,
        final_buckets: Vec<PrivateOramOwnerFinalBucketIndexV1>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let mutation = &mutation_bundle.mutation;
        let old = &mutation.old_state.state.indexes;
        let new = &mutation.new_state.state.indexes;
        if old.len() != new.len()
            || old.len() != mutation.writebacks.len()
            || old.len() != final_buckets.len()
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "test_fixture_indexes",
            ));
        }
        let indexes = old
            .iter()
            .zip(new)
            .zip(&mutation.writebacks)
            .zip(&final_buckets)
            .map(|(((old, new), writeback), final_buckets)| {
                if old.kind != new.kind
                    || old.kind != writeback.kind
                    || old.kind != final_buckets.buckets.kind()
                    || old.index_name != new.index_name
                    || old.index_name != writeback.index_name
                    || old.index_name != final_buckets.index_name
                {
                    return Err(PrivateOramOwnerJournalError::InvalidInput(
                        "test_fixture_index",
                    ));
                }
                let final_bucket_refs = match &final_buckets.buckets {
                    PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => buckets
                        .iter()
                        .map(|bucket| PrivateOramAppendBucketRefV1 {
                            bucket_id: bucket.bucket_id,
                            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                            bucket_commitment: bucket.bucket_commitment.clone(),
                        })
                        .collect(),
                    PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => buckets
                        .iter()
                        .map(|bucket| PrivateOramAppendBucketRefV1 {
                            bucket_id: bucket.bucket_id,
                            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                            bucket_commitment: bucket.bucket_commitment.clone(),
                        })
                        .collect(),
                };
                Ok(PrivateOramOwnerJournalIndexDescriptorV1 {
                    kind: old.kind,
                    index_name: old.index_name.clone(),
                    old_epoch: old.index_epoch,
                    new_epoch: new.index_epoch,
                    old_root_hash: old.root_hash.clone(),
                    new_root_hash: new.root_hash.clone(),
                    writeback_digest: new.last_writeback_digest.clone(),
                    read_path_count: writeback.read_path_count,
                    read_transcript_digest: writeback.read_transcript_digest.clone(),
                    ordered_bucket_refs: writeback.updated_buckets.clone(),
                    final_bucket_refs,
                })
            })
            .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
        let final_bucket_bytes = encode_final_bucket_frame(&indexes, &final_buckets)?;
        let mut descriptor = PrivateOramOwnerJournalDescriptorV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION,
            parent_descriptor_digest: parent_descriptor_digest.to_string(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.to_string(),
            owner_peer_id,
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest: qdrant_sec::private_oram_append_mutation_v1_digest(mutation)
                .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("test_fixture_mutation"))?,
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            indexes,
            final_bucket_frame_version: PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION,
            final_bucket_frame_length: final_bucket_bytes.len() as u64,
            final_bucket_frame_sha256: digest_string(&final_bucket_bytes),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        let descriptor_bytes = encode_descriptor(&descriptor)?;
        let mut state = PrivateOramOwnerJournalStateV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
            sequence: 1,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            previous_record_digest: None,
            phase: PrivateOramOwnerJournalPhaseV1::Prepared,
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state)?;
        let state_bytes = encode_state(&state)?;
        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal: None,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes)?;
        self.prepare_validated(ValidatedOwnerJournal {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes: None,
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn finalize_store_adapter_test_fixture_v1(
        &self,
        consensus_authority_record_digest: &str,
        reconciliation_authority_digest: &str,
        canonical_state_marker: u8,
    ) -> Result<PrivateOramDurableOwnerFinalizedTokenV1, PrivateOramOwnerJournalError> {
        let snapshot = self
            .inspect_structural()?
            .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
        let descriptor_digest = snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = snapshot.descriptor.parent_descriptor_digest.clone();
        let owner_peer_id = snapshot.descriptor.owner_peer_id;
        let canonical_index_states = snapshot
            .descriptor
            .indexes
            .iter()
            .enumerate()
            .map(
                |(position, index)| PrivateOramOwnerJournalTerminalIndexStateV1 {
                    kind: index.kind,
                    index_name: index.index_name.clone(),
                    canonical_state_digest: BASE64URL_NOPAD.encode(
                        &[canonical_state_marker.wrapping_add(position as u8); DIGEST_BYTES],
                    ),
                },
            )
            .collect::<Vec<_>>();
        let (_, token) = self.record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: owner_peer_id,
            consensus_authority_record_digest,
            reconciliation_authority_digest,
            canonical_index_states: &canonical_index_states,
        })?;
        Ok(token)
    }

    #[deprecated(note = "use inspect_structural, which also describes terminal snapshots")]
    pub fn inspect_prepared_structural(
        &self,
    ) -> Result<Option<PrivateOramOwnerJournalSnapshotV1>, PrivateOramOwnerJournalError> {
        self.inspect_structural()
    }

    /// Records a durable Finalized terminal state after a higher-level adapter has verified the
    /// canonical new index state and exact-new reconciliation authority.
    fn record_finalized(
        &self,
        context: PrivateOramOwnerJournalFinalizeContextV1<'_>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerFinalizedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let journal = self.record_terminal(TerminalTransition {
            phase: PrivateOramOwnerJournalPhaseV1::Finalized,
            expected_journal_descriptor_digest: context.expected_journal_descriptor_digest,
            parent_descriptor_digest: context.parent_descriptor_digest,
            authenticated_owner_peer_id: context.authenticated_owner_peer_id,
            consensus_authority_record_digest: context.consensus_authority_record_digest,
            reconciliation_authority_digest: context.reconciliation_authority_digest,
            canonical_index_states: context.canonical_index_states,
        })?;
        let token = finalized_token(&journal.snapshot)?;
        Ok((journal.snapshot, token))
    }

    /// Records a durable AbortedOld terminal state after a higher-level adapter has verified the
    /// canonical old index state and consensus-linearized abort authority.
    fn record_aborted_old(
        &self,
        context: PrivateOramOwnerJournalAbortOldContextV1<'_>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerAbortedOldTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let journal = self.record_terminal(TerminalTransition {
            phase: PrivateOramOwnerJournalPhaseV1::AbortedOld,
            expected_journal_descriptor_digest: context.expected_journal_descriptor_digest,
            parent_descriptor_digest: context.parent_descriptor_digest,
            authenticated_owner_peer_id: context.authenticated_owner_peer_id,
            consensus_authority_record_digest: context.consensus_authority_record_digest,
            reconciliation_authority_digest: context.reconciliation_authority_digest,
            canonical_index_states: context.canonical_index_states,
        })?;
        let token = aborted_old_token(&journal.snapshot)?;
        Ok((journal.snapshot, token))
    }

    fn prepare_validated(
        &self,
        desired: ValidatedOwnerJournal,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        let root_file = self.ensure_root()?;
        let root_lock = lock_private_journal_root(&root_file)?;
        self.prepare_validated_under_exclusive_lock(&root_lock, desired)
    }

    fn prepare_validated_under_exclusive_lock(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        desired: ValidatedOwnerJournal,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        root_lock.require_exclusive()?;
        let root_file = root_lock.root;
        validate_open_directory_at_path(root_file, &self.root)?;
        if Self::stable_root_entry_from(&root_file)? == StableRootEntry::Active {
            let existing = self.load_active_structural_from(&root_file, true, None)?;
            if !existing.exactly_matches(&desired) {
                return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
            }
            sync_open_directory(&root_file)
                .and_then(|()| validate_open_directory_at_path(&root_file, &self.root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            return Ok(existing.into_output());
        }

        let candidate = tempfile::Builder::new()
            .prefix(CANDIDATE_PREFIX)
            .tempdir_in(&self.root)
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
        set_private_directory_permissions(candidate.path())?;
        validate_private_directory_exact(candidate.path())?;
        write_new_private_file(
            &candidate.path().join(DESCRIPTOR_FILE),
            &desired.descriptor_bytes,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(FINAL_BUCKETS_FILE),
            &desired.final_bucket_bytes,
            MAX_FINAL_BUCKET_FRAME_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(STATE_FILE),
            &desired.state_bytes,
            MAX_STATE_BYTES,
        )?;
        let candidate_temp = candidate.path().join(ACTIVE_TEMP_DIR);
        create_private_directory(&candidate_temp)?;
        validate_directory_is_empty(&candidate_temp)?;
        validate_active_entry_set(candidate.path())?;
        sync_private_directory(&candidate_temp).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        sync_private_directory(candidate.path()).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        let candidate_file = open_private_directory(candidate.path())?;
        private_oram_owner_journal_crash_point("prepare_candidate_synced");

        validate_open_directory_at_path(root_file, &self.root)?;
        let candidate_name = candidate
            .path()
            .file_name()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        match rename_directory_noreplace(root_file, candidate_name, OsStr::new(ACTIVE_DIR)) {
            Ok(()) => {
                private_oram_owner_journal_crash_point("prepare_active_installed");
                validate_open_directory_at_path(&root_file, &self.root)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed = self
                    .load_active_structural_from(&root_file, true, Some(&candidate_file))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if !installed.exactly_matches(&desired) {
                    return Err(PrivateOramOwnerJournalError::Indeterminate);
                }
                Ok(installed.into_output())
            }
            Err(PrivateOramOwnerJournalError::ConcurrentMutation) => {
                validate_open_directory_at_path(&root_file, &self.root)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let existing = self.load_active_structural_from(&root_file, true, None)?;
                if !existing.exactly_matches(&desired) {
                    return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
                }
                Ok(existing.into_output())
            }
            Err(error) => Err(error),
        }
    }

    fn prepare_validated_with_lifecycle_guard(
        &self,
        lifecycle_lock: &PrivateOramOwnerLifecycleRootLock<'_>,
        canonical_lock: &PrivateJournalRootLock<'_>,
        desired: ValidatedOwnerJournal,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        lifecycle_lock.require_exclusive()?;
        self.prepare_validated_under_exclusive_lock(canonical_lock, desired)
    }

    fn record_terminal(
        &self,
        transition: TerminalTransition<'_>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        validate_terminal_transition(transition)?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }

        let root = open_private_directory(&self.root)?;
        let root_lock = lock_private_journal_root(&root)?;
        self.record_terminal_under_exclusive_lock(&root_lock, transition)
    }

    fn record_terminal_under_exclusive_lock(
        &self,
        root_lock: &PrivateJournalRootLock<'_>,
        transition: TerminalTransition<'_>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        root_lock.require_exclusive()?;
        validate_terminal_transition(transition)?;
        let root = root_lock.root;
        validate_open_directory_at_path(root, &self.root)?;
        if Self::stable_root_entry_from(root)? != StableRootEntry::Active {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let current = self.load_active_structural_from(root, true, None)?;
        if current.snapshot.descriptor.descriptor_digest
            != transition.expected_journal_descriptor_digest
            || current.snapshot.descriptor.parent_descriptor_digest
                != transition.parent_descriptor_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let desired_terminal = build_terminal_record(&current.snapshot, transition)?;
        let desired_terminal_bytes = encode_terminal_record(&desired_terminal)?;
        if let Some(existing) = current.snapshot.terminal.as_ref() {
            if existing != &desired_terminal
                || current.terminal_bytes.as_deref() != Some(desired_terminal_bytes.as_slice())
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            sync_open_directory(root)
                .and_then(|()| validate_open_directory_at_path(root, &self.root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            return Ok(current);
        }

        let active_path = open_directory_entry_path(root, OsStr::new(ACTIVE_DIR))?;
        let active = open_private_directory(&active_path)?;
        let temp_path = open_directory_entry_path(&active, OsStr::new(ACTIVE_TEMP_DIR))?;
        let temp = open_private_directory(&temp_path)?;
        validate_terminal_temp_entries_open(&temp)?;
        let candidate = tempfile::Builder::new()
            .prefix(TERMINAL_CANDIDATE_PREFIX)
            .tempdir_in(&temp_path)
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
        set_private_directory_permissions(candidate.path())?;
        validate_private_directory_exact(candidate.path())?;
        write_new_private_file(
            &candidate.path().join(TERMINAL_RECORD_FILE),
            &desired_terminal_bytes,
            MAX_TERMINAL_RECORD_BYTES,
        )?;
        validate_terminal_entry_set(candidate.path())?;
        sync_private_directory(candidate.path()).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        let candidate_directory = open_private_directory(candidate.path())?;
        sync_open_directory(&temp).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        private_oram_owner_journal_crash_point("terminal_candidate_synced");

        validate_open_directory_at_path(root, &self.root)?;
        validate_open_directory_at_path(&active, &active_path)?;
        validate_open_directory_at_path(&temp, &temp_path)?;
        let candidate_name = candidate
            .path()
            .file_name()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        match rename_entry_noreplace(&temp, candidate_name, &active, OsStr::new(TERMINAL_DIR)) {
            Ok(()) => {
                private_oram_owner_journal_crash_point("terminal_installed");
                let installed_terminal_path =
                    open_directory_entry_path(&active, OsStr::new(TERMINAL_DIR))
                        .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed_terminal = open_private_directory(&installed_terminal_path)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                ensure_same_open_inode(&candidate_directory, &installed_terminal)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed = self
                    .load_active_structural_from(root, true, None)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                ensure_same_open_inode(&candidate_directory, &installed_terminal)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if installed.snapshot.terminal.as_ref() != Some(&desired_terminal)
                    || installed.terminal_bytes.as_deref()
                        != Some(desired_terminal_bytes.as_slice())
                {
                    return Err(PrivateOramOwnerJournalError::Indeterminate);
                }
                Ok(installed)
            }
            Err(PrivateOramOwnerJournalError::ConcurrentMutation) => {
                let existing = self.load_active_structural_from(root, true, None)?;
                if existing.snapshot.terminal.as_ref() != Some(&desired_terminal)
                    || existing.terminal_bytes.as_deref() != Some(desired_terminal_bytes.as_slice())
                {
                    return Err(PrivateOramOwnerJournalError::InvalidTransition);
                }
                Ok(existing)
            }
            Err(error) => Err(error),
        }
    }

    fn ensure_root(&self) -> Result<File, PrivateOramOwnerJournalError> {
        let parent = self
            .root
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        let parent_file = open_private_directory(parent)?;
        let anchored_root =
            open_directory_entry_path(&parent_file, OsStr::new(PRIVATE_ORAM_OWNER_JOURNAL_DIR))?;
        create_private_directory(&anchored_root)?;
        sync_open_directory(&parent_file).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        validate_open_directory_at_path(&parent_file, parent)?;
        let root_file = open_private_directory(&anchored_root)?;
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(root_file)
    }

    fn open_existing_root(&self) -> Result<File, PrivateOramOwnerJournalError> {
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::NotEnrolled);
        }
        let parent = self
            .root
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        let parent_file = open_private_directory(parent)?;
        let anchored_root =
            open_directory_entry_path(&parent_file, OsStr::new(PRIVATE_ORAM_OWNER_JOURNAL_DIR))?;
        let root_file = open_private_directory(&anchored_root)?;
        validate_open_directory_at_path(&parent_file, parent)?;
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(root_file)
    }

    fn stable_root_entry_from(
        root: &File,
    ) -> Result<StableRootEntry, PrivateOramOwnerJournalError> {
        let mut has_active = false;
        for name in directory_entry_names_open(root)? {
            if name == OsStr::new(ACTIVE_DIR) {
                has_active = true;
            } else if completed_generation_from_name(&name)?.is_some() {
                let completed = open_private_directory(&open_directory_entry_path(root, &name)?)?;
                validate_completed_entry_set_open(&completed)?;
            } else if is_candidate_name(&name) {
                // Stranded candidates are preserved for operator inspection but are never
                // adopted as canonical state.
                validate_private_directory_exact(&open_directory_entry_path(root, &name)?)?;
            } else {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
        Ok(if has_active {
            StableRootEntry::Active
        } else {
            StableRootEntry::Empty
        })
    }

    fn load_active_structural_from(
        &self,
        root: &File,
        durably_sync: bool,
        expected_active: Option<&File>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        let validated = self.load_structural_from_named(
            root,
            OsStr::new(ACTIVE_DIR),
            false,
            durably_sync,
            expected_active,
        )?;
        if Self::stable_root_entry_from(root)? != StableRootEntry::Active {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(validated)
    }

    fn load_completed_structural_from(
        &self,
        root: &File,
        generation: u64,
        durably_sync: bool,
        expected_completed: Option<&File>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        let name = completed_generation_name(generation)?;
        self.load_structural_from_named(
            root,
            OsStr::new(&name),
            true,
            durably_sync,
            expected_completed,
        )
    }

    fn load_structural_from_named(
        &self,
        root: &File,
        entry_name: &OsStr,
        completed: bool,
        durably_sync: bool,
        expected_entry: Option<&File>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        let entry_path = open_directory_entry_path(root, entry_name)?;
        let entry = open_private_directory(&entry_path)?;
        if let Some(expected_entry) = expected_entry {
            ensure_same_open_inode(expected_entry, &entry)?;
        }
        let has_terminal = if completed {
            validate_completed_entry_set_open(&entry)?.0
        } else {
            validate_active_entry_set_open(&entry)?
        };
        if completed && !has_terminal {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let temp_path = open_directory_entry_path(&entry, OsStr::new(ACTIVE_TEMP_DIR))?;
        let temp = open_private_directory(&temp_path)?;
        validate_terminal_temp_entries_open(&temp)?;

        let (mut descriptor_file, descriptor_bytes) = read_private_file_pinned(
            &open_directory_entry_path(&entry, OsStr::new(DESCRIPTOR_FILE))?,
            MAX_DESCRIPTOR_BYTES,
        )?;
        let (mut final_bucket_file, final_bucket_bytes) = read_private_file_pinned(
            &open_directory_entry_path(&entry, OsStr::new(FINAL_BUCKETS_FILE))?,
            MAX_FINAL_BUCKET_FRAME_BYTES,
        )?;
        let (mut state_file, state_bytes) = read_private_file_pinned(
            &open_directory_entry_path(&entry, OsStr::new(STATE_FILE))?,
            MAX_STATE_BYTES,
        )?;
        let (mut terminal_file, terminal_bytes, terminal_directory, terminal_path) = if has_terminal
        {
            let terminal_path = open_directory_entry_path(&entry, OsStr::new(TERMINAL_DIR))?;
            let terminal_directory = open_private_directory(&terminal_path)?;
            validate_terminal_entry_set_open(&terminal_directory)?;
            let (terminal_file, terminal_bytes) = read_private_file_pinned(
                &open_directory_entry_path(&terminal_directory, OsStr::new(TERMINAL_RECORD_FILE))?,
                MAX_TERMINAL_RECORD_BYTES,
            )?;
            (
                Some(terminal_file),
                Some(terminal_bytes),
                Some(terminal_directory),
                Some(terminal_path),
            )
        } else {
            (None, None, None, None)
        };

        let validated = ValidatedOwnerJournal::decode(
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes,
        )?;
        if durably_sync {
            descriptor_file.sync()?;
            final_bucket_file.sync()?;
            state_file.sync()?;
            if let Some(terminal_file) = terminal_file.as_ref() {
                terminal_file.sync()?;
            }
            if let Some(terminal_directory) = terminal_directory.as_ref() {
                sync_open_directory(terminal_directory)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
            sync_open_directory(&temp).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            sync_open_directory(&entry).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            sync_open_directory(root).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }

        let reloaded_has_terminal = if completed {
            validate_completed_entry_set_open(&entry)?.0
        } else {
            validate_active_entry_set_open(&entry)?
        };
        if reloaded_has_terminal != has_terminal {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        validate_terminal_temp_entries_open(&temp)?;
        descriptor_file.validate_exact_contents(&validated.descriptor_bytes)?;
        final_bucket_file.validate_exact_contents(&validated.final_bucket_bytes)?;
        state_file.validate_exact_contents(&validated.state_bytes)?;
        if let (Some(terminal_file), Some(terminal_bytes)) =
            (terminal_file.as_mut(), validated.terminal_bytes.as_deref())
        {
            terminal_file.validate_exact_contents(terminal_bytes)?;
        }
        descriptor_file.validate_at_path()?;
        final_bucket_file.validate_at_path()?;
        state_file.validate_at_path()?;
        if let Some(terminal_file) = terminal_file.as_ref() {
            terminal_file.validate_at_path()?;
        }
        validate_open_directory_at_path(&temp, &temp_path)?;
        if let (Some(terminal_directory), Some(terminal_path)) =
            (terminal_directory.as_ref(), terminal_path.as_ref())
        {
            validate_terminal_entry_set_open(terminal_directory)?;
            validate_open_directory_at_path(terminal_directory, terminal_path)?;
        }
        validate_open_directory_at_path(&entry, &entry_path)?;
        if let Some(expected_entry) = expected_entry {
            ensure_same_open_inode(expected_entry, &entry)?;
        }
        validate_open_directory_at_path(root, &self.root)?;
        Ok(validated)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StableRootEntry {
    Empty,
    Active,
}

#[derive(Clone, Copy)]
struct TerminalTransition<'a> {
    phase: PrivateOramOwnerJournalPhaseV1,
    expected_journal_descriptor_digest: &'a str,
    parent_descriptor_digest: &'a str,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: &'a str,
    reconciliation_authority_digest: &'a str,
    canonical_index_states: &'a [PrivateOramOwnerJournalTerminalIndexStateV1],
}

#[derive(Clone)]
struct ValidatedOwnerJournal {
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    descriptor_bytes: Vec<u8>,
    final_bucket_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    terminal_bytes: Option<Vec<u8>>,
}

impl ValidatedOwnerJournal {
    fn build(
        validated: &PrivateOramValidatedOwnerPrepareV1,
        context: PrivateOramOwnerJournalPrepareContextV1<'_>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_digest(context.parent_descriptor_digest, "parent_descriptor_digest")?;
        validate_digest(
            context.parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        )?;
        let mutation = &validated.mutation_bundle().mutation;
        validate_digest(validated.mutation_digest(), "signed_mutation_digest")?;
        validate_digest(&mutation.mutation_id, "mutation_id")?;
        validate_digest(&mutation.writer_lease_digest, "writer_lease_digest")?;
        validate_resource_id(&mutation.collection_id, "collection_id")?;
        if validated.indexes().is_empty()
            || validated.indexes().len() > MAX_PAIRED_OWNER_INDEXES
            || validated.indexes().len() != context.requirements.len()
            || validated.indexes()[0].kind() != PrivateOramIndexKindV2::Hnsw
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput("indexes"));
        }

        let mut names = BTreeSet::new();
        let mut saw_result = false;
        let mut total_ordered_bucket_refs = 0usize;
        let mut indexes = Vec::with_capacity(validated.indexes().len());
        let mut final_buckets = Vec::with_capacity(validated.indexes().len());
        for (index, requirement) in validated.indexes().iter().zip(context.requirements) {
            validate_resource_id(index.index_name(), "index_name")?;
            if !names.insert(index.index_name().to_string())
                || index.kind() != requirement.kind
                || index.index_name() != requirement.index_name
                || index.old_epoch() != requirement.old_epoch
                || index.new_epoch() != requirement.new_epoch
                || index.old_root_hash() != requirement.old_root_hash
                || index.new_root_hash() != requirement.new_root_hash
                || index.writeback_digest() != requirement.writeback_digest
            {
                return Err(PrivateOramOwnerJournalError::InvalidInput("requirements"));
            }
            match index.kind() {
                PrivateOramIndexKindV2::Hnsw if indexes.is_empty() => {}
                PrivateOramIndexKindV2::Result if !saw_result => saw_result = true,
                _ => return Err(PrivateOramOwnerJournalError::InvalidInput("indexes")),
            }
            total_ordered_bucket_refs = total_ordered_bucket_refs
                .checked_add(index.ordered_bucket_refs().len())
                .ok_or(PrivateOramOwnerJournalError::InvalidInput(
                    "ordered_bucket_refs",
                ))?;
            if index.ordered_bucket_refs().is_empty()
                || index.final_bucket_refs().is_empty()
                || index.final_bucket_refs().len() > index.ordered_bucket_refs().len()
                || index
                    .final_bucket_refs()
                    .windows(2)
                    .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
            {
                return Err(PrivateOramOwnerJournalError::InvalidInput("bucket_refs"));
            }
            validate_digest(index.old_root_hash(), "old_root_hash")?;
            validate_digest(index.new_root_hash(), "new_root_hash")?;
            validate_digest(index.writeback_digest(), "writeback_digest")?;
            validate_digest(
                &index.read_transcript().transcript_digest,
                "read_transcript_digest",
            )?;
            for bucket in index
                .ordered_bucket_refs()
                .iter()
                .chain(index.final_bucket_refs())
            {
                validate_bucket_ref(bucket)?;
            }
            indexes.push(PrivateOramOwnerJournalIndexDescriptorV1 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                old_epoch: index.old_epoch(),
                new_epoch: index.new_epoch(),
                old_root_hash: index.old_root_hash().to_string(),
                new_root_hash: index.new_root_hash().to_string(),
                writeback_digest: index.writeback_digest().to_string(),
                read_path_count: index.read_transcript().read_path_count,
                read_transcript_digest: index.read_transcript().transcript_digest.clone(),
                ordered_bucket_refs: index.ordered_bucket_refs().to_vec(),
                final_bucket_refs: index.final_bucket_refs().to_vec(),
            });
            final_buckets.push(PrivateOramOwnerFinalBucketIndexV1 {
                index_name: index.index_name().to_string(),
                buckets: match index.final_buckets() {
                    PrivateOramValidatedOwnerFinalBucketsV1::Hnsw(buckets) => {
                        PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets.clone())
                    }
                    PrivateOramValidatedOwnerFinalBucketsV1::Result(buckets) => {
                        PrivateOramOwnerFinalBucketBatchV1::Result(buckets.clone())
                    }
                },
            });
        }
        if total_ordered_bucket_refs == 0
            || total_ordered_bucket_refs > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "ordered_bucket_refs",
            ));
        }

        let final_bucket_bytes = encode_final_bucket_frame(&indexes, &final_buckets)?;
        let mut descriptor = PrivateOramOwnerJournalDescriptorV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION,
            parent_descriptor_digest: context.parent_descriptor_digest.to_string(),
            parent_lease_acquired_record_digest: context
                .parent_lease_acquired_record_digest
                .to_string(),
            owner_peer_id: context.owner_peer_id,
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest: validated.mutation_digest().to_string(),
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            indexes,
            final_bucket_frame_version: PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION,
            final_bucket_frame_length: u64::try_from(final_bucket_bytes.len()).map_err(|_| {
                PrivateOramOwnerJournalError::InvalidInput("final_bucket_frame_length")
            })?,
            final_bucket_frame_sha256: digest_string(&final_bucket_bytes),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        let descriptor_bytes = encode_descriptor(&descriptor)?;

        let mut state = PrivateOramOwnerJournalStateV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
            sequence: 1,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            previous_record_digest: None,
            phase: PrivateOramOwnerJournalPhaseV1::Prepared,
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state)?;
        let state_bytes = encode_state(&state)?;

        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal: None,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes)?;
        Ok(Self {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes: None,
        })
    }

    fn decode(
        descriptor_bytes: Vec<u8>,
        final_bucket_bytes: Vec<u8>,
        state_bytes: Vec<u8>,
        terminal_bytes: Option<Vec<u8>>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        let descriptor = decode_descriptor(&descriptor_bytes)?;
        let final_buckets = decode_final_bucket_frame(&descriptor.indexes, &final_bucket_bytes)?;
        let state = decode_state(&state_bytes)?;
        let terminal = terminal_bytes
            .as_deref()
            .map(decode_terminal_record)
            .transpose()?;
        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes)?;
        Ok(Self {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes,
        })
    }

    fn exactly_matches(&self, other: &Self) -> bool {
        self.descriptor_bytes == other.descriptor_bytes
            && self.final_bucket_bytes == other.final_bucket_bytes
            && self.state_bytes == other.state_bytes
            && self.terminal_bytes == other.terminal_bytes
    }

    fn into_output(
        self,
    ) -> (
        PrivateOramOwnerJournalSnapshotV1,
        PrivateOramDurableOwnerPreparedTokenV1,
    ) {
        assert!(self.snapshot.terminal.is_none());
        let token = prepared_token(&self.snapshot.descriptor)
            .expect("decoded owner journal descriptor must produce prepared evidence");
        (self.snapshot, token)
    }
}

fn validate_snapshot(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    final_bucket_bytes: &[u8],
) -> Result<(), PrivateOramOwnerJournalError> {
    if snapshot.state.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION
        || snapshot.state.sequence != 1
        || snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || snapshot.state.previous_record_digest.is_some()
        || snapshot.state.descriptor_digest != snapshot.descriptor.descriptor_digest
        || snapshot.descriptor.final_bucket_frame_version
            != PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION
        || snapshot.descriptor.final_bucket_frame_length
            != u64::try_from(final_bucket_bytes.len())
                .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
        || snapshot.descriptor.final_bucket_frame_sha256 != digest_string(final_bucket_bytes)
        || snapshot.descriptor.indexes.len() != snapshot.final_buckets.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    for (index, final_index) in snapshot
        .descriptor
        .indexes
        .iter()
        .zip(&snapshot.final_buckets)
    {
        if index.kind != final_index.buckets.kind()
            || index.index_name != final_index.index_name
            || index.final_bucket_refs != final_bucket_refs(&final_index.buckets)
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    if let Some(terminal) = snapshot.terminal.as_ref() {
        if terminal.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION
            || terminal.sequence != 2
            || terminal.phase == PrivateOramOwnerJournalPhaseV1::Prepared
            || terminal.descriptor_digest != snapshot.descriptor.descriptor_digest
            || terminal.previous_record_digest != snapshot.state.state_digest
            || terminal.parent_descriptor_digest != snapshot.descriptor.parent_descriptor_digest
            || terminal.authenticated_owner_peer_id != snapshot.descriptor.owner_peer_id
            || terminal.canonical_index_states.len() != snapshot.descriptor.indexes.len()
            || terminal_record_digest(terminal)? != terminal.record_digest
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        for (index, canonical) in snapshot
            .descriptor
            .indexes
            .iter()
            .zip(&terminal.canonical_index_states)
        {
            if index.kind != canonical.kind
                || index.index_name != canonical.index_name
                || validate_digest(&canonical.canonical_state_digest, "canonical_state_digest")
                    .is_err()
            {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
    }
    Ok(())
}

fn prepared_token(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<PrivateOramDurableOwnerPreparedTokenV1, PrivateOramOwnerJournalError> {
    let indexes = descriptor
        .indexes
        .iter()
        .map(|index| {
            Ok(PrivateOramOwnerPreparedIndexEvidenceV1 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index_prepared_evidence_digest(descriptor, index)?,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    Ok(PrivateOramDurableOwnerPreparedTokenV1 {
        owner_peer_id: descriptor.owner_peer_id,
        journal_descriptor_digest: descriptor.descriptor_digest.clone(),
        parent_descriptor_digest: descriptor.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: descriptor.parent_lease_acquired_record_digest.clone(),
        indexes,
    })
}

fn prepared_store_binding(
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    prepared: &PrivateOramDurableOwnerPreparedTokenV1,
) -> Result<PrivateOramOwnerPreparedStoreBindingV1, PrivateOramOwnerJournalError> {
    if snapshot.terminal.is_some()
        || snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || prepared_token(&snapshot.descriptor)? != *prepared
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    Ok(PrivateOramOwnerPreparedStoreBindingV1 { snapshot })
}

fn recovery_prepared_binding<'lock>(
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    projection: &PrivateOramOwnerRecoveryProjectionV1,
    _root_lock: &'lock PrivateJournalRootLock<'_>,
) -> Result<PrivateOramOwnerRecoveryPreparedBindingV1<'lock>, PrivateOramOwnerJournalError> {
    let prepared = revalidate_recovery_projection(&snapshot, projection)?;
    let store_binding = prepared_store_binding(snapshot, &prepared)?;
    Ok(PrivateOramOwnerRecoveryPreparedBindingV1 {
        prepared,
        store_binding,
        lock_lifetime: PhantomData,
    })
}

fn recovery_exclusive_binding<'lock>(
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    projection: &PrivateOramOwnerRecoveryProjectionV1,
    root_lock: &'lock PrivateJournalRootLock<'_>,
) -> Result<PrivateOramOwnerRecoveryExclusiveBindingV1<'lock>, PrivateOramOwnerJournalError> {
    root_lock.require_exclusive()?;
    revalidate_recovery_projection(&snapshot, projection)?;
    let state = match snapshot.terminal.as_ref().map(|terminal| terminal.phase) {
        None => PrivateOramOwnerRecoveryExclusiveStateV1::Prepared,
        Some(PrivateOramOwnerJournalPhaseV1::Finalized) => {
            PrivateOramOwnerRecoveryExclusiveStateV1::FinalizedReplay
        }
        Some(PrivateOramOwnerJournalPhaseV1::AbortedOld) => {
            PrivateOramOwnerRecoveryExclusiveStateV1::AbortedOldReplay
        }
        Some(PrivateOramOwnerJournalPhaseV1::Prepared) => {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    };
    Ok(PrivateOramOwnerRecoveryExclusiveBindingV1 {
        state,
        snapshot,
        lock_lifetime: PhantomData,
        not_send_or_sync: PhantomData,
    })
}

fn revalidate_recovery_projection(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    projection: &PrivateOramOwnerRecoveryProjectionV1,
) -> Result<PrivateOramDurableOwnerPreparedTokenV1, PrivateOramOwnerJournalError> {
    let descriptor = &snapshot.descriptor;
    if snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || descriptor.indexes.len() != MAX_PAIRED_OWNER_INDEXES
        || descriptor.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || descriptor.indexes[1].kind != PrivateOramIndexKindV2::Result
        || descriptor.owner_peer_id != projection.expected_owner_peer_id
        || descriptor.parent_descriptor_digest != projection.parent_descriptor_digest
        || descriptor.parent_lease_acquired_record_digest
            != projection.parent_lease_acquired_record_digest
        || descriptor.collection_id != projection.collection_id
        || descriptor.mutation_id != projection.mutation_id
        || descriptor.signed_mutation_digest != projection.signed_mutation_digest
        || descriptor.writer_lease_digest != projection.writer_lease_digest
        || descriptor.writer_fence != projection.writer_fence
        || descriptor.indexes.len() != projection.indexes.len()
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }

    let prepared = prepared_token(descriptor)?;
    for ((descriptor_index, prepared_index), projected_index) in descriptor
        .indexes
        .iter()
        .zip(prepared.indexes())
        .zip(&projection.indexes)
    {
        if descriptor_index.kind != projected_index.kind
            || descriptor_index.index_name != projected_index.index_name
            || descriptor_index.old_epoch != projected_index.old_epoch
            || descriptor_index.new_epoch != projected_index.new_epoch
            || descriptor_index.old_root_hash != projected_index.old_root_hash
            || descriptor_index.new_root_hash != projected_index.new_root_hash
            || descriptor_index.writeback_digest != projected_index.writeback_digest
            || prepared_index.kind != projected_index.kind
            || prepared_index.index_name != projected_index.index_name
            || prepared_index.prepared_journal_digest != projected_index.prepared_journal_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
    }
    Ok(prepared)
}

fn index_prepared_evidence_digest(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
    index: &PrivateOramOwnerJournalIndexDescriptorV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    let mut bytes = Vec::with_capacity(512);
    push_domain(&mut bytes, INDEX_PREPARED_EVIDENCE_DOMAIN)?;
    push_digest(
        &mut bytes,
        &descriptor.descriptor_digest,
        "descriptor_digest",
    )?;
    bytes.extend_from_slice(&descriptor.owner_peer_id.to_be_bytes());
    bytes.push(kind_tag(index.kind));
    push_resource_id(&mut bytes, &index.index_name, "index_name")?;
    bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
    bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
    push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
    push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
    push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
    Ok(digest_string(&bytes))
}

fn build_terminal_record(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    transition: TerminalTransition<'_>,
) -> Result<PrivateOramOwnerJournalTerminalRecordV1, PrivateOramOwnerJournalError> {
    if snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || transition.phase == PrivateOramOwnerJournalPhaseV1::Prepared
        || snapshot.descriptor.descriptor_digest != transition.expected_journal_descriptor_digest
        || snapshot.descriptor.parent_descriptor_digest != transition.parent_descriptor_digest
        || snapshot.descriptor.owner_peer_id != transition.authenticated_owner_peer_id
        || snapshot.descriptor.indexes.len() != transition.canonical_index_states.len()
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    for (index, canonical) in snapshot
        .descriptor
        .indexes
        .iter()
        .zip(transition.canonical_index_states)
    {
        if index.kind != canonical.kind || index.index_name != canonical.index_name {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        validate_digest(&canonical.canonical_state_digest, "canonical_state_digest")?;
    }
    let mut record = PrivateOramOwnerJournalTerminalRecordV1 {
        version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
        sequence: 2,
        descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        previous_record_digest: snapshot.state.state_digest.clone(),
        phase: transition.phase,
        parent_descriptor_digest: transition.parent_descriptor_digest.to_string(),
        authenticated_owner_peer_id: transition.authenticated_owner_peer_id,
        consensus_authority_record_digest: transition.consensus_authority_record_digest.to_string(),
        reconciliation_authority_digest: transition.reconciliation_authority_digest.to_string(),
        canonical_index_states: transition.canonical_index_states.to_vec(),
        record_digest: String::new(),
    };
    record.record_digest = terminal_record_digest(&record)?;
    Ok(record)
}

fn validate_terminal_transition(
    transition: TerminalTransition<'_>,
) -> Result<(), PrivateOramOwnerJournalError> {
    if transition.phase == PrivateOramOwnerJournalPhaseV1::Prepared {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    validate_digest(
        transition.expected_journal_descriptor_digest,
        "expected_journal_descriptor_digest",
    )?;
    validate_digest(
        transition.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    validate_digest(
        transition.consensus_authority_record_digest,
        "consensus_authority_record_digest",
    )?;
    validate_digest(
        transition.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )
}

fn finalized_token(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
) -> Result<PrivateOramDurableOwnerFinalizedTokenV1, PrivateOramOwnerJournalError> {
    let terminal = snapshot
        .terminal
        .as_ref()
        .filter(|terminal| terminal.phase == PrivateOramOwnerJournalPhaseV1::Finalized)
        .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
    let indexes = snapshot
        .descriptor
        .indexes
        .iter()
        .map(|index| {
            Ok(PrivateOramOwnerFinalizedIndexEvidenceV1 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index_prepared_evidence_digest(
                    &snapshot.descriptor,
                    index,
                )?,
                finalized_state_digest: index_terminal_evidence_digest(snapshot, terminal, index)?,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    Ok(PrivateOramDurableOwnerFinalizedTokenV1 {
        owner_peer_id: snapshot.descriptor.owner_peer_id,
        journal_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        prepared_state_digest: snapshot.state.state_digest.clone(),
        terminal_record_digest: terminal.record_digest.clone(),
        parent_descriptor_digest: terminal.parent_descriptor_digest.clone(),
        consensus_authority_record_digest: terminal.consensus_authority_record_digest.clone(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest.clone(),
        indexes,
    })
}

fn aborted_old_token(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
) -> Result<PrivateOramDurableOwnerAbortedOldTokenV1, PrivateOramOwnerJournalError> {
    let terminal = snapshot
        .terminal
        .as_ref()
        .filter(|terminal| terminal.phase == PrivateOramOwnerJournalPhaseV1::AbortedOld)
        .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
    let indexes = snapshot
        .descriptor
        .indexes
        .iter()
        .map(|index| {
            Ok(PrivateOramOwnerAbortedOldIndexEvidenceV1 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index_prepared_evidence_digest(
                    &snapshot.descriptor,
                    index,
                )?,
                aborted_old_state_digest: index_terminal_evidence_digest(
                    snapshot, terminal, index,
                )?,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    Ok(PrivateOramDurableOwnerAbortedOldTokenV1 {
        owner_peer_id: snapshot.descriptor.owner_peer_id,
        journal_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        prepared_state_digest: snapshot.state.state_digest.clone(),
        terminal_record_digest: terminal.record_digest.clone(),
        parent_descriptor_digest: terminal.parent_descriptor_digest.clone(),
        consensus_authority_record_digest: terminal.consensus_authority_record_digest.clone(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest.clone(),
        indexes,
    })
}

fn index_terminal_evidence_digest(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    terminal: &PrivateOramOwnerJournalTerminalRecordV1,
    index: &PrivateOramOwnerJournalIndexDescriptorV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    let domain = match terminal.phase {
        PrivateOramOwnerJournalPhaseV1::Finalized => INDEX_FINALIZED_EVIDENCE_DOMAIN,
        PrivateOramOwnerJournalPhaseV1::AbortedOld => INDEX_ABORTED_OLD_EVIDENCE_DOMAIN,
        PrivateOramOwnerJournalPhaseV1::Prepared => {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    };
    let canonical = terminal
        .canonical_index_states
        .iter()
        .find(|canonical| canonical.kind == index.kind && canonical.index_name == index.index_name)
        .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
    let mut bytes = Vec::with_capacity(1024);
    push_domain(&mut bytes, domain)?;
    push_digest(
        &mut bytes,
        &snapshot.descriptor.descriptor_digest,
        "descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &snapshot.state.state_digest,
        "prepared_state_digest",
    )?;
    push_digest(
        &mut bytes,
        &terminal.record_digest,
        "terminal_record_digest",
    )?;
    bytes.extend_from_slice(&snapshot.descriptor.owner_peer_id.to_be_bytes());
    bytes.push(kind_tag(index.kind));
    push_resource_id(&mut bytes, &index.index_name, "index_name")?;
    bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
    bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
    push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
    push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
    push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
    push_bucket_refs(&mut bytes, &index.final_bucket_refs)?;
    push_digest(
        &mut bytes,
        &canonical.canonical_state_digest,
        "canonical_state_digest",
    )?;
    Ok(digest_string(&bytes))
}

fn descriptor_digest(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    Ok(digest_string(&descriptor_body(descriptor)?))
}

fn encode_descriptor(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let mut bytes = descriptor_body(descriptor)?;
    if descriptor.descriptor_digest != digest_string(&bytes) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    push_digest(
        &mut bytes,
        &descriptor.descriptor_digest,
        "descriptor_digest",
    )?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn descriptor_body(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if descriptor.version != PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION
        || descriptor.indexes.is_empty()
        || descriptor.indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || descriptor.final_bucket_frame_version != PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION
        || descriptor.final_bucket_frame_length == 0
        || descriptor.final_bucket_frame_length > MAX_FINAL_BUCKET_FRAME_BYTES
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(4096);
    push_domain(&mut bytes, DESCRIPTOR_DOMAIN)?;
    bytes.extend_from_slice(&descriptor.version.to_be_bytes());
    push_digest(
        &mut bytes,
        &descriptor.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.parent_lease_acquired_record_digest,
        "parent_lease_acquired_record_digest",
    )?;
    bytes.extend_from_slice(&descriptor.owner_peer_id.to_be_bytes());
    push_resource_id(&mut bytes, &descriptor.collection_id, "collection_id")?;
    push_digest(&mut bytes, &descriptor.mutation_id, "mutation_id")?;
    push_digest(
        &mut bytes,
        &descriptor.signed_mutation_digest,
        "signed_mutation_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.writer_lease_digest,
        "writer_lease_digest",
    )?;
    bytes.extend_from_slice(&descriptor.writer_fence.to_be_bytes());
    push_len(&mut bytes, descriptor.indexes.len(), "indexes")?;
    let mut names = BTreeSet::new();
    let mut total_ordered = 0usize;
    for (ordinal, index) in descriptor.indexes.iter().enumerate() {
        if !names.insert(index.index_name.as_str())
            || (ordinal == 0 && index.kind != PrivateOramIndexKindV2::Hnsw)
            || (ordinal > 0 && index.kind != PrivateOramIndexKindV2::Result)
            || index.old_epoch.checked_add(1) != Some(index.new_epoch)
            || index.old_root_hash == index.new_root_hash
            || index.read_path_count == 0
            || index.ordered_bucket_refs.is_empty()
            || index.final_bucket_refs.is_empty()
            || index.final_bucket_refs.len() > index.ordered_bucket_refs.len()
            || index
                .final_bucket_refs
                .windows(2)
                .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
            || collapse_ordered_bucket_refs(&index.ordered_bucket_refs) != index.final_bucket_refs
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        total_ordered = total_ordered
            .checked_add(index.ordered_bucket_refs.len())
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        bytes.push(kind_tag(index.kind));
        push_resource_id(&mut bytes, &index.index_name, "index_name")?;
        bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
        bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
        push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
        push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
        push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
        bytes.extend_from_slice(&index.read_path_count.to_be_bytes());
        push_digest(
            &mut bytes,
            &index.read_transcript_digest,
            "read_transcript_digest",
        )?;
        push_bucket_refs(&mut bytes, &index.ordered_bucket_refs)?;
        push_bucket_refs(&mut bytes, &index.final_bucket_refs)?;
    }
    if total_ordered == 0 || total_ordered > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    bytes.extend_from_slice(&descriptor.final_bucket_frame_version.to_be_bytes());
    bytes.extend_from_slice(&descriptor.final_bucket_frame_length.to_be_bytes());
    push_digest(
        &mut bytes,
        &descriptor.final_bucket_frame_sha256,
        "final_bucket_frame_sha256",
    )?;
    Ok(bytes)
}

fn decode_descriptor(
    bytes: &[u8],
) -> Result<PrivateOramOwnerJournalDescriptorV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(DESCRIPTOR_DOMAIN)?;
    let version = decoder.read_u16()?;
    let parent_descriptor_digest = decoder.read_digest()?;
    let parent_lease_acquired_record_digest = decoder.read_digest()?;
    let owner_peer_id = decoder.read_u64()?;
    let collection_id = decoder.read_resource_id()?;
    let mutation_id = decoder.read_digest()?;
    let signed_mutation_digest = decoder.read_digest()?;
    let writer_lease_digest = decoder.read_digest()?;
    let writer_fence = decoder.read_u64()?;
    let index_count = decoder.read_len(MAX_PAIRED_OWNER_INDEXES)?;
    let mut indexes = Vec::with_capacity(index_count);
    for _ in 0..index_count {
        indexes.push(PrivateOramOwnerJournalIndexDescriptorV1 {
            kind: decoder.read_kind()?,
            index_name: decoder.read_resource_id()?,
            old_epoch: decoder.read_u64()?,
            new_epoch: decoder.read_u64()?,
            old_root_hash: decoder.read_digest()?,
            new_root_hash: decoder.read_digest()?,
            writeback_digest: decoder.read_digest()?,
            read_path_count: decoder.read_u32()?,
            read_transcript_digest: decoder.read_digest()?,
            ordered_bucket_refs: decoder
                .read_bucket_refs(PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)?,
            final_bucket_refs: decoder
                .read_bucket_refs(PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)?,
        });
    }
    let final_bucket_frame_version = decoder.read_u16()?;
    let final_bucket_frame_length = decoder.read_u64()?;
    let final_bucket_frame_sha256 = decoder.read_digest()?;
    let descriptor_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let descriptor = PrivateOramOwnerJournalDescriptorV1 {
        version,
        parent_descriptor_digest,
        parent_lease_acquired_record_digest,
        owner_peer_id,
        collection_id,
        mutation_id,
        signed_mutation_digest,
        writer_lease_digest,
        writer_fence,
        indexes,
        final_bucket_frame_version,
        final_bucket_frame_length,
        final_bucket_frame_sha256,
        descriptor_digest,
    };
    if encode_descriptor(&descriptor)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(descriptor)
}

fn state_digest(
    state: &PrivateOramOwnerJournalStateV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    Ok(digest_string(&state_body(state)?))
}

fn encode_state(
    state: &PrivateOramOwnerJournalStateV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let mut bytes = state_body(state)?;
    if state.state_digest != digest_string(&bytes) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    push_digest(&mut bytes, &state.state_digest, "state_digest")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn state_body(
    state: &PrivateOramOwnerJournalStateV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if state.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION
        || state.sequence != 1
        || state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || state.previous_record_digest.is_some()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(160);
    push_domain(&mut bytes, STATE_DOMAIN)?;
    bytes.extend_from_slice(&state.version.to_be_bytes());
    bytes.extend_from_slice(&state.sequence.to_be_bytes());
    bytes.push(PREPARED_PHASE_TAG);
    push_digest(&mut bytes, &state.descriptor_digest, "descriptor_digest")?;
    bytes.push(0);
    Ok(bytes)
}

fn decode_state(
    bytes: &[u8],
) -> Result<PrivateOramOwnerJournalStateV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(STATE_DOMAIN)?;
    let version = decoder.read_u16()?;
    let sequence = decoder.read_u64()?;
    let phase = match decoder.read_u8()? {
        PREPARED_PHASE_TAG => PrivateOramOwnerJournalPhaseV1::Prepared,
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    let descriptor_digest = decoder.read_digest()?;
    let previous_record_digest = match decoder.read_u8()? {
        0 => None,
        1 => Some(decoder.read_digest()?),
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    let state_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let state = PrivateOramOwnerJournalStateV1 {
        version,
        sequence,
        descriptor_digest,
        previous_record_digest,
        phase,
        state_digest,
    };
    if encode_state(&state)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(state)
}

fn terminal_record_digest(
    record: &PrivateOramOwnerJournalTerminalRecordV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    Ok(digest_string(&terminal_record_body(record)?))
}

fn encode_terminal_record(
    record: &PrivateOramOwnerJournalTerminalRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let mut bytes = terminal_record_body(record)?;
    if record.record_digest != digest_string(&bytes) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    push_digest(&mut bytes, &record.record_digest, "terminal_record_digest")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TERMINAL_RECORD_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn terminal_record_body(
    record: &PrivateOramOwnerJournalTerminalRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if record.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION || record.sequence != 2 {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    validate_digest(&record.descriptor_digest, "descriptor_digest")?;
    validate_digest(&record.previous_record_digest, "previous_record_digest")?;
    validate_digest(&record.parent_descriptor_digest, "parent_descriptor_digest")?;
    validate_digest(
        &record.consensus_authority_record_digest,
        "consensus_authority_record_digest",
    )?;
    validate_digest(
        &record.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )?;
    if record.canonical_index_states.is_empty()
        || record.canonical_index_states.len() > MAX_PAIRED_OWNER_INDEXES
        || record.canonical_index_states[0].kind != PrivateOramIndexKindV2::Hnsw
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut names = BTreeSet::new();
    for (position, canonical) in record.canonical_index_states.iter().enumerate() {
        validate_resource_id(&canonical.index_name, "index_name")?;
        validate_digest(&canonical.canonical_state_digest, "canonical_state_digest")?;
        if !names.insert(canonical.index_name.clone()) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        match (position, canonical.kind) {
            (0, PrivateOramIndexKindV2::Hnsw) | (1, PrivateOramIndexKindV2::Result) => {}
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        }
    }
    let mut bytes = Vec::with_capacity(512);
    push_domain(&mut bytes, terminal_record_domain(record.phase)?)?;
    bytes.extend_from_slice(&record.version.to_be_bytes());
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.push(terminal_phase_tag(record.phase)?);
    push_digest(&mut bytes, &record.descriptor_digest, "descriptor_digest")?;
    push_digest(
        &mut bytes,
        &record.previous_record_digest,
        "previous_record_digest",
    )?;
    push_digest(
        &mut bytes,
        &record.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &record.consensus_authority_record_digest,
        "consensus_authority_record_digest",
    )?;
    push_digest(
        &mut bytes,
        &record.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )?;
    bytes.extend_from_slice(&record.authenticated_owner_peer_id.to_be_bytes());
    push_len(
        &mut bytes,
        record.canonical_index_states.len(),
        "canonical_index_states",
    )?;
    for canonical in &record.canonical_index_states {
        bytes.push(kind_tag(canonical.kind));
        push_resource_id(&mut bytes, &canonical.index_name, "index_name")?;
        push_digest(
            &mut bytes,
            &canonical.canonical_state_digest,
            "canonical_state_digest",
        )?;
    }
    Ok(bytes)
}

fn decode_terminal_record(
    bytes: &[u8],
) -> Result<PrivateOramOwnerJournalTerminalRecordV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_TERMINAL_RECORD_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    let domain_index =
        decoder.read_domain_choice(&[FINALIZED_STATE_DOMAIN, ABORTED_OLD_STATE_DOMAIN])?;
    let domain_phase = match domain_index {
        0 => PrivateOramOwnerJournalPhaseV1::Finalized,
        1 => PrivateOramOwnerJournalPhaseV1::AbortedOld,
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    let version = decoder.read_u16()?;
    let sequence = decoder.read_u64()?;
    let phase = match decoder.read_u8()? {
        FINALIZED_PHASE_TAG => PrivateOramOwnerJournalPhaseV1::Finalized,
        ABORTED_OLD_PHASE_TAG => PrivateOramOwnerJournalPhaseV1::AbortedOld,
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    if phase != domain_phase {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let descriptor_digest = decoder.read_digest()?;
    let previous_record_digest = decoder.read_digest()?;
    let parent_descriptor_digest = decoder.read_digest()?;
    let consensus_authority_record_digest = decoder.read_digest()?;
    let reconciliation_authority_digest = decoder.read_digest()?;
    let authenticated_owner_peer_id = decoder.read_u64()?;
    let canonical_index_count = decoder.read_len(MAX_PAIRED_OWNER_INDEXES)?;
    let mut canonical_index_states = Vec::with_capacity(canonical_index_count);
    for _ in 0..canonical_index_count {
        let kind = match decoder.read_u8()? {
            HNSW_KIND_TAG => PrivateOramIndexKindV2::Hnsw,
            RESULT_KIND_TAG => PrivateOramIndexKindV2::Result,
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        };
        canonical_index_states.push(PrivateOramOwnerJournalTerminalIndexStateV1 {
            kind,
            index_name: decoder.read_resource_id()?,
            canonical_state_digest: decoder.read_digest()?,
        });
    }
    let record_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let record = PrivateOramOwnerJournalTerminalRecordV1 {
        version,
        sequence,
        descriptor_digest,
        previous_record_digest,
        phase,
        parent_descriptor_digest,
        authenticated_owner_peer_id,
        consensus_authority_record_digest,
        reconciliation_authority_digest,
        canonical_index_states,
        record_digest,
    };
    if encode_terminal_record(&record)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(record)
}

fn terminal_record_domain(
    phase: PrivateOramOwnerJournalPhaseV1,
) -> Result<&'static [u8], PrivateOramOwnerJournalError> {
    match phase {
        PrivateOramOwnerJournalPhaseV1::Finalized => Ok(FINALIZED_STATE_DOMAIN),
        PrivateOramOwnerJournalPhaseV1::AbortedOld => Ok(ABORTED_OLD_STATE_DOMAIN),
        PrivateOramOwnerJournalPhaseV1::Prepared => Err(PrivateOramOwnerJournalError::Corrupt),
    }
}

fn terminal_phase_tag(
    phase: PrivateOramOwnerJournalPhaseV1,
) -> Result<u8, PrivateOramOwnerJournalError> {
    match phase {
        PrivateOramOwnerJournalPhaseV1::Finalized => Ok(FINALIZED_PHASE_TAG),
        PrivateOramOwnerJournalPhaseV1::AbortedOld => Ok(ABORTED_OLD_PHASE_TAG),
        PrivateOramOwnerJournalPhaseV1::Prepared => Err(PrivateOramOwnerJournalError::Corrupt),
    }
}

fn validate_committed_archive_grant_indexes_v1(
    indexes: &[PrivateOramOwnerCommittedArchiveGrantIndexV1],
) -> Result<(), PrivateOramOwnerJournalError> {
    if indexes.is_empty()
        || indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || indexes[0].kind != PrivateOramIndexKindV2::Hnsw
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput(
            "archive_indexes",
        ));
    }
    let mut names = BTreeSet::new();
    for (position, index) in indexes.iter().enumerate() {
        validate_resource_id(&index.index_name, "index_name")?;
        validate_digest(&index.prepared_journal_digest, "prepared_journal_digest")?;
        validate_digest(&index.terminal_state_digest, "terminal_state_digest")?;
        if !names.insert(index.index_name.as_str())
            || !matches!(
                (position, index.kind),
                (0, PrivateOramIndexKindV2::Hnsw) | (1, PrivateOramIndexKindV2::Result)
            )
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "archive_indexes",
            ));
        }
    }
    Ok(())
}

fn committed_archive_grant_digest_v1(
    grant: &PrivateOramOwnerCommittedArchiveGrantV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    validate_private_oram_owner_prestage_receipt_v2(&grant.receipt)?;
    validate_committed_archive_grant_indexes_v1(&grant.indexes)?;
    let mut bytes = Vec::with_capacity(4096);
    push_domain(&mut bytes, OWNER_COMMITTED_ARCHIVE_GRANT_DOMAIN)?;
    bytes.extend_from_slice(&grant.version.to_be_bytes());
    push_len(
        &mut bytes,
        grant.terminal_archive_format.len(),
        "terminal_archive_format",
    )?;
    bytes.extend_from_slice(grant.terminal_archive_format.as_bytes());
    bytes.extend_from_slice(&grant.terminal_archive_file_len.to_be_bytes());
    push_digest(
        &mut bytes,
        &grant.terminal_archive_file_sha256,
        "terminal_archive_file_sha256",
    )?;
    bytes.extend_from_slice(&grant.generation.to_be_bytes());
    push_resource_id(&mut bytes, &grant.collection_id, "collection_id")?;
    push_digest(&mut bytes, &grant.mutation_id, "mutation_id")?;
    push_resource_id(&mut bytes, &grant.vector_name, "vector_name")?;
    bytes.extend_from_slice(&grant.owner_peer_id.to_be_bytes());
    push_digest(
        &mut bytes,
        &grant.owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    bytes.extend_from_slice(&grant.writer_fence.to_be_bytes());
    push_digest(&mut bytes, &grant.intent_key, "intent_key")?;
    push_digest(
        &mut bytes,
        &grant.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &grant.parent_lease_acquired_record_digest,
        "parent_lease_acquired_record_digest",
    )?;
    push_digest(
        &mut bytes,
        grant.receipt.receipt_digest(),
        "prestage_receipt_digest",
    )?;
    for (field, digest) in [
        (
            "parent_terminal_record_digest",
            grant.parent_terminal_record_digest.as_str(),
        ),
        (
            "parent_archive_record_digest",
            grant.parent_archive_record_digest.as_str(),
        ),
        (
            "pending_tombstone_digest",
            grant.pending_tombstone_digest.as_str(),
        ),
        ("clear_receipt_digest", grant.clear_receipt_digest.as_str()),
        (
            "owner_terminal_record_digest",
            grant.owner_terminal_record_digest.as_str(),
        ),
        (
            "decision_authority_record_digest",
            grant.decision_authority_record_digest.as_str(),
        ),
        (
            "reconciliation_authority_digest",
            grant.reconciliation_authority_digest.as_str(),
        ),
        (
            "owner_terminal_evidence_digest",
            grant.owner_terminal_evidence_digest.as_str(),
        ),
    ] {
        push_digest(&mut bytes, digest, field)?;
    }
    push_len(&mut bytes, grant.indexes.len(), "archive_indexes")?;
    for index in &grant.indexes {
        bytes.push(kind_tag(index.kind));
        push_resource_id(&mut bytes, &index.index_name, "index_name")?;
        push_digest(
            &mut bytes,
            &index.prepared_journal_digest,
            "prepared_journal_digest",
        )?;
        push_digest(
            &mut bytes,
            &index.terminal_state_digest,
            "terminal_state_digest",
        )?;
    }
    Ok(digest_string(&bytes))
}

fn validate_committed_archive_grant_v1(
    grant: &PrivateOramOwnerCommittedArchiveGrantV1,
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_oram_owner_prestage_receipt_v2(&grant.receipt)?;
    validate_committed_archive_grant_indexes_v1(&grant.indexes)?;
    if grant.version != OWNER_COMMITTED_ARCHIVE_GRANT_VERSION
        || grant.terminal_archive_format != OWNER_COMMITTED_ARCHIVE_TERMINAL_FORMAT_V2
        || grant.terminal_archive_file_len == 0
        || grant.terminal_archive_file_len > PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_MAX_BYTES_V2
        || grant.generation == 0
        || grant.writer_fence == 0
        || grant.generation != grant.receipt.lease_generation()
        || grant.collection_id != grant.receipt.collection_id()
        || grant.mutation_id != grant.receipt.mutation_id()
        || grant.owner_peer_id != grant.receipt.owner_peer_id()
        || grant.owner_store_incarnation_digest != grant.receipt.owner_store_incarnation_digest()
        || grant.writer_fence != grant.receipt.writer_fence()
        || grant.intent_key != grant.receipt.intent_key()
        || grant.prestage_receipt_digest != grant.receipt.receipt_digest()
        || grant.parent_descriptor_digest != grant.receipt.parent_descriptor_digest()
        || grant.parent_lease_acquired_record_digest
            != grant.receipt.parent_lease_acquired_record_digest()
        || grant.indexes[0].index_name != grant.vector_name
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    validate_resource_id(&grant.collection_id, "collection_id")?;
    validate_resource_id(&grant.vector_name, "vector_name")?;
    for (field, digest) in [
        ("mutation_id", grant.mutation_id.as_str()),
        (
            "owner_store_incarnation_digest",
            grant.owner_store_incarnation_digest.as_str(),
        ),
        (
            "terminal_archive_file_sha256",
            grant.terminal_archive_file_sha256.as_str(),
        ),
        ("intent_key", grant.intent_key.as_str()),
        (
            "prestage_receipt_digest",
            grant.prestage_receipt_digest.as_str(),
        ),
        (
            "parent_descriptor_digest",
            grant.parent_descriptor_digest.as_str(),
        ),
        (
            "parent_lease_acquired_record_digest",
            grant.parent_lease_acquired_record_digest.as_str(),
        ),
        (
            "parent_terminal_record_digest",
            grant.parent_terminal_record_digest.as_str(),
        ),
        (
            "parent_archive_record_digest",
            grant.parent_archive_record_digest.as_str(),
        ),
        (
            "pending_tombstone_digest",
            grant.pending_tombstone_digest.as_str(),
        ),
        ("clear_receipt_digest", grant.clear_receipt_digest.as_str()),
        (
            "owner_terminal_record_digest",
            grant.owner_terminal_record_digest.as_str(),
        ),
        (
            "decision_authority_record_digest",
            grant.decision_authority_record_digest.as_str(),
        ),
        (
            "reconciliation_authority_digest",
            grant.reconciliation_authority_digest.as_str(),
        ),
        (
            "owner_terminal_evidence_digest",
            grant.owner_terminal_evidence_digest.as_str(),
        ),
        ("grant_digest", grant.grant_digest.as_str()),
    ] {
        validate_digest(digest, field)?;
    }
    if grant.grant_digest != committed_archive_grant_digest_v1(grant)? {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn build_owner_terminal_archive_v1(
    authority: &PrivateOramOwnerCommittedArchiveGrantV1,
    owner_store_incarnation_digest: &str,
    loaded: &LoadedPrivateOramOwnerPrestageIntentV2,
    journal: &ValidatedOwnerJournal,
) -> Result<PrivateOramOwnerTerminalArchiveV1, PrivateOramOwnerJournalError> {
    validate_digest(
        owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    if validate_committed_archive_grant_v1(authority).is_err()
        || owner_store_incarnation_digest != authority.owner_store_incarnation_digest
        || loaded.receipt != authority.receipt
        || loaded.state() != PrivateOramOwnerLocalIntentStateV2::Adopted
        || !terminalized_journal_matches_prestaged_v1(&loaded.prepared, journal)
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    let descriptor = &journal.snapshot.descriptor;
    let state = &journal.snapshot.state;
    let terminal = journal
        .snapshot
        .terminal
        .as_ref()
        .filter(|terminal| terminal.phase == PrivateOramOwnerJournalPhaseV1::Finalized)
        .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
    if descriptor.collection_id != authority.receipt.collection_id()
        || descriptor.mutation_id != authority.receipt.mutation_id()
        || descriptor.signed_mutation_digest != authority.receipt.mutation_digest()
        || descriptor.writer_fence != authority.receipt.writer_fence()
        || descriptor.owner_peer_id != authority.receipt.owner_peer_id()
        || descriptor.parent_descriptor_digest != authority.receipt.parent_descriptor_digest()
        || descriptor.parent_lease_acquired_record_digest
            != authority.receipt.parent_lease_acquired_record_digest()
        || descriptor.descriptor_digest != authority.receipt.owner_journal_descriptor_digest()
        || state.state_digest != authority.receipt.prepared_state_digest()
        || terminal.record_digest != authority.owner_terminal_record_digest
        || terminal.parent_descriptor_digest != authority.receipt.parent_descriptor_digest()
        || terminal.authenticated_owner_peer_id != authority.receipt.owner_peer_id()
        || terminal.consensus_authority_record_digest != authority.decision_authority_record_digest
        || terminal.reconciliation_authority_digest != authority.reconciliation_authority_digest
        || descriptor.indexes.len() != authority.indexes.len()
        || terminal.canonical_index_states.len() != authority.indexes.len()
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    let indexes = descriptor
        .indexes
        .iter()
        .zip(&authority.indexes)
        .map(|(descriptor_index, expected)| {
            let prepared_journal_digest =
                index_prepared_evidence_digest(descriptor, descriptor_index)?;
            let terminal_state_digest =
                index_terminal_evidence_digest(&journal.snapshot, terminal, descriptor_index)?;
            if descriptor_index.kind != expected.kind
                || descriptor_index.index_name != expected.index_name
                || prepared_journal_digest != expected.prepared_journal_digest
                || terminal_state_digest != expected.terminal_state_digest
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            Ok(PrivateOramOwnerTerminalArchiveIndexV1 {
                kind: descriptor_index.kind,
                index_name: descriptor_index.index_name.clone(),
                old_epoch: descriptor_index.old_epoch,
                new_epoch: descriptor_index.new_epoch,
                old_root_hash: descriptor_index.old_root_hash.clone(),
                new_root_hash: descriptor_index.new_root_hash.clone(),
                writeback_digest: descriptor_index.writeback_digest.clone(),
                prepared_journal_digest,
                terminal_state_digest,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    let adopted_marker = loaded
        .adopted_marker
        .as_ref()
        .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
    let mut archive = PrivateOramOwnerTerminalArchiveV1 {
        version: OWNER_TERMINAL_ARCHIVE_VERSION,
        generation: authority.receipt.lease_generation(),
        owner_store_incarnation_digest: owner_store_incarnation_digest.to_string(),
        collection_id: descriptor.collection_id.clone(),
        owner_peer_id: descriptor.owner_peer_id,
        mutation_id: descriptor.mutation_id.clone(),
        signed_mutation_digest: descriptor.signed_mutation_digest.clone(),
        writer_fence: descriptor.writer_fence,
        parent_descriptor_digest: descriptor.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: descriptor.parent_lease_acquired_record_digest.clone(),
        parent_terminal_record_digest: authority.parent_terminal_record_digest.clone(),
        parent_archive_record_digest: authority.parent_archive_record_digest.clone(),
        pending_tombstone_digest: authority.pending_tombstone_digest.clone(),
        clear_receipt_digest: authority.clear_receipt_digest.clone(),
        owner_journal_descriptor_digest: descriptor.descriptor_digest.clone(),
        owner_prepared_state_digest: state.state_digest.clone(),
        owner_terminal_record_digest: terminal.record_digest.clone(),
        owner_terminal_phase: terminal.phase,
        decision_authority_record_digest: terminal.consensus_authority_record_digest.clone(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest.clone(),
        owner_terminal_evidence_digest: authority.owner_terminal_evidence_digest.clone(),
        intent_key: authority.receipt.intent_key().to_string(),
        prestage_receipt_digest: authority.receipt.receipt_digest().to_string(),
        prestage_adopted_marker_digest: adopted_marker.marker_digest.clone(),
        indexes,
        archive_authority_digest: authority.grant_digest.clone(),
        archive_record_digest: String::new(),
    };
    archive.archive_record_digest = owner_terminal_archive_digest_v1(&archive)?;
    validate_owner_terminal_archive_v1(&archive)?;
    Ok(archive)
}

fn owner_terminal_archive_digest_v1(
    archive: &PrivateOramOwnerTerminalArchiveV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    let mut bytes = Vec::with_capacity(4096);
    push_domain(&mut bytes, OWNER_TERMINAL_ARCHIVE_DOMAIN)?;
    bytes.extend_from_slice(&archive.version.to_be_bytes());
    bytes.extend_from_slice(&archive.generation.to_be_bytes());
    push_digest(
        &mut bytes,
        &archive.owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    push_resource_id(&mut bytes, &archive.collection_id, "collection_id")?;
    bytes.extend_from_slice(&archive.owner_peer_id.to_be_bytes());
    push_digest(&mut bytes, &archive.mutation_id, "mutation_id")?;
    push_digest(
        &mut bytes,
        &archive.signed_mutation_digest,
        "signed_mutation_digest",
    )?;
    bytes.extend_from_slice(&archive.writer_fence.to_be_bytes());
    for (field, digest) in [
        (
            "parent_descriptor_digest",
            archive.parent_descriptor_digest.as_str(),
        ),
        (
            "parent_lease_acquired_record_digest",
            archive.parent_lease_acquired_record_digest.as_str(),
        ),
        (
            "parent_terminal_record_digest",
            archive.parent_terminal_record_digest.as_str(),
        ),
        (
            "parent_archive_record_digest",
            archive.parent_archive_record_digest.as_str(),
        ),
        (
            "pending_tombstone_digest",
            archive.pending_tombstone_digest.as_str(),
        ),
        (
            "clear_receipt_digest",
            archive.clear_receipt_digest.as_str(),
        ),
        (
            "owner_journal_descriptor_digest",
            archive.owner_journal_descriptor_digest.as_str(),
        ),
        (
            "owner_prepared_state_digest",
            archive.owner_prepared_state_digest.as_str(),
        ),
        (
            "owner_terminal_record_digest",
            archive.owner_terminal_record_digest.as_str(),
        ),
        (
            "decision_authority_record_digest",
            archive.decision_authority_record_digest.as_str(),
        ),
        (
            "reconciliation_authority_digest",
            archive.reconciliation_authority_digest.as_str(),
        ),
        (
            "owner_terminal_evidence_digest",
            archive.owner_terminal_evidence_digest.as_str(),
        ),
    ] {
        push_digest(&mut bytes, digest, field)?;
    }
    bytes.push(terminal_phase_tag(archive.owner_terminal_phase)?);
    push_digest(&mut bytes, &archive.intent_key, "intent_key")?;
    push_digest(
        &mut bytes,
        &archive.prestage_receipt_digest,
        "prestage_receipt_digest",
    )?;
    push_digest(
        &mut bytes,
        &archive.prestage_adopted_marker_digest,
        "prestage_adopted_marker_digest",
    )?;
    push_len(&mut bytes, archive.indexes.len(), "archive_indexes")?;
    for index in &archive.indexes {
        bytes.push(kind_tag(index.kind));
        push_resource_id(&mut bytes, &index.index_name, "index_name")?;
        bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
        bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
        push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
        push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
        push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
        push_digest(
            &mut bytes,
            &index.prepared_journal_digest,
            "prepared_journal_digest",
        )?;
        push_digest(
            &mut bytes,
            &index.terminal_state_digest,
            "terminal_state_digest",
        )?;
    }
    push_digest(
        &mut bytes,
        &archive.archive_authority_digest,
        "archive_authority_digest",
    )?;
    Ok(digest_string(&bytes))
}

fn validate_owner_terminal_archive_v1(
    archive: &PrivateOramOwnerTerminalArchiveV1,
) -> Result<(), PrivateOramOwnerJournalError> {
    if archive.version != OWNER_TERMINAL_ARCHIVE_VERSION
        || archive.generation == 0
        || archive.owner_peer_id == 0
        || archive.writer_fence == 0
        || archive.owner_terminal_phase != PrivateOramOwnerJournalPhaseV1::Finalized
        || archive.indexes.is_empty()
        || archive.indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || archive.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    validate_resource_id(&archive.collection_id, "collection_id")?;
    for (field, digest) in [
        (
            "owner_store_incarnation_digest",
            archive.owner_store_incarnation_digest.as_str(),
        ),
        ("mutation_id", archive.mutation_id.as_str()),
        (
            "signed_mutation_digest",
            archive.signed_mutation_digest.as_str(),
        ),
        (
            "parent_descriptor_digest",
            archive.parent_descriptor_digest.as_str(),
        ),
        (
            "parent_lease_acquired_record_digest",
            archive.parent_lease_acquired_record_digest.as_str(),
        ),
        (
            "parent_terminal_record_digest",
            archive.parent_terminal_record_digest.as_str(),
        ),
        (
            "parent_archive_record_digest",
            archive.parent_archive_record_digest.as_str(),
        ),
        (
            "pending_tombstone_digest",
            archive.pending_tombstone_digest.as_str(),
        ),
        (
            "clear_receipt_digest",
            archive.clear_receipt_digest.as_str(),
        ),
        (
            "owner_journal_descriptor_digest",
            archive.owner_journal_descriptor_digest.as_str(),
        ),
        (
            "owner_prepared_state_digest",
            archive.owner_prepared_state_digest.as_str(),
        ),
        (
            "owner_terminal_record_digest",
            archive.owner_terminal_record_digest.as_str(),
        ),
        (
            "decision_authority_record_digest",
            archive.decision_authority_record_digest.as_str(),
        ),
        (
            "reconciliation_authority_digest",
            archive.reconciliation_authority_digest.as_str(),
        ),
        (
            "owner_terminal_evidence_digest",
            archive.owner_terminal_evidence_digest.as_str(),
        ),
        ("intent_key", archive.intent_key.as_str()),
        (
            "prestage_receipt_digest",
            archive.prestage_receipt_digest.as_str(),
        ),
        (
            "prestage_adopted_marker_digest",
            archive.prestage_adopted_marker_digest.as_str(),
        ),
        (
            "archive_authority_digest",
            archive.archive_authority_digest.as_str(),
        ),
        (
            "archive_record_digest",
            archive.archive_record_digest.as_str(),
        ),
    ] {
        validate_digest(digest, field)?;
    }
    let mut names = BTreeSet::new();
    for (position, index) in archive.indexes.iter().enumerate() {
        validate_resource_id(&index.index_name, "index_name")?;
        for (field, digest) in [
            ("old_root_hash", index.old_root_hash.as_str()),
            ("new_root_hash", index.new_root_hash.as_str()),
            ("writeback_digest", index.writeback_digest.as_str()),
            (
                "prepared_journal_digest",
                index.prepared_journal_digest.as_str(),
            ),
            (
                "terminal_state_digest",
                index.terminal_state_digest.as_str(),
            ),
        ] {
            validate_digest(digest, field)?;
        }
        if index.old_epoch.checked_add(1) != Some(index.new_epoch)
            || index.old_root_hash == index.new_root_hash
            || !names.insert(index.index_name.as_str())
            || !matches!(
                (position, index.kind),
                (0, PrivateOramIndexKindV2::Hnsw) | (1, PrivateOramIndexKindV2::Result)
            )
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    if archive.archive_record_digest != owner_terminal_archive_digest_v1(archive)? {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn encode_owner_terminal_archive_v1(
    archive: &PrivateOramOwnerTerminalArchiveV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    validate_owner_terminal_archive_v1(archive)?;
    let bytes = serde_json::to_vec(archive).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_OWNER_TERMINAL_ARCHIVE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn decode_owner_terminal_archive_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerTerminalArchiveV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_OWNER_TERMINAL_ARCHIVE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let archive = serde_json::from_slice::<PrivateOramOwnerTerminalArchiveV1>(bytes)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_owner_terminal_archive_v1(&archive)?;
    if serde_json::to_vec(&archive).map_err(|_| PrivateOramOwnerJournalError::Corrupt)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(archive)
}

fn encode_final_bucket_frame(
    indexes: &[PrivateOramOwnerJournalIndexDescriptorV1],
    final_buckets: &[PrivateOramOwnerFinalBucketIndexV1],
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if indexes.is_empty()
        || indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || indexes.len() != final_buckets.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut bytes = Vec::new();
    push_domain(&mut bytes, FINAL_BUCKET_FRAME_DOMAIN)?;
    bytes.extend_from_slice(&PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION.to_be_bytes());
    push_len(&mut bytes, indexes.len(), "indexes")?;
    let mut total_buckets = 0usize;
    for (index, final_index) in indexes.iter().zip(final_buckets) {
        if index.kind != final_index.buckets.kind()
            || index.index_name != final_index.index_name
            || index.final_bucket_refs != final_bucket_refs(&final_index.buckets)
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        bytes.push(kind_tag(index.kind));
        push_resource_id(&mut bytes, &index.index_name, "index_name")?;
        push_len(&mut bytes, final_index.buckets.len(), "final_buckets")?;
        total_buckets = total_buckets
            .checked_add(final_index.buckets.len())
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        match &final_index.buckets {
            PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => {
                for bucket in buckets {
                    encode_final_bucket(
                        &mut bytes,
                        bucket.version,
                        bucket.bucket_id,
                        bucket.index_epoch,
                        &bucket.ciphertext,
                        &bucket.ciphertext_sha256,
                        &bucket.bucket_commitment,
                        index.new_epoch,
                    )?;
                }
            }
            PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => {
                for bucket in buckets {
                    encode_final_bucket(
                        &mut bytes,
                        bucket.version,
                        bucket.bucket_id,
                        bucket.index_epoch,
                        &bucket.ciphertext,
                        &bucket.ciphertext_sha256,
                        &bucket.bucket_commitment,
                        index.new_epoch,
                    )?;
                }
            }
        }
    }
    if total_buckets == 0 || total_buckets > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    if bytes.is_empty() || bytes.len() as u64 > MAX_FINAL_BUCKET_FRAME_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn encode_final_bucket(
    bytes: &mut Vec<u8>,
    version: u16,
    bucket_id: u64,
    index_epoch: u64,
    ciphertext: &str,
    ciphertext_sha256: &str,
    bucket_commitment: &str,
    expected_epoch: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if version != 1 || index_epoch != expected_epoch {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let ciphertext_bytes = decode_base64url_canonical(ciphertext, "ciphertext")?;
    if ciphertext_bytes.is_empty()
        || ciphertext_bytes.len() as u64 > MAX_FINAL_BUCKET_FRAME_BYTES
        || digest_string(&ciphertext_bytes) != ciphertext_sha256
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    validate_digest(ciphertext_sha256, "ciphertext_sha256")?;
    validate_digest(bucket_commitment, "bucket_commitment")?;
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&bucket_id.to_be_bytes());
    bytes.extend_from_slice(&index_epoch.to_be_bytes());
    push_len(bytes, ciphertext_bytes.len(), "ciphertext")?;
    bytes.extend_from_slice(&ciphertext_bytes);
    push_digest(bytes, ciphertext_sha256, "ciphertext_sha256")?;
    push_digest(bytes, bucket_commitment, "bucket_commitment")?;
    Ok(())
}

fn decode_final_bucket_frame(
    indexes: &[PrivateOramOwnerJournalIndexDescriptorV1],
    bytes: &[u8],
) -> Result<Vec<PrivateOramOwnerFinalBucketIndexV1>, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_FINAL_BUCKET_FRAME_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(FINAL_BUCKET_FRAME_DOMAIN)?;
    if decoder.read_u16()? != PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION
        || decoder.read_len(MAX_PAIRED_OWNER_INDEXES)? != indexes.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut final_indexes = Vec::with_capacity(indexes.len());
    let mut total_buckets = 0usize;
    for index in indexes {
        if decoder.read_kind()? != index.kind || decoder.read_resource_id()? != index.index_name {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let bucket_count = decoder.read_len(PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)?;
        if bucket_count == 0 {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        total_buckets = total_buckets
            .checked_add(bucket_count)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        if total_buckets > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let buckets = match index.kind {
            PrivateOramIndexKindV2::Hnsw => {
                let mut buckets = Vec::with_capacity(bucket_count);
                for _ in 0..bucket_count {
                    let bucket = decoder.read_final_bucket(index.new_epoch)?;
                    buckets.push(PrivateHnswOramBucket {
                        version: bucket.version,
                        bucket_id: bucket.bucket_id,
                        index_epoch: bucket.index_epoch,
                        ciphertext: bucket.ciphertext,
                        ciphertext_sha256: bucket.ciphertext_sha256,
                        bucket_commitment: bucket.bucket_commitment,
                    });
                }
                PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets)
            }
            PrivateOramIndexKindV2::Result => {
                let mut buckets = Vec::with_capacity(bucket_count);
                for _ in 0..bucket_count {
                    let bucket = decoder.read_final_bucket(index.new_epoch)?;
                    buckets.push(PrivateResultOramBucket {
                        version: bucket.version,
                        bucket_id: bucket.bucket_id,
                        index_epoch: bucket.index_epoch,
                        ciphertext: bucket.ciphertext,
                        ciphertext_sha256: bucket.ciphertext_sha256,
                        bucket_commitment: bucket.bucket_commitment,
                    });
                }
                PrivateOramOwnerFinalBucketBatchV1::Result(buckets)
            }
        };
        final_indexes.push(PrivateOramOwnerFinalBucketIndexV1 {
            index_name: index.index_name.clone(),
            buckets,
        });
    }
    if total_buckets == 0 || !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    if encode_final_bucket_frame(indexes, &final_indexes)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(final_indexes)
}

fn final_bucket_refs(
    buckets: &PrivateOramOwnerFinalBucketBatchV1,
) -> Vec<PrivateOramAppendBucketRefV1> {
    match buckets {
        PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => buckets
            .iter()
            .map(|bucket| PrivateOramAppendBucketRefV1 {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
        PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => buckets
            .iter()
            .map(|bucket| PrivateOramAppendBucketRefV1 {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
    }
}

fn collapse_ordered_bucket_refs(
    ordered: &[PrivateOramAppendBucketRefV1],
) -> Vec<PrivateOramAppendBucketRefV1> {
    let mut final_refs = BTreeMap::new();
    for bucket in ordered {
        final_refs.insert(bucket.bucket_id, bucket.clone());
    }
    final_refs.into_values().collect()
}

fn validate_bucket_ref(
    bucket: &PrivateOramAppendBucketRefV1,
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_digest(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
    validate_digest(&bucket.bucket_commitment, "bucket_commitment")
}

fn kind_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => HNSW_KIND_TAG,
        PrivateOramIndexKindV2::Result => RESULT_KIND_TAG,
    }
}

fn push_domain(bytes: &mut Vec<u8>, domain: &[u8]) -> Result<(), PrivateOramOwnerJournalError> {
    push_len(bytes, domain.len(), "domain")?;
    bytes.extend_from_slice(domain);
    Ok(())
}

fn push_digest(
    bytes: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    bytes.extend_from_slice(&decode_digest(value, field)?);
    Ok(())
}

fn push_resource_id(
    bytes: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_resource_id(value, field)?;
    push_len(bytes, value.len(), field)?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_len(
    bytes: &mut Vec<u8>,
    length: usize,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    let length =
        u32::try_from(length).map_err(|_| PrivateOramOwnerJournalError::InvalidInput(field))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn push_bucket_refs(
    bytes: &mut Vec<u8>,
    buckets: &[PrivateOramAppendBucketRefV1],
) -> Result<(), PrivateOramOwnerJournalError> {
    push_len(bytes, buckets.len(), "bucket_refs")?;
    for bucket in buckets {
        validate_bucket_ref(bucket)?;
        bytes.extend_from_slice(&bucket.bucket_id.to_be_bytes());
        push_digest(bytes, &bucket.ciphertext_sha256, "ciphertext_sha256")?;
        push_digest(bytes, &bucket.bucket_commitment, "bucket_commitment")?;
    }
    Ok(())
}

fn validate_resource_id(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), PrivateOramOwnerJournalError> {
    decode_digest(value, field).map(drop)
}

fn decode_digest(
    value: &str,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], PrivateOramOwnerJournalError> {
    let decoded = decode_base64url_canonical(value, field)?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput(field))
}

fn decode_base64url_canonical(
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput(field))?;
    if BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerJournalError::InvalidInput(field));
    }
    Ok(decoded)
}

fn digest_string(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(bytes))
}

struct DecodedFinalBucket {
    version: u16,
    bucket_id: u64,
    index_epoch: u64,
    ciphertext: String,
    ciphertext_sha256: String,
    bucket_commitment: String,
}

struct BinaryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_domain(&mut self, expected: &[u8]) -> Result<(), PrivateOramOwnerJournalError> {
        let length = self.read_len(expected.len())?;
        if length != expected.len() || self.read_exact(length)? != expected {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(())
    }

    fn read_domain_choice(
        &mut self,
        expected: &[&[u8]],
    ) -> Result<usize, PrivateOramOwnerJournalError> {
        let max_length = expected.iter().map(|value| value.len()).max().unwrap_or(0);
        let length = self.read_len(max_length)?;
        let actual = self.read_exact(length)?;
        expected
            .iter()
            .position(|candidate| *candidate == actual)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)
    }

    fn read_u8(&mut self) -> Result<u8, PrivateOramOwnerJournalError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PrivateOramOwnerJournalError> {
        let value: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(u16::from_be_bytes(value))
    }

    fn read_u32(&mut self) -> Result<u32, PrivateOramOwnerJournalError> {
        let value: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(u32::from_be_bytes(value))
    }

    fn read_u64(&mut self) -> Result<u64, PrivateOramOwnerJournalError> {
        let value: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(u64::from_be_bytes(value))
    }

    fn read_len(&mut self, max: usize) -> Result<usize, PrivateOramOwnerJournalError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        if length > max {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(length)
    }

    fn read_kind(&mut self) -> Result<PrivateOramIndexKindV2, PrivateOramOwnerJournalError> {
        match self.read_u8()? {
            HNSW_KIND_TAG => Ok(PrivateOramIndexKindV2::Hnsw),
            RESULT_KIND_TAG => Ok(PrivateOramIndexKindV2::Result),
            _ => Err(PrivateOramOwnerJournalError::Corrupt),
        }
    }

    fn read_digest(&mut self) -> Result<String, PrivateOramOwnerJournalError> {
        Ok(BASE64URL_NOPAD.encode(self.read_exact(DIGEST_BYTES)?))
    }

    fn read_resource_id(&mut self) -> Result<String, PrivateOramOwnerJournalError> {
        let length = self.read_len(MAX_RESOURCE_ID_BYTES)?;
        let value = std::str::from_utf8(self.read_exact(length)?)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_resource_id(value, "resource_id")
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(value.to_string())
    }

    fn read_bucket_refs(
        &mut self,
        max: usize,
    ) -> Result<Vec<PrivateOramAppendBucketRefV1>, PrivateOramOwnerJournalError> {
        let count = self.read_len(max)?;
        let mut buckets = Vec::with_capacity(count);
        for _ in 0..count {
            buckets.push(PrivateOramAppendBucketRefV1 {
                bucket_id: self.read_u64()?,
                ciphertext_sha256: self.read_digest()?,
                bucket_commitment: self.read_digest()?,
            });
        }
        Ok(buckets)
    }

    fn read_final_bucket(
        &mut self,
        expected_epoch: u64,
    ) -> Result<DecodedFinalBucket, PrivateOramOwnerJournalError> {
        let version = self.read_u16()?;
        let bucket_id = self.read_u64()?;
        let index_epoch = self.read_u64()?;
        if version != 1 || index_epoch != expected_epoch {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let max_ciphertext = usize::try_from(MAX_FINAL_BUCKET_FRAME_BYTES)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let ciphertext_bytes = self.read_blob(max_ciphertext)?;
        if ciphertext_bytes.is_empty() {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let ciphertext = BASE64URL_NOPAD.encode(ciphertext_bytes);
        let ciphertext_sha256 = self.read_digest()?;
        let bucket_commitment = self.read_digest()?;
        if digest_string(ciphertext_bytes) != ciphertext_sha256 {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(DecodedFinalBucket {
            version,
            bucket_id,
            index_epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        })
    }

    fn read_blob(&mut self, max: usize) -> Result<&'a [u8], PrivateOramOwnerJournalError> {
        let length = self.read_len(max)?;
        self.read_exact(length)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PrivateOramOwnerJournalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
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

fn path_entry_exists(path: &Path) -> Result<bool, PrivateOramOwnerJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PrivateOramOwnerJournalError::Io),
    }
}

fn create_private_directory(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_private_directory_exact(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrivateOramOwnerJournalError::Io),
    }
    match fs::create_dir(path) {
        Ok(()) => {
            set_private_directory_permissions(path)?;
            validate_private_directory_exact(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_private_directory_exact(path)
        }
        Err(_) => Err(PrivateOramOwnerJournalError::Io),
    }
}

fn set_private_directory_permissions(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    Ok(())
}

fn private_directory_identity(
    path: &Path,
) -> Result<DirectoryIdentity, PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&before)?;
    let opened = open_private_directory(path)?;
    let after = opened
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
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

fn validate_private_directory_exact(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    private_directory_identity(path).map(drop)
}

fn validate_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn validate_owned_ancestry_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || mode & 0o022 != 0
            || mode & 0o700 != 0o700
            || metadata.nlink() < 2
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn validate_stranded_candidate_file(
    path: &Path,
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_stranded_candidate_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_stranded_candidate_file_metadata(&after, max_bytes)?;
    ensure_same_inode(&before, &after)
}

fn validate_stranded_candidate_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_same_inode(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramOwnerJournalError> {
    if before.file_type().is_file() != after.file_type().is_file()
        || before.file_type().is_dir() != after.file_type().is_dir()
        || before.len() != after.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_same_open_inode(first: &File, second: &File) -> Result<(), PrivateOramOwnerJournalError> {
    let first_metadata = first
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let second_metadata = second
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    ensure_same_inode(&first_metadata, &second_metadata)
}

fn open_private_directory(path: &Path) -> Result<File, PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    Ok(file)
}

fn open_owned_ancestry_directory(path: &Path) -> Result<File, PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_owned_ancestry_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_owned_ancestry_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    Ok(file)
}

fn write_new_private_file(
    path: &Path,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(PrivateOramOwnerJournalError::InvalidInput("file_bytes"));
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
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let mut file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    file.write_all(bytes)
        .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    file.flush().map_err(|_| PrivateOramOwnerJournalError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    validate_file_metadata(&metadata, max_bytes)?;
    if metadata.len() != bytes.len() as u64 {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    file.sync_all()
        .map_err(|_| PrivateOramOwnerJournalError::Io)
}

struct PinnedPrivateFile {
    file: File,
    path: PathBuf,
    max_bytes: u64,
}

struct PinnedPrivateLockFile {
    file: File,
    path: PathBuf,
}

impl PinnedPrivateLockFile {
    fn validate_at_path(&self) -> Result<(), PrivateOramOwnerJournalError> {
        let opened = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_private_lock_file_metadata(&opened)?;
        let current =
            fs::symlink_metadata(&self.path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_private_lock_file_metadata(&current)?;
        ensure_same_inode(&opened, &current)
    }
}

impl PinnedPrivateFile {
    fn sync(&self) -> Result<(), PrivateOramOwnerJournalError> {
        self.file
            .sync_all()
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)
    }

    fn validate_at_path(&self) -> Result<(), PrivateOramOwnerJournalError> {
        let opened = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&opened, self.max_bytes)?;
        let current =
            fs::symlink_metadata(&self.path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&current, self.max_bytes)?;
        ensure_same_inode(&opened, &current)
    }

    fn validate_exact_contents(
        &mut self,
        expected: &[u8],
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let before = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&before, self.max_bytes)?;
        if before.len() != expected.len() as u64 {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let mut actual = Vec::new();
        actual
            .try_reserve_exact(expected.len())
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        (&mut self.file)
            .take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut actual)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let after = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&after, self.max_bytes)?;
        ensure_same_inode(&before, &after)?;
        if actual != expected {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        self.validate_at_path()
    }
}

struct LoadedCanonicalParentArchiveGrantV1 {
    hnsw_root: File,
    hnsw_parent: File,
    collection_root: File,
    parent_journal_root: File,
    parent_journal_lock: PinnedPrivateLockFile,
    completed: File,
    terminal_file: PinnedPrivateFile,
    grant_file: PinnedPrivateFile,
    hnsw_root_path: PathBuf,
    hnsw_parent_path: PathBuf,
    collection_root_path: PathBuf,
    parent_journal_root_path: PathBuf,
    completed_path: PathBuf,
    vector_name: std::ffi::OsString,
    completed_name: std::ffi::OsString,
    terminal_bytes: Vec<u8>,
    grant_bytes: Vec<u8>,
    grant: PrivateOramOwnerCommittedArchiveGrantV1,
}

impl LoadedCanonicalParentArchiveGrantV1 {
    fn load(
        primary_hnsw_store_root: &Path,
        generation: u64,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        let hnsw_root_path = require_absolute_normal_path(primary_hnsw_store_root)?;
        let vector_name = hnsw_root_path
            .file_name()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?
            .to_owned();
        let vector_name_str = vector_name
            .to_str()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        validate_resource_id(vector_name_str, "vector_name")?;
        let hnsw_parent_path = hnsw_root_path
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?
            .to_path_buf();
        if hnsw_parent_path.file_name() != Some(OsStr::new(PRIVATE_HNSW_ORAM_DIR)) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let collection_root_path = hnsw_parent_path
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?
            .to_path_buf();
        validate_absolute_normal_path(&collection_root_path)?;

        let collection_root = open_owned_ancestry_directory(&collection_root_path)?;
        let hnsw_parent_path_from_collection =
            open_owned_directory_entry_path(&collection_root, OsStr::new(PRIVATE_HNSW_ORAM_DIR))?;
        let hnsw_parent = open_private_directory(&hnsw_parent_path_from_collection)?;
        validate_open_directory_at_path(&hnsw_parent, &hnsw_parent_path)?;
        let hnsw_root_path_from_parent = open_directory_entry_path(&hnsw_parent, &vector_name)?;
        let hnsw_root = open_private_directory(&hnsw_root_path_from_parent)?;
        validate_open_directory_at_path(&hnsw_root, &hnsw_root_path)?;
        let parent_journal_root_path =
            collection_root_path.join(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2);
        let parent_journal_path_from_collection = open_owned_directory_entry_path(
            &collection_root,
            OsStr::new(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2),
        )?;
        let parent_journal_root = open_private_directory(&parent_journal_path_from_collection)?;
        validate_open_directory_at_path(&parent_journal_root, &parent_journal_root_path)?;
        let parent_journal_lock = open_private_lock_file_shared(&open_directory_entry_path(
            &parent_journal_root,
            OsStr::new(PRIVATE_ORAM_PARENT_JOURNAL_LOCK_FILE_V2),
        )?)?;

        let completed_name = std::ffi::OsString::from(completed_generation_name(generation)?);
        let completed_path = parent_journal_root_path.join(&completed_name);
        let completed_path_from_parent =
            open_directory_entry_path(&parent_journal_root, &completed_name)?;
        let completed = open_private_directory(&completed_path_from_parent)?;
        validate_open_directory_at_path(&completed, &completed_path)?;

        let terminal_path = open_directory_entry_path(
            &completed,
            OsStr::new(PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_FILE_V2),
        )?;
        let (terminal_file, terminal_bytes) = read_private_file_pinned(
            &terminal_path,
            PRIVATE_ORAM_PARENT_TERMINAL_ARCHIVE_MAX_BYTES_V2,
        )?;
        let grant_path = open_directory_entry_path(
            &completed,
            OsStr::new(PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_FILE_V1),
        )?;
        let (grant_file, grant_bytes) = read_private_file_pinned(
            &grant_path,
            PRIVATE_ORAM_PARENT_CHILD_ARCHIVE_GRANT_MAX_BYTES_V1,
        )?;
        let grant = decode_private_oram_owner_committed_archive_grant_v1(&grant_bytes)?;
        if grant.generation != generation
            || grant.vector_name != vector_name_str
            || grant.terminal_archive_file_len != terminal_bytes.len() as u64
            || grant.terminal_archive_file_sha256
                != BASE64URL_NOPAD.encode(&Sha256::digest(&terminal_bytes))
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }

        let mut loaded = Self {
            hnsw_root,
            hnsw_parent,
            collection_root,
            parent_journal_root,
            parent_journal_lock,
            completed,
            terminal_file,
            grant_file,
            hnsw_root_path,
            hnsw_parent_path,
            collection_root_path,
            parent_journal_root_path,
            completed_path,
            vector_name,
            completed_name,
            terminal_bytes,
            grant_bytes,
            grant,
        };
        loaded.validate_bindings_and_contents()?;
        Ok(loaded)
    }

    fn grant(&self) -> &PrivateOramOwnerCommittedArchiveGrantV1 {
        &self.grant
    }

    fn establish_durable(&mut self) -> Result<(), PrivateOramOwnerJournalError> {
        self.terminal_file.sync()?;
        self.grant_file.sync()?;
        sync_open_directory(&self.completed)
            .and_then(|()| sync_open_directory(&self.parent_journal_root))
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        self.validate_bindings_and_contents()
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)
    }

    fn open_child_lifecycle_root_namespaces(
        &mut self,
        expected_owner_temp_path: &Path,
        expected_root_path: &Path,
    ) -> Result<Option<(File, File)>, PrivateOramOwnerJournalError> {
        validate_absolute_normal_path(expected_owner_temp_path)?;
        validate_absolute_normal_path(expected_root_path)?;
        self.validate_bindings_and_contents()?;

        let owner_temp_path =
            open_directory_entry_path(&self.hnsw_root, OsStr::new(OWNER_STORE_TEMP_DIR))?;
        if !path_entry_exists(&owner_temp_path)? {
            return Ok(None);
        }
        let owner_temp = open_private_directory(&owner_temp_path)?;
        validate_open_directory_at_path(&owner_temp, expected_owner_temp_path)?;

        let root_path = open_directory_entry_path(&owner_temp, OsStr::new(PRESTAGE_ROOT_DIR))?;
        if !path_entry_exists(&root_path)? {
            return Ok(None);
        }
        let root = open_private_directory(&root_path)?;
        validate_open_directory_at_path(&root, expected_root_path)?;
        self.validate_bindings_and_contents()?;
        Ok(Some((owner_temp, root)))
    }

    fn validate_bindings_and_contents(&mut self) -> Result<(), PrivateOramOwnerJournalError> {
        validate_open_owned_ancestry_directory_at_path(
            &self.collection_root,
            &self.collection_root_path,
        )?;
        validate_open_directory_at_path(&self.hnsw_parent, &self.hnsw_parent_path)?;
        validate_open_directory_at_path(&self.hnsw_root, &self.hnsw_root_path)?;
        validate_open_directory_at_path(&self.parent_journal_root, &self.parent_journal_root_path)?;
        self.parent_journal_lock.validate_at_path()?;
        validate_open_directory_at_path(&self.completed, &self.completed_path)?;

        let rebound_hnsw_parent = open_private_directory(&open_owned_directory_entry_path(
            &self.collection_root,
            OsStr::new(PRIVATE_HNSW_ORAM_DIR),
        )?)?;
        ensure_same_open_inode(&self.hnsw_parent, &rebound_hnsw_parent)?;
        let rebound_hnsw_root = open_private_directory(&open_directory_entry_path(
            &self.hnsw_parent,
            &self.vector_name,
        )?)?;
        ensure_same_open_inode(&self.hnsw_root, &rebound_hnsw_root)?;
        let rebound_parent = open_private_directory(&open_owned_directory_entry_path(
            &self.collection_root,
            OsStr::new(PRIVATE_ORAM_PARENT_JOURNAL_DIR_V2),
        )?)?;
        ensure_same_open_inode(&self.parent_journal_root, &rebound_parent)?;
        let rebound_completed = open_private_directory(&open_directory_entry_path(
            &self.parent_journal_root,
            &self.completed_name,
        )?)?;
        ensure_same_open_inode(&self.completed, &rebound_completed)?;

        self.terminal_file
            .validate_exact_contents(&self.terminal_bytes)?;
        self.grant_file.validate_exact_contents(&self.grant_bytes)?;
        let decoded = decode_private_oram_owner_committed_archive_grant_v1(&self.grant_bytes)?;
        if decoded != self.grant
            || self.grant.terminal_archive_file_len != self.terminal_bytes.len() as u64
            || self.grant.terminal_archive_file_sha256
                != BASE64URL_NOPAD.encode(&Sha256::digest(&self.terminal_bytes))
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(())
    }
}

fn require_absolute_normal_path(path: &Path) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    validate_absolute_normal_path(path)?;
    Ok(path.to_path_buf())
}

fn validate_absolute_normal_path(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

struct PrivateJournalRootLock<'a> {
    root: &'a File,
    mode: PrivateJournalRootLockMode,
}

/// Rank-1 guard for a prestage lifecycle transaction. A canonical owner-journal lock may only be
/// nested after this guard has been acquired and revalidated.
struct PrivateOramOwnerLifecycleRootLock<'a> {
    root_lock: PrivateJournalRootLock<'a>,
    parent_lock: PrivateJournalRootLock<'a>,
    expected_parent: &'a Path,
    expected_root: &'a Path,
}

impl PrivateOramOwnerLifecycleRootLock<'_> {
    fn root_lock(&self) -> &PrivateJournalRootLock<'_> {
        &self.root_lock
    }

    fn validate_held(&self) -> Result<(), PrivateOramOwnerJournalError> {
        if self.root_lock.mode != self.parent_lock.mode {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        validate_open_directory_at_path(self.parent_lock.root, self.expected_parent)?;
        validate_open_directory_at_path(self.root_lock.root, self.expected_root)
    }

    fn require_exclusive(&self) -> Result<(), PrivateOramOwnerJournalError> {
        self.parent_lock.require_exclusive()?;
        self.root_lock.require_exclusive()?;
        self.validate_held()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PrivateJournalRootLockMode {
    Shared,
    Exclusive,
}

impl PrivateJournalRootLock<'_> {
    fn require_exclusive(&self) -> Result<(), PrivateOramOwnerJournalError> {
        if self.mode != PrivateJournalRootLockMode::Exclusive {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for PrivateJournalRootLock<'_> {
    fn drop(&mut self) {
        // SAFETY: the guard retains the live directory fd for the full lock lifetime.
        let _ = unsafe { nix::libc::flock(self.root.as_raw_fd(), nix::libc::LOCK_UN) };
    }
}

#[cfg(target_os = "linux")]
fn lock_private_journal_root(
    root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    lock_private_journal_root_with_mode(root, PrivateJournalRootLockMode::Exclusive)
}

fn lock_private_oram_owner_lifecycle_root<'a>(
    parent: &'a File,
    expected_parent: &'a Path,
    root: &'a File,
    expected_root: &'a Path,
) -> Result<PrivateOramOwnerLifecycleRootLock<'a>, PrivateOramOwnerJournalError> {
    let parent_lock = lock_private_journal_root(parent)?;
    let root_lock = lock_private_journal_root(root)?;
    let guard = PrivateOramOwnerLifecycleRootLock {
        root_lock,
        parent_lock,
        expected_parent,
        expected_root,
    };
    guard.require_exclusive()?;
    Ok(guard)
}

fn lock_private_oram_owner_lifecycle_root_shared<'a>(
    parent: &'a File,
    expected_parent: &'a Path,
    root: &'a File,
    expected_root: &'a Path,
) -> Result<PrivateOramOwnerLifecycleRootLock<'a>, PrivateOramOwnerJournalError> {
    let parent_lock = lock_private_journal_root_shared(parent)?;
    let root_lock = lock_private_journal_root_shared(root)?;
    let guard = PrivateOramOwnerLifecycleRootLock {
        root_lock,
        parent_lock,
        expected_parent,
        expected_root,
    };
    guard.validate_held()?;
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn lock_private_journal_root_shared(
    root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    lock_private_journal_root_with_mode(root, PrivateJournalRootLockMode::Shared)
}

#[cfg(target_os = "linux")]
fn lock_private_journal_root_with_mode(
    root: &File,
    mode: PrivateJournalRootLockMode,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    let operation = match mode {
        PrivateJournalRootLockMode::Shared => nix::libc::LOCK_SH,
        PrivateJournalRootLockMode::Exclusive => nix::libc::LOCK_EX,
    };
    // SAFETY: root is a validated, live directory fd retained by the returned guard.
    let result = unsafe { nix::libc::flock(root.as_raw_fd(), operation | nix::libc::LOCK_NB) };
    if result == 0 {
        return Ok(PrivateJournalRootLock { root, mode });
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(nix::libc::EWOULDBLOCK) {
        Err(PrivateOramOwnerJournalError::ConcurrentMutation)
    } else {
        Err(PrivateOramOwnerJournalError::Unsupported)
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_private_journal_root(
    _root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn lock_private_journal_root_shared(
    _root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

fn read_private_file_pinned(
    path: &Path,
    max_bytes: u64,
) -> Result<(PinnedPrivateFile, Vec<u8>), PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let mut file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let opened = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_file_metadata(&opened, max_bytes)?;
    ensure_same_inode(&before, &opened)?;

    let expected_length =
        usize::try_from(opened.len()).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.len() != expected_length {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_file_metadata(&after, max_bytes)?;
    ensure_same_inode(&opened, &after)?;
    let pinned = PinnedPrivateFile {
        file,
        path: path.to_path_buf(),
        max_bytes,
    };
    pinned.validate_at_path()?;
    Ok((pinned, bytes))
}

fn open_private_lock_file_shared(
    path: &Path,
) -> Result<PinnedPrivateLockFile, PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_private_lock_file_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let opened = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_private_lock_file_metadata(&opened)?;
    ensure_same_inode(&before, &opened)?;
    fs4::fs_std::FileExt::lock_shared(file.file())
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let pinned = PinnedPrivateLockFile {
        file,
        path: path.to_path_buf(),
    };
    pinned.validate_at_path()?;
    Ok(pinned)
}

fn validate_private_lock_file_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_file() || metadata.len() != 0 {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn sync_private_directory(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    sync_open_directory(&open_private_directory(path)?)
}

fn sync_open_directory(directory: &File) -> Result<(), PrivateOramOwnerJournalError> {
    directory
        .sync_all()
        .map_err(|_| PrivateOramOwnerJournalError::Io)
}

fn validate_open_directory_at_path(
    directory: &File,
    path: &Path,
) -> Result<(), PrivateOramOwnerJournalError> {
    let opened = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&opened)?;
    let current = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&current)?;
    ensure_same_inode(&opened, &current)
}

fn validate_open_owned_ancestry_directory_at_path(
    directory: &File,
    path: &Path,
) -> Result<(), PrivateOramOwnerJournalError> {
    let opened = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_owned_ancestry_directory_metadata(&opened)?;
    let current = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_owned_ancestry_directory_metadata(&current)?;
    ensure_same_inode(&opened, &current)
}

fn directory_entry_names(
    path: &Path,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramOwnerJournalError> {
    directory_entry_names_bounded(path, usize::MAX, PrivateOramOwnerJournalError::Corrupt)
}

fn directory_entry_names_bounded(
    path: &Path,
    max_entries: usize,
    overflow_error: PrivateOramOwnerJournalError,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramOwnerJournalError> {
    let mut names = BTreeSet::new();
    let entries = fs::read_dir(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    for entry in entries {
        let entry = entry.map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        if !names.insert(entry.file_name()) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        if names.len() > max_entries {
            return Err(overflow_error);
        }
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn open_directory_entry_path(
    directory: &File,
    name: &OsStr,
) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    checked_single_component_cstring(name)?;
    let metadata = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&metadata)?;
    Ok(PathBuf::from("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(name))
}

#[cfg(target_os = "linux")]
fn open_owned_directory_entry_path(
    directory: &File,
    name: &OsStr,
) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    checked_single_component_cstring(name)?;
    let metadata = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_owned_ancestry_directory_metadata(&metadata)?;
    Ok(PathBuf::from("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(name))
}

#[cfg(not(target_os = "linux"))]
fn open_directory_entry_path(
    _directory: &File,
    _name: &OsStr,
) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn open_owned_directory_entry_path(
    _directory: &File,
    _name: &OsStr,
) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

fn directory_entry_names_open(
    directory: &File,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramOwnerJournalError> {
    directory_entry_names_open_bounded(directory, usize::MAX, PrivateOramOwnerJournalError::Corrupt)
}

fn directory_entry_names_open_bounded(
    directory: &File,
    max_entries: usize,
    overflow_error: PrivateOramOwnerJournalError,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramOwnerJournalError> {
    let before = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&before)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (max_entries, overflow_error);
        Err(PrivateOramOwnerJournalError::Unsupported)
    }
    #[cfg(target_os = "linux")]
    {
        let path = PathBuf::from("/proc/self/fd").join(directory.as_raw_fd().to_string());
        let names = directory_entry_names_bounded(&path, max_entries, overflow_error);
        let after = directory
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_directory_metadata(&after)?;
        ensure_same_inode(&before, &after)?;
        names
    }
}

fn validate_active_entry_set(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_directory_exact(path)?;
    let actual = directory_entry_names(path)?;
    let expected = [
        DESCRIPTOR_FILE,
        FINAL_BUCKETS_FILE,
        STATE_FILE,
        ACTIVE_TEMP_DIR,
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_active_entry_set_open(directory: &File) -> Result<bool, PrivateOramOwnerJournalError> {
    let actual = directory_entry_names_open(directory)?;
    let mut expected = [
        DESCRIPTOR_FILE,
        FINAL_BUCKETS_FILE,
        STATE_FILE,
        ACTIVE_TEMP_DIR,
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<BTreeSet<_>>();
    let has_terminal = actual.contains(OsStr::new(TERMINAL_DIR));
    if has_terminal {
        expected.insert(std::ffi::OsString::from(TERMINAL_DIR));
    }
    if actual != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(has_terminal)
}

fn validate_completed_entry_set_open(
    directory: &File,
) -> Result<(bool, bool), PrivateOramOwnerJournalError> {
    let actual = directory_entry_names_open(directory)?;
    let mut expected = [
        DESCRIPTOR_FILE,
        FINAL_BUCKETS_FILE,
        STATE_FILE,
        ACTIVE_TEMP_DIR,
        TERMINAL_DIR,
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<BTreeSet<_>>();
    let has_archive = actual.contains(OsStr::new(OWNER_TERMINAL_ARCHIVE_FILE));
    if has_archive {
        expected.insert(std::ffi::OsString::from(OWNER_TERMINAL_ARCHIVE_FILE));
    }
    if actual != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok((true, has_archive))
}

fn validate_directory_is_empty(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_directory_exact(path)?;
    if !directory_entry_names(path)?.is_empty() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_directory_is_empty_open(directory: &File) -> Result<(), PrivateOramOwnerJournalError> {
    if !directory_entry_names_open(directory)?.is_empty() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_entry_set(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_directory_exact(path)?;
    let expected = [std::ffi::OsString::from(TERMINAL_RECORD_FILE)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if directory_entry_names(path)? != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_entry_set_open(directory: &File) -> Result<(), PrivateOramOwnerJournalError> {
    let expected = [std::ffi::OsString::from(TERMINAL_RECORD_FILE)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if directory_entry_names_open(directory)? != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_temp_entries_open(
    directory: &File,
) -> Result<(), PrivateOramOwnerJournalError> {
    for name in directory_entry_names_open(directory)? {
        if !is_terminal_candidate_name(&name) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let candidate_path = open_directory_entry_path(directory, &name)?;
        let candidate = open_private_directory(&candidate_path)?;
        let entries = directory_entry_names_open(&candidate)?;
        if entries.is_empty() {
            continue;
        }
        let expected = [std::ffi::OsString::from(TERMINAL_RECORD_FILE)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if entries != expected {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let record_path = open_directory_entry_path(&candidate, OsStr::new(TERMINAL_RECORD_FILE))?;
        validate_stranded_candidate_file(&record_path, MAX_TERMINAL_RECORD_BYTES)?;
    }
    Ok(())
}

fn is_candidate_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() > CANDIDATE_PREFIX.len() && name.starts_with(CANDIDATE_PREFIX)
    })
}

fn completed_generation_name(generation: u64) -> Result<String, PrivateOramOwnerJournalError> {
    if generation == 0 {
        return Err(PrivateOramOwnerJournalError::InvalidInput("generation"));
    }
    Ok(format!("{COMPLETED_DIR_PREFIX}{generation:020}"))
}

fn completed_generation_from_name(
    name: &OsStr,
) -> Result<Option<u64>, PrivateOramOwnerJournalError> {
    let Some(name) = name.to_str() else {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    };
    if !name.starts_with(COMPLETED_DIR_PREFIX) {
        return Ok(None);
    }
    let suffix = &name[COMPLETED_DIR_PREFIX.len()..];
    if suffix.len() != 20 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let generation = suffix
        .parse::<u64>()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if generation == 0 || completed_generation_name(generation)? != name {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(Some(generation))
}

fn is_terminal_candidate_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() > TERMINAL_CANDIDATE_PREFIX.len() && name.starts_with(TERMINAL_CANDIDATE_PREFIX)
    })
}

#[cfg(target_os = "linux")]
fn rename_directory_noreplace(
    root: &File,
    source_name: &OsStr,
    destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    rename_entry_noreplace(root, source_name, root, destination_name)
}

#[cfg(target_os = "linux")]
fn rename_entry_noreplace(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    let source = checked_single_component_cstring(source_name)?;
    let destination = checked_single_component_cstring(destination_name)?;
    // SAFETY: both names are validated single-component C strings and both directory descriptors
    // are pinned, live, no-follow handles retained across the non-replacing rename.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_renameat2,
            source_directory.as_raw_fd(),
            source.as_ptr(),
            destination_directory.as_raw_fd(),
            destination.as_ptr(),
            nix::libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(nix::libc::EEXIST) => Err(PrivateOramOwnerJournalError::ConcurrentMutation),
        Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::EOPNOTSUPP | nix::libc::EXDEV) => {
            Err(PrivateOramOwnerJournalError::Unsupported)
        }
        _ => Err(PrivateOramOwnerJournalError::Indeterminate),
    }
}

#[cfg(target_os = "linux")]
fn rename_entry_replace(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    let source = checked_single_component_cstring(source_name)?;
    let destination = checked_single_component_cstring(destination_name)?;
    // SAFETY: both names are validated single components and the live, no-follow directory
    // descriptors remain pinned across the atomic replacement.
    let result = unsafe {
        nix::libc::renameat(
            source_directory.as_raw_fd(),
            source.as_ptr(),
            destination_directory.as_raw_fd(),
            destination.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(nix::libc::EXDEV | nix::libc::EINVAL | nix::libc::EOPNOTSUPP) => {
                Err(PrivateOramOwnerJournalError::Unsupported)
            }
            _ => Err(PrivateOramOwnerJournalError::Io),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_directory_noreplace(
    _root: &File,
    _source_name: &OsStr,
    _destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn rename_entry_noreplace(
    _source_directory: &File,
    _source_name: &OsStr,
    _destination_directory: &File,
    _destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn rename_entry_replace(
    _source_directory: &File,
    _source_name: &OsStr,
    _destination_directory: &File,
    _destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(target_os = "linux")]
fn checked_single_component_cstring(name: &OsStr) -> Result<CString, PrivateOramOwnerJournalError> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(PrivateOramOwnerJournalError::InvalidInput(
            "rename_component",
        ));
    }
    CString::new(bytes).map_err(|_| PrivateOramOwnerJournalError::InvalidInput("rename_component"))
}

#[cfg(not(target_os = "linux"))]
const fn ensure_supported_platform() -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1, private_oram_owner_cleanup_signer_v1,
        sign_private_oram_owner_reservation_prepare_v1,
        validate_private_oram_owner_reservation_prepare_v1,
    };
    use ring::signature::Ed25519KeyPair;
    use tempfile::TempDir;

    use super::*;

    struct JournalFixture {
        _temp: TempDir,
        hnsw_root: PathBuf,
        journal: PrivateOramOwnerJournal,
    }

    fn digest(fill: u8) -> String {
        BASE64URL_NOPAD.encode(&[fill; DIGEST_BYTES])
    }

    fn canonical_index_states(
        desired: &ValidatedOwnerJournal,
        marker: u8,
    ) -> Vec<PrivateOramOwnerJournalTerminalIndexStateV1> {
        desired
            .snapshot
            .descriptor
            .indexes
            .iter()
            .enumerate()
            .map(
                |(position, index)| PrivateOramOwnerJournalTerminalIndexStateV1 {
                    kind: index.kind,
                    index_name: index.index_name.clone(),
                    canonical_state_digest: digest(marker.wrapping_add(position as u8)),
                },
            )
            .collect()
    }

    fn recovery_projection(
        desired: &ValidatedOwnerJournal,
    ) -> PrivateOramOwnerRecoveryProjectionV1 {
        let descriptor = &desired.snapshot.descriptor;
        let prepared = prepared_token(descriptor).unwrap();
        PrivateOramOwnerRecoveryProjectionV1 {
            expected_owner_peer_id: descriptor.owner_peer_id,
            parent_descriptor_digest: descriptor.parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: descriptor
                .parent_lease_acquired_record_digest
                .clone(),
            collection_id: descriptor.collection_id.clone(),
            mutation_id: descriptor.mutation_id.clone(),
            signed_mutation_digest: descriptor.signed_mutation_digest.clone(),
            writer_lease_digest: descriptor.writer_lease_digest.clone(),
            writer_fence: descriptor.writer_fence,
            indexes: descriptor
                .indexes
                .iter()
                .zip(prepared.indexes())
                .map(
                    |(index, evidence)| PrivateOramOwnerRecoveryIndexProjectionV1 {
                        kind: index.kind,
                        index_name: index.index_name.clone(),
                        old_epoch: index.old_epoch,
                        new_epoch: index.new_epoch,
                        old_root_hash: index.old_root_hash.clone(),
                        new_root_hash: index.new_root_hash.clone(),
                        writeback_digest: index.writeback_digest.clone(),
                        prepared_journal_digest: evidence.prepared_journal_digest.clone(),
                    },
                )
                .collect(),
        }
    }

    fn bucket_ref(
        bucket_id: u64,
        ciphertext_sha256: String,
        bucket_commitment: String,
    ) -> PrivateOramAppendBucketRefV1 {
        PrivateOramAppendBucketRefV1 {
            bucket_id,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn ciphertext(marker: u8, bucket_id: u64) -> String {
        let mut bytes = vec![marker; 48];
        bytes.extend_from_slice(&bucket_id.to_be_bytes());
        BASE64URL_NOPAD.encode(&bytes)
    }

    fn hnsw_bucket(marker: u8, bucket_id: u64, epoch: u64) -> PrivateHnswOramBucket {
        let ciphertext = ciphertext(marker, bucket_id);
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext_sha256: digest_string(
                &BASE64URL_NOPAD.decode(ciphertext.as_bytes()).unwrap(),
            ),
            bucket_commitment: digest(marker.wrapping_add(80).wrapping_add(bucket_id as u8)),
            ciphertext,
        }
    }

    fn result_bucket(marker: u8, bucket_id: u64, epoch: u64) -> PrivateResultOramBucket {
        let ciphertext = ciphertext(marker, bucket_id);
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext_sha256: digest_string(
                &BASE64URL_NOPAD.decode(ciphertext.as_bytes()).unwrap(),
            ),
            bucket_commitment: digest(marker.wrapping_add(90).wrapping_add(bucket_id as u8)),
            ciphertext,
        }
    }

    fn validated_fixture(marker: u8, include_result: bool) -> ValidatedOwnerJournal {
        let hnsw_epoch = 12;
        let hnsw_buckets = vec![
            hnsw_bucket(marker.wrapping_add(1), 0, hnsw_epoch),
            hnsw_bucket(marker.wrapping_add(2), 1, hnsw_epoch),
        ];
        let hnsw_final_refs = hnsw_buckets
            .iter()
            .map(|bucket| {
                bucket_ref(
                    bucket.bucket_id,
                    bucket.ciphertext_sha256.clone(),
                    bucket.bucket_commitment.clone(),
                )
            })
            .collect::<Vec<_>>();
        let hnsw_ordered_refs = vec![
            bucket_ref(
                1,
                digest(marker.wrapping_add(30)),
                digest(marker.wrapping_add(31)),
            ),
            hnsw_final_refs[0].clone(),
            hnsw_final_refs[1].clone(),
        ];
        let mut indexes = vec![PrivateOramOwnerJournalIndexDescriptorV1 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text".to_string(),
            old_epoch: 11,
            new_epoch: hnsw_epoch,
            old_root_hash: digest(marker.wrapping_add(3)),
            new_root_hash: digest(marker.wrapping_add(4)),
            writeback_digest: digest(marker.wrapping_add(5)),
            read_path_count: 8,
            read_transcript_digest: digest(marker.wrapping_add(6)),
            ordered_bucket_refs: hnsw_ordered_refs,
            final_bucket_refs: hnsw_final_refs,
        }];
        let mut final_buckets = vec![PrivateOramOwnerFinalBucketIndexV1 {
            index_name: "text".to_string(),
            buckets: PrivateOramOwnerFinalBucketBatchV1::Hnsw(hnsw_buckets),
        }];
        if include_result {
            let result_epoch = 22;
            let result_buckets = vec![result_bucket(marker.wrapping_add(7), 2, result_epoch)];
            let result_refs = result_buckets
                .iter()
                .map(|bucket| {
                    bucket_ref(
                        bucket.bucket_id,
                        bucket.ciphertext_sha256.clone(),
                        bucket.bucket_commitment.clone(),
                    )
                })
                .collect::<Vec<_>>();
            indexes.push(PrivateOramOwnerJournalIndexDescriptorV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: "private-result".to_string(),
                old_epoch: 21,
                new_epoch: result_epoch,
                old_root_hash: digest(marker.wrapping_add(8)),
                new_root_hash: digest(marker.wrapping_add(9)),
                writeback_digest: digest(marker.wrapping_add(10)),
                read_path_count: 4,
                read_transcript_digest: digest(marker.wrapping_add(11)),
                ordered_bucket_refs: result_refs.clone(),
                final_bucket_refs: result_refs,
            });
            final_buckets.push(PrivateOramOwnerFinalBucketIndexV1 {
                index_name: "private-result".to_string(),
                buckets: PrivateOramOwnerFinalBucketBatchV1::Result(result_buckets),
            });
        }
        validated_from_parts(marker, indexes, final_buckets)
    }

    fn validated_from_parts(
        marker: u8,
        indexes: Vec<PrivateOramOwnerJournalIndexDescriptorV1>,
        final_buckets: Vec<PrivateOramOwnerFinalBucketIndexV1>,
    ) -> ValidatedOwnerJournal {
        let final_bucket_bytes = encode_final_bucket_frame(&indexes, &final_buckets).unwrap();
        let mut descriptor = PrivateOramOwnerJournalDescriptorV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION,
            parent_descriptor_digest: digest(marker.wrapping_add(12)),
            parent_lease_acquired_record_digest: digest(marker.wrapping_add(13)),
            owner_peer_id: 7,
            collection_id: format!("collection-{marker}"),
            mutation_id: digest(marker.wrapping_add(14)),
            signed_mutation_digest: digest(marker.wrapping_add(15)),
            writer_lease_digest: digest(marker.wrapping_add(16)),
            writer_fence: 9,
            indexes,
            final_bucket_frame_version: PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION,
            final_bucket_frame_length: final_bucket_bytes.len() as u64,
            final_bucket_frame_sha256: digest_string(&final_bucket_bytes),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor).unwrap();
        let descriptor_bytes = encode_descriptor(&descriptor).unwrap();
        let mut state = PrivateOramOwnerJournalStateV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
            sequence: 1,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            previous_record_digest: None,
            phase: PrivateOramOwnerJournalPhaseV1::Prepared,
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state).unwrap();
        let state_bytes = encode_state(&state).unwrap();
        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal: None,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes).unwrap();
        ValidatedOwnerJournal {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes: None,
        }
    }

    fn fixture() -> JournalFixture {
        let temp = TempDir::new().unwrap();
        let hnsw_root = temp.path().join("private-hnsw-root");
        create_private_directory(&hnsw_root).unwrap();
        create_private_directory(&hnsw_root.join(OWNER_STORE_TEMP_DIR)).unwrap();
        let journal = PrivateOramOwnerJournal::new(&hnsw_root);
        JournalFixture {
            _temp: temp,
            hnsw_root,
            journal,
        }
    }

    fn reservation_challenge(
        lifecycle: &PrivateOramOwnerLifecycleStateV1,
        committed_seed: u8,
    ) -> PrivateOramOwnerReservationPrepareChallengeV1 {
        PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 7,
            protocol_capability_digest: digest(6),
            membership_epoch: 9,
            reservation_intent_digest: digest(7),
            checkpoint_context_digest: digest(8),
            committed_challenge_digest: digest(committed_seed),
            challenge_applied_term: 3,
            challenge_applied_index: u64::from(committed_seed),
            attempt_id: digest(10),
            challenge_nonce: BASE64URL_NOPAD.encode(&[11; 16]),
            expected_checkpoint_record_digest: digest(12),
            expected_checkpoint_sequence: 1,
            expected_owner_target_digest: digest(13),
            reserved_terminal_intent_key: digest(14),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: digest(15),
            owner_peer_id: 11,
            owner_store_incarnation_digest: lifecycle.owner_store_incarnation_digest.clone(),
            authority_registry_digest: digest(16),
            owner_registry_digest: digest(17),
        }
    }

    #[test]
    fn reservation_prepare_does_not_create_an_unenrolled_store() {
        let fixture = fixture();
        let store = PrivateOramOwnerPrestageStoreV2::new(&fixture.hnsw_root);
        let lifecycle = private_oram_owner_lifecycle_genesis_state_v1(digest(20)).unwrap();
        let challenge = reservation_challenge(&lifecycle, 21);

        assert_eq!(
            store.prepare_reservation_fence_v1(&challenge, &lifecycle),
            Err(PrivateOramOwnerJournalError::NotEnrolled)
        );
        assert!(!store.root_path().exists());
    }

    #[test]
    fn bounded_directory_scan_rejects_before_collecting_beyond_the_limit() {
        let temp = TempDir::new().unwrap();
        let directory_path = temp.path().join("bounded");
        create_private_directory(&directory_path).unwrap();
        for index in 0..=PRESTAGE_MAX_TERMINAL_RECORDS {
            fs::write(directory_path.join(format!("entry-{index}")), []).unwrap();
        }
        let directory = open_private_directory(&directory_path).unwrap();

        assert_eq!(
            directory_entry_names_open_bounded(
                &directory,
                PRESTAGE_MAX_TERMINAL_RECORDS,
                PrivateOramOwnerJournalError::Corrupt,
            ),
            Err(PrivateOramOwnerJournalError::Corrupt)
        );
    }

    #[test]
    fn reservation_prepare_requires_durable_exclusive_fence_before_signing() {
        let fixture = fixture();
        let store = PrivateOramOwnerPrestageStoreV2::new(&fixture.hnsw_root);
        let lifecycle = store
            .inspect_lifecycle_v2(&digest(14))
            .unwrap()
            .lifecycle_state()
            .clone();
        let challenge = reservation_challenge(&lifecycle, 18);
        let fence = store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        let replay = store
            .prepare_reservation_fence_v1(&challenge, &lifecycle)
            .unwrap();
        assert_eq!(fence, replay);

        let key = Ed25519KeyPair::from_seed_unchecked(&[41; 32]).unwrap();
        let signer = private_oram_owner_cleanup_signer_v1(&key, 2).unwrap();
        let prepare = sign_private_oram_owner_reservation_prepare_v1(
            &key,
            fence.challenge().clone(),
            fence.lifecycle_state().clone(),
            fence.local_terminal_generation(),
            fence.fence_record_digest().to_string(),
            signer.clone(),
        )
        .unwrap();
        let _verified = validate_private_oram_owner_reservation_prepare_v1(
            &prepare, &challenge, &signer, &lifecycle,
        )
        .unwrap();

        let conflicting = reservation_challenge(&lifecycle, 19);
        assert_eq!(
            store.prepare_reservation_fence_v1(&conflicting, &lifecycle),
            Err(PrivateOramOwnerJournalError::ConcurrentMutation)
        );
    }

    /// Process kill matrix (PLAN V2-E gate): a child process aborts (like `SIGKILL`, no
    /// unwinding, no tempdir cleanup) at each durable boundary of a journal prepare and of a
    /// Finalized or AbortedOld terminal record. Afterwards the journal must hold either the
    /// previous durable state or the next one, never a partial one, and an exact retry must
    /// finish the transition despite the candidate directories the child left behind.
    #[cfg(target_os = "linux")]
    #[test]
    fn journal_survives_process_abort_at_every_durable_boundary() {
        const CHILD_ROOT_ENV: &str = "QDRANT_SEC_PRIVATE_ORAM_OWNER_JOURNAL_CRASH_CHILD_ROOT";
        const CHILD_PHASE_ENV: &str = "QDRANT_SEC_PRIVATE_ORAM_OWNER_JOURNAL_CRASH_CHILD_PHASE";
        const MARKER: u8 = 140;

        fn record_terminal(
            journal: &PrivateOramOwnerJournal,
            desired: &ValidatedOwnerJournal,
            finalize: bool,
        ) -> Result<PrivateOramOwnerJournalSnapshotV1, PrivateOramOwnerJournalError> {
            let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
            let parent_descriptor_digest =
                desired.snapshot.descriptor.parent_descriptor_digest.clone();
            let consensus_authority_record_digest = digest(MARKER.wrapping_add(20));
            let reconciliation_authority_digest = digest(MARKER.wrapping_add(21));
            let canonical_index_states = canonical_index_states(desired, MARKER.wrapping_add(22));
            if finalize {
                journal
                    .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                        expected_journal_descriptor_digest: &descriptor_digest,
                        parent_descriptor_digest: &parent_descriptor_digest,
                        authenticated_owner_peer_id: 7,
                        consensus_authority_record_digest: &consensus_authority_record_digest,
                        reconciliation_authority_digest: &reconciliation_authority_digest,
                        canonical_index_states: &canonical_index_states,
                    })
                    .map(|(snapshot, _)| snapshot)
            } else {
                journal
                    .record_aborted_old(PrivateOramOwnerJournalAbortOldContextV1 {
                        expected_journal_descriptor_digest: &descriptor_digest,
                        parent_descriptor_digest: &parent_descriptor_digest,
                        authenticated_owner_peer_id: 7,
                        consensus_authority_record_digest: &consensus_authority_record_digest,
                        reconciliation_authority_digest: &reconciliation_authority_digest,
                        canonical_index_states: &canonical_index_states,
                    })
                    .map(|(snapshot, _)| snapshot)
            }
        }

        if let (Some(hnsw_root), Some(phase)) = (
            std::env::var_os(CHILD_ROOT_ENV),
            std::env::var_os(CHILD_PHASE_ENV),
        ) {
            let journal = PrivateOramOwnerJournal::new(hnsw_root);
            let desired = validated_fixture(MARKER, true);
            let _ = journal.prepare_validated(desired.clone());
            let _ = record_terminal(&journal, &desired, phase == "finalize");
            panic!("the configured crash point was not reached");
        }

        for (crash_point, finalize) in [
            ("prepare_candidate_synced", true),
            ("prepare_active_installed", true),
            ("terminal_candidate_synced", true),
            ("terminal_installed", true),
            ("terminal_candidate_synced", false),
            ("terminal_installed", false),
        ] {
            let fixture = fixture();
            let desired = validated_fixture(MARKER, true);
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("private_oram_owner_journal::tests::journal_survives_process_abort_at_every_durable_boundary")
                .arg("--exact")
                .arg("--test-threads=1")
                .env(CHILD_ROOT_ENV, &fixture.hnsw_root)
                .env(CHILD_PHASE_ENV, if finalize { "finalize" } else { "abort_old" })
                .env(PRIVATE_ORAM_OWNER_JOURNAL_CRASH_POINT_ENV, crash_point)
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            {
                use std::os::unix::process::ExitStatusExt as _;
                assert_eq!(
                    status.signal(),
                    Some(nix::libc::SIGABRT),
                    "child did not abort at {crash_point}: {status}",
                );
            }

            let expected_phase = if finalize {
                PrivateOramOwnerJournalPhaseV1::Finalized
            } else {
                PrivateOramOwnerJournalPhaseV1::AbortedOld
            };
            let reopened = fixture.journal.inspect_structural().unwrap();
            match crash_point {
                "prepare_candidate_synced" => {
                    assert!(reopened.is_none(), "a stranded candidate became active");
                }
                "prepare_active_installed" | "terminal_candidate_synced" => {
                    let reopened = reopened.unwrap();
                    assert_eq!(
                        reopened, desired.snapshot,
                        "prepared state after {crash_point}"
                    );
                }
                "terminal_installed" => {
                    let phase = reopened.unwrap().terminal.unwrap().phase;
                    assert_eq!(phase, expected_phase, "terminal phase after {crash_point}");
                }
                _ => unreachable!(),
            }

            // An exact prepare retry replays the prepared record; once a terminal record exists
            // it is refused as a new mutation instead.
            match fixture.journal.prepare_validated(desired.clone()) {
                Ok((prepared, _)) => {
                    assert_ne!(crash_point, "terminal_installed");
                    assert_eq!(
                        prepared, desired.snapshot,
                        "prepare retry after {crash_point}"
                    );
                }
                Err(error) => assert_eq!(
                    (crash_point, error),
                    (
                        "terminal_installed",
                        PrivateOramOwnerJournalError::ConcurrentMutation
                    ),
                ),
            }
            let finished = record_terminal(&fixture.journal, &desired, finalize)
                .unwrap_or_else(|error| panic!("terminal retry after {crash_point}: {error:?}"));
            assert_eq!(finished.terminal.as_ref().unwrap().phase, expected_phase);
            assert_eq!(
                fixture.journal.inspect_structural().unwrap().unwrap(),
                finished
            );
            // The other terminal phase stays refused after recovery.
            assert_eq!(
                record_terminal(&fixture.journal, &desired, !finalize).unwrap_err(),
                PrivateOramOwnerJournalError::InvalidTransition,
                "terminal substitution after {crash_point}",
            );
        }
    }

    fn active_path(fixture: &JournalFixture) -> PathBuf {
        fixture.journal.root.join(ACTIVE_DIR)
    }

    fn terminal_path(fixture: &JournalFixture) -> PathBuf {
        active_path(fixture).join(TERMINAL_DIR)
    }

    fn prepare_and_finalize(fixture: &JournalFixture, marker: u8) {
        let desired = validated_fixture(marker, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(marker.wrapping_add(120));
        let reconciliation_authority_digest = digest(marker.wrapping_add(121));
        let canonical_index_states = canonical_index_states(&desired, marker.wrapping_add(122));
        fixture.journal.prepare_validated(desired).unwrap();
        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
    }

    #[test]
    fn canonical_codecs_round_trip() {
        let desired = validated_fixture(1, true);
        let decoded = ValidatedOwnerJournal::decode(
            desired.descriptor_bytes.clone(),
            desired.final_bucket_bytes.clone(),
            desired.state_bytes.clone(),
            None,
        )
        .unwrap();

        assert!(decoded.exactly_matches(&desired));
        assert_eq!(decoded.snapshot.descriptor.indexes.len(), 2);
        assert_eq!(
            decoded.snapshot.descriptor.indexes[0]
                .ordered_bucket_refs
                .len(),
            3
        );
        assert_eq!(
            decoded.snapshot.descriptor.indexes[0]
                .final_bucket_refs
                .len(),
            2
        );
        assert_eq!(
            (
                desired.snapshot.descriptor.descriptor_digest.as_str(),
                desired
                    .snapshot
                    .descriptor
                    .final_bucket_frame_sha256
                    .as_str(),
                desired.snapshot.state.state_digest.as_str(),
            ),
            (
                "roOyXeChO0guhChkl6yBmv9_TsfQo4nK7lrsXt1VWZY",
                "h_xkYfrPQjXyBnKbMSgp4ZfEkB4xog6HaVht2CGCoM0",
                "-ji2rNgkMAUaRNGwJsrrUuGPk35jHqh4W5bouJgNTpo",
            )
        );
    }

    #[test]
    fn terminal_codecs_round_trip_with_distinct_known_answers() {
        let desired = validated_fixture(19, true);
        let consensus_authority_record_digest = digest(90);
        let finalize_authority_digest = digest(91);
        let abort_authority_digest = digest(92);
        let finalized_index_states = canonical_index_states(&desired, 105);
        let aborted_index_states = canonical_index_states(&desired, 107);
        let finalized = build_terminal_record(
            &desired.snapshot,
            TerminalTransition {
                phase: PrivateOramOwnerJournalPhaseV1::Finalized,
                expected_journal_descriptor_digest: &desired.snapshot.descriptor.descriptor_digest,
                parent_descriptor_digest: &desired.snapshot.descriptor.parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &finalize_authority_digest,
                canonical_index_states: &finalized_index_states,
            },
        )
        .unwrap();
        let aborted = build_terminal_record(
            &desired.snapshot,
            TerminalTransition {
                phase: PrivateOramOwnerJournalPhaseV1::AbortedOld,
                expected_journal_descriptor_digest: &desired.snapshot.descriptor.descriptor_digest,
                parent_descriptor_digest: &desired.snapshot.descriptor.parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &abort_authority_digest,
                canonical_index_states: &aborted_index_states,
            },
        )
        .unwrap();
        let finalized_bytes = encode_terminal_record(&finalized).unwrap();
        let aborted_bytes = encode_terminal_record(&aborted).unwrap();
        let mut finalized_snapshot = desired.snapshot.clone();
        finalized_snapshot.terminal = Some(finalized.clone());
        let mut aborted_snapshot = desired.snapshot;
        aborted_snapshot.terminal = Some(aborted.clone());

        assert_eq!(decode_terminal_record(&finalized_bytes).unwrap(), finalized);
        assert_eq!(decode_terminal_record(&aborted_bytes).unwrap(), aborted);
        assert_ne!(finalized_bytes, aborted_bytes);
        assert_eq!(
            (
                finalized.record_digest.as_str(),
                aborted.record_digest.as_str(),
                index_terminal_evidence_digest(
                    &finalized_snapshot,
                    finalized_snapshot.terminal.as_ref().unwrap(),
                    &finalized_snapshot.descriptor.indexes[0],
                )
                .unwrap(),
                index_terminal_evidence_digest(
                    &aborted_snapshot,
                    aborted_snapshot.terminal.as_ref().unwrap(),
                    &aborted_snapshot.descriptor.indexes[0],
                )
                .unwrap(),
            ),
            (
                "jZhaXH4MRgJwDEN_Y6-OZWStljvlUMGJKPcnAJQxh-w",
                "9-LWfFY2Nz1jzF24JDe5-zXrfm22cbldScGIvVZDJGo",
                "YCC1KyQTJvinV6YCB149WrgesDcLVRCwwfFpnwx95Xk".to_string(),
                "JfZ28r4ATcFOFUuPIcBhDcgEFkySkUQywfEOHZfTKZY".to_string()
            )
        );
    }

    #[test]
    fn descriptor_rejects_invalid_epoch_and_non_last_final_ref() {
        let desired = validated_fixture(14, false);
        let mut invalid_epoch = desired.snapshot.descriptor.clone();
        invalid_epoch.indexes[0].new_epoch = invalid_epoch.indexes[0].old_epoch;
        invalid_epoch.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&invalid_epoch).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mut invalid_root = desired.snapshot.descriptor.clone();
        invalid_root.indexes[0].new_root_hash = invalid_root.indexes[0].old_root_hash.clone();
        invalid_root.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&invalid_root).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mut invalid_final = desired.snapshot.descriptor;
        invalid_final.indexes[0].ordered_bucket_refs[2].ciphertext_sha256 = digest(230);
        invalid_final.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&invalid_final).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let paired = validated_fixture(15, true);
        let mut too_many = paired.snapshot.descriptor;
        let mut extra_result = too_many.indexes[1].clone();
        extra_result.index_name = "private-result-2".to_string();
        too_many.indexes.push(extra_result);
        too_many.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&too_many).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn prepare_reopen_and_exact_replay_return_same_token() {
        let fixture = fixture();
        let desired = validated_fixture(2, true);

        let (prepared, token) = fixture.journal.prepare_validated(desired.clone()).unwrap();
        let (replayed, replay_token) = fixture.journal.prepare_validated(desired).unwrap();
        let reopened = fixture.journal.inspect_structural().unwrap().unwrap();

        assert_eq!(prepared, replayed);
        assert_eq!(prepared, reopened);
        assert_eq!(token, replay_token);
        assert_eq!(token.indexes().len(), 2);
        assert_eq!(
            directory_entry_names(&fixture.journal.root).unwrap().len(),
            1
        );
    }

    #[test]
    fn conflicting_prepare_never_replaces_active() {
        let fixture = fixture();
        let first = validated_fixture(3, false);
        let second = validated_fixture(4, false);
        let (_, first_token) = fixture.journal.prepare_validated(first).unwrap();

        assert_eq!(
            fixture.journal.prepare_validated(second).unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
        let current = fixture.journal.inspect_structural().unwrap().unwrap();
        assert_eq!(
            current.descriptor.descriptor_digest,
            first_token.journal_descriptor_digest()
        );
    }

    #[test]
    fn paired_indexes_publish_as_one_active_artifact() {
        let fixture = fixture();
        let (snapshot, token) = fixture
            .journal
            .prepare_validated(validated_fixture(5, true))
            .unwrap();

        assert_eq!(snapshot.descriptor.indexes.len(), 2);
        assert_eq!(snapshot.final_buckets.len(), 2);
        assert_eq!(token.indexes().len(), 2);
        assert_eq!(
            directory_entry_names(&active_path(&fixture)).unwrap(),
            [
                DESCRIPTOR_FILE,
                FINAL_BUCKETS_FILE,
                STATE_FILE,
                ACTIVE_TEMP_DIR
            ]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect()
        );
    }

    #[test]
    fn earlier_duplicate_changes_descriptor_but_not_final_image() {
        let first = validated_fixture(6, false);
        let mut indexes = first.snapshot.descriptor.indexes.clone();
        indexes[0].ordered_bucket_refs[0].ciphertext_sha256 = digest(201);
        indexes[0].ordered_bucket_refs[0].bucket_commitment = digest(202);
        let second = validated_from_parts(6, indexes, first.snapshot.final_buckets.clone());

        assert_eq!(first.final_bucket_bytes, second.final_bucket_bytes);
        assert_ne!(
            first.snapshot.descriptor.descriptor_digest,
            second.snapshot.descriptor.descriptor_digest
        );
        assert_eq!(
            second.snapshot.descriptor.indexes[0]
                .ordered_bucket_refs
                .len(),
            3
        );
        assert_eq!(
            second.snapshot.descriptor.indexes[0]
                .final_bucket_refs
                .len(),
            2
        );
    }

    #[test]
    fn stranded_candidate_is_never_adopted() {
        let fixture = fixture();
        fixture.journal.ensure_root().unwrap();
        let stranded = fixture.journal.root.join(".candidate-stranded");
        create_private_directory(&stranded).unwrap();

        assert!(fixture.journal.inspect_structural().unwrap().is_none());
        fixture
            .journal
            .prepare_validated(validated_fixture(7, false))
            .unwrap();

        assert!(stranded.exists());
        assert!(active_path(&fixture).exists());
    }

    #[test]
    fn prepare_does_not_modify_canonical_store_files() {
        let fixture = fixture();
        let bucket_sentinel = fixture.hnsw_root.join("canonical-buckets.sentinel");
        let merkle_sentinel = fixture.hnsw_root.join("canonical-merkle.sentinel");
        let epoch_sentinel = fixture.hnsw_root.join("canonical-epoch.sentinel");
        fs::write(&bucket_sentinel, b"old-buckets").unwrap();
        fs::write(&merkle_sentinel, b"old-merkle").unwrap();
        fs::write(&epoch_sentinel, b"old-epoch").unwrap();

        fixture
            .journal
            .prepare_validated(validated_fixture(8, true))
            .unwrap();

        assert_eq!(fs::read(bucket_sentinel).unwrap(), b"old-buckets");
        assert_eq!(fs::read(merkle_sentinel).unwrap(), b"old-merkle");
        assert_eq!(fs::read(epoch_sentinel).unwrap(), b"old-epoch");
    }

    #[test]
    fn active_file_tamper_fails_closed() {
        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(9, false))
            .unwrap();
        let state = active_path(&fixture).join(STATE_FILE);
        let mut bytes = fs::read(&state).unwrap();
        bytes[0] ^= 1;
        fs::write(state, bytes).unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn pinned_file_detects_same_inode_content_rewrite() {
        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(17, false))
            .unwrap();
        let state_path = active_path(&fixture).join(STATE_FILE);
        let (mut pinned, expected) =
            read_private_file_pinned(&state_path, MAX_STATE_BYTES).unwrap();
        let mut changed = expected.clone();
        changed[0] ^= 1;
        fs::write(state_path, changed).unwrap();

        assert_eq!(
            pinned.validate_exact_contents(&expected).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn live_prepared_store_binding_requires_exact_token_and_holds_shared_lock() {
        let fixture = fixture();
        let desired = validated_fixture(18, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(91);
        let reconciliation_authority_digest = digest(92);
        let canonical_index_states = canonical_index_states(&desired, 107);
        let (_, prepared) = fixture.journal.prepare_validated(desired.clone()).unwrap();

        let binding = fixture
            .journal
            .bind_live_prepared_store_adapter_v1(&prepared)
            .unwrap();
        assert_eq!(binding.snapshot(), &desired.snapshot);

        let mut forged = prepared.clone();
        forged.owner_peer_id += 1;
        assert_eq!(
            fixture
                .journal
                .bind_live_prepared_store_adapter_v1(&forged)
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );

        let concurrent_terminal = fixture
            .journal
            .with_live_prepared_store_binding_v1(&prepared, |live_binding| {
                assert_eq!(live_binding, &binding);
                fixture
                    .journal
                    .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                        expected_journal_descriptor_digest: &descriptor_digest,
                        parent_descriptor_digest: &parent_descriptor_digest,
                        authenticated_owner_peer_id: 7,
                        consensus_authority_record_digest: &consensus_authority_record_digest,
                        reconciliation_authority_digest: &reconciliation_authority_digest,
                        canonical_index_states: &canonical_index_states,
                    })
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(
            concurrent_terminal,
            PrivateOramOwnerJournalError::ConcurrentMutation
        );

        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
        assert_eq!(
            fixture
                .journal
                .bind_live_prepared_store_adapter_v1(&prepared)
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn recovery_rebind_recomputes_exact_pair_and_holds_shared_lock() {
        let fixture = fixture();
        let desired = validated_fixture(119, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(120);
        let reconciliation_authority_digest = digest(121);
        let canonical_index_states = canonical_index_states(&desired, 122);
        let expected_snapshot = desired.snapshot.clone();
        let expected_prepared = prepared_token(&expected_snapshot.descriptor).unwrap();
        let projection = recovery_projection(&desired);
        fixture.journal.prepare_validated(desired).unwrap();

        let concurrent_terminal = fixture
            .journal
            .with_revalidated_recovery_prepared_v1(&projection, |binding| {
                assert_eq!(&binding.prepared, &expected_prepared);
                assert_eq!(binding.store_binding.snapshot(), &expected_snapshot);
                let rendered = format!("{binding:?}");
                assert!(!rendered.contains(&descriptor_digest));
                assert!(!rendered.contains("collection-119"));
                fixture
                    .journal
                    .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                        expected_journal_descriptor_digest: &descriptor_digest,
                        parent_descriptor_digest: &parent_descriptor_digest,
                        authenticated_owner_peer_id: 7,
                        consensus_authority_record_digest: &consensus_authority_record_digest,
                        reconciliation_authority_digest: &reconciliation_authority_digest,
                        canonical_index_states: &canonical_index_states,
                    })
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(
            concurrent_terminal,
            PrivateOramOwnerJournalError::ConcurrentMutation
        );

        let mut substitutions = Vec::new();
        let mut forged = projection.clone();
        forged.expected_owner_peer_id += 1;
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.parent_descriptor_digest = digest(123);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.parent_lease_acquired_record_digest = digest(124);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.mutation_id = digest(125);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.writer_fence += 1;
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.indexes.swap(0, 1);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.indexes[0].prepared_journal_digest = digest(126);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.indexes[1].new_root_hash = digest(127);
        substitutions.push(forged);

        for forged in substitutions {
            let mut called = false;
            assert_eq!(
                fixture
                    .journal
                    .with_revalidated_recovery_prepared_v1(&forged, |_| called = true)
                    .unwrap_err(),
                PrivateOramOwnerJournalError::InvalidTransition
            );
            assert!(!called);
        }

        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
        assert_eq!(
            fixture
                .journal
                .with_revalidated_recovery_prepared_v1(&projection, |_| ())
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn recovery_rebind_requires_hnsw_result_pair() {
        let fixture = fixture();
        let desired = validated_fixture(120, false);
        let projection = recovery_projection(&desired);
        fixture.journal.prepare_validated(desired).unwrap();

        assert_eq!(
            fixture
                .journal
                .with_revalidated_recovery_prepared_v1(&projection, |_| ())
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn recovery_exclusive_binding_records_and_replays_finalized_terminal() {
        let fixture = fixture();
        let desired = validated_fixture(121, true);
        let projection = recovery_projection(&desired);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(128);
        let reconciliation_authority_digest = digest(129);
        let canonical_index_states = canonical_index_states(&desired, 130);
        fixture.journal.prepare_validated(desired).unwrap();
        let context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &reconciliation_authority_digest,
            canonical_index_states: &canonical_index_states,
        };

        let outcome = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                assert!(binding.untrusted_snapshot_view().terminal.is_none());
                assert_eq!(
                    binding.state(),
                    PrivateOramOwnerRecoveryExclusiveStateV1::Prepared
                );
                assert_eq!(
                    fixture.journal.inspect_structural().unwrap_err(),
                    PrivateOramOwnerJournalError::ConcurrentMutation
                );
                binding.finalize_action(context)
            })
            .unwrap();
        let token = match outcome.unwrap() {
            PrivateOramOwnerRecoveryExclusiveOutcomeV1::Finalized(token) => token,
            _ => panic!("expected finalized outcome"),
        };

        let replayed_outcome = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                assert_eq!(
                    binding.state(),
                    PrivateOramOwnerRecoveryExclusiveStateV1::FinalizedReplay
                );
                binding.finalize_action(context)
            })
            .unwrap()
            .unwrap();
        let replayed = match replayed_outcome {
            PrivateOramOwnerRecoveryExclusiveOutcomeV1::Finalized(token) => token,
            _ => panic!("expected finalized replay outcome"),
        };

        assert_eq!(token, replayed);
    }

    #[test]
    fn recovery_terminal_continuation_runs_before_child_lock_release() {
        let fixture = fixture();
        let desired = validated_fixture(132, true);
        let projection = recovery_projection(&desired);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(133);
        let reconciliation_authority_digest = digest(134);
        let canonical_index_states = canonical_index_states(&desired, 135);
        fixture.journal.prepare_validated(desired).unwrap();
        let context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &reconciliation_authority_digest,
            canonical_index_states: &canonical_index_states,
        };

        let output = fixture
            .journal
            .with_revalidated_recovery_exclusive_then_v1(
                &projection,
                |binding| binding.finalize_action(context),
                |outcome| {
                    assert!(matches!(
                        outcome,
                        PrivateOramOwnerRecoveryExclusiveOutcomeV1::Finalized(_)
                    ));
                    assert_eq!(
                        fixture.journal.inspect_structural().unwrap_err(),
                        PrivateOramOwnerJournalError::ConcurrentMutation
                    );
                    Ok::<_, PrivateOramOwnerJournalError>(7_u8)
                },
            )
            .unwrap()
            .unwrap();

        assert_eq!(output, 7);
        assert_eq!(
            fixture
                .journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .unwrap()
                .phase,
            PrivateOramOwnerJournalPhaseV1::Finalized
        );
    }

    #[test]
    fn recovery_exclusive_root_replacement_cannot_expose_terminal_token() {
        let fixture = fixture();
        let desired = validated_fixture(124, true);
        let projection = recovery_projection(&desired);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(139);
        let reconciliation_authority_digest = digest(140);
        let canonical_index_states = canonical_index_states(&desired, 141);
        fixture.journal.prepare_validated(desired).unwrap();
        let context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &reconciliation_authority_digest,
            canonical_index_states: &canonical_index_states,
        };
        let moved_root = fixture
            .journal
            .root_path()
            .parent()
            .unwrap()
            .join("private-oram-owner-journal-moved");

        assert_eq!(
            fixture
                .journal
                .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                    fs::rename(fixture.journal.root_path(), &moved_root).unwrap();
                    binding.finalize_action(context)
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
        let moved = PrivateOramOwnerJournal { root: moved_root };
        assert!(
            moved
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );
    }

    #[test]
    fn recovery_exclusive_callback_error_releases_lock_without_terminal() {
        let fixture = fixture();
        let desired = validated_fixture(125, true);
        let projection = recovery_projection(&desired);
        fixture.journal.prepare_validated(desired).unwrap();

        let callback_result = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |_| {
                Err::<PrivateOramOwnerRecoveryExclusiveActionV1<'_>, _>("sentinel")
            })
            .unwrap();
        assert_eq!(callback_result.unwrap_err(), "sentinel");
        let outcome = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                Ok::<_, ()>(binding.no_terminal_action())
            })
            .unwrap()
            .unwrap();
        assert!(matches!(
            outcome,
            PrivateOramOwnerRecoveryExclusiveOutcomeV1::NoTerminal
        ));
        assert!(
            fixture
                .journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );
    }

    #[test]
    fn recovery_exclusive_terminal_replay_rejects_phase_substitution() {
        let fixture = fixture();
        let desired = validated_fixture(122, true);
        let projection = recovery_projection(&desired);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(131);
        let abort_authority_digest = digest(132);
        let finalize_authority_digest = digest(133);
        let aborted_index_states = canonical_index_states(&desired, 134);
        let finalized_index_states = canonical_index_states(&desired, 135);
        fixture.journal.prepare_validated(desired).unwrap();
        let abort_context = PrivateOramOwnerJournalAbortOldContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &abort_authority_digest,
            canonical_index_states: &aborted_index_states,
        };
        let finalize_context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &finalize_authority_digest,
            canonical_index_states: &finalized_index_states,
        };

        let outcome = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                binding.abort_old_action(abort_context)
            })
            .unwrap()
            .unwrap();
        let token = match outcome {
            PrivateOramOwnerRecoveryExclusiveOutcomeV1::AbortedOld(token) => token,
            _ => panic!("expected aborted-old outcome"),
        };
        let substituted = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                assert_eq!(
                    binding.state(),
                    PrivateOramOwnerRecoveryExclusiveStateV1::AbortedOldReplay
                );
                binding.finalize_action(finalize_context)
            })
            .unwrap();
        assert_eq!(
            substituted.unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let replayed_outcome = fixture
            .journal
            .with_revalidated_recovery_exclusive_v1(&projection, |binding| {
                binding.abort_old_action(abort_context)
            })
            .unwrap()
            .unwrap();
        let replayed = match replayed_outcome {
            PrivateOramOwnerRecoveryExclusiveOutcomeV1::AbortedOld(token) => token,
            _ => panic!("expected aborted-old replay outcome"),
        };

        assert_eq!(token, replayed);
    }

    #[test]
    fn locked_terminal_recorder_rejects_shared_root_guard() {
        let fixture = fixture();
        let desired = validated_fixture(123, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(136);
        let reconciliation_authority_digest = digest(137);
        let canonical_index_states = canonical_index_states(&desired, 138);
        fixture.journal.prepare_validated(desired).unwrap();
        let root = open_private_directory(fixture.journal.root_path()).unwrap();
        let root_lock = lock_private_journal_root_shared(&root).unwrap();

        let error = match fixture.journal.record_terminal_under_exclusive_lock(
            &root_lock,
            TerminalTransition {
                phase: PrivateOramOwnerJournalPhaseV1::Finalized,
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            },
        ) {
            Ok(_) => panic!("shared root guard authorized terminal publication"),
            Err(error) => error,
        };
        assert_eq!(error, PrivateOramOwnerJournalError::InvalidTransition);
        drop(root_lock);
        assert!(
            fixture
                .journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );
    }

    #[test]
    fn finalized_terminal_reopens_and_exact_replay_returns_same_token() {
        let fixture = fixture();
        let desired = validated_fixture(20, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(93);
        let reconciliation_authority_digest = digest(94);
        let canonical_index_states = canonical_index_states(&desired, 109);
        fixture.journal.prepare_validated(desired.clone()).unwrap();
        let context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &reconciliation_authority_digest,
            canonical_index_states: &canonical_index_states,
        };

        let (finalized, token) = fixture.journal.record_finalized(context).unwrap();
        let (replayed, replay_token) = fixture.journal.record_finalized(context).unwrap();
        let reopened = fixture.journal.inspect_structural().unwrap().unwrap();

        assert_eq!(finalized, replayed);
        assert_eq!(finalized, reopened);
        assert_eq!(token, replay_token);
        assert_eq!(
            finalized.terminal.as_ref().unwrap().phase,
            PrivateOramOwnerJournalPhaseV1::Finalized
        );
        assert_eq!(token.owner_peer_id(), 7);
        assert_eq!(token.journal_descriptor_digest(), descriptor_digest);
        assert_eq!(token.indexes().len(), 2);
        assert_eq!(
            token.indexes()[0].prepared_journal_digest(),
            prepared_token(&finalized.descriptor).unwrap().indexes()[0].prepared_journal_digest()
        );
        assert!(terminal_path(&fixture).join(TERMINAL_RECORD_FILE).exists());
        assert_eq!(
            fixture.journal.prepare_validated(desired).unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
    }

    #[test]
    fn aborted_old_terminal_replays_and_rejects_finalize_substitution() {
        let fixture = fixture();
        let desired = validated_fixture(21, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(95);
        let abort_authority_digest = digest(96);
        let finalize_authority_digest = digest(97);
        let aborted_index_states = canonical_index_states(&desired, 111);
        let finalized_index_states = canonical_index_states(&desired, 112);
        fixture.journal.prepare_validated(desired).unwrap();
        let abort_context = PrivateOramOwnerJournalAbortOldContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &abort_authority_digest,
            canonical_index_states: &aborted_index_states,
        };

        let (aborted, token) = fixture.journal.record_aborted_old(abort_context).unwrap();
        let (replayed, replay_token) = fixture.journal.record_aborted_old(abort_context).unwrap();
        let finalize_context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &finalize_authority_digest,
            canonical_index_states: &finalized_index_states,
        };

        assert_eq!(aborted, replayed);
        assert_eq!(token, replay_token);
        assert_eq!(
            aborted.terminal.as_ref().unwrap().phase,
            PrivateOramOwnerJournalPhaseV1::AbortedOld
        );
        assert_eq!(token.owner_peer_id(), 7);
        assert_eq!(token.indexes().len(), 1);
        assert_eq!(
            fixture
                .journal
                .record_finalized(finalize_context)
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn terminal_requires_exact_descriptor_parent_and_authenticated_owner() {
        let fixture = fixture();
        let desired = validated_fixture(22, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let wrong_digest = digest(98);
        let consensus_authority_record_digest = digest(99);
        let authority_digest = digest(100);
        let canonical_index_states = canonical_index_states(&desired, 113);
        fixture.journal.prepare_validated(desired).unwrap();

        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &wrong_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &wrong_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 8,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert!(!terminal_path(&fixture).exists());
    }

    #[test]
    fn terminal_requires_exact_authorities_and_canonical_index_states() {
        let fixture = fixture();
        let desired = validated_fixture(25, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(116);
        let reconciliation_authority_digest = digest(117);
        let canonical_index_states = canonical_index_states(&desired, 118);
        fixture.journal.prepare_validated(desired).unwrap();

        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &canonical_index_states[..1],
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let mut wrong_identity = canonical_index_states.clone();
        wrong_identity[1].index_name.push_str("-wrong");
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &wrong_identity,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert!(!terminal_path(&fixture).exists());

        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();

        let changed_consensus_authority = digest(119);
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &changed_consensus_authority,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let changed_reconciliation_authority = digest(120);
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &changed_reconciliation_authority,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let mut changed_canonical_state = canonical_index_states;
        changed_canonical_state[0].canonical_state_digest = digest(121);
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &changed_canonical_state,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn stranded_terminal_candidate_is_preserved_but_never_adopted() {
        let fixture = fixture();
        let desired = validated_fixture(23, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(101);
        let authority_digest = digest(102);
        let canonical_index_states = canonical_index_states(&desired, 114);
        fixture.journal.prepare_validated(desired).unwrap();
        let stranded = active_path(&fixture)
            .join(ACTIVE_TEMP_DIR)
            .join(".terminal-candidate-stranded");
        create_private_directory(&stranded).unwrap();

        let structural = fixture.journal.inspect_structural().unwrap().unwrap();
        assert!(structural.terminal.is_none());
        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();

        assert!(stranded.exists());
        assert!(terminal_path(&fixture).exists());
    }

    #[test]
    fn terminal_record_tamper_fails_closed() {
        let fixture = fixture();
        let desired = validated_fixture(24, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(103);
        let authority_digest = digest(104);
        let canonical_index_states = canonical_index_states(&desired, 115);
        fixture.journal.prepare_validated(desired).unwrap();
        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
        let record_path = terminal_path(&fixture).join(TERMINAL_RECORD_FILE);
        let mut bytes = fs::read(&record_path).unwrap();
        bytes[0] ^= 1;
        fs::write(record_path, bytes).unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exclusive_root_lock_rejects_concurrent_prepare() {
        let fixture = fixture();
        let root = fixture.journal.ensure_root().unwrap();
        let _lock = lock_private_journal_root(&root).unwrap();

        assert_eq!(
            fixture
                .journal
                .prepare_validated(validated_fixture(18, false))
                .unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structural_read_rejects_concurrent_terminal_writer() {
        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(26, false))
            .unwrap();
        let root = open_private_directory(&fixture.journal.root).unwrap();
        let _lock = lock_private_journal_root(&root).unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_bad_mode_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let symlink_fixture = fixture();
        symlink_fixture
            .journal
            .prepare_validated(validated_fixture(10, false))
            .unwrap();
        let symlink_state = active_path(&symlink_fixture).join(STATE_FILE);
        let outside = symlink_fixture.hnsw_root.join("outside-state");
        fs::rename(&symlink_state, &outside).unwrap();
        symlink(&outside, &symlink_state).unwrap();
        assert_eq!(
            symlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let hardlink_fixture = fixture();
        hardlink_fixture
            .journal
            .prepare_validated(validated_fixture(11, false))
            .unwrap();
        let hardlink_state = active_path(&hardlink_fixture).join(STATE_FILE);
        fs::hard_link(
            &hardlink_state,
            hardlink_fixture.hnsw_root.join("state-hardlink"),
        )
        .unwrap();
        assert_eq!(
            hardlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mode_fixture = fixture();
        mode_fixture
            .journal
            .prepare_validated(validated_fixture(12, false))
            .unwrap();
        let mode_state = active_path(&mode_fixture).join(STATE_FILE);
        fs::set_permissions(&mode_state, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            mode_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_symlink_hardlink_bad_mode_and_oversize_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let symlink_fixture = fixture();
        prepare_and_finalize(&symlink_fixture, 27);
        let symlink_record = terminal_path(&symlink_fixture).join(TERMINAL_RECORD_FILE);
        let outside = symlink_fixture.hnsw_root.join("outside-terminal-record");
        fs::rename(&symlink_record, &outside).unwrap();
        symlink(&outside, &symlink_record).unwrap();
        assert_eq!(
            symlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let hardlink_fixture = fixture();
        prepare_and_finalize(&hardlink_fixture, 28);
        let hardlink_record = terminal_path(&hardlink_fixture).join(TERMINAL_RECORD_FILE);
        fs::hard_link(
            &hardlink_record,
            hardlink_fixture.hnsw_root.join("terminal-record-hardlink"),
        )
        .unwrap();
        assert_eq!(
            hardlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mode_fixture = fixture();
        prepare_and_finalize(&mode_fixture, 29);
        let mode_record = terminal_path(&mode_fixture).join(TERMINAL_RECORD_FILE);
        fs::set_permissions(&mode_record, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            mode_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let oversized_fixture = fixture();
        prepare_and_finalize(&oversized_fixture, 30);
        let oversized_record = terminal_path(&oversized_fixture).join(TERMINAL_RECORD_FILE);
        OpenOptions::new()
            .write(true)
            .open(&oversized_record)
            .unwrap()
            .set_len(MAX_TERMINAL_RECORD_BYTES + 1)
            .unwrap();
        assert_eq!(
            oversized_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_candidate_allows_partial_record_but_rejects_unknown_entry() {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(31, false))
            .unwrap();
        let temp = active_path(&fixture).join(ACTIVE_TEMP_DIR);
        let partial = temp.join(".terminal-candidate-partial");
        create_private_directory(&partial).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(partial.join(TERMINAL_RECORD_FILE))
            .unwrap();
        assert!(
            fixture
                .journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );

        let unknown = temp.join(".terminal-candidate-unknown");
        create_private_directory(&unknown).unwrap();
        fs::write(unknown.join("unexpected"), b"x").unwrap();
        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn unknown_root_entry_fails_closed() {
        let fixture = fixture();
        fixture.journal.ensure_root().unwrap();
        fs::write(fixture.journal.root.join("unexpected"), b"x").unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn debug_and_errors_redact_sensitive_values() {
        let desired = validated_fixture(13, true);
        let debug = format!("{:?}", desired.snapshot);
        let error_debug = format!("{:?}", PrivateOramOwnerJournalError::Corrupt);
        let error_display = PrivateOramOwnerJournalError::Corrupt.to_string();

        assert!(!debug.contains(&desired.snapshot.descriptor.collection_id));
        assert!(!debug.contains(&desired.snapshot.descriptor.mutation_id));
        assert!(!debug.contains(
            &desired.snapshot.descriptor.indexes[0].ordered_bucket_refs[0].ciphertext_sha256
        ));
        assert!(!error_debug.contains("collection-13"));
        assert!(!error_display.contains("collection-13"));
    }
}
