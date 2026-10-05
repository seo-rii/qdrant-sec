use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, EncryptionRuleRef,
    EncryptionSelector, private_hnsw_oram_api_required_message,
};
use collection::operations::types::CollectionError;
use collection::private_hnsw_oram_store::{
    PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND, PrivateHnswOramConsensusWriteback,
    PrivateHnswOramEpochState, PrivateHnswOramLiveReplicationBundle, PrivateHnswOramMerkleProof,
    PrivateHnswOramStore, PrivateHnswOramWritebackBatch,
};
use collection::shards::transfer::ShardTransfer;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING, PrivateHnswBucketAeadContext,
    PrivateHnswManifestValidationContext, PrivateHnswOramBucket, PrivateHnswOramCommitBucketRef,
    PrivateHnswOramCommitSignatureInput, PrivateHnswOramError, PrivateHnswOramManifest,
    PrivateHnswOramReadPathsSignatureInput, PrivateHnswOramSignature, PrivateHnswOramUploadBundle,
    PrivateHnswParams, PrivateHnswSignatureVerification, ResultPrivacyMode,
    VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, decode_private_hnsw_oram_leaf_label,
    private_hnsw_bucket_commitment, private_hnsw_oram_bucket_ciphertext_bytes,
    private_hnsw_oram_bucket_count, private_hnsw_oram_bucket_ids_for_leaf,
    private_hnsw_oram_fixed_writeback_bucket_budget,
    private_hnsw_oram_session_writeback_bucket_budget, private_hnsw_oram_writeback_digest,
    validate_private_hnsw_oram_commit_signature, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_manifest_signature_shape,
    validate_private_hnsw_oram_read_paths_signature,
};
use segment::types::Distance;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::{
    PRIVATE_ORAM_JSON_MERKLE_TREE_HEIGHT_MAX, PRIVATE_ORAM_PATH_BATCH_SIZE_MAX,
    validate_collection_crypto_runtime_with_crypto_id,
};
use crate::settings::{CryptoInstanceConfig, Settings};

const SIGNATURE_PUBLIC_KEYS_OPTION: &str = "signature_public_keys";
const KEY_ID_OPTION: &str = "key_id";
const EXPECTED_RK_ID_OPTION: &str = "expected_rk_id";
const MIN_RK_EPOCH_OPTION: &str = "min_rk_epoch";
const MAX_RK_EPOCH_OPTION: &str = "max_rk_epoch";
const RESULT_PRIVACY_OPTION: &str = "result_privacy";
const HNSW_OPTION: &str = "hnsw";
const ORAM_OPTION: &str = "oram";
const FIXED_BUDGET_OPTION: &str = "fixed_budget";
const ZERO_TRUST_PROFILE_STRICT: &str = "strict";
const SESSION_LEASE_SECS: u64 = 300;
const MAX_SESSION_COUNT: usize = 1024;
const PRIVATE_HNSW_ORAM_LEAF_LABEL_B64_LEN: usize = 11;
const PRIVATE_HNSW_ORAM_ROOT_HASH_B64_LEN: usize = 43;
const PRIVATE_HNSW_ORAM_SIGNATURE_B64_LEN: usize = 86;
const PRIVATE_HNSW_ORAM_CLIENT_ID_MAX_LEN: usize = 256;
const PRIVATE_HNSW_ORAM_SESSION_ID_MAX_LEN: usize = 128;
const PRIVATE_HNSW_ORAM_PATH_BATCH_SIZE_MAX: usize = PRIVATE_ORAM_PATH_BATCH_SIZE_MAX as usize;
const PRIVATE_HNSW_ORAM_TREE_HEIGHT_MAX: usize = PRIVATE_ORAM_JSON_MERKLE_TREE_HEIGHT_MAX as usize;
const PRIVATE_HNSW_ORAM_WRITEBACK_BUCKETS_MAX: usize =
    PRIVATE_HNSW_ORAM_PATH_BATCH_SIZE_MAX * (PRIVATE_HNSW_ORAM_TREE_HEIGHT_MAX + 1);
const PRIVATE_HNSW_ORAM_UPLOAD_BUCKETS_MAX: usize =
    (1usize << PRIVATE_HNSW_ORAM_TREE_HEIGHT_MAX) * 2 - 1;
const PRIVATE_HNSW_ORAM_ENCRYPTION_REQUIRED: &str =
    "collection does not configure private HNSW ORAM encryption";

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswManifestRecord {
    pub manifest: PrivateHnswOramManifest,
    pub signature: PrivateHnswOramSignature,
}

impl Debug for PrivateHnswManifestRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswManifestRecord")
            .field("manifest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub vector_name: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: PrivateHnswOramManifest,
    pub lease_expires_unix: u64,
}

impl Debug for PrivateHnswSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSessionResponse")
            .field("session_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("manifest", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct PrivateHnswOwnerWritebackContext {
    collection_id: String,
    vector_name: String,
    session_id: String,
    store: PrivateHnswOramStore,
    max_ciphertext_bytes: usize,
    signing_key_id: String,
    public_key: Vec<u8>,
    batch: PrivateHnswOramWritebackBatch,
    transition: PrivateHnswOramConsensusWriteback,
    /// Set once the staged commit was finalized, aborted or cancelled; shared by clones.
    settled: Arc<AtomicBool>,
}

impl Drop for PrivateHnswOwnerWritebackContext {
    fn drop(&mut self) {
        // Only the last clone decides, and only when nobody recorded an outcome: an early
        // error return or panic between staging and finalize/abort must not leave the
        // session's writer slot wedged in `commit_in_progress` until restart. `try_lock`
        // keeps a drop under the registry lock from deadlocking.
        if Arc::strong_count(&self.settled) != 1 || self.settled.load(Ordering::Acquire) {
            return;
        }
        let Ok(mut registry) = session_registry().try_lock() else {
            return;
        };
        log::warn!(
            "private HNSW ORAM staged owner writeback was dropped without an outcome; releasing \
             the session commit slot"
        );
        let _ = registry.cancel_commit(&self.collection_id, &self.vector_name, &self.session_id);
    }
}

impl Debug for PrivateHnswOwnerWritebackContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOwnerWritebackContext")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("store", &"[redacted]")
            .field("max_ciphertext_bytes", &"[redacted]")
            .field("signing_key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .field("batch", &self.batch)
            .field("transition", &self.transition)
            .finish()
    }
}

impl PrivateHnswOwnerWritebackContext {
    pub(crate) fn collection_id(&self) -> &str {
        &self.collection_id
    }

    pub(crate) fn batch(&self) -> &PrivateHnswOramWritebackBatch {
        &self.batch
    }

    pub(crate) fn transition(&self) -> &PrivateHnswOramConsensusWriteback {
        &self.transition
    }

    pub(crate) fn prepare_local(&self) -> StorageResult<()> {
        let prepared = self
            .store
            .prepare_durable_writeback_with_signature(
                &self.batch.old,
                &self.batch.new,
                self.batch.bucket_count,
                &self.batch.updated_buckets,
                self.max_ciphertext_bytes,
                &self.batch.commit_signature,
                self.signature_verification(),
            )
            .map_err(private_hnsw_commit_writeback_store_error)?;
        if prepared != self.transition {
            return Err(StorageError::service_error(
                "private HNSW ORAM owner prepare digest does not match staged transition",
            ));
        }
        Ok(())
    }

    pub(crate) fn abort_local(&self) -> StorageResult<()> {
        self.store
            .abort_replica_writeback_with_signature(
                &self.transition,
                self.max_ciphertext_bytes,
                self.signature_verification(),
            )
            .map_err(private_hnsw_commit_writeback_store_error)?;
        self.settled.store(true, Ordering::Release);
        session_registry()
            .lock()
            .map_err(|_| {
                StorageError::service_error("private HNSW ORAM session registry poisoned")
            })?
            .cancel_commit(&self.collection_id, &self.vector_name, &self.session_id)
    }

    pub(crate) fn finalize_local(
        &self,
        now_unix: u64,
        lease_expires_unix: u64,
    ) -> StorageResult<()> {
        let committed = self
            .store
            .commit_replica_writeback_with_signature(
                &self.transition,
                self.max_ciphertext_bytes,
                self.signature_verification(),
            )
            .map_err(private_hnsw_commit_writeback_store_error)?;
        self.settled.store(true, Ordering::Release);
        session_registry()
            .lock()
            .map_err(|_| {
                StorageError::service_error("private HNSW ORAM session registry poisoned")
            })?
            .complete_commit(
                &self.collection_id,
                &self.vector_name,
                &self.session_id,
                &committed,
                now_unix,
                lease_expires_unix,
            )
    }

    pub(crate) fn cancel_staged_session(&self) -> StorageResult<()> {
        self.settled.store(true, Ordering::Release);
        session_registry()
            .lock()
            .map_err(|_| {
                StorageError::service_error("private HNSW ORAM session registry poisoned")
            })?
            .cancel_commit(&self.collection_id, &self.vector_name, &self.session_id)
    }

    fn signature_verification(&self) -> PrivateHnswSignatureVerification<'_> {
        PrivateHnswSignatureVerification {
            expected_key_id: &self.signing_key_id,
            public_key: &self.public_key,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswReadPathsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<PrivateHnswOramBucket>,
    pub proof: PrivateHnswReadProof,
}

impl Debug for PrivateHnswReadPathsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswReadPathsResponse")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswReadProof {
    pub kind: String,
    pub value: String,
}

impl Debug for PrivateHnswReadProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswReadProof")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHnswReadPadding {
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
}

impl Debug for PrivateHnswReadPadding {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswReadPadding")
            .field("requested_paths", &"[redacted]")
            .field("dummy_paths_included", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHnswClientSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateHnswClientSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
struct PrivateHnswSession {
    session_id: String,
    _client_id: String,
    collection_id: String,
    collection_path: std::path::PathBuf,
    vector_name: String,
    index_epoch: u64,
    root_hash: String,
    lease_expires_unix: u64,
    bucket_count: u64,
    tree_height: u32,
    path_batch_size: u32,
    max_bucket_ciphertext_bytes: usize,
    manifest: PrivateHnswOramManifest,
    commit_in_progress: bool,
    owner: PrivateHnswSessionOwner,
    /// Paths read through this session so far; bounds the writeback a commit may carry.
    read_path_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateHnswSessionOwner {
    Standalone,
    PairedMutation,
}

/// Everything a validated path read needs once the session registry lock is released.
struct PrivateHnswReadPlan {
    collection_path: std::path::PathBuf,
    index_epoch: u64,
    root_hash: String,
    bucket_ids: Vec<u64>,
    bucket_count: u64,
    max_bucket_ciphertext_bytes: usize,
    manifest: PrivateHnswOramManifest,
}

/// Everything a validated single-node commit needs once the registry lock is released.
struct PrivateHnswCommitPlan {
    store: PrivateHnswOramStore,
    bucket_count: u64,
    max_bucket_ciphertext_bytes: usize,
    public_key: Vec<u8>,
}

impl Debug for PrivateHnswSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSession")
            .field("session_id", &"[redacted]")
            .field("client_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("collection_path", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .field("bucket_count", &"[redacted]")
            .field("tree_height", &"[redacted]")
            .field("path_batch_size", &"[redacted]")
            .field("max_bucket_ciphertext_bytes", &"[redacted]")
            .field("manifest", &"[redacted]")
            .field("commit_in_progress", &"[redacted]")
            .field("owner", &self.owner)
            .field("read_path_count", &"[redacted]")
            .finish()
    }
}

#[derive(Default)]
struct PrivateHnswSessionRegistry {
    sessions: HashMap<String, PrivateHnswSession>,
    active_writer_by_index: HashMap<(String, String), String>,
    active_snapshot_by_collection: HashMap<String, usize>,
    active_lifecycle_by_collection: HashSet<String>,
    active_upload_by_index: HashSet<(String, String)>,
}

impl PrivateHnswSessionRegistry {
    fn consensus_lease_identity(
        &mut self,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
    ) -> StorageResult<(String, u64)> {
        self.expire(now_unix);
        let session = self.sessions.get(session_id).ok_or_else(|| {
            StorageError::bad_request("private HNSW ORAM session is missing or expired")
        })?;
        if session.vector_name != vector_name {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session does not match collection/vector",
            ));
        }
        if session.owner != PrivateHnswSessionOwner::Standalone {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session belongs to a different protocol",
            ));
        }
        let index_key = private_hnsw_index_key(&session.collection_id, vector_name);
        if !self
            .active_writer_by_index
            .get(&index_key)
            .is_some_and(|active| active == session_id)
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session writer lock is missing or stale",
            ));
        }
        if session.commit_in_progress {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session commit is already in progress",
            ));
        }
        Ok((session.collection_id.clone(), session.lease_expires_unix))
    }

    fn open(
        &mut self,
        mut session: PrivateHnswSession,
        now_unix: u64,
    ) -> StorageResult<PrivateHnswSessionResponse> {
        self.expire(now_unix);
        if self.sessions.len() >= MAX_SESSION_COUNT {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session registry is full",
            ));
        }
        if self
            .active_snapshot_by_collection
            .contains_key(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session open requires no active collection snapshot",
            ));
        }
        if self
            .active_lifecycle_by_collection
            .contains(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session open requires no active collection lifecycle operation",
            ));
        }

        let index_key = private_hnsw_index_key(&session.collection_id, &session.vector_name);
        if self.active_upload_by_index.contains(&index_key) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session open requires no active upload for this index",
            ));
        }
        if self.active_writer_by_index.contains_key(&index_key) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM ConcurrentWriter: an active session already holds this index",
            ));
        }
        while self.sessions.contains_key(&session.session_id) {
            session.session_id = new_session_id();
        }

        let response = session.response();
        self.active_writer_by_index
            .insert(index_key, session.session_id.clone());
        self.sessions.insert(session.session_id.clone(), session);
        Ok(response)
    }

    fn open_after_upload_reservation(
        &mut self,
        session: PrivateHnswSession,
        now_unix: u64,
    ) -> StorageResult<PrivateHnswSessionResponse> {
        let index_key = private_hnsw_index_key(&session.collection_id, &session.vector_name);
        if !self.active_upload_by_index.remove(&index_key) {
            return Err(StorageError::service_error(
                "private HNSW ORAM recovery reservation is missing",
            ));
        }
        self.open(session, now_unix)
    }

    fn close_owned(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        expected_owner: PrivateHnswSessionOwner,
    ) -> bool {
        self.expire(now_unix);
        if self
            .sessions
            .get(session_id)
            .is_some_and(|session| session.commit_in_progress || session.owner != expected_owner)
        {
            return false;
        }
        let removed = self.sessions.remove(session_id);
        if let Some(session) = removed {
            if session.collection_id == collection_id && session.vector_name == vector_name {
                let index_key = private_hnsw_index_key(collection_id, vector_name);
                if self
                    .active_writer_by_index
                    .get(&index_key)
                    .is_some_and(|active| active == session_id)
                {
                    self.active_writer_by_index.remove(&index_key);
                    return true;
                }
            }
            self.sessions.insert(session_id.to_string(), session);
        }
        false
    }

    fn close(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
    ) -> bool {
        self.close_owned(
            collection_id,
            vector_name,
            session_id,
            now_unix,
            PrivateHnswSessionOwner::Standalone,
        )
    }

    fn release_paired(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        self.expire(now_unix);
        let Some(session) = self.sessions.get(session_id) else {
            return Ok(());
        };
        if session.owner != PrivateHnswSessionOwner::PairedMutation
            || session.collection_id != collection_id
            || session.vector_name != vector_name
            || session.commit_in_progress
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM paired session release is invalid",
            ));
        }
        if !self.close_owned(
            collection_id,
            vector_name,
            session_id,
            now_unix,
            PrivateHnswSessionOwner::PairedMutation,
        ) {
            return Err(StorageError::service_error(
                "private HNSW ORAM paired session release failed",
            ));
        }
        Ok(())
    }

    fn has_active_collection(&mut self, collection_id: &str, now_unix: u64) -> bool {
        self.expire(now_unix);
        self.sessions
            .values()
            .any(|session| session.collection_id == collection_id)
    }

    fn has_active_index(&mut self, collection_id: &str, vector_name: &str, now_unix: u64) -> bool {
        self.expire(now_unix);
        self.active_writer_by_index
            .contains_key(&private_hnsw_index_key(collection_id, vector_name))
    }

    fn has_active_upload_collection(&self, collection_id: &str) -> bool {
        self.active_upload_by_index
            .iter()
            .any(|(active_collection_id, _)| active_collection_id == collection_id)
    }

    fn begin_collection_snapshot(
        &mut self,
        collection_id: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        if self.active_lifecycle_by_collection.contains(collection_id) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM collection snapshot requires no active collection lifecycle operation",
            ));
        }
        ensure_no_active_private_hnsw_collection_session_in_registry(
            self,
            collection_id,
            now_unix,
        )?;
        let count = self
            .active_snapshot_by_collection
            .entry(collection_id.to_string())
            .or_insert(0);
        *count = count.checked_add(1).ok_or_else(|| {
            StorageError::service_error("private HNSW ORAM snapshot reference count overflowed")
        })?;
        Ok(())
    }

    fn begin_collection_lifecycle_operation(
        &mut self,
        collection_id: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        if self
            .active_snapshot_by_collection
            .contains_key(collection_id)
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM collection lifecycle operation requires no active collection snapshot",
            ));
        }
        if self.active_lifecycle_by_collection.contains(collection_id) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM collection lifecycle operation requires no active collection lifecycle operation",
            ));
        }
        ensure_no_active_private_hnsw_collection_lifecycle_in_registry(
            self,
            collection_id,
            now_unix,
        )?;
        self.active_lifecycle_by_collection
            .insert(collection_id.to_string());
        Ok(())
    }

    fn release_collection_snapshot(&mut self, collection_id: &str) {
        let Some(count) = self.active_snapshot_by_collection.get_mut(collection_id) else {
            return;
        };
        if *count <= 1 {
            self.active_snapshot_by_collection.remove(collection_id);
        } else {
            *count -= 1;
        }
    }

    fn release_collection_lifecycle_operation(&mut self, collection_id: &str) {
        self.active_lifecycle_by_collection.remove(collection_id);
    }

    fn begin_upload(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        ensure_private_hnsw_write_window_in_registry(self, collection_id, vector_name, now_unix)?;
        self.active_upload_by_index
            .insert(private_hnsw_index_key(collection_id, vector_name));
        Ok(())
    }

    fn release_upload(&mut self, collection_id: &str, vector_name: &str) {
        self.active_upload_by_index
            .remove(&private_hnsw_index_key(collection_id, vector_name));
    }

    fn with_session_mut<T>(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        action: impl FnOnce(&mut PrivateHnswSession) -> StorageResult<T>,
    ) -> StorageResult<T> {
        self.with_session_mut_owned(
            collection_id,
            vector_name,
            session_id,
            now_unix,
            PrivateHnswSessionOwner::Standalone,
            action,
        )
    }

    fn with_session_mut_owned<T>(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        expected_owner: PrivateHnswSessionOwner,
        action: impl FnOnce(&mut PrivateHnswSession) -> StorageResult<T>,
    ) -> StorageResult<T> {
        let session = self.checked_session_mut_owned(
            collection_id,
            vector_name,
            session_id,
            now_unix,
            false,
            expected_owner,
        )?;
        if session.commit_in_progress {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session commit is already in progress",
            ));
        }
        action(session)
    }

    fn begin_commit<T>(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        action: impl FnOnce(&PrivateHnswSession) -> StorageResult<T>,
    ) -> StorageResult<T> {
        let session =
            self.checked_session_mut(collection_id, vector_name, session_id, now_unix, false)?;
        if session.commit_in_progress {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session commit is already in progress",
            ));
        }
        let result = action(session)?;
        session.commit_in_progress = true;
        Ok(result)
    }

    /// Records a finished commit. `now_unix` drives the expiry sweep and `lease_expires_unix`
    /// is the renewed lease of this session only: sweeping with the (future) lease instead
    /// used to expire every other idle session on the node whenever one client committed.
    fn complete_commit(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        committed: &PrivateHnswOramEpochState,
        now_unix: u64,
        lease_expires_unix: u64,
    ) -> StorageResult<()> {
        let session =
            self.checked_session_mut(collection_id, vector_name, session_id, now_unix, true)?;
        if !session.commit_in_progress {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session has no commit in progress",
            ));
        }
        session.index_epoch = committed.index_epoch;
        session.root_hash = committed.root_hash.clone();
        session.lease_expires_unix = lease_expires_unix;
        session.commit_in_progress = false;
        // The committed reads are spent: the next write-back is bounded by the paths read at
        // the new epoch, not by everything read since the session opened.
        session.read_path_count = 0;
        Ok(())
    }

    fn cancel_commit(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
    ) -> StorageResult<()> {
        let session = self.checked_session_mut(collection_id, vector_name, session_id, 0, true)?;
        if !session.commit_in_progress {
            return Ok(());
        }
        session.commit_in_progress = false;
        Ok(())
    }

    fn recover_commit(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        committed: &PrivateHnswOramEpochState,
        abort: bool,
    ) -> StorageResult<bool> {
        let index_key = private_hnsw_index_key(collection_id, vector_name);
        let Some(session_id) = self.active_writer_by_index.get(&index_key).cloned() else {
            return Ok(false);
        };
        let session = self.sessions.get_mut(&session_id).ok_or_else(|| {
            StorageError::service_error(
                "private HNSW ORAM recovery found an inconsistent session writer lock",
            )
        })?;
        if session.collection_id != collection_id || session.vector_name != vector_name {
            return Err(StorageError::service_error(
                "private HNSW ORAM recovery session context is inconsistent",
            ));
        }
        if !session.commit_in_progress {
            return Err(StorageError::service_error(
                "private HNSW ORAM recovery session has no commit in progress",
            ));
        }
        if !abort {
            session.index_epoch = committed.index_epoch;
            session.root_hash = committed.root_hash.clone();
            session.read_path_count = 0;
        }
        session.commit_in_progress = false;
        Ok(true)
    }

    fn has_active_writer(&self, collection_id: &str, vector_name: &str) -> StorageResult<bool> {
        let index_key = private_hnsw_index_key(collection_id, vector_name);
        let Some(session_id) = self.active_writer_by_index.get(&index_key) else {
            return Ok(false);
        };
        let session = self.sessions.get(session_id).ok_or_else(|| {
            StorageError::service_error(
                "private HNSW ORAM recovery found an inconsistent session writer lock",
            )
        })?;
        if session.collection_id != collection_id || session.vector_name != vector_name {
            return Err(StorageError::service_error(
                "private HNSW ORAM recovery session context is inconsistent",
            ));
        }
        Ok(true)
    }

    fn checked_session_mut(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        allow_expired_commit: bool,
    ) -> StorageResult<&mut PrivateHnswSession> {
        self.checked_session_mut_owned(
            collection_id,
            vector_name,
            session_id,
            now_unix,
            allow_expired_commit,
            PrivateHnswSessionOwner::Standalone,
        )
    }

    fn checked_session_mut_owned(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        allow_expired_commit: bool,
        expected_owner: PrivateHnswSessionOwner,
    ) -> StorageResult<&mut PrivateHnswSession> {
        self.expire(now_unix);
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            StorageError::bad_request("private HNSW ORAM session is missing or expired")
        })?;
        if session.collection_id != collection_id || session.vector_name != vector_name {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session does not match collection/vector",
            ));
        }
        if session.owner != expected_owner {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session belongs to a different protocol",
            ));
        }
        let index_key = private_hnsw_index_key(collection_id, vector_name);
        if !self
            .active_writer_by_index
            .get(&index_key)
            .is_some_and(|active| active == session_id)
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session writer lock is missing or stale",
            ));
        }
        if !allow_expired_commit && session.lease_expires_unix <= now_unix {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session lease expired",
            ));
        }
        Ok(session)
    }

    fn expire(&mut self, now_unix: u64) {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (session.lease_expires_unix <= now_unix && !session.commit_in_progress)
                    .then_some(session_id.clone())
            })
            .collect::<Vec<_>>();
        for session_id in expired {
            if let Some(session) = self.sessions.remove(&session_id) {
                let index_key =
                    private_hnsw_index_key(&session.collection_id, &session.vector_name);
                if self
                    .active_writer_by_index
                    .get(&index_key)
                    .is_some_and(|active| active == &session_id)
                {
                    self.active_writer_by_index.remove(&index_key);
                }
            }
        }
    }
}

pub(crate) fn private_hnsw_session_consensus_lease_identity(
    vector_name: &str,
    session_id: &str,
    now_unix: u64,
) -> StorageResult<(String, u64)> {
    validate_private_hnsw_session_id_shape(session_id)?;
    session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .consensus_lease_identity(vector_name, session_id, now_unix)
}

pub(crate) fn recover_private_hnsw_session_writeback(
    collection_id: &str,
    vector_name: &str,
    committed: &PrivateHnswOramEpochState,
    abort: bool,
) -> StorageResult<bool> {
    session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .recover_commit(collection_id, vector_name, committed, abort)
}

pub(crate) fn private_hnsw_has_active_session(
    collection_id: &str,
    vector_name: &str,
) -> StorageResult<bool> {
    session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .has_active_writer(collection_id, vector_name)
}

pub(crate) fn release_private_hnsw_session_for_paired_mutation(
    collection_id: &str,
    vector_name: &str,
    session_id: &str,
) -> StorageResult<()> {
    validate_private_hnsw_session_id_shape(session_id)?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.release_paired(collection_id, vector_name, session_id, now_unix)
}

impl PrivateHnswSession {
    fn response(&self) -> PrivateHnswSessionResponse {
        PrivateHnswSessionResponse {
            session_id: self.session_id.clone(),
            collection_id: self.collection_id.clone(),
            vector_name: self.vector_name.clone(),
            index_epoch: self.index_epoch,
            root_hash: self.root_hash.clone(),
            manifest: self.manifest.clone(),
            lease_expires_unix: self.lease_expires_unix,
        }
    }
}

pub(crate) struct ResolvedPrivateHnswContext {
    collection_path: std::path::PathBuf,
    collection_crypto_id: String,
    vector_name: String,
    expected_key_id: String,
    expected_rk_id: String,
    min_rk_epoch: u64,
    max_rk_epoch: u64,
    expected_dim: u32,
    expected_distance: DistanceKind,
    expected_result_privacy: ResultPrivacyMode,
    private_result_oram_binding_configured: bool,
    expected_hnsw: PrivateHnswParams,
    expected_oram: OramParams,
    expected_fixed_budget: FixedBudgetParams,
    signature_public_keys: HashMap<String, String>,
    public_key: Vec<u8>,
}

fn session_registry() -> &'static Mutex<PrivateHnswSessionRegistry> {
    static REGISTRY: OnceLock<Mutex<PrivateHnswSessionRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(PrivateHnswSessionRegistry::default()))
}

enum PrivateHnswCollectionGuardKind {
    Snapshot,
    Lifecycle,
}

pub(crate) struct PrivateHnswCollectionSnapshotGuard {
    collection_id: String,
    kind: PrivateHnswCollectionGuardKind,
}

struct PrivateHnswUploadGuard {
    collection_id: String,
    vector_name: String,
}

impl Drop for PrivateHnswCollectionSnapshotGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = session_registry().lock() {
            match self.kind {
                PrivateHnswCollectionGuardKind::Snapshot => {
                    registry.release_collection_snapshot(&self.collection_id)
                }
                PrivateHnswCollectionGuardKind::Lifecycle => {
                    registry.release_collection_lifecycle_operation(&self.collection_id)
                }
            }
        }
    }
}

impl Drop for PrivateHnswUploadGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.release_upload(&self.collection_id, &self.vector_name);
        }
    }
}

impl ResolvedPrivateHnswContext {
    pub(crate) fn collection_path(&self) -> &std::path::Path {
        &self.collection_path
    }

    pub(crate) fn collection_crypto_id(&self) -> &str {
        &self.collection_crypto_id
    }

    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub(crate) fn manifest_context<'a>(
        &'a self,
        signature_key_id: &'a str,
    ) -> PrivateHnswManifestValidationContext<'a> {
        PrivateHnswManifestValidationContext {
            expected_collection_id: &self.collection_crypto_id,
            expected_vector_name: &self.vector_name,
            expected_key_id: &self.expected_key_id,
            expected_rk_id: &self.expected_rk_id,
            min_rk_epoch: self.min_rk_epoch,
            max_rk_epoch: self.max_rk_epoch,
            expected_dim: self.expected_dim,
            expected_distance: self.expected_distance,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: signature_key_id,
                public_key: &self.public_key,
            },
        }
    }

    pub(crate) fn validate_manifest_runtime_policy(
        &self,
        manifest: &PrivateHnswOramManifest,
    ) -> StorageResult<()> {
        self.validate_manifest_runtime_context(manifest)?;
        Ok(())
    }

    fn validate_manifest_runtime_context(
        &self,
        manifest: &PrivateHnswOramManifest,
    ) -> StorageResult<()> {
        if manifest.collection_id != self.collection_crypto_id {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest collection_id does not match runtime context",
            ));
        }
        if manifest.vector_name != self.vector_name {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest vector_name does not match runtime context",
            ));
        }
        if manifest.key_id != self.expected_key_id {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest key_id does not match runtime instance",
            ));
        }
        if manifest.rk_id != self.expected_rk_id {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest rk_id does not match runtime instance",
            ));
        }
        if manifest.rk_epoch < self.min_rk_epoch || manifest.rk_epoch > self.max_rk_epoch {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest rk_epoch does not match runtime instance",
            ));
        }
        if manifest.dim != self.expected_dim {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest dim does not match runtime vector size",
            ));
        }
        if manifest.distance != self.expected_distance {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest distance does not match runtime vector distance",
            ));
        }
        if manifest.result_privacy != self.expected_result_privacy {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest result_privacy does not match runtime instance",
            ));
        }
        if manifest.result_privacy == ResultPrivacyMode::PrivatePayloadOramRequired
            && !self.private_result_oram_binding_configured
        {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM result_privacy=private_payload_oram_required requires a {PRIVATE_RESULT_ORAM_BINDING} payload rule backed by {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}"
            )));
        }
        if manifest.hnsw != self.expected_hnsw {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest hnsw does not match runtime instance",
            ));
        }
        if manifest.oram != self.expected_oram {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest oram does not match runtime instance",
            ));
        }
        if manifest.fixed_budget != self.expected_fixed_budget {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest fixed_budget does not match runtime instance",
            ));
        }
        Ok(())
    }

    fn signature_public_key(&self, signature_key_id: &str) -> StorageResult<Vec<u8>> {
        let public_key_b64 = self
            .signature_public_keys
            .get(signature_key_id)
            .ok_or_else(|| {
                StorageError::bad_request("private HNSW ORAM signature key id is not configured")
            })?;
        decode_signature_public_key(public_key_b64)
    }
}

pub async fn do_upload_private_hnsw_manifest(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    manifest: PrivateHnswOramManifest,
    signature: PrivateHnswOramSignature,
) -> StorageResult<PrivateHnswOramEpochState> {
    do_upload_private_hnsw_manifest_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        manifest,
        signature,
        false,
    )
    .await
}

pub(crate) async fn do_stage_private_hnsw_manifest_for_initial_replication(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    manifest: PrivateHnswOramManifest,
    signature: PrivateHnswOramSignature,
) -> StorageResult<PrivateHnswOramEpochState> {
    do_upload_private_hnsw_manifest_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        manifest,
        signature,
        true,
    )
    .await
}

async fn do_upload_private_hnsw_manifest_inner(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    manifest: PrivateHnswOramManifest,
    signature: PrivateHnswOramSignature,
    coordinated_initial_replication: bool,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let resolved = resolve_private_hnsw_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        &signature.key_id,
        "private_hnsw_manifest_upload",
        AccessRequirements::new().write(),
    )
    .await?;
    validate_private_hnsw_oram_upload_epoch_mode(
        toc.is_distributed(),
        coordinated_initial_replication,
    )?;
    let epoch = validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let _upload_guard =
        begin_private_hnsw_upload_write_window(&resolved.collection_crypto_id, vector_name)?;

    let epoch_state = PrivateHnswOramEpochState {
        index_epoch: epoch.epoch,
        root_hash: manifest.root_hash.clone(),
    };
    let store = PrivateHnswOramStore::new(resolved.collection_path, vector_name)?;
    store
        .write_manifest_with_initial_epoch_if_absent_or_matching(
            &manifest,
            &signature,
            &epoch_state,
        )
        .map_err(private_hnsw_manifest_store_error)?;
    Ok(epoch_state)
}

pub(crate) fn begin_private_hnsw_collection_snapshot(
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> StorageResult<Option<PrivateHnswCollectionSnapshotGuard>> {
    if !collection_uses_private_hnsw_oram(config) {
        return Ok(None);
    }

    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.begin_collection_snapshot(&collection_crypto_id, now_unix)?;
    Ok(Some(PrivateHnswCollectionSnapshotGuard {
        collection_id: collection_crypto_id,
        kind: PrivateHnswCollectionGuardKind::Snapshot,
    }))
}

pub(crate) fn begin_private_hnsw_collection_lifecycle(
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> StorageResult<Option<PrivateHnswCollectionSnapshotGuard>> {
    if !collection_uses_private_hnsw_oram(config) {
        return Ok(None);
    }

    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.begin_collection_lifecycle_operation(&collection_crypto_id, now_unix)?;
    Ok(Some(PrivateHnswCollectionSnapshotGuard {
        collection_id: collection_crypto_id,
        kind: PrivateHnswCollectionGuardKind::Lifecycle,
    }))
}

pub async fn do_get_private_hnsw_manifest(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
) -> StorageResult<PrivateHnswManifestRecord> {
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "private_hnsw_manifest_read",
    )?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_HNSW_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    };
    validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    Ok(PrivateHnswManifestRecord {
        manifest,
        signature,
    })
}

pub async fn do_export_private_hnsw_initial_replication_bundle(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    max_bundle_bytes: usize,
) -> StorageResult<qdrant_sec::PrivateHnswOramUploadBundle> {
    let record =
        do_get_private_hnsw_manifest(toc, auth, settings, collection_name, vector_name).await?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_initial_replication_export",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let _guard =
        begin_private_hnsw_upload_write_window(&record.manifest.collection_id, vector_name)?;
    let bundle = PrivateHnswOramStore::new(collection.path(), vector_name)?
        .read_initial_upload_bundle(
            max_bucket_ciphertext_bytes(&record.manifest)?,
            max_bundle_bytes,
        )
        .map_err(private_hnsw_upload_store_error)?;
    if bundle.manifest != record.manifest || bundle.manifest_signature != record.signature {
        return Err(StorageError::bad_request(
            "private HNSW ORAM initial replication bundle does not match validated manifest",
        ));
    }
    Ok(bundle)
}

pub async fn do_export_private_hnsw_live_replication_bundle(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    max_bundle_bytes: usize,
) -> StorageResult<PrivateHnswOramLiveReplicationBundle> {
    let record =
        do_get_private_hnsw_manifest(toc, auth, settings, collection_name, vector_name).await?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_live_replication_export",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let _guard =
        begin_private_hnsw_upload_write_window(&record.manifest.collection_id, vector_name)?;
    let bundle = PrivateHnswOramStore::new(collection.path(), vector_name)?
        .read_live_replication_bundle(
            max_bucket_ciphertext_bytes(&record.manifest)?,
            max_bundle_bytes,
        )
        .map_err(private_hnsw_upload_store_error)?;
    if bundle.manifest != record.manifest || bundle.manifest_signature != record.signature {
        return Err(StorageError::bad_request(
            "private HNSW ORAM live replication bundle does not match validated manifest",
        ));
    }
    Ok(bundle)
}

pub async fn do_upload_private_hnsw_buckets(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<PrivateHnswOramBucket>,
) -> StorageResult<PrivateHnswOramEpochState> {
    do_upload_private_hnsw_buckets_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        index_epoch,
        root_hash,
        buckets,
        false,
    )
    .await
}

pub(crate) async fn do_stage_private_hnsw_buckets_for_initial_replication(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<PrivateHnswOramBucket>,
) -> StorageResult<PrivateHnswOramEpochState> {
    do_upload_private_hnsw_buckets_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        index_epoch,
        root_hash,
        buckets,
        true,
    )
    .await
}

async fn do_upload_private_hnsw_buckets_inner(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<PrivateHnswOramBucket>,
    coordinated_initial_replication: bool,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_root_hash_string(&root_hash, "root_hash")?;
    validate_private_hnsw_upload_bucket_request_shape(&buckets)?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_buckets_upload",
    )?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    validate_private_hnsw_oram_upload_epoch_mode(
        toc.is_distributed(),
        coordinated_initial_replication,
    )?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_HNSW_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    };
    validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let _upload_guard =
        begin_private_hnsw_upload_write_window(&resolved.collection_crypto_id, vector_name)?;
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current_epoch.index_epoch != index_epoch || current_epoch.root_hash != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload epoch/root does not match current manifest epoch",
        ));
    }
    let max_ciphertext_bytes = max_bucket_ciphertext_bytes(&manifest)?;
    for bucket in &buckets {
        store
            .validate_bucket_for_write(
                bucket,
                index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .map_err(private_hnsw_upload_store_error)?;
        validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
    }
    let _ =
        validate_initial_private_hnsw_upload_bundle(&manifest, index_epoch, &root_hash, &buckets)?;
    let uploaded = PrivateHnswOramEpochState {
        index_epoch,
        root_hash,
    };
    store
        .write_initial_bucket_set(&uploaded, &buckets, max_ciphertext_bytes)
        .map_err(private_hnsw_upload_store_error)?;
    Ok(uploaded)
}

pub async fn do_open_private_hnsw_session(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
    result_privacy: ResultPrivacyMode,
) -> StorageResult<PrivateHnswSessionResponse> {
    do_open_private_hnsw_session_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        client_id,
        desired_epoch,
        fixed_budget,
        result_privacy,
        false,
        PrivateHnswSessionOwner::Standalone,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_open_private_hnsw_session_coordinated(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
    result_privacy: ResultPrivacyMode,
) -> StorageResult<PrivateHnswSessionResponse> {
    do_open_private_hnsw_session_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        client_id,
        desired_epoch,
        fixed_budget,
        result_privacy,
        true,
        PrivateHnswSessionOwner::Standalone,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_open_private_hnsw_session_for_paired_mutation(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
    result_privacy: ResultPrivacyMode,
) -> StorageResult<PrivateHnswSessionResponse> {
    do_open_private_hnsw_session_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        client_id,
        desired_epoch,
        fixed_budget,
        result_privacy,
        true,
        PrivateHnswSessionOwner::PairedMutation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn do_open_private_hnsw_session_inner(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
    result_privacy: ResultPrivacyMode,
    coordinated_distributed: bool,
    owner: PrivateHnswSessionOwner,
) -> StorageResult<PrivateHnswSessionResponse> {
    validate_private_hnsw_client_id_shape(&client_id)?;
    if is_strict(settings) && !fixed_budget {
        return Err(StorageError::bad_request(
            "private HNSW ORAM strict mode requires fixed_budget=true",
        ));
    }

    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_session_open",
    )?;
    if !coordinated_distributed {
        validate_private_hnsw_oram_single_node_epoch_mode(toc.is_distributed())?;
    }
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    ensure_no_private_oram_shard_transfer(&collection).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_HNSW_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    };
    let manifest_epoch = validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let max_bucket_ciphertext_bytes = max_bucket_ciphertext_bytes(&manifest)?;
    let pending_writeback = store
        .pending_writeback_exists()
        .map_err(private_hnsw_commit_writeback_store_error)?;
    if coordinated_distributed && pending_writeback {
        return Err(StorageError::service_error(
            "private HNSW ORAM distributed session open requires coordinated recovery",
        ));
    }
    let recovery_guard = pending_writeback
        .then(|| begin_private_hnsw_upload_write_window(&collection_crypto_id, vector_name))
        .transpose()?;
    if recovery_guard.is_some() {
        store
            .recover_pending_writeback_with_signature(
                max_bucket_ciphertext_bytes,
                PrivateHnswSignatureVerification {
                    expected_key_id: &signature.key_id,
                    public_key: &resolved.public_key,
                },
            )
            .map_err(private_hnsw_commit_writeback_store_error)?;
    }
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current_epoch.index_epoch < manifest_epoch.epoch
        || (current_epoch.index_epoch == manifest_epoch.epoch
            && current_epoch.root_hash != manifest.root_hash)
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM current epoch is inconsistent with manifest epoch",
        ));
    }
    if desired_epoch != current_epoch.index_epoch {
        return Err(StorageError::bad_request(
            "private HNSW ORAM requested epoch is not current epoch",
        ));
    }
    if manifest.result_privacy != result_privacy {
        return Err(StorageError::bad_request(
            "private HNSW ORAM requested result_privacy does not match manifest",
        ));
    }
    if !manifest.fixed_budget.enabled || !fixed_budget {
        return Err(StorageError::bad_request(
            "private HNSW ORAM sessions require fixed_budget=true",
        ));
    }
    let expected_open_epoch = current_epoch.clone();
    let expected_open_manifest = manifest.clone();
    let expected_open_signature = signature.clone();

    let now_unix = current_unix_secs()?;
    let session = PrivateHnswSession {
        session_id: new_session_id(),
        _client_id: client_id,
        collection_id: collection_crypto_id.clone(),
        collection_path: collection.path().to_path_buf(),
        vector_name: vector_name.to_string(),
        index_epoch: current_epoch.index_epoch,
        root_hash: current_epoch.root_hash.clone(),
        lease_expires_unix: session_lease_expires_unix(now_unix)?,
        bucket_count: manifest.bucket_count,
        tree_height: manifest.oram.tree_height,
        path_batch_size: manifest.oram.path_batch_size,
        max_bucket_ciphertext_bytes,
        manifest,
        commit_in_progress: false,
        owner,
        read_path_count: 0,
    };
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    let response = if recovery_guard.is_some() {
        registry.open_after_upload_reservation(session, now_unix)?
    } else {
        registry.open(session, now_unix)?
    };
    drop(registry);
    drop(recovery_guard);
    if let Err(err) = ensure_private_hnsw_session_open_storage_matches(
        &store,
        &expected_open_epoch,
        &expected_open_manifest,
        &expected_open_signature,
    ) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.close_owned(
                &collection_crypto_id,
                vector_name,
                &response.session_id,
                now_unix,
                owner,
            );
        }
        return Err(err);
    }
    Ok(response)
}

fn validate_private_hnsw_read_fixed_path_budget(
    padding: PrivateHnswReadPadding,
    path_count: usize,
    session_path_batch_size: u32,
) -> StorageResult<()> {
    let session_path_batch_size: usize = session_path_batch_size.try_into().map_err(|_| {
        StorageError::bad_request("private HNSW ORAM session path budget exceeds platform capacity")
    })?;
    if padding.requested_paths != session_path_batch_size as u32
        || path_count != session_path_batch_size
        || !padding.dummy_paths_included
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM read_paths request must match fixed path budget",
        ));
    }
    Ok(())
}

pub async fn do_read_private_hnsw_paths(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: &str,
    paths: Vec<String>,
    padding: PrivateHnswReadPadding,
    client_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    do_read_private_hnsw_paths_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        session_id,
        index_epoch,
        root_hash,
        paths,
        padding,
        client_signature,
        false,
        PrivateHnswSessionOwner::Standalone,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_read_private_hnsw_paths_coordinated(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: &str,
    paths: Vec<String>,
    padding: PrivateHnswReadPadding,
    client_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    do_read_private_hnsw_paths_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        session_id,
        index_epoch,
        root_hash,
        paths,
        padding,
        client_signature,
        true,
        PrivateHnswSessionOwner::Standalone,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_read_private_hnsw_paths_for_paired_mutation(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: &str,
    paths: Vec<String>,
    padding: PrivateHnswReadPadding,
    client_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    do_read_private_hnsw_paths_inner(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        session_id,
        index_epoch,
        root_hash,
        paths,
        padding,
        client_signature,
        true,
        PrivateHnswSessionOwner::PairedMutation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn do_read_private_hnsw_paths_inner(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: &str,
    paths: Vec<String>,
    padding: PrivateHnswReadPadding,
    client_signature: PrivateHnswClientSignature,
    coordinated_distributed: bool,
    expected_owner: PrivateHnswSessionOwner,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    validate_client_signature_shape(&client_signature)?;
    validate_private_hnsw_session_id_shape(session_id)?;
    validate_root_hash_string(root_hash, "root_hash")?;
    validate_private_hnsw_read_path_label_request_shape(&paths)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_read_paths",
        AccessRequirements::new(),
    )
    .await?;
    if !coordinated_distributed {
        validate_private_hnsw_oram_single_node_epoch_mode(toc.is_distributed())?;
    }
    let now_unix = current_unix_secs()?;
    // The registry guard lives in its own block so the future stays `Send`: the store I/O
    // below runs on a blocking thread while no lock is held.
    let plan = {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private HNSW ORAM session registry poisoned")
        })?;
        registry.with_session_mut_owned(
            &request_context.collection_crypto_id,
            vector_name,
            session_id,
            now_unix,
            expected_owner,
            |session| {
                request_context.validate_manifest_runtime_context(&session.manifest)?;
                if session.index_epoch != index_epoch || session.root_hash != root_hash {
                    return Err(StorageError::bad_request(
                        "private HNSW ORAM session epoch/root mismatch",
                    ));
                }
                validate_private_hnsw_read_fixed_path_budget(
                    padding,
                    paths.len(),
                    session.path_batch_size,
                )?;
                validate_session_signature_owner_key(session, &client_signature.key_id)?;
                let public_key = request_context.signature_public_key(&client_signature.key_id)?;
                let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
                validate_private_hnsw_oram_read_paths_signature(
                    PrivateHnswOramReadPathsSignatureInput {
                        collection_id: &session.collection_id,
                        vector_name,
                        key_id: &session.manifest.key_id,
                        rk_id: &session.manifest.rk_id,
                        rk_epoch: session.manifest.rk_epoch,
                        index_epoch,
                        root_hash,
                        paths: &path_refs,
                        requested_paths: padding.requested_paths,
                        dummy_paths_included: padding.dummy_paths_included,
                        signature_alg: &client_signature.alg,
                        signature_key_id: &client_signature.key_id,
                    },
                    &client_signature.sig,
                    PrivateHnswSignatureVerification {
                        expected_key_id: &client_signature.key_id,
                        public_key: &public_key,
                    },
                )
                .map_err(private_hnsw_error)?;
                validate_private_hnsw_read_path_labels(&paths, session.tree_height)?;
                let bucket_ids =
                    bucket_ids_for_path_batch(&paths, session.tree_height, session.bucket_count)?;
                // Every path served through this session extends the writeback the client may commit.
                session.read_path_count = session
                    .read_path_count
                    .saturating_add(u64::try_from(paths.len()).unwrap_or(u64::MAX));
                Ok(PrivateHnswReadPlan {
                    collection_path: session.collection_path.clone(),
                    index_epoch: session.index_epoch,
                    root_hash: session.root_hash.clone(),
                    bucket_ids,
                    bucket_count: session.bucket_count,
                    max_bucket_ciphertext_bytes: session.max_bucket_ciphertext_bytes,
                    manifest: session.manifest.clone(),
                })
            },
        )?
    };
    // Store I/O runs off the registry mutex and off the async worker thread: one tenant's slow
    // path reads no longer stall every other private ORAM request on the node.
    let vector_name = vector_name.to_string();
    let (plan, buckets, proof) = tokio::task::spawn_blocking(move || -> StorageResult<_> {
        let store = PrivateHnswOramStore::new(&plan.collection_path, &vector_name)?;
        ensure_private_hnsw_active_session_current_epoch(
            &store,
            plan.index_epoch,
            &plan.root_hash,
        )?;
        let (buckets, proof) = store
            .read_bucket_batch_with_proof(
                &plan.bucket_ids,
                plan.index_epoch,
                &plan.root_hash,
                plan.bucket_count,
                plan.max_bucket_ciphertext_bytes,
            )
            .map_err(private_hnsw_read_batch_store_error)?;
        ensure_private_hnsw_read_proof_matches_buckets(&proof, &buckets)?;
        validate_private_hnsw_read_bucket_ciphertexts_fixed_size(&plan.manifest, &buckets)?;
        Ok((plan, buckets, proof))
    })
    .await
    .map_err(|_| StorageError::service_error("private HNSW ORAM read task failed"))??;
    let proof_value = serde_json::to_string(&proof).map_err(|_| {
        StorageError::service_error("failed to serialize private HNSW ORAM Merkle proof")
    })?;
    Ok(PrivateHnswReadPathsResponse {
        index_epoch: plan.index_epoch,
        root_hash: plan.root_hash,
        buckets,
        proof: PrivateHnswReadProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            value: proof_value,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_stage_private_hnsw_owner_writeback(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    updated_buckets: Vec<PrivateHnswOramBucket>,
    commit_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswOwnerWritebackContext> {
    validate_client_signature_shape(&commit_signature)?;
    validate_private_hnsw_session_id_shape(session_id)?;
    validate_root_hash_string(&old_root_hash, "old_root_hash")?;
    validate_root_hash_string(&new_root_hash, "new_root_hash")?;
    validate_private_hnsw_commit_request_shape(&updated_buckets)?;
    if !toc.is_distributed() {
        return Err(StorageError::service_error(
            "private HNSW ORAM owner writeback staging requires distributed mode",
        ));
    }
    let transfer_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_oram_distributed_commit",
    )?;
    let transfer_collection = toc.get_collection(&transfer_pass).await?;
    ensure_no_private_oram_shard_transfer(&transfer_collection).await?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_distributed_commit",
        AccessRequirements::new().write(),
    )
    .await?;
    let now_unix = current_unix_secs()?;
    session_registry()
        .lock()
        .map_err(|_| {
            StorageError::service_error("private HNSW ORAM session registry poisoned")
        })?
        .begin_commit(
            &request_context.collection_crypto_id,
            vector_name,
            session_id,
            now_unix,
            |session| {
                request_context.validate_manifest_runtime_context(&session.manifest)?;
                if session.index_epoch != old_epoch || session.root_hash != old_root_hash {
                    return Err(StorageError::bad_request(
                        "private HNSW ORAM commit old epoch/root does not match active session",
                    ));
                }
                if Some(new_epoch) != old_epoch.checked_add(1) {
                    return Err(StorageError::bad_request(
                        "private HNSW ORAM commit new_epoch must be exactly old_epoch + 1",
                    ));
                }
                let max_updated_buckets = max_updated_bucket_count(session)?;
                if updated_buckets.is_empty() || updated_buckets.len() > max_updated_buckets {
                    return Err(StorageError::bad_request(
                        "private HNSW ORAM commit updated_buckets must contain at least one bucket and fit the fixed writeback budget",
                    ));
                }
                let updated_bucket_refs = updated_buckets
                    .iter()
                    .map(|bucket| PrivateHnswOramCommitBucketRef {
                        bucket_id: bucket.bucket_id,
                        ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
                    })
                    .collect::<Vec<_>>();
                validate_session_signature_owner_key(session, &commit_signature.key_id)?;
                let public_key = request_context.signature_public_key(&commit_signature.key_id)?;
                let signature_input = PrivateHnswOramCommitSignatureInput {
                    collection_id: &session.collection_id,
                    vector_name,
                    key_id: &session.manifest.key_id,
                    rk_id: &session.manifest.rk_id,
                    rk_epoch: session.manifest.rk_epoch,
                    old_epoch,
                    new_epoch,
                    old_root_hash: &old_root_hash,
                    new_root_hash: &new_root_hash,
                    updated_buckets: &updated_bucket_refs,
                    signature_alg: &commit_signature.alg,
                    signature_key_id: &commit_signature.key_id,
                };
                validate_private_hnsw_oram_commit_signature(
                    signature_input,
                    &commit_signature.sig,
                    PrivateHnswSignatureVerification {
                        expected_key_id: &commit_signature.key_id,
                        public_key: &public_key,
                    },
                )
                .map_err(private_hnsw_error)?;
                for bucket in &updated_buckets {
                    validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
                        &session.manifest,
                        std::slice::from_ref(bucket),
                    )?;
                }

                let store = PrivateHnswOramStore::new(&session.collection_path, vector_name)?;
                ensure_private_hnsw_active_session_current_epoch(
                    &store,
                    old_epoch,
                    &old_root_hash,
                )?;
                let old = PrivateHnswOramEpochState {
                    index_epoch: old_epoch,
                    root_hash: old_root_hash.clone(),
                };
                let new = PrivateHnswOramEpochState {
                    index_epoch: new_epoch,
                    root_hash: new_root_hash.clone(),
                };
                let store_commit_signature = PrivateHnswOramSignature {
                    alg: commit_signature.alg.clone(),
                    key_id: commit_signature.key_id.clone(),
                    sig: commit_signature.sig.clone(),
                };
                let transition = PrivateHnswOramConsensusWriteback {
                    old: old.clone(),
                    new: new.clone(),
                    writeback_digest: private_hnsw_oram_writeback_digest(signature_input)
                        .map_err(private_hnsw_error)?,
                };
                let batch = PrivateHnswOramWritebackBatch {
                    version: 1,
                    old,
                    new,
                    bucket_count: session.bucket_count,
                    updated_buckets: updated_buckets.clone(),
                    commit_signature: store_commit_signature,
                };
                Ok(PrivateHnswOwnerWritebackContext {
                    collection_id: session.collection_id.clone(),
                    vector_name: vector_name.to_string(),
                    session_id: session_id.to_string(),
                    store,
                    max_ciphertext_bytes: session.max_bucket_ciphertext_bytes,
                    signing_key_id: commit_signature.key_id.clone(),
                    public_key,
                    batch,
                    transition,
                    settled: Arc::new(AtomicBool::new(false)),
                })
            },
        )
}

fn private_oram_shard_transfer_active(transfers: &HashSet<ShardTransfer>) -> bool {
    transfers
        .iter()
        .any(|transfer| transfer.private_oram_preinstalled)
}

async fn ensure_no_private_oram_shard_transfer(
    collection: &collection::collection::Collection,
) -> StorageResult<()> {
    if private_oram_shard_transfer_active(&collection.state().await.transfers) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM sessions are unavailable while shard transfer is active",
        ));
    }
    Ok(())
}

pub async fn do_commit_private_hnsw_paths(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    updated_buckets: Vec<PrivateHnswOramBucket>,
    commit_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_client_signature_shape(&commit_signature)?;
    validate_private_hnsw_session_id_shape(session_id)?;
    validate_root_hash_string(&old_root_hash, "old_root_hash")?;
    validate_root_hash_string(&new_root_hash, "new_root_hash")?;
    validate_private_hnsw_commit_request_shape(&updated_buckets)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_commit",
        AccessRequirements::new().write(),
    )
    .await?;
    validate_private_hnsw_oram_single_node_epoch_mode(toc.is_distributed())?;
    let now_unix = current_unix_secs()?;
    // The registry guard lives in its own block so the future stays `Send`: the store I/O
    // below runs on a blocking thread while no lock is held.
    let plan = {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private HNSW ORAM session registry poisoned")
        })?;
        registry.begin_commit(
        &request_context.collection_crypto_id,
        vector_name,
        session_id,
        now_unix,
        |session| {
        request_context.validate_manifest_runtime_context(&session.manifest)?;
        if session.index_epoch != old_epoch || session.root_hash != old_root_hash {
            return Err(StorageError::bad_request(
                "private HNSW ORAM commit old epoch/root does not match active session",
            ));
        }
        if Some(new_epoch) != old_epoch.checked_add(1) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM commit new_epoch must be exactly old_epoch + 1",
            ));
        }
        let max_updated_buckets = max_updated_bucket_count(session)?;
        if updated_buckets.is_empty() || updated_buckets.len() > max_updated_buckets {
            return Err(StorageError::bad_request(
                "private HNSW ORAM commit updated_buckets must contain at least one bucket and fit the fixed writeback budget",
            ));
        }
        let updated_bucket_refs = updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        validate_session_signature_owner_key(session, &commit_signature.key_id)?;
        let public_key = request_context.signature_public_key(&commit_signature.key_id)?;
        validate_private_hnsw_oram_commit_signature(
            PrivateHnswOramCommitSignatureInput {
                collection_id: &session.collection_id,
                vector_name,
                key_id: &session.manifest.key_id,
                rk_id: &session.manifest.rk_id,
                rk_epoch: session.manifest.rk_epoch,
                old_epoch,
                new_epoch,
                old_root_hash: &old_root_hash,
                new_root_hash: &new_root_hash,
                updated_buckets: &updated_bucket_refs,
                signature_alg: &commit_signature.alg,
                signature_key_id: &commit_signature.key_id,
            },
            &commit_signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: &commit_signature.key_id,
                public_key: &public_key,
            },
        )
        .map_err(private_hnsw_error)?;
        for bucket in &updated_buckets {
            validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
                &session.manifest,
                std::slice::from_ref(bucket),
            )?;
        }

        let store = PrivateHnswOramStore::new(&session.collection_path, vector_name)?;
        ensure_private_hnsw_active_session_current_epoch(&store, old_epoch, &old_root_hash)?;
        Ok(PrivateHnswCommitPlan {
            store,
            bucket_count: session.bucket_count,
            max_bucket_ciphertext_bytes: session.max_bucket_ciphertext_bytes,
            public_key,
        })
        },
        )?
    };
    // Bucket writes and fsyncs run off the registry mutex and off the async worker; the session
    // stays `commit_in_progress` until the outcome is recorded below.
    let old = PrivateHnswOramEpochState {
        index_epoch: old_epoch,
        root_hash: old_root_hash,
    };
    let new = PrivateHnswOramEpochState {
        index_epoch: new_epoch,
        root_hash: new_root_hash,
    };
    let store_commit_signature = PrivateHnswOramSignature {
        alg: commit_signature.alg.clone(),
        key_id: commit_signature.key_id.clone(),
        sig: commit_signature.sig.clone(),
    };
    // The store commit and the registry outcome run in one detached task: if the request future
    // is dropped (client disconnect, gRPC deadline) while the commit is in flight, the outcome
    // is still recorded instead of leaving the session `commit_in_progress` forever.
    let collection_crypto_id = request_context.collection_crypto_id.clone();
    let vector_name = vector_name.to_string();
    let session_id = session_id.to_string();
    tokio::spawn(async move {
        let committed = tokio::task::spawn_blocking(move || {
            plan.store
                .commit_writeback_with_signature(
                    &old,
                    &new,
                    plan.bucket_count,
                    &updated_buckets,
                    plan.max_bucket_ciphertext_bytes,
                    &store_commit_signature,
                    PrivateHnswSignatureVerification {
                        expected_key_id: &store_commit_signature.key_id,
                        public_key: &plan.public_key,
                    },
                )
                .map_err(private_hnsw_commit_writeback_store_error)
        })
        .await
        .unwrap_or_else(|_| {
            Err(StorageError::service_error(
                "private HNSW ORAM commit task failed",
            ))
        });
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private HNSW ORAM session registry poisoned")
        })?;
        match committed {
            Ok(committed) => {
                registry.complete_commit(
                    &collection_crypto_id,
                    &vector_name,
                    &session_id,
                    &committed,
                    now_unix,
                    session_lease_expires_unix(now_unix)?,
                )?;
                Ok(committed)
            }
            Err(error) => {
                let _ = registry.cancel_commit(&collection_crypto_id, &vector_name, &session_id);
                Err(error)
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(StorageError::service_error(
            "private HNSW ORAM commit task failed",
        ))
    })
}

pub async fn do_close_private_hnsw_session(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
) -> StorageResult<bool> {
    validate_private_hnsw_session_id_shape(session_id)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_session_close",
        AccessRequirements::new().write(),
    )
    .await?;
    let now_unix = current_unix_secs()?;
    let closed = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .close(
            &request_context.collection_crypto_id,
            vector_name,
            session_id,
            now_unix,
        );
    if !closed {
        return Err(StorageError::bad_request(
            "private HNSW ORAM session is missing or already closed",
        ));
    }
    Ok(true)
}

pub async fn do_prepare_private_hnsw_replica_writeback(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    collection_id: &str,
    batch: &PrivateHnswOramWritebackBatch,
    expected: &PrivateHnswOramConsensusWriteback,
) -> StorageResult<PrivateHnswOramConsensusWriteback> {
    let context = private_hnsw_replica_store_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        collection_id,
        &batch.commit_signature.key_id,
        "private_hnsw_replica_prepare",
    )
    .await?;
    let _guard = begin_private_hnsw_upload_write_window(collection_id, vector_name)?;
    context
        .store
        .prepare_replica_writeback_with_signature(
            batch,
            expected,
            context.max_ciphertext_bytes,
            context.signature_verification(),
        )
        .map_err(private_hnsw_commit_writeback_store_error)
}

pub async fn do_install_private_hnsw_replica_bundle(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    collection_id: &str,
    bundle: PrivateHnswOramUploadBundle,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_private_hnsw_oram_manifest_signature_shape(&bundle.manifest_signature)
        .map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(
        &bundle.manifest,
        &bundle.manifest_signature,
    )?;
    let resolved = resolve_private_hnsw_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        &bundle.manifest_signature.key_id,
        "private_hnsw_replica_initial_install",
        AccessRequirements::new().write(),
    )
    .await?;
    if resolved.collection_crypto_id != collection_id {
        return Err(StorageError::bad_request(
            "private HNSW ORAM initial replication collection identity does not match",
        ));
    }
    resolved.validate_manifest_runtime_policy(&bundle.manifest)?;
    let max_ciphertext_bytes = max_bucket_ciphertext_bytes(&bundle.manifest)?;
    let collection_id = collection_id.to_owned();
    let vector_name = vector_name.to_owned();
    tokio::task::spawn_blocking(move || {
        let _guard = begin_private_hnsw_upload_write_window(&collection_id, &vector_name)?;
        PrivateHnswOramStore::new(&resolved.collection_path, &vector_name)?
            .write_initial_upload_bundle_with_signature(
                &bundle,
                max_ciphertext_bytes,
                resolved.manifest_context(&bundle.manifest_signature.key_id),
            )
            .map_err(private_hnsw_upload_store_error)
    })
    .await
    .map_err(|_| StorageError::service_error("private HNSW ORAM replica install worker failed"))?
}

#[allow(clippy::too_many_arguments)]
pub async fn do_install_private_hnsw_live_replica_bundle(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    collection_id: &str,
    bundle: PrivateHnswOramLiveReplicationBundle,
    expected_current: PrivateHnswOramEpochState,
    expected_writeback_digest: Option<String>,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_private_hnsw_oram_manifest_signature_shape(&bundle.manifest_signature)
        .map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(
        &bundle.manifest,
        &bundle.manifest_signature,
    )?;
    let resolved = resolve_private_hnsw_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        &bundle.manifest_signature.key_id,
        "private_hnsw_replica_live_install",
        AccessRequirements::new().write(),
    )
    .await?;
    if resolved.collection_crypto_id != collection_id {
        return Err(StorageError::bad_request(
            "private HNSW ORAM live replication collection identity does not match",
        ));
    }
    resolved.validate_manifest_runtime_policy(&bundle.manifest)?;
    let max_ciphertext_bytes = max_bucket_ciphertext_bytes(&bundle.manifest)?;
    let collection_id = collection_id.to_owned();
    let vector_name = vector_name.to_owned();
    tokio::task::spawn_blocking(move || {
        let _guard = begin_private_hnsw_upload_write_window(&collection_id, &vector_name)?;
        PrivateHnswOramStore::new(&resolved.collection_path, &vector_name)?
            .write_live_replication_bundle_with_signature(
                &bundle,
                max_ciphertext_bytes,
                resolved.manifest_context(&bundle.manifest_signature.key_id),
                &expected_current,
                expected_writeback_digest.as_deref(),
            )
            .map_err(private_hnsw_upload_store_error)
    })
    .await
    .map_err(|_| {
        StorageError::service_error("private HNSW ORAM live replica install worker failed")
    })?
}

pub async fn do_complete_private_hnsw_replica_writeback(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    collection_id: &str,
    signing_key_id: &str,
    expected: &PrivateHnswOramConsensusWriteback,
    abort: bool,
) -> StorageResult<bool> {
    let context = private_hnsw_replica_store_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        collection_id,
        signing_key_id,
        "private_hnsw_replica_complete",
    )
    .await?;
    let _guard = begin_private_hnsw_upload_write_window(collection_id, vector_name)?;
    if abort {
        context
            .store
            .abort_replica_writeback_with_signature(
                expected,
                context.max_ciphertext_bytes,
                context.signature_verification(),
            )
            .map_err(private_hnsw_commit_writeback_store_error)
    } else {
        if context
            .store
            .completed_replica_writeback_matches(expected)
            .map_err(private_hnsw_commit_writeback_store_error)?
        {
            return Ok(true);
        }
        context
            .store
            .commit_replica_writeback_with_signature(
                expected,
                context.max_ciphertext_bytes,
                context.signature_verification(),
            )
            .map(|_| true)
            .map_err(private_hnsw_commit_writeback_store_error)
    }
}

pub struct PrivateHnswRecoveryContext {
    pub collection_id: String,
    pub current: PrivateHnswOramEpochState,
    pub pending: Option<(
        PrivateHnswOramWritebackBatch,
        PrivateHnswOramConsensusWriteback,
    )>,
    replica: PrivateHnswReplicaStoreContext,
    _guard: PrivateHnswUploadGuard,
}

impl PrivateHnswRecoveryContext {
    pub fn complete_pending(
        &self,
        expected: &PrivateHnswOramConsensusWriteback,
        abort: bool,
    ) -> StorageResult<bool> {
        if abort {
            self.replica
                .store
                .abort_replica_writeback_with_signature(
                    expected,
                    self.replica.max_ciphertext_bytes,
                    self.replica.signature_verification(),
                )
                .map_err(private_hnsw_commit_writeback_store_error)
        } else {
            if self
                .replica
                .store
                .completed_replica_writeback_matches(expected)
                .map_err(private_hnsw_commit_writeback_store_error)?
            {
                return Ok(true);
            }
            self.replica
                .store
                .commit_replica_writeback_with_signature(
                    expected,
                    self.replica.max_ciphertext_bytes,
                    self.replica.signature_verification(),
                )
                .map(|_| true)
                .map_err(private_hnsw_commit_writeback_store_error)
        }
    }
}

pub async fn do_inspect_private_hnsw_recovery(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
) -> StorageResult<PrivateHnswRecoveryContext> {
    let record =
        do_get_private_hnsw_manifest(toc, auth, settings, collection_name, vector_name).await?;
    let collection_id = record.manifest.collection_id.clone();
    let signing_key_id = record.manifest.owner_signing_key_id.clone();
    let replica = private_hnsw_replica_store_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        &collection_id,
        &signing_key_id,
        "private_hnsw_recovery_inspect",
    )
    .await?;
    let guard = begin_private_hnsw_upload_write_window(&collection_id, vector_name)?;
    let current = replica
        .store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    let pending = replica
        .store
        .pending_writeback_replication_batch_with_signature(
            replica.max_ciphertext_bytes,
            replica.signature_verification(),
        )
        .map_err(private_hnsw_commit_writeback_store_error)?;
    Ok(PrivateHnswRecoveryContext {
        collection_id,
        current,
        pending,
        replica,
        _guard: guard,
    })
}

struct PrivateHnswReplicaStoreContext {
    resolved: ResolvedPrivateHnswContext,
    store: PrivateHnswOramStore,
    signing_key_id: String,
    max_ciphertext_bytes: usize,
}

impl PrivateHnswReplicaStoreContext {
    fn signature_verification(&self) -> PrivateHnswSignatureVerification<'_> {
        PrivateHnswSignatureVerification {
            expected_key_id: &self.signing_key_id,
            public_key: &self.resolved.public_key,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn private_hnsw_replica_store_context(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    collection_id: &str,
    signing_key_id: &str,
    method: &str,
) -> StorageResult<PrivateHnswReplicaStoreContext> {
    let resolved = resolve_private_hnsw_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        signing_key_id,
        method,
        AccessRequirements::new().write(),
    )
    .await?;
    if resolved.collection_crypto_id != collection_id {
        return Err(StorageError::bad_request(
            "private HNSW ORAM replication collection identity does not match",
        ));
    }
    let store = PrivateHnswOramStore::new(&resolved.collection_path, vector_name)?;
    let (manifest, manifest_signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&manifest_signature)
        .map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &manifest_signature)?;
    if manifest.owner_signing_key_id != signing_key_id {
        return Err(StorageError::bad_request(
            "private HNSW ORAM replication signing key does not match manifest owner",
        ));
    }
    validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&manifest_signature),
        resolved.manifest_context(&manifest_signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    Ok(PrivateHnswReplicaStoreContext {
        max_ciphertext_bytes: max_bucket_ciphertext_bytes(&manifest)?,
        resolved,
        store,
        signing_key_id: signing_key_id.to_string(),
    })
}

pub fn validate_recovered_private_hnsw_oram_snapshot_signatures(
    settings: &Settings,
    collection_name: &str,
    config: &CollectionConfigInternal,
    collection_path: &Path,
) -> StorageResult<()> {
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(encryption) = config.params.effective_encryption() else {
        return Ok(());
    };
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?;

    let mut checked_vectors = HashSet::new();
    for rule in encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING))
    {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            return Err(StorageError::bad_request(
                "private HNSW ORAM snapshot rule must use vector_names selector",
            ));
        };
        let instance = private_hnsw_instance(settings, rule)?;
        for vector_name in names {
            if !checked_vectors.insert(vector_name.clone()) {
                continue;
            }
            let store = PrivateHnswOramStore::new(collection_path, vector_name)?;
            let (manifest, signature) = read_uploaded_manifest(&store)?;
            validate_private_hnsw_oram_manifest_signature_shape(&signature)
                .map_err(private_hnsw_error)?;
            validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
            let runtime_context = manifest_context_from_runtime(
                &config.params,
                &collection_crypto_id,
                vector_name,
                instance,
                has_private_result_oram_binding(settings, &encryption),
            )?;
            let public_key = signature_public_key(instance, &signature.key_id)?;
            let resolved = ResolvedPrivateHnswContext {
                collection_path: collection_path.to_path_buf(),
                public_key,
                ..runtime_context
            };
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&signature),
                resolved.manifest_context(&signature.key_id),
            )
            .map_err(private_hnsw_error)?;
            resolved.validate_manifest_runtime_policy(&manifest)?;
            let expected_epoch = PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            };
            ensure_private_hnsw_restored_snapshot_storage_matches(
                &store,
                &expected_epoch,
                &manifest,
                &signature,
            )?;
        }
    }

    Ok(())
}

async fn resolve_private_hnsw_context(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    signature_key_id: &str,
    method: &str,
    requirements: AccessRequirements,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let pass = auth.check_collection_access(collection_name, requirements, method)?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        signature_key_id,
    )
}

pub(crate) fn resolve_private_hnsw_context_from_snapshot(
    settings: &Settings,
    collection_name: &str,
    collection_path: &std::path::Path,
    config: &CollectionConfigInternal,
    vector_name: &str,
    signature_key_id: &str,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_HNSW_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    Ok(ResolvedPrivateHnswContext {
        collection_path: collection_path.to_path_buf(),
        public_key: signature_public_key(instance, signature_key_id)?,
        ..runtime_context
    })
}

fn private_hnsw_rule<'a>(
    encryption: &'a CollectionEncryptionConfig,
    vector_name: &str,
) -> StorageResult<&'a EncryptionRuleRef> {
    encryption
        .rules
        .iter()
        .find(|rule| {
            rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING)
                && matches!(
                    &rule.selector,
                    EncryptionSelector::VectorNames { names }
                        if names.iter().any(|name| name == vector_name)
                )
        })
        .ok_or_else(|| {
            StorageError::bad_request(private_hnsw_oram_api_required_message(vector_name))
        })
}

fn private_hnsw_instance<'a>(
    settings: &'a Settings,
    rule: &EncryptionRuleRef,
) -> StorageResult<&'a CryptoInstanceConfig> {
    let instance = settings
        .crypto
        .instances
        .get(&rule.instance)
        .ok_or_else(|| {
            StorageError::bad_request(
                "private HNSW ORAM collection binding references a missing runtime instance",
            )
        })?;
    if instance.provider != VECTOR_PRIVATE_HNSW_ORAM_PROVIDER {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM collection binding must reference a {VECTOR_PRIVATE_HNSW_ORAM_PROVIDER} runtime instance",
        )));
    }
    Ok(instance)
}

pub(crate) fn resolve_private_hnsw_external_recovery_owner_public_key(
    settings: &Settings,
    rule: &EncryptionRuleRef,
    signing_key_id: &str,
) -> StorageResult<Vec<u8>> {
    let instance = private_hnsw_instance(settings, rule)?;
    signature_public_key(instance, signing_key_id)
}

fn has_private_result_oram_binding(
    settings: &Settings,
    encryption: &CollectionEncryptionConfig,
) -> bool {
    encryption.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING)
            && settings
                .crypto
                .instances
                .get(&rule.instance)
                .is_some_and(|instance| instance.provider == PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
    })
}

fn read_uploaded_manifest(
    store: &PrivateHnswOramStore,
) -> StorageResult<(PrivateHnswOramManifest, PrivateHnswOramSignature)> {
    store
        .read_manifest()
        .map_err(private_hnsw_manifest_read_store_error)
}

fn validate_private_hnsw_manifest_signature_owner_key(
    manifest: &PrivateHnswOramManifest,
    signature: &PrivateHnswOramSignature,
) -> StorageResult<()> {
    if signature.key_id != manifest.owner_signing_key_id {
        return Err(private_hnsw_error(
            qdrant_sec::PrivateHnswOramError::SignatureKeyIdMismatch,
        ));
    }
    Ok(())
}

fn ensure_private_hnsw_session_open_storage_matches(
    store: &PrivateHnswOramStore,
    expected_epoch: &PrivateHnswOramEpochState,
    expected_manifest: &PrivateHnswOramManifest,
    expected_signature: &PrivateHnswOramSignature,
) -> StorageResult<()> {
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    let (stored_manifest, stored_signature) = read_uploaded_manifest(store)?;
    if current_epoch != *expected_epoch
        || stored_manifest != *expected_manifest
        || stored_signature != *expected_signature
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM session open observed concurrent manifest or epoch update",
        ));
    }
    store
        .read_bucket_batch_with_proof(
            &[0],
            expected_epoch.index_epoch,
            &expected_epoch.root_hash,
            expected_manifest.bucket_count,
            max_bucket_ciphertext_bytes(expected_manifest)?,
        )
        .map_err(private_hnsw_read_batch_store_error)?;
    Ok(())
}

fn ensure_private_hnsw_restored_snapshot_storage_matches(
    store: &PrivateHnswOramStore,
    expected_epoch: &PrivateHnswOramEpochState,
    expected_manifest: &PrivateHnswOramManifest,
    expected_signature: &PrivateHnswOramSignature,
) -> StorageResult<()> {
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    let (stored_manifest, stored_signature) = read_uploaded_manifest(store)?;
    if current_epoch != *expected_epoch
        || stored_manifest != *expected_manifest
        || stored_signature != *expected_signature
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM restored snapshot manifest or epoch does not match current storage",
        ));
    }
    let max_bucket_ciphertext_bytes = max_bucket_ciphertext_bytes(expected_manifest)?;
    // Every proof read recomputes the Merkle levels of the whole tree, so buckets are verified
    // in batches: one recomputation per batch instead of one per bucket.
    let bucket_ids: Vec<u64> = (0..expected_manifest.bucket_count).collect();
    for batch in bucket_ids.chunks(PRIVATE_HNSW_SNAPSHOT_VERIFICATION_BATCH) {
        store
            .read_bucket_batch_with_proof(
                batch,
                expected_epoch.index_epoch,
                &expected_epoch.root_hash,
                expected_manifest.bucket_count,
                max_bucket_ciphertext_bytes,
            )
            .map_err(private_hnsw_read_batch_store_error)?;
    }
    Ok(())
}

/// Buckets verified per proof read while checking a restored snapshot against its tree.
const PRIVATE_HNSW_SNAPSHOT_VERIFICATION_BATCH: usize = 1024;

fn private_hnsw_manifest_read_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM manifest has not been uploaded")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM manifest store validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM manifest store validation failed")
        }
        _ => StorageError::service_error("private HNSW ORAM manifest store validation failed"),
    }
}

fn private_hnsw_read_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM encrypted bucket data is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM encrypted bucket store validation failed")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
        _ => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
    }
}

fn private_hnsw_read_batch_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::BadRequest { description }
            if description.contains(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            ) =>
        {
            StorageError::bad_request(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            )
        }
        other => private_hnsw_read_store_error(other),
    }
}

fn private_hnsw_manifest_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM manifest store is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM manifest store validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM manifest store validation failed")
        }
        _ => StorageError::service_error("private HNSW ORAM manifest store validation failed"),
    }
}

fn private_hnsw_epoch_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM current epoch is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM current epoch validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM current epoch validation failed")
        }
        _ => StorageError::service_error("private HNSW ORAM current epoch validation failed"),
    }
}

fn private_hnsw_upload_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM encrypted bucket store is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM encrypted bucket store validation failed")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
        _ => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
    }
}

fn private_hnsw_commit_writeback_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => StorageError::not_found(
            "private HNSW ORAM encrypted bucket store metadata is unavailable",
        ),
        CollectionError::BadRequest { description }
            if description.contains("commit signature verification failed") =>
        {
            StorageError::bad_request("private HNSW ORAM commit signature verification failed")
        }
        CollectionError::BadRequest { description }
            if description.contains("commit bucket commitment context mismatch") =>
        {
            StorageError::bad_request("private HNSW ORAM commit bucket commitment context mismatch")
        }
        CollectionError::BadRequest { description }
            if description.contains("bucket ciphertext must match fixed ciphertext size") =>
        {
            StorageError::bad_request(
                "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
            )
        }
        CollectionError::BadRequest { description }
            if description.contains("bucket ciphertext") =>
        {
            StorageError::bad_request("private HNSW ORAM bucket ciphertext validation failed")
        }
        CollectionError::BadRequest { .. } => StorageError::bad_request(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
        _ => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
    }
}

fn manifest_context_from_runtime(
    params: &CollectionParams,
    collection_crypto_id: &str,
    vector_name: &str,
    instance: &CryptoInstanceConfig,
    private_result_oram_binding_configured: bool,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let vector_params = params.vectors.get_params(vector_name).ok_or_else(|| {
        CollectionError::bad_input("private HNSW ORAM vector is not configured as a dense vector")
    })?;
    let key_id = required_option_string(instance, KEY_ID_OPTION)?;
    let expected_rk_id = required_option_string(instance, EXPECTED_RK_ID_OPTION)?;
    let min_rk_epoch = required_option_u64(instance, MIN_RK_EPOCH_OPTION)?;
    let max_rk_epoch = required_option_u64(instance, MAX_RK_EPOCH_OPTION)?;
    let expected_result_privacy = result_privacy_from_runtime(instance)?;
    let expected_hnsw = required_option_struct(instance, HNSW_OPTION)?;
    let expected_oram = required_option_struct(instance, ORAM_OPTION)?;
    let expected_fixed_budget = required_option_struct(instance, FIXED_BUDGET_OPTION)?;
    let verifier_public_keys = signature_public_keys(instance)?;
    let expected_distance = distance_kind(vector_params.distance);
    let expected_dim = u32::try_from(vector_params.size.get()).map_err(|_| {
        StorageError::bad_request(
            "private HNSW ORAM vector size exceeds supported manifest dim range",
        )
    })?;
    Ok(ResolvedPrivateHnswContext {
        collection_path: std::path::PathBuf::new(),
        collection_crypto_id: collection_crypto_id.to_string(),
        vector_name: vector_name.to_string(),
        expected_key_id: key_id,
        expected_rk_id,
        min_rk_epoch,
        max_rk_epoch,
        expected_dim,
        expected_distance,
        expected_result_privacy,
        private_result_oram_binding_configured,
        expected_hnsw,
        expected_oram,
        expected_fixed_budget,
        signature_public_keys: verifier_public_keys,
        public_key: Vec::new(),
    })
}

fn result_privacy_from_runtime(
    instance: &CryptoInstanceConfig,
) -> StorageResult<ResultPrivacyMode> {
    match required_option_string(instance, RESULT_PRIVACY_OPTION)?.as_str() {
        "ids_visible" => Ok(ResultPrivacyMode::IdsVisible),
        "private_payload_oram_required" => Ok(ResultPrivacyMode::PrivatePayloadOramRequired),
        _ => Err(StorageError::bad_request(
            "private HNSW ORAM result privacy option has unsupported value",
        )),
    }
}

fn signature_public_key(
    instance: &CryptoInstanceConfig,
    signature_key_id: &str,
) -> StorageResult<Vec<u8>> {
    let registry = signature_public_keys(instance)?;
    let public_key_b64 = registry.get(signature_key_id).ok_or_else(|| {
        StorageError::bad_request("private HNSW ORAM signature key id is not configured")
    })?;
    decode_signature_public_key(public_key_b64)
}

fn signature_public_keys(
    instance: &CryptoInstanceConfig,
) -> StorageResult<HashMap<String, String>> {
    let registry = instance
        .options
        .get(SIGNATURE_PUBLIC_KEYS_OPTION)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            StorageError::bad_request(
                "private HNSW ORAM runtime instance must configure signature_public_keys",
            )
        })?;
    if registry.is_empty() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM runtime instance must configure signature_public_keys",
        ));
    }
    registry
        .iter()
        .map(|(key_id, public_key)| {
            let public_key_b64 = public_key.as_str().ok_or_else(|| {
                StorageError::bad_request("private HNSW ORAM public key is not base64url")
            })?;
            Ok((key_id.clone(), public_key_b64.to_string()))
        })
        .collect()
}

fn decode_signature_public_key(public_key_b64: &str) -> StorageResult<Vec<u8>> {
    if public_key_b64.len() != PRIVATE_HNSW_ORAM_ROOT_HASH_B64_LEN {
        return Err(StorageError::bad_request(
            "private HNSW ORAM public key must be 32 bytes",
        ));
    }
    let public_key = BASE64URL_NOPAD
        .decode(public_key_b64.as_bytes())
        .map_err(|_| StorageError::bad_request("private HNSW ORAM public key is not base64url"))?;
    if public_key.len() != 32 {
        return Err(StorageError::bad_request(
            "private HNSW ORAM public key must be 32 bytes",
        ));
    }
    Ok(public_key)
}

async fn collection_context_for_request(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    signature_key_id: Option<&str>,
    method: &str,
    requirements: AccessRequirements,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let pass = auth.check_collection_access(collection_name, requirements, method)?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_HNSW_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = if let Some(signature_key_id) = signature_key_id {
        signature_public_key(instance, signature_key_id)?
    } else {
        Vec::new()
    };
    Ok(ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    })
}

fn validate_client_signature_shape(signature: &PrivateHnswClientSignature) -> StorageResult<()> {
    if signature.alg != "ed25519" {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature algorithm must be ed25519",
        ));
    }
    if signature.key_id.is_empty() || signature.sig.is_empty() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature key_id and sig are required",
        ));
    }
    validate_client_signature_key_id_shape(&signature.key_id)?;
    if signature.sig.len() != PRIVATE_HNSW_ORAM_SIGNATURE_B64_LEN {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature must encode 64 bytes",
        ));
    }
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| StorageError::bad_request("private HNSW ORAM signature is not base64url"))?;
    if signature_bytes.len() != 64 {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature must encode 64 bytes",
        ));
    }
    Ok(())
}

fn validate_client_signature_key_id_shape(key_id: &str) -> StorageResult<()> {
    if key_id.len() > 128
        || !key_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature key_id is invalid",
        ));
    }
    Ok(())
}

fn validate_private_hnsw_client_id_shape(client_id: &str) -> StorageResult<()> {
    if client_id.is_empty() || client_id.len() > PRIVATE_HNSW_ORAM_CLIENT_ID_MAX_LEN {
        return Err(StorageError::bad_request(
            "private HNSW ORAM client_id must be non-empty and at most 256 bytes",
        ));
    }
    if !client_id.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
    }) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM client_id is invalid",
        ));
    }
    Ok(())
}

fn validate_private_hnsw_session_id_shape(session_id: &str) -> StorageResult<()> {
    if session_id.is_empty()
        || session_id.len() > PRIVATE_HNSW_ORAM_SESSION_ID_MAX_LEN
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM session_id is invalid",
        ));
    }
    Ok(())
}

fn required_option_string(instance: &CryptoInstanceConfig, key: &str) -> StorageResult<String> {
    instance
        .options
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM runtime option is missing"))
}

fn required_option_u64(instance: &CryptoInstanceConfig, key: &str) -> StorageResult<u64> {
    instance
        .options
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM runtime option is missing"))
}

fn required_option_struct<T>(instance: &CryptoInstanceConfig, key: &str) -> StorageResult<T>
where
    T: DeserializeOwned,
{
    let value = instance
        .options
        .get(key)
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM runtime option is missing"))?;
    serde_json::from_value(value.clone())
        .map_err(|_| StorageError::bad_request("private HNSW ORAM runtime option is invalid"))
}

fn distance_kind(distance: Distance) -> DistanceKind {
    match distance {
        Distance::Cosine => DistanceKind::Cosine,
        Distance::Euclid => DistanceKind::Euclid,
        Distance::Dot => DistanceKind::Dot,
        Distance::Manhattan => DistanceKind::Manhattan,
    }
}

fn private_hnsw_error(err: qdrant_sec::PrivateHnswOramError) -> StorageError {
    match err {
        qdrant_sec::PrivateHnswOramError::UnsupportedSignatureAlgorithm(_) => {
            StorageError::bad_request("private HNSW ORAM signature algorithm must be ed25519")
        }
        qdrant_sec::PrivateHnswOramError::SignatureKeyIdMismatch => StorageError::bad_request(
            "private HNSW ORAM signature key_id does not match manifest owner_signing_key_id",
        ),
        _ => StorageError::bad_request("private HNSW ORAM request validation failed"),
    }
}

fn is_strict(settings: &Settings) -> bool {
    settings.crypto.zero_trust_profile.as_deref() == Some(ZERO_TRUST_PROFILE_STRICT)
}

fn validate_private_hnsw_oram_single_node_epoch_mode(distributed: bool) -> StorageResult<()> {
    if distributed {
        return Err(StorageError::bad_request(
            "private HNSW ORAM distributed operations require consensus-backed epoch/root CAS; \
             this MVP supports private ORAM sessions only in single-node mode",
        ));
    }
    Ok(())
}

fn validate_private_hnsw_oram_upload_epoch_mode(
    distributed: bool,
    coordinated_initial_replication: bool,
) -> StorageResult<()> {
    if distributed && !coordinated_initial_replication {
        return validate_private_hnsw_oram_single_node_epoch_mode(true);
    }
    Ok(())
}

fn begin_private_hnsw_upload_write_window(
    collection_id: &str,
    vector_name: &str,
) -> StorageResult<PrivateHnswUploadGuard> {
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.begin_upload(collection_id, vector_name, now_unix)?;
    Ok(PrivateHnswUploadGuard {
        collection_id: collection_id.to_string(),
        vector_name: vector_name.to_string(),
    })
}

fn ensure_private_hnsw_write_window_in_registry(
    registry: &mut PrivateHnswSessionRegistry,
    collection_id: &str,
    vector_name: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry
        .active_snapshot_by_collection
        .contains_key(collection_id)
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active collection snapshot",
        ));
    }
    if registry
        .active_lifecycle_by_collection
        .contains(collection_id)
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active collection lifecycle operation",
        ));
    }
    if registry.has_active_index(collection_id, vector_name, now_unix) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active session for this index",
        ));
    }
    if registry
        .active_upload_by_index
        .contains(&private_hnsw_index_key(collection_id, vector_name))
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active upload for this index",
        ));
    }
    Ok(())
}

fn ensure_no_active_private_hnsw_collection_session_in_registry(
    registry: &mut PrivateHnswSessionRegistry,
    collection_id: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry.has_active_collection(collection_id, now_unix) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM collection snapshot requires no active private ORAM session",
        ));
    }
    if registry.has_active_upload_collection(collection_id) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM collection snapshot requires no active private ORAM upload",
        ));
    }
    Ok(())
}

fn ensure_no_active_private_hnsw_collection_lifecycle_in_registry(
    registry: &mut PrivateHnswSessionRegistry,
    collection_id: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry.has_active_collection(collection_id, now_unix) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM collection lifecycle operation requires no active private ORAM session",
        ));
    }
    if registry.has_active_upload_collection(collection_id) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM collection lifecycle operation requires no active private ORAM upload",
        ));
    }
    Ok(())
}

fn collection_uses_private_hnsw_oram(config: &CollectionConfigInternal) -> bool {
    config
        .params
        .effective_encryption()
        .is_some_and(|encryption| {
            encryption
                .rules
                .iter()
                .any(|rule| rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING))
        })
}

fn ensure_private_hnsw_active_session_current_epoch(
    store: &PrivateHnswOramStore,
    expected_epoch: u64,
    expected_root_hash: &str,
) -> StorageResult<()> {
    let current = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current.index_epoch != expected_epoch || current.root_hash != expected_root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM current epoch/root does not match active session",
        ));
    }
    Ok(())
}

fn validate_session_signature_owner_key(
    session: &PrivateHnswSession,
    signature_key_id: &str,
) -> StorageResult<()> {
    if signature_key_id != session.manifest.owner_signing_key_id {
        return Err(StorageError::bad_request(
            "private HNSW ORAM request signature key_id does not match manifest owner_signing_key_id",
        ));
    }
    Ok(())
}

fn current_unix_secs() -> StorageResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StorageError::service_error("system clock before UNIX epoch"))
}

fn session_lease_expires_unix(now_unix: u64) -> StorageResult<u64> {
    now_unix.checked_add(SESSION_LEASE_SECS).ok_or_else(|| {
        StorageError::service_error("private HNSW ORAM session lease calculation overflowed")
    })
}

fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn private_hnsw_index_key(collection_id: &str, vector_name: &str) -> (String, String) {
    (collection_id.to_string(), vector_name.to_string())
}

fn ensure_private_hnsw_read_proof_matches_buckets(
    proof: &PrivateHnswOramMerkleProof,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(StorageError::bad_request(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

/// Pre-decode ceiling for bucket ciphertexts: buckets have exactly the fixed ciphertext size,
/// so the ceiling is that size (the former `block_size * bucket_size + 4096` heuristic fell
/// below it for `bucket_size > 4053`).
pub(crate) fn max_bucket_ciphertext_bytes(
    manifest: &PrivateHnswOramManifest,
) -> StorageResult<usize> {
    expected_bucket_ciphertext_bytes(manifest)
}

fn expected_bucket_ciphertext_bytes(manifest: &PrivateHnswOramManifest) -> StorageResult<usize> {
    private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_hnsw_bucket_ciphertext_size_error)
}

fn private_hnsw_bucket_ciphertext_size_error(_err: PrivateHnswOramError) -> StorageError {
    StorageError::bad_request("private HNSW ORAM bucket ciphertext size is invalid")
}

fn validate_bucket_ciphertext_fixed_size(
    bucket: &PrivateHnswOramBucket,
    manifest: &PrivateHnswOramManifest,
) -> StorageResult<()> {
    let expected = expected_bucket_ciphertext_bytes(manifest)?;
    let expected_encoded_len = max_base64url_nopad_encoded_len(expected).ok_or_else(|| {
        StorageError::bad_request("private HNSW ORAM bucket ciphertext size is invalid")
    })?;
    if bucket.ciphertext.len() != expected_encoded_len {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            StorageError::bad_request("private HNSW ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() != expected {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    Ok(())
}

fn max_base64url_nopad_encoded_len(byte_len: usize) -> Option<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => return None,
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
}

fn validate_private_hnsw_read_bucket_ciphertexts_fixed_size(
    manifest: &PrivateHnswOramManifest,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    for bucket in buckets {
        validate_bucket_ciphertext_fixed_size(bucket, manifest)?;
    }
    Ok(())
}

fn validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
    manifest: &PrivateHnswOramManifest,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    validate_private_hnsw_read_bucket_ciphertexts_fixed_size(manifest, buckets).map_err(|_| {
        StorageError::bad_request("private HNSW ORAM bucket ciphertext validation failed")
    })
}

/// A commit may rewrite one path worth of buckets per path the session read (a fixed-budget
/// search reads `upper_layer_steps + base_layer_steps` paths and commits once), never less than
/// one fixed read round and never more than the tree.
fn max_updated_bucket_count(session: &PrivateHnswSession) -> StorageResult<usize> {
    let read_path_count = usize::try_from(session.read_path_count).unwrap_or(usize::MAX);
    private_hnsw_oram_session_writeback_bucket_budget(&session.manifest.oram, read_path_count)
        .map_err(|_| StorageError::bad_request("private HNSW ORAM writeback size overflows"))
}

fn validate_initial_private_hnsw_upload_bundle(
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    root_hash: &str,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<Vec<String>> {
    if manifest.index_epoch != index_epoch || manifest.root_hash != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload epoch/root does not match manifest",
        ));
    }
    let leaf_commitments =
        ordered_initial_bucket_commitments(buckets, index_epoch, manifest.bucket_count)?;
    validate_bucket_commitment_context(manifest, index_epoch, buckets)?;
    let computed_root = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments)?;
    if computed_root != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload Merkle root mismatch",
        ));
    }
    Ok(leaf_commitments)
}

fn validate_bucket_commitment_context(
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
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
            StorageError::bad_request("private HNSW ORAM bucket commitment context mismatch")
        })?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(StorageError::bad_request(
                "private HNSW ORAM bucket commitment context mismatch",
            ));
        }
    }
    Ok(())
}

fn ordered_initial_bucket_commitments(
    buckets: &[PrivateHnswOramBucket],
    expected_epoch: u64,
    bucket_count: u64,
) -> StorageResult<Vec<String>> {
    let bucket_count_usize = usize::try_from(bucket_count).map_err(|_| {
        StorageError::bad_request("private HNSW ORAM bucket_count exceeds supported range")
    })?;
    if buckets.len() != bucket_count_usize {
        return Err(StorageError::bad_request(
            "private HNSW ORAM initial upload must include the configured bucket count",
        ));
    }
    let mut commitments = vec![None; bucket_count_usize];
    for bucket in buckets {
        if bucket.index_epoch != expected_epoch {
            return Err(StorageError::bad_request(
                "private HNSW ORAM initial upload bucket has stale epoch",
            ));
        }
        if bucket.bucket_id >= bucket_count {
            return Err(StorageError::bad_request(
                "private HNSW ORAM initial upload bucket is out of range",
            ));
        }
        validate_root_hash_string(&bucket.bucket_commitment, "bucket_commitment")?;
        let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
            StorageError::bad_request("private HNSW ORAM bucket id exceeds supported range")
        })?;
        if commitments[bucket_index].is_some() {
            return Err(StorageError::bad_request(
                "private HNSW ORAM initial upload contains duplicate bucket",
            ));
        }
        commitments[bucket_index] = Some(bucket.bucket_commitment.clone());
    }
    commitments
        .into_iter()
        .enumerate()
        .map(|(_bucket_id, commitment)| {
            commitment.ok_or_else(|| {
                StorageError::bad_request("private HNSW ORAM initial upload is missing a bucket")
            })
        })
        .collect()
}

fn validate_unique_path_labels(paths: &[String]) -> StorageResult<()> {
    let mut seen_paths = HashSet::new();
    for path in paths {
        if !seen_paths.insert(path.as_str()) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM read_paths request contains duplicate path label",
            ));
        }
    }
    Ok(())
}

fn validate_private_hnsw_read_path_label_request_shape(paths: &[String]) -> StorageResult<()> {
    if paths.is_empty() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM read_paths request is empty",
        ));
    }
    if paths.len() > PRIVATE_HNSW_ORAM_PATH_BATCH_SIZE_MAX {
        return Err(StorageError::bad_request(
            "private HNSW ORAM read_paths request exceeds maximum path batch size",
        ));
    }
    validate_unique_path_labels(paths)?;
    for path in paths {
        if path.len() != PRIVATE_HNSW_ORAM_LEAF_LABEL_B64_LEN {
            return Err(StorageError::bad_request(
                "private HNSW ORAM request validation failed",
            ));
        }
        let bytes = BASE64URL_NOPAD.decode(path.as_bytes()).map_err(|_| {
            StorageError::bad_request("private HNSW ORAM request validation failed")
        })?;
        if bytes.len() != 8 {
            return Err(StorageError::bad_request(
                "private HNSW ORAM request validation failed",
            ));
        }
    }
    Ok(())
}

fn validate_private_hnsw_commit_request_shape(
    updated_buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    if updated_buckets.is_empty() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM commit updated_buckets must contain at least one bucket",
        ));
    }
    if updated_buckets.len() > PRIVATE_HNSW_ORAM_WRITEBACK_BUCKETS_MAX {
        return Err(StorageError::bad_request(
            "private HNSW ORAM commit updated_buckets exceeds maximum writeback bucket batch size",
        ));
    }
    let mut seen_bucket_ids = HashSet::with_capacity(updated_buckets.len());
    for bucket in updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM commit updated_buckets contains duplicate bucket",
            ));
        }
        validate_root_hash_string(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
        validate_root_hash_string(&bucket.bucket_commitment, "bucket_commitment")?;
    }
    Ok(())
}

fn validate_private_hnsw_upload_bucket_request_shape(
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    if buckets.is_empty() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload must contain at least one bucket",
        ));
    }
    validate_private_hnsw_upload_bucket_count_shape(buckets.len())?;
    let mut seen_bucket_ids = HashSet::with_capacity(buckets.len());
    for bucket in buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM bucket upload contains duplicate bucket",
            ));
        }
        validate_root_hash_string(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
        validate_root_hash_string(&bucket.bucket_commitment, "bucket_commitment")?;
    }
    Ok(())
}

fn validate_private_hnsw_upload_bucket_count_shape(bucket_count: usize) -> StorageResult<()> {
    if bucket_count > PRIVATE_HNSW_ORAM_UPLOAD_BUCKETS_MAX {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload exceeds maximum bucket batch size",
        ));
    }
    Ok(())
}

fn validate_private_hnsw_read_path_labels(paths: &[String], tree_height: u32) -> StorageResult<()> {
    validate_unique_path_labels(paths)?;
    for path in paths {
        if path.len() != PRIVATE_HNSW_ORAM_LEAF_LABEL_B64_LEN {
            return Err(StorageError::bad_request(
                "private HNSW ORAM read_paths request contains invalid path label",
            ));
        }
        decode_private_hnsw_oram_leaf_label(path, tree_height).map_err(|_| {
            StorageError::bad_request(
                "private HNSW ORAM read_paths request contains invalid path label",
            )
        })?;
    }
    Ok(())
}

fn bucket_ids_for_path_batch(
    paths: &[String],
    tree_height: u32,
    bucket_count: u64,
) -> StorageResult<Vec<u64>> {
    let expected_bucket_count = private_hnsw_oram_bucket_count(tree_height)
        .map_err(|_| StorageError::bad_request("private HNSW ORAM tree_height is invalid"))?;
    if bucket_count != expected_bucket_count {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket_count does not match tree_height",
        ));
    }

    let path_len = usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM tree_height is too large"))?;
    let bucket_id_capacity = paths.len().checked_mul(path_len).ok_or_else(|| {
        StorageError::bad_request("private HNSW ORAM read_paths batch is too large")
    })?;
    let mut bucket_ids = Vec::with_capacity(bucket_id_capacity);
    for path in paths {
        let leaf = decode_private_hnsw_oram_leaf_label(path, tree_height).map_err(|_| {
            StorageError::bad_request(
                "private HNSW ORAM read_paths request contains invalid path label",
            )
        })?;
        bucket_ids.extend(
            private_hnsw_oram_bucket_ids_for_leaf(leaf, tree_height).map_err(|_| {
                StorageError::bad_request("private HNSW ORAM read_paths bucket derivation failed")
            })?,
        );
    }
    Ok(bucket_ids)
}

fn validate_root_hash_string(value: &str, field: &str) -> StorageResult<()> {
    if value.len() != PRIVATE_HNSW_ORAM_ROOT_HASH_B64_LEN {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM {field} must encode 32 bytes",
        )));
    }
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        StorageError::bad_request(format!("private HNSW ORAM {field} is not base64url"))
    })?;
    if bytes.len() != 32 {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM {field} must encode 32 bytes",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod private_hnsw_tests {
    use std::collections::BTreeMap;

    use collection::config::{CryptoMigrationState, WalConfig};
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        FixedBudgetParams, OramKind, OramParams, PrivateHnswBucketAeadBaseContext,
        PrivateHnswBuildPoint, PrivateHnswClientKeys, PrivateHnswManifestBuildContext,
        PrivateHnswOramClientConfig, PrivateHnswParams, PrivateHnswSignatureVerification,
        SecretKey, build_private_hnsw_oram_manifest_from_encrypted_index,
        build_private_hnsw_oram_plaintext_index_from_f32_points,
        encode_private_hnsw_oram_leaf_label, seal_private_hnsw_oram_plaintext_index,
        sign_private_hnsw_oram_manifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::settings::CryptoSettings;

    #[test]
    fn transfer_freeze_requires_verified_private_oram_preinstall() {
        let ordinary = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 1,
            to: 2,
            sync: true,
            method: Some(collection::shards::transfer::ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: false,
            private_oram_layout_transition: None,
            filter: None,
        };
        assert!(!private_oram_shard_transfer_active(&HashSet::from([
            ordinary.clone()
        ])));
        assert!(private_oram_shard_transfer_active(&HashSet::from([
            ShardTransfer {
                private_oram_preinstalled: true,
                ..ordinary
            }
        ])));
    }

    #[test]
    fn path_oram_leaf_labels_map_to_heap_bucket_paths() {
        let leaf = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let bucket_ids = bucket_ids_for_path_batch(&[leaf], 3, 15).unwrap();
        assert_eq!(bucket_ids, vec![0, 2, 5, 12]);
    }

    #[test]
    fn path_oram_batch_preserves_fixed_size_bucket_sequence() {
        let left = BASE64URL_NOPAD.encode(&4u64.to_be_bytes());
        let right = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let bucket_ids = bucket_ids_for_path_batch(&[left, right], 3, 15).unwrap();
        assert_eq!(bucket_ids, vec![0, 2, 5, 11, 0, 2, 5, 12]);
    }

    #[test]
    fn private_hnsw_bucket_shape_errors_are_sanitized() {
        let rendered = private_hnsw_bucket_ciphertext_size_error(
            qdrant_sec::PrivateHnswOramError::InvalidManifestField("oram.bucket_size"),
        )
        .to_string();
        assert!(rendered.contains("bucket ciphertext size is invalid"));
        assert!(!rendered.contains("oram.bucket_size"), "{rendered}");

        let leaf = BASE64URL_NOPAD.encode(&0u64.to_be_bytes());
        let rendered = bucket_ids_for_path_batch(&[leaf], 63, 1)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("tree_height is invalid"));
        assert!(!rendered.contains("63"), "{rendered}");

        let leaf = BASE64URL_NOPAD.encode(&0u64.to_be_bytes());
        let sentinel_bucket_count = 987_654_321_u64;
        let rendered = bucket_ids_for_path_batch(&[leaf], 3, sentinel_bucket_count)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket_count does not match tree_height"));
        assert!(
            !rendered.contains(&sentinel_bucket_count.to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn read_path_budget_rejects_duplicate_path_labels() {
        let leaf = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let err = validate_unique_path_labels(&[leaf.clone(), leaf]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate path label"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains(&BASE64URL_NOPAD.encode(&5u64.to_be_bytes())));
    }

    #[test]
    fn read_path_fixed_budget_rejects_padding_mismatch() {
        let valid_padding = PrivateHnswReadPadding {
            requested_paths: 2,
            dummy_paths_included: true,
        };
        validate_private_hnsw_read_fixed_path_budget(valid_padding, 2, 2).unwrap();

        let wrong_requested_paths = PrivateHnswReadPadding {
            requested_paths: 1,
            dummy_paths_included: true,
        };
        let err =
            validate_private_hnsw_read_fixed_path_budget(wrong_requested_paths, 2, 2).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed path budget"), "{rendered}");
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains("1"), "{rendered}");
        assert!(!rendered.contains("2"), "{rendered}");

        let err = validate_private_hnsw_read_fixed_path_budget(valid_padding, 1, 2).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed path budget"), "{rendered}");
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains("1"), "{rendered}");
        assert!(!rendered.contains("2"), "{rendered}");

        let missing_dummy_padding = PrivateHnswReadPadding {
            requested_paths: 2,
            dummy_paths_included: false,
        };
        let err =
            validate_private_hnsw_read_fixed_path_budget(missing_dummy_padding, 2, 2).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed path budget"), "{rendered}");
        assert!(!rendered.contains("dummy"), "{rendered}");
        assert!(!rendered.contains("false"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"));
    }

    #[test]
    fn read_path_label_request_shape_rejects_malformed_values_before_session_lookup() {
        let valid = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let valid_other = BASE64URL_NOPAD.encode(&6u64.to_be_bytes());
        validate_private_hnsw_read_path_label_request_shape(std::slice::from_ref(&valid)).unwrap();
        validate_private_hnsw_read_path_label_request_shape(&[valid.clone(), valid_other]).unwrap();

        let err = validate_private_hnsw_read_path_label_request_shape(&[]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("read_paths request is empty"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_hnsw_oram"));

        let oversized_batch = (0..=PRIVATE_HNSW_ORAM_PATH_BATCH_SIZE_MAX)
            .map(|leaf| BASE64URL_NOPAD.encode(&(leaf as u64).to_be_bytes()))
            .collect::<Vec<_>>();
        let err =
            validate_private_hnsw_read_path_label_request_shape(&oversized_batch).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maximum path batch size"));
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains(&oversized_batch[0]), "{rendered}");

        let err =
            validate_private_hnsw_read_path_label_request_shape(&[valid.clone(), valid.clone()])
                .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate path label"));
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains(&valid), "{rendered}");

        let oversized = format!(
            "{}{}",
            BASE64URL_NOPAD.encode(&5u64.to_be_bytes()),
            "A".repeat(128)
        );
        let err =
            validate_private_hnsw_read_path_label_request_shape(std::slice::from_ref(&oversized))
                .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains(&oversized));

        let malformed = "not-base64!".to_string();
        let err =
            validate_private_hnsw_read_path_label_request_shape(std::slice::from_ref(&malformed))
                .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains(&malformed), "{rendered}");

        for alias_label in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let err = validate_private_hnsw_read_path_label_request_shape(std::slice::from_ref(
                &alias_label.to_string(),
            ))
            .unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("request validation failed"));
            assert!(!rendered.contains("session is missing or expired"));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains(alias_label), "{rendered}");
        }
    }

    #[test]
    fn commit_request_shape_rejects_empty_writeback_before_session_lookup() {
        let updated_bucket = fixture_bucket(0, 43);
        validate_private_hnsw_commit_request_shape(std::slice::from_ref(&updated_bucket)).unwrap();

        let err = validate_private_hnsw_commit_request_shape(&[]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("updated_buckets must contain"));
        assert!(!rendered.contains("session is missing or expired"));
    }

    #[test]
    fn commit_request_shape_rejects_oversized_writeback_before_session_lookup() {
        let buckets = (0..=PRIVATE_HNSW_ORAM_WRITEBACK_BUCKETS_MAX)
            .map(|bucket_id| fixture_bucket(bucket_id as u64, 43))
            .collect::<Vec<_>>();

        let err = validate_private_hnsw_commit_request_shape(&buckets).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maximum writeback bucket batch size"));
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains(&buckets[0].ciphertext), "{rendered}");
        assert!(!rendered.contains(&buckets.len().to_string()), "{rendered}");
    }

    #[test]
    fn commit_request_shape_rejects_duplicate_bucket_before_session_lookup() {
        let bucket = fixture_bucket(0, 43);
        let duplicate = vec![bucket.clone(), bucket];

        let err = validate_private_hnsw_commit_request_shape(&duplicate).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate bucket"));
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains(&duplicate[0].ciphertext), "{rendered}");
    }

    #[test]
    fn commit_request_shape_rejects_malformed_bucket_hash_before_session_lookup() {
        let mut bucket = fixture_bucket(0, 43);
        let sentinel = "hnsw-commit-hash-sentinel";
        bucket.ciphertext_sha256 = sentinel.to_string();

        let err =
            validate_private_hnsw_commit_request_shape(std::slice::from_ref(&bucket)).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ciphertext_sha256"), "{rendered}");
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn commit_request_shape_rejects_malformed_bucket_commitment_before_session_lookup() {
        let mut bucket = fixture_bucket(0, 43);
        let sentinel = "hnsw-commit-commitment-sentinel";
        bucket.bucket_commitment = sentinel.to_string();

        let err =
            validate_private_hnsw_commit_request_shape(std::slice::from_ref(&bucket)).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket_commitment"), "{rendered}");
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn upload_bucket_request_shape_rejects_empty_bucket_set_before_store_lookup() {
        let bucket = fixture_bucket(0, 42);
        validate_private_hnsw_upload_bucket_request_shape(std::slice::from_ref(&bucket)).unwrap();

        let err = validate_private_hnsw_upload_bucket_request_shape(&[]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket upload must contain"));
        assert!(!rendered.contains("manifest"));
        assert!(!rendered.contains("private_hnsw_oram"));
    }

    #[test]
    fn upload_bucket_request_shape_static_limit_matches_max_runtime_tree_height() {
        validate_private_hnsw_upload_bucket_count_shape(PRIVATE_HNSW_ORAM_UPLOAD_BUCKETS_MAX)
            .unwrap();

        let err = validate_private_hnsw_upload_bucket_count_shape(
            PRIVATE_HNSW_ORAM_UPLOAD_BUCKETS_MAX + 1,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maximum bucket batch size"));
        assert!(!rendered.contains(&(PRIVATE_HNSW_ORAM_UPLOAD_BUCKETS_MAX + 1).to_string()));
        assert!(!rendered.contains("private_hnsw_oram"));
    }

    #[test]
    fn upload_bucket_request_shape_rejects_duplicate_bucket_before_store_lookup() {
        let bucket = fixture_bucket(0, 42);
        let duplicate = vec![bucket.clone(), bucket];

        let err = validate_private_hnsw_upload_bucket_request_shape(&duplicate).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate bucket"));
        assert!(!rendered.contains("manifest"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains(&duplicate[0].ciphertext));
    }

    #[test]
    fn upload_bucket_request_shape_rejects_malformed_bucket_hash_before_store_lookup() {
        let mut bucket = fixture_bucket(0, 42);
        let sentinel = "hnsw-upload-hash-sentinel";
        bucket.ciphertext_sha256 = sentinel.to_string();

        let err = validate_private_hnsw_upload_bucket_request_shape(std::slice::from_ref(&bucket))
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ciphertext_sha256"), "{rendered}");
        assert!(!rendered.contains("manifest"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn upload_bucket_request_shape_rejects_malformed_bucket_commitment_before_store_lookup() {
        let mut bucket = fixture_bucket(0, 42);
        let sentinel = "hnsw-upload-commitment-sentinel";
        bucket.bucket_commitment = sentinel.to_string();

        let err = validate_private_hnsw_upload_bucket_request_shape(std::slice::from_ref(&bucket))
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket_commitment"), "{rendered}");
        assert!(!rendered.contains("manifest"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn read_path_labels_reject_oversized_or_malformed_values_without_reflecting_label() {
        let oversized = format!(
            "{}{}",
            BASE64URL_NOPAD.encode(&5u64.to_be_bytes()),
            "A".repeat(128)
        );
        let err = validate_private_hnsw_read_path_labels(std::slice::from_ref(&oversized), 3)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(!rendered.contains(&oversized));

        let malformed = "not-base64!".to_string();
        let err = validate_private_hnsw_read_path_labels(std::slice::from_ref(&malformed), 3)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(!rendered.contains(&malformed), "{rendered}");

        for alias_label in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let err =
                validate_private_hnsw_read_path_labels(&[alias_label.to_string()], 3).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("invalid path label"));
            assert!(!rendered.contains(alias_label), "{rendered}");
        }
    }

    #[test]
    fn path_oram_rejects_out_of_range_leaf() {
        let leaf = BASE64URL_NOPAD.encode(&8u64.to_be_bytes());
        let err = bucket_ids_for_path_batch(&[leaf], 3, 15).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(
            !rendered.contains(&BASE64URL_NOPAD.encode(&8u64.to_be_bytes())),
            "{rendered}"
        );

        let malformed = "qdrant-sec-private-hnsw-path-helper-sentinel".to_string();
        let err = bucket_ids_for_path_batch(std::slice::from_ref(&malformed), 3, 15).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(!rendered.contains(&malformed), "{rendered}");

        for alias_label in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let err = bucket_ids_for_path_batch(&[alias_label.to_string()], 3, 15).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("invalid path label"));
            assert!(!rendered.contains(alias_label), "{rendered}");
        }
    }

    #[test]
    fn result_privacy_runtime_option_rejects_unsupported_value_without_reflecting_value() {
        let unsupported = "tenant-a-private-result-mode-sentinel";
        let instance = CryptoInstanceConfig {
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            materials: HashMap::new(),
            backend_ref: None,
            options: serde_json::json!({
                RESULT_PRIVACY_OPTION: unsupported,
            }),
        };

        let rendered = result_privacy_from_runtime(&instance)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("result privacy option has unsupported value"));
        assert!(!rendered.contains(RESULT_PRIVACY_OPTION), "{rendered}");
        assert!(!rendered.contains(unsupported), "{rendered}");
    }

    #[test]
    fn private_hnsw_instance_errors_do_not_reflect_rule_or_instance_ids() {
        let rule_id = "private_hnsw_rule_secret_sentinel";
        let instance_id = "private_hnsw_instance_secret_sentinel";
        let rule = EncryptionRuleRef {
            id: rule_id.to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec!["text".to_string()],
            },
            instance: instance_id.to_string(),
            binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
        };

        let missing_settings = Settings::new(None).unwrap();
        let rendered = private_hnsw_instance(&missing_settings, &rule)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("missing runtime instance"), "{rendered}");
        assert!(!rendered.contains(rule_id), "{rendered}");
        assert!(!rendered.contains(instance_id), "{rendered}");

        let mut wrong_provider_settings = Settings::new(None).unwrap();
        wrong_provider_settings.crypto.instances.insert(
            instance_id.to_string(),
            CryptoInstanceConfig {
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: serde_json::json!({}),
            },
        );
        let rendered = private_hnsw_instance(&wrong_provider_settings, &rule)
            .unwrap_err()
            .to_string();
        assert!(
            rendered.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
            "{rendered}"
        );
        assert!(!rendered.contains(rule_id), "{rendered}");
        assert!(!rendered.contains(instance_id), "{rendered}");
    }

    #[test]
    fn external_recovery_owner_key_resolution_validates_instance_provider_and_key() {
        let instance_id = "docs_text_private_hnsw";
        let signing_key_id = "tenant-a/private-hnsw-signing-v1";
        let rule = EncryptionRuleRef {
            id: "docs_text_private_hnsw".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec!["text".to_string()],
            },
            instance: instance_id.to_string(),
            binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
        };

        let missing_settings = Settings::new(None).unwrap();
        let rendered = resolve_private_hnsw_external_recovery_owner_public_key(
            &missing_settings,
            &rule,
            signing_key_id,
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("missing runtime instance"), "{rendered}");

        let mut settings = Settings::new(None).unwrap();
        settings.crypto.instances.insert(
            instance_id.to_string(),
            CryptoInstanceConfig {
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: serde_json::json!({}),
            },
        );
        let rendered = resolve_private_hnsw_external_recovery_owner_public_key(
            &settings,
            &rule,
            signing_key_id,
        )
        .unwrap_err()
        .to_string();
        assert!(
            rendered.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
            "{rendered}"
        );

        settings.crypto.instances.insert(
            instance_id.to_string(),
            CryptoInstanceConfig {
                provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: serde_json::json!({
                    SIGNATURE_PUBLIC_KEYS_OPTION: {
                        signing_key_id: BASE64URL_NOPAD.encode(&[7; 32]),
                    },
                }),
            },
        );
        let rendered = resolve_private_hnsw_external_recovery_owner_public_key(
            &settings,
            &rule,
            "tenant-a/missing-private-hnsw-signing-key",
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("signature key id is not configured"));
        assert_eq!(
            resolve_private_hnsw_external_recovery_owner_public_key(
                &settings,
                &rule,
                signing_key_id,
            )
            .unwrap(),
            [7; 32]
        );
    }

    #[test]
    fn manifest_context_missing_vector_error_does_not_reflect_vector_name() {
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let config = recovered_snapshot_config(uuid, &manifest);
        let instance = settings
            .crypto
            .instances
            .get("docs_text_private_hnsw")
            .unwrap();
        let missing_vector = "private-hnsw-runtime-vector-secret";

        let err = match manifest_context_from_runtime(
            &config.params,
            &uuid.to_string(),
            missing_vector,
            instance,
            false,
        ) {
            Ok(_) => panic!("missing private HNSW vector must fail runtime context validation"),
            Err(err) => err,
        };
        let rendered = err.to_string();

        assert!(
            rendered.contains("not configured as a dense vector"),
            "{rendered}"
        );
        assert!(!rendered.contains(missing_vector), "{rendered}");
    }

    fn fixture_bucket(bucket_id: u64, epoch: u64) -> PrivateHnswOramBucket {
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&[bucket_id as u8]),
            ciphertext_sha256: BASE64URL_NOPAD.encode(&[bucket_id as u8; 32]),
            bucket_commitment: BASE64URL_NOPAD.encode(&[bucket_id as u8; 32]),
        }
    }

    fn fixture_readable_bucket(
        bucket_id: u64,
        epoch: u64,
        domain: u8,
        bucket_commitment: &str,
    ) -> PrivateHnswOramBucket {
        let ciphertext = vec![domain, bucket_id as u8];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256,
            bucket_commitment: bucket_commitment.to_string(),
        }
    }

    #[test]
    fn initial_bucket_upload_requires_complete_orderable_bucket_set() {
        let buckets = vec![fixture_bucket(1, 42), fixture_bucket(0, 42)];
        let commitments = ordered_initial_bucket_commitments(&buckets, 42, 2).unwrap();
        assert_eq!(
            commitments,
            vec![
                BASE64URL_NOPAD.encode(&[0; 32]),
                BASE64URL_NOPAD.encode(&[1; 32])
            ]
        );

        let err = ordered_initial_bucket_commitments(&buckets[..1], 42, 2).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("configured bucket count"));
        assert!(!rendered.contains("2"), "{rendered}");

        let err = ordered_initial_bucket_commitments(
            &[fixture_bucket(0, 42), fixture_bucket(0, 42)],
            42,
            2,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate bucket"));
        assert!(!rendered.contains("0"), "{rendered}");

        let err = ordered_initial_bucket_commitments(&[fixture_bucket(0, 41)], 42, 1).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("stale epoch"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(!rendered.contains("41"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");

        let err = ordered_initial_bucket_commitments(
            &[fixture_bucket(0, 42), fixture_bucket(2, 42)],
            42,
            2,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("2"), "{rendered}");
    }

    #[test]
    fn read_proof_bucket_commitment_mismatch_rejects_without_ciphertext_leak() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        let bucket = fixture_bucket(0, 42);
        let root =
            PrivateHnswOramStore::merkle_root_for_commitments(&[bucket.bucket_commitment.clone()])
                .unwrap();
        store
            .write_merkle_tree_from_commitments(
                42,
                root.clone(),
                vec![bucket.bucket_commitment.clone()],
            )
            .unwrap();

        let mut proof = store.read_merkle_path_batch(&[0], 42, &root, 1).unwrap();
        proof.leaves[0].leaf_hash = BASE64URL_NOPAD.encode(&[99; 32]);

        let err = ensure_private_hnsw_read_proof_matches_buckets(&proof, &[bucket.clone()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("bucket/proof consistency validation failed"));
        assert!(!err.contains(&bucket.ciphertext));

        let sentinel_bucket_id = 987_654_321_u64;
        let mut wrong_bucket_id_proof = store.read_merkle_path_batch(&[0], 42, &root, 1).unwrap();
        wrong_bucket_id_proof.leaves[0].bucket_id = sentinel_bucket_id;
        let err = ensure_private_hnsw_read_proof_matches_buckets(
            &wrong_bucket_id_proof,
            &[bucket.clone()],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("bucket/proof consistency validation failed"));
        assert!(!err.contains(&bucket.ciphertext));
        assert!(!err.contains(&bucket.bucket_commitment));
        assert!(!err.contains(&sentinel_bucket_id.to_string()));

        let err = ensure_private_hnsw_read_proof_matches_buckets(&proof, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("bucket/proof consistency validation failed"));
        assert!(!err.contains(&bucket.ciphertext));
        assert!(!err.contains(&bucket.bucket_commitment));
        assert!(!err.contains(&root));
    }

    #[test]
    fn sdk_packaged_initial_upload_bundle_matches_server_contract() {
        let collection_id = "collection-uuid-1";
        let vector_name = "text";
        let key_id = "tenant-a/vector-private-rk";
        let signing_key_id = "tenant-a/private-hnsw-signing-v1";
        let rk_epoch = 7;
        let config = PrivateHnswOramClientConfig {
            tree_height: 1,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 2,
        };
        let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes([9; 32]),
            collection_id,
            vector_name,
            key_id,
            rk_epoch,
        )
        .unwrap();
        let base_context = PrivateHnswBucketAeadBaseContext {
            collection_id,
            vector_name,
            key_id,
            rk_id: key_id,
            rk_epoch,
        };
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![0.0, 1.0],
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
            base_context,
            42,
            &plaintext_build,
            config,
        )
        .unwrap();
        let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
            PrivateHnswManifestBuildContext {
                collection_id,
                vector_name,
                key_id,
                rk_id: key_id,
                rk_epoch,
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
                    path_batch_size: 1,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 2,
                    paths_per_round: 1,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: signing_key_id,
                created_at_unix: 1_770_000_000,
            },
            &encrypted_build,
        )
        .unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest).unwrap();
        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                expected_collection_id: collection_id,
                expected_vector_name: vector_name,
                expected_key_id: key_id,
                expected_rk_id: key_id,
                min_rk_epoch: rk_epoch,
                max_rk_epoch: rk_epoch,
                expected_dim: 2,
                expected_distance: DistanceKind::Euclid,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: signing_key_id,
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap();

        let leaf_commitments = validate_initial_private_hnsw_upload_bundle(
            &manifest,
            encrypted_build.index_epoch,
            &encrypted_build.root_hash,
            &encrypted_build.buckets,
        )
        .unwrap();
        assert_eq!(leaf_commitments.len() as u64, manifest.bucket_count);
        assert_eq!(
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap(),
            manifest.root_hash,
        );
        for bucket in &encrypted_build.buckets {
            validate_bucket_ciphertext_fixed_size(bucket, &manifest).unwrap();
        }
        validate_private_hnsw_read_bucket_ciphertexts_fixed_size(
            &manifest,
            &encrypted_build.buckets,
        )
        .unwrap();

        let mut short_ciphertext_bucket = encrypted_build.buckets[0].clone();
        let mut short_raw = BASE64URL_NOPAD
            .decode(short_ciphertext_bucket.ciphertext.as_bytes())
            .unwrap();
        short_raw.pop().unwrap();
        short_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(&short_raw);
        short_ciphertext_bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&short_raw).as_ref());
        let err =
            validate_bucket_ciphertext_fixed_size(&short_ciphertext_bucket, &manifest).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(
            !rendered.contains(&short_ciphertext_bucket.ciphertext),
            "{rendered}"
        );
        let rendered = validate_private_hnsw_read_bucket_ciphertexts_fixed_size(
            &manifest,
            std::slice::from_ref(&short_ciphertext_bucket),
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(
            !rendered.contains(&short_ciphertext_bucket.ciphertext),
            "{rendered}"
        );
        let rendered = validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
            &manifest,
            std::slice::from_ref(&short_ciphertext_bucket),
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("bucket ciphertext validation failed"));
        assert!(!rendered.contains("fixed ciphertext size"), "{rendered}");
        assert!(
            !rendered.contains(&short_ciphertext_bucket.ciphertext),
            "{rendered}"
        );

        let mut oversized_ciphertext_bucket = encrypted_build.buckets[0].clone();
        oversized_ciphertext_bucket
            .ciphertext
            .push_str("private-hnsw-oversized-ciphertext-sentinel");
        let rendered =
            validate_bucket_ciphertext_fixed_size(&oversized_ciphertext_bucket, &manifest)
                .unwrap_err()
                .to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(
            !rendered.contains("private-hnsw-oversized-ciphertext-sentinel"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&oversized_ciphertext_bucket.ciphertext),
            "{rendered}"
        );

        let mut wrong_commitment_buckets = encrypted_build.buckets.clone();
        wrong_commitment_buckets[0].bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        let err = validate_initial_private_hnsw_upload_bundle(
            &manifest,
            encrypted_build.index_epoch,
            &encrypted_build.root_hash,
            &wrong_commitment_buckets,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("bucket commitment context mismatch")
        );
        assert!(!err.to_string().contains("initial upload"));

        let first_leaf = encode_private_hnsw_oram_leaf_label(0, config.tree_height).unwrap();
        assert_eq!(
            bucket_ids_for_path_batch(
                std::slice::from_ref(&first_leaf),
                manifest.oram.tree_height,
                manifest.bucket_count
            )
            .unwrap(),
            vec![0, 1],
        );
        let second_leaf = encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap();
        assert_eq!(
            bucket_ids_for_path_batch(
                &[first_leaf, second_leaf],
                manifest.oram.tree_height,
                manifest.bucket_count
            )
            .unwrap(),
            vec![0, 1, 0, 2],
        );
    }

    #[test]
    fn distributed_epoch_operations_require_consensus_backed_cas() {
        assert!(validate_private_hnsw_oram_single_node_epoch_mode(false).is_ok());
        assert!(validate_private_hnsw_oram_upload_epoch_mode(false, false).is_ok());
        assert!(validate_private_hnsw_oram_upload_epoch_mode(false, true).is_ok());
        assert!(validate_private_hnsw_oram_upload_epoch_mode(true, true).is_ok());

        let err = validate_private_hnsw_oram_single_node_epoch_mode(true).unwrap_err();
        assert!(err.to_string().contains("consensus-backed epoch/root CAS"));
        let err = validate_private_hnsw_oram_upload_epoch_mode(true, false).unwrap_err();
        assert!(err.to_string().contains("consensus-backed epoch/root CAS"));
    }

    #[test]
    fn session_lease_expiry_fails_closed_on_overflow() {
        assert_eq!(
            session_lease_expires_unix(10).unwrap(),
            10 + SESSION_LEASE_SECS
        );
        let err = session_lease_expires_unix(u64::MAX).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lease calculation overflowed"));
        assert!(!rendered.contains(&u64::MAX.to_string()), "{rendered}");
    }

    #[test]
    fn session_id_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_private_hnsw_session_id_shape("missing-session-id-sentinel").unwrap();
        validate_private_hnsw_session_id_shape(&uuid::Uuid::new_v4().to_string()).unwrap();

        let oversized = "s".repeat(PRIVATE_HNSW_ORAM_SESSION_ID_MAX_LEN + 1);
        let err = validate_private_hnsw_session_id_shape(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session_id is invalid"));
        assert!(!rendered.contains(&oversized));

        let malformed = "bad/session-id";
        let err = validate_private_hnsw_session_id_shape(malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session_id is invalid"));
        assert!(!rendered.contains(malformed));

        for alias_session_id in [
            "stashBackup/session",
            "stashBackup.json/session",
            "stashBackups/session",
            "stashBackups.json/session",
            "clientStateCiphertextHash/session",
            "client_state_ciphertext_hash.bin/session",
            "client_state_ciphertext_hash.json/session",
            "client_state_ciphertext_hashes.bin/session",
            "client_state_ciphertext_hashes.json/session",
            "client_state_ciphertext_sha256.bin/session",
            "client_state_ciphertext_sha256.json/session",
            "client_state_ciphertexts_sha256.bin/session",
            "client_state_ciphertexts_sha256.json/session",
            "encrypted.client.state/session",
            "encrypted_client_state_snapshot/session",
            "encrypted_client_state_ciphertext_hash.bin/session",
            "encrypted_client_state_ciphertext_hash.json/session",
            "encrypted_client_state_ciphertext_hashes.bin/session",
            "encrypted_client_state_ciphertext_hashes.json/session",
            "encrypted_client_state_ciphertext_sha256.bin/session",
            "encrypted_client_state_ciphertext_sha256.json/session",
            "encrypted_client_state_ciphertexts_sha256.bin/session",
            "encrypted_client_state_ciphertexts_sha256.json/session",
            "oramPositionMapBackup/session",
            "state_ciphertext_hash.bin/session",
            "state_ciphertext_hash.json/session",
            "state_ciphertext_hashes.bin/session",
            "state_ciphertext_hashes.json/session",
            "state_ciphertext_sha256.bin/session",
            "state_ciphertext_sha256.json/session",
            "state_ciphertexts_sha256.bin/session",
            "state_ciphertexts_sha256.json/session",
            "tokenMapBackups/session",
            "token_map_backups/session",
            "token_position_map_backups/session",
        ] {
            let err = validate_private_hnsw_session_id_shape(alias_session_id).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("session_id is invalid"));
            assert!(!rendered.contains(alias_session_id));
        }
    }

    #[test]
    fn client_id_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_private_hnsw_client_id_shape("tenant-a/sdk.instance_1@host:1").unwrap();

        let oversized = format!(
            "client-id-sentinel{}",
            "x".repeat(PRIVATE_HNSW_ORAM_CLIENT_ID_MAX_LEN)
        );
        let err = validate_private_hnsw_client_id_shape(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("client_id must be non-empty and at most 256 bytes"));
        assert!(!rendered.contains("client-id-sentinel"));

        let malformed = "client-id!sentinel";
        let err = validate_private_hnsw_client_id_shape(malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("client_id is invalid"));
        assert!(!rendered.contains(malformed));

        for alias_client_id in [
            "client_state_ciphertext!sentinel",
            "client_state_ciphertext_hash.bin!sentinel",
            "client_state_ciphertext_hash.json!sentinel",
            "client_state_ciphertext_hashes.bin!sentinel",
            "client_state_ciphertext_hashes.json!sentinel",
            "client_state_ciphertext_sha256.bin!sentinel",
            "client_state_ciphertext_sha256.json!sentinel",
            "client_state_ciphertexts_sha256.bin!sentinel",
            "client_state_ciphertexts_sha256.json!sentinel",
            "clientStateCiphertextHash!sentinel",
            "encrypted.client.state!sentinel",
            "encrypted_client_state_snapshot!sentinel",
            "encrypted_client_state_ciphertext_hash.bin!sentinel",
            "encrypted_client_state_ciphertext_hash.json!sentinel",
            "encrypted_client_state_ciphertext_hashes.bin!sentinel",
            "encrypted_client_state_ciphertext_hashes.json!sentinel",
            "encrypted_client_state_ciphertext_sha256.bin!sentinel",
            "encrypted_client_state_ciphertext_sha256.json!sentinel",
            "encrypted_client_state_ciphertexts_sha256.bin!sentinel",
            "encrypted_client_state_ciphertexts_sha256.json!sentinel",
            "oramPositionMapBackup!sentinel",
            "stashBackup.json!sentinel",
            "stashBackups.json!sentinel",
            "state_ciphertext_hash.bin!sentinel",
            "state_ciphertext_hash.json!sentinel",
            "state_ciphertext_hashes.bin!sentinel",
            "state_ciphertext_hashes.json!sentinel",
            "state_ciphertext_sha256.bin!sentinel",
            "state_ciphertext_sha256.json!sentinel",
            "state_ciphertexts_sha256.bin!sentinel",
            "state_ciphertexts_sha256.json!sentinel",
            "tokenMapBackups!sentinel",
            "token_map_backups!sentinel",
            "token_position_map_backups!sentinel",
        ] {
            let err = validate_private_hnsw_client_id_shape(alias_client_id).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("client_id is invalid"));
            assert!(!rendered.contains(alias_client_id));
        }
    }

    #[test]
    fn root_hash_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_root_hash_string(&BASE64URL_NOPAD.encode(&[42; 32]), "root_hash").unwrap();

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[42; 32]), "A".repeat(64));
        let err = validate_root_hash_string(&oversized, "root_hash").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("root_hash must encode 32 bytes"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[42; 32]);
        malformed.replace_range(0..1, "!");
        let err = validate_root_hash_string(&malformed, "root_hash").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("root_hash is not base64url"));
        assert!(!rendered.contains(&malformed));

        for alias_root_hash in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let err = validate_root_hash_string(alias_root_hash, "root_hash").unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("root_hash"));
            assert!(!rendered.contains(alias_root_hash), "{rendered}");
        }
    }

    #[test]
    fn client_signature_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        })
        .unwrap();

        let unsupported_alg = "rsa-pss-hnsw-client-signature-sentinel";
        let err = validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: unsupported_alg.to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        })
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature algorithm must be ed25519"));
        assert!(!rendered.contains(unsupported_alg), "{rendered}");

        let malformed_key_id = "tenant-a/private-hnsw-signing-v1!sentinel";
        let err = validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: malformed_key_id.to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        })
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key_id is invalid"));
        assert!(!rendered.contains(malformed_key_id), "{rendered}");

        for alias_key_id in [
            "encrypted.client.state!sentinel",
            "client_state_ciphertext_hash.bin!sentinel",
            "client_state_ciphertext_hash.json!sentinel",
            "client_state_ciphertext_hashes.bin!sentinel",
            "client_state_ciphertext_hashes.json!sentinel",
            "client_state_ciphertext_sha256.bin!sentinel",
            "client_state_ciphertext_sha256.json!sentinel",
            "encrypted_client_state_ciphertext_hash.bin!sentinel",
            "encrypted_client_state_ciphertext_hash.json!sentinel",
            "encrypted_client_state_ciphertext_hashes.bin!sentinel",
            "encrypted_client_state_ciphertext_hashes.json!sentinel",
            "encrypted_client_state_ciphertext_sha256.bin!sentinel",
            "encrypted_client_state_ciphertext_sha256.json!sentinel",
            "stashBackup.json!sentinel",
            "state_ciphertext_hash.bin!sentinel",
            "state_ciphertext_hash.json!sentinel",
            "state_ciphertext_hashes.bin!sentinel",
            "state_ciphertext_hashes.json!sentinel",
            "state_ciphertext_sha256.bin!sentinel",
            "state_ciphertext_sha256.json!sentinel",
        ] {
            let err = validate_client_signature_shape(&PrivateHnswClientSignature {
                alg: "ed25519".to_string(),
                key_id: alias_key_id.to_string(),
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            })
            .unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("signature key_id is invalid"));
            assert!(!rendered.contains(alias_key_id), "{rendered}");
        }

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[7; 64]), "A".repeat(64));
        let err = validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: oversized.clone(),
        })
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature must encode 64 bytes"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[7; 64]);
        malformed.replace_range(0..1, "!");
        let err = validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: malformed.clone(),
        })
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature is not base64url"));
        assert!(!rendered.contains(&malformed));

        for alias_sig in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let err = validate_client_signature_shape(&PrivateHnswClientSignature {
                alg: "ed25519".to_string(),
                key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
                sig: alias_sig.to_string(),
            })
            .unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("signature"));
            assert!(!rendered.contains(alias_sig), "{rendered}");
        }
    }

    #[test]
    fn signature_public_key_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        let signing_key_id = "tenant-a/private-hnsw-signing-v1";
        let valid = BASE64URL_NOPAD.encode(&[7; 32]);
        decode_signature_public_key(&valid).unwrap();
        let instance = CryptoInstanceConfig {
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            materials: HashMap::new(),
            backend_ref: None,
            options: serde_json::json!({
                SIGNATURE_PUBLIC_KEYS_OPTION: {
                    signing_key_id: valid,
                },
            }),
        };
        assert_eq!(
            signature_public_key(&instance, signing_key_id).unwrap(),
            [7; 32]
        );

        let empty_registry_instance = CryptoInstanceConfig {
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            materials: HashMap::new(),
            backend_ref: None,
            options: serde_json::json!({
                SIGNATURE_PUBLIC_KEYS_OPTION: {},
            }),
        };
        let rendered = signature_public_keys(&empty_registry_instance)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("must configure signature_public_keys"));
        assert!(!rendered.contains("{}"), "{rendered}");

        let missing_key_id = "tenant-a/missing-hnsw-key-sentinel";
        let err = signature_public_key(&instance, missing_key_id).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key id is not configured"));
        assert!(!rendered.contains(missing_key_id), "{rendered}");

        for missing_alias_key_id in [
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let err = signature_public_key(&instance, missing_alias_key_id).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("signature key id is not configured"));
            assert!(!rendered.contains(missing_alias_key_id), "{rendered}");
        }

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[7; 32]), "A".repeat(64));
        let err = decode_signature_public_key(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("public key must be 32 bytes"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[7; 32]);
        malformed.replace_range(0..1, "!");
        let err = decode_signature_public_key(&malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("public key is not base64url"));
        assert!(!rendered.contains(&malformed));
    }

    #[test]
    fn manifest_signature_owner_key_preflight_rejects_non_owner_key() {
        let manifest = fixture_session("session-1", 20).manifest;
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v3".to_string(),
            sig: BASE64URL_NOPAD.encode(&[9; 64]),
        };

        let err =
            validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key_id does not match manifest owner_signing_key_id"));
        assert!(!rendered.contains(&signature.key_id));
        assert!(!rendered.contains(&manifest.owner_signing_key_id));
        assert!(!rendered.contains("not configured"));
    }

    #[test]
    fn private_hnsw_error_mapping_redacts_qdrant_sec_fields() {
        let err = private_hnsw_error(qdrant_sec::PrivateHnswOramError::InvalidManifestField(
            "secret_manifest_field",
        ));
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM request validation failed"));
        assert!(!rendered.contains("secret_manifest_field"), "{rendered}");

        let err = private_hnsw_error(qdrant_sec::PrivateHnswOramError::InvalidManifestField(
            "encrypted_client_state_ciphertext_hash",
        ));
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM request validation failed"));
        assert!(
            !rendered.contains("encrypted_client_state_ciphertext_hash"),
            "{rendered}"
        );

        let err = private_hnsw_error(qdrant_sec::PrivateHnswOramError::InvalidManifestField(
            "encrypted_client_state_ciphertext_sha256",
        ));
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM request validation failed"));
        assert!(
            !rendered.contains("encrypted_client_state_ciphertext_sha256"),
            "{rendered}"
        );
    }

    #[test]
    fn common_debug_redacts_private_hnsw_session_and_read_values() {
        let mut session = fixture_session("hnsw-common-session-sentinel", 20);
        session._client_id = "hnsw-common-client-sentinel".to_string();
        session.collection_id = "hnsw-common-collection-sentinel".to_string();
        session.manifest.collection_id = session.collection_id.clone();
        session.vector_name = "hnsw-common-vector-sentinel".to_string();
        session.manifest.vector_name = session.vector_name.clone();
        session.collection_path =
            std::path::PathBuf::from("/tmp/qdrant-private-hnsw-common-path-sentinel");
        let root_hash = session.root_hash.clone();
        let response = session.response();
        let bucket = fixture_readable_bucket(0, session.index_epoch, 21, &root_hash);
        let ciphertext = bucket.ciphertext.clone();
        let read_response = PrivateHnswReadPathsResponse {
            index_epoch: session.index_epoch,
            root_hash: root_hash.clone(),
            buckets: vec![bucket],
            proof: PrivateHnswReadProof {
                kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
                value: "hnsw-common-proof-sentinel".to_string(),
            },
        };
        let client_signature = PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "hnsw-common-client-signature-key-sentinel".to_string(),
            sig: "hnsw-common-client-signature-body-sentinel".to_string(),
        };
        let manifest_record = PrivateHnswManifestRecord {
            manifest: session.manifest.clone(),
            signature: PrivateHnswOramSignature {
                alg: "ed25519".to_string(),
                key_id: "hnsw-common-manifest-signature-key-sentinel".to_string(),
                sig: "hnsw-common-manifest-signature-body-sentinel".to_string(),
            },
        };
        let padding = PrivateHnswReadPadding {
            requested_paths: 77,
            dummy_paths_included: false,
        };

        let rendered = [
            format!("{session:?}"),
            format!("{response:?}"),
            format!("{read_response:?}"),
            format!("{client_signature:?}"),
            format!("{manifest_record:?}"),
            format!("{padding:?}"),
        ]
        .join("\n");
        let session_debug = format!("{session:?}");
        for leaked_session_value in [
            "PrivateHnswOramManifest".to_string(),
            format!("bucket_count: {}", session.bucket_count),
            format!("tree_height: {}", session.tree_height),
            format!("path_batch_size: {}", session.path_batch_size),
            format!(
                "max_bucket_ciphertext_bytes: {}",
                session.max_bucket_ciphertext_bytes
            ),
        ] {
            assert!(
                !session_debug.contains(&leaked_session_value),
                "{session_debug}"
            );
        }
        let response_debug = format!("{response:?}");
        for leaked_response_value in [
            "PrivateHnswOramManifest".to_string(),
            format!("bucket_count: {}", response.manifest.bucket_count),
            format!("tree_height: {}", response.manifest.oram.tree_height),
            format!(
                "path_batch_size: {}",
                response.manifest.oram.path_batch_size
            ),
        ] {
            assert!(
                !response_debug.contains(&leaked_response_value),
                "{response_debug}"
            );
        }
        for leaked in [
            "hnsw-common-session-sentinel",
            "hnsw-common-client-sentinel",
            "hnsw-common-collection-sentinel",
            "hnsw-common-vector-sentinel",
            "qdrant-private-hnsw-common-path-sentinel",
            root_hash.as_str(),
            ciphertext.as_str(),
            "hnsw-common-proof-sentinel",
            "hnsw-common-client-signature-key-sentinel",
            "hnsw-common-client-signature-body-sentinel",
            "hnsw-common-manifest-signature-key-sentinel",
            "hnsw-common-manifest-signature-body-sentinel",
            "client_state_ciphertext",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_sha256",
            "position_map_backup",
            "position_map_backups",
            "payload_fetch_token",
            "payload.fetch.token",
            "stashBackup",
            "stashBackups",
            "77",
            "false",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
        let read_response_debug = format!("{read_response:?}");
        assert!(
            !read_response_debug.contains("bucket_count: 1"),
            "{read_response_debug}"
        );
        let manifest_record_debug = format!("{manifest_record:?}");
        for leaked_record_value in [
            "PrivateHnswOramManifest".to_string(),
            format!("bucket_count: {}", manifest_record.manifest.bucket_count),
            format!("tree_height: {}", manifest_record.manifest.oram.tree_height),
            format!(
                "path_batch_size: {}",
                manifest_record.manifest.oram.path_batch_size
            ),
        ] {
            assert!(
                !manifest_record_debug.contains(&leaked_record_value),
                "{manifest_record_debug}"
            );
        }
    }

    #[test]
    fn signature_shape_errors_do_not_reflect_submitted_values() {
        let unsupported_alg = "rsa-pss-hnsw-signature-sentinel";
        let rendered = private_hnsw_error(
            validate_private_hnsw_oram_manifest_signature_shape(&PrivateHnswOramSignature {
                alg: unsupported_alg.to_string(),
                key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("signature algorithm must be ed25519"));
        assert!(!rendered.contains(unsupported_alg), "{rendered}");

        let malformed_key_id = "tenant-a/private-hnsw-signing-v1!sentinel";
        let rendered = private_hnsw_error(
            validate_private_hnsw_oram_manifest_signature_shape(&PrivateHnswOramSignature {
                alg: "ed25519".to_string(),
                key_id: malformed_key_id.to_string(),
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(malformed_key_id), "{rendered}");

        for alias_key_id in [
            "encrypted.client.state!sentinel",
            "client_state_ciphertext_hash.bin!sentinel",
            "client_state_ciphertext_hash.json!sentinel",
            "client_state_ciphertext_hashes.bin!sentinel",
            "client_state_ciphertext_hashes.json!sentinel",
            "client_state_ciphertext_sha256.bin!sentinel",
            "client_state_ciphertext_sha256.json!sentinel",
            "encrypted_client_state_ciphertext_hash.bin!sentinel",
            "encrypted_client_state_ciphertext_hash.json!sentinel",
            "encrypted_client_state_ciphertext_hashes.bin!sentinel",
            "encrypted_client_state_ciphertext_hashes.json!sentinel",
            "encrypted_client_state_ciphertext_sha256.bin!sentinel",
            "encrypted_client_state_ciphertext_sha256.json!sentinel",
            "stashBackup.json!sentinel",
            "state_ciphertext_hash.bin!sentinel",
            "state_ciphertext_hash.json!sentinel",
            "state_ciphertext_hashes.bin!sentinel",
            "state_ciphertext_hashes.json!sentinel",
            "state_ciphertext_sha256.bin!sentinel",
            "state_ciphertext_sha256.json!sentinel",
        ] {
            let rendered = private_hnsw_error(
                validate_private_hnsw_oram_manifest_signature_shape(&PrivateHnswOramSignature {
                    alg: "ed25519".to_string(),
                    key_id: alias_key_id.to_string(),
                    sig: BASE64URL_NOPAD.encode(&[7; 64]),
                })
                .unwrap_err(),
            )
            .to_string();
            assert!(rendered.contains("request validation failed"));
            assert!(!rendered.contains(alias_key_id), "{rendered}");
        }

        let oversized_signature = format!("{}{}", BASE64URL_NOPAD.encode(&[7; 64]), "A".repeat(64));
        let rendered = private_hnsw_error(
            validate_private_hnsw_oram_manifest_signature_shape(&PrivateHnswOramSignature {
                alg: "ed25519".to_string(),
                key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
                sig: oversized_signature.clone(),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(&oversized_signature), "{rendered}");

        let mut malformed_signature = BASE64URL_NOPAD.encode(&[7; 64]);
        malformed_signature.replace_range(0..1, "!");
        let rendered = private_hnsw_error(
            validate_private_hnsw_oram_manifest_signature_shape(&PrivateHnswOramSignature {
                alg: "ed25519".to_string(),
                key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
                sig: malformed_signature.clone(),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(&malformed_signature), "{rendered}");

        for alias_signature in [
            "encrypted.client.state",
            "encrypted.client.state.json",
            "encrypted.client.state.snapshot",
            "encrypted.client.state.snapshot.json",
            "client_state_ciphertext_hash.bin",
            "client_state_ciphertext_hash.json",
            "client_state_ciphertext_hashes.bin",
            "client_state_ciphertext_hashes.json",
            "client_state_ciphertext_sha256.bin",
            "client_state_ciphertext_sha256.json",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_hashes.bin",
            "encrypted_client_state_ciphertext_hashes.json",
            "encrypted_client_state_ciphertext_sha256.bin",
            "encrypted_client_state_ciphertext_sha256.json",
            "stashBackup.json",
            "state_ciphertext_hash.bin",
            "state_ciphertext_hash.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
            "state_ciphertext_sha256.bin",
            "state_ciphertext_sha256.json",
        ] {
            let rendered = private_hnsw_error(
                validate_private_hnsw_oram_manifest_signature_shape(&PrivateHnswOramSignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
                    sig: alias_signature.to_string(),
                })
                .unwrap_err(),
            )
            .to_string();
            assert!(rendered.contains("request validation failed"));
            assert!(!rendered.contains(alias_signature), "{rendered}");
        }
    }

    #[test]
    fn private_hnsw_store_error_mapping_redacts_store_details() {
        let sentinels = [
            "qdrant-sec-private-hnsw-store-detail-sentinel",
            "private_hnsw_oram/text/buckets/00000000.bucket",
            "private-hnsw-bucket-ciphertext-sentinel",
            "private_hnsw_oram/text/clientStateSnapshot.json",
            "private_hnsw_oram/text/clientStateSnapshots.json",
            "private_hnsw_oram/text/client.state.snapshot.json",
            "private_hnsw_oram/text/client_state_snapshot.bin",
            "private_hnsw_oram/text/client_state_snapshot.json",
            "private_hnsw_oram/text/client_state_snapshots.json",
            "private_hnsw_oram/text/client.state.snapshots.json",
            "private_hnsw_oram/text/client_state_ciphertext_hash.bin",
            "private_hnsw_oram/text/client_state_ciphertext_hash.json",
            "private_hnsw_oram/text/client_state_ciphertext_hashes.bin",
            "private_hnsw_oram/text/client_state_ciphertext_hashes.json",
            "private_hnsw_oram/text/client_state_ciphertext_sha256.bin",
            "private_hnsw_oram/text/client_state_ciphertext_sha256.json",
            "private_hnsw_oram/text/client_state_ciphertexts_sha256.bin",
            "private_hnsw_oram/text/client_state_ciphertexts_sha256.json",
            "private_hnsw_oram/text/encryptedClientStateSnapshot.json",
            "private_hnsw_oram/text/encryptedClientStateSnapshots.json",
            "private_hnsw_oram/text/encrypted.client.state.json",
            "private_hnsw_oram/text/encrypted.client.state.snapshot.json",
            "private_hnsw_oram/text/encrypted_client_state_snapshot.bin",
            "private_hnsw_oram/text/encrypted_client_state_snapshot.json",
            "private_hnsw_oram/text/encrypted_client_state_snapshots.json",
            "private_hnsw_oram/text/encrypted.client.state.snapshots.json",
            "private_hnsw_oram/text/encrypted_client_state_ciphertext_hash.bin",
            "private_hnsw_oram/text/encrypted_client_state_ciphertext_hash.json",
            "private_hnsw_oram/text/encrypted_client_state_ciphertext_hashes.bin",
            "private_hnsw_oram/text/encrypted_client_state_ciphertext_hashes.json",
            "private_hnsw_oram/text/encrypted_client_state_ciphertext_sha256.bin",
            "private_hnsw_oram/text/encrypted_client_state_ciphertext_sha256.json",
            "private_hnsw_oram/text/encrypted_client_state_ciphertexts_sha256.bin",
            "private_hnsw_oram/text/encrypted_client_state_ciphertexts_sha256.json",
            "private_hnsw_oram/text/state_ciphertext_hash.bin",
            "private_hnsw_oram/text/state_ciphertext_hash.json",
            "private_hnsw_oram/text/state_ciphertext_hashes.bin",
            "private_hnsw_oram/text/state_ciphertext_hashes.json",
            "private_hnsw_oram/text/state_ciphertext_sha256.bin",
            "private_hnsw_oram/text/state_ciphertext_sha256.json",
            "private_hnsw_oram/text/stateCiphertextSha256.json",
            "private_hnsw_oram/text/state_ciphertexts_sha256.bin",
            "private_hnsw_oram/text/state_ciphertexts_sha256.json",
            "private_hnsw_oram/text/oramPositionMapBackup.json",
            "private_hnsw_oram/text/oramPositionMapBackups.json",
            "private_hnsw_oram/text/oram_position_map_backup.json",
            "private_hnsw_oram/text/oram_position_map_backups.json",
            "private_hnsw_oram/text/positionMapBackup.json",
            "private_hnsw_oram/text/positionMapBackups.json",
            "private_hnsw_oram/text/position_map_backup.json",
            "private_hnsw_oram/text/position_map_backups.json",
            "private_hnsw_oram/text/tokenPositionMapBackup.json",
            "private_hnsw_oram/text/tokenPositionMapBackups.json",
            "private_hnsw_oram/text/tokenMapBackup.json",
            "private_hnsw_oram/text/tokenMapBackups.json",
            "private_hnsw_oram/text/token.map.backup.json",
            "private_hnsw_oram/text/token.map.backups.json",
            "private_hnsw_oram/text/token_map_backup.json",
            "private_hnsw_oram/text/token_map_backups.json",
            "private_hnsw_oram/text/token.position.map.backup.json",
            "private_hnsw_oram/text/token.position.map.backups.json",
            "private_hnsw_oram/text/token_position_map_backup.json",
            "private_hnsw_oram/text/token_position_map_backups.json",
            "private_hnsw_oram/text/payload_fetch_token.json",
            "private_hnsw_oram/text/payload.fetch.token",
            "private_hnsw_oram/text/stashBackup.json",
            "private_hnsw_oram/text/stashBackups.json",
        ];
        for sentinel in sentinels {
            let rendered =
                private_hnsw_manifest_store_error(CollectionError::bad_request(sentinel))
                    .to_string();
            assert!(rendered.contains("manifest store validation failed"));
            assert!(!rendered.contains(sentinel), "{rendered}");

            let rendered =
                private_hnsw_upload_store_error(CollectionError::bad_request(sentinel)).to_string();
            assert!(rendered.contains("encrypted bucket store validation failed"));
            assert!(!rendered.contains(sentinel), "{rendered}");
        }

        let unexpected = || CollectionError::BadInput {
            description: sentinels.join(" "),
        };
        let rendered_errors = [
            private_hnsw_manifest_read_store_error(unexpected()).to_string(),
            private_hnsw_read_store_error(unexpected()).to_string(),
            private_hnsw_read_batch_store_error(unexpected()).to_string(),
            private_hnsw_manifest_store_error(unexpected()).to_string(),
            private_hnsw_epoch_store_error(unexpected()).to_string(),
            private_hnsw_upload_store_error(unexpected()).to_string(),
            private_hnsw_commit_writeback_store_error(unexpected()).to_string(),
        ];
        for rendered in rendered_errors {
            assert!(rendered.contains("private HNSW ORAM"));
            for sentinel in sentinels {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }
    }

    #[test]
    fn recovered_snapshot_signature_preflight_verifies_manifest_signature() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-recovered-signature")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let leaf_commitments = recovered_snapshot_leaf_commitments(manifest.bucket_count, 31);
        manifest.root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest)
            .expect("fixture manifest should sign");
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let config = recovered_snapshot_config(uuid, &manifest);
        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        store.write_manifest(&manifest, &signature).unwrap();
        install_recovered_private_hnsw_snapshot_storage(&store, &manifest, leaf_commitments);

        validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();

        let mut tampered_signature = signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        store
            .write_manifest(&manifest, &tampered_signature)
            .unwrap();
        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM request validation failed"));
        assert!(!rendered.contains(&tampered_signature.sig));
        assert!(!rendered.contains(&manifest.root_hash));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_BINDING));

        let mut mismatched_manifest = manifest.clone();
        mismatched_manifest.root_hash = BASE64URL_NOPAD.encode(&[88; 32]);
        let mismatched_signature = sign_private_hnsw_oram_manifest(&key_pair, &mismatched_manifest)
            .expect("fixture manifest should sign");
        store
            .write_manifest(&mismatched_manifest, &mismatched_signature)
            .unwrap();
        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("restored snapshot manifest or epoch does not match current storage")
        );
        assert!(!rendered.contains(&mismatched_manifest.root_hash));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_BINDING));
    }

    #[test]
    fn recovered_snapshot_signature_preflight_validates_runtime_key_epoch_pinning() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-recovered-runtime")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let mut config = recovered_snapshot_config(uuid, &manifest);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.key_id = Some("tenant-a/other-private-hnsw-rk".to_string());

        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM key_id must match collection key_id"),
            "{rendered}"
        );
        assert!(!rendered.contains("tenant-a/other-private-hnsw-rk"));
        assert!(!rendered.contains(&manifest.key_id));
        assert!(!rendered.contains("manifest has not been uploaded"));
    }

    #[test]
    fn recovered_snapshot_signature_preflight_rejects_wrong_selector_without_rule_details() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-recovered-wrong-selector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let mut config = recovered_snapshot_config(uuid, &manifest);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.rules[0].id = "private_hnsw_restore_secret_rule".to_string();
        encryption.rules[0].selector = EncryptionSelector::PayloadPaths {
            paths: vec!["private.hnsw.secret.payload".to_string()],
        };

        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("vector_names selector"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_restore_secret_rule"));
        assert!(!rendered.contains("private.hnsw.secret.payload"));
        assert!(!rendered.contains("manifest has not been uploaded"));
    }

    fn recovered_snapshot_leaf_commitments(bucket_count: u64, domain: u8) -> Vec<String> {
        (0..bucket_count)
            .map(|bucket_id| {
                let mut bytes = [domain; 32];
                bytes[..8].copy_from_slice(&bucket_id.to_be_bytes());
                let leaf_commitment = BASE64URL_NOPAD.encode(&bytes);
                leaf_commitment
            })
            .collect()
    }

    fn install_recovered_private_hnsw_snapshot_storage(
        store: &PrivateHnswOramStore,
        manifest: &PrivateHnswOramManifest,
        leaf_commitments: Vec<String>,
    ) {
        store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for (bucket_id, bucket_commitment) in leaf_commitments.iter().enumerate() {
            let bucket = fixture_readable_bucket(
                bucket_id as u64,
                manifest.index_epoch,
                31,
                bucket_commitment,
            );
            store
                .write_bucket(
                    &bucket,
                    manifest.index_epoch,
                    manifest.bucket_count,
                    max_bucket_ciphertext_bytes(manifest).unwrap(),
                )
                .unwrap();
        }
    }

    #[test]
    fn restored_snapshot_storage_recheck_requires_bucket_file() {
        let mut session = fixture_session("session-1", 20);
        let bucket_count = 3;
        let leaf_commitments = recovered_snapshot_leaf_commitments(bucket_count, 53);
        let root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        session.bucket_count = bucket_count;
        session.root_hash = root_hash.clone();
        session.manifest.bucket_count = bucket_count;
        session.manifest.root_hash = root_hash;
        let expected_epoch = PrivateHnswOramEpochState {
            index_epoch: session.index_epoch,
            root_hash: session.root_hash.clone(),
        };
        let signature = fixture_signature();

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for (bucket_id, bucket_commitment) in leaf_commitments.iter().enumerate() {
            let bucket = fixture_readable_bucket(
                bucket_id as u64,
                expected_epoch.index_epoch,
                17,
                bucket_commitment,
            );
            store
                .write_bucket(
                    &bucket,
                    expected_epoch.index_epoch,
                    session.manifest.bucket_count,
                    4096,
                )
                .unwrap();
        }
        ensure_private_hnsw_restored_snapshot_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap();

        for missing_bucket_id in [0_u64, 1, bucket_count - 1] {
            let temp = tempfile::TempDir::new().unwrap();
            let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
            store.write_initial_epoch(&expected_epoch).unwrap();
            store.write_manifest(&session.manifest, &signature).unwrap();
            store
                .write_merkle_tree_from_commitments(
                    expected_epoch.index_epoch,
                    expected_epoch.root_hash.clone(),
                    leaf_commitments.clone(),
                )
                .unwrap();
            for (bucket_id, bucket_commitment) in leaf_commitments.iter().enumerate() {
                if bucket_id as u64 == missing_bucket_id {
                    continue;
                }
                let bucket = fixture_readable_bucket(
                    bucket_id as u64,
                    expected_epoch.index_epoch,
                    19,
                    bucket_commitment,
                );
                store
                    .write_bucket(
                        &bucket,
                        expected_epoch.index_epoch,
                        session.manifest.bucket_count,
                        4096,
                    )
                    .unwrap();
            }
            let err = ensure_private_hnsw_restored_snapshot_storage_matches(
                &store,
                &expected_epoch,
                &session.manifest,
                &signature,
            )
            .unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("encrypted bucket data is unavailable"));
            assert!(!rendered.contains(&format!("{missing_bucket_id:08}.bucket")));
            assert!(!rendered.contains(&expected_epoch.root_hash));
        }
    }

    #[test]
    fn active_session_current_epoch_preflight_rejects_stale_store_epoch() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        let old_root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let old = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: old_root_hash.clone(),
        };
        let stale_current = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };

        store.write_initial_epoch(&old).unwrap();
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let err = ensure_private_hnsw_active_session_current_epoch(
            &store,
            old.index_epoch,
            &old.root_hash,
        )
        .unwrap_err()
        .to_string();

        for operation in ["commit", "read_paths", "private-hnsw-operation-sentinel"] {
            assert!(err.contains("current epoch/root does not match active session"));
            assert!(!err.contains(operation), "{err}");
        }
    }

    #[test]
    fn session_open_storage_recheck_rejects_manifest_or_epoch_drift() {
        let mut session = fixture_session("session-1", 20);
        session.bucket_count = 1;
        session.manifest.bucket_count = 1;
        let signature = fixture_signature();
        let expected_epoch = PrivateHnswOramEpochState {
            index_epoch: session.index_epoch,
            root_hash: session.root_hash.clone(),
        };

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let bucket =
            fixture_readable_bucket(0, expected_epoch.index_epoch, 11, &expected_epoch.root_hash);
        store
            .write_bucket(
                &bucket,
                expected_epoch.index_epoch,
                session.manifest.bucket_count,
                4096,
            )
            .unwrap();
        ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap();

        let stale_epoch = PrivateHnswOramEpochState {
            index_epoch: session.index_epoch + 1,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };
        store
            .compare_and_swap_epoch(&expected_epoch, &stale_epoch)
            .unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open observed concurrent manifest or epoch update"));
        assert!(!rendered.contains(&stale_epoch.root_hash));
        assert!(!rendered.contains(&expected_epoch.root_hash));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let bucket =
            fixture_readable_bucket(0, expected_epoch.index_epoch, 12, &expected_epoch.root_hash);
        store
            .write_bucket(
                &bucket,
                expected_epoch.index_epoch,
                session.manifest.bucket_count,
                4096,
            )
            .unwrap();
        let mut changed_manifest = session.manifest.clone();
        changed_manifest.logical_node_count += 1;
        store.write_manifest(&changed_manifest, &signature).unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open observed concurrent manifest or epoch update"));
        assert!(!rendered.contains(&expected_epoch.root_hash));
        assert!(!rendered.contains(&signature.sig));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("encrypted bucket data is unavailable"));
        assert!(!rendered.contains(&expected_epoch.root_hash));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("encrypted bucket data is unavailable"));
        assert!(!rendered.contains("00000000.bucket"));
        assert!(!rendered.contains(&expected_epoch.root_hash));
    }

    fn fixture_signature() -> PrivateHnswOramSignature {
        PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_session(session_id: &str, lease_expires_unix: u64) -> PrivateHnswSession {
        let manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: qdrant_sec::PrivateHnswParams {
                m: 2,
                ef_construction: 4,
                max_layers: 2,
                fixed_neighbor_slots: 4,
            },
            oram: qdrant_sec::OramParams {
                kind: qdrant_sec::OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 4096,
                tree_height: 3,
                path_batch_size: 1,
            },
            fixed_budget: qdrant_sec::FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 1,
                paths_per_round: 1,
                fixed_result_k: 1,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 15,
            logical_node_count: 1,
            dummy_node_count: 0,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1,
        };
        PrivateHnswSession {
            session_id: session_id.to_string(),
            _client_id: "hnsw-client-id-sentinel".to_string(),
            collection_id: "collection-uuid-1".to_string(),
            collection_path: std::path::PathBuf::from("/tmp/qdrant-private-hnsw-test"),
            vector_name: "text".to_string(),
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            lease_expires_unix,
            bucket_count: 15,
            tree_height: 3,
            path_batch_size: 1,
            max_bucket_ciphertext_bytes: 4096,
            manifest,
            commit_in_progress: false,
            owner: PrivateHnswSessionOwner::Standalone,
            read_path_count: 0,
        }
    }

    fn assert_private_hnsw_registry_error_redacts_ids(rendered: &str) {
        for sentinel in [
            "collection-uuid-1",
            "text",
            "session-1",
            "session-2",
            "hnsw-client-id-sentinel",
            "tenant-a/vector-private-rk",
            "OioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio",
            "qdrant-private-hnsw-test",
            "bucket_commitment",
            "bucket.commitment",
            "bucketCommitment",
            "bucket_commitments",
            "bucket.commitments",
            "bucketCommitments",
            "ciphertext_sha256",
            "ciphertextSha256",
            "ciphertexts_sha256",
            "ciphertextsSha256",
            "updated_bucket_commitment",
            "updated.bucket.commitment",
            "updatedBucketCommitment",
            "updated_bucket_commitments",
            "updated.bucket.commitments",
            "updatedBucketCommitments",
            "path_label",
            "path.label",
            "pathLabel",
            "path_labels",
            "path.labels",
            "pathLabels",
            "read_path_label",
            "read.path.label",
            "readPathLabel",
            "read_path_labels",
            "read.path.labels",
            "readPathLabels",
            "proof.value",
            "proof.values",
            "path.count",
            "path.counts",
            "leaf_label",
            "leaf.label",
            "leafLabels",
            "leaf_labels",
            "leaf.labels",
            "node_id",
            "node.id",
            "nodeId",
            "node_ids",
            "node.ids",
            "nodeIds",
            "entry_node_id",
            "entry.node.id",
            "entryNodeId",
            "entry_node_ids",
            "entry.node.ids",
            "entryNodeIds",
            "visited_node_id",
            "visited.node.id",
            "visitedNodeId",
            "visited_node_ids",
            "visited.node.ids",
            "visitedNodeIds",
            "bucket_sequence",
            "bucket.sequence",
            "bucketSequence",
            "bucket_sequences",
            "bucket.sequences",
            "bucketSequences",
            "bucket_id_sequence",
            "bucket.id.sequence",
            "bucketIdSequence",
            "bucket_id_sequences",
            "bucket.id.sequences",
            "bucketIdSequences",
            "client_state",
            "clientState",
            "client_states",
            "clientStates",
            "client_state_ciphertext",
            "clientStateCiphertext",
            "client_state_ciphertexts",
            "clientStateCiphertexts",
            "client_state_ciphertext_hash",
            "clientStateCiphertextHash",
            "client_state_ciphertext_hashes",
            "clientStateCiphertextHashes",
            "client_state_ciphertext_sha256",
            "clientStateCiphertextSha256",
            "client_state_ciphertexts_sha256",
            "clientStateCiphertextsSha256",
            "encrypted_client_state",
            "encryptedClientState",
            "encrypted_client_states",
            "encryptedClientStates",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertext",
            "encrypted_client_state_ciphertexts",
            "encryptedClientStateCiphertexts",
            "encrypted_client_state_ciphertext_hash",
            "encryptedClientStateCiphertextHash",
            "encrypted_client_state_ciphertext_hashes",
            "encryptedClientStateCiphertextHashes",
            "encrypted_client_state_ciphertext_sha256",
            "encryptedClientStateCiphertextSha256",
            "encrypted_client_state_ciphertexts_sha256",
            "encryptedClientStateCiphertextsSha256",
            "oram_position_map",
            "oram_position_maps",
            "oram_position_map_backup",
            "oram_position_map_backups",
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
            "position_map_backup",
            "position_map_backups",
            "positionMap",
            "positionMaps",
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
            "stateCiphertextHash",
            "state_ciphertext_hashes",
            "stateCiphertextHashes",
            "state_ciphertext_sha256",
            "stateCiphertextSha256",
            "state_ciphertexts_sha256",
            "stateCiphertextsSha256",
            "payload_fetch_token",
            "payload_fetch_tokens",
            "payloadFetchToken",
            "payloadFetchTokens",
            "payload.fetch.token",
            "payload.fetch.tokens",
            "token_map",
            "token_maps",
            "token.maps",
            "token_map_backup",
            "token_map_backups",
            "tokenMap",
            "tokenMaps",
            "tokenMapBackup",
            "tokenMapBackups",
            "token_map_snapshot",
            "token.map.snapshot",
            "token_map_snapshots",
            "token.map.snapshots",
            "tokenMapSnapshot",
            "tokenMapSnapshots",
            "token_position_map",
            "token_position_maps",
            "token.position.maps",
            "token_position_map_backup",
            "token_position_map_backups",
            "tokenPositionMap",
            "tokenPositionMaps",
            "tokenPositionMapBackup",
            "tokenPositionMapBackups",
            "token_position_map_snapshot",
            "token.position.map.snapshot",
            "token_position_map_snapshots",
            "token.position.map.snapshots",
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
        ] {
            assert!(
                !rendered.contains(sentinel),
                "private HNSW ORAM registry error leaked `{sentinel}`: {rendered}",
            );
        }
    }

    fn fixture_runtime_context(manifest: &PrivateHnswOramManifest) -> ResolvedPrivateHnswContext {
        ResolvedPrivateHnswContext {
            collection_path: std::path::PathBuf::from("/tmp/qdrant-private-hnsw-test"),
            collection_crypto_id: manifest.collection_id.clone(),
            vector_name: manifest.vector_name.clone(),
            expected_key_id: manifest.key_id.clone(),
            expected_rk_id: manifest.rk_id.clone(),
            min_rk_epoch: manifest.rk_epoch,
            max_rk_epoch: manifest.rk_epoch,
            expected_dim: manifest.dim,
            expected_distance: manifest.distance,
            expected_result_privacy: manifest.result_privacy,
            private_result_oram_binding_configured: false,
            expected_hnsw: manifest.hnsw.clone(),
            expected_oram: manifest.oram.clone(),
            expected_fixed_budget: manifest.fixed_budget.clone(),
            signature_public_keys: HashMap::new(),
            public_key: vec![0; 32],
        }
    }

    fn recovered_snapshot_config(
        uuid: Uuid,
        manifest: &PrivateHnswOramManifest,
    ) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    manifest.vector_name.clone().into(),
                    VectorParamsBuilder::new(u64::from(manifest.dim), Distance::Cosine).build(),
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some(manifest.key_id.clone()),
                    crypto_schema_version: 1,
                    encryption_epoch: manifest.rk_epoch,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "docs_text_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![manifest.vector_name.clone()],
                        },
                        instance: "docs_text_private_hnsw".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: segment::types::HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1000,
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
            uuid: Some(uuid),
            metadata: None,
        }
    }

    fn recovered_snapshot_settings(
        manifest: &PrivateHnswOramManifest,
        public_key: &[u8],
    ) -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            zero_trust_profile: Some(ZERO_TRUST_PROFILE_STRICT.to_string()),
            instances: HashMap::from([(
                "docs_text_private_hnsw".to_string(),
                CryptoInstanceConfig {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: serde_json::json!({
                        KEY_ID_OPTION: manifest.key_id,
                        EXPECTED_RK_ID_OPTION: manifest.rk_id,
                        MIN_RK_EPOCH_OPTION: manifest.rk_epoch,
                        MAX_RK_EPOCH_OPTION: manifest.rk_epoch,
                        "search_execution": "client_led",
                        "search_mode": "private_hnsw_oram",
                        RESULT_PRIVACY_OPTION: "ids_visible",
                        "distance": "cosine",
                        "dim": manifest.dim,
                        HNSW_OPTION: manifest.hnsw,
                        ORAM_OPTION: manifest.oram,
                        FIXED_BUDGET_OPTION: manifest.fixed_budget,
                        "integrity": {
                            "manifest_signature_required": true,
                            "commit_signature_required": true,
                            "merkle_root_required": true,
                        },
                        SIGNATURE_PUBLIC_KEYS_OPTION: {
                            "tenant-a/private-hnsw-signing-v1": BASE64URL_NOPAD.encode(public_key),
                        },
                    }),
                },
            )]),
            ..CryptoSettings::default()
        };
        settings
    }

    #[test]
    fn manifest_runtime_context_rejects_lineage_and_policy_drift() {
        let session = fixture_session("session-1", 20);
        let manifest = session.manifest;
        fixture_runtime_context(&manifest)
            .validate_manifest_runtime_context(&manifest)
            .unwrap();

        let mut context = fixture_runtime_context(&manifest);
        context.expected_key_id = "runtime-key-id-sentinel".to_string();
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest key_id does not match runtime instance"));
        assert!(!rendered.contains("runtime-key-id-sentinel"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_rk_id = "runtime-rk-id-sentinel".to_string();
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest rk_id does not match runtime instance"));
        assert!(!rendered.contains("runtime-rk-id-sentinel"));

        let mut context = fixture_runtime_context(&manifest);
        context.min_rk_epoch = manifest.rk_epoch + 1;
        context.max_rk_epoch = manifest.rk_epoch + 1;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest rk_epoch does not match runtime instance"));
        assert!(!rendered.contains(&(manifest.rk_epoch + 1).to_string()));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_dim = 1536;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest dim does not match runtime vector size"));
        assert!(!rendered.contains("1536"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_distance = DistanceKind::Dot;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest distance does not match runtime vector distance"));
        assert!(!rendered.contains("Dot"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        context.private_result_oram_binding_configured = true;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest result_privacy does not match runtime instance"));
        assert!(!rendered.contains("private_payload_oram_required"));

        let mut private_payload_manifest = manifest.clone();
        private_payload_manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        let context = fixture_runtime_context(&private_payload_manifest);
        let rendered = context
            .validate_manifest_runtime_context(&private_payload_manifest)
            .unwrap_err()
            .to_string();
        assert!(
            rendered.contains("requires a private-result-oram/v1 payload rule"),
            "{rendered}"
        );
        assert!(
            rendered.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
            "{rendered}"
        );

        let mut context = fixture_runtime_context(&private_payload_manifest);
        context.private_result_oram_binding_configured = true;
        context
            .validate_manifest_runtime_context(&private_payload_manifest)
            .unwrap();

        let mut context = fixture_runtime_context(&manifest);
        context.expected_hnsw.m = 99;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest hnsw does not match runtime instance"));
        assert!(!rendered.contains("99"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_oram.bucket_size = 99;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest oram does not match runtime instance"));
        assert!(!rendered.contains("99"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_fixed_budget.fixed_result_k = 99;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest fixed_budget does not match runtime instance"));
        assert!(!rendered.contains("99"));
    }

    #[test]
    fn completing_a_commit_does_not_expire_other_sessions() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
        registry
            .open(
                PrivateHnswSession {
                    collection_id: "other-collection".to_string(),
                    ..fixture_session("session-2", 20)
                },
                now,
            )
            .unwrap();
        registry
            .with_session_mut("collection-uuid-1", "text", "session-1", now, |session| {
                session.read_path_count = 7;
                Ok(())
            })
            .unwrap();
        registry
            .begin_commit("collection-uuid-1", "text", "session-1", now, |_| Ok(()))
            .unwrap();
        let committed = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };
        // The renewed lease lies in the future; it must not serve as the clock that expires
        // everybody else.
        registry
            .complete_commit(
                "collection-uuid-1",
                "text",
                "session-1",
                &committed,
                now,
                session_lease_expires_unix(now).unwrap(),
            )
            .unwrap();
        assert!(
            registry.has_active_index("other-collection", "text", now),
            "another tenant's session was expired by this commit"
        );
        assert!(registry.has_active_index("collection-uuid-1", "text", now));
        registry
            .with_session_mut("other-collection", "text", "session-2", now, |_| Ok(()))
            .unwrap();
        registry
            .with_session_mut("collection-uuid-1", "text", "session-1", now, |session| {
                assert_eq!(
                    session.read_path_count, 0,
                    "committed reads must not widen the next write-back"
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn session_registry_enforces_single_writer() {
        let now = 10;
        let session = fixture_session("session-1", 20);
        let mut registry = PrivateHnswSessionRegistry::default();
        registry.open(session.clone(), now).unwrap();
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(!registry.has_active_collection("other-collection", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));
        assert!(!registry.has_active_index("collection-uuid-1", "other-vector", now));
        let err = registry.open(
            PrivateHnswSession {
                session_id: "session-2".to_string(),
                ..session
            },
            now,
        );
        let rendered = err.unwrap_err().to_string();
        assert!(rendered.contains("ConcurrentWriter"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(!registry.has_active_collection("collection-uuid-1", now));
        assert!(!registry.has_active_index("collection-uuid-1", "text", now));
    }

    #[test]
    fn paired_session_cannot_be_used_through_standalone_protocol() {
        let now = 10;
        let mut session = fixture_session("paired-session", 20);
        session.owner = PrivateHnswSessionOwner::PairedMutation;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry.open(session, now).unwrap();

        for error in [
            registry
                .with_session_mut("collection-uuid-1", "text", "paired-session", now, |_| {
                    Ok(())
                })
                .unwrap_err(),
            registry
                .begin_commit("collection-uuid-1", "text", "paired-session", now, |_| {
                    Ok(())
                })
                .unwrap_err(),
            registry
                .consensus_lease_identity("text", "paired-session", now)
                .unwrap_err(),
        ] {
            let rendered = error.to_string();
            assert!(rendered.contains("different protocol"));
            assert_private_hnsw_registry_error_redacts_ids(&rendered);
        }
        assert!(!registry.close("collection-uuid-1", "text", "paired-session", now,));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));
        registry
            .release_paired("collection-uuid-1", "text", "paired-session", now)
            .unwrap();
        registry
            .release_paired("collection-uuid-1", "text", "paired-session", now)
            .unwrap();
        assert!(!registry.has_active_index("collection-uuid-1", "text", now));
    }

    #[test]
    fn session_registry_atomically_converts_recovery_reservation_to_writer() {
        let now = 10;
        let session = fixture_session("recovered-session", 20);
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let response = registry
            .open_after_upload_reservation(session, now)
            .unwrap();

        assert_eq!(response.session_id, "recovered-session");
        assert!(registry.active_upload_by_index.is_empty());
        assert!(registry.has_active_index("collection-uuid-1", "text", now));
    }

    #[test]
    fn session_registry_rejects_full_registry_without_reflecting_values() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        for index in 0..MAX_SESSION_COUNT {
            let mut session = fixture_session(&format!("capacity-session-{index}"), 20);
            session.collection_id = format!("capacity-collection-{index}");
            session.manifest.collection_id = session.collection_id.clone();
            session.vector_name = format!("capacity-vector-{index}");
            session.manifest.vector_name = session.vector_name.clone();
            registry.open(session, now).unwrap();
        }

        let mut overflow = fixture_session("capacity-overflow-session-sentinel", 20);
        overflow.collection_id = "capacity-overflow-collection-sentinel".to_string();
        overflow.manifest.collection_id = overflow.collection_id.clone();
        overflow.vector_name = "capacity-overflow-vector-sentinel".to_string();
        overflow.manifest.vector_name = overflow.vector_name.clone();
        let rendered = registry.open(overflow, now).unwrap_err().to_string();
        assert!(rendered.contains("session registry is full"));
        for sentinel in [
            "capacity-overflow-session-sentinel",
            "capacity-overflow-collection-sentinel",
            "capacity-overflow-vector-sentinel",
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }

        let mut replacement = fixture_session("capacity-replacement-session", 30);
        replacement.collection_id = "capacity-replacement-collection".to_string();
        replacement.manifest.collection_id = replacement.collection_id.clone();
        replacement.vector_name = "capacity-replacement-vector".to_string();
        replacement.manifest.vector_name = replacement.vector_name.clone();
        registry.open(replacement, 20).unwrap();
        assert_eq!(registry.sessions.len(), 1);
        assert_eq!(registry.active_writer_by_index.len(), 1);
        assert!(registry.has_active_index(
            "capacity-replacement-collection",
            "capacity-replacement-vector",
            20
        ));
    }

    #[test]
    fn session_registry_keeps_writer_lock_after_failed_action() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = registry
            .with_session_mut(
                "collection-uuid-1",
                "text",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    Err(StorageError::bad_request("synthetic failed session action"))
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("synthetic failed session action"));
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));

        let err = registry
            .open(fixture_session("session-2", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ConcurrentWriter"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        registry
            .open(fixture_session("session-2", 20), now)
            .unwrap();
    }

    #[test]
    fn session_registry_pins_writer_while_commit_is_in_progress() {
        let now = 10;
        let expired_at = 20;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", expired_at), now)
            .unwrap();

        let epoch = registry
            .begin_commit("collection-uuid-1", "text", "session-1", now, |session| {
                Ok(session.index_epoch)
            })
            .unwrap();
        assert_eq!(epoch, 42);

        let rendered = registry
            .with_session_mut("collection-uuid-1", "text", "session-1", now, |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("commit is already in progress"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", expired_at));

        let committed = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };
        registry
            .complete_commit(
                "collection-uuid-1",
                "text",
                "session-1",
                &committed,
                now,
                30,
            )
            .unwrap();
        registry
            .with_session_mut(
                "collection-uuid-1",
                "text",
                "session-1",
                expired_at,
                |session| {
                    assert_eq!(session.index_epoch, committed.index_epoch);
                    assert_eq!(session.root_hash, committed.root_hash);
                    assert_eq!(session.lease_expires_unix, 30);
                    Ok(())
                },
            )
            .unwrap();

        registry
            .begin_commit("collection-uuid-1", "text", "session-1", expired_at, |_| {
                Ok(())
            })
            .unwrap();
        registry
            .cancel_commit("collection-uuid-1", "text", "session-1")
            .unwrap();
        assert!(registry.close("collection-uuid-1", "text", "session-1", expired_at));
    }

    #[test]
    fn session_registry_recovers_pinned_commit_without_replacing_writer() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 30), now)
            .unwrap();
        registry
            .begin_commit("collection-uuid-1", "text", "session-1", now, |_| Ok(()))
            .unwrap();

        let committed = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };
        assert!(
            registry
                .recover_commit("collection-uuid-1", "text", &committed, false)
                .unwrap()
        );
        registry
            .with_session_mut("collection-uuid-1", "text", "session-1", now, |session| {
                assert_eq!(session.index_epoch, committed.index_epoch);
                assert_eq!(session.root_hash, committed.root_hash);
                Ok(())
            })
            .unwrap();

        registry
            .begin_commit("collection-uuid-1", "text", "session-1", now, |_| Ok(()))
            .unwrap();
        assert!(
            registry
                .recover_commit("collection-uuid-1", "text", &committed, true)
                .unwrap()
        );
        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(
            !registry
                .recover_commit("collection-uuid-1", "text", &committed, false)
                .unwrap()
        );
    }

    #[test]
    fn session_registry_requires_writer_lock_for_session_action() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
        let index_key = private_hnsw_index_key("collection-uuid-1", "text");

        registry
            .active_writer_by_index
            .insert(index_key.clone(), "session-2".to_string());
        let err = registry
            .with_session_mut(
                "collection-uuid-1",
                "text",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    panic!("private HNSW action must not run without the writer lock")
                },
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("writer lock is missing or stale"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        registry.active_writer_by_index.remove(&index_key);
        let err = registry
            .with_session_mut(
                "collection-uuid-1",
                "text",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    panic!("private HNSW action must not run with a missing writer lock")
                },
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("writer lock is missing or stale"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
    }

    #[test]
    fn session_registry_close_requires_matching_writer_lock() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
        let index_key = private_hnsw_index_key("collection-uuid-1", "text");

        registry
            .active_writer_by_index
            .insert(index_key.clone(), "session-2".to_string());
        assert!(!registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(registry.sessions.contains_key("session-1"));
        assert_eq!(
            registry.active_writer_by_index.get(&index_key),
            Some(&"session-2".to_string())
        );

        registry.active_writer_by_index.remove(&index_key);
        assert!(!registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(registry.sessions.contains_key("session-1"));
        assert!(!registry.active_writer_by_index.contains_key(&index_key));
    }

    #[test]
    fn session_registry_wrong_close_keeps_writer_lock() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        assert!(!registry.close("other-collection", "text", "session-1", now));
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));

        assert!(!registry.close("collection-uuid-1", "other-vector", "session-1", now));
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));

        let err = registry
            .open(fixture_session("session-2", 20), now)
            .unwrap_err();
        assert!(err.to_string().contains("ConcurrentWriter"));

        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(!registry.has_active_index("collection-uuid-1", "text", now));
    }

    #[test]
    fn collection_snapshot_guard_rejects_active_collection_session() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = ensure_no_active_private_hnsw_collection_session_in_registry(
            &mut registry,
            "collection-uuid-1",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active private ORAM session"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(
            ensure_no_active_private_hnsw_collection_session_in_registry(
                &mut registry,
                "other-collection",
                now,
            )
            .is_ok()
        );
        assert!(
            ensure_no_active_private_hnsw_collection_session_in_registry(
                &mut registry,
                "collection-uuid-10",
                now,
            )
            .is_ok()
        );
        assert!(
            ensure_no_active_private_hnsw_collection_session_in_registry(
                &mut registry,
                "collection-uuid-1-suffix",
                now,
            )
            .is_ok()
        );
    }

    #[test]
    fn collection_lifecycle_guard_rejects_active_collection_session() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM session"));
        assert!(!rendered.contains("collection snapshot requires"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        assert!(
            registry
                .begin_collection_lifecycle_operation("other-collection", now)
                .is_ok()
        );
        registry.release_collection_lifecycle_operation("other-collection");
    }

    #[test]
    fn session_registry_rejects_session_open_during_collection_snapshot() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();

        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open requires no active collection snapshot"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        registry.release_collection_snapshot("collection-uuid-1");
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
    }

    #[test]
    fn session_registry_blocks_snapshot_during_collection_lifecycle() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap();

        let err = registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active collection lifecycle operation"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("session open requires no active collection lifecycle operation")
        );
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        let err = ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active collection lifecycle operation"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        registry.release_collection_lifecycle_operation("collection-uuid-1");
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();
        registry.release_collection_snapshot("collection-uuid-1");
    }

    #[test]
    fn collection_lifecycle_guard_rejects_active_collection_snapshot() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();

        let err = registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active collection snapshot"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        registry.release_collection_snapshot("collection-uuid-1");
        registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap();
        registry.release_collection_lifecycle_operation("collection-uuid-1");
    }

    #[test]
    fn session_registry_snapshot_refcounts_and_upload_marker_cleanup_fail_closed() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .active_snapshot_by_collection
            .insert("collection-uuid-1".to_string(), usize::MAX);
        let err = registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("snapshot reference count overflowed")
        );

        registry
            .active_snapshot_by_collection
            .insert("collection-uuid-1".to_string(), 0);
        registry.release_collection_snapshot("collection-uuid-1");
        assert!(
            !registry
                .active_snapshot_by_collection
                .contains_key("collection-uuid-1")
        );

        let index_key = private_hnsw_index_key("collection-uuid-1", "text");
        registry.active_upload_by_index.insert(index_key.clone());
        registry.release_upload("collection-uuid-1", "text");
        assert!(!registry.active_upload_by_index.contains(&index_key));
    }

    #[test]
    fn collection_snapshot_guard_rejects_private_hnsw_upload_write_window() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();

        let err = ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active collection snapshot"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        registry.release_collection_snapshot("collection-uuid-1");
        ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap();
    }

    #[test]
    fn upload_write_window_rejects_concurrent_session_and_upload() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open requires no active upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        let err = registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);

        registry.release_upload("collection-uuid-1", "text");
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
    }

    #[test]
    fn upload_write_window_rejects_collection_snapshot() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let err = registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active private ORAM upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        registry
            .begin_collection_snapshot("other-collection", now)
            .unwrap();
        registry.release_collection_snapshot("other-collection");

        registry.release_upload("collection-uuid-1", "text");
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();
    }

    #[test]
    fn upload_write_window_rejects_collection_lifecycle() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let err = registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        registry
            .begin_collection_lifecycle_operation("other-collection", now)
            .unwrap();
        registry.release_collection_lifecycle_operation("other-collection");

        registry.release_upload("collection-uuid-1", "text");
        registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap();
    }

    #[test]
    fn collection_snapshot_guard_uses_exact_private_hnsw_upload_collection_marker() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-10", "text", now)
            .unwrap();

        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();
        registry.release_collection_snapshot("collection-uuid-1");

        let err = registry
            .begin_collection_snapshot("collection-uuid-10", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active private ORAM upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!rendered.contains("collection-uuid-10"), "{rendered}");
        registry.release_upload("collection-uuid-10", "text");

        registry
            .begin_upload("collection-uuid-1", "image", now)
            .unwrap();
        let err = registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active private ORAM upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!rendered.contains("image"), "{rendered}");
    }

    #[test]
    fn collection_lifecycle_guard_uses_exact_private_hnsw_upload_collection_marker() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-10", "text", now)
            .unwrap();

        registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap();
        registry.release_collection_lifecycle_operation("collection-uuid-1");

        let err = registry
            .begin_collection_lifecycle_operation("collection-uuid-10", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!rendered.contains("collection-uuid-10"), "{rendered}");
        registry.release_upload("collection-uuid-10", "text");

        registry
            .begin_upload("collection-uuid-1", "image", now)
            .unwrap();
        let err = registry
            .begin_collection_lifecycle_operation("collection-uuid-1", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!rendered.contains("image"), "{rendered}");
    }

    #[test]
    fn upload_write_window_uses_exact_private_hnsw_index() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();

        registry
            .begin_upload("collection-uuid-10", "text", now)
            .unwrap();
        registry
            .begin_upload("collection-uuid-1", "image", now)
            .unwrap();
        ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let err = registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active upload"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!rendered.contains("collection-uuid-1"), "{rendered}");
        assert!(!rendered.contains("text"), "{rendered}");

        registry.release_upload("collection-uuid-1", "text");
        registry.release_upload("collection-uuid-1", "image");
        registry.release_upload("collection-uuid-10", "text");

        registry
            .begin_collection_snapshot("collection-uuid-10", now)
            .unwrap();
        ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap();
        registry.release_collection_snapshot("collection-uuid-10");

        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();
        let err = ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active collection snapshot"));
        assert_private_hnsw_registry_error_redacts_ids(&rendered);
        assert!(!rendered.contains("collection-uuid-1"), "{rendered}");
        assert!(!rendered.contains("text"), "{rendered}");
    }

    #[test]
    fn session_registry_expiration_releases_writer_lock() {
        let now = 10;
        let expired_at = 20;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", expired_at), now)
            .unwrap();

        let err = registry
            .with_session_mut("collection-uuid-1", "text", "session-1", expired_at, |_| {
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("session is missing or expired"));
        assert!(!registry.has_active_collection("collection-uuid-1", expired_at));
        assert!(!registry.has_active_index("collection-uuid-1", "text", expired_at));
        assert!(!registry.close("collection-uuid-1", "text", "session-1", expired_at));

        registry
            .open(fixture_session("session-2", expired_at + 10), expired_at)
            .unwrap();
        assert!(registry.has_active_index("collection-uuid-1", "text", expired_at));
    }
}
