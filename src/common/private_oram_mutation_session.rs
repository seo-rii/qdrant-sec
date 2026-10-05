use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use collection::operations::verification::new_unchecked_verification_pass;
use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_HNSW_ORAM_V2_BINDING,
    PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES, PRIVATE_RESULT_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_V2_BINDING, PrivateOramAppendOwnerPrepareV1,
    PrivateOramAppendOwnerPrepareValidationContextV1, PrivateOramAppendReadTranscriptDigestInput,
    PrivateOramAppendReadWindowV1, PrivateOramDurableReadObservationV2,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableManifestBundleV2,
    PrivateOramIndexKindV2, PrivateOramServerReadEvidenceRecorderV1,
    PrivateOramServerReadEvidenceV1, PrivateOramSignatureVerification,
    PrivateOramSignedStateBundleV2, PrivateOramSignedStateV2, PrivateOramStagedInsertFrameV1,
    PrivateOramValidatedOwnerPrepareV1, PrivateOramVisiblePointRecordV1,
    PrivateResultOramSignature, ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
    VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, decode_private_oram_staged_insert_frame_v1,
    encode_private_result_oram_leaf_label, private_oram_immutable_manifest_v2_digest,
    private_oram_owner_prestage_read_observations_v2, private_oram_signed_state_v2_digest,
    private_oram_staged_insert_frame_v1_digest, private_oram_staged_point_id_canonical_string,
    validate_private_oram_append_owner_prepare_v1,
    validate_private_oram_immutable_manifest_v2_shape,
    validate_private_oram_immutable_manifest_v2_signature,
    validate_private_oram_signed_state_v2_shape, validate_private_oram_signed_state_v2_signature,
    validate_private_oram_staged_insert_frame_v1_against_mutation_bundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage::content_manager::consensus_manager::PrivateOramMutationV2ActivationStatus;
use storage::content_manager::consensus_ops::{
    PrivateOramConsensusCollectionStateV2, PrivateOramConsensusLayout, PrivateOramIndexKind,
    PrivateOramLayoutKey, PrivateOramMutationKey, PrivateOramMutationLeaseSlotV2,
};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAdmissionPlanV2, PrivateOramMutationAllOwnersPrestagedV2,
    PrivateOramMutationNeedLocalCleanupV2,
};
use storage::dispatcher::{
    Dispatcher, PrivateOramLiveAdmissionPermitV2, PrivateOramLiveAdmissionSeedV2,
};
use storage::rbac::AccessRequirements;
use tokio::sync::Notify;

use super::auth::Auth;
use super::private_hnsw::{
    PrivateHnswClientSignature, PrivateHnswReadPadding, PrivateHnswReadPathsResponse,
    PrivateHnswSessionResponse, do_open_private_hnsw_session_for_paired_mutation,
    do_read_private_hnsw_paths_for_paired_mutation,
    release_private_hnsw_session_for_paired_mutation, resolve_private_hnsw_context_from_snapshot,
};
use super::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use super::private_result_oram::{
    PrivateResultOramReadBucketsResponse, PrivateResultOramSessionResponse,
    do_open_private_result_oram_session_for_paired_mutation,
    do_read_private_result_oram_buckets_for_paired_mutation,
    release_private_result_oram_session_for_paired_mutation,
};
use crate::settings::Settings;

pub(crate) const PRIVATE_ORAM_MUTATION_SESSION_LEASE_SECS: u64 = 300;
const PRIVATE_ORAM_MUTATION_MAX_SESSION_COUNT: usize = 512;
const PRIVATE_ORAM_MUTATION_MAX_APPEND_JOB_COUNT: usize = 128;
const PRIVATE_ORAM_MUTATION_WRITER_LEASE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-mutation-writer-lease/v2";
const PRIVATE_ORAM_MUTATION_FREEZE_NONCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-mutation-freeze-nonce/v2";
const PRIVATE_ORAM_MUTATION_APPEND_JOB_KEY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-job-key/v2";
const PRIVATE_ORAM_MUTATION_LIVE_SESSION_COMMITMENT_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-mutation-live-session-commitment/v2";

#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateOramMutationLeaderTokenV2 {
    peer_id: u64,
    term: u64,
}

impl Debug for PrivateOramMutationLeaderTokenV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationLeaderTokenV2")
            .field("peer_id", &self.peer_id)
            .field("term", &self.term)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PrivateOramMutationFreezeTokenV2 {
    session_incarnation: u64,
    freeze_nonce: [u8; 32],
    leader: PrivateOramMutationLeaderTokenV2,
}

impl Debug for PrivateOramMutationFreezeTokenV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationFreezeTokenV2")
            .field("session_incarnation", &self.session_incarnation)
            .field("freeze_nonce", &"[redacted]")
            .field("leader", &self.leader)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
enum PrivateOramMutationFreezeOwnerV2 {
    Request(PrivateOramMutationFreezeTokenV2),
    #[allow(
        dead_code,
        reason = "D4 detached append jobs take ownership before owner pre-stage"
    )]
    Job {
        mutation_id: String,
        token: PrivateOramMutationFreezeTokenV2,
    },
    #[allow(
        dead_code,
        reason = "D4 admitted append recovery takes ownership after Raft submission"
    )]
    Recovery {
        mutation_id: String,
        generation: u64,
        writer_fence: u64,
    },
}

impl Debug for PrivateOramMutationFreezeOwnerV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(token) => formatter.debug_tuple("Request").field(token).finish(),
            Self::Job { token, .. } => formatter
                .debug_struct("Job")
                .field("mutation_id", &"[redacted]")
                .field("token", token)
                .finish(),
            Self::Recovery {
                generation,
                writer_fence,
                ..
            } => formatter
                .debug_struct("Recovery")
                .field("mutation_id", &"[redacted]")
                .field("generation", generation)
                .field("writer_fence", writer_fence)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationOpenInputV2 {
    pub client_id: String,
    pub vector_name: String,
    pub mutation_id: String,
    pub immutable_manifest: PrivateOramImmutableManifestBundleV2,
    pub old_state: PrivateOramSignedStateBundleV2,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationAppendInputV2 {
    pub session_id: String,
    pub owner_prepare: PrivateOramAppendOwnerPrepareV1,
    pub staged_insert_frame_b64: Option<String>,
}

impl Debug for PrivateOramMutationAppendInputV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendInputV2")
            .field("session_id", &"[redacted]")
            .field("owner_prepare", &"[redacted]")
            .field(
                "has_staged_insert_frame",
                &self.staged_insert_frame_b64.is_some(),
            )
            .finish()
    }
}

impl Debug for PrivateOramMutationOpenInputV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationOpenInputV2")
            .field("client_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("old_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PrivateOramMutationIndexSessionV2 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub read_session_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub paths_per_window: u32,
    pub tree_height: u32,
    pub fixed_append_read_path_count: u32,
}

impl Debug for PrivateOramMutationIndexSessionV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationIndexSessionV2")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("read_session_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("paths_per_window", &self.paths_per_window)
            .field("tree_height", &self.tree_height)
            .field(
                "fixed_append_read_path_count",
                &self.fixed_append_read_path_count,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PrivateOramMutationOpenResponseV2 {
    pub session_id: String,
    pub collection_id: String,
    pub vector_name: String,
    pub mutation_id: String,
    pub manifest_digest: String,
    pub old_state_digest: String,
    pub mutation_lease_generation: u64,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub issued_at_unix: u64,
    pub lease_expires_unix: u64,
    pub indexes: Vec<PrivateOramMutationIndexSessionV2>,
}

impl Debug for PrivateOramMutationOpenResponseV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationOpenResponseV2")
            .field("session_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("mutation_lease_generation", &self.mutation_lease_generation)
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("lease_expires_unix", &self.lease_expires_unix)
            .field("indexes", &self.indexes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationSessionPhaseV2 {
    Reading,
    ReadComplete,
    AppendInProgress,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PrivateOramMutationSessionStatusV2 {
    pub phase: PrivateOramMutationSessionPhaseV2,
    pub append_phase: Option<PrivateOramMutationAppendJobPhaseV2>,
    pub lease_expires_unix: u64,
    pub hnsw_windows_accepted: u32,
    pub hnsw_windows_required: u32,
    pub result_windows_accepted: Option<u32>,
    pub result_windows_required: Option<u32>,
}

impl Debug for PrivateOramMutationSessionStatusV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationSessionStatusV2")
            .field("phase", &self.phase)
            .field("append_phase", &self.append_phase)
            .field("lease_expires_unix", &self.lease_expires_unix)
            .field("hnsw_windows_accepted", &self.hnsw_windows_accepted)
            .field("hnsw_windows_required", &self.hnsw_windows_required)
            .field("result_windows_accepted", &self.result_windows_accepted)
            .field("result_windows_required", &self.result_windows_required)
            .finish()
    }
}

#[derive(Clone)]
struct PrivateOramMutationIndexReadStateV2 {
    session_id: String,
    index_name: String,
    index_epoch: u64,
    root_hash: String,
    paths_per_window: u32,
    tree_height: u32,
    fixed_append_read_path_count: u32,
    windows: Vec<PrivateOramAppendReadWindowV1>,
    read_in_progress: bool,
}

impl PrivateOramMutationIndexReadStateV2 {
    fn required_window_count(&self) -> StorageResult<u32> {
        if self.paths_per_window == 0
            || !self
                .fixed_append_read_path_count
                .is_multiple_of(self.paths_per_window)
        {
            return Err(invalid_mutation_session());
        }
        Ok(self.fixed_append_read_path_count / self.paths_per_window)
    }

    fn begin_read(&mut self) -> StorageResult<()> {
        let accepted = u32::try_from(self.windows.len()).map_err(|_| invalid_mutation_session())?;
        if self.read_in_progress || accepted >= self.required_window_count()? {
            return Err(StorageError::bad_request(
                "private ORAM mutation read window is unavailable",
            ));
        }
        self.read_in_progress = true;
        Ok(())
    }

    fn finish_read(&mut self, paths: Vec<String>) -> StorageResult<()> {
        if !self.read_in_progress || paths.len() != self.paths_per_window as usize {
            return Err(invalid_mutation_session());
        }
        let sequence = u32::try_from(self.windows.len()).map_err(|_| invalid_mutation_session())?;
        self.windows
            .push(PrivateOramAppendReadWindowV1 { sequence, paths });
        self.read_in_progress = false;
        Ok(())
    }

    fn cancel_read(&mut self) {
        self.read_in_progress = false;
    }
}

#[derive(Clone)]
struct PrivateOramMutationSessionV2 {
    incarnation: u64,
    leader: PrivateOramMutationLeaderTokenV2,
    response: PrivateOramMutationOpenResponseV2,
    collection_name: String,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    old_state: PrivateOramSignedStateBundleV2,
    owner_public_key: Vec<u8>,
    recorder: PrivateOramServerReadEvidenceRecorderV1,
    admission_seed: Option<PrivateOramLiveAdmissionSeedV2>,
    hnsw: PrivateOramMutationIndexReadStateV2,
    result: Option<PrivateOramMutationIndexReadStateV2>,
    freeze_owner: Option<PrivateOramMutationFreezeOwnerV2>,
    closing: bool,
}

impl Debug for PrivateOramMutationSessionV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationSessionV2")
            .field("incarnation", &self.incarnation)
            .field("leader", &self.leader)
            .field("response", &self.response)
            .field("collection_name", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("old_state", &"[redacted]")
            .field("owner_public_key", &"[redacted]")
            .field("recorder", &self.recorder)
            .field("has_admission_seed", &self.admission_seed.is_some())
            .field("hnsw_window_count", &self.hnsw.windows.len())
            .field(
                "result_window_count",
                &self.result.as_ref().map(|result| result.windows.len()),
            )
            .field("freeze_owner", &self.freeze_owner)
            .field("closing", &self.closing)
            .finish()
    }
}

impl PrivateOramMutationSessionV2 {
    fn status(
        &self,
        append_phase: Option<PrivateOramMutationAppendJobPhaseV2>,
    ) -> StorageResult<PrivateOramMutationSessionStatusV2> {
        let hnsw_required = self.hnsw.required_window_count()?;
        let result_required = self
            .result
            .as_ref()
            .map(PrivateOramMutationIndexReadStateV2::required_window_count)
            .transpose()?;
        let hnsw_accepted =
            u32::try_from(self.hnsw.windows.len()).map_err(|_| invalid_mutation_session())?;
        let result_accepted = self
            .result
            .as_ref()
            .map(|result| u32::try_from(result.windows.len()))
            .transpose()
            .map_err(|_| invalid_mutation_session())?;
        let read_complete = hnsw_accepted == hnsw_required
            && result_accepted
                .zip(result_required)
                .is_none_or(|(accepted, required)| accepted == required);
        Ok(PrivateOramMutationSessionStatusV2 {
            phase: if self.freeze_owner.is_some() {
                PrivateOramMutationSessionPhaseV2::AppendInProgress
            } else if read_complete {
                PrivateOramMutationSessionPhaseV2::ReadComplete
            } else {
                PrivateOramMutationSessionPhaseV2::Reading
            },
            append_phase,
            lease_expires_unix: self.response.lease_expires_unix,
            hnsw_windows_accepted: hnsw_accepted,
            hnsw_windows_required: hnsw_required,
            result_windows_accepted: result_accepted,
            result_windows_required: result_required,
        })
    }

    fn read_evidence(&self) -> StorageResult<Vec<PrivateOramServerReadEvidenceV1>> {
        if self.status(None)?.phase != PrivateOramMutationSessionPhaseV2::ReadComplete {
            return Err(StorageError::bad_request(
                "private ORAM mutation fixed read budget is incomplete",
            ));
        }
        let mut evidence = Vec::with_capacity(1 + usize::from(self.result.is_some()));
        evidence.push(self.record_index_evidence(PrivateOramIndexKindV2::Hnsw, &self.hnsw)?);
        if let Some(result) = self.result.as_ref() {
            evidence.push(self.record_index_evidence(PrivateOramIndexKindV2::Result, result)?);
        }
        Ok(evidence)
    }

    fn record_index_evidence(
        &self,
        kind: PrivateOramIndexKindV2,
        index: &PrivateOramMutationIndexReadStateV2,
    ) -> StorageResult<PrivateOramServerReadEvidenceV1> {
        self.recorder
            .record(PrivateOramAppendReadTranscriptDigestInput {
                collection_id: &self.response.collection_id,
                manifest_digest: &self.response.manifest_digest,
                mutation_id: &self.response.mutation_id,
                old_state_digest: &self.response.old_state_digest,
                writer_lease_digest: &self.response.writer_lease_digest,
                writer_fence: self.response.writer_fence,
                paths_per_window: index.paths_per_window,
                tree_height: index.tree_height,
                kind,
                index_name: &index.index_name,
                windows: &index.windows,
            })
            .map_err(|_| invalid_mutation_session())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PrivateOramMutationRuntimeAuthorityV2 {
    collection_id: String,
    mutation_id: String,
    owner_peer_id: PeerId,
    generation: u64,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PrivateOramMutationCleanupClaimBindingV2 {
    authority: PrivateOramMutationRuntimeAuthorityV2,
    descriptor_digest: String,
    terminal_record_digest: String,
    witness_digest: String,
    cleanup_evidence_digest: String,
}

#[derive(Default)]
struct PrivateOramMutationSessionRegistryV2 {
    sessions: HashMap<String, PrivateOramMutationSessionV2>,
    active_by_collection: HashMap<String, String>,
    opening_collections: HashSet<String>,
    append_jobs: HashMap<String, Arc<PrivateOramMutationAppendJobV2>>,
    cleanup_claimed_collections: HashSet<String>,
    cleanup_claims: HashMap<String, PrivateOramMutationCleanupClaimBindingV2>,
    seen_job_authorities: HashSet<PrivateOramMutationRuntimeAuthorityV2>,
    cleanup_tombstones:
        HashMap<PrivateOramMutationRuntimeAuthorityV2, PrivateOramMutationCleanupClaimBindingV2>,
}

impl PrivateOramMutationSessionRegistryV2 {
    fn reserve_open(&mut self, collection_id: &str, _now_unix: u64) -> StorageResult<()> {
        if self.sessions.len() >= PRIVATE_ORAM_MUTATION_MAX_SESSION_COUNT {
            return Err(StorageError::bad_request(
                "private ORAM mutation session registry is full",
            ));
        }
        if self.cleanup_claimed_collections.contains(collection_id)
            || self.active_by_collection.contains_key(collection_id)
            || !self.opening_collections.insert(collection_id.to_string())
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation session already exists for collection",
            ));
        }
        Ok(())
    }

    fn release_open(&mut self, collection_id: &str) {
        self.opening_collections.remove(collection_id);
    }

    fn install(&mut self, session: PrivateOramMutationSessionV2) -> StorageResult<()> {
        let collection_id = session.response.collection_id.clone();
        if !self.opening_collections.remove(&collection_id)
            || self.cleanup_claimed_collections.contains(&collection_id)
            || self.active_by_collection.contains_key(&collection_id)
            || self.sessions.contains_key(&session.response.session_id)
        {
            return Err(invalid_mutation_session());
        }
        self.active_by_collection
            .insert(collection_id, session.response.session_id.clone());
        self.sessions
            .insert(session.response.session_id.clone(), session);
        Ok(())
    }

    fn drain_expired(&mut self, now_unix: u64) -> Vec<PrivateOramMutationSessionV2> {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (session.response.lease_expires_unix <= now_unix
                    && session.freeze_owner.is_none()
                    && !session.closing
                    && !session.hnsw.read_in_progress
                    && !session
                        .result
                        .as_ref()
                        .is_some_and(|result| result.read_in_progress))
                .then_some(session_id.clone())
            })
            .collect::<Vec<_>>();
        let mut removed = Vec::with_capacity(expired.len());
        for session_id in expired {
            if let Some(session) = self.sessions.remove(&session_id) {
                self.active_by_collection
                    .remove(&session.response.collection_id);
                removed.push(session);
            }
        }
        removed
    }

    fn session_mut(
        &mut self,
        collection_name: &str,
        session_id: &str,
        _now_unix: u64,
    ) -> StorageResult<&mut PrivateOramMutationSessionV2> {
        // A missing session and one of another collection answer identically, so a caller
        // probing session ids cannot tell which ids exist.
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(invalid_mutation_session)?;
        if session.collection_name != collection_name {
            return Err(invalid_mutation_session());
        }
        Ok(session)
    }
}

struct PrivateOramMutationOpenReservation {
    collection_id: String,
    armed: bool,
}

impl PrivateOramMutationOpenReservation {
    fn acquire(collection_id: &str, now_unix: u64) -> StorageResult<Self> {
        reap_expired_sessions(now_unix)?;
        session_registry()
            .lock()
            .map_err(|_| {
                StorageError::service_error("private ORAM mutation session registry poisoned")
            })?
            .reserve_open(collection_id, now_unix)?;
        Ok(Self {
            collection_id: collection_id.to_string(),
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PrivateOramMutationOpenReservation {
    fn drop(&mut self) {
        if self.armed {
            release_open_reservation(&self.collection_id);
        }
    }
}

struct PrivateOramOpenedIndexSessions {
    collection_id: String,
    vector_name: String,
    hnsw_session_id: Option<String>,
    result_session_id: Option<String>,
    armed: bool,
}

impl PrivateOramOpenedIndexSessions {
    fn new(collection_id: &str, vector_name: &str) -> Self {
        Self {
            collection_id: collection_id.to_string(),
            vector_name: vector_name.to_string(),
            hnsw_session_id: None,
            result_session_id: None,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PrivateOramOpenedIndexSessions {
    fn drop(&mut self) {
        if self.armed {
            let _ = release_raw_underlying_sessions(
                &self.collection_id,
                &self.vector_name,
                self.hnsw_session_id.as_deref(),
                self.result_session_id.as_deref(),
            );
        }
    }
}

struct PrivateOramMutationAppendReservationV2 {
    collection_name: String,
    session_id: String,
    token: PrivateOramMutationFreezeTokenV2,
    release_on_drop: bool,
}

impl Debug for PrivateOramMutationAppendReservationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendReservationV2")
            .field("collection_name", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("release_on_drop", &self.release_on_drop)
            .finish()
    }
}

impl PrivateOramMutationAppendReservationV2 {
    fn acquire(
        collection_name: &str,
        session_id: &str,
        now_unix: u64,
        leader: PrivateOramMutationLeaderTokenV2,
    ) -> StorageResult<(
        Self,
        PrivateOramMutationSessionV2,
        Vec<PrivateOramServerReadEvidenceV1>,
    )> {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?;
        let session = registry.session_mut(collection_name, session_id, now_unix)?;
        if session.leader != leader
            || session.freeze_owner.is_some()
            || session.closing
            || session.hnsw.read_in_progress
            || session
                .result
                .as_ref()
                .is_some_and(|result| result.read_in_progress)
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation append is unavailable",
            ));
        }
        let evidence = session.read_evidence()?;
        let token = PrivateOramMutationFreezeTokenV2 {
            session_incarnation: session.incarnation,
            freeze_nonce: new_private_oram_mutation_freeze_nonce_v2(
                session_id,
                session.incarnation,
            ),
            leader,
        };
        session.freeze_owner = Some(PrivateOramMutationFreezeOwnerV2::Request(token.clone()));
        Ok((
            Self {
                collection_name: collection_name.to_string(),
                session_id: session_id.to_string(),
                token,
                release_on_drop: true,
            },
            session.clone(),
            evidence,
        ))
    }

    fn transfer_to_job(&mut self, job: Arc<PrivateOramMutationAppendJobV2>) -> StorageResult<()> {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?;
        if registry.append_jobs.len() >= PRIVATE_ORAM_MUTATION_MAX_APPEND_JOB_COUNT
            || registry.append_jobs.contains_key(&job.binding.job_key)
            || registry
                .cleanup_claimed_collections
                .contains(&job.binding.collection_id)
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation append job registry is unavailable",
            ));
        }
        let session = registry.sessions.get(&self.session_id).ok_or_else(|| {
            StorageError::bad_request("private ORAM mutation session is missing or expired")
        })?;
        if session.collection_name != self.collection_name
            || session.response.collection_id != job.binding.collection_id
            || session.response.mutation_id != job.binding.mutation_id
            || session.incarnation != self.token.session_incarnation
            || session.freeze_owner.as_ref()
                != Some(&PrivateOramMutationFreezeOwnerV2::Request(
                    self.token.clone(),
                ))
            || job.binding.collection_name != self.collection_name
            || job.binding.session_id != self.session_id
            || job.binding.token != self.token
            || !registry
                .active_by_collection
                .get(&session.response.collection_id)
                .is_some_and(|active| active == &self.session_id)
        {
            return Err(invalid_mutation_session());
        }

        let runtime_authority = private_oram_mutation_job_authority_v2(&job)?;
        registry
            .append_jobs
            .insert(job.binding.job_key.clone(), Arc::clone(&job));
        registry.seen_job_authorities.insert(runtime_authority);
        let session = registry
            .sessions
            .get_mut(&self.session_id)
            .expect("session was validated under the same registry lock");
        session.freeze_owner = Some(PrivateOramMutationFreezeOwnerV2::Job {
            mutation_id: job.binding.mutation_id.clone(),
            token: self.token.clone(),
        });
        self.release_on_drop = false;
        Ok(())
    }
}

impl Drop for PrivateOramMutationAppendReservationV2 {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        if let Ok(mut registry) = session_registry().lock()
            && let Some(session) = registry.sessions.get_mut(&self.session_id)
            && session.collection_name == self.collection_name
            && session.incarnation == self.token.session_incarnation
            && session.freeze_owner.as_ref()
                == Some(&PrivateOramMutationFreezeOwnerV2::Request(
                    self.token.clone(),
                ))
        {
            session.freeze_owner = None;
        }
    }
}

struct PrivateOramValidatedMutationAppendMaterialV2 {
    session: PrivateOramMutationSessionV2,
    validated_owner_prepare: PrivateOramValidatedOwnerPrepareV1,
    owner_prepare: PrivateOramAppendOwnerPrepareV1,
    durable_read_observations: Vec<PrivateOramDurableReadObservationV2>,
    staged_insert_frame: Option<PrivateOramStagedInsertFrameV1>,
    staged_insert_frame_bytes: Option<Vec<u8>>,
    consensus_state: PrivateOramConsensusCollectionStateV2,
    consensus_slot: PrivateOramMutationLeaseSlotV2,
    consensus_layout: PrivateOramConsensusLayout,
}

pub(crate) struct PrivateOramValidatedMutationAppendV2 {
    reservation: PrivateOramMutationAppendReservationV2,
    material: PrivateOramValidatedMutationAppendMaterialV2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationAppendJobPhaseV2 {
    PrestagePending,
    Prestaging,
    AdmissionReady,
    AdmissionSubmitting,
    AdmissionUnknown,
    AdmittedAckPending,
    AdmittedAckComplete,
    RejectedAckPending,
    RejectedAckComplete,
    NotSubmitted,
    ParentSequence1,
    OwnersAdopting,
    ParentSequence2,
    PointsStaging,
    Deciding,
    Finalizing,
    Cleaning,
    TerminalCommitted,
    TerminalAborted,
    Quarantined,
}

#[derive(Clone, PartialEq, Eq)]
struct PrivateOramMutationAppendJobBindingV2 {
    job_key: String,
    collection_name: String,
    collection_id: String,
    session_id: String,
    mutation_id: String,
    token: PrivateOramMutationFreezeTokenV2,
}

struct PrivateOramMutationAppendJobV2 {
    binding: PrivateOramMutationAppendJobBindingV2,
    material: PrivateOramValidatedMutationAppendMaterialV2,
    phase: Mutex<PrivateOramMutationAppendJobPhaseV2>,
    worker_active: AtomicBool,
    cleanup_claimed: AtomicBool,
    worker_quiesced: Notify,
}

fn private_oram_mutation_job_authority_v2(
    job: &PrivateOramMutationAppendJobV2,
) -> StorageResult<PrivateOramMutationRuntimeAuthorityV2> {
    let lease = job
        .material
        .consensus_slot
        .active
        .as_ref()
        .ok_or_else(invalid_mutation_session)?;
    let generation = job.material.session.response.mutation_lease_generation;
    if lease.collection_id != job.binding.collection_id
        || lease.mutation_id != job.binding.mutation_id
        || job.material.consensus_slot.generation != generation
    {
        return Err(invalid_mutation_session());
    }
    Ok(PrivateOramMutationRuntimeAuthorityV2 {
        collection_id: job.binding.collection_id.clone(),
        mutation_id: job.binding.mutation_id.clone(),
        owner_peer_id: lease.owner_peer_id,
        generation,
    })
}

impl Debug for PrivateOramMutationAppendJobV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendJobV2")
            .field("job_key", &"[redacted]")
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("session_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("token", &self.binding.token)
            .field("phase", &self.phase.lock().ok().as_deref())
            .field("worker_active", &self.worker_active.load(Ordering::Acquire))
            .field(
                "cleanup_claimed",
                &self.cleanup_claimed.load(Ordering::Acquire),
            )
            .field("material", &"[redacted]")
            .finish()
    }
}

pub(crate) struct PrivateOramDetachedMutationAppendV2 {
    job: Arc<PrivateOramMutationAppendJobV2>,
    owns_worker_liveness: bool,
}

impl Debug for PrivateOramDetachedMutationAppendV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramDetachedMutationAppendV2")
            .field("job", &self.job)
            .finish()
    }
}

impl Debug for PrivateOramValidatedMutationAppendV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramValidatedMutationAppendV2")
            .field("reservation", &self.reservation)
            .field("session", &"[redacted]")
            .field("validated_owner_prepare", &"[redacted]")
            .field("owner_prepare", &"[redacted]")
            .field(
                "durable_read_observation_count",
                &self.material.durable_read_observations.len(),
            )
            .field(
                "has_staged_insert_frame",
                &self.material.staged_insert_frame.is_some(),
            )
            .field("staged_insert_frame_bytes", &"[redacted]")
            .field("consensus_state", &"[redacted]")
            .field("consensus_slot", &"[redacted]")
            .field("consensus_layout", &"[redacted]")
            .finish()
    }
}

impl PrivateOramValidatedMutationAppendV2 {
    pub(crate) fn immutable_manifest(&self) -> &PrivateOramImmutableManifestBundleV2 {
        &self.material.session.immutable_manifest
    }

    pub(crate) fn collection_name(&self) -> &str {
        &self.material.session.collection_name
    }

    pub(crate) fn vector_name(&self) -> &str {
        &self.material.session.response.vector_name
    }

    pub(crate) fn validated_owner_prepare(&self) -> &PrivateOramValidatedOwnerPrepareV1 {
        &self.material.validated_owner_prepare
    }

    pub(crate) fn owner_prepare_for_transport(&self) -> &PrivateOramAppendOwnerPrepareV1 {
        &self.material.owner_prepare
    }

    pub(crate) fn durable_read_observations(&self) -> &[PrivateOramDurableReadObservationV2] {
        &self.material.durable_read_observations
    }

    pub(crate) fn staged_insert_frame(&self) -> Option<&PrivateOramStagedInsertFrameV1> {
        self.material.staged_insert_frame.as_ref()
    }

    pub(crate) fn staged_insert_frame_bytes(&self) -> Option<&[u8]> {
        self.material.staged_insert_frame_bytes.as_deref()
    }

    pub(crate) fn consensus_state(&self) -> &PrivateOramConsensusCollectionStateV2 {
        &self.material.consensus_state
    }

    pub(crate) fn consensus_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        &self.material.consensus_slot
    }

    pub(crate) fn consensus_layout(&self) -> &PrivateOramConsensusLayout {
        &self.material.consensus_layout
    }

    pub(crate) fn detach_to_registry_job(
        self,
        dispatcher: &Dispatcher,
    ) -> StorageResult<PrivateOramDetachedMutationAppendV2> {
        let current_leader = current_active_mutation_leader_token(dispatcher)?;
        if current_leader != self.reservation.token.leader
            || self.material.session.leader != current_leader
            || self.material.session.response.lease_expires_unix <= current_unix_secs()?
        {
            return Err(invalid_mutation_session());
        }
        let Self {
            mut reservation,
            material,
        } = self;
        let collection_id = material.session.response.collection_id.clone();
        let mutation_id = material.session.response.mutation_id.clone();
        let binding = PrivateOramMutationAppendJobBindingV2 {
            job_key: private_oram_mutation_append_job_key_v2(&collection_id, &mutation_id),
            collection_name: material.session.collection_name.clone(),
            collection_id,
            session_id: material.session.response.session_id.clone(),
            mutation_id,
            token: reservation.token.clone(),
        };
        let job = Arc::new(PrivateOramMutationAppendJobV2 {
            binding,
            material,
            phase: Mutex::new(PrivateOramMutationAppendJobPhaseV2::PrestagePending),
            worker_active: AtomicBool::new(true),
            cleanup_claimed: AtomicBool::new(false),
            worker_quiesced: Notify::new(),
        });
        reservation.transfer_to_job(Arc::clone(&job))?;
        Ok(PrivateOramDetachedMutationAppendV2 {
            job,
            owns_worker_liveness: true,
        })
    }
}

impl Drop for PrivateOramDetachedMutationAppendV2 {
    fn drop(&mut self) {
        if self.owns_worker_liveness {
            self.job.worker_active.store(false, Ordering::Release);
            self.job.worker_quiesced.notify_waiters();
            self.owns_worker_liveness = false;
        }
    }
}

impl PrivateOramDetachedMutationAppendV2 {
    fn ensure_cleanup_not_claimed(&self) -> StorageResult<()> {
        if self.job.cleanup_claimed.load(Ordering::Acquire) {
            return Err(StorageError::service_error(
                "private ORAM mutation worker is quiescing for terminal cleanup",
            ));
        }
        Ok(())
    }

    pub(crate) fn controller_peer_id(&self) -> PeerId {
        self.job.binding.token.leader.peer_id
    }

    pub(crate) fn controller_term(&self) -> u64 {
        self.job.binding.token.leader.term
    }

    pub(crate) fn phase(&self) -> StorageResult<PrivateOramMutationAppendJobPhaseV2> {
        self.job
            .phase
            .lock()
            .map(|phase| *phase)
            .map_err(|_| StorageError::service_error("private ORAM mutation append job poisoned"))
    }

    pub(crate) fn begin_owner_prestage(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::PrestagePending,
            PrivateOramMutationAppendJobPhaseV2::Prestaging,
        )
    }

    pub(crate) fn complete_owner_prestage(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::Prestaging,
            PrivateOramMutationAppendJobPhaseV2::AdmissionReady,
        )
    }

    pub(crate) fn bind_live_admission_permit(
        &self,
        dispatcher: &Dispatcher,
        plan: &PrivateOramMutationAdmissionPlanV2,
        all_owners_prestaged: &PrivateOramMutationAllOwnersPrestagedV2,
    ) -> StorageResult<PrivateOramLiveAdmissionPermitV2> {
        self.ensure_cleanup_not_claimed()?;
        let lease = plan.lease();
        let material = &self.job.material;
        if lease.collection_id != self.job.binding.collection_id
            || lease.mutation_id != self.job.binding.mutation_id
            || lease.generation != material.session.response.mutation_lease_generation
            || lease.writer_fence != material.session.response.writer_fence
        {
            return Err(invalid_mutation_session());
        }
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if *phase != PrivateOramMutationAppendJobPhaseV2::AdmissionReady {
            return Err(invalid_mutation_session());
        }
        let seed = material
            .session
            .admission_seed
            .as_ref()
            .ok_or_else(invalid_mutation_session)?;
        let session_commitment = private_oram_mutation_live_session_commitment_v2(&self.job)?;
        let permit = dispatcher.bind_private_oram_mutation_live_admission_permit_v2(
            seed,
            session_commitment,
            plan,
            all_owners_prestaged,
        )?;
        *phase = PrivateOramMutationAppendJobPhaseV2::AdmissionSubmitting;
        Ok(permit)
    }

    pub(crate) fn quarantine(&self) -> StorageResult<()> {
        self.ensure_cleanup_not_claimed()?;
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if matches!(
            *phase,
            PrivateOramMutationAppendJobPhaseV2::AdmissionSubmitting
                | PrivateOramMutationAppendJobPhaseV2::AdmissionUnknown
                | PrivateOramMutationAppendJobPhaseV2::AdmittedAckPending
                | PrivateOramMutationAppendJobPhaseV2::AdmittedAckComplete
                | PrivateOramMutationAppendJobPhaseV2::RejectedAckPending
                | PrivateOramMutationAppendJobPhaseV2::RejectedAckComplete
                | PrivateOramMutationAppendJobPhaseV2::NotSubmitted
                | PrivateOramMutationAppendJobPhaseV2::TerminalCommitted
                | PrivateOramMutationAppendJobPhaseV2::TerminalAborted
        ) {
            return Err(invalid_mutation_session());
        }
        *phase = PrivateOramMutationAppendJobPhaseV2::Quarantined;
        Ok(())
    }

    pub(crate) fn mark_admission_unknown(&self) -> StorageResult<()> {
        self.ensure_cleanup_not_claimed()?;
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        match *phase {
            PrivateOramMutationAppendJobPhaseV2::AdmissionSubmitting => {
                *phase = PrivateOramMutationAppendJobPhaseV2::AdmissionUnknown;
                Ok(())
            }
            PrivateOramMutationAppendJobPhaseV2::AdmissionUnknown => Ok(()),
            _ => Err(invalid_mutation_session()),
        }
    }

    pub(crate) fn mark_admitted_ack_pending(&self) -> StorageResult<()> {
        self.transition_admission_outcome(PrivateOramMutationAppendJobPhaseV2::AdmittedAckPending)
    }

    pub(crate) fn mark_parent_sequence1(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::AdmittedAckPending,
            PrivateOramMutationAppendJobPhaseV2::ParentSequence1,
        )
    }

    pub(crate) fn begin_owner_adoption(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::ParentSequence1,
            PrivateOramMutationAppendJobPhaseV2::OwnersAdopting,
        )
    }

    pub(crate) fn mark_parent_sequence2(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::OwnersAdopting,
            PrivateOramMutationAppendJobPhaseV2::ParentSequence2,
        )
    }

    pub(crate) fn mark_admitted_ack_complete(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::PointsStaging,
            PrivateOramMutationAppendJobPhaseV2::AdmittedAckComplete,
        )
    }

    pub(crate) fn begin_point_staging(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::ParentSequence2,
            PrivateOramMutationAppendJobPhaseV2::PointsStaging,
        )
    }

    pub(crate) fn mark_deciding(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::AdmittedAckComplete,
            PrivateOramMutationAppendJobPhaseV2::Deciding,
        )
    }

    pub(crate) fn mark_rejected_ack_pending(&self) -> StorageResult<()> {
        self.transition_admission_outcome(PrivateOramMutationAppendJobPhaseV2::RejectedAckPending)
    }

    pub(crate) fn mark_rejected_ack_complete(&self) -> StorageResult<()> {
        self.transition_phase(
            PrivateOramMutationAppendJobPhaseV2::RejectedAckPending,
            PrivateOramMutationAppendJobPhaseV2::RejectedAckComplete,
        )
    }

    pub(crate) fn mark_not_submitted(&self) -> StorageResult<()> {
        self.ensure_cleanup_not_claimed()?;
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if !matches!(
            *phase,
            PrivateOramMutationAppendJobPhaseV2::AdmissionReady
                | PrivateOramMutationAppendJobPhaseV2::AdmissionSubmitting
        ) {
            return Err(invalid_mutation_session());
        }
        *phase = PrivateOramMutationAppendJobPhaseV2::NotSubmitted;
        Ok(())
    }

    pub(crate) fn mark_preadmission_recovery_required(&self) -> StorageResult<()> {
        self.ensure_cleanup_not_claimed()?;
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if !matches!(
            *phase,
            PrivateOramMutationAppendJobPhaseV2::AdmissionReady
                | PrivateOramMutationAppendJobPhaseV2::AdmissionSubmitting
        ) {
            return Err(invalid_mutation_session());
        }
        *phase = PrivateOramMutationAppendJobPhaseV2::Quarantined;
        Ok(())
    }

    fn transition_admission_outcome(
        &self,
        next: PrivateOramMutationAppendJobPhaseV2,
    ) -> StorageResult<()> {
        self.ensure_cleanup_not_claimed()?;
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if !matches!(
            *phase,
            PrivateOramMutationAppendJobPhaseV2::AdmissionReady
                | PrivateOramMutationAppendJobPhaseV2::AdmissionSubmitting
                | PrivateOramMutationAppendJobPhaseV2::AdmissionUnknown
        ) {
            return Err(invalid_mutation_session());
        }
        *phase = next;
        Ok(())
    }

    fn transition_phase(
        &self,
        expected: PrivateOramMutationAppendJobPhaseV2,
        next: PrivateOramMutationAppendJobPhaseV2,
    ) -> StorageResult<()> {
        self.ensure_cleanup_not_claimed()?;
        let mut phase = self.job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if *phase != expected {
            return Err(invalid_mutation_session());
        }
        *phase = next;
        Ok(())
    }

    pub(crate) fn immutable_manifest(&self) -> &PrivateOramImmutableManifestBundleV2 {
        &self.job.material.session.immutable_manifest
    }

    pub(crate) fn collection_name(&self) -> &str {
        &self.job.material.session.collection_name
    }

    pub(crate) fn vector_name(&self) -> &str {
        &self.job.material.session.response.vector_name
    }

    pub(crate) fn validated_owner_prepare(&self) -> &PrivateOramValidatedOwnerPrepareV1 {
        &self.job.material.validated_owner_prepare
    }

    pub(crate) fn owner_prepare_for_transport(&self) -> &PrivateOramAppendOwnerPrepareV1 {
        &self.job.material.owner_prepare
    }

    pub(crate) fn durable_read_observations(&self) -> &[PrivateOramDurableReadObservationV2] {
        &self.job.material.durable_read_observations
    }

    pub(crate) fn staged_insert_frame_bytes(&self) -> Option<&[u8]> {
        self.job.material.staged_insert_frame_bytes.as_deref()
    }

    pub(crate) fn consensus_state(&self) -> &PrivateOramConsensusCollectionStateV2 {
        &self.job.material.consensus_state
    }

    pub(crate) fn consensus_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        &self.job.material.consensus_slot
    }

    pub(crate) fn consensus_layout(&self) -> &PrivateOramConsensusLayout {
        &self.job.material.consensus_layout
    }
}

fn session_registry() -> &'static Mutex<PrivateOramMutationSessionRegistryV2> {
    static REGISTRY: OnceLock<Mutex<PrivateOramMutationSessionRegistryV2>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(PrivateOramMutationSessionRegistryV2::default()))
}

pub(crate) fn private_oram_detached_job_exists_for_collection_v2(
    collection_id: &str,
) -> StorageResult<bool> {
    let registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private ORAM mutation session registry is poisoned")
    })?;
    for job in registry
        .append_jobs
        .values()
        .filter(|job| job.binding.collection_id == collection_id)
    {
        let phase = *job.phase.lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation append job poisoned")
        })?;
        if !matches!(
            phase,
            PrivateOramMutationAppendJobPhaseV2::Deciding
                | PrivateOramMutationAppendJobPhaseV2::Finalizing
                | PrivateOramMutationAppendJobPhaseV2::Cleaning
                | PrivateOramMutationAppendJobPhaseV2::TerminalCommitted
                | PrivateOramMutationAppendJobPhaseV2::TerminalAborted
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[must_use]
pub(crate) struct PrivateOramMutationQuiescedCleanupV2 {
    claim: PrivateOramMutationCleanupClaimBindingV2,
    process_incarnation: String,
    restart_absence: bool,
}

impl Debug for PrivateOramMutationQuiescedCleanupV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationQuiescedCleanupV2")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("owner_peer_id", &self.claim.authority.owner_peer_id)
            .field("generation", &self.claim.authority.generation)
            .field("cleanup_claim", &"[redacted]")
            .field("process_incarnation", &"[redacted]")
            .field("restart_absence", &self.restart_absence)
            .finish()
    }
}

impl PrivateOramMutationQuiescedCleanupV2 {
    pub(crate) fn validate(
        &self,
        identity: &PrivateOramPeerRecoveryIdentity,
        permit: &PrivateOramMutationNeedLocalCleanupV2,
    ) -> StorageResult<()> {
        let expected = private_oram_mutation_cleanup_claim_binding_v2(permit);
        let process_incarnation = identity
            .require_process_lifetime_fence(expected.authority.owner_peer_id)
            .map_err(|_| {
                StorageError::service_error(
                    "private ORAM mutation process-lifetime fence is unavailable",
                )
            })?;
        self.validate_binding(&expected, process_incarnation)
    }

    fn validate_binding(
        &self,
        expected: &PrivateOramMutationCleanupClaimBindingV2,
        process_incarnation: &str,
    ) -> StorageResult<()> {
        if &self.claim != expected || self.process_incarnation != process_incarnation {
            return Err(StorageError::service_error(
                "private ORAM mutation cleanup quiescence binding changed",
            ));
        }
        Ok(())
    }
}

fn private_oram_mutation_cleanup_claim_binding_v2(
    permit: &PrivateOramMutationNeedLocalCleanupV2,
) -> PrivateOramMutationCleanupClaimBindingV2 {
    let (descriptor_digest, terminal_record_digest, witness_digest, cleanup_evidence_digest) =
        permit.cleanup_claim_binding();
    PrivateOramMutationCleanupClaimBindingV2 {
        authority: PrivateOramMutationRuntimeAuthorityV2 {
            collection_id: permit.collection_id().to_string(),
            mutation_id: permit.mutation_id().to_string(),
            owner_peer_id: permit.owner_peer_id(),
            generation: permit.generation(),
        },
        descriptor_digest: descriptor_digest.to_string(),
        terminal_record_digest: terminal_record_digest.to_string(),
        witness_digest: witness_digest.to_string(),
        cleanup_evidence_digest: cleanup_evidence_digest.to_string(),
    }
}

async fn wait_for_private_oram_mutation_worker_quiescence_v2(
    worker_active: &AtomicBool,
    worker_quiesced: &Notify,
) {
    loop {
        let notified = worker_quiesced.notified();
        if !worker_active.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

pub(crate) async fn complete_private_oram_detached_job_local_cleanup_v2(
    identity: &PrivateOramPeerRecoveryIdentity,
    permit: &PrivateOramMutationNeedLocalCleanupV2,
) -> StorageResult<PrivateOramMutationQuiescedCleanupV2> {
    let claim = private_oram_mutation_cleanup_claim_binding_v2(permit);
    let process_incarnation = identity
        .require_process_lifetime_fence(claim.authority.owner_peer_id)
        .map_err(|_| {
            StorageError::service_error(
                "private ORAM mutation process-lifetime fence is unavailable",
            )
        })?
        .to_string();
    complete_private_oram_detached_job_local_cleanup_with_binding_v2(claim, process_incarnation)
        .await
}

async fn complete_private_oram_detached_job_local_cleanup_with_binding_v2(
    claim: PrivateOramMutationCleanupClaimBindingV2,
    process_incarnation: String,
) -> StorageResult<PrivateOramMutationQuiescedCleanupV2> {
    let authority = &claim.authority;
    let collection_id = authority.collection_id.as_str();
    let claimed = {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?;
        if let Some(existing) = registry.cleanup_tombstones.get(authority) {
            if existing != &claim {
                return Err(StorageError::service_error(
                    "private ORAM mutation cleanup tombstone binding changed",
                ));
            }
            return Ok(PrivateOramMutationQuiescedCleanupV2 {
                claim,
                process_incarnation,
                restart_absence: false,
            });
        }
        if registry
            .cleanup_claims
            .get(collection_id)
            .is_some_and(|existing| existing != &claim)
        {
            return Err(StorageError::service_error(
                "private ORAM mutation cleanup claim binding changed",
            ));
        }
        if registry.opening_collections.contains(collection_id) {
            return Err(StorageError::service_error(
                "private ORAM mutation cleanup found an open reservation in progress",
            ));
        }
        let matching = registry
            .append_jobs
            .values()
            .filter(|job| job.binding.collection_id == collection_id)
            .cloned()
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [] => {
                if registry.seen_job_authorities.contains(authority) {
                    return Err(StorageError::service_error(
                        "private ORAM mutation cleanup found an unexpectedly missing same-process job",
                    ));
                }
                if registry.active_by_collection.contains_key(collection_id)
                    || registry
                        .sessions
                        .values()
                        .any(|session| session.response.collection_id == collection_id)
                {
                    return Err(StorageError::service_error(
                        "private ORAM mutation cleanup found a session without its exact runtime job",
                    ));
                }
                registry
                    .cleanup_claimed_collections
                    .insert(collection_id.to_string());
                registry
                    .cleanup_claims
                    .insert(collection_id.to_string(), claim.clone());
                None
            }
            [job] => {
                if private_oram_mutation_job_authority_v2(job)? != *authority {
                    return Err(StorageError::service_error(
                        "private ORAM mutation cleanup authority does not match the runtime job",
                    ));
                }
                let mut phase = job.phase.lock().map_err(|_| {
                    StorageError::service_error("private ORAM mutation append job poisoned")
                })?;
                if !matches!(
                    *phase,
                    PrivateOramMutationAppendJobPhaseV2::Deciding
                        | PrivateOramMutationAppendJobPhaseV2::Finalizing
                        | PrivateOramMutationAppendJobPhaseV2::Cleaning
                ) {
                    return Err(invalid_mutation_session());
                }
                let session = registry
                    .sessions
                    .get(&job.binding.session_id)
                    .filter(|session| {
                        session.response.collection_id == collection_id
                            && session.response.mutation_id == authority.mutation_id
                            && session.response.mutation_lease_generation == authority.generation
                            && session.incarnation == job.binding.token.session_incarnation
                    })
                    .cloned()
                    .ok_or_else(|| {
                        StorageError::service_error(
                            "private ORAM mutation cleanup found a job without its exact runtime session",
                        )
                    })?;
                registry
                    .cleanup_claimed_collections
                    .insert(collection_id.to_string());
                registry
                    .cleanup_claims
                    .insert(collection_id.to_string(), claim.clone());
                job.cleanup_claimed.store(true, Ordering::Release);
                *phase = PrivateOramMutationAppendJobPhaseV2::Cleaning;
                Some((Arc::clone(job), session))
            }
            _ => {
                return Err(StorageError::service_error(
                    "private ORAM mutation append job registry is inconsistent",
                ));
            }
        }
    };

    let restart_absence = claimed.is_none();
    if let Some((job, session)) = claimed {
        wait_for_private_oram_mutation_worker_quiescence_v2(
            &job.worker_active,
            &job.worker_quiesced,
        )
        .await;
        release_underlying_sessions(&session)?;
    }

    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private ORAM mutation session registry poisoned")
    })?;
    let matching_job = registry
        .append_jobs
        .iter()
        .find(|(_, job)| job.binding.collection_id == collection_id)
        .map(|(job_key, job)| (job_key.clone(), Arc::clone(job)));
    if let Some((job_key, job)) = matching_job {
        if private_oram_mutation_job_authority_v2(&job)? != *authority
            || job.worker_active.load(Ordering::Acquire)
            || !job.cleanup_claimed.load(Ordering::Acquire)
            || *job.phase.lock().map_err(|_| {
                StorageError::service_error("private ORAM mutation append job poisoned")
            })? != PrivateOramMutationAppendJobPhaseV2::Cleaning
        {
            return Err(StorageError::service_error(
                "private ORAM mutation cleanup did not reach runtime quiescence",
            ));
        }
        let session_id = job.binding.session_id.clone();
        let expected_incarnation = job.binding.token.session_incarnation;
        let removed_job = registry
            .append_jobs
            .remove(&job_key)
            .ok_or_else(invalid_mutation_session)?;
        if !Arc::ptr_eq(&removed_job, &job) {
            return Err(invalid_mutation_session());
        }
        let removed = registry.sessions.remove(&session_id).ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation cleanup lost its exact runtime session",
            )
        })?;
        if removed.response.collection_id != collection_id
            || removed.response.mutation_id != authority.mutation_id
            || removed.response.mutation_lease_generation != authority.generation
            || removed.incarnation != expected_incarnation
            || registry
                .active_by_collection
                .get(collection_id)
                .is_none_or(|active| active != &session_id)
        {
            return Err(invalid_mutation_session());
        }
        registry.active_by_collection.remove(collection_id);
    } else if registry.seen_job_authorities.contains(authority)
        && !registry.cleanup_tombstones.contains_key(authority)
    {
        return Err(StorageError::service_error(
            "private ORAM mutation cleanup lost its claimed same-process job",
        ));
    }
    if registry.cleanup_claims.get(collection_id) != Some(&claim) {
        return Err(StorageError::service_error(
            "private ORAM mutation cleanup lost its exact claim",
        ));
    }
    if registry.opening_collections.contains(collection_id)
        || registry.active_by_collection.contains_key(collection_id)
        || registry
            .sessions
            .values()
            .any(|session| session.response.collection_id == collection_id)
        || registry
            .append_jobs
            .values()
            .any(|job| job.binding.collection_id == collection_id)
    {
        return Err(StorageError::service_error(
            "private ORAM mutation cleanup did not preserve exact negative presence",
        ));
    }
    if registry
        .cleanup_tombstones
        .insert(authority.clone(), claim.clone())
        .is_some()
    {
        return Err(StorageError::service_error(
            "private ORAM mutation cleanup tombstone changed concurrently",
        ));
    }
    registry.cleanup_claims.remove(collection_id);
    registry.cleanup_claimed_collections.remove(collection_id);
    Ok(PrivateOramMutationQuiescedCleanupV2 {
        claim,
        process_incarnation,
        restart_absence,
    })
}

pub(crate) async fn do_open_private_oram_mutation_session_v2(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    input: PrivateOramMutationOpenInputV2,
) -> StorageResult<PrivateOramMutationOpenResponseV2> {
    let leader = current_active_mutation_leader_token(dispatcher)?;
    validate_mutation_id(&input.mutation_id)?;

    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_session_open_v2",
    )?;
    let verification_pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &verification_pass);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &input.vector_name,
        &input.immutable_manifest.manifest.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != collection_id {
        return Err(invalid_mutation_session());
    }
    let signature_verification = PrivateOramSignatureVerification {
        expected_key_id: &input.immutable_manifest.manifest.owner_signing_key_id,
        public_key: hnsw_context.public_key(),
    };
    validate_open_crypto_material(&collection_id, &input, signature_verification)?;
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&input.immutable_manifest.manifest)
            .map_err(|_| invalid_mutation_session())?;
    let old_state_digest = private_oram_signed_state_v2_digest(&input.old_state.state)
        .map_err(|_| invalid_mutation_session())?;

    let key = PrivateOramMutationKey {
        collection_id: collection_id.clone(),
    };
    let current_state = dispatcher
        .private_oram_consensus_mutation_state(&key)?
        .ok_or_else(invalid_mutation_session)?;
    let current_slot = dispatcher
        .private_oram_consensus_mutation_lease_slot(&key)?
        .ok_or_else(invalid_mutation_session)?;
    let layout_key = PrivateOramLayoutKey {
        collection_id: collection_id.clone(),
    };
    let layout = dispatcher
        .private_oram_consensus_layout(&layout_key)?
        .ok_or_else(invalid_mutation_session)?;
    validate_open_consensus_bindings(
        dispatcher.this_peer_id(),
        &manifest_digest,
        &old_state_digest,
        &input.old_state.state,
        &current_state,
        &current_slot,
        &layout,
    )?;

    let mutation_lease_generation = current_slot
        .generation
        .checked_add(1)
        .ok_or_else(invalid_mutation_session)?;
    let writer_fence = current_slot
        .max_writer_fence
        .checked_add(1)
        .ok_or_else(invalid_mutation_session)?;
    let issued_at_unix = current_unix_secs()?;
    let requested_expires_unix = issued_at_unix
        .checked_add(PRIVATE_ORAM_MUTATION_SESSION_LEASE_SECS)
        .ok_or_else(invalid_mutation_session)?;
    let writer_lease_digest = new_writer_lease_digest(
        &collection_id,
        &input.mutation_id,
        mutation_lease_generation,
        writer_fence,
    );

    let hnsw_old_epoch =
        signed_index(&input.old_state.state, PrivateOramIndexKindV2::Hnsw)?.index_epoch;
    let has_result =
        manifest_index_optional(&input.immutable_manifest, PrivateOramIndexKindV2::Result)
            .is_some();
    let result_old_epoch = if has_result {
        Some(signed_index(&input.old_state.state, PrivateOramIndexKindV2::Result)?.index_epoch)
    } else {
        None
    };
    let mut reservation =
        PrivateOramMutationOpenReservation::acquire(&collection_id, issued_at_unix)?;
    let mut opened = PrivateOramOpenedIndexSessions::new(&collection_id, &input.vector_name);
    let hnsw_session = match do_open_private_hnsw_session_for_paired_mutation(
        toc,
        auth,
        settings,
        collection_name,
        &input.vector_name,
        input.client_id.clone(),
        hnsw_old_epoch,
        true,
        input.immutable_manifest.manifest.result_privacy,
    )
    .await
    {
        Ok(session) => session,
        Err(error) => return Err(error),
    };
    opened.hnsw_session_id = Some(hnsw_session.session_id.clone());

    let result_session = if let Some(result_old_epoch) = result_old_epoch {
        match do_open_private_result_oram_session_for_paired_mutation(
            toc,
            auth,
            settings,
            collection_name,
            input.client_id.clone(),
            result_old_epoch,
            true,
        )
        .await
        {
            Ok(session) => {
                opened.result_session_id = Some(session.session_id.clone());
                Some(session)
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };

    let lease_expires_unix = result_session
        .as_ref()
        .map_or(hnsw_session.lease_expires_unix, |result| {
            hnsw_session
                .lease_expires_unix
                .min(result.lease_expires_unix)
        })
        .min(requested_expires_unix);
    let mut built = build_session(
        collection_name,
        input,
        manifest_digest,
        old_state_digest,
        mutation_lease_generation,
        writer_lease_digest,
        writer_fence,
        issued_at_unix,
        lease_expires_unix,
        hnsw_context.public_key().to_vec(),
        leader,
        hnsw_session.clone(),
        result_session.clone(),
    )?;
    let response = built.response.clone();

    let still_current = current_active_mutation_leader_token(dispatcher)
        .is_ok_and(|current| current == leader)
        && matches!(
            (
                dispatcher.private_oram_consensus_mutation_state(&key),
                dispatcher.private_oram_consensus_mutation_lease_slot(&key),
                dispatcher.private_oram_consensus_layout(&layout_key),
            ),
            (Ok(Some(state)), Ok(Some(slot)), Ok(Some(current_layout)))
                if state == current_state && slot == current_slot && current_layout == layout
        )
        && collection.config_snapshot().await == config;
    if !still_current {
        return Err(invalid_mutation_session());
    }

    let admission_seed = dispatcher.issue_private_oram_mutation_live_admission_seed_v2(
        &built.response.collection_id,
        &built.response.mutation_id,
        built.response.lease_expires_unix,
    )?;
    built.admission_seed = Some(admission_seed.clone());

    let install_result = match session_registry().lock() {
        Ok(mut registry) => registry.install(built),
        Err(_) => Err(StorageError::service_error(
            "private ORAM mutation session registry poisoned",
        )),
    };
    if let Err(error) = install_result {
        dispatcher.revoke_private_oram_mutation_live_admission_seed_v2(&admission_seed);
        return Err(error);
    }
    reservation.disarm();
    opened.disarm();
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_read_private_oram_mutation_hnsw_paths_v2(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
    paths: Vec<String>,
    padding: PrivateHnswReadPadding,
    client_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    // Authorize before the registry is touched: an unauthorized caller must neither flip the
    // session's read-in-progress state nor learn from distinct errors whether it exists.
    // Reads move session state (read-in-progress, path budget), so they need the same write
    // access as opening, reporting and closing the session.
    auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_read_hnsw_paths",
    )?;
    let leader = current_active_mutation_leader_token(dispatcher)?;
    let now_unix = current_unix_secs()?;
    reap_expired_sessions(now_unix)?;
    let routing = {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?;
        let session = registry.session_mut(collection_name, session_id, now_unix)?;
        if session.leader != leader || session.freeze_owner.is_some() || session.closing {
            return Err(invalid_mutation_session());
        }
        session.hnsw.begin_read()?;
        (
            session.response.vector_name.clone(),
            session.hnsw.session_id.clone(),
            session.hnsw.index_epoch,
            session.hnsw.root_hash.clone(),
        )
    };
    let verification_pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &verification_pass);
    let result = do_read_private_hnsw_paths_for_paired_mutation(
        toc,
        auth,
        settings,
        collection_name,
        &routing.0,
        &routing.1,
        routing.2,
        &routing.3,
        paths.clone(),
        padding,
        client_signature,
    )
    .await
    .and_then(|response| {
        require_active_mutation_leader(dispatcher)?;
        Ok(response)
    });
    finish_hnsw_read(collection_name, session_id, now_unix, result, paths)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_read_private_oram_mutation_result_buckets_v2(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
    bucket_ids: Vec<u64>,
    read_signature: PrivateResultOramSignature,
) -> StorageResult<PrivateResultOramReadBucketsResponse> {
    auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_read_result_buckets",
    )?;
    let leader = current_active_mutation_leader_token(dispatcher)?;
    let now_unix = current_unix_secs()?;
    reap_expired_sessions(now_unix)?;
    let routing = {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?;
        let session = registry.session_mut(collection_name, session_id, now_unix)?;
        if session.leader != leader || session.freeze_owner.is_some() || session.closing {
            return Err(invalid_mutation_session());
        }
        let result = session
            .result
            .as_mut()
            .ok_or_else(invalid_mutation_session)?;
        result.begin_read()?;
        (
            result.session_id.clone(),
            result.index_epoch,
            result.root_hash.clone(),
            result.tree_height,
        )
    };
    let verification_pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &verification_pass);
    let result = do_read_private_result_oram_buckets_for_paired_mutation(
        toc,
        auth,
        settings,
        collection_name,
        &routing.0,
        routing.1,
        routing.2,
        bucket_ids.clone(),
        read_signature,
    )
    .await
    .and_then(|response| {
        require_active_mutation_leader(dispatcher)?;
        Ok(response)
    });
    let (result, paths) = match result {
        Ok(response) => match result_leaf_labels(&bucket_ids, routing.3) {
            Ok(paths) => (Ok(response), Some(paths)),
            Err(error) => (Err(error), None),
        },
        Err(error) => (Err(error), None),
    };
    finish_result_read(collection_name, session_id, now_unix, result, paths)
}

pub(crate) async fn do_validate_private_oram_mutation_append_v2(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    input: PrivateOramMutationAppendInputV2,
) -> StorageResult<PrivateOramValidatedMutationAppendV2> {
    let leader = current_active_mutation_leader_token(dispatcher)?;
    validate_mutation_session_id(&input.session_id)?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_append_validate_v2",
    )?;
    let now_unix = current_unix_secs()?;
    reap_expired_sessions(now_unix)?;
    let (reservation, session, read_evidence) = PrivateOramMutationAppendReservationV2::acquire(
        collection_name,
        &input.session_id,
        now_unix,
        leader,
    )?;
    if session.response.lease_expires_unix <= now_unix {
        return Err(StorageError::bad_request(
            "private ORAM mutation session is missing or expired",
        ));
    }

    let verification_pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &verification_pass);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &session.response.vector_name,
        &session.immutable_manifest.manifest.owner_signing_key_id,
    )?;
    if collection_id != session.response.collection_id
        || hnsw_context.collection_crypto_id() != collection_id
        || hnsw_context.public_key() != session.owner_public_key
    {
        return Err(invalid_mutation_session());
    }

    let key = PrivateOramMutationKey {
        collection_id: collection_id.clone(),
    };
    let state = dispatcher
        .private_oram_consensus_mutation_state(&key)?
        .ok_or_else(invalid_mutation_session)?;
    let slot = dispatcher
        .private_oram_consensus_mutation_lease_slot(&key)?
        .ok_or_else(invalid_mutation_session)?;
    let layout_key = PrivateOramLayoutKey {
        collection_id: collection_id.clone(),
    };
    let layout = dispatcher
        .private_oram_consensus_layout(&layout_key)?
        .ok_or_else(invalid_mutation_session)?;
    validate_append_consensus_bindings(
        dispatcher.this_peer_id(),
        &session,
        &state,
        &slot,
        &layout,
    )?;

    let (staged_insert_frame, staged_insert_frame_bytes, point_id, staged_insert_digest) =
        decode_append_staged_insert_frame(input.staged_insert_frame_b64.as_deref())?;
    let expected_visible_point_record = match session.immutable_manifest.manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => {
            let frame = staged_insert_frame
                .as_ref()
                .ok_or_else(invalid_mutation_session)?;
            if !frame.point.vectors.is_empty() {
                return Err(StorageError::bad_request(
                    "private ORAM staged point must not contain server vectors",
                ));
            }
            Some(PrivateOramVisiblePointRecordV1 {
                point_id: point_id.as_deref().ok_or_else(invalid_mutation_session)?,
                staged_insert_sha256: staged_insert_digest
                    .as_deref()
                    .ok_or_else(invalid_mutation_session)?,
            })
        }
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if staged_insert_frame.is_some() {
                return Err(invalid_mutation_session());
            }
            None
        }
    };
    let mutation = &input.owner_prepare.mutation_bundle.mutation;
    validate_append_session_binding(&session, mutation)?;
    let max_mutation_ttl_secs = session
        .response
        .lease_expires_unix
        .checked_sub(session.response.issued_at_unix)
        .ok_or_else(invalid_mutation_session)?;
    let validated_owner_prepare = validate_private_oram_append_owner_prepare_v1(
        &session.immutable_manifest,
        &input.owner_prepare,
        PrivateOramAppendOwnerPrepareValidationContextV1 {
            expected_collection_id: &session.response.collection_id,
            expected_manifest_digest: &session.response.manifest_digest,
            expected_owner_signing_key_id: &session
                .immutable_manifest
                .manifest
                .owner_signing_key_id,
            expected_layout_generation: layout.generation,
            expected_layout_digest: &layout.layout_digest,
            expected_writer_lease_digest: &session.response.writer_lease_digest,
            expected_writer_fence: session.response.writer_fence,
            expected_state_sequence: session.old_state.state.state_sequence,
            expected_old_state_digest: &session.response.old_state_digest,
            expected_visible_point_record,
            server_read_evidence_recorder: &session.recorder,
            server_read_evidence: &read_evidence,
            now_unix,
            max_mutation_ttl_secs,
            public_key: &session.owner_public_key,
        },
    )
    .map_err(|_| invalid_mutation_session())?;
    if let Some(frame) = staged_insert_frame.as_ref() {
        validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
            frame,
            validated_owner_prepare.mutation_bundle(),
        )
        .map_err(|_| invalid_mutation_session())?;
    }

    if current_active_mutation_leader_token(dispatcher)? != leader {
        return Err(invalid_mutation_session());
    }
    let post_now_unix = current_unix_secs()?;
    if post_now_unix >= session.response.lease_expires_unix
        || collection.config_snapshot().await != config
        || dispatcher
            .private_oram_consensus_mutation_state(&key)?
            .as_ref()
            != Some(&state)
        || dispatcher
            .private_oram_consensus_mutation_lease_slot(&key)?
            .as_ref()
            != Some(&slot)
        || dispatcher
            .private_oram_consensus_layout(&layout_key)?
            .as_ref()
            != Some(&layout)
    {
        return Err(invalid_mutation_session());
    }

    let observed_read_transcripts = validated_owner_prepare
        .indexes()
        .iter()
        .map(|index| index.read_transcript().clone())
        .collect::<Vec<_>>();
    let durable_read_observations =
        private_oram_owner_prestage_read_observations_v2(&observed_read_transcripts)
            .map_err(|_| invalid_mutation_session())?;
    Ok(PrivateOramValidatedMutationAppendV2 {
        reservation,
        material: PrivateOramValidatedMutationAppendMaterialV2 {
            session,
            validated_owner_prepare,
            owner_prepare: input.owner_prepare,
            durable_read_observations,
            staged_insert_frame,
            staged_insert_frame_bytes,
            consensus_state: state,
            consensus_slot: slot,
            consensus_layout: layout,
        },
    })
}

pub(crate) fn private_oram_mutation_session_status_v2(
    auth: &Auth,
    collection_name: &str,
    session_id: &str,
) -> StorageResult<PrivateOramMutationSessionStatusV2> {
    auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_session_status_v2",
    )?;
    let now_unix = current_unix_secs()?;
    reap_expired_sessions(now_unix)?;
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private ORAM mutation session registry poisoned")
    })?;
    let (job_key, session_incarnation) = {
        let session = registry.session_mut(collection_name, session_id, now_unix)?;
        let job_key = match session.freeze_owner.as_ref() {
            Some(PrivateOramMutationFreezeOwnerV2::Job { mutation_id, .. }) => {
                Some(private_oram_mutation_append_job_key_v2(
                    &session.response.collection_id,
                    mutation_id,
                ))
            }
            _ => None,
        };
        (job_key, session.incarnation)
    };
    let append_phase = match job_key.as_ref() {
        Some(key) => {
            let job = registry
                .append_jobs
                .get(key)
                .filter(|job| {
                    job.binding.session_id == session_id
                        && job.binding.token.session_incarnation == session_incarnation
                })
                .ok_or_else(invalid_mutation_session)?;
            Some(job.phase.lock().map(|phase| *phase).map_err(|_| {
                StorageError::service_error("private ORAM mutation append job poisoned")
            })?)
        }
        None => None,
    };
    let session = registry.session_mut(collection_name, session_id, now_unix)?;
    if session.closing {
        return Err(invalid_mutation_session());
    }
    session.status(append_phase)
}

pub(crate) fn close_private_oram_mutation_session_v2(
    auth: &Auth,
    collection_name: &str,
    session_id: &str,
) -> StorageResult<bool> {
    auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_session_close_v2",
    )?;
    let now_unix = current_unix_secs()?;
    reap_expired_sessions(now_unix)?;
    let session = {
        let mut registry = session_registry().lock().map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?;
        let session = registry.session_mut(collection_name, session_id, now_unix)?;
        if session.freeze_owner.is_some()
            || session.closing
            || session.hnsw.read_in_progress
            || session
                .result
                .as_ref()
                .is_some_and(|result| result.read_in_progress)
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation session has an operation in progress",
            ));
        }
        session.closing = true;
        session.clone()
    };
    if let Err(error) = release_underlying_sessions(&session) {
        if let Ok(mut registry) = session_registry().lock()
            && let Some(current) = registry.sessions.get_mut(session_id)
            && current.response.collection_id == session.response.collection_id
        {
            current.closing = false;
        }
        return Err(error);
    }
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private ORAM mutation session registry poisoned")
    })?;
    let removed = registry
        .sessions
        .remove(session_id)
        .ok_or_else(invalid_mutation_session)?;
    registry
        .active_by_collection
        .remove(&removed.response.collection_id);
    Ok(true)
}

fn finish_hnsw_read(
    collection_name: &str,
    session_id: &str,
    now_unix: u64,
    result: StorageResult<PrivateHnswReadPathsResponse>,
    paths: Vec<String>,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private ORAM mutation session registry poisoned")
    })?;
    let session = registry.session_mut(collection_name, session_id, now_unix)?;
    match result {
        Ok(response) => {
            session.hnsw.finish_read(paths)?;
            Ok(response)
        }
        Err(error) => {
            session.hnsw.cancel_read();
            Err(error)
        }
    }
}

fn finish_result_read(
    collection_name: &str,
    session_id: &str,
    now_unix: u64,
    result: StorageResult<PrivateResultOramReadBucketsResponse>,
    paths: Option<Vec<String>>,
) -> StorageResult<PrivateResultOramReadBucketsResponse> {
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private ORAM mutation session registry poisoned")
    })?;
    let session = registry.session_mut(collection_name, session_id, now_unix)?;
    let state = session
        .result
        .as_mut()
        .ok_or_else(invalid_mutation_session)?;
    match (result, paths) {
        (Ok(response), Some(paths)) => {
            state.finish_read(paths)?;
            Ok(response)
        }
        (Err(error), _) => {
            state.cancel_read();
            Err(error)
        }
        (Ok(_), None) => {
            state.cancel_read();
            Err(invalid_mutation_session())
        }
    }
}

fn release_open_reservation(collection_id: &str) {
    if let Ok(mut registry) = session_registry().lock() {
        registry.release_open(collection_id);
    }
}

fn release_underlying_sessions(session: &PrivateOramMutationSessionV2) -> StorageResult<()> {
    release_raw_underlying_sessions(
        &session.response.collection_id,
        &session.response.vector_name,
        Some(&session.hnsw.session_id),
        session
            .result
            .as_ref()
            .map(|result| result.session_id.as_str()),
    )
}

fn release_raw_underlying_sessions(
    collection_id: &str,
    vector_name: &str,
    hnsw_session_id: Option<&str>,
    result_session_id: Option<&str>,
) -> StorageResult<()> {
    let mut first_error = None;
    if let Some(session_id) = hnsw_session_id
        && let Err(error) =
            release_private_hnsw_session_for_paired_mutation(collection_id, vector_name, session_id)
    {
        first_error = Some(error);
    }
    if let Some(session_id) = result_session_id
        && let Err(error) =
            release_private_result_oram_session_for_paired_mutation(collection_id, session_id)
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    first_error.map_or(Ok(()), Err)
}

fn reap_expired_sessions(now_unix: u64) -> StorageResult<()> {
    let expired = session_registry()
        .lock()
        .map_err(|_| {
            StorageError::service_error("private ORAM mutation session registry poisoned")
        })?
        .drain_expired(now_unix);
    let mut first_error = None;
    for session in expired {
        if let Err(error) = release_underlying_sessions(&session)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[allow(clippy::too_many_arguments)]
fn build_session(
    collection_name: &str,
    input: PrivateOramMutationOpenInputV2,
    manifest_digest: String,
    old_state_digest: String,
    mutation_lease_generation: u64,
    writer_lease_digest: String,
    writer_fence: u64,
    issued_at_unix: u64,
    lease_expires_unix: u64,
    owner_public_key: Vec<u8>,
    leader: PrivateOramMutationLeaderTokenV2,
    hnsw_session: PrivateHnswSessionResponse,
    result_session: Option<PrivateResultOramSessionResponse>,
) -> StorageResult<PrivateOramMutationSessionV2> {
    let hnsw_manifest = manifest_index(&input.immutable_manifest, PrivateOramIndexKindV2::Hnsw)?;
    let hnsw_old = signed_index(&input.old_state.state, PrivateOramIndexKindV2::Hnsw)?;
    validate_live_hnsw_binding(hnsw_manifest, &hnsw_session)?;
    validate_live_session_state(hnsw_old, hnsw_session.index_epoch, &hnsw_session.root_hash)?;
    if input.immutable_manifest.manifest.collection_id != hnsw_session.collection_id
        || input.immutable_manifest.manifest.result_privacy != hnsw_session.manifest.result_privacy
        || input.immutable_manifest.manifest.owner_signing_key_id
            != hnsw_session.manifest.owner_signing_key_id
        || input.immutable_manifest.manifest.created_at_unix
            != hnsw_session.manifest.created_at_unix
    {
        return Err(invalid_mutation_session());
    }
    let mut hnsw = index_read_state(hnsw_manifest, hnsw_session.session_id.clone())?;
    hnsw.index_epoch = hnsw_session.index_epoch;
    hnsw.root_hash = hnsw_session.root_hash.clone();

    let result_manifest =
        manifest_index_optional(&input.immutable_manifest, PrivateOramIndexKindV2::Result);
    let result = match (result_manifest, result_session) {
        (Some(manifest), Some(session)) => {
            let result_old = signed_index(&input.old_state.state, PrivateOramIndexKindV2::Result)?;
            validate_live_result_binding(manifest, &session)?;
            validate_live_session_state(result_old, session.index_epoch, &session.root_hash)?;
            if input.immutable_manifest.manifest.collection_id != session.collection_id
                || input.immutable_manifest.manifest.owner_signing_key_id
                    != session.manifest.owner_signing_key_id
                || input.immutable_manifest.manifest.created_at_unix
                    != session.manifest.created_at_unix
            {
                return Err(invalid_mutation_session());
            }
            let mut state = index_read_state(manifest, session.session_id)?;
            state.index_epoch = session.index_epoch;
            state.root_hash = session.root_hash;
            Some(state)
        }
        (None, None) => None,
        _ => return Err(invalid_mutation_session()),
    };
    let mut indexes = vec![index_session_view(hnsw_manifest, &hnsw)?];
    if let (Some(manifest), Some(state)) = (result_manifest, result.as_ref()) {
        indexes.push(index_session_view(manifest, state)?);
    }
    let response = PrivateOramMutationOpenResponseV2 {
        session_id: uuid::Uuid::new_v4().to_string(),
        collection_id: hnsw_session.collection_id,
        vector_name: input.vector_name.clone(),
        mutation_id: input.mutation_id.clone(),
        manifest_digest,
        old_state_digest,
        mutation_lease_generation,
        writer_lease_digest,
        writer_fence,
        issued_at_unix,
        lease_expires_unix,
        indexes,
    };
    Ok(PrivateOramMutationSessionV2 {
        incarnation: next_private_oram_mutation_session_incarnation_v2()?,
        leader,
        response,
        collection_name: collection_name.to_string(),
        immutable_manifest: input.immutable_manifest,
        old_state: input.old_state,
        owner_public_key,
        recorder: PrivateOramServerReadEvidenceRecorderV1::new(),
        admission_seed: None,
        hnsw,
        result,
        freeze_owner: None,
        closing: false,
    })
}

fn index_read_state(
    manifest: &qdrant_sec::PrivateOramImmutableIndexV2,
    session_id: String,
) -> StorageResult<PrivateOramMutationIndexReadStateV2> {
    let oram = match &manifest.params {
        PrivateOramImmutableIndexParamsV2::Hnsw { oram, .. }
        | PrivateOramImmutableIndexParamsV2::Result { oram, .. } => oram,
    };
    let state = PrivateOramMutationIndexReadStateV2 {
        session_id,
        index_name: manifest.index_name.clone(),
        index_epoch: 0,
        root_hash: String::new(),
        paths_per_window: oram.path_batch_size,
        tree_height: oram.tree_height,
        fixed_append_read_path_count: manifest.capacity.fixed_append_read_path_count,
        windows: Vec::new(),
        read_in_progress: false,
    };
    state.required_window_count()?;
    Ok(state)
}

fn index_session_view(
    manifest: &qdrant_sec::PrivateOramImmutableIndexV2,
    state: &PrivateOramMutationIndexReadStateV2,
) -> StorageResult<PrivateOramMutationIndexSessionV2> {
    state.required_window_count()?;
    Ok(PrivateOramMutationIndexSessionV2 {
        kind: manifest.kind(),
        index_name: state.index_name.clone(),
        read_session_id: state.session_id.clone(),
        index_epoch: state.index_epoch,
        root_hash: state.root_hash.clone(),
        paths_per_window: state.paths_per_window,
        tree_height: state.tree_height,
        fixed_append_read_path_count: state.fixed_append_read_path_count,
    })
}

fn validate_live_hnsw_binding(
    immutable: &qdrant_sec::PrivateOramImmutableIndexV2,
    session: &PrivateHnswSessionResponse,
) -> StorageResult<()> {
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        provider,
        binding,
        key_id,
        rk_id,
        rk_epoch,
        dim,
        distance,
        hnsw,
        oram,
        fixed_search_budget,
        ..
    } = &immutable.params
    else {
        return Err(invalid_mutation_session());
    };
    let live = &session.manifest;
    let occupancy = live
        .logical_node_count
        .checked_add(live.dummy_node_count)
        .ok_or_else(invalid_mutation_session)?;
    if immutable.index_name != session.vector_name
        || provider != VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER
        || binding != PRIVATE_HNSW_ORAM_V2_BINDING
        || live.provider != VECTOR_PRIVATE_HNSW_ORAM_PROVIDER
        || live.binding != PRIVATE_HNSW_ORAM_BINDING
        || key_id != &live.key_id
        || rk_id != &live.rk_id
        || *rk_epoch != live.rk_epoch
        || *dim != live.dim
        || distance != &live.distance
        || hnsw != &live.hnsw
        || oram != &live.oram
        || fixed_search_budget != &live.fixed_budget
        || immutable.capacity.bucket_count != live.bucket_count
        || occupancy != immutable.capacity.logical_capacity
    {
        return Err(invalid_mutation_session());
    }
    Ok(())
}

fn validate_live_result_binding(
    immutable: &qdrant_sec::PrivateOramImmutableIndexV2,
    session: &PrivateResultOramSessionResponse,
) -> StorageResult<()> {
    let PrivateOramImmutableIndexParamsV2::Result {
        provider,
        binding,
        key_id,
        rk_id,
        rk_epoch,
        oram,
    } = &immutable.params
    else {
        return Err(invalid_mutation_session());
    };
    let live = &session.manifest;
    let occupancy = live
        .logical_result_count
        .checked_add(live.dummy_result_count)
        .ok_or_else(invalid_mutation_session)?;
    if provider != PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER
        || binding != PRIVATE_RESULT_ORAM_V2_BINDING
        || live.provider != PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER
        || live.binding != PRIVATE_RESULT_ORAM_BINDING
        || key_id != &live.key_id
        || rk_id != &live.rk_id
        || *rk_epoch != live.rk_epoch
        || oram != &live.oram
        || immutable.capacity.bucket_count != live.bucket_count
        || occupancy != immutable.capacity.logical_capacity
    {
        return Err(invalid_mutation_session());
    }
    Ok(())
}

fn validate_live_session_state(
    signed: &qdrant_sec::PrivateOramIndexStateV2,
    index_epoch: u64,
    root_hash: &str,
) -> StorageResult<()> {
    if signed.index_epoch != index_epoch || signed.root_hash != root_hash {
        return Err(invalid_mutation_session());
    }
    Ok(())
}

fn validate_open_crypto_material(
    collection_id: &str,
    input: &PrivateOramMutationOpenInputV2,
    verification: PrivateOramSignatureVerification<'_>,
) -> StorageResult<()> {
    validate_private_oram_immutable_manifest_v2_shape(&input.immutable_manifest.manifest)
        .map_err(|_| invalid_mutation_session())?;
    validate_private_oram_immutable_manifest_v2_signature(
        &input.immutable_manifest.manifest,
        Some(&input.immutable_manifest.signature),
        verification,
    )
    .map_err(|_| invalid_mutation_session())?;
    validate_private_oram_signed_state_v2_shape(&input.old_state.state)
        .map_err(|_| invalid_mutation_session())?;
    validate_private_oram_signed_state_v2_signature(
        &input.old_state.state,
        Some(&input.old_state.signature),
        verification,
    )
    .map_err(|_| invalid_mutation_session())?;
    if input.immutable_manifest.manifest.collection_id != collection_id
        || input.old_state.state.collection_id != collection_id
        || input.old_state.state.owner_signing_key_id
            != input.immutable_manifest.manifest.owner_signing_key_id
        || input.old_state.state.last_mutation_id.as_deref() == Some(&input.mutation_id)
    {
        return Err(invalid_mutation_session());
    }
    Ok(())
}

fn validate_open_consensus_bindings(
    coordinator_peer_id: u64,
    manifest_digest: &str,
    old_state_digest: &str,
    old_state: &PrivateOramSignedStateV2,
    consensus: &PrivateOramConsensusCollectionStateV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    layout: &PrivateOramConsensusLayout,
) -> StorageResult<()> {
    if slot.active.is_some()
        || !layout.owner_peer_ids.contains(&coordinator_peer_id)
        || layout.generation != consensus.layout_generation
        || layout.layout_digest != consensus.layout_digest
        || manifest_digest != consensus.manifest_digest
        || old_state_digest != consensus.signed_state_digest
        || old_state.collection_id != consensus.collection_id
        || old_state.manifest_digest != consensus.manifest_digest
        || old_state.layout_generation != consensus.layout_generation
        || old_state.layout_digest != consensus.layout_digest
        || old_state.state_sequence != consensus.state_sequence
        || old_state.client_state_digest != consensus.client_state_digest
        || old_state.indexes.len() != consensus.indexes.len()
    {
        return Err(invalid_mutation_session());
    }
    for (signed, current) in old_state.indexes.iter().zip(&consensus.indexes) {
        let expected_kind = match signed.kind {
            PrivateOramIndexKindV2::Hnsw => PrivateOramIndexKind::Hnsw,
            PrivateOramIndexKindV2::Result => PrivateOramIndexKind::ResultPayload,
        };
        let expected_name = match signed.kind {
            PrivateOramIndexKindV2::Hnsw => signed.index_name.as_str(),
            PrivateOramIndexKindV2::Result => "",
        };
        if current.index_kind != expected_kind
            || current.index_name != expected_name
            || current.epoch.index_epoch != signed.index_epoch
            || current.epoch.root_hash != signed.root_hash
            || current.epoch.writeback_digest.as_deref() != Some(&signed.last_writeback_digest)
            || current.logical_count != signed.logical_count
            || current.dummy_count != signed.dummy_count
        {
            return Err(invalid_mutation_session());
        }
    }
    Ok(())
}

fn validate_append_consensus_bindings(
    coordinator_peer_id: u64,
    session: &PrivateOramMutationSessionV2,
    consensus: &PrivateOramConsensusCollectionStateV2,
    slot: &PrivateOramMutationLeaseSlotV2,
    layout: &PrivateOramConsensusLayout,
) -> StorageResult<()> {
    validate_open_consensus_bindings(
        coordinator_peer_id,
        &session.response.manifest_digest,
        &session.response.old_state_digest,
        &session.old_state.state,
        consensus,
        slot,
        layout,
    )?;
    if slot.generation.checked_add(1) != Some(session.response.mutation_lease_generation)
        || slot.max_writer_fence.checked_add(1) != Some(session.response.writer_fence)
        || session.response.collection_id != consensus.collection_id
        || session.response.mutation_id == consensus_state_last_mutation_id(consensus).unwrap_or("")
    {
        return Err(invalid_mutation_session());
    }
    Ok(())
}

fn consensus_state_last_mutation_id(state: &PrivateOramConsensusCollectionStateV2) -> Option<&str> {
    match &state.last_transition {
        storage::content_manager::consensus_ops::PrivateOramConsensusTransitionV2::Genesis => None,
        storage::content_manager::consensus_ops::PrivateOramConsensusTransitionV2::Mutation(
            receipt,
        ) => Some(&receipt.mutation_id),
    }
}

fn validate_append_session_binding(
    session: &PrivateOramMutationSessionV2,
    mutation: &qdrant_sec::PrivateOramAppendMutationV1,
) -> StorageResult<()> {
    if mutation.mutation_id != session.response.mutation_id
        || mutation.collection_id != session.response.collection_id
        || mutation.manifest_digest != session.response.manifest_digest
        || mutation.layout_generation != session.old_state.state.layout_generation
        || mutation.writer_lease_digest != session.response.writer_lease_digest
        || mutation.writer_fence != session.response.writer_fence
        || mutation.issued_at_unix != session.response.issued_at_unix
        || mutation.expires_at_unix != session.response.lease_expires_unix
        || mutation.old_state != session.old_state
        || mutation.owner_signing_key_id != session.immutable_manifest.manifest.owner_signing_key_id
    {
        return Err(invalid_mutation_session());
    }
    Ok(())
}

type DecodedStagedInsertFrame = (
    Option<PrivateOramStagedInsertFrameV1>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
);

fn decode_append_staged_insert_frame(
    encoded: Option<&str>,
) -> StorageResult<DecodedStagedInsertFrame> {
    let Some(encoded) = encoded else {
        return Ok((None, None, None, None));
    };
    let max_encoded_bytes = PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(invalid_mutation_session)?;
    if encoded.is_empty() || encoded.len() > max_encoded_bytes {
        return Err(StorageError::bad_request(
            "private ORAM staged insert frame is invalid",
        ));
    }
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| StorageError::bad_request("private ORAM staged insert frame is invalid"))?;
    if bytes.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES
        || BASE64URL_NOPAD.encode(&bytes) != encoded
    {
        return Err(StorageError::bad_request(
            "private ORAM staged insert frame is invalid",
        ));
    }
    let frame = decode_private_oram_staged_insert_frame_v1(&bytes)
        .map_err(|_| StorageError::bad_request("private ORAM staged insert frame is invalid"))?;
    let point_id = private_oram_staged_point_id_canonical_string(&frame.point.id)
        .map_err(|_| StorageError::bad_request("private ORAM staged insert frame is invalid"))?;
    let digest = private_oram_staged_insert_frame_v1_digest(&frame)
        .map_err(|_| StorageError::bad_request("private ORAM staged insert frame is invalid"))?;
    Ok((Some(frame), Some(bytes), Some(point_id), Some(digest)))
}

fn signed_index(
    state: &PrivateOramSignedStateV2,
    kind: PrivateOramIndexKindV2,
) -> StorageResult<&qdrant_sec::PrivateOramIndexStateV2> {
    state
        .indexes
        .iter()
        .find(|index| index.kind == kind)
        .ok_or_else(invalid_mutation_session)
}

fn manifest_index(
    manifest: &PrivateOramImmutableManifestBundleV2,
    kind: PrivateOramIndexKindV2,
) -> StorageResult<&qdrant_sec::PrivateOramImmutableIndexV2> {
    manifest_index_optional(manifest, kind).ok_or_else(invalid_mutation_session)
}

fn manifest_index_optional(
    manifest: &PrivateOramImmutableManifestBundleV2,
    kind: PrivateOramIndexKindV2,
) -> Option<&qdrant_sec::PrivateOramImmutableIndexV2> {
    manifest
        .manifest
        .indexes
        .iter()
        .find(|index| index.kind() == kind)
}

fn result_leaf_labels(bucket_ids: &[u64], tree_height: u32) -> StorageResult<Vec<String>> {
    let path_len = usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or_else(invalid_mutation_session)?;
    let leaf_start = 1u64
        .checked_shl(tree_height)
        .and_then(|count| count.checked_sub(1))
        .ok_or_else(invalid_mutation_session)?;
    if bucket_ids.is_empty() || !bucket_ids.len().is_multiple_of(path_len) {
        return Err(invalid_mutation_session());
    }
    bucket_ids
        .chunks(path_len)
        .map(|path| {
            let leaf = path
                .last()
                .copied()
                .and_then(|bucket_id| bucket_id.checked_sub(leaf_start))
                .ok_or_else(invalid_mutation_session)?;
            encode_private_result_oram_leaf_label(leaf, tree_height)
                .map_err(|_| invalid_mutation_session())
        })
        .collect()
}

fn new_writer_lease_digest(
    collection_id: &str,
    mutation_id: &str,
    generation: u64,
    writer_fence: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_MUTATION_WRITER_LEASE_DOMAIN);
    hasher.update(collection_id.as_bytes());
    hasher.update(mutation_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(writer_fence.to_be_bytes());
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn next_private_oram_mutation_session_incarnation_v2() -> StorageResult<u64> {
    static NEXT_INCARNATION: AtomicU64 = AtomicU64::new(1);
    NEXT_INCARNATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| {
            StorageError::service_error("private ORAM mutation session incarnation exhausted")
        })
}

fn new_private_oram_mutation_freeze_nonce_v2(
    session_id: &str,
    session_incarnation: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_MUTATION_FREEZE_NONCE_DOMAIN);
    hasher.update(session_id.as_bytes());
    hasher.update(session_incarnation.to_be_bytes());
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.finalize().into()
}

fn private_oram_mutation_append_job_key_v2(collection_id: &str, mutation_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_MUTATION_APPEND_JOB_KEY_DOMAIN);
    hasher.update((collection_id.len() as u64).to_be_bytes());
    hasher.update(collection_id.as_bytes());
    hasher.update((mutation_id.len() as u64).to_be_bytes());
    hasher.update(mutation_id.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn private_oram_mutation_live_session_commitment_v2(
    job: &PrivateOramMutationAppendJobV2,
) -> StorageResult<String> {
    fn hash_field(hasher: &mut Sha256, value: &str) -> StorageResult<()> {
        hasher.update(
            u64::try_from(value.len())
                .map_err(|_| invalid_mutation_session())?
                .to_be_bytes(),
        );
        hasher.update(value.as_bytes());
        Ok(())
    }

    let session = &job.material.session;
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_MUTATION_LIVE_SESSION_COMMITMENT_DOMAIN);
    for field in [
        job.binding.collection_id.as_str(),
        job.binding.mutation_id.as_str(),
        job.binding.session_id.as_str(),
        session.response.manifest_digest.as_str(),
        session.response.old_state_digest.as_str(),
        session.response.writer_lease_digest.as_str(),
        job.material.validated_owner_prepare.mutation_digest(),
        job.material.consensus_state.signed_state_digest.as_str(),
        job.material.consensus_state.layout_digest.as_str(),
    ] {
        hash_field(&mut hasher, field)?;
    }
    hasher.update(job.binding.token.session_incarnation.to_be_bytes());
    hasher.update(job.binding.token.freeze_nonce);
    hasher.update(job.binding.token.leader.peer_id.to_be_bytes());
    hasher.update(job.binding.token.leader.term.to_be_bytes());
    hasher.update(session.response.mutation_lease_generation.to_be_bytes());
    hasher.update(session.response.writer_fence.to_be_bytes());
    hasher.update(job.material.consensus_state.state_sequence.to_be_bytes());
    hasher.update(job.material.consensus_state.layout_generation.to_be_bytes());
    hasher.update(job.material.consensus_slot.generation.to_be_bytes());
    hasher.update(job.material.consensus_slot.max_writer_fence.to_be_bytes());
    hasher.update(
        u64::try_from(job.material.durable_read_observations.len())
            .map_err(|_| invalid_mutation_session())?
            .to_be_bytes(),
    );
    for observation in &job.material.durable_read_observations {
        hash_field(&mut hasher, &observation.transcript_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_mutation_id(mutation_id: &str) -> StorageResult<()> {
    let decoded = BASE64URL_NOPAD
        .decode(mutation_id.as_bytes())
        .map_err(|_| StorageError::bad_request("private ORAM mutation_id is invalid"))?;
    if mutation_id.len() != 43 || decoded.len() != 32 {
        return Err(StorageError::bad_request(
            "private ORAM mutation_id is invalid",
        ));
    }
    Ok(())
}

fn validate_mutation_session_id(session_id: &str) -> StorageResult<()> {
    let parsed = uuid::Uuid::parse_str(session_id)
        .map_err(|_| StorageError::bad_request("private ORAM mutation session_id is invalid"))?;
    if parsed.hyphenated().to_string() != session_id {
        return Err(StorageError::bad_request(
            "private ORAM mutation session_id is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn current_unix_secs() -> StorageResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StorageError::service_error("system clock before UNIX epoch"))
}

fn require_active_mutation_leader(dispatcher: &Dispatcher) -> StorageResult<()> {
    current_active_mutation_leader_token(dispatcher).map(|_| ())
}

fn current_active_mutation_leader_token(
    dispatcher: &Dispatcher,
) -> StorageResult<PrivateOramMutationLeaderTokenV2> {
    let consensus = dispatcher.consensus_state().ok_or_else(|| {
        StorageError::service_error("private ORAM mutation sessions require distributed mode")
    })?;
    consensus.require_private_oram_mutation_coordinator_is_local_leader()?;
    if consensus.private_oram_mutation_v2_activation_status()?
        != PrivateOramMutationV2ActivationStatus::Active
    {
        return Err(StorageError::PreconditionFailed {
            description: "private ORAM mutation V2 is not active".to_string(),
        });
    }
    let term = consensus.hard_state().term;
    if term == 0 {
        return Err(StorageError::PreconditionFailed {
            description: "private ORAM mutation leader term is unavailable".to_string(),
        });
    }
    Ok(PrivateOramMutationLeaderTokenV2 {
        peer_id: dispatcher.this_peer_id(),
        term,
    })
}

fn invalid_mutation_session() -> StorageError {
    StorageError::bad_request("private ORAM mutation session is invalid")
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        DistanceKind, FixedBudgetParams, OramKind, OramParams,
        PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        PrivateHnswOramManifest, PrivateHnswParams, PrivateHnswVectorEncoding,
        PrivateOramImmutableIndexV2, PrivateOramImmutableManifestBundleV2,
        PrivateOramImmutableManifestV2, PrivateOramIndexCapacityV2, PrivateOramIndexStateV2,
        PrivateOramSignature, PrivateOramSignedStateBundleV2, PrivateOramSignedStateV2,
        ResultPrivacyMode, encode_private_hnsw_oram_leaf_label,
    };
    use storage::rbac::Access;

    use super::*;

    fn test_digest(fill: u8) -> String {
        BASE64URL_NOPAD.encode(&[fill; 32])
    }

    fn hnsw_live_binding_fixture() -> (
        PrivateOramImmutableIndexV2,
        PrivateHnswSessionResponse,
        PrivateOramIndexStateV2,
    ) {
        let oram = OramParams {
            kind: OramKind::PathOram,
            bucket_size: 4,
            block_size_bytes: 8_192,
            tree_height: 3,
            path_batch_size: 4,
        };
        let hnsw = PrivateHnswParams {
            m: 4,
            ef_construction: 16,
            max_layers: 4,
            fixed_neighbor_slots: 8,
        };
        let fixed_budget = FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 4,
            base_layer_steps: 16,
            paths_per_round: 4,
            fixed_result_k: 4,
        };
        let initial_root = BASE64URL_NOPAD.encode(&[1; 32]);
        let current_root = BASE64URL_NOPAD.encode(&[2; 32]);
        let immutable = PrivateOramImmutableIndexV2 {
            index_name: "text".to_string(),
            params: PrivateOramImmutableIndexParamsV2::Hnsw {
                provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                key_id: "tenant-a/vector-private-rk".to_string(),
                rk_id: "tenant-a/vector-private-rk".to_string(),
                rk_epoch: 7,
                dim: 16,
                vector_encoding: PrivateHnswVectorEncoding::F32Le,
                distance: DistanceKind::Cosine,
                hnsw: hnsw.clone(),
                oram: oram.clone(),
                fixed_search_budget: fixed_budget.clone(),
                max_neighbor_rewrites: 4,
            },
            capacity: PrivateOramIndexCapacityV2 {
                bucket_count: 15,
                logical_capacity: 16,
                reserved_physical_slots: 44,
                max_client_stash_blocks: 8,
                fixed_append_read_path_count: 8,
                fixed_append_write_bucket_count: 32,
            },
        };
        let physical = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-a".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 16,
            distance: DistanceKind::Cosine,
            hnsw,
            oram,
            fixed_budget,
            index_epoch: 7,
            root_hash: initial_root,
            bucket_count: 15,
            logical_node_count: 5,
            dummy_node_count: 11,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "owner-key".to_string(),
            created_at_unix: 100,
        };
        let session = PrivateHnswSessionResponse {
            session_id: "hnsw-session".to_string(),
            collection_id: "collection-a".to_string(),
            vector_name: "text".to_string(),
            index_epoch: 9,
            root_hash: current_root.clone(),
            manifest: physical,
            lease_expires_unix: 1_000,
        };
        let signed = PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text".to_string(),
            index_epoch: 9,
            root_hash: current_root,
            logical_count: 5,
            dummy_count: 11,
            last_writeback_digest: BASE64URL_NOPAD.encode(&[3; 32]),
        };
        (immutable, session, signed)
    }

    fn mutation_session_fixture(
        collection_name: &str,
        session_id: &str,
        recorder: PrivateOramServerReadEvidenceRecorderV1,
    ) -> PrivateOramMutationSessionV2 {
        let (immutable_index, physical_session, signed_index) = hnsw_live_binding_fixture();
        let collection_id = format!("{collection_name}-id");
        let digest = |fill| BASE64URL_NOPAD.encode(&[fill; 32]);
        let signature = PrivateOramSignature {
            alg: "ed25519".to_string(),
            key_id: "owner-key".to_string(),
            sig: digest(9),
        };
        let immutable_manifest = PrivateOramImmutableManifestBundleV2 {
            manifest: PrivateOramImmutableManifestV2 {
                version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
                collection_id: collection_id.clone(),
                manifest_nonce: digest(10),
                indexes: vec![immutable_index],
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: "owner-key".to_string(),
                created_at_unix: 100,
            },
            signature: signature.clone(),
        };
        let old_state = PrivateOramSignedStateBundleV2 {
            state: PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: collection_id.clone(),
                manifest_digest: digest(11),
                layout_generation: 1,
                layout_digest: digest(12),
                state_sequence: 1,
                indexes: vec![signed_index],
                client_state_digest: digest(13),
                last_mutation_id: None,
                owner_signing_key_id: "owner-key".to_string(),
                signed_at_unix: 100,
            },
            signature,
        };
        let hnsw = PrivateOramMutationIndexReadStateV2 {
            session_id: physical_session.session_id,
            index_name: physical_session.vector_name.clone(),
            index_epoch: physical_session.index_epoch,
            root_hash: physical_session.root_hash,
            paths_per_window: 4,
            tree_height: 3,
            fixed_append_read_path_count: 8,
            windows: vec![
                PrivateOramAppendReadWindowV1 {
                    sequence: 0,
                    paths: (0..4)
                        .map(|leaf| encode_private_hnsw_oram_leaf_label(leaf, 3).unwrap())
                        .collect(),
                },
                PrivateOramAppendReadWindowV1 {
                    sequence: 1,
                    paths: (4..8)
                        .map(|leaf| encode_private_hnsw_oram_leaf_label(leaf, 3).unwrap())
                        .collect(),
                },
            ],
            read_in_progress: false,
        };
        PrivateOramMutationSessionV2 {
            incarnation: next_private_oram_mutation_session_incarnation_v2().unwrap(),
            leader: test_mutation_leader_token(),
            response: PrivateOramMutationOpenResponseV2 {
                session_id: session_id.to_string(),
                collection_id,
                vector_name: physical_session.vector_name,
                mutation_id: digest(25),
                manifest_digest: old_state.state.manifest_digest.clone(),
                old_state_digest: digest(22),
                mutation_lease_generation: 1,
                writer_lease_digest: digest(23),
                writer_fence: 1,
                issued_at_unix: 100,
                lease_expires_unix: u64::MAX,
                indexes: Vec::new(),
            },
            collection_name: collection_name.to_string(),
            immutable_manifest,
            old_state,
            owner_public_key: vec![24; 32],
            recorder,
            admission_seed: None,
            hnsw,
            result: None,
            freeze_owner: None,
            closing: false,
        }
    }

    fn test_mutation_leader_token() -> PrivateOramMutationLeaderTokenV2 {
        PrivateOramMutationLeaderTokenV2 {
            peer_id: 11,
            term: 7,
        }
    }

    fn install_test_mutation_session(session: PrivateOramMutationSessionV2) {
        let mut registry = session_registry().lock().unwrap();
        assert!(
            registry
                .active_by_collection
                .insert(
                    session.response.collection_id.clone(),
                    session.response.session_id.clone(),
                )
                .is_none()
        );
        assert!(
            registry
                .sessions
                .insert(session.response.session_id.clone(), session)
                .is_none()
        );
    }

    fn remove_test_mutation_session(session_id: &str) {
        let mut registry = session_registry().lock().unwrap();
        if let Some(session) = registry.sessions.remove(session_id) {
            registry
                .active_by_collection
                .remove(&session.response.collection_id);
        }
    }

    #[test]
    fn result_leaf_labels_reconstruct_ordered_paths() {
        let labels = result_leaf_labels(&[0, 1, 4, 9, 0, 2, 5, 12], 3).unwrap();
        assert_eq!(
            labels,
            vec![
                encode_private_result_oram_leaf_label(2, 3).unwrap(),
                encode_private_result_oram_leaf_label(5, 3).unwrap(),
            ]
        );
    }

    #[test]
    fn index_read_state_enforces_exact_window_budget() {
        let valid = PrivateOramMutationIndexReadStateV2 {
            session_id: "session".to_string(),
            index_name: "text".to_string(),
            index_epoch: 7,
            root_hash: BASE64URL_NOPAD.encode(&[1; 32]),
            paths_per_window: 4,
            tree_height: 3,
            fixed_append_read_path_count: 8,
            windows: Vec::new(),
            read_in_progress: false,
        };
        assert_eq!(valid.required_window_count().unwrap(), 2);
        let mut invalid = valid;
        invalid.fixed_append_read_path_count = 9;
        assert!(invalid.required_window_count().is_err());
    }

    #[test]
    fn live_binding_uses_v2_to_physical_v1_mapping_and_current_signed_state() {
        let (immutable, session, signed) = hnsw_live_binding_fixture();
        assert_ne!(session.manifest.index_epoch, session.index_epoch);
        assert_ne!(session.manifest.root_hash, session.root_hash);
        validate_live_hnsw_binding(&immutable, &session).unwrap();
        validate_live_session_state(&signed, session.index_epoch, &session.root_hash).unwrap();
    }

    #[test]
    fn live_session_state_rejects_signed_root_substitution() {
        let (_, session, mut signed) = hnsw_live_binding_fixture();
        signed.root_hash = BASE64URL_NOPAD.encode(&[4; 32]);
        assert!(
            validate_live_session_state(&signed, session.index_epoch, &session.root_hash).is_err()
        );
    }

    #[test]
    fn index_read_state_serializes_window_reads() {
        let mut state = PrivateOramMutationIndexReadStateV2 {
            session_id: "session".to_string(),
            index_name: "text".to_string(),
            index_epoch: 7,
            root_hash: BASE64URL_NOPAD.encode(&[1; 32]),
            paths_per_window: 2,
            tree_height: 3,
            fixed_append_read_path_count: 4,
            windows: Vec::new(),
            read_in_progress: false,
        };
        state.begin_read().unwrap();
        assert!(state.begin_read().is_err());
        state.cancel_read();
        state.begin_read().unwrap();
        state
            .finish_read(vec![
                BASE64URL_NOPAD.encode(&[5; 8]),
                BASE64URL_NOPAD.encode(&[6; 8]),
            ])
            .unwrap();
        assert_eq!(state.windows.len(), 1);
        assert_eq!(state.windows[0].sequence, 0);
    }

    #[test]
    fn index_session_debug_redacts_lower_read_session_id() {
        let sentinel = "lower-read-session-id-sentinel";
        let session = PrivateOramMutationIndexSessionV2 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text".to_string(),
            read_session_id: sentinel.to_string(),
            index_epoch: 7,
            root_hash: BASE64URL_NOPAD.encode(&[1; 32]),
            paths_per_window: 4,
            tree_height: 3,
            fixed_append_read_path_count: 8,
        };
        let rendered = format!("{session:?}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    #[tokio::test]
    async fn cleanup_quiescence_waits_for_exact_worker_exit() {
        struct WorkerState {
            active: AtomicBool,
            quiesced: Notify,
        }

        let worker = Arc::new(WorkerState {
            active: AtomicBool::new(true),
            quiesced: Notify::new(),
        });
        let waiting = Arc::clone(&worker);
        let waiter = tokio::spawn(async move {
            wait_for_private_oram_mutation_worker_quiescence_v2(&waiting.active, &waiting.quiesced)
                .await;
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        worker.active.store(false, Ordering::Release);
        worker.quiesced.notify_waiters();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cleanup_rejects_same_process_job_loss_and_replays_restart_absence() {
        let collection_id = "cleanup-absence-regression-collection";
        let mutation_id = test_digest(90);
        let owner_peer_id = 11;
        let observed_generation = 91;
        let restart_generation = 92;
        let observed_authority = PrivateOramMutationRuntimeAuthorityV2 {
            collection_id: collection_id.to_string(),
            mutation_id: mutation_id.clone(),
            owner_peer_id,
            generation: observed_generation,
        };
        let cleanup_claim = |generation| PrivateOramMutationCleanupClaimBindingV2 {
            authority: PrivateOramMutationRuntimeAuthorityV2 {
                collection_id: collection_id.to_string(),
                mutation_id: mutation_id.clone(),
                owner_peer_id,
                generation,
            },
            descriptor_digest: test_digest(93),
            terminal_record_digest: test_digest(94),
            witness_digest: test_digest(95),
            cleanup_evidence_digest: test_digest(96),
        };
        {
            let mut registry = session_registry().lock().unwrap();
            registry
                .seen_job_authorities
                .insert(observed_authority.clone());
        }
        assert!(
            complete_private_oram_detached_job_local_cleanup_with_binding_v2(
                cleanup_claim(observed_generation),
                "test-process-incarnation".to_string(),
            )
            .await
            .is_err()
        );

        let restart_claim = cleanup_claim(restart_generation);
        let quiesced = complete_private_oram_detached_job_local_cleanup_with_binding_v2(
            restart_claim.clone(),
            "test-process-incarnation".to_string(),
        )
        .await
        .unwrap();
        assert!(quiesced.claim == restart_claim);
        let _ = complete_private_oram_detached_job_local_cleanup_with_binding_v2(
            restart_claim.clone(),
            "test-process-incarnation".to_string(),
        )
        .await
        .unwrap();

        let mut wrong_collection = restart_claim.clone();
        wrong_collection.authority.collection_id.push_str("-other");
        let mut wrong_mutation = restart_claim.clone();
        wrong_mutation.authority.mutation_id = test_digest(97);
        let mut wrong_owner = restart_claim.clone();
        wrong_owner.authority.owner_peer_id += 1;
        let mut wrong_generation = restart_claim.clone();
        wrong_generation.authority.generation += 1;
        let mut wrong_claim = restart_claim.clone();
        wrong_claim.witness_digest = test_digest(98);
        for invalid in [
            wrong_collection,
            wrong_mutation,
            wrong_owner,
            wrong_generation,
            wrong_claim.clone(),
        ] {
            assert!(
                quiesced
                    .validate_binding(&invalid, "test-process-incarnation")
                    .is_err()
            );
        }
        assert!(
            quiesced
                .validate_binding(&restart_claim, "other-process-incarnation")
                .is_err()
        );
        assert!(
            complete_private_oram_detached_job_local_cleanup_with_binding_v2(
                wrong_claim,
                "test-process-incarnation".to_string(),
            )
            .await
            .is_err()
        );

        let mut registry = session_registry().lock().unwrap();
        registry.seen_job_authorities.remove(&observed_authority);
        registry.cleanup_tombstones.remove(&restart_claim.authority);
        registry.cleanup_claims.remove(collection_id);
        registry.cleanup_claimed_collections.remove(collection_id);
    }

    #[tokio::test]
    async fn cleanup_linearizes_against_open_reservation_and_session_install() {
        let collection_name = "cleanup-registration-race-collection";
        let session_id = "00000000-0000-4000-8000-000000000199";
        let session = mutation_session_fixture(
            collection_name,
            session_id,
            PrivateOramServerReadEvidenceRecorderV1::new(),
        );
        let collection_id = session.response.collection_id.clone();
        let authority = PrivateOramMutationRuntimeAuthorityV2 {
            collection_id: collection_id.clone(),
            mutation_id: session.response.mutation_id.clone(),
            owner_peer_id: 11,
            generation: session.response.mutation_lease_generation,
        };
        let claim = PrivateOramMutationCleanupClaimBindingV2 {
            authority: authority.clone(),
            descriptor_digest: test_digest(201),
            terminal_record_digest: test_digest(202),
            witness_digest: test_digest(203),
            cleanup_evidence_digest: test_digest(204),
        };

        {
            let mut registry = session_registry().lock().unwrap();
            registry.reserve_open(&collection_id, 100).unwrap();
        }
        assert!(
            complete_private_oram_detached_job_local_cleanup_with_binding_v2(
                claim.clone(),
                "registration-race-process".to_string(),
            )
            .await
            .is_err()
        );

        {
            let mut registry = session_registry().lock().unwrap();
            registry.release_open(&collection_id);
            registry.reserve_open(&collection_id, 100).unwrap();
            registry
                .cleanup_claimed_collections
                .insert(collection_id.clone());
            assert!(registry.install(session.clone()).is_err());
            registry.cleanup_claimed_collections.remove(&collection_id);
            assert!(!registry.opening_collections.contains(&collection_id));
            assert!(!registry.active_by_collection.contains_key(&collection_id));
            registry.reserve_open(&collection_id, 100).unwrap();
            registry.install(session).unwrap();
        }
        assert!(
            complete_private_oram_detached_job_local_cleanup_with_binding_v2(
                claim.clone(),
                "registration-race-process".to_string(),
            )
            .await
            .is_err()
        );
        remove_test_mutation_session(session_id);

        let quiesced = complete_private_oram_detached_job_local_cleanup_with_binding_v2(
            claim.clone(),
            "registration-race-process".to_string(),
        )
        .await
        .unwrap();
        quiesced
            .validate_binding(&claim, "registration-race-process")
            .unwrap();

        let mut registry = session_registry().lock().unwrap();
        registry.cleanup_tombstones.remove(&authority);
        registry.cleanup_claims.remove(&collection_id);
        registry.cleanup_claimed_collections.remove(&collection_id);
    }

    #[test]
    fn append_reservation_drop_releases_only_its_exact_session() {
        let collection_name = "append-reservation-release-collection";
        let session_id = "00000000-0000-4000-8000-000000000101";
        install_test_mutation_session(mutation_session_fixture(
            collection_name,
            session_id,
            PrivateOramServerReadEvidenceRecorderV1::new(),
        ));

        let (reservation, _, _) = PrivateOramMutationAppendReservationV2::acquire(
            collection_name,
            session_id,
            101,
            test_mutation_leader_token(),
        )
        .unwrap();
        assert!(matches!(
            session_registry()
                .lock()
                .unwrap()
                .sessions
                .get(session_id)
                .unwrap()
                .freeze_owner,
            Some(PrivateOramMutationFreezeOwnerV2::Request(_))
        ));
        drop(reservation);
        assert!(
            session_registry()
                .lock()
                .unwrap()
                .sessions
                .get(session_id)
                .unwrap()
                .freeze_owner
                .is_none()
        );
        remove_test_mutation_session(session_id);
    }

    #[test]
    fn append_reservation_nonce_is_single_owner_and_reacquire_is_fresh() {
        let collection_name = "append-reservation-fresh-collection";
        let session_id = "00000000-0000-4000-8000-000000000102";
        install_test_mutation_session(mutation_session_fixture(
            collection_name,
            session_id,
            PrivateOramServerReadEvidenceRecorderV1::new(),
        ));

        let (first, _, _) = PrivateOramMutationAppendReservationV2::acquire(
            collection_name,
            session_id,
            101,
            test_mutation_leader_token(),
        )
        .unwrap();
        assert!(
            PrivateOramMutationAppendReservationV2::acquire(
                collection_name,
                session_id,
                101,
                test_mutation_leader_token(),
            )
            .is_err()
        );
        let first_nonce = first.token.freeze_nonce;
        drop(first);
        let (second, _, _) = PrivateOramMutationAppendReservationV2::acquire(
            collection_name,
            session_id,
            101,
            test_mutation_leader_token(),
        )
        .unwrap();
        assert_ne!(first_nonce, second.token.freeze_nonce);
        drop(second);
        remove_test_mutation_session(session_id);
    }

    #[test]
    fn stale_append_reservation_cannot_release_reused_session_id() {
        let collection_name = "append-reservation-aba-collection";
        let session_id = "00000000-0000-4000-8000-000000000103";
        install_test_mutation_session(mutation_session_fixture(
            collection_name,
            session_id,
            PrivateOramServerReadEvidenceRecorderV1::new(),
        ));
        let (reservation, _, _) = PrivateOramMutationAppendReservationV2::acquire(
            collection_name,
            session_id,
            101,
            test_mutation_leader_token(),
        )
        .unwrap();

        let mut replacement = mutation_session_fixture(
            collection_name,
            session_id,
            PrivateOramServerReadEvidenceRecorderV1::new(),
        );
        let replacement_token = PrivateOramMutationFreezeTokenV2 {
            session_incarnation: replacement.incarnation,
            freeze_nonce: new_private_oram_mutation_freeze_nonce_v2(
                session_id,
                replacement.incarnation,
            ),
            leader: replacement.leader,
        };
        replacement.freeze_owner = Some(PrivateOramMutationFreezeOwnerV2::Request(
            replacement_token.clone(),
        ));
        {
            let mut registry = session_registry().lock().unwrap();
            registry
                .sessions
                .insert(session_id.to_string(), replacement);
        }
        drop(reservation);
        assert!(
            session_registry()
                .lock()
                .unwrap()
                .sessions
                .get(session_id)
                .unwrap()
                .freeze_owner
                .as_ref()
                == Some(&PrivateOramMutationFreezeOwnerV2::Request(
                    replacement_token
                ))
        );
        remove_test_mutation_session(session_id);
    }

    #[test]
    fn detached_job_freeze_without_registry_job_fails_status_closed() {
        let collection_name = "append-job-missing-collection";
        let session_id = "00000000-0000-4000-8000-000000000104";
        install_test_mutation_session(mutation_session_fixture(
            collection_name,
            session_id,
            PrivateOramServerReadEvidenceRecorderV1::new(),
        ));
        let (reservation, _, _) = PrivateOramMutationAppendReservationV2::acquire(
            collection_name,
            session_id,
            101,
            test_mutation_leader_token(),
        )
        .unwrap();
        {
            let mut registry = session_registry().lock().unwrap();
            let session = registry.sessions.get_mut(session_id).unwrap();
            session.freeze_owner = Some(PrivateOramMutationFreezeOwnerV2::Job {
                mutation_id: session.response.mutation_id.clone(),
                token: reservation.token.clone(),
            });
        }
        drop(reservation);

        let auth = Auth::new_internal(Access::full("private ORAM mutation status test"));
        assert!(
            private_oram_mutation_session_status_v2(&auth, collection_name, session_id).is_err()
        );
        remove_test_mutation_session(session_id);
    }
}
