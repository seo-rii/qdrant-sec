use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::{cmp, fmt};

#[cfg(not(unix))]
use atomicwrites::replace_atomic;
use collection::operations::types::PeerMetadata;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::File;
use http::Uri;
use parking_lot::{Mutex, RwLock};
use qdrant_sec::{
    PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION, PrivateOramActivationAuthorityBundleV1,
    PrivateOramActivationAuthorityTrustAnchorV1, PrivateOramActivationRegistryExpectationV1,
    decode_private_oram_owner_enrollment_genesis_commitment_v1,
    decode_private_oram_owner_enrollment_prepared_v1,
    validate_private_oram_activation_authority_bundle_v1,
};
use raft::RaftState;
use raft::eraftpb::{ConfState, HardState, SnapshotMetadata};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StorageError;
use crate::content_manager::collection_meta_ops::{
    CollectionMetaOperations, ReshardingOperation, ShardTransferOperations,
};
use crate::content_manager::consensus::entry_queue::{EntryApplyProgressQueue, EntryId};
use crate::content_manager::consensus::private_oram_activation_authority::{
    PrivateOramActivationAuthorityCurrentAtReadV1, PrivateOramActivationAuthorityLocatorV1,
    PrivateOramActivationAuthorityStateError, PrivateOramActivationAuthorityStateV1,
    PrivateOramActivationAuthorityStoreInstanceId, plan_private_oram_activation_authority_cas_v1,
    validate_private_oram_activation_authority_snapshot_transition_v1,
    validate_private_oram_activation_authority_state_v1_shape,
    verify_private_oram_activation_authority_current_at_read_v1,
};
use crate::content_manager::consensus::private_oram_mutation_activation_barrier::{
    PrivateOramMutationActivationApplyFactsV2, PrivateOramMutationActivationPendingV2,
    validate_private_oram_mutation_activation_barrier_v2,
    validate_private_oram_mutation_activation_pending_v2,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::append_reservation_v3::{
    decode_private_oram_mutation_append_reservation_v3,
    decode_private_oram_mutation_append_reservation_wire,
    decode_private_oram_mutation_prepared_reservation_challenge_v3,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::authority::{
    DecodedPrivateOramMutationAuthorityWireV2, PrivateOramMutationAuthorityStateV2,
    PrivateOramMutationConsensusAggregateV2, PrivateOramMutationMaterialOperationV2,
    PrivateOramMutationPendingReservationChallengeV1,
    PrivateOramMutationRecoveryCapsulesCertificateV2,
    PrivateOramMutationReservationChallengeOutcomeV1,
    acknowledge_private_oram_mutation_authority_clear_v2,
    activate_private_oram_mutation_authority_v2,
    apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3,
    apply_private_oram_mutation_authority_admission_rejected_v2,
    apply_private_oram_mutation_authority_admission_v2,
    apply_private_oram_mutation_authority_append_prepared_v2,
    apply_private_oram_mutation_authority_cancel_append_reservation_challenge_v3,
    apply_private_oram_mutation_authority_cleanup_witness_v2,
    apply_private_oram_mutation_authority_clear_pending_v2,
    apply_private_oram_mutation_authority_clear_v2,
    apply_private_oram_mutation_authority_create_append_reservation_v2,
    apply_private_oram_mutation_authority_create_append_reservation_v3,
    apply_private_oram_mutation_authority_lease_transition_v2,
    apply_private_oram_mutation_authority_owner_enrollment_activated_v2,
    apply_private_oram_mutation_authority_owner_enrollment_prepared_v2,
    apply_private_oram_mutation_authority_parent_progress_v2,
    apply_private_oram_mutation_authority_prepare_append_reservation_challenge_v3,
    apply_private_oram_mutation_authority_recovery_capsules_ready_v2,
    apply_private_oram_mutation_authority_reserved_attempt_rejected_v2,
    canonical_private_oram_mutation_legacy_authority_from_wire_v2,
    decode_private_oram_mutation_reservation_challenge_cancellation_v1,
    decode_private_oram_mutation_reservation_outcome_acknowledgement_v1,
    private_oram_mutation_activation_context_from_barrier_v2,
    private_oram_mutation_aggregate_apply_context_v2, private_oram_mutation_authority_key_v2,
    private_oram_mutation_collection_lifetime_id_digest_v2,
    private_oram_mutation_outer_binding_digest_v2,
    validate_private_oram_mutation_authority_state_v2,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::floor_store::{
    PrivateOramMutationFloorStoreV2, PrivateOramMutationLocalFloorCheckpointV2,
    plan_private_oram_mutation_local_floor_checkpoint_v2,
    private_oram_mutation_raft_state_image_digest_v2,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::format::{
    PrivateOramMutationAuthorityFloorV2, PrivateOramMutationFormatFloorV2,
    plan_private_oram_mutation_authority_floor_acceptance_v2,
    plan_private_oram_mutation_snapshot_authority_acceptance_v2,
    validate_private_oram_mutation_format_floor_v2,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::owner_checkpoint::PrivateOramOwnerCheckpointTableV1;
use crate::content_manager::consensus::private_oram_mutation_cleanup::{
    PrivateOramMutationCleanupLifecycleV2, PrivateOramMutationClearedPendingArchivePermitV2,
    decode_private_oram_mutation_cleanup_expectation_v2,
    private_oram_mutation_admission_request_digest_v2, private_oram_mutation_lease_state_digest_v2,
};
use crate::content_manager::consensus::private_oram_mutation_recovery_capsules::{
    decode_private_oram_mutation_recovery_capsules_ready_v2,
    validate_private_oram_mutation_recovery_capsules_ready_against_authority_v2,
};
use crate::content_manager::consensus::private_oram_mutation_watermark::{
    PrivateOramMutationParentWatermarkV2,
    decode_private_oram_mutation_parent_watermark_expectation_v2,
};
use crate::content_manager::consensus_ops::{
    ApplyPrivateOramMutation, ApplyPrivateOramMutationMaterialV2, CompareAndSwapPrivateOramEpoch,
    CompareAndSwapPrivateOramExternalRecovery, CompareAndSwapPrivateOramLayout,
    CompareAndSwapPrivateOramMutationLease, CompareAndSwapPrivateOramSessionLease,
    ConfirmPrivateOramMutationAuthorityV2, InitializePrivateOramMutationState,
    PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION, PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION,
    PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION, PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
    PrivateOramCollectionLayoutTransition, PrivateOramConsensusCollectionIndexStateV2,
    PrivateOramConsensusCollectionStateV2, PrivateOramConsensusEpoch, PrivateOramConsensusLayout,
    PrivateOramConsensusTransitionV2, PrivateOramEpochKey, PrivateOramExternalRecoveryKey,
    PrivateOramExternalRecoveryLease, PrivateOramExternalRecoveryLeasePhase,
    PrivateOramExternalRecoveryOperation, PrivateOramExternalRecoveryPhase,
    PrivateOramExternalRecoveryState, PrivateOramIndexKind, PrivateOramLayoutKey,
    PrivateOramMutationActivationBarrierPhaseV2, PrivateOramMutationActivationBarrierV2,
    PrivateOramMutationClearOutcome, PrivateOramMutationClearReceiptV1, PrivateOramMutationKey,
    PrivateOramMutationLease, PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
    PrivateOramMutationMaterialTransitionV2, PrivateOramMutationReceiptV2,
    PrivateOramReshardingOperation, PrivateOramSessionLease, PrivateOramShardKeyLayoutChange,
    PrivateOramShardKeyLayoutChangeKind, PrivateOramShardTransferFinish,
    PrivateOramShardTransferStart, canonical_private_oram_consensus_state_record_digest,
    canonical_private_oram_index_state_digest, canonical_private_oram_mutation_receipt_digest,
    canonical_private_oram_mutation_transition_digest,
    private_oram_layout_is_precommitted_transfer_recovery, private_oram_transfer_consensus_layouts,
    private_oram_transfer_consensus_states,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationAppendAuthorityContextV2,
    PrivateOramMutationAppendReservationV2, PrivateOramMutationJournalError,
    decode_private_oram_mutation_admission_recovery_manifest_v2,
    decode_private_oram_mutation_append_reservation_v2,
};
use crate::content_manager::private_oram_mutation_state_v2::private_oram_collection_id_digest_v2;
use crate::types::{PeerAddressById, PeerMetadataById};

// Deprecated, use `STATE_FILE_NAME` instead
const STATE_FILE_NAME_CBOR: &str = "raft_state";

const STATE_FILE_NAME: &str = "raft_state.json";
const PRIVATE_ORAM_EPOCH_KEY_DOMAIN: &[u8] = b"qdrant-sec/private-oram-consensus-epoch-key/v1";
const PRIVATE_ORAM_LAYOUT_KEY_DOMAIN: &[u8] = b"qdrant-sec/private-oram-consensus-layout-key/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_KEY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-consensus-key/v1";
const PRIVATE_ORAM_MUTATION_KEY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-mutation-consensus-key/v1";
const PRIVATE_ORAM_EPOCH_MAX_RECORDS: usize = 1_000_000;
const PRIVATE_ORAM_LAYOUT_MAX_OWNERS: usize = 10_000;
const PRIVATE_ORAM_SHA256_BASE64URL_LEN: usize = 43;
const PRIVATE_ORAM_SESSION_LEASE_MAX_SECS: u64 = 3_600;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_LEASE_MAX_SECS: u64 = 3_600;
const PRIVATE_ORAM_MUTATION_LEASE_MAX_SECS: u64 = 3_600;
const PERSISTENT_PARENT_SYNC_ATTEMPTS: usize = 3;
const PERSISTENT_SAVE_INDETERMINATE_MESSAGE: &str = "Raft persistent state durability is indeterminate; restart this peer before applying more consensus operations";

fn validate_persisted_private_oram_activation_authority(
    authority: Option<&PrivateOramActivationAuthorityStateV1>,
    trust_anchor: Option<&PrivateOramActivationAuthorityTrustAnchorV1>,
) -> Result<(), StorageError> {
    let Some(authority) = authority else {
        return Ok(());
    };
    validate_private_oram_activation_authority_state_v1_shape(authority).map_err(|_| {
        StorageError::service_error("persisted private ORAM activation authority state is invalid")
    })?;
    let trust_anchor = trust_anchor.ok_or_else(|| {
        StorageError::service_error(
            "persisted private ORAM activation authority requires an external trust anchor",
        )
    })?;
    validate_private_oram_activation_authority_bundle_v1(
        authority.bundle(),
        trust_anchor,
        PrivateOramActivationRegistryExpectationV1::Anchored {
            registry_generation: authority.registry_generation(),
            manifest_digest: authority.manifest_digest(),
        },
    )
    .map(|_| ())
    .map_err(|_| {
        StorageError::service_error(
            "persisted private ORAM activation authority signature is invalid",
        )
    })
}

#[derive(Debug)]
enum PersistentSaveError {
    Definitive(StorageError),
    Indeterminate,
}

impl PersistentSaveError {
    fn is_definitive(&self) -> bool {
        matches!(self, Self::Definitive(_))
    }

    fn into_storage_error(self) -> StorageError {
        match self {
            Self::Definitive(error) => error,
            Self::Indeterminate => {
                StorageError::service_error(PERSISTENT_SAVE_INDETERMINATE_MESSAGE)
            }
        }
    }
}

trait PersistentSaveBackend {
    fn publish(&self, candidate: tempfile::NamedTempFile, destination: &Path) -> io::Result<()>;

    fn sync_parent(&self, parent: &Path) -> io::Result<()>;
}

struct FilesystemPersistentSaveBackend;

struct PreparedPersistentStateImage {
    candidate: tempfile::NamedTempFile,
    candidate_digest: [u8; 32],
    parent: PathBuf,
}

impl PersistentSaveBackend for FilesystemPersistentSaveBackend {
    fn publish(&self, candidate: tempfile::NamedTempFile, destination: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            candidate
                .persist(destination)
                .map(|_| ())
                .map_err(|error| error.error)
        }
        #[cfg(not(unix))]
        {
            replace_atomic(candidate.path(), destination)
        }
    }

    fn sync_parent(&self, parent: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(parent)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Ok(())
        }
    }
}

struct Sha256Writer<'a, W> {
    inner: W,
    hasher: &'a mut Sha256,
}

impl<W: Write> Write for Sha256Writer<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// State of the Raft consensus, which should be saved between restarts.
/// State of the collections, aliases and transfers are stored as regular storage.
#[derive(Serialize, Deserialize, Default)]
pub struct Persistent {
    /// last known state of the Raft consensus
    #[serde(with = "RaftStateDef")]
    pub state: RaftState,
    /// Store last applied snapshot index, required in case if there are no raft change log except
    /// for this last snapshot ID (term + commit)
    #[serde(default)] // TODO quick fix to avoid breaking the compat. with 0.8.1
    pub latest_snapshot_meta: SnapshotMetadataSer,
    /// Operations to be applied, consensus considers them committed, but this peer didn't apply them yet
    #[serde(default)]
    pub apply_progress_queue: EntryApplyProgressQueue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_voter: Option<PeerId>,
    /// Last known cluster topology
    #[serde(with = "serialize_peer_addresses")]
    pub peer_address_by_id: Arc<RwLock<PeerAddressById>>,
    #[serde(default)]
    pub peer_metadata_by_id: Arc<RwLock<PeerMetadataById>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub cluster_metadata: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) private_oram_activation_authority: Option<PrivateOramActivationAuthorityStateV1>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_epochs: HashMap<String, PrivateOramConsensusEpoch>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_session_leases: HashMap<String, PrivateOramSessionLease>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_layouts: HashMap<String, PrivateOramConsensusLayout>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_external_recoveries: HashMap<String, PrivateOramExternalRecoveryState>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_mutation_states: HashMap<String, PrivateOramConsensusCollectionStateV2>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) private_oram_mutation_lease_slots:
        HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) private_oram_mutation_format_floor: Option<PrivateOramMutationFormatFloorV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) private_oram_mutation_activation_pending:
        Option<PrivateOramMutationActivationPendingV2>,
    pub this_peer_id: PeerId,
    #[serde(skip)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) private_oram_activation_authority_store_instance:
        PrivateOramActivationAuthorityStoreInstanceId,
    #[serde(skip)]
    pub(crate) private_oram_activation_authority_trust_anchor:
        OnceLock<PrivateOramActivationAuthorityTrustAnchorV1>,
    #[serde(skip)]
    pub path: PathBuf,
    /// Serializes every publication of the complete persisted state image, including off-side
    /// mutation candidates that share this transaction guard with the live state.
    #[serde(skip)]
    pub(crate) persistence_transaction: Arc<Mutex<()>>,
    /// Tracks if there are some unsaved changes due to the failure on save
    #[serde(skip)]
    pub dirty: AtomicBool,
    /// A published state could not be made durably discoverable. Consensus must stop until restart.
    #[serde(skip)]
    pub(crate) save_indeterminate: AtomicBool,
}

/// Off-side image for one legacy private-ORAM mutation state-machine transition.
///
/// The candidate is serialized and durably published before its mutation fields and applied
/// cursor become visible through the live `Persistent` value.
struct PrivateOramMutationCompletePatch {
    next: Box<Persistent>,
    disposition: PrivateOramMutationPatchDisposition,
}

enum PrivateOramMutationCommand<'a> {
    Initialize(&'a InitializePrivateOramMutationState),
    CompareAndSwapLease(&'a CompareAndSwapPrivateOramMutationLease),
    ConfirmAuthority(&'a ConfirmPrivateOramMutationAuthorityV2),
    Apply(&'a ApplyPrivateOramMutation),
    ActivateV2(
        &'a PrivateOramMutationActivationBarrierV2,
        PrivateOramMutationActivationApplyFactsV2,
    ),
    ApplyMaterialV2 {
        operation: &'a ApplyPrivateOramMutationMaterialV2,
        entry_term: u64,
        entry_index: u64,
    },
}

enum PrivateOramMutationPatchDisposition {
    Detached,
    AppliedAtEntry,
    RejectedAtEntry(StorageError),
}

#[derive(Debug)]
pub(crate) enum PrivateOramMutationAtEntryOutcome {
    Applied,
    Rejected(StorageError),
}

/// The complete set of fields a legacy private-ORAM mutation may publish.
///
/// Keep construction and installation exhaustive so adding a field requires updating both sides.
struct PrivateOramMutationDurableFields {
    apply_progress_queue: EntryApplyProgressQueue,
    private_oram_epochs: HashMap<String, PrivateOramConsensusEpoch>,
    private_oram_layouts: HashMap<String, PrivateOramConsensusLayout>,
    private_oram_mutation_states: HashMap<String, PrivateOramConsensusCollectionStateV2>,
    private_oram_mutation_lease_slots: HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    private_oram_mutation_format_floor: Option<PrivateOramMutationFormatFloorV2>,
    private_oram_mutation_activation_pending: Option<PrivateOramMutationActivationPendingV2>,
}

impl PrivateOramMutationDurableFields {
    fn take_from(persistent: &mut Persistent) -> Self {
        Self {
            apply_progress_queue: std::mem::take(&mut persistent.apply_progress_queue),
            private_oram_epochs: std::mem::take(&mut persistent.private_oram_epochs),
            private_oram_layouts: std::mem::take(&mut persistent.private_oram_layouts),
            private_oram_mutation_states: std::mem::take(
                &mut persistent.private_oram_mutation_states,
            ),
            private_oram_mutation_lease_slots: std::mem::take(
                &mut persistent.private_oram_mutation_lease_slots,
            ),
            private_oram_mutation_format_floor: persistent
                .private_oram_mutation_format_floor
                .take(),
            private_oram_mutation_activation_pending: persistent
                .private_oram_mutation_activation_pending
                .take(),
        }
    }

    fn install_into(self, persistent: &mut Persistent) {
        let Self {
            apply_progress_queue,
            private_oram_epochs,
            private_oram_layouts,
            private_oram_mutation_states,
            private_oram_mutation_lease_slots,
            private_oram_mutation_format_floor,
            private_oram_mutation_activation_pending,
        } = self;
        persistent.apply_progress_queue = apply_progress_queue;
        persistent.private_oram_epochs = private_oram_epochs;
        persistent.private_oram_layouts = private_oram_layouts;
        persistent.private_oram_mutation_states = private_oram_mutation_states;
        persistent.private_oram_mutation_lease_slots = private_oram_mutation_lease_slots;
        persistent.private_oram_mutation_format_floor = private_oram_mutation_format_floor;
        persistent.private_oram_mutation_activation_pending =
            private_oram_mutation_activation_pending;
    }
}

/// Capability-limited reducer view for the legacy private-ORAM mutation bridge.
///
/// Reducers cannot reach unrelated `Persistent` fields through this type. Read-only maps are
/// exposed only for cross-operation exclusion checks; the four mutable maps exactly match the
/// mutation portion of `PrivateOramMutationDurableFields`.
struct PrivateOramMutationPatchView<'a> {
    private_oram_epochs: &'a mut HashMap<String, PrivateOramConsensusEpoch>,
    private_oram_session_leases: &'a HashMap<String, PrivateOramSessionLease>,
    private_oram_layouts: &'a mut HashMap<String, PrivateOramConsensusLayout>,
    private_oram_external_recoveries: &'a HashMap<String, PrivateOramExternalRecoveryState>,
    private_oram_mutation_states: &'a mut HashMap<String, PrivateOramConsensusCollectionStateV2>,
    private_oram_mutation_lease_slots:
        &'a mut HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    private_oram_activation_authority: Option<PrivateOramActivationAuthorityStateV1>,
    private_oram_mutation_v3_write_floor_active: bool,
}

impl<'a> PrivateOramMutationPatchView<'a> {
    fn new(persistent: &'a mut Persistent) -> Self {
        let private_oram_activation_authority =
            persistent.private_oram_activation_authority.clone();
        let private_oram_mutation_v3_write_floor_active =
            persistent.private_oram_mutation_v3_write_floor_active();
        Self {
            private_oram_epochs: &mut persistent.private_oram_epochs,
            private_oram_session_leases: &persistent.private_oram_session_leases,
            private_oram_layouts: &mut persistent.private_oram_layouts,
            private_oram_external_recoveries: &persistent.private_oram_external_recoveries,
            private_oram_mutation_states: &mut persistent.private_oram_mutation_states,
            private_oram_mutation_lease_slots: &mut persistent.private_oram_mutation_lease_slots,
            private_oram_activation_authority,
            private_oram_mutation_v3_write_floor_active,
        }
    }

    fn private_oram_mutation_v3_write_floor_active(&self) -> bool {
        self.private_oram_mutation_v3_write_floor_active
    }

    fn apply_initialize(
        &mut self,
        operation: &InitializePrivateOramMutationState,
    ) -> Result<(), StorageError> {
        validate_initialize_private_oram_mutation_state(operation)?;
        let key_digest = private_oram_mutation_key_digest(&operation.key);
        let genesis_slot = PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        };
        let current_state = self.private_oram_mutation_states.get(&key_digest);
        let current_slot = self.historical_mutation_lease_slot_by_digest(&key_digest)?;
        if current_state == Some(&operation.state) && current_slot.as_ref() == Some(&genesis_slot) {
            return Ok(());
        }
        if current_state.is_some() || current_slot.is_some() {
            return Err(StorageError::bad_request(
                "private ORAM mutation state initialization precondition failed",
            ));
        }
        if self.external_recovery_is_active(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "private ORAM mutation state initialization conflicts with active external recovery",
            ));
        }
        self.validate_state_bindings(&operation.state)?;
        if self.state_has_active_session(&operation.state) {
            return Err(StorageError::bad_request(
                "private ORAM mutation state initialization conflicts with active session lease",
            ));
        }
        if self.private_oram_mutation_states.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS {
            return Err(StorageError::bad_request(
                "private ORAM mutation state capacity exceeded",
            ));
        }

        self.private_oram_mutation_states
            .insert(key_digest.clone(), operation.state.clone());
        self.private_oram_mutation_lease_slots
            .insert(key_digest, genesis_slot.into());
        Ok(())
    }

    fn apply_compare_and_swap_lease(
        &mut self,
        operation: &CompareAndSwapPrivateOramMutationLease,
    ) -> Result<(), StorageError> {
        validate_private_oram_mutation_lease_cas(operation)?;
        let key_digest = private_oram_mutation_key_digest(&operation.key);
        let current = self.historical_mutation_lease_slot_by_digest(&key_digest)?;
        if current.as_ref() == Some(&operation.new) {
            let state = self.mutation_state(&operation.key).ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM mutation lease requires initialized collection state",
                )
            })?;
            self.validate_state_bindings(&state)?;
            validate_private_oram_mutation_slot_state_relationship(
                &operation.new,
                &state,
                &operation.key,
            )?;
            return Ok(());
        }
        if current.as_ref() != Some(&operation.expected) {
            return Err(StorageError::bad_request(
                "private ORAM mutation lease CAS precondition failed",
            ));
        }
        let state = self.mutation_state(&operation.key).ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM mutation lease requires initialized collection state",
            )
        })?;
        self.validate_state_bindings(&state)?;
        let acquiring = operation.expected.active.is_none() && operation.new.active.is_some();
        if acquiring {
            if self.external_recovery_is_active(&operation.key.collection_id) {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease conflicts with active external recovery",
                ));
            }
            if self.state_has_active_session(&state) {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease conflicts with active session lease",
                ));
            }
            let lease = operation
                .new
                .active
                .as_ref()
                .expect("acquire transition must contain a lease");
            let layout = self.layout(&PrivateOramLayoutKey {
                collection_id: state.collection_id.clone(),
            });
            if !layout
                .as_ref()
                .is_some_and(|layout| layout.owner_peer_ids.contains(&lease.owner_peer_id))
                || lease.base_record_digest
                    != canonical_private_oram_consensus_state_record_digest(&state)?
                || lease.base_state_sequence != state.state_sequence
                || private_oram_state_last_mutation_id(&state)
                    .is_some_and(|mutation_id| mutation_id == lease.mutation_id)
                || operation
                    .expected
                    .last_clear
                    .as_ref()
                    .is_some_and(|receipt| receipt.mutation_id == lease.mutation_id)
            {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease acquisition is invalid",
                ));
            }
        }
        validate_private_oram_mutation_slot_state_relationship(
            &operation.expected,
            &state,
            &operation.key,
        )?;
        validate_private_oram_mutation_slot_state_relationship(
            &operation.new,
            &state,
            &operation.key,
        )?;

        self.private_oram_mutation_lease_slots
            .insert(key_digest, operation.new.clone().into());
        Ok(())
    }

    fn apply_mutation(&mut self, operation: &ApplyPrivateOramMutation) -> Result<(), StorageError> {
        validate_apply_private_oram_mutation(operation)?;
        let state_key_digest = private_oram_mutation_key_digest(&operation.key);
        let current_state = self.private_oram_mutation_states.get(&state_key_digest);
        if current_state == Some(&operation.new_state) {
            self.validate_state_bindings(&operation.new_state)?;
            let slot = self.mutation_lease_slot(&operation.key)?.ok_or_else(|| {
                StorageError::bad_request("private ORAM mutation lease slot is missing")
            })?;
            validate_private_oram_mutation_slot_state_relationship(
                &slot,
                &operation.new_state,
                &operation.key,
            )?;
            return Ok(());
        }
        if current_state != Some(&operation.expected_state) {
            return Err(StorageError::bad_request(
                "private ORAM mutation CAS precondition failed",
            ));
        }
        if self.external_recovery_is_active(&operation.key.collection_id)
            || self.state_has_active_session(&operation.expected_state)
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation conflicts with another collection operation",
            ));
        }
        self.validate_state_bindings(&operation.expected_state)?;
        let previous_slot = self.mutation_lease_slot(&operation.key)?.ok_or_else(|| {
            StorageError::bad_request("private ORAM mutation lease slot is missing")
        })?;
        let preparing_lease = previous_slot.active.as_ref().ok_or_else(|| {
            StorageError::bad_request("private ORAM mutation lease is not active")
        })?;
        validate_apply_private_oram_mutation_lease(
            operation,
            &operation.expected_state,
            preparing_lease,
        )?;
        let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &operation.new_state.last_transition
        else {
            return Err(StorageError::bad_request(
                "private ORAM mutation transition is invalid",
            ));
        };
        let committed_record_digest =
            canonical_private_oram_consensus_state_record_digest(&operation.new_state)?;
        let receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt)?;
        let mut committed_lease = preparing_lease.clone();
        committed_lease.phase = PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_record_digest,
            committed_state_sequence: operation.new_state.state_sequence,
            committed_signed_state_digest: operation.new_state.signed_state_digest.clone(),
            receipt_digest,
        };
        let mut new_slot = previous_slot;
        new_slot.active = Some(committed_lease);

        let layout_key = PrivateOramLayoutKey {
            collection_id: operation.key.collection_id.clone(),
        };
        let layout_key_digest = private_oram_layout_key_digest(&layout_key);
        let previous_layout = self
            .private_oram_layouts
            .get(&layout_key_digest)
            .cloned()
            .ok_or_else(|| StorageError::bad_request("private ORAM mutation layout is missing"))?;
        let mut new_layout = previous_layout;
        new_layout.index_state_digest =
            private_oram_consensus_state_index_digest(&operation.new_state)?;

        for index in &operation.new_state.indexes {
            let epoch_key =
                private_oram_mutation_index_epoch_key(&operation.new_state.collection_id, index);
            self.private_oram_epochs.insert(
                private_oram_epoch_key_digest(&epoch_key),
                index.epoch.clone(),
            );
        }
        self.private_oram_mutation_states
            .insert(state_key_digest.clone(), operation.new_state.clone());
        self.private_oram_layouts
            .insert(layout_key_digest, new_layout);
        self.private_oram_mutation_lease_slots
            .insert(state_key_digest, new_slot.into());
        Ok(())
    }

    fn apply_material_v2(
        &mut self,
        operation: &ApplyPrivateOramMutationMaterialV2,
        entry_term: u64,
        entry_index: u64,
    ) -> Result<(), StorageError> {
        validate_private_oram_mutation_material_v2(operation, entry_term, entry_index)?;
        let key = operation.key();
        let key_digest = private_oram_mutation_key_digest(key);
        let current_state = self
            .private_oram_mutation_states
            .get(&key_digest)
            .cloned()
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 material operation requires initialized collection state",
                )
            })?;
        self.validate_state_bindings(&current_state)?;
        let current_authority = self
            .private_oram_mutation_lease_slots
            .get(&key_digest)
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .cloned()
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 material operation requires activated authority",
                )
            })?;
        let current_aggregate = current_authority.aggregate().ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM V2 material operation requires activated authority",
            )
        })?;
        let current_slot = current_authority.lease_slot().clone();
        validate_private_oram_mutation_slot_state_relationship(&current_slot, &current_state, key)?;
        let current_record_digest =
            canonical_private_oram_consensus_state_record_digest(&current_state)?;
        let recomputed_current_outer = private_oram_mutation_outer_binding_digest_v2(
            &key.collection_id,
            &current_record_digest,
            &current_slot,
        )
        .map_err(private_oram_mutation_authority_corrupt)?;
        if current_aggregate.outer_binding_digest() != recomputed_current_outer {
            return Err(StorageError::service_error(
                "private ORAM V2 mutation authority outer binding is inconsistent",
            ));
        }

        match operation.transition() {
            PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentPrepared {
                prepared_canonical_json,
            } => {
                let prepared = decode_private_oram_owner_enrollment_prepared_v1(
                    prepared_canonical_json.as_bytes(),
                )
                .map_err(|_| {
                    StorageError::bad_request("private ORAM V2 owner enrollment prepare is invalid")
                })?;
                if prepared.collection_id != key.collection_id
                    || self.external_recovery_is_active(&key.collection_id)
                {
                    return Err(StorageError::bad_request(
                        "private ORAM V2 owner enrollment prepare is invalid",
                    ));
                }
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::OwnerEnrollmentPrepared,
                    prepared.prepared_record_digest.clone(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_owner_enrollment_prepared_v2(
                        &current_authority,
                        prepared,
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentActivated {
                commitment_canonical_json,
            } => {
                let commitment = decode_private_oram_owner_enrollment_genesis_commitment_v1(
                    commitment_canonical_json.as_bytes(),
                )
                .map_err(|_| {
                    StorageError::bad_request(
                        "private ORAM V2 owner enrollment activation is invalid",
                    )
                })?;
                if commitment.collection_id != key.collection_id
                    || self.external_recovery_is_active(&key.collection_id)
                {
                    return Err(StorageError::bad_request(
                        "private ORAM V2 owner enrollment activation is invalid",
                    ));
                }
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::OwnerEnrollmentActivated,
                    commitment.commitment_digest.clone(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_owner_enrollment_activated_v2(
                        &current_authority,
                        commitment,
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AppendReservationChallengePrepared {
                challenge_canonical_json,
            } => {
                if !self.private_oram_mutation_v3_write_floor_active() {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 reservation challenge requires the V3 write floor",
                    ));
                }
                let challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
                    challenge_canonical_json,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let reservation = challenge.base_reservation();
                if reservation.collection_id() != key.collection_id
                    || reservation.expected_aggregate_digest()
                        != operation.expected_aggregate_digest()
                {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 reservation challenge is invalid",
                    ));
                }
                self.validate_private_oram_append_reservation_environment_v2(
                    key,
                    &current_state,
                    &current_record_digest,
                    &current_slot,
                    reservation,
                )?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengePrepared,
                    challenge.prepared_challenge_digest().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_prepare_append_reservation_challenge_v3(
                        &current_authority,
                        challenge_canonical_json.clone(),
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AppendReservationFinalizedV3 {
                reservation_canonical_json,
            } => {
                if !self.private_oram_mutation_v3_write_floor_active() {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 append reservation requires the V3 write floor",
                    ));
                }
                let reservation =
                    decode_private_oram_mutation_append_reservation_v3(reservation_canonical_json)
                        .map_err(private_oram_mutation_authority_invalid)?;
                if reservation.collection_id() != key.collection_id {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 append reservation is invalid",
                    ));
                }
                self.validate_private_oram_append_reservation_environment_v2(
                    key,
                    &current_state,
                    &current_record_digest,
                    &current_slot,
                    reservation.base_reservation(),
                )?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AppendReservationFinalizedV3,
                    reservation.reservation_digest_v3().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_create_append_reservation_v3(
                        &current_authority,
                        reservation_canonical_json.clone(),
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AppendReservationChallengeCancelled {
                cancellation_canonical_json,
            } => {
                if !self.private_oram_mutation_v3_write_floor_active() {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 reservation cancellation requires the V3 write floor",
                    ));
                }
                let cancellation =
                    decode_private_oram_mutation_reservation_challenge_cancellation_v1(
                        cancellation_canonical_json,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                if cancellation.collection_key_digest()
                    != private_oram_collection_id_digest_v2(&key.collection_id)
                        .map_err(private_oram_mutation_authority_invalid)?
                {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 reservation challenge cancellation is invalid",
                    ));
                }
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AppendReservationChallengeCancelled,
                    cancellation.cancellation_digest().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_cancel_append_reservation_challenge_v3(
                        &current_authority,
                        cancellation_canonical_json.clone(),
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AppendReservationOutcomeAcknowledged {
                acknowledgement_canonical_json,
            } => {
                if !self.private_oram_mutation_v3_write_floor_active() {
                    return Err(StorageError::bad_request(
                        "private ORAM V3 reservation outcome acknowledgement requires the V3 write floor",
                    ));
                }
                let acknowledgement =
                    decode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                        acknowledgement_canonical_json,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AppendReservationOutcomeAcknowledged,
                    acknowledgement.acknowledgement_digest().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_acknowledge_reservation_outcome_v3(
                        &current_authority,
                        acknowledgement_canonical_json.clone(),
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AppendReservation {
                reservation_canonical_json,
            } => {
                if self.private_oram_mutation_v3_write_floor_active() {
                    return Err(StorageError::bad_request(
                        "private ORAM V2 reservation creation is disabled by the V3 floor",
                    ));
                }
                let reservation =
                    decode_private_oram_mutation_append_reservation_v2(reservation_canonical_json)
                        .map_err(private_oram_mutation_authority_invalid)?;
                if reservation.collection_id() != key.collection_id
                    || reservation.expected_aggregate_digest()
                        != operation.expected_aggregate_digest()
                {
                    return Err(StorageError::bad_request(
                        "private ORAM V2 append reservation is invalid",
                    ));
                }
                self.validate_private_oram_append_reservation_environment_v2(
                    key,
                    &current_state,
                    &current_record_digest,
                    &current_slot,
                    &reservation,
                )?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AppendReservation,
                    reservation.reservation_digest().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_create_append_reservation_v2(
                        &current_authority,
                        reservation_canonical_json.clone(),
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AppendPrepared {
                recovery_manifest_canonical_json,
            } => {
                let active = current_aggregate.active_append_attempt().ok_or_else(|| {
                    StorageError::bad_request(
                        "private ORAM V2 append prepare requires an active reservation",
                    )
                })?;
                let reservation = decode_private_oram_mutation_append_reservation_wire(
                    active.reservation_canonical_json(),
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
                    recovery_manifest_canonical_json,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                reservation
                    .validate_manifest(&manifest)
                    .map_err(private_oram_mutation_authority_invalid)?;
                let request_digest = reservation
                    .append_prepared_request_digest(&manifest)
                    .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AppendPrepared,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_append_prepared_v2(
                    &current_authority,
                    recovery_manifest_canonical_json.clone(),
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::ReservedAttemptRejected {
                reservation_canonical_json,
            } => {
                let reservation = decode_private_oram_mutation_append_reservation_wire(
                    reservation_canonical_json,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                if reservation.base_reservation().collection_id() != key.collection_id {
                    return Err(StorageError::bad_request(
                        "private ORAM V2 reserved append rejection is invalid",
                    ));
                }
                let request_digest = reservation
                    .reserved_rejection_request_digest()
                    .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::ReservedAttemptRejected,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_reserved_attempt_rejected_v2(
                        &current_authority,
                        reservation_canonical_json.clone(),
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::Admission {
                lease,
                recovery_manifest_canonical_json,
            } => {
                let recovery_manifest =
                    decode_private_oram_mutation_admission_recovery_manifest_v2(
                        recovery_manifest_canonical_json,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                recovery_manifest
                    .validate_admission_lease(lease)
                    .map_err(private_oram_mutation_authority_invalid)?;
                let replay = current_slot.active.as_ref() == Some(lease)
                    || current_aggregate
                        .retains_admission(lease, recovery_manifest.manifest_digest())
                        .map_err(private_oram_mutation_authority_invalid)?;
                let next_slot = if replay {
                    current_slot.clone()
                } else {
                    let mut next = current_slot.clone();
                    next.generation = lease.generation;
                    next.max_writer_fence = lease.writer_fence;
                    next.active = Some(lease.clone());
                    let legacy_shape = CompareAndSwapPrivateOramMutationLease {
                        key: key.clone(),
                        expected: current_slot.clone(),
                        new: next.clone(),
                    };
                    validate_private_oram_mutation_lease_cas(&legacy_shape)?;
                    if self.external_recovery_is_active(&key.collection_id) {
                        return Err(StorageError::bad_request(
                            "private ORAM V2 mutation admission conflicts with active external recovery",
                        ));
                    }
                    if self.state_has_active_session(&current_state) {
                        return Err(StorageError::bad_request(
                            "private ORAM V2 mutation admission conflicts with active session lease",
                        ));
                    }
                    let layout = self.layout(&PrivateOramLayoutKey {
                        collection_id: current_state.collection_id.clone(),
                    });
                    if !layout
                        .as_ref()
                        .is_some_and(|layout| layout.owner_peer_ids.contains(&lease.owner_peer_id))
                        || lease.base_record_digest != current_record_digest
                        || lease.base_state_sequence != current_state.state_sequence
                        || private_oram_state_last_mutation_id(&current_state)
                            .is_some_and(|mutation_id| mutation_id == lease.mutation_id)
                        || current_slot
                            .last_clear
                            .as_ref()
                            .is_some_and(|receipt| receipt.mutation_id == lease.mutation_id)
                    {
                        return Err(StorageError::bad_request(
                            "private ORAM V2 mutation admission is invalid",
                        ));
                    }
                    next
                };
                validate_private_oram_mutation_slot_state_relationship(
                    &next_slot,
                    &current_state,
                    key,
                )?;
                let next_outer = if replay {
                    recomputed_current_outer
                } else {
                    private_oram_mutation_outer_binding_digest_v2(
                        &key.collection_id,
                        &current_record_digest,
                        &next_slot,
                    )
                    .map_err(private_oram_mutation_authority_corrupt)?
                };
                let request_digest = private_oram_mutation_admission_request_digest_v2(
                    lease,
                    recovery_manifest.manifest_digest(),
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::Admission,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    next_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_admission_v2(
                    &current_authority,
                    lease.clone(),
                    recovery_manifest_canonical_json.clone(),
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(&next_authority, &next_slot, &next_outer)?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::AdmissionRejected {
                lease,
                recovery_manifest_canonical_json,
            } => {
                let recovery_manifest =
                    decode_private_oram_mutation_admission_recovery_manifest_v2(
                        recovery_manifest_canonical_json,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                recovery_manifest
                    .validate_admission_lease(lease)
                    .map_err(private_oram_mutation_authority_invalid)?;
                let replay = current_aggregate
                    .retains_rejected_admission(lease, recovery_manifest.manifest_digest())
                    .map_err(private_oram_mutation_authority_invalid)?;
                if !replay {
                    let mut candidate_slot = current_slot.clone();
                    candidate_slot.generation = lease.generation;
                    candidate_slot.max_writer_fence = lease.writer_fence;
                    candidate_slot.active = Some(lease.clone());
                    validate_private_oram_mutation_lease_cas(
                        &CompareAndSwapPrivateOramMutationLease {
                            key: key.clone(),
                            expected: current_slot.clone(),
                            new: candidate_slot.clone(),
                        },
                    )?;
                    validate_private_oram_mutation_slot_state_relationship(
                        &candidate_slot,
                        &current_state,
                        key,
                    )?;
                    if self.external_recovery_is_active(&key.collection_id)
                        || self.state_has_active_session(&current_state)
                    {
                        return Err(StorageError::bad_request(
                            "private ORAM V2 rejected admission conflicts with active recovery",
                        ));
                    }
                    let layout = self.layout(&PrivateOramLayoutKey {
                        collection_id: current_state.collection_id.clone(),
                    });
                    if !layout
                        .as_ref()
                        .is_some_and(|layout| layout.owner_peer_ids.contains(&lease.owner_peer_id))
                        || lease.base_record_digest != current_record_digest
                        || lease.base_state_sequence != current_state.state_sequence
                        || private_oram_state_last_mutation_id(&current_state)
                            .is_some_and(|mutation_id| mutation_id == lease.mutation_id)
                        || current_slot
                            .last_clear
                            .as_ref()
                            .is_some_and(|receipt| receipt.mutation_id == lease.mutation_id)
                    {
                        return Err(StorageError::bad_request(
                            "private ORAM V2 rejected admission is invalid",
                        ));
                    }
                }
                let request_digest = private_oram_mutation_admission_request_digest_v2(
                    lease,
                    recovery_manifest.manifest_digest(),
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::AdmissionRejected,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_admission_rejected_v2(
                    &current_authority,
                    lease.clone(),
                    recovery_manifest_canonical_json.clone(),
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::Renewal { lease }
            | PrivateOramMutationMaterialTransitionV2::AbortDecision { lease } => {
                let operation_kind = match operation.transition() {
                    PrivateOramMutationMaterialTransitionV2::Renewal { .. } => {
                        PrivateOramMutationMaterialOperationV2::Renewal
                    }
                    PrivateOramMutationMaterialTransitionV2::AbortDecision { .. } => {
                        PrivateOramMutationMaterialOperationV2::AbortDecision
                    }
                    _ => unreachable!(),
                };
                let replay = current_slot.active.as_ref() == Some(lease);
                let next_slot = if replay {
                    current_slot.clone()
                } else {
                    let mut next = current_slot.clone();
                    next.active = Some(lease.clone());
                    validate_private_oram_mutation_lease_cas(
                        &CompareAndSwapPrivateOramMutationLease {
                            key: key.clone(),
                            expected: current_slot.clone(),
                            new: next.clone(),
                        },
                    )?;
                    next
                };
                validate_private_oram_mutation_slot_state_relationship(
                    &next_slot,
                    &current_state,
                    key,
                )?;
                let next_outer = if replay {
                    recomputed_current_outer
                } else {
                    private_oram_mutation_outer_binding_digest_v2(
                        &key.collection_id,
                        &current_record_digest,
                        &next_slot,
                    )
                    .map_err(private_oram_mutation_authority_corrupt)?
                };
                let request_digest = private_oram_mutation_lease_state_digest_v2(lease)
                    .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    operation_kind,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    next_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_lease_transition_v2(
                    &current_authority,
                    lease.clone(),
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(&next_authority, &next_slot, &next_outer)?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::ConsensusCommit {
                mutation_lease_generation,
                new_state,
            } => {
                let replay = current_state == *new_state;
                let (committed_lease, next_slot, next_record_digest) = if replay {
                    self.validate_state_bindings(new_state)?;
                    let lease = current_slot
                        .active
                        .as_ref()
                        .or_else(|| current_aggregate.retained_terminal_lease())
                        .filter(|lease| lease.generation == *mutation_lease_generation)
                        .cloned()
                        .ok_or_else(|| {
                            StorageError::bad_request(
                                "private ORAM V2 mutation commit replay has no terminal lease",
                            )
                        })?;
                    validate_private_oram_committed_lease_for_state_v2(
                        &lease,
                        new_state,
                        key,
                        *mutation_lease_generation,
                    )?;
                    (
                        lease,
                        current_slot.clone(),
                        canonical_private_oram_consensus_state_record_digest(new_state)?,
                    )
                } else {
                    let legacy_shape = ApplyPrivateOramMutation {
                        key: key.clone(),
                        mutation_lease_generation: *mutation_lease_generation,
                        expected_state: current_state.clone(),
                        new_state: new_state.clone(),
                    };
                    validate_apply_private_oram_mutation(&legacy_shape)?;
                    if self.external_recovery_is_active(&key.collection_id)
                        || self.state_has_active_session(&current_state)
                    {
                        return Err(StorageError::bad_request(
                            "private ORAM V2 mutation commit conflicts with another collection operation",
                        ));
                    }
                    let preparing_lease = current_slot.active.as_ref().ok_or_else(|| {
                        StorageError::bad_request(
                            "private ORAM V2 mutation commit requires an active lease",
                        )
                    })?;
                    validate_apply_private_oram_mutation_lease(
                        &legacy_shape,
                        &current_state,
                        preparing_lease,
                    )?;
                    let PrivateOramConsensusTransitionV2::Mutation(receipt) =
                        &new_state.last_transition
                    else {
                        unreachable!()
                    };
                    let committed_record_digest =
                        canonical_private_oram_consensus_state_record_digest(new_state)?;
                    let receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt)?;
                    let mut lease = preparing_lease.clone();
                    lease.phase = PrivateOramMutationLeasePhase::ConsensusCommitted {
                        committed_record_digest: committed_record_digest.clone(),
                        committed_state_sequence: new_state.state_sequence,
                        committed_signed_state_digest: new_state.signed_state_digest.clone(),
                        receipt_digest,
                    };
                    let mut next = current_slot.clone();
                    next.active = Some(lease.clone());
                    validate_private_oram_mutation_slot_state_relationship(&next, new_state, key)?;
                    (lease, next, committed_record_digest)
                };
                let next_outer = if replay {
                    recomputed_current_outer
                } else {
                    private_oram_mutation_outer_binding_digest_v2(
                        &key.collection_id,
                        &next_record_digest,
                        &next_slot,
                    )
                    .map_err(private_oram_mutation_authority_corrupt)?
                };
                let request_digest = private_oram_mutation_lease_state_digest_v2(&committed_lease)
                    .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::ConsensusCommit,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    next_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_lease_transition_v2(
                    &current_authority,
                    committed_lease,
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(&next_authority, &next_slot, &next_outer)?;
                if !replay {
                    let layout_key = PrivateOramLayoutKey {
                        collection_id: key.collection_id.clone(),
                    };
                    let layout_key_digest = private_oram_layout_key_digest(&layout_key);
                    let mut new_layout = self
                        .private_oram_layouts
                        .get(&layout_key_digest)
                        .cloned()
                        .ok_or_else(|| {
                            StorageError::bad_request("private ORAM V2 mutation layout is missing")
                        })?;
                    new_layout.index_state_digest =
                        private_oram_consensus_state_index_digest(new_state)?;
                    for index in &new_state.indexes {
                        let epoch_key =
                            private_oram_mutation_index_epoch_key(&new_state.collection_id, index);
                        self.private_oram_epochs.insert(
                            private_oram_epoch_key_digest(&epoch_key),
                            index.epoch.clone(),
                        );
                    }
                    self.private_oram_mutation_states
                        .insert(key_digest.clone(), new_state.clone());
                    self.private_oram_layouts
                        .insert(layout_key_digest, new_layout);
                }
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::ParentProgress {
                watermark_canonical_json,
            } => {
                let expected = decode_private_oram_mutation_parent_watermark_expectation_v2(
                    watermark_canonical_json,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let request_digest = expected.watermark().watermark_digest().to_string();
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::ParentProgress,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_parent_progress_v2(
                    &current_authority,
                    &expected,
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::RecoveryCapsulesReady {
                expectation_canonical_json,
            } => {
                let expected = decode_private_oram_mutation_recovery_capsules_ready_v2(
                    expectation_canonical_json,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let layout = self
                    .layout(&PrivateOramLayoutKey {
                        collection_id: key.collection_id.clone(),
                    })
                    .ok_or_else(|| {
                        StorageError::bad_request(
                            "private ORAM V2 recovery capsule layout is missing",
                        )
                    })?;
                let current_activation = self
                    .private_oram_activation_authority
                    .as_ref()
                    .ok_or_else(|| {
                        StorageError::bad_request("private ORAM V2 activation authority is missing")
                    })?;
                validate_private_oram_mutation_recovery_capsules_ready_against_authority_v2(
                    expected.ready(),
                    &key.collection_id,
                    current_activation,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                if expected.ready().owner_peer_ids() != layout.owner_peer_ids
                    || expected.ready().activation_authority() != &current_activation.locator()
                {
                    return Err(StorageError::bad_request(
                        "private ORAM V2 recovery capsule certificate is invalid",
                    ));
                }
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::RecoveryCapsulesReady,
                    expected.ready().ready_digest().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_recovery_capsules_ready_v2(
                        &current_authority,
                        &expected,
                        context,
                    )
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::CleanupWitness {
                expectation_canonical_json,
            } => {
                let expected =
                    decode_private_oram_mutation_cleanup_expectation_v2(expectation_canonical_json)
                        .map_err(private_oram_mutation_authority_invalid)?;
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::CleanupWitness,
                    expected.evidence_digest().to_string(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_cleanup_witness_v2(
                    &current_authority,
                    &expected,
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::ClearPending {
                clear_attempt_id_digest,
            } => {
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::ClearPending,
                    clear_attempt_id_digest.clone(),
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = apply_private_oram_mutation_authority_clear_pending_v2(
                    &current_authority,
                    clear_attempt_id_digest.clone(),
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::Clear => {
                let (request_digest, next_slot, replay) = current_aggregate
                    .clear_transition_preview()
                    .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_mutation_slot_state_relationship(
                    &next_slot,
                    &current_state,
                    key,
                )?;
                let next_outer = if replay {
                    recomputed_current_outer
                } else {
                    private_oram_mutation_outer_binding_digest_v2(
                        &key.collection_id,
                        &current_record_digest,
                        &next_slot,
                    )
                    .map_err(private_oram_mutation_authority_corrupt)?
                };
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::Clear,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    next_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority =
                    apply_private_oram_mutation_authority_clear_v2(&current_authority, context)
                        .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(&next_authority, &next_slot, &next_outer)?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
            PrivateOramMutationMaterialTransitionV2::ClearAcknowledgement => {
                let request_digest = current_aggregate
                    .clear_acknowledgement_request_digest()
                    .map_err(private_oram_mutation_authority_invalid)?
                    .to_string();
                let context = private_oram_mutation_aggregate_apply_context_v2(
                    &current_authority,
                    PrivateOramMutationMaterialOperationV2::ClearAcknowledgement,
                    request_digest,
                    operation.expected_aggregate_digest().to_string(),
                    recomputed_current_outer.clone(),
                    entry_term,
                    entry_index,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                let next_authority = acknowledge_private_oram_mutation_authority_clear_v2(
                    &current_authority,
                    context,
                )
                .map_err(private_oram_mutation_authority_invalid)?;
                validate_private_oram_material_result_v2(
                    &next_authority,
                    &current_slot,
                    &recomputed_current_outer,
                )?;
                self.private_oram_mutation_lease_slots.insert(
                    key_digest,
                    DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next_authority),
                );
            }
        }
        Ok(())
    }

    fn validate_private_oram_append_reservation_environment_v2(
        &self,
        key: &PrivateOramMutationKey,
        current_state: &PrivateOramConsensusCollectionStateV2,
        current_record_digest: &str,
        current_slot: &PrivateOramMutationLeaseSlotV2,
        reservation: &PrivateOramMutationAppendReservationV2,
    ) -> Result<(), StorageError> {
        let current_activation =
            self.private_oram_activation_authority
                .as_ref()
                .ok_or_else(|| {
                    StorageError::bad_request("private ORAM V2 activation authority is missing")
                })?;
        let layout = self
            .layout(&PrivateOramLayoutKey {
                collection_id: current_state.collection_id.clone(),
            })
            .ok_or_else(|| {
                StorageError::bad_request("private ORAM V2 append reservation layout is missing")
            })?;
        let reserved_owner_ids = reservation
            .owner_targets()
            .iter()
            .map(|target| target.owner_peer_id())
            .collect::<Vec<_>>();
        if reservation.activation_authority() != &current_activation.locator()
            || reserved_owner_ids != layout.owner_peer_ids
            || reservation.owner_targets().iter().any(|target| {
                current_activation
                    .manifest()
                    .peers
                    .binary_search_by_key(&target.owner_peer_id(), |peer| peer.peer_id)
                    .ok()
                    .map(|index| &current_activation.manifest().peers[index])
                    .is_none_or(|pin| &pin.signer != target.owner_signer())
            })
        {
            return Err(StorageError::bad_request(
                "private ORAM V2 append reservation authority is invalid",
            ));
        }
        let lease = reservation.preparing_lease();
        let mut candidate_slot = current_slot.clone();
        candidate_slot.generation = lease.generation;
        candidate_slot.max_writer_fence = lease.writer_fence;
        candidate_slot.active = Some(lease.clone());
        validate_private_oram_mutation_lease_cas(&CompareAndSwapPrivateOramMutationLease {
            key: key.clone(),
            expected: current_slot.clone(),
            new: candidate_slot.clone(),
        })?;
        validate_private_oram_mutation_slot_state_relationship(
            &candidate_slot,
            current_state,
            key,
        )?;
        if self.external_recovery_is_active(&key.collection_id)
            || self.state_has_active_session(current_state)
            || lease.base_record_digest != current_record_digest
            || lease.base_state_sequence != current_state.state_sequence
            || private_oram_state_last_mutation_id(current_state)
                .is_some_and(|mutation_id| mutation_id == lease.mutation_id)
            || current_slot
                .last_clear
                .as_ref()
                .is_some_and(|receipt| receipt.mutation_id == lease.mutation_id)
        {
            return Err(StorageError::bad_request(
                "private ORAM V2 append reservation conflicts with current state",
            ));
        }
        Ok(())
    }

    fn mutation_state(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramConsensusCollectionStateV2> {
        self.private_oram_mutation_states
            .get(&private_oram_mutation_key_digest(key))
            .cloned()
    }

    fn mutation_lease_slot(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationLeaseSlotV2>, StorageError> {
        self.historical_mutation_lease_slot_by_digest(&private_oram_mutation_key_digest(key))
    }

    fn historical_mutation_lease_slot_by_digest(
        &self,
        key_digest: &str,
    ) -> Result<Option<PrivateOramMutationLeaseSlotV2>, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(key_digest)
            .map(|wire| {
                // Every replica holds the same tagged slot, so refusing the legacy operation is
                // deterministic: reject the entry (and advance the apply cursor) instead of
                // raising a service error, which stops consensus on every node for good.
                wire.historical_raw_slot().cloned().ok_or_else(|| {
                    StorageError::bad_request(
                        "legacy private ORAM mutation operation encountered tagged authority state",
                    )
                })
            })
            .transpose()
    }

    fn external_recovery_is_active(&self, collection_id: &str) -> bool {
        self.private_oram_external_recoveries
            .get(&private_oram_external_recovery_key_digest(
                &PrivateOramExternalRecoveryKey {
                    collection_id: collection_id.to_string(),
                },
            ))
            .and_then(|state| state.active_lease.as_ref())
            .is_some()
    }

    fn layout(&self, key: &PrivateOramLayoutKey) -> Option<PrivateOramConsensusLayout> {
        self.private_oram_layouts
            .get(&private_oram_layout_key_digest(key))
            .cloned()
    }

    fn epoch(&self, key: &PrivateOramEpochKey) -> Option<PrivateOramConsensusEpoch> {
        self.private_oram_epochs
            .get(&private_oram_epoch_key_digest(key))
            .cloned()
    }

    fn session_lease(&self, key: &PrivateOramEpochKey) -> Option<PrivateOramSessionLease> {
        self.private_oram_session_leases
            .get(&private_oram_epoch_key_digest(key))
            .cloned()
    }

    fn validate_state_bindings(
        &self,
        state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<(), StorageError> {
        let layout = self.layout(&PrivateOramLayoutKey {
            collection_id: state.collection_id.clone(),
        });
        let expected_index_state_digest = private_oram_consensus_state_index_digest(state)?;
        if !layout.as_ref().is_some_and(|layout| {
            layout.generation == state.layout_generation
                && layout.layout_digest == state.layout_digest
                && layout.index_state_digest == expected_index_state_digest
        }) || state.indexes.iter().any(|index| {
            self.epoch(&private_oram_mutation_index_epoch_key(
                &state.collection_id,
                index,
            ))
            .as_ref()
                != Some(&index.epoch)
        }) {
            return Err(StorageError::bad_request(
                "private ORAM mutation state bindings are inconsistent",
            ));
        }
        Ok(())
    }

    fn state_has_active_session(&self, state: &PrivateOramConsensusCollectionStateV2) -> bool {
        state.indexes.iter().any(|index| {
            self.session_lease(&private_oram_mutation_index_epoch_key(
                &state.collection_id,
                index,
            ))
            .is_some()
        })
    }
}

impl fmt::Debug for Persistent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let peer_address_count = self.peer_address_by_id.read().len();
        let peer_metadata = self.peer_metadata_by_id.read();
        let peer_metadata_count = peer_metadata.len();
        let peer_crypto_fingerprint_count = peer_metadata
            .values()
            .filter(|metadata| metadata.crypto_runtime_capability_fingerprint().is_some())
            .count();
        let mut cluster_metadata_keys = self.cluster_metadata.keys().collect::<Vec<_>>();
        cluster_metadata_keys.sort();

        f.debug_struct("Persistent")
            .field("state", &self.state)
            .field("latest_snapshot_meta", &self.latest_snapshot_meta)
            .field("apply_progress_queue", &self.apply_progress_queue)
            .field("first_voter", &self.first_voter)
            .field("peer_address_count", &peer_address_count)
            .field("peer_metadata_count", &peer_metadata_count)
            .field(
                "peer_crypto_runtime_capability_fingerprint_count",
                &peer_crypto_fingerprint_count,
            )
            .field("cluster_metadata_keys", &cluster_metadata_keys)
            .field(
                "has_private_oram_activation_authority",
                &self.private_oram_activation_authority.is_some(),
            )
            .field("private_oram_epoch_count", &self.private_oram_epochs.len())
            .field(
                "private_oram_session_lease_count",
                &self.private_oram_session_leases.len(),
            )
            .field(
                "private_oram_layout_count",
                &self.private_oram_layouts.len(),
            )
            .field(
                "private_oram_external_recovery_count",
                &self.private_oram_external_recoveries.len(),
            )
            .field(
                "private_oram_mutation_state_count",
                &self.private_oram_mutation_states.len(),
            )
            .field(
                "private_oram_mutation_lease_slot_count",
                &self.private_oram_mutation_lease_slots.len(),
            )
            .field(
                "private_oram_mutation_format_epoch",
                &self
                    .private_oram_mutation_format_floor
                    .as_ref()
                    .map(PrivateOramMutationFormatFloorV2::format_epoch),
            )
            .field("this_peer_id", &self.this_peer_id)
            .field("path", &self.path)
            .field("dirty", &self.dirty.load(Ordering::Relaxed))
            .field(
                "save_indeterminate",
                &self.save_indeterminate.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl Persistent {
    fn clone_for_private_oram_mutation_patch(&self) -> Self {
        let private_oram_activation_authority_trust_anchor = OnceLock::new();
        if let Some(trust_anchor) = self.private_oram_activation_authority_trust_anchor.get() {
            private_oram_activation_authority_trust_anchor
                .set(trust_anchor.clone())
                .expect("fresh private ORAM trust-anchor cell must be empty");
        }

        Self {
            state: self.state.clone(),
            latest_snapshot_meta: self.latest_snapshot_meta.clone(),
            apply_progress_queue: self.apply_progress_queue,
            first_voter: self.first_voter,
            peer_address_by_id: Arc::clone(&self.peer_address_by_id),
            peer_metadata_by_id: Arc::clone(&self.peer_metadata_by_id),
            cluster_metadata: self.cluster_metadata.clone(),
            private_oram_activation_authority: self.private_oram_activation_authority.clone(),
            private_oram_epochs: self.private_oram_epochs.clone(),
            private_oram_session_leases: self.private_oram_session_leases.clone(),
            private_oram_layouts: self.private_oram_layouts.clone(),
            private_oram_external_recoveries: self.private_oram_external_recoveries.clone(),
            private_oram_mutation_states: self.private_oram_mutation_states.clone(),
            private_oram_mutation_lease_slots: self.private_oram_mutation_lease_slots.clone(),
            private_oram_mutation_format_floor: self.private_oram_mutation_format_floor.clone(),
            private_oram_mutation_activation_pending: self
                .private_oram_mutation_activation_pending
                .clone(),
            this_peer_id: self.this_peer_id,
            private_oram_activation_authority_store_instance: self
                .private_oram_activation_authority_store_instance,
            private_oram_activation_authority_trust_anchor,
            path: self.path.clone(),
            persistence_transaction: Arc::clone(&self.persistence_transaction),
            dirty: AtomicBool::new(self.dirty.load(Ordering::Acquire)),
            save_indeterminate: AtomicBool::new(self.save_indeterminate.load(Ordering::Acquire)),
        }
    }

    fn apply_private_oram_mutation_activation_barrier(
        &mut self,
        operation: &PrivateOramMutationActivationBarrierV2,
        facts: PrivateOramMutationActivationApplyFactsV2,
    ) -> Result<(), StorageError> {
        let prior_applied_index = self
            .apply_progress_queue
            .get_last_applied()
            .unwrap_or(self.latest_snapshot_meta.index);
        if prior_applied_index != facts.prior_applied_index {
            return Err(StorageError::service_error(
                "private ORAM mutation activation apply cursor is inconsistent",
            ));
        }

        let trust_anchor = self
            .private_oram_activation_authority_trust_anchor()?
            .clone();
        let authority = self.private_oram_activation_authority_at_read(&trust_anchor)?;
        let peer_addresses = self.peer_address_by_id.read().clone();
        let verified = validate_private_oram_mutation_activation_barrier_v2(
            operation,
            &authority,
            self.private_oram_mutation_format_floor.as_ref(),
            self.private_oram_mutation_activation_pending.as_ref(),
            &self.state.conf_state,
            &peer_addresses,
            facts,
        )?;

        if self
            .private_oram_mutation_lease_slots
            .values()
            .any(|wire| wire.lease_slot().active.is_some())
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation activation requires quiescent mutation leases",
            ));
        }
        if self.private_oram_mutation_states.len() != self.private_oram_mutation_lease_slots.len() {
            return Err(StorageError::service_error(
                "private ORAM mutation activation state is inconsistent",
            ));
        }

        let mut keys = self
            .private_oram_mutation_states
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort_unstable();
        let mut next_authorities = HashMap::with_capacity(keys.len());
        for key_digest in keys {
            let state = self
                .private_oram_mutation_states
                .get(&key_digest)
                .ok_or_else(|| {
                    StorageError::service_error(
                        "private ORAM mutation activation state is inconsistent",
                    )
                })?;
            if private_oram_mutation_key_digest(&PrivateOramMutationKey {
                collection_id: state.collection_id.clone(),
            }) != key_digest
            {
                return Err(StorageError::service_error(
                    "private ORAM mutation activation state is inconsistent",
                ));
            }
            let current_wire = self
                .private_oram_mutation_lease_slots
                .get(&key_digest)
                .ok_or_else(|| {
                    StorageError::service_error(
                        "private ORAM mutation activation state is inconsistent",
                    )
                })?;
            let next = match operation.phase() {
                PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites => {
                    let state_record_digest = canonical_private_oram_consensus_state_record_digest(
                        state,
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?;
                    let lifetime_digest = private_oram_mutation_collection_lifetime_id_digest_v2(
                        &state.collection_id,
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?;
                    let authority_key = private_oram_mutation_authority_key_v2(
                        &state.collection_id,
                        verified.consensus_history_id_digest().to_string(),
                        verified.raft_group_id_digest().to_string(),
                        lifetime_digest,
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?;
                    let outer_binding_digest = private_oram_mutation_outer_binding_digest_v2(
                        &state.collection_id,
                        &state_record_digest,
                        current_wire.lease_slot(),
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?;
                    canonical_private_oram_mutation_legacy_authority_from_wire_v2(
                        current_wire,
                        &authority_key,
                        &outer_binding_digest,
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?
                }
                PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2 => {
                    let current = current_wire.tagged_authority().ok_or_else(|| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?;
                    let context = private_oram_mutation_activation_context_from_barrier_v2(
                        verified.consensus_history_id_digest().to_string(),
                        verified.raft_group_id_digest().to_string(),
                        facts.entry_term,
                        facts.entry_index,
                        verified.next_format_floor().format_epoch(),
                        verified.proof().proof_digest(),
                        &state.collection_id,
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?;
                    activate_private_oram_mutation_authority_v2(
                        current,
                        &state.collection_id,
                        context,
                    )
                    .map_err(|_| {
                        StorageError::service_error(
                            "private ORAM mutation activation state is inconsistent",
                        )
                    })?
                }
                PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads
                | PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes => {
                    let current = current_wire.tagged_authority().ok_or_else(|| {
                        StorageError::service_error(
                            "private ORAM mutation V3 floor upgrade authority is inconsistent",
                        )
                    })?;
                    // A reservation can commit between the proposer's quiescence check and this
                    // entry; reject the barrier deterministically so it can be re-proposed rather
                    // than stopping consensus on every node.
                    if current
                        .aggregate()
                        .is_some_and(|aggregate| !aggregate.is_reservation_v3_floor_quiescent())
                    {
                        return Err(StorageError::bad_request(
                            "private ORAM mutation V3 floor upgrade requires quiescent reservation history",
                        ));
                    }
                    current.clone()
                }
            };
            next_authorities.insert(
                key_digest,
                DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(next),
            );
        }

        self.private_oram_mutation_lease_slots = next_authorities;
        self.private_oram_mutation_format_floor = Some(verified.next_format_floor().clone());
        self.private_oram_mutation_activation_pending = verified.next_pending().cloned();
        Ok(())
    }

    fn confirm_private_oram_mutation_authority_v2(
        &self,
        operation: &ConfirmPrivateOramMutationAuthorityV2,
    ) -> Result<(), StorageError> {
        validate_private_oram_mutation_key(&operation.key)?;
        validate_private_oram_mutation_lease_slot(&operation.expected)?;
        let Some(expected_lease) = operation.expected.active.as_ref() else {
            return Err(StorageError::bad_request(
                "private ORAM mutation authority confirmation requires an active lease",
            ));
        };
        if expected_lease.collection_id != operation.key.collection_id {
            return Err(StorageError::bad_request(
                "private ORAM mutation authority confirmation is invalid",
            ));
        }
        let current = self
            .private_oram_mutation_lease_slot(&operation.key)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM mutation authority confirmation has no enrolled state",
                )
            })?;
        if current != operation.expected {
            return Err(StorageError::bad_request(
                "private ORAM mutation authority confirmation is stale",
            ));
        }
        let state = self
            .private_oram_mutation_state(&operation.key)
            .ok_or_else(|| {
                StorageError::service_error("private ORAM mutation authority state is inconsistent")
            })?;
        validate_private_oram_mutation_slot_state_relationship(
            &operation.expected,
            &state,
            &operation.key,
        )
    }

    fn prepare_private_oram_mutation_complete_patch(
        &self,
        applied_entry_index: Option<EntryId>,
        command: PrivateOramMutationCommand<'_>,
    ) -> Result<PrivateOramMutationCompletePatch, StorageError> {
        self.ensure_persistence_writable()?;
        if let Some(entry_index) = applied_entry_index
            && self.apply_progress_queue.current() != Some(entry_index)
        {
            return Err(StorageError::service_error(
                "private ORAM mutation Raft apply cursor does not match the committed entry",
            ));
        }

        let mut next = Box::new(self.clone_for_private_oram_mutation_patch());
        let apply_result = match command {
            PrivateOramMutationCommand::Initialize(operation) => {
                PrivateOramMutationPatchView::new(&mut next).apply_initialize(operation)
            }
            PrivateOramMutationCommand::CompareAndSwapLease(operation) => {
                PrivateOramMutationPatchView::new(&mut next).apply_compare_and_swap_lease(operation)
            }
            PrivateOramMutationCommand::ConfirmAuthority(operation) => {
                next.confirm_private_oram_mutation_authority_v2(operation)
            }
            PrivateOramMutationCommand::Apply(operation) => {
                PrivateOramMutationPatchView::new(&mut next).apply_mutation(operation)
            }
            PrivateOramMutationCommand::ActivateV2(operation, facts) => {
                next.apply_private_oram_mutation_activation_barrier(operation, facts)
            }
            PrivateOramMutationCommand::ApplyMaterialV2 {
                operation,
                entry_term,
                entry_index,
            } => PrivateOramMutationPatchView::new(&mut next).apply_material_v2(
                operation,
                entry_term,
                entry_index,
            ),
        };
        let disposition = match (applied_entry_index, apply_result) {
            (None, Ok(())) => PrivateOramMutationPatchDisposition::Detached,
            (None, Err(error)) => return Err(error),
            (Some(_), Ok(())) => PrivateOramMutationPatchDisposition::AppliedAtEntry,
            (Some(_), Err(error @ StorageError::ServiceError { .. })) => return Err(error),
            (Some(_), Err(error)) => {
                next = Box::new(self.clone_for_private_oram_mutation_patch());
                PrivateOramMutationPatchDisposition::RejectedAtEntry(error)
            }
        };

        if let Some(entry_index) = applied_entry_index {
            next.apply_progress_queue.applied();
            if next.apply_progress_queue.get_last_applied() != Some(entry_index) {
                return Err(StorageError::service_error(
                    "private ORAM mutation Raft apply cursor failed to advance exactly once",
                ));
            }
        }

        let applied_index = next
            .apply_progress_queue
            .get_last_applied()
            .unwrap_or(next.latest_snapshot_meta.index);
        Self::validate_private_oram_snapshot_state_at_index(
            &next.private_oram_epochs,
            &next.private_oram_session_leases,
            &next.private_oram_layouts,
            &next.private_oram_external_recoveries,
            &next.private_oram_mutation_states,
            &next.private_oram_mutation_lease_slots,
            next.private_oram_mutation_format_floor.as_ref(),
            next.private_oram_mutation_activation_pending.as_ref(),
            next.private_oram_activation_authority.as_ref(),
            applied_index,
        )?;
        Ok(PrivateOramMutationCompletePatch { next, disposition })
    }

    fn commit_private_oram_mutation_complete_patch_with_backend(
        &mut self,
        mut patch: PrivateOramMutationCompletePatch,
        backend: &impl PersistentSaveBackend,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        match patch.next.save_classified_with_backend(backend) {
            Ok(()) => {
                PrivateOramMutationDurableFields::take_from(&mut patch.next).install_into(self);
                self.dirty.store(false, Ordering::Release);
                match patch.disposition {
                    PrivateOramMutationPatchDisposition::Detached
                    | PrivateOramMutationPatchDisposition::AppliedAtEntry => {
                        Ok(PrivateOramMutationAtEntryOutcome::Applied)
                    }
                    PrivateOramMutationPatchDisposition::RejectedAtEntry(error) => {
                        Ok(PrivateOramMutationAtEntryOutcome::Rejected(error))
                    }
                }
            }
            Err(error @ PersistentSaveError::Definitive(_)) => Err(error.into_storage_error()),
            Err(PersistentSaveError::Indeterminate) => {
                self.dirty.store(true, Ordering::Release);
                self.save_indeterminate.store(true, Ordering::Release);
                Err(PersistentSaveError::Indeterminate.into_storage_error())
            }
        }
    }

    pub(crate) fn validate_private_oram_snapshot_state(
        private_oram_epochs: &HashMap<String, PrivateOramConsensusEpoch>,
        private_oram_session_leases: &HashMap<String, PrivateOramSessionLease>,
        private_oram_layouts: &HashMap<String, PrivateOramConsensusLayout>,
        private_oram_external_recoveries: &HashMap<String, PrivateOramExternalRecoveryState>,
        private_oram_mutation_states: &HashMap<String, PrivateOramConsensusCollectionStateV2>,
        private_oram_mutation_lease_slots: &HashMap<
            String,
            DecodedPrivateOramMutationAuthorityWireV2,
        >,
        private_oram_activation_authority: Option<&PrivateOramActivationAuthorityStateV1>,
    ) -> Result<(), StorageError> {
        validate_private_oram_epoch_snapshot(private_oram_epochs)?;
        validate_private_oram_session_lease_snapshot(private_oram_session_leases)?;
        validate_private_oram_layout_snapshot(private_oram_layouts)?;
        validate_private_oram_external_recovery_snapshot(private_oram_external_recoveries)?;
        validate_private_oram_mutation_state_snapshot(
            private_oram_mutation_states,
            private_oram_epochs,
            private_oram_layouts,
        )?;
        validate_private_oram_mutation_lease_slot_snapshot(
            private_oram_mutation_lease_slots,
            private_oram_mutation_states,
            private_oram_layouts,
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_external_recoveries,
        )?;
        if let Some(authority) = private_oram_activation_authority {
            validate_private_oram_activation_authority_state_v1_shape(authority).map_err(|_| {
                StorageError::bad_request("private ORAM activation authority snapshot is invalid")
            })?;
        }
        Ok(())
    }

    pub(crate) fn validate_private_oram_snapshot_state_at_index(
        private_oram_epochs: &HashMap<String, PrivateOramConsensusEpoch>,
        private_oram_session_leases: &HashMap<String, PrivateOramSessionLease>,
        private_oram_layouts: &HashMap<String, PrivateOramConsensusLayout>,
        private_oram_external_recoveries: &HashMap<String, PrivateOramExternalRecoveryState>,
        private_oram_mutation_states: &HashMap<String, PrivateOramConsensusCollectionStateV2>,
        private_oram_mutation_lease_slots: &HashMap<
            String,
            DecodedPrivateOramMutationAuthorityWireV2,
        >,
        private_oram_mutation_format_floor: Option<&PrivateOramMutationFormatFloorV2>,
        private_oram_mutation_activation_pending: Option<&PrivateOramMutationActivationPendingV2>,
        private_oram_activation_authority: Option<&PrivateOramActivationAuthorityStateV1>,
        applied_index: u64,
    ) -> Result<(), StorageError> {
        Self::validate_private_oram_snapshot_state(
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_layouts,
            private_oram_external_recoveries,
            private_oram_mutation_states,
            private_oram_mutation_lease_slots,
            private_oram_activation_authority,
        )?;
        if private_oram_mutation_format_floor.is_some_and(|floor| {
            PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION < floor.minimum_reader_protocol()
                || PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION < floor.minimum_writer_protocol()
        }) {
            return Err(StorageError::bad_request(
                "private ORAM mutation snapshot requires a newer consensus protocol",
            ));
        }
        validate_private_oram_mutation_activation_pending_v2(
            private_oram_mutation_activation_pending,
            private_oram_mutation_format_floor,
            applied_index,
            private_oram_activation_authority.is_some(),
        )?;
        validate_private_oram_mutation_authority_format_snapshot(
            private_oram_mutation_lease_slots,
            private_oram_mutation_states,
            private_oram_mutation_format_floor,
            applied_index,
        )
    }

    pub fn state(&self) -> &RaftState {
        &self.state
    }

    pub fn latest_snapshot_meta(&self) -> &SnapshotMetadataSer {
        &self.latest_snapshot_meta
    }

    pub(crate) fn update_from_snapshot(
        &mut self,
        meta: &SnapshotMetadata,
        address_by_id: PeerAddressById,
        mut metadata_by_id: PeerMetadataById,
        new_cluster_metadata: HashMap<String, serde_json::Value>,
        new_private_oram_epochs: HashMap<String, PrivateOramConsensusEpoch>,
        new_private_oram_session_leases: HashMap<String, PrivateOramSessionLease>,
        new_private_oram_layouts: HashMap<String, PrivateOramConsensusLayout>,
        new_private_oram_external_recoveries: HashMap<String, PrivateOramExternalRecoveryState>,
        new_private_oram_mutation_states: HashMap<String, PrivateOramConsensusCollectionStateV2>,
        new_private_oram_mutation_lease_slots: HashMap<
            String,
            DecodedPrivateOramMutationAuthorityWireV2,
        >,
        new_private_oram_mutation_format_floor: Option<PrivateOramMutationFormatFloorV2>,
        new_private_oram_mutation_activation_pending: Option<
            PrivateOramMutationActivationPendingV2,
        >,
        new_private_oram_activation_authority: Option<PrivateOramActivationAuthorityStateV1>,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        Self::validate_private_oram_snapshot_state_at_index(
            &new_private_oram_epochs,
            &new_private_oram_session_leases,
            &new_private_oram_layouts,
            &new_private_oram_external_recoveries,
            &new_private_oram_mutation_states,
            &new_private_oram_mutation_lease_slots,
            new_private_oram_mutation_format_floor.as_ref(),
            new_private_oram_mutation_activation_pending.as_ref(),
            new_private_oram_activation_authority.as_ref(),
            meta.index,
        )?;
        validate_private_oram_external_recovery_snapshot_transition_for_peer(
            &self.private_oram_external_recoveries,
            &new_private_oram_external_recoveries,
            self.this_peer_id,
        )?;
        self.validate_private_oram_activation_authority_for_snapshot(
            new_private_oram_activation_authority.as_ref(),
        )?;
        let previous_state = self.state.clone();
        let previous_latest_snapshot_meta = self.latest_snapshot_meta.clone();
        let previous_apply_progress_queue = self.apply_progress_queue;
        let previous_peer_address_by_id = self.peer_address_by_id.read().clone();
        let previous_peer_metadata_by_id = self.peer_metadata_by_id.read().clone();
        let previous_cluster_metadata = self.cluster_metadata.clone();
        let previous_private_oram_epochs = self.private_oram_epochs.clone();
        let previous_private_oram_session_leases = self.private_oram_session_leases.clone();
        let previous_private_oram_layouts = self.private_oram_layouts.clone();
        let previous_private_oram_external_recoveries =
            self.private_oram_external_recoveries.clone();
        let previous_private_oram_mutation_states = self.private_oram_mutation_states.clone();
        let previous_private_oram_mutation_lease_slots =
            self.private_oram_mutation_lease_slots.clone();
        let previous_private_oram_mutation_format_floor =
            self.private_oram_mutation_format_floor.clone();
        let previous_private_oram_mutation_activation_pending =
            self.private_oram_mutation_activation_pending.clone();
        let previous_private_oram_activation_authority =
            self.private_oram_activation_authority.clone();
        // IF YOU ADD NEW DATA INTO `PERSISTENT` STATE, DON'T FORGET TO ALSO ADD IT INTO RAFT SNAPSHOT!
        let Self {
            state,
            latest_snapshot_meta,
            apply_progress_queue,
            first_voter: _,
            peer_address_by_id,
            peer_metadata_by_id,
            cluster_metadata,
            private_oram_activation_authority,
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_layouts,
            private_oram_external_recoveries,
            private_oram_mutation_states,
            private_oram_mutation_lease_slots,
            private_oram_mutation_format_floor,
            private_oram_mutation_activation_pending,
            this_peer_id: _,
            private_oram_activation_authority_store_instance: _,
            private_oram_activation_authority_trust_anchor: _,
            path: _,
            persistence_transaction: _,
            dirty: _,
            save_indeterminate: _,
        } = self;

        state.conf_state = meta.get_conf_state().clone();
        state.hard_state.term = cmp::max(state.hard_state.term, meta.term);
        state.hard_state.commit = meta.index;

        apply_progress_queue.set_from_snapshot(meta.index);
        *latest_snapshot_meta = meta.into();

        metadata_by_id.retain(|peer_id, _| address_by_id.contains_key(peer_id));

        *peer_address_by_id.write() = address_by_id;
        *peer_metadata_by_id.write() = metadata_by_id;
        *cluster_metadata = new_cluster_metadata;
        *private_oram_activation_authority = new_private_oram_activation_authority;
        *private_oram_epochs = new_private_oram_epochs;
        *private_oram_session_leases = new_private_oram_session_leases;
        *private_oram_layouts = new_private_oram_layouts;
        *private_oram_external_recoveries = new_private_oram_external_recoveries;
        *private_oram_mutation_states = new_private_oram_mutation_states;
        *private_oram_mutation_lease_slots = new_private_oram_mutation_lease_slots;
        *private_oram_mutation_format_floor = new_private_oram_mutation_format_floor;
        *private_oram_mutation_activation_pending = new_private_oram_mutation_activation_pending;

        // Last Raft commit and last snapshot index must be equal and persisted in one operation
        // Our `ConsensusManager::new` function relies on this for reconciling WAL clears
        debug_assert_eq!(
            state.hard_state.commit, latest_snapshot_meta.index,
            "applied Raft commit and last snapshot index must be equal",
        );

        self.save_or_rollback_on_definitive(move |persistent| {
            persistent.state = previous_state;
            persistent.latest_snapshot_meta = previous_latest_snapshot_meta;
            persistent.apply_progress_queue = previous_apply_progress_queue;
            *persistent.peer_address_by_id.write() = previous_peer_address_by_id;
            *persistent.peer_metadata_by_id.write() = previous_peer_metadata_by_id;
            persistent.cluster_metadata = previous_cluster_metadata;
            persistent.private_oram_epochs = previous_private_oram_epochs;
            persistent.private_oram_session_leases = previous_private_oram_session_leases;
            persistent.private_oram_layouts = previous_private_oram_layouts;
            persistent.private_oram_external_recoveries = previous_private_oram_external_recoveries;
            persistent.private_oram_mutation_states = previous_private_oram_mutation_states;
            persistent.private_oram_mutation_lease_slots =
                previous_private_oram_mutation_lease_slots;
            persistent.private_oram_mutation_format_floor =
                previous_private_oram_mutation_format_floor;
            persistent.private_oram_mutation_activation_pending =
                previous_private_oram_mutation_activation_pending;
            persistent.private_oram_activation_authority =
                previous_private_oram_activation_authority;
        })
    }

    /// Returns state and if it was initialized for the first time
    ///
    /// `peer_id` is used only when raft state is not found.
    pub fn load_or_init(
        storage_path: impl AsRef<Path>,
        first_peer: bool,
        reinit: bool,
        peer_id: Option<PeerId>,
    ) -> Result<Self, StorageError> {
        Self::load_or_init_inner(storage_path, first_peer, reinit, peer_id, None)
    }

    /// Loads Raft state under an external activation trust anchor and installs exactly one signed
    /// genesis registry when the durable authority is still empty.
    ///
    /// A configured bundle is an immutable startup expectation. A consecutive externally signed
    /// successor may be installed only while no two-phase activation barrier is pending; this is
    /// the operator-controlled capability upgrade path used before gathering a new cluster proof.
    pub fn load_or_init_with_private_oram_mutation_v2_activation(
        storage_path: impl AsRef<Path>,
        first_peer: bool,
        reinit: bool,
        peer_id: Option<PeerId>,
        trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
        authority_bundle: &PrivateOramActivationAuthorityBundleV1,
    ) -> Result<Self, StorageError> {
        let mut state = Self::load_or_init_inner(
            storage_path,
            first_peer,
            reinit,
            peer_id,
            Some(trust_anchor),
        )?;
        let current = state.private_oram_activation_authority_at_read(trust_anchor)?;
        if current.is_empty() {
            state.compare_and_swap_private_oram_activation_authority(
                current,
                authority_bundle,
                trust_anchor,
            )?;
        } else if state
            .private_oram_activation_authority
            .as_ref()
            .is_none_or(|authority| authority.bundle() != authority_bundle)
        {
            if state.private_oram_mutation_activation_pending.is_some()
                || state.current_unapplied_entry().is_some()
            {
                return Err(StorageError::PreconditionFailed {
                    description: "private ORAM activation authority cannot rotate while an activation barrier is pending"
                        .to_string(),
                });
            }
            state.compare_and_swap_private_oram_activation_authority(
                current,
                authority_bundle,
                trust_anchor,
            )?;
        }
        Ok(state)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn load_or_init_with_private_oram_activation_authority_trust_anchor(
        storage_path: impl AsRef<Path>,
        first_peer: bool,
        reinit: bool,
        peer_id: Option<PeerId>,
        trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    ) -> Result<Self, StorageError> {
        Self::load_or_init_inner(
            storage_path,
            first_peer,
            reinit,
            peer_id,
            Some(trust_anchor),
        )
    }

    fn load_or_init_inner(
        storage_path: impl AsRef<Path>,
        first_peer: bool,
        reinit: bool,
        peer_id: Option<PeerId>,
        trust_anchor: Option<&PrivateOramActivationAuthorityTrustAnchorV1>,
    ) -> Result<Self, StorageError> {
        fs::create_dir_all(storage_path.as_ref())?;
        let path_legacy = storage_path.as_ref().join(STATE_FILE_NAME_CBOR);
        let path_json = storage_path.as_ref().join(STATE_FILE_NAME);
        let (mut state, migrate_legacy) = if path_json.exists() {
            log::info!("Loading raft state from {}", path_json.display());
            (Self::load_json(path_json.clone())?, false)
        } else if path_legacy.exists() {
            log::info!("Loading raft state from {}", path_legacy.display());
            (Self::load(path_legacy)?, true)
        } else {
            log::info!("Initializing new raft state at {}", path_json.display());
            if let Some(peer_id) = peer_id {
                log::debug!("Using peer ID: {peer_id}");
            };
            (Self::init(path_json.clone(), first_peer, peer_id)?, false)
        };

        let has_private_oram_mutation_local_floor =
            state.recover_and_validate_private_oram_mutation_local_floor()?;
        if state
            .private_oram_mutation_format_floor
            .as_ref()
            .is_some_and(|floor| {
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION < floor.minimum_reader_protocol()
                    || PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
                        < floor.minimum_writer_protocol()
            })
        {
            return Err(StorageError::service_error(
                "binary consensus protocol is older than the private ORAM mutation format floor",
            ));
        }
        if migrate_legacy && has_private_oram_mutation_local_floor {
            return Err(StorageError::service_error(
                "legacy Raft-state migration cannot move a snapshot-independent private ORAM mutation floor",
            ));
        }

        if reinit
            && (state.private_oram_activation_authority.is_some()
                || state.private_oram_mutation_format_floor.is_some())
        {
            return Err(StorageError::service_error(
                "Raft reinitialization cannot discard private ORAM activation or mutation format authority; use a new storage namespace",
            ));
        }
        match trust_anchor {
            Some(trust_anchor) => {
                state.configure_private_oram_activation_authority_trust_anchor(trust_anchor)?;
            }
            None => validate_persisted_private_oram_activation_authority(
                state.private_oram_activation_authority.as_ref(),
                None,
            )?,
        }
        if migrate_legacy {
            state.path = path_json.clone();
            state.save()?;
        }

        let state = if reinit {
            if first_peer {
                // Re-initialize consensus of the first peer is different from the rest
                // Effectively, we should remove all other peers from voters and learners
                // assuming that other peers would need to join consensus again.
                // PeerId if the current peer should stay in the list of voters,
                // so we can accept consensus operations.
                state.state.conf_state.voters = vec![state.this_peer_id];
                state.state.conf_state.learners = vec![];
                state.state.hard_state.vote = state.this_peer_id;
                state.save()?;
                state
            } else {
                // We want to re-initialize consensus while preserve the peer ID
                // which is needed for migration from one cluster to another
                let keep_peer_id = state.this_peer_id;
                Self::init(path_json, first_peer, Some(keep_peer_id))?
            }
        } else {
            state
        };

        if let Some(trust_anchor) = trust_anchor {
            state.configure_private_oram_activation_authority_trust_anchor(trust_anchor)?;
        }

        state.remove_unknown_peer_metadata()?;

        log::debug!("State: {state:?}");
        Ok(state)
    }

    pub(crate) fn configure_private_oram_activation_authority_trust_anchor(
        &self,
        trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    ) -> Result<(), StorageError> {
        if let Some(pinned) = self.private_oram_activation_authority_trust_anchor.get() {
            if pinned != trust_anchor {
                return Err(StorageError::PreconditionFailed {
                    description: "private ORAM activation authority trust anchor changed"
                        .to_string(),
                });
            }
            return validate_persisted_private_oram_activation_authority(
                self.private_oram_activation_authority.as_ref(),
                Some(pinned),
            );
        }
        validate_persisted_private_oram_activation_authority(
            self.private_oram_activation_authority.as_ref(),
            Some(trust_anchor),
        )?;
        if self
            .private_oram_activation_authority_trust_anchor
            .set(trust_anchor.clone())
            .is_err()
            && self.private_oram_activation_authority_trust_anchor.get() != Some(trust_anchor)
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM activation authority trust anchor changed".to_string(),
            });
        }
        Ok(())
    }

    fn private_oram_activation_authority_trust_anchor(
        &self,
    ) -> Result<&PrivateOramActivationAuthorityTrustAnchorV1, StorageError> {
        self.private_oram_activation_authority_trust_anchor
            .get()
            .ok_or_else(|| {
                StorageError::service_error(
                    "private ORAM activation authority requires an external trust anchor",
                )
            })
    }

    pub(crate) fn ensure_persistence_writable(&self) -> Result<(), StorageError> {
        if self.save_indeterminate.load(Ordering::Acquire) {
            return Err(StorageError::service_error(
                PERSISTENT_SAVE_INDETERMINATE_MESSAGE,
            ));
        }
        Ok(())
    }

    fn ensure_private_oram_activation_authority_durability_known(
        &self,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()
    }

    pub(crate) fn fence_after_snapshot_side_effect_failure(&self) {
        self.dirty.store(true, Ordering::Release);
        self.save_indeterminate.store(true, Ordering::Release);
        log::error!(
            "Raft snapshot side effects are indeterminate; stopping consensus until restart"
        );
    }

    pub(crate) fn validate_private_oram_activation_authority_for_snapshot(
        &self,
        incoming: Option<&PrivateOramActivationAuthorityStateV1>,
    ) -> Result<(), StorageError> {
        if self.private_oram_activation_authority.is_none() && incoming.is_none() {
            return Ok(());
        }
        self.ensure_private_oram_activation_authority_durability_known()?;
        validate_private_oram_activation_authority_snapshot_transition_v1(
            self.private_oram_activation_authority.as_ref(),
            incoming,
            self.private_oram_activation_authority_trust_anchor()?,
        )
        .map_err(|_| {
            StorageError::bad_request(
                "private ORAM activation authority snapshot transition is invalid",
            )
        })
    }

    pub(crate) fn validate_private_oram_activation_authority_snapshot_source(
        &self,
    ) -> Result<(), StorageError> {
        if self.private_oram_activation_authority.is_none() {
            return Ok(());
        }
        self.ensure_private_oram_activation_authority_durability_known()?;
        validate_persisted_private_oram_activation_authority(
            self.private_oram_activation_authority.as_ref(),
            Some(self.private_oram_activation_authority_trust_anchor()?),
        )
    }

    fn remove_unknown_peer_metadata(&self) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        let is_updated = {
            let mut peer_metadata = self.peer_metadata_by_id.write();
            let peer_address = self.peer_address_by_id.read();
            peer_metadata
                .extract_if(|peer_id, _| !peer_address.contains_key(peer_id))
                .count()
                > 0
        };

        if is_updated {
            self.save()?;
        }

        Ok(())
    }

    pub fn unapplied_entities_count(&self) -> usize {
        self.apply_progress_queue.len()
    }

    pub fn apply_state_update(
        &mut self,
        update: impl FnOnce(&mut RaftState),
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        let mut state = self.state.clone();
        update(&mut state);
        self.state = state;
        self.save()
    }

    pub fn current_unapplied_entry(&self) -> Option<EntryId> {
        self.apply_progress_queue.current()
    }

    pub fn entry_applied(&mut self) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        self.apply_progress_queue.applied();
        self.save()
    }

    pub fn set_unapplied_entries(
        &mut self,
        first_index: EntryId,
        last_index: EntryId,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        self.apply_progress_queue = EntryApplyProgressQueue::new(first_index, last_index);
        self.save()
    }

    pub fn set_peer_address_by_id(
        &mut self,
        peer_address_by_id: PeerAddressById,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        *self.peer_address_by_id.write() = peer_address_by_id;
        self.save()
    }

    pub fn insert_peer(&mut self, peer_id: PeerId, address: Uri) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        let address_display = address.to_string();
        match self
            .peer_address_by_id
            .write()
            .insert(peer_id, address.clone())
        {
            Some(prev_address) if prev_address != address => log::warn!(
                "Replaced address of peer {peer_id} from {prev_address} to {address_display}"
            ),
            Some(_) => log::debug!(
                "Re-added peer with id {peer_id} with the same address {address_display}"
            ),
            None => log::debug!("Added peer with id {peer_id} and address {address_display}"),
        }
        self.save()
    }

    pub fn update_peer_metadata(
        &mut self,
        peer_id: PeerId,
        metadata: PeerMetadata,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        if let Some(prev_metadata) = self
            .peer_metadata_by_id
            .write()
            .insert(peer_id, metadata.clone())
        {
            log::info!(
                "Replaced metadata of peer {peer_id} from {prev_metadata:?} to {metadata:?}"
            );
        } else {
            log::debug!("Added metadata for peer with id {peer_id}: {metadata:?}")
        }
        self.save()
    }

    pub fn get_cluster_metadata_keys(&self) -> Vec<String> {
        self.cluster_metadata.keys().cloned().collect()
    }

    pub fn get_cluster_metadata_key(&self, key: &str) -> serde_json::Value {
        self.cluster_metadata
            .get(key)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    }

    pub fn update_cluster_metadata_key(
        &mut self,
        key: String,
        value: serde_json::Value,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        if !value.is_null() {
            self.cluster_metadata.insert(key, value);
        } else {
            self.cluster_metadata.remove(&key);
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn private_oram_activation_authority_at_read(
        &self,
        trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    ) -> Result<PrivateOramActivationAuthorityCurrentAtReadV1, StorageError> {
        self.ensure_private_oram_activation_authority_durability_known()?;
        self.configure_private_oram_activation_authority_trust_anchor(trust_anchor)?;
        verify_private_oram_activation_authority_current_at_read_v1(
            self.private_oram_activation_authority.as_ref(),
            trust_anchor,
            self.private_oram_activation_authority_store_instance,
        )
        .map_err(|_| {
            StorageError::service_error(
                "persisted private ORAM activation authority failed verification",
            )
        })
    }

    pub(crate) fn private_oram_activation_authority_at_configured_read(
        &self,
    ) -> Result<PrivateOramActivationAuthorityCurrentAtReadV1, StorageError> {
        let trust_anchor = self
            .private_oram_activation_authority_trust_anchor()?
            .clone();
        self.private_oram_activation_authority_at_read(&trust_anchor)
    }

    /// Dormant local CAS primitive. No consensus operation invokes it until mixed-version safety is
    /// established, so successful return must not be treated as cluster-wide activation.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn compare_and_swap_private_oram_activation_authority(
        &mut self,
        expected: PrivateOramActivationAuthorityCurrentAtReadV1,
        new_bundle: &PrivateOramActivationAuthorityBundleV1,
        trust_anchor: &PrivateOramActivationAuthorityTrustAnchorV1,
    ) -> Result<(), StorageError> {
        self.ensure_private_oram_activation_authority_durability_known()?;
        self.configure_private_oram_activation_authority_trust_anchor(trust_anchor)?;
        let new_state = plan_private_oram_activation_authority_cas_v1(
            self.private_oram_activation_authority.as_ref(),
            expected,
            new_bundle,
            trust_anchor,
            self.private_oram_activation_authority_store_instance,
        )
        .map_err(|error| match error {
            PrivateOramActivationAuthorityStateError::PreconditionFailed => {
                StorageError::PreconditionFailed {
                    description: "private ORAM activation authority CAS precondition failed"
                        .to_string(),
                }
            }
            PrivateOramActivationAuthorityStateError::InvalidCandidate => {
                StorageError::bad_request("private ORAM activation authority candidate is invalid")
            }
            _ => StorageError::service_error(
                "persisted private ORAM activation authority failed verification",
            ),
        })?;
        let previous = self.private_oram_activation_authority.replace(new_state);
        self.save_or_rollback_on_definitive(move |persistent| {
            persistent.private_oram_activation_authority = previous;
        })
    }

    pub fn private_oram_epoch(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramConsensusEpoch> {
        self.private_oram_epochs
            .get(&private_oram_epoch_key_digest(key))
            .cloned()
    }

    pub fn compare_and_swap_private_oram_epoch(
        &mut self,
        operation: &CompareAndSwapPrivateOramEpoch,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        validate_private_oram_epoch_cas(operation)?;
        let key = private_oram_epoch_key_digest(&operation.key);
        let current = self.private_oram_epochs.get(&key);
        if current == Some(&operation.new) {
            return Ok(());
        }
        if self.private_oram_external_recovery_is_active(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "private ORAM epoch/root CAS conflicts with active external recovery",
            ));
        }
        if self.private_oram_mutation_is_active(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "private ORAM epoch/root CAS conflicts with active mutation",
            ));
        }
        if self.private_oram_mutation_is_enrolled(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "standalone private ORAM epoch/root CAS conflicts with enrolled v2 mutation state",
            ));
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM consensus epoch/root CAS precondition failed",
            ));
        }
        if operation.expected.is_none()
            && self.private_oram_epochs.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus epoch capacity exceeded",
            ));
        }

        let previous = self
            .private_oram_epochs
            .insert(key.clone(), operation.new.clone());
        self.save_or_rollback_on_definitive(move |persistent| match previous {
            Some(previous) => {
                persistent.private_oram_epochs.insert(key, previous);
            }
            None => {
                persistent.private_oram_epochs.remove(&key);
            }
        })
    }

    pub fn private_oram_session_lease(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramSessionLease> {
        self.private_oram_session_leases
            .get(&private_oram_epoch_key_digest(key))
            .cloned()
    }

    pub fn compare_and_swap_private_oram_session_lease(
        &mut self,
        operation: &CompareAndSwapPrivateOramSessionLease,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        validate_private_oram_session_lease_cas(operation)?;
        let key = private_oram_epoch_key_digest(&operation.key);
        let current = self.private_oram_session_leases.get(&key);
        if current == operation.new.as_ref() {
            return Ok(());
        }
        if operation.new.is_some()
            && self.private_oram_external_recovery_is_active(&operation.key.collection_id)
        {
            return Err(StorageError::bad_request(
                "private ORAM session lease conflicts with active external recovery",
            ));
        }
        if operation.new.is_some()
            && self.private_oram_mutation_is_active(&operation.key.collection_id)
        {
            return Err(StorageError::bad_request(
                "private ORAM session lease conflicts with active mutation",
            ));
        }
        if operation.new.is_some()
            && self.private_oram_mutation_is_enrolled(&operation.key.collection_id)
        {
            return Err(StorageError::bad_request(
                "private ORAM session lease conflicts with enrolled v2 mutation state",
            ));
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM consensus session lease CAS precondition failed",
            ));
        }
        if current.is_none()
            && operation.new.is_some()
            && self.private_oram_session_leases.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus session lease capacity exceeded",
            ));
        }

        let previous = match &operation.new {
            Some(new) => self
                .private_oram_session_leases
                .insert(key.clone(), new.clone()),
            None => self.private_oram_session_leases.remove(&key),
        };
        self.save_or_rollback_on_definitive(move |persistent| match previous {
            Some(previous) => {
                persistent.private_oram_session_leases.insert(key, previous);
            }
            None => {
                persistent.private_oram_session_leases.remove(&key);
            }
        })
    }

    pub fn private_oram_mutation_state(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramConsensusCollectionStateV2> {
        self.private_oram_mutation_states
            .get(&private_oram_mutation_key_digest(key))
            .cloned()
    }

    pub(crate) fn private_oram_activation_authority_locator(
        &self,
    ) -> Option<PrivateOramActivationAuthorityLocatorV1> {
        self.private_oram_activation_authority
            .as_ref()
            .map(PrivateOramActivationAuthorityStateV1::locator)
    }

    pub fn private_oram_mutation_lease_slot(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationLeaseSlotV2> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .map(DecodedPrivateOramMutationAuthorityWireV2::lease_slot)
            .cloned()
    }

    pub(crate) fn private_oram_mutation_recovery_capsules_certificate(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationRecoveryCapsulesCertificateV2> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .and_then(|aggregate| aggregate.recovery_capsules_certificate())
            .cloned()
    }

    pub(crate) fn private_oram_mutation_parent_watermark(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationParentWatermarkV2> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .and_then(PrivateOramMutationConsensusAggregateV2::parent_watermark)
            .cloned()
    }

    pub(crate) fn private_oram_mutation_cleanup_lifecycle(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationCleanupLifecycleV2> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .map(|aggregate| aggregate.lifecycle().clone())
    }

    pub fn private_oram_mutation_lease(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationLease> {
        self.private_oram_mutation_lease_slot(key)
            .and_then(|slot| slot.active)
    }

    pub(crate) fn private_oram_mutation_v2_aggregate_digest(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<String, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .map(|aggregate| aggregate.aggregate_digest().to_string())
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })
    }

    pub(crate) fn private_oram_mutation_v2_append_authority_context(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<PrivateOramMutationAppendAuthorityContextV2, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })?
            .append_authority_context()
            .map_err(private_oram_mutation_authority_corrupt)
    }

    fn private_oram_mutation_v3_write_floor_active(&self) -> bool {
        self.private_oram_mutation_format_floor
            .as_ref()
            .is_some_and(|floor| {
                floor.activation_enabled()
                    && floor.minimum_reader_protocol()
                        >= PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
                    && floor.minimum_writer_protocol()
                        >= PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
            })
            && self.private_oram_mutation_activation_pending.is_none()
    }

    pub(crate) fn private_oram_mutation_v3_floor_upgrade_quiescent(
        &self,
    ) -> Result<bool, StorageError> {
        self.private_oram_mutation_lease_slots
            .values()
            .try_fold(true, |quiescent, authority| {
                let tagged = authority.tagged_authority().ok_or_else(|| {
                    StorageError::service_error(
                        "private ORAM mutation V3 floor upgrade authority is inconsistent",
                    )
                })?;
                Ok(quiescent
                    && tagged.aggregate().is_none_or(
                        PrivateOramMutationConsensusAggregateV2::is_reservation_v3_floor_quiescent,
                    ))
            })
    }

    pub(crate) fn private_oram_mutation_v2_pending_reservation_challenge(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationPendingReservationChallengeV1>, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .map(|aggregate| aggregate.pending_reservation_challenge().cloned())
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })
    }

    pub(crate) fn private_oram_mutation_v3_reservation_challenge_outcome(
        &self,
        key: &PrivateOramMutationKey,
        challenge_digest: &str,
        challenge_applied_term: u64,
        challenge_applied_index: u64,
        reservation_intent_digest: &str,
        attempt_id: &str,
    ) -> Result<Option<PrivateOramMutationReservationChallengeOutcomeV1>, StorageError> {
        let aggregate = self
            .private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })?;
        let mut matching = aggregate
            .reservation_challenge_outcomes()
            .iter()
            .filter(|outcome| {
                outcome.challenge_digest() == challenge_digest
                    && outcome.challenge_applied().term() == challenge_applied_term
                    && outcome.challenge_applied().index() == challenge_applied_index
                    && outcome.reservation_intent_digest() == reservation_intent_digest
                    && outcome.attempt_id() == attempt_id
            });
        let outcome = matching.next().cloned();
        if matching.next().is_some() {
            return Err(private_oram_mutation_authority_corrupt(
                PrivateOramMutationJournalError::Corrupt,
            ));
        }
        Ok(outcome)
    }

    pub(crate) fn private_oram_mutation_v3_latest_reservation_challenge_outcome(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationReservationChallengeOutcomeV1>, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .map(|aggregate| aggregate.reservation_challenge_outcomes().last().cloned())
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })
    }

    pub(crate) fn private_oram_mutation_v3_oldest_reservation_challenge_outcome(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationReservationChallengeOutcomeV1>, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .map(|aggregate| aggregate.reservation_challenge_outcomes().first().cloned())
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })
    }

    pub(crate) fn private_oram_mutation_v3_prestage_aborted_outcome_digest(
        &self,
        key: &PrivateOramMutationKey,
        attempt_id: &str,
    ) -> Result<Option<String>, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })?
            .prestage_aborted_outcome_digest(attempt_id)
            .map(|digest| digest.map(str::to_string))
            .map_err(private_oram_mutation_authority_corrupt)
    }

    pub(crate) fn private_oram_mutation_v2_owner_checkpoint_table(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<PrivateOramOwnerCheckpointTableV1, StorageError> {
        self.private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .map(|aggregate| aggregate.owner_checkpoint_table().clone())
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })
    }

    pub(crate) fn private_oram_mutation_v2_active_recovery_manifest(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationAllOwnersPrestagedV2>, StorageError> {
        let aggregate = self
            .private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })?;
        aggregate
            .active_admission_recovery_manifest()
            .map_err(private_oram_mutation_authority_corrupt)
    }

    pub(crate) fn private_oram_mutation_v2_exact_admitted_recovery_manifest(
        &self,
        key: &PrivateOramMutationKey,
        lease: &PrivateOramMutationLease,
    ) -> Result<Option<PrivateOramMutationAllOwnersPrestagedV2>, StorageError> {
        if self.private_oram_mutation_lease(key).as_ref() != Some(lease) {
            return Ok(None);
        }
        let Some(manifest) = self.private_oram_mutation_v2_active_recovery_manifest(key)? else {
            return Err(StorageError::service_error(
                "private ORAM admitted mutation recovery manifest is unavailable",
            ));
        };
        manifest
            .validate_admission_lease(lease)
            .map_err(private_oram_mutation_authority_corrupt)?;
        Ok(Some(manifest))
    }

    pub(crate) fn private_oram_mutation_v2_active_append_attempt(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<
        Option<(
            PrivateOramMutationAppendReservationV2,
            Option<PrivateOramMutationAllOwnersPrestagedV2>,
        )>,
        StorageError,
    > {
        let aggregate = self
            .private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })?;
        aggregate
            .active_append_attempt()
            .map(|active| {
                let reservation = decode_private_oram_mutation_append_reservation_wire(
                    active.reservation_canonical_json(),
                )?;
                let prepared = active
                    .prepared_manifest_canonical_json()
                    .map(decode_private_oram_mutation_admission_recovery_manifest_v2)
                    .transpose()?;
                Ok((reservation.base_reservation().clone(), prepared))
            })
            .transpose()
            .map_err(private_oram_mutation_authority_corrupt)
    }

    pub(crate) fn private_oram_mutation_v2_retains_rejected_admission(
        &self,
        key: &PrivateOramMutationKey,
        lease: &PrivateOramMutationLease,
        recovery_manifest_digest: &str,
    ) -> Result<bool, StorageError> {
        let aggregate = self
            .private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM V2 mutation authority is not active for collection",
                )
            })?;
        aggregate
            .retains_rejected_admission(lease, recovery_manifest_digest)
            .map_err(private_oram_mutation_authority_corrupt)
    }

    pub fn has_active_private_oram_mutation(&self) -> bool {
        self.private_oram_mutation_lease_slots
            .values()
            .any(|wire| wire.lease_slot().active.is_some())
    }

    pub(crate) fn active_private_oram_mutation_keys(
        &self,
    ) -> Result<Vec<PrivateOramMutationKey>, StorageError> {
        let mut keys = Vec::new();
        for state in self.private_oram_mutation_states.values() {
            let key = PrivateOramMutationKey {
                collection_id: state.collection_id.clone(),
            };
            let key_digest = private_oram_mutation_key_digest(&key);
            let slot = self
                .private_oram_mutation_lease_slots
                .get(&key_digest)
                .ok_or_else(|| {
                    StorageError::service_error(
                        "private ORAM mutation authority state is inconsistent",
                    )
                })?;
            if slot.lease_slot().active.is_some() {
                keys.push(key);
            }
        }
        keys.sort_unstable_by(|left, right| left.collection_id.cmp(&right.collection_id));
        if keys
            .windows(2)
            .any(|pair| pair[0].collection_id >= pair[1].collection_id)
        {
            return Err(StorageError::service_error(
                "private ORAM mutation authority state is inconsistent",
            ));
        }
        Ok(keys)
    }

    pub(crate) fn private_oram_mutation_pending_acknowledgement_keys(
        &self,
    ) -> Result<Vec<(PrivateOramMutationKey, PeerId, u64)>, StorageError> {
        let mut keys = Vec::new();
        for state in self.private_oram_mutation_states.values() {
            let key = PrivateOramMutationKey {
                collection_id: state.collection_id.clone(),
            };
            let aggregate = self
                .private_oram_mutation_lease_slots
                .get(&private_oram_mutation_key_digest(&key))
                .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
                .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
                .ok_or_else(|| {
                    StorageError::service_error(
                        "private ORAM mutation authority state is inconsistent",
                    )
                })?;
            if let Some((owner_peer_id, generation)) = aggregate
                .lifecycle()
                .pending_acknowledgement_owner()
                .map_err(private_oram_mutation_authority_corrupt)?
            {
                keys.push((key, owner_peer_id, generation));
            }
        }
        keys.sort_unstable_by(|left, right| left.0.collection_id.cmp(&right.0.collection_id));
        if keys
            .windows(2)
            .any(|pair| pair[0].0.collection_id >= pair[1].0.collection_id)
        {
            return Err(StorageError::service_error(
                "private ORAM mutation authority state is inconsistent",
            ));
        }
        Ok(keys)
    }

    pub(crate) fn private_oram_mutation_cleared_pending_archive_permit(
        &self,
        key: &PrivateOramMutationKey,
        expected_owner_peer_id: PeerId,
        expected_generation: u64,
    ) -> Result<PrivateOramMutationClearedPendingArchivePermitV2, StorageError> {
        let aggregate = self
            .private_oram_mutation_lease_slots
            .get(&private_oram_mutation_key_digest(key))
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .and_then(PrivateOramMutationAuthorityStateV2::aggregate)
            .ok_or_else(|| {
                StorageError::service_error("private ORAM mutation authority state is inconsistent")
            })?;
        aggregate
            .lifecycle()
            .cleared_pending_archive_permit(
                key.collection_id.clone(),
                expected_owner_peer_id,
                expected_generation,
            )
            .map_err(private_oram_mutation_authority_corrupt)
    }

    fn private_oram_mutation_is_active(&self, collection_id: &str) -> bool {
        self.private_oram_mutation_lease(&PrivateOramMutationKey {
            collection_id: collection_id.to_string(),
        })
        .is_some()
    }

    fn private_oram_mutation_is_enrolled(&self, collection_id: &str) -> bool {
        self.private_oram_mutation_state(&PrivateOramMutationKey {
            collection_id: collection_id.to_string(),
        })
        .is_some()
    }

    #[cfg(test)]
    pub fn initialize_private_oram_mutation_state(
        &mut self,
        operation: &InitializePrivateOramMutationState,
    ) -> Result<(), StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            None,
            PrivateOramMutationCommand::Initialize(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
        .map(|_| ())
    }

    pub(crate) fn initialize_private_oram_mutation_state_at_applied_entry(
        &mut self,
        operation: &InitializePrivateOramMutationState,
        entry_index: EntryId,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            Some(entry_index),
            PrivateOramMutationCommand::Initialize(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
    }

    #[cfg(test)]
    pub fn compare_and_swap_private_oram_mutation_lease(
        &mut self,
        operation: &CompareAndSwapPrivateOramMutationLease,
    ) -> Result<(), StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            None,
            PrivateOramMutationCommand::CompareAndSwapLease(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
        .map(|_| ())
    }

    pub(crate) fn compare_and_swap_private_oram_mutation_lease_at_applied_entry(
        &mut self,
        operation: &CompareAndSwapPrivateOramMutationLease,
        entry_index: EntryId,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            Some(entry_index),
            PrivateOramMutationCommand::CompareAndSwapLease(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
    }

    pub(crate) fn confirm_private_oram_mutation_authority_v2_at_applied_entry(
        &mut self,
        operation: &ConfirmPrivateOramMutationAuthorityV2,
        entry_index: EntryId,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            Some(entry_index),
            PrivateOramMutationCommand::ConfirmAuthority(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
    }

    #[cfg(test)]
    pub fn apply_private_oram_mutation(
        &mut self,
        operation: &ApplyPrivateOramMutation,
    ) -> Result<(), StorageError> {
        self.apply_private_oram_mutation_with_backend(operation, &FilesystemPersistentSaveBackend)
    }

    pub(crate) fn apply_private_oram_mutation_at_applied_entry(
        &mut self,
        operation: &ApplyPrivateOramMutation,
        entry_index: EntryId,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        self.apply_private_oram_mutation_at_applied_entry_with_backend(
            operation,
            entry_index,
            &FilesystemPersistentSaveBackend,
        )
    }

    pub(crate) fn activate_private_oram_mutation_v2_at_applied_entry(
        &mut self,
        operation: &PrivateOramMutationActivationBarrierV2,
        entry_term: u64,
        entry_index: EntryId,
        barrier_base_entry_term: u64,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        let prior_applied_index = self
            .apply_progress_queue
            .get_last_applied()
            .unwrap_or(self.latest_snapshot_meta.index);
        let patch = self.prepare_private_oram_mutation_complete_patch(
            Some(entry_index),
            PrivateOramMutationCommand::ActivateV2(
                operation,
                PrivateOramMutationActivationApplyFactsV2 {
                    entry_term,
                    entry_index,
                    prior_applied_index,
                    barrier_base_entry_term,
                },
            ),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
    }

    pub(crate) fn apply_private_oram_mutation_material_v2_at_applied_entry(
        &mut self,
        operation: &ApplyPrivateOramMutationMaterialV2,
        entry_term: u64,
        entry_index: EntryId,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            Some(entry_index),
            PrivateOramMutationCommand::ApplyMaterialV2 {
                operation,
                entry_term,
                entry_index,
            },
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(
            patch,
            &FilesystemPersistentSaveBackend,
        )
    }

    fn apply_private_oram_mutation_at_applied_entry_with_backend(
        &mut self,
        operation: &ApplyPrivateOramMutation,
        entry_index: EntryId,
        backend: &impl PersistentSaveBackend,
    ) -> Result<PrivateOramMutationAtEntryOutcome, StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            Some(entry_index),
            PrivateOramMutationCommand::Apply(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(patch, backend)
    }

    #[cfg(test)]
    fn apply_private_oram_mutation_with_backend(
        &mut self,
        operation: &ApplyPrivateOramMutation,
        backend: &impl PersistentSaveBackend,
    ) -> Result<(), StorageError> {
        let patch = self.prepare_private_oram_mutation_complete_patch(
            None,
            PrivateOramMutationCommand::Apply(operation),
        )?;
        self.commit_private_oram_mutation_complete_patch_with_backend(patch, backend)
            .map(|_| ())
    }

    pub fn private_oram_external_recovery(
        &self,
        key: &PrivateOramExternalRecoveryKey,
    ) -> Option<PrivateOramExternalRecoveryState> {
        self.private_oram_external_recoveries
            .get(&private_oram_external_recovery_key_digest(key))
            .cloned()
    }

    pub fn has_active_private_oram_external_recovery(&self) -> bool {
        self.private_oram_external_recoveries
            .values()
            .any(|state| state.active_lease.is_some())
    }

    fn private_oram_external_recovery_is_active(&self, collection_id: &str) -> bool {
        self.private_oram_external_recovery(&PrivateOramExternalRecoveryKey {
            collection_id: collection_id.to_string(),
        })
        .and_then(|state| state.active_lease)
        .is_some()
    }

    fn compare_and_swap_private_oram_external_recovery(
        &mut self,
        operation: &CompareAndSwapPrivateOramExternalRecovery,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        validate_private_oram_external_recovery_cas(operation)?;
        if self.private_oram_mutation_is_active(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "private ORAM external recovery conflicts with active mutation",
            ));
        }
        let key = private_oram_external_recovery_key_digest(&operation.key);
        let current = self.private_oram_external_recoveries.get(&key);
        if current == operation.new.as_ref() {
            return Ok(());
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM external recovery CAS precondition failed",
            ));
        }
        if current.is_none()
            && operation.new.is_some()
            && self.private_oram_external_recoveries.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM external recovery capacity exceeded",
            ));
        }

        let previous = match &operation.new {
            Some(new) => self
                .private_oram_external_recoveries
                .insert(key.clone(), new.clone()),
            None => self.private_oram_external_recoveries.remove(&key),
        };
        self.save_or_rollback_on_definitive(move |persistent| match previous {
            Some(previous) => {
                persistent
                    .private_oram_external_recoveries
                    .insert(key, previous);
            }
            None => {
                persistent.private_oram_external_recoveries.remove(&key);
            }
        })
    }

    pub fn apply_private_oram_external_recovery(
        &mut self,
        operation: &PrivateOramExternalRecoveryOperation,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        self.validate_private_oram_external_recovery_operation(operation)?;
        self.compare_and_swap_private_oram_external_recovery(&operation.recovery)
    }

    fn validate_private_oram_external_recovery_operation(
        &self,
        operation: &PrivateOramExternalRecoveryOperation,
    ) -> Result<(), StorageError> {
        validate_private_oram_external_recovery_cas(&operation.recovery)
            .map_err(|_| invalid_private_oram_external_recovery_operation())?;
        validate_private_oram_consensus_layout(&operation.layout)
            .map_err(|_| invalid_private_oram_external_recovery_operation())?;
        if operation.index_states.is_empty()
            || operation.index_states.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(invalid_private_oram_external_recovery_operation());
        }

        let collection_id = &operation.recovery.key.collection_id;
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.clone(),
        };
        if self.private_oram_layout(&layout_key).as_ref() != Some(&operation.layout) {
            return Err(invalid_private_oram_external_recovery_operation());
        }

        let mut states = Vec::with_capacity(operation.index_states.len());
        let mut previous_key = None;
        for binding in &operation.index_states {
            let key_order = private_oram_epoch_key_order(&binding.key);
            if &binding.key.collection_id != collection_id
                || self.private_oram_epoch(&binding.key).as_ref() != Some(&binding.state)
                || previous_key
                    .as_ref()
                    .is_some_and(|previous| previous >= &key_order)
            {
                return Err(invalid_private_oram_external_recovery_operation());
            }
            if self.private_oram_session_lease(&binding.key).is_some() {
                return Err(StorageError::bad_request(
                    "private ORAM external recovery conflicts with active session lease",
                ));
            }
            previous_key = Some(key_order);
            states.push((binding.key.clone(), binding.state.clone()));
        }
        let index_state_digest = canonical_private_oram_index_state_digest(collection_id, &states)
            .map_err(|_| invalid_private_oram_external_recovery_operation())?;
        if operation.layout.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_external_recovery_operation());
        }

        let expected = operation.recovery.expected.as_ref();
        let new = operation.recovery.new.as_ref();
        let expected_lease = expected.and_then(|state| state.active_lease.as_ref());
        let new_lease = new.and_then(|state| state.active_lease.as_ref());
        let same_recovery = expected_lease
            .zip(new_lease)
            .is_some_and(|(expected, new)| {
                expected.owner_peer_id == new.owner_peer_id
                    && expected.operation_id_hash == new.operation_id_hash
                    && expected.checkpoint_digest == new.checkpoint_digest
                    && expected.backup_generation == new.backup_generation
            });
        let phase_is_valid = match operation.phase {
            PrivateOramExternalRecoveryPhase::Begin => {
                new_lease.is_some_and(|lease| {
                    lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                }) && (expected_lease.is_none() || !same_recovery)
            }
            PrivateOramExternalRecoveryPhase::Renew => {
                same_recovery
                    && expected_lease
                        .zip(new_lease)
                        .is_some_and(|(expected, new)| expected.phase == new.phase)
            }
            PrivateOramExternalRecoveryPhase::PrepareInstall => {
                same_recovery
                    && expected_lease
                        .zip(new_lease)
                        .is_some_and(|(expected, new)| {
                            expected.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                                && new.phase == PrivateOramExternalRecoveryLeasePhase::Installing
                                && expected.install_intent_digest.is_none()
                                && new.install_intent_digest.is_some()
                        })
            }
            PrivateOramExternalRecoveryPhase::RollbackInstall => {
                same_recovery
                    && expected_lease
                        .zip(new_lease)
                        .is_some_and(|(expected, new)| {
                            expected.phase == PrivateOramExternalRecoveryLeasePhase::Installing
                                && new.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                                && expected.install_intent_digest.is_some()
                                && new.install_intent_digest.is_none()
                        })
            }
            PrivateOramExternalRecoveryPhase::Commit => {
                expected_lease.is_some_and(|lease| {
                    lease.phase == PrivateOramExternalRecoveryLeasePhase::Installing
                        && lease.install_intent_digest.is_some()
                }) && new.is_some_and(|state| {
                    state.active_lease.is_none()
                        && state.committed_install_intent_digest
                            == expected_lease.and_then(|lease| lease.install_intent_digest.clone())
                        && state.committed_backup_generation
                            > expected
                                .expect("commit phase requires expected recovery state")
                                .committed_backup_generation
                })
            }
            PrivateOramExternalRecoveryPhase::Abort => {
                expected_lease.is_some_and(|lease| {
                    lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                }) && new_lease.is_none()
            }
        };
        let owner_peer_id = new_lease
            .or(expected_lease)
            .map(|lease| lease.owner_peer_id);
        if !phase_is_valid
            || owner_peer_id.is_none_or(|owner| {
                operation
                    .layout
                    .owner_peer_ids
                    .binary_search(&owner)
                    .is_err()
            })
        {
            return Err(invalid_private_oram_external_recovery_operation());
        }
        Ok(())
    }

    pub fn private_oram_layout(
        &self,
        key: &PrivateOramLayoutKey,
    ) -> Option<PrivateOramConsensusLayout> {
        self.private_oram_layouts
            .get(&private_oram_layout_key_digest(key))
            .cloned()
    }

    pub fn validate_private_oram_collection_layout_transition(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<(), StorageError> {
        validate_private_oram_layout_cas(&transition.layout)?;
        let Some(expected_layout) = transition.layout.expected.as_ref() else {
            return Err(invalid_private_oram_collection_layout_transition());
        };
        if transition.leases.is_empty()
            || transition.leases.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS
            || expected_layout.layout_digest == transition.layout.new.layout_digest
        {
            return Err(invalid_private_oram_collection_layout_transition());
        }
        match (
            transition.shard_key_change.as_ref(),
            transition.collection_meta.as_ref(),
        ) {
            (None, CollectionMetaOperations::CreateShardKey(_))
            | (None, CollectionMetaOperations::DropShardKey(_)) => {
                return Err(invalid_private_oram_collection_layout_transition());
            }
            (Some(change), CollectionMetaOperations::CreateShardKey(operation))
                if change.kind == PrivateOramShardKeyLayoutChangeKind::Create
                    && change.shard_key == operation.shard_key
                    && operation.initial_state == Some(ReplicaState::Active)
                    && !change.entries.is_empty()
                    && change.entries.len() == operation.placement.len() => {}
            (Some(change), CollectionMetaOperations::DropShardKey(operation))
                if change.kind == PrivateOramShardKeyLayoutChangeKind::Drop
                    && change.shard_key == operation.shard_key
                    && !change.entries.is_empty() => {}
            (Some(_), _) => {
                return Err(invalid_private_oram_collection_layout_transition());
            }
            (None, _) => {}
        }
        if let Some(change) = transition.shard_key_change.as_ref() {
            validate_private_oram_shard_key_preinstalled_owners(
                change,
                expected_layout,
                &transition.layout.new,
            )?;
        }

        let mut states = Vec::with_capacity(transition.leases.len());
        let mut previous_key = None;
        let expected_lease = &transition.leases[0].lease;
        for binding in &transition.leases {
            if binding.key.collection_id != transition.layout.key.collection_id
                || &binding.lease != expected_lease
                || self.private_oram_session_lease(&binding.key).as_ref() != Some(&binding.lease)
            {
                return Err(invalid_private_oram_collection_layout_transition());
            }
            let key_order = private_oram_epoch_key_order(&binding.key);
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key_order)
            {
                return Err(invalid_private_oram_collection_layout_transition());
            }
            previous_key = Some(key_order);
            let state = self
                .private_oram_epoch(&binding.key)
                .ok_or_else(invalid_private_oram_collection_layout_transition)?;
            states.push((binding.key.clone(), state));
        }

        let index_state_digest = canonical_private_oram_index_state_digest(
            &transition.layout.key.collection_id,
            &states,
        )?;
        if transition.layout.new.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_collection_layout_transition());
        }

        let current = self.private_oram_layout(&transition.layout.key);
        if current.as_ref() != Some(expected_layout)
            && current.as_ref() != Some(&transition.layout.new)
        {
            return Err(invalid_private_oram_collection_layout_transition());
        }
        Ok(())
    }

    pub fn validate_private_oram_resharding_operation(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<CompareAndSwapPrivateOramLayout, StorageError> {
        let (phase, resharding_key) = match operation.collection_meta.as_ref() {
            CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(key)) => {
                (PrivateOramReshardingPhase::Start, key)
            }
            CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(key)) => {
                (PrivateOramReshardingPhase::Finish, key)
            }
            _ => return Err(invalid_private_oram_resharding_transition()),
        };
        if resharding_key != &operation.transition.resharding_key {
            return Err(invalid_private_oram_resharding_transition());
        }

        validate_private_oram_layout_cas(&operation.transition.layout)
            .map_err(|_| invalid_private_oram_resharding_transition())?;
        let expected_layout = operation
            .transition
            .layout
            .expected
            .as_ref()
            .ok_or_else(invalid_private_oram_resharding_transition)?;
        if operation.leases.is_empty()
            || operation.leases.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS
            || operation.leases.len() != operation.transition.index_states.len()
            || expected_layout.layout_digest == operation.transition.layout.new.layout_digest
            || expected_layout.index_state_digest
                != operation.transition.layout.new.index_state_digest
        {
            return Err(invalid_private_oram_resharding_transition());
        }

        let expected_lease = &operation.leases[0].lease;
        let mut states = Vec::with_capacity(operation.transition.index_states.len());
        let mut previous_key = None;
        for (lease_binding, state_binding) in operation
            .leases
            .iter()
            .zip(&operation.transition.index_states)
        {
            let key_order = private_oram_epoch_key_order(&state_binding.key);
            if lease_binding.key != state_binding.key
                || state_binding.key.collection_id != operation.transition.layout.key.collection_id
                || &lease_binding.lease != expected_lease
                || self.private_oram_session_lease(&state_binding.key).as_ref()
                    != Some(&lease_binding.lease)
                || self.private_oram_epoch(&state_binding.key).as_ref()
                    != Some(&state_binding.state)
                || previous_key
                    .as_ref()
                    .is_some_and(|previous| previous >= &key_order)
            {
                return Err(invalid_private_oram_resharding_transition());
            }
            previous_key = Some(key_order);
            states.push((state_binding.key.clone(), state_binding.state.clone()));
        }

        let index_state_digest = canonical_private_oram_index_state_digest(
            &operation.transition.layout.key.collection_id,
            &states,
        )
        .map_err(|_| invalid_private_oram_resharding_transition())?;
        if expected_layout.index_state_digest != index_state_digest {
            return Err(invalid_private_oram_resharding_transition());
        }

        let current = self.private_oram_layout(&operation.transition.layout.key);
        let valid_current = match phase {
            PrivateOramReshardingPhase::Start => current.as_ref() == Some(expected_layout),
            PrivateOramReshardingPhase::Finish => {
                current.as_ref() == Some(expected_layout)
                    || current.as_ref() == Some(&operation.transition.layout.new)
            }
        };
        if !valid_current {
            return Err(invalid_private_oram_resharding_transition());
        }
        Ok(operation.transition.layout.clone())
    }

    pub fn validate_private_oram_shard_transfer_start(
        &self,
        operation: &PrivateOramShardTransferStart,
    ) -> Result<Option<CompareAndSwapPrivateOramLayout>, StorageError> {
        let transition = private_oram_transfer_transition(
            &operation.collection_meta,
            PrivateOramTransferOperationKind::Start,
        )?;
        let (layout_key, expected_layout, new_layout, states) =
            self.validate_private_oram_transfer_state(transition)?;
        if operation.leases.len() != states.len() || operation.leases.is_empty() {
            return Err(invalid_private_oram_transfer_transition());
        }
        let expected_lease = &operation.leases[0].lease;
        for (lease_binding, (state_key, _)) in operation.leases.iter().zip(&states) {
            if &lease_binding.key != state_key
                || &lease_binding.lease != expected_lease
                || self.private_oram_session_lease(&lease_binding.key).as_ref()
                    != Some(&lease_binding.lease)
            {
                return Err(invalid_private_oram_transfer_transition());
            }
        }
        let layout = CompareAndSwapPrivateOramLayout {
            key: layout_key,
            expected: Some(expected_layout.clone()),
            new: new_layout.clone(),
        };
        validate_private_oram_layout_cas(&layout)
            .map_err(|_| invalid_private_oram_transfer_transition())?;

        let current = self
            .private_oram_layout(&layout.key)
            .ok_or_else(invalid_private_oram_transfer_transition)?;
        if current == expected_layout || current == new_layout {
            return Ok(None);
        }
        if !private_oram_layout_is_precommitted_transfer_recovery(
            &current,
            &expected_layout,
            &new_layout,
        ) {
            return Err(invalid_private_oram_transfer_transition());
        }
        Ok(Some(CompareAndSwapPrivateOramLayout {
            key: layout.key,
            expected: Some(current),
            new: new_layout,
        }))
    }

    pub fn validate_private_oram_shard_transfer_finish(
        &self,
        operation: &PrivateOramShardTransferFinish,
    ) -> Result<CompareAndSwapPrivateOramLayout, StorageError> {
        let transition = private_oram_transfer_transition(
            &operation.collection_meta,
            PrivateOramTransferOperationKind::Finish,
        )?;
        let (layout_key, expected_layout, new_layout, _) =
            self.validate_private_oram_transfer_state(transition)?;
        let layout = CompareAndSwapPrivateOramLayout {
            key: layout_key,
            expected: Some(expected_layout.clone()),
            new: new_layout.clone(),
        };
        validate_private_oram_layout_cas(&layout)
            .map_err(|_| invalid_private_oram_transfer_transition())?;
        let current = self.private_oram_layout(&layout.key);
        if current.as_ref() != Some(&expected_layout) && current.as_ref() != Some(&new_layout) {
            return Err(invalid_private_oram_transfer_transition());
        }
        Ok(layout)
    }

    fn validate_private_oram_transfer_state(
        &self,
        transition: &collection::shards::transfer::PrivateOramTransferLayoutTransition,
    ) -> Result<
        (
            PrivateOramLayoutKey,
            PrivateOramConsensusLayout,
            PrivateOramConsensusLayout,
            Vec<(PrivateOramEpochKey, PrivateOramConsensusEpoch)>,
        ),
        StorageError,
    > {
        let (layout_key, expected_layout, new_layout) =
            private_oram_transfer_consensus_layouts(transition);
        let states = private_oram_transfer_consensus_states(transition);
        if states.is_empty() || states.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
            return Err(invalid_private_oram_transfer_transition());
        }
        let mut previous_key = None;
        for (key, expected_state) in &states {
            let key_order = private_oram_epoch_key_order(key);
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key_order)
                || self.private_oram_epoch(key).as_ref() != Some(expected_state)
            {
                return Err(invalid_private_oram_transfer_transition());
            }
            previous_key = Some(key_order);
        }
        let index_state_digest =
            canonical_private_oram_index_state_digest(&layout_key.collection_id, &states)
                .map_err(|_| invalid_private_oram_transfer_transition())?;
        if new_layout.index_state_digest != index_state_digest
            || expected_layout.layout_digest == new_layout.layout_digest
        {
            return Err(invalid_private_oram_transfer_transition());
        }
        Ok((layout_key, expected_layout, new_layout, states))
    }

    pub fn compare_and_swap_private_oram_layout(
        &mut self,
        operation: &CompareAndSwapPrivateOramLayout,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        validate_private_oram_layout_cas(operation)?;
        let key = private_oram_layout_key_digest(&operation.key);
        let current = self.private_oram_layouts.get(&key);
        if current == Some(&operation.new) {
            return Ok(());
        }
        if self.private_oram_external_recovery_is_active(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "private ORAM layout CAS conflicts with active external recovery",
            ));
        }
        if self.private_oram_mutation_is_active(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "private ORAM layout CAS conflicts with active mutation",
            ));
        }
        if self.private_oram_mutation_is_enrolled(&operation.key.collection_id) {
            return Err(StorageError::bad_request(
                "standalone private ORAM layout CAS conflicts with enrolled v2 mutation state",
            ));
        }
        if current != operation.expected.as_ref() {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout CAS precondition failed",
            ));
        }
        if operation.expected.is_none()
            && self.private_oram_layouts.len() >= PRIVATE_ORAM_EPOCH_MAX_RECORDS
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout capacity exceeded",
            ));
        }

        let previous = self
            .private_oram_layouts
            .insert(key.clone(), operation.new.clone());
        self.save_or_rollback_on_definitive(move |persistent| match previous {
            Some(previous) => {
                persistent.private_oram_layouts.insert(key, previous);
            }
            None => {
                persistent.private_oram_layouts.remove(&key);
            }
        })
    }

    pub fn last_applied_entry(&self) -> Option<u64> {
        self.apply_progress_queue.get_last_applied()
    }

    /// Get the last applied commit and term, reflected in our current state.
    pub fn applied_commit_term(&self) -> (u64, u64) {
        let hard_state = &self.state().hard_state;

        // Fall back to 0 because it's always less than any commit
        let last_commit = self.last_applied_entry().unwrap_or(0);

        (last_commit, hard_state.term)
    }

    pub fn first_voter(&self) -> Option<PeerId> {
        self.first_voter
    }

    pub fn set_first_voter(&mut self, id: PeerId) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        self.first_voter = Some(id);
        self.save()
    }

    pub(crate) fn remove_peer_metadata_and_save(
        &mut self,
        peer_id: PeerId,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        let previous = self.peer_metadata_by_id.write().remove(&peer_id);
        self.save_or_rollback_on_definitive(move |persistent| {
            if let Some(previous) = previous {
                persistent
                    .peer_metadata_by_id
                    .write()
                    .insert(peer_id, previous);
            }
        })
    }

    pub fn peer_address_by_id(&self) -> PeerAddressById {
        self.peer_address_by_id.read().clone()
    }

    pub fn peer_metadata_by_id(&self) -> PeerMetadataById {
        self.peer_metadata_by_id.read().clone()
    }

    pub fn is_our_metadata_outdated(&self, current_metadata: &PeerMetadata) -> bool {
        self.peer_metadata_by_id
            .read()
            .get(&self.this_peer_id())
            .is_none_or(|metadata| metadata.is_different_from(current_metadata))
    }

    pub fn this_peer_id(&self) -> PeerId {
        self.this_peer_id
    }

    /// ## Arguments
    /// `path` - full name of the file where state will be saved
    ///
    /// `first_peer` - if this is a first peer in a new deployment (e.g. it does not bootstrap from anyone)
    /// It is `None` if distributed deployment is disabled
    fn init(
        path: PathBuf,
        first_peer: bool,
        peer_id: Option<PeerId>,
    ) -> Result<Self, StorageError> {
        // Do not generate too big peer ID, to avoid problems with serialization
        // (especially in json format)
        let this_peer_id = peer_id.unwrap_or_else(|| rand::random::<PeerId>() % (1 << 53) + 1);
        let voters = if first_peer {
            vec![this_peer_id]
        } else {
            // `Some(false)` - Leave empty the network topology for the peer, if it is not starting a network itself.
            // This way it will not be able to become a leader and commit data
            // until it joins an existing network.
            vec![]
        };
        let state = Self {
            state: RaftState {
                hard_state: HardState::default(),
                // For network with 1 node, set it as voter.
                // First vec is voters, second is learners.
                conf_state: ConfState::from((voters, vec![])),
            },
            apply_progress_queue: Default::default(),
            first_voter: if first_peer { Some(this_peer_id) } else { None },
            peer_address_by_id: Default::default(),
            peer_metadata_by_id: Default::default(),
            cluster_metadata: Default::default(),
            private_oram_activation_authority: None,
            private_oram_epochs: Default::default(),
            private_oram_session_leases: Default::default(),
            private_oram_layouts: Default::default(),
            private_oram_external_recoveries: Default::default(),
            private_oram_mutation_states: Default::default(),
            private_oram_mutation_lease_slots: Default::default(),
            private_oram_mutation_format_floor: None,
            private_oram_mutation_activation_pending: None,
            this_peer_id,
            private_oram_activation_authority_store_instance: Default::default(),
            private_oram_activation_authority_trust_anchor: Default::default(),
            path,
            persistence_transaction: Default::default(),
            latest_snapshot_meta: Default::default(),
            dirty: AtomicBool::new(false),
            save_indeterminate: AtomicBool::new(false),
        };
        state.save()?;
        Ok(state)
    }

    fn load(path: PathBuf) -> Result<Self, StorageError> {
        let reader = BufReader::new(File::open(&path)?);
        let mut state: Self = serde_cbor::from_reader(reader)?;
        Self::validate_private_oram_snapshot_state_at_index(
            &state.private_oram_epochs,
            &state.private_oram_session_leases,
            &state.private_oram_layouts,
            &state.private_oram_external_recoveries,
            &state.private_oram_mutation_states,
            &state.private_oram_mutation_lease_slots,
            state.private_oram_mutation_format_floor.as_ref(),
            state.private_oram_mutation_activation_pending.as_ref(),
            state.private_oram_activation_authority.as_ref(),
            state.private_oram_applied_index(),
        )?;
        state.path = path;
        Ok(state)
    }

    fn load_json(path: PathBuf) -> Result<Self, StorageError> {
        let reader = BufReader::new(File::open(&path)?);
        let mut state: Self = serde_json::from_reader(reader)?;
        Self::validate_private_oram_snapshot_state_at_index(
            &state.private_oram_epochs,
            &state.private_oram_session_leases,
            &state.private_oram_layouts,
            &state.private_oram_external_recoveries,
            &state.private_oram_mutation_states,
            &state.private_oram_mutation_lease_slots,
            state.private_oram_mutation_format_floor.as_ref(),
            state.private_oram_mutation_activation_pending.as_ref(),
            state.private_oram_activation_authority.as_ref(),
            state.private_oram_applied_index(),
        )?;
        state.path = path;
        Ok(state)
    }

    fn save_classified(&self) -> Result<(), PersistentSaveError> {
        self.save_classified_with_backend(&FilesystemPersistentSaveBackend)
    }

    fn save_classified_with_backend(
        &self,
        backend: &impl PersistentSaveBackend,
    ) -> Result<(), PersistentSaveError> {
        let _transaction = self.persistence_transaction.lock();
        if self.save_indeterminate.load(Ordering::Acquire) {
            return Err(PersistentSaveError::Indeterminate);
        }

        validate_persisted_private_oram_activation_authority(
            self.private_oram_activation_authority.as_ref(),
            self.private_oram_activation_authority_trust_anchor.get(),
        )
        .map_err(PersistentSaveError::Definitive)?;
        Self::validate_private_oram_snapshot_state_at_index(
            &self.private_oram_epochs,
            &self.private_oram_session_leases,
            &self.private_oram_layouts,
            &self.private_oram_external_recoveries,
            &self.private_oram_mutation_states,
            &self.private_oram_mutation_lease_slots,
            self.private_oram_mutation_format_floor.as_ref(),
            self.private_oram_mutation_activation_pending.as_ref(),
            self.private_oram_activation_authority.as_ref(),
            self.private_oram_applied_index(),
        )
        .map_err(PersistentSaveError::Definitive)?;

        let result = self.persist_state_image(backend);
        match result {
            Ok(()) => {
                self.dirty.store(false, Ordering::Release);
                log::trace!("Saved state: {self:?}");
                Ok(())
            }
            Err(error @ PersistentSaveError::Definitive(_)) => {
                self.dirty.store(true, Ordering::Release);
                Err(error)
            }
            Err(PersistentSaveError::Indeterminate) => {
                self.dirty.store(true, Ordering::Release);
                self.save_indeterminate.store(true, Ordering::Release);
                log::error!(
                    "Raft persistent state durability is indeterminate; stopping consensus until restart"
                );
                Err(PersistentSaveError::Indeterminate)
            }
        }
    }

    fn persist_state_image(
        &self,
        backend: &impl PersistentSaveBackend,
    ) -> Result<(), PersistentSaveError> {
        let prepared = self.prepare_state_image()?;
        let next_raft_state_digest = BASE64URL_NOPAD.encode(&prepared.candidate_digest);
        let prior_raft_state_digest = match persistent_state_file_digest(&self.path) {
            Ok(digest) => BASE64URL_NOPAD.encode(&digest),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                private_oram_mutation_raft_state_image_digest_v2(&[])
            }
            Err(error) => return Err(PersistentSaveError::Definitive(error.into())),
        };
        let floor_store = self.private_oram_mutation_floor_store();
        let current_checkpoint = floor_store
            .recover(&prior_raft_state_digest)
            .map_err(private_oram_floor_persistent_save_error)?;
        let next_checkpoint = plan_private_oram_local_floor_for_persistent_state(
            current_checkpoint.as_ref(),
            self.private_oram_mutation_format_floor.as_ref(),
            &self.private_oram_mutation_lease_slots,
            self.private_oram_applied_index(),
        )
        .map_err(private_oram_floor_persistent_save_error)?;

        if next_checkpoint.as_ref() == current_checkpoint.as_ref() {
            return self.publish_prepared_state_image(prepared, backend);
        }
        let next_checkpoint = next_checkpoint.ok_or_else(|| {
            PersistentSaveError::Definitive(StorageError::service_error(
                "private ORAM mutation floor cannot be removed",
            ))
        })?;
        let floor_transition = floor_store
            .begin_transition_guard(
                &next_checkpoint,
                prior_raft_state_digest,
                next_raft_state_digest.clone(),
            )
            .map_err(private_oram_floor_persistent_save_error)?;
        self.publish_prepared_state_image(prepared, backend)?;
        floor_transition
            .finalize(&next_raft_state_digest)
            .map_err(|error| {
                log::error!(
                    "private ORAM mutation floor finalization failed after Raft-state publication: {error:?}"
                );
                PersistentSaveError::Indeterminate
            })?;
        Ok(())
    }

    fn prepare_state_image(&self) -> Result<PreparedPersistentStateImage, PersistentSaveError> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut candidate = tempfile::Builder::new()
            .prefix(".raft-state-")
            .tempfile_in(parent)
            .map_err(|error| PersistentSaveError::Definitive(error.into()))?;
        let mut candidate_hasher = Sha256::new();
        {
            let writer = BufWriter::new(candidate.as_file_mut());
            let mut writer = Sha256Writer {
                inner: writer,
                hasher: &mut candidate_hasher,
            };
            serde_json::to_writer(&mut writer, self)
                .map_err(|error| PersistentSaveError::Definitive(error.into()))?;
            writer
                .flush()
                .map_err(|error| PersistentSaveError::Definitive(error.into()))?;
        }
        let candidate_path = candidate.path().to_path_buf();
        File::from_parts(
            candidate
                .reopen()
                .map_err(|error| PersistentSaveError::Definitive(error.into()))?,
            candidate_path,
        )
        .sync_all()
        .map_err(|error| PersistentSaveError::Definitive(error.into()))?;
        let candidate_digest: [u8; 32] = candidate_hasher.finalize().into();

        Ok(PreparedPersistentStateImage {
            candidate,
            candidate_digest,
            parent: parent.to_path_buf(),
        })
    }

    fn publish_prepared_state_image(
        &self,
        prepared: PreparedPersistentStateImage,
        backend: &impl PersistentSaveBackend,
    ) -> Result<(), PersistentSaveError> {
        let PreparedPersistentStateImage {
            candidate,
            candidate_digest,
            parent,
        } = prepared;

        if let Err(error) = backend.publish(candidate, &self.path) {
            if persistent_state_file_digest(&self.path).ok() != Some(candidate_digest) {
                log::error!("Raft persistent state publish outcome is indeterminate: {error}");
                return Err(PersistentSaveError::Indeterminate);
            }
            log::warn!(
                "Raft persistent state publish returned an error after exposing the candidate image; retrying parent-directory sync"
            );
        }

        let mut last_sync_error = None;
        for _ in 0..PERSISTENT_PARENT_SYNC_ATTEMPTS {
            match backend.sync_parent(&parent) {
                Ok(()) => return Ok(()),
                Err(error) => last_sync_error = Some(error),
            }
            if persistent_state_file_digest(&self.path).ok() != Some(candidate_digest) {
                log::error!(
                    "Raft persistent state image changed while recovering a parent-directory sync failure"
                );
                return Err(PersistentSaveError::Indeterminate);
            }
        }

        if let Some(error) = last_sync_error {
            log::error!(
                "Raft persistent state parent-directory sync failed after publish and retry: {error}"
            );
        }
        Err(PersistentSaveError::Indeterminate)
    }

    fn save_or_rollback_on_definitive(
        &mut self,
        rollback: impl FnOnce(&mut Self),
    ) -> Result<(), StorageError> {
        self.save_or_rollback_on_definitive_with_backend(&FilesystemPersistentSaveBackend, rollback)
    }

    fn save_or_rollback_on_definitive_with_backend(
        &mut self,
        backend: &impl PersistentSaveBackend,
        rollback: impl FnOnce(&mut Self),
    ) -> Result<(), StorageError> {
        match self.save_classified_with_backend(backend) {
            Ok(()) => Ok(()),
            Err(error) => {
                if error.is_definitive() {
                    rollback(self);
                }
                Err(error.into_storage_error())
            }
        }
    }

    /// Removes every private ORAM consensus record owned by a deleted collection.
    ///
    /// The maps are keyed by digests of the collection's stable crypto id, which a re-created
    /// collection never reuses, so without this every create/delete cycle of an encrypted
    /// collection leaked a permanent set of entries into raft_state.json and every snapshot.
    pub fn prune_private_oram_collection_state(
        &mut self,
        index_keys: &[PrivateOramEpochKey],
    ) -> Result<bool, StorageError> {
        let Some(collection_id) = index_keys.first().map(|key| key.collection_id.clone()) else {
            return Ok(false);
        };
        let mutation_digest = private_oram_mutation_key_digest(&PrivateOramMutationKey {
            collection_id: collection_id.clone(),
        });
        // An activated authority with an aggregate pins a local floor, and the floor checkpoint
        // refuses a floor that disappears (that rule is what stops a snapshot omitting the
        // collection from replaying its older authority). Removing it here failed the save on
        // every node and stopped consensus. Snapshot and load validation also cross-check the
        // mutation state, lease slot, epochs, layouts, session leases and external recoveries,
        // so the collection's records are retained as a whole until a validated retirement
        // (a Raft-ordered tombstone) exists. Every replica holds the same authority, so the
        // decision is the same everywhere.
        if self
            .private_oram_mutation_lease_slots
            .get(&mutation_digest)
            .and_then(DecodedPrivateOramMutationAuthorityWireV2::tagged_authority)
            .is_some_and(|authority| authority.aggregate().is_some())
        {
            log::warn!(
                "retaining private ORAM consensus records of a deleted collection whose mutation                  authority pins a local floor"
            );
            return Ok(false);
        }
        let mut removed = false;
        for key in index_keys {
            let digest = private_oram_epoch_key_digest(key);
            removed |= self.private_oram_epochs.remove(&digest).is_some();
            removed |= self.private_oram_session_leases.remove(&digest).is_some();
        }
        let layout_digest = private_oram_layout_key_digest(&PrivateOramLayoutKey {
            collection_id: collection_id.clone(),
        });
        removed |= self.private_oram_layouts.remove(&layout_digest).is_some();
        let recovery_digest =
            private_oram_external_recovery_key_digest(&PrivateOramExternalRecoveryKey {
                collection_id: collection_id.clone(),
            });
        removed |= self
            .private_oram_external_recoveries
            .remove(&recovery_digest)
            .is_some();
        removed |= self
            .private_oram_mutation_states
            .remove(&mutation_digest)
            .is_some();
        removed |= self
            .private_oram_mutation_lease_slots
            .remove(&mutation_digest)
            .is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn save(&self) -> Result<(), StorageError> {
        self.save_classified()
            .map_err(PersistentSaveError::into_storage_error)
    }

    pub fn save_if_dirty(&mut self) -> Result<(), StorageError> {
        if self.dirty.load(Ordering::Relaxed) {
            self.save()?;
        }
        Ok(())
    }

    fn private_oram_applied_index(&self) -> u64 {
        self.apply_progress_queue
            .get_last_applied()
            .unwrap_or(self.latest_snapshot_meta.index)
    }

    fn private_oram_mutation_floor_store(&self) -> PrivateOramMutationFloorStoreV2 {
        let storage_path = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        PrivateOramMutationFloorStoreV2::new(storage_path)
    }

    fn recover_and_validate_private_oram_mutation_local_floor(&self) -> Result<bool, StorageError> {
        let checkpoint = self.recover_private_oram_mutation_local_floor_checkpoint()?;
        validate_private_oram_local_floor_against_persistent_state(
            checkpoint.as_ref(),
            self.private_oram_mutation_format_floor.as_ref(),
            &self.private_oram_mutation_lease_slots,
            self.private_oram_applied_index(),
        )
        .map_err(|error| {
            private_oram_floor_storage_error(
                "persisted Raft state contradicts the private ORAM mutation floor",
                error,
            )
        })?;
        Ok(checkpoint.is_some())
    }

    fn recover_private_oram_mutation_local_floor_checkpoint(
        &self,
    ) -> Result<Option<PrivateOramMutationLocalFloorCheckpointV2>, StorageError> {
        let observed_digest = BASE64URL_NOPAD.encode(
            &persistent_state_file_digest(&self.path).map_err(|error| {
                StorageError::service_error(format!(
                    "failed to hash persisted Raft state for private ORAM mutation floor recovery: {error}"
                ))
            })?,
        );
        self.private_oram_mutation_floor_store()
            .recover(&observed_digest)
            .map_err(|error| {
                private_oram_floor_storage_error(
                    "private ORAM mutation floor recovery failed",
                    error,
                )
            })
    }

    pub(crate) fn validate_private_oram_mutation_floor_snapshot_source(
        &self,
    ) -> Result<(), StorageError> {
        self.recover_and_validate_private_oram_mutation_local_floor()
            .map(|_| ())
    }

    pub(crate) fn validate_private_oram_mutation_floor_for_snapshot(
        &self,
        incoming_format_floor: Option<&PrivateOramMutationFormatFloorV2>,
        incoming_authority_wires: &HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
        incoming_applied_index: u64,
    ) -> Result<(), StorageError> {
        self.ensure_persistence_writable()?;
        let checkpoint = self.recover_private_oram_mutation_local_floor_checkpoint()?;
        validate_private_oram_local_floor_against_persistent_state(
            checkpoint.as_ref(),
            self.private_oram_mutation_format_floor.as_ref(),
            &self.private_oram_mutation_lease_slots,
            self.private_oram_applied_index(),
        )
        .map_err(|error| {
            private_oram_floor_storage_error(
                "persisted Raft state contradicts the private ORAM mutation floor",
                error,
            )
        })?;
        plan_private_oram_local_floor_for_persistent_state(
            checkpoint.as_ref(),
            incoming_format_floor,
            incoming_authority_wires,
            incoming_applied_index,
        )
        .map(|_| ())
        .map_err(|error| {
            private_oram_floor_storage_error(
                "private ORAM mutation snapshot would violate the local floor",
                error,
            )
        })
    }
}

fn persistent_state_file_digest(path: &Path) -> io::Result<[u8; 32]> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn plan_private_oram_local_floor_for_persistent_state(
    current: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    format_floor: Option<&PrivateOramMutationFormatFloorV2>,
    authority_wires: &HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    applied_index: u64,
) -> Result<Option<PrivateOramMutationLocalFloorCheckpointV2>, PrivateOramMutationJournalError> {
    let Some(format_floor) = format_floor else {
        if current.is_some()
            || authority_wires
                .values()
                .any(|wire| wire.tagged_authority().is_some())
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        return Ok(None);
    };

    let mut authority_floors = BTreeMap::new();
    for wire in authority_wires.values() {
        let Some(authority) = wire.tagged_authority() else {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        };
        if authority.aggregate().is_none() {
            continue;
        }
        let collection_key_digest = authority.collection_key_digest().to_string();
        let current_authority_floor =
            current.and_then(|checkpoint| checkpoint.authority_floor(&collection_key_digest));
        let pinned_applied_index = current_authority_floor
            .map(PrivateOramMutationAuthorityFloorV2::accepted_state_applied_index)
            .filter(|accepted| *accepted <= applied_index)
            .unwrap_or(applied_index);
        let candidate = plan_private_oram_mutation_authority_floor_acceptance_v2(
            current_authority_floor,
            format_floor,
            authority,
            pinned_applied_index,
        )
        .or_else(|_| {
            plan_private_oram_mutation_authority_floor_acceptance_v2(
                current_authority_floor,
                format_floor,
                authority,
                applied_index,
            )
        })?;
        if authority_floors
            .insert(collection_key_digest, candidate)
            .is_some()
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }

    plan_private_oram_mutation_local_floor_checkpoint_v2(
        current,
        format_floor.clone(),
        authority_floors,
    )
    .map(Some)
}

fn validate_private_oram_local_floor_against_persistent_state(
    current: Option<&PrivateOramMutationLocalFloorCheckpointV2>,
    format_floor: Option<&PrivateOramMutationFormatFloorV2>,
    authority_wires: &HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    applied_index: u64,
) -> Result<(), PrivateOramMutationJournalError> {
    let planned = plan_private_oram_local_floor_for_persistent_state(
        current,
        format_floor,
        authority_wires,
        applied_index,
    )?;
    if planned.as_ref() != current {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if let Some(checkpoint) = current {
        for (collection_key_digest, authority_floor) in checkpoint.authority_floors() {
            let wire = authority_wires.values().find(|wire| {
                wire.tagged_authority().is_some_and(|authority| {
                    authority.collection_key_digest() == collection_key_digest
                })
            });
            plan_private_oram_mutation_snapshot_authority_acceptance_v2(
                authority_floor,
                checkpoint.format_floor(),
                wire,
                applied_index,
            )?;
        }
    }
    Ok(())
}

fn private_oram_floor_storage_error(
    context: &'static str,
    error: PrivateOramMutationJournalError,
) -> StorageError {
    log::error!("{context}: {error:?}");
    StorageError::service_error(context)
}

fn private_oram_floor_persistent_save_error(
    error: PrivateOramMutationJournalError,
) -> PersistentSaveError {
    log::error!("private ORAM mutation floor save failed: {error:?}");
    if matches!(error, PrivateOramMutationJournalError::Indeterminate) {
        PersistentSaveError::Indeterminate
    } else {
        PersistentSaveError::Definitive(StorageError::service_error(
            "private ORAM mutation floor save failed",
        ))
    }
}

pub(crate) fn private_oram_epoch_key_digest(key: &PrivateOramEpochKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EPOCH_KEY_DOMAIN);
    update_length_prefixed(&mut hasher, key.collection_id.as_bytes());
    hasher.update([match key.index_kind {
        PrivateOramIndexKind::Hnsw => 1,
        PrivateOramIndexKind::ResultPayload => 2,
    }]);
    update_length_prefixed(&mut hasher, key.index_name.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

pub(crate) fn private_oram_epoch_snapshot_value<'a>(
    epochs: &'a HashMap<String, PrivateOramConsensusEpoch>,
    key: &PrivateOramEpochKey,
) -> Option<&'a PrivateOramConsensusEpoch> {
    epochs.get(&private_oram_epoch_key_digest(key))
}

pub(crate) fn private_oram_layout_key_digest(key: &PrivateOramLayoutKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_LAYOUT_KEY_DOMAIN);
    update_length_prefixed(&mut hasher, key.collection_id.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

pub(crate) fn private_oram_layout_snapshot_value<'a>(
    layouts: &'a HashMap<String, PrivateOramConsensusLayout>,
    key: &PrivateOramLayoutKey,
) -> Option<&'a PrivateOramConsensusLayout> {
    layouts.get(&private_oram_layout_key_digest(key))
}

pub(crate) fn private_oram_external_recovery_key_digest(
    key: &PrivateOramExternalRecoveryKey,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_KEY_DOMAIN);
    update_length_prefixed(&mut hasher, key.collection_id.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

pub(crate) fn private_oram_mutation_key_digest(key: &PrivateOramMutationKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_MUTATION_KEY_DOMAIN);
    update_length_prefixed(&mut hasher, key.collection_id.as_bytes());
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

fn private_oram_mutation_index_epoch_key(
    collection_id: &str,
    index: &PrivateOramConsensusCollectionIndexStateV2,
) -> PrivateOramEpochKey {
    PrivateOramEpochKey {
        collection_id: collection_id.to_string(),
        index_kind: index.index_kind,
        index_name: index.index_name.clone(),
    }
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_private_oram_epoch_cas(
    operation: &CompareAndSwapPrivateOramEpoch,
) -> Result<(), StorageError> {
    validate_private_oram_epoch_key(&operation.key)?;

    validate_private_oram_consensus_root_hash(&operation.new.root_hash)?;
    validate_private_oram_consensus_writeback_digest(operation.new.writeback_digest.as_deref())?;
    if let Some(expected) = &operation.expected {
        validate_private_oram_consensus_root_hash(&expected.root_hash)?;
        validate_private_oram_consensus_writeback_digest(expected.writeback_digest.as_deref())?;
        if operation.new.index_epoch <= expected.index_epoch {
            return Err(StorageError::bad_request(
                "private ORAM consensus epoch must increase",
            ));
        }
    }
    Ok(())
}

fn validate_private_oram_epoch_key(key: &PrivateOramEpochKey) -> Result<(), StorageError> {
    let valid_key = !key.collection_id.is_empty()
        && key.collection_id.len() <= 1024
        && match key.index_kind {
            PrivateOramIndexKind::Hnsw => !key.index_name.is_empty() && key.index_name.len() <= 128,
            PrivateOramIndexKind::ResultPayload => key.index_name.is_empty(),
        };
    if !valid_key {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch key is invalid",
        ));
    }

    Ok(())
}

fn validate_private_oram_mutation_key(key: &PrivateOramMutationKey) -> Result<(), StorageError> {
    if key.collection_id.is_empty() || key.collection_id.len() > 1024 {
        return Err(StorageError::bad_request(
            "private ORAM mutation key is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_mutation_receipt(
    receipt: &PrivateOramMutationReceiptV2,
) -> Result<(), StorageError> {
    if receipt.version != PRIVATE_ORAM_MUTATION_RECEIPT_VERSION
        || receipt.writer_fence == 0
        || receipt.mutation_lease_generation == 0
        || receipt
            .old_state_sequence
            .checked_add(1)
            .is_none_or(|sequence| sequence != receipt.new_state_sequence)
        || receipt.old_state_digest == receipt.new_state_digest
    {
        return Err(StorageError::bad_request(
            "private ORAM mutation receipt is invalid",
        ));
    }
    for digest in [
        &receipt.mutation_id,
        &receipt.signed_mutation_digest,
        &receipt.transition_digest,
        &receipt.old_state_digest,
        &receipt.new_state_digest,
        &receipt.point_operation_digest,
        &receipt.writer_lease_digest,
    ] {
        validate_private_oram_consensus_digest(digest)
            .map_err(|_| StorageError::bad_request("private ORAM mutation receipt is invalid"))?;
    }
    Ok(())
}

fn validate_private_oram_consensus_collection_state(
    state: &PrivateOramConsensusCollectionStateV2,
) -> Result<(), StorageError> {
    if state.version != PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION
        || state.collection_id.is_empty()
        || state.collection_id.len() > 1024
        || state.layout_generation == 0
        || state.indexes.is_empty()
        || state.indexes.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS
    {
        return Err(StorageError::bad_request(
            "private ORAM consensus collection state is invalid",
        ));
    }
    for digest in [
        &state.manifest_digest,
        &state.layout_digest,
        &state.signed_state_digest,
        &state.client_state_digest,
    ] {
        validate_private_oram_consensus_digest(digest).map_err(|_| {
            StorageError::bad_request("private ORAM consensus collection state is invalid")
        })?;
    }
    match &state.last_transition {
        PrivateOramConsensusTransitionV2::Genesis if state.state_sequence == 0 => {}
        PrivateOramConsensusTransitionV2::Mutation(receipt) if state.state_sequence > 0 => {
            validate_private_oram_mutation_receipt(receipt)?;
            if receipt.new_state_sequence != state.state_sequence
                || receipt.new_state_digest != state.signed_state_digest
            {
                return Err(StorageError::bad_request(
                    "private ORAM consensus collection state is invalid",
                ));
            }
        }
        _ => {
            return Err(StorageError::bad_request(
                "private ORAM consensus collection state is invalid",
            ));
        }
    }

    let mut previous_order = None;
    for index in &state.indexes {
        let key = private_oram_mutation_index_epoch_key(&state.collection_id, index);
        validate_private_oram_epoch_key(&key).map_err(|_| {
            StorageError::bad_request("private ORAM consensus collection state is invalid")
        })?;
        validate_private_oram_consensus_root_hash(&index.epoch.root_hash).map_err(|_| {
            StorageError::bad_request("private ORAM consensus collection state is invalid")
        })?;
        validate_private_oram_consensus_writeback_digest(index.epoch.writeback_digest.as_deref())
            .map_err(|_| {
            StorageError::bad_request("private ORAM consensus collection state is invalid")
        })?;
        let order = (private_oram_epoch_key_order(&key).0, key.index_name.clone());
        if previous_order
            .as_ref()
            .is_some_and(|previous| previous >= &order)
        {
            return Err(StorageError::bad_request(
                "private ORAM consensus collection state is invalid",
            ));
        }
        index
            .logical_count
            .checked_add(index.dummy_count)
            .ok_or_else(|| {
                StorageError::bad_request("private ORAM consensus collection state is invalid")
            })?;
        previous_order = Some(order);
    }
    canonical_private_oram_consensus_state_record_digest(state).map_err(|_| {
        StorageError::bad_request("private ORAM consensus collection state is invalid")
    })?;
    Ok(())
}

fn validate_initialize_private_oram_mutation_state(
    operation: &InitializePrivateOramMutationState,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_key(&operation.key)?;
    validate_private_oram_consensus_collection_state(&operation.state)?;
    if operation.state.collection_id != operation.key.collection_id
        || operation.state.state_sequence != 0
        || !matches!(
            operation.state.last_transition,
            PrivateOramConsensusTransitionV2::Genesis
        )
    {
        return Err(StorageError::bad_request(
            "private ORAM mutation state initialization is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_mutation_material_v2(
    operation: &ApplyPrivateOramMutationMaterialV2,
    entry_term: u64,
    entry_index: u64,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_key(operation.key())?;
    validate_private_oram_consensus_digest(operation.expected_aggregate_digest())
        .map_err(|_| StorageError::bad_request("private ORAM V2 material operation is invalid"))?;
    let requires_v7 = matches!(
        operation.transition(),
        PrivateOramMutationMaterialTransitionV2::AppendReservationChallengePrepared { .. }
            | PrivateOramMutationMaterialTransitionV2::AppendReservationFinalizedV3 { .. }
            | PrivateOramMutationMaterialTransitionV2::AppendReservationChallengeCancelled { .. }
            | PrivateOramMutationMaterialTransitionV2::AppendReservationOutcomeAcknowledged { .. }
    );
    let expected_version = if requires_v7 {
        crate::content_manager::consensus_ops::PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION_V7
    } else {
        crate::content_manager::consensus_ops::PRIVATE_ORAM_MUTATION_MATERIAL_OPERATION_VERSION
    };
    if operation.version() != expected_version || entry_term == 0 || entry_index == 0 {
        return Err(StorageError::bad_request(
            "private ORAM V2 material operation is invalid",
        ));
    }
    match operation.transition() {
        PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentPrepared {
            prepared_canonical_json,
        } => {
            let prepared = decode_private_oram_owner_enrollment_prepared_v1(
                prepared_canonical_json.as_bytes(),
            )
            .map_err(|_| {
                StorageError::bad_request("private ORAM V2 material operation is invalid")
            })?;
            if prepared.collection_id != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::OwnerEnrollmentActivated {
            commitment_canonical_json,
        } => {
            let commitment = decode_private_oram_owner_enrollment_genesis_commitment_v1(
                commitment_canonical_json.as_bytes(),
            )
            .map_err(|_| {
                StorageError::bad_request("private ORAM V2 material operation is invalid")
            })?;
            if commitment.collection_id != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::AppendReservationChallengePrepared {
            challenge_canonical_json,
        } => {
            let challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
                challenge_canonical_json,
            )
            .map_err(private_oram_mutation_authority_invalid)?;
            if challenge.base_reservation().collection_id() != operation.key().collection_id
                || challenge.base_reservation().expected_aggregate_digest()
                    != operation.expected_aggregate_digest()
            {
                return Err(StorageError::bad_request(
                    "private ORAM V3 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::AppendReservationFinalizedV3 {
            reservation_canonical_json,
        } => {
            let reservation =
                decode_private_oram_mutation_append_reservation_v3(reservation_canonical_json)
                    .map_err(private_oram_mutation_authority_invalid)?;
            if reservation.collection_id() != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V3 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::AppendReservationChallengeCancelled {
            cancellation_canonical_json,
        } => {
            let cancellation = decode_private_oram_mutation_reservation_challenge_cancellation_v1(
                cancellation_canonical_json,
            )
            .map_err(private_oram_mutation_authority_invalid)?;
            if cancellation.collection_key_digest()
                != private_oram_collection_id_digest_v2(&operation.key().collection_id)
                    .map_err(private_oram_mutation_authority_invalid)?
            {
                return Err(StorageError::bad_request(
                    "private ORAM V3 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::AppendReservationOutcomeAcknowledged {
            acknowledgement_canonical_json,
        } => {
            decode_private_oram_mutation_reservation_outcome_acknowledgement_v1(
                acknowledgement_canonical_json,
            )
            .map_err(private_oram_mutation_authority_invalid)?;
        }
        PrivateOramMutationMaterialTransitionV2::AppendReservation {
            reservation_canonical_json,
        } => {
            let reservation =
                decode_private_oram_mutation_append_reservation_v2(reservation_canonical_json)
                    .map_err(private_oram_mutation_authority_invalid)?;
            if reservation.collection_id() != operation.key().collection_id
                || reservation.expected_aggregate_digest() != operation.expected_aggregate_digest()
            {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::AppendPrepared {
            recovery_manifest_canonical_json,
        } => {
            let manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
                recovery_manifest_canonical_json,
            )
            .map_err(private_oram_mutation_authority_invalid)?;
            if manifest.collection_id() != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::ReservedAttemptRejected {
            reservation_canonical_json,
        } => {
            let reservation =
                decode_private_oram_mutation_append_reservation_wire(reservation_canonical_json)
                    .map_err(private_oram_mutation_authority_invalid)?;
            if reservation.base_reservation().collection_id() != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::Admission {
            lease,
            recovery_manifest_canonical_json,
        }
        | PrivateOramMutationMaterialTransitionV2::AdmissionRejected {
            lease,
            recovery_manifest_canonical_json,
        } => {
            validate_private_oram_mutation_lease(lease)?;
            if lease.collection_id != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
            let recovery_manifest = decode_private_oram_mutation_admission_recovery_manifest_v2(
                recovery_manifest_canonical_json,
            )
            .map_err(private_oram_mutation_authority_invalid)?;
            recovery_manifest
                .validate_admission_lease(lease)
                .map_err(private_oram_mutation_authority_invalid)?;
        }
        PrivateOramMutationMaterialTransitionV2::Renewal { lease }
        | PrivateOramMutationMaterialTransitionV2::AbortDecision { lease } => {
            validate_private_oram_mutation_lease(lease)?;
            if lease.collection_id != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::ConsensusCommit {
            mutation_lease_generation,
            new_state,
        } => {
            if *mutation_lease_generation == 0 {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
            validate_private_oram_consensus_collection_state(new_state)?;
            if new_state.collection_id != operation.key().collection_id {
                return Err(StorageError::bad_request(
                    "private ORAM V2 material operation is invalid",
                ));
            }
        }
        PrivateOramMutationMaterialTransitionV2::ParentProgress {
            watermark_canonical_json,
        } => {
            decode_private_oram_mutation_parent_watermark_expectation_v2(watermark_canonical_json)
                .map_err(private_oram_mutation_authority_invalid)?;
        }
        PrivateOramMutationMaterialTransitionV2::RecoveryCapsulesReady {
            expectation_canonical_json,
        } => {
            decode_private_oram_mutation_recovery_capsules_ready_v2(expectation_canonical_json)
                .map_err(private_oram_mutation_authority_invalid)?;
        }
        PrivateOramMutationMaterialTransitionV2::CleanupWitness {
            expectation_canonical_json,
        } => {
            decode_private_oram_mutation_cleanup_expectation_v2(expectation_canonical_json)
                .map_err(private_oram_mutation_authority_invalid)?;
        }
        PrivateOramMutationMaterialTransitionV2::ClearPending {
            clear_attempt_id_digest,
        } => {
            validate_private_oram_consensus_digest(clear_attempt_id_digest).map_err(|_| {
                StorageError::bad_request("private ORAM V2 material operation is invalid")
            })?;
        }
        PrivateOramMutationMaterialTransitionV2::Clear
        | PrivateOramMutationMaterialTransitionV2::ClearAcknowledgement => {}
    }
    Ok(())
}

fn validate_private_oram_material_result_v2(
    authority: &PrivateOramMutationAuthorityStateV2,
    expected_slot: &PrivateOramMutationLeaseSlotV2,
    expected_outer_binding_digest: &str,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_authority_state_v2(authority)
        .map_err(private_oram_mutation_authority_corrupt)?;
    let aggregate = authority.aggregate().ok_or_else(|| {
        StorageError::service_error("private ORAM V2 material transition lost activated authority")
    })?;
    if authority.lease_slot() != expected_slot
        || aggregate.outer_binding_digest() != expected_outer_binding_digest
    {
        return Err(StorageError::service_error(
            "private ORAM V2 material transition produced inconsistent authority",
        ));
    }
    Ok(())
}

fn validate_private_oram_committed_lease_for_state_v2(
    lease: &PrivateOramMutationLease,
    state: &PrivateOramConsensusCollectionStateV2,
    key: &PrivateOramMutationKey,
    mutation_lease_generation: u64,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_lease(lease)?;
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &state.last_transition else {
        return Err(StorageError::bad_request(
            "private ORAM V2 mutation commit replay is invalid",
        ));
    };
    let PrivateOramMutationLeasePhase::ConsensusCommitted {
        committed_record_digest,
        committed_state_sequence,
        committed_signed_state_digest,
        receipt_digest,
    } = &lease.phase
    else {
        return Err(StorageError::bad_request(
            "private ORAM V2 mutation commit replay is invalid",
        ));
    };
    if lease.collection_id != key.collection_id
        || lease.generation != mutation_lease_generation
        || committed_record_digest != &canonical_private_oram_consensus_state_record_digest(state)?
        || *committed_state_sequence != state.state_sequence
        || committed_signed_state_digest != &state.signed_state_digest
        || receipt_digest != &canonical_private_oram_mutation_receipt_digest(receipt)?
        || receipt.mutation_lease_generation != lease.generation
        || receipt.mutation_id != lease.mutation_id
        || receipt.signed_mutation_digest != lease.signed_mutation_digest
        || receipt.transition_digest != lease.transition_digest
        || receipt.writer_lease_digest != lease.writer_lease_digest
        || receipt.writer_fence != lease.writer_fence
    {
        return Err(StorageError::bad_request(
            "private ORAM V2 mutation commit replay is invalid",
        ));
    }
    Ok(())
}

fn private_oram_mutation_authority_invalid(
    _error: PrivateOramMutationJournalError,
) -> StorageError {
    StorageError::bad_request("private ORAM V2 material transition is invalid")
}

fn private_oram_mutation_authority_corrupt(
    _error: PrivateOramMutationJournalError,
) -> StorageError {
    StorageError::service_error("private ORAM V2 mutation authority is inconsistent")
}

fn private_oram_state_last_mutation_id(
    state: &PrivateOramConsensusCollectionStateV2,
) -> Option<&str> {
    match &state.last_transition {
        PrivateOramConsensusTransitionV2::Genesis => None,
        PrivateOramConsensusTransitionV2::Mutation(receipt) => Some(&receipt.mutation_id),
    }
}

fn private_oram_consensus_state_index_digest(
    state: &PrivateOramConsensusCollectionStateV2,
) -> Result<String, StorageError> {
    let indexes = state
        .indexes
        .iter()
        .map(|index| {
            (
                private_oram_mutation_index_epoch_key(&state.collection_id, index),
                index.epoch.clone(),
            )
        })
        .collect::<Vec<_>>();
    canonical_private_oram_index_state_digest(&state.collection_id, &indexes)
}

fn validate_private_oram_mutation_lease(
    lease: &PrivateOramMutationLease,
) -> Result<(), StorageError> {
    if lease.generation == 0
        || lease.collection_id.is_empty()
        || lease.collection_id.len() > 1024
        || lease.writer_fence == 0
        || lease.expires_at_unix <= lease.issued_at_unix
        || lease.expires_at_unix - lease.issued_at_unix > PRIVATE_ORAM_MUTATION_LEASE_MAX_SECS
    {
        return Err(StorageError::bad_request(
            "private ORAM mutation lease is invalid",
        ));
    }
    for digest in [
        &lease.mutation_id,
        &lease.signed_mutation_digest,
        &lease.transition_digest,
        &lease.base_record_digest,
        &lease.writer_lease_digest,
    ] {
        validate_private_oram_consensus_digest(digest)
            .map_err(|_| StorageError::bad_request("private ORAM mutation lease is invalid"))?;
    }
    if let PrivateOramMutationLeasePhase::ConsensusCommitted {
        committed_record_digest,
        committed_signed_state_digest,
        receipt_digest,
        ..
    } = &lease.phase
    {
        for digest in [
            committed_record_digest,
            committed_signed_state_digest,
            receipt_digest,
        ] {
            validate_private_oram_consensus_digest(digest)
                .map_err(|_| StorageError::bad_request("private ORAM mutation lease is invalid"))?;
        }
    }
    Ok(())
}

fn private_oram_mutation_lease_has_same_identity(
    expected: &PrivateOramMutationLease,
    new: &PrivateOramMutationLease,
) -> bool {
    expected.generation == new.generation
        && expected.collection_id == new.collection_id
        && expected.owner_peer_id == new.owner_peer_id
        && expected.mutation_id == new.mutation_id
        && expected.signed_mutation_digest == new.signed_mutation_digest
        && expected.transition_digest == new.transition_digest
        && expected.base_record_digest == new.base_record_digest
        && expected.base_state_sequence == new.base_state_sequence
        && expected.writer_lease_digest == new.writer_lease_digest
        && expected.writer_fence == new.writer_fence
        && expected.issued_at_unix == new.issued_at_unix
}

fn validate_private_oram_mutation_clear_receipt(
    receipt: &PrivateOramMutationClearReceiptV1,
) -> Result<(), StorageError> {
    if receipt.version != PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION || receipt.generation == 0 {
        return Err(StorageError::bad_request(
            "private ORAM mutation clear receipt is invalid",
        ));
    }
    for digest in [
        &receipt.mutation_id,
        &receipt.terminal_state_digest,
        &receipt.reconciliation_digest,
    ] {
        validate_private_oram_consensus_digest(digest).map_err(|_| {
            StorageError::bad_request("private ORAM mutation clear receipt is invalid")
        })?;
    }
    Ok(())
}

fn validate_private_oram_mutation_lease_slot(
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<(), StorageError> {
    if slot.version != PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION
        || slot.generation != slot.max_writer_fence
    {
        return Err(StorageError::bad_request(
            "private ORAM mutation lease slot is invalid",
        ));
    }
    if let Some(receipt) = &slot.last_clear {
        validate_private_oram_mutation_clear_receipt(receipt)?;
        if receipt.generation > slot.generation {
            return Err(StorageError::bad_request(
                "private ORAM mutation lease slot is invalid",
            ));
        }
    }
    match &slot.active {
        Some(lease) => {
            validate_private_oram_mutation_lease(lease)?;
            if lease.generation != slot.generation
                || lease.writer_fence != slot.max_writer_fence
                || slot
                    .last_clear
                    .as_ref()
                    .is_some_and(|receipt| receipt.generation >= lease.generation)
            {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease slot is invalid",
                ));
            }
        }
        None if slot.generation == 0 => {
            if slot.last_clear.is_some() {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease slot is invalid",
                ));
            }
        }
        None => {
            if slot
                .last_clear
                .as_ref()
                .is_none_or(|receipt| receipt.generation != slot.generation)
            {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease slot is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_private_oram_mutation_lease_cas(
    operation: &CompareAndSwapPrivateOramMutationLease,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_key(&operation.key)?;
    validate_private_oram_mutation_lease_slot(&operation.expected)?;
    validate_private_oram_mutation_lease_slot(&operation.new)?;
    for lease in [
        operation.expected.active.as_ref(),
        operation.new.active.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if lease.collection_id != operation.key.collection_id {
            return Err(StorageError::bad_request(
                "private ORAM mutation lease CAS is invalid",
            ));
        }
    }
    let transition_is_valid = match (&operation.expected.active, &operation.new.active) {
        (None, Some(new)) => {
            operation.expected.generation.checked_add(1) == Some(operation.new.generation)
                && operation.expected.max_writer_fence.checked_add(1)
                    == Some(operation.new.max_writer_fence)
                && operation.expected.last_clear == operation.new.last_clear
                && new.generation == operation.new.generation
                && new.writer_fence == operation.new.max_writer_fence
                && new.renewal_revision == 0
                && matches!(new.phase, PrivateOramMutationLeasePhase::Preparing)
        }
        (Some(expected), Some(new)) => {
            let shared_slot_is_unchanged = operation.expected.generation
                == operation.new.generation
                && operation.expected.max_writer_fence == operation.new.max_writer_fence
                && operation.expected.last_clear == operation.new.last_clear
                && private_oram_mutation_lease_has_same_identity(expected, new);
            let renewal_is_valid = expected.phase == new.phase
                && expected
                    .renewal_revision
                    .checked_add(1)
                    .is_some_and(|revision| revision == new.renewal_revision)
                && new.expires_at_unix > expected.expires_at_unix;
            let abort_decision_is_valid = matches!(
                (&expected.phase, &new.phase),
                (
                    PrivateOramMutationLeasePhase::Preparing,
                    PrivateOramMutationLeasePhase::AbortDecided
                )
            ) && new.renewal_revision == expected.renewal_revision
                && new.expires_at_unix == expected.expires_at_unix;
            shared_slot_is_unchanged && (renewal_is_valid || abort_decision_is_valid)
        }
        (Some(expected), None) => {
            let Some(clear) = operation.new.last_clear.as_ref() else {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease transition is invalid",
                ));
            };
            let (expected_outcome, terminal_state_digest) = match &expected.phase {
                PrivateOramMutationLeasePhase::AbortDecided => (
                    PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit,
                    expected.base_record_digest.as_str(),
                ),
                PrivateOramMutationLeasePhase::Preparing => {
                    return Err(StorageError::bad_request(
                        "private ORAM mutation lease transition is invalid",
                    ));
                }
                PrivateOramMutationLeasePhase::ConsensusCommitted {
                    committed_record_digest,
                    ..
                } => (
                    PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
                    committed_record_digest.as_str(),
                ),
            };
            operation.expected.generation == operation.new.generation
                && operation.expected.max_writer_fence == operation.new.max_writer_fence
                && clear.generation == expected.generation
                && clear.mutation_id == expected.mutation_id
                && clear.outcome == expected_outcome
                && clear.terminal_state_digest == terminal_state_digest
        }
        (None, None) => false,
    };
    if !transition_is_valid {
        return Err(StorageError::bad_request(
            "private ORAM mutation lease transition is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_mutation_slot_state_relationship(
    slot: &PrivateOramMutationLeaseSlotV2,
    state: &PrivateOramConsensusCollectionStateV2,
    key: &PrivateOramMutationKey,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_lease_slot(slot)?;
    let state_record_digest = canonical_private_oram_consensus_state_record_digest(state)?;
    if let Some(lease) = &slot.active {
        if lease.collection_id != key.collection_id {
            return Err(StorageError::bad_request(
                "private ORAM mutation lease state relationship is invalid",
            ));
        }
        match &lease.phase {
            PrivateOramMutationLeasePhase::Preparing
            | PrivateOramMutationLeasePhase::AbortDecided => {
                if lease.base_record_digest != state_record_digest
                    || lease.base_state_sequence != state.state_sequence
                {
                    return Err(StorageError::bad_request(
                        "private ORAM mutation lease state relationship is invalid",
                    ));
                }
            }
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                committed_state_sequence,
                committed_signed_state_digest,
                receipt_digest,
            } => {
                let PrivateOramConsensusTransitionV2::Mutation(receipt) = &state.last_transition
                else {
                    return Err(StorageError::bad_request(
                        "private ORAM mutation lease state relationship is invalid",
                    ));
                };
                if committed_record_digest != &state_record_digest
                    || *committed_state_sequence != state.state_sequence
                    || committed_signed_state_digest != &state.signed_state_digest
                    || receipt_digest != &canonical_private_oram_mutation_receipt_digest(receipt)?
                    || receipt.mutation_lease_generation != lease.generation
                    || receipt.mutation_id != lease.mutation_id
                    || receipt.signed_mutation_digest != lease.signed_mutation_digest
                    || receipt.transition_digest != lease.transition_digest
                    || receipt.writer_lease_digest != lease.writer_lease_digest
                    || receipt.writer_fence != lease.writer_fence
                {
                    return Err(StorageError::bad_request(
                        "private ORAM mutation lease state relationship is invalid",
                    ));
                }
            }
        }
    } else if let Some(clear) = &slot.last_clear {
        if clear.terminal_state_digest != state_record_digest {
            return Err(StorageError::bad_request(
                "private ORAM mutation lease state relationship is invalid",
            ));
        }
        if clear.outcome
            == PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit
        {
            let PrivateOramConsensusTransitionV2::Mutation(receipt) = &state.last_transition else {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease state relationship is invalid",
                ));
            };
            if receipt.mutation_lease_generation != clear.generation
                || receipt.mutation_id != clear.mutation_id
            {
                return Err(StorageError::bad_request(
                    "private ORAM mutation lease state relationship is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_apply_private_oram_mutation(
    operation: &ApplyPrivateOramMutation,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_key(&operation.key)?;
    if operation.mutation_lease_generation == 0 {
        return Err(StorageError::bad_request(
            "private ORAM mutation transition is invalid",
        ));
    }
    validate_private_oram_consensus_collection_state(&operation.expected_state)?;
    validate_private_oram_consensus_collection_state(&operation.new_state)?;

    let expected = &operation.expected_state;
    let new = &operation.new_state;
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &new.last_transition else {
        return Err(StorageError::bad_request(
            "private ORAM mutation transition is invalid",
        ));
    };
    let state_identity_is_valid = expected.collection_id == operation.key.collection_id
        && new.collection_id == operation.key.collection_id
        && expected.version == new.version
        && expected.manifest_digest == new.manifest_digest
        && expected.layout_generation == new.layout_generation
        && expected.layout_digest == new.layout_digest
        && expected
            .state_sequence
            .checked_add(1)
            .is_some_and(|sequence| sequence == new.state_sequence)
        && expected.signed_state_digest != new.signed_state_digest
        && expected.client_state_digest != new.client_state_digest
        && receipt.old_state_sequence == expected.state_sequence
        && receipt.old_state_digest == expected.signed_state_digest
        && receipt.new_state_sequence == new.state_sequence
        && receipt.new_state_digest == new.signed_state_digest
        && receipt.mutation_lease_generation == operation.mutation_lease_generation
        && receipt.writer_fence == operation.mutation_lease_generation
        && private_oram_state_last_mutation_id(expected)
            .is_none_or(|previous| previous != receipt.mutation_id)
        && canonical_private_oram_mutation_transition_digest(expected, new)
            .is_ok_and(|digest| digest == receipt.transition_digest);
    if !state_identity_is_valid || expected.indexes.len() != new.indexes.len() {
        return Err(StorageError::bad_request(
            "private ORAM mutation transition is invalid",
        ));
    }
    for (old_index, new_index) in expected.indexes.iter().zip(&new.indexes) {
        let same_capacity = old_index
            .logical_count
            .checked_add(old_index.dummy_count)
            .zip(new_index.logical_count.checked_add(new_index.dummy_count))
            .is_some_and(|(old_capacity, new_capacity)| old_capacity == new_capacity);
        if old_index.index_kind != new_index.index_kind
            || old_index.index_name != new_index.index_name
            || old_index
                .epoch
                .index_epoch
                .checked_add(1)
                .is_none_or(|epoch| epoch != new_index.epoch.index_epoch)
            || old_index.epoch.root_hash == new_index.epoch.root_hash
            || new_index.epoch.writeback_digest.is_none()
            || old_index.epoch.writeback_digest == new_index.epoch.writeback_digest
            || old_index
                .logical_count
                .checked_add(1)
                .is_none_or(|count| count != new_index.logical_count)
            || new_index
                .dummy_count
                .checked_add(1)
                .is_none_or(|count| count != old_index.dummy_count)
            || !same_capacity
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation transition is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_apply_private_oram_mutation_lease(
    operation: &ApplyPrivateOramMutation,
    expected_state: &PrivateOramConsensusCollectionStateV2,
    lease: &PrivateOramMutationLease,
) -> Result<(), StorageError> {
    validate_private_oram_mutation_lease(lease)?;
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &operation.new_state.last_transition
    else {
        return Err(StorageError::bad_request(
            "private ORAM mutation lease transition is invalid",
        ));
    };
    if !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing)
        || lease.generation != operation.mutation_lease_generation
        || lease.collection_id != operation.key.collection_id
        || lease.base_record_digest
            != canonical_private_oram_consensus_state_record_digest(expected_state)?
        || lease.base_state_sequence != expected_state.state_sequence
        || lease.mutation_id != receipt.mutation_id
        || lease.signed_mutation_digest != receipt.signed_mutation_digest
        || lease.transition_digest != receipt.transition_digest
        || lease.writer_lease_digest != receipt.writer_lease_digest
        || lease.writer_fence != receipt.writer_fence
    {
        return Err(StorageError::bad_request(
            "private ORAM mutation lease transition is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_external_recovery_cas(
    operation: &CompareAndSwapPrivateOramExternalRecovery,
) -> Result<(), StorageError> {
    validate_private_oram_external_recovery_key(&operation.key)?;
    if operation.expected.is_none() && operation.new.is_none() {
        return Err(invalid_private_oram_external_recovery_transition());
    }
    if let Some(expected) = &operation.expected {
        validate_private_oram_external_recovery_state(expected)?;
    }
    if let Some(new) = &operation.new {
        validate_private_oram_external_recovery_state(new)?;
    }

    match (&operation.expected, &operation.new) {
        (None, Some(new)) => {
            if new.committed_backup_generation != 0
                || new.committed_checkpoint_digest.is_some()
                || new.committed_install_intent_digest.is_some()
                || !new.active_lease.as_ref().is_some_and(|lease| {
                    lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                })
            {
                return Err(invalid_private_oram_external_recovery_transition());
            }
        }
        (Some(expected), None) => {
            if expected.committed_backup_generation != 0
                || !expected.active_lease.as_ref().is_some_and(|lease| {
                    lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                })
            {
                return Err(invalid_private_oram_external_recovery_transition());
            }
        }
        (Some(expected), Some(new))
            if new.committed_backup_generation == expected.committed_backup_generation =>
        {
            if new.committed_checkpoint_digest != expected.committed_checkpoint_digest
                || new.committed_install_intent_digest != expected.committed_install_intent_digest
            {
                return Err(invalid_private_oram_external_recovery_transition());
            }
            match (&expected.active_lease, &new.active_lease) {
                (None, Some(lease))
                    if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging => {}
                (Some(lease), None)
                    if expected.committed_backup_generation > 0
                        && lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging => {}
                (Some(expected_lease), Some(new_lease)) => {
                    validate_private_oram_external_recovery_lease_transition(
                        expected_lease,
                        new_lease,
                    )?;
                }
                _ => return Err(invalid_private_oram_external_recovery_transition()),
            }
        }
        (Some(expected), Some(new))
            if new.committed_backup_generation > expected.committed_backup_generation =>
        {
            let Some(active_lease) = &expected.active_lease else {
                return Err(invalid_private_oram_external_recovery_transition());
            };
            if new.committed_backup_generation != active_lease.backup_generation
                || new.committed_checkpoint_digest.as_deref()
                    != Some(active_lease.checkpoint_digest.as_str())
                || new.committed_install_intent_digest.as_deref()
                    != active_lease.install_intent_digest.as_deref()
                || active_lease.install_intent_digest.is_none()
                || new.active_lease.is_some()
                || active_lease.phase != PrivateOramExternalRecoveryLeasePhase::Installing
            {
                return Err(invalid_private_oram_external_recovery_transition());
            }
        }
        _ => return Err(invalid_private_oram_external_recovery_transition()),
    }
    Ok(())
}

fn validate_private_oram_external_recovery_key(
    key: &PrivateOramExternalRecoveryKey,
) -> Result<(), StorageError> {
    if key.collection_id.is_empty() || key.collection_id.len() > 1024 {
        return Err(StorageError::bad_request(
            "private ORAM external recovery key is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_external_recovery_state(
    state: &PrivateOramExternalRecoveryState,
) -> Result<(), StorageError> {
    let committed_digest_is_valid = match (
        state.committed_backup_generation,
        state.committed_checkpoint_digest.as_deref(),
        state.committed_install_intent_digest.as_deref(),
    ) {
        (0, None, None) => true,
        (0, _, _) | (_, None, _) => false,
        (_, Some(checkpoint_digest), install_intent_digest) => {
            validate_private_oram_consensus_digest(checkpoint_digest).is_ok()
                && install_intent_digest
                    .map(validate_private_oram_consensus_digest)
                    .transpose()
                    .is_ok()
        }
    };
    if !committed_digest_is_valid {
        return Err(invalid_private_oram_external_recovery_state());
    }
    if let Some(active_lease) = &state.active_lease {
        validate_private_oram_external_recovery_lease(active_lease)?;
        if active_lease.backup_generation <= state.committed_backup_generation {
            return Err(invalid_private_oram_external_recovery_state());
        }
    }
    Ok(())
}

fn validate_private_oram_external_recovery_lease(
    lease: &PrivateOramExternalRecoveryLease,
) -> Result<(), StorageError> {
    let install_intent_is_valid = match (lease.phase, lease.install_intent_digest.as_deref()) {
        (PrivateOramExternalRecoveryLeasePhase::Staging, None) => true,
        (PrivateOramExternalRecoveryLeasePhase::Installing, Some(digest)) => {
            validate_private_oram_consensus_digest(digest).is_ok()
        }
        _ => false,
    };
    let valid = lease.backup_generation > 0
        && validate_private_oram_consensus_digest(&lease.operation_id_hash).is_ok()
        && validate_private_oram_consensus_digest(&lease.checkpoint_digest).is_ok()
        && install_intent_is_valid
        && lease.expires_at_unix > lease.issued_at_unix
        && lease.expires_at_unix - lease.issued_at_unix
            <= PRIVATE_ORAM_EXTERNAL_RECOVERY_LEASE_MAX_SECS;
    if !valid {
        return Err(invalid_private_oram_external_recovery_state());
    }
    Ok(())
}

fn validate_private_oram_external_recovery_lease_transition(
    expected: &PrivateOramExternalRecoveryLease,
    new: &PrivateOramExternalRecoveryLease,
) -> Result<(), StorageError> {
    let same_recovery = expected.owner_peer_id == new.owner_peer_id
        && expected.operation_id_hash == new.operation_id_hash
        && expected.checkpoint_digest == new.checkpoint_digest
        && expected.backup_generation == new.backup_generation;
    let valid_renewal = same_recovery
        && new.phase == expected.phase
        && new.install_intent_digest == expected.install_intent_digest
        && new.issued_at_unix >= expected.issued_at_unix
        && new.expires_at_unix > expected.expires_at_unix;
    let valid_prepare = same_recovery
        && expected.phase == PrivateOramExternalRecoveryLeasePhase::Staging
        && new.phase == PrivateOramExternalRecoveryLeasePhase::Installing
        && expected.install_intent_digest.is_none()
        && new.install_intent_digest.is_some()
        && new.issued_at_unix == expected.issued_at_unix
        && new.expires_at_unix == expected.expires_at_unix;
    let valid_install_rollback = same_recovery
        && expected.phase == PrivateOramExternalRecoveryLeasePhase::Installing
        && new.phase == PrivateOramExternalRecoveryLeasePhase::Staging
        && expected.install_intent_digest.is_some()
        && new.install_intent_digest.is_none()
        && new.issued_at_unix == expected.issued_at_unix
        && new.expires_at_unix == expected.expires_at_unix;
    let valid_takeover = !same_recovery
        && expected.phase == PrivateOramExternalRecoveryLeasePhase::Staging
        && new.phase == PrivateOramExternalRecoveryLeasePhase::Staging
        && new.issued_at_unix >= expected.expires_at_unix;
    if !valid_renewal && !valid_prepare && !valid_install_rollback && !valid_takeover {
        return Err(invalid_private_oram_external_recovery_transition());
    }
    Ok(())
}

fn invalid_private_oram_external_recovery_state() -> StorageError {
    StorageError::bad_request("private ORAM external recovery state is invalid")
}

fn invalid_private_oram_external_recovery_transition() -> StorageError {
    StorageError::bad_request("private ORAM external recovery transition is invalid")
}

fn invalid_private_oram_external_recovery_operation() -> StorageError {
    StorageError::bad_request("private ORAM external recovery operation is invalid")
}

fn validate_private_oram_layout_cas(
    operation: &CompareAndSwapPrivateOramLayout,
) -> Result<(), StorageError> {
    validate_private_oram_layout_key(&operation.key)?;
    validate_private_oram_consensus_layout(&operation.new)?;
    match &operation.expected {
        Some(expected) => {
            validate_private_oram_consensus_layout(expected)?;
            if expected
                .generation
                .checked_add(1)
                .is_none_or(|next_generation| operation.new.generation != next_generation)
            {
                return Err(StorageError::bad_request(
                    "private ORAM consensus layout generation must increase by one",
                ));
            }
        }
        None if operation.new.generation != 1 => {
            return Err(StorageError::bad_request(
                "private ORAM consensus layout must start at generation one",
            ));
        }
        None => {}
    }
    Ok(())
}

fn validate_private_oram_shard_key_preinstalled_owners(
    change: &PrivateOramShardKeyLayoutChange,
    expected: &PrivateOramConsensusLayout,
    new: &PrivateOramConsensusLayout,
) -> Result<(), StorageError> {
    if change.preinstalled_new_owner_peer_ids.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS
        || change
            .preinstalled_new_owner_peer_ids
            .windows(2)
            .any(|owners| owners[0] >= owners[1])
    {
        return Err(invalid_private_oram_collection_layout_transition());
    }

    let expected_is_subset = expected
        .owner_peer_ids
        .iter()
        .all(|owner| new.owner_peer_ids.binary_search(owner).is_ok());
    let new_is_subset = new
        .owner_peer_ids
        .iter()
        .all(|owner| expected.owner_peer_ids.binary_search(owner).is_ok());
    let added_owners = new
        .owner_peer_ids
        .iter()
        .copied()
        .filter(|owner| expected.owner_peer_ids.binary_search(owner).is_err())
        .collect::<Vec<_>>();
    let valid = match change.kind {
        PrivateOramShardKeyLayoutChangeKind::Create => {
            expected_is_subset && added_owners == change.preinstalled_new_owner_peer_ids
        }
        PrivateOramShardKeyLayoutChangeKind::Drop => {
            new_is_subset && change.preinstalled_new_owner_peer_ids.is_empty()
        }
    };
    if !valid {
        return Err(invalid_private_oram_collection_layout_transition());
    }
    Ok(())
}

fn private_oram_epoch_key_order(key: &PrivateOramEpochKey) -> (u8, &[u8]) {
    let kind = match key.index_kind {
        PrivateOramIndexKind::Hnsw => 1,
        PrivateOramIndexKind::ResultPayload => 2,
    };
    (kind, key.index_name.as_bytes())
}

#[derive(Clone, Copy)]
enum PrivateOramTransferOperationKind {
    Start,
    Finish,
}

#[derive(Clone, Copy)]
enum PrivateOramReshardingPhase {
    Start,
    Finish,
}

fn private_oram_transfer_transition(
    collection_meta: &CollectionMetaOperations,
    kind: PrivateOramTransferOperationKind,
) -> Result<&collection::shards::transfer::PrivateOramTransferLayoutTransition, StorageError> {
    let CollectionMetaOperations::TransferShard(_, operation) = collection_meta else {
        return Err(invalid_private_oram_transfer_transition());
    };
    let transfer = match (kind, operation) {
        (PrivateOramTransferOperationKind::Start, ShardTransferOperations::Start(transfer))
        | (PrivateOramTransferOperationKind::Finish, ShardTransferOperations::Finish(transfer)) => {
            transfer
        }
        _ => return Err(invalid_private_oram_transfer_transition()),
    };
    transfer
        .private_oram_layout_transition
        .as_ref()
        .ok_or_else(invalid_private_oram_transfer_transition)
}

fn invalid_private_oram_collection_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM collection layout transition is invalid")
}

fn invalid_private_oram_transfer_transition() -> StorageError {
    StorageError::bad_request("private ORAM shard transfer layout transition is invalid")
}

fn invalid_private_oram_resharding_transition() -> StorageError {
    StorageError::bad_request("private ORAM resharding layout transition is invalid")
}

fn validate_private_oram_layout_key(key: &PrivateOramLayoutKey) -> Result<(), StorageError> {
    if key.collection_id.is_empty() || key.collection_id.len() > 1024 {
        return Err(StorageError::bad_request(
            "private ORAM consensus layout key is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_consensus_layout(
    layout: &PrivateOramConsensusLayout,
) -> Result<(), StorageError> {
    let owners_are_canonical = !layout.owner_peer_ids.is_empty()
        && layout.owner_peer_ids.len() <= PRIVATE_ORAM_LAYOUT_MAX_OWNERS
        && layout
            .owner_peer_ids
            .windows(2)
            .all(|owners| owners[0] < owners[1]);
    if layout.generation == 0 || !owners_are_canonical {
        return Err(StorageError::bad_request(
            "private ORAM consensus layout is invalid",
        ));
    }
    validate_private_oram_consensus_digest(&layout.layout_digest)
        .map_err(|_| StorageError::bad_request("private ORAM consensus layout is invalid"))?;
    validate_private_oram_consensus_digest(&layout.index_state_digest)
        .map_err(|_| StorageError::bad_request("private ORAM consensus layout is invalid"))?;
    Ok(())
}

fn validate_private_oram_session_lease_cas(
    operation: &CompareAndSwapPrivateOramSessionLease,
) -> Result<(), StorageError> {
    validate_private_oram_epoch_key(&operation.key)?;
    if operation.expected.is_none() && operation.new.is_none() {
        return Err(StorageError::bad_request(
            "private ORAM consensus session lease CAS is invalid",
        ));
    }
    if let Some(expected) = &operation.expected {
        validate_private_oram_session_lease(expected)?;
    }
    if let Some(new) = &operation.new {
        validate_private_oram_session_lease(new)?;
    }
    if let (Some(expected), Some(new)) = (&operation.expected, &operation.new) {
        let same_owner = expected.owner_peer_id == new.owner_peer_id
            && expected.lease_id_hash == new.lease_id_hash;
        let valid_renewal = same_owner
            && new.issued_at_unix >= expected.issued_at_unix
            && new.expires_at_unix > expected.expires_at_unix;
        let valid_takeover = !same_owner && new.issued_at_unix >= expected.expires_at_unix;
        if !valid_renewal && !valid_takeover {
            return Err(StorageError::bad_request(
                "private ORAM consensus session lease transition is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_private_oram_session_lease(
    lease: &PrivateOramSessionLease,
) -> Result<(), StorageError> {
    validate_private_oram_consensus_digest(&lease.lease_id_hash).map_err(|_| {
        StorageError::bad_request("private ORAM consensus session lease is invalid")
    })?;
    if lease.expires_at_unix <= lease.issued_at_unix
        || lease.expires_at_unix - lease.issued_at_unix > PRIVATE_ORAM_SESSION_LEASE_MAX_SECS
    {
        return Err(StorageError::bad_request(
            "private ORAM consensus session lease is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_consensus_root_hash(root_hash: &str) -> Result<(), StorageError> {
    if root_hash.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(StorageError::bad_request(
            "private ORAM consensus root hash is invalid",
        ));
    }
    let decoded = BASE64URL_NOPAD
        .decode(root_hash.as_bytes())
        .map_err(|_| StorageError::bad_request("private ORAM consensus root hash is invalid"))?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != root_hash {
        return Err(StorageError::bad_request(
            "private ORAM consensus root hash is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_consensus_writeback_digest(
    digest: Option<&str>,
) -> Result<(), StorageError> {
    let Some(digest) = digest else {
        return Ok(());
    };
    if digest.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(StorageError::bad_request(
            "private ORAM consensus writeback digest is invalid",
        ));
    }
    let decoded = BASE64URL_NOPAD.decode(digest.as_bytes()).map_err(|_| {
        StorageError::bad_request("private ORAM consensus writeback digest is invalid")
    })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != digest {
        return Err(StorageError::bad_request(
            "private ORAM consensus writeback digest is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_epoch_snapshot(
    epochs: &HashMap<String, PrivateOramConsensusEpoch>,
) -> Result<(), StorageError> {
    if epochs.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch snapshot is invalid",
        ));
    }
    for (key_digest, epoch) in epochs {
        validate_private_oram_consensus_digest(key_digest)?;
        validate_private_oram_consensus_root_hash(&epoch.root_hash)?;
        validate_private_oram_consensus_writeback_digest(epoch.writeback_digest.as_deref())?;
    }
    Ok(())
}

fn validate_private_oram_session_lease_snapshot(
    leases: &HashMap<String, PrivateOramSessionLease>,
) -> Result<(), StorageError> {
    if leases.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM consensus session lease snapshot is invalid",
        ));
    }
    for (key_digest, lease) in leases {
        validate_private_oram_consensus_digest(key_digest).map_err(|_| {
            StorageError::bad_request("private ORAM consensus session lease snapshot is invalid")
        })?;
        validate_private_oram_session_lease(lease).map_err(|_| {
            StorageError::bad_request("private ORAM consensus session lease snapshot is invalid")
        })?;
    }
    Ok(())
}

fn validate_private_oram_layout_snapshot(
    layouts: &HashMap<String, PrivateOramConsensusLayout>,
) -> Result<(), StorageError> {
    if layouts.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM consensus layout snapshot is invalid",
        ));
    }
    for (key_digest, layout) in layouts {
        validate_private_oram_consensus_digest(key_digest).map_err(|_| {
            StorageError::bad_request("private ORAM consensus layout snapshot is invalid")
        })?;
        validate_private_oram_consensus_layout(layout).map_err(|_| {
            StorageError::bad_request("private ORAM consensus layout snapshot is invalid")
        })?;
    }
    Ok(())
}

fn validate_private_oram_external_recovery_snapshot(
    recoveries: &HashMap<String, PrivateOramExternalRecoveryState>,
) -> Result<(), StorageError> {
    if recoveries.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM external recovery snapshot is invalid",
        ));
    }
    for (key_digest, state) in recoveries {
        validate_private_oram_consensus_digest(key_digest).map_err(|_| {
            StorageError::bad_request("private ORAM external recovery snapshot is invalid")
        })?;
        validate_private_oram_external_recovery_state(state).map_err(|_| {
            StorageError::bad_request("private ORAM external recovery snapshot is invalid")
        })?;
    }
    Ok(())
}

fn validate_private_oram_mutation_state_snapshot(
    states: &HashMap<String, PrivateOramConsensusCollectionStateV2>,
    epochs: &HashMap<String, PrivateOramConsensusEpoch>,
    layouts: &HashMap<String, PrivateOramConsensusLayout>,
) -> Result<(), StorageError> {
    if states.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM mutation state snapshot is invalid",
        ));
    }
    for (key_digest, state) in states {
        validate_private_oram_consensus_collection_state(state).map_err(|_| {
            StorageError::bad_request("private ORAM mutation state snapshot is invalid")
        })?;
        let key = PrivateOramMutationKey {
            collection_id: state.collection_id.clone(),
        };
        if key_digest != &private_oram_mutation_key_digest(&key) {
            return Err(StorageError::bad_request(
                "private ORAM mutation state snapshot is invalid",
            ));
        }
        let layout_key = PrivateOramLayoutKey {
            collection_id: state.collection_id.clone(),
        };
        let layout = layouts
            .get(&private_oram_layout_key_digest(&layout_key))
            .ok_or_else(|| {
                StorageError::bad_request("private ORAM mutation state snapshot is invalid")
            })?;
        if layout.generation != state.layout_generation
            || layout.layout_digest != state.layout_digest
            || layout.index_state_digest
                != private_oram_consensus_state_index_digest(state).map_err(|_| {
                    StorageError::bad_request("private ORAM mutation state snapshot is invalid")
                })?
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation state snapshot is invalid",
            ));
        }
        for index in &state.indexes {
            let epoch_key = private_oram_mutation_index_epoch_key(&state.collection_id, index);
            if epochs.get(&private_oram_epoch_key_digest(&epoch_key)) != Some(&index.epoch) {
                return Err(StorageError::bad_request(
                    "private ORAM mutation state snapshot is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_private_oram_mutation_lease_slot_snapshot(
    slots: &HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    states: &HashMap<String, PrivateOramConsensusCollectionStateV2>,
    layouts: &HashMap<String, PrivateOramConsensusLayout>,
    epochs: &HashMap<String, PrivateOramConsensusEpoch>,
    session_leases: &HashMap<String, PrivateOramSessionLease>,
    recoveries: &HashMap<String, PrivateOramExternalRecoveryState>,
) -> Result<(), StorageError> {
    if slots.len() != states.len() || slots.len() > PRIVATE_ORAM_EPOCH_MAX_RECORDS {
        return Err(StorageError::bad_request(
            "private ORAM mutation lease slot snapshot is invalid",
        ));
    }
    for (key_digest, wire) in slots {
        wire.validate().map_err(|_| {
            StorageError::bad_request("private ORAM mutation lease slot snapshot is invalid")
        })?;
        let slot = wire.lease_slot();
        let state = states.get(key_digest).ok_or_else(|| {
            StorageError::bad_request("private ORAM mutation lease slot snapshot is invalid")
        })?;
        let key = PrivateOramMutationKey {
            collection_id: state.collection_id.clone(),
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: state.collection_id.clone(),
        };
        let layout = layouts
            .get(&private_oram_layout_key_digest(&layout_key))
            .ok_or_else(|| {
                StorageError::bad_request("private ORAM mutation lease slot snapshot is invalid")
            })?;
        validate_private_oram_mutation_slot_state_relationship(slot, state, &key).map_err(
            |_| StorageError::bad_request("private ORAM mutation lease slot snapshot is invalid"),
        )?;
        let recovery_key = PrivateOramExternalRecoveryKey {
            collection_id: state.collection_id.clone(),
        };
        let has_active_recovery = recoveries
            .get(&private_oram_external_recovery_key_digest(&recovery_key))
            .and_then(|recovery| recovery.active_lease.as_ref())
            .is_some();
        let has_session = state.indexes.iter().any(|index| {
            let epoch_key = private_oram_mutation_index_epoch_key(&state.collection_id, index);
            let epoch_key_digest = private_oram_epoch_key_digest(&epoch_key);
            session_leases.contains_key(&epoch_key_digest)
                || epochs.get(&epoch_key_digest) != Some(&index.epoch)
        });
        if key_digest != &private_oram_mutation_key_digest(&key)
            || slot
                .active
                .as_ref()
                .is_some_and(|lease| !layout.owner_peer_ids.contains(&lease.owner_peer_id))
            || (has_active_recovery && slot.active.is_some())
            || has_session
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation lease slot snapshot is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_private_oram_mutation_authority_format_snapshot(
    slots: &HashMap<String, DecodedPrivateOramMutationAuthorityWireV2>,
    states: &HashMap<String, PrivateOramConsensusCollectionStateV2>,
    format_floor: Option<&PrivateOramMutationFormatFloorV2>,
    applied_index: u64,
) -> Result<(), StorageError> {
    let invalid =
        || StorageError::bad_request("private ORAM mutation authority format snapshot is invalid");
    let Some(format_floor) = format_floor else {
        if slots.values().any(|wire| wire.tagged_authority().is_some()) {
            return Err(invalid());
        }
        return Ok(());
    };

    validate_private_oram_mutation_format_floor_v2(format_floor).map_err(|_| invalid())?;
    if !format_floor.tagged_write_required() || format_floor.floor_applied_index() > applied_index {
        return Err(invalid());
    }

    for (key_digest, wire) in slots {
        let authority = wire.tagged_authority().ok_or_else(&invalid)?;
        let state = states.get(key_digest).ok_or_else(&invalid)?;
        let collection_key_digest =
            private_oram_collection_id_digest_v2(&state.collection_id).map_err(|_| invalid())?;
        let state_record_digest =
            canonical_private_oram_consensus_state_record_digest(state).map_err(|_| invalid())?;
        let expected_outer_binding = private_oram_mutation_outer_binding_digest_v2(
            &state.collection_id,
            &state_record_digest,
            authority.lease_slot(),
        )
        .map_err(|_| invalid())?;
        if authority.collection_key_digest() != collection_key_digest
            || authority.consensus_history_id_digest() != format_floor.consensus_history_id_digest()
            || authority.raft_group_id_digest() != format_floor.raft_group_id_digest()
            || authority.outer_binding_digest() != expected_outer_binding
        {
            return Err(invalid());
        }
        if authority.aggregate().is_some() {
            if !format_floor.activation_enabled() {
                return Err(invalid());
            }
            plan_private_oram_mutation_authority_floor_acceptance_v2(
                None,
                format_floor,
                authority,
                applied_index,
            )
            .map_err(|_| invalid())?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_private_oram_external_recovery_snapshot_transition(
    current: &HashMap<String, PrivateOramExternalRecoveryState>,
    incoming: &HashMap<String, PrivateOramExternalRecoveryState>,
) -> Result<(), StorageError> {
    validate_private_oram_external_recovery_snapshot_transition_inner(current, incoming, None)
}

pub(crate) fn validate_private_oram_external_recovery_snapshot_transition_for_peer(
    current: &HashMap<String, PrivateOramExternalRecoveryState>,
    incoming: &HashMap<String, PrivateOramExternalRecoveryState>,
    this_peer_id: PeerId,
) -> Result<(), StorageError> {
    validate_private_oram_external_recovery_snapshot_transition_inner(
        current,
        incoming,
        Some(this_peer_id),
    )
}

fn validate_private_oram_external_recovery_snapshot_transition_inner(
    current: &HashMap<String, PrivateOramExternalRecoveryState>,
    incoming: &HashMap<String, PrivateOramExternalRecoveryState>,
    this_peer_id: Option<PeerId>,
) -> Result<(), StorageError> {
    for (key, current_state) in current {
        let Some(incoming_state) = incoming.get(key) else {
            if current_state.committed_backup_generation == 0
                && !current_state.active_lease.as_ref().is_some_and(|lease| {
                    lease.phase == PrivateOramExternalRecoveryLeasePhase::Installing
                        && this_peer_id.is_none_or(|peer_id| lease.owner_peer_id == peer_id)
                })
            {
                continue;
            }
            return Err(StorageError::bad_request(
                "private ORAM external recovery snapshot would roll back committed state",
            ));
        };
        if incoming_state.committed_backup_generation < current_state.committed_backup_generation
            || incoming_state.committed_backup_generation
                == current_state.committed_backup_generation
                && (incoming_state.committed_checkpoint_digest
                    != current_state.committed_checkpoint_digest
                    || incoming_state.committed_install_intent_digest
                        != current_state.committed_install_intent_digest)
        {
            return Err(StorageError::bad_request(
                "private ORAM external recovery snapshot would roll back committed state",
            ));
        }
        if let Some(installing_lease) = current_state
            .active_lease
            .as_ref()
            .filter(|lease| lease.phase == PrivateOramExternalRecoveryLeasePhase::Installing)
        {
            if this_peer_id.is_some_and(|peer_id| installing_lease.owner_peer_id != peer_id) {
                continue;
            }
            let preserves_install =
                incoming_state
                    .active_lease
                    .as_ref()
                    .is_some_and(|incoming_lease| {
                        incoming_state.committed_backup_generation
                            == current_state.committed_backup_generation
                            && incoming_state.committed_checkpoint_digest
                                == current_state.committed_checkpoint_digest
                            && incoming_state.committed_install_intent_digest
                                == current_state.committed_install_intent_digest
                            && incoming_lease.phase
                                == PrivateOramExternalRecoveryLeasePhase::Installing
                            && incoming_lease.owner_peer_id == installing_lease.owner_peer_id
                            && incoming_lease.operation_id_hash
                                == installing_lease.operation_id_hash
                            && incoming_lease.checkpoint_digest
                                == installing_lease.checkpoint_digest
                            && incoming_lease.backup_generation
                                == installing_lease.backup_generation
                            && incoming_lease.install_intent_digest
                                == installing_lease.install_intent_digest
                            && incoming_lease.issued_at_unix >= installing_lease.issued_at_unix
                            && incoming_lease.expires_at_unix >= installing_lease.expires_at_unix
                    });
            let commits_install = incoming_state.committed_backup_generation
                == installing_lease.backup_generation
                && incoming_state.committed_checkpoint_digest.as_deref()
                    == Some(installing_lease.checkpoint_digest.as_str())
                && incoming_state.committed_install_intent_digest
                    == installing_lease.install_intent_digest
                && installing_lease.install_intent_digest.is_some();
            let rolls_back_install =
                incoming_state
                    .active_lease
                    .as_ref()
                    .is_some_and(|incoming_lease| {
                        incoming_state.committed_backup_generation
                            == current_state.committed_backup_generation
                            && incoming_state.committed_checkpoint_digest
                                == current_state.committed_checkpoint_digest
                            && incoming_state.committed_install_intent_digest
                                == current_state.committed_install_intent_digest
                            && incoming_lease.phase
                                == PrivateOramExternalRecoveryLeasePhase::Staging
                            && incoming_lease.owner_peer_id == installing_lease.owner_peer_id
                            && incoming_lease.operation_id_hash
                                == installing_lease.operation_id_hash
                            && incoming_lease.checkpoint_digest
                                == installing_lease.checkpoint_digest
                            && incoming_lease.backup_generation
                                == installing_lease.backup_generation
                            && incoming_lease.install_intent_digest.is_none()
                            && incoming_lease.issued_at_unix == installing_lease.issued_at_unix
                            && incoming_lease.expires_at_unix == installing_lease.expires_at_unix
                    });
            if !preserves_install
                && !commits_install
                && !(this_peer_id.is_some() && rolls_back_install)
            {
                return Err(StorageError::bad_request(
                    "private ORAM external recovery snapshot would roll back installing state",
                ));
            }
        }
    }
    Ok(())
}

fn validate_private_oram_consensus_digest(digest: &str) -> Result<(), StorageError> {
    if digest.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch snapshot is invalid",
        ));
    }
    let decoded = BASE64URL_NOPAD.decode(digest.as_bytes()).map_err(|_| {
        StorageError::bad_request("private ORAM consensus epoch snapshot is invalid")
    })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != digest {
        return Err(StorageError::bad_request(
            "private ORAM consensus epoch snapshot is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferIndexState,
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition, ShardTransfer,
        ShardTransferMethod,
    };
    use segment::types::ShardKey;
    use uuid::Uuid;

    use super::*;
    use crate::content_manager::consensus::private_oram_activation_authority::private_oram_activation_authority_fixture_v1_for_test;
    use crate::content_manager::consensus::private_oram_mutation_activation_barrier::{
        private_oram_mutation_activation_barrier_fixture_v2_for_test,
        private_oram_mutation_v3_floor_upgrade_fixture_for_test,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::append_reservation_v3::{
        encode_private_oram_mutation_append_reservation_v3,
        encode_private_oram_mutation_prepared_reservation_challenge_v3,
        private_oram_mutation_append_reservation_v3,
        private_oram_mutation_prepared_reservation_challenge_v3,
        private_oram_mutation_reservation_intent_v3,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::authority::{
        PrivateOramMutationAuthorityStateV2, activate_private_oram_mutation_authority_v2,
        private_oram_mutation_activation_context_for_test, private_oram_mutation_authority_key_v2,
        private_oram_mutation_legacy_authority_v2,
        private_oram_mutation_owner_enrollment_fixture_for_test,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::format::{
        PrivateOramMutationFormatFloorTestInputV2, private_oram_mutation_format_floor_for_test,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::owner_checkpoint::{
        private_oram_owner_checkpoint_reservation_binding_v1,
        private_oram_owner_checkpoint_reservation_context_v1,
    };
    use crate::content_manager::consensus::private_oram_mutation_recovery_capsules::{
        PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2,
        derive_private_oram_mutation_recovery_capsules_ready_v2,
        encode_private_oram_mutation_recovery_capsules_ready_v2,
        private_oram_owner_capsule_set_digest_v2,
    };
    use crate::content_manager::consensus::private_oram_mutation_watermark::{
        encode_private_oram_mutation_parent_watermark_expectation_v2,
        private_oram_mutation_parent_watermark_expectation_for_test,
        truncate_private_oram_mutation_parent_watermark_expectation_for_test,
    };
    use crate::content_manager::consensus_ops::{
        PrivateOramLayoutIndexStateBinding, PrivateOramLayoutLeaseBinding,
        PrivateOramReshardingLayoutTransition, PrivateOramShardKeyLayoutChange,
        PrivateOramShardLayoutEntry,
    };
    use crate::content_manager::private_oram_mutation_journal::{
        PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
        encode_private_oram_mutation_admission_recovery_manifest_v2,
        encode_private_oram_mutation_append_reservation_v2,
        encode_private_oram_owner_recovery_capsule_install_receipt_v2,
        private_oram_mutation_append_fixture_for_test,
        private_oram_mutation_append_fixture_with_owner_signer_seeds_for_test,
        private_oram_owner_recovery_capsule_install_receipt_for_test,
    };

    struct PrivateOramMutationFixture {
        key: PrivateOramMutationKey,
        layout_key: PrivateOramLayoutKey,
        layout: PrivateOramConsensusLayout,
        hnsw_key: PrivateOramEpochKey,
        result_key: PrivateOramEpochKey,
        old_state: PrivateOramConsensusCollectionStateV2,
        new_state: PrivateOramConsensusCollectionStateV2,
        genesis_slot: PrivateOramMutationLeaseSlotV2,
        preparing_slot: PrivateOramMutationLeaseSlotV2,
        committed_slot: PrivateOramMutationLeaseSlotV2,
    }

    struct ParentSyncFaultBackend {
        remaining_failures: std::sync::atomic::AtomicUsize,
    }

    struct PublishFaultBackend {
        expose_candidate: bool,
    }

    impl ParentSyncFaultBackend {
        fn new(remaining_failures: usize) -> Self {
            Self {
                remaining_failures: std::sync::atomic::AtomicUsize::new(remaining_failures),
            }
        }
    }

    impl PersistentSaveBackend for ParentSyncFaultBackend {
        fn publish(
            &self,
            candidate: tempfile::NamedTempFile,
            destination: &Path,
        ) -> io::Result<()> {
            FilesystemPersistentSaveBackend.publish(candidate, destination)
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            let injected = self
                .remaining_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            if injected {
                return Err(io::Error::other("injected parent-directory sync failure"));
            }
            FilesystemPersistentSaveBackend.sync_parent(parent)
        }
    }

    impl PersistentSaveBackend for PublishFaultBackend {
        fn publish(
            &self,
            candidate: tempfile::NamedTempFile,
            destination: &Path,
        ) -> io::Result<()> {
            if self.expose_candidate {
                FilesystemPersistentSaveBackend.publish(candidate, destination)?;
            }
            Err(io::Error::other("injected atomic publish failure"))
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            FilesystemPersistentSaveBackend.sync_parent(parent)
        }
    }

    fn test_digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn owner_capsule_install_evidence_for_test(
        collection_id: &str,
        mutation_id: &str,
        receipt: PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
        signer_seed: u8,
    ) -> PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2 {
        let receipt_canonical_json =
            encode_private_oram_owner_recovery_capsule_install_receipt_v2(&receipt).unwrap();
        let statement = qdrant_sec::PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
            protocol_version: qdrant_sec::PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
            collection_id: collection_id.to_string(),
            mutation_id: mutation_id.to_string(),
            parent_descriptor_digest: receipt.parent_descriptor_digest().to_string(),
            owner_peer_id: receipt.owner_peer_id(),
            activation_registry_generation: receipt.activation_authority().registry_generation(),
            activation_manifest_digest: receipt
                .activation_authority()
                .manifest_digest()
                .to_string(),
            capsule_digest: receipt.capsule_digest().to_string(),
            capsule_set_digest: receipt.capsule_set_digest().to_string(),
            receipt_digest: receipt.receipt_digest().to_string(),
            receipt_canonical_sha256: qdrant_sec::private_oram_owner_capsule_canonical_sha256_v2(
                &receipt_canonical_json,
            ),
        };
        let signer =
            ring::signature::Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32]).unwrap();
        let attestation = qdrant_sec::sign_private_oram_owner_capsule_install_attestation_v2(
            &signer, 1, &statement,
        )
        .unwrap();
        PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2::from_signed_attestation(
            receipt,
            attestation,
        )
        .unwrap()
    }

    fn mutation_format_floor(
        format_epoch: u64,
        activation_enabled: bool,
        index: u64,
    ) -> PrivateOramMutationFormatFloorV2 {
        private_oram_mutation_format_floor_for_test(PrivateOramMutationFormatFloorTestInputV2 {
            consensus_history_id_digest: test_digest(1),
            raft_group_id_digest: test_digest(2),
            format_epoch,
            minimum_reader_protocol: 2,
            minimum_writer_protocol: 2,
            snapshot_format_epoch: 2,
            membership_generation: 1,
            eligible_peer_set_digest: test_digest(3),
            eligible_process_incarnations_digest: test_digest(4),
            capability_manifest_digest: test_digest(5),
            activation_enabled,
            term: 1,
            index,
        })
        .unwrap()
    }

    fn mutation_legacy_authority(
        fixture: &PrivateOramMutationFixture,
    ) -> PrivateOramMutationAuthorityStateV2 {
        let state_record_digest =
            canonical_private_oram_consensus_state_record_digest(&fixture.old_state).unwrap();
        let outer_binding_digest = private_oram_mutation_outer_binding_digest_v2(
            &fixture.key.collection_id,
            &state_record_digest,
            &fixture.genesis_slot,
        )
        .unwrap();
        private_oram_mutation_legacy_authority_v2(
            private_oram_mutation_authority_key_v2(
                &fixture.key.collection_id,
                test_digest(1),
                test_digest(2),
                test_digest(30),
            )
            .unwrap(),
            fixture.genesis_slot.clone(),
            outer_binding_digest,
        )
        .unwrap()
    }

    fn install_tagged_legacy_floor(
        persistent: &mut Persistent,
        fixture: &PrivateOramMutationFixture,
    ) -> PrivateOramMutationAuthorityStateV2 {
        let legacy = mutation_legacy_authority(fixture);
        persistent.private_oram_mutation_lease_slots.insert(
            private_oram_mutation_key_digest(&fixture.key),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(legacy.clone()),
        );
        persistent.private_oram_mutation_format_floor = Some(mutation_format_floor(1, false, 1));
        persistent.state.hard_state.commit = 1;
        persistent.latest_snapshot_meta.index = 1;
        persistent.apply_progress_queue.set_from_snapshot(1);
        legacy
    }

    fn private_oram_mutation_fixture() -> PrivateOramMutationFixture {
        let collection_id = "collection-uuid-private-oram-mutation".to_string();
        let key = PrivateOramMutationKey {
            collection_id: collection_id.clone(),
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.clone(),
        };
        let layout_digest = test_digest(50);
        let hnsw_key = PrivateOramEpochKey {
            collection_id: collection_id.clone(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let result_key = PrivateOramEpochKey {
            collection_id: collection_id.clone(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let old_hnsw_epoch = PrivateOramConsensusEpoch {
            index_epoch: 11,
            root_hash: test_digest(11),
            writeback_digest: Some(test_digest(12)),
        };
        let old_result_epoch = PrivateOramConsensusEpoch {
            index_epoch: 21,
            root_hash: test_digest(21),
            writeback_digest: Some(test_digest(22)),
        };
        let old_state = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: test_digest(60),
            layout_generation: 1,
            layout_digest: layout_digest.clone(),
            state_sequence: 0,
            signed_state_digest: test_digest(10),
            indexes: vec![
                PrivateOramConsensusCollectionIndexStateV2 {
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: "text".to_string(),
                    epoch: old_hnsw_epoch,
                    logical_count: 4,
                    dummy_count: 6,
                },
                PrivateOramConsensusCollectionIndexStateV2 {
                    index_kind: PrivateOramIndexKind::ResultPayload,
                    index_name: String::new(),
                    epoch: old_result_epoch,
                    logical_count: 4,
                    dummy_count: 6,
                },
            ],
            client_state_digest: test_digest(30),
            last_transition: PrivateOramConsensusTransitionV2::Genesis,
        };
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest,
            index_state_digest: private_oram_consensus_state_index_digest(&old_state).unwrap(),
        };
        let mutation_receipt = PrivateOramMutationReceiptV2 {
            version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
            mutation_id: test_digest(20),
            signed_mutation_digest: test_digest(40),
            transition_digest: test_digest(99),
            old_state_sequence: old_state.state_sequence,
            old_state_digest: old_state.signed_state_digest.clone(),
            new_state_sequence: old_state.state_sequence + 1,
            new_state_digest: test_digest(31),
            point_operation_digest: test_digest(41),
            writer_lease_digest: test_digest(42),
            writer_fence: 1,
            mutation_lease_generation: 1,
        };
        let mut new_state = PrivateOramConsensusCollectionStateV2 {
            state_sequence: old_state.state_sequence + 1,
            signed_state_digest: mutation_receipt.new_state_digest.clone(),
            indexes: vec![
                PrivateOramConsensusCollectionIndexStateV2 {
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: "text".to_string(),
                    epoch: PrivateOramConsensusEpoch {
                        index_epoch: 12,
                        root_hash: test_digest(13),
                        writeback_digest: Some(test_digest(14)),
                    },
                    logical_count: 5,
                    dummy_count: 5,
                },
                PrivateOramConsensusCollectionIndexStateV2 {
                    index_kind: PrivateOramIndexKind::ResultPayload,
                    index_name: String::new(),
                    epoch: PrivateOramConsensusEpoch {
                        index_epoch: 22,
                        root_hash: test_digest(23),
                        writeback_digest: Some(test_digest(24)),
                    },
                    logical_count: 5,
                    dummy_count: 5,
                },
            ],
            client_state_digest: test_digest(32),
            last_transition: PrivateOramConsensusTransitionV2::Mutation(mutation_receipt),
            ..old_state.clone()
        };
        let transition_digest =
            canonical_private_oram_mutation_transition_digest(&old_state, &new_state).unwrap();
        let mutation_receipt = match &mut new_state.last_transition {
            PrivateOramConsensusTransitionV2::Mutation(receipt) => {
                receipt.transition_digest = transition_digest;
                receipt.clone()
            }
            PrivateOramConsensusTransitionV2::Genesis => unreachable!(),
        };
        let preparing_lease = PrivateOramMutationLease {
            generation: 1,
            collection_id,
            owner_peer_id: 7,
            mutation_id: mutation_receipt.mutation_id.clone(),
            signed_mutation_digest: mutation_receipt.signed_mutation_digest.clone(),
            transition_digest: mutation_receipt.transition_digest.clone(),
            base_record_digest: canonical_private_oram_consensus_state_record_digest(&old_state)
                .unwrap(),
            base_state_sequence: old_state.state_sequence,
            writer_lease_digest: mutation_receipt.writer_lease_digest.clone(),
            writer_fence: mutation_receipt.writer_fence,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let committed_lease = PrivateOramMutationLease {
            phase: PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest: canonical_private_oram_consensus_state_record_digest(
                    &new_state,
                )
                .unwrap(),
                committed_state_sequence: new_state.state_sequence,
                committed_signed_state_digest: new_state.signed_state_digest.clone(),
                receipt_digest: canonical_private_oram_mutation_receipt_digest(&mutation_receipt)
                    .unwrap(),
            },
            ..preparing_lease.clone()
        };
        let genesis_slot = PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 0,
            active: None,
            last_clear: None,
            max_writer_fence: 0,
        };
        let preparing_slot = PrivateOramMutationLeaseSlotV2 {
            generation: 1,
            active: Some(preparing_lease),
            max_writer_fence: 1,
            ..genesis_slot.clone()
        };
        let committed_slot = PrivateOramMutationLeaseSlotV2 {
            active: Some(committed_lease),
            ..preparing_slot.clone()
        };
        PrivateOramMutationFixture {
            key,
            layout_key,
            layout,
            hnsw_key,
            result_key,
            old_state,
            new_state,
            genesis_slot,
            preparing_slot,
            committed_slot,
        }
    }

    fn install_private_oram_mutation_outer_fixture(
        persistent: &mut Persistent,
        fixture: &PrivateOramMutationFixture,
    ) {
        for (key, epoch) in [
            (
                fixture.hnsw_key.clone(),
                fixture.old_state.indexes[0].epoch.clone(),
            ),
            (
                fixture.result_key.clone(),
                fixture.old_state.indexes[1].epoch.clone(),
            ),
        ] {
            persistent
                .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                    key,
                    expected: None,
                    new: epoch,
                })
                .unwrap();
        }
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: fixture.layout_key.clone(),
                expected: None,
                new: fixture.layout.clone(),
            })
            .unwrap();
    }

    fn install_private_oram_mutation_fixture(
        persistent: &mut Persistent,
        fixture: &PrivateOramMutationFixture,
    ) {
        install_private_oram_mutation_outer_fixture(persistent, fixture);
        persistent
            .initialize_private_oram_mutation_state(&InitializePrivateOramMutationState {
                key: fixture.key.clone(),
                state: fixture.old_state.clone(),
            })
            .unwrap();
    }

    #[test]
    fn private_oram_activation_authority_cas_is_store_bound_stale_safe_and_persistent() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let mut first = Persistent::load_or_init(first_dir.path(), true, false, Some(7)).unwrap();
        let second = Persistent::load_or_init(second_dir.path(), true, false, Some(9)).unwrap();

        let foreign = second
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        assert!(foreign.is_empty());
        assert!(
            first
                .compare_and_swap_private_oram_activation_authority(
                    foreign,
                    &bundle,
                    &trust_anchor,
                )
                .is_err()
        );
        assert!(first.private_oram_activation_authority.is_none());

        let stale = first
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        let expected = first
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        first
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        let installed = first.private_oram_activation_authority.clone().unwrap();
        assert_eq!(installed.registry_generation(), 1);
        assert!(
            first
                .compare_and_swap_private_oram_activation_authority(stale, &bundle, &trust_anchor,)
                .is_err()
        );

        drop(first);
        let missing_anchor_error = Persistent::load_or_init(first_dir.path(), true, false, Some(7))
            .unwrap_err()
            .to_string();
        assert!(missing_anchor_error.contains("requires an external trust anchor"));
        let reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                first_dir.path(),
                true,
                false,
                Some(7),
                &trust_anchor,
            )
            .unwrap();
        assert_eq!(
            reloaded.private_oram_activation_authority.as_ref(),
            Some(&installed),
        );
        let current = reloaded
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        assert_eq!(current.locator().unwrap(), installed.locator());
    }

    #[test]
    fn startup_installs_a_consecutive_activation_authority_capability_successor() {
        let (authority_key, trust_anchor, genesis) =
            private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let first = Persistent::load_or_init_with_private_oram_mutation_v2_activation(
            temp.path(),
            true,
            false,
            Some(7),
            &trust_anchor,
            &genesis,
        )
        .unwrap();
        let installed = first
            .private_oram_activation_authority
            .as_ref()
            .unwrap()
            .clone();
        drop(first);

        let mut successor_manifest = installed.manifest().clone();
        successor_manifest.registry_generation += 1;
        successor_manifest.parent_manifest_digest = Some(installed.manifest_digest().to_string());
        successor_manifest.required_binary_capability_digest = test_digest(91);
        let successor = qdrant_sec::package_private_oram_activation_authority_manifest_v1(
            &authority_key,
            successor_manifest.authority_key_epoch,
            successor_manifest,
        )
        .unwrap();
        let upgraded = Persistent::load_or_init_with_private_oram_mutation_v2_activation(
            temp.path(),
            true,
            false,
            Some(7),
            &trust_anchor,
            &successor,
        )
        .unwrap();
        let durable = upgraded.private_oram_activation_authority.as_ref().unwrap();
        assert_eq!(durable.registry_generation(), 2);
        assert_eq!(durable.bundle(), &successor);
        drop(upgraded);

        let reloaded = Persistent::load_or_init_with_private_oram_mutation_v2_activation(
            temp.path(),
            true,
            false,
            Some(7),
            &trust_anchor,
            &successor,
        )
        .unwrap();
        assert_eq!(
            reloaded
                .private_oram_activation_authority
                .as_ref()
                .unwrap()
                .bundle(),
            &successor,
        );
    }

    #[test]
    fn private_oram_activation_authority_definitive_save_failure_rolls_back_memory() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent.path = temp.path().join("missing-parent").join(STATE_FILE_NAME);

        assert!(
            persistent
                .compare_and_swap_private_oram_activation_authority(
                    expected,
                    &bundle,
                    &trust_anchor,
                )
                .is_err()
        );
        assert!(persistent.private_oram_activation_authority.is_none());
    }

    #[test]
    fn private_oram_activation_authority_indeterminate_save_keeps_candidate_and_fences_peer() {
        let (key_pair, trust_anchor, bundle) =
            private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        let candidate = plan_private_oram_activation_authority_cas_v1(
            persistent.private_oram_activation_authority.as_ref(),
            expected,
            &bundle,
            &trust_anchor,
            persistent.private_oram_activation_authority_store_instance,
        )
        .unwrap();
        let previous = persistent
            .private_oram_activation_authority
            .replace(candidate.clone());
        let current_before_fence = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        let mut successor_manifest = candidate.manifest().clone();
        successor_manifest.registry_generation += 1;
        successor_manifest.parent_manifest_digest = Some(candidate.manifest_digest().to_string());
        let successor = qdrant_sec::package_private_oram_activation_authority_manifest_v1(
            &key_pair,
            successor_manifest.authority_key_epoch,
            successor_manifest,
        )
        .unwrap();

        assert!(
            persistent
                .save_or_rollback_on_definitive_with_backend(
                    &PublishFaultBackend {
                        expose_candidate: false,
                    },
                    move |persistent| {
                        persistent.private_oram_activation_authority = previous;
                    },
                )
                .is_err()
        );
        assert_eq!(
            persistent.private_oram_activation_authority.as_ref(),
            Some(&candidate),
        );
        assert!(persistent.save_indeterminate.load(Ordering::Acquire));
        assert!(persistent.save().is_err());
        assert!(
            persistent
                .private_oram_activation_authority_at_read(&trust_anchor)
                .is_err()
        );
        assert!(
            persistent
                .compare_and_swap_private_oram_activation_authority(
                    current_before_fence,
                    &successor,
                    &trust_anchor,
                )
                .is_err()
        );
        assert_eq!(
            persistent.private_oram_activation_authority.as_ref(),
            Some(&candidate),
        );
    }

    #[test]
    fn private_oram_activation_authority_tamper_fails_closed_on_restart() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        let path = persistent.path.clone();
        drop(persistent);

        let mut encoded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        encoded["private_oram_activation_authority"]["manifest_digest"] =
            serde_json::json!("private-oram-authority-tamper-sentinel");
        fs::write(&path, serde_json::to_vec_pretty(&encoded).unwrap()).unwrap();

        let error = Persistent::load_or_init(temp.path(), true, false, Some(7))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("activation authority snapshot is invalid"),
            "unexpected redacted restart error: {error}"
        );
        assert!(!error.contains("private-oram-authority-tamper-sentinel"));
    }

    #[test]
    fn private_oram_activation_authority_restart_rejects_shape_valid_bad_signature() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        let path = persistent.path.clone();
        drop(persistent);

        let mut encoded: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        encoded["private_oram_activation_authority"]["bundle"]["manifest"]["required_binary_capability_digest"] =
            serde_json::json!(BASE64URL_NOPAD.encode(&[73; 32]));
        let tampered_bundle: PrivateOramActivationAuthorityBundleV1 =
            serde_json::from_value(encoded["private_oram_activation_authority"]["bundle"].clone())
                .unwrap();
        encoded["private_oram_activation_authority"]["manifest_digest"] = serde_json::json!(
            qdrant_sec::private_oram_activation_authority_manifest_digest_v1(
                &tampered_bundle.manifest,
            )
            .unwrap()
        );
        encoded["private_oram_activation_authority"]["bundle"]["signature"]["sig"] =
            serde_json::json!(BASE64URL_NOPAD.encode(&[74; 64]));
        fs::write(&path, serde_json::to_vec_pretty(&encoded).unwrap()).unwrap();

        let error = Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
            temp.path(),
            true,
            false,
            Some(7),
            &trust_anchor,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("activation authority signature is invalid"));
    }

    #[test]
    fn private_oram_activation_authority_wrong_anchor_does_not_poison_anchor_pin() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        let path = persistent.path.clone();
        drop(persistent);

        let loaded = Persistent::load_json(path).unwrap();
        let wrong_key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[91; 32]).unwrap();
        let wrong_authority =
            qdrant_sec::private_oram_activation_authority_public_key_v1(&wrong_key, 1).unwrap();
        let wrong_anchor =
            PrivateOramActivationAuthorityTrustAnchorV1::from_external_configuration(
                wrong_authority,
                trust_anchor.cluster_identity_digest().to_string(),
                trust_anchor.cluster_first_voter_peer_id(),
            )
            .unwrap();

        assert!(
            loaded
                .configure_private_oram_activation_authority_trust_anchor(&wrong_anchor)
                .is_err()
        );
        assert!(
            loaded
                .private_oram_activation_authority_trust_anchor
                .get()
                .is_none()
        );

        loaded
            .configure_private_oram_activation_authority_trust_anchor(&trust_anchor)
            .unwrap();
        assert_eq!(
            loaded.private_oram_activation_authority_trust_anchor.get(),
            Some(&trust_anchor),
        );
        assert!(
            loaded
                .private_oram_activation_authority_at_read(&trust_anchor)
                .unwrap()
                .locator()
                .is_some()
        );
    }

    #[test]
    fn private_oram_activation_authority_blocks_in_place_raft_reinit() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let temp = tempfile::tempdir().unwrap();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        drop(persistent);

        let error = Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
            temp.path(),
            false,
            true,
            None,
            &trust_anchor,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(
                "Raft reinitialization cannot discard private ORAM activation or mutation format authority"
            ),
            "unexpected redacted reinitialization error: {error}"
        );
        let reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                None,
                &trust_anchor,
            )
            .unwrap();
        assert!(reloaded.private_oram_activation_authority.is_some());
    }

    #[test]
    fn private_oram_activation_authority_absence_is_legacy_serde_default() {
        let persistent = Persistent::default();
        let encoded = serde_json::to_value(&persistent).unwrap();
        assert!(encoded.get("private_oram_activation_authority").is_none());
        let decoded: Persistent = serde_json::from_value(encoded).unwrap();
        assert!(decoded.private_oram_activation_authority.is_none());
        assert_ne!(
            decoded.private_oram_activation_authority_store_instance,
            persistent.private_oram_activation_authority_store_instance,
        );
    }

    #[test]
    fn persistent_debug_redacts_peer_and_cluster_metadata_values() {
        let mut peer_address_by_id = PeerAddressById::new();
        peer_address_by_id.insert(
            7,
            "http://qdrant-sec-peer-address-sentinel:6335"
                .parse()
                .unwrap(),
        );

        let mut peer_metadata_by_id = PeerMetadataById::new();
        peer_metadata_by_id.insert(
            7,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "qdrant-sec-peer-fingerprint-sentinel".to_string(),
            )),
        );

        let mut cluster_metadata = HashMap::new();
        cluster_metadata.insert(
            "crypto_policy".to_string(),
            serde_json::json!("qdrant-sec-cluster-metadata-sentinel"),
        );

        let private_oram_key = PrivateOramEpochKey {
            collection_id: "qdrant-sec-private-oram-collection-sentinel".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "qdrant-sec-private-oram-vector-sentinel".to_string(),
        };
        let private_oram_root = BASE64URL_NOPAD.encode(b"private-oram-root-hash-sentinel");
        let private_oram_epochs = HashMap::from([(
            private_oram_epoch_key_digest(&private_oram_key),
            PrivateOramConsensusEpoch {
                index_epoch: 42,
                root_hash: private_oram_root.clone(),
                writeback_digest: None,
            },
        )]);
        let private_oram_layout_key = PrivateOramLayoutKey {
            collection_id: "qdrant-sec-private-oram-layout-collection-sentinel".to_string(),
        };
        let private_oram_layout_digest = BASE64URL_NOPAD.encode(&[51; 32]);
        let private_oram_index_state_digest = BASE64URL_NOPAD.encode(&[52; 32]);
        let private_oram_layouts = HashMap::from([(
            private_oram_layout_key_digest(&private_oram_layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids: vec![7, 9],
                layout_digest: private_oram_layout_digest.clone(),
                index_state_digest: private_oram_index_state_digest.clone(),
            },
        )]);

        let persistent = Persistent {
            state: RaftState::default(),
            latest_snapshot_meta: SnapshotMetadataSer::default(),
            apply_progress_queue: EntryApplyProgressQueue::default(),
            first_voter: Some(7),
            peer_address_by_id: Arc::new(RwLock::new(peer_address_by_id)),
            peer_metadata_by_id: Arc::new(RwLock::new(peer_metadata_by_id)),
            cluster_metadata,
            private_oram_activation_authority: None,
            private_oram_epochs,
            private_oram_session_leases: Default::default(),
            private_oram_layouts,
            private_oram_external_recoveries: Default::default(),
            private_oram_mutation_states: Default::default(),
            private_oram_mutation_lease_slots: Default::default(),
            private_oram_mutation_format_floor: None,
            private_oram_mutation_activation_pending: None,
            this_peer_id: 7,
            private_oram_activation_authority_store_instance: Default::default(),
            private_oram_activation_authority_trust_anchor: Default::default(),
            path: PathBuf::from("/tmp/qdrant-sec-persistent-state"),
            persistence_transaction: Default::default(),
            dirty: AtomicBool::new(false),
            save_indeterminate: AtomicBool::new(false),
        };

        let rendered = format!("{persistent:?}");

        assert!(rendered.contains("peer_address_count: 1"), "{rendered}");
        assert!(
            rendered.contains("peer_crypto_runtime_capability_fingerprint_count: 1"),
            "{rendered}",
        );
        assert!(rendered.contains("crypto_policy"), "{rendered}");
        assert!(
            rendered.contains("private_oram_epoch_count: 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("private_oram_layout_count: 1"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-peer-address-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-peer-fingerprint-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-cluster-metadata-sentinel"),
            "{rendered}",
        );
        assert!(!rendered.contains(&private_oram_root), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-private-oram-collection-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-private-oram-vector-sentinel"),
            "{rendered}",
        );
        assert!(
            !rendered.contains(&private_oram_layout_digest),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&private_oram_index_state_digest),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-private-oram-layout-collection-sentinel"),
            "{rendered}"
        );
    }

    fn private_oram_mutation_acquire(
        fixture: &PrivateOramMutationFixture,
    ) -> CompareAndSwapPrivateOramMutationLease {
        CompareAndSwapPrivateOramMutationLease {
            key: fixture.key.clone(),
            expected: fixture.genesis_slot.clone(),
            new: fixture.preparing_slot.clone(),
        }
    }

    fn private_oram_mutation_apply(
        fixture: &PrivateOramMutationFixture,
    ) -> ApplyPrivateOramMutation {
        ApplyPrivateOramMutation {
            key: fixture.key.clone(),
            mutation_lease_generation: 1,
            expected_state: fixture.old_state.clone(),
            new_state: fixture.new_state.clone(),
        }
    }

    fn private_oram_mutation_abort_decided_slot(
        fixture: &PrivateOramMutationFixture,
    ) -> PrivateOramMutationLeaseSlotV2 {
        let mut lease = fixture.preparing_slot.active.clone().unwrap();
        lease.phase = PrivateOramMutationLeasePhase::AbortDecided;
        PrivateOramMutationLeaseSlotV2 {
            active: Some(lease),
            ..fixture.preparing_slot.clone()
        }
    }

    fn private_oram_mutation_cleared_slot(
        active_slot: &PrivateOramMutationLeaseSlotV2,
        state: &PrivateOramConsensusCollectionStateV2,
        outcome: PrivateOramMutationClearOutcome,
        reconciliation_byte: u8,
    ) -> PrivateOramMutationLeaseSlotV2 {
        let lease = active_slot.active.as_ref().unwrap();
        PrivateOramMutationLeaseSlotV2 {
            active: None,
            last_clear: Some(PrivateOramMutationClearReceiptV1 {
                version: PRIVATE_ORAM_MUTATION_CLEAR_RECEIPT_VERSION,
                generation: lease.generation,
                mutation_id: lease.mutation_id.clone(),
                outcome,
                terminal_state_digest: canonical_private_oram_consensus_state_record_digest(state)
                    .unwrap(),
                reconciliation_digest: test_digest(reconciliation_byte),
            }),
            ..active_slot.clone()
        }
    }

    #[test]
    fn private_oram_mutation_lease_slot_prevents_aba_and_requires_clear_tombstone() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        let acquire = private_oram_mutation_acquire(&fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&acquire)
            .unwrap();

        let invalid_clear = PrivateOramMutationLeaseSlotV2 {
            active: None,
            ..fixture.preparing_slot.clone()
        };
        let missing_tombstone = persistent
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key.clone(),
                expected: fixture.preparing_slot.clone(),
                new: invalid_clear,
            })
            .unwrap_err();
        assert!(missing_tombstone.to_string().contains("slot is invalid"));

        let cleared = private_oram_mutation_cleared_slot(
            &fixture.preparing_slot,
            &fixture.old_state,
            PrivateOramMutationClearOutcome::AbortedBeforeConsensusCommit,
            92,
        );
        let unsafe_clear = CompareAndSwapPrivateOramMutationLease {
            key: fixture.key.clone(),
            expected: fixture.preparing_slot.clone(),
            new: cleared.clone(),
        };
        let unsafe_clear_error = persistent
            .compare_and_swap_private_oram_mutation_lease(&unsafe_clear)
            .unwrap_err();
        assert!(
            unsafe_clear_error
                .to_string()
                .contains("transition is invalid")
        );

        let abort_decided = private_oram_mutation_abort_decided_slot(&fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key.clone(),
                expected: fixture.preparing_slot.clone(),
                new: abort_decided.clone(),
            })
            .unwrap();
        let clear = CompareAndSwapPrivateOramMutationLease {
            key: fixture.key.clone(),
            expected: abort_decided,
            new: cleared.clone(),
        };
        persistent
            .compare_and_swap_private_oram_mutation_lease(&clear)
            .unwrap();

        let delayed_acquire = persistent
            .compare_and_swap_private_oram_mutation_lease(&acquire)
            .unwrap_err();
        assert!(delayed_acquire.to_string().contains("precondition failed"));

        let mut next_lease = fixture.preparing_slot.active.clone().unwrap();
        next_lease.generation = 2;
        next_lease.mutation_id = test_digest(90);
        next_lease.signed_mutation_digest = test_digest(91);
        next_lease.transition_digest = test_digest(93);
        next_lease.writer_lease_digest = test_digest(94);
        next_lease.writer_fence = 2;
        next_lease.issued_at_unix = 300;
        next_lease.expires_at_unix = 400;
        let next_preparing = PrivateOramMutationLeaseSlotV2 {
            generation: 2,
            active: Some(next_lease.clone()),
            max_writer_fence: 2,
            ..cleared.clone()
        };
        persistent
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key.clone(),
                expected: cleared,
                new: next_preparing.clone(),
            })
            .unwrap();

        next_lease.owner_peer_id = 9;
        next_lease.issued_at_unix = 401;
        next_lease.expires_at_unix = 500;
        let expired_takeover = persistent
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key,
                expected: next_preparing.clone(),
                new: PrivateOramMutationLeaseSlotV2 {
                    active: Some(next_lease),
                    ..next_preparing
                },
            })
            .unwrap_err();
        assert!(
            expired_takeover
                .to_string()
                .contains("transition is invalid")
        );
    }

    #[test]
    fn active_private_oram_mutation_keys_survive_restart() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        assert!(
            persistent
                .active_private_oram_mutation_keys()
                .unwrap()
                .is_empty()
        );

        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        assert_eq!(
            persistent.active_private_oram_mutation_keys().unwrap(),
            vec![fixture.key.clone()]
        );
        persistent.save().unwrap();
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.active_private_oram_mutation_keys().unwrap(),
            vec![fixture.key]
        );
    }

    #[test]
    fn deleting_a_collection_retains_records_pinned_by_an_authority_floor() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        let key_digest = private_oram_mutation_key_digest(&fixture.key);
        // The floor checkpoint only accepts the activated authority after the tagged legacy
        // authority was durable at the pre-activation format floor.
        let legacy = mutation_legacy_authority(&fixture);
        persistent.private_oram_mutation_lease_slots.insert(
            key_digest.clone(),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(legacy.clone()),
        );
        persistent.private_oram_mutation_format_floor = Some(mutation_format_floor(1, false, 1));
        persistent.state.hard_state.commit = 1;
        persistent.latest_snapshot_meta.index = 1;
        persistent.apply_progress_queue.set_from_snapshot(1);
        persistent.save().unwrap();
        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            &fixture.key.collection_id,
            private_oram_mutation_activation_context_for_test(
                test_digest(1),
                test_digest(2),
                1,
                10,
                2,
                test_digest(32),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(activated.aggregate().is_some());
        persistent.private_oram_mutation_lease_slots.insert(
            key_digest.clone(),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(activated),
        );
        persistent.private_oram_mutation_format_floor = Some(mutation_format_floor(2, true, 11));
        persistent.state.hard_state.commit = 11;
        persistent.latest_snapshot_meta.index = 11;
        persistent.apply_progress_queue.set_from_snapshot(11);
        persistent.save().unwrap();
        let durable_digest = persistent_state_file_digest(&persistent.path).unwrap();

        // The delete must not remove the floor-pinning authority (the floor checkpoint would
        // refuse the save on every node); the collection's records are retained as a whole.
        let pruned = persistent
            .prune_private_oram_collection_state(&[PrivateOramEpochKey {
                collection_id: fixture.key.collection_id.clone(),
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "vector".to_string(),
            }])
            .unwrap();
        assert!(!pruned);
        assert!(
            persistent
                .private_oram_mutation_lease_slots
                .contains_key(&key_digest)
        );
        assert!(
            persistent
                .private_oram_mutation_states
                .contains_key(&key_digest)
        );
        assert_eq!(
            persistent_state_file_digest(&persistent.path).unwrap(),
            durable_digest
        );
        persistent.save().unwrap();
        drop(persistent);
        Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
    }

    #[test]
    fn tagged_mutation_authority_survives_persistence_and_fences_legacy_reducers() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        let key_digest = private_oram_mutation_key_digest(&fixture.key);
        let legacy = mutation_legacy_authority(&fixture);
        persistent.private_oram_mutation_lease_slots.insert(
            key_digest.clone(),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(legacy.clone()),
        );
        persistent.private_oram_mutation_format_floor = Some(mutation_format_floor(1, false, 1));
        persistent.state.hard_state.commit = 1;
        persistent.latest_snapshot_meta.index = 1;
        persistent.apply_progress_queue.set_from_snapshot(1);
        persistent.save().unwrap();
        drop(persistent);

        let mut reloaded = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        assert!(matches!(
            reloaded.private_oram_mutation_lease_slots.get(&key_digest),
            Some(DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(
                authority
            )) if authority == &legacy
        ));
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );

        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            &fixture.key.collection_id,
            private_oram_mutation_activation_context_for_test(
                test_digest(1),
                test_digest(2),
                1,
                10,
                2,
                test_digest(32),
            )
            .unwrap(),
        )
        .unwrap();
        reloaded.private_oram_mutation_lease_slots.insert(
            key_digest.clone(),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(activated.clone()),
        );
        reloaded.private_oram_mutation_format_floor = Some(mutation_format_floor(2, true, 11));
        reloaded.state.hard_state.commit = 11;
        reloaded.latest_snapshot_meta.index = 11;
        reloaded.apply_progress_queue.set_from_snapshot(11);
        reloaded.save().unwrap();
        let durable_digest = persistent_state_file_digest(&reloaded.path).unwrap();

        let error = reloaded
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap_err();
        assert!(matches!(error, StorageError::BadRequest { .. }));
        assert!(error.to_string().contains("tagged authority state"));
        assert_eq!(
            persistent_state_file_digest(&reloaded.path).unwrap(),
            durable_digest
        );
        assert!(matches!(
            reloaded.private_oram_mutation_lease_slots.get(&key_digest),
            Some(DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(
                authority
            )) if authority == &activated
        ));
        drop(reloaded);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        assert!(matches!(
            reloaded.private_oram_mutation_lease_slots.get(&key_digest),
            Some(DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(
                authority
            )) if authority == &activated
        ));
    }

    #[test]
    fn mutation_authority_format_floor_rejects_unbound_tagged_and_raw_downgrade_images() {
        let tagged_without_floor = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent =
            Persistent::load_or_init(tagged_without_floor.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent.private_oram_mutation_lease_slots.insert(
            private_oram_mutation_key_digest(&fixture.key),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(
                mutation_legacy_authority(&fixture),
            ),
        );
        let error = persistent.save().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authority format snapshot is invalid")
        );

        let raw_after_floor = tempfile::tempdir().unwrap();
        let mut persistent =
            Persistent::load_or_init(raw_after_floor.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent.private_oram_mutation_format_floor = Some(mutation_format_floor(1, false, 1));
        persistent.state.hard_state.commit = 1;
        persistent.latest_snapshot_meta.index = 1;
        persistent.apply_progress_queue.set_from_snapshot(1);
        let error = persistent.save().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authority format snapshot is invalid")
        );

        let wrong_collection = private_oram_mutation_legacy_authority_v2(
            private_oram_mutation_authority_key_v2(
                "different-collection",
                test_digest(1),
                test_digest(2),
                test_digest(30),
            )
            .unwrap(),
            fixture.genesis_slot.clone(),
            test_digest(31),
        )
        .unwrap();
        persistent.private_oram_mutation_lease_slots.insert(
            private_oram_mutation_key_digest(&fixture.key),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(wrong_collection),
        );
        let error = persistent.save().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authority format snapshot is invalid")
        );
    }

    #[test]
    fn mutation_local_floor_rejects_raft_state_rollback_and_snapshot_downgrade() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        let legacy = install_tagged_legacy_floor(&mut persistent, &fixture);
        persistent.save().unwrap();
        let floor_one_state = fs::read(&persistent.path).unwrap();

        let activated = activate_private_oram_mutation_authority_v2(
            &legacy,
            &fixture.key.collection_id,
            private_oram_mutation_activation_context_for_test(
                test_digest(1),
                test_digest(2),
                1,
                10,
                2,
                test_digest(32),
            )
            .unwrap(),
        )
        .unwrap();
        persistent.private_oram_mutation_lease_slots.insert(
            private_oram_mutation_key_digest(&fixture.key),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(activated),
        );
        persistent.private_oram_mutation_format_floor = Some(mutation_format_floor(2, true, 11));
        persistent.state.hard_state.commit = 11;
        persistent.latest_snapshot_meta.index = 11;
        persistent.apply_progress_queue.set_from_snapshot(11);
        persistent.save().unwrap();

        let legacy_wires = HashMap::from([(
            private_oram_mutation_key_digest(&fixture.key),
            DecodedPrivateOramMutationAuthorityWireV2::TaggedAuthorityV2(legacy),
        )]);
        assert!(
            persistent
                .validate_private_oram_mutation_floor_for_snapshot(
                    Some(&mutation_format_floor(1, false, 1)),
                    &legacy_wires,
                    1,
                )
                .is_err()
        );
        assert!(
            persistent
                .validate_private_oram_mutation_floor_for_snapshot(None, &HashMap::new(), 0)
                .is_err()
        );

        fs::write(&persistent.path, floor_one_state).unwrap();
        File::open(&persistent.path).unwrap().sync_all().unwrap();
        File::open(temp.path()).unwrap().sync_all().unwrap();
        drop(persistent);
        let error = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("contradicts the private ORAM mutation floor")
        );
    }

    #[test]
    fn mutation_local_floor_pending_recovers_exact_old_and_new_raft_images() {
        for publish_new_state in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let fixture = private_oram_mutation_fixture();
            let mut persistent =
                Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
            install_private_oram_mutation_fixture(&mut persistent, &fixture);
            install_tagged_legacy_floor(&mut persistent, &fixture);

            let prepared = persistent.prepare_state_image().unwrap();
            let next_raft_state_digest = BASE64URL_NOPAD.encode(&prepared.candidate_digest);
            let prior_raft_state_digest =
                BASE64URL_NOPAD.encode(&persistent_state_file_digest(&persistent.path).unwrap());
            let store = persistent.private_oram_mutation_floor_store();
            let checkpoint = plan_private_oram_local_floor_for_persistent_state(
                None,
                persistent.private_oram_mutation_format_floor.as_ref(),
                &persistent.private_oram_mutation_lease_slots,
                persistent.private_oram_applied_index(),
            )
            .unwrap()
            .unwrap();
            store
                .begin_transition(&checkpoint, prior_raft_state_digest, next_raft_state_digest)
                .unwrap();
            if publish_new_state {
                persistent
                    .publish_prepared_state_image(prepared, &FilesystemPersistentSaveBackend)
                    .unwrap();
            } else {
                drop(prepared);
            }
            drop(persistent);

            let recovered = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
            assert_eq!(
                recovered.private_oram_mutation_format_floor.is_some(),
                publish_new_state
            );
            assert_eq!(
                recovered
                    .private_oram_mutation_lease_slots
                    .values()
                    .any(|wire| wire.tagged_authority().is_some()),
                publish_new_state
            );
            recovered
                .validate_private_oram_mutation_floor_snapshot_source()
                .unwrap();
        }
    }

    #[test]
    fn private_oram_abort_decision_and_mutation_apply_are_mutually_exclusive() {
        let abort_first_temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut abort_first =
            Persistent::load_or_init(abort_first_temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut abort_first, &fixture);
        abort_first
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        let abort_decided = private_oram_mutation_abort_decided_slot(&fixture);
        let abort_operation = CompareAndSwapPrivateOramMutationLease {
            key: fixture.key.clone(),
            expected: fixture.preparing_slot.clone(),
            new: abort_decided.clone(),
        };
        let mut renewal_smuggled_into_decision = abort_decided.clone();
        let smuggled_lease = renewal_smuggled_into_decision.active.as_mut().unwrap();
        smuggled_lease.expires_at_unix += 10;
        smuggled_lease.renewal_revision += 1;
        let smuggled_decision_error = abort_first
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key.clone(),
                expected: fixture.preparing_slot.clone(),
                new: renewal_smuggled_into_decision,
            })
            .unwrap_err();
        assert!(
            smuggled_decision_error
                .to_string()
                .contains("transition is invalid")
        );
        abort_first
            .compare_and_swap_private_oram_mutation_lease(&abort_operation)
            .unwrap();
        drop(abort_first);

        let mut abort_first =
            Persistent::load_or_init(abort_first_temp.path(), true, false, None).unwrap();
        abort_first
            .compare_and_swap_private_oram_mutation_lease(&abort_operation)
            .unwrap();
        for invalid_new in [
            fixture.preparing_slot.clone(),
            fixture.committed_slot.clone(),
        ] {
            let terminal_escape_error = abort_first
                .compare_and_swap_private_oram_mutation_lease(
                    &CompareAndSwapPrivateOramMutationLease {
                        key: fixture.key.clone(),
                        expected: abort_decided.clone(),
                        new: invalid_new,
                    },
                )
                .unwrap_err();
            assert!(
                terminal_escape_error
                    .to_string()
                    .contains("transition is invalid")
            );
        }
        let mut renewed_abort_decided = abort_decided.clone();
        let renewed_lease = renewed_abort_decided.active.as_mut().unwrap();
        renewed_lease.expires_at_unix += 10;
        renewed_lease.renewal_revision += 1;
        abort_first
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key.clone(),
                expected: abort_decided,
                new: renewed_abort_decided.clone(),
            })
            .unwrap();
        assert_eq!(
            abort_first.private_oram_mutation_lease_slot(&fixture.key),
            Some(renewed_abort_decided)
        );
        let delayed_apply_error = abort_first
            .apply_private_oram_mutation(&private_oram_mutation_apply(&fixture))
            .unwrap_err();
        assert!(
            delayed_apply_error
                .to_string()
                .contains("lease transition is invalid")
        );

        let commit_first_temp = tempfile::tempdir().unwrap();
        let mut commit_first =
            Persistent::load_or_init(commit_first_temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut commit_first, &fixture);
        commit_first
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        commit_first
            .apply_private_oram_mutation(&private_oram_mutation_apply(&fixture))
            .unwrap();
        let delayed_abort_error = commit_first
            .compare_and_swap_private_oram_mutation_lease(&abort_operation)
            .unwrap_err();
        assert!(
            delayed_abort_error
                .to_string()
                .contains("precondition failed")
        );
        assert_eq!(
            commit_first.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.committed_slot.clone())
        );
    }

    #[test]
    fn private_oram_mutation_enrollment_fences_standalone_index_operations() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);

        let session_error = persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: fixture.hnsw_key.clone(),
                expected: None,
                new: Some(PrivateOramSessionLease {
                    owner_peer_id: 7,
                    lease_id_hash: test_digest(70),
                    issued_at_unix: 100,
                    expires_at_unix: 160,
                }),
            })
            .unwrap_err();
        assert!(
            session_error
                .to_string()
                .contains("enrolled v2 mutation state")
        );

        let epoch_error = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: fixture.hnsw_key.clone(),
                expected: Some(fixture.old_state.indexes[0].epoch.clone()),
                new: fixture.new_state.indexes[0].epoch.clone(),
            })
            .unwrap_err();
        assert!(epoch_error.to_string().contains("enrolled v2"));
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: fixture.hnsw_key.clone(),
                expected: None,
                new: fixture.old_state.indexes[0].epoch.clone(),
            })
            .unwrap();

        let layout_error = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: fixture.layout_key.clone(),
                expected: Some(fixture.layout.clone()),
                new: PrivateOramConsensusLayout {
                    generation: fixture.layout.generation + 1,
                    layout_digest: test_digest(71),
                    ..fixture.layout.clone()
                },
            })
            .unwrap_err();
        assert!(layout_error.to_string().contains("enrolled v2"));

        let recovery_key = PrivateOramExternalRecoveryKey {
            collection_id: fixture.key.collection_id.clone(),
        };
        let recovery_state = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 7,
                operation_id_hash: test_digest(72),
                checkpoint_digest: test_digest(73),
                backup_generation: 1,
                issued_at_unix: 100,
                expires_at_unix: 160,
                install_intent_digest: None,
                phase: PrivateOramExternalRecoveryLeasePhase::Staging,
            }),
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: recovery_key.clone(),
                    expected: None,
                    new: Some(recovery_state.clone()),
                },
            )
            .unwrap();
        let mutation_during_recovery = persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap_err();
        assert!(
            mutation_during_recovery
                .to_string()
                .contains("active external recovery")
        );
        persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: recovery_key.clone(),
                    expected: Some(recovery_state.clone()),
                    new: None,
                },
            )
            .unwrap();

        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        let recovery_error = persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: recovery_key,
                    expected: None,
                    new: Some(recovery_state),
                },
            )
            .unwrap_err();
        assert!(recovery_error.to_string().contains("active mutation"));
    }

    #[test]
    fn private_oram_mutation_atomically_advances_and_replays_after_clear() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        let operation = private_oram_mutation_apply(&fixture);

        persistent.apply_private_oram_mutation(&operation).unwrap();
        persistent.apply_private_oram_mutation(&operation).unwrap();
        assert_eq!(
            persistent.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state.clone())
        );
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.committed_slot.clone())
        );
        assert_eq!(
            persistent.private_oram_epoch(&fixture.hnsw_key),
            Some(fixture.new_state.indexes[0].epoch.clone())
        );
        assert_eq!(
            persistent.private_oram_epoch(&fixture.result_key),
            Some(fixture.new_state.indexes[1].epoch.clone())
        );
        assert_eq!(
            persistent
                .private_oram_layout(&fixture.layout_key)
                .unwrap()
                .index_state_digest,
            private_oram_consensus_state_index_digest(&fixture.new_state).unwrap()
        );

        let cleared = private_oram_mutation_cleared_slot(
            &fixture.committed_slot,
            &fixture.new_state,
            PrivateOramMutationClearOutcome::FinalizedOrReconciledAfterConsensusCommit,
            95,
        );
        persistent
            .compare_and_swap_private_oram_mutation_lease(&CompareAndSwapPrivateOramMutationLease {
                key: fixture.key.clone(),
                expected: fixture.committed_slot.clone(),
                new: cleared.clone(),
            })
            .unwrap();
        persistent.apply_private_oram_mutation(&operation).unwrap();
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(cleared.clone())
        );
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(cleared)
        );
    }

    #[test]
    fn private_oram_mutation_rejects_tampered_writeback_and_fence() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();

        let mut unchanged_writeback = private_oram_mutation_apply(&fixture);
        unchanged_writeback.new_state.indexes[0]
            .epoch
            .writeback_digest = unchanged_writeback.expected_state.indexes[0]
            .epoch
            .writeback_digest
            .clone();
        let transition_digest = canonical_private_oram_mutation_transition_digest(
            &unchanged_writeback.expected_state,
            &unchanged_writeback.new_state,
        )
        .unwrap();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &mut unchanged_writeback.new_state.last_transition
        else {
            unreachable!();
        };
        receipt.transition_digest = transition_digest;
        let writeback_error = persistent
            .apply_private_oram_mutation(&unchanged_writeback)
            .unwrap_err();
        assert!(
            writeback_error
                .to_string()
                .contains("transition is invalid")
        );

        let mut stale_fence = private_oram_mutation_apply(&fixture);
        stale_fence.mutation_lease_generation = 2;
        let fence_error = persistent
            .apply_private_oram_mutation(&stale_fence)
            .unwrap_err();
        assert!(fence_error.to_string().contains("transition is invalid"));

        let mut different_receipt = private_oram_mutation_apply(&fixture);
        if let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &mut different_receipt.new_state.last_transition
        {
            receipt.point_operation_digest = test_digest(98);
        }
        let transition_digest = canonical_private_oram_mutation_transition_digest(
            &different_receipt.expected_state,
            &different_receipt.new_state,
        )
        .unwrap();
        if let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &mut different_receipt.new_state.last_transition
        {
            receipt.transition_digest = transition_digest;
        }
        let receipt_error = persistent
            .apply_private_oram_mutation(&different_receipt)
            .unwrap_err();
        assert!(
            receipt_error
                .to_string()
                .contains("lease transition is invalid")
        );
    }

    #[test]
    fn private_oram_legacy_mutation_commands_persist_with_the_exact_applied_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_outer_fixture(&mut persistent, &fixture);
        persistent.set_unapplied_entries(70, 72).unwrap();

        persistent
            .initialize_private_oram_mutation_state_at_applied_entry(
                &InitializePrivateOramMutationState {
                    key: fixture.key.clone(),
                    state: fixture.old_state.clone(),
                },
                70,
            )
            .unwrap();
        assert_eq!(persistent.current_unapplied_entry(), Some(71));

        persistent
            .compare_and_swap_private_oram_mutation_lease_at_applied_entry(
                &private_oram_mutation_acquire(&fixture),
                71,
            )
            .unwrap();
        assert_eq!(persistent.current_unapplied_entry(), Some(72));

        persistent
            .apply_private_oram_mutation_at_applied_entry(
                &private_oram_mutation_apply(&fixture),
                72,
            )
            .unwrap();
        assert_eq!(persistent.current_unapplied_entry(), None);
        assert_eq!(persistent.last_applied_entry(), Some(72));
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.last_applied_entry(), Some(72));
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.committed_slot)
        );
    }

    #[test]
    fn private_oram_authority_confirmation_is_exact_and_advances_rejected_entries() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_outer_fixture(&mut persistent, &fixture);
        persistent.set_unapplied_entries(70, 73).unwrap();
        persistent
            .initialize_private_oram_mutation_state_at_applied_entry(
                &InitializePrivateOramMutationState {
                    key: fixture.key.clone(),
                    state: fixture.old_state.clone(),
                },
                70,
            )
            .unwrap();
        persistent
            .compare_and_swap_private_oram_mutation_lease_at_applied_entry(
                &private_oram_mutation_acquire(&fixture),
                71,
            )
            .unwrap();

        let confirmed = ConfirmPrivateOramMutationAuthorityV2 {
            key: fixture.key.clone(),
            expected: fixture.preparing_slot.clone(),
        };
        assert!(matches!(
            persistent
                .confirm_private_oram_mutation_authority_v2_at_applied_entry(&confirmed, 72)
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(persistent.last_applied_entry(), Some(72));

        let mut stale_slot = fixture.preparing_slot.clone();
        stale_slot.active.as_mut().unwrap().expires_at_unix += 1;
        stale_slot.active.as_mut().unwrap().renewal_revision += 1;
        let stale = ConfirmPrivateOramMutationAuthorityV2 {
            key: fixture.key.clone(),
            expected: stale_slot,
        };
        assert!(matches!(
            persistent
                .confirm_private_oram_mutation_authority_v2_at_applied_entry(&stale, 73)
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Rejected(_)
        ));
        assert_eq!(persistent.last_applied_entry(), Some(73));
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot.clone())
        );
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.last_applied_entry(), Some(73));
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot)
        );
    }

    #[test]
    fn private_oram_two_phase_activation_is_atomic_restart_safe_and_irreversible() {
        let temp = tempfile::tempdir().unwrap();
        let mutation = private_oram_mutation_fixture();
        let barrier = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let mut persistent =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        persistent
            .set_peer_address_by_id(barrier.peer_addresses.clone())
            .unwrap();
        persistent
            .apply_state_update(|state| {
                state.conf_state = barrier.conf_state.clone();
                state.hard_state.term = barrier.current_term;
                state.hard_state.commit = barrier.base_index + 3;
            })
            .unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &mutation);
        let key_digest = private_oram_mutation_key_digest(&mutation.key);
        assert!(
            persistent.private_oram_mutation_lease_slots[&key_digest]
                .historical_raw_slot()
                .is_some()
        );
        persistent
            .set_unapplied_entries(barrier.base_index + 1, barrier.base_index + 3)
            .unwrap();

        assert!(matches!(
            persistent
                .activate_private_oram_mutation_v2_at_applied_entry(
                    &barrier.prepare_operation,
                    barrier.current_term,
                    barrier.base_index + 1,
                    barrier.base_entry_term,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent.current_unapplied_entry(),
            Some(barrier.base_index + 2)
        );
        let prepared_floor = persistent
            .private_oram_mutation_format_floor
            .clone()
            .unwrap();
        assert_eq!(prepared_floor.format_epoch(), 1);
        assert!(!prepared_floor.activation_enabled());
        let pending = persistent
            .private_oram_mutation_activation_pending
            .clone()
            .unwrap();
        assert_eq!(
            pending.enable_operation().unwrap(),
            barrier.enable_operation
        );
        assert!(matches!(
            persistent.private_oram_mutation_lease_slots[&key_digest].tagged_authority(),
            Some(PrivateOramMutationAuthorityStateV2::Legacy(_))
        ));
        let rejected_enable = persistent
            .activate_private_oram_mutation_v2_at_applied_entry(
                &barrier.prepare_operation,
                barrier.current_term,
                barrier.base_index + 2,
                barrier.base_entry_term,
            )
            .unwrap();
        assert!(matches!(
            rejected_enable,
            PrivateOramMutationAtEntryOutcome::Rejected(_)
        ));
        assert_eq!(
            persistent.current_unapplied_entry(),
            Some(barrier.base_index + 3)
        );
        assert_eq!(
            persistent.private_oram_mutation_activation_pending.as_ref(),
            Some(&pending)
        );
        drop(persistent);

        let mut reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        assert_eq!(
            reloaded.current_unapplied_entry(),
            Some(barrier.base_index + 3)
        );
        assert_eq!(
            reloaded.private_oram_mutation_format_floor.as_ref(),
            Some(&prepared_floor)
        );
        assert_eq!(
            reloaded.private_oram_mutation_activation_pending.as_ref(),
            Some(&pending)
        );
        assert!(matches!(
            reloaded.private_oram_mutation_lease_slots[&key_digest].tagged_authority(),
            Some(PrivateOramMutationAuthorityStateV2::Legacy(_))
        ));

        let resumed_enable = reloaded
            .private_oram_mutation_activation_pending
            .as_ref()
            .unwrap()
            .enable_operation()
            .unwrap();
        assert!(matches!(
            reloaded
                .activate_private_oram_mutation_v2_at_applied_entry(
                    &resumed_enable,
                    barrier.current_term + 1,
                    barrier.base_index + 3,
                    barrier.base_entry_term,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(reloaded.current_unapplied_entry(), None);
        assert_eq!(reloaded.last_applied_entry(), Some(barrier.base_index + 3));
        assert!(reloaded.private_oram_mutation_activation_pending.is_none());
        let active_floor = reloaded.private_oram_mutation_format_floor.clone().unwrap();
        assert_eq!(active_floor.format_epoch(), 2);
        assert!(active_floor.activation_enabled());
        let activated_wire = reloaded.private_oram_mutation_lease_slots[&key_digest].clone();
        assert!(matches!(
            activated_wire.tagged_authority(),
            Some(PrivateOramMutationAuthorityStateV2::Activated(_))
        ));

        reloaded
            .set_unapplied_entries(barrier.base_index + 4, barrier.base_index + 4)
            .unwrap();
        let rejected = reloaded
            .activate_private_oram_mutation_v2_at_applied_entry(
                &barrier.prepare_operation,
                barrier.current_term + 1,
                barrier.base_index + 4,
                barrier.base_entry_term,
            )
            .unwrap();
        assert!(matches!(
            rejected,
            PrivateOramMutationAtEntryOutcome::Rejected(_)
        ));
        assert_eq!(reloaded.current_unapplied_entry(), None);
        assert_eq!(reloaded.last_applied_entry(), Some(barrier.base_index + 4));
        assert_eq!(
            reloaded.private_oram_mutation_format_floor.as_ref(),
            Some(&active_floor)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slots[&key_digest],
            activated_wire
        );
        drop(reloaded);

        let final_state =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        assert_eq!(
            final_state.last_applied_entry(),
            Some(barrier.base_index + 4)
        );
        assert_eq!(
            final_state.private_oram_mutation_format_floor.as_ref(),
            Some(&active_floor)
        );
        assert_eq!(
            final_state.private_oram_mutation_lease_slots[&key_digest],
            activated_wire
        );
    }

    #[test]
    fn private_oram_v2_material_admission_manifest_is_one_replayable_patch() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let barrier = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let mut persistent =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        persistent
            .set_peer_address_by_id(barrier.peer_addresses.clone())
            .unwrap();
        persistent
            .apply_state_update(|state| {
                state.conf_state = barrier.conf_state.clone();
                state.hard_state.term = barrier.current_term;
                state.hard_state.commit = barrier.base_index + 7;
            })
            .unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .set_unapplied_entries(barrier.base_index + 1, barrier.base_index + 7)
            .unwrap();

        assert!(matches!(
            persistent
                .activate_private_oram_mutation_v2_at_applied_entry(
                    &barrier.prepare_operation,
                    barrier.current_term,
                    barrier.base_index + 1,
                    barrier.base_entry_term,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert!(matches!(
            persistent
                .activate_private_oram_mutation_v2_at_applied_entry(
                    &barrier.enable_operation,
                    barrier.current_term,
                    barrier.base_index + 2,
                    barrier.base_entry_term,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));

        let reservation_context = persistent
            .private_oram_mutation_v2_append_authority_context(&fixture.key)
            .unwrap();
        let reservation_expected = reservation_context.expected_aggregate_digest().to_string();
        let (reservation, expected_recovery_manifest) =
            private_oram_mutation_append_fixture_for_test(
                fixture.preparing_slot.active.as_ref().unwrap(),
                reservation_context,
                barrier.current_term,
                &fixture.layout.owner_peer_ids,
                persistent
                    .private_oram_activation_authority_locator()
                    .unwrap(),
            );
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap();
        let recovery_manifest_canonical_json =
            encode_private_oram_mutation_admission_recovery_manifest_v2(
                &expected_recovery_manifest,
            )
            .unwrap();
        let reserve = ApplyPrivateOramMutationMaterialV2::append_reservation(
            fixture.key.clone(),
            reservation_expected.clone(),
            reservation_canonical_json,
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &reserve,
                    barrier.current_term,
                    barrier.base_index + 3,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );
        assert_eq!(
            persistent
                .private_oram_mutation_v2_active_append_attempt(&fixture.key)
                .unwrap(),
            Some((reservation.clone(), None))
        );

        let prepared_expected = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        let prepare = ApplyPrivateOramMutationMaterialV2::append_prepared(
            fixture.key.clone(),
            prepared_expected,
            recovery_manifest_canonical_json.clone(),
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &prepare,
                    barrier.current_term,
                    barrier.base_index + 4,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );
        assert_eq!(
            persistent
                .private_oram_mutation_v2_active_append_attempt(&fixture.key)
                .unwrap(),
            Some((reservation, Some(expected_recovery_manifest.clone())))
        );

        let admission_expected = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        let admission = ApplyPrivateOramMutationMaterialV2::admission(
            fixture.key.clone(),
            admission_expected.clone(),
            fixture.preparing_slot.active.clone().unwrap(),
            recovery_manifest_canonical_json.clone(),
        );
        let rejection = ApplyPrivateOramMutationMaterialV2::admission_rejected(
            fixture.key.clone(),
            admission_expected.clone(),
            fixture.preparing_slot.active.clone().unwrap(),
            recovery_manifest_canonical_json,
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &admission,
                    barrier.current_term,
                    barrier.base_index + 5,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot.clone())
        );
        let retained_recovery_manifest = persistent
            .private_oram_mutation_v2_active_recovery_manifest(&fixture.key)
            .unwrap()
            .unwrap();
        assert_eq!(retained_recovery_manifest, expected_recovery_manifest);
        assert_eq!(
            persistent
                .private_oram_mutation_v2_exact_admitted_recovery_manifest(
                    &fixture.key,
                    fixture.preparing_slot.active.as_ref().unwrap(),
                )
                .unwrap(),
            Some(expected_recovery_manifest.clone())
        );
        assert_eq!(
            retained_recovery_manifest.expected_aggregate_digest(),
            reservation_expected
        );
        assert!(!retained_recovery_manifest.owner_evidence().is_empty());

        let aggregate_after_admission = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        assert_eq!(
            persistent.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state.clone())
        );
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot.clone())
        );

        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &rejection,
                    barrier.current_term,
                    barrier.base_index + 6,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Rejected(_)
        ));
        assert_eq!(
            persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            aggregate_after_admission
        );
        assert!(
            !persistent
                .private_oram_mutation_v2_retains_rejected_admission(
                    &fixture.key,
                    fixture.preparing_slot.active.as_ref().unwrap(),
                    expected_recovery_manifest.manifest_digest(),
                )
                .unwrap()
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &admission,
                    barrier.current_term,
                    barrier.base_index + 7,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(persistent.current_unapplied_entry(), None);
        drop(persistent);

        let reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot)
        );
        assert_eq!(
            reloaded
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            aggregate_after_admission
        );
        assert_eq!(
            reloaded
                .private_oram_mutation_v2_active_recovery_manifest(&fixture.key)
                .unwrap(),
            Some(expected_recovery_manifest)
        );
        assert_eq!(reloaded.last_applied_entry(), Some(barrier.base_index + 7));
    }

    #[test]
    fn private_oram_v2_rejected_admission_wins_exact_cas_and_survives_restart() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let barrier = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let mut persistent =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        persistent
            .set_peer_address_by_id(barrier.peer_addresses.clone())
            .unwrap();
        persistent
            .apply_state_update(|state| {
                state.conf_state = barrier.conf_state.clone();
                state.hard_state.term = barrier.current_term;
                state.hard_state.commit = barrier.base_index + 7;
            })
            .unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .set_unapplied_entries(barrier.base_index + 1, barrier.base_index + 7)
            .unwrap();

        for (offset, operation) in [
            (1, &barrier.prepare_operation),
            (2, &barrier.enable_operation),
        ] {
            assert!(matches!(
                persistent
                    .activate_private_oram_mutation_v2_at_applied_entry(
                        operation,
                        barrier.current_term,
                        barrier.base_index + offset,
                        barrier.base_entry_term,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));
        }

        let reservation_context = persistent
            .private_oram_mutation_v2_append_authority_context(&fixture.key)
            .unwrap();
        let reservation_expected = reservation_context.expected_aggregate_digest().to_string();
        let lease = fixture.preparing_slot.active.clone().unwrap();
        let (reservation, recovery_manifest) = private_oram_mutation_append_fixture_for_test(
            &lease,
            reservation_context,
            barrier.current_term,
            &fixture.layout.owner_peer_ids,
            persistent
                .private_oram_activation_authority_locator()
                .unwrap(),
        );
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap();
        let recovery_manifest_canonical_json =
            encode_private_oram_mutation_admission_recovery_manifest_v2(&recovery_manifest)
                .unwrap();
        let reserve = ApplyPrivateOramMutationMaterialV2::append_reservation(
            fixture.key.clone(),
            reservation_expected.clone(),
            reservation_canonical_json,
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &reserve,
                    barrier.current_term,
                    barrier.base_index + 3,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        let prepared_expected = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        let prepare = ApplyPrivateOramMutationMaterialV2::append_prepared(
            fixture.key.clone(),
            prepared_expected,
            recovery_manifest_canonical_json.clone(),
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &prepare,
                    barrier.current_term,
                    barrier.base_index + 4,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );
        let admission_expected = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        let admission = ApplyPrivateOramMutationMaterialV2::admission(
            fixture.key.clone(),
            admission_expected.clone(),
            lease.clone(),
            recovery_manifest_canonical_json.clone(),
        );
        let rejection = ApplyPrivateOramMutationMaterialV2::admission_rejected(
            fixture.key.clone(),
            admission_expected.clone(),
            lease.clone(),
            recovery_manifest_canonical_json,
        );

        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &rejection,
                    barrier.current_term,
                    barrier.base_index + 5,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        let aggregate_after_rejection = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        assert_ne!(aggregate_after_rejection, admission_expected);
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );
        assert!(
            persistent
                .private_oram_mutation_v2_retains_rejected_admission(
                    &fixture.key,
                    &lease,
                    recovery_manifest.manifest_digest(),
                )
                .unwrap()
        );
        assert_eq!(
            persistent
                .private_oram_mutation_v2_exact_admitted_recovery_manifest(&fixture.key, &lease)
                .unwrap(),
            None
        );
        assert_eq!(
            persistent
                .private_oram_mutation_v2_active_recovery_manifest(&fixture.key)
                .unwrap(),
            None
        );

        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &admission,
                    barrier.current_term,
                    barrier.base_index + 6,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Rejected(_)
        ));
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &rejection,
                    barrier.current_term,
                    barrier.base_index + 7,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            aggregate_after_rejection
        );
        assert_eq!(persistent.current_unapplied_entry(), None);
        drop(persistent);

        let reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot)
        );
        assert!(
            reloaded
                .private_oram_mutation_v2_retains_rejected_admission(
                    &fixture.key,
                    &lease,
                    recovery_manifest.manifest_digest(),
                )
                .unwrap()
        );
        assert_eq!(reloaded.last_applied_entry(), Some(barrier.base_index + 7));
    }

    #[test]
    fn private_oram_v2_reservation_fences_other_transitions_and_abort_replays_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let barrier = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let mut persistent =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        persistent
            .set_peer_address_by_id(barrier.peer_addresses.clone())
            .unwrap();
        persistent
            .apply_state_update(|state| {
                state.conf_state = barrier.conf_state.clone();
                state.hard_state.term = barrier.current_term;
                state.hard_state.commit = barrier.base_index + 7;
            })
            .unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .set_unapplied_entries(barrier.base_index + 1, barrier.base_index + 7)
            .unwrap();

        for (offset, operation) in [
            (1, &barrier.prepare_operation),
            (2, &barrier.enable_operation),
        ] {
            assert!(matches!(
                persistent
                    .activate_private_oram_mutation_v2_at_applied_entry(
                        operation,
                        barrier.current_term,
                        barrier.base_index + offset,
                        barrier.base_entry_term,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));
        }

        let reservation_context = persistent
            .private_oram_mutation_v2_append_authority_context(&fixture.key)
            .unwrap();
        let reservation_expected = reservation_context.expected_aggregate_digest().to_string();
        let lease = fixture.preparing_slot.active.clone().unwrap();
        let (reservation, _) = private_oram_mutation_append_fixture_for_test(
            &lease,
            reservation_context,
            barrier.current_term,
            &fixture.layout.owner_peer_ids,
            persistent
                .private_oram_activation_authority_locator()
                .unwrap(),
        );
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap();
        let reserve = ApplyPrivateOramMutationMaterialV2::append_reservation(
            fixture.key.clone(),
            reservation_expected,
            reservation_canonical_json.clone(),
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &reserve,
                    barrier.current_term,
                    barrier.base_index + 3,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));

        let reserved_aggregate_digest = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        let blocked_renewal = ApplyPrivateOramMutationMaterialV2::renewal(
            fixture.key.clone(),
            reserved_aggregate_digest.clone(),
            lease,
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &blocked_renewal,
                    barrier.current_term,
                    barrier.base_index + 4,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Rejected(_)
        ));
        assert_eq!(
            persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            reserved_aggregate_digest
        );
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );

        let reject_reservation = ApplyPrivateOramMutationMaterialV2::reserved_attempt_rejected(
            fixture.key.clone(),
            reserved_aggregate_digest,
            reservation_canonical_json,
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &reject_reservation,
                    barrier.current_term,
                    barrier.base_index + 5,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent
                .private_oram_mutation_v2_active_append_attempt(&fixture.key)
                .unwrap(),
            None
        );
        let rejected_aggregate_digest = persistent
            .private_oram_mutation_v2_aggregate_digest(&fixture.key)
            .unwrap();
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &reject_reservation,
                    barrier.current_term,
                    barrier.base_index + 6,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            rejected_aggregate_digest
        );
        drop(persistent);

        let mut reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        assert_eq!(
            reloaded
                .private_oram_mutation_v2_active_append_attempt(&fixture.key)
                .unwrap(),
            None
        );
        assert_eq!(
            reloaded
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            rejected_aggregate_digest
        );
        assert!(matches!(
            reloaded
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &reject_reservation,
                    barrier.current_term,
                    barrier.base_index + 7,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert_eq!(
            reloaded
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            rejected_aggregate_digest
        );
        assert_eq!(reloaded.current_unapplied_entry(), None);
    }

    #[test]
    fn private_oram_v3_reservation_challenge_finalizes_after_restart() {
        use qdrant_sec::{
            PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            PrivateOramOwnerReservationPrepareChallengeV1,
            encode_private_oram_owner_enrollment_genesis_commitment_v1,
            encode_private_oram_owner_enrollment_prepared_v1,
            sign_private_oram_owner_reservation_prepare_v1,
        };
        use ring::signature::Ed25519KeyPair;

        let temp = tempfile::tempdir().unwrap();
        let mut fixture = private_oram_mutation_fixture();
        fixture.layout.owner_peer_ids = vec![7];
        let barrier = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let floor_upgrade = private_oram_mutation_v3_floor_upgrade_fixture_for_test(
            barrier.base_index + 2,
            barrier.current_term,
            barrier.current_term,
        );
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let mut persistent =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        let expected = persistent
            .private_oram_activation_authority_at_read(&trust_anchor)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_activation_authority(expected, &bundle, &trust_anchor)
            .unwrap();
        persistent
            .set_peer_address_by_id(barrier.peer_addresses.clone())
            .unwrap();
        persistent
            .apply_state_update(|state| {
                state.conf_state = barrier.conf_state.clone();
                state.hard_state.term = barrier.current_term;
                state.hard_state.commit = barrier.base_index + 8;
            })
            .unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .set_unapplied_entries(barrier.base_index + 1, barrier.base_index + 8)
            .unwrap();

        for (offset, operation) in [
            (1, &barrier.prepare_operation),
            (2, &barrier.enable_operation),
        ] {
            assert!(matches!(
                persistent
                    .activate_private_oram_mutation_v2_at_applied_entry(
                        operation,
                        barrier.current_term,
                        barrier.base_index + offset,
                        barrier.base_entry_term,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));
        }
        for (offset, operation) in [
            (3, &floor_upgrade.prepare_operation),
            (4, &floor_upgrade.enable_operation),
        ] {
            assert!(matches!(
                persistent
                    .activate_private_oram_mutation_v2_at_applied_entry(
                        operation,
                        barrier.current_term,
                        barrier.base_index + offset,
                        barrier.current_term,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));
        }
        assert!(persistent.private_oram_mutation_v3_write_floor_active());

        let key_digest = private_oram_mutation_key_digest(&fixture.key);
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[70; 32]).unwrap();
        let current_authority = persistent.private_oram_mutation_lease_slots[&key_digest]
            .tagged_authority()
            .unwrap()
            .clone();
        let (owner_enrollment, owner_commitment) =
            private_oram_mutation_owner_enrollment_fixture_for_test(
                &current_authority,
                &fixture.key.collection_id,
                barrier.base_index,
                7,
                &owner_key,
                70,
            )
            .unwrap();
        let enrollment_prepare = ApplyPrivateOramMutationMaterialV2::owner_enrollment_prepared(
            fixture.key.clone(),
            persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            String::from_utf8(
                encode_private_oram_owner_enrollment_prepared_v1(&owner_enrollment).unwrap(),
            )
            .unwrap(),
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &enrollment_prepare,
                    barrier.current_term,
                    barrier.base_index + 5,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        let enrollment_activate = ApplyPrivateOramMutationMaterialV2::owner_enrollment_activated(
            fixture.key.clone(),
            persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            String::from_utf8(
                encode_private_oram_owner_enrollment_genesis_commitment_v1(&owner_commitment)
                    .unwrap(),
            )
            .unwrap(),
        );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &enrollment_activate,
                    barrier.current_term,
                    barrier.base_index + 6,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));

        let reservation_context = persistent
            .private_oram_mutation_v2_append_authority_context(&fixture.key)
            .unwrap();
        let (base_reservation, _) = private_oram_mutation_append_fixture_for_test(
            fixture.preparing_slot.active.as_ref().unwrap(),
            reservation_context,
            barrier.current_term,
            &fixture.layout.owner_peer_ids,
            persistent
                .private_oram_activation_authority_locator()
                .unwrap(),
        );
        let reservation_intent =
            private_oram_mutation_reservation_intent_v3(&base_reservation).unwrap();
        let checkpoint_table = persistent.private_oram_mutation_lease_slots[&key_digest]
            .tagged_authority()
            .unwrap()
            .aggregate()
            .unwrap()
            .owner_checkpoint_table()
            .clone();
        let checkpoint_context = private_oram_owner_checkpoint_reservation_context_v1(
            &checkpoint_table,
            reservation_intent.intent_digest().to_string(),
        )
        .unwrap();
        let owner_nonce = BASE64URL_NOPAD.encode(&[71; 16]);
        let prepared_challenge = private_oram_mutation_prepared_reservation_challenge_v3(
            base_reservation.clone(),
            reservation_intent.clone(),
            checkpoint_context.clone(),
            vec![owner_nonce.clone()],
        )
        .unwrap();
        let challenge_operation =
            ApplyPrivateOramMutationMaterialV2::append_reservation_challenge_prepared_v3(
                fixture.key.clone(),
                base_reservation.expected_aggregate_digest().to_string(),
                encode_private_oram_mutation_prepared_reservation_challenge_v3(&prepared_challenge)
                    .unwrap(),
            );
        assert!(matches!(
            persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &challenge_operation,
                    barrier.current_term,
                    barrier.base_index + 7,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        let pending = persistent
            .private_oram_mutation_v2_pending_reservation_challenge(&fixture.key)
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.challenge_digest(),
            prepared_challenge.prepared_challenge_digest()
        );
        drop(persistent);

        let mut reloaded =
            Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                temp.path(),
                true,
                false,
                Some(11),
                &trust_anchor,
            )
            .unwrap();
        let pending = reloaded
            .private_oram_mutation_v2_pending_reservation_challenge(&fixture.key)
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.challenge_digest(),
            prepared_challenge.prepared_challenge_digest()
        );
        let challenge_applied = pending.challenge_applied().clone();
        let checkpoint = &checkpoint_table.checkpoints()[0];
        let owner_target = &base_reservation.owner_targets()[0];
        let owner_challenge = PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: base_reservation.consensus_history_id_digest().to_string(),
            raft_group_id_digest: base_reservation.raft_group_id_digest().to_string(),
            collection_id: fixture.key.collection_id.clone(),
            collection_lifetime_id_digest: base_reservation
                .collection_lifetime_id_digest()
                .to_string(),
            collection_incarnation_digest: base_reservation
                .collection_incarnation_digest()
                .to_string(),
            activation_anchor_digest: base_reservation.activation_anchor_digest().to_string(),
            capability_epoch: checkpoint_context.capability_epoch(),
            protocol_capability_digest: checkpoint_context.protocol_capability_digest().to_string(),
            membership_epoch: checkpoint_context.membership_epoch(),
            reservation_intent_digest: reservation_intent.intent_digest().to_string(),
            checkpoint_context_digest: checkpoint_context.context_digest().to_string(),
            committed_challenge_digest: prepared_challenge.prepared_challenge_digest().to_string(),
            challenge_applied_term: challenge_applied.term(),
            challenge_applied_index: challenge_applied.index(),
            attempt_id: base_reservation.attempt_id().to_string(),
            challenge_nonce: owner_nonce,
            expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest().to_string(),
            expected_checkpoint_sequence: checkpoint.checkpoint_sequence(),
            expected_owner_target_digest: owner_target.target_digest().to_string(),
            reserved_terminal_intent_key: owner_target.intent_key().to_string(),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: checkpoint.owner_enrollment_id().to_string(),
            owner_peer_id: checkpoint.owner_peer_id(),
            owner_store_incarnation_digest: checkpoint
                .lifecycle_state()
                .owner_store_incarnation_digest
                .clone(),
            authority_registry_digest: test_digest(72),
            owner_registry_digest: test_digest(73),
        };
        let owner_prepare = sign_private_oram_owner_reservation_prepare_v1(
            &owner_key,
            owner_challenge,
            checkpoint.lifecycle_state().clone(),
            checkpoint.lifecycle_state().generation,
            test_digest(74),
            checkpoint.owner_signer().clone(),
        )
        .unwrap();
        let binding =
            private_oram_owner_checkpoint_reservation_binding_v1(0, checkpoint, owner_prepare)
                .unwrap();
        let final_reservation = private_oram_mutation_append_reservation_v3(
            base_reservation.clone(),
            reservation_intent,
            checkpoint_context,
            prepared_challenge,
            challenge_applied,
            vec![binding],
        )
        .unwrap();
        let final_operation = ApplyPrivateOramMutationMaterialV2::append_reservation_finalized_v3(
            fixture.key.clone(),
            reloaded
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap(),
            encode_private_oram_mutation_append_reservation_v3(&final_reservation).unwrap(),
        );
        assert!(matches!(
            reloaded
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &final_operation,
                    barrier.current_term,
                    barrier.base_index + 8,
                )
                .unwrap(),
            PrivateOramMutationAtEntryOutcome::Applied
        ));
        assert!(
            reloaded
                .private_oram_mutation_v2_pending_reservation_challenge(&fixture.key)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reloaded
                .private_oram_mutation_v2_active_append_attempt(&fixture.key)
                .unwrap(),
            Some((base_reservation.clone(), None))
        );
        drop(reloaded);

        let durable = Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
            temp.path(),
            true,
            false,
            Some(11),
            &trust_anchor,
        )
        .unwrap();
        assert!(
            durable
                .private_oram_mutation_v2_pending_reservation_challenge(&fixture.key)
                .unwrap()
                .is_none()
        );
        assert!(
            durable.private_oram_mutation_lease_slots[&key_digest]
                .tagged_authority()
                .unwrap()
                .aggregate()
                .unwrap()
                .owner_checkpoint_table()
                .has_active_leases()
        );
        let durable_outcome = durable
            .private_oram_mutation_v3_latest_reservation_challenge_outcome(&fixture.key)
            .unwrap()
            .unwrap();
        let recovered_challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
            durable_outcome.challenge_canonical_json().unwrap(),
        )
        .unwrap();
        assert_eq!(
            recovered_challenge.prepared_challenge_digest(),
            final_reservation
                .prepared_challenge()
                .prepared_challenge_digest(),
        );
        assert_eq!(durable.last_applied_entry(), Some(barrier.base_index + 8));
    }

    #[test]
    fn private_oram_recovery_readiness_apply_requires_authority_pinned_owner_signers() {
        fn apply_readiness_with_peer_11_seed(
            peer_11_seed: u8,
        ) -> (
            PrivateOramMutationAtEntryOutcome,
            String,
            String,
            Option<EntryId>,
        ) {
            let temp = tempfile::tempdir().unwrap();
            let mut fixture = private_oram_mutation_fixture();
            fixture.layout.owner_peer_ids = vec![11, 13];
            fixture
                .preparing_slot
                .active
                .as_mut()
                .unwrap()
                .owner_peer_id = 11;
            fixture
                .committed_slot
                .active
                .as_mut()
                .unwrap()
                .owner_peer_id = 11;
            let barrier = private_oram_mutation_activation_barrier_fixture_v2_for_test();
            let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
            let mut persistent =
                Persistent::load_or_init_with_private_oram_activation_authority_trust_anchor(
                    temp.path(),
                    true,
                    false,
                    Some(11),
                    &trust_anchor,
                )
                .unwrap();
            let expected = persistent
                .private_oram_activation_authority_at_read(&trust_anchor)
                .unwrap();
            persistent
                .compare_and_swap_private_oram_activation_authority(
                    expected,
                    &bundle,
                    &trust_anchor,
                )
                .unwrap();
            persistent
                .set_peer_address_by_id(barrier.peer_addresses.clone())
                .unwrap();
            persistent
                .apply_state_update(|state| {
                    state.conf_state = barrier.conf_state.clone();
                    state.hard_state.term = barrier.current_term;
                    state.hard_state.commit = barrier.base_index + 9;
                })
                .unwrap();
            install_private_oram_mutation_fixture(&mut persistent, &fixture);
            persistent
                .set_unapplied_entries(barrier.base_index + 1, barrier.base_index + 9)
                .unwrap();

            for (offset, operation) in [
                (1, &barrier.prepare_operation),
                (2, &barrier.enable_operation),
            ] {
                assert!(matches!(
                    persistent
                        .activate_private_oram_mutation_v2_at_applied_entry(
                            operation,
                            barrier.current_term,
                            barrier.base_index + offset,
                            barrier.base_entry_term,
                        )
                        .unwrap(),
                    PrivateOramMutationAtEntryOutcome::Applied
                ));
            }

            let reservation_context = persistent
                .private_oram_mutation_v2_append_authority_context(&fixture.key)
                .unwrap();
            let reservation_expected = reservation_context.expected_aggregate_digest().to_string();
            let (reservation, recovery_manifest) =
                private_oram_mutation_append_fixture_with_owner_signer_seeds_for_test(
                    fixture.preparing_slot.active.as_ref().unwrap(),
                    reservation_context,
                    barrier.current_term,
                    &fixture.layout.owner_peer_ids,
                    persistent
                        .private_oram_activation_authority_locator()
                        .unwrap(),
                    &[(11, 21), (13, 22)],
                );
            let recovery_manifest_canonical_json =
                encode_private_oram_mutation_admission_recovery_manifest_v2(&recovery_manifest)
                    .unwrap();
            let reserve = ApplyPrivateOramMutationMaterialV2::append_reservation(
                fixture.key.clone(),
                reservation_expected,
                encode_private_oram_mutation_append_reservation_v2(&reservation).unwrap(),
            );
            assert!(matches!(
                persistent
                    .apply_private_oram_mutation_material_v2_at_applied_entry(
                        &reserve,
                        barrier.current_term,
                        barrier.base_index + 3,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));

            let prepare = ApplyPrivateOramMutationMaterialV2::append_prepared(
                fixture.key.clone(),
                persistent
                    .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                    .unwrap(),
                recovery_manifest_canonical_json.clone(),
            );
            assert!(matches!(
                persistent
                    .apply_private_oram_mutation_material_v2_at_applied_entry(
                        &prepare,
                        barrier.current_term,
                        barrier.base_index + 4,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));

            let admission = ApplyPrivateOramMutationMaterialV2::admission(
                fixture.key.clone(),
                persistent
                    .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                    .unwrap(),
                fixture.preparing_slot.active.clone().unwrap(),
                recovery_manifest_canonical_json,
            );
            assert!(matches!(
                persistent
                    .apply_private_oram_mutation_material_v2_at_applied_entry(
                        &admission,
                        barrier.current_term,
                        barrier.base_index + 5,
                    )
                    .unwrap(),
                PrivateOramMutationAtEntryOutcome::Applied
            ));

            let point_stage = private_oram_mutation_parent_watermark_expectation_for_test(
                fixture.preparing_slot.active.as_ref().unwrap(),
                test_digest(80),
                vec![test_digest(81), test_digest(82), test_digest(83)],
            )
            .unwrap();
            for sequence in 1..=3 {
                let watermark =
                    truncate_private_oram_mutation_parent_watermark_expectation_for_test(
                        &point_stage,
                        sequence,
                    )
                    .unwrap();
                let operation = ApplyPrivateOramMutationMaterialV2::parent_progress(
                    fixture.key.clone(),
                    persistent
                        .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                        .unwrap(),
                    encode_private_oram_mutation_parent_watermark_expectation_v2(&watermark)
                        .unwrap(),
                );
                assert!(matches!(
                    persistent
                        .apply_private_oram_mutation_material_v2_at_applied_entry(
                            &operation,
                            barrier.current_term,
                            barrier.base_index + 5 + sequence,
                        )
                        .unwrap(),
                    PrivateOramMutationAtEntryOutcome::Applied
                ));
            }

            let activation = persistent
                .private_oram_activation_authority
                .as_ref()
                .unwrap()
                .locator();
            let capsule_entries = vec![(11, test_digest(91)), (13, test_digest(93))];
            let capsule_set_digest =
                private_oram_owner_capsule_set_digest_v2(&capsule_entries).unwrap();
            let owner_evidence = capsule_entries
                .into_iter()
                .map(|(owner_peer_id, capsule_digest)| {
                    let receipt = private_oram_owner_recovery_capsule_install_receipt_for_test(
                        owner_peer_id,
                        point_stage.watermark().descriptor_digest().to_string(),
                        capsule_digest,
                        capsule_set_digest.clone(),
                        activation.clone(),
                    )
                    .unwrap();
                    let seed = if owner_peer_id == 11 {
                        peer_11_seed
                    } else {
                        22
                    };
                    owner_capsule_install_evidence_for_test(
                        &fixture.key.collection_id,
                        &fixture.preparing_slot.active.as_ref().unwrap().mutation_id,
                        receipt,
                        seed,
                    )
                })
                .collect();
            let readiness = derive_private_oram_mutation_recovery_capsules_ready_v2(
                &point_stage,
                activation,
                owner_evidence,
            )
            .unwrap();
            let before = persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap();
            let operation = ApplyPrivateOramMutationMaterialV2::recovery_capsules_ready(
                fixture.key.clone(),
                before.clone(),
                encode_private_oram_mutation_recovery_capsules_ready_v2(&readiness).unwrap(),
            );
            let outcome = persistent
                .apply_private_oram_mutation_material_v2_at_applied_entry(
                    &operation,
                    barrier.current_term,
                    barrier.base_index + 9,
                )
                .unwrap();
            let after = persistent
                .private_oram_mutation_v2_aggregate_digest(&fixture.key)
                .unwrap();
            (outcome, before, after, persistent.current_unapplied_entry())
        }

        let (valid, valid_before, valid_after, valid_cursor) =
            apply_readiness_with_peer_11_seed(21);
        assert!(matches!(valid, PrivateOramMutationAtEntryOutcome::Applied));
        assert_ne!(valid_before, valid_after);
        assert_eq!(valid_cursor, None);

        let (attacker, attacker_before, attacker_after, attacker_cursor) =
            apply_readiness_with_peer_11_seed(99);
        let PrivateOramMutationAtEntryOutcome::Rejected(error) = attacker else {
            panic!("attacker-signed readiness must be rejected");
        };
        assert!(error.to_string().contains("material transition is invalid"));
        assert_eq!(attacker_before, attacker_after);
        assert_eq!(attacker_cursor, None);
    }

    #[test]
    fn private_oram_mutation_complete_patch_rejects_an_unexpected_apply_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        persistent.set_unapplied_entries(80, 80).unwrap();

        let error = persistent
            .apply_private_oram_mutation_at_applied_entry(
                &private_oram_mutation_apply(&fixture),
                81,
            )
            .unwrap_err();
        assert!(error.to_string().contains("cursor does not match"));
        assert_eq!(persistent.current_unapplied_entry(), Some(80));
        assert_eq!(
            persistent.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state.clone())
        );
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.current_unapplied_entry(), Some(80));
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state)
        );
    }

    #[test]
    fn private_oram_mutation_deterministic_rejection_commits_only_the_exact_cursor() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent.set_unapplied_entries(85, 85).unwrap();

        let outcome = persistent
            .apply_private_oram_mutation_at_applied_entry(
                &private_oram_mutation_apply(&fixture),
                85,
            )
            .unwrap();
        let PrivateOramMutationAtEntryOutcome::Rejected(error) = outcome else {
            panic!("mutation without an active lease must be rejected");
        };
        assert!(error.to_string().contains("lease is not active"));
        assert_eq!(persistent.current_unapplied_entry(), None);
        assert_eq!(persistent.last_applied_entry(), Some(85));
        assert_eq!(
            persistent.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state.clone())
        );
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot.clone())
        );
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.last_applied_entry(), Some(85));
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.genesis_slot)
        );
    }

    #[test]
    fn private_oram_mutation_save_failure_restores_every_consensus_map() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        let previous_states = persistent.private_oram_mutation_states.clone();
        let previous_slots = persistent.private_oram_mutation_lease_slots.clone();
        let previous_epochs = persistent.private_oram_epochs.clone();
        let previous_layouts = persistent.private_oram_layouts.clone();
        persistent.path = temp.path().join("missing-parent").join("raft_state.json");

        persistent
            .apply_private_oram_mutation(&private_oram_mutation_apply(&fixture))
            .unwrap_err();
        assert_eq!(persistent.private_oram_mutation_states, previous_states);
        assert_eq!(persistent.private_oram_mutation_lease_slots, previous_slots);
        assert_eq!(persistent.private_oram_epochs, previous_epochs);
        assert_eq!(persistent.private_oram_layouts, previous_layouts);
        assert!(!persistent.save_indeterminate.load(Ordering::Acquire));
    }

    #[test]
    fn private_oram_mutation_publish_failure_preserves_live_and_durable_prestate() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        persistent.set_unapplied_entries(41, 41).unwrap();
        let operation = private_oram_mutation_apply(&fixture);

        let error = persistent
            .apply_private_oram_mutation_at_applied_entry_with_backend(
                &operation,
                41,
                &PublishFaultBackend {
                    expose_candidate: false,
                },
            )
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains(PERSISTENT_SAVE_INDETERMINATE_MESSAGE)
        );
        assert!(persistent.save_indeterminate.load(Ordering::Acquire));
        assert_eq!(
            persistent.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state.clone())
        );
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot.clone())
        );
        assert_eq!(persistent.current_unapplied_entry(), Some(41));
        drop(persistent);

        let mut reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state.clone())
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot.clone())
        );
        assert_eq!(reloaded.current_unapplied_entry(), Some(41));
        reloaded
            .apply_private_oram_mutation_at_applied_entry(&operation, 41)
            .unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state)
        );
        assert_eq!(reloaded.current_unapplied_entry(), None);
        assert_eq!(reloaded.last_applied_entry(), Some(41));
    }

    #[test]
    fn private_oram_mutation_publish_error_after_rename_recovers_with_parent_sync() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();

        persistent
            .apply_private_oram_mutation_with_backend(
                &private_oram_mutation_apply(&fixture),
                &PublishFaultBackend {
                    expose_candidate: true,
                },
            )
            .unwrap();

        assert!(!persistent.dirty.load(Ordering::Acquire));
        assert!(!persistent.save_indeterminate.load(Ordering::Acquire));
        drop(persistent);
        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state)
        );
    }

    #[test]
    fn private_oram_mutation_retries_parent_sync_before_reporting_success() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();

        persistent
            .apply_private_oram_mutation_with_backend(
                &private_oram_mutation_apply(&fixture),
                &ParentSyncFaultBackend::new(1),
            )
            .unwrap();

        assert!(!persistent.dirty.load(Ordering::Acquire));
        assert!(!persistent.save_indeterminate.load(Ordering::Acquire));
        drop(persistent);
        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.committed_slot)
        );
    }

    #[test]
    fn private_oram_mutation_indeterminate_save_fences_live_prestate_and_reloads_poststate() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        persistent.set_unapplied_entries(52, 52).unwrap();
        let operation = private_oram_mutation_apply(&fixture);

        let error = persistent
            .apply_private_oram_mutation_at_applied_entry_with_backend(
                &operation,
                52,
                &ParentSyncFaultBackend::new(PERSISTENT_PARENT_SYNC_ATTEMPTS),
            )
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains(PERSISTENT_SAVE_INDETERMINATE_MESSAGE)
        );
        assert!(persistent.dirty.load(Ordering::Acquire));
        assert!(persistent.save_indeterminate.load(Ordering::Acquire));
        assert_eq!(
            persistent.private_oram_mutation_state(&fixture.key),
            Some(fixture.old_state.clone())
        );
        assert_eq!(
            persistent.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.preparing_slot.clone())
        );
        assert_eq!(persistent.current_unapplied_entry(), Some(52));
        let retry_error = persistent.save_if_dirty().unwrap_err();
        assert!(
            retry_error
                .to_string()
                .contains(PERSISTENT_SAVE_INDETERMINATE_MESSAGE)
        );
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.private_oram_mutation_state(&fixture.key),
            Some(fixture.new_state)
        );
        assert_eq!(
            reloaded.private_oram_mutation_lease_slot(&fixture.key),
            Some(fixture.committed_slot)
        );
        assert_eq!(reloaded.current_unapplied_entry(), None);
        assert_eq!(reloaded.last_applied_entry(), Some(52));
    }

    #[test]
    fn indeterminate_complete_patch_quarantines_every_persistent_mutation_until_restart() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = private_oram_mutation_fixture();
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        install_private_oram_mutation_fixture(&mut persistent, &fixture);
        persistent
            .compare_and_swap_private_oram_mutation_lease(&private_oram_mutation_acquire(&fixture))
            .unwrap();
        persistent.set_unapplied_entries(92, 92).unwrap();

        persistent
            .apply_private_oram_mutation_at_applied_entry_with_backend(
                &private_oram_mutation_apply(&fixture),
                92,
                &ParentSyncFaultBackend::new(PERSISTENT_PARENT_SYNC_ATTEMPTS),
            )
            .unwrap_err();
        assert!(persistent.save_indeterminate.load(Ordering::Acquire));

        let term_before = persistent.state.hard_state.term;
        let current_entry_before = persistent.current_unapplied_entry();
        let last_applied_before = persistent.last_applied_entry();
        let first_voter_before = persistent.first_voter;
        let metadata_before = persistent.cluster_metadata.clone();
        let mutation_state_before = persistent.private_oram_mutation_states.clone();
        let destination_digest = persistent_state_file_digest(&persistent.path).unwrap();

        let errors = [
            persistent
                .apply_state_update(|state| state.hard_state.term = 999)
                .unwrap_err(),
            persistent.set_unapplied_entries(100, 101).unwrap_err(),
            persistent.set_first_voter(999).unwrap_err(),
            persistent
                .update_cluster_metadata_key("must-not-appear".to_string(), serde_json::json!(1))
                .unwrap_err(),
            persistent
                .apply_private_oram_mutation(&private_oram_mutation_apply(&fixture))
                .unwrap_err(),
            persistent.save().unwrap_err(),
        ];
        for error in errors {
            assert!(
                error
                    .to_string()
                    .contains(PERSISTENT_SAVE_INDETERMINATE_MESSAGE)
            );
        }

        assert_eq!(persistent.state.hard_state.term, term_before);
        assert_eq!(persistent.current_unapplied_entry(), current_entry_before);
        assert_eq!(persistent.last_applied_entry(), last_applied_before);
        assert_eq!(persistent.first_voter, first_voter_before);
        assert_eq!(persistent.cluster_metadata, metadata_before);
        assert_eq!(
            persistent.private_oram_mutation_states,
            mutation_state_before
        );
        assert_eq!(
            persistent_state_file_digest(&persistent.path).unwrap(),
            destination_digest
        );
    }

    #[test]
    fn private_oram_mutation_snapshot_requires_exact_state_slot_and_epochs() {
        let fixture = private_oram_mutation_fixture();
        let state_key = private_oram_mutation_key_digest(&fixture.key);
        let layout_key = private_oram_layout_key_digest(&fixture.layout_key);
        let epoch_maps = HashMap::from([
            (
                private_oram_epoch_key_digest(&fixture.hnsw_key),
                fixture.old_state.indexes[0].epoch.clone(),
            ),
            (
                private_oram_epoch_key_digest(&fixture.result_key),
                fixture.old_state.indexes[1].epoch.clone(),
            ),
        ]);
        let states = HashMap::from([(state_key.clone(), fixture.old_state.clone())]);
        let layouts = HashMap::from([(layout_key, fixture.layout.clone())]);
        let genesis_slots =
            HashMap::from([(state_key.clone(), fixture.genesis_slot.clone().into())]);
        Persistent::validate_private_oram_snapshot_state(
            &epoch_maps,
            &HashMap::new(),
            &layouts,
            &HashMap::new(),
            &states,
            &genesis_slots,
            None,
        )
        .unwrap();

        let abort_decided_slots = HashMap::from([(
            state_key.clone(),
            private_oram_mutation_abort_decided_slot(&fixture).into(),
        )]);
        Persistent::validate_private_oram_snapshot_state(
            &epoch_maps,
            &HashMap::new(),
            &layouts,
            &HashMap::new(),
            &states,
            &abort_decided_slots,
            None,
        )
        .unwrap();

        let missing_slot = Persistent::validate_private_oram_snapshot_state(
            &epoch_maps,
            &HashMap::new(),
            &layouts,
            &HashMap::new(),
            &states,
            &HashMap::new(),
            None,
        )
        .unwrap_err();
        assert!(missing_slot.to_string().contains("lease slot snapshot"));

        let mut mixed_epochs = epoch_maps.clone();
        mixed_epochs.insert(
            private_oram_epoch_key_digest(&fixture.hnsw_key),
            fixture.new_state.indexes[0].epoch.clone(),
        );
        let mixed_epoch = Persistent::validate_private_oram_snapshot_state(
            &mixed_epochs,
            &HashMap::new(),
            &layouts,
            &HashMap::new(),
            &states,
            &genesis_slots,
            None,
        )
        .unwrap_err();
        assert!(mixed_epoch.to_string().contains("mutation state snapshot"));

        let active_slots =
            HashMap::from([(state_key.clone(), fixture.preparing_slot.clone().into())]);
        Persistent::validate_private_oram_snapshot_state(
            &epoch_maps,
            &HashMap::new(),
            &layouts,
            &HashMap::new(),
            &states,
            &active_slots,
            None,
        )
        .unwrap();

        let mut rogue_owner_slot = fixture.preparing_slot;
        rogue_owner_slot.active.as_mut().unwrap().owner_peer_id = 99;
        let rogue_owner_slots = HashMap::from([(state_key, rogue_owner_slot.into())]);
        let rogue_owner = Persistent::validate_private_oram_snapshot_state(
            &epoch_maps,
            &HashMap::new(),
            &layouts,
            &HashMap::new(),
            &states,
            &rogue_owner_slots,
            None,
        )
        .unwrap_err();
        assert!(rogue_owner.to_string().contains("lease slot snapshot"));

        let committed_epochs = HashMap::from([
            (
                private_oram_epoch_key_digest(&fixture.hnsw_key),
                fixture.new_state.indexes[0].epoch.clone(),
            ),
            (
                private_oram_epoch_key_digest(&fixture.result_key),
                fixture.new_state.indexes[1].epoch.clone(),
            ),
        ]);
        let committed_layout = PrivateOramConsensusLayout {
            index_state_digest: private_oram_consensus_state_index_digest(&fixture.new_state)
                .unwrap(),
            ..fixture.layout
        };
        let committed_states = HashMap::from([(
            private_oram_mutation_key_digest(&fixture.key),
            fixture.new_state.clone(),
        )]);
        let committed_layouts = HashMap::from([(
            private_oram_layout_key_digest(&fixture.layout_key),
            committed_layout,
        )]);
        let abort_after_commit = Persistent::validate_private_oram_snapshot_state(
            &committed_epochs,
            &HashMap::new(),
            &committed_layouts,
            &HashMap::new(),
            &committed_states,
            &abort_decided_slots,
            None,
        )
        .unwrap_err();
        assert!(
            abort_after_commit
                .to_string()
                .contains("lease slot snapshot")
        );

        let committed_slots = HashMap::from([(
            private_oram_mutation_key_digest(&fixture.key),
            fixture.committed_slot.into(),
        )]);
        Persistent::validate_private_oram_snapshot_state(
            &committed_epochs,
            &HashMap::new(),
            &committed_layouts,
            &HashMap::new(),
            &committed_states,
            &committed_slots,
            None,
        )
        .unwrap();
    }

    #[test]
    fn private_oram_mutation_v2_nested_schema_is_strict() {
        let fixture = private_oram_mutation_fixture();

        let mut missing_transition = serde_json::to_value(&fixture.new_state).unwrap();
        missing_transition
            .as_object_mut()
            .unwrap()
            .remove("last_transition");
        assert!(
            serde_json::from_value::<PrivateOramConsensusCollectionStateV2>(missing_transition)
                .is_err()
        );

        let mut unknown_index_field = serde_json::to_value(&fixture.new_state).unwrap();
        unknown_index_field["indexes"][0]
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<PrivateOramConsensusCollectionStateV2>(unknown_index_field)
                .is_err()
        );

        let mut unknown_transition_field = serde_json::to_value(&fixture.new_state).unwrap();
        unknown_transition_field["last_transition"]
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<PrivateOramConsensusCollectionStateV2>(
                unknown_transition_field,
            )
            .is_err()
        );

        let committed_phase = fixture.committed_slot.active.unwrap().phase;
        let mut unknown_phase_field = serde_json::to_value(&committed_phase).unwrap();
        unknown_phase_field["consensus_committed"]
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<PrivateOramMutationLeasePhase>(unknown_phase_field).is_err()
        );

        let abort_decided = PrivateOramMutationLeasePhase::AbortDecided;
        assert_eq!(
            serde_json::to_value(&abort_decided).unwrap(),
            serde_json::Value::String("abort_decided".to_string())
        );
        assert_eq!(
            serde_json::from_value::<PrivateOramMutationLeasePhase>(serde_json::Value::String(
                "abort_decided".to_string(),
            ))
            .unwrap(),
            abort_decided
        );
        assert!(
            serde_json::from_value::<PrivateOramMutationLeasePhase>(serde_json::json!({
                "abort_decided": {}
            }))
            .is_err()
        );
        let abort_decided_cbor = serde_cbor::to_vec(&abort_decided).unwrap();
        assert_eq!(
            serde_cbor::from_slice::<PrivateOramMutationLeasePhase>(&abort_decided_cbor).unwrap(),
            abort_decided
        );
    }

    #[test]
    fn private_oram_mutation_consensus_digests_match_known_answer() {
        let fixture = private_oram_mutation_fixture();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &fixture.new_state.last_transition
        else {
            unreachable!();
        };
        let old_record =
            canonical_private_oram_consensus_state_record_digest(&fixture.old_state).unwrap();
        let new_core =
            crate::content_manager::consensus_ops::canonical_private_oram_consensus_state_core_digest(
                &fixture.new_state,
            )
            .unwrap();
        let transition = canonical_private_oram_mutation_transition_digest(
            &fixture.old_state,
            &fixture.new_state,
        )
        .unwrap();
        let receipt = canonical_private_oram_mutation_receipt_digest(receipt).unwrap();
        let new_record =
            canonical_private_oram_consensus_state_record_digest(&fixture.new_state).unwrap();

        assert_eq!(old_record, "LvW2Zp_Bli40rzOYerpyVv5r7mA_orFhFsQoyU-c1vg");
        assert_eq!(new_core, "p1Oei5zjwOqaw6lr7INVHoUAkUvJcZecoGNcAuXwFWI");
        assert_eq!(transition, "3RJ_qZ_CBzLkctDMQOKd-jUFA_Yesx2g2h9E_j93XQY");
        assert_eq!(receipt, "RnlVSq33mERZh9WH874pHc1YW3DXe9ahLQdx5bIZ83g");
        assert_eq!(new_record, "4156xu4D3H6HOWeywE2nRBusgZVQplLSaRxz_ch-XJc");
    }

    #[test]
    fn private_oram_epoch_cas_persists_and_rejects_stale_or_invalid_updates() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let initial = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: None,
        };
        let next = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[11; 32])),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let stale = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: next.clone(),
            })
            .unwrap_err();
        assert!(
            stale
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let non_increasing = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: initial.index_epoch,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: next.writeback_digest.clone(),
                },
            })
            .unwrap_err();
        assert!(
            non_increasing
                .to_string()
                .contains("consensus epoch must increase"),
        );

        let invalid_root_sentinel = "private-oram-invalid-root-sentinel";
        let invalid_root = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: invalid_root_sentinel.to_string(),
                    writeback_digest: next.writeback_digest.clone(),
                },
            })
            .unwrap_err();
        assert!(
            invalid_root
                .to_string()
                .contains("consensus root hash is invalid"),
        );
        assert!(!invalid_root.to_string().contains(invalid_root_sentinel));

        let invalid_writeback_digest_sentinel = "private-oram-invalid-writeback-digest-sentinel";
        let invalid_writeback_digest = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: Some(invalid_writeback_digest_sentinel.to_string()),
                },
            })
            .unwrap_err();
        assert!(
            invalid_writeback_digest
                .to_string()
                .contains("consensus writeback digest is invalid"),
        );
        assert!(
            !invalid_writeback_digest
                .to_string()
                .contains(invalid_writeback_digest_sentinel),
        );

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: next.clone(),
            })
            .unwrap();

        let conflicting_digest = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(initial),
                new: PrivateOramConsensusEpoch {
                    index_epoch: next.index_epoch,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: Some(BASE64URL_NOPAD.encode(&[12; 32])),
                },
            })
            .unwrap_err();
        assert!(
            conflicting_digest
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(next.clone()));
        drop(persistent);

        let mut reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        reloaded
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: Some(PrivateOramConsensusEpoch {
                    index_epoch: 42,
                    root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                    writeback_digest: None,
                }),
                new: next.clone(),
            })
            .unwrap();
        assert_eq!(reloaded.private_oram_epoch(&key), Some(next));
    }

    #[test]
    fn private_oram_layout_cas_persists_and_enforces_canonical_transitions() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramLayoutKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let initial = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[41; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[42; 32]),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9, 11],
            layout_digest: BASE64URL_NOPAD.encode(&[43; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[44; 32]),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        let invalid_initial_generation = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: None,
                new: PrivateOramConsensusLayout {
                    generation: 2,
                    ..initial.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(
            invalid_initial_generation.contains("layout must start at generation one"),
            "{invalid_initial_generation}"
        );

        let initial_operation = CompareAndSwapPrivateOramLayout {
            key: key.clone(),
            expected: None,
            new: initial.clone(),
        };
        persistent
            .compare_and_swap_private_oram_layout(&initial_operation)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&initial_operation)
            .unwrap();
        assert_eq!(persistent.private_oram_layout(&key), Some(initial.clone()));

        let stale = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: None,
                new: PrivateOramConsensusLayout {
                    layout_digest: BASE64URL_NOPAD.encode(&[45; 32]),
                    ..initial.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(stale.contains("layout CAS precondition failed"), "{stale}");

        let skipped_generation = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusLayout {
                    generation: 3,
                    ..next.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(
            skipped_generation.contains("layout generation must increase by one"),
            "{skipped_generation}"
        );

        let invalid_owner_sets = [
            Vec::new(),
            vec![9, 7],
            vec![7, 7],
            (0..=PRIVATE_ORAM_LAYOUT_MAX_OWNERS as PeerId).collect(),
        ];
        for owner_peer_ids in invalid_owner_sets {
            let noncanonical_owners = persistent
                .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                    key: key.clone(),
                    expected: Some(initial.clone()),
                    new: PrivateOramConsensusLayout {
                        owner_peer_ids,
                        ..next.clone()
                    },
                })
                .unwrap_err()
                .to_string();
            assert!(
                noncanonical_owners.contains("consensus layout is invalid"),
                "{noncanonical_owners}"
            );
        }

        let invalid_digest_sentinel = "private-oram-layout-digest-sentinel";
        let invalid_digest = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: Some(initial.clone()),
                new: PrivateOramConsensusLayout {
                    layout_digest: invalid_digest_sentinel.to_string(),
                    ..next.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(invalid_digest.contains("consensus layout is invalid"));
        assert!(!invalid_digest.contains(invalid_digest_sentinel));

        let transition = CompareAndSwapPrivateOramLayout {
            key: key.clone(),
            expected: Some(initial),
            new: next.clone(),
        };
        persistent
            .compare_and_swap_private_oram_layout(&transition)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&transition)
            .unwrap();
        assert_eq!(persistent.private_oram_layout(&key), Some(next.clone()));
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.private_oram_layout(&key), Some(next));
    }

    #[test]
    fn private_oram_collection_layout_transition_binds_exact_lease_and_current_index_state() {
        let temp = tempfile::tempdir().unwrap();
        let collection_id = "collection-uuid-1";
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[43; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[44; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[45; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[46; 32]),
        };
        let current_index_state_digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[(epoch_key.clone(), epoch.clone())],
        )
        .unwrap();
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[47; 32]),
            index_state_digest: current_index_state_digest,
        };
        let transition = PrivateOramCollectionLayoutTransition {
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(current.clone()),
                new: next,
            },
            leases: vec![
                crate::content_manager::consensus_ops::PrivateOramLayoutLeaseBinding {
                    key: epoch_key.clone(),
                    lease: lease.clone(),
                },
            ],
            shard_key_change: None,
            collection_meta: Box::new(
                crate::content_manager::collection_meta_ops::CollectionMetaOperations::Nop {
                    token: 7,
                },
            ),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key.clone(),
                expected: None,
                new: epoch,
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key,
                expected: None,
                new: Some(lease),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key,
                expected: None,
                new: current,
            })
            .unwrap();

        persistent
            .validate_private_oram_collection_layout_transition(&transition)
            .unwrap();

        let shard_key_sentinel = ShardKey::Keyword("private-layout-key-sentinel".into());
        let mut missing_descriptor = transition.clone();
        missing_descriptor.collection_meta = Box::new(
            crate::content_manager::collection_meta_ops::CollectionMetaOperations::DropShardKey(
                crate::content_manager::collection_meta_ops::DropShardKey {
                    collection_name: "docs".to_string(),
                    shard_key: shard_key_sentinel.clone(),
                },
            ),
        );
        assert!(
            persistent
                .validate_private_oram_collection_layout_transition(&missing_descriptor)
                .is_err()
        );

        let mut new_owner_transition = transition.clone();
        new_owner_transition.layout.new.owner_peer_ids = vec![7, 9, 11];
        new_owner_transition.layout.new.layout_digest = BASE64URL_NOPAD.encode(&[49; 32]);
        new_owner_transition.collection_meta = Box::new(
            crate::content_manager::collection_meta_ops::CollectionMetaOperations::CreateShardKey(
                crate::content_manager::collection_meta_ops::CreateShardKey {
                    collection_name: "docs".to_string(),
                    shard_key: shard_key_sentinel.clone(),
                    placement: vec![vec![11]],
                    initial_state: Some(ReplicaState::Active),
                },
            ),
        );
        new_owner_transition.shard_key_change = Some(PrivateOramShardKeyLayoutChange {
            kind: PrivateOramShardKeyLayoutChangeKind::Create,
            shard_key: shard_key_sentinel.clone(),
            entries: vec![PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: Some(shard_key_sentinel.clone()),
                owner_peer_ids: vec![11],
            }],
            preinstalled_new_owner_peer_ids: vec![11],
        });
        persistent
            .validate_private_oram_collection_layout_transition(&new_owner_transition)
            .unwrap();

        let mut missing_new_owner_preinstall = new_owner_transition.clone();
        missing_new_owner_preinstall
            .shard_key_change
            .as_mut()
            .unwrap()
            .preinstalled_new_owner_peer_ids
            .clear();
        assert!(
            persistent
                .validate_private_oram_collection_layout_transition(&missing_new_owner_preinstall,)
                .is_err()
        );

        let mut forged_new_owner_preinstall = new_owner_transition;
        forged_new_owner_preinstall
            .shard_key_change
            .as_mut()
            .unwrap()
            .preinstalled_new_owner_peer_ids = vec![12];
        assert!(
            persistent
                .validate_private_oram_collection_layout_transition(&forged_new_owner_preinstall,)
                .is_err()
        );

        let mut mismatched_descriptor = transition.clone();
        mismatched_descriptor.shard_key_change = Some(PrivateOramShardKeyLayoutChange {
            kind: PrivateOramShardKeyLayoutChangeKind::Drop,
            shard_key: shard_key_sentinel.clone(),
            entries: vec![PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: Some(shard_key_sentinel),
                owner_peer_ids: vec![7],
            }],
            preinstalled_new_owner_peer_ids: Vec::new(),
        });
        assert!(
            persistent
                .validate_private_oram_collection_layout_transition(&mismatched_descriptor)
                .is_err()
        );

        let mut wrong_lease = transition.clone();
        wrong_lease.leases[0].lease.lease_id_hash = BASE64URL_NOPAD.encode(&[48; 32]);
        let error = persistent
            .validate_private_oram_collection_layout_transition(&wrong_lease)
            .unwrap_err()
            .to_string();
        assert!(error.contains("layout transition is invalid"), "{error}");
        assert!(!error.contains(&wrong_lease.leases[0].lease.lease_id_hash));
    }

    #[test]
    fn private_oram_resharding_validator_binds_leases_layout_and_index_state() {
        let temp = tempfile::tempdir().unwrap();
        let collection_id = "qdrant-sec-resharding-collection-sentinel";
        let index_name_sentinel = "qdrant-sec-resharding-index-sentinel";
        let shard_key_sentinel = "qdrant-sec-resharding-shard-key-sentinel";
        let lease_hash_sentinel = BASE64URL_NOPAD.encode(&[81; 32]);
        let root_sentinel = BASE64URL_NOPAD.encode(&[82; 32]);
        let hnsw_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: index_name_sentinel.to_string(),
        };
        let result_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let hnsw_epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: root_sentinel.clone(),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[83; 32])),
        };
        let result_epoch = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[84; 32]),
            writeback_digest: None,
        };
        let state_bindings = vec![
            PrivateOramLayoutIndexStateBinding {
                key: hnsw_key.clone(),
                state: hnsw_epoch.clone(),
            },
            PrivateOramLayoutIndexStateBinding {
                key: result_key.clone(),
                state: result_epoch.clone(),
            },
        ];
        let states = state_bindings
            .iter()
            .map(|binding| (binding.key.clone(), binding.state.clone()))
            .collect::<Vec<_>>();
        let index_state_digest =
            canonical_private_oram_index_state_digest(collection_id, &states).unwrap();
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let expected = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[85; 32]),
            index_state_digest: index_state_digest.clone(),
        };
        let new = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[86; 32]),
            index_state_digest,
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash_sentinel.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let lease_bindings = states
            .iter()
            .map(|(key, _)| PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease: lease.clone(),
            })
            .collect::<Vec<_>>();
        let resharding_key = ReshardKey {
            uuid: Uuid::from_u128(21),
            direction: ReshardingDirection::Up,
            peer_id: 9,
            shard_id: 2,
            shard_key: Some(ShardKey::from(shard_key_sentinel)),
        };
        let transition = PrivateOramReshardingLayoutTransition {
            resharding_key: resharding_key.clone(),
            target_shard_owner_peer_ids: vec![9],
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(expected.clone()),
                new: new.clone(),
            },
            index_states: state_bindings,
        };
        let start = PrivateOramReshardingOperation {
            leases: lease_bindings.clone(),
            transition: transition.clone(),
            collection_meta: Box::new(CollectionMetaOperations::Resharding(
                "qdrant-sec-resharding-name-sentinel".to_string(),
                ReshardingOperation::Start(resharding_key.clone()),
            )),
        };
        let finish = PrivateOramReshardingOperation {
            leases: lease_bindings,
            transition,
            collection_meta: Box::new(CollectionMetaOperations::Resharding(
                "qdrant-sec-resharding-name-sentinel".to_string(),
                ReshardingOperation::Finish(resharding_key.clone()),
            )),
        };

        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        for (key, epoch) in &states {
            persistent
                .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                    key: key.clone(),
                    expected: None,
                    new: epoch.clone(),
                })
                .unwrap();
            persistent
                .compare_and_swap_private_oram_session_lease(
                    &CompareAndSwapPrivateOramSessionLease {
                        key: key.clone(),
                        expected: None,
                        new: Some(lease.clone()),
                    },
                )
                .unwrap();
        }
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: expected.clone(),
            })
            .unwrap();

        assert_eq!(
            persistent
                .validate_private_oram_resharding_operation(&start)
                .unwrap(),
            start.transition.layout,
        );
        assert_eq!(
            persistent
                .validate_private_oram_resharding_operation(&finish)
                .unwrap(),
            finish.transition.layout,
        );

        for rendered in [format!("{start:?}"), format!("{finish:?}")] {
            for sentinel in [
                collection_id,
                index_name_sentinel,
                shard_key_sentinel,
                &lease_hash_sentinel,
                &root_sentinel,
                "qdrant-sec-resharding-name-sentinel",
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }

        let mut wrong_lease = start.clone();
        wrong_lease.leases[0].lease.lease_id_hash = BASE64URL_NOPAD.encode(&[87; 32]);
        let wrong_lease_hash = wrong_lease.leases[0].lease.lease_id_hash.clone();
        let error = persistent
            .validate_private_oram_resharding_operation(&wrong_lease)
            .unwrap_err()
            .to_string();
        assert!(error.contains("resharding layout transition is invalid"));
        assert!(!error.contains(&wrong_lease_hash));

        let mut noncanonical = finish.clone();
        noncanonical.transition.index_states.reverse();
        assert!(
            persistent
                .validate_private_oram_resharding_operation(&noncanonical)
                .unwrap_err()
                .to_string()
                .contains("resharding layout transition is invalid")
        );

        let mut wrong_key = start.clone();
        let CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(key)) =
            wrong_key.collection_meta.as_mut()
        else {
            unreachable!();
        };
        key.uuid = Uuid::from_u128(22);
        assert!(
            persistent
                .validate_private_oram_resharding_operation(&wrong_key)
                .unwrap_err()
                .to_string()
                .contains("resharding layout transition is invalid")
        );

        persistent
            .compare_and_swap_private_oram_layout(&finish.transition.layout)
            .unwrap();
        assert_eq!(
            persistent
                .validate_private_oram_resharding_operation(&finish)
                .unwrap(),
            finish.transition.layout,
        );
        assert!(
            persistent
                .validate_private_oram_resharding_operation(&start)
                .unwrap_err()
                .to_string()
                .contains("resharding layout transition is invalid")
        );
    }

    #[test]
    fn private_oram_shard_transfer_validators_bind_leases_layout_and_index_state() {
        let temp = tempfile::tempdir().unwrap();
        let collection_id = "collection-uuid-1";
        let hnsw_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let result_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let hnsw_epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[41; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[42; 32])),
        };
        let result_epoch = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
            writeback_digest: None,
        };
        let states = vec![
            (hnsw_key.clone(), hnsw_epoch.clone()),
            (result_key.clone(), result_epoch.clone()),
        ];
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[44; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let expected = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[45; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[46; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[47; 32]),
            index_state_digest: canonical_private_oram_index_state_digest(collection_id, &states)
                .unwrap(),
        };
        let transition = PrivateOramTransferLayoutTransition {
            collection_id: collection_id.to_string(),
            expected: PrivateOramTransferLayoutState {
                generation: expected.generation,
                owner_peer_ids: expected.owner_peer_ids.clone(),
                layout_digest: expected.layout_digest.clone(),
                index_state_digest: expected.index_state_digest.clone(),
            },
            new: PrivateOramTransferLayoutState {
                generation: new.generation,
                owner_peer_ids: new.owner_peer_ids.clone(),
                layout_digest: new.layout_digest.clone(),
                index_state_digest: new.index_state_digest.clone(),
            },
            index_states: vec![
                PrivateOramTransferIndexState {
                    index_kind: PrivateOramTransferIndexKind::Hnsw,
                    index_name: hnsw_key.index_name.clone(),
                    index_epoch: hnsw_epoch.index_epoch,
                    root_hash: hnsw_epoch.root_hash.clone(),
                    writeback_digest: hnsw_epoch.writeback_digest.clone(),
                },
                PrivateOramTransferIndexState {
                    index_kind: PrivateOramTransferIndexKind::ResultPayload,
                    index_name: result_key.index_name.clone(),
                    index_epoch: result_epoch.index_epoch,
                    root_hash: result_epoch.root_hash.clone(),
                    writeback_digest: result_epoch.writeback_digest.clone(),
                },
            ],
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 7,
            to: 9,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(transition),
            filter: None,
        };
        let lease_bindings = states
            .iter()
            .map(|(key, _)| PrivateOramLayoutLeaseBinding {
                key: key.clone(),
                lease: lease.clone(),
            })
            .collect::<Vec<_>>();
        let start = PrivateOramShardTransferStart {
            leases: lease_bindings,
            collection_meta: Box::new(CollectionMetaOperations::TransferShard(
                "docs".to_string(),
                ShardTransferOperations::Start(transfer.clone()),
            )),
        };
        let finish = PrivateOramShardTransferFinish {
            collection_meta: Box::new(CollectionMetaOperations::TransferShard(
                "docs".to_string(),
                ShardTransferOperations::Finish(transfer),
            )),
        };

        let recovery_temp = tempfile::tempdir().unwrap();
        let mut recovery_start = start.clone();
        let CollectionMetaOperations::TransferShard(_, ShardTransferOperations::Start(transfer)) =
            recovery_start.collection_meta.as_mut()
        else {
            unreachable!();
        };
        let transition = transfer.private_oram_layout_transition.as_mut().unwrap();
        transition.expected.index_state_digest = new.index_state_digest.clone();
        let recovery_expected = PrivateOramConsensusLayout {
            index_state_digest: new.index_state_digest.clone(),
            ..expected.clone()
        };
        let precommitted = PrivateOramConsensusLayout {
            generation: recovery_expected.generation,
            owner_peer_ids: new.owner_peer_ids.clone(),
            layout_digest: new.layout_digest.clone(),
            index_state_digest: new.index_state_digest.clone(),
        };
        let mut recovery =
            Persistent::load_or_init(recovery_temp.path(), true, false, Some(7)).unwrap();
        for (key, epoch) in &states {
            recovery
                .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                    key: key.clone(),
                    expected: None,
                    new: epoch.clone(),
                })
                .unwrap();
            recovery
                .compare_and_swap_private_oram_session_lease(
                    &CompareAndSwapPrivateOramSessionLease {
                        key: key.clone(),
                        expected: None,
                        new: Some(lease.clone()),
                    },
                )
                .unwrap();
        }
        recovery
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: precommitted.clone(),
            })
            .unwrap();
        let recovery_cas = recovery
            .validate_private_oram_shard_transfer_start(&recovery_start)
            .unwrap()
            .unwrap();
        assert_eq!(recovery_cas.expected, Some(precommitted));
        assert_eq!(recovery_cas.new, new.clone());
        recovery
            .compare_and_swap_private_oram_layout(&recovery_cas)
            .unwrap();
        assert_eq!(
            recovery
                .validate_private_oram_shard_transfer_start(&recovery_start)
                .unwrap(),
            None,
        );

        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        for (key, epoch) in &states {
            persistent
                .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                    key: key.clone(),
                    expected: None,
                    new: epoch.clone(),
                })
                .unwrap();
            persistent
                .compare_and_swap_private_oram_session_lease(
                    &CompareAndSwapPrivateOramSessionLease {
                        key: key.clone(),
                        expected: None,
                        new: Some(lease.clone()),
                    },
                )
                .unwrap();
        }
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: expected.clone(),
            })
            .unwrap();

        assert!(
            persistent
                .validate_private_oram_shard_transfer_start(&start)
                .unwrap()
                .is_none()
        );
        let layout_cas = persistent
            .validate_private_oram_shard_transfer_finish(&finish)
            .unwrap();
        assert_eq!(layout_cas.expected, Some(expected));
        assert_eq!(layout_cas.new, new.clone());

        let mut wrong_lease = start.clone();
        wrong_lease.leases[1].lease.lease_id_hash = BASE64URL_NOPAD.encode(&[48; 32]);
        let error = persistent
            .validate_private_oram_shard_transfer_start(&wrong_lease)
            .unwrap_err()
            .to_string();
        assert!(error.contains("transfer layout transition is invalid"));
        assert!(!error.contains(&wrong_lease.leases[1].lease.lease_id_hash));

        let mut noncanonical = finish.clone();
        let CollectionMetaOperations::TransferShard(_, ShardTransferOperations::Finish(transfer)) =
            noncanonical.collection_meta.as_mut()
        else {
            unreachable!();
        };
        transfer
            .private_oram_layout_transition
            .as_mut()
            .unwrap()
            .index_states
            .reverse();
        assert!(
            persistent
                .validate_private_oram_shard_transfer_finish(&noncanonical)
                .unwrap_err()
                .to_string()
                .contains("transfer layout transition is invalid")
        );

        persistent
            .compare_and_swap_private_oram_layout(&layout_cas)
            .unwrap();
        assert_eq!(persistent.private_oram_layout(&layout_key), Some(new));
        assert_eq!(
            persistent
                .validate_private_oram_shard_transfer_finish(&finish)
                .unwrap(),
            layout_cas,
        );

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: hnsw_key,
                expected: Some(hnsw_epoch),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 44,
                    root_hash: BASE64URL_NOPAD.encode(&[49; 32]),
                    writeback_digest: Some(BASE64URL_NOPAD.encode(&[50; 32])),
                },
            })
            .unwrap();
        assert!(
            persistent
                .validate_private_oram_shard_transfer_finish(&finish)
                .unwrap_err()
                .to_string()
                .contains("transfer layout transition is invalid")
        );
    }

    #[test]
    fn private_oram_layout_snapshot_validation_rejects_malformed_records_before_replace() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramLayoutKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let initial = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[61; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[62; 32]),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();

        let invalid_key_sentinel = "private-oram-layout-snapshot-key-sentinel";
        let invalid_key_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                HashMap::from([(invalid_key_sentinel.to_string(), initial.clone())]),
                Default::default(),
                Default::default(),
                Default::default(),
                None,
                None,
                None,
            )
            .unwrap_err()
            .to_string();
        assert!(
            invalid_key_error.contains("consensus layout snapshot is invalid"),
            "{invalid_key_error}"
        );
        assert!(!invalid_key_error.contains(invalid_key_sentinel));
        assert_eq!(persistent.private_oram_layout(&key), Some(initial.clone()));

        let invalid_digest_sentinel = "private-oram-layout-snapshot-digest-sentinel";
        let invalid_layout_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                HashMap::from([(
                    private_oram_layout_key_digest(&key),
                    PrivateOramConsensusLayout {
                        layout_digest: invalid_digest_sentinel.to_string(),
                        ..initial.clone()
                    },
                )]),
                Default::default(),
                Default::default(),
                Default::default(),
                None,
                None,
                None,
            )
            .unwrap_err()
            .to_string();
        assert!(
            invalid_layout_error.contains("consensus layout snapshot is invalid"),
            "{invalid_layout_error}"
        );
        assert!(!invalid_layout_error.contains(invalid_digest_sentinel));
        assert_eq!(persistent.private_oram_layout(&key), Some(initial));
    }

    #[test]
    fn private_oram_session_lease_cas_enforces_renewal_takeover_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let lease_hash_a = BASE64URL_NOPAD.encode(&[21; 32]);
        let lease_hash_b = BASE64URL_NOPAD.encode(&[22; 32]);
        let lease_a = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash_a.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let renewed_a = PrivateOramSessionLease {
            issued_at_unix: 120,
            expires_at_unix: 220,
            ..lease_a.clone()
        };
        let lease_b = PrivateOramSessionLease {
            owner_peer_id: 9,
            lease_id_hash: lease_hash_b.clone(),
            issued_at_unix: 220,
            expires_at_unix: 280,
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        let acquire = CompareAndSwapPrivateOramSessionLease {
            key: key.clone(),
            expected: None,
            new: Some(lease_a.clone()),
        };
        persistent
            .compare_and_swap_private_oram_session_lease(&acquire)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&acquire)
            .unwrap();
        assert_eq!(
            persistent.private_oram_session_lease(&key),
            Some(lease_a.clone())
        );

        let early_takeover = persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_a.clone()),
                new: Some(PrivateOramSessionLease {
                    issued_at_unix: 159,
                    expires_at_unix: 219,
                    ..lease_b.clone()
                }),
            })
            .unwrap_err()
            .to_string();
        assert!(early_takeover.contains("session lease transition is invalid"));

        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_a.clone()),
                new: Some(renewed_a.clone()),
            })
            .unwrap();
        let stale_release = persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_a),
                new: None,
            })
            .unwrap_err()
            .to_string();
        assert!(stale_release.contains("session lease CAS precondition failed"));

        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(renewed_a),
                new: Some(lease_b.clone()),
            })
            .unwrap();
        assert_eq!(
            persistent.private_oram_session_lease(&key),
            Some(lease_b.clone())
        );

        let rendered = format!("{:?}", persistent.private_oram_session_lease(&key).unwrap());
        assert!(rendered.contains("owner_peer_id: 9"));
        assert!(!rendered.contains(&lease_hash_a));
        assert!(!rendered.contains(&lease_hash_b));

        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease_b),
                new: None,
            })
            .unwrap();
        assert_eq!(persistent.private_oram_session_lease(&key), None);
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(reloaded.private_oram_session_lease(&key), None);

        let invalid_hash = "private-oram-session-lease-hash-sentinel";
        let invalid = validate_private_oram_session_lease(&PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: invalid_hash.to_string(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        })
        .unwrap_err()
        .to_string();
        assert!(invalid.contains("session lease is invalid"));
        assert!(!invalid.contains(invalid_hash));

        let overlong = validate_private_oram_session_lease(&PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[23; 32]),
            issued_at_unix: 100,
            expires_at_unix: 100 + PRIVATE_ORAM_SESSION_LEASE_MAX_SECS + 1,
        })
        .unwrap_err()
        .to_string();
        assert!(overlong.contains("session lease is invalid"));

        let malformed_snapshot_key = "private-oram-session-lease-snapshot-key-sentinel";
        let malformed_snapshot = validate_private_oram_session_lease_snapshot(&HashMap::from([(
            malformed_snapshot_key.to_string(),
            PrivateOramSessionLease {
                owner_peer_id: 7,
                lease_id_hash: BASE64URL_NOPAD.encode(&[24; 32]),
                issued_at_unix: 100,
                expires_at_unix: 160,
            },
        )]))
        .unwrap_err()
        .to_string();
        assert!(malformed_snapshot.contains("session lease snapshot is invalid"));
        assert!(!malformed_snapshot.contains(malformed_snapshot_key));
    }

    #[test]
    fn private_oram_external_recovery_cas_commits_monotonically_and_replays() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let operation_id_hash = BASE64URL_NOPAD.encode(&[31; 32]);
        let checkpoint_digest = BASE64URL_NOPAD.encode(&[32; 32]);
        let install_intent_digest = BASE64URL_NOPAD.encode(&[30; 32]);
        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 7,
            operation_id_hash: operation_id_hash.clone(),
            checkpoint_digest: checkpoint_digest.clone(),
            backup_generation: 7,
            issued_at_unix: 100,
            expires_at_unix: 160,
            install_intent_digest: None,
            phase: PrivateOramExternalRecoveryLeasePhase::Staging,
        };
        let acquired = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(lease.clone()),
        };
        let prepared = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                phase: PrivateOramExternalRecoveryLeasePhase::Installing,
                install_intent_digest: Some(install_intent_digest.clone()),
                ..lease.clone()
            }),
            ..acquired.clone()
        };
        let committed = PrivateOramExternalRecoveryState {
            committed_backup_generation: 7,
            committed_checkpoint_digest: Some(checkpoint_digest.clone()),
            committed_install_intent_digest: Some(install_intent_digest.clone()),
            active_lease: None,
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        let acquire = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: None,
            new: Some(acquired.clone()),
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(&acquire)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&acquire)
            .unwrap();
        assert_eq!(
            persistent.private_oram_external_recovery(&key),
            Some(acquired.clone())
        );

        let direct_commit = persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(acquired.clone()),
                    new: Some(committed.clone()),
                },
            )
            .unwrap_err()
            .to_string();
        assert!(direct_commit.contains("external recovery transition is invalid"));

        let prepare = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(acquired.clone()),
            new: Some(prepared.clone()),
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(&prepare)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&prepare)
            .unwrap();

        let rollback_install = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(prepared.clone()),
            new: Some(acquired.clone()),
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(&rollback_install)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&rollback_install)
            .unwrap();
        assert_eq!(
            persistent.private_oram_external_recovery(&key),
            Some(acquired.clone())
        );
        let second_prepared = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                phase: PrivateOramExternalRecoveryLeasePhase::Installing,
                install_intent_digest: Some(BASE64URL_NOPAD.encode(&[39; 32])),
                ..lease.clone()
            }),
            ..acquired.clone()
        };
        let second_prepare = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(acquired.clone()),
            new: Some(second_prepared.clone()),
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(&second_prepare)
            .unwrap();
        assert!(
            persistent
                .compare_and_swap_private_oram_external_recovery(&rollback_install)
                .is_err()
        );
        assert_eq!(
            persistent.private_oram_external_recovery(&key),
            Some(second_prepared.clone())
        );
        persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(second_prepared),
                    new: Some(acquired.clone()),
                },
            )
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&prepare)
            .unwrap();

        let invalid_commit = persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(prepared.clone()),
                    new: Some(PrivateOramExternalRecoveryState {
                        committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[33; 32])),
                        ..committed.clone()
                    }),
                },
            )
            .unwrap_err()
            .to_string();
        assert!(invalid_commit.contains("external recovery transition is invalid"));
        assert_eq!(
            persistent.private_oram_external_recovery(&key),
            Some(prepared.clone())
        );

        let invalid_install_intent = persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(prepared.clone()),
                    new: Some(PrivateOramExternalRecoveryState {
                        committed_install_intent_digest: Some(BASE64URL_NOPAD.encode(&[29; 32])),
                        ..committed.clone()
                    }),
                },
            )
            .unwrap_err()
            .to_string();
        assert!(invalid_install_intent.contains("external recovery transition is invalid"));
        assert_eq!(
            persistent.private_oram_external_recovery(&key),
            Some(prepared.clone())
        );

        let commit = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(prepared),
            new: Some(committed.clone()),
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(&commit)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&commit)
            .unwrap();

        let delete_committed = persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(committed.clone()),
                    new: None,
                },
            )
            .unwrap_err()
            .to_string();
        assert!(delete_committed.contains("external recovery transition is invalid"));

        let next_lease = PrivateOramExternalRecoveryLease {
            operation_id_hash: BASE64URL_NOPAD.encode(&[34; 32]),
            checkpoint_digest: BASE64URL_NOPAD.encode(&[35; 32]),
            backup_generation: 8,
            issued_at_unix: 200,
            expires_at_unix: 260,
            ..lease
        };
        let next_acquired = PrivateOramExternalRecoveryState {
            active_lease: Some(next_lease),
            ..committed.clone()
        };
        persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(committed.clone()),
                    new: Some(next_acquired.clone()),
                },
            )
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(
                &CompareAndSwapPrivateOramExternalRecovery {
                    key: key.clone(),
                    expected: Some(next_acquired),
                    new: Some(committed.clone()),
                },
            )
            .unwrap();

        let rendered = format!(
            "{:?}",
            persistent.private_oram_external_recovery(&key).unwrap()
        );
        assert!(rendered.contains("committed_backup_generation: 7"));
        assert!(!rendered.contains(&key.collection_id));
        assert!(!rendered.contains(&operation_id_hash));
        assert!(!rendered.contains(&checkpoint_digest));
        drop(persistent);

        let reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        assert_eq!(
            reloaded.private_oram_external_recovery(&key),
            Some(committed)
        );
    }

    #[test]
    fn private_oram_external_recovery_lease_requires_expiry_for_takeover() {
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let legacy_lease: PrivateOramExternalRecoveryLease =
            serde_json::from_value(serde_json::json!({
                "owner_peer_id": 7,
                "operation_id_hash": BASE64URL_NOPAD.encode(&[40; 32]),
                "checkpoint_digest": BASE64URL_NOPAD.encode(&[41; 32]),
                "backup_generation": 7,
                "issued_at_unix": 100,
                "expires_at_unix": 160,
            }))
            .unwrap();
        assert_eq!(
            legacy_lease.phase,
            PrivateOramExternalRecoveryLeasePhase::Staging
        );
        assert_eq!(legacy_lease.install_intent_digest, None);

        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 7,
            operation_id_hash: BASE64URL_NOPAD.encode(&[41; 32]),
            checkpoint_digest: BASE64URL_NOPAD.encode(&[42; 32]),
            backup_generation: 7,
            issued_at_unix: 100,
            expires_at_unix: 160,
            install_intent_digest: None,
            phase: PrivateOramExternalRecoveryLeasePhase::Staging,
        };
        let acquired = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(lease.clone()),
        };
        let early_takeover = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 9,
                operation_id_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                checkpoint_digest: BASE64URL_NOPAD.encode(&[44; 32]),
                backup_generation: 8,
                issued_at_unix: 159,
                expires_at_unix: 219,
                install_intent_digest: None,
                phase: PrivateOramExternalRecoveryLeasePhase::Staging,
            }),
            ..acquired.clone()
        };
        let error = validate_private_oram_external_recovery_cas(
            &CompareAndSwapPrivateOramExternalRecovery {
                key: key.clone(),
                expected: Some(acquired.clone()),
                new: Some(early_takeover),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("external recovery transition is invalid"));

        let renewed = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                issued_at_unix: 120,
                expires_at_unix: 220,
                ..lease.clone()
            }),
            ..acquired.clone()
        };
        validate_private_oram_external_recovery_cas(&CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(acquired.clone()),
            new: Some(renewed),
        })
        .unwrap();

        let installing = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                phase: PrivateOramExternalRecoveryLeasePhase::Installing,
                install_intent_digest: Some(BASE64URL_NOPAD.encode(&[45; 32])),
                ..lease.clone()
            }),
            ..acquired.clone()
        };
        validate_private_oram_external_recovery_cas(&CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(acquired.clone()),
            new: Some(installing.clone()),
        })
        .unwrap();

        let installing_abort = validate_private_oram_external_recovery_cas(
            &CompareAndSwapPrivateOramExternalRecovery {
                key: key.clone(),
                expected: Some(installing.clone()),
                new: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(installing_abort.contains("external recovery transition is invalid"));

        let installing_takeover = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 9,
                operation_id_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                checkpoint_digest: BASE64URL_NOPAD.encode(&[44; 32]),
                backup_generation: 8,
                issued_at_unix: 160,
                expires_at_unix: 220,
                install_intent_digest: None,
                phase: PrivateOramExternalRecoveryLeasePhase::Staging,
            }),
            ..installing.clone()
        };
        let takeover_error = validate_private_oram_external_recovery_cas(
            &CompareAndSwapPrivateOramExternalRecovery {
                key: key.clone(),
                expected: Some(installing),
                new: Some(installing_takeover),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(takeover_error.contains("external recovery transition is invalid"));

        let initial_abort = CompareAndSwapPrivateOramExternalRecovery {
            key,
            expected: Some(acquired),
            new: None,
        };
        validate_private_oram_external_recovery_cas(&initial_abort).unwrap();

        let malformed_hash_sentinel = "private-oram-recovery-hash-sentinel";
        let malformed =
            validate_private_oram_external_recovery_lease(&PrivateOramExternalRecoveryLease {
                operation_id_hash: malformed_hash_sentinel.to_string(),
                ..lease
            })
            .unwrap_err()
            .to_string();
        assert!(malformed.contains("external recovery state is invalid"));
        assert!(!malformed.contains(malformed_hash_sentinel));
    }

    #[test]
    fn private_oram_external_recovery_initial_abort_replays_and_save_failure_rolls_back() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let acquired = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 7,
                operation_id_hash: BASE64URL_NOPAD.encode(&[45; 32]),
                checkpoint_digest: BASE64URL_NOPAD.encode(&[46; 32]),
                backup_generation: 1,
                issued_at_unix: 100,
                expires_at_unix: 160,
                install_intent_digest: None,
                phase: PrivateOramExternalRecoveryLeasePhase::Staging,
            }),
        };
        let acquire = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: None,
            new: Some(acquired.clone()),
        };
        let abort = CompareAndSwapPrivateOramExternalRecovery {
            key: key.clone(),
            expected: Some(acquired),
            new: None,
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();

        persistent
            .compare_and_swap_private_oram_external_recovery(&acquire)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&abort)
            .unwrap();
        persistent
            .compare_and_swap_private_oram_external_recovery(&abort)
            .unwrap();
        assert_eq!(persistent.private_oram_external_recovery(&key), None);
        drop(persistent);

        let mut reloaded = Persistent::load_or_init(temp.path(), true, false, None).unwrap();
        reloaded.path = temp.path().join("missing-parent").join("raft_state.json");
        reloaded
            .compare_and_swap_private_oram_external_recovery(&acquire)
            .unwrap_err();
        assert_eq!(reloaded.private_oram_external_recovery(&key), None);
    }

    #[test]
    fn private_oram_external_recovery_operation_cross_fences_session_leases() {
        let temp = tempfile::tempdir().unwrap();
        let collection_id = "collection-uuid-1".to_string();
        let recovery_key = PrivateOramExternalRecoveryKey {
            collection_id: collection_id.clone(),
        };
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.clone(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[47; 32]),
            writeback_digest: None,
        };
        let index_states = vec![PrivateOramLayoutIndexStateBinding {
            key: epoch_key.clone(),
            state: epoch.clone(),
        }];
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[48; 32]),
            index_state_digest: canonical_private_oram_index_state_digest(
                &collection_id,
                &[(epoch_key.clone(), epoch.clone())],
            )
            .unwrap(),
        };
        let session_lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[49; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let checkpoint_digest = BASE64URL_NOPAD.encode(&[50; 32]);
        let install_intent_digest = BASE64URL_NOPAD.encode(&[54; 32]);
        let acquired = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 7,
                operation_id_hash: BASE64URL_NOPAD.encode(&[51; 32]),
                checkpoint_digest: checkpoint_digest.clone(),
                backup_generation: 7,
                issued_at_unix: 100,
                expires_at_unix: 160,
                install_intent_digest: None,
                phase: PrivateOramExternalRecoveryLeasePhase::Staging,
            }),
        };
        let begin = PrivateOramExternalRecoveryOperation {
            phase: PrivateOramExternalRecoveryPhase::Begin,
            recovery: CompareAndSwapPrivateOramExternalRecovery {
                key: recovery_key.clone(),
                expected: None,
                new: Some(acquired.clone()),
            },
            layout: layout.clone(),
            index_states: index_states.clone(),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key.clone(),
                expected: None,
                new: epoch,
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: PrivateOramLayoutKey {
                    collection_id: collection_id.clone(),
                },
                expected: None,
                new: layout.clone(),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key.clone(),
                expected: None,
                new: Some(session_lease.clone()),
            })
            .unwrap();

        let conflict = persistent
            .apply_private_oram_external_recovery(&begin)
            .unwrap_err()
            .to_string();
        assert!(conflict.contains("conflicts with active session lease"));
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key.clone(),
                expected: Some(session_lease.clone()),
                new: None,
            })
            .unwrap();

        persistent
            .apply_private_oram_external_recovery(&begin)
            .unwrap();
        persistent
            .apply_private_oram_external_recovery(&begin)
            .unwrap();
        let blocked_session = persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key.clone(),
                expected: None,
                new: Some(session_lease),
            })
            .unwrap_err()
            .to_string();
        assert!(blocked_session.contains("conflicts with active external recovery"));
        let blocked_epoch = persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key,
                expected: Some(index_states[0].state.clone()),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: BASE64URL_NOPAD.encode(&[52; 32]),
                    writeback_digest: None,
                },
            })
            .unwrap_err()
            .to_string();
        assert!(blocked_epoch.contains("conflicts with active external recovery"));
        let blocked_layout = persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: PrivateOramLayoutKey { collection_id },
                expected: Some(layout.clone()),
                new: PrivateOramConsensusLayout {
                    generation: 2,
                    layout_digest: BASE64URL_NOPAD.encode(&[53; 32]),
                    ..layout.clone()
                },
            })
            .unwrap_err()
            .to_string();
        assert!(blocked_layout.contains("conflicts with active external recovery"));

        let prepared = PrivateOramExternalRecoveryState {
            active_lease: Some(PrivateOramExternalRecoveryLease {
                phase: PrivateOramExternalRecoveryLeasePhase::Installing,
                install_intent_digest: Some(install_intent_digest.clone()),
                ..acquired
                    .active_lease
                    .clone()
                    .expect("acquired recovery must have a lease")
            }),
            ..acquired.clone()
        };
        let committed = PrivateOramExternalRecoveryState {
            committed_backup_generation: 7,
            committed_checkpoint_digest: Some(checkpoint_digest),
            committed_install_intent_digest: Some(install_intent_digest),
            active_lease: None,
        };
        let direct_commit = persistent
            .apply_private_oram_external_recovery(&PrivateOramExternalRecoveryOperation {
                phase: PrivateOramExternalRecoveryPhase::Commit,
                recovery: CompareAndSwapPrivateOramExternalRecovery {
                    key: recovery_key.clone(),
                    expected: Some(acquired.clone()),
                    new: Some(committed.clone()),
                },
                layout: layout.clone(),
                index_states: index_states.clone(),
            })
            .unwrap_err()
            .to_string();
        assert!(direct_commit.contains("external recovery operation is invalid"));

        let prepare = PrivateOramExternalRecoveryOperation {
            phase: PrivateOramExternalRecoveryPhase::PrepareInstall,
            recovery: CompareAndSwapPrivateOramExternalRecovery {
                key: recovery_key.clone(),
                expected: Some(acquired.clone()),
                new: Some(prepared.clone()),
            },
            layout: layout.clone(),
            index_states: index_states.clone(),
        };
        persistent
            .apply_private_oram_external_recovery(&prepare)
            .unwrap();
        persistent
            .apply_private_oram_external_recovery(&prepare)
            .unwrap();

        let rollback_install = PrivateOramExternalRecoveryOperation {
            phase: PrivateOramExternalRecoveryPhase::RollbackInstall,
            recovery: CompareAndSwapPrivateOramExternalRecovery {
                key: recovery_key.clone(),
                expected: Some(prepared.clone()),
                new: Some(acquired.clone()),
            },
            layout: layout.clone(),
            index_states: index_states.clone(),
        };
        persistent
            .apply_private_oram_external_recovery(&rollback_install)
            .unwrap();
        persistent
            .apply_private_oram_external_recovery(&rollback_install)
            .unwrap();
        assert_eq!(
            persistent.private_oram_external_recovery(&recovery_key),
            Some(acquired)
        );
        persistent
            .apply_private_oram_external_recovery(&prepare)
            .unwrap();

        let abort_install = persistent
            .apply_private_oram_external_recovery(&PrivateOramExternalRecoveryOperation {
                phase: PrivateOramExternalRecoveryPhase::Abort,
                recovery: CompareAndSwapPrivateOramExternalRecovery {
                    key: recovery_key.clone(),
                    expected: Some(prepared.clone()),
                    new: None,
                },
                layout: layout.clone(),
                index_states: index_states.clone(),
            })
            .unwrap_err()
            .to_string();
        assert!(abort_install.contains("external recovery operation is invalid"));

        persistent
            .apply_private_oram_external_recovery(&PrivateOramExternalRecoveryOperation {
                phase: PrivateOramExternalRecoveryPhase::Commit,
                recovery: CompareAndSwapPrivateOramExternalRecovery {
                    key: recovery_key.clone(),
                    expected: Some(prepared),
                    new: Some(committed.clone()),
                },
                layout,
                index_states,
            })
            .unwrap();
        assert_eq!(
            persistent.private_oram_external_recovery(&recovery_key),
            Some(committed)
        );
    }

    #[test]
    fn private_oram_external_recovery_snapshot_rejects_committed_rollback() {
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let key_digest = private_oram_external_recovery_key_digest(&key);
        let committed = PrivateOramExternalRecoveryState {
            committed_backup_generation: 7,
            committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[51; 32])),
            committed_install_intent_digest: None,
            active_lease: None,
        };
        let current = HashMap::from([(key_digest.clone(), committed.clone())]);

        let missing =
            validate_private_oram_external_recovery_snapshot_transition(&current, &HashMap::new())
                .unwrap_err()
                .to_string();
        assert!(missing.contains("would roll back committed state"));

        let lower = HashMap::from([(
            key_digest.clone(),
            PrivateOramExternalRecoveryState {
                committed_backup_generation: 6,
                committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[50; 32])),
                committed_install_intent_digest: None,
                active_lease: None,
            },
        )]);
        assert!(
            validate_private_oram_external_recovery_snapshot_transition(&current, &lower).is_err()
        );

        let conflicting = HashMap::from([(
            key_digest.clone(),
            PrivateOramExternalRecoveryState {
                committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[52; 32])),
                ..committed.clone()
            },
        )]);
        assert!(
            validate_private_oram_external_recovery_snapshot_transition(&current, &conflicting)
                .is_err()
        );

        let later = HashMap::from([(
            key_digest,
            PrivateOramExternalRecoveryState {
                committed_backup_generation: 8,
                committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[53; 32])),
                committed_install_intent_digest: None,
                active_lease: None,
            },
        )]);
        validate_private_oram_external_recovery_snapshot_transition(&current, &later).unwrap();

        let active_only = HashMap::from([(
            private_oram_external_recovery_key_digest(&PrivateOramExternalRecoveryKey {
                collection_id: "collection-uuid-2".to_string(),
            }),
            PrivateOramExternalRecoveryState {
                committed_backup_generation: 0,
                committed_checkpoint_digest: None,
                committed_install_intent_digest: None,
                active_lease: Some(PrivateOramExternalRecoveryLease {
                    owner_peer_id: 7,
                    operation_id_hash: BASE64URL_NOPAD.encode(&[54; 32]),
                    checkpoint_digest: BASE64URL_NOPAD.encode(&[55; 32]),
                    backup_generation: 1,
                    issued_at_unix: 100,
                    expires_at_unix: 160,
                    install_intent_digest: None,
                    phase: PrivateOramExternalRecoveryLeasePhase::Staging,
                }),
            },
        )]);
        validate_private_oram_external_recovery_snapshot_transition(&active_only, &HashMap::new())
            .unwrap();

        let installing_key_digest =
            private_oram_external_recovery_key_digest(&PrivateOramExternalRecoveryKey {
                collection_id: "collection-uuid-3".to_string(),
            });
        let installing_lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 7,
            operation_id_hash: BASE64URL_NOPAD.encode(&[56; 32]),
            checkpoint_digest: BASE64URL_NOPAD.encode(&[57; 32]),
            backup_generation: 9,
            issued_at_unix: 200,
            expires_at_unix: 260,
            install_intent_digest: Some(BASE64URL_NOPAD.encode(&[60; 32])),
            phase: PrivateOramExternalRecoveryLeasePhase::Installing,
        };
        let installing_state = PrivateOramExternalRecoveryState {
            committed_backup_generation: 7,
            committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[51; 32])),
            committed_install_intent_digest: None,
            active_lease: Some(installing_lease.clone()),
        };
        let installing = HashMap::from([(installing_key_digest.clone(), installing_state.clone())]);
        let missing_install = validate_private_oram_external_recovery_snapshot_transition(
            &installing,
            &HashMap::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(missing_install.contains("would roll back committed state"));

        validate_private_oram_external_recovery_snapshot_transition(&installing, &installing)
            .unwrap();

        let rolled_back_install = HashMap::from([(
            installing_key_digest.clone(),
            PrivateOramExternalRecoveryState {
                active_lease: Some(PrivateOramExternalRecoveryLease {
                    phase: PrivateOramExternalRecoveryLeasePhase::Staging,
                    install_intent_digest: None,
                    ..installing_lease.clone()
                }),
                ..installing_state.clone()
            },
        )]);
        assert!(
            validate_private_oram_external_recovery_snapshot_transition(
                &installing,
                &rolled_back_install,
            )
            .is_err()
        );
        validate_private_oram_external_recovery_snapshot_transition_for_peer(
            &installing,
            &rolled_back_install,
            29,
        )
        .unwrap();
        validate_private_oram_external_recovery_snapshot_transition_for_peer(
            &installing,
            &rolled_back_install,
            7,
        )
        .unwrap();

        let inexact_rolled_back_install = HashMap::from([(
            installing_key_digest.clone(),
            PrivateOramExternalRecoveryState {
                active_lease: Some(PrivateOramExternalRecoveryLease {
                    phase: PrivateOramExternalRecoveryLeasePhase::Staging,
                    install_intent_digest: None,
                    expires_at_unix: installing_lease.expires_at_unix + 1,
                    ..installing_lease.clone()
                }),
                ..installing_state.clone()
            },
        )]);
        assert!(
            validate_private_oram_external_recovery_snapshot_transition_for_peer(
                &installing,
                &inexact_rolled_back_install,
                7,
            )
            .is_err()
        );

        let dropped_install = HashMap::from([(
            installing_key_digest.clone(),
            PrivateOramExternalRecoveryState {
                active_lease: None,
                ..installing_state.clone()
            },
        )]);
        let dropped_error = validate_private_oram_external_recovery_snapshot_transition(
            &installing,
            &dropped_install,
        )
        .unwrap_err()
        .to_string();
        assert!(dropped_error.contains("would roll back installing state"));

        let changed_base = HashMap::from([(
            installing_key_digest.clone(),
            PrivateOramExternalRecoveryState {
                committed_backup_generation: 8,
                committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[58; 32])),
                committed_install_intent_digest: None,
                active_lease: Some(installing_lease.clone()),
            },
        )]);
        assert!(
            validate_private_oram_external_recovery_snapshot_transition(
                &installing,
                &changed_base,
            )
            .is_err()
        );

        let committed_install = HashMap::from([(
            installing_key_digest.clone(),
            PrivateOramExternalRecoveryState {
                committed_backup_generation: installing_lease.backup_generation,
                committed_checkpoint_digest: Some(installing_lease.checkpoint_digest.clone()),
                committed_install_intent_digest: installing_lease.install_intent_digest.clone(),
                active_lease: None,
            },
        )]);
        validate_private_oram_external_recovery_snapshot_transition(
            &installing,
            &committed_install,
        )
        .unwrap();

        let skipped_install = HashMap::from([(
            installing_key_digest,
            PrivateOramExternalRecoveryState {
                committed_backup_generation: installing_lease.backup_generation + 1,
                committed_checkpoint_digest: Some(BASE64URL_NOPAD.encode(&[59; 32])),
                committed_install_intent_digest: Some(BASE64URL_NOPAD.encode(&[61; 32])),
                active_lease: None,
            },
        )]);
        assert!(
            validate_private_oram_external_recovery_snapshot_transition(
                &installing,
                &skipped_install,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_epoch_cas_rolls_back_memory_state_when_persist_fails() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent.path = temp.path().join("missing-parent").join("raft_state.json");

        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: PrivateOramConsensusEpoch {
                    index_epoch: 7,
                    root_hash: BASE64URL_NOPAD.encode(&[7; 32]),
                    writeback_digest: None,
                },
            })
            .unwrap_err();

        assert_eq!(persistent.private_oram_epoch(&key), None);
    }

    #[test]
    fn private_oram_recovery_snapshot_save_failure_preserves_memory_fence() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-snapshot-save-failure".to_string(),
        };
        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 7,
            operation_id_hash: BASE64URL_NOPAD.encode(&[81; 32]),
            checkpoint_digest: BASE64URL_NOPAD.encode(&[82; 32]),
            backup_generation: 9,
            issued_at_unix: 100,
            expires_at_unix: 160,
            install_intent_digest: Some(BASE64URL_NOPAD.encode(&[83; 32])),
            phase: PrivateOramExternalRecoveryLeasePhase::Installing,
        };
        let installing = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(lease.clone()),
        };
        let committed = PrivateOramExternalRecoveryState {
            committed_backup_generation: lease.backup_generation,
            committed_checkpoint_digest: Some(lease.checkpoint_digest.clone()),
            committed_install_intent_digest: lease.install_intent_digest.clone(),
            active_lease: None,
        };
        let key_digest = private_oram_external_recovery_key_digest(&key);
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent.state.hard_state.term = 3;
        persistent.state.hard_state.commit = 2;
        persistent.latest_snapshot_meta = SnapshotMetadataSer { term: 3, index: 2 };
        persistent.apply_progress_queue = EntryApplyProgressQueue::new(3, 5);
        persistent
            .peer_address_by_id
            .write()
            .insert(7, "http://127.0.0.1:6335".parse().unwrap());
        persistent.cluster_metadata.insert(
            "snapshot-rollback-sentinel".to_string(),
            serde_json::json!(true),
        );
        persistent
            .private_oram_external_recoveries
            .insert(key_digest.clone(), installing.clone());
        persistent.save().unwrap();
        persistent.path = temp.path().join("missing-parent").join("raft_state.json");

        let incoming_meta = SnapshotMetadata {
            conf_state: Some(ConfState::from((vec![9], vec![]))),
            index: 8,
            term: 9,
        };

        assert!(
            persistent
                .update_from_snapshot(
                    &incoming_meta,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    HashMap::from([(key_digest, committed)]),
                    Default::default(),
                    Default::default(),
                    None,
                    None,
                    None,
                )
                .is_err()
        );
        assert_eq!(
            persistent.private_oram_external_recovery(&key),
            Some(installing)
        );
        assert_eq!(persistent.state.hard_state.term, 3);
        assert_eq!(persistent.state.hard_state.commit, 2);
        assert_eq!(persistent.latest_snapshot_meta.term, 3);
        assert_eq!(persistent.latest_snapshot_meta.index, 2);
        assert_eq!(persistent.apply_progress_queue.current(), Some(3));
        assert_eq!(persistent.peer_address_by_id.read().len(), 1);
        assert_eq!(
            persistent
                .cluster_metadata
                .get("snapshot-rollback-sentinel"),
            Some(&serde_json::json!(true)),
        );
    }

    #[test]
    fn private_oram_epoch_snapshot_validation_rejects_malformed_records_before_replace() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let initial = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: None,
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: key.clone(),
                expected: None,
                new: initial.clone(),
            })
            .unwrap();

        let invalid_key_digest_sentinel = "private-oram-invalid-key-digest-sentinel";
        let malformed_key_digest = HashMap::from([(
            invalid_key_digest_sentinel.to_string(),
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                writeback_digest: None,
            },
        )]);
        let digest_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                malformed_key_digest,
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            digest_error
                .to_string()
                .contains("consensus epoch snapshot is invalid"),
        );
        assert!(
            !digest_error
                .to_string()
                .contains(invalid_key_digest_sentinel),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let invalid_writeback_digest_sentinel =
            "private-oram-invalid-snapshot-writeback-digest-sentinel";
        let malformed_writeback_digest = HashMap::from([(
            private_oram_epoch_key_digest(&key),
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                writeback_digest: Some(invalid_writeback_digest_sentinel.to_string()),
            },
        )]);
        let writeback_digest_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                malformed_writeback_digest,
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            writeback_digest_error
                .to_string()
                .contains("consensus writeback digest is invalid"),
        );
        assert!(
            !writeback_digest_error
                .to_string()
                .contains(invalid_writeback_digest_sentinel),
        );
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial.clone()));

        let invalid_root_sentinel = "private-oram-invalid-snapshot-root-sentinel";
        let malformed_root = HashMap::from([(
            private_oram_epoch_key_digest(&key),
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: invalid_root_sentinel.to_string(),
                writeback_digest: None,
            },
        )]);
        let root_error = persistent
            .update_from_snapshot(
                &SnapshotMetadata::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                malformed_root,
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            root_error
                .to_string()
                .contains("consensus root hash is invalid"),
        );
        assert!(!root_error.to_string().contains(invalid_root_sentinel));
        assert_eq!(persistent.private_oram_epoch(&key), Some(initial));
    }

    #[test]
    fn private_oram_epoch_load_rejects_malformed_persisted_state() {
        let temp = tempfile::tempdir().unwrap();
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let mut persistent = Persistent::load_or_init(temp.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key,
                expected: None,
                new: PrivateOramConsensusEpoch {
                    index_epoch: 42,
                    root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                    writeback_digest: None,
                },
            })
            .unwrap();
        drop(persistent);

        let state_path = temp.path().join(STATE_FILE_NAME);
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let epochs = state["private_oram_epochs"].as_object_mut().unwrap();
        let epoch = epochs.values_mut().next().unwrap().as_object_mut().unwrap();
        let invalid_root_sentinel = "private-oram-persisted-root-sentinel";
        epoch.insert(
            "root_hash".to_string(),
            serde_json::json!(invalid_root_sentinel),
        );
        fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();

        let error = Persistent::load_or_init(temp.path(), true, false, None).unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("consensus root hash is invalid"),
            "{rendered}"
        );
        assert!(!rendered.contains(invalid_root_sentinel), "{rendered}");
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct SnapshotMetadataSer {
    pub term: u64,
    /// Aka: commit
    pub index: u64,
}

impl From<&SnapshotMetadata> for SnapshotMetadataSer {
    fn from(meta: &SnapshotMetadata) -> Self {
        Self {
            term: meta.term,
            index: meta.index,
        }
    }
}

mod serialize_peer_addresses {
    use std::collections::HashMap;
    use std::sync::Arc;

    use http::Uri;
    use parking_lot::RwLock;
    use serde::{self, Deserializer, Serializer};

    use crate::serialize_peer_addresses;
    use crate::types::PeerAddressById;

    pub fn serialize<S>(
        addresses: &Arc<RwLock<PeerAddressById>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_peer_addresses::serialize(&addresses.read(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<RwLock<PeerAddressById>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addresses: HashMap<u64, Uri> = serialize_peer_addresses::deserialize(deserializer)?;
        Ok(Arc::new(RwLock::new(addresses)))
    }
}

/// Definition of struct to help with serde serialization.
/// Should be used only in `[serde(with=...)]`
#[derive(Serialize, Deserialize)]
#[serde(remote = "RaftState")]
struct RaftStateDef {
    #[serde(with = "HardStateDef")]
    hard_state: HardState,
    #[serde(with = "ConfStateDef")]
    conf_state: ConfState,
}

/// Definition of struct to help with serde serialization.
/// Should be used only in `[serde(with=...)]`
#[derive(Serialize, Deserialize)]
#[serde(remote = "HardState")]
struct HardStateDef {
    term: u64,
    vote: u64,
    commit: u64,
}

/// Definition of struct to help with serde serialization.
/// Should be used only in `[serde(with=...)]`
#[derive(Serialize, Deserialize)]
#[serde(remote = "ConfState")]
struct ConfStateDef {
    voters: Vec<u64>,
    learners: Vec<u64>,
    voters_outgoing: Vec<u64>,
    learners_next: Vec<u64>,
    auto_leave: bool,
}
