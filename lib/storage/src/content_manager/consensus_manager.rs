use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt::{self, Display};
use std::future::Future;
use std::ops::Deref;
use std::path::Path;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use chrono::Utc;
use collection::collection_state;
use collection::common::is_ready::IsReady;
use collection::operations::types::PeerMetadata;
use collection::shards::CollectionId;
use collection::shards::shard::PeerId;
use common::defaults;
use futures::future::join_all;
use parking_lot::{Mutex, RwLock};
use qdrant_sec::{
    PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION, PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION,
    PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1, PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY,
    PrivateOramConsensusConfigurationV1, PrivateOramMixedVersionActivationProofV1,
    PrivateOramOwnerCleanupSignerV1, PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    PrivateOramOwnerEnrollmentPreparedV1, PrivateOramOwnerLifecycleStateV1,
    PrivateOramOwnerReservationPrepareChallengeV1, PrivateOramOwnerReservationPrepareV1,
    PrivateOramPeerActivationChallengeV1, PrivateOramPeerActivationEvidenceV1,
    PrivateOramPeerActivationObservationV1, PrivateOramPeerActivationSignedAckV1,
    PrivateOramPeerRecoveryPublicKeyV1, SignedPrivateOramOwnerReservationResolutionReceiptV1,
    encode_private_oram_owner_enrollment_genesis_commitment_v1,
    encode_private_oram_owner_enrollment_prepared_v1,
    package_private_oram_mixed_version_activation_proof_v1,
    private_oram_consensus_configuration_member_ids_v1,
    try_private_oram_consensus_configuration_digest_v1,
    validate_private_oram_owner_reservation_prepare_challenge_v1,
    validate_private_oram_peer_activation_challenge_v1_shape,
    validate_private_oram_peer_activation_observation_v1_shape,
};
use raft::eraftpb::{ConfChange, ConfChangeType, ConfChangeV2, Entry as RaftEntry, EntryType};
use raft::{GetEntriesContext, RaftState, RawNode, SoftState, Storage};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::time::error::Elapsed;
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::Uri;

use super::CollectionContainer;
use super::alias_mapping::AliasMapping;
use super::consensus_ops::{
    ApplyPrivateOramMutationMaterialV2, ConfirmPrivateOramMutationAuthorityV2, ConsensusOperations,
    PrivateOramCollectionLayoutTransition, PrivateOramConsensusCollectionStateV2,
    PrivateOramConsensusEpoch, PrivateOramConsensusLayout, PrivateOramEpochKey,
    PrivateOramExternalRecoveryKey, PrivateOramExternalRecoveryState, PrivateOramLayoutKey,
    PrivateOramLayoutTransitionState, PrivateOramMutationActivationBarrierPhaseV2,
    PrivateOramMutationActivationBarrierV2, PrivateOramMutationKey, PrivateOramMutationLease,
    PrivateOramMutationLeaseSlotV2, PrivateOramReshardingOperation, PrivateOramSessionLease,
    PrivateOramShardTransferFinish, PrivateOramShardTransferStart, SnapshotStatus,
};
use super::errors::StorageError;
use crate::content_manager::consensus::consensus_wal::ConsensusOpWal;
use crate::content_manager::consensus::entry_queue::EntryId;
use crate::content_manager::consensus::operation_sender::OperationSender;
use crate::content_manager::consensus::persistent::{
    Persistent, PrivateOramMutationAtEntryOutcome,
};
use crate::content_manager::consensus::private_oram_activation_authority::{
    PrivateOramActivationAuthorityLocatorV1, PrivateOramActivationAuthorityStateV1,
};
use crate::content_manager::consensus::private_oram_mutation_activation_barrier::{
    PrivateOramMutationActivationApplyFactsV2, PrivateOramMutationActivationPendingV2,
    private_oram_activation_uri_digest, validate_private_oram_mutation_activation_barrier_v2,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::append_reservation_v3::{
    decode_private_oram_mutation_prepared_reservation_challenge_v3,
    encode_private_oram_mutation_append_reservation_v3,
    encode_private_oram_mutation_prepared_reservation_challenge_v3,
    private_oram_mutation_append_reservation_v3,
    private_oram_mutation_prepared_reservation_challenge_v3,
    private_oram_mutation_reservation_intent_v3,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::authority::{
    DecodedPrivateOramMutationAuthorityWireV2, PrivateOramMutationPendingReservationChallengeV1,
    PrivateOramMutationRecoveryCapsulesCertificateV2,
    PrivateOramMutationReservationChallengeOutcomeKindV1,
    encode_private_oram_mutation_reservation_challenge_cancellation_v1,
    encode_private_oram_mutation_reservation_outcome_acknowledgement_v1,
    private_oram_mutation_reservation_challenge_cancellation_v1,
    private_oram_mutation_reservation_outcome_acknowledgement_v1,
};
use crate::content_manager::consensus::private_oram_mutation_cleanup::format::PrivateOramMutationFormatFloorV2;
use crate::content_manager::consensus::private_oram_mutation_cleanup::owner_checkpoint::private_oram_owner_checkpoint_reservation_binding_v1;
use crate::content_manager::consensus::private_oram_mutation_cleanup::{
    PrivateOramMutationCleanupExpectationV2, PrivateOramMutationCleanupLifecycleV2,
    PrivateOramMutationClearedPendingArchivePermitV2, PrivateOramRaftApplyLocatorV2,
    encode_private_oram_mutation_cleanup_expectation_v2,
};
use crate::content_manager::consensus::private_oram_mutation_recovery_capsules::{
    PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
    encode_private_oram_mutation_recovery_capsules_ready_v2,
};
use crate::content_manager::consensus::private_oram_mutation_watermark::{
    PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationParentWatermarkV2,
    encode_private_oram_mutation_parent_watermark_expectation_v2,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationAppendAuthorityContextV2,
    PrivateOramMutationAppendReservationV2,
    encode_private_oram_mutation_admission_recovery_manifest_v2,
    encode_private_oram_mutation_append_reservation_v2,
};
use crate::types::{
    ClusterInfo, ClusterStatus, ConsensusThreadStatus, MessageSendErrors, PeerAddressById,
    PeerInfo, PeerMetadataById, RaftInfo,
};

pub mod prelude {
    use crate::content_manager::toc::TableOfContent;

    pub type ConsensusState = super::ConsensusManager<TableOfContent>;
}

/// Allow us updating our peer metadata once every 60 seconds
const CONSENSUS_PEER_METADATA_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize, Clone)]
pub struct SnapshotData {
    pub collections_data: CollectionsSnapshot,
    #[serde(with = "crate::serialize_peer_addresses")]
    pub address_by_id: PeerAddressById,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata_by_id: PeerMetadataById,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub cluster_metadata: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_oram_activation_authority: Option<PrivateOramActivationAuthorityStateV1>,
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
}

impl fmt::Debug for SnapshotData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotData")
            .field("collection_count", &self.collections_data.collections.len())
            .field("peer_address_count", &self.address_by_id.len())
            .field("peer_metadata_count", &self.metadata_by_id.len())
            .field("cluster_metadata_count", &self.cluster_metadata.len())
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
            .field(
                "has_private_oram_mutation_activation_pending",
                &self.private_oram_mutation_activation_pending.is_some(),
            )
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CollectionsSnapshot {
    pub collections: HashMap<CollectionId, collection_state::State>,
    pub aliases: AliasMapping,
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationReconcileSnapshotV1 {
    consensus_state: PrivateOramConsensusCollectionStateV2,
    lease_slot: PrivateOramMutationLeaseSlotV2,
    parent_watermark: Option<PrivateOramMutationParentWatermarkV2>,
    recovery_capsules_certificate: Option<PrivateOramMutationRecoveryCapsulesCertificateV2>,
    activation_authority: Option<PrivateOramActivationAuthorityLocatorV1>,
    cleanup_lifecycle: Option<PrivateOramMutationCleanupLifecycleV2>,
}

/// Linearizable, non-cloneable authority for coordinator-owned recovery side effects.
///
/// Construction requires an exact lease-slot confirmation committed through Raft. Consumers can
/// inspect the paired state only inside the storage ownership boundary.
#[doc(hidden)]
pub struct LinearizablePrivateOramMutationReconcileSnapshotV2 {
    snapshot: PrivateOramMutationReconcileSnapshotV1,
    applied_index: u64,
}

impl fmt::Debug for LinearizablePrivateOramMutationReconcileSnapshotV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinearizablePrivateOramMutationReconcileSnapshotV2")
            .field("authority", &"[redacted]")
            .field("applied_index", &self.applied_index)
            .finish()
    }
}

impl LinearizablePrivateOramMutationReconcileSnapshotV2 {
    pub(in crate::content_manager) fn snapshot(&self) -> &PrivateOramMutationReconcileSnapshotV1 {
        &self.snapshot
    }

    pub(in crate::content_manager) const fn applied_index(&self) -> u64 {
        self.applied_index
    }

    pub(in crate::content_manager) fn into_snapshot(
        self,
    ) -> PrivateOramMutationReconcileSnapshotV1 {
        self.snapshot
    }

    #[cfg(test)]
    pub(super) fn from_snapshot_for_test(
        snapshot: PrivateOramMutationReconcileSnapshotV1,
        applied_index: u64,
    ) -> Self {
        Self {
            snapshot,
            applied_index,
        }
    }
}

impl fmt::Debug for PrivateOramMutationReconcileSnapshotV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationReconcileSnapshotV1")
            .field("consensus_state", &"[redacted]")
            .field("lease_slot", &"[redacted]")
            .field("has_parent_watermark", &self.parent_watermark.is_some())
            .field(
                "has_recovery_capsules_certificate",
                &self.recovery_capsules_certificate.is_some(),
            )
            .field(
                "has_activation_authority",
                &self.activation_authority.is_some(),
            )
            .field("has_cleanup_lifecycle", &self.cleanup_lifecycle.is_some())
            .finish()
    }
}

impl PrivateOramMutationReconcileSnapshotV1 {
    pub(in crate::content_manager) fn consensus_state(
        &self,
    ) -> &PrivateOramConsensusCollectionStateV2 {
        &self.consensus_state
    }

    pub(in crate::content_manager) fn lease_slot(&self) -> &PrivateOramMutationLeaseSlotV2 {
        &self.lease_slot
    }

    pub(in crate::content_manager) fn recovery_capsules_certificate(
        &self,
    ) -> Option<&PrivateOramMutationRecoveryCapsulesCertificateV2> {
        self.recovery_capsules_certificate.as_ref()
    }

    pub(in crate::content_manager) fn parent_watermark(
        &self,
    ) -> Option<&PrivateOramMutationParentWatermarkV2> {
        self.parent_watermark.as_ref()
    }

    pub(in crate::content_manager) fn activation_authority(
        &self,
    ) -> Option<&PrivateOramActivationAuthorityLocatorV1> {
        self.activation_authority.as_ref()
    }

    pub(in crate::content_manager) fn cleanup_lifecycle(
        &self,
    ) -> Option<&PrivateOramMutationCleanupLifecycleV2> {
        self.cleanup_lifecycle.as_ref()
    }

    #[cfg(test)]
    pub(super) fn from_parts_for_test(
        consensus_state: PrivateOramConsensusCollectionStateV2,
        lease_slot: PrivateOramMutationLeaseSlotV2,
    ) -> Self {
        Self {
            consensus_state,
            lease_slot,
            parent_watermark: None,
            recovery_capsules_certificate: None,
            activation_authority: None,
            cleanup_lifecycle: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_parent_watermark_for_test(
        mut self,
        parent_watermark: PrivateOramMutationParentWatermarkV2,
    ) -> Self {
        self.parent_watermark = Some(parent_watermark);
        self
    }

    #[cfg(test)]
    pub(super) fn with_cleanup_lifecycle_for_test(
        mut self,
        cleanup_lifecycle: PrivateOramMutationCleanupLifecycleV2,
    ) -> Self {
        self.cleanup_lifecycle = Some(cleanup_lifecycle);
        self
    }

    #[cfg(test)]
    pub(super) fn from_parts_with_recovery_capsules_for_test(
        consensus_state: PrivateOramConsensusCollectionStateV2,
        lease_slot: PrivateOramMutationLeaseSlotV2,
        recovery_capsules_certificate: PrivateOramMutationRecoveryCapsulesCertificateV2,
        activation_authority: PrivateOramActivationAuthorityLocatorV1,
    ) -> Self {
        let parent_watermark = recovery_capsules_certificate
            .ready()
            .point_stage_watermark()
            .clone();
        Self {
            consensus_state,
            lease_slot,
            parent_watermark: Some(parent_watermark),
            recovery_capsules_certificate: Some(recovery_capsules_certificate),
            activation_authority: Some(activation_authority),
            cleanup_lifecycle: None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramSnapshotState<'a> {
    pub incoming_epochs: &'a HashMap<String, PrivateOramConsensusEpoch>,
    pub current_epochs: &'a HashMap<String, PrivateOramConsensusEpoch>,
    pub incoming_layouts: &'a HashMap<String, PrivateOramConsensusLayout>,
    pub current_layouts: &'a HashMap<String, PrivateOramConsensusLayout>,
}

/// Why a collections snapshot could not be applied locally.
///
/// The distinction decides whether the node must be fenced: a rejection happened before any
/// local state changed, so consensus state stays consistent and a restart needs no operator
/// intervention, while an indeterminate failure may have left collections half-applied.
#[derive(Debug)]
pub enum CollectionsSnapshotApplyError {
    /// Validation refused the snapshot before any local side effect.
    Rejected(StorageError),
    /// The apply failed after local side effects started.
    Indeterminate(StorageError),
}

impl CollectionsSnapshotApplyError {
    pub fn into_storage_error(self) -> StorageError {
        match self {
            Self::Rejected(error) | Self::Indeterminate(error) => error,
        }
    }
}

impl TryFrom<&[u8]> for SnapshotData {
    type Error = serde_cbor::Error;

    fn try_from(bytes: &[u8]) -> Result<SnapshotData, Self::Error> {
        serde_cbor::from_slice(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramMutationV2ActivationStatus {
    Unprepared,
    Prepared,
    Active,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramPeerRecoverySignerPin {
    signer: PrivateOramPeerRecoveryPublicKeyV1,
    registry_generation: u64,
    manifest_digest: String,
}

impl fmt::Debug for PrivateOramPeerRecoverySignerPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPeerRecoverySignerPin")
            .field("signer", &"[redacted]")
            .field("registry_generation", &self.registry_generation)
            .field("manifest_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramPeerRecoverySignerPin {
    pub fn signer(&self) -> &PrivateOramPeerRecoveryPublicKeyV1 {
        &self.signer
    }

    pub fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn activation_authority(&self) -> PrivateOramActivationAuthorityLocatorV1 {
        PrivateOramActivationAuthorityLocatorV1::from_verified_parts(
            self.registry_generation,
            self.manifest_digest.clone(),
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramPeerRecoverySignerPairPin {
    owner: PrivateOramPeerRecoverySignerPin,
    coordinator: PrivateOramPeerRecoverySignerPin,
}

impl fmt::Debug for PrivateOramPeerRecoverySignerPairPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPeerRecoverySignerPairPin")
            .field("owner", &"[redacted]")
            .field("coordinator", &"[redacted]")
            .finish()
    }
}

impl PrivateOramPeerRecoverySignerPairPin {
    pub fn owner(&self) -> &PrivateOramPeerRecoverySignerPin {
        &self.owner
    }

    pub fn coordinator(&self) -> &PrivateOramPeerRecoverySignerPin {
        &self.coordinator
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerReservationPrepareContextV3 {
    challenge: PrivateOramOwnerReservationPrepareChallengeV1,
    expected_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    expected_owner_signer: PrivateOramOwnerCleanupSignerV1,
}

impl fmt::Debug for PrivateOramOwnerReservationPrepareContextV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationPrepareContextV3")
            .field("owner_peer_id", &self.challenge.owner_peer_id)
            .field("owner_index", &self.challenge.owner_index)
            .field("challenge", &"[redacted]")
            .field("expected_lifecycle_state", &self.expected_lifecycle_state)
            .field("expected_owner_signer", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerReservationPrepareContextV3 {
    pub fn challenge(&self) -> &PrivateOramOwnerReservationPrepareChallengeV1 {
        &self.challenge
    }

    pub fn expected_lifecycle_state(&self) -> &PrivateOramOwnerLifecycleStateV1 {
        &self.expected_lifecycle_state
    }

    pub fn expected_owner_signer(&self) -> &PrivateOramOwnerCleanupSignerV1 {
        &self.expected_owner_signer
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramReservationChallengeDispositionKindV3 {
    Finalized,
    Cancelled,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramReservationChallengeDispositionV3 {
    kind: PrivateOramReservationChallengeDispositionKindV3,
    resolution_applied_term: u64,
    resolution_applied_index: u64,
    finalized_reservation_digest: Option<String>,
}

impl fmt::Debug for PrivateOramReservationChallengeDispositionV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramReservationChallengeDispositionV3")
            .field("kind", &self.kind)
            .field("resolution_applied_term", &self.resolution_applied_term)
            .field("resolution_applied_index", &self.resolution_applied_index)
            .field("finalized_reservation_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramReservationChallengeDispositionV3 {
    pub const fn kind(&self) -> PrivateOramReservationChallengeDispositionKindV3 {
        self.kind
    }

    pub const fn resolution_applied_term(&self) -> u64 {
        self.resolution_applied_term
    }

    pub const fn resolution_applied_index(&self) -> u64 {
        self.resolution_applied_index
    }

    pub fn finalized_reservation_digest(&self) -> Option<&str> {
        self.finalized_reservation_digest.as_deref()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramReservationOutcomeRecoveryV3 {
    outcome_digest: String,
    owner_contexts: Vec<PrivateOramOwnerReservationPrepareContextV3>,
    disposition: PrivateOramReservationChallengeDispositionV3,
}

impl fmt::Debug for PrivateOramReservationOutcomeRecoveryV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramReservationOutcomeRecoveryV3")
            .field("outcome_digest", &"[redacted]")
            .field("owner_count", &self.owner_contexts.len())
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl PrivateOramReservationOutcomeRecoveryV3 {
    pub fn outcome_digest(&self) -> &str {
        &self.outcome_digest
    }

    pub fn owner_contexts(&self) -> &[PrivateOramOwnerReservationPrepareContextV3] {
        &self.owner_contexts
    }

    pub fn disposition(&self) -> &PrivateOramReservationChallengeDispositionV3 {
        &self.disposition
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramPeerActivationChallengeSetV1 {
    configuration: PrivateOramConsensusConfigurationV1,
    peer_uri_digests: BTreeMap<u64, String>,
    challenges: Vec<PrivateOramPeerActivationChallengeV1>,
}

impl fmt::Debug for PrivateOramPeerActivationChallengeSetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPeerActivationChallengeSetV1")
            .field("peer_count", &self.challenges.len())
            .field("configuration", &"[redacted]")
            .field("peer_uri_digests", &"[redacted]")
            .field("challenges", &"[redacted]")
            .finish()
    }
}

impl PrivateOramPeerActivationChallengeSetV1 {
    pub fn configuration(&self) -> &PrivateOramConsensusConfigurationV1 {
        &self.configuration
    }

    pub fn peer_uri_digests(&self) -> &BTreeMap<u64, String> {
        &self.peer_uri_digests
    }

    pub fn challenges(&self) -> &[PrivateOramPeerActivationChallengeV1] {
        &self.challenges
    }
}

/// Whether raft-rs still has an uncommitted/unapplied configuration change in flight.
///
/// raft-rs sets `Raft::pending_conf_index` to the last log index every time a node becomes
/// leader and only treats a configuration change as pending while that index is above the
/// applied index (`Raft::has_pending_conf`). Comparing the field against zero therefore rejects
/// every membership change on any leader with a non-empty log; this mirrors raft's own check.
pub fn raft_conf_change_pending(pending_conf_index: u64, applied_index: u64) -> bool {
    pending_conf_index > applied_index
}

/// Outcome of a consensus proposal, distinguishing "never submitted" from "submitted but not
/// observed". Callers that hold prepared local state must only roll it back on a definitive
/// outcome: an entry whose wait timed out may still commit later.
#[derive(Debug)]
pub enum ConsensusProposalOutcome {
    /// The entry committed and was applied locally; the receipt carries the operation result.
    Applied(ConsensusApplyReceipt),
    /// The entry never reached the Raft thread; nothing was proposed.
    NotSubmitted(StorageError),
    /// The entry was handed to Raft but its commit/apply was not observed (the wait timed out
    /// or the apply channel was dropped). It may still commit.
    Indeterminate(StorageError),
    /// The entry was applied and the operation itself failed.
    Failed(StorageError),
}

pub struct ConsensusManager<C: CollectionContainer> {
    pub persistent: RwLock<Persistent>,
    /// Notifies if the current node knows who the leader and is not in the process of election
    /// Otherwise the proposals are not accepted
    pub is_leader_established: Arc<IsReady>,
    wal: Mutex<ConsensusOpWal>,
    /// Raft consensus state, which is not saved on disk.
    /// They will change on restart anyway (role + leader id)
    soft_state: RwLock<Option<SoftState>>,
    /// Storage-related container. Should apply and persist changes not related to consensus
    /// (user changes)
    toc: Arc<C>,
    /// Operation apply notifier.
    /// Fires a signal if some specific operation is applied to the state machine.
    /// Signal is changed on change proposal and triggered if the change was applied by consensus on this peer.
    /// Also sends the result of the operation.
    on_consensus_op_apply: Mutex<
        HashMap<
            ConsensusOperations,
            broadcast::Sender<Result<ConsensusApplyReceipt, StorageError>>,
        >,
    >,
    /// Propose operation to the consensus.
    /// Sends messages to the consensus thread, which is defined externally, outside of the state.
    /// (e.g. in the `src/consensus.rs`)
    propose_sender: OperationSender,
    /// Status of the consensus thread, changed by the consensus thread
    consensus_thread_status: RwLock<ConsensusThreadStatus>,
    /// Consensus thread errors, changed by the consensus thread
    message_send_failures: RwLock<HashMap<String, MessageSendErrors>>,
    /// Local peer metadata proposed to consensus for cluster capability checks.
    current_peer_metadata: PeerMetadata,
    /// Last time we attempted to update the peer metadata
    next_peer_metadata_update_attempt: Mutex<Instant>,
}

enum NormalEntryCursorDisposition {
    NeedsSeparateCommit,
    Committed(EntryId),
}

#[derive(Clone, Copy)]
enum NormalEntryApplyContext {
    CommittedAtCurrentCursor,
    #[cfg(test)]
    DetachedForTest,
}

struct NormalEntryApplyOutcome {
    operation_result: Result<bool, StorageError>,
    cursor_disposition: NormalEntryCursorDisposition,
}

#[derive(Clone, Copy, Debug)]
pub struct ConsensusApplyReceipt {
    applied: bool,
    local_applied_index: Option<EntryId>,
}

impl ConsensusApplyReceipt {
    /// Whether the applied entry reported success for its operation.
    pub fn applied(&self) -> bool {
        self.applied
    }

    const fn configuration_change(applied: bool) -> Self {
        Self {
            applied,
            local_applied_index: None,
        }
    }

    const fn normal_entry(applied: bool, local_applied_index: EntryId) -> Self {
        Self {
            applied,
            local_applied_index: Some(local_applied_index),
        }
    }
}

/// Classifies a private ORAM topology meta-op that did not reach its committed state. A
/// deterministic refusal (any non-service error) that left the topology `Pending` is the same
/// on every replica, so it is returned as is and rejects the entry; a local failure or a
/// partially applied transition stays a service error and stops consensus.
fn private_oram_meta_op_not_applied(
    apply_result: Result<bool, StorageError>,
    state: PrivateOramLayoutTransitionState,
    message: &'static str,
) -> StorageError {
    match apply_result {
        Err(error)
            if state == PrivateOramLayoutTransitionState::Pending
                && !matches!(error, StorageError::ServiceError { .. }) =>
        {
            error
        }
        _ => StorageError::service_error(message),
    }
}

impl<C: CollectionContainer> ConsensusManager<C> {
    pub fn new(
        persistent_state: Persistent,
        toc: Arc<C>,
        propose_sender: OperationSender,
        storage_path: &Path,
        current_peer_metadata: PeerMetadata,
    ) -> Result<Self, StorageError> {
        let mut wal = ConsensusOpWal::new(storage_path)?;

        // When our Raft index and last snapshot index match, the last thing we did is apply a Raft
        // snapshot. It is possible that we crashed before clearing the WAL, so we still do it now.
        // Specifically, if the last operation was applying a snapshot and our WAL does still have
        // older Raft entries, we clear the whole WAL. Consensus will take care of us catching up
        // with the rest.
        // See `apply_snapshot` function and <https://github.com/qdrant/qdrant/pull/7577>.
        let raft_index = persistent_state.state().hard_state.commit;
        let snapshot_index = persistent_state.latest_snapshot_meta.index;
        let last_operation_was_snapshot = raft_index == persistent_state.latest_snapshot_meta.index;
        if last_operation_was_snapshot
            && let Ok(Some(last)) = wal.last_entry()
            && last.index < snapshot_index
        {
            log::warn!(
                "Consensus WAL was not cleared after applying consensus snapshot, clearing it now"
            );
            wal.clear()?;
        }

        Ok(Self {
            persistent: RwLock::new(persistent_state),
            is_leader_established: Arc::new(IsReady::default()),
            wal: Mutex::new(wal),
            soft_state: RwLock::new(None),
            toc,
            on_consensus_op_apply: Default::default(),
            propose_sender,
            consensus_thread_status: RwLock::new(ConsensusThreadStatus::Working {
                last_update: Utc::now(),
            }),
            message_send_failures: Default::default(),
            current_peer_metadata,
            next_peer_metadata_update_attempt: Mutex::new(Instant::now()),
        })
    }

    pub fn report_snapshot(
        &self,
        peer_id: u64,
        status: impl Into<SnapshotStatus>,
    ) -> Result<(), StorageError> {
        self.propose_sender
            .send(ConsensusOperations::report_snapshot(peer_id, status))
            .map_err(|_err| {
                StorageError::service_error(
                    "failed to send ReportSnapshot message to consensus thread",
                )
            })
    }

    pub fn record_message_send_failure<E: Error>(&self, peer_address: &Uri, error: E) {
        let mut message_send_failures = self.message_send_failures.write();
        let entry = message_send_failures
            .entry(peer_address.to_string())
            .or_default();
        // Log only first error
        if entry.count == 0 {
            log::warn!("Failed to send message to {peer_address} with error: {error}")
        }
        entry.count += 1;
        entry.latest_error = Some(error.to_string());
        entry.latest_error_timestamp = Some(Utc::now());
    }

    pub fn record_message_send_success(&self, peer_address: &Uri) {
        self.message_send_failures
            .write()
            .remove(&peer_address.to_string());
    }

    pub fn record_consensus_working(&self) {
        *self.consensus_thread_status.write() = ConsensusThreadStatus::Working {
            last_update: Utc::now(),
        }
    }

    pub fn on_consensus_stopped(&self) {
        *self.consensus_thread_status.write() = ConsensusThreadStatus::Stopped
    }

    pub fn on_consensus_thread_err<E: Display>(&self, err: E) {
        *self.consensus_thread_status.write() = ConsensusThreadStatus::StoppedWithErr {
            err: err.to_string(),
        }
    }

    pub fn set_raft_soft_state(&self, state: &SoftState) {
        *self.soft_state.write() = Some(SoftState { ..*state });
    }

    pub fn this_peer_id(&self) -> PeerId {
        self.persistent.read().this_peer_id
    }

    pub fn peers(&self) -> Vec<PeerId> {
        self.persistent
            .read()
            .peer_address_by_id()
            .keys()
            .copied()
            .collect()
    }

    pub fn first_voter(&self) -> PeerId {
        let state = self.persistent.read();

        match state.first_voter() {
            Some(peer_id) if peer_id != PeerId::MAX => peer_id,
            _ => state.this_peer_id(),
        }
    }

    pub fn set_first_voter(&self, id: PeerId) -> Result<(), StorageError> {
        self.persistent.write().set_first_voter(id)
    }

    pub fn recover_first_voter(&self) -> Result<(), StorageError> {
        if self.persistent.read().first_voter().is_none() {
            log::debug!("Recovering first voter peer...");

            let wal = self.wal.lock();
            let peers = self.peers();

            if let Some(peer_id) = recover_first_voter(&wal, &peers)? {
                log::debug!("Recovered first voter peer {peer_id}");
                self.set_first_voter(peer_id)?;
            }
        }

        Ok(())
    }

    /// Report aggregated information about the cluster.
    /// Useful for API reporting.
    pub fn cluster_status(&self) -> ClusterStatus {
        let persistent = self.persistent.read();
        let hard_state = &persistent.state.hard_state;
        let peers = persistent
            .peer_address_by_id()
            .into_iter()
            .map(|(peer_id, uri)| {
                (
                    peer_id,
                    PeerInfo {
                        uri: uri.to_string(),
                    },
                )
            })
            .collect();
        let pending_operations = persistent.unapplied_entities_count();
        let soft_state = self.soft_state.read();
        let leader = soft_state.as_ref().map(|state| state.leader_id);
        let role = soft_state.as_ref().map(|state| state.raft_state.into());
        let peer_id = persistent.this_peer_id;
        let is_voter = persistent.state.conf_state.get_voters().contains(&peer_id);
        ClusterStatus::Enabled(ClusterInfo {
            peer_id,
            peers,
            raft_info: RaftInfo {
                term: hard_state.term,
                commit: hard_state.commit,
                pending_operations,
                leader,
                role,
                is_voter,
            },
            consensus_thread_status: self.consensus_thread_status.read().clone(),
            message_send_failures: self.message_send_failures.read().clone(),
        })
    }

    /// Handle peer removal operation.
    ///
    /// 1. Try to remove peer
    /// 2. Handle peer removal error
    /// 3. Report to the listeners
    ///
    /// Return if consensus should be stopped.
    pub fn on_peer_remove(&self, peer_id: PeerId) -> Result<bool, StorageError> {
        let mut stop_consensus: bool = false;

        let report = match self.remove_peer(peer_id) {
            Ok(()) => {
                if self.this_peer_id() == peer_id {
                    stop_consensus = true;
                }
                Ok(ConsensusApplyReceipt::configuration_change(true))
            }
            Err(err) => match err {
                err @ StorageError::ServiceError { .. } => {
                    return Err(err);
                }
                _ => Err(err),
            },
        };
        let operation = ConsensusOperations::RemovePeer(peer_id);
        let on_apply = self.on_consensus_op_apply.lock().remove(&operation);
        if let Some(on_apply) = on_apply
            && on_apply.send(report).is_err()
        {
            log::warn!(
                "Failed to notify on consensus operation completion: channel receiver is dropped",
            )
        }
        Ok(stop_consensus)
    }

    pub fn set_unapplied_entries(
        &self,
        first_index: EntryId,
        last_index: EntryId,
    ) -> Result<(), raft::Error> {
        self.persistent
            .write()
            .set_unapplied_entries(first_index, last_index)
            .map_err(raft_error_other)
    }

    /// Process the consensus operation, which are already committed.
    /// If return Error - consensus should be stopped with error.
    /// Return `true` if consensus should be stopped (peer removed)
    /// Return `false` if everything is ok.
    pub fn apply_entries<T: Storage>(&self, raw_node: &mut RawNode<T>) -> anyhow::Result<bool> {
        use raft::eraftpb::EntryType;

        self.persistent
            .write()
            .save_if_dirty()
            .context("Failed to save new state of applied entries queue")?;

        loop {
            let unapplied_index = self.persistent.read().current_unapplied_entry();
            let Some(entry_index) = unapplied_index else {
                break;
            };
            log::debug!("Applying committed entry with index {entry_index}");
            let entry = self
                .wal
                .lock()
                .entry(entry_index)
                .context(format!("Failed to get entry at index {entry_index}"))?;
            let (stop_consensus, cursor_disposition) = if entry.data.is_empty() {
                // Empty entry, when the peer becomes Leader it will send an empty entry.
                (false, NormalEntryCursorDisposition::NeedsSeparateCommit)
            } else {
                match entry.get_entry_type() {
                    EntryType::EntryNormal => {
                        match self.apply_normal_entry_at_current_cursor(&entry) {
                            Ok(outcome) => {
                                match &outcome.operation_result {
                                    Ok(result) => log::debug!(
                                        "Successfully applied consensus operation entry. Index: {}. Result: {result}",
                                        entry.index,
                                    ),
                                    Err(error) => log::warn!(
                                        "Rejected collection meta operation entry with user error. Index: {}. Error: {error}",
                                        entry.index,
                                    ),
                                }
                                (false, outcome.cursor_disposition)
                            }
                            Err(err @ StorageError::ServiceError { .. }) => {
                                // This is a service error - stop consensus. Peer can be restarted when the problem is fixed.
                                return Err(err)
                                    .context("Failed to apply collection meta operation entry");
                            }
                            Err(err) => {
                                log::warn!(
                                    "Failed to apply collection meta operation entry with user error: {err}",
                                );
                                // This is a user error so we can safely consider it applied but with error as it was incorrect.
                                (false, NormalEntryCursorDisposition::NeedsSeparateCommit)
                            }
                        }
                    }
                    EntryType::EntryConfChangeV2 => {
                        let stop_consensus = self
                            .apply_conf_change_entry(&entry, raw_node)
                            .context("Failed to apply configuration change entry")?;
                        log::debug!(
                            "Successfully applied configuration change entry. Index: {}. Stop consensus: {}",
                            entry.index,
                            stop_consensus
                        );
                        (
                            stop_consensus,
                            NormalEntryCursorDisposition::NeedsSeparateCommit,
                        )
                    }
                    ty @ EntryType::EntryConfChange => {
                        return Err(anyhow!("Unexpected entry type: {ty:?}"));
                    }
                }
            };
            if stop_consensus {
                return Ok(stop_consensus);
            }
            match cursor_disposition {
                NormalEntryCursorDisposition::NeedsSeparateCommit => {
                    self.persistent
                        .write()
                        .entry_applied()
                        .context("Failed to save new state of applied entries queue")?;
                }
                NormalEntryCursorDisposition::Committed(index) => {
                    if index != entry_index {
                        return Err(anyhow!(
                            "private ORAM mutation committed an unexpected Raft apply cursor"
                        ));
                    }
                }
            }
        }
        Ok(false) // do not stop consensus
    }

    /// Process the consensus operation, which are already committed.
    /// In this particular function - operations related to the cluster topology change:
    ///
    /// - AddPeer (different states)
    /// - RemovePeer
    pub fn apply_conf_change_entry<T: Storage>(
        &self,
        entry: &RaftEntry,
        raw_node: &mut RawNode<T>,
    ) -> Result<bool, StorageError> {
        if self.private_oram_mutation_format_floor_installed() {
            // A committed configuration change must be applied or this peer's state machine
            // diverges from the quorum and consensus halts for good. The private ORAM roster is
            // bound to the activation-time configuration, so ORAM mutation paths keep failing
            // closed for peers outside it until the authority is re-established.
            log::warn!(
                "committed cluster topology change crossed the private ORAM activation floor;                  private ORAM mutation participation is limited to the activation-time roster"
            );
        }
        let change: ConfChangeV2 = prost_for_raft::Message::decode(entry.get_data())?;

        let conf_state = raw_node.apply_conf_change(&change)?;
        log::debug!("Applied conf state {conf_state:?}");
        self.persistent
            .write()
            .apply_state_update(|state| state.conf_state = conf_state)?;

        let mut stop_consensus: bool = false;
        for single_change in &change.changes {
            match single_change.change_type() {
                ConfChangeType::AddNode => {
                    let context = entry.get_context();

                    if !context.is_empty() {
                        let peer_uri = str::from_utf8(context)
                            .map_err(|err| {
                                StorageError::service_error(format!(
                                    "failed to parse peer URI: {err}"
                                ))
                            })?
                            .parse()
                            .map_err(|err| {
                                StorageError::service_error(format!(
                                    "failed to parse peer URI: {err}"
                                ))
                            })?;

                        self.add_peer(single_change.node_id, peer_uri)?;
                    } else {
                        debug_assert!(
                            self.peer_address_by_id()
                                .contains_key(&single_change.node_id),
                            "Peer should be already known"
                        )
                    }
                }
                ConfChangeType::RemoveNode => {
                    log::debug!("Removing node {}", single_change.node_id);
                    stop_consensus |= self.on_peer_remove(single_change.node_id)?;
                }
                ConfChangeType::AddLearnerNode => {
                    log::debug!("Adding learner node {}", single_change.node_id);
                    if let Ok(peer_uri) = String::from_utf8_lossy(entry.get_context())
                        .deref()
                        .try_into()
                    {
                        let peer_uri: Uri = peer_uri;
                        // Add peer to state
                        self.add_peer(single_change.node_id, peer_uri.clone())?;

                        // Notify the submitter, that operation was performed
                        {
                            let operation = ConsensusOperations::AddPeer {
                                peer_id: single_change.node_id,
                                uri: peer_uri.to_string(),
                            };
                            let on_apply = self.on_consensus_op_apply.lock().remove(&operation);
                            if let Some(on_apply) = on_apply
                                && on_apply
                                    .send(Ok(ConsensusApplyReceipt::configuration_change(true)))
                                    .is_err()
                            {
                                log::warn!(
                                    "Failed to notify on consensus operation completion: channel receiver is dropped",
                                )
                            }
                        }
                    } else if entry.get_context().is_empty() {
                        // Allow empty context for compatibility
                        log::warn!(
                            "Outdated peer addition entry found with index: {}",
                            entry.get_index()
                        )
                    } else {
                        // Should not be reachable as it is checked in API
                        return Err(StorageError::service_error("Failed to parse peer uri"));
                    }
                }
            }
        }
        Ok(stop_consensus)
    }

    /// Process the consensus operation, which are already committed.
    /// In this particular function - operations related to user data:
    ///
    /// - CreateCollection
    /// - DropCollection
    /// - Update collection params
    /// - Update collection aliases
    /// - Shards operations (transfer, remove, sync)
    /// - e.t.c
    ///
    #[cfg(test)]
    pub fn apply_normal_entry(&self, entry: &RaftEntry) -> Result<bool, StorageError> {
        self.apply_normal_entry_inner(entry, NormalEntryApplyContext::DetachedForTest)?
            .operation_result
    }

    fn apply_normal_entry_at_current_cursor(
        &self,
        entry: &RaftEntry,
    ) -> Result<NormalEntryApplyOutcome, StorageError> {
        self.apply_normal_entry_inner(entry, NormalEntryApplyContext::CommittedAtCurrentCursor)
    }

    /// Resolves the term of the entry the activation proof is anchored on.
    ///
    /// This runs inside apply, so every outcome must be the same on every replica regardless of
    /// local WAL compaction or snapshot timing: a refusal is a `bad_request` (rejected entry),
    /// never a service error that stops consensus.
    /// - An enable barrier resolves from the durable pending activation: its proof was checked
    ///   against the real base term when the prepare barrier applied, and the base entry may
    ///   since have been compacted from the local WAL.
    /// - A prepare barrier applied at `entry_index` must sit directly after its base entry, which
    ///   is then the last applied entry and is never compacted.
    fn private_oram_activation_barrier_base_term(
        &self,
        operation: &PrivateOramMutationActivationBarrierV2,
        entry_index: Option<u64>,
    ) -> Result<u64, StorageError> {
        let unavailable = || {
            StorageError::bad_request("private ORAM mutation activation base term is unavailable")
        };
        let proof = operation.decode_proof()?;
        if matches!(
            operation.phase(),
            PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2
                | PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes
        ) {
            let pending_enable = self
                .persistent
                .read()
                .private_oram_mutation_activation_pending
                .as_ref()
                .map(PrivateOramMutationActivationPendingV2::enable_operation)
                .transpose()?
                .as_ref()
                == Some(operation);
            if pending_enable {
                return Ok(proof.expected_commit_entry_term());
            }
            return Err(StorageError::bad_request(
                "private ORAM mutation activation enable barrier does not match the pending activation",
            ));
        }
        let base_index = proof.expected_hard_commit();
        if let Some(entry_index) = entry_index
            && base_index.checked_add(1) != Some(entry_index)
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation activation prepare barrier must follow its base entry",
            ));
        }
        let snapshot_meta = self.persistent.read().latest_snapshot_meta().clone();
        if snapshot_meta.index == base_index {
            if snapshot_meta.term == 0 {
                return Err(unavailable());
            }
            return Ok(snapshot_meta.term);
        }
        if base_index < snapshot_meta.index {
            return Err(StorageError::bad_request(
                "private ORAM mutation activation proof is older than the installed snapshot",
            ));
        }
        let base_entry = self
            .wal
            .lock()
            .entry(base_index)
            .map_err(|_| unavailable())?;
        if base_entry.term == 0 {
            return Err(unavailable());
        }
        Ok(base_entry.term)
    }

    /// Revalidates the complete live proof immediately before the leader proposes either barrier
    /// entry. The caller must pass values from the same `RawNode` observation.
    pub fn validate_private_oram_mutation_activation_proposal(
        &self,
        operation: &PrivateOramMutationActivationBarrierV2,
        current_term: u64,
        last_log_index: u64,
        last_applied_index: u64,
        pending_conf_index: u64,
    ) -> Result<(), StorageError> {
        let invalid = || {
            StorageError::bad_request(
                "private ORAM mutation activation proposal precondition failed",
            )
        };
        let proof = operation.decode_proof()?;
        let base_term = self.private_oram_activation_barrier_base_term(operation, None)?;
        let persistent = self.persistent.read();
        let hard_commit = persistent.state.hard_state.commit;
        let phase_preconditions_hold = match operation.phase() {
            PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites => {
                current_term == proof.expected_current_term()
                    && hard_commit == proof.expected_hard_commit()
                    && persistent
                        .private_oram_mutation_activation_pending
                        .is_none()
            }
            PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads => {
                current_term == proof.expected_current_term()
                    && hard_commit == proof.expected_hard_commit()
                    && persistent
                        .private_oram_mutation_activation_pending
                        .is_none()
                    && persistent.private_oram_mutation_v3_floor_upgrade_quiescent()?
            }
            PrivateOramMutationActivationBarrierPhaseV2::EnableMutationV2 => persistent
                .private_oram_mutation_activation_pending
                .as_ref()
                .is_some_and(|pending| {
                    current_term >= pending.prepare_entry_term()
                        && hard_commit >= pending.prepare_entry_index()
                }),
            PrivateOramMutationActivationBarrierPhaseV2::EnableReservationV3Writes => {
                persistent
                    .private_oram_mutation_activation_pending
                    .as_ref()
                    .is_some_and(|pending| {
                        current_term >= pending.prepare_entry_term()
                            && hard_commit >= pending.prepare_entry_index()
                    })
                    && persistent.private_oram_mutation_v3_floor_upgrade_quiescent()?
            }
        };
        if !phase_preconditions_hold
            || last_log_index != hard_commit
            || last_applied_index != hard_commit
            || raft_conf_change_pending(pending_conf_index, last_applied_index)
            || persistent.current_unapplied_entry().is_some()
        {
            return Err(invalid());
        }
        let authority = persistent.private_oram_activation_authority_at_configured_read()?;
        let peer_addresses = persistent.peer_address_by_id.read().clone();
        let entry_index = hard_commit.checked_add(1).ok_or_else(invalid)?;
        validate_private_oram_mutation_activation_barrier_v2(
            operation,
            &authority,
            persistent.private_oram_mutation_format_floor.as_ref(),
            persistent.private_oram_mutation_activation_pending.as_ref(),
            &persistent.state.conf_state,
            &peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: current_term,
                entry_index,
                prior_applied_index: last_applied_index,
                barrier_base_entry_term: base_term,
            },
        )?;
        Ok(())
    }

    pub fn private_oram_mutation_format_floor_installed(&self) -> bool {
        self.persistent
            .read()
            .private_oram_mutation_format_floor
            .is_some()
    }

    /// Reconstructs the exact second barrier operation after a restart or leader change.
    pub fn private_oram_mutation_pending_enable_operation(
        &self,
    ) -> Result<Option<PrivateOramMutationActivationBarrierV2>, StorageError> {
        self.persistent
            .read()
            .private_oram_mutation_activation_pending
            .as_ref()
            .map(PrivateOramMutationActivationPendingV2::enable_operation)
            .transpose()
    }

    pub fn private_oram_mutation_v2_activation_status(
        &self,
    ) -> Result<PrivateOramMutationV2ActivationStatus, StorageError> {
        let persistent = self.persistent.read();
        match (
            persistent.private_oram_mutation_format_floor.as_ref(),
            persistent.private_oram_mutation_activation_pending.as_ref(),
        ) {
            (None, None) => Ok(PrivateOramMutationV2ActivationStatus::Unprepared),
            (Some(floor), None) if floor.activation_enabled() => {
                Ok(PrivateOramMutationV2ActivationStatus::Active)
            }
            (Some(floor), Some(pending))
                if floor.activation_enabled()
                    && pending.prepare_phase()
                        == PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads =>
            {
                Ok(PrivateOramMutationV2ActivationStatus::Active)
            }
            (Some(floor), Some(_)) if !floor.activation_enabled() => {
                Ok(PrivateOramMutationV2ActivationStatus::Prepared)
            }
            _ => Err(StorageError::service_error(
                "private ORAM mutation V2 activation state is inconsistent",
            )),
        }
    }

    pub fn private_oram_mutation_v3_write_floor_active(&self) -> Result<bool, StorageError> {
        let persistent = self.persistent.read();
        let Some(floor) = persistent.private_oram_mutation_format_floor.as_ref() else {
            return Ok(false);
        };
        Ok(floor.activation_enabled()
            && floor.minimum_reader_protocol() >= PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
            && floor.minimum_writer_protocol() >= PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
            && persistent
                .private_oram_mutation_activation_pending
                .is_none())
    }

    pub fn private_oram_mutation_v3_floor_upgrade_pending(&self) -> Result<bool, StorageError> {
        let persistent = self.persistent.read();
        Ok(persistent
            .private_oram_mutation_activation_pending
            .as_ref()
            .is_some_and(|pending| {
                pending.prepare_phase()
                    == PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads
            }))
    }

    /// Returns the peer recovery signer pinned by the currently active authority and the exact
    /// authority locator observed in the same persistent read section.
    pub fn private_oram_peer_recovery_signer_pin(
        &self,
        peer_id: PeerId,
    ) -> Result<PrivateOramPeerRecoverySignerPin, StorageError> {
        let invalid = || StorageError::PreconditionFailed {
            description: "private ORAM peer recovery authority is unavailable".to_string(),
        };
        let persistent = self.persistent.read();
        if !persistent
            .private_oram_mutation_format_floor
            .as_ref()
            .is_some_and(PrivateOramMutationFormatFloorV2::activation_enabled)
            || persistent
                .private_oram_mutation_activation_pending
                .is_some()
            || !persistent.state.conf_state.voters.contains(&peer_id)
            || !persistent.state.conf_state.voters_outgoing.is_empty()
            || !persistent.state.conf_state.learners.is_empty()
            || !persistent.state.conf_state.learners_next.is_empty()
            || persistent.state.conf_state.auto_leave
        {
            return Err(invalid());
        }
        let authority = persistent.private_oram_activation_authority_at_configured_read()?;
        let verified = authority.verified_manifest().ok_or_else(invalid)?;
        let pin = verified.peer_pin(peer_id).ok_or_else(invalid)?;
        let observed_uri = persistent
            .peer_address_by_id
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(invalid)?;
        if private_oram_activation_uri_digest(&observed_uri).map_err(|_| invalid())?
            != pin.peer_uri_digest
        {
            return Err(invalid());
        }
        let locator = authority.locator().ok_or_else(invalid)?;
        Ok(PrivateOramPeerRecoverySignerPin {
            signer: pin.signer.clone(),
            registry_generation: locator.registry_generation(),
            manifest_digest: locator.manifest_digest().to_string(),
        })
    }

    /// Captures owner and coordinator signer pins under one persistent read guard.
    pub fn private_oram_peer_recovery_signer_pair_pin(
        &self,
        owner_peer_id: PeerId,
        coordinator_peer_id: PeerId,
    ) -> Result<PrivateOramPeerRecoverySignerPairPin, StorageError> {
        let invalid = || StorageError::PreconditionFailed {
            description: "private ORAM peer recovery authority is unavailable".to_string(),
        };
        if owner_peer_id == coordinator_peer_id {
            return Err(invalid());
        }
        let persistent = self.persistent.read();
        if !persistent
            .private_oram_mutation_format_floor
            .as_ref()
            .is_some_and(PrivateOramMutationFormatFloorV2::activation_enabled)
            || persistent
                .private_oram_mutation_activation_pending
                .is_some()
            || !persistent.state.conf_state.voters.contains(&owner_peer_id)
            || !persistent
                .state
                .conf_state
                .voters
                .contains(&coordinator_peer_id)
            || !persistent.state.conf_state.voters_outgoing.is_empty()
            || !persistent.state.conf_state.learners.is_empty()
            || !persistent.state.conf_state.learners_next.is_empty()
            || persistent.state.conf_state.auto_leave
        {
            return Err(invalid());
        }
        let authority = persistent.private_oram_activation_authority_at_configured_read()?;
        let verified = authority.verified_manifest().ok_or_else(invalid)?;
        let locator = authority.locator().ok_or_else(invalid)?;
        let addresses = persistent.peer_address_by_id.read();
        let resolve = |peer_id| {
            let pin = verified.peer_pin(peer_id).ok_or_else(invalid)?;
            let observed_uri = addresses.get(&peer_id).ok_or_else(invalid)?;
            if private_oram_activation_uri_digest(observed_uri).map_err(|_| invalid())?
                != pin.peer_uri_digest
            {
                return Err(invalid());
            }
            Ok(PrivateOramPeerRecoverySignerPin {
                signer: pin.signer.clone(),
                registry_generation: locator.registry_generation(),
                manifest_digest: locator.manifest_digest().to_string(),
            })
        };
        Ok(PrivateOramPeerRecoverySignerPairPin {
            owner: resolve(owner_peer_id)?,
            coordinator: resolve(coordinator_peer_id)?,
        })
    }

    fn private_oram_mutation_v2_expected_aggregate_digest(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<String, StorageError> {
        if self.private_oram_mutation_v2_activation_status()?
            != PrivateOramMutationV2ActivationStatus::Active
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V2 is not active".to_string(),
            });
        }
        self.persistent
            .read()
            .private_oram_mutation_v2_aggregate_digest(key)
    }

    fn require_private_oram_mutation_v3_write_floor(&self) -> Result<(), StorageError> {
        if !self.private_oram_mutation_v3_write_floor_active()? {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V3 write floor is not active".to_string(),
            });
        }
        Ok(())
    }

    pub fn private_oram_mutation_v2_current_aggregate_digest(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<String, StorageError> {
        self.private_oram_mutation_v2_expected_aggregate_digest(key)
    }

    pub fn private_oram_mutation_v2_append_authority_context(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<PrivateOramMutationAppendAuthorityContextV2, StorageError> {
        if self.private_oram_mutation_v2_activation_status()?
            != PrivateOramMutationV2ActivationStatus::Active
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V2 is not active".to_string(),
            });
        }
        self.persistent
            .read()
            .private_oram_mutation_v2_append_authority_context(key)
    }

    fn private_oram_mutation_v3_pending_reservation_challenge(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationPendingReservationChallengeV1>, StorageError> {
        if self.private_oram_mutation_v2_activation_status()?
            != PrivateOramMutationV2ActivationStatus::Active
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V2 is not active".to_string(),
            });
        }
        self.persistent
            .read()
            .private_oram_mutation_v2_pending_reservation_challenge(key)
    }

    pub fn private_oram_mutation_v3_reservation_challenge_pending(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<bool, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        Ok(self
            .private_oram_mutation_v3_pending_reservation_challenge(key)?
            .is_some())
    }

    pub fn private_oram_mutation_v3_pending_reservation_matches_base(
        &self,
        key: &PrivateOramMutationKey,
        base_reservation: &PrivateOramMutationAppendReservationV2,
    ) -> Result<bool, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let Some(pending) = self.private_oram_mutation_v3_pending_reservation_challenge(key)?
        else {
            return Ok(false);
        };
        let prepared = decode_private_oram_mutation_prepared_reservation_challenge_v3(
            pending.challenge_canonical_json(),
        )
        .map_err(|_| {
            StorageError::service_error("private ORAM reservation challenge is corrupt")
        })?;
        Ok(prepared.base_reservation() == base_reservation)
    }

    pub fn private_oram_mutation_v3_reservation_challenge_disposition(
        &self,
        key: &PrivateOramMutationKey,
        challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    ) -> Result<Option<PrivateOramReservationChallengeDispositionV3>, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        validate_private_oram_owner_reservation_prepare_challenge_v1(challenge).map_err(|_| {
            StorageError::bad_request("private ORAM owner reservation challenge is invalid")
        })?;
        if challenge.collection_id != key.collection_id {
            return Err(StorageError::bad_request(
                "private ORAM owner reservation challenge collection does not match",
            ));
        }
        self.persistent
            .read()
            .private_oram_mutation_v3_reservation_challenge_outcome(
                key,
                &challenge.committed_challenge_digest,
                challenge.challenge_applied_term,
                challenge.challenge_applied_index,
                &challenge.reservation_intent_digest,
                &challenge.attempt_id,
            )?
            .map(|outcome| {
                let kind = match outcome.kind() {
                    PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3 => {
                        PrivateOramReservationChallengeDispositionKindV3::Finalized
                    }
                    PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled => {
                        PrivateOramReservationChallengeDispositionKindV3::Cancelled
                    }
                };
                Ok(PrivateOramReservationChallengeDispositionV3 {
                    kind,
                    resolution_applied_term: outcome.resolution_applied().term(),
                    resolution_applied_index: outcome.resolution_applied().index(),
                    finalized_reservation_digest: outcome
                        .finalized_reservation_digest()
                        .map(str::to_string),
                })
            })
            .transpose()
    }

    pub fn private_oram_mutation_v3_prestage_aborted_outcome_digest(
        &self,
        key: &PrivateOramMutationKey,
        attempt_id: &str,
    ) -> Result<Option<String>, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        self.persistent
            .read()
            .private_oram_mutation_v3_prestage_aborted_outcome_digest(key, attempt_id)
    }

    pub(crate) fn private_oram_mutation_v2_owner_enrollment_prepared_operation(
        &self,
        prepared: &PrivateOramOwnerEnrollmentPreparedV1,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: prepared.collection_id.clone(),
        };
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let prepared_canonical_json = encode_private_oram_owner_enrollment_prepared_v1(prepared)
            .map_err(|_| {
                StorageError::bad_request("private ORAM owner enrollment prepare is invalid")
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::owner_enrollment_prepared(
                key,
                expected,
                String::from_utf8(prepared_canonical_json).map_err(|_| {
                    StorageError::bad_request("private ORAM owner enrollment prepare is invalid")
                })?,
            ),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_owner_enrollment_activated_operation(
        &self,
        commitment: &PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: commitment.collection_id.clone(),
        };
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let commitment_canonical_json = encode_private_oram_owner_enrollment_genesis_commitment_v1(
            commitment,
        )
        .map_err(|_| {
            StorageError::bad_request("private ORAM owner enrollment activation is invalid")
        })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::owner_enrollment_activated(
                key,
                expected,
                String::from_utf8(commitment_canonical_json).map_err(|_| {
                    StorageError::bad_request("private ORAM owner enrollment activation is invalid")
                })?,
            ),
        ))
    }

    #[doc(hidden)]
    pub fn private_oram_mutation_v2_append_reservation_operation(
        &self,
        reservation: &PrivateOramMutationAppendReservationV2,
    ) -> Result<ConsensusOperations, StorageError> {
        if self.private_oram_mutation_v3_write_floor_active()? {
            return Err(StorageError::PreconditionFailed {
                description:
                    "private ORAM mutation V2 reservation creation is disabled by the V3 floor"
                        .to_string(),
            });
        }
        let key = PrivateOramMutationKey {
            collection_id: reservation.collection_id().to_string(),
        };
        let expected = reservation.expected_aggregate_digest().to_string();
        if self.private_oram_mutation_v2_expected_aggregate_digest(&key)? != expected {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM append reservation authority changed".to_string(),
            });
        }
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v2(reservation).map_err(|_| {
                StorageError::bad_request("private ORAM append reservation is invalid")
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::append_reservation(
                key,
                expected,
                reservation_canonical_json,
            ),
        ))
    }

    pub fn private_oram_mutation_v3_reservation_challenge_operation(
        &self,
        base_reservation: &PrivateOramMutationAppendReservationV2,
        owner_challenge_nonces: Vec<String>,
    ) -> Result<ConsensusOperations, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let key = PrivateOramMutationKey {
            collection_id: base_reservation.collection_id().to_string(),
        };
        if self
            .private_oram_mutation_v3_pending_reservation_challenge(&key)?
            .is_some()
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM reservation challenge is already pending".to_string(),
            });
        }
        if self
            .persistent
            .read()
            .private_oram_mutation_v3_oldest_reservation_challenge_outcome(&key)?
            .is_some()
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM reservation outcome acknowledgement is pending"
                    .to_string(),
            });
        }
        let expected = base_reservation.expected_aggregate_digest().to_string();
        if self.private_oram_mutation_v2_expected_aggregate_digest(&key)? != expected {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM reservation challenge authority changed".to_string(),
            });
        }
        let reservation_intent = private_oram_mutation_reservation_intent_v3(base_reservation)
            .map_err(|_| StorageError::bad_request("private ORAM reservation intent is invalid"))?;
        let checkpoint_table = self
            .persistent
            .read()
            .private_oram_mutation_v2_owner_checkpoint_table(&key)?;
        let checkpoint_context = crate::content_manager::consensus::private_oram_mutation_cleanup::owner_checkpoint::private_oram_owner_checkpoint_reservation_context_v1(
            &checkpoint_table,
            reservation_intent.intent_digest().to_string(),
        )
        .map_err(|_| {
            StorageError::PreconditionFailed {
                description: "private ORAM owner checkpoints are not reservable".to_string(),
            }
        })?;
        let challenge = private_oram_mutation_prepared_reservation_challenge_v3(
            base_reservation.clone(),
            reservation_intent,
            checkpoint_context,
            owner_challenge_nonces,
        )
        .map_err(|_| StorageError::bad_request("private ORAM reservation challenge is invalid"))?;
        let challenge_canonical_json =
            encode_private_oram_mutation_prepared_reservation_challenge_v3(&challenge).map_err(
                |_| StorageError::bad_request("private ORAM reservation challenge is invalid"),
            )?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::append_reservation_challenge_prepared_v3(
                key,
                expected,
                challenge_canonical_json,
            ),
        ))
    }

    pub fn private_oram_mutation_v3_owner_reservation_prepare_contexts(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Vec<PrivateOramOwnerReservationPrepareContextV3>, StorageError> {
        self.private_oram_mutation_v3_owner_reservation_contexts_inner(key, false)
    }

    pub fn private_oram_mutation_v3_owner_reservation_resolution_contexts(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Vec<PrivateOramOwnerReservationPrepareContextV3>, StorageError> {
        self.private_oram_mutation_v3_owner_reservation_contexts_inner(key, true)
    }

    pub fn private_oram_mutation_v3_oldest_reservation_outcome_recovery(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramReservationOutcomeRecoveryV3>, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let outcome = self
            .persistent
            .read()
            .private_oram_mutation_v3_oldest_reservation_challenge_outcome(key)?;
        let Some(outcome) = outcome else {
            return Ok(None);
        };
        let challenge_canonical_json =
            outcome
                .challenge_canonical_json()
                .ok_or_else(|| StorageError::PreconditionFailed {
                    description:
                        "private ORAM reservation outcome predates owner resolution recovery"
                            .to_string(),
                })?;
        let owner_contexts =
            Self::private_oram_mutation_v3_owner_reservation_contexts_from_canonical(
                challenge_canonical_json,
                outcome.challenge_digest(),
                outcome.challenge_applied(),
            )?;
        let disposition = PrivateOramReservationChallengeDispositionV3 {
            kind: match outcome.kind() {
                PrivateOramMutationReservationChallengeOutcomeKindV1::FinalizedV3 => {
                    PrivateOramReservationChallengeDispositionKindV3::Finalized
                }
                PrivateOramMutationReservationChallengeOutcomeKindV1::Cancelled => {
                    PrivateOramReservationChallengeDispositionKindV3::Cancelled
                }
            },
            resolution_applied_term: outcome.resolution_applied().term(),
            resolution_applied_index: outcome.resolution_applied().index(),
            finalized_reservation_digest: outcome
                .finalized_reservation_digest()
                .map(str::to_string),
        };
        Ok(Some(PrivateOramReservationOutcomeRecoveryV3 {
            outcome_digest: outcome.outcome_digest().to_string(),
            owner_contexts,
            disposition,
        }))
    }

    fn private_oram_mutation_v3_owner_reservation_contexts_inner(
        &self,
        key: &PrivateOramMutationKey,
        allow_resolved: bool,
    ) -> Result<Vec<PrivateOramOwnerReservationPrepareContextV3>, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let persistent = self.persistent.read();
        let pending = persistent.private_oram_mutation_v2_pending_reservation_challenge(key)?;
        let resolved = if pending.is_none() && allow_resolved {
            persistent.private_oram_mutation_v3_latest_reservation_challenge_outcome(key)?
        } else {
            None
        };
        let (challenge_canonical_json, expected_challenge_digest, challenge_applied) =
            match (pending.as_ref(), resolved.as_ref()) {
                (Some(pending), None) => (
                    pending.challenge_canonical_json(),
                    pending.challenge_digest(),
                    pending.challenge_applied(),
                ),
                (None, Some(outcome)) => (
                    outcome.challenge_canonical_json().ok_or_else(|| {
                        StorageError::PreconditionFailed {
                        description:
                            "private ORAM reservation outcome predates owner resolution recovery"
                                .to_string(),
                    }
                    })?,
                    outcome.challenge_digest(),
                    outcome.challenge_applied(),
                ),
                _ => {
                    return Err(StorageError::PreconditionFailed {
                        description: "private ORAM reservation challenge is not committed"
                            .to_string(),
                    });
                }
            };
        Self::private_oram_mutation_v3_owner_reservation_contexts_from_canonical(
            challenge_canonical_json,
            expected_challenge_digest,
            challenge_applied,
        )
    }

    fn private_oram_mutation_v3_owner_reservation_contexts_from_canonical(
        challenge_canonical_json: &str,
        expected_challenge_digest: &str,
        challenge_applied: &PrivateOramRaftApplyLocatorV2,
    ) -> Result<Vec<PrivateOramOwnerReservationPrepareContextV3>, StorageError> {
        let prepared = decode_private_oram_mutation_prepared_reservation_challenge_v3(
            challenge_canonical_json,
        )
        .map_err(|_| {
            StorageError::service_error("private ORAM reservation challenge is corrupt")
        })?;
        if expected_challenge_digest != prepared.prepared_challenge_digest() {
            return Err(StorageError::service_error(
                "private ORAM reservation challenge authority is corrupt",
            ));
        }
        let base = prepared.base_reservation();
        let checkpoint_context = prepared.checkpoint_context();
        let expectations = checkpoint_context.owner_expectations();
        let targets = base.owner_targets();
        let nonces = prepared.owner_challenge_nonces();
        if expectations.len() != targets.len() || expectations.len() != nonces.len() {
            return Err(StorageError::service_error(
                "private ORAM reservation challenge owner set is corrupt",
            ));
        }
        let owner_count = u32::try_from(expectations.len()).map_err(|_| {
            StorageError::service_error("private ORAM reservation challenge owner set is corrupt")
        })?;
        targets
            .iter()
            .zip(expectations)
            .zip(nonces)
            .enumerate()
            .map(|(position, ((target, expectation), nonce))| {
                let owner_index = u32::try_from(position).map_err(|_| {
                    StorageError::service_error(
                        "private ORAM reservation challenge owner set is corrupt",
                    )
                })?;
                if target.owner_index() != owner_index
                    || expectation.owner_index() != owner_index
                    || target.owner_peer_id() != expectation.owner_peer_id()
                {
                    return Err(StorageError::service_error(
                        "private ORAM reservation challenge owner set is corrupt",
                    ));
                }
                let challenge = PrivateOramOwnerReservationPrepareChallengeV1 {
                    version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
                    consensus_history_id_digest: base.consensus_history_id_digest().to_string(),
                    raft_group_id_digest: base.raft_group_id_digest().to_string(),
                    collection_id: base.collection_id().to_string(),
                    collection_lifetime_id_digest: base.collection_lifetime_id_digest().to_string(),
                    collection_incarnation_digest: base.collection_incarnation_digest().to_string(),
                    activation_anchor_digest: base.activation_anchor_digest().to_string(),
                    capability_epoch: checkpoint_context.capability_epoch(),
                    protocol_capability_digest: checkpoint_context
                        .protocol_capability_digest()
                        .to_string(),
                    membership_epoch: checkpoint_context.membership_epoch(),
                    reservation_intent_digest: prepared
                        .reservation_intent()
                        .intent_digest()
                        .to_string(),
                    checkpoint_context_digest: checkpoint_context.context_digest().to_string(),
                    committed_challenge_digest: prepared.prepared_challenge_digest().to_string(),
                    challenge_applied_term: challenge_applied.term(),
                    challenge_applied_index: challenge_applied.index(),
                    attempt_id: base.attempt_id().to_string(),
                    challenge_nonce: nonce.clone(),
                    expected_checkpoint_record_digest: expectation
                        .expected_checkpoint_record_digest()
                        .to_string(),
                    expected_checkpoint_sequence: expectation.expected_checkpoint_sequence(),
                    expected_owner_target_digest: target.target_digest().to_string(),
                    reserved_terminal_intent_key: target.intent_key().to_string(),
                    owner_index,
                    owner_count,
                    owner_enrollment_id: expectation.owner_enrollment_id().to_string(),
                    owner_peer_id: expectation.owner_peer_id(),
                    owner_store_incarnation_digest: expectation
                        .owner_store_incarnation_digest()
                        .to_string(),
                    authority_registry_digest: expectation.authority_registry_digest().to_string(),
                    owner_registry_digest: expectation.owner_registry_digest().to_string(),
                };
                validate_private_oram_owner_reservation_prepare_challenge_v1(&challenge).map_err(
                    |_| {
                        StorageError::service_error(
                            "private ORAM reservation challenge context is corrupt",
                        )
                    },
                )?;
                Ok(PrivateOramOwnerReservationPrepareContextV3 {
                    challenge,
                    expected_lifecycle_state: expectation.expected_lifecycle_state().clone(),
                    expected_owner_signer: expectation.owner_signer().clone(),
                })
            })
            .collect()
    }

    pub fn private_oram_mutation_v3_append_reservation_operation(
        &self,
        key: &PrivateOramMutationKey,
        owner_prepares: Vec<PrivateOramOwnerReservationPrepareV1>,
    ) -> Result<ConsensusOperations, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let persistent = self.persistent.read();
        let expected = persistent.private_oram_mutation_v2_aggregate_digest(key)?;
        let pending = persistent
            .private_oram_mutation_v2_pending_reservation_challenge(key)?
            .ok_or_else(|| StorageError::PreconditionFailed {
                description: "private ORAM reservation challenge is not committed".to_string(),
            })?;
        let prepared_challenge = decode_private_oram_mutation_prepared_reservation_challenge_v3(
            pending.challenge_canonical_json(),
        )
        .map_err(|_| {
            StorageError::service_error("private ORAM reservation challenge is corrupt")
        })?;
        let checkpoint_table = persistent.private_oram_mutation_v2_owner_checkpoint_table(key)?;
        drop(persistent);
        let contexts = self.private_oram_mutation_v3_owner_reservation_prepare_contexts(key)?;
        if owner_prepares.len() != contexts.len() {
            return Err(StorageError::bad_request(
                "private ORAM owner reservation prepare set is incomplete",
            ));
        }
        let mut checkpoints = checkpoint_table.checkpoints().iter().collect::<Vec<_>>();
        checkpoints.sort_by_key(|checkpoint| checkpoint.owner_peer_id());
        let bindings = owner_prepares
            .into_iter()
            .zip(&contexts)
            .zip(checkpoints)
            .enumerate()
            .map(|(position, ((prepare, context), checkpoint))| {
                if &prepare.challenge != context.challenge() {
                    return Err(StorageError::bad_request(
                        "private ORAM owner reservation prepare context changed",
                    ));
                }
                private_oram_owner_checkpoint_reservation_binding_v1(
                    u32::try_from(position).map_err(|_| {
                        StorageError::bad_request(
                            "private ORAM owner reservation prepare set is oversized",
                        )
                    })?,
                    checkpoint,
                    prepare,
                )
                .map_err(|_| {
                    StorageError::bad_request("private ORAM owner reservation prepare is invalid")
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        let reservation = private_oram_mutation_append_reservation_v3(
            prepared_challenge.base_reservation().clone(),
            prepared_challenge.reservation_intent().clone(),
            prepared_challenge.checkpoint_context().clone(),
            prepared_challenge,
            pending.challenge_applied().clone(),
            bindings,
        )
        .map_err(|_| StorageError::bad_request("private ORAM V3 append reservation is invalid"))?;
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v3(&reservation).map_err(|_| {
                StorageError::bad_request("private ORAM V3 append reservation is invalid")
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::append_reservation_finalized_v3(
                key.clone(),
                expected,
                reservation_canonical_json,
            ),
        ))
    }

    pub fn private_oram_mutation_v3_reservation_challenge_cancellation_operation(
        &self,
        key: PrivateOramMutationKey,
        cancellation_operation_id: String,
    ) -> Result<ConsensusOperations, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let pending = self
            .private_oram_mutation_v3_pending_reservation_challenge(&key)?
            .ok_or_else(|| StorageError::PreconditionFailed {
                description: "private ORAM reservation challenge is not committed".to_string(),
            })?;
        let cancellation = private_oram_mutation_reservation_challenge_cancellation_v1(
            &pending,
            cancellation_operation_id,
        )
        .map_err(|_| {
            StorageError::bad_request("private ORAM reservation challenge cancellation is invalid")
        })?;
        let cancellation_canonical_json =
            encode_private_oram_mutation_reservation_challenge_cancellation_v1(&cancellation)
                .map_err(|_| {
                    StorageError::bad_request(
                        "private ORAM reservation challenge cancellation is invalid",
                    )
                })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::append_reservation_challenge_cancelled_v3(
                key,
                expected,
                cancellation_canonical_json,
            ),
        ))
    }

    pub fn private_oram_mutation_v3_reservation_outcome_acknowledgement_operation(
        &self,
        key: PrivateOramMutationKey,
        outcome_digest: String,
        owner_resolution_receipts: Vec<SignedPrivateOramOwnerReservationResolutionReceiptV1>,
    ) -> Result<ConsensusOperations, StorageError> {
        self.require_private_oram_mutation_v3_write_floor()?;
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let acknowledgement = private_oram_mutation_reservation_outcome_acknowledgement_v1(
            outcome_digest,
            owner_resolution_receipts,
        )
        .map_err(|_| {
            StorageError::bad_request("private ORAM reservation outcome acknowledgement is invalid")
        })?;
        let acknowledgement_canonical_json =
            encode_private_oram_mutation_reservation_outcome_acknowledgement_v1(&acknowledgement)
                .map_err(|_| {
                StorageError::bad_request(
                    "private ORAM reservation outcome acknowledgement is invalid",
                )
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::append_reservation_outcome_acknowledged_v3(
                key,
                expected,
                acknowledgement_canonical_json,
            ),
        ))
    }

    #[doc(hidden)]
    pub fn private_oram_mutation_v2_append_prepared_operation_at_expected(
        &self,
        manifest: &PrivateOramMutationAllOwnersPrestagedV2,
        expected: String,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: manifest.collection_id().to_string(),
        };
        if self.private_oram_mutation_v2_expected_aggregate_digest(&key)? != expected {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM append prepare authority changed".to_string(),
            });
        }
        let recovery_manifest_canonical_json =
            encode_private_oram_mutation_admission_recovery_manifest_v2(manifest).map_err(
                |_| StorageError::bad_request("private ORAM append prepare manifest is invalid"),
            )?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::append_prepared(
                key,
                expected,
                recovery_manifest_canonical_json,
            ),
        ))
    }

    #[doc(hidden)]
    pub fn private_oram_mutation_v2_reserved_attempt_rejected_operation_at_expected(
        &self,
        reservation: &PrivateOramMutationAppendReservationV2,
        expected: String,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: reservation.collection_id().to_string(),
        };
        if self.private_oram_mutation_v2_expected_aggregate_digest(&key)? != expected {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM reserved append authority changed".to_string(),
            });
        }
        let reservation_canonical_json =
            encode_private_oram_mutation_append_reservation_v2(reservation).map_err(|_| {
                StorageError::bad_request("private ORAM append reservation is invalid")
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::reserved_attempt_rejected(
                key,
                expected,
                reservation_canonical_json,
            ),
        ))
    }

    pub fn private_oram_mutation_v2_admission_operation(
        &self,
        lease: PrivateOramMutationLease,
        recovery_manifest_canonical_json: String,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        self.private_oram_mutation_v2_admission_operation_at_expected(
            lease,
            recovery_manifest_canonical_json,
            expected,
        )
    }

    pub(crate) fn private_oram_mutation_v2_admission_operation_at_expected(
        &self,
        lease: PrivateOramMutationLease,
        recovery_manifest_canonical_json: String,
        expected: String,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        if self.private_oram_mutation_v2_expected_aggregate_digest(&key)? != expected {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation admission authority changed".to_string(),
            });
        }
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::admission(
                key,
                expected,
                lease,
                recovery_manifest_canonical_json,
            ),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_admission_rejected_operation_at_expected(
        &self,
        lease: PrivateOramMutationLease,
        recovery_manifest_canonical_json: String,
        expected: String,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        if self.private_oram_mutation_v2_expected_aggregate_digest(&key)? != expected {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation admission authority changed".to_string(),
            });
        }
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::admission_rejected(
                key,
                expected,
                lease,
                recovery_manifest_canonical_json,
            ),
        ))
    }

    pub fn private_oram_mutation_v2_renewal_operation(
        &self,
        lease: PrivateOramMutationLease,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::renewal(key, expected, lease),
        ))
    }

    pub fn private_oram_mutation_v2_abort_decision_operation(
        &self,
        lease: PrivateOramMutationLease,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: lease.collection_id.clone(),
        };
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::abort_decision(key, expected, lease),
        ))
    }

    pub fn private_oram_mutation_v2_consensus_commit_operation(
        &self,
        mutation_lease_generation: u64,
        new_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<ConsensusOperations, StorageError> {
        let key = PrivateOramMutationKey {
            collection_id: new_state.collection_id.clone(),
        };
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::consensus_commit(
                key,
                expected,
                mutation_lease_generation,
                new_state,
            ),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_parent_progress_operation(
        &self,
        key: PrivateOramMutationKey,
        expectation: &PrivateOramMutationParentWatermarkExpectationV2,
    ) -> Result<ConsensusOperations, StorageError> {
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let encoded = encode_private_oram_mutation_parent_watermark_expectation_v2(expectation)
            .map_err(|_| {
                StorageError::bad_request("private ORAM mutation parent watermark is invalid")
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::parent_progress(key, expected, encoded),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_recovery_capsules_ready_operation(
        &self,
        key: PrivateOramMutationKey,
        expectation: &PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
    ) -> Result<ConsensusOperations, StorageError> {
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let encoded = encode_private_oram_mutation_recovery_capsules_ready_v2(expectation)
            .map_err(|_| {
                StorageError::bad_request(
                    "private ORAM mutation recovery capsule certificate is invalid",
                )
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::recovery_capsules_ready(key, expected, encoded),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_cleanup_witness_operation(
        &self,
        key: PrivateOramMutationKey,
        expectation: &PrivateOramMutationCleanupExpectationV2,
    ) -> Result<ConsensusOperations, StorageError> {
        let expected = self.private_oram_mutation_v2_expected_aggregate_digest(&key)?;
        let encoded =
            encode_private_oram_mutation_cleanup_expectation_v2(expectation).map_err(|_| {
                StorageError::bad_request("private ORAM mutation cleanup witness is invalid")
            })?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::cleanup_witness(key, expected, encoded),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_clear_pending_operation(
        &self,
        key: PrivateOramMutationKey,
        expected_generation: u64,
        expected_witness_digest: &str,
        clear_attempt_id_digest: String,
    ) -> Result<ConsensusOperations, StorageError> {
        if self.private_oram_mutation_v2_activation_status()?
            != PrivateOramMutationV2ActivationStatus::Active
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V2 is not active".to_string(),
            });
        }
        let persistent = self.persistent.read();
        let lifecycle = persistent
            .private_oram_mutation_cleanup_lifecycle(&key)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM mutation clear-pending authority is unavailable",
                )
            })?;
        if !lifecycle
            .matches_cleanup_witness(expected_generation, expected_witness_digest)
            .map_err(|_| {
                StorageError::service_error("private ORAM mutation cleanup lifecycle is corrupt")
            })?
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation clear-pending authority is stale",
            ));
        }
        let expected = persistent.private_oram_mutation_v2_aggregate_digest(&key)?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::clear_pending(
                key,
                expected,
                clear_attempt_id_digest,
            ),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_clear_operation(
        &self,
        key: PrivateOramMutationKey,
        expected_generation: u64,
        expected_clear_attempt_id_digest: &str,
    ) -> Result<ConsensusOperations, StorageError> {
        if self.private_oram_mutation_v2_activation_status()?
            != PrivateOramMutationV2ActivationStatus::Active
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V2 is not active".to_string(),
            });
        }
        let persistent = self.persistent.read();
        let lifecycle = persistent
            .private_oram_mutation_cleanup_lifecycle(&key)
            .ok_or_else(|| {
                StorageError::bad_request("private ORAM mutation clear authority is unavailable")
            })?;
        if !lifecycle
            .matches_clear_pending(expected_generation, expected_clear_attempt_id_digest)
            .map_err(|_| {
                StorageError::service_error("private ORAM mutation cleanup lifecycle is corrupt")
            })?
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation clear authority is stale",
            ));
        }
        let expected = persistent.private_oram_mutation_v2_aggregate_digest(&key)?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::clear(key, expected),
        ))
    }

    pub(crate) fn private_oram_mutation_v2_clear_acknowledgement_operation(
        &self,
        key: PrivateOramMutationKey,
        expected_owner_peer_id: PeerId,
        expected_generation: u64,
    ) -> Result<ConsensusOperations, StorageError> {
        if self.private_oram_mutation_v2_activation_status()?
            != PrivateOramMutationV2ActivationStatus::Active
        {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation V2 is not active".to_string(),
            });
        }
        let persistent = self.persistent.read();
        let lifecycle = persistent
            .private_oram_mutation_cleanup_lifecycle(&key)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM mutation clear acknowledgement authority is unavailable",
                )
            })?;
        if lifecycle.pending_acknowledgement_owner().map_err(|_| {
            StorageError::service_error("private ORAM mutation cleanup lifecycle is corrupt")
        })? != Some((expected_owner_peer_id, expected_generation))
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation clear acknowledgement authority is stale",
            ));
        }
        let expected = persistent.private_oram_mutation_v2_aggregate_digest(&key)?;
        Ok(ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
            ApplyPrivateOramMutationMaterialV2::clear_acknowledgement(key, expected),
        ))
    }

    pub fn require_private_oram_activation_coordinator_is_local_leader(
        &self,
    ) -> Result<(), StorageError> {
        self.require_private_oram_mutation_coordinator_is_local_leader()
            .map_err(|_| StorageError::PreconditionFailed {
                description:
                    "private ORAM mutation V2 activation must be coordinated by the current leader"
                        .to_string(),
            })
    }

    pub fn require_private_oram_mutation_coordinator_is_local_leader(
        &self,
    ) -> Result<(), StorageError> {
        let this_peer_id = self.this_peer_id();
        let leader_id = self.soft_state.read().as_ref().map(|state| state.leader_id);
        if leader_id != Some(this_peer_id) {
            return Err(StorageError::PreconditionFailed {
                description: "private ORAM mutation must be coordinated by the current leader"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub fn private_oram_activation_voter_ids(&self) -> Result<Vec<PeerId>, StorageError> {
        let stale = || StorageError::PreconditionFailed {
            description: "private ORAM activation requires a stable voter configuration"
                .to_string(),
        };
        let persistent = self.persistent.read();
        let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &persistent.state.conf_state.voters,
            &persistent.state.conf_state.voters_outgoing,
            &persistent.state.conf_state.learners,
            &persistent.state.conf_state.learners_next,
            persistent.state.conf_state.auto_leave,
        )
        .map_err(|_| stale())?;
        if !configuration.voters_outgoing().is_empty()
            || !configuration.learners().is_empty()
            || !configuration.learners_next().is_empty()
            || configuration.auto_leave()
        {
            return Err(stale());
        }
        private_oram_consensus_configuration_member_ids_v1(&configuration).map_err(|_| stale())
    }

    pub fn private_oram_activation_required_binary_capability_digest(
        &self,
    ) -> Result<String, StorageError> {
        self.persistent
            .read()
            .private_oram_activation_authority_at_configured_read()?
            .manifest()
            .map(|manifest| manifest.required_binary_capability_digest.clone())
            .ok_or_else(|| {
                StorageError::service_error("private ORAM activation authority is unavailable")
            })
    }

    pub fn private_oram_peer_activation_challenge_set(
        &self,
        activation_id: String,
        challenge_nonces: BTreeMap<u64, String>,
        runtime_capability_fingerprint: &str,
        binary_capability_digest: &str,
        activation_protocol_version: u16,
    ) -> Result<PrivateOramPeerActivationChallengeSetV1, StorageError> {
        let stale = || StorageError::PreconditionFailed {
            description: "private ORAM activation requires a stable local consensus state"
                .to_string(),
        };
        let activation_status = self.private_oram_mutation_v2_activation_status()?;
        let initial_activation =
            activation_status == PrivateOramMutationV2ActivationStatus::Unprepared;
        let reservation_v3_upgrade = activation_status
            == PrivateOramMutationV2ActivationStatus::Active
            && !self.private_oram_mutation_v3_write_floor_active()?
            && !self.private_oram_mutation_v3_floor_upgrade_pending()?;
        if !initial_activation && !reservation_v3_upgrade {
            return Err(stale());
        }

        let wal = self.wal.lock();
        let persistent = self.persistent.read();
        let hard_state = &persistent.state.hard_state;
        let applied_index = persistent
            .last_applied_entry()
            .unwrap_or(persistent.latest_snapshot_meta().index);
        let last_log_index = wal
            .last_entry()
            .map_err(|_| {
                StorageError::service_error(
                    "private ORAM activation local WAL state is unavailable",
                )
            })?
            .map(|entry| entry.index)
            .unwrap_or(persistent.latest_snapshot_meta().index);
        let commit_entry_term = if hard_state.commit == persistent.latest_snapshot_meta().index {
            persistent.latest_snapshot_meta().term
        } else {
            wal.entry(hard_state.commit)
                .map_err(|_| {
                    StorageError::service_error(
                        "private ORAM activation commit entry is unavailable",
                    )
                })?
                .term
        };
        if hard_state.term == 0
            || hard_state.commit == 0
            || commit_entry_term == 0
            || hard_state.commit != applied_index
            || hard_state.commit != last_log_index
            || persistent.current_unapplied_entry().is_some()
        {
            return Err(stale());
        }

        let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &persistent.state.conf_state.voters,
            &persistent.state.conf_state.voters_outgoing,
            &persistent.state.conf_state.learners,
            &persistent.state.conf_state.learners_next,
            persistent.state.conf_state.auto_leave,
        )
        .map_err(|_| stale())?;
        if !configuration.voters_outgoing().is_empty()
            || !configuration.learners().is_empty()
            || !configuration.learners_next().is_empty()
            || configuration.auto_leave()
        {
            return Err(stale());
        }
        let members = private_oram_consensus_configuration_member_ids_v1(&configuration)
            .map_err(|_| stale())?;
        if challenge_nonces.len() != members.len()
            || members
                .iter()
                .any(|peer_id| !challenge_nonces.contains_key(peer_id))
        {
            return Err(StorageError::bad_request(
                "private ORAM activation challenge nonce set is invalid",
            ));
        }
        let configuration_digest =
            try_private_oram_consensus_configuration_digest_v1(&configuration)
                .map_err(|_| stale())?;
        let peer_addresses = persistent.peer_address_by_id.read();
        let mut peer_uri_digests = BTreeMap::new();
        for peer_id in &members {
            let uri = peer_addresses.get(peer_id).ok_or_else(stale)?;
            peer_uri_digests.insert(
                *peer_id,
                private_oram_activation_uri_digest(uri).map_err(|_| stale())?,
            );
        }

        let authority = persistent.private_oram_activation_authority_at_configured_read()?;
        let manifest = authority.manifest().ok_or_else(stale)?;
        let locator = authority.locator().ok_or_else(stale)?;
        if manifest.required_binary_capability_digest != binary_capability_digest {
            return Err(stale());
        }
        if !matches!(
            activation_protocol_version,
            qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1
                | qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2
        ) {
            return Err(stale());
        }
        let legacy_protocol = activation_protocol_version
            == qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1;
        let mut challenges = Vec::with_capacity(members.len());
        for peer_id in members {
            let challenge = PrivateOramPeerActivationChallengeV1 {
                protocol_version: activation_protocol_version,
                activation_id: activation_id.clone(),
                activation_generation: locator.registry_generation(),
                challenge_nonce: challenge_nonces[&peer_id].clone(),
                cluster_identity_digest: manifest.cluster_identity_digest.clone(),
                cluster_first_voter_peer_id: manifest.cluster_first_voter_peer_id,
                coordinator_peer_id: persistent.this_peer_id,
                target_peer_id: peer_id,
                target_peer_uri_digest: peer_uri_digests[&peer_id].clone(),
                membership_generation: hard_state.commit,
                required_consensus_wire_protocol: if legacy_protocol {
                    0
                } else {
                    PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
                },
                expected_current_term: hard_state.term,
                expected_hard_commit: hard_state.commit,
                expected_last_applied: applied_index,
                expected_last_log_index: if legacy_protocol { 0 } else { last_log_index },
                expected_pending_conf_index: 0,
                expected_commit_entry_term: commit_entry_term,
                expected_configuration_digest: configuration_digest.clone(),
                expected_runtime_capability_fingerprint: runtime_capability_fingerprint.to_string(),
                pin_registry_generation: locator.registry_generation(),
                pin_registry_digest: locator.manifest_digest().to_string(),
                required_capability: manifest.required_capability.clone(),
                required_binary_capability_digest: binary_capability_digest.to_string(),
            };
            validate_private_oram_peer_activation_challenge_v1_shape(&challenge)
                .map_err(|_| stale())?;
            authority
                .signer_for_challenge_at_read(
                    &configuration,
                    &peer_uri_digests[&peer_id],
                    &challenge,
                )
                .map_err(|_| stale())?;
            challenges.push(challenge);
        }
        Ok(PrivateOramPeerActivationChallengeSetV1 {
            configuration,
            peer_uri_digests,
            challenges,
        })
    }

    /// Revalidates the exact challenge set against the current local Raft view and packages one
    /// signed acknowledgement per voter into a canonical aggregate proof.
    pub fn private_oram_package_peer_activation_proof(
        &self,
        challenge_set: PrivateOramPeerActivationChallengeSetV1,
        mut signed_acks: BTreeMap<u64, PrivateOramPeerActivationSignedAckV1>,
        runtime_capability_fingerprint: &str,
        binary_capability_digest: &str,
    ) -> Result<PrivateOramMixedVersionActivationProofV1, StorageError> {
        let stale = || StorageError::PreconditionFailed {
            description:
                "private ORAM activation evidence does not match stable local consensus state"
                    .to_string(),
        };
        let first = challenge_set.challenges.first().ok_or_else(stale)?;
        let activation_id = first.activation_id.clone();
        let challenge_nonces = challenge_set
            .challenges
            .iter()
            .map(|challenge| (challenge.target_peer_id, challenge.challenge_nonce.clone()))
            .collect::<BTreeMap<_, _>>();
        let fresh = self.private_oram_peer_activation_challenge_set(
            activation_id,
            challenge_nonces,
            runtime_capability_fingerprint,
            binary_capability_digest,
            first.protocol_version,
        )?;
        if fresh != challenge_set || signed_acks.len() != challenge_set.challenges.len() {
            return Err(stale());
        }

        let evidence = challenge_set
            .challenges
            .into_iter()
            .map(|challenge| {
                let signed_ack = signed_acks
                    .remove(&challenge.target_peer_id)
                    .ok_or_else(stale)?;
                Ok(PrivateOramPeerActivationEvidenceV1 {
                    challenge,
                    signed_ack,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        if !signed_acks.is_empty() {
            return Err(stale());
        }

        let persistent = self.persistent.read();
        let authority = persistent.private_oram_activation_authority_at_configured_read()?;
        package_private_oram_mixed_version_activation_proof_v1(
            authority.verified_manifest().ok_or_else(stale)?,
            challenge_set.configuration,
            &challenge_set.peer_uri_digests,
            evidence,
        )
        .map_err(|_| stale())
    }

    /// Captures one activation observation from a stable local Raft view.
    ///
    /// No challenge field is copied into the observation until it has been independently matched
    /// against the persisted authority, current peer URI, WAL tail, apply cursor, and local runtime
    /// capability values.
    pub fn private_oram_peer_activation_observation(
        &self,
        challenge: &PrivateOramPeerActivationChallengeV1,
        process_incarnation: &str,
        qdrant_version: &str,
        binary_capability_digest: &str,
        runtime_capability_fingerprint: &str,
    ) -> Result<
        (
            PrivateOramPeerActivationObservationV1,
            PrivateOramPeerRecoveryPublicKeyV1,
        ),
        StorageError,
    > {
        let stale = || StorageError::PreconditionFailed {
            description:
                "private ORAM activation challenge does not match stable local consensus state"
                    .to_string(),
        };

        // Match the snapshot lock order: WAL first, then persistent state.
        let wal = self.wal.lock();
        let persistent = self.persistent.read();
        let hard_state = &persistent.state.hard_state;
        let applied_index = persistent
            .last_applied_entry()
            .unwrap_or(persistent.latest_snapshot_meta().index);
        let last_log_index = wal
            .last_entry()
            .map_err(|_| {
                StorageError::service_error(
                    "private ORAM activation local WAL state is unavailable",
                )
            })?
            .map(|entry| entry.index)
            .unwrap_or(persistent.latest_snapshot_meta().index);
        let commit_entry_term = if hard_state.commit == persistent.latest_snapshot_meta().index {
            persistent.latest_snapshot_meta().term
        } else {
            wal.entry(hard_state.commit)
                .map_err(|_| {
                    StorageError::service_error(
                        "private ORAM activation commit entry is unavailable",
                    )
                })?
                .term
        };
        if hard_state.term == 0
            || hard_state.commit == 0
            || commit_entry_term == 0
            || hard_state.commit != applied_index
            || hard_state.commit != last_log_index
            || persistent.current_unapplied_entry().is_some()
        {
            return Err(stale());
        }

        let configuration = PrivateOramConsensusConfigurationV1::from_raft_peer_sets(
            &persistent.state.conf_state.voters,
            &persistent.state.conf_state.voters_outgoing,
            &persistent.state.conf_state.learners,
            &persistent.state.conf_state.learners_next,
            persistent.state.conf_state.auto_leave,
        )
        .map_err(|_| stale())?;
        if !configuration.voters_outgoing().is_empty()
            || !configuration.learners().is_empty()
            || !configuration.learners_next().is_empty()
            || configuration.auto_leave()
        {
            return Err(stale());
        }
        let configuration_digest =
            try_private_oram_consensus_configuration_digest_v1(&configuration)
                .map_err(|_| stale())?;
        let target_uri = persistent
            .peer_address_by_id
            .read()
            .get(&persistent.this_peer_id)
            .cloned()
            .ok_or_else(stale)?;
        let target_uri_digest =
            private_oram_activation_uri_digest(&target_uri).map_err(|_| stale())?;

        let authority = persistent.private_oram_activation_authority_at_configured_read()?;
        let manifest = authority.manifest().ok_or_else(stale)?;
        let locator = authority.locator().ok_or_else(stale)?;
        let expected_signer = authority
            .signer_for_challenge_at_read(&configuration, &target_uri_digest, challenge)
            .map_err(|_| stale())?
            .clone();

        let legacy_protocol = challenge.protocol_version
            == qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1;
        if challenge.target_peer_id != persistent.this_peer_id
            || challenge.target_peer_uri_digest != target_uri_digest
            || challenge.membership_generation != hard_state.commit
            || challenge.expected_current_term != hard_state.term
            || challenge.expected_hard_commit != hard_state.commit
            || challenge.expected_last_applied != applied_index
            || (!legacy_protocol && challenge.expected_last_log_index != last_log_index)
            || challenge.expected_pending_conf_index != 0
            || challenge.expected_commit_entry_term != commit_entry_term
            || challenge.expected_configuration_digest != configuration_digest
            || challenge.expected_runtime_capability_fingerprint != runtime_capability_fingerprint
            || (!legacy_protocol
                && challenge.required_consensus_wire_protocol
                    != PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION)
            || challenge.required_capability != PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY
            || challenge.required_binary_capability_digest != binary_capability_digest
            || manifest.required_binary_capability_digest != binary_capability_digest
        {
            return Err(stale());
        }

        let observation = PrivateOramPeerActivationObservationV1 {
            responder_peer_id: persistent.this_peer_id,
            process_incarnation: process_incarnation.to_string(),
            qdrant_version: qdrant_version.to_string(),
            capability: PRIVATE_ORAM_PEER_ACTIVATION_CAPABILITY.to_string(),
            binary_capability_digest: binary_capability_digest.to_string(),
            cluster_identity_digest: manifest.cluster_identity_digest.clone(),
            runtime_capability_fingerprint: runtime_capability_fingerprint.to_string(),
            membership_generation: hard_state.commit,
            supported_consensus_wire_protocol_min: if legacy_protocol {
                0
            } else {
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_MIN_VERSION
            },
            supported_consensus_wire_protocol_max: if legacy_protocol {
                0
            } else {
                PRIVATE_ORAM_CONSENSUS_WIRE_PROTOCOL_VERSION
            },
            observed_current_term: hard_state.term,
            observed_hard_commit: hard_state.commit,
            observed_last_applied: applied_index,
            observed_last_log_index: if legacy_protocol { 0 } else { last_log_index },
            observed_pending_conf_index: 0,
            observed_commit_entry_term: commit_entry_term,
            observed_configuration_digest: configuration_digest,
            pin_registry_generation: locator.registry_generation(),
            pin_registry_digest: locator.manifest_digest().to_string(),
        };
        validate_private_oram_peer_activation_observation_v1_shape(&observation)
            .map_err(|_| stale())?;
        Ok((observation, expected_signer))
    }

    /// Returns whether the Raft log is between the two irreversible private ORAM mutation
    /// activation barriers. This is reconstructed from durable state and the unapplied WAL so a
    /// leader change or process restart cannot reopen the ordinary proposal stream mid-transition.
    pub fn private_oram_mutation_activation_transition_pending(
        &self,
        last_applied_index: u64,
        last_log_index: u64,
    ) -> Result<bool, StorageError> {
        let snapshot_index = {
            let persistent = self.persistent.read();
            if persistent
                .private_oram_mutation_activation_pending
                .is_some()
                || persistent
                    .private_oram_mutation_format_floor
                    .as_ref()
                    .is_some_and(|floor| !floor.activation_enabled())
            {
                return Ok(true);
            }
            persistent.latest_snapshot_meta().index
        };

        if last_log_index <= last_applied_index {
            return Ok(false);
        }

        let first_index = last_applied_index
            .checked_add(1)
            .ok_or_else(|| StorageError::service_error("Raft apply index overflow"))?
            .max(snapshot_index.saturating_add(1));
        if first_index > last_log_index {
            return Ok(false);
        }

        // This scan only gates promotions and ordinary proposals, and it reads uncommitted
        // entries a peer may have forwarded: an unreadable or undecodable entry is treated as a
        // possible pending activation (fail closed) instead of an error, which would stop the
        // leader's consensus thread before Raft could even truncate the entry.
        let wal = self.wal.lock();
        for index in first_index..=last_log_index {
            let Ok(entry) = wal.entry(index) else {
                return Ok(true);
            };
            if entry.get_entry_type() != EntryType::EntryNormal || entry.get_data().is_empty() {
                continue;
            }
            let Ok(operation) = ConsensusOperations::try_from(&entry) else {
                return Ok(true);
            };
            if matches!(
                operation,
                ConsensusOperations::ActivatePrivateOramMutationV2(_)
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn apply_normal_entry_inner(
        &self,
        entry: &RaftEntry,
        context: NormalEntryApplyContext,
    ) -> Result<NormalEntryApplyOutcome, StorageError> {
        let operation: ConsensusOperations = entry.try_into()?;
        let on_apply = self.on_consensus_op_apply.lock().remove(&operation);
        let mut cursor_disposition = NormalEntryCursorDisposition::NeedsSeparateCommit;
        let result = match operation {
            ConsensusOperations::CollectionMeta(operation) => {
                // Capture the private ORAM keys of a collection about to be deleted so its
                // consensus records can be pruned once the deletion applied.
                let prune_keys = match operation.as_ref() {
                    crate::content_manager::collection_meta_ops::CollectionMetaOperations::DeleteCollection(delete) => self
                        .toc
                        .private_oram_index_keys_for_collection(&delete.0)
                        .unwrap_or_default(),
                    _ => Vec::new(),
                };
                let applied = self.toc.perform_collection_meta_op(*operation);
                if applied.is_ok() && !prune_keys.is_empty() {
                    self.persistent
                        .write()
                        .prune_private_oram_collection_state(&prune_keys)?;
                }
                applied
            }

            ConsensusOperations::AddPeer { .. } | ConsensusOperations::RemovePeer(_) => {
                // RemovePeer or AddPeer should be converted into native ConfChangeV2 message before sending to the Raft.
                // So we do not expect to receive these operations as a normal entry.
                // This is a debug assert so production migrations should be ok.
                // TODO: parse into CollectionMetaOperation as we will not handle other cases here, but this removes compatibility with previous entry storage
                debug_assert!(
                    false,
                    "Do not expect RemovePeer or AddPeer to be directly proposed"
                );
                Ok(false)
            }

            ConsensusOperations::UpdatePeerMetadata { peer_id, metadata } => self
                .persistent
                .write()
                .update_peer_metadata(peer_id, metadata)
                .map(|()| true),

            ConsensusOperations::UpdateClusterMetadata { key, value } => self
                .persistent
                .write()
                .update_cluster_metadata_key(key, value)
                .map(|()| true),

            ConsensusOperations::CompareAndSwapPrivateOramEpoch(operation) => self
                .persistent
                .write()
                .compare_and_swap_private_oram_epoch(&operation)
                .map(|()| true),
            ConsensusOperations::CompareAndSwapPrivateOramSessionLease(operation) => self
                .persistent
                .write()
                .compare_and_swap_private_oram_session_lease(&operation)
                .map(|()| true),
            ConsensusOperations::InitializePrivateOramMutationState(operation) => match context {
                NormalEntryApplyContext::CommittedAtCurrentCursor => match self
                    .persistent
                    .write()
                    .initialize_private_oram_mutation_state_at_applied_entry(
                        &operation,
                        entry.index,
                    ) {
                    Ok(PrivateOramMutationAtEntryOutcome::Applied) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Ok(true)
                    }
                    Ok(PrivateOramMutationAtEntryOutcome::Rejected(error)) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Err(error)
                    }
                    Err(error) => Err(error),
                },
                #[cfg(test)]
                NormalEntryApplyContext::DetachedForTest => self
                    .persistent
                    .write()
                    .initialize_private_oram_mutation_state(&operation)
                    .map(|()| true),
            },
            ConsensusOperations::CompareAndSwapPrivateOramMutationLease(operation) => match context
            {
                NormalEntryApplyContext::CommittedAtCurrentCursor => match self
                    .persistent
                    .write()
                    .compare_and_swap_private_oram_mutation_lease_at_applied_entry(
                        &operation,
                        entry.index,
                    ) {
                    Ok(PrivateOramMutationAtEntryOutcome::Applied) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Ok(true)
                    }
                    Ok(PrivateOramMutationAtEntryOutcome::Rejected(error)) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Err(error)
                    }
                    Err(error) => Err(error),
                },
                #[cfg(test)]
                NormalEntryApplyContext::DetachedForTest => self
                    .persistent
                    .write()
                    .compare_and_swap_private_oram_mutation_lease(&operation)
                    .map(|()| true),
            },
            ConsensusOperations::ConfirmPrivateOramMutationAuthorityV2(operation) => {
                match context {
                    NormalEntryApplyContext::CommittedAtCurrentCursor => match self
                        .persistent
                        .write()
                        .confirm_private_oram_mutation_authority_v2_at_applied_entry(
                            &operation,
                            entry.index,
                        ) {
                        Ok(PrivateOramMutationAtEntryOutcome::Applied) => {
                            cursor_disposition =
                                NormalEntryCursorDisposition::Committed(entry.index);
                            Ok(true)
                        }
                        Ok(PrivateOramMutationAtEntryOutcome::Rejected(error)) => {
                            cursor_disposition =
                                NormalEntryCursorDisposition::Committed(entry.index);
                            Err(error)
                        }
                        Err(error) => Err(error),
                    },
                    #[cfg(test)]
                    NormalEntryApplyContext::DetachedForTest => Err(StorageError::service_error(
                        "private ORAM mutation authority confirmation requires a committed Raft entry",
                    )),
                }
            }
            ConsensusOperations::ApplyPrivateOramMutation(operation) => match context {
                NormalEntryApplyContext::CommittedAtCurrentCursor => match self
                    .persistent
                    .write()
                    .apply_private_oram_mutation_at_applied_entry(&operation, entry.index)
                {
                    Ok(PrivateOramMutationAtEntryOutcome::Applied) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Ok(true)
                    }
                    Ok(PrivateOramMutationAtEntryOutcome::Rejected(error)) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Err(error)
                    }
                    Err(error) => Err(error),
                },
                #[cfg(test)]
                NormalEntryApplyContext::DetachedForTest => self
                    .persistent
                    .write()
                    .apply_private_oram_mutation(&operation)
                    .map(|()| true),
            },
            ConsensusOperations::ActivatePrivateOramMutationV2(operation) => match context {
                NormalEntryApplyContext::CommittedAtCurrentCursor => {
                    let base_term = self
                        .private_oram_activation_barrier_base_term(&operation, Some(entry.index))?;
                    match self
                        .persistent
                        .write()
                        .activate_private_oram_mutation_v2_at_applied_entry(
                            &operation,
                            entry.term,
                            entry.index,
                            base_term,
                        ) {
                        Ok(PrivateOramMutationAtEntryOutcome::Applied) => {
                            cursor_disposition =
                                NormalEntryCursorDisposition::Committed(entry.index);
                            Ok(true)
                        }
                        Ok(PrivateOramMutationAtEntryOutcome::Rejected(error)) => {
                            cursor_disposition =
                                NormalEntryCursorDisposition::Committed(entry.index);
                            Err(error)
                        }
                        Err(error) => Err(error),
                    }
                }
                #[cfg(test)]
                NormalEntryApplyContext::DetachedForTest => Err(StorageError::service_error(
                    "private ORAM mutation activation requires a committed Raft entry",
                )),
            },
            ConsensusOperations::ApplyPrivateOramMutationMaterialV2(operation) => match context {
                NormalEntryApplyContext::CommittedAtCurrentCursor => match self
                    .persistent
                    .write()
                    .apply_private_oram_mutation_material_v2_at_applied_entry(
                        &operation,
                        entry.term,
                        entry.index,
                    ) {
                    Ok(PrivateOramMutationAtEntryOutcome::Applied) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Ok(true)
                    }
                    Ok(PrivateOramMutationAtEntryOutcome::Rejected(error)) => {
                        cursor_disposition = NormalEntryCursorDisposition::Committed(entry.index);
                        Err(error)
                    }
                    Err(error) => Err(error),
                },
                #[cfg(test)]
                NormalEntryApplyContext::DetachedForTest => Err(StorageError::service_error(
                    "private ORAM V2 material operation requires a committed Raft entry",
                )),
            },
            ConsensusOperations::ApplyPrivateOramExternalRecovery(operation) => self
                .persistent
                .write()
                .apply_private_oram_external_recovery(&operation)
                .map(|()| true),
            ConsensusOperations::CompareAndSwapPrivateOramLayout(operation) => self
                .persistent
                .write()
                .compare_and_swap_private_oram_layout(&operation)
                .map(|()| true),
            ConsensusOperations::ApplyPrivateOramCollectionLayout(operation) => {
                self.apply_private_oram_collection_layout_transition(&operation)
            }
            ConsensusOperations::StartPrivateOramShardTransfer(operation) => {
                self.apply_private_oram_shard_transfer_start(&operation)
            }
            ConsensusOperations::FinishPrivateOramShardTransfer(operation) => {
                self.apply_private_oram_shard_transfer_finish(&operation)
            }
            ConsensusOperations::StartPrivateOramResharding(operation) => {
                self.apply_private_oram_resharding_start(&operation)
            }
            ConsensusOperations::FinishPrivateOramResharding(operation) => {
                self.apply_private_oram_resharding_finish(&operation)
            }

            ConsensusOperations::RequestSnapshot | ConsensusOperations::ReportSnapshot { .. } => {
                Err(StorageError::service_error(
                    "snapshot consensus operation cannot be applied as a normal Raft entry",
                ))
            }
        };

        if let Some(on_apply) = on_apply
            && on_apply
                .send(
                    result
                        .clone()
                        .map(|applied| ConsensusApplyReceipt::normal_entry(applied, entry.index)),
                )
                .is_err()
        {
            log::warn!(
                "Failed to notify on consensus operation completion: channel receiver is dropped",
            )
        }
        if let Err(error @ StorageError::ServiceError { .. }) = &result {
            return Err(error.clone());
        }
        Ok(NormalEntryApplyOutcome {
            operation_result: result,
            cursor_disposition,
        })
    }

    fn apply_private_oram_collection_layout_transition(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<bool, StorageError> {
        let topology_state = self.toc.private_oram_layout_transition_state(transition)?;
        self.persistent
            .read()
            .validate_private_oram_collection_layout_transition(transition)?;

        // Apply the collection meta-op before the layout CAS: a deterministic meta-op failure
        // then leaves the layout untouched instead of a layout that already names owners the
        // collection state never reached (which crash-looped the peer on every re-apply).
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self
                .toc
                .perform_private_oram_collection_layout_meta_op(transition);
            if !matches!(apply_result, Ok(true)) {
                let state = self.toc.private_oram_layout_transition_state(transition)?;
                if state != PrivateOramLayoutTransitionState::Applied {
                    return Err(private_oram_meta_op_not_applied(
                        apply_result,
                        state,
                        "private ORAM collection layout transition was not applied",
                    ));
                }
            }
        }
        self.persistent
            .write()
            .compare_and_swap_private_oram_layout(&transition.layout)?;
        if self.toc.private_oram_layout_transition_state(transition)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM collection layout transition did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_shard_transfer_start(
        &self,
        operation: &PrivateOramShardTransferStart,
    ) -> Result<bool, StorageError> {
        let topology_state = self
            .toc
            .private_oram_shard_transfer_start_state(operation)?;
        let precommitted_recovery = self
            .persistent
            .read()
            .validate_private_oram_shard_transfer_start(operation)?;
        if let Some(layout) = precommitted_recovery {
            self.persistent
                .write()
                .compare_and_swap_private_oram_layout(&layout)?;
        }
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self
                .toc
                .perform_collection_meta_op((*operation.collection_meta).clone());
            if !matches!(apply_result, Ok(true))
                && self
                    .toc
                    .private_oram_shard_transfer_start_state(operation)?
                    != PrivateOramLayoutTransitionState::Applied
            {
                return Err(StorageError::service_error(
                    "private ORAM shard transfer start was not applied",
                ));
            }
        }
        if self
            .toc
            .private_oram_shard_transfer_start_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM shard transfer start did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_shard_transfer_finish(
        &self,
        operation: &PrivateOramShardTransferFinish,
    ) -> Result<bool, StorageError> {
        let topology_state = self
            .toc
            .private_oram_shard_transfer_finish_state(operation)?;
        let layout = self
            .persistent
            .read()
            .validate_private_oram_shard_transfer_finish(operation)?;
        // Meta-op first, layout CAS second (see `apply_private_oram_collection_layout_transition`).
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self
                .toc
                .perform_collection_meta_op((*operation.collection_meta).clone());
            if !matches!(apply_result, Ok(true)) {
                let state = self
                    .toc
                    .private_oram_shard_transfer_finish_state(operation)?;
                if state != PrivateOramLayoutTransitionState::Applied {
                    return Err(private_oram_meta_op_not_applied(
                        apply_result,
                        state,
                        "private ORAM shard transfer finish was not applied",
                    ));
                }
            }
        }
        self.persistent
            .write()
            .compare_and_swap_private_oram_layout(&layout)?;
        if self
            .toc
            .private_oram_shard_transfer_finish_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM shard transfer finish did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_resharding_start(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        let topology_state = self.toc.private_oram_resharding_state(operation)?;
        self.persistent
            .read()
            .validate_private_oram_resharding_operation(operation)?;
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self.toc.perform_private_oram_resharding_meta_op(operation);
            if !matches!(apply_result, Ok(true)) {
                let state = self.toc.private_oram_resharding_state(operation)?;
                if state != PrivateOramLayoutTransitionState::Applied {
                    return Err(private_oram_meta_op_not_applied(
                        apply_result,
                        state,
                        "private ORAM resharding start was not applied",
                    ));
                }
            }
        }
        if self.toc.private_oram_resharding_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM resharding start did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_resharding_finish(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        let topology_state = self.toc.private_oram_resharding_state(operation)?;
        let layout = self
            .persistent
            .read()
            .validate_private_oram_resharding_operation(operation)?;
        // Meta-op first, layout CAS second (see `apply_private_oram_collection_layout_transition`).
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self.toc.perform_private_oram_resharding_meta_op(operation);
            if !matches!(apply_result, Ok(true)) {
                let state = self.toc.private_oram_resharding_state(operation)?;
                if state != PrivateOramLayoutTransitionState::Applied {
                    return Err(private_oram_meta_op_not_applied(
                        apply_result,
                        state,
                        "private ORAM resharding finish was not applied",
                    ));
                }
            }
        }
        self.persistent
            .write()
            .compare_and_swap_private_oram_layout(&layout)?;
        if self.toc.private_oram_resharding_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM resharding finish did not reach its committed state",
            ));
        }
        Ok(true)
    }

    // Outer `Result` is "fatal" error, inner `Result` is "transient"/"local" error.
    pub fn apply_snapshot(
        &self,
        snapshot: &raft::eraftpb::Snapshot,
    ) -> Result<Result<(), StorageError>, StorageError> {
        let meta = snapshot.get_metadata();

        let SnapshotData {
            collections_data,
            address_by_id,
            metadata_by_id,
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
        } = snapshot.get_data().try_into()?;

        Persistent::validate_private_oram_snapshot_state_at_index(
            &private_oram_epochs,
            &private_oram_session_leases,
            &private_oram_layouts,
            &private_oram_external_recoveries,
            &private_oram_mutation_states,
            &private_oram_mutation_lease_slots,
            private_oram_mutation_format_floor.as_ref(),
            private_oram_mutation_activation_pending.as_ref(),
            private_oram_activation_authority.as_ref(),
            meta.index,
        )?;
        let mut persistent = self.persistent.write();
        let current_private_oram_epochs = persistent.private_oram_epochs.clone();
        let current_private_oram_layouts = persistent.private_oram_layouts.clone();
        let current_private_oram_external_recoveries =
            persistent.private_oram_external_recoveries.clone();
        let this_peer_id = persistent.this_peer_id();
        crate::content_manager::consensus::persistent::validate_private_oram_external_recovery_snapshot_transition_for_peer(
            &current_private_oram_external_recoveries,
            &private_oram_external_recoveries,
            this_peer_id,
        )?;
        persistent.validate_private_oram_activation_authority_for_snapshot(
            private_oram_activation_authority.as_ref(),
        )?;
        persistent.validate_private_oram_mutation_floor_for_snapshot(
            private_oram_mutation_format_floor.as_ref(),
            &private_oram_mutation_lease_slots,
            meta.index,
        )?;
        match self.toc.apply_collections_snapshot_with_private_oram_state(
            collections_data,
            PrivateOramSnapshotState {
                incoming_epochs: &private_oram_epochs,
                current_epochs: &current_private_oram_epochs,
                incoming_layouts: &private_oram_layouts,
                current_layouts: &current_private_oram_layouts,
            },
        ) {
            Ok(()) => {}
            Err(CollectionsSnapshotApplyError::Rejected(error)) => {
                // Nothing local changed: report the rejection without arming the fence that
                // would otherwise demand a restart for a state that is still consistent.
                log::error!("Raft snapshot rejected before any local side effect: {error}");
                return Err(error);
            }
            Err(CollectionsSnapshotApplyError::Indeterminate(error)) => {
                persistent.fence_after_snapshot_side_effect_failure();
                return Err(error);
            }
        }
        if let Err(error) = persistent.update_from_snapshot(
            meta,
            address_by_id,
            metadata_by_id,
            cluster_metadata,
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_layouts,
            private_oram_external_recoveries,
            private_oram_mutation_states,
            private_oram_mutation_lease_slots,
            private_oram_mutation_format_floor,
            private_oram_mutation_activation_pending,
            private_oram_activation_authority,
        ) {
            persistent.fence_after_snapshot_side_effect_failure();
            return Err(error);
        }
        drop(persistent);

        // Clear now obsolete WAL entries after persisting new Raft state
        // This way we prevent a crash due to an empty WAL if we crash right after clearing it,
        // without bumping the Raft state. If we now crash after persisting the new state but
        // before clearing the WAL, we will clear the WAL on next startup by truncating all entries
        // above our commit.
        self.wal.lock().clear()?;

        Ok(Ok(()))
    }

    pub fn set_hard_state(&self, hard_state: raft::eraftpb::HardState) -> Result<(), StorageError> {
        self.persistent
            .write()
            .apply_state_update(move |state| state.hard_state = hard_state)
    }

    pub fn set_conf_state(&self, conf_state: raft::eraftpb::ConfState) -> Result<(), StorageError> {
        self.persistent
            .write()
            .apply_state_update(move |state| state.conf_state = conf_state)
    }

    /// Check if the consensus have empty operations log
    pub fn is_new_deployment(&self) -> bool {
        self.hard_state().term == 0
    }

    pub fn hard_state(&self) -> raft::eraftpb::HardState {
        self.persistent.read().state().hard_state.clone()
    }

    pub fn conf_state(&self) -> raft::eraftpb::ConfState {
        self.persistent.read().state().conf_state.clone()
    }

    pub fn set_commit_index(&self, index: u64) -> Result<(), StorageError> {
        self.persistent
            .write()
            .apply_state_update(|state| state.hard_state.commit = index)
    }

    pub fn peer_has_shards(&self, peer_id: PeerId) -> bool {
        self.toc
            .collections_snapshot()
            .collections
            .values()
            .flat_map(|state| state.shards.values())
            .flat_map(|shard_info| shard_info.replicas.keys())
            .any(|&id| id == peer_id)
    }

    pub fn add_peer(&self, peer_id: PeerId, uri: Uri) -> Result<(), StorageError> {
        self.persistent.write().insert_peer(peer_id, uri)
    }

    pub fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError> {
        // We sincerely apologize for this piece of code.
        // The `id_to_address` is shared between `channel_pool` and `persistent`,
        // plus we need to make additional removing in the `channel_pool`.
        // So we handle `remove_peer` inside the `toc` and persist changes in the `persistent` after that.
        self.persistent.read().ensure_persistence_writable()?;
        self.toc.remove_peer(peer_id)?;

        self.persistent
            .write()
            .remove_peer_metadata_and_save(peer_id)
    }

    async fn await_receiver(
        &self,
        receiver: Receiver<Result<ConsensusApplyReceipt, StorageError>>,
        wait_timeout: Duration,
        operation: &ConsensusOperations,
    ) -> Result<ConsensusApplyReceipt, StorageError> {
        match self
            .await_receiver_outcome(receiver, wait_timeout, operation)
            .await
        {
            ConsensusProposalOutcome::Applied(receipt) => Ok(receipt),
            ConsensusProposalOutcome::NotSubmitted(error)
            | ConsensusProposalOutcome::Indeterminate(error)
            | ConsensusProposalOutcome::Failed(error) => Err(error),
        }
    }

    async fn await_receiver_outcome(
        &self,
        mut receiver: Receiver<Result<ConsensusApplyReceipt, StorageError>>,
        wait_timeout: Duration,
        operation: &ConsensusOperations,
    ) -> ConsensusProposalOutcome {
        match tokio::time::timeout(wait_timeout, receiver.recv()).await {
            Err(_elapsed) => {
                self.on_consensus_op_apply.lock().remove(operation);
                ConsensusProposalOutcome::Indeterminate(StorageError::service_error(format!(
                    "Waiting for consensus operation commit failed. Timeout set at: {} seconds",
                    wait_timeout.as_secs_f64(),
                )))
            }
            // The sender was dropped before an apply receipt was delivered: the entry may or
            // may not have committed.
            Ok(Err(err)) => {
                ConsensusProposalOutcome::Indeterminate(StorageError::service_error(format!(
                    "Error occurred while waiting for consensus operation. Channel sender dropped ({err})"
                )))
            }
            Ok(Ok(Err(apply_error))) => ConsensusProposalOutcome::Failed(apply_error),
            Ok(Ok(Ok(receipt))) => ConsensusProposalOutcome::Applied(receipt),
        }
    }

    pub fn await_for_multiple_operations(
        &self,
        operations: Vec<ConsensusOperations>,
        wait_timeout: Option<Duration>,
    ) -> impl Future<Output = Result<Result<(), StorageError>, Elapsed>> {
        let mut receivers = vec![];
        for operation in operations {
            // one-shot broadcast channel
            let (sender, mut receiver) = broadcast::channel(1);
            let mut on_apply_lock = self.on_consensus_op_apply.lock();
            // check that the exact same operation is not already in-flight
            match on_apply_lock.get(&operation) {
                Some(existing_sender) => {
                    // subscribe to existing sender for faster feedback
                    receiver = existing_sender.subscribe()
                }
                None => {
                    // insert new sender
                    on_apply_lock.insert(operation, sender);
                }
            };
            receivers.push(receiver);
        }

        async move {
            let await_for_all = join_all(receivers.iter_mut().map(|receiver| receiver.recv()));
            let results = tokio::time::timeout(
                wait_timeout.unwrap_or(defaults::CONSENSUS_META_OP_WAIT),
                await_for_all,
            )
            .await?;
            for result in results {
                match result {
                    Ok(response_res) => match response_res {
                        Ok(_) => {}
                        Err(err) => return Ok(Err(err)),
                    },
                    Err(recv_error) => return Ok(Err(recv_error.into())),
                }
            }
            Ok(Ok(()))
        }
    }

    /// Wait and block until consensus reaches a `term` and actually applies the `commit`.
    ///
    /// # Errors
    ///
    /// Returns an error if we have diverged commit/term for example.
    pub async fn wait_for_consensus_commit(
        &self,
        commit: u64,
        term: u64,
        consensus_tick: Duration,
        timeout: Duration,
    ) -> Result<(), ()> {
        let start = Instant::now();

        // TODO: naive approach with spinlock for waiting on commit/term, find better way
        while start.elapsed() < timeout {
            let (current_commit, current_term) = self.persistent.read().applied_commit_term();

            // Okay if on the same term and have at least the specified commit
            let is_ok = current_term == term && current_commit >= commit;
            if is_ok {
                return Ok(());
            }

            // Fail if on a newer term
            let is_fail = current_term > term;
            if is_fail {
                return Err(());
            }

            tokio::time::sleep(consensus_tick).await
        }

        // Fail on timeout
        Err(())
    }

    /// Send operation to the consensus thread and listen for the result.
    ///
    /// # Arguments
    ///
    /// * `operation` - operation to propose
    /// * `wait_timeout` - How long do we need to wait for the confirmation
    pub async fn propose_consensus_op_with_await(
        &self,
        operation: ConsensusOperations,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        self.propose_consensus_op_with_local_apply_receipt(operation, wait_timeout)
            .await
            .map(|receipt| receipt.applied)
    }

    async fn propose_consensus_op_with_local_apply_receipt(
        &self,
        operation: ConsensusOperations,
        wait_timeout: Option<Duration>,
    ) -> Result<ConsensusApplyReceipt, StorageError> {
        match self
            .propose_consensus_op_with_outcome(operation, wait_timeout)
            .await
        {
            ConsensusProposalOutcome::Applied(receipt) => Ok(receipt),
            ConsensusProposalOutcome::NotSubmitted(error)
            | ConsensusProposalOutcome::Indeterminate(error)
            | ConsensusProposalOutcome::Failed(error) => Err(error),
        }
    }

    /// Proposes `operation` and reports whether it was applied, failed definitively, was never
    /// submitted, or is still unresolved after `wait_timeout`.
    pub async fn propose_consensus_op_with_outcome(
        &self,
        operation: ConsensusOperations,
        wait_timeout: Option<Duration>,
    ) -> ConsensusProposalOutcome {
        let wait_timeout = wait_timeout.unwrap_or(defaults::CONSENSUS_META_OP_WAIT);

        let is_leader_established = self.is_leader_established.clone();

        let await_ready_for_timeout_future =
            AbortOnDropHandle::new(tokio::task::spawn_blocking(move || {
                is_leader_established.await_ready_for_timeout(wait_timeout)
            }));

        let is_leader_established = match await_ready_for_timeout_future.await {
            Ok(is_leader_established) => is_leader_established,
            Err(err) => {
                return ConsensusProposalOutcome::NotSubmitted(StorageError::service_error(
                    err.to_string(),
                ));
            }
        };

        if !is_leader_established {
            return ConsensusProposalOutcome::NotSubmitted(StorageError::service_error(format!(
                "Failed to propose operation: leader is not established within {wait_timeout:?}"
            )));
        }

        // one-shot broadcast channel
        let (sender, mut receiver) = broadcast::channel(1);
        {
            // acquire lock to insert new operation to apply
            let mut on_apply_lock = self.on_consensus_op_apply.lock();
            // check that the exact same operation is not already in-flight
            match on_apply_lock.get(&operation) {
                Some(existing_sender) => {
                    // subscribe to existing sender for faster feedback
                    receiver = existing_sender.subscribe()
                }
                None => {
                    // propose operation to consensus thread
                    if let Err(err) = self.propose_sender.send(operation.clone()) {
                        return ConsensusProposalOutcome::NotSubmitted(err.into());
                    }
                    // insert new sender
                    on_apply_lock.insert(operation.clone(), sender);
                }
            };
        }

        self.await_receiver_outcome(receiver, wait_timeout, &operation)
            .await
    }

    pub fn peer_address_by_id(&self) -> PeerAddressById {
        self.persistent.read().peer_address_by_id()
    }

    pub fn private_oram_epoch(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramConsensusEpoch> {
        self.persistent.read().private_oram_epoch(key)
    }

    pub fn private_oram_session_lease(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramSessionLease> {
        self.persistent.read().private_oram_session_lease(key)
    }

    pub fn private_oram_mutation_state(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramConsensusCollectionStateV2> {
        self.persistent.read().private_oram_mutation_state(key)
    }

    pub fn private_oram_mutation_lease(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationLease> {
        self.persistent.read().private_oram_mutation_lease(key)
    }

    pub fn private_oram_mutation_lease_slot(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationLeaseSlotV2> {
        self.persistent.read().private_oram_mutation_lease_slot(key)
    }

    pub(crate) fn private_oram_mutation_v2_active_recovery_manifest(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<Option<PrivateOramMutationAllOwnersPrestagedV2>, StorageError> {
        self.persistent
            .read()
            .private_oram_mutation_v2_active_recovery_manifest(key)
    }

    pub fn private_oram_mutation_v2_exact_admitted_recovery_manifest(
        &self,
        key: &PrivateOramMutationKey,
        lease: &PrivateOramMutationLease,
    ) -> Result<Option<PrivateOramMutationAllOwnersPrestagedV2>, StorageError> {
        self.persistent
            .read()
            .private_oram_mutation_v2_exact_admitted_recovery_manifest(key, lease)
    }

    pub fn private_oram_mutation_v2_active_append_attempt(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Result<
        Option<(
            PrivateOramMutationAppendReservationV2,
            Option<PrivateOramMutationAllOwnersPrestagedV2>,
        )>,
        StorageError,
    > {
        self.persistent
            .read()
            .private_oram_mutation_v2_active_append_attempt(key)
    }

    pub(crate) fn private_oram_mutation_v2_retains_rejected_admission(
        &self,
        key: &PrivateOramMutationKey,
        lease: &PrivateOramMutationLease,
        recovery_manifest_digest: &str,
    ) -> Result<bool, StorageError> {
        self.persistent
            .read()
            .private_oram_mutation_v2_retains_rejected_admission(
                key,
                lease,
                recovery_manifest_digest,
            )
    }

    #[allow(
        dead_code,
        reason = "D3-B3 restart recovery consumes the paired state under one persistent read guard"
    )]
    /// Captures the collection state and mutation lease slot under one persistent read guard.
    pub fn private_oram_mutation_reconcile_snapshot(
        &self,
        key: &PrivateOramMutationKey,
    ) -> Option<PrivateOramMutationReconcileSnapshotV1> {
        let persistent = self.persistent.read();
        Some(PrivateOramMutationReconcileSnapshotV1 {
            consensus_state: persistent.private_oram_mutation_state(key)?,
            lease_slot: persistent.private_oram_mutation_lease_slot(key)?,
            parent_watermark: persistent.private_oram_mutation_parent_watermark(key),
            recovery_capsules_certificate: persistent
                .private_oram_mutation_recovery_capsules_certificate(key),
            activation_authority: persistent.private_oram_activation_authority_locator(),
            cleanup_lifecycle: persistent.private_oram_mutation_cleanup_lifecycle(key),
        })
    }

    /// Confirms one exact active mutation generation through Raft and captures its paired state.
    ///
    /// This method is intentionally available on followers: Raft forwards the proposal to the
    /// current leader, while the original lease owner remains the recovery coordinator.
    pub async fn linearizable_private_oram_mutation_reconcile_snapshot_v2(
        &self,
        key: &PrivateOramMutationKey,
        expected_owner_peer_id: PeerId,
        wait_timeout: Option<Duration>,
    ) -> Result<LinearizablePrivateOramMutationReconcileSnapshotV2, StorageError> {
        let expected = self
            .persistent
            .read()
            .private_oram_mutation_lease_slot(key)
            .ok_or_else(|| {
                StorageError::bad_request(
                    "private ORAM mutation authority confirmation has no enrolled state",
                )
            })?;
        let expected_lease = expected.active.as_ref().ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM mutation authority confirmation requires an active lease",
            )
        })?;
        if expected_lease.owner_peer_id != expected_owner_peer_id {
            return Err(StorageError::bad_request(
                "private ORAM mutation authority confirmation owner does not match",
            ));
        }
        let operation = ConfirmPrivateOramMutationAuthorityV2 {
            key: key.clone(),
            expected: expected.clone(),
        };
        let confirmation_receipt = self
            .propose_consensus_op_with_local_apply_receipt(
                ConsensusOperations::ConfirmPrivateOramMutationAuthorityV2(operation),
                wait_timeout,
            )
            .await?;
        if !confirmation_receipt.applied {
            return Err(StorageError::service_error(
                "private ORAM mutation authority confirmation was not applied",
            ));
        }
        let confirmation_applied_index =
            confirmation_receipt.local_applied_index.ok_or_else(|| {
                StorageError::service_error(
                    "private ORAM mutation authority confirmation has no local apply receipt",
                )
            })?;

        let persistent = self.persistent.read();
        let lease_slot = persistent
            .private_oram_mutation_lease_slot(key)
            .ok_or_else(|| {
                StorageError::service_error(
                    "private ORAM mutation authority disappeared after confirmation",
                )
            })?;
        if lease_slot != expected
            || lease_slot
                .active
                .as_ref()
                .is_none_or(|lease| lease.owner_peer_id != expected_owner_peer_id)
        {
            return Err(StorageError::bad_request(
                "private ORAM mutation authority changed after confirmation",
            ));
        }
        let applied_index = persistent.last_applied_entry().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM mutation authority confirmation has no applied index",
            )
        })?;
        if applied_index < confirmation_applied_index {
            return Err(StorageError::service_error(
                "private ORAM mutation authority snapshot precedes its local confirmation apply",
            ));
        }
        let snapshot = PrivateOramMutationReconcileSnapshotV1 {
            consensus_state: persistent.private_oram_mutation_state(key).ok_or_else(|| {
                StorageError::service_error(
                    "private ORAM mutation consensus state disappeared after confirmation",
                )
            })?,
            lease_slot,
            parent_watermark: persistent.private_oram_mutation_parent_watermark(key),
            recovery_capsules_certificate: persistent
                .private_oram_mutation_recovery_capsules_certificate(key),
            activation_authority: persistent.private_oram_activation_authority_locator(),
            cleanup_lifecycle: persistent.private_oram_mutation_cleanup_lifecycle(key),
        };
        Ok(LinearizablePrivateOramMutationReconcileSnapshotV2 {
            snapshot,
            applied_index,
        })
    }

    pub fn active_private_oram_mutation_keys(
        &self,
    ) -> Result<Vec<PrivateOramMutationKey>, StorageError> {
        self.persistent.read().active_private_oram_mutation_keys()
    }

    pub fn private_oram_mutation_pending_acknowledgement_keys(
        &self,
    ) -> Result<Vec<(PrivateOramMutationKey, PeerId, u64)>, StorageError> {
        self.persistent
            .read()
            .private_oram_mutation_pending_acknowledgement_keys()
    }

    pub fn private_oram_mutation_cleared_pending_archive_permit(
        &self,
        key: &PrivateOramMutationKey,
        expected_owner_peer_id: PeerId,
        expected_generation: u64,
    ) -> Result<PrivateOramMutationClearedPendingArchivePermitV2, StorageError> {
        self.persistent
            .read()
            .private_oram_mutation_cleared_pending_archive_permit(
                key,
                expected_owner_peer_id,
                expected_generation,
            )
    }

    pub fn private_oram_external_recovery(
        &self,
        key: &PrivateOramExternalRecoveryKey,
    ) -> Option<PrivateOramExternalRecoveryState> {
        self.persistent.read().private_oram_external_recovery(key)
    }

    pub fn private_oram_layout(
        &self,
        key: &PrivateOramLayoutKey,
    ) -> Option<PrivateOramConsensusLayout> {
        self.persistent.read().private_oram_layout(key)
    }

    pub fn peer_count(&self) -> usize {
        self.persistent.read().peer_address_by_id.read().len()
    }

    pub fn append_entries(&self, entries: Vec<RaftEntry>) -> Result<(), StorageError> {
        self.wal.lock().append_entries(entries)
    }

    pub fn last_applied_entry(&self) -> Option<u64> {
        self.persistent.read().last_applied_entry()
    }

    pub fn sync_local_state(&self) -> Result<(), StorageError> {
        self.try_update_peer_metadata();
        self.toc.sync_local_state()
    }

    pub fn clear_wal(&self) -> Result<(), StorageError> {
        self.wal.lock().clear()
    }

    pub fn compact_wal(&self, min_entries_to_compact: u64) -> Result<bool, StorageError> {
        if min_entries_to_compact == 0 {
            return Ok(false);
        }

        let Some(first_entry) = self.wal.lock().first_entry()? else {
            return Ok(false);
        };

        let Some(last_applied_index) = self.persistent.read().last_applied_entry() else {
            return Ok(false);
        };

        debug_assert!(
            first_entry.index <= last_applied_index + 1,
            "Raft WAL is missing {} unapplied entries (last applied index: {}, first WAL entry index: {})",
            first_entry.index - last_applied_index - 1,
            last_applied_index,
            first_entry.index,
        );

        if last_applied_index.saturating_sub(first_entry.index) < min_entries_to_compact {
            return Ok(false);
        }

        self.wal.lock().compact(last_applied_index)?;
        Ok(true)
    }

    /// Try to update our peer metadata if it's outdated
    ///
    /// It rate limits updating to `CONSENSUS_PEER_METADATA_UPDATE_INTERVAL`.
    fn try_update_peer_metadata(&self) {
        // Throttle updates to prevent spamming consensus
        if Instant::now() < *self.next_peer_metadata_update_attempt.lock() {
            return;
        }

        if !self
            .persistent
            .read()
            .is_our_metadata_outdated(&self.current_peer_metadata)
        {
            return;
        }

        log::debug!("Proposing consensus peer metadata update for this peer");
        let result = self
            .propose_sender
            .send(ConsensusOperations::UpdatePeerMetadata {
                peer_id: self.this_peer_id(),
                metadata: self.current_peer_metadata.clone(),
            });
        if let Err(err) = result {
            log::error!("Failed to propose consensus peer metadata update for this peer: {err}");
        }
        *self.next_peer_metadata_update_attempt.lock() =
            Instant::now() + CONSENSUS_PEER_METADATA_UPDATE_INTERVAL;
    }
}

fn recover_first_voter(
    wal: &ConsensusOpWal,
    peers: &[PeerId],
) -> Result<Option<PeerId>, StorageError> {
    let Some(first_entry) = wal.first_entry()? else {
        log::debug!("Skipped recovering first voter peer: WAL is empty");
        return Ok(None);
    };

    let Some(last_entry) = wal.last_entry()? else {
        log::error!(
            "Failed to recover first voter peer: \
             WAL contains first entry, but no last entry"
        );

        return Ok(None);
    };

    if first_entry.index != 1 {
        log::warn!("Failed to recover first voter peer: WAL is truncated");
        return Ok(Some(PeerId::MAX));
    }

    // Try to recover first voter peer from WAL (if it was not removed from cluster yet!):
    // - collect a list of current peers
    // - scroll WAL and *remove* a peer from the list when `AddPeer`/`AddLearnerPeer` operation encountered
    // - if there's exactly one peer left in the list at the end, this peer should be the first voter

    let mut peers: HashSet<_> = peers.iter().copied().collect();

    for index in first_entry.index..last_entry.index + 1 {
        let entry = wal.entry(index)?;

        match entry.get_entry_type() {
            EntryType::EntryConfChangeV2 => {
                let change: ConfChangeV2 = prost_for_raft::Message::decode(entry.get_data())?;

                for change in change.changes {
                    match change.get_change_type() {
                        ConfChangeType::AddNode | ConfChangeType::AddLearnerNode => {
                            peers.remove(&change.get_node_id());
                        }

                        ConfChangeType::RemoveNode => (),
                    }
                }
            }

            EntryType::EntryConfChange => {
                log::warn!(
                    "Encountered deprecated ConfChange message while recovering first voter peer"
                );

                let change: ConfChange = prost_for_raft::Message::decode(entry.get_data())?;

                match change.get_change_type() {
                    ConfChangeType::AddNode | ConfChangeType::AddLearnerNode => {
                        peers.remove(&change.get_node_id());
                    }

                    ConfChangeType::RemoveNode => (),
                }
            }

            EntryType::EntryNormal => (),
        }
    }

    if peers.len() > 1 {
        log::warn!(
            "Failed to recover first voter peer: \
             found multiple peers without ConfChange entry in WAL: \
             {peers:?}"
        );

        return Ok(Some(PeerId::MAX));
    }

    Ok(peers.into_iter().next())
}

/// Implementation of the methods for Raft library to get information from
/// our implementation of the storage.
/// Well tested magic
impl<C: CollectionContainer> Storage for ConsensusManager<C> {
    fn initial_state(&self) -> raft::Result<RaftState> {
        Ok(self.persistent.read().state.clone())
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        _context: GetEntriesContext,
    ) -> raft::Result<Vec<RaftEntry>> {
        let max_size: Option<_> = max_size.into();
        let first_index = self.first_index()?;
        if low < first_index {
            log::debug!(
                "Requested entries from {low} to {high} are already compacted (first index: {first_index})"
            );
            return Err(raft::Error::Store(raft::StorageError::Compacted));
        }

        log::debug!("Requesting entries from {low} to {high}");

        if high > self.last_index()? + 1 {
            return Err(raft_error_other(std::io::Error::other(format!(
                "index out of bound (last: {}, high: {})",
                self.last_index()? + 1,
                high
            ))));
        }
        self.wal.lock().entries(low, high, max_size)
    }

    fn term(&self, idx: u64) -> raft::Result<u64> {
        let wal_guard = self.wal.lock();
        let persistent = self.persistent.read();
        let snapshot_meta = persistent.latest_snapshot_meta();
        if idx == snapshot_meta.index {
            return Ok(snapshot_meta.term);
        }
        Ok(wal_guard.entry(idx)?.term)
    }

    fn first_index(&self) -> raft::Result<u64> {
        let index = match self.wal.lock().first_entry().map_err(raft_error_other)? {
            Some(entry) => entry.index,
            None => self.persistent.read().latest_snapshot_meta().index + 1,
        };
        Ok(index)
    }

    fn last_index(&self) -> raft::Result<u64> {
        let index = match self.wal.lock().last_entry().map_err(raft_error_other)? {
            Some(entry) => entry.index,
            None => self.persistent.read().latest_snapshot_meta().index,
        };
        Ok(index)
    }

    fn snapshot(&self, request_index: u64, _to: u64) -> raft::Result<raft::eraftpb::Snapshot> {
        let collections_data = self.toc.collections_snapshot();

        // Lock first WAL and then persistent to avoid deadlock
        let wal_guard = self.wal.lock();
        // TODO: Should we lock `persistent` *before* calling `TableOfContent::collections_snapshot`!?
        let persistent = self.persistent.read();

        if persistent.state.hard_state.commit < request_index {
            // TODO: `raft::storage::MemStorage::snapshot` does `snapshot.mut_metadata().index = request_index` in this case... 🤔
            return Err(raft::Error::Store(
                raft::StorageError::SnapshotTemporarilyUnavailable,
            ));
        }
        persistent
            .validate_private_oram_activation_authority_snapshot_source()
            .map_err(raft_error_other)?;
        persistent
            .validate_private_oram_mutation_floor_snapshot_source()
            .map_err(raft_error_other)?;
        let data = SnapshotData {
            collections_data,
            address_by_id: persistent.peer_address_by_id(),
            metadata_by_id: persistent.peer_metadata_by_id(),
            cluster_metadata: persistent.cluster_metadata.clone(),
            private_oram_activation_authority: persistent.private_oram_activation_authority.clone(),
            private_oram_epochs: persistent.private_oram_epochs.clone(),
            private_oram_session_leases: persistent.private_oram_session_leases.clone(),
            private_oram_layouts: persistent.private_oram_layouts.clone(),
            private_oram_external_recoveries: persistent.private_oram_external_recoveries.clone(),
            private_oram_mutation_states: persistent.private_oram_mutation_states.clone(),
            private_oram_mutation_lease_slots: persistent.private_oram_mutation_lease_slots.clone(),
            private_oram_mutation_format_floor: persistent
                .private_oram_mutation_format_floor
                .clone(),
            private_oram_mutation_activation_pending: persistent
                .private_oram_mutation_activation_pending
                .clone(),
        };
        Persistent::validate_private_oram_snapshot_state_at_index(
            &data.private_oram_epochs,
            &data.private_oram_session_leases,
            &data.private_oram_layouts,
            &data.private_oram_external_recoveries,
            &data.private_oram_mutation_states,
            &data.private_oram_mutation_lease_slots,
            data.private_oram_mutation_format_floor.as_ref(),
            data.private_oram_mutation_activation_pending.as_ref(),
            data.private_oram_activation_authority.as_ref(),
            persistent.state.hard_state.commit,
        )
        .map_err(raft_error_other)?;

        let raft_state = persistent.state();

        // Index of snapshot is the current *commit* index.
        let index = raft_state.hard_state.commit;

        // Term of snapshot is the term of the entry at current commit index. Not the current term!
        //
        // Last committed entry should either be available in the WAL, or, if current node applied
        // Raft snapshot (and so completely compacted the WAL) and no new entries were committed yet,
        // it should be the term of `latest_snapshot_meta`.
        let term = if index == persistent.latest_snapshot_meta.index {
            persistent.latest_snapshot_meta.term
        } else {
            wal_guard.entry(index)?.term
        };

        let meta = raft::eraftpb::SnapshotMetadata {
            conf_state: Some(raft_state.conf_state.clone()),
            index,
            term,
        };

        let snapshot = raft::eraftpb::Snapshot {
            data: serde_cbor::to_vec(&data).map_err(raft_error_other)?,
            metadata: Some(meta),
        };

        Ok(snapshot)
    }
}

#[derive(Clone)]
pub struct ConsensusStateRef(pub Arc<prelude::ConsensusState>);

impl Deref for ConsensusStateRef {
    type Target = prelude::ConsensusState;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl From<prelude::ConsensusState> for ConsensusStateRef {
    fn from(state: prelude::ConsensusState) -> Self {
        Self(Arc::new(state))
    }
}

impl Storage for ConsensusStateRef {
    fn initial_state(&self) -> raft::Result<RaftState> {
        self.0.initial_state()
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        context: GetEntriesContext,
    ) -> raft::Result<Vec<RaftEntry>> {
        self.0.entries(low, high, max_size, context)
    }

    fn term(&self, idx: u64) -> raft::Result<u64> {
        self.0.term(idx)
    }

    fn first_index(&self) -> raft::Result<EntryId> {
        self.0.first_index()
    }

    fn last_index(&self) -> raft::Result<EntryId> {
        self.0.last_index()
    }

    fn snapshot(&self, request_index: u64, to: u64) -> raft::Result<raft::eraftpb::Snapshot> {
        self.0.snapshot(request_index, to)
    }
}

pub fn raft_error_other(e: impl std::error::Error) -> raft::Error {
    #[derive(thiserror::Error, Debug)]
    #[error("{0}")]
    struct StrError(String);

    raft::Error::Store(raft::StorageError::Other(Box::new(StrError(e.to_string()))))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};

    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::operations::types::PeerMetadata;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::shard::PeerId;
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferIndexState,
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition, ShardTransfer,
        ShardTransferMethod,
    };
    use data_encoding::BASE64URL_NOPAD;
    use proptest::prelude::*;
    use raft::eraftpb::{
        ConfChange, ConfChangeSingle, ConfChangeType, ConfChangeV2, ConfState, Entry, EntryType,
        HardState,
    };
    use raft::storage::{MemStorage, Storage};
    use raft::{SoftState, StateRole};
    use tempfile::Builder;
    use uuid::Uuid;

    use super::{ConsensusManager, SnapshotData};
    use crate::content_manager::CollectionContainer;
    use crate::content_manager::consensus::consensus_wal::ConsensusOpWal;
    use crate::content_manager::consensus::entry_queue::EntryApplyProgressQueue;
    use crate::content_manager::consensus::operation_sender::OperationSender;
    use crate::content_manager::consensus::persistent::Persistent;
    use crate::content_manager::consensus::private_oram_activation_authority::private_oram_activation_authority_fixture_v1_for_test;
    use crate::content_manager::consensus::private_oram_mutation_activation_barrier::{
        PrivateOramMutationActivationApplyFactsV2,
        private_oram_mutation_activation_barrier_fixture_v2_for_test,
        validate_private_oram_mutation_activation_barrier_v2,
    };
    use crate::content_manager::consensus_ops::{
        CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramExternalRecovery,
        CompareAndSwapPrivateOramLayout, CompareAndSwapPrivateOramMutationLease,
        CompareAndSwapPrivateOramSessionLease, ConsensusOperations,
        InitializePrivateOramMutationState, PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
        PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION, PrivateOramCollectionLayoutTransition,
        PrivateOramConsensusCollectionIndexStateV2, PrivateOramConsensusCollectionStateV2,
        PrivateOramConsensusEpoch, PrivateOramConsensusLayout, PrivateOramConsensusTransitionV2,
        PrivateOramEpochKey, PrivateOramExternalRecoveryKey, PrivateOramExternalRecoveryLease,
        PrivateOramExternalRecoveryLeasePhase, PrivateOramExternalRecoveryOperation,
        PrivateOramExternalRecoveryPhase, PrivateOramExternalRecoveryState, PrivateOramIndexKind,
        PrivateOramLayoutIndexStateBinding, PrivateOramLayoutKey, PrivateOramLayoutLeaseBinding,
        PrivateOramLayoutTransitionState, PrivateOramMutationKey, PrivateOramMutationLease,
        PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
        PrivateOramReshardingLayoutTransition, PrivateOramReshardingOperation,
        PrivateOramSessionLease, PrivateOramShardTransferFinish, PrivateOramShardTransferStart,
        canonical_private_oram_consensus_state_record_digest,
        canonical_private_oram_index_state_digest,
    };

    fn setup_private_oram_activation_probe_manager(
        path: &std::path::Path,
    ) -> ConsensusManager<NoCollections> {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let persistent = Persistent::load_or_init_with_private_oram_mutation_v2_activation(
            path,
            true,
            false,
            Some(11),
            &trust_anchor,
            &bundle,
        )
        .unwrap();
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            Arc::new(NoCollections::default()),
            OperationSender::new(sender),
            path,
            PeerMetadata::current(),
        )
        .unwrap();
        manager
            .add_peer(11, "https://node-11.internal:6335".parse().unwrap())
            .unwrap();
        manager
            .add_peer(13, "https://node-13.internal:6335".parse().unwrap())
            .unwrap();
        manager
            .set_conf_state(ConfState {
                voters: vec![11, 13],
                ..Default::default()
            })
            .unwrap();
        manager
            .append_entries(vec![Entry {
                index: 1,
                term: 3,
                ..Default::default()
            }])
            .unwrap();
        manager
            .set_hard_state(HardState {
                term: 4,
                commit: 1,
                ..Default::default()
            })
            .unwrap();
        manager.set_unapplied_entries(1, 1).unwrap();
        manager.persistent.write().entry_applied().unwrap();
        manager.set_raft_soft_state(&SoftState {
            leader_id: 11,
            raft_state: StateRole::Leader,
        });
        manager
    }

    #[test]
    fn private_oram_activation_probe_is_live_state_bound_and_redacted() {
        let dir = Builder::new()
            .prefix("private_oram_activation_probe")
            .tempdir()
            .unwrap();
        let manager = setup_private_oram_activation_probe_manager(dir.path());
        let digest = |value| BASE64URL_NOPAD.encode(&[value; 32]);
        let runtime_fingerprint = digest(3);
        let binary_digest = digest(2);
        let activation_id = digest(4);
        let nonces = [(11, digest(5)), (13, digest(6))].into_iter().collect();

        assert_eq!(
            manager.private_oram_activation_voter_ids().unwrap(),
            vec![11, 13]
        );
        manager
            .require_private_oram_activation_coordinator_is_local_leader()
            .unwrap();
        let challenge_set = manager
            .private_oram_peer_activation_challenge_set(
                activation_id.clone(),
                nonces,
                &runtime_fingerprint,
                &binary_digest,
                qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
            )
            .unwrap();
        assert_eq!(challenge_set.challenges().len(), 2);
        assert_eq!(challenge_set.configuration().voters(), &[11, 13]);
        let rendered = format!("{challenge_set:?}");
        for secret in [&activation_id, &digest(5), &digest(6)] {
            assert!(!rendered.contains(secret), "{rendered}");
        }

        let local_challenge = challenge_set
            .challenges()
            .iter()
            .find(|challenge| challenge.target_peer_id == 11)
            .unwrap();
        let (observation, signer) = manager
            .private_oram_peer_activation_observation(
                local_challenge,
                &digest(7),
                "1.17.1-sec-v2",
                &binary_digest,
                &runtime_fingerprint,
            )
            .unwrap();
        assert_eq!(observation.responder_peer_id, 11);
        assert_eq!(observation.observed_current_term, 4);
        assert_eq!(observation.observed_hard_commit, 1);
        assert_eq!(observation.observed_last_applied, 1);
        assert_eq!(observation.observed_last_log_index, 1);
        assert_eq!(signer.key_epoch, 1);
        let legacy_challenge_set = manager
            .private_oram_peer_activation_challenge_set(
                digest(12),
                [(11, digest(13)), (13, digest(14))].into_iter().collect(),
                &runtime_fingerprint,
                &binary_digest,
                qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1,
            )
            .unwrap();
        let legacy_challenge = legacy_challenge_set
            .challenges()
            .iter()
            .find(|challenge| challenge.target_peer_id == 11)
            .unwrap();
        assert_eq!(legacy_challenge.required_consensus_wire_protocol, 0);
        assert_eq!(legacy_challenge.expected_last_log_index, 0);
        let (legacy_observation, _) = manager
            .private_oram_peer_activation_observation(
                legacy_challenge,
                &digest(15),
                "1.17.1-sec-v2",
                &binary_digest,
                &runtime_fingerprint,
            )
            .unwrap();
        assert_eq!(legacy_observation.supported_consensus_wire_protocol_min, 0);
        assert_eq!(legacy_observation.supported_consensus_wire_protocol_max, 0);
        assert_eq!(legacy_observation.observed_last_log_index, 0);
        assert!(
            manager
                .private_oram_peer_activation_observation(
                    local_challenge,
                    &digest(7),
                    "1.17.1-sec-v2",
                    &binary_digest,
                    &digest(8),
                )
                .is_err()
        );

        manager
            .append_entries(vec![Entry {
                index: 2,
                term: 4,
                ..Default::default()
            }])
            .unwrap();
        assert!(
            manager
                .private_oram_peer_activation_challenge_set(
                    digest(9),
                    [(11, digest(10)), (13, digest(11))].into_iter().collect(),
                    &runtime_fingerprint,
                    &binary_digest,
                    qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION,
                )
                .is_err()
        );

        manager.set_raft_soft_state(&SoftState {
            leader_id: 13,
            raft_state: StateRole::Follower,
        });
        assert!(
            manager
                .require_private_oram_activation_coordinator_is_local_leader()
                .is_err()
        );
    }

    #[test]
    fn private_oram_peer_recovery_signer_pair_is_atomic_live_and_redacted() {
        let dir = Builder::new()
            .prefix("private_oram_recovery_signer_pair")
            .tempdir()
            .unwrap();
        let manager = setup_private_oram_activation_probe_manager(dir.path());
        let fixture = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let prepared = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.prepare_operation,
            &fixture.authority,
            None,
            None,
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term,
                entry_index: fixture.base_index + 1,
                prior_applied_index: fixture.base_index,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        let enabled = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.enable_operation,
            &fixture.authority,
            Some(prepared.next_format_floor()),
            prepared.next_pending(),
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term + 1,
                entry_index: fixture.base_index + 3,
                prior_applied_index: fixture.base_index + 2,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        {
            let mut persistent = manager.persistent.write();
            persistent.private_oram_mutation_format_floor =
                Some(enabled.next_format_floor().clone());
            persistent.private_oram_mutation_activation_pending = enabled.next_pending().cloned();
        }

        let pair = manager
            .private_oram_peer_recovery_signer_pair_pin(13, 11)
            .unwrap();
        assert_eq!(
            pair.owner().registry_generation(),
            pair.coordinator().registry_generation()
        );
        assert_eq!(
            pair.owner().manifest_digest(),
            pair.coordinator().manifest_digest()
        );
        assert_ne!(pair.owner().signer(), pair.coordinator().signer());
        let rendered = format!("{pair:?}");
        for secret in [
            pair.owner().manifest_digest(),
            pair.owner().signer().key_id.as_str(),
            pair.coordinator().signer().key_id.as_str(),
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(
            manager
                .private_oram_peer_recovery_signer_pair_pin(11, 11)
                .is_err()
        );

        manager.persistent.write().state.conf_state = ConfState {
            voters: vec![11, 13],
            voters_outgoing: vec![11, 13],
            ..Default::default()
        };
        assert!(
            manager
                .private_oram_peer_recovery_signer_pair_pin(13, 11)
                .is_err()
        );
        manager.persistent.write().state.conf_state = ConfState {
            voters: vec![11, 13],
            learners: vec![17],
            ..Default::default()
        };
        assert!(
            manager
                .private_oram_peer_recovery_signer_pair_pin(13, 11)
                .is_err()
        );
        manager.persistent.write().state.conf_state = ConfState {
            voters: vec![11, 13],
            ..Default::default()
        };

        let peer_addresses = manager.persistent.read().peer_address_by_id.clone();
        peer_addresses
            .write()
            .insert(13, "https://drifted-node-13.internal:6335".parse().unwrap());
        assert!(
            manager
                .private_oram_peer_recovery_signer_pair_pin(13, 11)
                .is_err()
        );
        peer_addresses
            .write()
            .insert(13, "https://node-13.internal:6335".parse().unwrap());
        {
            manager
                .persistent
                .write()
                .private_oram_mutation_activation_pending =
                Some(prepared.next_pending().unwrap().clone());
        }
        assert!(
            manager
                .private_oram_peer_recovery_signer_pair_pin(13, 11)
                .is_err()
        );
    }

    #[test]
    fn update_is_applied() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut state = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        assert_eq!(state.state().hard_state.commit, 0);
        state
            .apply_state_update(|state| state.hard_state.commit = 1)
            .unwrap();
        assert_eq!(state.state().hard_state.commit, 1);
    }

    #[test]
    fn save_failure() {
        let mut state = Persistent {
            path: "./unexistent_dir/file".into(),
            ..Default::default()
        };
        assert!(
            state
                .apply_state_update(|state| { state.hard_state.commit = 1 })
                .is_err(),
        );
    }

    #[test]
    fn state_is_loaded() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut state = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        state
            .apply_state_update(|state| state.hard_state.commit = 1)
            .unwrap();
        assert_eq!(state.state().hard_state.commit, 1);

        let state_loaded = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        assert_eq!(state_loaded.state().hard_state.commit, 1);
    }

    #[test]
    fn default_peer_id_is_persisted() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let peer_id = Some(101);
        let state = Persistent::load_or_init(dir.path(), false, false, peer_id).unwrap();
        assert_eq!(state.this_peer_id, 101);

        let state_loaded = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        assert_eq!(state_loaded.this_peer_id, 101);
    }

    #[test]
    fn unapplied_entries() {
        let mut entries = EntryApplyProgressQueue::new(0, 2);
        assert_eq!(entries.current(), Some(0));
        assert_eq!(entries.len(), 3);
        entries.applied();
        assert_eq!(entries.current(), Some(1));
        assert_eq!(entries.len(), 2);
        entries.applied();
        assert_eq!(entries.current(), Some(2));
        assert_eq!(entries.len(), 1);
        entries.applied();
        assert_eq!(entries.current(), None);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn private_oram_activation_transition_is_reconstructed_from_wal_and_floor() {
        let dir = Builder::new()
            .prefix("private_oram_activation_transition")
            .tempdir()
            .unwrap();
        let persistent = Persistent::load_or_init(dir.path(), true, false, Some(11)).unwrap();
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            Arc::new(NoCollections::default()),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();
        let fixture = private_oram_mutation_activation_barrier_fixture_v2_for_test();
        let ordinary = ConsensusOperations::UpdateClusterMetadata {
            key: "ordinary-before-activation".to_string(),
            value: serde_json::Value::Null,
        };
        let activation =
            ConsensusOperations::ActivatePrivateOramMutationV2(fixture.prepare_operation.clone());
        manager
            .wal
            .lock()
            .append_entries(vec![
                Entry {
                    index: 1,
                    data: serde_cbor::to_vec(&ordinary).unwrap(),
                    ..Default::default()
                },
                Entry {
                    index: 2,
                    data: serde_cbor::to_vec(&activation).unwrap(),
                    ..Default::default()
                },
                Entry {
                    index: 3,
                    data: vec![0xff],
                    ..Default::default()
                },
            ])
            .unwrap();

        assert!(
            manager
                .private_oram_mutation_activation_transition_pending(0, 2)
                .unwrap()
        );
        assert!(
            manager
                .private_oram_mutation_activation_transition_pending(1, 2)
                .unwrap()
        );
        assert!(
            !manager
                .private_oram_mutation_activation_transition_pending(2, 2)
                .unwrap()
        );
        assert!(
            manager
                .private_oram_mutation_activation_transition_pending(2, 3)
                .unwrap_err()
                .to_string()
                .contains("WAL entry is malformed")
        );

        let prepared = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.prepare_operation,
            &fixture.authority,
            None,
            None,
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term,
                entry_index: fixture.base_index + 1,
                prior_applied_index: fixture.base_index,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        {
            let mut persistent = manager.persistent.write();
            persistent.private_oram_mutation_format_floor =
                Some(prepared.next_format_floor().clone());
            persistent.private_oram_mutation_activation_pending = prepared.next_pending().cloned();
        }
        assert!(
            manager
                .private_oram_mutation_activation_transition_pending(3, 3)
                .unwrap()
        );
        assert_eq!(
            manager
                .private_oram_mutation_pending_enable_operation()
                .unwrap(),
            Some(fixture.enable_operation.clone())
        );
        {
            let mut persistent = manager.persistent.write();
            persistent.latest_snapshot_meta.index = fixture.base_index + 1;
            persistent.latest_snapshot_meta.term = fixture.current_term;
        }
        assert_eq!(
            manager
                .private_oram_activation_barrier_base_term(&fixture.enable_operation, None)
                .unwrap(),
            fixture.base_entry_term,
        );

        let enabled = validate_private_oram_mutation_activation_barrier_v2(
            &fixture.enable_operation,
            &fixture.authority,
            Some(prepared.next_format_floor()),
            prepared.next_pending(),
            &fixture.conf_state,
            &fixture.peer_addresses,
            PrivateOramMutationActivationApplyFactsV2 {
                entry_term: fixture.current_term,
                entry_index: fixture.base_index + 2,
                prior_applied_index: fixture.base_index + 1,
                barrier_base_entry_term: fixture.base_entry_term,
            },
        )
        .unwrap();
        {
            let mut persistent = manager.persistent.write();
            persistent.private_oram_mutation_format_floor =
                Some(enabled.next_format_floor().clone());
            persistent.private_oram_mutation_activation_pending = enabled.next_pending().cloned();
        }
        assert!(
            !manager
                .private_oram_mutation_activation_transition_pending(3, 3)
                .unwrap()
        );
        assert!(
            manager
                .private_oram_mutation_pending_enable_operation()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn correct_entry_with_offset() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut wal = ConsensusOpWal::new(dir.path()).unwrap();
        wal.append_entries(vec![Entry {
            index: 4,
            ..Default::default()
        }])
        .unwrap();
        wal.append_entries(vec![Entry {
            index: 5,
            ..Default::default()
        }])
        .unwrap();
        wal.append_entries(vec![Entry {
            index: 6,
            ..Default::default()
        }])
        .unwrap();
        assert_eq!(wal.entry(5).unwrap().index, 5)
    }

    #[test]
    fn at_least_1_entry() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut wal = ConsensusOpWal::new(dir.path()).unwrap();
        wal.append_entries(vec![
            Entry {
                index: 4,
                ..Default::default()
            },
            Entry {
                index: 5,
                ..Default::default()
            },
        ])
        .unwrap();
        // Even when `max_size` is `0` this fn should return at least 1 entry
        assert_eq!(wal.entries(4, 5, Some(0)).unwrap().len(), 1)
    }

    #[derive(Default)]
    struct NoCollections {
        snapshot_apply_count: AtomicUsize,
    }

    impl CollectionContainer for NoCollections {
        fn perform_collection_meta_op(
            &self,
            _operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            Ok(true)
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &crate::content_manager::consensus_ops::PrivateOramCollectionLayoutTransition,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM collection layout transitions require a collection container",
            ))
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &crate::content_manager::consensus_ops::PrivateOramShardTransferStart,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM shard transfers require a collection container",
            ))
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &crate::content_manager::consensus_ops::PrivateOramShardTransferFinish,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM shard transfers require a collection container",
            ))
        }

        fn private_oram_resharding_state(
            &self,
            _operation: &crate::content_manager::consensus_ops::PrivateOramReshardingOperation,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM resharding requires a collection container",
            ))
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            self.snapshot_apply_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    struct LayoutTransitionCollections {
        state: AtomicU8,
        apply_count: AtomicUsize,
        fail_after_apply: bool,
    }

    impl LayoutTransitionCollections {
        fn new(fail_after_apply: bool) -> Self {
            Self {
                state: AtomicU8::new(0),
                apply_count: AtomicUsize::new(0),
                fail_after_apply,
            }
        }
    }

    impl CollectionContainer for LayoutTransitionCollections {
        fn perform_collection_meta_op(
            &self,
            operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            assert!(matches!(
                operation,
                crate::content_manager::collection_meta_ops::CollectionMetaOperations::Nop {
                    token: 7
                }
            ));
            self.apply_count.fetch_add(1, Ordering::SeqCst);
            self.state.store(1, Ordering::SeqCst);
            if self.fail_after_apply {
                Err(crate::content_manager::errors::StorageError::service_error(
                    "injected post-apply failure",
                ))
            } else {
                Ok(true)
            }
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &PrivateOramCollectionLayoutTransition,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Ok(if self.state.load(Ordering::SeqCst) == 0 {
                PrivateOramLayoutTransitionState::Pending
            } else {
                PrivateOramLayoutTransitionState::Applied
            })
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &PrivateOramShardTransferStart,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer start",
            ))
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &PrivateOramShardTransferFinish,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer finish",
            ))
        }

        fn private_oram_resharding_state(
            &self,
            _operation: &PrivateOramReshardingOperation,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM resharding operation",
            ))
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    struct ShardTransferCollections {
        state: AtomicU8,
        start_apply_count: AtomicUsize,
        finish_apply_count: AtomicUsize,
    }

    impl ShardTransferCollections {
        fn new() -> Self {
            Self {
                state: AtomicU8::new(0),
                start_apply_count: AtomicUsize::new(0),
                finish_apply_count: AtomicUsize::new(0),
            }
        }
    }

    impl CollectionContainer for ShardTransferCollections {
        fn perform_collection_meta_op(
            &self,
            operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            use crate::content_manager::collection_meta_ops::{
                CollectionMetaOperations, ShardTransferOperations,
            };

            match operation {
                CollectionMetaOperations::TransferShard(_, ShardTransferOperations::Start(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 0);
                    self.start_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(1, Ordering::SeqCst);
                }
                CollectionMetaOperations::TransferShard(_, ShardTransferOperations::Finish(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 1);
                    self.finish_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(2, Ordering::SeqCst);
                }
                _ => {
                    return Err(crate::content_manager::errors::StorageError::service_error(
                        "unexpected private ORAM shard transfer operation",
                    ));
                }
            }
            Err(crate::content_manager::errors::StorageError::service_error(
                "injected post-apply failure",
            ))
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &PrivateOramCollectionLayoutTransition,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM collection layout transition",
            ))
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &PrivateOramShardTransferStart,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            match self.state.load(Ordering::SeqCst) {
                0 => Ok(PrivateOramLayoutTransitionState::Pending),
                1 => Ok(PrivateOramLayoutTransitionState::Applied),
                _ => Err(crate::content_manager::errors::StorageError::service_error(
                    "private ORAM shard transfer start state is invalid",
                )),
            }
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &PrivateOramShardTransferFinish,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            match self.state.load(Ordering::SeqCst) {
                1 => Ok(PrivateOramLayoutTransitionState::Pending),
                2 => Ok(PrivateOramLayoutTransitionState::Applied),
                _ => Err(crate::content_manager::errors::StorageError::service_error(
                    "private ORAM shard transfer finish state is invalid",
                )),
            }
        }

        fn private_oram_resharding_state(
            &self,
            _operation: &PrivateOramReshardingOperation,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM resharding operation",
            ))
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    struct ReshardingCollections {
        state: AtomicU8,
        start_apply_count: AtomicUsize,
        finish_apply_count: AtomicUsize,
    }

    impl ReshardingCollections {
        fn new() -> Self {
            Self {
                state: AtomicU8::new(0),
                start_apply_count: AtomicUsize::new(0),
                finish_apply_count: AtomicUsize::new(0),
            }
        }
    }

    impl CollectionContainer for ReshardingCollections {
        fn perform_collection_meta_op(
            &self,
            operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            use crate::content_manager::collection_meta_ops::{
                CollectionMetaOperations, ReshardingOperation,
            };

            match operation {
                CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 0);
                    self.start_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(1, Ordering::SeqCst);
                }
                CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 1);
                    self.finish_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(2, Ordering::SeqCst);
                }
                _ => {
                    return Err(crate::content_manager::errors::StorageError::service_error(
                        "unexpected private ORAM resharding meta operation",
                    ));
                }
            }
            Err(crate::content_manager::errors::StorageError::service_error(
                "injected post-apply failure",
            ))
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &PrivateOramCollectionLayoutTransition,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM collection layout transition",
            ))
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &PrivateOramShardTransferStart,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer start",
            ))
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &PrivateOramShardTransferFinish,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer finish",
            ))
        }

        fn private_oram_resharding_state(
            &self,
            operation: &PrivateOramReshardingOperation,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            use crate::content_manager::collection_meta_ops::{
                CollectionMetaOperations, ReshardingOperation,
            };

            match (
                operation.collection_meta.as_ref(),
                self.state.load(Ordering::SeqCst),
            ) {
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)), 0) => {
                    Ok(PrivateOramLayoutTransitionState::Pending)
                }
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)), 1) => {
                    Ok(PrivateOramLayoutTransitionState::Applied)
                }
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)), 1) => {
                    Ok(PrivateOramLayoutTransitionState::Pending)
                }
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)), 2) => {
                    Ok(PrivateOramLayoutTransitionState::Applied)
                }
                _ => Err(crate::content_manager::errors::StorageError::service_error(
                    "private ORAM resharding state is invalid",
                )),
            }
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    #[test]
    fn private_oram_collection_layout_transition_applies_meta_before_layout_and_replays() {
        let dir = Builder::new()
            .prefix("private_oram_collection_layout_transition")
            .tempdir()
            .unwrap();
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
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[47; 32]),
            index_state_digest: canonical_private_oram_index_state_digest(
                collection_id,
                &[(epoch_key.clone(), epoch.clone())],
            )
            .unwrap(),
        };
        let transition = PrivateOramCollectionLayoutTransition {
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(current.clone()),
                new: next.clone(),
            },
            leases: vec![PrivateOramLayoutLeaseBinding {
                key: epoch_key.clone(),
                lease: lease.clone(),
            }],
            shard_key_change: None,
            collection_meta: Box::new(
                crate::content_manager::collection_meta_ops::CollectionMetaOperations::Nop {
                    token: 7,
                },
            ),
        };
        let entry = Entry {
            data: serde_cbor::to_vec(&ConsensusOperations::ApplyPrivateOramCollectionLayout(
                transition,
            ))
            .unwrap(),
            ..Default::default()
        };

        let mut persistent = Persistent::load_or_init(dir.path(), true, false, Some(7)).unwrap();
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
                key: layout_key.clone(),
                expected: None,
                new: current,
            })
            .unwrap();
        let collections = Arc::new(LayoutTransitionCollections::new(true));
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            collections.clone(),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(manager.apply_normal_entry(&entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next));
        assert_eq!(collections.apply_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn private_oram_shard_transfer_start_and_finish_replay_after_post_apply_failures() {
        use crate::content_manager::collection_meta_ops::{
            CollectionMetaOperations, ShardTransferOperations,
        };

        let dir = Builder::new()
            .prefix("private_oram_shard_transfer_transition")
            .tempdir()
            .unwrap();
        let collection_id = "collection-uuid-1";
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[41; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[42; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[43; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let index_state_digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[(epoch_key.clone(), epoch.clone())],
        )
        .unwrap();
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[44; 32]),
            index_state_digest: index_state_digest.clone(),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[46; 32]),
            index_state_digest,
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 7,
            to: 9,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: collection_id.to_string(),
                expected: PrivateOramTransferLayoutState {
                    generation: current.generation,
                    owner_peer_ids: current.owner_peer_ids.clone(),
                    layout_digest: current.layout_digest.clone(),
                    index_state_digest: current.index_state_digest.clone(),
                },
                new: PrivateOramTransferLayoutState {
                    generation: next.generation,
                    owner_peer_ids: next.owner_peer_ids.clone(),
                    layout_digest: next.layout_digest.clone(),
                    index_state_digest: next.index_state_digest.clone(),
                },
                index_states: vec![PrivateOramTransferIndexState {
                    index_kind: PrivateOramTransferIndexKind::Hnsw,
                    index_name: epoch_key.index_name.clone(),
                    index_epoch: epoch.index_epoch,
                    root_hash: epoch.root_hash.clone(),
                    writeback_digest: epoch.writeback_digest.clone(),
                }],
            }),
            filter: None,
        };
        let start = PrivateOramShardTransferStart {
            leases: vec![PrivateOramLayoutLeaseBinding {
                key: epoch_key.clone(),
                lease: lease.clone(),
            }],
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
        let start_entry = Entry {
            data: serde_cbor::to_vec(&ConsensusOperations::StartPrivateOramShardTransfer(start))
                .unwrap(),
            ..Default::default()
        };
        let finish_entry = Entry {
            data: serde_cbor::to_vec(&ConsensusOperations::FinishPrivateOramShardTransfer(finish))
                .unwrap(),
            ..Default::default()
        };
        let recovery_epoch_key = epoch_key.clone();
        let recovery_epoch = epoch.clone();
        let recovery_lease = lease.clone();
        let precommitted = PrivateOramConsensusLayout {
            generation: current.generation,
            owner_peer_ids: next.owner_peer_ids.clone(),
            layout_digest: next.layout_digest.clone(),
            index_state_digest: next.index_state_digest.clone(),
        };

        let mut persistent = Persistent::load_or_init(dir.path(), true, false, Some(7)).unwrap();
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
                key: layout_key.clone(),
                expected: None,
                new: current.clone(),
            })
            .unwrap();
        let collections = Arc::new(ShardTransferCollections::new());
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            collections.clone(),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(current));
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);

        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);

        let recovery_dir = Builder::new()
            .prefix("private_oram_precommitted_recovery_transition")
            .tempdir()
            .unwrap();
        let mut recovery_persistent =
            Persistent::load_or_init(recovery_dir.path(), true, false, Some(7)).unwrap();
        recovery_persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: recovery_epoch_key.clone(),
                expected: None,
                new: recovery_epoch,
            })
            .unwrap();
        recovery_persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: recovery_epoch_key,
                expected: None,
                new: Some(recovery_lease),
            })
            .unwrap();
        recovery_persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: precommitted,
            })
            .unwrap();
        let recovery_collections = Arc::new(ShardTransferCollections::new());
        let (sender, _) = mpsc::channel();
        let recovery_manager = ConsensusManager::new(
            recovery_persistent,
            recovery_collections.clone(),
            OperationSender::new(sender),
            recovery_dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(recovery_manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(
            recovery_manager.private_oram_layout(&layout_key),
            Some(next.clone()),
        );
        assert_eq!(
            recovery_collections
                .start_apply_count
                .load(Ordering::SeqCst),
            1,
        );
        assert!(recovery_manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(
            recovery_manager.private_oram_layout(&layout_key),
            Some(next),
        );
        assert_eq!(
            recovery_collections
                .start_apply_count
                .load(Ordering::SeqCst),
            1,
        );
    }

    #[test]
    fn private_oram_resharding_start_and_finish_replay_after_post_apply_failures() {
        use crate::content_manager::collection_meta_ops::{
            CollectionMetaOperations, ReshardingOperation,
        };

        let dir = Builder::new()
            .prefix("private_oram_resharding_transition")
            .tempdir()
            .unwrap();
        let collection_id = "qdrant-sec-resharding-collection-sentinel";
        let index_name_sentinel = "qdrant-sec-resharding-index-sentinel";
        let root_sentinel = BASE64URL_NOPAD.encode(&[91; 32]);
        let lease_hash_sentinel = BASE64URL_NOPAD.encode(&[92; 32]);
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: index_name_sentinel.to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: root_sentinel.clone(),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[93; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash_sentinel.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let index_state_digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[(epoch_key.clone(), epoch.clone())],
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[94; 32]),
            index_state_digest: index_state_digest.clone(),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[95; 32]),
            index_state_digest,
        };
        let resharding_key = ReshardKey {
            uuid: Uuid::from_u128(31),
            direction: ReshardingDirection::Up,
            peer_id: 9,
            shard_id: 2,
            shard_key: None,
        };
        let transition = PrivateOramReshardingLayoutTransition {
            resharding_key: resharding_key.clone(),
            target_shard_owner_peer_ids: vec![9],
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(current.clone()),
                new: next.clone(),
            },
            index_states: vec![PrivateOramLayoutIndexStateBinding {
                key: epoch_key.clone(),
                state: epoch.clone(),
            }],
        };
        let leases = vec![PrivateOramLayoutLeaseBinding {
            key: epoch_key.clone(),
            lease: lease.clone(),
        }];
        let start = PrivateOramReshardingOperation {
            leases: leases.clone(),
            transition: transition.clone(),
            collection_meta: Box::new(CollectionMetaOperations::Resharding(
                "qdrant-sec-resharding-name-sentinel".to_string(),
                ReshardingOperation::Start(resharding_key.clone()),
            )),
        };
        let finish = PrivateOramReshardingOperation {
            leases,
            transition,
            collection_meta: Box::new(CollectionMetaOperations::Resharding(
                "qdrant-sec-resharding-name-sentinel".to_string(),
                ReshardingOperation::Finish(resharding_key),
            )),
        };
        let start_operation = ConsensusOperations::StartPrivateOramResharding(start);
        let finish_operation = ConsensusOperations::FinishPrivateOramResharding(finish);
        for rendered in [
            format!("{start_operation:?}"),
            format!("{:?}", start_operation.redacted_log()),
            format!("{finish_operation:?}"),
            format!("{:?}", finish_operation.redacted_log()),
        ] {
            for sentinel in [
                collection_id,
                index_name_sentinel,
                &root_sentinel,
                &lease_hash_sentinel,
                "qdrant-sec-resharding-name-sentinel",
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }
        let start_entry = Entry {
            data: serde_cbor::to_vec(&start_operation).unwrap(),
            ..Default::default()
        };
        let finish_entry = Entry {
            data: serde_cbor::to_vec(&finish_operation).unwrap(),
            ..Default::default()
        };

        let mut persistent = Persistent::load_or_init(dir.path(), true, false, Some(7)).unwrap();
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
                key: layout_key.clone(),
                expected: None,
                new: current.clone(),
            })
            .unwrap();
        let collections = Arc::new(ReshardingCollections::new());
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            collections.clone(),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(current));
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);

        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);
    }

    fn setup_storages(
        entries: Vec<Entry>,
        path: &std::path::Path,
    ) -> (ConsensusManager<NoCollections>, MemStorage) {
        let persistent = Persistent::load_or_init(path, true, false, None).unwrap();
        let (sender, _) = mpsc::channel();
        let consensus_state = ConsensusManager::new(
            persistent,
            Arc::new(NoCollections::default()),
            OperationSender::new(sender),
            path,
            PeerMetadata::current(),
        )
        .expect("initialize consensus manager");
        let mem_storage = MemStorage::new();
        mem_storage.wl().append(entries.as_ref()).unwrap();
        consensus_state.append_entries(entries).unwrap();
        (consensus_state, mem_storage)
    }

    #[test]
    fn private_oram_epoch_cas_replays_and_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
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

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    None,
                    initial.clone(),
                ))
                .unwrap(),
        );
        assert_eq!(source.private_oram_epoch(&key), Some(initial.clone()));
        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    None,
                    initial.clone(),
                ))
                .unwrap(),
        );

        let stale = source
            .apply_normal_entry(&private_oram_epoch_entry(key.clone(), None, next.clone()))
            .unwrap_err();
        assert!(
            stale
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(source.private_oram_epoch(&key), Some(initial.clone()));

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    Some(initial.clone()),
                    next.clone(),
                ))
                .unwrap(),
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    Some(initial.clone()),
                    next.clone(),
                ))
                .unwrap(),
        );

        let conflicting_digest = source
            .apply_normal_entry(&private_oram_epoch_entry(
                key.clone(),
                Some(initial),
                PrivateOramConsensusEpoch {
                    index_epoch: next.index_epoch,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: Some(BASE64URL_NOPAD.encode(&[12; 32])),
                },
            ))
            .unwrap_err();
        assert!(
            conflicting_digest
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(source.private_oram_epoch(&key), Some(next.clone()));

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_epochs.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_epoch(&key), Some(next));
    }

    #[test]
    fn private_oram_activation_authority_survives_snapshot_and_cannot_disappear() {
        let (_, trust_anchor, bundle) = private_oram_activation_authority_fixture_v1_for_test();
        let source_dir = Builder::new()
            .prefix("private_oram_authority_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        {
            let mut persistent = source.persistent.write();
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
        }
        let installed = source
            .persistent
            .read()
            .private_oram_activation_authority
            .clone()
            .unwrap();
        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(
            snapshot_data.private_oram_activation_authority.as_ref(),
            Some(&installed),
        );

        let target_dir = Builder::new()
            .prefix("private_oram_authority_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target
            .persistent
            .read()
            .configure_private_oram_activation_authority_trust_anchor(&trust_anchor)
            .unwrap();
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(
            target
                .persistent
                .read()
                .private_oram_activation_authority
                .as_ref(),
            Some(&installed),
        );
        assert_eq!(
            target
                .persistent
                .read()
                .private_oram_activation_authority_at_read(&trust_anchor)
                .unwrap()
                .locator()
                .unwrap(),
            installed.locator(),
        );

        let mut rollback_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        rollback_data.private_oram_activation_authority = None;
        let rollback = raft::eraftpb::Snapshot {
            data: serde_cbor::to_vec(&rollback_data).unwrap(),
            metadata: snapshot.metadata.clone(),
        };
        assert!(target.apply_snapshot(&rollback).is_err());
        assert_eq!(
            target
                .persistent
                .read()
                .private_oram_activation_authority
                .as_ref(),
            Some(&installed),
        );
    }

    #[test]
    fn private_oram_session_lease_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_lease_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[31; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        assert!(
            source
                .apply_normal_entry(&private_oram_session_lease_entry(
                    key.clone(),
                    None,
                    Some(lease.clone()),
                ))
                .unwrap()
        );
        assert_eq!(source.private_oram_session_lease(&key), Some(lease.clone()));

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_session_leases.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_lease_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_session_lease(&key), Some(lease));
    }

    #[test]
    fn active_private_oram_mutation_slot_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_mutation_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let digest = |byte| BASE64URL_NOPAD.encode(&[byte; 32]);
        let collection_id = "collection-uuid-mutation-snapshot".to_string();
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.clone(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 7,
            root_hash: digest(7),
            writeback_digest: Some(digest(8)),
        };
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![source.persistent.read().this_peer_id()],
            layout_digest: digest(9),
            index_state_digest: canonical_private_oram_index_state_digest(
                &collection_id,
                &[(epoch_key.clone(), epoch.clone())],
            )
            .unwrap(),
        };
        let state = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: digest(10),
            layout_generation: layout.generation,
            layout_digest: layout.layout_digest.clone(),
            state_sequence: 0,
            signed_state_digest: digest(11),
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "text".to_string(),
                epoch: epoch.clone(),
                logical_count: 4,
                dummy_count: 6,
            }],
            client_state_digest: digest(12),
            last_transition: PrivateOramConsensusTransitionV2::Genesis,
        };
        let mutation_key = PrivateOramMutationKey {
            collection_id: collection_id.clone(),
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
            active: Some(PrivateOramMutationLease {
                generation: 1,
                collection_id: collection_id.clone(),
                owner_peer_id: layout.owner_peer_ids[0],
                mutation_id: digest(13),
                signed_mutation_digest: digest(14),
                transition_digest: digest(15),
                base_record_digest: canonical_private_oram_consensus_state_record_digest(&state)
                    .unwrap(),
                base_state_sequence: state.state_sequence,
                writer_lease_digest: digest(16),
                writer_fence: 1,
                issued_at_unix: 100,
                expires_at_unix: 200,
                renewal_revision: 0,
                phase: PrivateOramMutationLeasePhase::Preparing,
            }),
            max_writer_fence: 1,
            ..genesis_slot.clone()
        };

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(epoch_key.clone(), None, epoch,))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_layout_entry(
                    PrivateOramLayoutKey {
                        collection_id: collection_id.clone(),
                    },
                    None,
                    layout,
                ))
                .unwrap()
        );
        let initialize = ConsensusOperations::InitializePrivateOramMutationState(
            InitializePrivateOramMutationState {
                key: mutation_key.clone(),
                state: state.clone(),
            },
        );
        assert!(
            source
                .apply_normal_entry(&Entry {
                    data: serde_cbor::to_vec(&initialize).unwrap(),
                    ..Default::default()
                })
                .unwrap()
        );
        let acquire = ConsensusOperations::CompareAndSwapPrivateOramMutationLease(
            CompareAndSwapPrivateOramMutationLease {
                key: mutation_key.clone(),
                expected: genesis_slot,
                new: preparing_slot.clone(),
            },
        );
        assert!(
            source
                .apply_normal_entry(&Entry {
                    data: serde_cbor::to_vec(&acquire).unwrap(),
                    ..Default::default()
                })
                .unwrap()
        );

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_mutation_states.len(), 1);
        assert_eq!(snapshot_data.private_oram_mutation_lease_slots.len(), 1);
        let snapshot_debug = format!("{snapshot_data:?}");
        assert!(
            snapshot_debug.contains("private_oram_mutation_state_count: 1"),
            "{snapshot_debug}",
        );
        assert!(
            snapshot_debug.contains("private_oram_mutation_lease_slot_count: 1"),
            "{snapshot_debug}",
        );
        for secret in [&collection_id, &digest(13), &digest(14), &digest(15)] {
            assert!(!snapshot_debug.contains(secret), "{snapshot_debug}");
        }

        let target_dir = Builder::new()
            .prefix("private_oram_mutation_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(
            target.private_oram_mutation_state(&mutation_key),
            Some(state.clone())
        );
        assert_eq!(
            target.private_oram_mutation_lease_slot(&mutation_key),
            Some(preparing_slot.clone())
        );

        let mut abort_decided_slot = preparing_slot.clone();
        abort_decided_slot.active.as_mut().unwrap().phase =
            PrivateOramMutationLeasePhase::AbortDecided;
        let abort_decision = ConsensusOperations::CompareAndSwapPrivateOramMutationLease(
            CompareAndSwapPrivateOramMutationLease {
                key: mutation_key.clone(),
                expected: preparing_slot,
                new: abort_decided_slot.clone(),
            },
        );
        assert!(
            source
                .apply_normal_entry(&Entry {
                    data: serde_cbor::to_vec(&abort_decision).unwrap(),
                    ..Default::default()
                })
                .unwrap()
        );
        let abort_snapshot = source.snapshot(0, 0).unwrap();
        let abort_target_dir = Builder::new()
            .prefix("private_oram_abort_decided_raft_target")
            .tempdir()
            .unwrap();
        let (abort_target, _) = setup_storages(Vec::new(), abort_target_dir.path());
        abort_target
            .apply_snapshot(&abort_snapshot)
            .unwrap()
            .unwrap();
        assert_eq!(
            abort_target.private_oram_mutation_state(&mutation_key),
            Some(state)
        );
        assert_eq!(
            abort_target.private_oram_mutation_lease_slot(&mutation_key),
            Some(abort_decided_slot)
        );
    }

    #[test]
    fn private_oram_external_recovery_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_recovery_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let epoch_key = PrivateOramEpochKey {
            collection_id: key.collection_id.clone(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[40; 32]),
            writeback_digest: None,
        };
        let index_states = vec![PrivateOramLayoutIndexStateBinding {
            key: epoch_key.clone(),
            state: epoch.clone(),
        }];
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[39; 32]),
            index_state_digest: canonical_private_oram_index_state_digest(
                &key.collection_id,
                &[(epoch_key.clone(), epoch.clone())],
            )
            .unwrap(),
        };
        let checkpoint_digest = BASE64URL_NOPAD.encode(&[41; 32]);
        let install_intent_digest = BASE64URL_NOPAD.encode(&[42; 32]);
        let acquired = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 7,
                operation_id_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                checkpoint_digest: checkpoint_digest.clone(),
                backup_generation: 7,
                issued_at_unix: 100,
                expires_at_unix: 160,
                install_intent_digest: None,
                phase: PrivateOramExternalRecoveryLeasePhase::Staging,
            }),
        };
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

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(epoch_key, None, epoch,))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_layout_entry(
                    PrivateOramLayoutKey {
                        collection_id: key.collection_id.clone(),
                    },
                    None,
                    layout.clone(),
                ))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_external_recovery_entry(
                    PrivateOramExternalRecoveryPhase::Begin,
                    CompareAndSwapPrivateOramExternalRecovery {
                        key: key.clone(),
                        expected: None,
                        new: Some(acquired.clone()),
                    },
                    layout.clone(),
                    index_states.clone(),
                ))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_external_recovery_entry(
                    PrivateOramExternalRecoveryPhase::PrepareInstall,
                    CompareAndSwapPrivateOramExternalRecovery {
                        key: key.clone(),
                        expected: Some(acquired),
                        new: Some(prepared.clone()),
                    },
                    layout.clone(),
                    index_states.clone(),
                ))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_external_recovery_entry(
                    PrivateOramExternalRecoveryPhase::Commit,
                    CompareAndSwapPrivateOramExternalRecovery {
                        key: key.clone(),
                        expected: Some(prepared),
                        new: Some(committed.clone()),
                    },
                    layout,
                    index_states,
                ))
                .unwrap()
        );

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_external_recoveries.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_recovery_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_external_recovery(&key), Some(committed));
    }

    #[test]
    fn private_oram_layout_cas_replays_and_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_layout_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramLayoutKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let initial = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[51; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[52; 32]),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9, 11],
            layout_digest: BASE64URL_NOPAD.encode(&[53; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[54; 32]),
        };

        let initial_entry = private_oram_layout_entry(key.clone(), None, initial.clone());
        assert!(source.apply_normal_entry(&initial_entry).unwrap());
        assert!(source.apply_normal_entry(&initial_entry).unwrap());
        assert_eq!(source.private_oram_layout(&key), Some(initial.clone()));

        let transition_entry = private_oram_layout_entry(key.clone(), Some(initial), next.clone());
        assert!(source.apply_normal_entry(&transition_entry).unwrap());
        assert!(source.apply_normal_entry(&transition_entry).unwrap());

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_layouts.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_layout_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_layout(&key), Some(next));
    }

    #[test]
    fn malformed_private_oram_snapshot_maps_fail_before_collection_apply() {
        let valid_digest = BASE64URL_NOPAD.encode(&[61; 32]);
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: valid_digest.clone(),
            writeback_digest: Some(valid_digest.clone()),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: valid_digest.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: valid_digest.clone(),
            index_state_digest: valid_digest.clone(),
        };
        let recovery = PrivateOramExternalRecoveryState {
            committed_backup_generation: 1,
            committed_checkpoint_digest: Some(valid_digest),
            committed_install_intent_digest: None,
            active_lease: None,
        };
        let malformed_snapshots = [
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_activation_authority: None,
                private_oram_epochs: std::collections::HashMap::from([(
                    "invalid-epoch-key".to_string(),
                    epoch,
                )]),
                private_oram_session_leases: Default::default(),
                private_oram_layouts: Default::default(),
                private_oram_external_recoveries: Default::default(),
                private_oram_mutation_states: Default::default(),
                private_oram_mutation_lease_slots: Default::default(),
                private_oram_mutation_format_floor: None,
                private_oram_mutation_activation_pending: None,
            },
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_activation_authority: None,
                private_oram_epochs: Default::default(),
                private_oram_session_leases: std::collections::HashMap::from([(
                    "invalid-lease-key".to_string(),
                    lease,
                )]),
                private_oram_layouts: Default::default(),
                private_oram_external_recoveries: Default::default(),
                private_oram_mutation_states: Default::default(),
                private_oram_mutation_lease_slots: Default::default(),
                private_oram_mutation_format_floor: None,
                private_oram_mutation_activation_pending: None,
            },
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_activation_authority: None,
                private_oram_epochs: Default::default(),
                private_oram_session_leases: Default::default(),
                private_oram_layouts: std::collections::HashMap::from([(
                    "invalid-layout-key".to_string(),
                    layout,
                )]),
                private_oram_external_recoveries: Default::default(),
                private_oram_mutation_states: Default::default(),
                private_oram_mutation_lease_slots: Default::default(),
                private_oram_mutation_format_floor: None,
                private_oram_mutation_activation_pending: None,
            },
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_activation_authority: None,
                private_oram_epochs: Default::default(),
                private_oram_session_leases: Default::default(),
                private_oram_layouts: Default::default(),
                private_oram_external_recoveries: std::collections::HashMap::from([(
                    "invalid-recovery-key".to_string(),
                    recovery,
                )]),
                private_oram_mutation_states: Default::default(),
                private_oram_mutation_lease_slots: Default::default(),
                private_oram_mutation_format_floor: None,
                private_oram_mutation_activation_pending: None,
            },
        ];

        for (index, snapshot_data) in malformed_snapshots.into_iter().enumerate() {
            let dir = Builder::new()
                .prefix(&format!("malformed_private_oram_snapshot_{index}"))
                .tempdir()
                .unwrap();
            let (target, _) = setup_storages(Vec::new(), dir.path());
            let snapshot = raft::eraftpb::Snapshot {
                data: serde_cbor::to_vec(&snapshot_data).unwrap(),
                metadata: Some(Default::default()),
            };

            let err = target.apply_snapshot(&snapshot).unwrap_err();
            assert!(err.to_string().contains("snapshot is invalid"));
            assert_eq!(target.toc.snapshot_apply_count.load(Ordering::SeqCst), 0);
            let persistent = target.persistent.read();
            assert!(persistent.private_oram_epochs.is_empty());
            assert!(persistent.private_oram_session_leases.is_empty());
            assert!(persistent.private_oram_layouts.is_empty());
            assert!(persistent.private_oram_external_recoveries.is_empty());
        }
    }

    #[test]
    fn raft_snapshot_without_private_oram_epochs_remains_compatible() {
        let snapshot = SnapshotData {
            collections_data: Default::default(),
            address_by_id: Default::default(),
            metadata_by_id: Default::default(),
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
        };
        let mut legacy_value = serde_json::to_value(snapshot).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_epochs");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_session_leases");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_mutation_states");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_mutation_lease_slots");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_layouts");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_external_recoveries");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_activation_authority");

        let decoded: SnapshotData = serde_json::from_value(legacy_value).unwrap();
        assert!(decoded.private_oram_epochs.is_empty());
        assert!(decoded.private_oram_session_leases.is_empty());
        assert!(decoded.private_oram_layouts.is_empty());
        assert!(decoded.private_oram_external_recoveries.is_empty());
        assert!(decoded.private_oram_mutation_states.is_empty());
        assert!(decoded.private_oram_mutation_lease_slots.is_empty());
        assert!(decoded.private_oram_activation_authority.is_none());
    }

    #[test]
    fn private_oram_epoch_without_writeback_digest_remains_compatible() {
        let legacy_epoch = serde_json::json!({
            "index_epoch": 42,
            "root_hash": BASE64URL_NOPAD.encode(&[42; 32]),
        });

        let decoded: PrivateOramConsensusEpoch = serde_json::from_value(legacy_epoch).unwrap();
        assert_eq!(decoded.writeback_digest, None);
    }

    fn private_oram_epoch_entry(
        key: PrivateOramEpochKey,
        expected: Option<PrivateOramConsensusEpoch>,
        new: PrivateOramConsensusEpoch,
    ) -> Entry {
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramEpoch(CompareAndSwapPrivateOramEpoch {
                key,
                expected,
                new,
            });
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    fn private_oram_session_lease_entry(
        key: PrivateOramEpochKey,
        expected: Option<PrivateOramSessionLease>,
        new: Option<PrivateOramSessionLease>,
    ) -> Entry {
        let operation = ConsensusOperations::CompareAndSwapPrivateOramSessionLease(
            CompareAndSwapPrivateOramSessionLease { key, expected, new },
        );
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    fn private_oram_external_recovery_entry(
        phase: PrivateOramExternalRecoveryPhase,
        recovery: CompareAndSwapPrivateOramExternalRecovery,
        layout: PrivateOramConsensusLayout,
        index_states: Vec<PrivateOramLayoutIndexStateBinding>,
    ) -> Entry {
        let operation = ConsensusOperations::ApplyPrivateOramExternalRecovery(
            PrivateOramExternalRecoveryOperation {
                phase,
                recovery,
                layout,
                index_states,
            },
        );
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    fn private_oram_layout_entry(
        key: PrivateOramLayoutKey,
        expected: Option<PrivateOramConsensusLayout>,
        new: PrivateOramConsensusLayout,
    ) -> Entry {
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramLayout(CompareAndSwapPrivateOramLayout {
                key,
                expected,
                new,
            });
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    prop_compose! {
        fn gen_entries(min_entries: u64, max_entries: u64)(n in min_entries..max_entries, inc_term_every in 1u64..max_entries) -> Vec<Entry> {
            (1..=n).map(|index| Entry {index, term: 1 + index/inc_term_every, ..Default::default()}).collect::<Vec<Entry>>()
        }
    }

    proptest! {
        #[test]
        fn check_first_and_last_indexes(entries in gen_entries(0, 100)) {
            let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
            let (consensus_state, mem_storage) = setup_storages(entries, dir.path());
            prop_assert_eq!(mem_storage.last_index(), consensus_state.last_index());
            prop_assert_eq!(mem_storage.first_index(), consensus_state.first_index());
        }

        #[test]
        fn check_term(entries in gen_entries(0, 100), id in 0u64..100) {
            let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
            let (consensus_state, mem_storage) = setup_storages(entries, dir.path());
            prop_assert_eq!(mem_storage.term(id), consensus_state.term(id))
        }

        #[test]
        fn check_entries(entries in gen_entries(1, 100),
                low in 0u64..100,
                len in 1u64..100,
                max_size in proptest::option::of(proptest::num::u64::ANY)
            ) {
            let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
            let (consensus_state, mem_storage) = setup_storages(entries, dir.path());
            let mut high = low + len;
            let last_index = mem_storage.last_index().unwrap();
            if high > last_index + 1 {
                high = last_index + 1;
            }
            let mut low = low;
            if low > last_index {
                low = last_index;
            }
            let context_1 = raft::storage::GetEntriesContext::empty(false);
            let context_2 = raft::storage::GetEntriesContext::empty(false);
            prop_assert_eq!(mem_storage.entries(low, high, max_size, context_1), consensus_state.entries(low, high, max_size, context_2));
        }
    }

    #[test]
    fn recover_first_voter() {
        let (_dir, wal) = wal(0);
        let peers = vec![1337, 42, 69];
        assert_eq!(
            super::recover_first_voter(&wal, &peers).unwrap(),
            Some(1337)
        );
    }

    #[test]
    fn recover_first_voter_empty() {
        let (_dir, wal) = empty_wal();
        let peers = vec![1337, 42, 69];
        assert_eq!(super::recover_first_voter(&wal, &peers).unwrap(), None);
    }

    #[test]
    fn recover_first_voter_committed() {
        let (_dir, wal) = wal(1);
        let peers = vec![1337, 42, 69];
        assert_eq!(super::recover_first_voter(&wal, &peers).unwrap(), None);
    }

    #[test]
    fn recover_first_voter_truncated() {
        let (_dir, wal) = wal(2);
        let peers = vec![1337, 42, 69];
        assert_eq!(
            super::recover_first_voter(&wal, &peers).unwrap(),
            Some(PeerId::MAX)
        );
    }

    #[test]
    fn recover_first_voter_multiple_peers() {
        let (_dir, wal) = wal(0);
        let peers = vec![1337, 42, 69, 228];
        assert_eq!(
            super::recover_first_voter(&wal, &peers).unwrap(),
            Some(PeerId::MAX)
        );
    }

    fn wal(first_index: u64) -> (tempfile::TempDir, ConsensusOpWal) {
        let (dir, mut wal) = empty_wal();
        wal.append_entries(entries(first_index)).unwrap();
        (dir, wal)
    }

    fn empty_wal() -> (tempfile::TempDir, ConsensusOpWal) {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let wal = ConsensusOpWal::new(dir.path()).unwrap();
        (dir, wal)
    }

    fn entries(first_index: u64) -> Vec<Entry> {
        use ConfChangeType::*;

        let mut entries = vec![
            conf_change_v2(first_index, &[(AddNode, 1337)]),
            conf_change_v2(
                first_index + 1,
                &[(AddLearnerNode, 42), (AddLearnerNode, 69)],
            ),
            conf_change_v2(first_index + 2, &[(AddNode, 42)]),
            conf_change(first_index + 3, RemoveNode, 228),
            conf_change(first_index + 4, AddLearnerNode, 666),
            conf_change_v2(first_index + 5, &[(AddNode, 69)]),
            conf_change(first_index + 6, AddNode, 666),
        ];

        // Remove first entry if `first_index` is 0, so that second entry would line up with index 1
        if first_index == 0 {
            entries.remove(0);
        }

        entries
    }

    fn conf_change_v2(index: u64, changes: &[(ConfChangeType, PeerId)]) -> Entry {
        let mut conf_change = ConfChangeV2::default();

        for &(change_type, node_id) in changes {
            conf_change.changes.push(ConfChangeSingle {
                change_type: change_type as _,
                node_id,
            });
        }

        Entry {
            index,
            entry_type: EntryType::EntryConfChangeV2 as _,
            data: prost_for_raft::Message::encode_to_vec(&conf_change),
            ..Default::default()
        }
    }

    fn conf_change(index: u64, change_type: ConfChangeType, node_id: PeerId) -> Entry {
        let conf_change = ConfChange {
            change_type: change_type as _,
            node_id,
            ..Default::default()
        };

        Entry {
            index,
            entry_type: EntryType::EntryConfChange as _,
            data: prost_for_raft::Message::encode_to_vec(&conf_change),
            ..Default::default()
        }
    }
}
