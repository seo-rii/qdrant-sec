#![allow(
    dead_code,
    reason = "D3-B3-B2 paired store evidence remains dormant until typed parent recovery is wired"
)]

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

use qdrant_sec::{
    PrivateHnswManifestValidationContext, PrivateOramAppendBucketRefV1,
    PrivateOramAppendMutationBundleV1, PrivateOramImmutableIndexV2,
    PrivateOramImmutableManifestBundleV2, PrivateOramImmutableManifestV2, PrivateOramIndexKindV2,
    PrivateOramIndexStateV2, PrivateOramSignatureVerification,
    PrivateResultOramManifestValidationContext, private_oram_append_mutation_v1_digest,
    private_oram_immutable_manifest_v2_digest, validate_private_oram_append_mutation_v1_shape,
    validate_private_oram_append_mutation_v1_signature,
    validate_private_oram_immutable_manifest_v2_shape,
    validate_private_oram_immutable_manifest_v2_signature,
    validate_private_oram_signed_state_v2_signature,
};
use sha2::{Digest, Sha256};

use crate::operations::types::{CollectionError, CollectionResult};
use crate::private_hnsw_oram_store::{
    PrivateHnswOramStore, PrivateHnswOwnerExactNewStoreTokenV1,
    PrivateHnswOwnerExactOldStoreTokenV1, PrivateHnswOwnerRecoveryPhaseV1,
    PrivateHnswOwnerStoreLockV1, PrivateHnswOwnerStoreObservationV1,
};
use crate::private_oram_owner_journal::{
    PrivateOramDurableOwnerAbortedOldTokenV1, PrivateOramDurableOwnerFinalizedTokenV1,
    PrivateOramDurableOwnerPreparedTokenV1, PrivateOramOwnerFinalBucketBatchV1,
    PrivateOramOwnerJournal, PrivateOramOwnerJournalIndexDescriptorV1,
    PrivateOramOwnerJournalSnapshotV1, PrivateOramOwnerJournalTerminalIndexStateV1,
    PrivateOramOwnerRecoveryExclusiveActionV1, PrivateOramOwnerRecoveryExclusiveBindingV1,
    PrivateOramOwnerRecoveryExclusiveOutcomeV1, PrivateOramOwnerRecoveryExclusiveStateV1,
    PrivateOramOwnerRecoveryProjectionV1,
};
use crate::private_result_oram_store::{
    PrivateResultOramStore, PrivateResultOwnerExactNewStoreTokenV1,
    PrivateResultOwnerExactOldStoreTokenV1, PrivateResultOwnerRecoveryProgressV1,
    PrivateResultOwnerStoreLockV1, PrivateResultOwnerStoreObservationV1,
};

const RECOVERY_TRANSACTION_IDENTITY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-recovery-transaction/v1";

#[derive(Clone, Copy)]
pub(crate) struct PrivateOramOwnerStorePairContextV1<'a> {
    pub(crate) owner_journal: &'a PrivateOramOwnerJournal,
    pub(crate) prepared_token: &'a PrivateOramDurableOwnerPreparedTokenV1,
    pub(crate) immutable_manifest: &'a PrivateOramImmutableManifestBundleV2,
    pub(crate) mutation_bundle: &'a PrivateOramAppendMutationBundleV1,
    pub(crate) signature_verification: PrivateOramSignatureVerification<'a>,
    pub(crate) hnsw_store: &'a PrivateHnswOramStore,
    pub(crate) hnsw_manifest_validation: PrivateHnswManifestValidationContext<'a>,
    pub(crate) hnsw_max_ciphertext_bytes: usize,
    pub(crate) result_store: &'a PrivateResultOramStore,
    pub(crate) result_manifest_validation: PrivateResultOramManifestValidationContext<'a>,
    pub(crate) result_max_ciphertext_bytes: usize,
}

impl Debug for PrivateOramOwnerStorePairContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerStorePairContextV1")
            .field("owner_journal", &self.owner_journal)
            .field("prepared_token", &self.prepared_token)
            .field("immutable_manifest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("signature_verification", &self.signature_verification)
            .field("hnsw_store", &self.hnsw_store)
            .field("hnsw_manifest_validation", &self.hnsw_manifest_validation)
            .field("hnsw_max_ciphertext_bytes", &self.hnsw_max_ciphertext_bytes)
            .field("result_store", &self.result_store)
            .field(
                "result_manifest_validation",
                &self.result_manifest_validation,
            )
            .field(
                "result_max_ciphertext_bytes",
                &self.result_max_ciphertext_bytes,
            )
            .finish()
    }
}

/// Server-side resources used for a read-only recovery classification.
///
/// This value contains no parent consensus authority. Storage must pair it with a projection made
/// from `PrivateOramValidatedOwnerRecoveryAuthorityV1` before invoking the classifier.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct PrivateOramOwnerRecoveryStorePairResourcesV1<'a> {
    pub owner_journal: &'a PrivateOramOwnerJournal,
    pub immutable_manifest: &'a PrivateOramImmutableManifestBundleV2,
    pub mutation_bundle: &'a PrivateOramAppendMutationBundleV1,
    pub signature_verification: PrivateOramSignatureVerification<'a>,
    pub hnsw_store: &'a PrivateHnswOramStore,
    pub hnsw_manifest_validation: PrivateHnswManifestValidationContext<'a>,
    pub hnsw_max_ciphertext_bytes: usize,
    pub result_store: &'a PrivateResultOramStore,
    pub result_manifest_validation: PrivateResultOramManifestValidationContext<'a>,
    pub result_max_ciphertext_bytes: usize,
}

impl Debug for PrivateOramOwnerRecoveryStorePairResourcesV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryStorePairResourcesV1")
            .field("owner_journal", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("signature_verification", &"[redacted]")
            .field("hnsw_store", &"[redacted]")
            .field("hnsw_manifest_validation", &"[redacted]")
            .field("hnsw_max_ciphertext_bytes", &self.hnsw_max_ciphertext_bytes)
            .field("result_store", &"[redacted]")
            .field("result_manifest_validation", &"[redacted]")
            .field(
                "result_max_ciphertext_bytes",
                &self.result_max_ciphertext_bytes,
            )
            .finish()
    }
}

/// Read-only, non-authoritative observation of the paired canonical stores.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramOwnerRecoveryStoreDispositionV1 {
    AllOld,
    AllNew,
    PartialNew,
    ThirdState,
}

#[derive(Debug)]
struct PrivateOramOwnerRecoveryParentBridgeIdentityV1;

/// Parent-journal endpoint retained by storage and used only while its exclusive lock is held.
#[doc(hidden)]
#[derive(Clone)]
pub struct PrivateOramOwnerRecoveryParentBridgeV1 {
    identity: Arc<PrivateOramOwnerRecoveryParentBridgeIdentityV1>,
}

impl Debug for PrivateOramOwnerRecoveryParentBridgeV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateOramOwnerRecoveryParentBridgeV1([redacted])")
    }
}

/// Matching collection-side verifier for one parent-journal bridge instance.
#[doc(hidden)]
#[derive(Clone)]
pub struct PrivateOramOwnerRecoveryParentVerifierV1 {
    identity: Arc<PrivateOramOwnerRecoveryParentBridgeIdentityV1>,
}

impl Debug for PrivateOramOwnerRecoveryParentVerifierV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateOramOwnerRecoveryParentVerifierV1([redacted])")
    }
}

/// Creates process-local matching endpoints for one mutation-journal root.
#[doc(hidden)]
pub fn new_private_oram_owner_recovery_parent_bridge_v1() -> (
    PrivateOramOwnerRecoveryParentBridgeV1,
    PrivateOramOwnerRecoveryParentVerifierV1,
) {
    let identity = Arc::new(PrivateOramOwnerRecoveryParentBridgeIdentityV1);
    (
        PrivateOramOwnerRecoveryParentBridgeV1 {
            identity: Arc::clone(&identity),
        },
        PrivateOramOwnerRecoveryParentVerifierV1 { identity },
    )
}

/// Consensus-backed disposition captured by storage before entering child recovery.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramOwnerRecoveryParentDispositionV1 {
    ObservedOldNeedsAbortDecision,
    ExactOldAbortDecided,
    ExactNew,
}

/// Structural parent values accepted only by a bridge endpoint retained inside storage.
///
/// This DTO is not authority. The adapter accepts only the lock-scoped capability minted from it.
#[doc(hidden)]
pub struct PrivateOramOwnerRecoveryParentInputV1 {
    pub projection: PrivateOramOwnerRecoveryProjectionV1,
    pub disposition: PrivateOramOwnerRecoveryParentDispositionV1,
    pub authenticated_owner_peer_id: u64,
    pub parent_descriptor_digest: String,
    pub parent_owners_prepared_record_digest: String,
    pub consensus_authority_record_digest: String,
    pub reconciliation_authority_digest: String,
}

impl Debug for PrivateOramOwnerRecoveryParentInputV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryParentInputV1")
            .field("projection", &"[redacted]")
            .field("disposition", &self.disposition)
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_owners_prepared_record_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .finish()
    }
}

type ParentRecoveryLockBrand<'lock> = PhantomData<fn(&'lock mut ()) -> &'lock mut ()>;

/// Opaque parent authority that cannot outlive the actual parent EX lock callback.
#[doc(hidden)]
pub struct PrivateOramOwnerRecoveryLiveParentV1<'lock> {
    identity: Arc<PrivateOramOwnerRecoveryParentBridgeIdentityV1>,
    input: PrivateOramOwnerRecoveryParentInputV1,
    parent_lock_lifetime: ParentRecoveryLockBrand<'lock>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl Debug for PrivateOramOwnerRecoveryLiveParentV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryLiveParentV1")
            .field("input", &self.input)
            .field("parent_lock", &"[held]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryParentBridgeV1 {
    /// Executes with an authority branded by the caller's actual parent-lock borrow.
    ///
    /// # Safety
    ///
    /// The caller must retain both endpoints privately in the exact parent mutation-journal
    /// instance, hold that journal's pinned exclusive root lock for `'lock`, and build `input`
    /// from the typed authority revalidated under that lock. Calling this with an unrelated
    /// borrow or caller-constructed parent state can authorize irreversible canonical writes.
    ///
    /// Safe downstream code cannot mint this authority:
    ///
    /// ```compile_fail,E0133
    /// use collection::{
    ///     PrivateOramOwnerRecoveryParentBridgeV1, PrivateOramOwnerRecoveryParentInputV1,
    /// };
    ///
    /// fn forge(
    ///     bridge: &PrivateOramOwnerRecoveryParentBridgeV1,
    ///     input: PrivateOramOwnerRecoveryParentInputV1,
    /// ) {
    ///     bridge.with_live_parent_v1(&(), input, |_| ());
    /// }
    /// ```
    #[doc(hidden)]
    pub unsafe fn with_live_parent_v1<'lock, T, R>(
        &self,
        parent_lock: &'lock T,
        input: PrivateOramOwnerRecoveryParentInputV1,
        action: impl FnOnce(&PrivateOramOwnerRecoveryLiveParentV1<'lock>) -> R,
    ) -> R {
        self.with_live_parent_unchecked_v1(parent_lock, input, action)
    }

    fn with_live_parent_unchecked_v1<'lock, T, R>(
        &self,
        _parent_lock: &'lock T,
        input: PrivateOramOwnerRecoveryParentInputV1,
        action: impl FnOnce(&PrivateOramOwnerRecoveryLiveParentV1<'lock>) -> R,
    ) -> R {
        let live = PrivateOramOwnerRecoveryLiveParentV1 {
            identity: Arc::clone(&self.identity),
            input,
            parent_lock_lifetime: PhantomData,
            not_send_or_sync: PhantomData,
        };
        action(&live)
    }

    #[cfg(test)]
    fn with_test_live_parent_v1<'lock, T, R>(
        &self,
        parent_lock: &'lock T,
        input: PrivateOramOwnerRecoveryParentInputV1,
        action: impl FnOnce(&PrivateOramOwnerRecoveryLiveParentV1<'lock>) -> R,
    ) -> R {
        self.with_live_parent_unchecked_v1(parent_lock, input, action)
    }
}

/// One terminalized index projected from the child token after parent root/tip revalidation.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryTerminalIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
    terminal_state_digest: String,
}

impl Debug for PrivateOramOwnerRecoveryTerminalIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryTerminalIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("terminal_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryTerminalIndexEvidenceV1 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub fn index_name(&self) -> &str {
        &self.index_name
    }

    pub fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }

    pub fn terminal_state_digest(&self) -> &str {
        &self.terminal_state_digest
    }
}

/// Opaque durable evidence retained from an exact finalized or aborted-old child pair.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryTerminalEvidenceV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    prepared_state_digest: String,
    terminal_record_digest: String,
    parent_descriptor_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    indexes: Vec<PrivateOramOwnerRecoveryTerminalIndexEvidenceV1>,
}

impl Debug for PrivateOramOwnerRecoveryTerminalEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryTerminalEvidenceV1")
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

impl PrivateOramOwnerRecoveryTerminalEvidenceV1 {
    pub const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub fn prepared_state_digest(&self) -> &str {
        &self.prepared_state_digest
    }

    pub fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub fn indexes(&self) -> &[PrivateOramOwnerRecoveryTerminalIndexEvidenceV1] {
        &self.indexes
    }
}

/// Durable child outcome. Storage exposes it only after revalidating the parent journal root/tip.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub enum PrivateOramOwnerRecoveryPairOutcomeV1 {
    ObservedOld,
    AbortedOld(PrivateOramOwnerRecoveryTerminalEvidenceV1),
    Finalized(PrivateOramOwnerRecoveryTerminalEvidenceV1),
}

impl Debug for PrivateOramOwnerRecoveryPairOutcomeV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservedOld => f.write_str("ObservedOld"),
            Self::AbortedOld(_) => f.write_str("AbortedOld([redacted])"),
            Self::Finalized(_) => f.write_str("Finalized([redacted])"),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a> {
    journal_descriptor_digest: &'a str,
    prepared_state_digest: &'a str,
    immutable_manifest_digest: &'a str,
    immutable_manifest: &'a PrivateOramImmutableManifestV2,
    immutable_index: &'a PrivateOramImmutableIndexV2,
    descriptor: &'a PrivateOramOwnerJournalIndexDescriptorV1,
    old_state: &'a PrivateOramIndexStateV2,
    new_state: &'a PrivateOramIndexStateV2,
    final_buckets: &'a PrivateOramOwnerFinalBucketBatchV1,
}

impl Debug for PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerIndexStoreInspectionAuthorityV1")
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("immutable_manifest_digest", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("kind", &self.descriptor.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_state.index_epoch)
            .field("new_epoch", &self.new_state.index_epoch)
            .field("final_bucket_count", &self.final_buckets.len())
            .finish()
    }
}

impl<'a> PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a> {
    pub(crate) fn journal_descriptor_digest(self) -> &'a str {
        self.journal_descriptor_digest
    }

    pub(crate) fn prepared_state_digest(self) -> &'a str {
        self.prepared_state_digest
    }

    pub(crate) fn immutable_manifest_digest(self) -> &'a str {
        self.immutable_manifest_digest
    }

    pub(crate) fn immutable_manifest(self) -> &'a PrivateOramImmutableManifestV2 {
        self.immutable_manifest
    }

    pub(crate) fn immutable_index(self) -> &'a PrivateOramImmutableIndexV2 {
        self.immutable_index
    }

    pub(crate) fn index_name(self) -> &'a str {
        &self.descriptor.index_name
    }

    pub(crate) fn old_state(self) -> &'a PrivateOramIndexStateV2 {
        self.old_state
    }

    pub(crate) fn new_state(self) -> &'a PrivateOramIndexStateV2 {
        self.new_state
    }

    pub(crate) fn final_bucket_refs(self) -> &'a [PrivateOramAppendBucketRefV1] {
        &self.descriptor.final_bucket_refs
    }

    pub(crate) fn final_buckets(self) -> &'a PrivateOramOwnerFinalBucketBatchV1 {
        self.final_buckets
    }

    pub(crate) fn hnsw_final_buckets(self) -> Option<&'a [qdrant_sec::PrivateHnswOramBucket]> {
        match self.final_buckets {
            PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => Some(buckets),
            PrivateOramOwnerFinalBucketBatchV1::Result(_) => None,
        }
    }

    pub(crate) fn result_final_buckets(self) -> Option<&'a [qdrant_sec::PrivateResultOramBucket]> {
        match self.final_buckets {
            PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => Some(buckets),
            PrivateOramOwnerFinalBucketBatchV1::Hnsw(_) => None,
        }
    }
}

pub(crate) struct PrivateOramOwnerExactOldStorePairV1<'hnsw, 'result> {
    hnsw: PrivateHnswOwnerExactOldStoreTokenV1<'hnsw>,
    result: PrivateResultOwnerExactOldStoreTokenV1<'result>,
}

impl Debug for PrivateOramOwnerExactOldStorePairV1<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerExactOldStorePairV1")
            .field("hnsw", &self.hnsw)
            .field("result", &self.result)
            .finish()
    }
}

impl PrivateOramOwnerExactOldStorePairV1<'_, '_> {
    pub(crate) fn terminal_index_states(&self) -> [PrivateOramOwnerJournalTerminalIndexStateV1; 2] {
        [
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: self.hnsw.index_name().to_string(),
                canonical_state_digest: self.hnsw.canonical_state_digest().to_string(),
            },
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: self.result.index_name().to_string(),
                canonical_state_digest: self.result.canonical_state_digest().to_string(),
            },
        ]
    }
}

pub(crate) struct PrivateOramOwnerExactNewStorePairV1<'hnsw, 'result> {
    hnsw: PrivateHnswOwnerExactNewStoreTokenV1<'hnsw>,
    result: PrivateResultOwnerExactNewStoreTokenV1<'result>,
}

impl Debug for PrivateOramOwnerExactNewStorePairV1<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerExactNewStorePairV1")
            .field("hnsw", &self.hnsw)
            .field("result", &self.result)
            .finish()
    }
}

impl PrivateOramOwnerExactNewStorePairV1<'_, '_> {
    pub(crate) fn terminal_index_states(&self) -> [PrivateOramOwnerJournalTerminalIndexStateV1; 2] {
        [
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: self.hnsw.index_name().to_string(),
                canonical_state_digest: self.hnsw.canonical_state_digest().to_string(),
            },
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: self.result.index_name().to_string(),
                canonical_state_digest: self.result.canonical_state_digest().to_string(),
            },
        ]
    }
}

type ChildRecoveryTransactionBrand<'child> = PhantomData<fn(&'child mut ()) -> &'child mut ()>;

struct PrivateOramOwnerRecoveryTransitionBrandV1<'parent, 'child> {
    identity: [u8; 32],
    parent_lock_lifetime: ParentRecoveryLockBrand<'parent>,
    child_lock_lifetime: ChildRecoveryTransactionBrand<'child>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

struct PrivateOramOwnerRecoveryExactOldPairPermitV1<'brand, 'parent, 'child, 'hnsw, 'result> {
    pair: PrivateOramOwnerExactOldStorePairV1<'hnsw, 'result>,
    transition: &'brand PrivateOramOwnerRecoveryTransitionBrandV1<'parent, 'child>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl PrivateOramOwnerRecoveryExactOldPairPermitV1<'_, '_, '_, '_, '_> {
    fn terminal_index_states(&self) -> [PrivateOramOwnerJournalTerminalIndexStateV1; 2] {
        let _ = self.transition.identity;
        self.pair.terminal_index_states()
    }
}

struct PrivateOramOwnerRecoveryExactNewPairPermitV1<'brand, 'parent, 'child, 'hnsw, 'result> {
    pair: PrivateOramOwnerExactNewStorePairV1<'hnsw, 'result>,
    transition: &'brand PrivateOramOwnerRecoveryTransitionBrandV1<'parent, 'child>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl PrivateOramOwnerRecoveryExactNewPairPermitV1<'_, '_, '_, '_, '_> {
    fn terminal_index_states(&self) -> [PrivateOramOwnerJournalTerminalIndexStateV1; 2] {
        let _ = self.transition.identity;
        self.pair.terminal_index_states()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateOramOwnerRecoveryDecisionV1 {
    ObserveOld,
    AbortOld,
    ReplayAbortOld,
    RollForwardAndFinalize,
    ReplayFinalized,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateOramOwnerRecoveryFaultPointV1 {
    AfterHnswPublication,
    AfterResultPublication,
}

/// Entry permit created only after the parent, HNSW, and result locks are held in order.
///
/// The child journal consumes this value through its fixed recovery entry point; no caller can
/// construct a child-first mutating callback.
pub(crate) struct PrivateOramOwnerLockedRecoveryTransactionV1<
    'resources,
    'parent_lock,
    'hnsw,
    'result,
> {
    verifier: &'resources PrivateOramOwnerRecoveryParentVerifierV1,
    parent: &'resources PrivateOramOwnerRecoveryLiveParentV1<'parent_lock>,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'resources>,
    static_pair: ValidatedStaticPair<'resources>,
    hnsw_lock: &'hnsw PrivateHnswOwnerStoreLockV1<'resources>,
    result_lock: &'result PrivateResultOwnerStoreLockV1<'resources>,
    #[cfg(test)]
    fault_point: Option<PrivateOramOwnerRecoveryFaultPointV1>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl<'resources, 'parent_lock, 'hnsw, 'result>
    PrivateOramOwnerLockedRecoveryTransactionV1<'resources, 'parent_lock, 'hnsw, 'result>
{
    #[cfg(test)]
    fn fail_at_test_checkpoint_v1(
        &self,
        checkpoint: PrivateOramOwnerRecoveryFaultPointV1,
    ) -> CollectionResult<()> {
        if self.fault_point == Some(checkpoint) {
            return Err(CollectionError::service_error(
                "injected private ORAM owner recovery checkpoint failure",
            ));
        }
        Ok(())
    }

    pub(crate) fn recover_under_child_exclusive_v1<'child>(
        self,
        binding: &PrivateOramOwnerRecoveryExclusiveBindingV1<'child>,
    ) -> CollectionResult<PrivateOramOwnerRecoveryExclusiveActionV1<'child>> {
        validate_live_parent_bridge(self.verifier, self.parent)?;
        let snapshot = binding.untrusted_snapshot_view();
        let pair = validate_child_pair_context(&self.static_pair, snapshot)?;
        validate_live_parent_child_context(self.parent, &self.static_pair, snapshot)?;
        let transition = recovery_transition_brand(
            self.parent,
            binding,
            recovery_transaction_identity(self.parent, &self.static_pair, snapshot),
        );

        // Both stores are classified before the first canonical mutation. The decision below is
        // the complete cross-store phase lattice for v1 paired recovery.
        let hnsw_phase = self.hnsw_lock.classify_owner_recovery_phase_v1(
            pair.hnsw,
            self.resources.hnsw_max_ciphertext_bytes,
            self.resources.hnsw_manifest_validation,
        )?;
        let result_progress = self.result_lock.classify_owner_recovery_progress_v1(
            pair.result,
            self.resources.result_max_ciphertext_bytes,
            self.resources.result_manifest_validation,
        )?;
        let decision = recovery_decision(
            self.parent.input.disposition,
            binding.state(),
            hnsw_phase,
            result_progress,
        )?;

        match decision {
            PrivateOramOwnerRecoveryDecisionV1::ObserveOld => {
                let permit = self.verify_exact_old_pair(pair, &transition)?;
                let _ = permit.terminal_index_states();
                Ok(binding.no_terminal_action())
            }
            PrivateOramOwnerRecoveryDecisionV1::AbortOld
            | PrivateOramOwnerRecoveryDecisionV1::ReplayAbortOld => {
                let permit = self.verify_exact_old_pair(pair, &transition)?;
                let canonical = permit.terminal_index_states();
                binding
                    .abort_old_recovery_store_pair_action_v1(
                        &snapshot.descriptor.descriptor_digest,
                        &self.parent.input.parent_descriptor_digest,
                        self.parent.input.authenticated_owner_peer_id,
                        &self.parent.input.consensus_authority_record_digest,
                        &self.parent.input.reconciliation_authority_digest,
                        &canonical,
                    )
                    .map_err(|_| invalid_authority())
            }
            PrivateOramOwnerRecoveryDecisionV1::RollForwardAndFinalize => {
                let hnsw = self.hnsw_lock.resume_owner_recovery_to_exact_new_v1(
                    pair.hnsw,
                    self.resources.hnsw_max_ciphertext_bytes,
                    self.resources.hnsw_manifest_validation,
                )?;
                #[cfg(test)]
                self.fail_at_test_checkpoint_v1(
                    PrivateOramOwnerRecoveryFaultPointV1::AfterHnswPublication,
                )?;
                let result = self.result_lock.resume_owner_recovery_to_exact_new_v1(
                    pair.result,
                    self.resources.result_max_ciphertext_bytes,
                    self.resources.result_manifest_validation,
                )?;
                #[cfg(test)]
                self.fail_at_test_checkpoint_v1(
                    PrivateOramOwnerRecoveryFaultPointV1::AfterResultPublication,
                )?;
                let permit = PrivateOramOwnerRecoveryExactNewPairPermitV1 {
                    pair: PrivateOramOwnerExactNewStorePairV1 { hnsw, result },
                    transition: &transition,
                    not_send_or_sync: PhantomData,
                };
                let canonical = permit.terminal_index_states();
                binding
                    .finalize_recovery_store_pair_action_v1(
                        &snapshot.descriptor.descriptor_digest,
                        &self.parent.input.parent_descriptor_digest,
                        self.parent.input.authenticated_owner_peer_id,
                        &self.parent.input.consensus_authority_record_digest,
                        &self.parent.input.reconciliation_authority_digest,
                        &canonical,
                    )
                    .map_err(|_| invalid_authority())
            }
            PrivateOramOwnerRecoveryDecisionV1::ReplayFinalized => {
                let hnsw = self.hnsw_lock.verify_owner_exact_new_v1(
                    pair.hnsw,
                    self.resources.hnsw_max_ciphertext_bytes,
                    self.resources.hnsw_manifest_validation,
                )?;
                let result = self.result_lock.verify_owner_exact_new_v1(
                    pair.result,
                    self.resources.result_max_ciphertext_bytes,
                    self.resources.result_manifest_validation,
                )?;
                let permit = PrivateOramOwnerRecoveryExactNewPairPermitV1 {
                    pair: PrivateOramOwnerExactNewStorePairV1 { hnsw, result },
                    transition: &transition,
                    not_send_or_sync: PhantomData,
                };
                let canonical = permit.terminal_index_states();
                binding
                    .finalize_recovery_store_pair_action_v1(
                        &snapshot.descriptor.descriptor_digest,
                        &self.parent.input.parent_descriptor_digest,
                        self.parent.input.authenticated_owner_peer_id,
                        &self.parent.input.consensus_authority_record_digest,
                        &self.parent.input.reconciliation_authority_digest,
                        &canonical,
                    )
                    .map_err(|_| invalid_authority())
            }
        }
    }

    fn verify_exact_old_pair<'brand, 'child>(
        &'brand self,
        pair: ValidatedStorePair<'resources>,
        transition: &'brand PrivateOramOwnerRecoveryTransitionBrandV1<'parent_lock, 'child>,
    ) -> CollectionResult<
        PrivateOramOwnerRecoveryExactOldPairPermitV1<'brand, 'parent_lock, 'child, 'hnsw, 'result>,
    > {
        let hnsw = self.hnsw_lock.verify_owner_exact_old_v1(
            pair.hnsw,
            self.resources.hnsw_max_ciphertext_bytes,
            self.resources.hnsw_manifest_validation,
        )?;
        let result = self.result_lock.verify_owner_exact_old_v1(
            pair.result,
            self.resources.result_max_ciphertext_bytes,
            self.resources.result_manifest_validation,
        )?;
        Ok(PrivateOramOwnerRecoveryExactOldPairPermitV1 {
            pair: PrivateOramOwnerExactOldStorePairV1 { hnsw, result },
            transition,
            not_send_or_sync: PhantomData,
        })
    }
}

/// Executes the full child transaction while storage still holds the matching parent EX lock.
#[doc(hidden)]
pub fn recover_private_oram_owner_store_pair_v1(
    verifier: &PrivateOramOwnerRecoveryParentVerifierV1,
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
) -> CollectionResult<PrivateOramOwnerRecoveryPairOutcomeV1> {
    recover_private_oram_owner_store_pair_then_v1(verifier, parent, resources, Ok)
}

/// Executes a continuation after the child terminal is durable while every recovery lock remains
/// held in canonical parent -> HNSW -> result -> child order.
#[doc(hidden)]
pub fn recover_private_oram_owner_store_pair_then_v1<R>(
    verifier: &PrivateOramOwnerRecoveryParentVerifierV1,
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    continuation: impl FnOnce(PrivateOramOwnerRecoveryPairOutcomeV1) -> CollectionResult<R>,
) -> CollectionResult<R> {
    recover_private_oram_owner_store_pair_then_inner_v1(
        verifier,
        parent,
        resources,
        #[cfg(test)]
        None,
        continuation,
    )
}

#[cfg(test)]
fn recover_private_oram_owner_store_pair_at_fault_v1(
    verifier: &PrivateOramOwnerRecoveryParentVerifierV1,
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    fault_point: PrivateOramOwnerRecoveryFaultPointV1,
) -> CollectionResult<PrivateOramOwnerRecoveryPairOutcomeV1> {
    recover_private_oram_owner_store_pair_then_inner_v1(
        verifier,
        parent,
        resources,
        Some(fault_point),
        Ok,
    )
}

fn recover_private_oram_owner_store_pair_then_inner_v1<R>(
    verifier: &PrivateOramOwnerRecoveryParentVerifierV1,
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    #[cfg(test)] fault_point: Option<PrivateOramOwnerRecoveryFaultPointV1>,
    continuation: impl FnOnce(PrivateOramOwnerRecoveryPairOutcomeV1) -> CollectionResult<R>,
) -> CollectionResult<R> {
    validate_live_parent_bridge(verifier, parent)?;
    let static_pair = validate_static_pair_context(
        resources.owner_journal,
        resources.hnsw_store,
        resources.result_store,
        resources.immutable_manifest,
        resources.mutation_bundle,
        resources.signature_verification,
    )?;
    resources.hnsw_store.with_owner_store_lock_v1(|hnsw_lock| {
        resources
            .result_store
            .with_owner_store_lock_v1(|result_lock| {
                let transaction = PrivateOramOwnerLockedRecoveryTransactionV1 {
                    verifier,
                    parent,
                    resources,
                    static_pair,
                    hnsw_lock,
                    result_lock,
                    #[cfg(test)]
                    fault_point,
                    not_send_or_sync: PhantomData,
                };
                resources
                    .owner_journal
                    .recover_revalidated_store_pair_exclusive_then_v1(
                        &parent.input.projection,
                        transaction,
                        |outcome| continuation(recovery_pair_outcome(outcome)),
                    )
            })
    })
}

fn recovery_pair_outcome(
    outcome: PrivateOramOwnerRecoveryExclusiveOutcomeV1,
) -> PrivateOramOwnerRecoveryPairOutcomeV1 {
    match outcome {
        PrivateOramOwnerRecoveryExclusiveOutcomeV1::NoTerminal => {
            PrivateOramOwnerRecoveryPairOutcomeV1::ObservedOld
        }
        PrivateOramOwnerRecoveryExclusiveOutcomeV1::Finalized(token) => {
            PrivateOramOwnerRecoveryPairOutcomeV1::Finalized(finalized_terminal_evidence(&token))
        }
        PrivateOramOwnerRecoveryExclusiveOutcomeV1::AbortedOld(token) => {
            PrivateOramOwnerRecoveryPairOutcomeV1::AbortedOld(aborted_terminal_evidence(&token))
        }
    }
}

fn finalized_terminal_evidence(
    token: &PrivateOramDurableOwnerFinalizedTokenV1,
) -> PrivateOramOwnerRecoveryTerminalEvidenceV1 {
    PrivateOramOwnerRecoveryTerminalEvidenceV1 {
        owner_peer_id: token.owner_peer_id(),
        journal_descriptor_digest: token.journal_descriptor_digest().to_string(),
        prepared_state_digest: token.prepared_state_digest().to_string(),
        terminal_record_digest: token.terminal_record_digest().to_string(),
        parent_descriptor_digest: token.parent_descriptor_digest().to_string(),
        consensus_authority_record_digest: token.consensus_authority_record_digest().to_string(),
        reconciliation_authority_digest: token.reconciliation_authority_digest().to_string(),
        indexes: token
            .indexes()
            .iter()
            .map(|index| PrivateOramOwnerRecoveryTerminalIndexEvidenceV1 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                prepared_journal_digest: index.prepared_journal_digest().to_string(),
                terminal_state_digest: index.finalized_state_digest().to_string(),
            })
            .collect(),
    }
}

fn aborted_terminal_evidence(
    token: &PrivateOramDurableOwnerAbortedOldTokenV1,
) -> PrivateOramOwnerRecoveryTerminalEvidenceV1 {
    PrivateOramOwnerRecoveryTerminalEvidenceV1 {
        owner_peer_id: token.owner_peer_id(),
        journal_descriptor_digest: token.journal_descriptor_digest().to_string(),
        prepared_state_digest: token.prepared_state_digest().to_string(),
        terminal_record_digest: token.terminal_record_digest().to_string(),
        parent_descriptor_digest: token.parent_descriptor_digest().to_string(),
        consensus_authority_record_digest: token.consensus_authority_record_digest().to_string(),
        reconciliation_authority_digest: token.reconciliation_authority_digest().to_string(),
        indexes: token
            .indexes()
            .iter()
            .map(|index| PrivateOramOwnerRecoveryTerminalIndexEvidenceV1 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                prepared_journal_digest: index.prepared_journal_digest().to_string(),
                terminal_state_digest: index.aborted_old_state_digest().to_string(),
            })
            .collect(),
    }
}

fn validate_live_parent_bridge(
    verifier: &PrivateOramOwnerRecoveryParentVerifierV1,
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
) -> CollectionResult<()> {
    if !Arc::ptr_eq(&verifier.identity, &parent.identity) {
        return Err(invalid_authority());
    }
    for digest in [
        parent.input.parent_descriptor_digest.as_str(),
        parent.input.parent_owners_prepared_record_digest.as_str(),
        parent.input.consensus_authority_record_digest.as_str(),
        parent.input.reconciliation_authority_digest.as_str(),
    ] {
        let decoded = data_encoding::BASE64URL_NOPAD
            .decode(digest.as_bytes())
            .map_err(|_| invalid_authority())?;
        if decoded.len() != 32 {
            return Err(invalid_authority());
        }
    }
    Ok(())
}

fn validate_live_parent_child_context(
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
    static_pair: &ValidatedStaticPair<'_>,
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
) -> CollectionResult<()> {
    if snapshot.descriptor.parent_descriptor_digest != parent.input.parent_descriptor_digest
        || snapshot.descriptor.owner_peer_id != parent.input.authenticated_owner_peer_id
        || snapshot.descriptor.signed_mutation_digest != static_pair.mutation_digest
    {
        return Err(invalid_authority());
    }
    Ok(())
}

fn recovery_decision(
    parent: PrivateOramOwnerRecoveryParentDispositionV1,
    child: PrivateOramOwnerRecoveryExclusiveStateV1,
    hnsw: PrivateHnswOwnerRecoveryPhaseV1,
    result: PrivateResultOwnerRecoveryProgressV1,
) -> CollectionResult<PrivateOramOwnerRecoveryDecisionV1> {
    use PrivateOramOwnerRecoveryDecisionV1 as Decision;
    use PrivateOramOwnerRecoveryExclusiveStateV1 as Child;
    use PrivateOramOwnerRecoveryParentDispositionV1 as Parent;

    match (parent, child) {
        (Parent::ObservedOldNeedsAbortDecision, Child::Prepared)
            if hnsw == PrivateHnswOwnerRecoveryPhaseV1::S0
                && result == PrivateResultOwnerRecoveryProgressV1::S0 =>
        {
            Ok(Decision::ObserveOld)
        }
        (Parent::ExactOldAbortDecided, Child::Prepared)
            if hnsw == PrivateHnswOwnerRecoveryPhaseV1::S0
                && result == PrivateResultOwnerRecoveryProgressV1::S0 =>
        {
            Ok(Decision::AbortOld)
        }
        (Parent::ExactOldAbortDecided, Child::AbortedOldReplay)
            if hnsw == PrivateHnswOwnerRecoveryPhaseV1::S0
                && result == PrivateResultOwnerRecoveryProgressV1::S0 =>
        {
            Ok(Decision::ReplayAbortOld)
        }
        (Parent::ExactNew, Child::Prepared) if prepared_exact_new_lattice(hnsw, result) => {
            Ok(Decision::RollForwardAndFinalize)
        }
        (Parent::ExactNew, Child::FinalizedReplay)
            if hnsw == PrivateHnswOwnerRecoveryPhaseV1::S4
                && result == PrivateResultOwnerRecoveryProgressV1::S4 =>
        {
            Ok(Decision::ReplayFinalized)
        }
        _ => Err(invalid_authority()),
    }
}

fn prepared_exact_new_lattice(
    hnsw: PrivateHnswOwnerRecoveryPhaseV1,
    result: PrivateResultOwnerRecoveryProgressV1,
) -> bool {
    match hnsw {
        PrivateHnswOwnerRecoveryPhaseV1::S0
        | PrivateHnswOwnerRecoveryPhaseV1::S1 { .. }
        | PrivateHnswOwnerRecoveryPhaseV1::S2
        | PrivateHnswOwnerRecoveryPhaseV1::S3 => result == PrivateResultOwnerRecoveryProgressV1::S0,
        PrivateHnswOwnerRecoveryPhaseV1::S4 => true,
    }
}

fn recovery_transaction_identity(
    parent: &PrivateOramOwnerRecoveryLiveParentV1<'_>,
    static_pair: &ValidatedStaticPair<'_>,
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    push_recovery_identity_field(&mut hasher, RECOVERY_TRANSACTION_IDENTITY_DOMAIN);
    hasher.update(parent.input.authenticated_owner_peer_id.to_be_bytes());
    hasher.update([match parent.input.disposition {
        PrivateOramOwnerRecoveryParentDispositionV1::ObservedOldNeedsAbortDecision => 1,
        PrivateOramOwnerRecoveryParentDispositionV1::ExactOldAbortDecided => 2,
        PrivateOramOwnerRecoveryParentDispositionV1::ExactNew => 3,
    }]);
    for field in [
        parent.input.parent_descriptor_digest.as_bytes(),
        parent.input.parent_owners_prepared_record_digest.as_bytes(),
        parent.input.consensus_authority_record_digest.as_bytes(),
        parent.input.reconciliation_authority_digest.as_bytes(),
        static_pair.mutation_digest.as_bytes(),
        snapshot.descriptor.descriptor_digest.as_bytes(),
        snapshot.state.state_digest.as_bytes(),
    ] {
        push_recovery_identity_field(&mut hasher, field);
    }
    hasher.finalize().into()
}

fn recovery_transition_brand<'parent, 'child>(
    _parent: &PrivateOramOwnerRecoveryLiveParentV1<'parent>,
    _binding: &PrivateOramOwnerRecoveryExclusiveBindingV1<'child>,
    identity: [u8; 32],
) -> PrivateOramOwnerRecoveryTransitionBrandV1<'parent, 'child> {
    PrivateOramOwnerRecoveryTransitionBrandV1 {
        identity,
        parent_lock_lifetime: PhantomData,
        child_lock_lifetime: PhantomData,
        not_send_or_sync: PhantomData,
    }
}

fn push_recovery_identity_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub(crate) fn with_private_oram_owner_exact_old_store_pair_v1<R>(
    context: PrivateOramOwnerStorePairContextV1<'_>,
    action: impl for<'hnsw, 'result> FnOnce(
        PrivateOramOwnerExactOldStorePairV1<'hnsw, 'result>,
    ) -> CollectionResult<R>,
) -> CollectionResult<R> {
    let static_pair = validate_static_pair_context(
        context.owner_journal,
        context.hnsw_store,
        context.result_store,
        context.immutable_manifest,
        context.mutation_bundle,
        context.signature_verification,
    )?;
    let binding = context
        .owner_journal
        .bind_live_prepared_store_adapter_v1(context.prepared_token)
        .map_err(|_| invalid_authority())?;
    let pair = validate_child_pair_context(&static_pair, binding.snapshot())?;
    context.hnsw_store.with_owner_exact_old_store_v1(
        pair.hnsw,
        context.hnsw_max_ciphertext_bytes,
        context.hnsw_manifest_validation,
        |hnsw| {
            context.result_store.with_owner_exact_old_store_v1(
                pair.result,
                context.result_max_ciphertext_bytes,
                context.result_manifest_validation,
                |result| {
                    context
                        .owner_journal
                        .with_live_prepared_store_binding_v1(
                            context.prepared_token,
                            |live_binding| {
                                if live_binding != &binding {
                                    return Err(invalid_authority());
                                }
                                action(PrivateOramOwnerExactOldStorePairV1 { hnsw, result })
                            },
                        )
                        .map_err(|_| invalid_authority())?
                },
            )
        },
    )
}

pub(crate) fn with_private_oram_owner_exact_new_store_pair_v1<R>(
    context: PrivateOramOwnerStorePairContextV1<'_>,
    action: impl for<'hnsw, 'result> FnOnce(
        PrivateOramOwnerExactNewStorePairV1<'hnsw, 'result>,
    ) -> CollectionResult<R>,
) -> CollectionResult<R> {
    let static_pair = validate_static_pair_context(
        context.owner_journal,
        context.hnsw_store,
        context.result_store,
        context.immutable_manifest,
        context.mutation_bundle,
        context.signature_verification,
    )?;
    let binding = context
        .owner_journal
        .bind_live_prepared_store_adapter_v1(context.prepared_token)
        .map_err(|_| invalid_authority())?;
    let pair = validate_child_pair_context(&static_pair, binding.snapshot())?;
    context.hnsw_store.with_owner_exact_new_store_v1(
        pair.hnsw,
        context.hnsw_max_ciphertext_bytes,
        context.hnsw_manifest_validation,
        |hnsw| {
            context.result_store.with_owner_exact_new_store_v1(
                pair.result,
                context.result_max_ciphertext_bytes,
                context.result_manifest_validation,
                |result| {
                    context
                        .owner_journal
                        .with_live_prepared_store_binding_v1(
                            context.prepared_token,
                            |live_binding| {
                                if live_binding != &binding {
                                    return Err(invalid_authority());
                                }
                                action(PrivateOramOwnerExactNewStorePairV1 { hnsw, result })
                            },
                        )
                        .map_err(|_| invalid_authority())?
                },
            )
        },
    )
}

/// Classifies the two canonical stores while holding HNSW, result, and child locks in that order.
///
/// The returned disposition is an inert observation. It does not authorize roll-forward, abort,
/// finalize, or any other mutation.
#[doc(hidden)]
pub fn classify_private_oram_owner_recovery_store_pair_v1(
    projection: &PrivateOramOwnerRecoveryProjectionV1,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
) -> CollectionResult<PrivateOramOwnerRecoveryStoreDispositionV1> {
    let static_pair = validate_static_pair_context(
        resources.owner_journal,
        resources.hnsw_store,
        resources.result_store,
        resources.immutable_manifest,
        resources.mutation_bundle,
        resources.signature_verification,
    )?;
    resources.hnsw_store.with_owner_store_lock_v1(|hnsw_lock| {
        resources
            .result_store
            .with_owner_store_lock_v1(|result_lock| {
                resources
                    .owner_journal
                    .with_revalidated_recovery_prepared_v1(projection, |binding| {
                        let pair = validate_child_pair_context(
                            &static_pair,
                            binding.untrusted_snapshot_view(),
                        )?;
                        let hnsw = hnsw_lock.classify_owner_state_v1(
                            pair.hnsw,
                            resources.hnsw_max_ciphertext_bytes,
                            resources.hnsw_manifest_validation,
                        )?;
                        let result = result_lock.classify_owner_state_v1(
                            pair.result,
                            resources.result_max_ciphertext_bytes,
                            resources.result_manifest_validation,
                        )?;
                        Ok(recovery_store_disposition(hnsw, result))
                    })
                    .map_err(|_| invalid_authority())?
            })
    })
}

fn recovery_store_disposition(
    hnsw: PrivateHnswOwnerStoreObservationV1<'_>,
    result: PrivateResultOwnerStoreObservationV1<'_>,
) -> PrivateOramOwnerRecoveryStoreDispositionV1 {
    match (hnsw, result) {
        (
            PrivateHnswOwnerStoreObservationV1::Old(_),
            PrivateResultOwnerStoreObservationV1::Old(_),
        ) => PrivateOramOwnerRecoveryStoreDispositionV1::AllOld,
        (
            PrivateHnswOwnerStoreObservationV1::New(_),
            PrivateResultOwnerStoreObservationV1::New(_),
        ) => PrivateOramOwnerRecoveryStoreDispositionV1::AllNew,
        (
            PrivateHnswOwnerStoreObservationV1::New(_),
            PrivateResultOwnerStoreObservationV1::Old(_),
        ) => PrivateOramOwnerRecoveryStoreDispositionV1::PartialNew,
        _ => PrivateOramOwnerRecoveryStoreDispositionV1::ThirdState,
    }
}

struct ValidatedStorePair<'a> {
    hnsw: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a>,
    result: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a>,
}

struct ValidatedStaticPair<'a> {
    manifest: &'a PrivateOramImmutableManifestV2,
    mutation: &'a qdrant_sec::PrivateOramAppendMutationV1,
    mutation_digest: String,
}

fn validate_static_pair_context<'a>(
    owner_journal: &PrivateOramOwnerJournal,
    hnsw_store: &PrivateHnswOramStore,
    result_store: &PrivateResultOramStore,
    immutable_manifest: &'a PrivateOramImmutableManifestBundleV2,
    mutation_bundle: &'a PrivateOramAppendMutationBundleV1,
    signature_verification: PrivateOramSignatureVerification<'a>,
) -> CollectionResult<ValidatedStaticPair<'a>> {
    validate_pair_store_paths(owner_journal, hnsw_store, result_store)?;
    let manifest = &immutable_manifest.manifest;
    let mutation = &mutation_bundle.mutation;
    validate_private_oram_immutable_manifest_v2_shape(manifest).map_err(|_| invalid_authority())?;
    validate_private_oram_immutable_manifest_v2_signature(
        manifest,
        Some(&immutable_manifest.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;
    validate_private_oram_append_mutation_v1_shape(mutation).map_err(|_| invalid_authority())?;
    validate_private_oram_append_mutation_v1_signature(
        mutation,
        Some(&mutation_bundle.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;
    validate_private_oram_signed_state_v2_signature(
        &mutation.old_state.state,
        Some(&mutation.old_state.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;
    validate_private_oram_signed_state_v2_signature(
        &mutation.new_state.state,
        Some(&mutation.new_state.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;

    let immutable_manifest_digest =
        private_oram_immutable_manifest_v2_digest(manifest).map_err(|_| invalid_authority())?;
    let mutation_digest =
        private_oram_append_mutation_v1_digest(mutation).map_err(|_| invalid_authority())?;
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    if immutable_manifest_digest != mutation.manifest_digest
        || old.manifest_digest != immutable_manifest_digest
        || new.manifest_digest != immutable_manifest_digest
        || manifest.collection_id != mutation.collection_id
        || old.collection_id != mutation.collection_id
        || new.collection_id != mutation.collection_id
        || mutation.layout_generation != old.layout_generation
        || mutation.layout_generation != new.layout_generation
        || manifest.owner_signing_key_id != mutation.owner_signing_key_id
        || old.owner_signing_key_id != mutation.owner_signing_key_id
        || new.owner_signing_key_id != mutation.owner_signing_key_id
        || manifest.indexes.len() != 2
        || old.indexes.len() != 2
        || new.indexes.len() != 2
        || mutation.writebacks.len() != 2
        || manifest.indexes[0].kind() != PrivateOramIndexKindV2::Hnsw
        || manifest.indexes[1].kind() != PrivateOramIndexKindV2::Result
        || old.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || old.indexes[1].kind != PrivateOramIndexKindV2::Result
        || new.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || new.indexes[1].kind != PrivateOramIndexKindV2::Result
        || mutation.writebacks[0].kind != PrivateOramIndexKindV2::Hnsw
        || mutation.writebacks[1].kind != PrivateOramIndexKindV2::Result
    {
        return Err(invalid_authority());
    }

    Ok(ValidatedStaticPair {
        manifest,
        mutation,
        mutation_digest,
    })
}

fn validate_child_pair_context<'a>(
    static_pair: &'a ValidatedStaticPair<'_>,
    snapshot: &'a PrivateOramOwnerJournalSnapshotV1,
) -> CollectionResult<ValidatedStorePair<'a>> {
    // The live Prepared token or recovery rebind is the inductive authority for the full
    // owner-prepare validation. Store inspection inputs are derived only from that exact child.
    let manifest = static_pair.manifest;
    let mutation = static_pair.mutation;
    let descriptor = &snapshot.descriptor;
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    if descriptor.collection_id != mutation.collection_id
        || descriptor.mutation_id != mutation.mutation_id
        || descriptor.signed_mutation_digest != static_pair.mutation_digest
        || descriptor.writer_lease_digest != mutation.writer_lease_digest
        || descriptor.writer_fence != mutation.writer_fence
        || descriptor.indexes.len() != 2
        || snapshot.final_buckets.len() != 2
    {
        return Err(invalid_authority());
    }

    let mut authorities = descriptor
        .indexes
        .iter()
        .zip(&snapshot.final_buckets)
        .zip(&manifest.indexes)
        .zip(&old.indexes)
        .zip(&new.indexes)
        .zip(&mutation.writebacks)
        .map(
            |(
                ((((descriptor, final_buckets), immutable_index), old_state), new_state),
                writeback,
            )| {
                if descriptor.kind != immutable_index.kind()
                    || descriptor.kind != old_state.kind
                    || descriptor.kind != new_state.kind
                    || descriptor.kind != writeback.kind
                    || descriptor.kind != final_buckets.buckets.kind()
                    || descriptor.index_name != immutable_index.index_name
                    || descriptor.index_name != old_state.index_name
                    || descriptor.index_name != new_state.index_name
                    || descriptor.index_name != writeback.index_name
                    || descriptor.index_name != final_buckets.index_name
                    || descriptor.old_epoch != old_state.index_epoch
                    || descriptor.new_epoch != new_state.index_epoch
                    || descriptor.old_root_hash != old_state.root_hash
                    || descriptor.new_root_hash != new_state.root_hash
                    || descriptor.writeback_digest != new_state.last_writeback_digest
                    || descriptor.read_path_count != writeback.read_path_count
                    || descriptor.read_transcript_digest != writeback.read_transcript_digest
                {
                    return Err(invalid_authority());
                }
                Ok(PrivateOramOwnerIndexStoreInspectionAuthorityV1 {
                    journal_descriptor_digest: &snapshot.descriptor.descriptor_digest,
                    prepared_state_digest: &snapshot.state.state_digest,
                    immutable_manifest_digest: &mutation.manifest_digest,
                    immutable_manifest: manifest,
                    immutable_index,
                    descriptor,
                    old_state,
                    new_state,
                    final_buckets: &final_buckets.buckets,
                })
            },
        )
        .collect::<CollectionResult<Vec<_>>>()?;
    let result = authorities.pop().ok_or_else(invalid_authority)?;
    let hnsw = authorities.pop().ok_or_else(invalid_authority)?;
    if !authorities.is_empty()
        || hnsw.old_state.kind != PrivateOramIndexKindV2::Hnsw
        || result.old_state.kind != PrivateOramIndexKindV2::Result
    {
        return Err(invalid_authority());
    }
    Ok(ValidatedStorePair { hnsw, result })
}

fn validate_pair_store_paths(
    owner_journal: &PrivateOramOwnerJournal,
    hnsw_store: &PrivateHnswOramStore,
    result_store: &PrivateResultOramStore,
) -> CollectionResult<()> {
    let expected_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());
    let collection_path = hnsw_store
        .root_path()
        .parent()
        .and_then(|private_hnsw_root| private_hnsw_root.parent())
        .ok_or_else(invalid_authority)?;
    let expected_result = PrivateResultOramStore::new(collection_path);
    if owner_journal.root_path() != expected_journal.root_path()
        || result_store.root_path() != expected_result.root_path()
    {
        return Err(invalid_authority());
    }
    Ok(())
}

fn invalid_authority() -> CollectionError {
    CollectionError::bad_request("private ORAM paired owner store authority is invalid")
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        DistanceKind, FixedBudgetParams, OramKind, OramParams,
        PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_HNSW_ORAM_BINDING,
        PRIVATE_HNSW_ORAM_V2_BINDING, PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
        PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        PRIVATE_RESULT_ORAM_BINDING, PRIVATE_RESULT_ORAM_V2_BINDING, PrivateHnswBucketAeadContext,
        PrivateHnswManifestValidationContext, PrivateHnswOramBucket, PrivateHnswOramManifest,
        PrivateHnswOramSignature, PrivateHnswOramUploadBundle, PrivateHnswParams,
        PrivateHnswSignatureVerification, PrivateHnswVectorEncoding,
        PrivateOramAppendIndexWritebackV1, PrivateOramAppendMutationV1,
        PrivateOramAppendWritebackDigestInput, PrivateOramImmutableIndexParamsV2,
        PrivateOramIndexCapacityV2, PrivateOramPointOperationKindV1, PrivateOramSignedStateV2,
        PrivateResultOramBucket, PrivateResultOramBucketCommitmentContext,
        PrivateResultOramManifest, PrivateResultOramManifestValidationContext,
        PrivateResultOramSignature, PrivateResultOramSignatureVerification,
        PrivateResultOramUploadBundle, ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
        VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, package_private_oram_append_mutation_v1,
        package_private_oram_immutable_manifest_v2, package_private_oram_signed_state_v2,
        private_hnsw_bucket_commitment, private_hnsw_oram_bucket_ciphertext_bytes,
        private_oram_append_writeback_v1_digest, private_oram_immutable_manifest_v2_digest,
        private_oram_no_server_point_record_v1_digest, private_result_oram_bucket_ciphertext_bytes,
        private_result_oram_bucket_commitment, sign_private_hnsw_oram_manifest,
        sign_private_result_oram_manifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::private_hnsw_oram_store::PrivateHnswOramEpochState;
    use crate::private_oram_owner_journal::{
        PrivateOramOwnerFinalBucketBatchV1, PrivateOramOwnerFinalBucketIndexV1,
        PrivateOramOwnerJournalError, PrivateOramOwnerJournalPhaseV1,
        PrivateOramOwnerRecoveryIndexProjectionInputV1, PrivateOramOwnerRecoveryIndexProjectionV1,
        PrivateOramOwnerRecoveryProjectionV1,
    };
    use crate::private_result_oram_store::PrivateResultOramEpochState;

    const COLLECTION_ID: &str = "collection-uuid-1";
    const HNSW_INDEX: &str = "text";
    const RESULT_INDEX: &str = "private-payload";
    const HNSW_KEY: &str = "tenant-a/vector-rk";
    const RESULT_KEY: &str = "tenant-a/result-rk";
    const OWNER_KEY: &str = "tenant-a/private-oram-owner-v2";

    static_assertions::assert_not_impl_any!(
        PrivateOramOwnerRecoveryLiveParentV1<'static>: Send, Sync, Clone
    );
    static_assertions::assert_not_impl_any!(
        PrivateOramOwnerLockedRecoveryTransactionV1<'static, 'static, 'static, 'static>:
            Send,
            Sync,
            Clone
    );

    struct PairFixture {
        _temp: TempDir,
        public_key: Vec<u8>,
        immutable_manifest: PrivateOramImmutableManifestBundleV2,
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        hnsw_store: PrivateHnswOramStore,
        result_store: PrivateResultOramStore,
        owner_journal: PrivateOramOwnerJournal,
        prepared_token: PrivateOramDurableOwnerPreparedTokenV1,
        hnsw_final: Vec<PrivateHnswOramBucket>,
        result_final: Vec<PrivateResultOramBucket>,
    }

    fn digest(marker: u8) -> String {
        BASE64URL_NOPAD.encode(&[marker; 32])
    }

    fn oram() -> OramParams {
        OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 2,
        }
    }

    fn capacity() -> PrivateOramIndexCapacityV2 {
        PrivateOramIndexCapacityV2 {
            bucket_count: 3,
            logical_capacity: 5,
            reserved_physical_slots: 1,
            max_client_stash_blocks: 1,
            fixed_append_read_path_count: 4,
            fixed_append_write_bucket_count: 8,
        }
    }

    fn ciphertext(size: usize, marker: u8) -> (String, String) {
        let mut bytes = vec![marker; size];
        bytes[0] = 1;
        (
            BASE64URL_NOPAD.encode(&bytes),
            BASE64URL_NOPAD.encode(Sha256::digest(&bytes).as_ref()),
        )
    }

    fn hnsw_bucket(
        manifest: &PrivateHnswOramManifest,
        bucket_id: u64,
        epoch: u64,
        marker: u8,
    ) -> PrivateHnswOramBucket {
        let (ciphertext, ciphertext_sha256) = ciphertext(
            private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            marker,
        );
        let bucket_commitment = private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch: epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn result_bucket(
        manifest: &PrivateResultOramManifest,
        bucket_id: u64,
        epoch: u64,
        marker: u8,
    ) -> PrivateResultOramBucket {
        let (ciphertext, ciphertext_sha256) = ciphertext(
            private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            marker,
        );
        let bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch: epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn hnsw_ref(bucket: &PrivateHnswOramBucket) -> PrivateOramAppendBucketRefV1 {
        PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        }
    }

    fn result_ref(bucket: &PrivateResultOramBucket) -> PrivateOramAppendBucketRefV1 {
        PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        }
    }

    fn repeated_path_refs(
        final_refs: &[PrivateOramAppendBucketRefV1],
    ) -> Vec<PrivateOramAppendBucketRefV1> {
        [0, 1, 0, 2, 0, 1, 0, 2]
            .into_iter()
            .map(|index| final_refs[index].clone())
            .collect()
    }

    fn pair_fixture() -> PairFixture {
        pair_fixture_with_immutable_params(2, RESULT_KEY)
    }

    fn pair_fixture_with_immutable_dim(immutable_dim: u32) -> PairFixture {
        pair_fixture_with_immutable_params(immutable_dim, RESULT_KEY)
    }

    fn pair_fixture_with_immutable_params(
        immutable_dim: u32,
        immutable_result_key: &str,
    ) -> PairFixture {
        let temp = TempDir::new().unwrap();
        let collection_path = temp.path().join("collection");
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let hnsw_store = PrivateHnswOramStore::new(&collection_path, HNSW_INDEX).unwrap();
        let result_store = PrivateResultOramStore::new(&collection_path);
        let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());

        let hnsw_params = PrivateHnswParams {
            m: 1,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 2,
        };
        let fixed_budget = FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 2,
            base_layer_steps: 4,
            paths_per_round: 2,
            fixed_result_k: 1,
        };
        let mut hnsw_manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: COLLECTION_ID.to_string(),
            vector_name: HNSW_INDEX.to_string(),
            key_id: HNSW_KEY.to_string(),
            rk_id: HNSW_KEY.to_string(),
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: hnsw_params.clone(),
            oram: oram(),
            fixed_budget: fixed_budget.clone(),
            index_epoch: 11,
            root_hash: digest(1),
            bucket_count: 3,
            logical_node_count: 2,
            dummy_node_count: 3,
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let hnsw_buckets = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 11, 10 + bucket_id as u8))
            .collect::<Vec<_>>();
        hnsw_manifest.root_hash = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let hnsw_signature: PrivateHnswOramSignature =
            sign_private_hnsw_oram_manifest(&key_pair, &hnsw_manifest).unwrap();
        hnsw_store
            .write_initial_upload_bundle_with_signature(
                &PrivateHnswOramUploadBundle {
                    manifest: hnsw_manifest.clone(),
                    manifest_signature: hnsw_signature,
                    buckets: hnsw_buckets,
                },
                4096,
                PrivateHnswManifestValidationContext {
                    expected_collection_id: COLLECTION_ID,
                    expected_vector_name: HNSW_INDEX,
                    expected_key_id: HNSW_KEY,
                    expected_rk_id: HNSW_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    expected_dim: 2,
                    expected_distance: DistanceKind::Cosine,
                    signature_verification: PrivateHnswSignatureVerification {
                        expected_key_id: OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let mut result_manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: COLLECTION_ID.to_string(),
            key_id: RESULT_KEY.to_string(),
            rk_id: RESULT_KEY.to_string(),
            rk_epoch: 7,
            oram: oram(),
            index_epoch: 11,
            root_hash: digest(2),
            bucket_count: 3,
            logical_result_count: 2,
            dummy_result_count: 3,
            owner_signing_key_id: OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let result_buckets = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 11, 20 + bucket_id as u8))
            .collect::<Vec<_>>();
        result_manifest.root_hash = PrivateResultOramStore::merkle_root_for_commitments(
            &result_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_signature: PrivateResultOramSignature =
            sign_private_result_oram_manifest(&key_pair, &result_manifest).unwrap();
        result_store
            .write_initial_upload_bundle_with_signature(
                &PrivateResultOramUploadBundle {
                    manifest: result_manifest.clone(),
                    manifest_signature: result_signature,
                    buckets: result_buckets,
                },
                4096,
                PrivateResultOramManifestValidationContext {
                    expected_collection_id: COLLECTION_ID,
                    expected_key_id: RESULT_KEY,
                    expected_rk_id: RESULT_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    signature_verification: PrivateResultOramSignatureVerification {
                        expected_key_id: OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let immutable_manifest = PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: COLLECTION_ID.to_string(),
            manifest_nonce: digest(3),
            indexes: vec![
                PrivateOramImmutableIndexV2 {
                    index_name: HNSW_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Hnsw {
                        provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                        key_id: HNSW_KEY.to_string(),
                        rk_id: HNSW_KEY.to_string(),
                        rk_epoch: 7,
                        dim: immutable_dim,
                        vector_encoding: PrivateHnswVectorEncoding::F32Le,
                        distance: DistanceKind::Cosine,
                        hnsw: hnsw_params,
                        oram: oram(),
                        fixed_search_budget: fixed_budget,
                        max_neighbor_rewrites: 1,
                    },
                    capacity: capacity(),
                },
                PrivateOramImmutableIndexV2 {
                    index_name: RESULT_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Result {
                        provider: qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                        key_id: immutable_result_key.to_string(),
                        rk_id: immutable_result_key.to_string(),
                        rk_epoch: 7,
                        oram: oram(),
                    },
                    capacity: capacity(),
                },
            ],
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let immutable_manifest =
            package_private_oram_immutable_manifest_v2(&key_pair, immutable_manifest).unwrap();

        let hnsw_final = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 12, 30 + bucket_id as u8))
            .collect::<Vec<_>>();
        let result_final = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 12, 40 + bucket_id as u8))
            .collect::<Vec<_>>();
        let hnsw_new_root = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_new_root = PrivateResultOramStore::merkle_root_for_commitments(
            &result_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let old_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: HNSW_INDEX.to_string(),
                index_epoch: 11,
                root_hash: hnsw_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(50),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: RESULT_INDEX.to_string(),
                index_epoch: 11,
                root_hash: result_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(51),
            },
        ];
        let mut new_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: HNSW_INDEX.to_string(),
                index_epoch: 12,
                root_hash: hnsw_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(52),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: RESULT_INDEX.to_string(),
                index_epoch: 12,
                root_hash: result_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(53),
            },
        ];
        let writebacks = vec![
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: HNSW_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: digest(54),
                updated_buckets: repeated_path_refs(
                    &hnsw_final.iter().map(hnsw_ref).collect::<Vec<_>>(),
                ),
            },
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: RESULT_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: digest(55),
                updated_buckets: repeated_path_refs(
                    &result_final.iter().map(result_ref).collect::<Vec<_>>(),
                ),
            },
        ];
        for offset in 0..writebacks.len() {
            let old = &old_indexes[offset];
            let new = &new_indexes[offset];
            let writeback = &writebacks[offset];
            new_indexes[offset].last_writeback_digest =
                private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                    collection_id: COLLECTION_ID,
                    manifest_digest: &manifest_digest,
                    kind: writeback.kind,
                    index_name: &writeback.index_name,
                    old_epoch: old.index_epoch,
                    new_epoch: new.index_epoch,
                    old_root_hash: &old.root_hash,
                    new_root_hash: &new.root_hash,
                    read_path_count: writeback.read_path_count,
                    read_transcript_digest: &writeback.read_transcript_digest,
                    updated_buckets: &writeback.updated_buckets,
                })
                .unwrap();
        }
        let mutation_id = digest(56);
        let old_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 1,
                indexes: old_indexes,
                client_state_digest: digest(58),
                last_mutation_id: Some(digest(63)),
                owner_signing_key_id: OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_100,
            },
        )
        .unwrap();
        let new_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 2,
                indexes: new_indexes,
                client_state_digest: digest(59),
                last_mutation_id: Some(mutation_id.clone()),
                owner_signing_key_id: OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_130,
            },
        )
        .unwrap();
        let mutation_bundle = package_private_oram_append_mutation_v1(
            &key_pair,
            PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: mutation_id.clone(),
                collection_id: COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                writer_lease_digest: digest(60),
                writer_fence: 1,
                issued_at_unix: 1_770_000_120,
                expires_at_unix: 1_770_000_180,
                old_state,
                new_state,
                point_operation_kind: PrivateOramPointOperationKindV1::NoServerPointRecord,
                point_operation_digest: private_oram_no_server_point_record_v1_digest(
                    COLLECTION_ID,
                    &manifest_digest,
                    &mutation_id,
                )
                .unwrap(),
                writebacks,
                owner_signing_key_id: OWNER_KEY.to_string(),
            },
        )
        .unwrap();
        let (_, prepared_token) = owner_journal
            .prepare_store_adapter_test_fixture_v1(
                &mutation_bundle,
                7,
                &digest(61),
                &digest(62),
                vec![
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: HNSW_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Hnsw(hnsw_final.clone()),
                    },
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: RESULT_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Result(result_final.clone()),
                    },
                ],
            )
            .unwrap();

        PairFixture {
            _temp: temp,
            public_key: key_pair.public_key().as_ref().to_vec(),
            immutable_manifest,
            mutation_bundle,
            hnsw_store,
            result_store,
            owner_journal,
            prepared_token,
            hnsw_final,
            result_final,
        }
    }

    fn pair_context<'a>(fixture: &'a PairFixture) -> PrivateOramOwnerStorePairContextV1<'a> {
        PrivateOramOwnerStorePairContextV1 {
            owner_journal: &fixture.owner_journal,
            prepared_token: &fixture.prepared_token,
            immutable_manifest: &fixture.immutable_manifest,
            mutation_bundle: &fixture.mutation_bundle,
            signature_verification: PrivateOramSignatureVerification {
                expected_key_id: OWNER_KEY,
                public_key: &fixture.public_key,
            },
            hnsw_store: &fixture.hnsw_store,
            hnsw_manifest_validation: PrivateHnswManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_vector_name: HNSW_INDEX,
                expected_key_id: HNSW_KEY,
                expected_rk_id: HNSW_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            hnsw_max_ciphertext_bytes: 4096,
            result_store: &fixture.result_store,
            result_manifest_validation: PrivateResultOramManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_key_id: RESULT_KEY,
                expected_rk_id: RESULT_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                signature_verification: PrivateResultOramSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            result_max_ciphertext_bytes: 4096,
        }
    }

    fn recovery_resources<'a>(
        fixture: &'a PairFixture,
    ) -> PrivateOramOwnerRecoveryStorePairResourcesV1<'a> {
        PrivateOramOwnerRecoveryStorePairResourcesV1 {
            owner_journal: &fixture.owner_journal,
            immutable_manifest: &fixture.immutable_manifest,
            mutation_bundle: &fixture.mutation_bundle,
            signature_verification: PrivateOramSignatureVerification {
                expected_key_id: OWNER_KEY,
                public_key: &fixture.public_key,
            },
            hnsw_store: &fixture.hnsw_store,
            hnsw_manifest_validation: PrivateHnswManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_vector_name: HNSW_INDEX,
                expected_key_id: HNSW_KEY,
                expected_rk_id: HNSW_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            hnsw_max_ciphertext_bytes: 4096,
            result_store: &fixture.result_store,
            result_manifest_validation: PrivateResultOramManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_key_id: RESULT_KEY,
                expected_rk_id: RESULT_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                signature_verification: PrivateResultOramSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            result_max_ciphertext_bytes: 4096,
        }
    }

    #[derive(Clone, Copy)]
    enum RecoveryFixtureStoreState {
        Old,
        New,
        Third,
    }

    fn set_hnsw_recovery_state(fixture: &PairFixture, state: RecoveryFixtureStoreState) {
        let mutation = &fixture.mutation_bundle.mutation;
        match state {
            RecoveryFixtureStoreState::Old => {}
            RecoveryFixtureStoreState::New => fixture
                .hnsw_store
                .apply_owner_exact_new_test_fixture_v1(
                    &mutation.old_state.state.indexes[0],
                    &mutation.new_state.state.indexes[0],
                    &fixture.hnsw_final,
                    3,
                    4096,
                )
                .unwrap(),
            RecoveryFixtureStoreState::Third => {
                // Two exact old+1 steps reach a third state that is neither the
                // mutation's old nor its new state.
                let old = fixture.hnsw_store.read_current_epoch().unwrap();
                let between = PrivateHnswOramEpochState {
                    index_epoch: old.index_epoch + 1,
                    root_hash: digest(210),
                };
                fixture
                    .hnsw_store
                    .compare_and_swap_epoch(&old, &between)
                    .unwrap();
                fixture
                    .hnsw_store
                    .compare_and_swap_epoch(
                        &between,
                        &PrivateHnswOramEpochState {
                            index_epoch: old.index_epoch + 2,
                            root_hash: digest(200),
                        },
                    )
                    .unwrap();
            }
        }
    }

    fn set_result_recovery_state(fixture: &PairFixture, state: RecoveryFixtureStoreState) {
        let mutation = &fixture.mutation_bundle.mutation;
        match state {
            RecoveryFixtureStoreState::Old => {}
            RecoveryFixtureStoreState::New => fixture
                .result_store
                .apply_owner_exact_new_test_fixture_v1(
                    &mutation.old_state.state.indexes[1],
                    &mutation.new_state.state.indexes[1],
                    &fixture.result_final,
                    3,
                    4096,
                )
                .unwrap(),
            RecoveryFixtureStoreState::Third => {
                // Two exact old+1 steps reach a third state that is neither the
                // mutation's old nor its new state.
                let old = fixture.result_store.read_current_epoch().unwrap();
                let between = PrivateResultOramEpochState {
                    index_epoch: old.index_epoch + 1,
                    root_hash: digest(211),
                };
                fixture
                    .result_store
                    .compare_and_swap_epoch(&old, &between)
                    .unwrap();
                fixture
                    .result_store
                    .compare_and_swap_epoch(
                        &between,
                        &PrivateResultOramEpochState {
                            index_epoch: old.index_epoch + 2,
                            root_hash: digest(201),
                        },
                    )
                    .unwrap();
            }
        }
    }

    fn recovery_projection(
        fixture: &PairFixture,
    ) -> Result<PrivateOramOwnerRecoveryProjectionV1, PrivateOramOwnerJournalError> {
        let mutation = &fixture.mutation_bundle.mutation;
        let indexes = mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation.new_state.state.indexes)
            .zip(fixture.prepared_token.indexes())
            .map(|((old, new), prepared)| {
                PrivateOramOwnerRecoveryIndexProjectionV1::try_from_input(
                    PrivateOramOwnerRecoveryIndexProjectionInputV1 {
                        kind: old.kind,
                        index_name: &old.index_name,
                        old_epoch: old.index_epoch,
                        new_epoch: new.index_epoch,
                        old_root_hash: &old.root_hash,
                        new_root_hash: &new.root_hash,
                        writeback_digest: &new.last_writeback_digest,
                        prepared_journal_digest: prepared.prepared_journal_digest(),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        PrivateOramOwnerRecoveryProjectionV1::try_new(
            7,
            &digest(61),
            &digest(62),
            &fixture.mutation_bundle,
            indexes,
        )
    }

    fn recovery_parent_input(
        fixture: &PairFixture,
        disposition: PrivateOramOwnerRecoveryParentDispositionV1,
    ) -> PrivateOramOwnerRecoveryParentInputV1 {
        PrivateOramOwnerRecoveryParentInputV1 {
            projection: recovery_projection(fixture).unwrap(),
            disposition,
            authenticated_owner_peer_id: 7,
            parent_descriptor_digest: digest(61),
            parent_owners_prepared_record_digest: digest(63),
            consensus_authority_record_digest: digest(64),
            reconciliation_authority_digest: digest(65),
        }
    }

    fn recover_pair(
        fixture: &PairFixture,
        disposition: PrivateOramOwnerRecoveryParentDispositionV1,
    ) -> CollectionResult<PrivateOramOwnerRecoveryPairOutcomeV1> {
        let (bridge, verifier) = new_private_oram_owner_recovery_parent_bridge_v1();
        let parent_lock = ();
        bridge.with_test_live_parent_v1(
            &parent_lock,
            recovery_parent_input(fixture, disposition),
            |parent| {
                recover_private_oram_owner_store_pair_v1(
                    &verifier,
                    parent,
                    recovery_resources(fixture),
                )
            },
        )
    }

    fn recover_pair_at_fault(
        fixture: &PairFixture,
        fault_point: PrivateOramOwnerRecoveryFaultPointV1,
    ) -> CollectionResult<PrivateOramOwnerRecoveryPairOutcomeV1> {
        let (bridge, verifier) = new_private_oram_owner_recovery_parent_bridge_v1();
        let parent_lock = ();
        bridge.with_test_live_parent_v1(
            &parent_lock,
            recovery_parent_input(
                fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            ),
            |parent| {
                recover_private_oram_owner_store_pair_at_fault_v1(
                    &verifier,
                    parent,
                    recovery_resources(fixture),
                    fault_point,
                )
            },
        )
    }

    fn finalized_evidence(
        outcome: PrivateOramOwnerRecoveryPairOutcomeV1,
    ) -> PrivateOramOwnerRecoveryTerminalEvidenceV1 {
        match outcome {
            PrivateOramOwnerRecoveryPairOutcomeV1::Finalized(evidence) => evidence,
            _ => panic!("expected finalized private ORAM owner recovery"),
        }
    }

    fn aborted_evidence(
        outcome: PrivateOramOwnerRecoveryPairOutcomeV1,
    ) -> PrivateOramOwnerRecoveryTerminalEvidenceV1 {
        match outcome {
            PrivateOramOwnerRecoveryPairOutcomeV1::AbortedOld(evidence) => evidence,
            _ => panic!("expected aborted-old private ORAM owner recovery"),
        }
    }

    fn write_historical_hnsw_commit(fixture: &PairFixture, epoch: u64) {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let path = fixture
            .hnsw_store
            .root_path()
            .join("epochs")
            .join(format!("{epoch:08}.commit"));
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "index_epoch": epoch,
                "root_hash": digest(171),
                "writeback_digest": digest(172),
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn pair_store_paths_reject_cross_journal_and_cross_collection_substitution() {
        let temp = TempDir::new().unwrap();
        let collection = temp.path().join("collection-a");
        let hnsw = PrivateHnswOramStore::new(&collection, "text").unwrap();
        let result = PrivateResultOramStore::new(&collection);
        let journal = PrivateOramOwnerJournal::new(hnsw.root_path());
        validate_pair_store_paths(&journal, &hnsw, &result).unwrap();

        let other_hnsw = PrivateHnswOramStore::new(&collection, "other").unwrap();
        let other_journal = PrivateOramOwnerJournal::new(other_hnsw.root_path());
        let error = validate_pair_store_paths(&other_journal, &hnsw, &result)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Bad request: private ORAM paired owner store authority is invalid"
        );
        assert!(!error.contains(temp.path().to_string_lossy().as_ref()));

        let other_result = PrivateResultOramStore::new(temp.path().join("collection-b"));
        let error = validate_pair_store_paths(&journal, &hnsw, &other_result)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Bad request: private ORAM paired owner store authority is invalid"
        );
        assert!(!error.contains(temp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn exact_old_pair_binds_signed_mutation_prepared_journal_and_both_stores() {
        let fixture = pair_fixture();
        let states =
            with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |pair| {
                let rendered = format!("{pair:?}");
                assert!(!rendered.contains(HNSW_INDEX));
                assert!(!rendered.contains(RESULT_INDEX));
                Ok(pair.terminal_index_states())
            })
            .unwrap();

        assert_eq!(states[0].kind, PrivateOramIndexKindV2::Hnsw);
        assert_eq!(states[0].index_name, HNSW_INDEX);
        assert_eq!(states[1].kind, PrivateOramIndexKindV2::Result);
        assert_eq!(states[1].index_name, RESULT_INDEX);
        for state in states {
            assert_eq!(
                BASE64URL_NOPAD
                    .decode(state.canonical_state_digest.as_bytes())
                    .unwrap()
                    .len(),
                32
            );
        }
    }

    #[test]
    fn recovery_projection_rebinds_the_live_prepared_pair() {
        let fixture = pair_fixture();
        let projection = recovery_projection(&fixture).unwrap();
        let mut called = false;

        fixture
            .owner_journal
            .with_revalidated_recovery_prepared_v1(&projection, |binding| {
                called = true;
                let rendered = format!("{projection:?} {binding:?}");
                assert!(!rendered.contains(COLLECTION_ID));
                assert!(!rendered.contains(HNSW_INDEX));
                assert!(!rendered.contains(RESULT_INDEX));
                assert!(!rendered.contains(fixture.prepared_token.journal_descriptor_digest()));
            })
            .unwrap();

        assert!(called);
    }

    #[test]
    fn recovery_projection_constructor_rejects_noncanonical_pair_order() {
        let fixture = pair_fixture();
        let mutation = &fixture.mutation_bundle.mutation;
        let mut indexes = mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation.new_state.state.indexes)
            .zip(fixture.prepared_token.indexes())
            .map(|((old, new), prepared)| {
                PrivateOramOwnerRecoveryIndexProjectionV1::try_from_input(
                    PrivateOramOwnerRecoveryIndexProjectionInputV1 {
                        kind: old.kind,
                        index_name: &old.index_name,
                        old_epoch: old.index_epoch,
                        new_epoch: new.index_epoch,
                        old_root_hash: &old.root_hash,
                        new_root_hash: &new.root_hash,
                        writeback_digest: &new.last_writeback_digest,
                        prepared_journal_digest: prepared.prepared_journal_digest(),
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        indexes.swap(0, 1);

        assert_eq!(
            PrivateOramOwnerRecoveryProjectionV1::try_new(
                7,
                &digest(61),
                &digest(62),
                &fixture.mutation_bundle,
                indexes,
            )
            .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidInput("indexes")
        );
    }

    #[test]
    fn recovery_classifier_covers_all_store_state_combinations() {
        use PrivateOramOwnerRecoveryStoreDispositionV1::{AllNew, AllOld, PartialNew, ThirdState};
        use RecoveryFixtureStoreState::{New, Old, Third};

        let cases = [
            (Old, Old, AllOld),
            (Old, New, ThirdState),
            (Old, Third, ThirdState),
            (New, Old, PartialNew),
            (New, New, AllNew),
            (New, Third, ThirdState),
            (Third, Old, ThirdState),
            (Third, New, ThirdState),
            (Third, Third, ThirdState),
        ];
        for (hnsw, result, expected) in cases {
            let fixture = pair_fixture();
            set_hnsw_recovery_state(&fixture, hnsw);
            set_result_recovery_state(&fixture, result);
            let projection = recovery_projection(&fixture).unwrap();

            let observed = classify_private_oram_owner_recovery_store_pair_v1(
                &projection,
                recovery_resources(&fixture),
            )
            .unwrap();

            assert_eq!(observed, expected);
            let rendered = format!("{projection:?} {:?}", recovery_resources(&fixture));
            assert!(!rendered.contains(COLLECTION_ID));
            assert!(!rendered.contains(&format!("\"{HNSW_INDEX}\"")));
            assert!(!rendered.contains(RESULT_INDEX));
            assert!(!rendered.contains(HNSW_KEY));
            assert!(!rendered.contains(RESULT_KEY));
            assert!(!rendered.contains(&digest(61)));
        }
    }

    #[test]
    fn recovery_classifier_errors_when_an_exact_pointer_has_corrupt_evidence() {
        let manifest_fixture = pair_fixture();
        let manifest_projection = recovery_projection(&manifest_fixture).unwrap();
        let (manifest, signature) = manifest_fixture.hnsw_store.read_manifest().unwrap();
        let mut substituted_manifest = manifest.clone();
        substituted_manifest.key_id = "tenant-a/substituted-hnsw-rk".to_string();
        manifest_fixture
            .hnsw_store
            .write_manifest(&substituted_manifest, &signature)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .is_err()
        );
        manifest_fixture
            .hnsw_store
            .write_manifest(&manifest, &signature)
            .unwrap();
        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );

        let commit_fixture = pair_fixture();
        let commit_projection = recovery_projection(&commit_fixture).unwrap();
        let current = commit_fixture.hnsw_store.read_current_epoch().unwrap();
        let expected_new = &commit_fixture
            .mutation_bundle
            .mutation
            .new_state
            .state
            .indexes[0];
        commit_fixture
            .hnsw_store
            .compare_and_swap_epoch(
                &current,
                &PrivateHnswOramEpochState {
                    index_epoch: expected_new.index_epoch,
                    root_hash: expected_new.root_hash.clone(),
                },
            )
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &commit_projection,
                recovery_resources(&commit_fixture),
            )
            .is_err()
        );

        let merkle_fixture = pair_fixture();
        let merkle_projection = recovery_projection(&merkle_fixture).unwrap();
        let leaves = vec![digest(210), digest(211), digest(212)];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&leaves).unwrap();
        merkle_fixture
            .hnsw_store
            .write_merkle_tree_from_commitments(11, root, leaves)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &merkle_projection,
                recovery_resources(&merkle_fixture),
            )
            .is_err()
        );

        let bucket_fixture = pair_fixture();
        let bucket_projection = recovery_projection(&bucket_fixture).unwrap();
        let (manifest, _) = bucket_fixture.hnsw_store.read_manifest().unwrap();
        let substituted = hnsw_bucket(&manifest, 0, 11, 213);
        bucket_fixture
            .hnsw_store
            .write_bucket(&substituted, 11, 3, 4096)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &bucket_projection,
                recovery_resources(&bucket_fixture),
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_classifier_errors_when_result_exact_pointer_has_corrupt_evidence() {
        let manifest_fixture = pair_fixture();
        let manifest_projection = recovery_projection(&manifest_fixture).unwrap();
        let (manifest, signature) = manifest_fixture.result_store.read_manifest().unwrap();
        let mut substituted_manifest = manifest.clone();
        substituted_manifest.key_id = "tenant-a/substituted-result-rk".to_string();
        manifest_fixture
            .result_store
            .write_manifest(&substituted_manifest, &signature)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .is_err()
        );
        manifest_fixture
            .result_store
            .write_manifest(&manifest, &signature)
            .unwrap();
        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );

        let commit_fixture = pair_fixture();
        let commit_projection = recovery_projection(&commit_fixture).unwrap();
        let current = commit_fixture.result_store.read_current_epoch().unwrap();
        let expected_new = &commit_fixture
            .mutation_bundle
            .mutation
            .new_state
            .state
            .indexes[1];
        commit_fixture
            .result_store
            .compare_and_swap_epoch(
                &current,
                &PrivateResultOramEpochState {
                    index_epoch: expected_new.index_epoch,
                    root_hash: expected_new.root_hash.clone(),
                },
            )
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &commit_projection,
                recovery_resources(&commit_fixture),
            )
            .is_err()
        );

        let merkle_fixture = pair_fixture();
        let merkle_projection = recovery_projection(&merkle_fixture).unwrap();
        let leaves = vec![digest(220), digest(221), digest(222)];
        let root = PrivateResultOramStore::merkle_root_for_commitments(&leaves).unwrap();
        merkle_fixture
            .result_store
            .write_merkle_tree_from_commitments(11, root, leaves)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &merkle_projection,
                recovery_resources(&merkle_fixture),
            )
            .is_err()
        );

        let bucket_fixture = pair_fixture();
        let bucket_projection = recovery_projection(&bucket_fixture).unwrap();
        let (manifest, _) = bucket_fixture.result_store.read_manifest().unwrap();
        let substituted = result_bucket(&manifest, 0, 11, 223);
        bucket_fixture
            .result_store
            .write_bucket(&substituted, 11, 3, 4096)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &bucket_projection,
                recovery_resources(&bucket_fixture),
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_classifier_rejects_hnsw_and_child_lock_contention() {
        let fixture = pair_fixture();
        let projection = recovery_projection(&fixture).unwrap();

        fixture
            .hnsw_store
            .with_owner_store_lock_v1(|_| {
                let error = classify_private_oram_owner_recovery_store_pair_v1(
                    &projection,
                    recovery_resources(&fixture),
                )
                .unwrap_err()
                .to_string();
                assert!(error.contains("another private HNSW ORAM owner store operation"));
                assert!(!error.contains(COLLECTION_ID));
                Ok(())
            })
            .unwrap();

        fixture
            .owner_journal
            .with_exclusive_root_lock_test_v1(|| {
                let error = classify_private_oram_owner_recovery_store_pair_v1(
                    &projection,
                    recovery_resources(&fixture),
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    error,
                    "Bad request: private ORAM paired owner store authority is invalid"
                );
                assert!(!error.contains(COLLECTION_ID));
            })
            .unwrap();

        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &projection,
                recovery_resources(&fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );
    }

    #[test]
    fn recovery_classifier_releases_hnsw_when_result_lock_is_contended() {
        let fixture = pair_fixture();
        let projection = recovery_projection(&fixture).unwrap();

        fixture
            .result_store
            .with_owner_store_lock_v1(|_| {
                let error = classify_private_oram_owner_recovery_store_pair_v1(
                    &projection,
                    recovery_resources(&fixture),
                )
                .unwrap_err()
                .to_string();
                assert!(error.contains("another private result ORAM owner store operation"));
                assert!(!error.contains(COLLECTION_ID));
                Ok(())
            })
            .unwrap();

        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &projection,
                recovery_resources(&fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );
    }

    #[test]
    fn exact_old_pair_rejects_mutation_signature_substitution_before_callback() {
        let fixture = pair_fixture();
        let mut tampered_mutation = fixture.mutation_bundle.clone();
        let mut signature = BASE64URL_NOPAD
            .decode(tampered_mutation.signature.sig.as_bytes())
            .unwrap();
        signature[0] ^= 1;
        tampered_mutation.signature.sig = BASE64URL_NOPAD.encode(&signature);
        let mut context = pair_context(&fixture);
        context.mutation_bundle = &tampered_mutation;
        let mut called = false;

        let error = with_private_oram_owner_exact_old_store_pair_v1(context, |_| {
            called = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(!called);
        assert_eq!(
            error,
            "Bad request: private ORAM paired owner store authority is invalid"
        );
        assert!(!error.contains(&tampered_mutation.signature.sig));
    }

    #[test]
    fn exact_old_pair_rejects_signed_v2_to_physical_hnsw_mismatch() {
        let fixture = pair_fixture_with_immutable_dim(3);
        let mut called = false;

        let error = with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |_| {
            called = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(!called);
        assert_eq!(
            error,
            "Bad request: private HNSW ORAM owner canonical store state does not match"
        );
        assert!(!error.contains(COLLECTION_ID));
        assert!(!error.contains(HNSW_KEY));
    }

    #[test]
    fn exact_old_pair_rejects_signed_v2_to_physical_result_mismatch() {
        let fixture = pair_fixture_with_immutable_params(2, "tenant-a/substituted-result-rk");
        let mut called = false;

        let error = with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |_| {
            called = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(!called);
        assert_eq!(
            error,
            "Bad request: private result ORAM owner canonical store state does not match"
        );
        assert!(!error.contains(COLLECTION_ID));
        assert!(!error.contains("substituted-result-rk"));
    }

    #[test]
    fn exact_new_pair_binds_both_digest_commits_and_final_bucket_bodies() {
        let fixture = pair_fixture();
        let old_states =
            with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |pair| {
                Ok(pair.terminal_index_states())
            })
            .unwrap();
        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        fixture
            .hnsw_store
            .apply_owner_exact_new_test_fixture_v1(&old[0], &new[0], &fixture.hnsw_final, 3, 4096)
            .unwrap();
        fixture
            .result_store
            .apply_owner_exact_new_test_fixture_v1(&old[1], &new[1], &fixture.result_final, 3, 4096)
            .unwrap();

        let new_states =
            with_private_oram_owner_exact_new_store_pair_v1(pair_context(&fixture), |pair| {
                Ok(pair.terminal_index_states())
            })
            .unwrap();

        assert_eq!(new_states[0].kind, PrivateOramIndexKindV2::Hnsw);
        assert_eq!(new_states[1].kind, PrivateOramIndexKindV2::Result);
        assert_ne!(
            old_states[0].canonical_state_digest,
            new_states[0].canonical_state_digest
        );
        assert_ne!(
            old_states[1].canonical_state_digest,
            new_states[1].canonical_state_digest
        );
    }

    #[test]
    fn mixed_old_new_pair_mints_neither_phase_token() {
        let fixture = pair_fixture();
        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        fixture
            .hnsw_store
            .apply_owner_exact_new_test_fixture_v1(&old[0], &new[0], &fixture.hnsw_final, 3, 4096)
            .unwrap();

        let mut old_called = false;
        let old_error =
            with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |_| {
                old_called = true;
                Ok(())
            })
            .unwrap_err()
            .to_string();
        let mut new_called = false;
        let new_error =
            with_private_oram_owner_exact_new_store_pair_v1(pair_context(&fixture), |_| {
                new_called = true;
                Ok(())
            })
            .unwrap_err()
            .to_string();

        assert!(!old_called);
        assert!(!new_called);
        assert_eq!(
            old_error,
            "Bad request: private HNSW ORAM owner canonical store state does not match"
        );
        assert_eq!(
            new_error,
            "Bad request: private result ORAM owner canonical store state does not match"
        );
    }

    #[test]
    fn paired_recovery_phase_lattice_is_explicit_and_directional() {
        let hnsw_phases = [
            PrivateHnswOwnerRecoveryPhaseV1::S0,
            PrivateHnswOwnerRecoveryPhaseV1::S1 {
                written_bucket_count: 1,
            },
            PrivateHnswOwnerRecoveryPhaseV1::S2,
            PrivateHnswOwnerRecoveryPhaseV1::S3,
            PrivateHnswOwnerRecoveryPhaseV1::S4,
        ];
        let result_phases = [
            PrivateResultOwnerRecoveryProgressV1::S0,
            PrivateResultOwnerRecoveryProgressV1::S1 { written_prefix: 1 },
            PrivateResultOwnerRecoveryProgressV1::S2,
            PrivateResultOwnerRecoveryProgressV1::S3,
            PrivateResultOwnerRecoveryProgressV1::S4,
        ];

        for hnsw in hnsw_phases {
            for result in result_phases {
                let decision = recovery_decision(
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
                    PrivateOramOwnerRecoveryExclusiveStateV1::Prepared,
                    hnsw,
                    result,
                );
                let expected = match hnsw {
                    PrivateHnswOwnerRecoveryPhaseV1::S0
                    | PrivateHnswOwnerRecoveryPhaseV1::S1 { .. }
                    | PrivateHnswOwnerRecoveryPhaseV1::S2
                    | PrivateHnswOwnerRecoveryPhaseV1::S3 => {
                        result == PrivateResultOwnerRecoveryProgressV1::S0
                    }
                    PrivateHnswOwnerRecoveryPhaseV1::S4 => true,
                };
                assert_eq!(decision.is_ok(), expected, "{hnsw:?} / {result:?}");
            }
        }

        assert!(
            recovery_decision(
                PrivateOramOwnerRecoveryParentDispositionV1::ExactOldAbortDecided,
                PrivateOramOwnerRecoveryExclusiveStateV1::Prepared,
                PrivateHnswOwnerRecoveryPhaseV1::S0,
                PrivateResultOwnerRecoveryProgressV1::S0,
            )
            .is_ok()
        );
        assert!(
            recovery_decision(
                PrivateOramOwnerRecoveryParentDispositionV1::ExactOldAbortDecided,
                PrivateOramOwnerRecoveryExclusiveStateV1::AbortedOldReplay,
                PrivateHnswOwnerRecoveryPhaseV1::S0,
                PrivateResultOwnerRecoveryProgressV1::S0,
            )
            .is_ok()
        );
        assert!(
            recovery_decision(
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
                PrivateOramOwnerRecoveryExclusiveStateV1::FinalizedReplay,
                PrivateHnswOwnerRecoveryPhaseV1::S4,
                PrivateResultOwnerRecoveryProgressV1::S4,
            )
            .is_ok()
        );
        assert!(
            recovery_decision(
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
                PrivateOramOwnerRecoveryExclusiveStateV1::FinalizedReplay,
                PrivateHnswOwnerRecoveryPhaseV1::S4,
                PrivateResultOwnerRecoveryProgressV1::S3,
            )
            .is_err()
        );
    }

    #[test]
    fn paired_recovery_rolls_forward_both_stores_and_replays_finalized() {
        let fixture = pair_fixture();
        let evidence = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        assert_eq!(evidence.owner_peer_id(), 7);
        assert_eq!(evidence.parent_descriptor_digest(), digest(61));
        assert_eq!(evidence.consensus_authority_record_digest(), digest(64));
        assert_eq!(evidence.reconciliation_authority_digest(), digest(65));
        assert_eq!(evidence.indexes().len(), 2);
        assert_eq!(evidence.indexes()[0].kind(), PrivateOramIndexKindV2::Hnsw);
        assert_eq!(evidence.indexes()[1].kind(), PrivateOramIndexKindV2::Result);
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        let hnsw = fixture.hnsw_store.read_current_epoch().unwrap();
        let result = fixture.result_store.read_current_epoch().unwrap();
        assert_eq!(
            (hnsw.index_epoch, hnsw.root_hash.as_str()),
            (new[0].index_epoch, new[0].root_hash.as_str())
        );
        assert_eq!(
            (result.index_epoch, result.root_hash.as_str()),
            (new[1].index_epoch, new[1].root_hash.as_str())
        );
        assert_eq!(
            fixture
                .owner_journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .unwrap()
                .phase,
            PrivateOramOwnerJournalPhaseV1::Finalized
        );

        let replay = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        assert_eq!(replay, evidence);
    }

    #[test]
    fn paired_recovery_continuation_keeps_store_and_child_locks() {
        let fixture = pair_fixture();
        let (bridge, verifier) = new_private_oram_owner_recovery_parent_bridge_v1();
        let parent_lock = ();
        let output = bridge
            .with_test_live_parent_v1(
                &parent_lock,
                recovery_parent_input(
                    &fixture,
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
                ),
                |parent| {
                    recover_private_oram_owner_store_pair_then_v1(
                        &verifier,
                        parent,
                        recovery_resources(&fixture),
                        |outcome| {
                            assert!(matches!(
                                outcome,
                                PrivateOramOwnerRecoveryPairOutcomeV1::Finalized(_)
                            ));
                            assert!(
                                classify_private_oram_owner_recovery_store_pair_v1(
                                    &recovery_projection(&fixture).unwrap(),
                                    recovery_resources(&fixture),
                                )
                                .is_err()
                            );
                            assert!(fixture.owner_journal.inspect_structural().is_err());
                            Ok(9_u8)
                        },
                    )
                },
            )
            .unwrap();

        assert_eq!(output, 9);
        assert_eq!(
            fixture
                .owner_journal
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
    fn paired_finalized_replay_rejects_historical_commit_replacement() {
        let fixture = pair_fixture();
        let _ = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        let terminal_before = fixture
            .owner_journal
            .inspect_structural()
            .unwrap()
            .unwrap()
            .terminal
            .unwrap();
        write_historical_hnsw_commit(&fixture, 1);

        assert!(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .is_err()
        );
        assert_eq!(
            fixture
                .owner_journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .unwrap(),
            terminal_before
        );
    }

    #[test]
    fn paired_recovery_replays_fault_after_hnsw_publication() {
        let fixture = pair_fixture();
        assert!(matches!(
            recover_pair_at_fault(
                &fixture,
                PrivateOramOwnerRecoveryFaultPointV1::AfterHnswPublication,
            ),
            Err(CollectionError::ServiceError { .. })
        ));
        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &recovery_projection(&fixture).unwrap(),
                recovery_resources(&fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::PartialNew
        );
        let child = fixture.owner_journal.inspect_structural().unwrap().unwrap();
        assert_eq!(child.state.phase, PrivateOramOwnerJournalPhaseV1::Prepared);
        assert!(child.terminal.is_none());

        let recovered = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        let replayed = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        assert_eq!(replayed, recovered);
    }

    #[test]
    fn paired_recovery_replays_fault_after_result_publication() {
        let fixture = pair_fixture();
        assert!(matches!(
            recover_pair_at_fault(
                &fixture,
                PrivateOramOwnerRecoveryFaultPointV1::AfterResultPublication,
            ),
            Err(CollectionError::ServiceError { .. })
        ));
        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &recovery_projection(&fixture).unwrap(),
                recovery_resources(&fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllNew
        );
        let child = fixture.owner_journal.inspect_structural().unwrap().unwrap();
        assert_eq!(child.state.phase, PrivateOramOwnerJournalPhaseV1::Prepared);
        assert!(child.terminal.is_none());

        let recovered = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        let replayed = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        assert_eq!(replayed, recovered);
    }

    #[test]
    fn paired_recovery_resumes_result_only_after_hnsw_is_exact_new() {
        let fixture = pair_fixture();
        set_hnsw_recovery_state(&fixture, RecoveryFixtureStoreState::New);

        let _ = finalized_evidence(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .unwrap(),
        );
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        let result = fixture.result_store.read_current_epoch().unwrap();
        assert_eq!(
            (result.index_epoch, result.root_hash),
            (new[1].index_epoch, new[1].root_hash.clone())
        );
    }

    #[test]
    fn paired_recovery_rejects_result_first_before_hnsw_mutation() {
        let fixture = pair_fixture();
        set_result_recovery_state(&fixture, RecoveryFixtureStoreState::New);
        let hnsw_before = fixture.hnsw_store.read_current_epoch().unwrap();

        assert!(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            )
            .is_err()
        );
        assert_eq!(
            fixture.hnsw_store.read_current_epoch().unwrap(),
            hnsw_before
        );
        assert!(
            fixture
                .owner_journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );
    }

    #[test]
    fn paired_recovery_observes_then_aborts_and_replays_exact_old() {
        let fixture = pair_fixture();
        assert_eq!(
            recover_pair(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ObservedOldNeedsAbortDecision,
            )
            .unwrap(),
            PrivateOramOwnerRecoveryPairOutcomeV1::ObservedOld
        );
        assert!(
            fixture
                .owner_journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );

        for _ in 0..2 {
            let evidence = aborted_evidence(
                recover_pair(
                    &fixture,
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactOldAbortDecided,
                )
                .unwrap(),
            );
            assert_eq!(evidence.owner_peer_id(), 7);
            assert_eq!(evidence.indexes().len(), 2);
        }
        assert_eq!(
            fixture
                .owner_journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .unwrap()
                .phase,
            PrivateOramOwnerJournalPhaseV1::AbortedOld
        );
    }

    #[test]
    fn paired_recovery_rejects_mismatched_parent_bridge_before_locks() {
        let fixture = pair_fixture();
        let (bridge, _) = new_private_oram_owner_recovery_parent_bridge_v1();
        let (_, wrong_verifier) = new_private_oram_owner_recovery_parent_bridge_v1();
        let parent_lock = ();
        let result = bridge.with_test_live_parent_v1(
            &parent_lock,
            recovery_parent_input(
                &fixture,
                PrivateOramOwnerRecoveryParentDispositionV1::ExactNew,
            ),
            |parent| {
                recover_private_oram_owner_store_pair_v1(
                    &wrong_verifier,
                    parent,
                    recovery_resources(&fixture),
                )
            },
        );

        assert!(result.is_err());
        assert!(
            fixture
                .owner_journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );
    }
}
