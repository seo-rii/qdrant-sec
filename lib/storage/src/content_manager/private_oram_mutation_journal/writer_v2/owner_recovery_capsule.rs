use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use fs4::fs_std::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::*;
use crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1;
use crate::content_manager::consensus::private_oram_mutation_recovery_capsules::private_oram_owner_capsule_set_digest_v2;
use crate::content_manager::consensus::private_oram_mutation_watermark::derive_private_oram_mutation_parent_watermark_for_state_v2;

const CAPSULE_VERSION: u16 = 2;
const CAPSULE_PACKAGE_VERSION: u16 = 1;
const CAPSULE_INSTALL_RECEIPT_VERSION: u16 = 1;
const CAPSULE_ROOT_DIR: &str = "private_oram_owner_recovery_capsules_v2";
const CAPSULE_FILE: &str = "capsule.json";
const CAPSULE_LOCK_FILE: &str = "capsule.lock";
const CAPSULE_MAX_BYTES: u64 = PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2 as u64;
const CAPSULE_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-recovery-capsule/v2";
const CAPSULE_INSTALL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-recovery-capsule-install-receipt/v2";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramOwnerRecoveryCapsuleV2 {
    version: u16,
    owner_peer_id: PeerId,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    descriptor: PrivateOramMutationJournalDescriptorV1,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    point_stage_state: PrivateOramMutationJournalStateV2,
    immutable_manifest_bundle_sha256: String,
    capsule_digest: String,
    capsule_set_digest: String,
}

impl Debug for PrivateOramOwnerRecoveryCapsuleV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerRecoveryCapsuleV2")
            .field("version", &self.version)
            .field("owner_peer_id", &"[redacted]")
            .field("activation_authority", &self.activation_authority)
            .field("descriptor", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("point_stage_state", &"[redacted]")
            .field("immutable_manifest_bundle_sha256", &"[redacted]")
            .field("capsule_digest", &"[redacted]")
            .field("capsule_set_digest", &"[redacted]")
            .finish()
    }
}

/// Inert, bounded wire package. Only a locally installed and pinned capsule can mint recovery
/// authority.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerRecoveryCapsulePackageV2 {
    version: u16,
    capsule: PrivateOramOwnerRecoveryCapsuleV2,
}

impl Debug for PrivateOramOwnerRecoveryCapsulePackageV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerRecoveryCapsulePackageV2")
            .field("version", &self.version)
            .field("capsule", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryCapsulePackageV2 {
    pub fn owner_peer_id(&self) -> PeerId {
        self.capsule.owner_peer_id
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.capsule.descriptor.descriptor_digest
    }

    pub fn capsule_digest(&self) -> &str {
        &self.capsule.capsule_digest
    }

    pub fn capsule_set_digest(&self) -> &str {
        &self.capsule.capsule_set_digest
    }

    pub fn activation_authority(&self) -> &PrivateOramActivationAuthorityLocatorV1 {
        &self.capsule.activation_authority
    }

    pub fn collection_id(&self) -> &str {
        &self
            .capsule
            .descriptor
            .mutation_bundle
            .mutation
            .collection_id
    }

    pub fn mutation_id(&self) -> &str {
        &self.capsule.descriptor.mutation_bundle.mutation.mutation_id
    }

    /// Mutation lease generation this capsule was minted for. Successive mutations of a
    /// collection carry strictly increasing generations.
    pub fn lease_generation(&self) -> u64 {
        self.capsule.descriptor.preparing_lease.generation
    }

    pub fn coordinator_peer_id(&self) -> PeerId {
        self.capsule.descriptor.coordinator_peer_id
    }

    pub fn owner_signing_key_id(&self) -> &str {
        &self
            .capsule
            .immutable_manifest
            .manifest
            .owner_signing_key_id
    }

    pub fn hnsw_vector_name(&self) -> Result<&str, PrivateOramMutationJournalError> {
        self.capsule
            .immutable_manifest
            .manifest
            .indexes
            .iter()
            .find(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
            .map(|index| index.index_name.as_str())
            .ok_or(PrivateOramMutationJournalError::Corrupt)
    }

    #[doc(hidden)]
    pub fn immutable_manifest_for_install_v2(&self) -> &PrivateOramImmutableManifestBundleV2 {
        &self.capsule.immutable_manifest
    }

    #[doc(hidden)]
    pub fn mutation_bundle_for_install_v2(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.capsule.descriptor.mutation_bundle
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 {
    version: u16,
    owner_peer_id: PeerId,
    parent_descriptor_digest: String,
    capsule_digest: String,
    capsule_set_digest: String,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    receipt_digest: String,
}

impl Debug for PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerRecoveryCapsuleInstallReceiptV2")
            .field("version", &self.version)
            .field("owner_peer_id", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("capsule_digest", &"[redacted]")
            .field("capsule_set_digest", &"[redacted]")
            .field("activation_authority", &self.activation_authority)
            .field("receipt_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 {
    pub fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub fn capsule_digest(&self) -> &str {
        &self.capsule_digest
    }

    pub fn capsule_set_digest(&self) -> &str {
        &self.capsule_set_digest
    }

    pub fn activation_authority(&self) -> &PrivateOramActivationAuthorityLocatorV1 {
        &self.activation_authority
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

/// Owner-local insert-only durable source used after the coordinator parent is unavailable.
#[derive(Clone)]
pub struct PrivateOramOwnerRecoveryCapsuleStoreV2 {
    root: PathBuf,
    expected_collection_id: String,
    expected_owner_peer_id: PeerId,
    validator: PrivateOramMutationJournal,
    parent_bridge: PrivateOramOwnerRecoveryParentBridgeV1,
    parent_verifier: PrivateOramOwnerRecoveryParentVerifierV1,
}

impl Debug for PrivateOramOwnerRecoveryCapsuleStoreV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerRecoveryCapsuleStoreV2")
            .field("root", &"[redacted]")
            .field("expected_collection_id", &"[redacted]")
            .field("expected_owner_peer_id", &"[redacted]")
            .field("validator", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryCapsuleStoreV2 {
    pub fn new(
        collection_path: &Path,
        expected_collection_id: impl Into<String>,
        expected_owner_peer_id: PeerId,
        expected_owner_signing_key_id: impl Into<String>,
        owner_public_key: Vec<u8>,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let expected_collection_id = expected_collection_id.into();
        if expected_collection_id.is_empty() || expected_collection_id.len() > 1_024 {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "collection_id",
            ));
        }
        let validator = PrivateOramMutationJournal::new(
            collection_path,
            expected_owner_signing_key_id,
            owner_public_key,
        )?;
        let (parent_bridge, parent_verifier) = new_private_oram_owner_recovery_parent_bridge_v1();
        Ok(Self {
            root: collection_path.join(CAPSULE_ROOT_DIR),
            expected_collection_id,
            expected_owner_peer_id,
            validator,
            parent_bridge,
            parent_verifier,
        })
    }

    pub fn install_for_reconcile_v2(
        &self,
        package: &PrivateOramOwnerRecoveryCapsulePackageV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramMutationJournalError>
    {
        let activation_authority = reconcile_snapshot
            .activation_authority()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        self.validate_reconcile_install(package, reconcile_snapshot)?;
        self.install(package, activation_authority, resources)
    }

    pub(crate) fn install(
        &self,
        package: &PrivateOramOwnerRecoveryCapsulePackageV2,
        current_activation_authority: &PrivateOramActivationAuthorityLocatorV1,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramMutationJournalError>
    {
        validate_capsule_package_v2(
            package,
            &self.validator,
            &self.expected_collection_id,
            self.expected_owner_peer_id,
            current_activation_authority,
        )?;
        self.ensure_layout()?;
        let lock = self.acquire_lock()?;
        self.validate_install_resources_locked(package, resources)?;
        let root = lock.root_file();
        let temp = PrivateOramPinnedDirectoryV2::open_at(root, std::ffi::OsStr::new(TEMP_DIR))?;
        temp.validate_binding(root, std::ffi::OsStr::new(TEMP_DIR))?;

        let mut superseding_previous_generation = false;
        if let Some(existing_file) = optional_private_oram_file_at_v2(
            root,
            std::ffi::OsStr::new(CAPSULE_FILE),
            CAPSULE_MAX_BYTES,
        )? {
            let existing: PrivateOramOwnerRecoveryCapsulePackageV2 = existing_file.deserialize()?;
            if existing == *package {
                existing_file.validate_binding_and_contents(root)?;
                root.sync_all()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                temp.sync()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                lock.validate_root_identity()?;
                return capsule_install_receipt_v2(package);
            }
            // Only one mutation is ever active per collection, so a capsule minted for a later
            // lease generation supersedes the previous mutation's capsule; the store is not a
            // one-shot per collection. Any other difference is a conflicting install for the
            // same generation (or a replay of an older one) and fails closed.
            if package.lease_generation() <= existing.lease_generation() {
                return Err(PrivateOramMutationJournalError::ConcurrentMutation);
            }
            superseding_previous_generation = true;
        }

        let candidate = PrivateOramJsonCandidateV2::new(&temp, package, CAPSULE_MAX_BYTES)?;
        candidate.validate_source(&temp)?;
        if let Err(error) = rename_private_oram_entry_at_v2(
            &temp.file,
            candidate.name(),
            root,
            std::ffi::OsStr::new(CAPSULE_FILE),
            !superseding_previous_generation,
        ) {
            if let Some(installed) = optional_private_oram_file_at_v2(
                root,
                std::ffi::OsStr::new(CAPSULE_FILE),
                CAPSULE_MAX_BYTES,
            )? {
                let actual: PrivateOramOwnerRecoveryCapsulePackageV2 = installed.deserialize()?;
                if actual != *package {
                    return Err(PrivateOramMutationJournalError::ConcurrentMutation);
                }
                installed.validate_binding_and_contents(root)?;
                sync_private_oram_root_publish_v2(root, &temp)?;
                lock.validate_root_identity()?;
                return capsule_install_receipt_v2(package);
            }
            return Err(error);
        }
        let installed = candidate
            .validate_installed(
                &lock.root_directory()?,
                std::ffi::OsStr::new(CAPSULE_FILE),
                CAPSULE_MAX_BYTES,
            )
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        let actual: PrivateOramOwnerRecoveryCapsulePackageV2 = installed
            .deserialize()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        if actual != *package {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        sync_private_oram_root_publish_v2(root, &temp)?;
        installed
            .validate_binding_and_contents(root)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        candidate.keep_after_publish()?;
        lock.validate_root_identity()?;
        capsule_install_receipt_v2(package)
    }

    fn validate_reconcile_install(
        &self,
        package: &PrivateOramOwnerRecoveryCapsulePackageV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let capsule = &package.capsule;
        let activation_authority = reconcile_snapshot
            .activation_authority()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        validate_capsule_package_v2(
            package,
            &self.validator,
            &self.expected_collection_id,
            self.expected_owner_peer_id,
            activation_authority,
        )?;
        let expected_watermark = derive_private_oram_mutation_parent_watermark_for_state_v2(
            &capsule.descriptor,
            &capsule.point_stage_state,
        )?;
        let slot = reconcile_snapshot.lease_slot();
        // The active lease may have been renewed since the capsule was minted (a longer expiry
        // and a higher renewal revision); `validate_reconcile_lease_slot` accepts exactly those
        // renewals and nothing else. Installs must still precede any abort decision.
        let active_lease = validate_reconcile_lease_slot(&capsule.descriptor, slot)?;
        if reconcile_snapshot.parent_watermark() != Some(expected_watermark.watermark())
            || reconcile_snapshot.consensus_state()
                != &capsule.descriptor.expected_consensus_old_state
            || active_lease.phase != PrivateOramMutationLeasePhase::Preparing
            || capsule.descriptor.preparing_lease.phase != PrivateOramMutationLeasePhase::Preparing
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        if let Some(certificate) = reconcile_snapshot.recovery_capsules_certificate() {
            let expected_receipt = capsule_install_receipt_v2(package)?;
            let ready = certificate.ready();
            if ready.point_stage_watermark() != expected_watermark.watermark()
                || ready.activation_authority() != activation_authority
                || ready.capsule_set_digest() != package.capsule_set_digest()
                || ready.receipt_for_owner(self.expected_owner_peer_id) != Some(&expected_receipt)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        Ok(())
    }

    pub fn load_recovery_material_v2(
        &self,
        current_activation_authority: &PrivateOramActivationAuthorityLocatorV1,
    ) -> Result<PrivateOramMutationRecoveryMaterialV2, PrivateOramMutationJournalError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.root.join(TEMP_DIR))?;
        let lock = self.acquire_lock()?;
        let package = self.load_package_locked(&lock, current_activation_authority)?;
        Ok(PrivateOramMutationRecoveryMaterialV2 {
            immutable_manifest: package.capsule.immutable_manifest,
            mutation_bundle: package.capsule.descriptor.mutation_bundle,
        })
    }

    pub fn load_recovery_material_for_reconcile_v2(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
    ) -> Result<PrivateOramMutationRecoveryMaterialV2, PrivateOramMutationJournalError> {
        let activation_authority = reconcile_snapshot
            .activation_authority()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        self.load_recovery_material_v2(activation_authority)
    }

    pub fn recover_remote_owner_pair_v2(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        request: &PrivateOramPeerRecoveryRequestV2,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<PrivateOramPeerRecoveryTerminalV2, PrivateOramMutationJournalError> {
        validate_private_oram_peer_recovery_request_v2_shape(request)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
        self.validator
            .validate_owner_recovery_resources_v1(&resources)?;
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.root.join(TEMP_DIR))?;

        let lock = self.acquire_lock()?;
        let activation_authority = reconcile_snapshot
            .activation_authority()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        let package = self.load_package_locked(&lock, activation_authority)?;
        let capsule = &package.capsule;
        if resources.immutable_manifest != &capsule.immutable_manifest
            || resources.mutation_bundle != &capsule.descriptor.mutation_bundle
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }

        let (active_lease, disposition, decision) = validated_reconcile_decision_for_v2_state(
            &capsule.descriptor,
            &capsule.point_stage_state,
            reconcile_snapshot,
        )?;
        let recovery_certificate = reconcile_snapshot
            .recovery_capsules_certificate()
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        let expected_point_stage = derive_private_oram_mutation_parent_watermark_for_state_v2(
            &capsule.descriptor,
            &capsule.point_stage_state,
        )?;
        let ready = recovery_certificate.ready();
        let owner_receipt = ready
            .receipt_for_owner(self.expected_owner_peer_id)
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        if recovery_certificate.generation() != active_lease.generation
            || ready.point_stage_watermark() != expected_point_stage.watermark()
            || ready.activation_authority() != activation_authority
            || ready.capsule_set_digest() != capsule.capsule_set_digest
            || owner_receipt.owner_peer_id() != capsule.owner_peer_id
            || owner_receipt.parent_descriptor_digest() != capsule.descriptor.descriptor_digest
            || owner_receipt.capsule_digest() != capsule.capsule_digest
            || owner_receipt.capsule_set_digest() != capsule.capsule_set_digest
            || owner_receipt.activation_authority() != activation_authority
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }

        let mutation = &capsule.descriptor.mutation_bundle.mutation;
        let manifest = &capsule.immutable_manifest.manifest;
        let hnsw_index = manifest
            .indexes
            .iter()
            .find(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if request.collection_id != mutation.collection_id
            || request.mutation_id != mutation.mutation_id
            || request.parent_descriptor_digest != capsule.descriptor.descriptor_digest
            || request.decision_record_digest != decision.authority_record_digest()
            || request.coordinator_peer_id != capsule.descriptor.coordinator_peer_id
            || request.owner_peer_id != self.expected_owner_peer_id
            || request.owner_signing_key_id != manifest.owner_signing_key_id
            || request.vector_name != hnsw_index.index_name
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }

        let authority = build_owner_recovery_authority_v2(
            &capsule.descriptor,
            &capsule.point_stage_state,
            &active_lease,
            disposition,
            self.expected_owner_peer_id,
        )?;
        let expected_package = package.clone();
        let live = PrivateOramLiveOwnerRecoveryAuthorityV1::new(
            authority,
            &lock,
            &self.parent_bridge,
            &self.parent_verifier,
        );
        let terminal = live
            .recover_pair_then_v1(resources, |outcome| {
                let revalidated = self
                    .load_package_locked(&lock, activation_authority)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                if revalidated != expected_package {
                    return Err(PrivateOramMutationJournalError::Indeterminate);
                }
                lock.validate_root_identity()
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                private_oram_peer_recovery_terminal_from_outcome_v2(request, &outcome)
            })
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)??;
        drop(live);
        lock.validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(terminal)
    }

    fn load_package_locked(
        &self,
        lock: &PrivateOramOwnerRecoveryCapsuleLockV2,
        current_activation_authority: &PrivateOramActivationAuthorityLocatorV1,
    ) -> Result<PrivateOramOwnerRecoveryCapsulePackageV2, PrivateOramMutationJournalError> {
        let root = lock.root_file();
        let temp = PrivateOramPinnedDirectoryV2::open_at(root, std::ffi::OsStr::new(TEMP_DIR))?;
        let file = required_v2_artifact(PrivateOramPinnedFileV2::open_at(
            root,
            std::ffi::OsStr::new(CAPSULE_FILE),
            CAPSULE_MAX_BYTES,
        ))?;
        let package: PrivateOramOwnerRecoveryCapsulePackageV2 = file.deserialize()?;
        validate_capsule_package_v2(
            &package,
            &self.validator,
            &self.expected_collection_id,
            self.expected_owner_peer_id,
            current_activation_authority,
        )?;
        file.validate_binding_and_contents(root)?;
        temp.validate_binding(root, std::ffi::OsStr::new(TEMP_DIR))?;
        lock.validate_root_identity()?;
        Ok(package)
    }

    fn validate_install_resources_locked(
        &self,
        package: &PrivateOramOwnerRecoveryCapsulePackageV2,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<(), PrivateOramMutationJournalError> {
        let capsule = &package.capsule;
        if resources.immutable_manifest != &capsule.immutable_manifest
            || resources.mutation_bundle != &capsule.descriptor.mutation_bundle
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        self.validator
            .validate_owner_recovery_resources_v1(&resources)?;
        let authority = build_owner_recovery_authority_v2(
            &capsule.descriptor,
            &capsule.point_stage_state,
            &capsule.descriptor.preparing_lease,
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision,
            capsule.owner_peer_id,
        )?;
        let disposition = authority
            .classify_pair_recovery_stores_v1(resources)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if disposition != PrivateOramOwnerRecoveryStoreDispositionV1::AllOld {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        Ok(())
    }

    fn ensure_layout(&self) -> Result<(), PrivateOramMutationJournalError> {
        let collection_path = self
            .root
            .parent()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let collection_metadata =
            fs::symlink_metadata(collection_path).map_err(PrivateOramMutationJournalError::Io)?;
        if !collection_metadata.file_type().is_dir() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        create_private_directory(&self.root)?;
        create_private_directory(&self.root.join(TEMP_DIR))
    }

    fn acquire_lock(
        &self,
    ) -> Result<PrivateOramOwnerRecoveryCapsuleLockV2, PrivateOramMutationJournalError> {
        let root = open_pinned_private_directory(&self.root)?;
        let file = open_private_oram_capsule_lock_v2(root.directory.file())?;
        file.lock_exclusive()
            .map_err(PrivateOramMutationJournalError::Io)?;
        let pinned = PrivateOramPinnedFileV2::open_at(
            root.directory.file(),
            std::ffi::OsStr::new(CAPSULE_LOCK_FILE),
            0,
        )?;
        ensure_same_file(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &pinned
                .file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
        )?;
        pinned.validate_binding_and_contents(root.directory.file())?;
        file.sync_all()
            .map_err(PrivateOramMutationJournalError::Io)?;
        root.directory
            .sync_all()
            .map_err(PrivateOramMutationJournalError::Io)?;
        let lock = PrivateOramOwnerRecoveryCapsuleLockV2 {
            _file: file,
            root,
            root_path: self.root.clone(),
        };
        lock.validate_root_identity()?;
        Ok(lock)
    }
}

struct PrivateOramOwnerRecoveryCapsuleLockV2 {
    _file: std::fs::File,
    root: PinnedPrivateDirectory,
    root_path: PathBuf,
}

impl Debug for PrivateOramOwnerRecoveryCapsuleLockV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerRecoveryCapsuleLockV2")
            .field("file", &"[held]")
            .field("root", &"[redacted]")
            .field("root_path", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryCapsuleLockV2 {
    fn root_file(&self) -> &std::fs::File {
        self.root.directory.file()
    }

    fn root_directory(
        &self,
    ) -> Result<PrivateOramPinnedDirectoryV2, PrivateOramMutationJournalError> {
        Ok(PrivateOramPinnedDirectoryV2 {
            file: self
                .root_file()
                .try_clone()
                .map_err(PrivateOramMutationJournalError::Io)?,
        })
    }

    fn validate_root_identity(&self) -> Result<(), PrivateOramMutationJournalError> {
        self.root.validate_at_path(&self.root_path)
    }
}

impl PrivateOramMutationJournal {
    pub fn owner_recovery_capsule_package_v2(
        &self,
        owner_peer_id: PeerId,
        activation_authority: PrivateOramActivationAuthorityLocatorV1,
    ) -> Result<PrivateOramOwnerRecoveryCapsulePackageV2, PrivateOramMutationJournalError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        let snapshot = self.load_v2_locked(&lock)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let history = canonical_private_oram_mutation_state_history_v2(
            &snapshot.descriptor,
            &snapshot.state,
        )?;
        let point_stage_state = history
            .get(
                usize::try_from(
                    PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence() - 1,
                )
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
            )
            .cloned()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        build_owner_recovery_authority_v2(
            &snapshot.descriptor,
            &point_stage_state,
            &snapshot.descriptor.preparing_lease,
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision,
            owner_peer_id,
        )?
        .pair_recovery_projection()?;
        let package = new_capsule_package_v2(
            owner_peer_id,
            activation_authority,
            snapshot.descriptor.clone(),
            snapshot.immutable_manifest.clone(),
            point_stage_state,
        )?;
        validate_capsule_package_v2(
            &package,
            self,
            &snapshot.descriptor.mutation_bundle.mutation.collection_id,
            owner_peer_id,
            package.activation_authority(),
        )?;
        if self.load_v2_locked(&lock)? != snapshot {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        lock.validate_root_identity()?;
        Ok(package)
    }
}

fn new_capsule_package_v2(
    owner_peer_id: PeerId,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    descriptor: PrivateOramMutationJournalDescriptorV1,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    point_stage_state: PrivateOramMutationJournalStateV2,
) -> Result<PrivateOramOwnerRecoveryCapsulePackageV2, PrivateOramMutationJournalError> {
    let immutable_manifest_bundle_sha256 = sha256_serialized_v2(&immutable_manifest)?;
    let mut capsule = PrivateOramOwnerRecoveryCapsuleV2 {
        version: CAPSULE_VERSION,
        owner_peer_id,
        activation_authority,
        descriptor,
        immutable_manifest,
        point_stage_state,
        immutable_manifest_bundle_sha256,
        capsule_digest: String::new(),
        capsule_set_digest: String::new(),
    };
    capsule.capsule_digest = capsule_digest_v2(&capsule, owner_peer_id)?;
    capsule.capsule_set_digest = capsule_set_digest_v2(&capsule)?;
    let package = PrivateOramOwnerRecoveryCapsulePackageV2 {
        version: CAPSULE_PACKAGE_VERSION,
        capsule,
    };
    validate_capsule_package_size_v2(&package)?;
    Ok(package)
}

fn validate_capsule_package_v2(
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
    validator: &PrivateOramMutationJournal,
    expected_collection_id: &str,
    expected_owner_peer_id: PeerId,
    current_activation_authority: &PrivateOramActivationAuthorityLocatorV1,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_capsule_package_size_v2(package)?;
    let capsule = &package.capsule;
    if package.version != CAPSULE_PACKAGE_VERSION
        || capsule.version != CAPSULE_VERSION
        || capsule.owner_peer_id != expected_owner_peer_id
        || &capsule.activation_authority != current_activation_authority
        || capsule.activation_authority.registry_generation() == 0
        || !is_sha256_digest(capsule.activation_authority.manifest_digest())
        || capsule.descriptor.mutation_bundle.mutation.collection_id != expected_collection_id
        || capsule.point_stage_state.phase != PrivateOramMutationJournalPhaseV2::PointStageDurable
        || capsule.point_stage_state.sequence
            != PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_descriptor(&capsule.descriptor, validator.signature_verification())?;
    validator.validate_immutable_manifest_for_descriptor(
        &capsule.immutable_manifest,
        &capsule.descriptor,
    )?;
    validate_private_oram_mutation_state_v2_structure(
        &capsule.descriptor,
        &capsule.point_stage_state,
    )?;
    let history = canonical_private_oram_mutation_state_history_v2(
        &capsule.descriptor,
        &capsule.point_stage_state,
    )?;
    if history.len()
        != usize::try_from(PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        || history.last() != Some(&capsule.point_stage_state)
        || capsule.immutable_manifest_bundle_sha256
            != sha256_serialized_v2(&capsule.immutable_manifest)?
        || capsule.capsule_digest != capsule_digest_v2(capsule, capsule.owner_peer_id)?
        || capsule.capsule_set_digest != capsule_set_digest_v2(capsule)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let owners = capsule_owner_peer_ids_v2(&capsule.descriptor)?;
    if owners.binary_search(&capsule.owner_peer_id).is_err() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn capsule_owner_peer_ids_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<Vec<PeerId>, PrivateOramMutationJournalError> {
    let expected_indexes = descriptor.mutation_bundle.mutation.writebacks.len();
    if expected_indexes == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut owners = BTreeSet::new();
    for requirement in &descriptor.owner_requirements {
        owners.insert(requirement.peer_id);
    }
    if owners.is_empty()
        || owners.iter().any(|owner| {
            descriptor
                .owner_requirements
                .iter()
                .filter(|requirement| requirement.peer_id == *owner)
                .count()
                != expected_indexes
        })
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(owners.into_iter().collect())
}

fn capsule_digest_v2(
    capsule: &PrivateOramOwnerRecoveryCapsuleV2,
    owner_peer_id: PeerId,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CAPSULE_DIGEST_DOMAIN);
    hasher.update(capsule.version.to_be_bytes());
    hasher.update(owner_peer_id.to_be_bytes());
    hasher.update(
        capsule
            .activation_authority
            .registry_generation()
            .to_be_bytes(),
    );
    hash_capsule_digest_field_v2(&mut hasher, capsule.activation_authority.manifest_digest())?;
    hash_capsule_digest_field_v2(&mut hasher, &capsule.descriptor.descriptor_digest)?;
    hash_capsule_digest_field_v2(&mut hasher, &capsule.immutable_manifest_bundle_sha256)?;
    hash_capsule_digest_field_v2(&mut hasher, &capsule.point_stage_state.record_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn capsule_set_digest_v2(
    capsule: &PrivateOramOwnerRecoveryCapsuleV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let owners = capsule_owner_peer_ids_v2(&capsule.descriptor)?;
    let entries = owners
        .into_iter()
        .map(|owner| Ok((owner, capsule_digest_v2(capsule, owner)?)))
        .collect::<Result<Vec<_>, PrivateOramMutationJournalError>>()?;
    private_oram_owner_capsule_set_digest_v2(&entries)
}

fn hash_capsule_digest_field_v2(
    hasher: &mut Sha256,
    value: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    if !is_sha256_digest(value) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(
        u64::try_from(decoded.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(decoded);
    Ok(())
}

fn sha256_serialized_v2<T: Serialize>(
    value: &T,
) -> Result<String, PrivateOramMutationJournalError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(bytes)))
}

fn validate_capsule_package_size_v2(
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let len = serde_json::to_vec(package)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?
        .len();
    if u64::try_from(len).map_err(|_| PrivateOramMutationJournalError::Corrupt)? > CAPSULE_MAX_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn capsule_install_receipt_v2(
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
) -> Result<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramMutationJournalError> {
    let mut receipt = PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 {
        version: CAPSULE_INSTALL_RECEIPT_VERSION,
        owner_peer_id: package.capsule.owner_peer_id,
        parent_descriptor_digest: package.capsule.descriptor.descriptor_digest.clone(),
        capsule_digest: package.capsule.capsule_digest.clone(),
        capsule_set_digest: package.capsule.capsule_set_digest.clone(),
        activation_authority: package.capsule.activation_authority.clone(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = capsule_install_receipt_digest_v2(&receipt)?;
    validate_private_oram_owner_recovery_capsule_install_receipt_v2(&receipt)?;
    Ok(receipt)
}

#[cfg(test)]
pub(crate) fn private_oram_owner_recovery_capsule_install_receipt_for_test(
    owner_peer_id: PeerId,
    parent_descriptor_digest: String,
    capsule_digest: String,
    capsule_set_digest: String,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
) -> Result<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramMutationJournalError> {
    let mut receipt = PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 {
        version: CAPSULE_INSTALL_RECEIPT_VERSION,
        owner_peer_id,
        parent_descriptor_digest,
        capsule_digest,
        capsule_set_digest,
        activation_authority,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = capsule_install_receipt_digest_v2(&receipt)?;
    validate_private_oram_owner_recovery_capsule_install_receipt_v2(&receipt)?;
    Ok(receipt)
}

#[doc(hidden)]
pub fn validate_private_oram_owner_recovery_capsule_install_receipt_v2(
    receipt: &PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if receipt.version != CAPSULE_INSTALL_RECEIPT_VERSION
        || receipt.owner_peer_id == 0
        || !is_sha256_digest(&receipt.parent_descriptor_digest)
        || !is_sha256_digest(&receipt.capsule_digest)
        || !is_sha256_digest(&receipt.capsule_set_digest)
        || receipt.activation_authority.registry_generation() == 0
        || !is_sha256_digest(receipt.activation_authority.manifest_digest())
        || !is_sha256_digest(&receipt.receipt_digest)
        || receipt.receipt_digest != capsule_install_receipt_digest_v2(receipt)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

#[doc(hidden)]
pub fn encode_private_oram_owner_recovery_capsule_package_v2(
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    validate_capsule_package_size_v2(package)?;
    let encoded = serde_json::to_vec(package)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(encoded)
}

#[doc(hidden)]
pub fn decode_private_oram_owner_recovery_capsule_package_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerRecoveryCapsulePackageV2, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let package: PrivateOramOwnerRecoveryCapsulePackageV2 =
        serde_json::from_slice(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encode_private_oram_owner_recovery_capsule_package_v2(&package)? != encoded {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(package)
}

#[doc(hidden)]
pub fn encode_private_oram_owner_recovery_capsule_install_receipt_v2(
    receipt: &PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    validate_private_oram_owner_recovery_capsule_install_receipt_v2(receipt)?;
    let encoded = serde_json::to_vec(receipt)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    if encoded.is_empty()
        || encoded.len() > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(encoded)
}

#[doc(hidden)]
pub fn decode_private_oram_owner_recovery_capsule_install_receipt_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramMutationJournalError> {
    if encoded.is_empty()
        || encoded.len() > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let receipt: PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 =
        serde_json::from_slice(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encode_private_oram_owner_recovery_capsule_install_receipt_v2(&receipt)? != encoded {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(receipt)
}

fn capsule_install_receipt_digest_v2(
    receipt: &PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(CAPSULE_INSTALL_RECEIPT_DIGEST_DOMAIN);
    hasher.update(receipt.version.to_be_bytes());
    hasher.update(receipt.owner_peer_id.to_be_bytes());
    hash_capsule_digest_field_v2(&mut hasher, &receipt.parent_descriptor_digest)?;
    hash_capsule_digest_field_v2(&mut hasher, &receipt.capsule_digest)?;
    hash_capsule_digest_field_v2(&mut hasher, &receipt.capsule_set_digest)?;
    hasher.update(
        receipt
            .activation_authority
            .registry_generation()
            .to_be_bytes(),
    );
    hash_capsule_digest_field_v2(&mut hasher, receipt.activation_authority.manifest_digest())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn open_private_oram_capsule_lock_v2(
    root: &std::fs::File,
) -> Result<std::fs::File, PrivateOramMutationJournalError> {
    let name = checked_private_oram_entry_name_v2(std::ffi::OsStr::new(CAPSULE_LOCK_FILE))?;
    let how = PrivateOramOpenHowV2 {
        flags: u64::try_from(
            nix::libc::O_RDWR | nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_CREAT,
        )
        .map_err(|_| PrivateOramMutationJournalError::Unsupported)?,
        mode: 0o600,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `name` is a single-component C string, `how` has the Linux open_how ABI, and the
    // returned descriptor is owned immediately on success.
    let descriptor = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<PrivateOramOpenHowV2>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::E2BIG) => {
                PrivateOramMutationJournalError::Unsupported
            }
            _ => PrivateOramMutationJournalError::Io(error),
        });
    }
    let descriptor =
        i32::try_from(descriptor).map_err(|_| PrivateOramMutationJournalError::Unsupported)?;
    // SAFETY: the successful syscall returned one owned file descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
    validate_private_file_metadata(
        &file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        0,
    )?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_private_oram_capsule_lock_v2(
    _root: &std::fs::File,
) -> Result<std::fs::File, PrivateOramMutationJournalError> {
    Err(PrivateOramMutationJournalError::Unsupported)
}
