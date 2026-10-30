//! Process-local signer storage and lifetime fence for private ORAM peer recovery.
//!
//! Temporary frame buffers are zeroized, but `ring` key objects and the kernel page cache are not
//! covered by that guarantee. Activated V2 startup retains an exclusive identity-directory lock
//! through this object's lifetime, so another process using the same storage root cannot infer
//! restart absence while this incarnation remains alive.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "security-sensitive raw-FD code requires explicit openat, inode, and fsync handling"
)]

use std::ffi::{CStr, CString};
use std::fmt::{self, Debug, Formatter};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateOramOwnerAdoptionRequestV1, PrivateOramOwnerAdoptionResponseV1,
    PrivateOramOwnerCapsuleInstallAttestationStatementV2,
    PrivateOramOwnerCapsuleInstallAttestationV2, PrivateOramOwnerCapsuleInstallRequestV2,
    PrivateOramOwnerCapsuleInstallResponseV2, PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramOwnerEnrollmentPreparedV1,
    PrivateOramOwnerLifecycleStateV1, PrivateOramOwnerPrestageAttestationStatementV2,
    PrivateOramOwnerPrestageAttestationV2, PrivateOramOwnerPrestageRequestV2,
    PrivateOramOwnerPrestageResponseV2, PrivateOramOwnerReservationPrepareChallengeV1,
    PrivateOramOwnerReservationPrepareV1, PrivateOramOwnerReservationResolutionReceiptV1,
    PrivateOramPeerActivationChallengeV1, PrivateOramPeerActivationObservationV1,
    PrivateOramPeerActivationSignedAckV1, PrivateOramPeerRecoveryPublicKeyV1,
    PrivateOramPeerRecoveryRequestV2, PrivateOramPeerRecoverySignatureV2,
    PrivateOramPeerRecoveryTerminalV2, SignedPrivateOramOwnerReservationResolutionReceiptV1,
    private_oram_owner_cleanup_signer_v1, private_oram_peer_recovery_public_key_v1,
    sign_private_oram_owner_adoption_request_v1, sign_private_oram_owner_adoption_response_v1,
    sign_private_oram_owner_capsule_install_attestation_v2,
    sign_private_oram_owner_capsule_install_request_v2,
    sign_private_oram_owner_capsule_install_response_v2,
    sign_private_oram_owner_enrollment_genesis_commitment_v1,
    sign_private_oram_owner_prestage_attestation_v2, sign_private_oram_owner_prestage_request_v2,
    sign_private_oram_owner_prestage_response_v2, sign_private_oram_owner_reservation_prepare_v1,
    sign_private_oram_owner_reservation_resolution_receipt_v1,
    sign_private_oram_peer_activation_ack_v1, sign_private_oram_peer_recovery_request_v2,
    sign_private_oram_peer_recovery_response_v2, validate_private_oram_peer_recovery_public_key_v1,
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::Ed25519KeyPair;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_DIRECTORY: &CStr = c".private_oram_peer_identity";
const IDENTITY_FILE: &CStr = c"identity.bin";
const IDENTITY_CANDIDATE_FILE: &CStr = c"identity.bin.candidate";
const IDENTITY_MAGIC: &[u8; 8] = b"QDPORID1";
const IDENTITY_FORMAT_VERSION: u16 = 1;
const IDENTITY_KEY_EPOCH: u64 = 1;
const IDENTITY_MAX_PKCS8_BYTES: usize = 512;
const IDENTITY_CHECKSUM_BYTES: usize = 32;
const IDENTITY_HEADER_BYTES: usize =
    IDENTITY_MAGIC.len() + size_of::<u16>() + size_of::<u64>() * 2 + size_of::<u32>();
const IDENTITY_MAX_FILE_BYTES: u64 =
    (IDENTITY_HEADER_BYTES + IDENTITY_MAX_PKCS8_BYTES + IDENTITY_CHECKSUM_BYTES) as u64;

#[derive(Error, PartialEq, Eq)]
pub(crate) enum PrivateOramPeerIdentityError {
    #[error("private ORAM peer identity is unsupported on this platform or filesystem")]
    Unsupported,
    #[error("private ORAM peer identity storage root is insecure or invalid")]
    InvalidStorageRoot,
    #[error("private ORAM peer identity directory is insecure or invalid")]
    InvalidIdentityDirectory,
    #[error("private ORAM peer identity is already locked by another process")]
    IdentityLocked,
    #[error("pinned private ORAM peer identity is missing")]
    MissingPinnedIdentity,
    #[error("private ORAM peer identity file is insecure, ambiguous, or corrupt")]
    InvalidIdentityFile,
    #[error("private ORAM peer identity belongs to a different peer")]
    PeerIdMismatch,
    #[error("private ORAM peer identity does not match the pinned public key")]
    PinnedKeyMismatch,
    #[error("private ORAM peer identity key generation failed")]
    KeyGenerationFailed,
    #[error("private ORAM peer identity cryptographic validation failed")]
    CryptographicValidationFailed,
    #[error("private ORAM peer identity persistence failed")]
    PersistenceFailed,
    #[error("private ORAM peer identity persistence outcome is indeterminate")]
    Indeterminate,
}

impl Debug for PrivateOramPeerIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramPeerIdentityError")
            .field(&self.to_string())
            .finish()
    }
}

pub(crate) struct PrivateOramPeerRecoveryIdentity {
    key_pair: Ed25519KeyPair,
    public_key: PrivateOramPeerRecoveryPublicKeyV1,
    peer_id: u64,
    process_incarnation: String,
    storage_root: File,
    directory_lock: File,
}

pub(crate) enum PrivateOramPeerIdentityOpenPolicy<'a> {
    BootstrapUnpinned,
    RequirePinned(&'a PrivateOramPeerRecoveryPublicKeyV1),
}

impl PrivateOramPeerIdentityOpenPolicy<'_> {
    fn expected_pin(&self) -> Option<&PrivateOramPeerRecoveryPublicKeyV1> {
        match self {
            Self::BootstrapUnpinned => None,
            Self::RequirePinned(public_key) => Some(public_key),
        }
    }

    fn may_create(&self) -> bool {
        matches!(self, Self::BootstrapUnpinned)
    }
}

impl Debug for PrivateOramPeerRecoveryIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramPeerRecoveryIdentity")
            .field("peer_id", &"[redacted]")
            .field("key_epoch", &self.public_key.key_epoch)
            .field("key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PrivateOramPeerRecoveryIdentity {
    pub(crate) fn open_or_create(
        storage_path: &Path,
        peer_id: u64,
        policy: PrivateOramPeerIdentityOpenPolicy<'_>,
    ) -> Result<Self, PrivateOramPeerIdentityError> {
        let expected_pin = policy.expected_pin();
        if let Some(expected_pin) = expected_pin {
            validate_private_oram_peer_recovery_public_key_v1(expected_pin)
                .map_err(|_| PrivateOramPeerIdentityError::PinnedKeyMismatch)?;
        }

        let storage_root = open_storage_root(storage_path)?;
        let directory_lock = open_or_create_identity_directory(&storage_root, policy.may_create())?;
        lock_identity_directory(&directory_lock)?;
        validate_identity_directory_binding(&storage_root, &directory_lock)?;
        directory_lock
            .sync_all()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;

        let loaded = match open_optional_private_file(&directory_lock, IDENTITY_FILE)? {
            Some(identity_file) => {
                if open_optional_private_file(&directory_lock, IDENTITY_CANDIDATE_FILE)?.is_some() {
                    return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
                }
                load_identity(
                    &directory_lock,
                    identity_file,
                    IDENTITY_FILE,
                    peer_id,
                    expected_pin,
                )?
            }
            None => match open_optional_private_file(&directory_lock, IDENTITY_CANDIDATE_FILE)? {
                Some(candidate_file) => {
                    let candidate_witness = candidate_file
                        .try_clone()
                        .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
                    let candidate_metadata = candidate_witness
                        .metadata()
                        .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
                    let candidate = load_identity(
                        &directory_lock,
                        candidate_file,
                        IDENTITY_CANDIDATE_FILE,
                        peer_id,
                        expected_pin,
                    )?;
                    sync_private_file_binding(
                        &directory_lock,
                        IDENTITY_CANDIDATE_FILE,
                        &candidate_witness,
                    )?;
                    rename_identity_candidate(&directory_lock)?;
                    directory_lock
                        .sync_all()
                        .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
                    let identity_file = open_optional_private_file(&directory_lock, IDENTITY_FILE)?
                        .ok_or(PrivateOramPeerIdentityError::Indeterminate)?;
                    let identity_metadata = identity_file
                        .metadata()
                        .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
                    let candidate_after_publish = candidate_witness
                        .metadata()
                        .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
                    ensure_same_inode(
                        &candidate_metadata,
                        &candidate_after_publish,
                        PrivateOramPeerIdentityError::Indeterminate,
                    )?;
                    ensure_same_inode(
                        &candidate_after_publish,
                        &identity_metadata,
                        PrivateOramPeerIdentityError::Indeterminate,
                    )?;
                    let installed = load_identity(
                        &directory_lock,
                        identity_file,
                        IDENTITY_FILE,
                        peer_id,
                        expected_pin,
                    )?;
                    if candidate.public_key != installed.public_key {
                        return Err(PrivateOramPeerIdentityError::Indeterminate);
                    }
                    installed
                }
                None => {
                    if expected_pin.is_some() {
                        return Err(PrivateOramPeerIdentityError::MissingPinnedIdentity);
                    }
                    create_identity(&directory_lock, peer_id)?
                }
            },
        };
        validate_identity_directory_binding(&storage_root, &directory_lock)?;
        let mut process_incarnation = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut process_incarnation)
            .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)?;

        Ok(Self {
            key_pair: loaded.key_pair,
            public_key: loaded.public_key,
            peer_id,
            process_incarnation: BASE64URL_NOPAD.encode(&process_incarnation),
            storage_root,
            directory_lock,
        })
    }

    pub(crate) fn public_key(&self) -> &PrivateOramPeerRecoveryPublicKeyV1 {
        &self.public_key
    }

    pub(crate) fn peer_id(&self) -> u64 {
        self.peer_id
    }

    pub(crate) fn process_incarnation(&self) -> &str {
        &self.process_incarnation
    }

    pub(crate) fn require_process_lifetime_fence(
        &self,
        expected_peer_id: u64,
    ) -> Result<&str, PrivateOramPeerIdentityError> {
        if self.peer_id != expected_peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        // The private descriptor is locked before construction and cannot be replaced by callers.
        // Rebinding it here proves this exact live object still names the secured storage root.
        validate_identity_directory_binding(&self.storage_root, &self.directory_lock)?;
        Ok(&self.process_incarnation)
    }

    pub(crate) fn owner_cleanup_signer(
        &self,
    ) -> Result<PrivateOramOwnerCleanupSignerV1, PrivateOramPeerIdentityError> {
        private_oram_owner_cleanup_signer_v1(&self.key_pair, self.public_key.key_epoch)
            .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_enrollment_genesis_commitment(
        &self,
        prepared: &PrivateOramOwnerEnrollmentPreparedV1,
    ) -> Result<PrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramPeerIdentityError> {
        if prepared.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_enrollment_genesis_commitment_v1(&self.key_pair, prepared)
            .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_reservation_prepare(
        &self,
        challenge: PrivateOramOwnerReservationPrepareChallengeV1,
        observed_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
        local_terminal_generation: u64,
        durable_fence_record_digest: String,
    ) -> Result<PrivateOramOwnerReservationPrepareV1, PrivateOramPeerIdentityError> {
        if challenge.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_reservation_prepare_v1(
            &self.key_pair,
            challenge,
            observed_lifecycle_state,
            local_terminal_generation,
            durable_fence_record_digest,
            self.owner_cleanup_signer()?,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    /// Signs this owner's genesis commitment for a committed prepared enrollment.
    pub(crate) fn sign_owner_enrollment_genesis(
        &self,
        prepared: &PrivateOramOwnerEnrollmentPreparedV1,
    ) -> Result<PrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramPeerIdentityError> {
        if prepared.owner_peer_id != self.peer_id
            || prepared.owner_signer != self.owner_cleanup_signer()?
        {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_enrollment_genesis_commitment_v1(&self.key_pair, prepared)
            .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_reservation_resolution(
        &self,
        receipt: PrivateOramOwnerReservationResolutionReceiptV1,
    ) -> Result<SignedPrivateOramOwnerReservationResolutionReceiptV1, PrivateOramPeerIdentityError>
    {
        if receipt.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_reservation_resolution_receipt_v1(
            &self.key_pair,
            receipt,
            self.owner_cleanup_signer()?,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_activation_ack(
        &self,
        challenge: &PrivateOramPeerActivationChallengeV1,
        observation: PrivateOramPeerActivationObservationV1,
    ) -> Result<PrivateOramPeerActivationSignedAckV1, PrivateOramPeerIdentityError> {
        if challenge.target_peer_id != self.peer_id || observation.responder_peer_id != self.peer_id
        {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_peer_activation_ack_v1(
            &self.key_pair,
            self.public_key.key_epoch,
            challenge,
            observation,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_response(
        &self,
        request: &PrivateOramPeerRecoveryRequestV2,
        terminal: &PrivateOramPeerRecoveryTerminalV2,
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.owner_peer_id != self.peer_id || terminal.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_peer_recovery_response_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
            terminal,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_recovery_request(
        &self,
        request: &PrivateOramPeerRecoveryRequestV2,
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.coordinator_peer_id != self.peer_id || request.owner_peer_id == self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_peer_recovery_request_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_capsule_install_request(
        &self,
        request: &PrivateOramOwnerCapsuleInstallRequestV2,
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.coordinator_peer_id != self.peer_id || request.owner_peer_id == self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_capsule_install_request_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_capsule_install_response(
        &self,
        request: &PrivateOramOwnerCapsuleInstallRequestV2,
        response: &PrivateOramOwnerCapsuleInstallResponseV2,
        receipt_canonical_json: &[u8],
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.owner_peer_id != self.peer_id || response.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_capsule_install_response_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
            response,
            receipt_canonical_json,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_capsule_install_attestation(
        &self,
        statement: &PrivateOramOwnerCapsuleInstallAttestationStatementV2,
    ) -> Result<PrivateOramOwnerCapsuleInstallAttestationV2, PrivateOramPeerIdentityError> {
        if statement.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_capsule_install_attestation_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            statement,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_adoption_request(
        &self,
        request: &PrivateOramOwnerAdoptionRequestV1,
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.coordinator_peer_id != self.peer_id || request.owner_peer_id == self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_adoption_request_v1(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_adoption_response(
        &self,
        request: &PrivateOramOwnerAdoptionRequestV1,
        response: &PrivateOramOwnerAdoptionResponseV1,
        evidence_canonical_json: &[u8],
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.owner_peer_id != self.peer_id || response.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_adoption_response_v1(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
            response,
            evidence_canonical_json,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_prestage_request(
        &self,
        request: &PrivateOramOwnerPrestageRequestV2,
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.coordinator_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_prestage_request_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_prestage_response(
        &self,
        request: &PrivateOramOwnerPrestageRequestV2,
        response: &PrivateOramOwnerPrestageResponseV2,
        receipt_canonical_json: &[u8],
    ) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramPeerIdentityError> {
        if request.owner_peer_id != self.peer_id || response.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_prestage_response_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            request,
            response,
            receipt_canonical_json,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }

    pub(crate) fn sign_owner_prestage_attestation(
        &self,
        statement: &PrivateOramOwnerPrestageAttestationStatementV2,
    ) -> Result<PrivateOramOwnerPrestageAttestationV2, PrivateOramPeerIdentityError> {
        if statement.owner_peer_id != self.peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        sign_private_oram_owner_prestage_attestation_v2(
            &self.key_pair,
            self.public_key.key_epoch,
            statement,
        )
        .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)
    }
}

struct LoadedIdentity {
    key_pair: Ed25519KeyPair,
    public_key: PrivateOramPeerRecoveryPublicKeyV1,
}

/// Linux-only filesystem primitives (O_PATH directory handles, /proc/self/fd re-opens,
/// inode witnesses, and advisory locks) that back the on-disk identity.
#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub(super) fn open_storage_root(
        storage_path: &Path,
    ) -> Result<File, PrivateOramPeerIdentityError> {
        if storage_path.as_os_str().is_empty() {
            return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
        }

        let mut components = Vec::new();
        for component in storage_path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(component) => components.push(
                    CString::new(component.as_bytes())
                        .map_err(|_| PrivateOramPeerIdentityError::InvalidStorageRoot)?,
                ),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
                }
            }
        }

        let anchor = if storage_path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut current = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(anchor)
            .map_err(|_| PrivateOramPeerIdentityError::InvalidStorageRoot)?;
        let anchor_metadata = current
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidStorageRoot)?;
        validate_storage_directory_metadata(&anchor_metadata, components.is_empty())?;

        let component_count = components.len();
        for (index, component) in components.iter().enumerate() {
            current = open_storage_directory_at(&current, component)?;
            let metadata = current
                .metadata()
                .map_err(|_| PrivateOramPeerIdentityError::InvalidStorageRoot)?;
            validate_storage_directory_metadata(&metadata, index + 1 == component_count)?;
        }
        Ok(current)
    }

    pub(super) fn open_storage_directory_at(
        parent: &File,
        component: &CStr,
    ) -> Result<File, PrivateOramPeerIdentityError> {
        // SAFETY: component was derived from one Path component and parent is a pinned directory fd.
        let descriptor = unsafe {
            nix::libc::openat(
                parent.as_raw_fd(),
                component.as_ptr(),
                nix::libc::O_RDONLY
                    | nix::libc::O_DIRECTORY
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
        }
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    pub(super) fn validate_storage_directory_metadata(
        metadata: &Metadata,
        is_final: bool,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        if !metadata.is_dir() {
            return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
        }
        let owner = metadata.uid();
        let effective_uid = unsafe { nix::libc::geteuid() };
        if owner != 0 && owner != effective_uid {
            return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
        }
        let mode = metadata.permissions().mode();
        if is_final {
            if mode & 0o022 != 0 {
                return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
            }
        } else if mode & 0o022 != 0 {
            let root_owned_sticky = owner == 0 && mode & 0o1000 != 0;
            if !root_owned_sticky {
                return Err(PrivateOramPeerIdentityError::InvalidStorageRoot);
            }
        }
        Ok(())
    }

    pub(super) fn open_or_create_identity_directory(
        storage_root: &File,
        create: bool,
    ) -> Result<File, PrivateOramPeerIdentityError> {
        match open_identity_directory(storage_root) {
            Ok(directory) => {
                storage_root
                    .sync_all()
                    .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
                return Ok(directory);
            }
            Err(PrivateOramPeerIdentityError::MissingPinnedIdentity) if create => {}
            Err(error) => return Err(error),
        }

        // SAFETY: the name is a fixed single component and storage_root is a validated directory fd.
        let result = unsafe {
            nix::libc::mkdirat(storage_root.as_raw_fd(), IDENTITY_DIRECTORY.as_ptr(), 0o700)
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::EEXIST) {
                return Err(PrivateOramPeerIdentityError::PersistenceFailed);
            }
        }
        let directory = open_identity_directory(storage_root)?;
        storage_root
            .sync_all()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        Ok(directory)
    }

    pub(super) fn open_identity_directory(
        storage_root: &File,
    ) -> Result<File, PrivateOramPeerIdentityError> {
        // SAFETY: the name is a fixed single component and storage_root is a validated directory fd.
        let descriptor = unsafe {
            nix::libc::openat(
                storage_root.as_raw_fd(),
                IDENTITY_DIRECTORY.as_ptr(),
                nix::libc::O_RDONLY
                    | nix::libc::O_DIRECTORY
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(nix::libc::ENOENT) {
                Err(PrivateOramPeerIdentityError::MissingPinnedIdentity)
            } else {
                Err(PrivateOramPeerIdentityError::InvalidIdentityDirectory)
            };
        }
        // SAFETY: openat returned a new owned descriptor.
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let metadata = directory
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityDirectory)?;
        validate_identity_directory_metadata(&metadata)?;
        Ok(directory)
    }

    pub(super) fn validate_identity_directory_metadata(
        metadata: &Metadata,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        let effective_uid = unsafe { nix::libc::geteuid() };
        if !metadata.is_dir()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityDirectory);
        }
        Ok(())
    }

    pub(super) fn validate_identity_directory_binding(
        storage_root: &File,
        directory: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        let opened = directory
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityDirectory)?;
        validate_identity_directory_metadata(&opened)?;
        let rebound = open_identity_directory(storage_root)
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityDirectory)?;
        let rebound_metadata = rebound
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityDirectory)?;
        ensure_same_inode(
            &opened,
            &rebound_metadata,
            PrivateOramPeerIdentityError::InvalidIdentityDirectory,
        )
    }

    pub(super) fn lock_identity_directory(
        directory: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        // SAFETY: directory is a validated live descriptor retained by the identity object.
        let result = unsafe {
            nix::libc::flock(
                directory.as_raw_fd(),
                nix::libc::LOCK_EX | nix::libc::LOCK_NB,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(nix::libc::EWOULDBLOCK) {
            Err(PrivateOramPeerIdentityError::IdentityLocked)
        } else {
            Err(PrivateOramPeerIdentityError::Unsupported)
        }
    }

    pub(super) fn open_optional_private_file(
        directory: &File,
        name: &CStr,
    ) -> Result<Option<File>, PrivateOramPeerIdentityError> {
        // Inspect the directory entry without opening a device, FIFO, or socket for I/O.
        // SAFETY: name is one of the fixed identity file names and directory is a validated fd.
        let path_descriptor = unsafe {
            nix::libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                nix::libc::O_PATH | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC,
            )
        };
        if path_descriptor < 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(nix::libc::ENOENT) {
                Ok(None)
            } else {
                Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
            };
        }
        // SAFETY: openat returned a new owned descriptor.
        let path_file = unsafe { File::from_raw_fd(path_descriptor) };
        let path_metadata = path_file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        validate_identity_file_metadata(&path_metadata)?;

        // SAFETY: the entry was validated through O_PATH and is reopened relative to the same fd.
        let read_descriptor = unsafe {
            nix::libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                nix::libc::O_RDONLY
                    | nix::libc::O_NONBLOCK
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            )
        };
        if read_descriptor < 0 {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(read_descriptor) };
        let metadata = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        validate_identity_file_metadata(&metadata)?;
        ensure_same_inode(
            &path_metadata,
            &metadata,
            PrivateOramPeerIdentityError::InvalidIdentityFile,
        )?;
        Ok(Some(file))
    }

    pub(super) fn sync_private_file_binding(
        directory: &File,
        name: &CStr,
        witness: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        let witness_metadata = witness
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        validate_identity_file_metadata(&witness_metadata)?;

        // SAFETY: name is fixed, directory is pinned, and O_NONBLOCK bounds special-file races.
        let descriptor = unsafe {
            nix::libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                nix::libc::O_RDWR
                    | nix::libc::O_NONBLOCK
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(PrivateOramPeerIdentityError::Indeterminate);
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let before_sync = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        validate_identity_file_metadata(&before_sync)?;
        ensure_same_inode(
            &witness_metadata,
            &before_sync,
            PrivateOramPeerIdentityError::Indeterminate,
        )?;
        file.sync_all()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        let after_sync = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        validate_identity_file_metadata(&after_sync)?;
        ensure_same_inode(
            &before_sync,
            &after_sync,
            PrivateOramPeerIdentityError::Indeterminate,
        )?;

        let rebound = open_optional_private_file(directory, name)?
            .ok_or(PrivateOramPeerIdentityError::Indeterminate)?;
        ensure_same_inode(
            &after_sync,
            &rebound
                .metadata()
                .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?,
            PrivateOramPeerIdentityError::Indeterminate,
        )
    }

    pub(super) fn validate_identity_file_metadata(
        metadata: &Metadata,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        let effective_uid = unsafe { nix::libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > IDENTITY_MAX_FILE_BYTES
        {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        Ok(())
    }

    pub(super) fn load_identity(
        directory: &File,
        mut file: File,
        name: &CStr,
        expected_peer_id: u64,
        expected_pin: Option<&PrivateOramPeerRecoveryPublicKeyV1>,
    ) -> Result<LoadedIdentity, PrivateOramPeerIdentityError> {
        let before = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        validate_identity_file_metadata(&before)?;
        let expected_length = usize::try_from(before.len())
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(expected_length)
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        (&mut file)
            .take(IDENTITY_MAX_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        if bytes.len() != expected_length {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let after = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        validate_identity_file_metadata(&after)?;
        ensure_same_inode(
            &before,
            &after,
            PrivateOramPeerIdentityError::InvalidIdentityFile,
        )?;

        let rebound = open_optional_private_file(directory, name)?
            .ok_or(PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        let rebound_metadata = rebound
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        ensure_same_inode(
            &after,
            &rebound_metadata,
            PrivateOramPeerIdentityError::InvalidIdentityFile,
        )?;

        decode_identity(&bytes, expected_peer_id, expected_pin)
    }

    pub(super) fn decode_identity(
        bytes: &[u8],
        expected_peer_id: u64,
        expected_pin: Option<&PrivateOramPeerRecoveryPublicKeyV1>,
    ) -> Result<LoadedIdentity, PrivateOramPeerIdentityError> {
        if bytes.len() < IDENTITY_HEADER_BYTES + IDENTITY_CHECKSUM_BYTES
            || bytes.len() as u64 > IDENTITY_MAX_FILE_BYTES
        {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let checksum_offset = bytes
            .len()
            .checked_sub(IDENTITY_CHECKSUM_BYTES)
            .ok_or(PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        let (body, expected_checksum) = bytes.split_at(checksum_offset);
        let actual_checksum = Sha256::digest(body);
        if &actual_checksum[..] != expected_checksum {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }

        let mut offset = 0usize;
        let magic = take_array::<8>(body, &mut offset)?;
        if &magic != IDENTITY_MAGIC {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let version = u16::from_be_bytes(take_array(body, &mut offset)?);
        if version != IDENTITY_FORMAT_VERSION {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let peer_id = u64::from_be_bytes(take_array(body, &mut offset)?);
        if peer_id != expected_peer_id {
            return Err(PrivateOramPeerIdentityError::PeerIdMismatch);
        }
        let key_epoch = u64::from_be_bytes(take_array(body, &mut offset)?);
        if key_epoch != IDENTITY_KEY_EPOCH {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let pkcs8_length = u32::from_be_bytes(take_array(body, &mut offset)?) as usize;
        if pkcs8_length == 0 || pkcs8_length > IDENTITY_MAX_PKCS8_BYTES {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let pkcs8_end = offset
            .checked_add(pkcs8_length)
            .ok_or(PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        if pkcs8_end != body.len() {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        let key_pair = Ed25519KeyPair::from_pkcs8(&body[offset..pkcs8_end])
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, key_epoch)
            .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)?;
        if expected_pin.is_some_and(|expected| expected != &public_key) {
            return Err(PrivateOramPeerIdentityError::PinnedKeyMismatch);
        }
        Ok(LoadedIdentity {
            key_pair,
            public_key,
        })
    }

    pub(super) fn take_array<const N: usize>(
        bytes: &[u8],
        offset: &mut usize,
    ) -> Result<[u8; N], PrivateOramPeerIdentityError> {
        let end = offset
            .checked_add(N)
            .ok_or(PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        let value = bytes
            .get(*offset..end)
            .ok_or(PrivateOramPeerIdentityError::InvalidIdentityFile)?
            .try_into()
            .map_err(|_| PrivateOramPeerIdentityError::InvalidIdentityFile)?;
        *offset = end;
        Ok(value)
    }

    pub(super) fn create_identity(
        directory: &File,
        peer_id: u64,
    ) -> Result<LoadedIdentity, PrivateOramPeerIdentityError> {
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random)
            .map_err(|_| PrivateOramPeerIdentityError::KeyGenerationFailed)?;
        let generated_key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| PrivateOramPeerIdentityError::KeyGenerationFailed)?;
        let generated_public_key =
            private_oram_peer_recovery_public_key_v1(&generated_key_pair, IDENTITY_KEY_EPOCH)
                .map_err(|_| PrivateOramPeerIdentityError::KeyGenerationFailed)?;
        let frame = encode_identity(peer_id, IDENTITY_KEY_EPOCH, pkcs8.as_ref())?;
        let candidate = write_identity_candidate(directory, &frame)?;
        let candidate_metadata = candidate
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        rename_identity_candidate(directory)?;
        directory
            .sync_all()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;

        let candidate_after_publish = candidate
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        ensure_same_inode(
            &candidate_metadata,
            &candidate_after_publish,
            PrivateOramPeerIdentityError::Indeterminate,
        )?;
        let identity_file = open_optional_private_file(directory, IDENTITY_FILE)?
            .ok_or(PrivateOramPeerIdentityError::Indeterminate)?;
        let identity_metadata = identity_file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        ensure_same_inode(
            &candidate_after_publish,
            &identity_metadata,
            PrivateOramPeerIdentityError::Indeterminate,
        )?;
        let installed = load_identity(
            directory,
            identity_file,
            IDENTITY_FILE,
            peer_id,
            Some(&generated_public_key),
        )?;
        if installed.public_key != generated_public_key {
            return Err(PrivateOramPeerIdentityError::Indeterminate);
        }
        Ok(installed)
    }

    pub(super) fn encode_identity(
        peer_id: u64,
        key_epoch: u64,
        pkcs8: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PrivateOramPeerIdentityError> {
        if key_epoch != IDENTITY_KEY_EPOCH
            || pkcs8.is_empty()
            || pkcs8.len() > IDENTITY_MAX_PKCS8_BYTES
        {
            return Err(PrivateOramPeerIdentityError::CryptographicValidationFailed);
        }
        let pkcs8_length = u32::try_from(pkcs8.len())
            .map_err(|_| PrivateOramPeerIdentityError::CryptographicValidationFailed)?;
        let mut frame = Zeroizing::new(Vec::with_capacity(
            IDENTITY_HEADER_BYTES + pkcs8.len() + IDENTITY_CHECKSUM_BYTES,
        ));
        frame.extend_from_slice(IDENTITY_MAGIC);
        frame.extend_from_slice(&IDENTITY_FORMAT_VERSION.to_be_bytes());
        frame.extend_from_slice(&peer_id.to_be_bytes());
        frame.extend_from_slice(&key_epoch.to_be_bytes());
        frame.extend_from_slice(&pkcs8_length.to_be_bytes());
        frame.extend_from_slice(pkcs8);
        // This unkeyed digest detects torn/corrupt frames; authenticity comes from the pinned key.
        let checksum = Sha256::digest(frame.as_slice());
        frame.extend_from_slice(checksum.as_ref());
        Ok(frame)
    }

    pub(super) fn write_identity_candidate(
        directory: &File,
        bytes: &[u8],
    ) -> Result<File, PrivateOramPeerIdentityError> {
        if bytes.is_empty() || bytes.len() as u64 > IDENTITY_MAX_FILE_BYTES {
            return Err(PrivateOramPeerIdentityError::CryptographicValidationFailed);
        }
        // SAFETY: the candidate name is fixed and directory is a validated locked descriptor.
        let descriptor = unsafe {
            nix::libc::openat(
                directory.as_raw_fd(),
                IDENTITY_CANDIDATE_FILE.as_ptr(),
                nix::libc::O_WRONLY
                    | nix::libc::O_CREAT
                    | nix::libc::O_EXCL
                    | nix::libc::O_NOFOLLOW
                    | nix::libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(PrivateOramPeerIdentityError::InvalidIdentityFile);
        }
        // SAFETY: openat returned a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        file.write_all(bytes)
            .map_err(|_| PrivateOramPeerIdentityError::PersistenceFailed)?;
        file.flush()
            .map_err(|_| PrivateOramPeerIdentityError::PersistenceFailed)?;
        let metadata = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::PersistenceFailed)?;
        validate_identity_file_metadata(&metadata)?;
        if metadata.len() != bytes.len() as u64 {
            return Err(PrivateOramPeerIdentityError::Indeterminate);
        }
        file.sync_all()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        let synced = file
            .metadata()
            .map_err(|_| PrivateOramPeerIdentityError::Indeterminate)?;
        validate_identity_file_metadata(&synced)?;
        ensure_same_inode(
            &metadata,
            &synced,
            PrivateOramPeerIdentityError::Indeterminate,
        )?;
        Ok(file)
    }

    pub(super) fn rename_identity_candidate(
        directory: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        // SAFETY: both names are fixed single components and directory is a validated locked fd.
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_renameat2,
                directory.as_raw_fd(),
                IDENTITY_CANDIDATE_FILE.as_ptr(),
                directory.as_raw_fd(),
                IDENTITY_FILE.as_ptr(),
                nix::libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(nix::libc::EEXIST) => Err(PrivateOramPeerIdentityError::InvalidIdentityFile),
            Some(
                nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::EOPNOTSUPP | nix::libc::EXDEV,
            ) => Err(PrivateOramPeerIdentityError::Unsupported),
            _ => Err(PrivateOramPeerIdentityError::Indeterminate),
        }
    }

    pub(super) fn ensure_same_inode(
        before: &Metadata,
        after: &Metadata,
        error: PrivateOramPeerIdentityError,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.file_type().is_dir() != after.file_type().is_dir()
            || before.file_type().is_file() != after.file_type().is_file()
            || before.len() != after.len()
        {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use platform::*;

/// Non-Linux builds keep the identity API type-checked but fail closed: every filesystem entry
/// point reports `Unsupported`, so the server refuses to bootstrap or open a peer identity.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code, unused_variables)]
mod platform {
    use super::*;

    pub(super) fn open_storage_root(
        storage_path: &Path,
    ) -> Result<File, PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn open_or_create_identity_directory(
        storage_root: &File,
        create: bool,
    ) -> Result<File, PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn validate_identity_directory_binding(
        storage_root: &File,
        directory: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn lock_identity_directory(
        directory: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn open_optional_private_file(
        directory: &File,
        name: &CStr,
    ) -> Result<Option<File>, PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn sync_private_file_binding(
        directory: &File,
        name: &CStr,
        witness: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn load_identity(
        directory: &File,
        file: File,
        name: &CStr,
        expected_peer_id: u64,
        expected_pin: Option<&PrivateOramPeerRecoveryPublicKeyV1>,
    ) -> Result<LoadedIdentity, PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn create_identity(
        directory: &File,
        peer_id: u64,
    ) -> Result<LoadedIdentity, PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn rename_identity_candidate(
        directory: &File,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }

    pub(super) fn ensure_same_inode(
        before: &Metadata,
        after: &Metadata,
        error: PrivateOramPeerIdentityError,
    ) -> Result<(), PrivateOramPeerIdentityError> {
        Err(PrivateOramPeerIdentityError::Unsupported)
    }
}

#[cfg(not(target_os = "linux"))]
use platform::*;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use std::{fs, thread};

    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
        PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION, PrivateOramIndexKindV2,
        PrivateOramOwnerReservationPrepareChallengeV1, PrivateOramPeerRecoveryRequestV2,
        PrivateOramPeerRecoveryTerminalIndexV2, PrivateOramPeerRecoveryTerminalKindV2,
        PrivateOramPeerRecoveryTerminalV2, private_oram_mutation_protocol_capability_digest_v2,
        private_oram_owner_lifecycle_genesis_state_v1,
        try_private_oram_peer_recovery_terminal_evidence_digest_v2,
        validate_private_oram_owner_reservation_prepare_v1,
        validate_private_oram_peer_recovery_response_signature_v2,
    };
    use tempfile::TempDir;

    use super::*;

    const PEER_ID: u64 = 23;
    const PROCESS_LOCK_TEST_ROLE: &str = "QDRANT_PRIVATE_ORAM_IDENTITY_LOCK_TEST_ROLE";
    const PROCESS_LOCK_TEST_STORAGE: &str = "QDRANT_PRIVATE_ORAM_IDENTITY_LOCK_TEST_STORAGE";
    const PROCESS_LOCK_TEST_READY: &str = "QDRANT_PRIVATE_ORAM_IDENTITY_LOCK_TEST_READY";
    const PROCESS_LOCK_HELPER_NAME: &str =
        "common::private_oram_peer_identity::tests::identity_process_lock_helper";

    fn identity_path(storage_path: &Path) -> PathBuf {
        storage_path
            .join(IDENTITY_DIRECTORY.to_str().unwrap())
            .join(IDENTITY_FILE.to_str().unwrap())
    }

    fn candidate_path(storage_path: &Path) -> PathBuf {
        storage_path
            .join(IDENTITY_DIRECTORY.to_str().unwrap())
            .join(IDENTITY_CANDIDATE_FILE.to_str().unwrap())
    }

    fn digest(value: u8) -> String {
        BASE64URL_NOPAD.encode(&[value; 32])
    }

    fn process_lock_test_command(role: &str, storage: &Path, ready: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(PROCESS_LOCK_HELPER_NAME)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(PROCESS_LOCK_TEST_ROLE, role)
            .env(PROCESS_LOCK_TEST_STORAGE, storage)
            .env(PROCESS_LOCK_TEST_READY, ready);
        command
    }

    fn reservation_challenge() -> PrivateOramOwnerReservationPrepareChallengeV1 {
        PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-uuid-1".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 2,
            protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
            membership_epoch: 101,
            reservation_intent_digest: digest(6),
            checkpoint_context_digest: digest(7),
            committed_challenge_digest: digest(8),
            challenge_applied_term: 4,
            challenge_applied_index: 106,
            attempt_id: digest(9),
            challenge_nonce: BASE64URL_NOPAD.encode(&[10; 16]),
            expected_checkpoint_record_digest: digest(11),
            expected_checkpoint_sequence: 1,
            expected_owner_target_digest: digest(12),
            reserved_terminal_intent_key: digest(13),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: digest(14),
            owner_peer_id: PEER_ID,
            owner_store_incarnation_digest: digest(15),
            authority_registry_digest: digest(16),
            owner_registry_digest: digest(17),
        }
    }

    fn generated_frame(peer_id: u64) -> Zeroizing<Vec<u8>> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        encode_identity(peer_id, IDENTITY_KEY_EPOCH, pkcs8.as_ref()).unwrap()
    }

    fn recompute_frame_checksum(frame: &mut [u8]) {
        let checksum_offset = frame.len() - IDENTITY_CHECKSUM_BYTES;
        let checksum = Sha256::digest(&frame[..checksum_offset]);
        frame[checksum_offset..].copy_from_slice(&checksum);
    }

    fn response_fixture() -> (
        PrivateOramPeerRecoveryRequestV2,
        PrivateOramPeerRecoveryTerminalV2,
    ) {
        let request = PrivateOramPeerRecoveryRequestV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: BASE64URL_NOPAD.encode(&[7; 16]),
            collection_name: "docs".to_string(),
            collection_id: "collection-uuid-1".to_string(),
            mutation_id: digest(13),
            parent_descriptor_digest: digest(11),
            decision_record_digest: digest(12),
            coordinator_peer_id: 17,
            owner_peer_id: PEER_ID,
            vector_name: "text".to_string(),
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
        };
        let mut terminal = PrivateOramPeerRecoveryTerminalV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: request.challenge_nonce.clone(),
            owner_peer_id: PEER_ID,
            terminal_kind: PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew,
            journal_descriptor_digest: digest(14),
            prepared_state_digest: digest(15),
            terminal_record_digest: digest(16),
            parent_descriptor_digest: request.parent_descriptor_digest.clone(),
            decision_authority_record_digest: request.decision_record_digest.clone(),
            reconciliation_authority_digest: digest(17),
            indexes: vec![
                PrivateOramPeerRecoveryTerminalIndexV2 {
                    kind: PrivateOramIndexKindV2::Hnsw,
                    index_name: "text".to_string(),
                    prepared_journal_digest: digest(18),
                    terminal_state_digest: digest(19),
                },
                PrivateOramPeerRecoveryTerminalIndexV2 {
                    kind: PrivateOramIndexKindV2::Result,
                    index_name: "text".to_string(),
                    prepared_journal_digest: digest(20),
                    terminal_state_digest: digest(21),
                },
            ],
            terminal_evidence_digest: digest(0),
        };
        terminal.terminal_evidence_digest =
            try_private_oram_peer_recovery_terminal_evidence_digest_v2(&request, &terminal)
                .unwrap();
        (request, terminal)
    }

    #[test]
    fn identity_frame_parser_rejects_truncation_and_field_mutations() {
        let frame = generated_frame(PEER_ID);
        assert!(decode_identity(&frame, PEER_ID, None).is_ok());
        for length in 0..frame.len() {
            assert!(decode_identity(&frame[..length], PEER_ID, None).is_err());
        }

        let mut trailing = frame.to_vec();
        trailing.push(0);
        assert!(decode_identity(&trailing, PEER_ID, None).is_err());

        let mut invalid_checksum = frame.to_vec();
        *invalid_checksum.last_mut().unwrap() ^= 1;
        assert!(decode_identity(&invalid_checksum, PEER_ID, None).is_err());

        let version_offset = IDENTITY_MAGIC.len();
        let peer_offset = version_offset + size_of::<u16>();
        let epoch_offset = peer_offset + size_of::<u64>();
        let length_offset = epoch_offset + size_of::<u64>();
        let pkcs8_offset = length_offset + size_of::<u32>();

        let mut invalid_magic = frame.to_vec();
        invalid_magic[0] ^= 1;
        recompute_frame_checksum(&mut invalid_magic);
        assert!(decode_identity(&invalid_magic, PEER_ID, None).is_err());

        let mut invalid_version = frame.to_vec();
        invalid_version[version_offset..peer_offset].copy_from_slice(&2u16.to_be_bytes());
        recompute_frame_checksum(&mut invalid_version);
        assert!(decode_identity(&invalid_version, PEER_ID, None).is_err());

        let mut wrong_peer = frame.to_vec();
        wrong_peer[peer_offset..epoch_offset].copy_from_slice(&(PEER_ID + 1).to_be_bytes());
        recompute_frame_checksum(&mut wrong_peer);
        assert!(matches!(
            decode_identity(&wrong_peer, PEER_ID, None),
            Err(PrivateOramPeerIdentityError::PeerIdMismatch)
        ));

        let mut invalid_epoch = frame.to_vec();
        invalid_epoch[epoch_offset..length_offset].copy_from_slice(&2u64.to_be_bytes());
        recompute_frame_checksum(&mut invalid_epoch);
        assert!(decode_identity(&invalid_epoch, PEER_ID, None).is_err());

        let mut zero_length = frame.to_vec();
        zero_length[length_offset..pkcs8_offset].copy_from_slice(&0u32.to_be_bytes());
        recompute_frame_checksum(&mut zero_length);
        assert!(decode_identity(&zero_length, PEER_ID, None).is_err());

        let mut oversized_length = frame.to_vec();
        oversized_length[length_offset..pkcs8_offset]
            .copy_from_slice(&((IDENTITY_MAX_PKCS8_BYTES + 1) as u32).to_be_bytes());
        recompute_frame_checksum(&mut oversized_length);
        assert!(decode_identity(&oversized_length, PEER_ID, None).is_err());

        let mut malformed_der = frame.to_vec();
        malformed_der[pkcs8_offset] = 0;
        recompute_frame_checksum(&mut malformed_der);
        assert!(decode_identity(&malformed_der, PEER_ID, None).is_err());
    }

    #[test]
    fn identity_is_durable_private_and_stable() {
        let storage = TempDir::new().unwrap();
        let first = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let public_key = first.public_key().clone();
        assert_eq!(first.peer_id(), PEER_ID);

        let identity_metadata = fs::metadata(identity_path(storage.path())).unwrap();
        assert_eq!(identity_metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(identity_metadata.nlink(), 1);
        let directory_metadata =
            fs::metadata(storage.path().join(IDENTITY_DIRECTORY.to_str().unwrap())).unwrap();
        assert_eq!(directory_metadata.permissions().mode() & 0o7777, 0o700);
        drop(first);

        let reopened = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::RequirePinned(&public_key),
        )
        .unwrap();
        assert_eq!(reopened.public_key(), &public_key);
    }

    #[test]
    fn identity_signs_only_its_bound_owner_response() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let (request, terminal) = response_fixture();
        let signature = identity.sign_response(&request, &terminal).unwrap();
        let _verified = validate_private_oram_peer_recovery_response_signature_v2(
            identity.public_key(),
            &request,
            &terminal,
            &signature,
        )
        .unwrap();

        let mut wrong_owner = request;
        wrong_owner.owner_peer_id += 1;
        assert_eq!(
            identity.sign_response(&wrong_owner, &terminal),
            Err(PrivateOramPeerIdentityError::PeerIdMismatch)
        );
    }

    #[test]
    fn identity_signs_checkpoint_bound_owner_reservation_prepare() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let challenge = reservation_challenge();
        let lifecycle_state = private_oram_owner_lifecycle_genesis_state_v1(
            challenge.owner_store_incarnation_digest.clone(),
        )
        .unwrap();
        let prepare = identity
            .sign_owner_reservation_prepare(
                challenge.clone(),
                lifecycle_state.clone(),
                lifecycle_state.generation,
                digest(18),
            )
            .unwrap();
        let signer = identity.owner_cleanup_signer().unwrap();
        let _verified = validate_private_oram_owner_reservation_prepare_v1(
            &prepare,
            &challenge,
            &signer,
            &lifecycle_state,
        )
        .unwrap();

        let mut wrong_owner = challenge;
        wrong_owner.owner_peer_id += 1;
        assert_eq!(
            identity.sign_owner_reservation_prepare(
                wrong_owner,
                lifecycle_state.clone(),
                lifecycle_state.generation,
                digest(18),
            ),
            Err(PrivateOramPeerIdentityError::PeerIdMismatch)
        );
    }

    #[test]
    fn identity_lock_rejects_a_second_process_owner() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        // SAFETY: dup returns a separately owned descriptor for the live lock descriptor.
        let duplicate_descriptor = unsafe { nix::libc::dup(identity.directory_lock.as_raw_fd()) };
        assert!(duplicate_descriptor >= 0);
        // SAFETY: dup returned a new owned descriptor; closing it must not release the original.
        drop(unsafe { File::from_raw_fd(duplicate_descriptor) });
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::IdentityLocked)
        ));
        assert_eq!(
            identity.require_process_lifetime_fence(PEER_ID).unwrap(),
            identity.process_incarnation()
        );
        assert!(
            identity
                .require_process_lifetime_fence(PEER_ID + 1)
                .is_err()
        );
    }

    #[test]
    fn identity_process_lock_helper() {
        let Ok(role) = std::env::var(PROCESS_LOCK_TEST_ROLE) else {
            return;
        };
        let storage = PathBuf::from(std::env::var_os(PROCESS_LOCK_TEST_STORAGE).unwrap());
        let ready = PathBuf::from(std::env::var_os(PROCESS_LOCK_TEST_READY).unwrap());
        match role.as_str() {
            "hold" => {
                let _identity = PrivateOramPeerRecoveryIdentity::open_or_create(
                    &storage,
                    PEER_ID,
                    PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
                )
                .unwrap();
                fs::write(&ready, b"ready").unwrap();
                thread::sleep(Duration::from_secs(60));
            }
            "expect-locked" => assert!(matches!(
                PrivateOramPeerRecoveryIdentity::open_or_create(
                    &storage,
                    PEER_ID,
                    PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
                ),
                Err(PrivateOramPeerIdentityError::IdentityLocked)
            )),
            "expect-acquired" => {
                PrivateOramPeerRecoveryIdentity::open_or_create(
                    &storage,
                    PEER_ID,
                    PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
                )
                .unwrap();
            }
            _ => panic!("unexpected process lock test role"),
        }
    }

    #[test]
    fn identity_lifetime_lock_fences_paused_and_dead_process_incarnations() {
        let storage = TempDir::new().unwrap();
        let ready = storage.path().join("holder.ready");
        let mut holder = process_lock_test_command("hold", storage.path(), &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        let holder_ready = ready.exists();
        // SAFETY: the child PID is live or kill returns an error that is asserted below.
        let stopped = unsafe { nix::libc::kill(holder.id() as i32, nix::libc::SIGSTOP) } == 0;
        let locked = process_lock_test_command("expect-locked", storage.path(), &ready)
            .output()
            .unwrap();
        // SIGKILL releases the kernel flock even when the prior incarnation was paused.
        let killed = unsafe { nix::libc::kill(holder.id() as i32, nix::libc::SIGKILL) } == 0;
        let _ = holder.wait();
        let acquired = process_lock_test_command("expect-acquired", storage.path(), &ready)
            .output()
            .unwrap();

        assert!(holder_ready, "holder did not publish readiness");
        assert!(stopped, "holder could not be paused");
        assert!(locked.status.success(), "{:?}", locked.stderr);
        assert!(killed, "holder could not be terminated");
        assert!(acquired.status.success(), "{:?}", acquired.stderr);
    }

    #[test]
    fn pinned_identity_is_never_regenerated() {
        let first_storage = TempDir::new().unwrap();
        let first = PrivateOramPeerRecoveryIdentity::open_or_create(
            first_storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let pin = first.public_key().clone();
        drop(first);

        let missing_storage = TempDir::new().unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                missing_storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::RequirePinned(&pin),
            ),
            Err(PrivateOramPeerIdentityError::MissingPinnedIdentity)
        ));
        assert!(
            !missing_storage
                .path()
                .join(IDENTITY_DIRECTORY.to_str().unwrap())
                .exists()
        );

        let second_storage = TempDir::new().unwrap();
        let second = PrivateOramPeerRecoveryIdentity::open_or_create(
            second_storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let wrong_pin = second.public_key().clone();
        drop(second);
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                first_storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::RequirePinned(&wrong_pin),
            ),
            Err(PrivateOramPeerIdentityError::PinnedKeyMismatch)
        ));
    }

    #[test]
    fn identity_rejects_peer_rebinding() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        drop(identity);
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID + 1,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::PeerIdMismatch)
        ));
    }

    #[test]
    fn valid_stranded_candidate_is_recovered_without_regeneration() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let pin = identity.public_key().clone();
        drop(identity);
        fs::rename(
            identity_path(storage.path()),
            candidate_path(storage.path()),
        )
        .unwrap();

        let recovered = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::RequirePinned(&pin),
        )
        .unwrap();
        assert_eq!(recovered.public_key(), &pin);
        assert!(identity_path(storage.path()).is_file());
        assert!(!candidate_path(storage.path()).exists());
    }

    #[test]
    fn invalid_stranded_candidate_fails_without_regeneration() {
        let storage = TempDir::new().unwrap();
        let directory = storage.path().join(IDENTITY_DIRECTORY.to_str().unwrap());
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(candidate_path(storage.path()), [0u8]).unwrap();
        fs::set_permissions(
            candidate_path(storage.path()),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));
        assert!(!identity_path(storage.path()).exists());
        assert!(candidate_path(storage.path()).is_file());
    }

    #[test]
    fn candidate_inode_witness_detects_pre_publish_replacement() {
        let storage = TempDir::new().unwrap();
        let storage_root = open_storage_root(storage.path()).unwrap();
        let directory = open_or_create_identity_directory(&storage_root, true).unwrap();
        lock_identity_directory(&directory).unwrap();

        let original = generated_frame(PEER_ID);
        let witness = write_identity_candidate(&directory, &original).unwrap();
        // SAFETY: the fixed candidate name is removed relative to the pinned identity directory.
        let unlink_result = unsafe {
            nix::libc::unlinkat(directory.as_raw_fd(), IDENTITY_CANDIDATE_FILE.as_ptr(), 0)
        };
        assert_eq!(unlink_result, 0);

        let replacement = generated_frame(PEER_ID);
        let replacement_file = write_identity_candidate(&directory, &replacement).unwrap();
        drop(replacement_file);
        assert!(sync_private_file_binding(&directory, IDENTITY_CANDIDATE_FILE, &witness).is_err());
        assert!(!identity_path(storage.path()).exists());
        assert!(candidate_path(storage.path()).is_file());
    }

    #[test]
    fn identity_rejects_symlinks_hardlinks_and_relaxed_modes() {
        let link_parent = TempDir::new().unwrap();
        let target_storage = TempDir::new().unwrap();
        let storage_link = link_parent.path().join("storage-link");
        symlink(target_storage.path(), &storage_link).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                &storage_link,
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidStorageRoot)
        ));

        let link_parent = TempDir::new().unwrap();
        let target_parent = TempDir::new().unwrap();
        let target_storage = target_parent.path().join("storage");
        fs::create_dir(&target_storage).unwrap();
        fs::set_permissions(&target_storage, fs::Permissions::from_mode(0o700)).unwrap();
        let intermediate_link = link_parent.path().join("intermediate");
        symlink(target_parent.path(), &intermediate_link).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                &intermediate_link.join("storage"),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
            ),
            Err(PrivateOramPeerIdentityError::InvalidStorageRoot)
        ));

        let storage = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        symlink(
            target.path(),
            storage.path().join(IDENTITY_DIRECTORY.to_str().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityDirectory)
        ));

        let storage = TempDir::new().unwrap();
        let directory = storage.path().join(IDENTITY_DIRECTORY.to_str().unwrap());
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let target_file = storage.path().join("identity-target");
        fs::write(&target_file, [1u8]).unwrap();
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target_file, identity_path(storage.path())).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));

        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        drop(identity);
        let identity_file_path = identity_path(storage.path());
        fs::hard_link(
            &identity_file_path,
            identity_file_path.with_extension("hardlink"),
        )
        .unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));

        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        drop(identity);
        fs::set_permissions(
            identity_path(storage.path()),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));

        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        drop(identity);
        fs::set_permissions(
            storage.path().join(IDENTITY_DIRECTORY.to_str().unwrap()),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityDirectory)
        ));
    }

    #[test]
    fn identity_rejects_corruption_and_ambiguous_candidates() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        drop(identity);
        let path = identity_path(storage.path());
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));

        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        drop(identity);
        fs::copy(
            identity_path(storage.path()),
            candidate_path(storage.path()),
        )
        .unwrap();
        fs::set_permissions(
            candidate_path(storage.path()),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));
    }

    #[test]
    fn identity_rejects_fifo_and_socket_entries_without_blocking() {
        let storage = TempDir::new().unwrap();
        let storage_root = open_storage_root(storage.path()).unwrap();
        let directory = open_or_create_identity_directory(&storage_root, true).unwrap();
        // SAFETY: the FIFO name is fixed and creation is relative to a validated directory fd.
        let fifo_result =
            unsafe { nix::libc::mkfifoat(directory.as_raw_fd(), IDENTITY_FILE.as_ptr(), 0o600) };
        assert_eq!(fifo_result, 0);
        drop(directory);
        drop(storage_root);
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));

        let storage = TempDir::new().unwrap();
        let directory = storage.path().join(IDENTITY_DIRECTORY.to_str().unwrap());
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let _socket =
            std::os::unix::net::UnixListener::bind(identity_path(storage.path())).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidIdentityFile)
        ));
    }

    #[test]
    fn identity_rejects_non_sticky_writable_storage_ancestor() {
        let parent = TempDir::new().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let storage = parent.path().join("storage");
        fs::create_dir(&storage).unwrap();
        fs::set_permissions(&storage, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                &storage,
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidStorageRoot)
        ));
    }

    #[test]
    fn identity_rejects_a_sticky_writable_storage_root() {
        let storage = TempDir::new().unwrap();
        fs::set_permissions(storage.path(), fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(matches!(
            PrivateOramPeerRecoveryIdentity::open_or_create(
                storage.path(),
                PEER_ID,
                PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned
            ),
            Err(PrivateOramPeerIdentityError::InvalidStorageRoot)
        ));
    }

    #[test]
    fn identity_debug_and_errors_redact_key_material() {
        let storage = TempDir::new().unwrap();
        let identity = PrivateOramPeerRecoveryIdentity::open_or_create(
            storage.path(),
            PEER_ID,
            PrivateOramPeerIdentityOpenPolicy::BootstrapUnpinned,
        )
        .unwrap();
        let key_id = identity.public_key().key_id.clone();
        let public_key = identity.public_key().public_key.clone();
        let rendered = format!("{identity:?}");
        assert!(!rendered.contains(&key_id));
        assert!(!rendered.contains(&public_key));
        assert!(!rendered.contains(&storage.path().display().to_string()));

        let error = PrivateOramPeerIdentityError::PinnedKeyMismatch;
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(&key_id));
        assert!(!rendered.contains(&public_key));
    }
}
