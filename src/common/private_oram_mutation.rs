use std::time::Duration;

#[cfg(debug_assertions)]
use std::path::Path;

use collection::operations::verification::new_unchecked_verification_pass;
use collection::private_hnsw_oram_store::PrivateHnswOramStore;
use collection::private_result_oram_store::PrivateResultOramStore;
use collection::shards::shard::PeerId;
use collection::{
    PrivateOramOwnerPrepareParentV2, PrivateOramOwnerPreparedEvidenceV2,
    PrivateOramOwnerPrestageReceiptV2, PrivateOramOwnerPrestageStoreV2,
    PrivateOramOwnerReservationResolutionKindV1, PrivateOramOwnerReservationResolutionV1,
    encode_private_oram_owner_prepare_parent_v2,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1,
    PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
    PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
    PrivateOramAppendOwnerPrestageValidationContextV2, PrivateOramOwnerAdoptionRequestV1,
    PrivateOramOwnerCapsuleInstallAttestationStatementV2, PrivateOramOwnerCapsuleInstallRequestV2,
    PrivateOramOwnerCleanupSignerV1, PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    PrivateOramOwnerLifecycleStateV1, PrivateOramOwnerPrestagePackageV2,
    PrivateOramOwnerReservationPrepareChallengeV1, PrivateOramOwnerReservationPrepareV1,
    PrivateOramOwnerReservationResolutionDispositionV1,
    PrivateOramOwnerReservationResolutionReceiptV1, PrivateOramVisiblePointRecordV1,
    ResultPrivacyMode, SignedPrivateOramOwnerReservationResolutionReceiptV1,
    VerifiedPrivateOramOwnerAdoptionRequestV1, VerifiedPrivateOramOwnerPrestageRequestV2,
    decode_private_oram_owner_prestage_package_v2, decode_private_oram_staged_insert_frame_v1,
    encode_private_oram_owner_prestage_package_v2,
    new_private_oram_owner_capsule_install_challenge_nonce_v2,
    new_private_oram_owner_prestage_challenge_nonce_v2,
    new_private_oram_peer_recovery_challenge_nonce_v2, private_oram_immutable_manifest_v2_digest,
    private_oram_owner_capsule_canonical_sha256_v2, private_oram_owner_lifecycle_genesis_state_v1,
    private_oram_owner_prestage_attestation_statement_v2, private_oram_owner_prestage_request_v2,
    private_oram_owner_prestage_response_v2, private_oram_owner_prestage_roster_digest_v2,
    private_oram_signed_state_v2_digest, private_oram_staged_insert_frame_v1_digest,
    private_oram_staged_point_id_canonical_string,
    validate_private_oram_append_owner_prepare_from_durable_recovery_v2,
    validate_private_oram_append_owner_prepare_from_verified_prestage_v2,
    validate_private_oram_owner_capsule_install_attestation_for_signer_v2,
    validate_private_oram_owner_prestage_attestation_for_signer_v2,
    validate_private_oram_owner_prestage_request_signature_v2,
};
use ring::rand::{SecureRandom, SystemRandom};
use storage::content_manager::consensus_manager::{
    PrivateOramMutationPreadmissionRecoveryCandidateV2, PrivateOramOwnerEnrollmentStepV2,
    PrivateOramOwnerReservationPrepareContextV3, PrivateOramPeerRecoverySignerPairPin,
    PrivateOramPeerRecoverySignerPin, PrivateOramReservationChallengeDispositionKindV3,
    PrivateOramReservationChallengeDispositionV3,
};
use storage::content_manager::consensus_ops::{
    PrivateOramConsensusLayout, PrivateOramLayoutKey, PrivateOramMutationKey,
    PrivateOramMutationLease, PrivateOramMutationLeasePhase,
};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAdmissionPlanV2, PrivateOramMutationAllOwnersPrestagedV2,
    PrivateOramMutationAppendReservationV2, PrivateOramMutationJournal,
    PrivateOramMutationOwnerPrestageEvidenceV2, PrivateOramMutationOwnersPreparedV2,
    PrivateOramMutationParentLeaseAcquiredV2, PrivateOramMutationPlannedParentV2,
    PrivateOramMutationPointStageDurableV2, PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2,
    PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramOwnerRecoveryCapsulePackageV2,
    decode_private_oram_owner_recovery_capsule_install_receipt_v2,
    derive_private_oram_mutation_admission_plan_v2,
    derive_private_oram_mutation_admitted_recovery_plan_v2,
    derive_private_oram_mutation_all_owners_prestaged_v2,
    derive_private_oram_mutation_append_reservation_v2,
    encode_private_oram_owner_recovery_capsule_install_receipt_v2,
    encode_private_oram_owner_recovery_capsule_package_v2,
};
use storage::dispatcher::{
    Dispatcher, PrivateOramMutationAdmissionFailureClassV2, PrivateOramMutationAdmissionOutcomeV2,
};
use storage::rbac::{Access, AccessRequirements};

use super::auth::Auth;
use super::private_hnsw::{
    begin_private_hnsw_collection_lifecycle, resolve_private_hnsw_context_from_snapshot,
};
use super::private_oram_mutation_session::{
    PRIVATE_ORAM_MUTATION_SESSION_LEASE_SECS, PrivateOramDetachedMutationAppendV2,
    acquire_private_oram_mutation_execution_v2, current_unix_secs,
    private_oram_detached_job_exists_for_collection_v2,
};
use super::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use super::private_oram_recovery::do_install_local_private_oram_owner_recovery_capsule_v2;
use super::private_result_oram::{
    begin_private_result_oram_collection_lifecycle,
    resolve_private_result_oram_context_from_snapshot,
};
use crate::settings::Settings;

const PRIVATE_ORAM_RECOVERY_READINESS_WAIT: Duration = Duration::from_secs(60);
/// Parent progress advances one journal sequence per proposal; the journal has fewer phases.
const PRIVATE_ORAM_PARENT_PROGRESS_MAX_STEPS: usize = 8;
/// Two proposals (prepared, activated) per owner, bounded by the owner table capacity.
const PRIVATE_ORAM_OWNER_ENROLLMENT_MAX_STEPS: usize = 2 * 1_024 + 1;
const PRIVATE_ORAM_ADMISSION_OUTCOME_POLL_INTERVAL: Duration = Duration::from_millis(250);
const PRIVATE_ORAM_ADMISSION_OUTCOME_POLL_ATTEMPTS: usize = 240;
const PRIVATE_ORAM_MUTATION_POST_PREPARED_PAUSE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_PREPARED_PAUSE_FILE";
const PRIVATE_ORAM_MUTATION_POST_ADMISSION_PAUSE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ADMISSION_PAUSE_FILE";
const PRIVATE_ORAM_MUTATION_REJECTION_PRE_ACK_PAUSE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_REJECTION_PRE_ACK_PAUSE_FILE";

#[cfg(debug_assertions)]
async fn private_oram_mutation_pause_v2(variable: &str, message: &str) {
    let Some(pause_file) = std::env::var_os(variable) else {
        return;
    };
    if pause_file.is_empty() {
        return;
    }
    log::warn!("{message}");
    while Path::new(&pause_file).exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(not(debug_assertions))]
async fn private_oram_mutation_pause_v2(_variable: &str, _message: &str) {}

fn private_oram_owner_reservation_resolution_input_v1(
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    disposition: &PrivateOramReservationChallengeDispositionV3,
) -> PrivateOramOwnerReservationResolutionV1 {
    PrivateOramOwnerReservationResolutionV1 {
        kind: match disposition.kind() {
            PrivateOramReservationChallengeDispositionKindV3::Finalized => {
                PrivateOramOwnerReservationResolutionKindV1::Finalized
            }
            PrivateOramReservationChallengeDispositionKindV3::Cancelled => {
                PrivateOramOwnerReservationResolutionKindV1::Cancelled
            }
        },
        committed_challenge_digest: challenge.committed_challenge_digest.clone(),
        reservation_intent_digest: challenge.reservation_intent_digest.clone(),
        attempt_id: challenge.attempt_id.clone(),
        challenge_applied_term: challenge.challenge_applied_term,
        challenge_applied_index: challenge.challenge_applied_index,
        resolution_applied_term: disposition.resolution_applied_term(),
        resolution_applied_index: disposition.resolution_applied_index(),
        finalized_reservation_digest: disposition
            .finalized_reservation_digest()
            .map(str::to_string),
    }
}

fn private_oram_random_token(byte_len: usize) -> StorageResult<String> {
    let mut bytes = vec![0_u8; byte_len];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StorageError::service_error("private ORAM randomness is unavailable"))?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

pub(crate) async fn prepare_private_oram_owner_reservation_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    context: &PrivateOramOwnerReservationPrepareContextV3,
) -> StorageResult<PrivateOramOwnerReservationPrepareV1> {
    let challenge = context.challenge();
    if identity.peer_id() != challenge.owner_peer_id
        || identity
            .owner_cleanup_signer()
            .map_err(|_| invalid_owner_prestage())?
            != *context.expected_owner_signer()
    {
        return Err(invalid_owner_prestage());
    }
    let key = PrivateOramMutationKey {
        collection_id: challenge.collection_id.clone(),
    };
    let committed_context = consensus
        .private_oram_mutation_v3_owner_reservation_prepare_contexts(&key)?
        .into_iter()
        .find(|candidate| candidate.challenge().owner_peer_id == identity.peer_id())
        .ok_or_else(invalid_owner_prestage)?;
    if &committed_context != context {
        return Err(invalid_owner_prestage());
    }
    let signer_pin = consensus.private_oram_peer_recovery_signer_pin(identity.peer_id())?;
    if signer_pin.signer() != identity.public_key() {
        return Err(invalid_owner_prestage());
    }

    let auth = Auth::new_internal(Access::full("private ORAM owner reservation prepare"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_reservation_prepare_v3",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let hnsw_store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let owner_store = PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path());
    let fence = owner_store
        .prepare_reservation_fence_v1(challenge, context.expected_lifecycle_state())
        .map_err(|_| invalid_owner_prestage())?;
    let prepare = identity
        .sign_owner_reservation_prepare(
            fence.challenge().clone(),
            fence.lifecycle_state().clone(),
            fence.local_terminal_generation(),
            fence.fence_record_digest().to_string(),
        )
        .map_err(|_| invalid_owner_prestage())?;
    let _verified = qdrant_sec::validate_private_oram_owner_reservation_prepare_v1(
        &prepare,
        challenge,
        context.expected_owner_signer(),
        context.expected_lifecycle_state(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    Ok(prepare)
}

/// Resolves this owner's store for an enrolled collection whose layout lists it as an owner.
async fn resolve_private_oram_enrollment_owner_store_v2(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
) -> StorageResult<(PrivateOramMutationKey, PrivateOramOwnerPrestageStoreV2)> {
    let auth = Auth::new_internal(Access::full("private ORAM owner enrollment"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_enrollment_v2",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != collection_id {
        return Err(invalid_owner_enrollment());
    }
    let key = PrivateOramMutationKey { collection_id };
    let layout = consensus
        .private_oram_layout(&PrivateOramLayoutKey {
            collection_id: key.collection_id.clone(),
        })
        .ok_or_else(invalid_owner_enrollment)?;
    let signer_pin = consensus.private_oram_peer_recovery_signer_pin(identity.peer_id())?;
    if consensus.private_oram_mutation_state(&key).is_none()
        || !layout.owner_peer_ids.contains(&identity.peer_id())
        || signer_pin.signer() != identity.public_key()
    {
        return Err(invalid_owner_enrollment());
    }
    let hnsw_store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    Ok((
        key,
        PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path()),
    ))
}

/// Creates this owner's empty owner store for an enrolled collection and reports the owner
/// signer and the store's lifecycle state (genesis for an empty store).
pub(crate) async fn describe_private_oram_owner_store_v2(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
) -> StorageResult<(
    PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerLifecycleStateV1,
)> {
    let (_key, owner_store) = resolve_private_oram_enrollment_owner_store_v2(
        toc,
        settings,
        consensus,
        identity,
        collection_name,
        vector_name,
        owner_signing_key_id,
    )
    .await?;
    let lifecycle_state = owner_store
        .ensure_lifecycle_state_v2()
        .map_err(|_| invalid_owner_enrollment())?;
    let signer = identity
        .owner_cleanup_signer()
        .map_err(|_| invalid_owner_enrollment())?;
    Ok((signer, lifecycle_state))
}

/// Signs this owner's genesis commitment for its committed prepared enrollment, after checking
/// that its owner store is still exactly the empty store the prepared record names.
pub(crate) async fn sign_private_oram_owner_enrollment_v2(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
) -> StorageResult<PrivateOramOwnerEnrollmentGenesisCommitmentV1> {
    let (key, owner_store) = resolve_private_oram_enrollment_owner_store_v2(
        toc,
        settings,
        consensus,
        identity,
        collection_name,
        vector_name,
        owner_signing_key_id,
    )
    .await?;
    let prepared = consensus
        .private_oram_mutation_v2_pending_owner_enrollment(&key, identity.peer_id())?
        .ok_or_else(|| StorageError::PreconditionFailed {
            description: "private ORAM owner enrollment is not pending for this owner".to_string(),
        })?;
    let lifecycle_state = owner_store
        .ensure_lifecycle_state_v2()
        .map_err(|_| invalid_owner_enrollment())?;
    if lifecycle_state != prepared.expected_genesis_state {
        return Err(invalid_owner_enrollment());
    }
    identity
        .sign_owner_enrollment_genesis(&prepared)
        .map_err(|_| invalid_owner_enrollment())
}

/// Walks the owner enrollment ceremony of an enrolled collection until every owner in its
/// layout roster holds an enrollment checkpoint (docs/private-oram-v2-enrollment.md). Every step
/// re-reads committed state, so an interrupted or repeated ceremony resumes where it stopped.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_private_oram_owner_enrollment_v2(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    key: &PrivateOramMutationKey,
) -> StorageResult<()> {
    let coordinator_peer_id = identity.peer_id();
    for _ in 0..PRIVATE_ORAM_OWNER_ENROLLMENT_MAX_STEPS {
        let step = consensus.private_oram_mutation_v2_owner_enrollment_step(key)?;
        if let PrivateOramOwnerEnrollmentStepV2::Prepare { owner_peer_id }
        | PrivateOramOwnerEnrollmentStepV2::Activate { owner_peer_id } = &step
        {
            if *owner_peer_id != coordinator_peer_id {
                // Local proposal completion does not mean this owner has applied the
                // enrollment authority yet. Its next RPC validates that exact state.
                let state = consensus.hard_state();
                toc.get_channel_service()
                    .await_commit_on_peer(
                        *owner_peer_id,
                        state.commit,
                        state.term,
                        PRIVATE_ORAM_RECOVERY_READINESS_WAIT,
                    )
                    .await
                    .map_err(|_| owner_enrollment_unreachable(*owner_peer_id))?;
            }
        }
        let operation = match step {
            PrivateOramOwnerEnrollmentStepV2::Complete => return Ok(()),
            PrivateOramOwnerEnrollmentStepV2::Prepare { owner_peer_id } => {
                let (owner_signer, lifecycle_state) = if owner_peer_id == coordinator_peer_id {
                    describe_private_oram_owner_store_v2(
                        toc,
                        settings,
                        consensus,
                        identity,
                        collection_name,
                        vector_name,
                        owner_signing_key_id,
                    )
                    .await?
                } else {
                    toc.get_channel_service()
                        .describe_private_oram_mutation_owner_store_v2(
                            owner_peer_id,
                            collection_name,
                            vector_name,
                            owner_signing_key_id,
                        )
                        .await
                        .map_err(|_| owner_enrollment_unreachable(owner_peer_id))?
                };
                let genesis = private_oram_owner_lifecycle_genesis_state_v1(
                    lifecycle_state.owner_store_incarnation_digest.clone(),
                )
                .map_err(|_| invalid_owner_enrollment())?;
                if lifecycle_state != genesis {
                    return Err(StorageError::PreconditionFailed {
                        description: format!(
                            "private ORAM owner store on peer {owner_peer_id} is not empty"
                        ),
                    });
                }
                consensus.private_oram_mutation_v2_owner_enrollment_prepare_operation(
                    key,
                    owner_peer_id,
                    owner_signer,
                    lifecycle_state.owner_store_incarnation_digest,
                )?
            }
            PrivateOramOwnerEnrollmentStepV2::Activate { owner_peer_id } => {
                let commitment = if owner_peer_id == coordinator_peer_id {
                    sign_private_oram_owner_enrollment_v2(
                        toc,
                        settings,
                        consensus,
                        identity,
                        collection_name,
                        vector_name,
                        owner_signing_key_id,
                    )
                    .await?
                } else {
                    toc.get_channel_service()
                        .sign_private_oram_mutation_owner_enrollment_v2(
                            owner_peer_id,
                            collection_name,
                            vector_name,
                            owner_signing_key_id,
                        )
                        .await
                        .map_err(|_| owner_enrollment_unreachable(owner_peer_id))?
                };
                consensus
                    .private_oram_mutation_v2_owner_enrollment_activate_operation(&commitment)?
            }
        };
        if !consensus
            .propose_consensus_op_with_await(operation, Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT))
            .await?
        {
            return Err(StorageError::service_error(
                "private ORAM owner enrollment step was not applied",
            ));
        }
    }
    Err(StorageError::service_error(
        "private ORAM owner enrollment did not complete",
    ))
}

fn invalid_owner_enrollment() -> StorageError {
    StorageError::bad_request("private ORAM owner enrollment is invalid")
}

fn owner_enrollment_unreachable(owner_peer_id: u64) -> StorageError {
    StorageError::service_error(format!(
        "private ORAM owner enrollment failed on peer {owner_peer_id}"
    ))
}

pub(crate) async fn resolve_private_oram_owner_reservation_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> StorageResult<Option<SignedPrivateOramOwnerReservationResolutionReceiptV1>> {
    if identity.peer_id() != challenge.owner_peer_id {
        return Err(invalid_owner_prestage());
    }
    let key = PrivateOramMutationKey {
        collection_id: challenge.collection_id.clone(),
    };
    let disposition = consensus
        .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
        .ok_or_else(invalid_owner_prestage)?;
    let committed_context = consensus
        .private_oram_mutation_v3_owner_reservation_resolution_contexts(&key)?
        .into_iter()
        .find(|candidate| candidate.challenge() == challenge)
        .ok_or_else(invalid_owner_prestage)?;
    if identity
        .owner_cleanup_signer()
        .map_err(|_| invalid_owner_prestage())?
        != *committed_context.expected_owner_signer()
    {
        return Err(invalid_owner_prestage());
    }
    let auth = Auth::new_internal(Access::full("private ORAM owner reservation resolution"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_reservation_resolution_v3",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let resolution = private_oram_owner_reservation_resolution_input_v1(challenge, &disposition);
    let kind = resolution.kind;
    let hnsw_store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let durable_resolution = PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path())
        .resolve_reservation_fence_or_record_absent_cancellation_v1(
            &resolution,
            challenge,
            committed_context.expected_lifecycle_state(),
        )
        .map_err(|_| invalid_owner_prestage_storage())?;
    if durable_resolution.kind() != kind
        || durable_resolution.reserved_terminal_intent_key()
            != challenge.reserved_terminal_intent_key
    {
        return Err(invalid_owner_prestage_storage());
    }
    if collection.config_snapshot().await != config
        || consensus
            .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
            .as_ref()
            != Some(&disposition)
    {
        return Err(invalid_owner_prestage());
    }
    if disposition.kind() == PrivateOramReservationChallengeDispositionKindV3::Finalized {
        return Ok(None);
    }
    identity
        .sign_owner_reservation_resolution(PrivateOramOwnerReservationResolutionReceiptV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
            disposition: PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased,
            collection_id: challenge.collection_id.clone(),
            owner_peer_id: challenge.owner_peer_id,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: disposition.resolution_applied_term(),
            resolution_applied_index: disposition.resolution_applied_index(),
            reserved_terminal_intent_key: durable_resolution
                .reserved_terminal_intent_key()
                .to_string(),
            finalized_reservation_digest: disposition
                .finalized_reservation_digest()
                .map(str::to_string),
            durable_fence_record_digest: durable_resolution
                .durable_fence_record_digest()
                .to_string(),
            owner_store_incarnation_digest: durable_resolution
                .owner_store_incarnation_digest()
                .to_string(),
            owner_store_binding_digest: durable_resolution.owner_store_binding_digest().to_string(),
            installed_intent_marker_digest: None,
            installed_prestage_receipt_digest: None,
            installed_package_sha256: None,
            abort_release_authority_digest: None,
            abort_release_marker_digest: None,
            local_resolution_record_digest: durable_resolution
                .resolution_record_digest()
                .to_string(),
        })
        .map(Some)
        .map_err(|_| invalid_owner_prestage())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn confirm_private_oram_owner_installed_reservation_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    prestage_receipt: &PrivateOramOwnerPrestageReceiptV2,
) -> StorageResult<SignedPrivateOramOwnerReservationResolutionReceiptV1> {
    confirm_private_oram_owner_installed_reservation_inner_v3(
        toc,
        settings,
        consensus,
        identity,
        collection_name,
        vector_name,
        owner_signing_key_id,
        challenge,
        Some(prestage_receipt),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn confirm_private_oram_owner_installed_reservation_inner_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    prestage_receipt: Option<&PrivateOramOwnerPrestageReceiptV2>,
) -> StorageResult<SignedPrivateOramOwnerReservationResolutionReceiptV1> {
    let key = PrivateOramMutationKey {
        collection_id: challenge.collection_id.clone(),
    };
    let context = consensus
        .private_oram_mutation_v3_owner_reservation_resolution_contexts(&key)?
        .into_iter()
        .find(|candidate| candidate.challenge() == challenge)
        .ok_or_else(invalid_owner_prestage)?;
    let disposition = consensus
        .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
        .filter(|candidate| {
            candidate.kind() == PrivateOramReservationChallengeDispositionKindV3::Finalized
        })
        .ok_or_else(invalid_owner_prestage)?;
    if identity.peer_id() != challenge.owner_peer_id
        || identity
            .owner_cleanup_signer()
            .map_err(|_| invalid_owner_prestage())?
            != *context.expected_owner_signer()
        || prestage_receipt.is_some_and(|receipt| {
            receipt.owner_peer_id() != challenge.owner_peer_id
                || receipt.intent_key() != challenge.reserved_terminal_intent_key
        })
    {
        return Err(invalid_owner_prestage());
    }
    let auth = Auth::new_internal(Access::full(
        "private ORAM owner installed reservation proof",
    ));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_installed_reservation_v3",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let resolution = private_oram_owner_reservation_resolution_input_v1(challenge, &disposition);
    let hnsw_store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let installed = PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path())
        .confirm_installed_reservation_resolution_v1(&resolution)
        .map_err(|_| invalid_owner_prestage_storage())?;
    if prestage_receipt.is_some_and(|receipt| {
        installed.installed_prestage_receipt_digest() != receipt.receipt_digest()
            || installed.installed_package_sha256() != receipt.package_sha256()
    }) || installed
        .durable_resolution()
        .reserved_terminal_intent_key()
        != challenge.reserved_terminal_intent_key
        || collection.config_snapshot().await != config
        || consensus
            .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
            .as_ref()
            != Some(&disposition)
    {
        return Err(invalid_owner_prestage());
    }
    let durable = installed.durable_resolution();
    identity
        .sign_owner_reservation_resolution(PrivateOramOwnerReservationResolutionReceiptV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
            disposition: PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled,
            collection_id: challenge.collection_id.clone(),
            owner_peer_id: challenge.owner_peer_id,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: disposition.resolution_applied_term(),
            resolution_applied_index: disposition.resolution_applied_index(),
            reserved_terminal_intent_key: durable.reserved_terminal_intent_key().to_string(),
            finalized_reservation_digest: disposition
                .finalized_reservation_digest()
                .map(str::to_string),
            durable_fence_record_digest: durable.durable_fence_record_digest().to_string(),
            owner_store_incarnation_digest: durable.owner_store_incarnation_digest().to_string(),
            owner_store_binding_digest: durable.owner_store_binding_digest().to_string(),
            installed_intent_marker_digest: Some(
                installed.installed_intent_marker_digest().to_string(),
            ),
            installed_prestage_receipt_digest: Some(
                installed.installed_prestage_receipt_digest().to_string(),
            ),
            installed_package_sha256: Some(installed.installed_package_sha256().to_string()),
            abort_release_authority_digest: None,
            abort_release_marker_digest: None,
            local_resolution_record_digest: durable.resolution_record_digest().to_string(),
        })
        .map_err(|_| invalid_owner_prestage())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn release_private_oram_owner_finalized_reservation_after_abort_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> StorageResult<SignedPrivateOramOwnerReservationResolutionReceiptV1> {
    let key = PrivateOramMutationKey {
        collection_id: challenge.collection_id.clone(),
    };
    let context = consensus
        .private_oram_mutation_v3_owner_reservation_resolution_contexts(&key)?
        .into_iter()
        .find(|candidate| candidate.challenge() == challenge)
        .ok_or_else(invalid_owner_prestage)?;
    let disposition = consensus
        .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
        .filter(|candidate| {
            candidate.kind() == PrivateOramReservationChallengeDispositionKindV3::Finalized
        })
        .ok_or_else(invalid_owner_prestage)?;
    let abort_release_authority_digest = consensus
        .private_oram_mutation_v3_prestage_aborted_outcome_digest(&key, &challenge.attempt_id)?
        .ok_or_else(invalid_owner_prestage)?;
    if identity.peer_id() != challenge.owner_peer_id
        || identity
            .owner_cleanup_signer()
            .map_err(|_| invalid_owner_prestage())?
            != *context.expected_owner_signer()
    {
        return Err(invalid_owner_prestage());
    }

    let auth = Auth::new_internal(Access::full(
        "private ORAM owner finalized reservation abort release",
    ));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_finalized_reservation_abort_release_v3",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != challenge.collection_id {
        return Err(invalid_owner_prestage());
    }

    let resolution = private_oram_owner_reservation_resolution_input_v1(challenge, &disposition);
    let hnsw_store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let released = PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path())
        .release_finalized_reservation_after_abort_v1(&resolution, &abort_release_authority_digest)
        .map_err(|_| invalid_owner_prestage_storage())?;
    if collection.config_snapshot().await != config
        || consensus
            .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
            .as_ref()
            != Some(&disposition)
        || consensus
            .private_oram_mutation_v3_prestage_aborted_outcome_digest(&key, &challenge.attempt_id)?
            .as_deref()
            != Some(abort_release_authority_digest.as_str())
    {
        return Err(invalid_owner_prestage());
    }

    let durable = released.durable_resolution();
    identity
        .sign_owner_reservation_resolution(PrivateOramOwnerReservationResolutionReceiptV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_RESOLUTION_VERSION_V1,
            disposition:
                PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort,
            collection_id: challenge.collection_id.clone(),
            owner_peer_id: challenge.owner_peer_id,
            committed_challenge_digest: challenge.committed_challenge_digest.clone(),
            reservation_intent_digest: challenge.reservation_intent_digest.clone(),
            attempt_id: challenge.attempt_id.clone(),
            challenge_applied_term: challenge.challenge_applied_term,
            challenge_applied_index: challenge.challenge_applied_index,
            resolution_applied_term: disposition.resolution_applied_term(),
            resolution_applied_index: disposition.resolution_applied_index(),
            reserved_terminal_intent_key: durable.reserved_terminal_intent_key().to_string(),
            finalized_reservation_digest: disposition
                .finalized_reservation_digest()
                .map(str::to_string),
            durable_fence_record_digest: durable.durable_fence_record_digest().to_string(),
            owner_store_incarnation_digest: durable.owner_store_incarnation_digest().to_string(),
            owner_store_binding_digest: durable.owner_store_binding_digest().to_string(),
            installed_intent_marker_digest: None,
            installed_prestage_receipt_digest: None,
            installed_package_sha256: None,
            abort_release_authority_digest: Some(
                released.abort_release_authority_digest().to_string(),
            ),
            abort_release_marker_digest: Some(released.abort_release_marker_digest().to_string()),
            local_resolution_record_digest: durable.resolution_record_digest().to_string(),
        })
        .map_err(|_| invalid_owner_prestage())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_private_oram_owner_reservation_completion_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> StorageResult<SignedPrivateOramOwnerReservationResolutionReceiptV1> {
    let key = PrivateOramMutationKey {
        collection_id: challenge.collection_id.clone(),
    };
    let disposition = consensus
        .private_oram_mutation_v3_reservation_challenge_disposition(&key, challenge)?
        .ok_or_else(invalid_owner_prestage)?;
    match disposition.kind() {
        PrivateOramReservationChallengeDispositionKindV3::Cancelled => {
            resolve_private_oram_owner_reservation_v3(
                toc,
                settings,
                consensus,
                identity,
                collection_name,
                vector_name,
                owner_signing_key_id,
                challenge,
            )
            .await?
            .ok_or_else(invalid_owner_prestage)
        }
        PrivateOramReservationChallengeDispositionKindV3::Finalized => {
            if let Ok(installed) = confirm_private_oram_owner_installed_reservation_inner_v3(
                toc,
                settings,
                consensus,
                identity,
                collection_name,
                vector_name,
                owner_signing_key_id,
                challenge,
                None,
            )
            .await
            {
                return Ok(installed);
            }
            release_private_oram_owner_finalized_reservation_after_abort_v3(
                toc,
                settings,
                consensus,
                identity,
                collection_name,
                vector_name,
                owner_signing_key_id,
                challenge,
            )
            .await
        }
    }
}

async fn resolve_private_oram_owner_reservation_fences_v3(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    contexts: &[PrivateOramOwnerReservationPrepareContextV3],
) -> StorageResult<Vec<SignedPrivateOramOwnerReservationResolutionReceiptV1>> {
    let mut receipts = Vec::with_capacity(contexts.len());
    for context in contexts {
        let challenge = context.challenge();
        let disposition = consensus
            .private_oram_mutation_v3_reservation_challenge_disposition(
                &PrivateOramMutationKey {
                    collection_id: challenge.collection_id.clone(),
                },
                challenge,
            )?
            .ok_or_else(invalid_owner_prestage)?;
        let expected_receipt_disposition = match disposition.kind() {
            PrivateOramReservationChallengeDispositionKindV3::Finalized => None,
            PrivateOramReservationChallengeDispositionKindV3::Cancelled => {
                Some(PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased)
            }
        };
        let receipt = if challenge.owner_peer_id == identity.peer_id() {
            resolve_private_oram_owner_reservation_v3(
                toc,
                settings,
                consensus,
                identity,
                collection_name,
                vector_name,
                owner_signing_key_id,
                challenge,
            )
            .await?
        } else {
            // The disposition is committed locally; the owner must apply it before resolving
            // its fence. Use the current commit/term pair, not the disposition's historical term.
            let state = consensus.hard_state();
            toc.get_channel_service()
                .await_commit_on_peer(
                    challenge.owner_peer_id,
                    state.commit,
                    state.term,
                    PRIVATE_ORAM_RECOVERY_READINESS_WAIT,
                )
                .await
                .map_err(|_| invalid_owner_prestage())?;
            toc.get_channel_service()
                .resolve_private_oram_mutation_owner_reservation_v3(
                    challenge.owner_peer_id,
                    collection_name,
                    vector_name,
                    owner_signing_key_id,
                    challenge,
                    context.expected_owner_signer(),
                    false,
                    expected_receipt_disposition,
                    disposition.resolution_applied_term(),
                    disposition.resolution_applied_index(),
                    disposition.finalized_reservation_digest(),
                    None,
                )
                .await
                .map_err(|_| invalid_owner_prestage())?
        };
        if receipt.is_some() != expected_receipt_disposition.is_some() {
            return Err(invalid_owner_prestage());
        }
        receipts.extend(receipt);
    }
    Ok(receipts)
}

/// Who proposes a reservation outcome acknowledgement. Before admission it is the leader that
/// coordinates the pre-stage. An admitted mutation's own outcome is acknowledged by its lease
/// owner whichever peer leads Raft by then: the acknowledgement carries the owners' signed
/// resolution receipts, which consensus validates regardless of the proposer, and Raft leadership
/// can move while an admitted mutation is in flight.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PrivateOramReservationAckProposerV3 {
    Leader,
    AdmittedLeaseOwner,
}

#[allow(clippy::too_many_arguments)]
async fn acknowledge_oldest_private_oram_reservation_outcome_v3(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    proposer: PrivateOramReservationAckProposerV3,
) -> StorageResult<bool> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    if proposer == PrivateOramReservationAckProposerV3::Leader {
        consensus.require_private_oram_activation_coordinator_is_local_leader()?;
    }
    let auth = Auth::new_internal(Access::full(
        "private ORAM reservation outcome acknowledgement",
    ));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_reservation_outcome_acknowledgement_v3",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    let key = PrivateOramMutationKey { collection_id };
    if proposer == PrivateOramReservationAckProposerV3::AdmittedLeaseOwner
        && !consensus
            .private_oram_mutation_lease_slot(&key)
            .and_then(|slot| slot.active)
            .is_some_and(|lease| {
                lease.owner_peer_id == identity.peer_id()
                    && lease.owner_peer_id == dispatcher.this_peer_id()
            })
    {
        return Err(invalid_owner_prestage());
    }
    let Some(recovery) =
        consensus.private_oram_mutation_v3_oldest_reservation_outcome_recovery(&key)?
    else {
        return Ok(false);
    };
    let local_peer_id = dispatcher.this_peer_id();
    if identity.peer_id() != local_peer_id
        || (consensus
            .require_private_oram_activation_coordinator_is_local_leader()
            .is_err()
            && !consensus
                .private_oram_mutation_lease(&key)
                .as_ref()
                .is_some_and(|lease| {
                    recovery.matches_active_controller_lease(local_peer_id, lease)
                }))
    {
        return Err(StorageError::PreconditionFailed {
            description:
                "private ORAM reservation outcome must be acknowledged by the current leader or immutable active controller"
                    .to_string(),
        });
    }
    let disposition = recovery.disposition().clone();
    let attempt_id = recovery
        .owner_contexts()
        .first()
        .map(|context| context.challenge().attempt_id.as_str())
        .ok_or_else(invalid_owner_prestage)?;
    let abort_release_authority_digest =
        if disposition.kind() == PrivateOramReservationChallengeDispositionKindV3::Finalized {
            consensus.private_oram_mutation_v3_prestage_aborted_outcome_digest(&key, attempt_id)?
        } else {
            None
        };
    let mut receipts = Vec::with_capacity(recovery.owner_contexts().len());
    for context in recovery.owner_contexts() {
        let challenge = context.challenge();
        let receipt = if challenge.owner_peer_id == identity.peer_id() {
            recover_private_oram_owner_reservation_completion_v3(
                toc,
                settings,
                consensus,
                identity,
                collection_name,
                vector_name,
                owner_signing_key_id,
                challenge,
            )
            .await?
        } else {
            let recover_completion =
                disposition.kind() == PrivateOramReservationChallengeDispositionKindV3::Finalized;
            toc.get_channel_service()
                .resolve_private_oram_mutation_owner_reservation_v3(
                    challenge.owner_peer_id,
                    collection_name,
                    vector_name,
                    owner_signing_key_id,
                    challenge,
                    context.expected_owner_signer(),
                    recover_completion,
                    Some(match disposition.kind() {
                        PrivateOramReservationChallengeDispositionKindV3::Finalized => {
                            PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled
                        }
                        PrivateOramReservationChallengeDispositionKindV3::Cancelled => {
                            PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased
                        }
                    }),
                    disposition.resolution_applied_term(),
                    disposition.resolution_applied_index(),
                    disposition.finalized_reservation_digest(),
                    abort_release_authority_digest.as_deref(),
                )
                .await
                .map_err(|_| invalid_owner_prestage())?
                .ok_or_else(invalid_owner_prestage)?
        };
        receipts.push(receipt);
    }
    if collection.config_snapshot().await != config
        || consensus
            .private_oram_mutation_v3_oldest_reservation_outcome_recovery(&key)?
            .as_ref()
            != Some(&recovery)
    {
        return Err(invalid_owner_prestage());
    }
    let outcome_digest = recovery.outcome_digest().to_string();
    let operation = consensus
        .private_oram_mutation_v3_reservation_outcome_acknowledgement_operation(
            key.clone(),
            outcome_digest.clone(),
            receipts,
        )?;
    let _proposal = consensus
        .propose_consensus_op_with_await(operation, Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT))
        .await;
    if consensus
        .private_oram_mutation_v3_oldest_reservation_outcome_recovery(&key)?
        .as_ref()
        .is_some_and(|retained| retained.outcome_digest() == outcome_digest)
    {
        return Err(StorageError::service_error(
            "private ORAM reservation outcome acknowledgement remains pending",
        ));
    }
    Ok(true)
}

pub(crate) struct PrivateOramCoordinatedPrestageV2 {
    admission: PrivateOramMutationAdmissionPlanV2,
    planned_parent: PrivateOramMutationPlannedParentV2,
    all_owners_prestaged: PrivateOramMutationAllOwnersPrestagedV2,
    prepared_aggregate_digest: String,
    owner_receipts: Vec<PrivateOramOwnerPrestageReceiptV2>,
    owner_resolution_receipts: Vec<SignedPrivateOramOwnerReservationResolutionReceiptV1>,
}

impl std::fmt::Debug for PrivateOramCoordinatedPrestageV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateOramCoordinatedPrestageV2")
            .field("admission", &"[redacted]")
            .field("planned_parent", &self.planned_parent)
            .field("all_owners_prestaged", &self.all_owners_prestaged)
            .field("prepared_aggregate_digest", &"[redacted]")
            .field("owner_receipt_count", &self.owner_receipts.len())
            .field(
                "owner_resolution_receipt_count",
                &self.owner_resolution_receipts.len(),
            )
            .finish()
    }
}

impl PrivateOramCoordinatedPrestageV2 {
    pub(crate) fn admission(&self) -> &PrivateOramMutationAdmissionPlanV2 {
        &self.admission
    }

    pub(crate) fn planned_parent(&self) -> &PrivateOramMutationPlannedParentV2 {
        &self.planned_parent
    }

    pub(crate) fn all_owners_prestaged(&self) -> &PrivateOramMutationAllOwnersPrestagedV2 {
        &self.all_owners_prestaged
    }

    pub(crate) fn owner_receipts(&self) -> &[PrivateOramOwnerPrestageReceiptV2] {
        &self.owner_receipts
    }

    pub(crate) fn owner_resolution_receipts(
        &self,
    ) -> &[SignedPrivateOramOwnerReservationResolutionReceiptV1] {
        &self.owner_resolution_receipts
    }

    pub(crate) fn prepared_aggregate_digest(&self) -> &str {
        &self.prepared_aggregate_digest
    }
}

trait PrivateOramAdmittedPlanContextV2 {
    fn admission(&self) -> &PrivateOramMutationAdmissionPlanV2;
    fn planned_parent(&self) -> &PrivateOramMutationPlannedParentV2;
    fn all_owners_prestaged(&self) -> &PrivateOramMutationAllOwnersPrestagedV2;
}

impl PrivateOramAdmittedPlanContextV2 for PrivateOramCoordinatedPrestageV2 {
    fn admission(&self) -> &PrivateOramMutationAdmissionPlanV2 {
        self.admission()
    }

    fn planned_parent(&self) -> &PrivateOramMutationPlannedParentV2 {
        self.planned_parent()
    }

    fn all_owners_prestaged(&self) -> &PrivateOramMutationAllOwnersPrestagedV2 {
        self.all_owners_prestaged()
    }
}

trait PrivateOramAdmittedExecutionContextV2 {
    fn controller_peer_id(&self) -> PeerId;
    fn collection_name(&self) -> &str;
    fn vector_name(&self) -> &str;
    fn immutable_manifest(&self) -> &qdrant_sec::PrivateOramImmutableManifestBundleV2;
    fn validated_owner_prepare(&self) -> &qdrant_sec::PrivateOramValidatedOwnerPrepareV1;
    fn staged_insert_frame_bytes(&self) -> Option<&[u8]>;
    fn consensus_layout(
        &self,
    ) -> &storage::content_manager::consensus_ops::PrivateOramConsensusLayout;
}

struct PrivateOramDurableAdmittedExecutionV2 {
    controller_peer_id: PeerId,
    collection_name: String,
    vector_name: String,
    immutable_manifest: qdrant_sec::PrivateOramImmutableManifestBundleV2,
    validated_owner_prepare: qdrant_sec::PrivateOramValidatedOwnerPrepareV1,
    staged_insert_frame_bytes: Option<Vec<u8>>,
    consensus_layout: PrivateOramConsensusLayout,
}

struct PrivateOramDurableAdmittedPlanV2 {
    admission: PrivateOramMutationAdmissionPlanV2,
    planned_parent: PrivateOramMutationPlannedParentV2,
    all_owners_prestaged: PrivateOramMutationAllOwnersPrestagedV2,
}

impl PrivateOramAdmittedPlanContextV2 for PrivateOramDurableAdmittedPlanV2 {
    fn admission(&self) -> &PrivateOramMutationAdmissionPlanV2 {
        &self.admission
    }

    fn planned_parent(&self) -> &PrivateOramMutationPlannedParentV2 {
        &self.planned_parent
    }

    fn all_owners_prestaged(&self) -> &PrivateOramMutationAllOwnersPrestagedV2 {
        &self.all_owners_prestaged
    }
}

impl PrivateOramAdmittedExecutionContextV2 for PrivateOramDurableAdmittedExecutionV2 {
    fn controller_peer_id(&self) -> PeerId {
        self.controller_peer_id
    }

    fn collection_name(&self) -> &str {
        &self.collection_name
    }

    fn vector_name(&self) -> &str {
        &self.vector_name
    }

    fn immutable_manifest(&self) -> &qdrant_sec::PrivateOramImmutableManifestBundleV2 {
        &self.immutable_manifest
    }

    fn validated_owner_prepare(&self) -> &qdrant_sec::PrivateOramValidatedOwnerPrepareV1 {
        &self.validated_owner_prepare
    }

    fn staged_insert_frame_bytes(&self) -> Option<&[u8]> {
        self.staged_insert_frame_bytes.as_deref()
    }

    fn consensus_layout(&self) -> &PrivateOramConsensusLayout {
        &self.consensus_layout
    }
}

impl PrivateOramAdmittedExecutionContextV2 for PrivateOramDetachedMutationAppendV2 {
    fn controller_peer_id(&self) -> PeerId {
        self.controller_peer_id()
    }

    fn collection_name(&self) -> &str {
        self.collection_name()
    }

    fn vector_name(&self) -> &str {
        self.vector_name()
    }

    fn immutable_manifest(&self) -> &qdrant_sec::PrivateOramImmutableManifestBundleV2 {
        self.immutable_manifest()
    }

    fn validated_owner_prepare(&self) -> &qdrant_sec::PrivateOramValidatedOwnerPrepareV1 {
        self.validated_owner_prepare()
    }

    fn staged_insert_frame_bytes(&self) -> Option<&[u8]> {
        self.staged_insert_frame_bytes()
    }

    fn consensus_layout(
        &self,
    ) -> &storage::content_manager::consensus_ops::PrivateOramConsensusLayout {
        self.consensus_layout()
    }
}

/// Runs through the cancellation boundary. Once admission may have reached Raft, this routine
/// never converts uncertainty into a pre-admission failure or releases the detached job.
pub(crate) async fn run_private_oram_mutation_append_v2(
    dispatcher: std::sync::Arc<Dispatcher>,
    settings: std::sync::Arc<Settings>,
    identity: std::sync::Arc<PrivateOramPeerRecoveryIdentity>,
    detached: PrivateOramDetachedMutationAppendV2,
) -> StorageResult<()> {
    let coordinated = match coordinate_private_oram_owner_prestage_v2(
        dispatcher.as_ref(),
        settings.as_ref(),
        identity.as_ref(),
        &detached,
    )
    .await
    {
        Ok(coordinated) => coordinated,
        Err(error) => {
            let _ = detached.quarantine();
            return Err(error);
        }
    };
    private_oram_mutation_pause_v2(
        PRIVATE_ORAM_MUTATION_POST_PREPARED_PAUSE_FILE_ENV,
        "Private ORAM staging mutation append post-prepared pause reached",
    )
    .await;
    let key = PrivateOramMutationKey {
        collection_id: detached.collection_id().to_string(),
    };
    let execution = acquire_private_oram_mutation_execution_v2(&key).await?;
    let readiness_result: StorageResult<()> = async {
        let auth = Auth::new_internal(Access::full("private ORAM mutation final owner readiness"));
        let pass = auth.check_collection_access(
            detached.collection_name(),
            AccessRequirements::new().write(),
            "private_oram_mutation_final_owner_readiness_v2",
        )?;
        let verification = new_unchecked_verification_pass();
        let toc = dispatcher.toc(&auth, &verification);
        let collection = toc.get_collection(&pass).await?;
        let config = collection.config_snapshot().await;
        if config.stable_crypto_id(collection.name())? != key.collection_id {
            return Err(invalid_owner_prestage());
        }
        let owner_signing_key_id = &detached.immutable_manifest().manifest.owner_signing_key_id;
        let hnsw_context = resolve_private_hnsw_context_from_snapshot(
            settings.as_ref(),
            collection.name(),
            collection.path(),
            &config,
            detached.vector_name(),
            owner_signing_key_id,
        )?;
        let expectation = dispatcher.private_oram_owner_new_generation_readiness_expectation_v2(
            &key,
            dispatcher.this_peer_id(),
        )?;
        if expectation.consensus_aggregate_digest() != coordinated.prepared_aggregate_digest() {
            return Err(invalid_owner_prestage());
        }
        PrivateOramOwnerPrestageStoreV2::try_new_pinned_absolute_v2(
            PrivateHnswOramStore::new(hnsw_context.collection_path(), detached.vector_name())
                .map_err(|_| invalid_owner_prestage())?
                .root_path(),
        )
        .map_err(|_| invalid_owner_prestage())?
        .require_ready_for_new_generation_v2(&expectation)
        .map_err(|_| StorageError::PreconditionFailed {
            description: "private ORAM owner journal is not ready for a new generation".to_string(),
        })?;
        if collection.config_snapshot().await != config {
            return Err(invalid_owner_prestage());
        }
        Ok(())
    }
    .await;
    if let Err(error) = readiness_result {
        drop(execution);
        return resolve_failed_private_oram_preadmission_v2(
            dispatcher.as_ref(),
            settings.as_ref(),
            identity.as_ref(),
            &detached,
            &coordinated,
            error,
        )
        .await;
    }
    let permit = match detached.bind_live_admission_permit(
        dispatcher.as_ref(),
        coordinated.admission(),
        coordinated.all_owners_prestaged(),
    ) {
        Ok(permit) => permit,
        Err(error) => {
            drop(execution);
            return resolve_failed_private_oram_preadmission_v2(
                dispatcher.as_ref(),
                settings.as_ref(),
                identity.as_ref(),
                &detached,
                &coordinated,
                error,
            )
            .await;
        }
    };
    let outcome = dispatcher
        .submit_private_oram_mutation_admission_v2(
            coordinated.admission(),
            coordinated.all_owners_prestaged(),
            coordinated.prepared_aggregate_digest(),
            permit,
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await;
    drop(execution);
    match outcome {
        Ok(PrivateOramMutationAdmissionOutcomeV2::AppliedExact) => {
            let handoff = complete_private_oram_admitted_handoff_v2(
                dispatcher.as_ref(),
                settings.as_ref(),
                identity.as_ref(),
                &detached,
                &coordinated,
            )
            .await;
            hand_failed_admitted_handoff_to_recovery_v2(&detached, handoff)
        }
        Ok(PrivateOramMutationAdmissionOutcomeV2::CommittedRejected) => {
            complete_private_oram_rejected_handoff_v2(
                dispatcher.as_ref(),
                settings.as_ref(),
                identity.as_ref(),
                &detached,
                coordinated.admission().lease(),
            )
            .await
        }
        Err(failure)
            if failure.class()
                == PrivateOramMutationAdmissionFailureClassV2::DefinitelyNotSubmitted =>
        {
            resolve_failed_private_oram_preadmission_v2(
                dispatcher.as_ref(),
                settings.as_ref(),
                identity.as_ref(),
                &detached,
                &coordinated,
                failure.into_storage_error(),
            )
            .await
        }
        Err(failure) => {
            detached.mark_admission_unknown()?;
            let initial_error = failure.into_storage_error();
            for _ in 0..PRIVATE_ORAM_ADMISSION_OUTCOME_POLL_ATTEMPTS {
                tokio::time::sleep(PRIVATE_ORAM_ADMISSION_OUTCOME_POLL_INTERVAL).await;
                match dispatcher.inspect_private_oram_mutation_admission_outcome_v2(
                    coordinated.admission().lease(),
                    coordinated.all_owners_prestaged().manifest_digest(),
                ) {
                    Ok(Some(PrivateOramMutationAdmissionOutcomeV2::AppliedExact)) => {
                        let handoff = complete_private_oram_admitted_handoff_v2(
                            dispatcher.as_ref(),
                            settings.as_ref(),
                            identity.as_ref(),
                            &detached,
                            &coordinated,
                        )
                        .await;
                        return hand_failed_admitted_handoff_to_recovery_v2(&detached, handoff);
                    }
                    Ok(Some(PrivateOramMutationAdmissionOutcomeV2::CommittedRejected)) => {
                        return complete_private_oram_rejected_handoff_v2(
                            dispatcher.as_ref(),
                            settings.as_ref(),
                            identity.as_ref(),
                            &detached,
                            coordinated.admission().lease(),
                        )
                        .await;
                    }
                    Ok(None) | Err(_) => {}
                }
            }
            Err(initial_error)
        }
    }
}

/// An admitted mutation is never abandoned: when its live handoff fails (a proposal timed out,
/// Raft leadership moved, ...), the job moves to `AdmittedRecovery` and the lease owner's
/// supervisor finishes it from the durable recovery material
/// (`reconcile_private_oram_admitted_to_commit_v2`).
fn hand_failed_admitted_handoff_to_recovery_v2(
    detached: &PrivateOramDetachedMutationAppendV2,
    handoff: StorageResult<()>,
) -> StorageResult<()> {
    if handoff.is_err() {
        let _ = detached.hand_admitted_job_to_recovery();
    }
    handoff
}

async fn complete_private_oram_admitted_handoff_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    detached: &PrivateOramDetachedMutationAppendV2,
    coordinated: &PrivateOramCoordinatedPrestageV2,
) -> StorageResult<()> {
    let key = PrivateOramMutationKey {
        collection_id: detached.collection_id().to_string(),
    };
    let _execution = acquire_private_oram_mutation_execution_v2(&key).await?;
    // Outcome ACK remains pending until point staging and the replicated recovery-readiness
    // certificate are durable. Startup reconciliation is not yet allowed to rely on sequence 2 as
    // the sole replacement for reservation retention.
    detached.mark_admitted_ack_pending()?;
    require_exact_admitted_recovery_manifest_v2(dispatcher, coordinated)?;
    storage::dispatcher::private_oram_crash_point("mutation_v2_after_admission");
    private_oram_mutation_pause_v2(
        PRIVATE_ORAM_MUTATION_POST_ADMISSION_PAUSE_FILE_ENV,
        "Private ORAM staging mutation append post-admission pause reached",
    )
    .await;
    let parent =
        materialize_private_oram_admitted_parent_v2(dispatcher, settings, detached, coordinated)
            .await?;
    detached.mark_parent_sequence1()?;
    detached.begin_owner_adoption()?;
    let owners_prepared = coordinate_private_oram_owner_adoption_v2(
        dispatcher,
        settings,
        identity,
        detached,
        coordinated,
        &parent,
    )
    .await?;
    detached.mark_parent_sequence2()?;
    detached.begin_point_staging()?;
    let _point_stage = stage_private_oram_mutation_point_v2(
        dispatcher,
        settings,
        detached,
        coordinated,
        &owners_prepared,
    )
    .await?;
    record_private_oram_parent_progress_v2(
        dispatcher,
        settings,
        identity,
        detached.collection_name(),
        detached.vector_name(),
        &detached.immutable_manifest().manifest.owner_signing_key_id,
    )
    .await?;
    coordinate_private_oram_recovery_readiness_v2(
        dispatcher,
        settings,
        identity,
        detached.collection_name(),
        detached.vector_name(),
        &detached.immutable_manifest().manifest.owner_signing_key_id,
    )
    .await?;
    acknowledge_detached_reservation_outcome_v3(
        dispatcher,
        settings,
        identity,
        detached,
        PrivateOramReservationAckProposerV3::AdmittedLeaseOwner,
    )
    .await?;
    detached.mark_admitted_ack_complete()?;
    detached.mark_deciding()?;
    decide_private_oram_admitted_mutation_v2(dispatcher, coordinated.admission()).await
}

/// Commits an admitted mutation whose recovery readiness is certified and whose reservation
/// outcome is acknowledged, while its signed lease is valid. Expiry alone is not abort
/// authority: an expired preparing lease remains fenced until an authorized recovery policy
/// can supply durable abort intent and worker-quiescence evidence.
async fn decide_private_oram_admitted_mutation_v2(
    dispatcher: &Dispatcher,
    admission: &PrivateOramMutationAdmissionPlanV2,
) -> StorageResult<()> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    let key = PrivateOramMutationKey {
        collection_id: admission.lease().collection_id.clone(),
    };
    // Renewals can move the expiry of the lease consensus holds.
    let expires_at_unix = match consensus
        .private_oram_mutation_lease_slot(&key)
        .and_then(|slot| slot.active)
        .filter(|lease| lease.generation == admission.lease().generation)
    {
        Some(lease) => match lease.phase {
            PrivateOramMutationLeasePhase::Preparing => {
                // Both the live handoff and admitted recovery reach this boundary after durable
                // recovery readiness and reservation ACK. A live handoff failure must not let
                // recovery bypass the test's pre-decision crash, including an expired lease.
                storage::dispatcher::private_oram_crash_point(
                    "mutation_v2_before_consensus_commit",
                );
                lease.expires_at_unix
            }
            PrivateOramMutationLeasePhase::ConsensusCommitted { .. } => {
                // Confirm the exact paired state and receipt even when a prior proposal won.
                return commit_private_oram_admitted_mutation_v2(dispatcher, admission).await;
            }
            // Existing durable decisions remain the terminal recovery path's responsibility.
            PrivateOramMutationLeasePhase::AbortDecided => return Ok(()),
        },
        None => admission.lease().expires_at_unix,
    };
    if current_unix_secs()? < expires_at_unix {
        commit_private_oram_admitted_mutation_v2(dispatcher, admission).await
    } else {
        Err(StorageError::PreconditionFailed {
            description:
                "private ORAM admitted mutation lease expired and requires authorized recovery"
                    .to_string(),
        })
    }
}

/// The commit decision. With every owner pre-staged and adopted, the point staged and the
/// replicated recovery-readiness certificate durable, the coordinator commits the admitted plan's
/// exact new state over its exact old state; the lease moves to `ConsensusCommitted` in the same
/// apply. From there the supervisor's terminal resume records the decision, collects the owner
/// terminals and cleans up. A proposal that is not applied leaves the lease `Preparing`, and the
/// lease owner's supervisor proposes the same commit again; whichever proposal applies second is
/// refused deterministically and finds the commit already applied.
async fn commit_private_oram_admitted_mutation_v2(
    dispatcher: &Dispatcher,
    admission: &PrivateOramMutationAdmissionPlanV2,
) -> StorageResult<()> {
    dispatcher
        .submit_private_oram_mutation_consensus_commit_v2(
            admission,
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await
}

/// Parent materialization, owner adoption and point staging advance the coordinator's journal
/// past the parent progress consensus holds (none, right after admission), and each owner's
/// recovery capsule install checks the consensus parent watermark. The coordinator records that
/// progress one sequence at a time until consensus has caught up with the journal.
async fn record_private_oram_parent_progress_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
) -> StorageResult<()> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    let auth = Auth::new_internal(Access::full("private ORAM mutation parent progress"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_parent_progress_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != collection_id {
        return Err(invalid_owner_prestage());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id,
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let key = PrivateOramMutationKey { collection_id };
    for _ in 0..PRIVATE_ORAM_PARENT_PROGRESS_MAX_STEPS {
        let authority = consensus
            .linearizable_private_oram_mutation_reconcile_snapshot_v2(
                &key,
                identity.peer_id(),
                Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
            )
            .await?;
        let Some(progress) = journal
            .next_private_oram_mutation_parent_progress_before_decision_v2(authority)
            .map_err(|_| invalid_owner_prestage())?
        else {
            return Ok(());
        };
        dispatcher
            .submit_private_oram_mutation_parent_progress_v2(
                progress,
                Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
            )
            .await?;
    }
    Err(invalid_owner_prestage())
}

/// The lease owner's recovery of an admitted mutation that is not committed yet: after a restart,
/// or when its live handoff failed (for example because Raft leadership moved while it was in
/// flight). It reloads the exact admitted plan from the retained recovery manifest, re-runs the
/// steps before recovery readiness unless readiness is already certified, acknowledges the
/// reservation outcome and commits while the signed lease is valid. An expired preparing lease
/// stays fenced for authorized recovery. A committed or previously abort-decided lease is the
/// terminal resume's.
pub(crate) async fn reconcile_private_oram_admitted_to_commit_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    key: &PrivateOramMutationKey,
) -> StorageResult<()> {
    let _execution = acquire_private_oram_mutation_execution_v2(key).await?;
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    let state = consensus
        .private_oram_mutation_state(key)
        .ok_or_else(invalid_owner_prestage)?;
    let slot = consensus
        .private_oram_mutation_lease_slot(key)
        .ok_or_else(invalid_owner_prestage)?;
    let active_lease = slot.active.as_ref().ok_or_else(invalid_owner_prestage)?;
    if active_lease.phase != PrivateOramMutationLeasePhase::Preparing {
        return Ok(());
    }
    if active_lease.collection_id != key.collection_id
        || active_lease.owner_peer_id != identity.peer_id()
        || active_lease.owner_peer_id != dispatcher.this_peer_id()
        || !matches!(active_lease.phase, PrivateOramMutationLeasePhase::Preparing)
    {
        return Err(invalid_owner_prestage());
    }
    let retained = consensus
        .private_oram_mutation_v2_exact_admitted_recovery_manifest(key, active_lease)?
        .ok_or_else(invalid_owner_prestage)?;
    let (package, expected_old_state) = retained
        .coordinator_recovery_envelope()
        .map_err(|_| invalid_owner_prestage())?;
    if package.collection_name != collection_name
        || package.collection_id != key.collection_id
        || package.coordinator_peer_id != active_lease.owner_peer_id
        || package.owner_peer_id != active_lease.owner_peer_id
        || package.mutation_id != active_lease.mutation_id
        || package.mutation_digest != active_lease.signed_mutation_digest
        || package.transition_digest != active_lease.transition_digest
        || package.lease_generation != active_lease.generation
        || package.writer_fence != active_lease.writer_fence
    {
        return Err(invalid_owner_prestage());
    }
    if package.immutable_manifest.manifest.result_privacy
        != ResultPrivacyMode::PrivatePayloadOramRequired
    {
        return Err(invalid_owner_prestage());
    }
    let auth = Auth::new_internal(Access::full("private ORAM admitted restart reconciliation"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_admitted_restart_reconciliation_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != key.collection_id {
        return Err(invalid_owner_prestage());
    }
    let layout = consensus
        .private_oram_layout(&PrivateOramLayoutKey {
            collection_id: key.collection_id.clone(),
        })
        .ok_or_else(invalid_owner_prestage)?;
    if layout.owner_peer_ids != package.owner_peer_ids
        || layout.generation != expected_old_state.layout_generation
        || layout.layout_digest != expected_old_state.layout_digest
        || state.layout_generation != layout.generation
        || state.layout_digest != layout.layout_digest
    {
        return Err(invalid_owner_prestage());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &package.vector_name,
        &package.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != key.collection_id {
        return Err(invalid_owner_prestage());
    }
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&package.immutable_manifest.manifest)
            .map_err(|_| invalid_owner_prestage())?;
    if manifest_digest
        != package
            .owner_prepare
            .mutation_bundle
            .mutation
            .manifest_digest
        || manifest_digest != expected_old_state.manifest_digest
    {
        return Err(invalid_owner_prestage());
    }
    let staged_frame = decode_prestage_frame(&package)?;
    let staged_insert_frame_bytes = package
        .staged_insert_frame_b64
        .as_deref()
        .map(|encoded| {
            BASE64URL_NOPAD
                .decode(encoded.as_bytes())
                .map_err(|_| invalid_owner_prestage())
        })
        .transpose()?;
    let point_id = staged_frame
        .as_ref()
        .map(|frame| private_oram_staged_point_id_canonical_string(&frame.point.id))
        .transpose()
        .map_err(|_| invalid_owner_prestage())?;
    let staged_digest = staged_frame
        .as_ref()
        .map(private_oram_staged_insert_frame_v1_digest)
        .transpose()
        .map_err(|_| invalid_owner_prestage())?;
    let expected_visible_point_record = match package.immutable_manifest.manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => Some(PrivateOramVisiblePointRecordV1 {
            point_id: point_id.as_deref().ok_or_else(invalid_owner_prestage)?,
            staged_insert_sha256: staged_digest
                .as_deref()
                .ok_or_else(invalid_owner_prestage)?,
        }),
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if staged_frame.is_some() {
                return Err(invalid_owner_prestage());
            }
            None
        }
    };
    let mutation = &package.owner_prepare.mutation_bundle.mutation;
    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)
        .map_err(|_| invalid_owner_prestage())?;
    let validated_owner_prepare =
        validate_private_oram_append_owner_prepare_from_durable_recovery_v2(
            &package.immutable_manifest,
            &package.owner_prepare,
            &package.durable_read_observations,
            PrivateOramAppendOwnerPrestageValidationContextV2 {
                expected_collection_id: &key.collection_id,
                expected_manifest_digest: &manifest_digest,
                expected_owner_signing_key_id: &package.owner_signing_key_id,
                expected_layout_generation: layout.generation,
                expected_layout_digest: &layout.layout_digest,
                expected_writer_lease_digest: &mutation.writer_lease_digest,
                expected_writer_fence: active_lease.writer_fence,
                expected_state_sequence: expected_old_state.state_sequence,
                expected_old_state_digest: &old_state_digest,
                expected_visible_point_record,
                now_unix: mutation.new_state.state.signed_at_unix,
                max_mutation_ttl_secs: PRIVATE_ORAM_MUTATION_SESSION_LEASE_SECS,
                public_key: hnsw_context.public_key(),
            },
        )
        .map_err(|_| invalid_owner_prestage())?;
    let admission = derive_private_oram_mutation_admitted_recovery_plan_v2(
        active_lease,
        &state,
        &retained,
        &validated_owner_prepare,
    )
    .map_err(|_| invalid_owner_prestage())?;
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        package.owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let planned_parent = journal
        .plan_admitted_parent_v2(
            active_lease.owner_peer_id,
            &layout.owner_peer_ids,
            &package.immutable_manifest,
            &validated_owner_prepare,
            &admission,
        )
        .map_err(|_| invalid_owner_prestage())?;
    if planned_parent.descriptor_digest() != retained.parent_descriptor_digest()
        || planned_parent.lease_acquired_record_digest()
            != retained.parent_lease_acquired_record_digest()
    {
        return Err(invalid_owner_prestage());
    }
    let execution = PrivateOramDurableAdmittedExecutionV2 {
        controller_peer_id: active_lease.owner_peer_id,
        collection_name: collection_name.to_string(),
        vector_name: package.vector_name.clone(),
        immutable_manifest: package.immutable_manifest,
        validated_owner_prepare,
        staged_insert_frame_bytes,
        consensus_layout: layout,
    };
    let plan = PrivateOramDurableAdmittedPlanV2 {
        admission,
        planned_parent,
        all_owners_prestaged: retained,
    };

    // The owner capsule installs only accept the preparing lease over the old state, so the
    // steps before readiness re-run only while readiness is not certified.
    if !consensus.private_oram_mutation_v2_recovery_ready(key) {
        let parent =
            materialize_private_oram_admitted_parent_v2(dispatcher, settings, &execution, &plan)
                .await?;
        let owners_prepared = coordinate_private_oram_owner_adoption_v2(
            dispatcher, settings, identity, &execution, &plan, &parent,
        )
        .await?;
        stage_private_oram_mutation_point_v2(
            dispatcher,
            settings,
            &execution,
            &plan,
            &owners_prepared,
        )
        .await?;
        record_private_oram_parent_progress_v2(
            dispatcher,
            settings,
            identity,
            execution.collection_name(),
            execution.vector_name(),
            &execution.immutable_manifest().manifest.owner_signing_key_id,
        )
        .await?;
        coordinate_private_oram_recovery_readiness_v2(
            dispatcher,
            settings,
            identity,
            execution.collection_name(),
            execution.vector_name(),
            &execution.immutable_manifest().manifest.owner_signing_key_id,
        )
        .await?;
    }
    acknowledge_detached_reservation_outcome_v3(
        dispatcher,
        settings,
        identity,
        &execution,
        PrivateOramReservationAckProposerV3::AdmittedLeaseOwner,
    )
    .await?;
    decide_private_oram_admitted_mutation_v2(dispatcher, &plan.admission).await
}

fn require_exact_admitted_recovery_manifest_v2(
    dispatcher: &Dispatcher,
    coordinated: &impl PrivateOramAdmittedPlanContextV2,
) -> StorageResult<()> {
    if !matches!(
        coordinated.admission().lease().phase,
        PrivateOramMutationLeasePhase::Preparing
    ) {
        return Err(invalid_owner_prestage());
    }
    let retained = dispatcher
        .private_oram_mutation_v2_exact_admitted_recovery_manifest(coordinated.admission().lease())?
        .ok_or_else(invalid_owner_prestage)?;
    if retained != *coordinated.all_owners_prestaged() {
        return Err(invalid_owner_prestage());
    }
    Ok(())
}

async fn materialize_private_oram_admitted_parent_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    detached: &impl PrivateOramAdmittedExecutionContextV2,
    coordinated: &impl PrivateOramAdmittedPlanContextV2,
) -> StorageResult<PrivateOramMutationParentLeaseAcquiredV2> {
    let auth = Auth::new_internal(Access::full("private ORAM admitted parent materialization"));
    let pass = auth.check_collection_access(
        detached.collection_name(),
        AccessRequirements::new().write(),
        "private_oram_admitted_parent_materialization_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let lease = coordinated.admission().lease();
    if config.stable_crypto_id(collection.name())? != lease.collection_id {
        return Err(invalid_owner_prestage());
    }

    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let has_result = detached
        .immutable_manifest()
        .manifest
        .indexes
        .iter()
        .any(|index| index.kind() == qdrant_sec::PrivateOramIndexKindV2::Result);
    let _result_lifecycle = if has_result {
        Some(begin_private_result_oram_collection_lifecycle(
            collection.name(),
            &config,
        )?)
    } else {
        None
    };
    let owner_signing_key_id = &detached.immutable_manifest().manifest.owner_signing_key_id;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        detached.vector_name(),
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != lease.collection_id {
        return Err(invalid_owner_prestage());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let parent = journal
        .begin_admitted_v2(
            detached.controller_peer_id(),
            &detached.consensus_layout().owner_peer_ids,
            detached.immutable_manifest().clone(),
            detached.validated_owner_prepare(),
            coordinated.admission(),
        )
        .map_err(|_| invalid_owner_prestage())?;
    let planned = coordinated.planned_parent();
    let planned_owner_peer_ids = planned.owner_peer_ids();
    let owner_requirements_match = planned_owner_peer_ids.iter().all(|owner_peer_id| {
        parent.requirements_for_owner(*owner_peer_id)
            == planned.requirements_for_owner(*owner_peer_id)
    });
    if parent.descriptor_digest() != planned.descriptor_digest()
        || parent.lease_acquired_record_digest() != planned.lease_acquired_record_digest()
        || parent.preparing_lease() != lease
        || !owner_requirements_match
        || parent
            .owner_requirements()
            .iter()
            .any(|requirement| !planned_owner_peer_ids.contains(&requirement.peer_id))
        || collection.config_snapshot().await != config
    {
        return Err(invalid_owner_prestage());
    }
    require_exact_admitted_recovery_manifest_v2(dispatcher, coordinated)?;
    Ok(parent)
}

async fn coordinate_private_oram_owner_adoption_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    detached: &impl PrivateOramAdmittedExecutionContextV2,
    coordinated: &impl PrivateOramAdmittedPlanContextV2,
    parent: &PrivateOramMutationParentLeaseAcquiredV2,
) -> StorageResult<PrivateOramMutationOwnersPreparedV2> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    let coordinator_peer_id = detached.controller_peer_id();
    if coordinator_peer_id != dispatcher.this_peer_id()
        || coordinator_peer_id != identity.peer_id()
        || parent.preparing_lease() != coordinated.admission().lease()
    {
        return Err(invalid_owner_prestage());
    }

    let auth = Auth::new_internal(Access::full("private ORAM owner adoption coordination"));
    let pass = auth.check_collection_access(
        detached.collection_name(),
        AccessRequirements::new().write(),
        "private_oram_owner_adoption_coordination_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let lease = coordinated.admission().lease();
    let collection_id = config.stable_crypto_id(collection.name())?;
    if collection_id != lease.collection_id {
        return Err(invalid_owner_prestage());
    }
    let owner_signing_key_id = &detached.immutable_manifest().manifest.owner_signing_key_id;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        detached.vector_name(),
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != collection_id {
        return Err(invalid_owner_prestage());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let retained = dispatcher
        .private_oram_mutation_v2_exact_admitted_recovery_manifest(lease)?
        .ok_or_else(invalid_owner_prestage)?;
    if retained != *coordinated.all_owners_prestaged() {
        return Err(invalid_owner_prestage());
    }
    let coordinator_pin = consensus.private_oram_peer_recovery_signer_pin(coordinator_peer_id)?;
    if coordinator_pin.signer() != identity.public_key() {
        return Err(invalid_owner_prestage());
    }

    let owner_peer_ids = &detached.consensus_layout().owner_peer_ids;
    let mut owner_projections = Vec::with_capacity(owner_peer_ids.len());
    for owner_peer_id in owner_peer_ids {
        let receipt = retained
            .owner_receipt(*owner_peer_id)
            .ok_or_else(invalid_owner_prestage)?;
        let owner_parent = parent
            .owner_prepare_parent(*owner_peer_id)
            .map_err(|_| invalid_owner_prestage())?;
        if receipt.owner_peer_id() != *owner_peer_id
            || receipt.parent_descriptor_digest() != parent.descriptor_digest()
            || receipt.parent_lease_acquired_record_digest()
                != parent.lease_acquired_record_digest()
        {
            return Err(invalid_owner_prestage());
        }

        let evidence = if *owner_peer_id == coordinator_peer_id {
            let _hnsw_lifecycle =
                begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
            let has_result = detached
                .immutable_manifest()
                .manifest
                .indexes
                .iter()
                .any(|index| index.kind() == qdrant_sec::PrivateOramIndexKindV2::Result);
            let _result_lifecycle = if has_result {
                Some(begin_private_result_oram_collection_lifecycle(
                    collection.name(),
                    &config,
                )?)
            } else {
                None
            };
            let hnsw_store = PrivateHnswOramStore::new(collection.path(), detached.vector_name())?;
            PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path())
                .adopt_for_parent_v2(
                    receipt.intent_key(),
                    receipt.package_sha256(),
                    &owner_parent,
                )
                .map_err(|_| invalid_owner_prestage_storage())?
        } else {
            let parent_canonical_json = encode_private_oram_owner_prepare_parent_v2(&owner_parent)
                .map_err(|_| invalid_owner_prestage())?;
            let request = PrivateOramOwnerAdoptionRequestV1 {
                version: PRIVATE_ORAM_OWNER_ADOPTION_PROTOCOL_VERSION_V1,
                challenge_nonce: new_private_oram_peer_recovery_challenge_nonce_v2()
                    .map_err(|_| invalid_owner_prestage())?,
                collection_name: detached.collection_name().to_string(),
                collection_id: collection_id.clone(),
                mutation_id: lease.mutation_id.clone(),
                mutation_digest: lease.signed_mutation_digest.clone(),
                transition_digest: lease.transition_digest.clone(),
                lease_generation: lease.generation,
                writer_fence: lease.writer_fence,
                coordinator_peer_id,
                owner_peer_id: *owner_peer_id,
                vector_name: detached.vector_name().to_string(),
                owner_signing_key_id: owner_signing_key_id.clone(),
                intent_key: receipt.intent_key().to_string(),
                package_sha256: receipt.package_sha256().to_string(),
                parent_descriptor_digest: parent.descriptor_digest().to_string(),
                parent_lease_acquired_record_digest: parent
                    .lease_acquired_record_digest()
                    .to_string(),
                parent_canonical_sha256: private_oram_owner_capsule_canonical_sha256_v2(
                    &parent_canonical_json,
                ),
                parent_canonical_len: u64::try_from(parent_canonical_json.len())
                    .map_err(|_| invalid_owner_prestage())?,
            };
            let coordinator_signature = identity
                .sign_owner_adoption_request(&request)
                .map_err(|_| invalid_owner_prestage())?;
            let pins = consensus
                .private_oram_peer_recovery_signer_pair_pin(*owner_peer_id, coordinator_peer_id)?;
            validate_pair_pin(&pins, identity, &coordinator_pin.activation_authority())
                .map_err(|_| invalid_owner_prestage())?;
            let response = toc
                .get_channel_service()
                .adopt_private_oram_mutation_owner_v2(
                    *owner_peer_id,
                    request,
                    &owner_parent,
                    identity.public_key().clone(),
                    coordinator_signature,
                    pins.coordinator().signer(),
                    pins.owner().signer(),
                )
                .await?;
            if response.peer_id() != *owner_peer_id
                || consensus.private_oram_peer_recovery_signer_pair_pin(
                    *owner_peer_id,
                    coordinator_peer_id,
                )? != pins
            {
                return Err(invalid_owner_prestage());
            }
            response.into_evidence()
        };
        if evidence.owner_peer_id() != *owner_peer_id
            || evidence.journal_descriptor_digest() != receipt.owner_journal_descriptor_digest()
        {
            return Err(invalid_owner_prestage());
        }
        owner_projections.push(
            parent
                .project_local_owner_prepared(&evidence)
                .map_err(|_| invalid_owner_prestage())?,
        );
    }

    repin_all_owners(
        consensus,
        identity,
        coordinator_peer_id,
        owner_peer_ids,
        &coordinator_pin,
    )
    .map_err(|_| invalid_owner_prestage())?;
    if collection.config_snapshot().await != config
        || dispatcher
            .private_oram_mutation_v2_exact_admitted_recovery_manifest(lease)?
            .as_ref()
            != Some(&retained)
    {
        return Err(invalid_owner_prestage());
    }

    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let has_result = detached
        .immutable_manifest()
        .manifest
        .indexes
        .iter()
        .any(|index| index.kind() == qdrant_sec::PrivateOramIndexKindV2::Result);
    let _result_lifecycle = if has_result {
        Some(begin_private_result_oram_collection_lifecycle(
            collection.name(),
            &config,
        )?)
    } else {
        None
    };
    let prepared = journal
        .mark_owners_prepared_from_durable_v2(parent, owner_projections)
        .map_err(|_| invalid_owner_prestage_storage())?;
    if collection.config_snapshot().await != config {
        return Err(invalid_owner_prestage());
    }
    require_exact_admitted_recovery_manifest_v2(dispatcher, coordinated)?;
    Ok(prepared)
}

async fn stage_private_oram_mutation_point_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    detached: &impl PrivateOramAdmittedExecutionContextV2,
    coordinated: &impl PrivateOramAdmittedPlanContextV2,
    owners_prepared: &PrivateOramMutationOwnersPreparedV2,
) -> StorageResult<PrivateOramMutationPointStageDurableV2> {
    let auth = Auth::new_internal(Access::full("private ORAM point staging"));
    let pass = auth.check_collection_access(
        detached.collection_name(),
        AccessRequirements::new().write(),
        "private_oram_point_staging_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let lease = coordinated.admission().lease();
    if config.stable_crypto_id(collection.name())? != lease.collection_id {
        return Err(invalid_owner_prestage());
    }
    let owner_signing_key_id = &detached.immutable_manifest().manifest.owner_signing_key_id;
    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let has_result = detached
        .immutable_manifest()
        .manifest
        .indexes
        .iter()
        .any(|index| index.kind() == qdrant_sec::PrivateOramIndexKindV2::Result);
    let _result_lifecycle = if has_result {
        Some(begin_private_result_oram_collection_lifecycle(
            collection.name(),
            &config,
        )?)
    } else {
        None
    };
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        detached.vector_name(),
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != lease.collection_id {
        return Err(invalid_owner_prestage());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let staged = journal
        .stage_point_from_prepared_v2(owners_prepared, detached.staged_insert_frame_bytes())
        .map_err(|_| invalid_owner_prestage_storage())?;
    if collection.config_snapshot().await != config {
        return Err(invalid_owner_prestage());
    }
    require_exact_admitted_recovery_manifest_v2(dispatcher, coordinated)?;
    Ok(staged)
}

/// A failure before submission must resolve the *prepared* attempt. Reserved-only rejection
/// deliberately refuses this state. The exact admission and rejection race through the same CAS,
/// so observing an admission here transfers responsibility to the admitted recovery path.
async fn resolve_failed_private_oram_preadmission_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    detached: &PrivateOramDetachedMutationAppendV2,
    coordinated: &PrivateOramCoordinatedPrestageV2,
    original_error: StorageError,
) -> StorageResult<()> {
    match dispatcher
        .reject_private_oram_mutation_prepared_admission_v2(
            coordinated.admission().lease(),
            coordinated.all_owners_prestaged(),
            coordinated.prepared_aggregate_digest(),
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await
    {
        Ok(PrivateOramMutationAdmissionOutcomeV2::AppliedExact) => {
            let handoff = complete_private_oram_admitted_handoff_v2(
                dispatcher,
                settings,
                identity,
                detached,
                coordinated,
            )
            .await;
            hand_failed_admitted_handoff_to_recovery_v2(detached, handoff)
        }
        Ok(PrivateOramMutationAdmissionOutcomeV2::CommittedRejected) => {
            // A follower cannot acknowledge this outcome itself. Keep the durable rejection and
            // its local pending phase for the current leader and the runtime retirement scan.
            let _ = complete_private_oram_rejected_handoff_v2(
                dispatcher,
                settings,
                identity,
                detached,
                coordinated.admission().lease(),
            )
            .await;
            Err(original_error)
        }
        Err(_) => {
            let _ = detached.mark_preadmission_recovery_required();
            Err(original_error)
        }
    }
}

async fn complete_private_oram_rejected_handoff_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    detached: &PrivateOramDetachedMutationAppendV2,
    lease: &PrivateOramMutationLease,
) -> StorageResult<()> {
    detached.mark_rejected_ack_pending()?;
    if !acknowledge_private_oram_rejected_admission_v2(
        dispatcher,
        settings,
        identity,
        detached.collection_name(),
        detached.vector_name(),
        &detached.immutable_manifest().manifest.owner_signing_key_id,
        lease,
    )
    .await?
    {
        return Err(StorageError::service_error(
            "private ORAM rejected admission acknowledgement requires recovery",
        ));
    }
    detached.mark_rejected_ack_complete()
}

#[allow(clippy::too_many_arguments)]
async fn acknowledge_private_oram_rejected_admission_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    lease: &PrivateOramMutationLease,
) -> StorageResult<bool> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    let key = PrivateOramMutationKey {
        collection_id: lease.collection_id.clone(),
    };
    if consensus
        .private_oram_mutation_v2_rejected_admission_acknowledgement(&key, lease)?
        .is_some()
    {
        return Ok(true);
    }
    consensus.require_private_oram_activation_coordinator_is_local_leader()?;
    private_oram_mutation_pause_v2(
        PRIVATE_ORAM_MUTATION_REJECTION_PRE_ACK_PAUSE_FILE_ENV,
        "Private ORAM staging mutation rejection pre-acknowledgement pause reached",
    )
    .await;
    acknowledge_oldest_private_oram_reservation_outcome_v3(
        dispatcher,
        settings,
        identity,
        collection_name,
        vector_name,
        owner_signing_key_id,
        PrivateOramReservationAckProposerV3::Leader,
    )
    .await?;
    Ok(consensus
        .private_oram_mutation_v2_rejected_admission_acknowledgement(&key, lease)?
        .is_some())
}

/// Reconcile only the durable boundary before admission. The admitted lease owner remains
/// responsible if its admission won, and a live worker in the current term keeps its opportunity
/// to admit. A leader change or a completed worker makes the prepared attempt an orphan.
pub(crate) async fn recover_private_oram_preadmission_once_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    candidate: &PrivateOramMutationPreadmissionRecoveryCandidateV2,
) -> StorageResult<bool> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    consensus.require_private_oram_activation_coordinator_is_local_leader()?;
    if identity.peer_id() != dispatcher.this_peer_id() {
        return Err(invalid_owner_prestage());
    }
    if let Some(snapshot) = candidate.prepared_snapshot()
        && snapshot.reservation().controller_peer_id() == dispatcher.this_peer_id()
        && snapshot.reservation().controller_term() == consensus.hard_state().term
        && private_oram_detached_job_exists_for_collection_v2(&candidate.key().collection_id)?
    {
        return Ok(false);
    }
    let (package, _) = candidate
        .manifest()
        .coordinator_recovery_envelope()
        .map_err(|_| invalid_owner_prestage())?;
    let lease = candidate.lease();
    if package.collection_name != collection_name
        || package.collection_id != candidate.key().collection_id
        || package.collection_id != lease.collection_id
        || package.coordinator_peer_id != lease.owner_peer_id
        || package.owner_peer_id != lease.owner_peer_id
        || package.mutation_id != lease.mutation_id
        || package.mutation_digest != lease.signed_mutation_digest
        || package.transition_digest != lease.transition_digest
        || package.lease_generation != lease.generation
        || package.writer_fence != lease.writer_fence
        || package.immutable_manifest.manifest.result_privacy
            != ResultPrivacyMode::PrivatePayloadOramRequired
    {
        return Err(invalid_owner_prestage());
    }
    let auth = Auth::new_internal(Access::full("private ORAM prepared append recovery"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_prepared_append_recovery_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let collection = dispatcher
        .toc(&auth, &verification)
        .get_collection(&pass)
        .await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != candidate.key().collection_id {
        return Err(invalid_owner_prestage());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &package.vector_name,
        &package.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != candidate.key().collection_id {
        return Err(invalid_owner_prestage());
    }
    if let Some(snapshot) = candidate.prepared_snapshot() {
        let execution = acquire_private_oram_mutation_execution_v2(candidate.key()).await?;
        consensus.require_private_oram_activation_coordinator_is_local_leader()?;
        let outcome = dispatcher
            .reject_private_oram_mutation_prepared_admission_v2(
                lease,
                snapshot.prepared(),
                snapshot.expected_aggregate_digest(),
                Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
            )
            .await?;
        drop(execution);
        if outcome == PrivateOramMutationAdmissionOutcomeV2::AppliedExact {
            return Ok(true);
        }
    }
    if collection.config_snapshot().await != config {
        return Err(invalid_owner_prestage());
    }
    acknowledge_private_oram_rejected_admission_v2(
        dispatcher,
        settings,
        identity,
        collection_name,
        &package.vector_name,
        &package.owner_signing_key_id,
        lease,
    )
    .await
}

async fn acknowledge_detached_reservation_outcome_v3(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    detached: &impl PrivateOramAdmittedExecutionContextV2,
    proposer: PrivateOramReservationAckProposerV3,
) -> StorageResult<()> {
    acknowledge_oldest_private_oram_reservation_outcome_v3(
        dispatcher,
        settings,
        identity,
        detached.collection_name(),
        detached.vector_name(),
        &detached.immutable_manifest().manifest.owner_signing_key_id,
        proposer,
    )
    .await
    .map(|_| ())
}

pub(crate) async fn coordinate_private_oram_owner_prestage_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    validated: &PrivateOramDetachedMutationAppendV2,
) -> StorageResult<PrivateOramCoordinatedPrestageV2> {
    if validated.immutable_manifest().manifest.result_privacy
        != ResultPrivacyMode::PrivatePayloadOramRequired
    {
        return Err(StorageError::bad_request(
            "private ORAM V2 mutation admission requires private_payload_oram_required",
        ));
    }
    validated.begin_owner_prestage()?;
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_prestage)?;
    consensus.require_private_oram_activation_coordinator_is_local_leader()?;
    let coordinator_peer_id = dispatcher.this_peer_id();
    if identity.peer_id() != coordinator_peer_id
        || !validated
            .consensus_layout()
            .owner_peer_ids
            .contains(&coordinator_peer_id)
    {
        return Err(invalid_owner_prestage());
    }
    let collection_id = &validated
        .validated_owner_prepare()
        .mutation_bundle()
        .mutation
        .collection_id;
    let key = PrivateOramMutationKey {
        collection_id: collection_id.clone(),
    };
    let authority_context = consensus.private_oram_mutation_v2_append_authority_context(&key)?;
    let expected_aggregate_digest = authority_context.expected_aggregate_digest().to_string();
    let admission = derive_private_oram_mutation_admission_plan_v2(
        coordinator_peer_id,
        validated
            .consensus_slot()
            .generation
            .checked_add(1)
            .ok_or_else(invalid_owner_prestage)?,
        validated
            .consensus_slot()
            .max_writer_fence
            .checked_add(1)
            .ok_or_else(invalid_owner_prestage)?,
        validated.consensus_slot(),
        validated.consensus_state(),
        validated.validated_owner_prepare(),
    )
    .map_err(|_| invalid_owner_prestage())?;

    let auth = Auth::new_internal(Access::full("private ORAM owner pre-stage coordinator"));
    let pass = auth.check_collection_access(
        validated.collection_name(),
        AccessRequirements::new().write(),
        "private_oram_owner_prestage_coordinator_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != *collection_id {
        return Err(invalid_owner_prestage());
    }
    let owner_signing_key_id = &validated.immutable_manifest().manifest.owner_signing_key_id;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        validated.vector_name(),
        owner_signing_key_id,
    )?;
    if acknowledge_oldest_private_oram_reservation_outcome_v3(
        dispatcher,
        settings,
        identity,
        validated.collection_name(),
        validated.vector_name(),
        owner_signing_key_id,
        PrivateOramReservationAckProposerV3::Leader,
    )
    .await?
    {
        return Err(StorageError::PreconditionFailed {
            description:
                "private ORAM prior reservation outcome was acknowledged; retry append validation"
                    .to_string(),
        });
    }
    if !consensus.private_oram_mutation_v3_reservation_challenge_pending(&key)?
        && let Ok(resolution_contexts) =
            consensus.private_oram_mutation_v3_owner_reservation_resolution_contexts(&key)
    {
        resolve_private_oram_owner_reservation_fences_v3(
            toc,
            settings,
            consensus,
            identity,
            validated.collection_name(),
            validated.vector_name(),
            owner_signing_key_id,
            &resolution_contexts,
        )
        .await?;
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let planned_parent = journal
        .plan_admitted_parent_v2(
            coordinator_peer_id,
            &validated.consensus_layout().owner_peer_ids,
            validated.immutable_manifest(),
            validated.validated_owner_prepare(),
            &admission,
        )
        .map_err(|_| invalid_owner_prestage())?;
    let coordinator_pin = consensus.private_oram_peer_recovery_signer_pin(coordinator_peer_id)?;
    if coordinator_pin.signer() != identity.public_key() {
        return Err(invalid_owner_prestage());
    }
    let activation = coordinator_pin.activation_authority();
    let owner_roster_digest =
        private_oram_owner_prestage_roster_digest_v2(&validated.consensus_layout().owner_peer_ids)
            .map_err(|_| invalid_owner_prestage())?;
    let staged_insert_frame_b64 = validated
        .staged_insert_frame_bytes()
        .map(|bytes| BASE64URL_NOPAD.encode(bytes));
    let mutation = &validated
        .validated_owner_prepare()
        .mutation_bundle()
        .mutation;
    let mut owner_calls = Vec::with_capacity(validated.consensus_layout().owner_peer_ids.len());
    for owner_peer_id in &validated.consensus_layout().owner_peer_ids {
        let package = PrivateOramOwnerPrestagePackageV2 {
            version: qdrant_sec::PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
            collection_name: validated.collection_name().to_string(),
            collection_id: collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            mutation_digest: admission.mutation_digest().to_string(),
            transition_digest: admission.lease().transition_digest.clone(),
            base_record_digest: admission.lease().base_record_digest.clone(),
            expected_aggregate_digest: expected_aggregate_digest.clone(),
            lease_generation: admission.lease().generation,
            writer_fence: admission.lease().writer_fence,
            coordinator_peer_id,
            owner_peer_id: *owner_peer_id,
            vector_name: validated.vector_name().to_string(),
            owner_signing_key_id: owner_signing_key_id.clone(),
            activation_registry_generation: activation.registry_generation(),
            activation_manifest_digest: activation.manifest_digest().to_string(),
            parent_descriptor_digest: planned_parent.descriptor_digest().to_string(),
            parent_lease_acquired_record_digest: planned_parent
                .lease_acquired_record_digest()
                .to_string(),
            owner_peer_ids: validated.consensus_layout().owner_peer_ids.clone(),
            owner_roster_digest: owner_roster_digest.clone(),
            immutable_manifest: validated.immutable_manifest().clone(),
            owner_prepare: validated.owner_prepare_for_transport().clone(),
            durable_read_observations: validated.durable_read_observations().to_vec(),
            staged_insert_frame_b64: staged_insert_frame_b64.clone(),
        };
        let package_canonical_json = encode_private_oram_owner_prestage_package_v2(&package)
            .map_err(|_| invalid_owner_prestage())?;
        let request = private_oram_owner_prestage_request_v2(
            new_private_oram_owner_prestage_challenge_nonce_v2()
                .map_err(|_| invalid_owner_prestage())?,
            &package,
            &package_canonical_json,
        )
        .map_err(|_| invalid_owner_prestage())?;
        let coordinator_signature = identity
            .sign_owner_prestage_request(&request)
            .map_err(|_| invalid_owner_prestage())?;
        let pair =
            if *owner_peer_id == coordinator_peer_id {
                None
            } else {
                Some(consensus.private_oram_peer_recovery_signer_pair_pin(
                    *owner_peer_id,
                    coordinator_peer_id,
                )?)
            };
        let expected_owner_signer = pair.as_ref().map_or_else(
            || coordinator_pin.signer().clone(),
            |pins| pins.owner().signer().clone(),
        );
        let _verified_request = validate_private_oram_owner_prestage_request_signature_v2(
            identity.public_key(),
            &request,
            &package_canonical_json,
            &coordinator_signature,
        )
        .map_err(|_| invalid_owner_prestage())?;
        owner_calls.push((
            *owner_peer_id,
            request,
            package_canonical_json,
            coordinator_signature,
            pair,
            expected_owner_signer,
        ));
    }
    let coordinator_recovery_package_canonical_json = owner_calls
        .iter()
        .find(|(owner_peer_id, ..)| *owner_peer_id == coordinator_peer_id)
        .map(|(_, _, package_canonical_json, ..)| package_canonical_json.clone())
        .ok_or_else(invalid_owner_prestage)?;
    let reservation = derive_private_oram_mutation_append_reservation_v2(
        &planned_parent,
        &admission,
        authority_context,
        activation.clone(),
        validated.controller_peer_id(),
        validated.controller_term(),
        owner_calls
            .iter()
            .map(|(_, request, _, _, _, signer)| (request.clone(), signer.clone()))
            .collect(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    if consensus.private_oram_mutation_v3_reservation_challenge_pending(&key)? {
        if !consensus
            .private_oram_mutation_v3_pending_reservation_matches_base(&key, &reservation)?
        {
            return Err(invalid_owner_prestage());
        }
    } else {
        let owner_challenge_nonces = (0..reservation.owner_targets().len())
            .map(|_| private_oram_random_token(16))
            .collect::<StorageResult<Vec<_>>>()?;
        let challenge_operation = consensus
            .private_oram_mutation_v3_reservation_challenge_operation(
                &reservation,
                owner_challenge_nonces,
            )?;
        let _challenge_proposal = consensus
            .propose_consensus_op_with_await(
                challenge_operation,
                Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
            )
            .await;
    }
    let reservation_contexts = consensus
        .private_oram_mutation_v3_owner_reservation_prepare_contexts(&key)
        .map_err(|_| invalid_owner_prestage())?;
    if reservation_contexts.len() != owner_calls.len()
        || reservation_contexts
            .iter()
            .zip(&owner_calls)
            .any(|(context, (owner_peer_id, ..))| {
                context.challenge().owner_peer_id != *owner_peer_id
                    || context.challenge().attempt_id != reservation.attempt_id()
            })
    {
        return Err(invalid_owner_prestage());
    }

    let mut owner_reservation_prepares = Vec::with_capacity(reservation_contexts.len());
    for (context, (owner_peer_id, ..)) in reservation_contexts.iter().zip(&owner_calls) {
        let prepare_result: StorageResult<PrivateOramOwnerReservationPrepareV1> =
            if *owner_peer_id == coordinator_peer_id {
                prepare_private_oram_owner_reservation_v3(
                    toc,
                    settings,
                    consensus,
                    identity,
                    validated.collection_name(),
                    validated.vector_name(),
                    owner_signing_key_id,
                    context,
                )
                .await
            } else {
                async {
                    // The remote prepare validates its own committed challenge. Synchronize
                    // this owner first, keeping wait failures in the cancellation path below.
                    let state = consensus.hard_state();
                    toc.get_channel_service()
                        .await_commit_on_peer(
                            *owner_peer_id,
                            state.commit,
                            state.term,
                            PRIVATE_ORAM_RECOVERY_READINESS_WAIT,
                        )
                        .await
                        .map_err(|_| invalid_owner_prestage())?;
                    toc.get_channel_service()
                        .prepare_private_oram_mutation_owner_reservation_v3(
                            *owner_peer_id,
                            validated.collection_name(),
                            validated.vector_name(),
                            owner_signing_key_id,
                            context.challenge(),
                            context.expected_owner_signer(),
                            context.expected_lifecycle_state(),
                        )
                        .await
                        .map(|response| response.into_verified().prepare().clone())
                        .map_err(|_| invalid_owner_prestage())
                }
                .await
            };
        match prepare_result {
            Ok(prepare) => owner_reservation_prepares.push(prepare),
            Err(error) => {
                if let Ok(operation) = consensus
                    .private_oram_mutation_v3_reservation_challenge_cancellation_operation(
                        key.clone(),
                        private_oram_random_token(32)?,
                    )
                {
                    let _cancellation = consensus
                        .propose_consensus_op_with_await(
                            operation,
                            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
                        )
                        .await;
                }
                if !consensus.private_oram_mutation_v3_reservation_challenge_pending(&key)? {
                    resolve_private_oram_owner_reservation_fences_v3(
                        toc,
                        settings,
                        consensus,
                        identity,
                        validated.collection_name(),
                        validated.vector_name(),
                        owner_signing_key_id,
                        &reservation_contexts,
                    )
                    .await?;
                    acknowledge_oldest_private_oram_reservation_outcome_v3(
                        dispatcher,
                        settings,
                        identity,
                        validated.collection_name(),
                        validated.vector_name(),
                        owner_signing_key_id,
                        PrivateOramReservationAckProposerV3::Leader,
                    )
                    .await?;
                }
                return Err(error);
            }
        }
    }
    let reservation_operation = consensus
        .private_oram_mutation_v3_append_reservation_operation(&key, owner_reservation_prepares)?;
    let _reservation_proposal = consensus
        .propose_consensus_op_with_await(
            reservation_operation,
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await;
    let Some((retained_reservation, retained_prepared)) =
        consensus.private_oram_mutation_v2_active_append_attempt(&key)?
    else {
        return Err(invalid_owner_prestage());
    };
    if retained_reservation != reservation || retained_prepared.is_some() {
        return Err(invalid_owner_prestage());
    }
    resolve_private_oram_owner_reservation_fences_v3(
        toc,
        settings,
        consensus,
        identity,
        validated.collection_name(),
        validated.vector_name(),
        owner_signing_key_id,
        &reservation_contexts,
    )
    .await?;
    let reserved_aggregate_digest =
        consensus.private_oram_mutation_v2_current_aggregate_digest(&key)?;

    let mut owner_evidence = Vec::with_capacity(owner_calls.len());
    let mut owner_receipts = Vec::with_capacity(owner_calls.len());
    let mut owner_resolution_receipts = Vec::with_capacity(owner_calls.len());
    for (
        owner_peer_id,
        request,
        package_canonical_json,
        coordinator_signature,
        pair,
        expected_owner_signer,
    ) in owner_calls
    {
        let reservation_challenge = reservation_contexts
            .iter()
            .find(|context| context.challenge().owner_peer_id == owner_peer_id)
            .map(PrivateOramOwnerReservationPrepareContextV3::challenge)
            .ok_or_else(invalid_owner_prestage)?;
        let verified_request = validate_private_oram_owner_prestage_request_signature_v2(
            identity.public_key(),
            &request,
            &package_canonical_json,
            &coordinator_signature,
        )
        .map_err(|_| invalid_owner_prestage())?;
        let owner_result: StorageResult<_> = async {
            if owner_peer_id == coordinator_peer_id {
                // Detaching the append job already released its paired read sessions.
                // The local owner acquires the same lifecycle guard as a remote owner;
                // requiring the consumed read sessions here would reject every append.
                let receipt = install_private_oram_owner_prestage_v2(
                    toc,
                    settings,
                    consensus,
                    &verified_request,
                    &package_canonical_json,
                )
                .await?;
                let resolution_receipt = confirm_private_oram_owner_installed_reservation_v3(
                    toc,
                    settings,
                    consensus,
                    identity,
                    validated.collection_name(),
                    validated.vector_name(),
                    owner_signing_key_id,
                    reservation_challenge,
                    &receipt,
                )
                .await?;
                let receipt_canonical_json =
                    collection::encode_private_oram_owner_prestage_receipt_v2(&receipt)
                        .map_err(|_| invalid_owner_prestage())?;
                let response = private_oram_owner_prestage_response_v2(
                    &request,
                    &receipt_canonical_json,
                    receipt.receipt_digest().to_string(),
                )
                .map_err(|_| invalid_owner_prestage())?;
                let statement = private_oram_owner_prestage_attestation_statement_v2(
                    &request,
                    &response,
                    &receipt_canonical_json,
                )
                .map_err(|_| invalid_owner_prestage())?;
                let attestation = identity
                    .sign_owner_prestage_attestation(&statement)
                    .map_err(|_| invalid_owner_prestage())?;
                let _verified = validate_private_oram_owner_prestage_attestation_for_signer_v2(
                    &attestation,
                    &expected_owner_signer,
                )
                .map_err(|_| invalid_owner_prestage())?;
                Ok((receipt, attestation, resolution_receipt))
            } else {
                let pins = pair.as_ref().expect("remote owner has signer pair");
                if pins.coordinator().signer() != identity.public_key()
                    || pins.coordinator().activation_authority() != activation
                    || pins.owner().activation_authority() != activation
                {
                    return Err(invalid_owner_prestage());
                }
                let response = toc
                    .get_channel_service()
                    .prestage_private_oram_mutation_owner_v2(
                        owner_peer_id,
                        request,
                        package_canonical_json,
                        identity.public_key().clone(),
                        coordinator_signature,
                        pins.coordinator().signer(),
                        pins.owner().signer(),
                        reservation_challenge,
                    )
                    .await?;
                Ok((
                    response.receipt().clone(),
                    response.owner_attestation().attestation().clone(),
                    response.reservation_resolution_receipt().clone(),
                ))
            }
        }
        .await;
        let (receipt, attestation, resolution_receipt) = match owner_result {
            Ok(result) => result,
            Err(error) => {
                resolve_private_oram_reserved_attempt_rejection_v2(consensus, &key, &reservation)
                    .await?;
                acknowledge_oldest_private_oram_reservation_outcome_v3(
                    dispatcher,
                    settings,
                    identity,
                    validated.collection_name(),
                    validated.vector_name(),
                    owner_signing_key_id,
                    PrivateOramReservationAckProposerV3::Leader,
                )
                .await?;
                return Err(error);
            }
        };
        owner_evidence.push(
            PrivateOramMutationOwnerPrestageEvidenceV2::from_signed_attestation(
                receipt.clone(),
                attestation,
                &expected_owner_signer,
            )
            .map_err(|_| invalid_owner_prestage())?,
        );
        owner_receipts.push(receipt);
        owner_resolution_receipts.push(resolution_receipt);
    }
    let repin_result = repin_all_owners(
        consensus,
        identity,
        coordinator_peer_id,
        &validated.consensus_layout().owner_peer_ids,
        &coordinator_pin,
    );
    let retained_attempt = consensus.private_oram_mutation_v2_active_append_attempt(&key)?;
    if repin_result.is_err()
        || collection.config_snapshot().await != config
        || consensus.private_oram_mutation_v2_current_aggregate_digest(&key)?
            != reserved_aggregate_digest
        || consensus.private_oram_mutation_state(&key).as_ref() != Some(validated.consensus_state())
        || consensus.private_oram_mutation_lease_slot(&key).as_ref()
            != Some(validated.consensus_slot())
        || retained_attempt
            .as_ref()
            .map(|(retained, prepared)| retained == &reservation && prepared.is_none())
            != Some(true)
    {
        resolve_private_oram_reserved_attempt_rejection_v2(consensus, &key, &reservation).await?;
        acknowledge_oldest_private_oram_reservation_outcome_v3(
            dispatcher,
            settings,
            identity,
            validated.collection_name(),
            validated.vector_name(),
            owner_signing_key_id,
            PrivateOramReservationAckProposerV3::Leader,
        )
        .await?;
        return Err(invalid_owner_prestage());
    }
    let all_owners_prestaged = derive_private_oram_mutation_all_owners_prestaged_v2(
        &planned_parent,
        &admission,
        expected_aggregate_digest,
        activation,
        owner_evidence,
        coordinator_recovery_package_canonical_json,
    )
    .map_err(|_| invalid_owner_prestage())?;
    let prepared_operation = consensus
        .private_oram_mutation_v2_append_prepared_operation_at_expected(
            &all_owners_prestaged,
            reserved_aggregate_digest,
        )?;
    let _prepared_proposal = consensus
        .propose_consensus_op_with_await(
            prepared_operation,
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await;
    let Some((retained_reservation, retained_prepared)) =
        consensus.private_oram_mutation_v2_active_append_attempt(&key)?
    else {
        return Err(invalid_owner_prestage());
    };
    if retained_reservation != reservation
        || retained_prepared.as_ref() != Some(&all_owners_prestaged)
    {
        return Err(invalid_owner_prestage());
    }
    let prepared_aggregate_digest =
        consensus.private_oram_mutation_v2_current_aggregate_digest(&key)?;
    validated.complete_owner_prestage()?;
    Ok(PrivateOramCoordinatedPrestageV2 {
        admission,
        planned_parent,
        all_owners_prestaged,
        prepared_aggregate_digest,
        owner_receipts,
        owner_resolution_receipts,
    })
}

async fn resolve_private_oram_reserved_attempt_rejection_v2(
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    key: &PrivateOramMutationKey,
    reservation: &PrivateOramMutationAppendReservationV2,
) -> StorageResult<()> {
    for _ in 0..3 {
        let Some((retained, prepared)) =
            consensus.private_oram_mutation_v2_active_append_attempt(key)?
        else {
            return Ok(());
        };
        if retained != *reservation || prepared.is_some() {
            return Err(StorageError::service_error(
                "private ORAM reserved append resolution found conflicting authority",
            ));
        }
        let expected = consensus.private_oram_mutation_v2_current_aggregate_digest(key)?;
        let operation = consensus
            .private_oram_mutation_v2_reserved_attempt_rejected_operation_at_expected(
                reservation,
                expected,
            )?;
        let _proposal = consensus
            .propose_consensus_op_with_await(operation, Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT))
            .await;
    }
    if consensus
        .private_oram_mutation_v2_active_append_attempt(key)?
        .is_none()
    {
        Ok(())
    } else {
        Err(StorageError::service_error(
            "private ORAM reserved append rejection remains pending",
        ))
    }
}

pub(crate) async fn install_private_oram_owner_prestage_v2(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    verified_request: &VerifiedPrivateOramOwnerPrestageRequestV2,
    package_canonical_json: &[u8],
) -> StorageResult<PrivateOramOwnerPrestageReceiptV2> {
    let request = verified_request.request();
    let package = decode_private_oram_owner_prestage_package_v2(package_canonical_json)
        .map_err(|_| invalid_owner_prestage())?;
    let auth = Auth::new_internal(Access::full("private ORAM owner pre-stage"));
    let pass = auth.check_collection_access(
        &request.collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_prestage_v2",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    if collection_id != request.collection_id
        || package.collection_id != collection_id
        || package.owner_peer_id != request.owner_peer_id
        || package.coordinator_peer_id != request.coordinator_peer_id
        || package.owner_signing_key_id != request.owner_signing_key_id
        || package.vector_name != request.vector_name
    {
        return Err(invalid_owner_prestage());
    }
    let has_result = package
        .immutable_manifest
        .manifest
        .indexes
        .iter()
        .any(|index| index.kind() == qdrant_sec::PrivateOramIndexKindV2::Result);
    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let _result_lifecycle = if has_result {
        begin_private_result_oram_collection_lifecycle(collection.name(), &config)?
    } else {
        None
    };
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &request.vector_name,
        &request.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != collection_id {
        return Err(invalid_owner_prestage());
    }
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&package.immutable_manifest.manifest)
            .map_err(|_| invalid_owner_prestage())?;
    if manifest_digest
        != package
            .owner_prepare
            .mutation_bundle
            .mutation
            .manifest_digest
    {
        return Err(invalid_owner_prestage());
    }
    let key = PrivateOramMutationKey {
        collection_id: collection_id.clone(),
    };
    let state = consensus
        .private_oram_mutation_state(&key)
        .ok_or_else(invalid_owner_prestage)?;
    let slot = consensus
        .private_oram_mutation_lease_slot(&key)
        .ok_or_else(invalid_owner_prestage)?;
    let layout = consensus
        .private_oram_layout(&PrivateOramLayoutKey {
            collection_id: collection_id.clone(),
        })
        .ok_or_else(invalid_owner_prestage)?;
    let (reservation, _) = consensus
        .private_oram_mutation_v2_active_append_attempt(&key)?
        .ok_or_else(invalid_owner_prestage)?;
    let aggregate_digest = consensus.private_oram_mutation_v2_current_aggregate_digest(&key)?;
    let target = reservation
        .owner_targets()
        .iter()
        .find(|target| target.owner_peer_id() == request.owner_peer_id)
        .ok_or_else(invalid_owner_prestage)?;
    if reservation.expected_aggregate_digest() != request.expected_aggregate_digest
        || reservation.expected_aggregate_digest() != package.expected_aggregate_digest
        || reservation.collection_id() != request.collection_id
        || reservation.mutation_id() != request.mutation_id
        || reservation.mutation_digest() != request.mutation_digest
        || reservation.transition_digest() != request.transition_digest
        || reservation.preparing_lease().generation != request.lease_generation
        || reservation.preparing_lease().writer_fence != request.writer_fence
        || reservation.parent_descriptor_digest() != request.parent_descriptor_digest
        || reservation.parent_lease_acquired_record_digest()
            != request.parent_lease_acquired_record_digest
        || reservation.owner_roster_digest() != request.owner_roster_digest
        || reservation.activation_authority().registry_generation()
            != request.activation_registry_generation
        || reservation.activation_authority().manifest_digest()
            != request.activation_manifest_digest
        || target.intent_key() != request.intent_key
        || target.package_sha256() != request.package_sha256
        || target.package_len() != request.package_len
        || slot.active.is_some()
        || slot.generation.checked_add(1) != Some(request.lease_generation)
        || slot.max_writer_fence.checked_add(1) != Some(request.writer_fence)
        || request.lease_generation != request.writer_fence
        || layout.owner_peer_ids != package.owner_peer_ids
        || !layout.owner_peer_ids.contains(&request.owner_peer_id)
        || !layout.owner_peer_ids.contains(&request.coordinator_peer_id)
        || layout.generation != state.layout_generation
        || layout.layout_digest != state.layout_digest
        || state.manifest_digest != manifest_digest
    {
        return Err(invalid_owner_prestage());
    }
    let hnsw_store = PrivateHnswOramStore::new(collection.path(), &request.vector_name)?;
    let hnsw_current = hnsw_store.read_current_epoch()?;
    let old_hnsw = package
        .owner_prepare
        .mutation_bundle
        .mutation
        .old_state
        .state
        .indexes
        .iter()
        .find(|index| index.kind == qdrant_sec::PrivateOramIndexKindV2::Hnsw)
        .ok_or_else(invalid_owner_prestage)?;
    if hnsw_current.index_epoch != old_hnsw.index_epoch
        || hnsw_current.root_hash != old_hnsw.root_hash
    {
        return Err(invalid_owner_prestage());
    }
    if has_result {
        let result_context = resolve_private_result_oram_context_from_snapshot(
            settings,
            collection.name(),
            collection.path(),
            &config,
            &request.owner_signing_key_id,
        )?;
        if result_context.collection_crypto_id() != collection_id
            || result_context.public_key() != hnsw_context.public_key()
        {
            return Err(invalid_owner_prestage());
        }
        let result_current = PrivateResultOramStore::new(collection.path()).read_current_epoch()?;
        let old_result = package
            .owner_prepare
            .mutation_bundle
            .mutation
            .old_state
            .state
            .indexes
            .iter()
            .find(|index| index.kind == qdrant_sec::PrivateOramIndexKindV2::Result)
            .ok_or_else(invalid_owner_prestage)?;
        if result_current.index_epoch != old_result.index_epoch
            || result_current.root_hash != old_result.root_hash
        {
            return Err(invalid_owner_prestage());
        }
    }
    let staged_frame = decode_prestage_frame(&package)?;
    let point_id = staged_frame
        .as_ref()
        .map(|frame| private_oram_staged_point_id_canonical_string(&frame.point.id))
        .transpose()
        .map_err(|_| invalid_owner_prestage())?;
    let staged_digest = staged_frame
        .as_ref()
        .map(private_oram_staged_insert_frame_v1_digest)
        .transpose()
        .map_err(|_| invalid_owner_prestage())?;
    let expected_visible_point_record = match package.immutable_manifest.manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => Some(PrivateOramVisiblePointRecordV1 {
            point_id: point_id.as_deref().ok_or_else(invalid_owner_prestage)?,
            staged_insert_sha256: staged_digest
                .as_deref()
                .ok_or_else(invalid_owner_prestage)?,
        }),
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if staged_frame.is_some() {
                return Err(invalid_owner_prestage());
            }
            None
        }
    };
    let old_state_digest = private_oram_signed_state_v2_digest(
        &package
            .owner_prepare
            .mutation_bundle
            .mutation
            .old_state
            .state,
    )
    .map_err(|_| invalid_owner_prestage())?;
    let validated_prepare = validate_private_oram_append_owner_prepare_from_verified_prestage_v2(
        &package.immutable_manifest,
        &package.owner_prepare,
        &package.durable_read_observations,
        verified_request,
        PrivateOramAppendOwnerPrestageValidationContextV2 {
            expected_collection_id: &collection_id,
            expected_manifest_digest: &manifest_digest,
            expected_owner_signing_key_id: &request.owner_signing_key_id,
            expected_layout_generation: layout.generation,
            expected_layout_digest: &layout.layout_digest,
            expected_writer_lease_digest: &package
                .owner_prepare
                .mutation_bundle
                .mutation
                .writer_lease_digest,
            expected_writer_fence: request.writer_fence,
            expected_state_sequence: state.state_sequence,
            expected_old_state_digest: &old_state_digest,
            expected_visible_point_record,
            now_unix: current_unix_secs()?,
            max_mutation_ttl_secs: PRIVATE_ORAM_MUTATION_SESSION_LEASE_SECS,
            public_key: hnsw_context.public_key(),
        },
    )
    .map_err(|_| invalid_owner_prestage())?;
    let admission = derive_private_oram_mutation_admission_plan_v2(
        request.coordinator_peer_id,
        request.lease_generation,
        request.writer_fence,
        &slot,
        &state,
        &validated_prepare,
    )
    .map_err(|_| invalid_owner_prestage())?;
    if admission.lease().transition_digest != request.transition_digest
        || admission.lease().base_record_digest != package.base_record_digest
    {
        return Err(invalid_owner_prestage());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        request.owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_prestage())?;
    let planned = journal
        .plan_admitted_parent_v2(
            request.coordinator_peer_id,
            &layout.owner_peer_ids,
            &package.immutable_manifest,
            &validated_prepare,
            &admission,
        )
        .map_err(|_| invalid_owner_prestage())?;
    if planned.descriptor_digest() != request.parent_descriptor_digest
        || planned.lease_acquired_record_digest() != request.parent_lease_acquired_record_digest
    {
        return Err(invalid_owner_prestage());
    }
    let plan = planned
        .owner_prestage_plan(request.owner_peer_id)
        .map_err(|_| invalid_owner_prestage())?;
    let owner_store = PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path());
    let receipt = if consensus.private_oram_mutation_v3_write_floor_active()? {
        owner_store.install_v3_reserved(
            verified_request,
            &package,
            package_canonical_json,
            &validated_prepare,
            &plan,
        )
    } else {
        owner_store.install_v2(
            verified_request,
            &package,
            package_canonical_json,
            &validated_prepare,
            &plan,
        )
    }
    .map_err(|_| invalid_owner_prestage_storage())?;
    if collection.config_snapshot().await != config
        || consensus.private_oram_mutation_state(&key).as_ref() != Some(&state)
        || consensus.private_oram_mutation_lease_slot(&key).as_ref() != Some(&slot)
        || consensus
            .private_oram_layout(&PrivateOramLayoutKey {
                collection_id: collection_id.clone(),
            })
            .as_ref()
            != Some(&layout)
        || consensus.private_oram_mutation_v2_current_aggregate_digest(&key)? != aggregate_digest
    {
        return Err(invalid_owner_prestage());
    }
    Ok(receipt)
}

pub(crate) async fn adopt_private_oram_mutation_owner_v2(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    verified_request: &VerifiedPrivateOramOwnerAdoptionRequestV1,
    parent: &PrivateOramOwnerPrepareParentV2,
) -> StorageResult<PrivateOramOwnerPreparedEvidenceV2> {
    let request = verified_request.request();
    let auth = Auth::new_internal(Access::full("private ORAM owner adoption"));
    let pass = auth.check_collection_access(
        &request.collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_adoption_v2",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != request.collection_id
        || parent.owner_peer_id() != request.owner_peer_id
        || parent.parent_descriptor_digest() != request.parent_descriptor_digest
        || parent.parent_lease_acquired_record_digest()
            != request.parent_lease_acquired_record_digest
    {
        return Err(invalid_owner_prestage());
    }

    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &request.vector_name,
        &request.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != request.collection_id {
        return Err(invalid_owner_prestage());
    }
    let key = PrivateOramMutationKey {
        collection_id: request.collection_id.clone(),
    };
    let lease = consensus
        .private_oram_mutation_lease(&key)
        .ok_or_else(invalid_owner_prestage)?;
    if lease.collection_id != request.collection_id
        || lease.mutation_id != request.mutation_id
        || lease.signed_mutation_digest != request.mutation_digest
        || lease.transition_digest != request.transition_digest
        || lease.generation != request.lease_generation
        || lease.writer_fence != request.writer_fence
        || lease.owner_peer_id != request.coordinator_peer_id
    {
        return Err(invalid_owner_prestage());
    }
    let retained_manifest = consensus
        .private_oram_mutation_v2_exact_admitted_recovery_manifest(&key, &lease)?
        .ok_or_else(invalid_owner_prestage)?;
    let receipt = retained_manifest
        .owner_receipt(request.owner_peer_id)
        .ok_or_else(invalid_owner_prestage)?;
    if retained_manifest.parent_descriptor_digest() != request.parent_descriptor_digest
        || retained_manifest.parent_lease_acquired_record_digest()
            != request.parent_lease_acquired_record_digest
        || receipt.intent_key() != request.intent_key
        || receipt.package_sha256() != request.package_sha256
        || receipt.mutation_id() != request.mutation_id
        || receipt.mutation_digest() != request.mutation_digest
        || receipt.lease_generation() != request.lease_generation
        || receipt.writer_fence() != request.writer_fence
    {
        return Err(invalid_owner_prestage());
    }

    let hnsw_store = PrivateHnswOramStore::new(collection.path(), &request.vector_name)?;
    let evidence = PrivateOramOwnerPrestageStoreV2::new(hnsw_store.root_path())
        .adopt_for_parent_v2(&request.intent_key, &request.package_sha256, parent)
        .map_err(|_| invalid_owner_prestage_storage())?;
    if evidence.owner_peer_id() != request.owner_peer_id
        || evidence.parent_descriptor_digest() != request.parent_descriptor_digest
        || evidence.parent_lease_acquired_record_digest()
            != request.parent_lease_acquired_record_digest
        || evidence.journal_descriptor_digest() != receipt.owner_journal_descriptor_digest()
        || collection.config_snapshot().await != config
        || consensus
            .private_oram_mutation_v2_exact_admitted_recovery_manifest(&key, &lease)?
            .as_ref()
            != Some(&retained_manifest)
    {
        return Err(invalid_owner_prestage());
    }
    Ok(evidence)
}

fn decode_prestage_frame(
    package: &PrivateOramOwnerPrestagePackageV2,
) -> StorageResult<Option<qdrant_sec::PrivateOramStagedInsertFrameV1>> {
    let Some(encoded) = package.staged_insert_frame_b64.as_deref() else {
        return Ok(None);
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| invalid_owner_prestage())?;
    if bytes.is_empty() || bytes.len() > qdrant_sec::PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES {
        return Err(invalid_owner_prestage());
    }
    decode_private_oram_staged_insert_frame_v1(&bytes)
        .map(Some)
        .map_err(|_| invalid_owner_prestage())
}

/// Installs the canonical sequence-3 recovery capsule on every owner and commits only
/// owner-signed, authority-pinned evidence to Raft.
pub(crate) async fn coordinate_private_oram_recovery_readiness_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
) -> StorageResult<()> {
    let consensus = dispatcher.consensus_state().ok_or_else(|| {
        StorageError::service_error(
            "private ORAM mutation recovery readiness requires distributed mode",
        )
    })?;
    let coordinator_peer_id = dispatcher.this_peer_id();
    if identity.peer_id() != coordinator_peer_id {
        return Err(invalid_recovery_readiness());
    }

    let auth = Auth::new_internal(Access::full("private ORAM mutation recovery readiness"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_recovery_readiness_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        vector_name,
        owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != collection_id {
        return Err(invalid_recovery_readiness());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id,
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_recovery_readiness())?;
    let key = PrivateOramMutationKey {
        collection_id: collection_id.clone(),
    };
    let linearizable = consensus
        .linearizable_private_oram_mutation_reconcile_snapshot_v2(
            &key,
            coordinator_peer_id,
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await?;
    let applied_parent_sequence = linearizable.active_parent_watermark_sequence().unwrap_or(0);
    let pending_parent_progress = journal
        .point_stage_parent_progress_proposals_v2()
        .map_err(|_| invalid_recovery_readiness())?;
    let applied_parent_count =
        usize::try_from(applied_parent_sequence).map_err(|_| invalid_recovery_readiness())?;
    if applied_parent_count > pending_parent_progress.len() {
        return Err(invalid_recovery_readiness());
    }
    for progress in pending_parent_progress
        .into_iter()
        .skip(applied_parent_count)
    {
        dispatcher
            .submit_private_oram_mutation_parent_progress_v2(
                progress,
                Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
            )
            .await?;
    }
    let layout = dispatcher
        .private_oram_consensus_layout(&PrivateOramLayoutKey {
            collection_id: collection_id.clone(),
        })?
        .ok_or_else(invalid_recovery_readiness)?;
    if layout.owner_peer_ids.is_empty()
        || !layout.owner_peer_ids.contains(&coordinator_peer_id)
        || layout
            .owner_peer_ids
            .windows(2)
            .any(|owners| owners[0] >= owners[1])
    {
        return Err(invalid_recovery_readiness());
    }

    let coordinator_pin = consensus.private_oram_peer_recovery_signer_pin(coordinator_peer_id)?;
    if coordinator_pin.signer() != identity.public_key() {
        return Err(invalid_recovery_readiness());
    }
    let activation = coordinator_pin.activation_authority();
    let mut owner_evidence = Vec::with_capacity(layout.owner_peer_ids.len());
    for owner_peer_id in &layout.owner_peer_ids {
        let package = journal
            .owner_recovery_capsule_package_v2(*owner_peer_id, activation.clone())
            .map_err(|_| invalid_recovery_readiness())?;
        validate_package_context(
            &package,
            collection_name,
            &collection_id,
            vector_name,
            owner_signing_key_id,
            coordinator_peer_id,
            *owner_peer_id,
        )?;
        let package_canonical_json =
            encode_private_oram_owner_recovery_capsule_package_v2(&package)
                .map_err(|_| invalid_recovery_readiness())?;
        let evidence = if *owner_peer_id == coordinator_peer_id {
            install_local_owner_capsule(
                toc,
                settings,
                consensus,
                identity,
                collection_name,
                &package,
                &package_canonical_json,
                &coordinator_pin,
            )
            .await?
        } else {
            install_remote_owner_capsule(
                dispatcher,
                identity,
                collection_name,
                &package,
                package_canonical_json,
                *owner_peer_id,
                &activation,
            )
            .await?
        };
        owner_evidence.push(evidence);
    }

    repin_all_owners(
        consensus,
        identity,
        coordinator_peer_id,
        &layout.owner_peer_ids,
        &coordinator_pin,
    )?;
    if collection.config_snapshot().await != config {
        return Err(invalid_recovery_readiness());
    }
    let proposal = journal
        .recovery_readiness_proposal_v2(activation, owner_evidence)
        .map_err(|_| invalid_recovery_readiness())?;
    if dispatcher
        .private_oram_consensus_mutation_state(&PrivateOramMutationKey {
            collection_id: collection_id.clone(),
        })?
        .is_none()
    {
        return Err(invalid_recovery_readiness());
    }
    dispatcher
        .submit_private_oram_mutation_recovery_readiness_v2(
            proposal,
            Some(PRIVATE_ORAM_RECOVERY_READINESS_WAIT),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
fn validate_package_context(
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
    collection_name: &str,
    collection_id: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
    coordinator_peer_id: PeerId,
    owner_peer_id: PeerId,
) -> StorageResult<()> {
    if collection_name.is_empty()
        || package.collection_id() != collection_id
        || package.coordinator_peer_id() != coordinator_peer_id
        || package.owner_peer_id() != owner_peer_id
        || package.owner_signing_key_id() != owner_signing_key_id
        || package
            .hnsw_vector_name()
            .map_err(|_| invalid_recovery_readiness())?
            != vector_name
    {
        return Err(invalid_recovery_readiness());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn install_local_owner_capsule(
    toc: &storage::content_manager::toc::TableOfContent,
    settings: &Settings,
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
    package_canonical_json: &[u8],
    expected_pin: &PrivateOramPeerRecoverySignerPin,
) -> StorageResult<PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2> {
    let receipt = do_install_local_private_oram_owner_recovery_capsule_v2(
        toc,
        settings,
        consensus,
        collection_name,
        identity.peer_id(),
        package_canonical_json,
    )
    .await?;
    let receipt_canonical_json =
        encode_private_oram_owner_recovery_capsule_install_receipt_v2(&receipt)
            .map_err(|_| invalid_recovery_readiness())?;
    let statement = local_install_attestation_statement(package, &receipt, &receipt_canonical_json);
    let attestation = identity
        .sign_owner_capsule_install_attestation(&statement)
        .map_err(|_| invalid_recovery_readiness())?;
    let _verified = validate_private_oram_owner_capsule_install_attestation_for_signer_v2(
        &attestation,
        expected_pin.signer(),
    )
    .map_err(|_| invalid_recovery_readiness())?;
    let current_pin = consensus.private_oram_peer_recovery_signer_pin(identity.peer_id())?;
    if &current_pin != expected_pin {
        return Err(invalid_recovery_readiness());
    }
    PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2::from_signed_attestation(receipt, attestation)
        .map_err(|_| invalid_recovery_readiness())
}

async fn install_remote_owner_capsule(
    dispatcher: &Dispatcher,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
    package_canonical_json: Vec<u8>,
    owner_peer_id: PeerId,
    activation: &storage::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1,
) -> StorageResult<PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2> {
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_recovery_readiness)?;
    let pins =
        consensus.private_oram_peer_recovery_signer_pair_pin(owner_peer_id, identity.peer_id())?;
    validate_pair_pin(&pins, identity, activation)?;
    let request = PrivateOramOwnerCapsuleInstallRequestV2 {
        protocol_version: PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
        challenge_nonce: new_private_oram_owner_capsule_install_challenge_nonce_v2()
            .map_err(|_| invalid_recovery_readiness())?,
        collection_name: collection_name.to_string(),
        collection_id: package.collection_id().to_string(),
        mutation_id: package.mutation_id().to_string(),
        parent_descriptor_digest: package.parent_descriptor_digest().to_string(),
        coordinator_peer_id: identity.peer_id(),
        owner_peer_id,
        vector_name: package
            .hnsw_vector_name()
            .map_err(|_| invalid_recovery_readiness())?
            .to_string(),
        owner_signing_key_id: package.owner_signing_key_id().to_string(),
        activation_registry_generation: activation.registry_generation(),
        activation_manifest_digest: activation.manifest_digest().to_string(),
        capsule_digest: package.capsule_digest().to_string(),
        capsule_set_digest: package.capsule_set_digest().to_string(),
        package_sha256: private_oram_owner_capsule_canonical_sha256_v2(&package_canonical_json),
        package_len: u64::try_from(package_canonical_json.len())
            .map_err(|_| invalid_recovery_readiness())?,
    };
    let coordinator_signature = identity
        .sign_owner_capsule_install_request(&request)
        .map_err(|_| invalid_recovery_readiness())?;
    let response = dispatcher
        .toc(
            &Auth::new_internal(Access::full("private ORAM owner capsule distribution")),
            &new_unchecked_verification_pass(),
        )
        .get_channel_service()
        .install_private_oram_owner_recovery_capsule_v2(
            owner_peer_id,
            request,
            package_canonical_json,
            identity.public_key().clone(),
            coordinator_signature,
            pins.coordinator().signer(),
            pins.owner().signer(),
        )
        .await?;
    let current_pins =
        consensus.private_oram_peer_recovery_signer_pair_pin(owner_peer_id, identity.peer_id())?;
    if current_pins != pins {
        return Err(invalid_recovery_readiness());
    }
    let receipt = decode_private_oram_owner_recovery_capsule_install_receipt_v2(
        response.receipt_canonical_json(),
    )
    .map_err(|_| invalid_recovery_readiness())?;
    PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2::from_signed_attestation(
        receipt,
        response.owner_install_attestation().attestation().clone(),
    )
    .map_err(|_| invalid_recovery_readiness())
}

fn local_install_attestation_statement(
    package: &PrivateOramOwnerRecoveryCapsulePackageV2,
    receipt: &PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
    receipt_canonical_json: &[u8],
) -> PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
    PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
        protocol_version: PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
        collection_id: package.collection_id().to_string(),
        mutation_id: package.mutation_id().to_string(),
        parent_descriptor_digest: package.parent_descriptor_digest().to_string(),
        owner_peer_id: package.owner_peer_id(),
        activation_registry_generation: package.activation_authority().registry_generation(),
        activation_manifest_digest: package.activation_authority().manifest_digest().to_string(),
        capsule_digest: package.capsule_digest().to_string(),
        capsule_set_digest: package.capsule_set_digest().to_string(),
        receipt_digest: receipt.receipt_digest().to_string(),
        receipt_canonical_sha256: private_oram_owner_capsule_canonical_sha256_v2(
            receipt_canonical_json,
        ),
    }
}

fn validate_pair_pin(
    pins: &PrivateOramPeerRecoverySignerPairPin,
    identity: &PrivateOramPeerRecoveryIdentity,
    activation: &storage::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1,
) -> StorageResult<()> {
    if pins.coordinator().signer() != identity.public_key()
        || pins.coordinator().activation_authority() != *activation
        || pins.owner().activation_authority() != *activation
    {
        return Err(invalid_recovery_readiness());
    }
    Ok(())
}

fn repin_all_owners(
    consensus: &storage::content_manager::consensus_manager::ConsensusStateRef,
    identity: &PrivateOramPeerRecoveryIdentity,
    coordinator_peer_id: PeerId,
    owner_peer_ids: &[PeerId],
    coordinator_pin: &PrivateOramPeerRecoverySignerPin,
) -> StorageResult<()> {
    for owner_peer_id in owner_peer_ids {
        if *owner_peer_id == coordinator_peer_id {
            if consensus.private_oram_peer_recovery_signer_pin(*owner_peer_id)? != *coordinator_pin
            {
                return Err(invalid_recovery_readiness());
            }
        } else {
            let pins = consensus
                .private_oram_peer_recovery_signer_pair_pin(*owner_peer_id, coordinator_peer_id)?;
            validate_pair_pin(&pins, identity, &coordinator_pin.activation_authority())?;
        }
    }
    Ok(())
}

fn invalid_recovery_readiness() -> StorageError {
    StorageError::bad_request("private ORAM mutation recovery readiness is invalid")
}

fn invalid_owner_prestage() -> StorageError {
    StorageError::bad_request("private ORAM owner pre-stage request is invalid")
}

fn invalid_owner_prestage_storage() -> StorageError {
    StorageError::service_error("private ORAM owner pre-stage storage failed")
}
