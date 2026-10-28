use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use api::grpc::private_oram_chunking::encode_private_oram_install_chunks;
use api::grpc::qdrant::qdrant_internal_client::QdrantInternalClient;
use api::grpc::qdrant::{
    AdoptPrivateOramMutationOwnerV2Request, CompletePrivateOramWritebackRequest,
    DescribePrivateOramMutationOwnerStoreV2Request, InstallPrivateOramIndexRequest,
    InstallPrivateOramIndexResponse, InstallPrivateOramLiveReplicaRequest,
    InstallPrivateOramLiveReplicaResponse, InstallPrivateOramOwnerRecoveryCapsuleV2Request,
    PreparePrivateOramMutationOwnerReservationV3Request, PreparePrivateOramWritebackRequest,
    PrestagePrivateOramMutationOwnerV2Request, PrestagePrivateOramMutationOwnerV2Response,
    RecoverPrivateOramMutationOwnerRequest, RequestPrivateOramReshardingResumeRequest,
    RequestPrivateOramReshardingResumeResponse, RequestPrivateOramShardRecoveryRequest,
    RequestPrivateOramShardRecoveryResponse, ResolvePrivateOramMutationOwnerReservationV3Request,
    SignPrivateOramMutationOwnerEnrollmentV2Request, WaitOnConsensusCommitRequest,
};
use api::grpc::transport_channel_pool::{AddTimeout, DEFAULT_RETRIES, TransportChannelPool};
use futures::future::try_join_all;
use futures::{Future, stream};
use qdrant_sec::{
    PRIVATE_ORAM_OWNER_CAPSULE_ATTESTATION_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2,
    PRIVATE_ORAM_OWNER_PRESTAGE_RECEIPT_MAX_CANONICAL_BYTES_V2, PrivateOramOwnerAdoptionRequestV1,
    PrivateOramOwnerAdoptionResponseV1, PrivateOramOwnerCapsuleInstallRequestV2,
    PrivateOramOwnerCapsuleInstallResponseV2, PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramOwnerLifecycleStateV1,
    PrivateOramOwnerPrestageRequestV2, PrivateOramOwnerPrestageResponseV2,
    PrivateOramOwnerReservationPrepareChallengeV1, PrivateOramOwnerReservationPrepareV1,
    PrivateOramOwnerReservationResolutionDispositionV1, PrivateOramPeerRecoveryPublicKeyV1,
    PrivateOramPeerRecoveryRequestV2, PrivateOramPeerRecoverySignatureV2,
    PrivateOramPeerRecoveryTerminalV2, SignedPrivateOramOwnerReservationResolutionReceiptV1,
    VerifiedPrivateOramOwnerCapsuleInstallAttestationV2,
    VerifiedPrivateOramOwnerCapsuleInstallResponseV2,
    VerifiedPrivateOramOwnerPrestageAttestationV2, VerifiedPrivateOramOwnerPrestageResponseV2,
    VerifiedPrivateOramOwnerReservationPrepareV1, VerifiedPrivateOramPeerRecoveryResponseV2,
    decode_private_oram_owner_capsule_install_attestation_v2,
    decode_private_oram_owner_enrollment_genesis_commitment_v1,
    decode_private_oram_owner_prestage_attestation_v2,
    decode_private_oram_owner_reservation_prepare_v1,
    decode_signed_private_oram_owner_reservation_resolution_receipt_v1,
    private_oram_owner_cleanup_signer_from_peer_key_v1,
    validate_private_oram_owner_adoption_request_signature_v1,
    validate_private_oram_owner_adoption_response_signature_v1,
    validate_private_oram_owner_capsule_install_attestation_for_signer_v2,
    validate_private_oram_owner_capsule_install_request_signature_v2,
    validate_private_oram_owner_capsule_install_response_signature_v2,
    validate_private_oram_owner_prestage_attestation_for_signer_v2,
    validate_private_oram_owner_prestage_request_signature_v2,
    validate_private_oram_owner_prestage_response_signature_v2,
    validate_private_oram_owner_reservation_prepare_challenge_v1,
    validate_private_oram_owner_reservation_prepare_v1,
    validate_private_oram_peer_recovery_request_signature_v2,
    validate_private_oram_peer_recovery_request_v2_shape,
    validate_private_oram_peer_recovery_response_signature_v2,
    validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1,
};
use semver::Version;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tonic::codegen::InterceptedService;
use tonic::transport::{Channel, Uri};
use tonic::{Request, Status};
use url::Url;

use crate::operations::types::{CollectionError, CollectionResult, PeerMetadata};
use crate::shards::shard::PeerId;
use crate::{
    PrivateOramOwnerPrepareParentV2, PrivateOramOwnerPreparedEvidenceV2,
    PrivateOramOwnerPrestageReceiptV2, decode_private_oram_owner_prepared_evidence_v2,
    decode_private_oram_owner_prestage_receipt_v2, encode_private_oram_owner_prepare_parent_v2,
};

// Full-store validation and fsync can outlive the normal peer RPC deadline.
const PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const PRIVATE_ORAM_INSTALL_RETRIES: usize = 1;
const PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES: usize = 64 * 1024;
const PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1: usize = 128 * 1024;
const PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_RESPONSE_BYTES_V1: usize =
    PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1 * 2;
const PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1: usize = 255;
const PRIVATE_ORAM_OWNER_RESERVATION_SIGNING_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Signature-verified owner capsule receipt fetched from the URI pinned to a peer.
pub struct PrivateOramAuthenticatedOwnerCapsuleInstallResponseV2 {
    peer_id: PeerId,
    verified: VerifiedPrivateOramOwnerCapsuleInstallResponseV2,
    owner_install_attestation: VerifiedPrivateOramOwnerCapsuleInstallAttestationV2,
    receipt_canonical_json: Vec<u8>,
}

/// Signature-verified durable owner pre-stage evidence fetched from a URI-pinned peer.
pub struct PrivateOramAuthenticatedOwnerPrestageResponseV2 {
    peer_id: PeerId,
    verified: VerifiedPrivateOramOwnerPrestageResponseV2,
    owner_attestation: VerifiedPrivateOramOwnerPrestageAttestationV2,
    receipt: PrivateOramOwnerPrestageReceiptV2,
    receipt_canonical_json: Vec<u8>,
    reservation_resolution_receipt: SignedPrivateOramOwnerReservationResolutionReceiptV1,
}

/// Signature- and context-verified durable owner adoption evidence from a URI-pinned peer.
pub struct PrivateOramAuthenticatedOwnerAdoptionV2 {
    peer_id: PeerId,
    evidence: PrivateOramOwnerPreparedEvidenceV2,
}

impl PrivateOramAuthenticatedOwnerAdoptionV2 {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn into_evidence(self) -> PrivateOramOwnerPreparedEvidenceV2 {
        self.evidence
    }
}

/// Signature- and context-verified V3 reservation fence prepared by the URI-pinned owner.
pub struct PrivateOramAuthenticatedOwnerReservationPrepareV3 {
    peer_id: PeerId,
    verified: VerifiedPrivateOramOwnerReservationPrepareV1,
}

impl std::fmt::Debug for PrivateOramAuthenticatedOwnerReservationPrepareV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateOramAuthenticatedOwnerReservationPrepareV3")
            .field("peer_id", &self.peer_id)
            .field("verified", &"[redacted]")
            .finish()
    }
}

impl PrivateOramAuthenticatedOwnerReservationPrepareV3 {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn verified(&self) -> &VerifiedPrivateOramOwnerReservationPrepareV1 {
        &self.verified
    }

    pub fn into_verified(self) -> VerifiedPrivateOramOwnerReservationPrepareV1 {
        self.verified
    }
}

impl std::fmt::Debug for PrivateOramAuthenticatedOwnerPrestageResponseV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateOramAuthenticatedOwnerPrestageResponseV2")
            .field("peer_id", &self.peer_id)
            .field("verified", &"[redacted]")
            .field("owner_attestation", &"[redacted]")
            .field("receipt", &"[redacted]")
            .field("reservation_resolution_receipt", &"[redacted]")
            .finish()
    }
}

impl PrivateOramAuthenticatedOwnerPrestageResponseV2 {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn receipt(&self) -> &PrivateOramOwnerPrestageReceiptV2 {
        &self.receipt
    }

    pub fn receipt_canonical_json(&self) -> &[u8] {
        &self.receipt_canonical_json
    }

    pub fn owner_attestation(&self) -> &VerifiedPrivateOramOwnerPrestageAttestationV2 {
        &self.owner_attestation
    }

    pub fn reservation_resolution_receipt(
        &self,
    ) -> &SignedPrivateOramOwnerReservationResolutionReceiptV1 {
        &self.reservation_resolution_receipt
    }

    pub fn verified(&self) -> &VerifiedPrivateOramOwnerPrestageResponseV2 {
        &self.verified
    }
}

impl std::fmt::Debug for PrivateOramAuthenticatedOwnerCapsuleInstallResponseV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateOramAuthenticatedOwnerCapsuleInstallResponseV2")
            .field("peer_id", &self.peer_id)
            .field("verified", &"[redacted]")
            .field("owner_install_attestation", &"[redacted]")
            .field("receipt_canonical_json", &"[redacted]")
            .finish()
    }
}

impl PrivateOramAuthenticatedOwnerCapsuleInstallResponseV2 {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn verified(&self) -> &VerifiedPrivateOramOwnerCapsuleInstallResponseV2 {
        &self.verified
    }

    pub fn receipt_canonical_json(&self) -> &[u8] {
        &self.receipt_canonical_json
    }

    pub fn owner_install_attestation(
        &self,
    ) -> &VerifiedPrivateOramOwnerCapsuleInstallAttestationV2 {
        &self.owner_install_attestation
    }
}

/// Signature-verified owner-recovery evidence fetched from the URI pinned to a peer.
pub struct PrivateOramAuthenticatedOwnerRecoveryResponse {
    peer_id: PeerId,
    verified: VerifiedPrivateOramPeerRecoveryResponseV2,
}

impl std::fmt::Debug for PrivateOramAuthenticatedOwnerRecoveryResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateOramAuthenticatedOwnerRecoveryResponse")
            .field("peer_id", &self.peer_id)
            .field("verified", &"[redacted]")
            .finish()
    }
}

impl PrivateOramAuthenticatedOwnerRecoveryResponse {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn verified(&self) -> &VerifiedPrivateOramPeerRecoveryResponseV2 {
        &self.verified
    }
}

fn decode_canonical_private_oram_recovery_json<T>(encoded: &[u8]) -> CollectionResult<T>
where
    T: DeserializeOwned + Serialize,
{
    if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES {
        return Err(CollectionError::service_error(
            "private ORAM owner recovery response is invalid",
        ));
    }
    let decoded = serde_json::from_slice(encoded).map_err(|_| {
        CollectionError::service_error("private ORAM owner recovery response is invalid")
    })?;
    if serde_json::to_vec(&decoded).map_err(|_| {
        CollectionError::service_error("private ORAM owner recovery response is invalid")
    })? != encoded
    {
        return Err(CollectionError::service_error(
            "private ORAM owner recovery response is invalid",
        ));
    }
    Ok(decoded)
}

fn validate_owner_prestage_response_bounds(
    peer_id: PeerId,
    response: &PrestagePrivateOramMutationOwnerV2Response,
) -> CollectionResult<()> {
    let total = response
        .receipt_canonical_json
        .len()
        .checked_add(response.prestage_response_canonical_json.len())
        .and_then(|length| length.checked_add(response.owner_public_key_canonical_json.len()))
        .and_then(|length| length.checked_add(response.owner_signature_canonical_json.len()))
        .and_then(|length| {
            length.checked_add(response.owner_prestage_attestation_canonical_json.len())
        })
        .and_then(|length| {
            length.checked_add(response.reservation_resolution_receipt_canonical_json.len())
        })
        .ok_or_else(|| {
            CollectionError::service_error("private ORAM owner pre-stage response is invalid")
        })?;
    if response.receipt_canonical_json.is_empty()
        || response.receipt_canonical_json.len()
            > PRIVATE_ORAM_OWNER_PRESTAGE_RECEIPT_MAX_CANONICAL_BYTES_V2
        || response
            .owner_prestage_attestation_canonical_json
            .is_empty()
        || response.owner_prestage_attestation_canonical_json.len()
            > PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_MAX_CANONICAL_BYTES_V2
        || response
            .reservation_resolution_receipt_canonical_json
            .is_empty()
        || response.reservation_resolution_receipt_canonical_json.len()
            > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1
        || total > PRIVATE_ORAM_OWNER_PRESTAGE_RECEIPT_MAX_CANONICAL_BYTES_V2 * 7
    {
        return Err(CollectionError::service_error(format!(
            "private ORAM owner pre-stage response is oversized on peer {peer_id}"
        )));
    }
    Ok(())
}

#[derive(Clone)]
pub struct ChannelService {
    // Shared with consensus_state
    pub id_to_address: Arc<parking_lot::RwLock<HashMap<PeerId, Uri>>>,
    // Shared with consensus_state
    pub id_to_metadata: Arc<parking_lot::RwLock<HashMap<PeerId, PeerMetadata>>>,
    pub channel_pool: Arc<TransportChannelPool>,
    /// Port at which the public REST API is exposed for the current peer.
    pub current_rest_port: u16,
    /// Indicates whether the TLS is enabled for the public REST API.
    pub rest_tls_enabled: bool,

    /// Instance wide API key if configured, must be used with care.
    pub api_key: Option<String>,

    /// Alternative API key, works the same as `api_key`. Intended for rolling key updates.
    pub alt_api_key: Option<String>,
}

const PRIVATE_ORAM_OWNER_ENROLLMENT_MAX_RESPONSE_BYTES_V2: usize = 64 * 1024;

fn validate_private_oram_owner_enrollment_names_v2(
    collection_name: &str,
    vector_name: &str,
    owner_signing_key_id: &str,
) -> CollectionResult<()> {
    if collection_name.is_empty()
        || collection_name.len() > PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1
        || vector_name.is_empty()
        || vector_name.len() > PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1
        || owner_signing_key_id.is_empty()
        || owner_signing_key_id.len() > PRIVATE_ORAM_OWNER_RESERVATION_SIGNING_KEY_ID_MAX_BYTES_V1
    {
        return Err(CollectionError::service_error(
            "private ORAM owner enrollment request is invalid",
        ));
    }
    Ok(())
}

impl ChannelService {
    /// Construct a new channel service with the given REST port.
    pub fn new(
        current_rest_port: u16,
        rest_tls_enabled: bool,
        api_key: Option<String>,
        alt_api_key: Option<String>,
    ) -> Self {
        Self {
            id_to_address: Default::default(),
            id_to_metadata: Default::default(),
            channel_pool: Default::default(),
            current_rest_port,
            rest_tls_enabled,
            api_key,
            alt_api_key,
        }
    }

    pub async fn remove_peer(&self, peer_id: PeerId) {
        let removed = self.id_to_address.write().remove(&peer_id);
        if let Some(uri) = removed {
            self.channel_pool.drop_pool(&uri).await;
        }
    }

    /// Wait until all other known peers reach the given commit
    ///
    /// # Errors
    ///
    /// This errors if:
    /// - any of the peers is not on the same term
    /// - waiting takes longer than the specified timeout
    /// - any of the peers cannot be reached
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn await_commit_on_all_peers(
        &self,
        this_peer_id: PeerId,
        commit: u64,
        term: u64,
        timeout: Duration,
    ) -> CollectionResult<()> {
        let requests = self
            .id_to_address
            .read()
            .keys()
            .filter(|id| **id != this_peer_id)
            // The collective timeout at the bottom of this function handles actually timing out.
            // Since an explicit timeout must be given here as well, it is multiplied by two to
            // give the collective timeout some space.
            .map(|peer_id| self.await_commit_on_peer(*peer_id, commit, term, timeout * 2))
            .collect::<Vec<_>>();
        let responses = try_join_all(requests);

        // Handle requests with timeout
        tokio::time::timeout(timeout, responses)
            .await
            // Timeout error
            .map_err(|_elapsed| CollectionError::Timeout {
                description: "Failed to wait for consensus commit on all peers, timed out.".into(),
            })?
            // Await consensus error
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "Failed to wait for consensus commit on peer: {err}"
                ))
            })?;
        Ok(())
    }

    /// Wait until the given peer reaches the given commit
    ///
    /// # Errors
    ///
    /// This errors if the given peer is on a different term. Also errors if the peer cannot be reached.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    async fn await_commit_on_peer(
        &self,
        peer_id: PeerId,
        commit: u64,
        term: u64,
        timeout: Duration,
    ) -> CollectionResult<()> {
        let response = self
            .with_qdrant_client(peer_id, |mut client| async move {
                let request = WaitOnConsensusCommitRequest {
                    commit: commit as i64,
                    term: term as i64,
                    timeout: timeout.as_secs() as i64,
                };
                client.wait_on_consensus_commit(Request::new(request)).await
            })
            .await
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "Failed to wait for consensus commit on peer {peer_id}: {err}"
                ))
            })?
            .into_inner();

        // Create error if wait request failed
        if !response.ok {
            return Err(CollectionError::service_error(format!(
                "Failed to wait for consensus commit on peer {peer_id}, has diverged commit/term or timed out."
            )));
        }
        Ok(())
    }

    pub async fn prepare_private_oram_writeback(
        &self,
        peer_id: PeerId,
        request: PreparePrivateOramWritebackRequest,
    ) -> CollectionResult<String> {
        self.with_qdrant_client(peer_id, |mut client| {
            let request = request.clone();
            async move {
                client
                    .prepare_private_oram_writeback(Request::new(request))
                    .await
            }
        })
        .await
        .map(|response| response.into_inner().writeback_digest)
        .map_err(|_| {
            CollectionError::service_error(format!("private ORAM prepare failed on peer {peer_id}"))
        })
    }

    pub async fn finalize_private_oram_writeback(
        &self,
        peer_id: PeerId,
        request: CompletePrivateOramWritebackRequest,
    ) -> CollectionResult<bool> {
        self.complete_private_oram_writeback(peer_id, request, false)
            .await
    }

    pub async fn abort_private_oram_writeback(
        &self,
        peer_id: PeerId,
        request: CompletePrivateOramWritebackRequest,
    ) -> CollectionResult<bool> {
        self.complete_private_oram_writeback(peer_id, request, true)
            .await
    }

    /// `request` carries the coordinator's fresh challenge nonce and `coordinator_signature`
    /// is the coordinator identity's signature over it; the owner verifies that signature
    /// against its authority pin before it starts any recovery work.
    pub async fn recover_private_oram_mutation_owner(
        &self,
        peer_id: PeerId,
        request: PrivateOramPeerRecoveryRequestV2,
        coordinator_public_key: PrivateOramPeerRecoveryPublicKeyV1,
        coordinator_signature: PrivateOramPeerRecoverySignatureV2,
        expected_signer: &PrivateOramPeerRecoveryPublicKeyV1,
    ) -> CollectionResult<PrivateOramAuthenticatedOwnerRecoveryResponse> {
        validate_private_oram_peer_recovery_request_v2_shape(&request).map_err(|_| {
            CollectionError::service_error("private ORAM owner recovery request is invalid")
        })?;
        if request.owner_peer_id != peer_id {
            return Err(CollectionError::service_error(
                "private ORAM owner recovery target does not match peer",
            ));
        }
        validate_private_oram_peer_recovery_request_signature_v2(
            &coordinator_public_key,
            &request,
            &coordinator_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner recovery request authentication failed",
            )
        })?;
        let request_canonical_json = serde_json::to_vec(&request).map_err(|_| {
            CollectionError::service_error("private ORAM owner recovery request is invalid")
        })?;
        let coordinator_public_key_canonical_json = serde_json::to_vec(&coordinator_public_key)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner recovery request is invalid")
            })?;
        let coordinator_signature_canonical_json = serde_json::to_vec(&coordinator_signature)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner recovery request is invalid")
            })?;
        if request_canonical_json.len() > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES
            || coordinator_public_key_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES
            || coordinator_signature_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES
        {
            return Err(CollectionError::service_error(
                "private ORAM owner recovery request is invalid",
            ));
        }
        let wire_request = RecoverPrivateOramMutationOwnerRequest {
            request_canonical_json,
            coordinator_public_key_canonical_json,
            coordinator_signature_canonical_json,
        };
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner recovery requires a configured TLS endpoint",
            ));
        }
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel)
                        .max_decoding_message_size(PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES);
                    let request = wire_request.clone();
                    async move {
                        client
                            .recover_private_oram_mutation_owner(Request::new(request))
                            .await
                    }
                },
                None,
                DEFAULT_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner recovery failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        let total_response_bytes = response
            .terminal_canonical_json
            .len()
            .checked_add(response.public_key_canonical_json.len())
            .and_then(|length| length.checked_add(response.signature_canonical_json.len()))
            .ok_or_else(|| {
                CollectionError::service_error("private ORAM owner recovery response is invalid")
            })?;
        if total_response_bytes > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner recovery response is oversized on peer {peer_id}"
            )));
        }
        let terminal: PrivateOramPeerRecoveryTerminalV2 =
            decode_canonical_private_oram_recovery_json(&response.terminal_canonical_json)?;
        let public_key: PrivateOramPeerRecoveryPublicKeyV1 =
            decode_canonical_private_oram_recovery_json(&response.public_key_canonical_json)?;
        let signature: PrivateOramPeerRecoverySignatureV2 =
            decode_canonical_private_oram_recovery_json(&response.signature_canonical_json)?;
        if &public_key != expected_signer {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner recovery signer mismatch on peer {peer_id}"
            )));
        }
        let verified = validate_private_oram_peer_recovery_response_signature_v2(
            &public_key,
            &request,
            &terminal,
            &signature,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner recovery signature failed on peer {peer_id}"
            ))
        })?;
        if verified.terminal().owner_peer_id != peer_id {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner recovery identity mismatch on peer {peer_id}"
            )));
        }
        if self.id_to_address.read().get(&peer_id) != Some(&address) {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner recovery peer mapping changed on peer {peer_id}"
            )));
        }
        Ok(PrivateOramAuthenticatedOwnerRecoveryResponse { peer_id, verified })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn install_private_oram_owner_recovery_capsule_v2(
        &self,
        peer_id: PeerId,
        request: PrivateOramOwnerCapsuleInstallRequestV2,
        package_canonical_json: Vec<u8>,
        coordinator_public_key: PrivateOramPeerRecoveryPublicKeyV1,
        coordinator_signature: PrivateOramPeerRecoverySignatureV2,
        expected_coordinator_signer: &PrivateOramPeerRecoveryPublicKeyV1,
        expected_owner_signer: &PrivateOramPeerRecoveryPublicKeyV1,
    ) -> CollectionResult<PrivateOramAuthenticatedOwnerCapsuleInstallResponseV2> {
        if request.owner_peer_id != peer_id
            || &coordinator_public_key != expected_coordinator_signer
            || package_canonical_json.is_empty()
            || package_canonical_json.len() > PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2
        {
            return Err(CollectionError::service_error(
                "private ORAM owner capsule install request is invalid",
            ));
        }
        let _verified_request = validate_private_oram_owner_capsule_install_request_signature_v2(
            &coordinator_public_key,
            &request,
            &package_canonical_json,
            &coordinator_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner capsule install request authentication failed",
            )
        })?;
        let install_request_canonical_json = serde_json::to_vec(&request).map_err(|_| {
            CollectionError::service_error("private ORAM owner capsule install request is invalid")
        })?;
        let coordinator_public_key_canonical_json = serde_json::to_vec(&coordinator_public_key)
            .map_err(|_| {
                CollectionError::service_error(
                    "private ORAM owner capsule install request is invalid",
                )
            })?;
        let coordinator_signature_canonical_json = serde_json::to_vec(&coordinator_signature)
            .map_err(|_| {
                CollectionError::service_error(
                    "private ORAM owner capsule install request is invalid",
                )
            })?;
        for encoded in [
            &install_request_canonical_json,
            &coordinator_public_key_canonical_json,
            &coordinator_signature_canonical_json,
        ] {
            if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES {
                return Err(CollectionError::service_error(
                    "private ORAM owner capsule install request is invalid",
                ));
            }
        }
        let wire_request = InstallPrivateOramOwnerRecoveryCapsuleV2Request {
            install_request_canonical_json,
            capsule_package_canonical_json: package_canonical_json,
            coordinator_public_key_canonical_json,
            coordinator_signature_canonical_json,
        };
        let chunks = Arc::new(
            encode_private_oram_install_chunks(&wire_request).map_err(|_| {
                CollectionError::service_error(
                    "private ORAM owner capsule install request is invalid",
                )
            })?,
        );
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner capsule install requires a configured TLS endpoint",
            ));
        }
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel).max_decoding_message_size(
                        PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2 * 5,
                    );
                    let chunks = Arc::clone(&chunks);
                    async move {
                        let chunk_count = chunks.len();
                        let chunk_stream =
                            stream::iter((0..chunk_count).map(move |index| chunks[index].clone()));
                        client
                            .install_private_oram_owner_recovery_capsule_v2(Request::new(
                                chunk_stream,
                            ))
                            .await
                    }
                },
                Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
                PRIVATE_ORAM_INSTALL_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner capsule install failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        let total_response_bytes = response
            .receipt_canonical_json
            .len()
            .checked_add(response.install_response_canonical_json.len())
            .and_then(|length| length.checked_add(response.owner_public_key_canonical_json.len()))
            .and_then(|length| length.checked_add(response.owner_signature_canonical_json.len()))
            .and_then(|length| {
                length.checked_add(response.owner_install_attestation_canonical_json.len())
            })
            .ok_or_else(|| {
                CollectionError::service_error(
                    "private ORAM owner capsule install response is invalid",
                )
            })?;
        if response.receipt_canonical_json.is_empty()
            || response.receipt_canonical_json.len()
                > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2
            || response.owner_install_attestation_canonical_json.is_empty()
            || response.owner_install_attestation_canonical_json.len()
                > PRIVATE_ORAM_OWNER_CAPSULE_ATTESTATION_MAX_CANONICAL_BYTES_V2
            || total_response_bytes > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2 * 5
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner capsule install response is oversized on peer {peer_id}"
            )));
        }
        let install_response: PrivateOramOwnerCapsuleInstallResponseV2 =
            decode_canonical_private_oram_recovery_json(&response.install_response_canonical_json)?;
        let owner_public_key: PrivateOramPeerRecoveryPublicKeyV1 =
            decode_canonical_private_oram_recovery_json(&response.owner_public_key_canonical_json)?;
        let owner_signature: PrivateOramPeerRecoverySignatureV2 =
            decode_canonical_private_oram_recovery_json(&response.owner_signature_canonical_json)?;
        if &owner_public_key != expected_owner_signer {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner capsule install signer mismatch on peer {peer_id}"
            )));
        }
        let verified = validate_private_oram_owner_capsule_install_response_signature_v2(
            &owner_public_key,
            &request,
            &install_response,
            &response.receipt_canonical_json,
            &owner_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner capsule install signature failed on peer {peer_id}"
            ))
        })?;
        let owner_install_attestation = decode_private_oram_owner_capsule_install_attestation_v2(
            &response.owner_install_attestation_canonical_json,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner capsule install attestation is invalid on peer {peer_id}"
            ))
        })?;
        let verified_attestation =
            validate_private_oram_owner_capsule_install_attestation_for_signer_v2(
                &owner_install_attestation,
                expected_owner_signer,
            )
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner capsule install attestation failed on peer {peer_id}"
                ))
            })?;
        let statement = verified_attestation.statement();
        if statement.collection_id != request.collection_id
            || statement.mutation_id != request.mutation_id
            || statement.parent_descriptor_digest != request.parent_descriptor_digest
            || statement.owner_peer_id != request.owner_peer_id
            || statement.activation_registry_generation != request.activation_registry_generation
            || statement.activation_manifest_digest != request.activation_manifest_digest
            || statement.capsule_digest != request.capsule_digest
            || statement.capsule_set_digest != request.capsule_set_digest
            || statement.receipt_digest != install_response.receipt_digest
            || statement.receipt_canonical_sha256 != install_response.receipt_sha256
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner capsule install attestation context mismatch on peer {peer_id}"
            )));
        }
        if verified.response().owner_peer_id != peer_id
            || self.id_to_address.read().get(&peer_id) != Some(&address)
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner capsule install peer authority changed on peer {peer_id}"
            )));
        }
        Ok(PrivateOramAuthenticatedOwnerCapsuleInstallResponseV2 {
            peer_id,
            verified,
            owner_install_attestation: verified_attestation,
            receipt_canonical_json: response.receipt_canonical_json,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prestage_private_oram_mutation_owner_v2(
        &self,
        peer_id: PeerId,
        request: PrivateOramOwnerPrestageRequestV2,
        package_canonical_json: Vec<u8>,
        coordinator_public_key: PrivateOramPeerRecoveryPublicKeyV1,
        coordinator_signature: PrivateOramPeerRecoverySignatureV2,
        expected_coordinator_signer: &PrivateOramPeerRecoveryPublicKeyV1,
        expected_owner_signer: &PrivateOramPeerRecoveryPublicKeyV1,
        reservation_challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    ) -> CollectionResult<PrivateOramAuthenticatedOwnerPrestageResponseV2> {
        if request.owner_peer_id != peer_id
            || request.coordinator_peer_id == request.owner_peer_id
            || &coordinator_public_key != expected_coordinator_signer
            || reservation_challenge.owner_peer_id != peer_id
            || package_canonical_json.is_empty()
            || package_canonical_json.len() > PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2
        {
            return Err(CollectionError::service_error(
                "private ORAM owner pre-stage request is invalid",
            ));
        }
        let _verified_request = validate_private_oram_owner_prestage_request_signature_v2(
            &coordinator_public_key,
            &request,
            &package_canonical_json,
            &coordinator_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner pre-stage request authentication failed",
            )
        })?;
        validate_private_oram_owner_reservation_prepare_challenge_v1(reservation_challenge)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner pre-stage request is invalid")
            })?;
        let reservation_challenge_canonical_json = serde_json::to_vec(reservation_challenge)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner pre-stage request is invalid")
            })?;
        if reservation_challenge_canonical_json.is_empty()
            || reservation_challenge_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1
        {
            return Err(CollectionError::service_error(
                "private ORAM owner pre-stage request is invalid",
            ));
        }
        let prestage_request_canonical_json = serde_json::to_vec(&request).map_err(|_| {
            CollectionError::service_error("private ORAM owner pre-stage request is invalid")
        })?;
        let coordinator_public_key_canonical_json = serde_json::to_vec(&coordinator_public_key)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner pre-stage request is invalid")
            })?;
        let coordinator_signature_canonical_json = serde_json::to_vec(&coordinator_signature)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner pre-stage request is invalid")
            })?;
        let wire_request = PrestagePrivateOramMutationOwnerV2Request {
            prestage_request_canonical_json,
            prestage_package_canonical_json: package_canonical_json,
            coordinator_public_key_canonical_json,
            coordinator_signature_canonical_json,
            reservation_challenge_canonical_json,
        };
        let chunks = Arc::new(
            encode_private_oram_install_chunks(&wire_request).map_err(|_| {
                CollectionError::service_error("private ORAM owner pre-stage request is invalid")
            })?,
        );
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner pre-stage requires a configured TLS endpoint",
            ));
        }
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel).max_decoding_message_size(
                        PRIVATE_ORAM_OWNER_PRESTAGE_RECEIPT_MAX_CANONICAL_BYTES_V2 * 6,
                    );
                    let chunks = Arc::clone(&chunks);
                    async move {
                        let chunk_count = chunks.len();
                        let chunk_stream =
                            stream::iter((0..chunk_count).map(move |index| chunks[index].clone()));
                        client
                            .prestage_private_oram_mutation_owner_v2(Request::new(chunk_stream))
                            .await
                    }
                },
                Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
                PRIVATE_ORAM_INSTALL_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner pre-stage failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        validate_owner_prestage_response_bounds(peer_id, &response)?;
        let receipt =
            decode_private_oram_owner_prestage_receipt_v2(&response.receipt_canonical_json)
                .map_err(|_| {
                    CollectionError::service_error(format!(
                        "private ORAM owner pre-stage receipt is invalid on peer {peer_id}"
                    ))
                })?;
        let reservation_resolution_receipt =
            decode_signed_private_oram_owner_reservation_resolution_receipt_v1(
                &response.reservation_resolution_receipt_canonical_json,
            )
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner reservation completion receipt is invalid on peer {peer_id}"
                ))
            })?;
        let expected_resolution_signer = private_oram_owner_cleanup_signer_from_peer_key_v1(
            expected_owner_signer,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner reservation completion signer is invalid on peer {peer_id}"
            ))
        })?;
        let _verified_resolution =
            validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1(
                &reservation_resolution_receipt,
            )
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner reservation completion authentication failed on peer {peer_id}"
                ))
            })?;
        let resolution = &reservation_resolution_receipt.receipt;
        if reservation_resolution_receipt.owner_signer != expected_resolution_signer
            || resolution.disposition
                != PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled
            || resolution.collection_id != reservation_challenge.collection_id
            || resolution.owner_peer_id != peer_id
            || resolution.committed_challenge_digest
                != reservation_challenge.committed_challenge_digest
            || resolution.reservation_intent_digest
                != reservation_challenge.reservation_intent_digest
            || resolution.attempt_id != reservation_challenge.attempt_id
            || resolution.challenge_applied_term != reservation_challenge.challenge_applied_term
            || resolution.challenge_applied_index != reservation_challenge.challenge_applied_index
            || resolution.reserved_terminal_intent_key != request.intent_key
            || resolution.owner_store_incarnation_digest
                != reservation_challenge.owner_store_incarnation_digest
            || resolution.owner_store_binding_digest
                != reservation_challenge.expected_checkpoint_record_digest
            || resolution.installed_prestage_receipt_digest.as_deref()
                != Some(receipt.receipt_digest())
            || resolution.installed_package_sha256.as_deref() != Some(receipt.package_sha256())
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation completion context mismatch on peer {peer_id}"
            )));
        }
        let prestage_response: PrivateOramOwnerPrestageResponseV2 =
            decode_canonical_private_oram_recovery_json(
                &response.prestage_response_canonical_json,
            )?;
        let owner_public_key: PrivateOramPeerRecoveryPublicKeyV1 =
            decode_canonical_private_oram_recovery_json(&response.owner_public_key_canonical_json)?;
        let owner_signature: PrivateOramPeerRecoverySignatureV2 =
            decode_canonical_private_oram_recovery_json(&response.owner_signature_canonical_json)?;
        if &owner_public_key != expected_owner_signer {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner pre-stage signer mismatch on peer {peer_id}"
            )));
        }
        let verified = validate_private_oram_owner_prestage_response_signature_v2(
            &owner_public_key,
            &request,
            &prestage_response,
            &response.receipt_canonical_json,
            &owner_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner pre-stage response signature failed on peer {peer_id}"
            ))
        })?;
        let attestation = decode_private_oram_owner_prestage_attestation_v2(
            &response.owner_prestage_attestation_canonical_json,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner pre-stage attestation is invalid on peer {peer_id}"
            ))
        })?;
        let owner_attestation = validate_private_oram_owner_prestage_attestation_for_signer_v2(
            &attestation,
            expected_owner_signer,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner pre-stage attestation failed on peer {peer_id}"
            ))
        })?;
        let statement = owner_attestation.statement();
        if statement.collection_id != request.collection_id
            || statement.mutation_id != request.mutation_id
            || statement.mutation_digest != request.mutation_digest
            || statement.transition_digest != request.transition_digest
            || statement.expected_aggregate_digest != request.expected_aggregate_digest
            || statement.lease_generation != request.lease_generation
            || statement.writer_fence != request.writer_fence
            || statement.parent_descriptor_digest != request.parent_descriptor_digest
            || statement.parent_lease_acquired_record_digest
                != request.parent_lease_acquired_record_digest
            || statement.owner_roster_digest != request.owner_roster_digest
            || statement.owner_peer_id != peer_id
            || statement.activation_registry_generation != request.activation_registry_generation
            || statement.activation_manifest_digest != request.activation_manifest_digest
            || statement.intent_key != request.intent_key
            || statement.package_sha256 != request.package_sha256
            || statement.receipt_digest != receipt.receipt_digest()
            || statement.receipt_sha256 != prestage_response.receipt_sha256
            || prestage_response.receipt_digest != receipt.receipt_digest()
            || receipt.owner_peer_id() != peer_id
            || receipt.intent_key() != request.intent_key
            || receipt.package_sha256() != request.package_sha256
            || receipt.package_len() != request.package_len
            || self.id_to_address.read().get(&peer_id) != Some(&address)
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner pre-stage context mismatch on peer {peer_id}"
            )));
        }
        Ok(PrivateOramAuthenticatedOwnerPrestageResponseV2 {
            peer_id,
            verified,
            owner_attestation,
            receipt,
            receipt_canonical_json: response.receipt_canonical_json,
            reservation_resolution_receipt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn adopt_private_oram_mutation_owner_v2(
        &self,
        peer_id: PeerId,
        request: PrivateOramOwnerAdoptionRequestV1,
        parent: &PrivateOramOwnerPrepareParentV2,
        coordinator_public_key: PrivateOramPeerRecoveryPublicKeyV1,
        coordinator_signature: PrivateOramPeerRecoverySignatureV2,
        expected_coordinator_signer: &PrivateOramPeerRecoveryPublicKeyV1,
        expected_owner_signer: &PrivateOramPeerRecoveryPublicKeyV1,
    ) -> CollectionResult<PrivateOramAuthenticatedOwnerAdoptionV2> {
        if request.owner_peer_id != peer_id
            || request.coordinator_peer_id == request.owner_peer_id
            || &coordinator_public_key != expected_coordinator_signer
            || parent.owner_peer_id() != peer_id
            || parent.parent_descriptor_digest() != request.parent_descriptor_digest
            || parent.parent_lease_acquired_record_digest()
                != request.parent_lease_acquired_record_digest
        {
            return Err(CollectionError::service_error(
                "private ORAM owner adoption request is invalid",
            ));
        }
        let _verified_request = validate_private_oram_owner_adoption_request_signature_v1(
            &coordinator_public_key,
            &request,
            &coordinator_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner adoption request authentication failed",
            )
        })?;
        let parent_canonical_json =
            encode_private_oram_owner_prepare_parent_v2(parent).map_err(|_| {
                CollectionError::service_error("private ORAM owner adoption request is invalid")
            })?;
        let adoption_request_canonical_json = serde_json::to_vec(&request).map_err(|_| {
            CollectionError::service_error("private ORAM owner adoption request is invalid")
        })?;
        let coordinator_public_key_canonical_json = serde_json::to_vec(&coordinator_public_key)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner adoption request is invalid")
            })?;
        let coordinator_signature_canonical_json = serde_json::to_vec(&coordinator_signature)
            .map_err(|_| {
                CollectionError::service_error("private ORAM owner adoption request is invalid")
            })?;
        for encoded in [
            &parent_canonical_json,
            &adoption_request_canonical_json,
            &coordinator_public_key_canonical_json,
            &coordinator_signature_canonical_json,
        ] {
            if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES {
                return Err(CollectionError::service_error(
                    "private ORAM owner adoption request is invalid",
                ));
            }
        }
        let wire_request = AdoptPrivateOramMutationOwnerV2Request {
            adoption_request_canonical_json,
            parent_canonical_json,
            coordinator_public_key_canonical_json,
            coordinator_signature_canonical_json,
        };
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner adoption requires a configured TLS endpoint",
            ));
        }
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel).max_decoding_message_size(
                        PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES * 4,
                    );
                    let request = wire_request.clone();
                    async move {
                        client
                            .adopt_private_oram_mutation_owner_v2(Request::new(request))
                            .await
                    }
                },
                Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
                PRIVATE_ORAM_INSTALL_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner adoption failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        for encoded in [
            &response.evidence_canonical_json,
            &response.adoption_response_canonical_json,
            &response.owner_public_key_canonical_json,
            &response.owner_signature_canonical_json,
        ] {
            if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES {
                return Err(CollectionError::service_error(format!(
                    "private ORAM owner adoption response is invalid on peer {peer_id}"
                )));
            }
        }
        let evidence =
            decode_private_oram_owner_prepared_evidence_v2(&response.evidence_canonical_json)
                .map_err(|_| {
                    CollectionError::service_error(format!(
                        "private ORAM owner adoption evidence is invalid on peer {peer_id}"
                    ))
                })?;
        let adoption_response: PrivateOramOwnerAdoptionResponseV1 =
            decode_canonical_private_oram_recovery_json(
                &response.adoption_response_canonical_json,
            )?;
        let owner_public_key: PrivateOramPeerRecoveryPublicKeyV1 =
            decode_canonical_private_oram_recovery_json(&response.owner_public_key_canonical_json)?;
        let owner_signature: PrivateOramPeerRecoverySignatureV2 =
            decode_canonical_private_oram_recovery_json(&response.owner_signature_canonical_json)?;
        if &owner_public_key != expected_owner_signer
            || evidence.owner_peer_id() != peer_id
            || evidence.parent_descriptor_digest() != request.parent_descriptor_digest
            || evidence.parent_lease_acquired_record_digest()
                != request.parent_lease_acquired_record_digest
            || evidence.journal_descriptor_digest() != adoption_response.journal_descriptor_digest
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner adoption context mismatch on peer {peer_id}"
            )));
        }
        validate_private_oram_owner_adoption_response_signature_v1(
            &owner_public_key,
            &request,
            &adoption_response,
            &response.evidence_canonical_json,
            &owner_signature,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner adoption response signature failed on peer {peer_id}"
            ))
        })?;
        if self.id_to_address.read().get(&peer_id) != Some(&address) {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner adoption peer authority changed on peer {peer_id}"
            )));
        }
        Ok(PrivateOramAuthenticatedOwnerAdoptionV2 { peer_id, evidence })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_private_oram_mutation_owner_reservation_v3(
        &self,
        peer_id: PeerId,
        collection_name: &str,
        vector_name: &str,
        owner_signing_key_id: &str,
        challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
        expected_owner_signer: &PrivateOramOwnerCleanupSignerV1,
        recover_completion: bool,
        expected_disposition: Option<PrivateOramOwnerReservationResolutionDispositionV1>,
        expected_resolution_applied_term: u64,
        expected_resolution_applied_index: u64,
        expected_finalized_reservation_digest: Option<&str>,
        expected_abort_release_authority_digest: Option<&str>,
    ) -> CollectionResult<Option<SignedPrivateOramOwnerReservationResolutionReceiptV1>> {
        if collection_name.is_empty()
            || collection_name.len() > PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1
            || vector_name.is_empty()
            || vector_name.len() > PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1
            || owner_signing_key_id.is_empty()
            || owner_signing_key_id.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_SIGNING_KEY_ID_MAX_BYTES_V1
            || challenge.owner_peer_id != peer_id
            || (recover_completion
                && (expected_disposition
                    != Some(
                        PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled,
                    )))
        {
            return Err(CollectionError::service_error(
                "private ORAM owner reservation resolve request is invalid",
            ));
        }
        validate_private_oram_owner_reservation_prepare_challenge_v1(challenge).map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner reservation resolve request is invalid",
            )
        })?;
        let challenge_canonical_json = serde_json::to_vec(challenge).map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner reservation resolve request is invalid",
            )
        })?;
        if challenge_canonical_json.is_empty()
            || challenge_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1
        {
            return Err(CollectionError::service_error(
                "private ORAM owner reservation resolve request is invalid",
            ));
        }
        let wire_request = ResolvePrivateOramMutationOwnerReservationV3Request {
            collection_name: collection_name.to_string(),
            vector_name: vector_name.to_string(),
            owner_signing_key_id: owner_signing_key_id.to_string(),
            challenge_canonical_json,
            recover_completion,
        };
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner reservation resolve requires a configured TLS endpoint",
            ));
        }
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel)
                        .max_decoding_message_size(PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES);
                    let request = wire_request.clone();
                    async move {
                        client
                            .resolve_private_oram_mutation_owner_reservation_v3(Request::new(
                                request,
                            ))
                            .await
                    }
                },
                None,
                DEFAULT_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner reservation resolve failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        if !response.resolved
            || response.resolution_receipt_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1
            || self.id_to_address.read().get(&peer_id) != Some(&address)
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation resolve verification failed on peer {peer_id}"
            )));
        }
        if expected_disposition.is_none() {
            if !response.resolution_receipt_canonical_json.is_empty() {
                return Err(CollectionError::service_error(format!(
                    "private ORAM owner reservation resolve verification failed on peer {peer_id}"
                )));
            }
            return Ok(None);
        }
        if response.resolution_receipt_canonical_json.is_empty() {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation resolve verification failed on peer {peer_id}"
            )));
        }
        let signed_receipt = decode_signed_private_oram_owner_reservation_resolution_receipt_v1(
            &response.resolution_receipt_canonical_json,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner reservation resolve verification failed on peer {peer_id}"
            ))
        })?;
        let receipt = &signed_receipt.receipt;
        let disposition_matches = if recover_completion {
            matches!(
                receipt.disposition,
                PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled
                    | PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort
            )
        } else {
            Some(receipt.disposition) == expected_disposition
        };
        let abort_authority_matches = match receipt.disposition {
            PrivateOramOwnerReservationResolutionDispositionV1::FinalizedReleasedAfterAbort => {
                receipt.abort_release_authority_digest.as_deref()
                    == expected_abort_release_authority_digest
            }
            PrivateOramOwnerReservationResolutionDispositionV1::FinalizedInstalled
            | PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased => {
                receipt.abort_release_authority_digest.is_none()
            }
        };
        if signed_receipt.owner_signer != *expected_owner_signer
            || receipt.collection_id != challenge.collection_id
            || receipt.owner_peer_id != peer_id
            || receipt.committed_challenge_digest != challenge.committed_challenge_digest
            || receipt.reservation_intent_digest != challenge.reservation_intent_digest
            || receipt.attempt_id != challenge.attempt_id
            || receipt.challenge_applied_term != challenge.challenge_applied_term
            || receipt.challenge_applied_index != challenge.challenge_applied_index
            || receipt.resolution_applied_term != expected_resolution_applied_term
            || receipt.resolution_applied_index != expected_resolution_applied_index
            || receipt.reserved_terminal_intent_key != challenge.reserved_terminal_intent_key
            || !disposition_matches
            || receipt.finalized_reservation_digest.as_deref()
                != expected_finalized_reservation_digest
            || !abort_authority_matches
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation resolve context mismatch on peer {peer_id}"
            )));
        }
        let _verified =
            validate_self_consistent_signed_private_oram_owner_reservation_resolution_receipt_v1(
                &signed_receipt,
            )
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner reservation resolve authentication failed on peer {peer_id}"
                ))
            })?;
        if self.id_to_address.read().get(&peer_id) != Some(&address) {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation resolve authority changed on peer {peer_id}"
            )));
        }
        Ok(Some(signed_receipt))
    }

    /// Asks an owner to create its empty owner store for a V2 enrollment. The caller checks
    /// the returned signer against the owner's pin and the state against the genesis state.
    pub async fn describe_private_oram_mutation_owner_store_v2(
        &self,
        peer_id: PeerId,
        collection_name: &str,
        vector_name: &str,
        owner_signing_key_id: &str,
    ) -> CollectionResult<(
        PrivateOramOwnerCleanupSignerV1,
        PrivateOramOwnerLifecycleStateV1,
    )> {
        validate_private_oram_owner_enrollment_names_v2(
            collection_name,
            vector_name,
            owner_signing_key_id,
        )?;
        let wire_request = DescribePrivateOramMutationOwnerStoreV2Request {
            collection_name: collection_name.to_string(),
            vector_name: vector_name.to_string(),
            owner_signing_key_id: owner_signing_key_id.to_string(),
        };
        let address = self.private_oram_owner_enrollment_address_v2(peer_id)?;
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel).max_decoding_message_size(
                        PRIVATE_ORAM_OWNER_ENROLLMENT_MAX_RESPONSE_BYTES_V2,
                    );
                    let request = wire_request.clone();
                    async move {
                        client
                            .describe_private_oram_mutation_owner_store_v2(Request::new(request))
                            .await
                    }
                },
                None,
                DEFAULT_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner store description failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        let invalid = || {
            CollectionError::service_error(
                "private ORAM owner store description response is invalid",
            )
        };
        let signer: PrivateOramOwnerCleanupSignerV1 =
            serde_json::from_slice(&response.owner_signer_canonical_json).map_err(|_| invalid())?;
        let lifecycle_state: PrivateOramOwnerLifecycleStateV1 =
            serde_json::from_slice(&response.lifecycle_state_canonical_json)
                .map_err(|_| invalid())?;
        if self.id_to_address.read().get(&peer_id) != Some(&address) {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner enrollment authority changed on peer {peer_id}"
            )));
        }
        Ok((signer, lifecycle_state))
    }

    /// Asks an owner to sign the genesis commitment of its committed prepared enrollment. The
    /// caller verifies the commitment against the committed prepared record before proposing.
    pub async fn sign_private_oram_mutation_owner_enrollment_v2(
        &self,
        peer_id: PeerId,
        collection_name: &str,
        vector_name: &str,
        owner_signing_key_id: &str,
    ) -> CollectionResult<PrivateOramOwnerEnrollmentGenesisCommitmentV1> {
        validate_private_oram_owner_enrollment_names_v2(
            collection_name,
            vector_name,
            owner_signing_key_id,
        )?;
        let wire_request = SignPrivateOramMutationOwnerEnrollmentV2Request {
            collection_name: collection_name.to_string(),
            vector_name: vector_name.to_string(),
            owner_signing_key_id: owner_signing_key_id.to_string(),
        };
        let address = self.private_oram_owner_enrollment_address_v2(peer_id)?;
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel).max_decoding_message_size(
                        PRIVATE_ORAM_OWNER_ENROLLMENT_MAX_RESPONSE_BYTES_V2,
                    );
                    let request = wire_request.clone();
                    async move {
                        client
                            .sign_private_oram_mutation_owner_enrollment_v2(Request::new(request))
                            .await
                    }
                },
                None,
                DEFAULT_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner enrollment signing failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        let commitment = decode_private_oram_owner_enrollment_genesis_commitment_v1(
            &response.commitment_canonical_json,
        )
        .map_err(|_| {
            CollectionError::service_error("private ORAM owner enrollment response is invalid")
        })?;
        if commitment.owner_peer_id != peer_id
            || self.id_to_address.read().get(&peer_id) != Some(&address)
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner enrollment authority changed on peer {peer_id}"
            )));
        }
        Ok(commitment)
    }

    fn private_oram_owner_enrollment_address_v2(&self, peer_id: PeerId) -> CollectionResult<Uri> {
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner enrollment requires a configured TLS endpoint",
            ));
        }
        Ok(address)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_private_oram_mutation_owner_reservation_v3(
        &self,
        peer_id: PeerId,
        collection_name: &str,
        vector_name: &str,
        owner_signing_key_id: &str,
        expected_challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
        expected_owner_signer: &PrivateOramOwnerCleanupSignerV1,
        expected_lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
    ) -> CollectionResult<PrivateOramAuthenticatedOwnerReservationPrepareV3> {
        if collection_name.is_empty()
            || collection_name.len() > PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1
            || vector_name.is_empty()
            || vector_name.len() > PRIVATE_ORAM_OWNER_RESERVATION_RESOURCE_NAME_MAX_BYTES_V1
            || owner_signing_key_id.is_empty()
            || owner_signing_key_id.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_SIGNING_KEY_ID_MAX_BYTES_V1
            || expected_challenge.owner_peer_id != peer_id
        {
            return Err(CollectionError::service_error(
                "private ORAM owner reservation prepare request is invalid",
            ));
        }
        validate_private_oram_owner_reservation_prepare_challenge_v1(expected_challenge).map_err(
            |_| {
                CollectionError::service_error(
                    "private ORAM owner reservation prepare request is invalid",
                )
            },
        )?;
        let challenge_canonical_json = serde_json::to_vec(expected_challenge).map_err(|_| {
            CollectionError::service_error(
                "private ORAM owner reservation prepare request is invalid",
            )
        })?;
        if challenge_canonical_json.is_empty()
            || challenge_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1
        {
            return Err(CollectionError::service_error(
                "private ORAM owner reservation prepare request is invalid",
            ));
        }
        let wire_request = PreparePrivateOramMutationOwnerReservationV3Request {
            collection_name: collection_name.to_string(),
            vector_name: vector_name.to_string(),
            challenge_canonical_json,
            owner_signing_key_id: owner_signing_key_id.to_string(),
        };
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?;
        if !self.channel_pool.tls_configured() || address.scheme_str() != Some("https") {
            return Err(CollectionError::service_error(
                "private ORAM owner reservation prepare requires a configured TLS endpoint",
            ));
        }
        let response = self
            .channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let mut client = QdrantInternalClient::new(channel).max_decoding_message_size(
                        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_RESPONSE_BYTES_V1,
                    );
                    let request = wire_request.clone();
                    async move {
                        client
                            .prepare_private_oram_mutation_owner_reservation_v3(Request::new(
                                request,
                            ))
                            .await
                    }
                },
                None,
                DEFAULT_RETRIES,
            )
            .await
            .map_err(|_| {
                CollectionError::service_error(format!(
                    "private ORAM owner reservation prepare failed on peer {peer_id}"
                ))
            })?
            .into_inner();
        let total_response_bytes = response
            .prepare_canonical_json
            .len()
            .checked_add(response.owner_public_key_canonical_json.len())
            .ok_or_else(|| {
                CollectionError::service_error(
                    "private ORAM owner reservation prepare response is invalid",
                )
            })?;
        if response.prepare_canonical_json.is_empty()
            || response.prepare_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_CANONICAL_BYTES_V1
            || response.owner_public_key_canonical_json.is_empty()
            || response.owner_public_key_canonical_json.len()
                > PRIVATE_ORAM_OWNER_RECOVERY_MAX_ENCODED_BYTES
            || total_response_bytes > PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_MAX_RESPONSE_BYTES_V1
        {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation prepare response is oversized on peer {peer_id}"
            )));
        }
        let prepare: PrivateOramOwnerReservationPrepareV1 =
            decode_private_oram_owner_reservation_prepare_v1(&response.prepare_canonical_json)
                .map_err(|_| {
                    CollectionError::service_error(format!(
                        "private ORAM owner reservation prepare response is invalid on peer {peer_id}"
                    ))
                })?;
        let owner_public_key: PrivateOramPeerRecoveryPublicKeyV1 =
            decode_canonical_private_oram_recovery_json(&response.owner_public_key_canonical_json)?;
        let response_owner_signer = private_oram_owner_cleanup_signer_from_peer_key_v1(
            &owner_public_key,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner reservation prepare signer is invalid on peer {peer_id}"
            ))
        })?;
        if &response_owner_signer != expected_owner_signer {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation prepare signer mismatch on peer {peer_id}"
            )));
        }
        let verified = validate_private_oram_owner_reservation_prepare_v1(
            &prepare,
            expected_challenge,
            expected_owner_signer,
            expected_lifecycle_state,
        )
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM owner reservation prepare verification failed on peer {peer_id}"
            ))
        })?;
        if self.id_to_address.read().get(&peer_id) != Some(&address) {
            return Err(CollectionError::service_error(format!(
                "private ORAM owner reservation prepare peer mapping changed on peer {peer_id}"
            )));
        }
        Ok(PrivateOramAuthenticatedOwnerReservationPrepareV3 { peer_id, verified })
    }

    pub async fn install_private_oram_index(
        &self,
        peer_id: PeerId,
        request: InstallPrivateOramIndexRequest,
    ) -> CollectionResult<InstallPrivateOramIndexResponse> {
        let chunks = Arc::new(
            encode_private_oram_install_chunks(&request)
                .map_err(|error| CollectionError::bad_request(error.to_string()))?,
        );
        self.with_qdrant_client_timeout(
            peer_id,
            Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
            PRIVATE_ORAM_INSTALL_RETRIES,
            |mut client| {
                let chunks = Arc::clone(&chunks);
                async move {
                    let chunk_count = chunks.len();
                    let chunk_stream =
                        stream::iter((0..chunk_count).map(move |index| chunks[index].clone()));
                    client
                        .install_private_oram_index_chunks(Request::new(chunk_stream))
                        .await
                }
            },
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM initial install failed on peer {peer_id}"
            ))
        })
    }

    pub async fn install_private_oram_live_replica(
        &self,
        peer_id: PeerId,
        request: InstallPrivateOramLiveReplicaRequest,
    ) -> CollectionResult<InstallPrivateOramLiveReplicaResponse> {
        let chunks = Arc::new(
            encode_private_oram_install_chunks(&request)
                .map_err(|error| CollectionError::bad_request(error.to_string()))?,
        );
        self.with_qdrant_client_timeout(
            peer_id,
            Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
            PRIVATE_ORAM_INSTALL_RETRIES,
            |mut client| {
                let chunks = Arc::clone(&chunks);
                async move {
                    let chunk_count = chunks.len();
                    let chunk_stream =
                        stream::iter((0..chunk_count).map(move |index| chunks[index].clone()));
                    client
                        .install_private_oram_live_replica_chunks(Request::new(chunk_stream))
                        .await
                }
            },
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM live install failed on peer {peer_id}"
            ))
        })
    }

    pub async fn request_private_oram_shard_recovery(
        &self,
        peer_id: PeerId,
        request: RequestPrivateOramShardRecoveryRequest,
    ) -> CollectionResult<RequestPrivateOramShardRecoveryResponse> {
        self.with_qdrant_client_timeout(
            peer_id,
            Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
            PRIVATE_ORAM_INSTALL_RETRIES,
            |mut client| {
                let request = request.clone();
                async move {
                    client
                        .request_private_oram_shard_recovery(Request::new(request))
                        .await
                }
            },
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|_| {
            CollectionError::service_error(format!(
                "Failed to request private ORAM shard recovery from peer {peer_id}"
            ))
        })
    }

    pub async fn request_private_oram_resharding_resume(
        &self,
        peer_id: PeerId,
        request: RequestPrivateOramReshardingResumeRequest,
    ) -> CollectionResult<RequestPrivateOramReshardingResumeResponse> {
        self.with_qdrant_client_timeout(
            peer_id,
            Some(PRIVATE_ORAM_INSTALL_GRPC_TIMEOUT),
            PRIVATE_ORAM_INSTALL_RETRIES,
            |mut client| {
                let request = request.clone();
                async move {
                    client
                        .request_private_oram_resharding_resume(Request::new(request))
                        .await
                }
            },
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|_| {
            CollectionError::service_error(format!(
                "Failed to request private ORAM resharding resume from peer {peer_id}"
            ))
        })
    }

    async fn complete_private_oram_writeback(
        &self,
        peer_id: PeerId,
        request: CompletePrivateOramWritebackRequest,
        abort: bool,
    ) -> CollectionResult<bool> {
        self.with_qdrant_client(peer_id, |mut client| {
            let request = request.clone();
            async move {
                if abort {
                    client
                        .abort_private_oram_writeback(Request::new(request))
                        .await
                } else {
                    client
                        .finalize_private_oram_writeback(Request::new(request))
                        .await
                }
            }
        })
        .await
        .map(|response| response.into_inner().completed)
        .map_err(|_| {
            CollectionError::service_error(format!(
                "private ORAM completion failed on peer {peer_id}"
            ))
        })
    }

    pub async fn with_qdrant_client<T, O: Future<Output = Result<T, Status>>>(
        &self,
        peer_id: PeerId,
        f: impl Fn(QdrantInternalClient<InterceptedService<Channel, AddTimeout>>) -> O,
    ) -> CollectionResult<T> {
        self.with_qdrant_client_timeout(peer_id, None, DEFAULT_RETRIES, f)
            .await
    }

    async fn with_qdrant_client_timeout<T, O: Future<Output = Result<T, Status>>>(
        &self,
        peer_id: PeerId,
        timeout: Option<Duration>,
        retries: usize,
        f: impl Fn(QdrantInternalClient<InterceptedService<Channel, AddTimeout>>) -> O,
    ) -> CollectionResult<T> {
        let address = self
            .id_to_address
            .read()
            .get(&peer_id)
            .ok_or_else(|| CollectionError::service_error("Address for peer ID is not found."))?
            .clone();
        self.channel_pool
            .with_channel_timeout(
                &address,
                |channel| {
                    let client = QdrantInternalClient::new(channel);
                    let client = client.max_decoding_message_size(usize::MAX);
                    f(client)
                },
                timeout,
                retries,
            )
            .await
            .map_err(Into::into)
    }

    /// Check whether all peers are running at least the given version
    ///
    /// If the version is not known for any peer, this returns `false`.
    /// Peer versions are known since 1.9 and up.
    pub fn all_peers_at_version(&self, version: &Version) -> bool {
        let id_to_address = self.id_to_address.read();
        let id_to_metadata = self.id_to_metadata.read();

        // Ensure there aren't more peer addresses than metadata
        if id_to_address.len() > id_to_metadata.len() {
            let peers_without_metadata =
                peers_without_metadata_for_log(&id_to_address, &id_to_metadata);
            log::info!(
                "Not all peers at version:{version} because there are peers without metadata:{peers_without_metadata:?}"
            );
            return false;
        }

        let all = id_to_metadata
            .values()
            .all(|metadata| &metadata.version >= version);

        if !all {
            let peers_below_version = peers_below_version_for_log(&id_to_metadata, version);
            log::info!(
                "Not all peers at version:{version} peers_below_version:{peers_below_version:?}"
            );
        }

        all
    }

    /// Check whether the specified peer is running at least the given version
    ///
    /// If the version is not known for the peer, this returns `false`.
    /// Peer versions are known since 1.9 and up.
    pub fn peer_is_at_version(&self, peer_id: PeerId, version: &Version) -> bool {
        self.id_to_metadata
            .read()
            .get(&peer_id)
            .is_some_and(|metadata| &metadata.version >= version)
    }

    /// Get the REST address for the current peer.
    pub fn current_rest_address(&self, this_peer_id: PeerId) -> CollectionResult<Url> {
        // Get local peer URI
        let local_peer_uri = self
            .id_to_address
            .read()
            .get(&this_peer_id)
            .cloned()
            .ok_or_else(|| {
                CollectionError::service_error(format!(
                    "Cannot determine REST address, this peer not found in cluster by ID {this_peer_id} ",
                ))
            })?;

        // Construct REST URL from URI
        let mut url = Url::parse(&local_peer_uri.to_string()).map_err(|err| {
            CollectionError::service_error(format!(
                "Cannot determine REST address, peer URI {local_peer_uri} is malformed: {err}",
            ))
        })?;
        url.set_port(Some(self.current_rest_port))
            .map_err(|()| {
                CollectionError::service_error(format!(
                    "Cannot determine REST address, cannot specify port on address {url} for peer ID {this_peer_id}",
                ))
            })?;
        let scheme = if self.rest_tls_enabled {
            "https"
        } else {
            "http"
        };
        url.set_scheme(scheme).map_err(|()| {
            CollectionError::service_error(format!(
                "Cannot determine REST address, cannot set {scheme} scheme on address {url} for peer ID {this_peer_id}",
            ))
        })?;

        Ok(url)
    }

    pub fn other_peers(&self, this_peer_id: PeerId) -> Vec<PeerId> {
        self.id_to_address
            .read()
            .keys()
            .filter(|id| **id != this_peer_id)
            .copied()
            .collect()
    }

    pub fn request_timeout(&self) -> Duration {
        self.channel_pool.request_timeout()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PeerVersionLogEntry {
    peer_id: PeerId,
    version: String,
    crypto_fingerprint_present: bool,
}

fn peers_without_metadata_for_log(
    id_to_address: &HashMap<PeerId, Uri>,
    id_to_metadata: &HashMap<PeerId, PeerMetadata>,
) -> Vec<PeerId> {
    let mut peers_without_metadata = id_to_address
        .keys()
        .filter(|id| !id_to_metadata.contains_key(id))
        .copied()
        .collect::<Vec<_>>();
    peers_without_metadata.sort_unstable();
    peers_without_metadata
}

fn peers_below_version_for_log(
    id_to_metadata: &HashMap<PeerId, PeerMetadata>,
    version: &Version,
) -> Vec<PeerVersionLogEntry> {
    let mut peers_below_version = id_to_metadata
        .iter()
        .filter(|(_peer_id, metadata)| &metadata.version < version)
        .map(|(peer_id, metadata)| PeerVersionLogEntry {
            peer_id: *peer_id,
            version: metadata.version.to_string(),
            crypto_fingerprint_present: metadata.crypto_runtime_capability_fingerprint().is_some(),
        })
        .collect::<Vec<_>>();
    peers_below_version.sort_unstable_by_key(|entry| entry.peer_id);
    peers_below_version
}

#[cfg(test)]
impl Default for ChannelService {
    fn default() -> Self {
        Self {
            id_to_address: Default::default(),
            id_to_metadata: Default::default(),
            channel_pool: Default::default(),
            current_rest_port: 6333,
            rest_tls_enabled: false,
            api_key: None,
            alt_api_key: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
        PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION, PrivateOramIndexKindV2,
        PrivateOramPeerRecoveryTerminalIndexV2, PrivateOramPeerRecoveryTerminalKindV2,
        private_oram_owner_cleanup_signer_v1, private_oram_owner_lifecycle_genesis_state_v1,
        private_oram_peer_recovery_public_key_v1, sign_private_oram_owner_reservation_prepare_v1,
        sign_private_oram_peer_recovery_request_v2, sign_private_oram_peer_recovery_response_v2,
        try_private_oram_peer_recovery_terminal_evidence_digest_v2,
    };
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    use super::*;

    fn recovery_fixture() -> (
        PrivateOramPeerRecoveryRequestV2,
        PrivateOramPeerRecoveryPublicKeyV1,
        VerifiedPrivateOramPeerRecoveryResponseV2,
    ) {
        let digest = |value| BASE64URL_NOPAD.encode(&[value; 32]);
        let request = PrivateOramPeerRecoveryRequestV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: BASE64URL_NOPAD.encode(&[7; 16]),
            collection_name: "collection-name-sentinel".to_string(),
            collection_id: "collection-id".to_string(),
            mutation_id: digest(1),
            parent_descriptor_digest: digest(2),
            decision_record_digest: digest(3),
            coordinator_peer_id: 8,
            owner_peer_id: 7,
            vector_name: "text".to_string(),
            owner_signing_key_id: "owner-signing-key".to_string(),
        };
        let mut terminal = PrivateOramPeerRecoveryTerminalV2 {
            protocol_version: PRIVATE_ORAM_PEER_RECOVERY_PROTOCOL_VERSION,
            challenge_nonce: request.challenge_nonce.clone(),
            owner_peer_id: 7,
            terminal_kind: PrivateOramPeerRecoveryTerminalKindV2::FinalizedNew,
            journal_descriptor_digest: digest(4),
            prepared_state_digest: digest(5),
            terminal_record_digest: digest(6),
            parent_descriptor_digest: request.parent_descriptor_digest.clone(),
            decision_authority_record_digest: request.decision_record_digest.clone(),
            reconciliation_authority_digest: digest(7),
            indexes: vec![
                PrivateOramPeerRecoveryTerminalIndexV2 {
                    kind: PrivateOramIndexKindV2::Hnsw,
                    index_name: "text".to_string(),
                    prepared_journal_digest: digest(8),
                    terminal_state_digest: digest(9),
                },
                PrivateOramPeerRecoveryTerminalIndexV2 {
                    kind: PrivateOramIndexKindV2::Result,
                    index_name: "text".to_string(),
                    prepared_journal_digest: digest(10),
                    terminal_state_digest: digest(11),
                },
            ],
            terminal_evidence_digest: digest(0),
        };
        terminal.terminal_evidence_digest =
            try_private_oram_peer_recovery_terminal_evidence_digest_v2(&request, &terminal)
                .unwrap();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = private_oram_peer_recovery_public_key_v1(&key_pair, 1).unwrap();
        let signature =
            sign_private_oram_peer_recovery_response_v2(&key_pair, 1, &request, &terminal).unwrap();
        let verified = validate_private_oram_peer_recovery_response_signature_v2(
            &public_key,
            &request,
            &terminal,
            &signature,
        )
        .unwrap();
        (request, public_key, verified)
    }

    fn owner_reservation_prepare_fixture() -> (
        PrivateOramOwnerReservationPrepareChallengeV1,
        PrivateOramOwnerCleanupSignerV1,
        PrivateOramOwnerLifecycleStateV1,
        VerifiedPrivateOramOwnerReservationPrepareV1,
    ) {
        let digest = |value| BASE64URL_NOPAD.encode(&[value; 32]);
        let owner_store_incarnation_digest = digest(27);
        let challenge = PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-id".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 7,
            protocol_capability_digest: digest(6),
            membership_epoch: 9,
            reservation_intent_digest: digest(7),
            checkpoint_context_digest: digest(8),
            committed_challenge_digest: digest(9),
            challenge_applied_term: 11,
            challenge_applied_index: 13,
            attempt_id: digest(10),
            challenge_nonce: BASE64URL_NOPAD.encode(&[11; 16]),
            expected_checkpoint_record_digest: digest(12),
            expected_checkpoint_sequence: 17,
            expected_owner_target_digest: digest(13),
            reserved_terminal_intent_key: digest(14),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: digest(15),
            owner_peer_id: 7,
            owner_store_incarnation_digest: owner_store_incarnation_digest.clone(),
            authority_registry_digest: digest(16),
            owner_registry_digest: digest(17),
        };
        let lifecycle =
            private_oram_owner_lifecycle_genesis_state_v1(owner_store_incarnation_digest).unwrap();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let signer = private_oram_owner_cleanup_signer_v1(&key_pair, 19).unwrap();
        let prepare = sign_private_oram_owner_reservation_prepare_v1(
            &key_pair,
            challenge.clone(),
            lifecycle.clone(),
            lifecycle.generation,
            digest(18),
            signer.clone(),
        )
        .unwrap();
        let verified = validate_private_oram_owner_reservation_prepare_v1(
            &prepare, &challenge, &signer, &lifecycle,
        )
        .unwrap();
        (challenge, signer, lifecycle, verified)
    }

    #[tokio::test]
    async fn private_oram_owner_recovery_rejects_non_tls_peer_before_network() {
        let service = ChannelService::default();
        service
            .id_to_address
            .write()
            .insert(7, Uri::from_static("http://peer.example.test:6335"));
        let (request, signer, _) = recovery_fixture();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let coordinator = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let coordinator_public_key =
            private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
        let coordinator_signature =
            sign_private_oram_peer_recovery_request_v2(&coordinator, 1, &request).unwrap();

        let error = service
            .recover_private_oram_mutation_owner(
                7,
                request,
                coordinator_public_key,
                coordinator_signature,
                &signer,
            )
            .await
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("requires a configured TLS endpoint"));
        assert!(!rendered.contains("collection-name-sentinel"));
        assert!(!rendered.contains("peer.example.test"));
    }

    #[tokio::test]
    async fn private_oram_owner_reservation_prepare_rejects_non_tls_peer_before_network() {
        let service = ChannelService::default();
        service
            .id_to_address
            .write()
            .insert(7, Uri::from_static("http://peer.example.test:6335"));
        let (challenge, signer, lifecycle, _) = owner_reservation_prepare_fixture();

        let error = service
            .prepare_private_oram_mutation_owner_reservation_v3(
                7,
                "collection-name-sentinel",
                "vector-name-sentinel",
                "owner-signing-key-sentinel",
                &challenge,
                &signer,
                &lifecycle,
            )
            .await
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("requires a configured TLS endpoint"));
        assert!(!rendered.contains("collection-name-sentinel"));
        assert!(!rendered.contains("vector-name-sentinel"));
        assert!(!rendered.contains("owner-signing-key-sentinel"));
        assert!(!rendered.contains("peer.example.test"));
    }

    #[tokio::test]
    async fn private_oram_owner_reservation_resolve_rejects_non_tls_peer_before_network() {
        let service = ChannelService::default();
        service
            .id_to_address
            .write()
            .insert(7, Uri::from_static("http://peer.example.test:6335"));
        let (challenge, signer, _, _) = owner_reservation_prepare_fixture();

        let error = service
            .resolve_private_oram_mutation_owner_reservation_v3(
                7,
                "collection-name-sentinel",
                "vector-name-sentinel",
                "owner-signing-key-sentinel",
                &challenge,
                &signer,
                false,
                None,
                12,
                14,
                Some(&challenge.reservation_intent_digest),
                None,
            )
            .await
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("requires a configured TLS endpoint"));
        assert!(!rendered.contains("collection-name-sentinel"));
        assert!(!rendered.contains("vector-name-sentinel"));
        assert!(!rendered.contains("owner-signing-key-sentinel"));
        assert!(!rendered.contains("peer.example.test"));
    }

    #[tokio::test]
    async fn private_oram_owner_reservation_resolve_rejects_invalid_challenge_before_network() {
        let service = ChannelService::default();
        let (mut challenge, signer, _, _) = owner_reservation_prepare_fixture();
        challenge.challenge_nonce.clear();

        let error = service
            .resolve_private_oram_mutation_owner_reservation_v3(
                7,
                "collection",
                "text",
                "owner-signing-key",
                &challenge,
                &signer,
                false,
                Some(PrivateOramOwnerReservationResolutionDispositionV1::CancelledReleased),
                12,
                14,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("request is invalid"));
    }

    #[tokio::test]
    async fn private_oram_owner_reservation_prepare_rejects_unbounded_signing_key_id() {
        let service = ChannelService::default();
        let (challenge, signer, lifecycle, _) = owner_reservation_prepare_fixture();

        for invalid_key_id in [
            String::new(),
            "k".repeat(PRIVATE_ORAM_OWNER_RESERVATION_SIGNING_KEY_ID_MAX_BYTES_V1 + 1),
        ] {
            let error = service
                .prepare_private_oram_mutation_owner_reservation_v3(
                    7,
                    "collection",
                    "text",
                    &invalid_key_id,
                    &challenge,
                    &signer,
                    &lifecycle,
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("request is invalid"));
        }
    }

    #[test]
    fn private_oram_authenticated_owner_reservation_prepare_debug_redacts_evidence() {
        let (_, _, _, verified) = owner_reservation_prepare_fixture();
        let prepare_digest = verified.prepare().prepare_digest.clone();
        let bound = PrivateOramAuthenticatedOwnerReservationPrepareV3 {
            peer_id: 7,
            verified,
        };

        let rendered = format!("{bound:?}");
        assert!(rendered.contains("peer_id: 7"));
        assert!(!rendered.contains(&prepare_digest));
    }

    #[test]
    fn private_oram_authenticated_owner_recovery_debug_redacts_evidence() {
        let (_, _, verified) = recovery_fixture();
        let terminal_digest = verified.terminal().terminal_record_digest.clone();
        let bound = PrivateOramAuthenticatedOwnerRecoveryResponse {
            peer_id: 7,
            verified,
        };

        let rendered = format!("{bound:?}");
        assert!(rendered.contains("peer_id: 7"));
        assert!(!rendered.contains(&terminal_digest));
    }

    #[test]
    fn peer_version_logs_omit_peer_urls_and_crypto_fingerprint_values() {
        let id_to_address = HashMap::from([(
            7,
            Uri::from_static("http://peer-with-token.example.test:6333"),
        )]);
        let id_to_metadata = HashMap::new();

        let missing = peers_without_metadata_for_log(&id_to_address, &id_to_metadata);
        let missing_log = format!("{missing:?}");
        assert_eq!(missing, vec![7]);
        assert!(!missing_log.contains("peer-with-token"));

        let id_to_metadata = HashMap::from([(
            3,
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
                "crypto-fingerprint-sentinel".to_string(),
            )),
        )]);
        let peers_below = peers_below_version_for_log(&id_to_metadata, &Version::new(999, 0, 0));
        let peers_below_log = format!("{peers_below:?}");
        assert!(peers_below_log.contains("crypto_fingerprint_present: true"));
        assert!(!peers_below_log.contains("crypto-fingerprint-sentinel"));
    }

    #[tokio::test]
    async fn private_oram_peer_rpc_errors_do_not_reflect_request_values() {
        let service = ChannelService::default();
        let collection_sentinel = "private-oram-collection-secret-sentinel";
        let digest_sentinel = "private-oram-digest-secret-sentinel";
        let prepare = PreparePrivateOramWritebackRequest {
            collection_name: collection_sentinel.to_string(),
            transition: Some(api::grpc::qdrant::PrivateOramReplicationTransition {
                writeback_digest: digest_sentinel.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = service
            .prepare_private_oram_writeback(7, prepare)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer 7"));
        assert!(!error.contains(collection_sentinel));
        assert!(!error.contains(digest_sentinel));

        let install = InstallPrivateOramIndexRequest {
            collection_name: collection_sentinel.to_string(),
            ..Default::default()
        };
        let error = service
            .install_private_oram_index(11, install)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer 11"));
        assert!(!error.contains(collection_sentinel));

        let recovery = RequestPrivateOramShardRecoveryRequest {
            collection_name: collection_sentinel.to_string(),
            shard_id: 3,
            source_peer_id: 13,
            target_peer_id: 17,
            active_transfer_resume: None,
            resume_if_task_missing: false,
        };
        let error = service
            .request_private_oram_shard_recovery(13, recovery)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer 13"));
        assert!(!error.contains(collection_sentinel));

        let resume = RequestPrivateOramReshardingResumeRequest {
            collection_name: collection_sentinel.to_string(),
            shard_id: 3,
            to_shard_id: 5,
            source_peer_id: 13,
            target_peer_id: 17,
        };
        let error = service
            .request_private_oram_resharding_resume(13, resume)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer 13"));
        assert!(!error.contains(collection_sentinel));

        let complete = CompletePrivateOramWritebackRequest {
            collection_name: collection_sentinel.to_string(),
            transition: Some(api::grpc::qdrant::PrivateOramReplicationTransition {
                writeback_digest: digest_sentinel.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let error = service
            .finalize_private_oram_writeback(9, complete)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer 9"));
        assert!(!error.contains(collection_sentinel));
        assert!(!error.contains(digest_sentinel));
    }
}
