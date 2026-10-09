use std::collections::BTreeMap;
use std::future::Future;
use std::time::{Duration, Instant};

use actix_web::{HttpResponse, delete, get, post, put, web};
use actix_web_validator::Query;
use api::grpc;
use api::grpc::transport_channel_pool::DEFAULT_GRPC_TIMEOUT;
use collection::operations::verification::new_unchecked_verification_pass;
use data_encoding::BASE64URL_NOPAD;
use futures::stream::FuturesUnordered;
use futures::{StreamExt, TryFutureExt};
use qdrant_sec::PrivateOramPeerActivationSignedAckV1;
use ring::rand::{SecureRandom, SystemRandom};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use storage::content_manager::consensus_manager::PrivateOramMutationV2ActivationStatus;
use storage::content_manager::consensus_ops::{
    ConsensusOperations, PrivateOramMutationActivationBarrierPhaseV2,
    PrivateOramMutationActivationBarrierV2,
};
use storage::content_manager::errors::StorageError;
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, AccessRequirements};
use validator::Validate;

use crate::actix::auth::ActixAuth;
use crate::actix::helpers;
use crate::common::error_reporting::redact_crypto_material_for_report;
use crate::common::private_oram_mutation_supervisor::{
    PrivateOramMutationSupervisorStatusV2, private_oram_mutation_supervisor_status_v2,
};
use crate::common::telemetry::TelemetryData;
use crate::common::telemetry_ops::distributed_telemetry::DistributedTelemetryData;
use crate::settings::Settings;

/// For now, we only handle details_level >= 2
/// TODO(cluster telemetry): Handle lower levels
const MIN_CLUSTER_TELEMETRY_DETAILS_LEVEL: u32 = 2;
const PRIVATE_ORAM_ACTIVATION_DEFAULT_TIMEOUT_SECONDS: u64 = 60;
const PRIVATE_ORAM_ACTIVATION_MAX_TIMEOUT_SECONDS: u64 = 300;
const PRIVATE_ORAM_ACTIVATION_MAX_ACK_JSON_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize, Validate)]
struct QueryParams {
    #[serde(default)]
    force: bool,
    #[serde(default)]
    #[validate(range(min = 1))]
    timeout: Option<u64>,
}

#[derive(Debug, Deserialize, Validate)]
struct PrivateOramActivationParams {
    #[serde(default)]
    #[validate(range(min = 1, max = 300))]
    timeout: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum PrivateOramMutationV2ActivationApiStatus {
    Unprepared,
    Prepared,
    Active,
}

#[derive(Debug, Serialize, JsonSchema)]
struct PrivateOramMutationV2ActivationResponse {
    status: PrivateOramMutationV2ActivationApiStatus,
    reservation_v3_write_floor_active: bool,
    supervisor: PrivateOramMutationSupervisorStatusV2,
}

impl From<PrivateOramMutationV2ActivationStatus> for PrivateOramMutationV2ActivationApiStatus {
    fn from(value: PrivateOramMutationV2ActivationStatus) -> Self {
        match value {
            PrivateOramMutationV2ActivationStatus::Unprepared => Self::Unprepared,
            PrivateOramMutationV2ActivationStatus::Prepared => Self::Prepared,
            PrivateOramMutationV2ActivationStatus::Active => Self::Active,
        }
    }
}

fn random_private_oram_activation_token() -> Result<String, StorageError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        StorageError::service_error("private ORAM activation randomness is unavailable")
    })?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

fn decode_private_oram_activation_ack(
    bytes: &[u8],
) -> Result<PrivateOramPeerActivationSignedAckV1, StorageError> {
    if bytes.is_empty() || bytes.len() > PRIVATE_ORAM_ACTIVATION_MAX_ACK_JSON_BYTES {
        return Err(StorageError::service_error(
            "private ORAM activation acknowledgement is oversized",
        ));
    }
    let acknowledgement: PrivateOramPeerActivationSignedAckV1 = serde_json::from_slice(bytes)
        .map_err(|_| {
            StorageError::service_error("private ORAM activation acknowledgement is invalid")
        })?;
    if serde_json::to_vec(&acknowledgement).map_err(|_| {
        StorageError::service_error("private ORAM activation acknowledgement is invalid")
    })? != bytes
    {
        return Err(StorageError::service_error(
            "private ORAM activation acknowledgement is not canonical JSON",
        ));
    }
    Ok(acknowledgement)
}

fn private_oram_activation_remaining(
    started: Instant,
    timeout: Duration,
) -> Result<Duration, StorageError> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| StorageError::service_error("private ORAM activation timed out"))
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct MetadataParams {
    #[serde(default)]
    pub wait: bool,
}

#[derive(Deserialize, JsonSchema, Validate)]
pub struct ClusterTelemetryParams {
    details_level: Option<u32>,
    #[validate(range(min = 1))]
    timeout: Option<u64>,
}

fn cluster_telemetry_peer_error_for_log(
    peer_id: impl std::fmt::Display,
    err: impl std::fmt::Display,
) -> String {
    let redacted_error = redact_crypto_material_for_report(&err.to_string());
    format!("Internal telemetry service failed for peer {peer_id}: {redacted_error}")
}

#[get("/cluster")]
fn cluster_status(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        auth.check_global_access(AccessRequirements::new(), "cluster_status")?;
        Ok(dispatcher.cluster_status())
    })
}

#[get("/cluster/private-oram/mutation-v2/status")]
async fn private_oram_mutation_v2_activation_status(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    helpers::time(async move {
        auth.check_global_access(
            AccessRequirements::new().manage(),
            "private_oram_mutation_v2_activation_status",
        )?;
        let consensus = dispatcher.consensus_state().ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM mutation V2 activation requires distributed mode",
            )
        })?;
        Ok(PrivateOramMutationV2ActivationResponse {
            status: consensus
                .private_oram_mutation_v2_activation_status()?
                .into(),
            reservation_v3_write_floor_active: consensus
                .private_oram_mutation_v3_write_floor_active()?,
            supervisor: private_oram_mutation_supervisor_status_v2(),
        })
    })
    .await
}

#[post("/cluster/private-oram/mutation-v2/activate")]
async fn activate_private_oram_mutation_v2(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    Query(params): Query<PrivateOramActivationParams>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    helpers::time(async move {
        auth.check_global_access(
            AccessRequirements::new().manage(),
            "activate_private_oram_mutation_v2",
        )?;
        let consensus = dispatcher.consensus_state().ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM mutation V2 activation requires distributed mode",
            )
        })?;
        let timeout = Duration::from_secs(
            params
                .timeout
                .unwrap_or(PRIVATE_ORAM_ACTIVATION_DEFAULT_TIMEOUT_SECONDS)
                .min(PRIVATE_ORAM_ACTIVATION_MAX_TIMEOUT_SECONDS),
        );
        let started = Instant::now();

        let mut status = consensus.private_oram_mutation_v2_activation_status()?;
        let mut reservation_v3_write_floor_active =
            consensus.private_oram_mutation_v3_write_floor_active()?;
        if status == PrivateOramMutationV2ActivationStatus::Active
            && reservation_v3_write_floor_active
        {
            return Ok(PrivateOramMutationV2ActivationResponse {
                status: status.into(),
                reservation_v3_write_floor_active,
                supervisor: private_oram_mutation_supervisor_status_v2(),
            });
        }
        consensus.require_private_oram_activation_coordinator_is_local_leader()?;

        let initial_activation = status == PrivateOramMutationV2ActivationStatus::Unprepared;
        let mut reservation_v3_upgrade_pending =
            consensus.private_oram_mutation_v3_floor_upgrade_pending()?;
        if initial_activation
            || (status == PrivateOramMutationV2ActivationStatus::Active
                && !reservation_v3_upgrade_pending)
        {
            let activation_id = random_private_oram_activation_token()?;
            let challenge_nonces = consensus
                .private_oram_activation_voter_ids()?
                .into_iter()
                .map(|peer_id| Ok((peer_id, random_private_oram_activation_token()?)))
                .collect::<Result<BTreeMap<_, _>, StorageError>>()?;
            let v2_binary_capability_digest =
                crate::common::crypto::private_oram_mutation_v2_binary_capability_digest();
            let v3_binary_capability_digest =
                crate::common::crypto::private_oram_mutation_v3_binary_capability_digest();
            let binary_capability_digest = if initial_activation {
                consensus.private_oram_activation_required_binary_capability_digest()?
            } else {
                v3_binary_capability_digest.clone()
            };
            let activation_protocol_version = if binary_capability_digest
                == v2_binary_capability_digest
            {
                qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V1
            } else if binary_capability_digest == v3_binary_capability_digest {
                qdrant_sec::PRIVATE_ORAM_PEER_ACTIVATION_PROTOCOL_VERSION_V2
            } else {
                return Err(StorageError::PreconditionFailed {
                    description: "private ORAM activation authority requires an unsupported binary capability"
                        .to_string(),
                });
            };
            let runtime_capability_fingerprint = {
                let settings = settings.clone().into_inner();
                crate::common::crypto::run_blocking_crypto_runtime_task(move || {
                    Ok(crate::common::crypto::crypto_runtime_capability_fingerprint(
                        &settings,
                    ))
                })
                .await?
            };
            let challenge_set = consensus.private_oram_peer_activation_challenge_set(
                activation_id,
                challenge_nonces,
                &runtime_capability_fingerprint,
                &binary_capability_digest,
                activation_protocol_version,
            )?;

            let pass = new_unchecked_verification_pass();
            let channel_service = dispatcher
                .toc(&auth, &pass)
                .get_channel_service();
            let gather = async {
                let mut pending = challenge_set
                    .challenges()
                    .iter()
                    .cloned()
                    .map(|challenge| {
                        let peer_id = challenge.target_peer_id;
                        let challenge_canonical_json = serde_json::to_vec(&challenge).map_err(
                            |_| {
                                StorageError::service_error(
                                    "private ORAM activation challenge encoding failed",
                                )
                            },
                        );
                        async move {
                            let challenge_canonical_json = challenge_canonical_json?;
                            if challenge_canonical_json.is_empty()
                                || challenge_canonical_json.len()
                                    > PRIVATE_ORAM_ACTIVATION_MAX_ACK_JSON_BYTES
                            {
                                return Err(StorageError::service_error(
                                    "private ORAM activation challenge is oversized",
                                ));
                            }
                            let response = channel_service
                                .with_qdrant_client(peer_id, |mut client| {
                                    let challenge_canonical_json =
                                        challenge_canonical_json.clone();
                                    async move {
                                        client
                                            .acknowledge_private_oram_mutation_activation(
                                                grpc::PrivateOramMutationActivationChallengeRequest {
                                                    challenge_canonical_json,
                                                },
                                            )
                                            .await
                                    }
                                })
                                .await
                                .map_err(|_| {
                                    StorageError::service_error(format!(
                                        "private ORAM activation acknowledgement failed on peer {peer_id}"
                                    ))
                                })?;
                            let acknowledgement = decode_private_oram_activation_ack(
                                &response.into_inner().signed_ack_canonical_json,
                            )?;
                            Ok((peer_id, acknowledgement))
                        }
                    })
                    .collect::<FuturesUnordered<_>>();
                let mut signed_acks = BTreeMap::new();
                while let Some(result) = pending.next().await {
                    let (peer_id, acknowledgement) = result?;
                    if signed_acks.insert(peer_id, acknowledgement).is_some() {
                        return Err(StorageError::service_error(
                            "private ORAM activation acknowledgement set is invalid",
                        ));
                    }
                }
                Ok::<_, StorageError>(signed_acks)
            };
            let signed_acks = tokio::time::timeout(
                private_oram_activation_remaining(started, timeout)?,
                gather,
            )
            .await
            .map_err(|_| StorageError::service_error("private ORAM activation timed out"))??;
            let proof = consensus.private_oram_package_peer_activation_proof(
                challenge_set,
                signed_acks,
                &runtime_capability_fingerprint,
                &binary_capability_digest,
            )?;
            let prepare_phase = if initial_activation {
                PrivateOramMutationActivationBarrierPhaseV2::PrepareTaggedWrites
            } else {
                PrivateOramMutationActivationBarrierPhaseV2::PrepareReservationV3Reads
            };
            let prepare = PrivateOramMutationActivationBarrierV2::try_new(
                prepare_phase,
                &proof,
            )?;
            let proposal = consensus
                .propose_consensus_op_with_await(
                    ConsensusOperations::ActivatePrivateOramMutationV2(prepare),
                    Some(private_oram_activation_remaining(started, timeout)?),
                )
                .await;
            status = consensus.private_oram_mutation_v2_activation_status()?;
            reservation_v3_upgrade_pending =
                consensus.private_oram_mutation_v3_floor_upgrade_pending()?;
            reservation_v3_write_floor_active =
                consensus.private_oram_mutation_v3_write_floor_active()?;
            let prepare_applied = if initial_activation {
                status != PrivateOramMutationV2ActivationStatus::Unprepared
            } else {
                reservation_v3_upgrade_pending || reservation_v3_write_floor_active
            };
            if !prepare_applied {
                return match proposal {
                    Err(error) => Err(error),
                    Ok(_) => Err(StorageError::service_error(
                        "private ORAM activation prepare barrier was not applied",
                    )),
                };
            }
        }

        status = consensus.private_oram_mutation_v2_activation_status()?;
        reservation_v3_upgrade_pending =
            consensus.private_oram_mutation_v3_floor_upgrade_pending()?;
        if status == PrivateOramMutationV2ActivationStatus::Prepared
            || reservation_v3_upgrade_pending
        {
            consensus.require_private_oram_activation_coordinator_is_local_leader()?;
            let enable = consensus
                .private_oram_mutation_pending_enable_operation()?
                .ok_or_else(|| {
                    StorageError::service_error(
                        "private ORAM activation pending proof is unavailable",
                    )
                })?;
            let proposal = consensus
                .propose_consensus_op_with_await(
                    ConsensusOperations::ActivatePrivateOramMutationV2(enable),
                    Some(private_oram_activation_remaining(started, timeout)?),
                )
                .await;
            status = consensus.private_oram_mutation_v2_activation_status()?;
            reservation_v3_write_floor_active =
                consensus.private_oram_mutation_v3_write_floor_active()?;
            if !reservation_v3_write_floor_active {
                return match proposal {
                    Err(error) => Err(error),
                    Ok(_) => Err(StorageError::service_error(
                        "private ORAM activation enable barrier was not applied",
                    )),
                };
            }
        }

        reservation_v3_write_floor_active =
            consensus.private_oram_mutation_v3_write_floor_active()?;
        if status != PrivateOramMutationV2ActivationStatus::Active
            || !reservation_v3_write_floor_active
        {
            return Err(StorageError::service_error(
                "private ORAM mutation activation did not reach the reservation V3 writer floor",
            ));
        }
        Ok(PrivateOramMutationV2ActivationResponse {
            status: status.into(),
            reservation_v3_write_floor_active,
            supervisor: private_oram_mutation_supervisor_status_v2(),
        })
    })
    .await
}

#[post("/cluster/recover")]
fn recover_current_peer(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> impl Future<Output = HttpResponse> {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();

    helpers::time(async move {
        auth.check_global_access(AccessRequirements::new().manage(), "recover_current_peer")?;
        dispatcher.toc(&auth, &pass).request_snapshot()?;
        Ok(true)
    })
}

#[delete("/cluster/peer/{peer_id}")]
fn remove_peer(
    dispatcher: web::Data<Dispatcher>,
    peer_id: web::Path<u64>,
    Query(params): Query<QueryParams>,
    ActixAuth(auth): ActixAuth,
) -> impl Future<Output = HttpResponse> {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();

    helpers::time(async move {
        auth.check_global_access(AccessRequirements::new().manage(), "remove_peer")?;

        let dispatcher = dispatcher.into_inner();
        let toc = dispatcher.toc(&auth, &pass);
        let peer_id = peer_id.into_inner();

        let has_shards = toc.peer_has_shards(peer_id).await;
        if !params.force && has_shards {
            return Err(StorageError::BadRequest {
                description: format!("Cannot remove peer {peer_id} as there are shards on it"),
            });
        }

        match dispatcher.consensus_state() {
            Some(consensus_state) => {
                consensus_state
                    .propose_consensus_op_with_await(
                        ConsensusOperations::RemovePeer(peer_id),
                        params.timeout.map(std::time::Duration::from_secs),
                    )
                    .await
            }
            None => Err(StorageError::BadRequest {
                description: "Distributed mode disabled.".to_string(),
            }),
        }
    })
}

#[get("/cluster/metadata/keys")]
async fn get_cluster_metadata_keys(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    helpers::time(async move {
        auth.check_global_access(AccessRequirements::new(), "get_cluster_metadata_keys")?;

        let keys = dispatcher
            .consensus_state()
            .ok_or_else(|| StorageError::service_error("Qdrant is running in standalone mode"))?
            .persistent
            .read()
            .get_cluster_metadata_keys();

        Ok(keys)
    })
    .await
}

#[get("/cluster/metadata/keys/{key}")]
async fn get_cluster_metadata_key(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
    key: web::Path<String>,
) -> HttpResponse {
    helpers::time(async move {
        auth.check_global_access(AccessRequirements::new(), "get_cluster_metadata_key")?;

        let value = dispatcher
            .consensus_state()
            .ok_or_else(|| StorageError::service_error("Qdrant is running in standalone mode"))?
            .persistent
            .read()
            .get_cluster_metadata_key(key.as_ref());

        Ok(value)
    })
    .await
}

#[put("/cluster/metadata/keys/{key}")]
async fn update_cluster_metadata_key(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
    key: web::Path<String>,
    params: Query<MetadataParams>,
    value: web::Json<serde_json::Value>,
) -> HttpResponse {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();
    helpers::time(async move {
        let toc = dispatcher.toc(&auth, &pass);
        auth.check_global_access(
            AccessRequirements::new().write(),
            "update_cluster_metadata_key",
        )?;

        toc.update_cluster_metadata(key.into_inner(), value.into_inner(), params.wait)
            .await?;
        Ok(true)
    })
    .await
}

#[delete("/cluster/metadata/keys/{key}")]
async fn delete_cluster_metadata_key(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
    key: web::Path<String>,
    params: Query<MetadataParams>,
) -> HttpResponse {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();
    helpers::time(async move {
        let toc = dispatcher.toc(&auth, &pass);
        auth.check_global_access(
            AccessRequirements::new().write(),
            "delete_cluster_metadata_key",
        )?;

        toc.update_cluster_metadata(key.into_inner(), serde_json::Value::Null, params.wait)
            .await?;
        Ok(true)
    })
    .await
}

#[get("/cluster/telemetry")]
async fn get_cluster_telemetry(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
    params: Query<ClusterTelemetryParams>,
) -> HttpResponse {
    // Not a collection level request.
    let pass = new_unchecked_verification_pass();
    helpers::time(async move {
        let toc = dispatcher.toc(&auth, &pass);
        let access = auth.access("cluster_telemetry");

        let channel_service = toc.get_channel_service();

        let details_level = params
            .details_level
            .unwrap_or_default()
            .max(MIN_CLUSTER_TELEMETRY_DETAILS_LEVEL);

        let collections_selector = match access {
            Access::Global(_) => None,
            Access::Collection(access_list) => {
                let list = access_list
                    .meeting_requirements(AccessRequirements::default())
                    .into_iter()
                    .cloned()
                    .collect();
                Some(grpc::CollectionsSelector {
                    only_collections: list,
                })
            }
        };

        let timeout = params.timeout.unwrap_or(DEFAULT_GRPC_TIMEOUT.as_secs());

        let all_peers: Vec<_> = channel_service
            .id_to_address
            .read()
            .keys()
            .copied()
            .collect();

        let mut futures = all_peers
            .into_iter()
            .map(|peer_id| {
                channel_service
                    .with_qdrant_client(peer_id, |mut client| {
                        let request = grpc::GetTelemetryRequest {
                            collections_selector: collections_selector.clone(),
                            details_level,
                            timeout,
                        };

                        async move { client.get_telemetry(request).await }
                    })
                    .map_err(move |err| (peer_id, err))
            })
            .collect::<FuturesUnordered<_>>();

        let mut telemetries = Vec::with_capacity(futures.len());
        let mut missing_peers = Vec::new();

        while let Some(result) = futures.next().await {
            match result {
                Ok(response) => {
                    let telemetry =
                        TelemetryData::try_from(response.into_inner().result.ok_or_else(|| {
                            StorageError::service_error(
                                "GetTelemetryResponse is missing `result` field",
                            )
                        })?)
                        .map_err(|err| StorageError::service_error(err.to_string()))?;
                    telemetries.push(telemetry);
                }
                Err((peer_id, err)) => {
                    log::error!("{}", cluster_telemetry_peer_error_for_log(peer_id, err));
                    missing_peers.push(peer_id);
                }
            };
        }

        let distributed_telemetry =
            DistributedTelemetryData::resolve_telemetries(access, telemetries, missing_peers)?;

        Ok(distributed_telemetry)
    })
    .await
}

// Configure services
pub fn config_cluster_api(cfg: &mut web::ServiceConfig) {
    cfg.service(cluster_status)
        .service(private_oram_mutation_v2_activation_status)
        .service(activate_private_oram_mutation_v2)
        .service(remove_peer)
        .service(recover_current_peer)
        .service(get_cluster_telemetry)
        .service(get_cluster_metadata_keys)
        .service(get_cluster_metadata_key)
        .service(update_cluster_metadata_key)
        .service(delete_cluster_metadata_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_telemetry_peer_error_log_redacts_crypto_material() {
        let rendered = cluster_telemetry_peer_error_for_log(
            7,
            "remote status included $qdrant_client_aead \
             ciphertext=qdrant-sec-telemetry-error-sentinel \
             readPath=qdrant-sec-telemetry-read-path-sentinel \
             readPathLabel=qdrant-sec-telemetry-read-path-label-sentinel",
        );

        assert!(rendered.contains("peer 7"), "{rendered}");
        assert!(
            rendered.contains("crypto material omitted"),
            "expected redaction marker in {rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-telemetry-error-sentinel"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-telemetry-read-path-sentinel"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("qdrant-sec-telemetry-read-path-label-sentinel"),
            "{rendered}"
        );
        assert!(!rendered.contains("$qdrant_client_aead"), "{rendered}");
    }
}
