use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use collection::operations::verification::new_unchecked_verification_pass;
use schemars::JsonSchema;
use serde::Serialize;
use storage::content_manager::consensus_ops::{
    PrivateOramMutationKey, PrivateOramMutationLeasePhase,
};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::dispatcher::Dispatcher;

use super::auth::Auth;
use super::private_oram_mutation::{
    reconcile_private_oram_admitted_to_commit_v2, recover_private_oram_preadmission_once_v2,
};
use super::private_oram_mutation_session::{
    current_unix_secs, private_oram_detached_job_deciding_for_collection_v2,
    private_oram_detached_job_exists_for_collection_v2,
    reconcile_private_oram_rejected_runtime_jobs_v2,
};
use super::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use super::private_oram_recovery::{
    PrivateOramMutationTerminalResumeOutcomeV2,
    archive_private_oram_mutation_before_acknowledgement_v2,
    resume_private_oram_mutation_terminal_once_v2,
};
use crate::settings::Settings;

const PRIVATE_ORAM_MUTATION_SUPERVISOR_INTERVAL: Duration = Duration::from_secs(5);
const PRIVATE_ORAM_MUTATION_SUPERVISOR_MAX_CANDIDATES: usize = 1_024;
const PRIVATE_ORAM_MUTATION_IMMUTABLE_OWNER_STALL_SECS: u64 = 300;
const PRIVATE_ORAM_MUTATION_PRE_ARCHIVE_PAUSE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_PRE_ARCHIVE_PAUSE_FILE";
const PRIVATE_ORAM_MUTATION_POST_ARCHIVE_PAUSE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_POST_ARCHIVE_PAUSE_FILE";
const PRIVATE_ORAM_MUTATION_SUPERVISOR_SCAN_PAUSE_FILE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_SUPERVISOR_SCAN_PAUSE_FILE";
const PRIVATE_ORAM_MUTATION_TERMINAL_RESUME_ATTEMPT_LOG_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_TERMINAL_RESUME_ATTEMPT_LOG";
const PRIVATE_ORAM_MUTATION_ADMITTED_RECONCILE_PROBE_ENV: &str =
    "QDRANT_STAGING_PRIVATE_ORAM_MUTATION_ADMITTED_RECONCILE_PROBE";

#[cfg(debug_assertions)]
async fn private_oram_mutation_pause_v2(env_name: &str, milestone: &str) {
    let Some(pause_file) = std::env::var_os(env_name) else {
        return;
    };
    if pause_file.is_empty() {
        return;
    }
    log::warn!("{milestone}");
    while std::path::Path::new(&pause_file).exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(not(debug_assertions))]
async fn private_oram_mutation_pause_v2(_env_name: &str, _milestone: &str) {}

#[cfg(debug_assertions)]
fn private_oram_mutation_log_terminal_resume_attempt_v2() {
    if std::env::var_os(PRIVATE_ORAM_MUTATION_TERMINAL_RESUME_ATTEMPT_LOG_ENV)
        .is_some_and(|value| !value.is_empty())
    {
        log::warn!("Private ORAM staging mutation terminal resume attempt reached");
    }
}

#[cfg(not(debug_assertions))]
fn private_oram_mutation_log_terminal_resume_attempt_v2() {}

#[cfg(debug_assertions)]
fn private_oram_mutation_admitted_reconcile_probe_v2() -> bool {
    std::env::var_os(PRIVATE_ORAM_MUTATION_ADMITTED_RECONCILE_PROBE_ENV)
        .is_some_and(|value| !value.is_empty())
}

#[cfg(not(debug_assertions))]
fn private_oram_mutation_admitted_reconcile_probe_v2() -> bool {
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationSupervisorStateV2 {
    Disabled,
    Starting,
    Ready,
    Pending,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PrivateOramMutationSupervisorBlockReasonV2 {
    ConsensusUnavailable,
    ReconcileFailure,
    ImmutableCoordinatorUnavailable,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
pub(crate) struct PrivateOramMutationSupervisorStatusV2 {
    pub state: PrivateOramMutationSupervisorStateV2,
    pub generation: u64,
    pub inspected: u32,
    pub reconciled: u32,
    pub process_local_pending: u32,
    pub owned_elsewhere: u32,
    pub awaiting_cleanup: u32,
    pub immutable_coordinator_unavailable: u32,
    pub oldest_foreign_pending_age_secs: u64,
    pub failed: u32,
    pub block_reason: Option<PrivateOramMutationSupervisorBlockReasonV2>,
    pub last_scan_unix: u64,
}

impl Debug for PrivateOramMutationSupervisorStatusV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationSupervisorStatusV2")
            .field("state", &self.state)
            .field("generation", &self.generation)
            .field("inspected", &self.inspected)
            .field("reconciled", &self.reconciled)
            .field("process_local_pending", &self.process_local_pending)
            .field("owned_elsewhere", &self.owned_elsewhere)
            .field("awaiting_cleanup", &self.awaiting_cleanup)
            .field(
                "immutable_coordinator_unavailable",
                &self.immutable_coordinator_unavailable,
            )
            .field(
                "oldest_foreign_pending_age_secs",
                &self.oldest_foreign_pending_age_secs,
            )
            .field("failed", &self.failed)
            .field("block_reason", &self.block_reason)
            .field("last_scan_unix", &self.last_scan_unix)
            .finish()
    }
}

impl Default for PrivateOramMutationSupervisorStatusV2 {
    fn default() -> Self {
        Self {
            state: PrivateOramMutationSupervisorStateV2::Disabled,
            generation: 0,
            inspected: 0,
            reconciled: 0,
            process_local_pending: 0,
            owned_elsewhere: 0,
            awaiting_cleanup: 0,
            immutable_coordinator_unavailable: 0,
            oldest_foreign_pending_age_secs: 0,
            failed: 0,
            block_reason: None,
            last_scan_unix: 0,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PrivateOramForeignOwnerObservationV2 {
    key: PrivateOramMutationKey,
    owner_peer_id: u64,
    generation: u64,
}

fn classify_foreign_owner_stalls_v2(
    first_seen: &mut HashMap<PrivateOramForeignOwnerObservationV2, u64>,
    observed: &HashSet<PrivateOramForeignOwnerObservationV2>,
    now_unix: u64,
    stall_secs: u64,
) -> (u32, u64) {
    first_seen.retain(|observation, _| observed.contains(observation));
    let mut blocked = 0_u32;
    let mut oldest_age = 0_u64;
    for observation in observed {
        let observed_since = *first_seen.entry(observation.clone()).or_insert(now_unix);
        let age = now_unix.saturating_sub(observed_since);
        oldest_age = oldest_age.max(age);
        if age >= stall_secs {
            blocked = blocked.saturating_add(1);
        }
    }
    (blocked, oldest_age)
}

fn update_foreign_owner_stalls_v2(
    observed: &HashSet<PrivateOramForeignOwnerObservationV2>,
    now_unix: u64,
) -> StorageResult<(u32, u64)> {
    static FIRST_SEEN: OnceLock<Mutex<HashMap<PrivateOramForeignOwnerObservationV2, u64>>> =
        OnceLock::new();
    let mut first_seen = FIRST_SEEN
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| {
            StorageError::service_error(
                "private ORAM mutation foreign-owner observation registry poisoned",
            )
        })?;
    Ok(classify_foreign_owner_stalls_v2(
        &mut first_seen,
        observed,
        now_unix,
        PRIVATE_ORAM_MUTATION_IMMUTABLE_OWNER_STALL_SECS,
    ))
}

pub(crate) fn initialize_private_oram_mutation_supervisor_v2() {
    if let Ok(mut status) = supervisor_status().write()
        && status.state == PrivateOramMutationSupervisorStateV2::Disabled
    {
        status.state = PrivateOramMutationSupervisorStateV2::Starting;
    }
}

pub(crate) fn private_oram_mutation_supervisor_ready_v2() -> bool {
    let status = private_oram_mutation_supervisor_status_v2();
    private_oram_mutation_supervisor_status_is_ready_v2(&status)
}

fn private_oram_mutation_supervisor_status_is_ready_v2(
    status: &PrivateOramMutationSupervisorStatusV2,
) -> bool {
    matches!(
        status.state,
        PrivateOramMutationSupervisorStateV2::Disabled
            | PrivateOramMutationSupervisorStateV2::Ready
            | PrivateOramMutationSupervisorStateV2::Pending
    ) || status.block_reason
        == Some(PrivateOramMutationSupervisorBlockReasonV2::ImmutableCoordinatorUnavailable)
}

pub(crate) fn private_oram_mutation_supervisor_status_v2() -> PrivateOramMutationSupervisorStatusV2
{
    supervisor_status().read().map(|status| *status).unwrap_or(
        PrivateOramMutationSupervisorStatusV2 {
            state: PrivateOramMutationSupervisorStateV2::Blocked,
            failed: 1,
            block_reason: Some(PrivateOramMutationSupervisorBlockReasonV2::ReconcileFailure),
            ..PrivateOramMutationSupervisorStatusV2::default()
        },
    )
}

pub(crate) async fn supervise_private_oram_mutations_v2(
    dispatcher: Arc<Dispatcher>,
    settings: Arc<Settings>,
    identity: Arc<PrivateOramPeerRecoveryIdentity>,
) {
    let mut interval = tokio::time::interval(PRIVATE_ORAM_MUTATION_SUPERVISOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let previous = private_oram_mutation_supervisor_status_v2();
        let next_generation = previous.generation.saturating_add(1);
        let status = match dispatcher.consensus_state() {
            Some(_) => match reconcile_private_oram_mutations_once_v2(
                dispatcher.as_ref(),
                settings.as_ref(),
                identity.as_ref(),
                next_generation,
            )
            .await
            {
                Ok(status) => status,
                Err(_) => {
                    log::warn!("private ORAM mutation supervisor scan failed");
                    PrivateOramMutationSupervisorStatusV2 {
                        state: PrivateOramMutationSupervisorStateV2::Blocked,
                        block_reason: Some(
                            PrivateOramMutationSupervisorBlockReasonV2::ReconcileFailure,
                        ),
                        generation: next_generation,
                        failed: 1,
                        last_scan_unix: current_unix_secs().unwrap_or_default(),
                        ..PrivateOramMutationSupervisorStatusV2::default()
                    }
                }
            },
            None => PrivateOramMutationSupervisorStatusV2 {
                state: PrivateOramMutationSupervisorStateV2::Blocked,
                block_reason: Some(
                    PrivateOramMutationSupervisorBlockReasonV2::ConsensusUnavailable,
                ),
                generation: next_generation,
                failed: 1,
                last_scan_unix: current_unix_secs().unwrap_or_default(),
                ..PrivateOramMutationSupervisorStatusV2::default()
            },
        };
        if let Ok(mut current) = supervisor_status().write() {
            *current = status;
        }
    }
}

async fn reconcile_private_oram_mutations_once_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    generation: u64,
) -> StorageResult<PrivateOramMutationSupervisorStatusV2> {
    private_oram_mutation_pause_v2(
        PRIVATE_ORAM_MUTATION_SUPERVISOR_SCAN_PAUSE_FILE_ENV,
        "Private ORAM staging mutation supervisor scan pause reached",
    )
    .await;
    let consensus = dispatcher.consensus_state().ok_or_else(|| {
        StorageError::service_error("private ORAM mutation supervisor requires distributed mode")
    })?;
    let keys = dispatcher.active_private_oram_mutation_keys()?;
    let pending_acknowledgements =
        dispatcher.private_oram_mutation_pending_acknowledgement_keys()?;
    let preadmission_candidates =
        consensus.private_oram_mutation_v2_preadmission_recovery_candidates()?;
    let candidate_count = keys
        .len()
        .checked_add(pending_acknowledgements.len())
        .and_then(|count| count.checked_add(preadmission_candidates.len()))
        .ok_or_else(|| {
            StorageError::service_error("private ORAM mutation supervisor candidate limit exceeded")
        })?;
    if candidate_count > PRIVATE_ORAM_MUTATION_SUPERVISOR_MAX_CANDIDATES {
        return Err(StorageError::service_error(
            "private ORAM mutation supervisor candidate limit exceeded",
        ));
    }

    let auth = Auth::new_internal(storage::rbac::Access::full(
        "private ORAM mutation supervisor discovery",
    ));
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let access = storage::rbac::Access::full("private ORAM mutation supervisor discovery");
    let mut collection_names = HashMap::new();
    for pass in toc.all_collections(&access).await {
        // A collection deleted between the listing and the lookup must not abort the whole
        // pass for every other collection.
        let collection = match toc.get_collection(&pass).await {
            Ok(collection) => collection,
            Err(_) => {
                log::debug!(
                    "private ORAM mutation supervisor skipped a collection that disappeared during discovery"
                );
                continue;
            }
        };
        let config = collection.config_snapshot().await;
        let Ok(collection_id) = config.stable_crypto_id(collection.name()) else {
            continue;
        };
        if collection_names
            .insert(collection_id, collection.name().to_string())
            .is_some()
        {
            return Err(StorageError::service_error(
                "private ORAM mutation supervisor found duplicate collection identity",
            ));
        }
    }

    let mut status = PrivateOramMutationSupervisorStatusV2 {
        generation,
        inspected: u32::try_from(candidate_count).map_err(|_| {
            StorageError::service_error("private ORAM mutation supervisor candidate limit exceeded")
        })?,
        last_scan_unix: current_unix_secs()?,
        ..PrivateOramMutationSupervisorStatusV2::default()
    };
    let mut foreign_owner_observations = HashSet::new();
    for candidate in preadmission_candidates {
        let Some(collection_name) = collection_names.get(&candidate.key().collection_id) else {
            status.failed = status.failed.saturating_add(1);
            continue;
        };
        if consensus
            .require_private_oram_activation_coordinator_is_local_leader()
            .is_err()
        {
            // Prepared attempts are recovered by the current leader, not an immutable
            // admitted owner. They must still keep follower readiness pending.
            status.owned_elsewhere = status.owned_elsewhere.saturating_add(1);
            continue;
        }
        match recover_private_oram_preadmission_once_v2(
            dispatcher,
            settings,
            identity,
            collection_name,
            &candidate,
        )
        .await
        {
            Ok(true) => status.reconciled = status.reconciled.saturating_add(1),
            Ok(false) => {
                status.process_local_pending = status.process_local_pending.saturating_add(1)
            }
            Err(_) => {
                log::warn!("private ORAM mutation supervisor pre-admission recovery failed");
                status.failed = status.failed.saturating_add(1);
            }
        }
    }
    // A new leader may have acknowledged an orphan while its original coordinator was
    // paused. Retire exact rejected local jobs on every peer, even after durable candidates
    // have disappeared from the leader's pending-work list.
    match reconcile_private_oram_rejected_runtime_jobs_v2(dispatcher).await {
        Ok(retired) => {
            status.reconciled = status
                .reconciled
                .saturating_add(u32::try_from(retired).unwrap_or(u32::MAX))
        }
        Err(_) => {
            log::warn!("private ORAM mutation supervisor rejected runtime cleanup failed");
            status.failed = status.failed.saturating_add(1);
        }
    }
    for (key, owner_peer_id, generation) in pending_acknowledgements {
        let Some(collection_name) = collection_names.get(&key.collection_id) else {
            status.failed = status.failed.saturating_add(1);
            continue;
        };
        if owner_peer_id != identity.peer_id() || owner_peer_id != dispatcher.this_peer_id() {
            status.owned_elsewhere = status.owned_elsewhere.saturating_add(1);
            foreign_owner_observations.insert(PrivateOramForeignOwnerObservationV2 {
                key,
                owner_peer_id,
                generation,
            });
            continue;
        }
        let result = async {
            private_oram_mutation_pause_v2(
                PRIVATE_ORAM_MUTATION_PRE_ARCHIVE_PAUSE_FILE_ENV,
                "Private ORAM staging mutation post-clear pre-archive pause reached",
            )
            .await;
            let ready = archive_private_oram_mutation_before_acknowledgement_v2(
                dispatcher,
                settings,
                identity,
                collection_name,
                &key,
                generation,
            )
            .await?;
            private_oram_mutation_pause_v2(
                PRIVATE_ORAM_MUTATION_POST_ARCHIVE_PAUSE_FILE_ENV,
                "Private ORAM staging mutation post-archive pre-acknowledgement pause reached",
            )
            .await;
            dispatcher
                .submit_private_oram_mutation_clear_acknowledgement_v2(
                    ready,
                    Some(Duration::from_secs(60)),
                )
                .await
        }
        .await;
        match result {
            Ok(()) => {
                status.reconciled = status.reconciled.saturating_add(1);
                status.awaiting_cleanup = status.awaiting_cleanup.saturating_add(1);
            }
            Err(_) => {
                log::warn!(
                    "private ORAM mutation supervisor could not acknowledge a cleared mutation"
                );
                status.failed = status.failed.saturating_add(1);
            }
        }
    }
    for key in keys {
        let Some(collection_name) = collection_names.get(&key.collection_id) else {
            status.failed = status.failed.saturating_add(1);
            continue;
        };
        let admitted_reconcile_probe = private_oram_mutation_admitted_reconcile_probe_v2();
        match private_oram_detached_job_exists_for_collection_v2(&key.collection_id) {
            Ok(true) if !admitted_reconcile_probe => {
                status.process_local_pending = status.process_local_pending.saturating_add(1);
                continue;
            }
            Ok(_) => {}
            Err(_) => {
                log::warn!("private ORAM mutation supervisor could not inspect detached jobs");
                status.failed = status.failed.saturating_add(1);
                continue;
            }
        }
        // A key listed as active whose lease slot is missing is a per-collection inconsistency;
        // report it and keep reconciling the other collections.
        let Some(slot) = consensus.private_oram_mutation_lease_slot(&key) else {
            log::warn!(
                "private ORAM mutation supervisor found an active mutation key without a lease slot"
            );
            status.failed = status.failed.saturating_add(1);
            continue;
        };
        let Some(lease) = slot.active.as_ref() else {
            continue;
        };
        if lease.owner_peer_id != identity.peer_id() {
            status.owned_elsewhere = status.owned_elsewhere.saturating_add(1);
            foreign_owner_observations.insert(PrivateOramForeignOwnerObservationV2 {
                key: key.clone(),
                owner_peer_id: lease.owner_peer_id,
                generation: slot.generation,
            });
            continue;
        }
        // The live job is proposing the commit of this admitted mutation; let it finish.
        if lease.phase == PrivateOramMutationLeasePhase::Preparing {
            match private_oram_detached_job_deciding_for_collection_v2(&key.collection_id) {
                Ok(true) => {
                    status.process_local_pending = status.process_local_pending.saturating_add(1);
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    log::warn!(
                        "private ORAM mutation supervisor could not inspect detached jobs: {error}"
                    );
                    status.failed = status.failed.saturating_add(1);
                    continue;
                }
            }
        }
        let admitted_ready = if private_oram_mutation_requires_admitted_reconcile_v2(&lease.phase) {
            if admitted_reconcile_probe {
                log::warn!("Private ORAM staging mutation admitted reconcile attempt reached");
            }
            reconcile_private_oram_admitted_to_commit_v2(
                dispatcher,
                settings,
                identity,
                collection_name,
                &key,
            )
            .await
        } else {
            Ok(())
        };
        match admitted_ready {
            Ok(()) => {
                private_oram_mutation_log_terminal_resume_attempt_v2();
                match resume_private_oram_mutation_terminal_once_v2(
                    dispatcher,
                    settings,
                    identity,
                    collection_name,
                    &key,
                )
                .await
                {
                    Ok(PrivateOramMutationTerminalResumeOutcomeV2::Advanced) => {
                        status.reconciled = status.reconciled.saturating_add(1);
                        status.process_local_pending =
                            status.process_local_pending.saturating_add(1);
                    }
                    Ok(PrivateOramMutationTerminalResumeOutcomeV2::AwaitingCleanup) => {
                        status.reconciled = status.reconciled.saturating_add(1);
                        status.awaiting_cleanup = status.awaiting_cleanup.saturating_add(1);
                    }
                    Err(_) => {
                        log::warn!("private ORAM mutation supervisor terminal resume failed");
                        status.failed = status.failed.saturating_add(1);
                    }
                }
            }
            Err(_) => {
                log::warn!("private ORAM mutation supervisor admitted reconcile failed");
                status.failed = status.failed.saturating_add(1);
            }
        }
    }
    let (immutable_coordinator_unavailable, oldest_foreign_pending_age_secs) =
        update_foreign_owner_stalls_v2(&foreign_owner_observations, status.last_scan_unix)?;
    status.immutable_coordinator_unavailable = immutable_coordinator_unavailable;
    status.oldest_foreign_pending_age_secs = oldest_foreign_pending_age_secs;
    status.block_reason = if status.failed != 0 {
        Some(PrivateOramMutationSupervisorBlockReasonV2::ReconcileFailure)
    } else if immutable_coordinator_unavailable != 0 {
        Some(PrivateOramMutationSupervisorBlockReasonV2::ImmutableCoordinatorUnavailable)
    } else {
        None
    };
    status.state = classify_private_oram_mutation_supervisor_state_v2(&status);
    Ok(status)
}

fn private_oram_mutation_requires_admitted_reconcile_v2(
    phase: &PrivateOramMutationLeasePhase,
) -> bool {
    matches!(phase, PrivateOramMutationLeasePhase::Preparing)
}

fn classify_private_oram_mutation_supervisor_state_v2(
    status: &PrivateOramMutationSupervisorStatusV2,
) -> PrivateOramMutationSupervisorStateV2 {
    if status.failed != 0 {
        PrivateOramMutationSupervisorStateV2::Blocked
    } else if status.immutable_coordinator_unavailable != 0 {
        PrivateOramMutationSupervisorStateV2::Blocked
    } else if status.process_local_pending != 0
        || status.owned_elsewhere != 0
        || status.awaiting_cleanup != 0
    {
        PrivateOramMutationSupervisorStateV2::Pending
    } else {
        PrivateOramMutationSupervisorStateV2::Ready
    }
}

fn supervisor_status() -> &'static RwLock<PrivateOramMutationSupervisorStatusV2> {
    static STATUS: OnceLock<RwLock<PrivateOramMutationSupervisorStatusV2>> = OnceLock::new();
    STATUS.get_or_init(|| RwLock::new(PrivateOramMutationSupervisorStatusV2::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_owned_mutation_is_pending_and_failure_is_blocked() {
        let foreign = PrivateOramMutationSupervisorStatusV2 {
            owned_elsewhere: 1,
            ..PrivateOramMutationSupervisorStatusV2::default()
        };
        assert_eq!(
            classify_private_oram_mutation_supervisor_state_v2(&foreign),
            PrivateOramMutationSupervisorStateV2::Pending
        );

        let failed = PrivateOramMutationSupervisorStatusV2 {
            state: PrivateOramMutationSupervisorStateV2::Blocked,
            failed: 1,
            owned_elsewhere: 1,
            block_reason: Some(PrivateOramMutationSupervisorBlockReasonV2::ReconcileFailure),
            ..PrivateOramMutationSupervisorStatusV2::default()
        };
        assert_eq!(
            classify_private_oram_mutation_supervisor_state_v2(&failed),
            PrivateOramMutationSupervisorStateV2::Blocked
        );

        let owner_unavailable = PrivateOramMutationSupervisorStatusV2 {
            state: PrivateOramMutationSupervisorStateV2::Blocked,
            owned_elsewhere: 1,
            immutable_coordinator_unavailable: 1,
            block_reason: Some(
                PrivateOramMutationSupervisorBlockReasonV2::ImmutableCoordinatorUnavailable,
            ),
            ..PrivateOramMutationSupervisorStatusV2::default()
        };
        assert_eq!(
            classify_private_oram_mutation_supervisor_state_v2(&owner_unavailable),
            PrivateOramMutationSupervisorStateV2::Blocked
        );
        assert!(private_oram_mutation_supervisor_status_is_ready_v2(
            &owner_unavailable
        ));
        assert!(!private_oram_mutation_supervisor_status_is_ready_v2(
            &failed
        ));
    }

    #[test]
    fn foreign_owner_stall_requires_a_bounded_unchanged_observation() {
        let observation = PrivateOramForeignOwnerObservationV2 {
            key: PrivateOramMutationKey {
                collection_id: "foreign-owner-stall-test".to_string(),
            },
            owner_peer_id: 17,
            generation: 9,
        };
        let observed = HashSet::from([observation]);
        let mut first_seen = HashMap::new();
        assert_eq!(
            classify_foreign_owner_stalls_v2(&mut first_seen, &observed, 100, 10),
            (0, 0)
        );
        assert_eq!(
            classify_foreign_owner_stalls_v2(&mut first_seen, &observed, 109, 10),
            (0, 9)
        );
        assert_eq!(
            classify_foreign_owner_stalls_v2(&mut first_seen, &observed, 110, 10),
            (1, 10)
        );
        assert_eq!(
            classify_foreign_owner_stalls_v2(&mut first_seen, &HashSet::new(), 120, 10),
            (0, 0)
        );
        assert!(first_seen.is_empty());
    }

    #[test]
    fn terminal_decisions_skip_admitted_reconciliation() {
        assert!(private_oram_mutation_requires_admitted_reconcile_v2(
            &PrivateOramMutationLeasePhase::Preparing
        ));
        assert!(!private_oram_mutation_requires_admitted_reconcile_v2(
            &PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest: "record".to_string(),
                committed_state_sequence: 1,
                committed_signed_state_digest: "state".to_string(),
                receipt_digest: "receipt".to_string(),
            }
        ));
        assert!(!private_oram_mutation_requires_admitted_reconcile_v2(
            &PrivateOramMutationLeasePhase::AbortDecided
        ));
    }
}
