use std::sync::mpsc::Sender;

use parking_lot::Mutex;

use crate::content_manager::consensus_ops::{
    PrivateOramMutationLeasePhase, PrivateOramMutationMaterialTransitionKindV2,
    PrivateOramMutationMaterialTransitionV2,
};
use crate::{ConsensusOperations, StorageError};

const PRIVATE_ORAM_ABORT_DECISION_DISABLED: &str =
    "private ORAM mutation AbortDecided proposals are disabled";

fn reject_private_oram_abort_decision(operation: &ConsensusOperations) -> Result<(), StorageError> {
    let issues_abort_decision = match operation {
        ConsensusOperations::CompareAndSwapPrivateOramMutationLease(operation) => {
            operation.new.active.as_ref().is_some_and(|lease| {
                matches!(lease.phase, PrivateOramMutationLeasePhase::AbortDecided)
            })
        }
        ConsensusOperations::ApplyPrivateOramMutationMaterialV2(operation) => {
            operation.transition_kind()
                == PrivateOramMutationMaterialTransitionKindV2::AbortDecision
                || match operation.transition() {
                    PrivateOramMutationMaterialTransitionV2::Admission { lease, .. }
                    | PrivateOramMutationMaterialTransitionV2::AdmissionRejected {
                        lease, ..
                    }
                    | PrivateOramMutationMaterialTransitionV2::Renewal { lease } => {
                        matches!(lease.phase, PrivateOramMutationLeasePhase::AbortDecided)
                    }
                    _ => false,
                }
        }
        _ => false,
    };
    if issues_abort_decision {
        Err(StorageError::bad_request(
            PRIVATE_ORAM_ABORT_DECISION_DISABLED,
        ))
    } else {
        Ok(())
    }
}

/// Structure used to notify consensus about operation
pub struct OperationSender(Mutex<Sender<ConsensusOperations>>);

impl OperationSender {
    pub fn new(sender: Sender<ConsensusOperations>) -> Self {
        OperationSender(Mutex::new(sender))
    }

    pub fn send(&self, operation: ConsensusOperations) -> Result<(), StorageError> {
        reject_private_oram_abort_decision(&operation)?;
        self.0.lock().send(operation)?;
        Ok(())
    }
}

impl Clone for OperationSender {
    fn clone(&self) -> Self {
        OperationSender::new(self.0.lock().clone())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::{OperationSender, PRIVATE_ORAM_ABORT_DECISION_DISABLED};
    use crate::content_manager::consensus_ops::{
        ApplyPrivateOramMutationMaterialV2, CompareAndSwapPrivateOramMutationLease,
        ConfirmPrivateOramMutationAuthorityV2, ConsensusOperations,
        PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION, PrivateOramMutationKey, PrivateOramMutationLease,
        PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2,
    };
    use crate::content_manager::errors::StorageError;

    fn mutation_lease(phase: PrivateOramMutationLeasePhase) -> PrivateOramMutationLease {
        PrivateOramMutationLease {
            generation: 1,
            collection_id: "collection-uuid".to_string(),
            owner_peer_id: 7,
            mutation_id: "mutation-id".to_string(),
            signed_mutation_digest: "signed-mutation-digest".to_string(),
            transition_digest: "transition-digest".to_string(),
            base_record_digest: "base-record-digest".to_string(),
            base_state_sequence: 0,
            writer_lease_digest: "writer-lease-digest".to_string(),
            writer_fence: 1,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase,
        }
    }

    fn mutation_slot(active: Option<PrivateOramMutationLease>) -> PrivateOramMutationLeaseSlotV2 {
        PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: 1,
            active,
            last_clear: None,
            max_writer_fence: 1,
        }
    }

    #[test]
    fn production_sender_rejects_abort_decision_but_allows_recovery_clear() {
        let key = PrivateOramMutationKey {
            collection_id: "collection-uuid".to_string(),
        };
        let preparing = mutation_lease(PrivateOramMutationLeasePhase::Preparing);
        let abort_decided = mutation_lease(PrivateOramMutationLeasePhase::AbortDecided);

        for operation in [
            ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
                ApplyPrivateOramMutationMaterialV2::abort_decision(
                    key.clone(),
                    "expected-aggregate-digest".to_string(),
                    abort_decided.clone(),
                ),
            ),
            ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
                ApplyPrivateOramMutationMaterialV2::renewal(
                    key.clone(),
                    "expected-aggregate-digest".to_string(),
                    abort_decided.clone(),
                ),
            ),
            ConsensusOperations::CompareAndSwapPrivateOramMutationLease(
                CompareAndSwapPrivateOramMutationLease {
                    key: key.clone(),
                    expected: mutation_slot(Some(preparing)),
                    new: mutation_slot(Some(abort_decided.clone())),
                },
            ),
        ] {
            let (channel, receiver) = mpsc::channel();
            let error = OperationSender::new(channel).send(operation).unwrap_err();
            assert!(matches!(
                error,
                StorageError::BadRequest { description }
                    if description == PRIVATE_ORAM_ABORT_DECISION_DISABLED
            ));
            assert!(receiver.try_recv().is_err());
        }

        for recovery_operation in [
            ConsensusOperations::CompareAndSwapPrivateOramMutationLease(
                CompareAndSwapPrivateOramMutationLease {
                    key: key.clone(),
                    expected: mutation_slot(Some(abort_decided.clone())),
                    new: mutation_slot(None),
                },
            ),
            ConsensusOperations::ApplyPrivateOramMutationMaterialV2(
                ApplyPrivateOramMutationMaterialV2::clear(
                    key.clone(),
                    "expected-aggregate-digest".to_string(),
                ),
            ),
            ConsensusOperations::ConfirmPrivateOramMutationAuthorityV2(
                ConfirmPrivateOramMutationAuthorityV2 {
                    key,
                    expected: mutation_slot(Some(abort_decided)),
                },
            ),
        ] {
            let (channel, receiver) = mpsc::channel();
            OperationSender::new(channel)
                .send(recovery_operation.clone())
                .unwrap();
            assert_eq!(receiver.recv().unwrap(), recovery_operation);
        }
    }
}
