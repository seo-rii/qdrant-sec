# Private ORAM V2 Collection Enrollment (design draft)

Status: draft for review; step 1 (enrollment after activation in consensus)
is implemented, the route and owner ceremony are not. Today no production path creates a
collection's V2 consensus state, so `POST .../private-oram/v2/mutation/open`
always fails on a real deployment (see docs/ckks.md, "multi-process V2
activation"). This document proposes the missing enrollment path.

## Current contract (facts)

- `InitializePrivateOramMutationState { key, state }` creates the collection's
  `PrivateOramConsensusCollectionStateV2` and a raw genesis lease slot
  (`persistent.rs` `apply_initialize`). Its state must be Genesis
  (`state_sequence` 0) and must bind exactly the current layout record
  (generation, layout digest, index-state digest) and every index epoch record,
  including `writeback_digest`. No V1 session lease may be held.
- Once the V2 format floor exists, every lease slot must be a tagged authority
  (`validate_private_oram_mutation_authority_format_snapshot`). An Initialize
  applied after activation creates a raw slot and is rejected. Tagged and
  activated authorities are created only by the one-shot activation barrier
  (`PrepareTaggedWrites`, `EnableMutationV2`), so a collection created after
  activation can never enroll today.
- Owner enrollment (`owner_enrollment_prepared` / `owner_enrollment_activated`)
  requires an activated aggregate, compare-and-swaps the aggregate digest, and
  installs one EnrollmentGenesis checkpoint per owner. Append reservations later
  require one checkpoint for exactly `layout.owner_peer_ids`, each with the
  owner's pinned activation-manifest signer.
- Open compares each index's `epoch.writeback_digest == Some(last_writeback_digest)`.
  A freshly uploaded index has `writeback_digest: None`, so each index needs one
  V1 write-back before genesis. After enrollment, V1 epoch CAS, layout CAS and
  session-lease acquire are refused for the collection.

## Proposal

1. **Floor-aware Initialize** (consensus change, wire-versioned). When the
   format floor has activation enabled, Initialize builds the raw genesis slot,
   tags it as a legacy authority, and activates it in the same apply, using a
   context whose locator is the Initialize entry's (term, index) and whose
   activation request digest is a domain-separated digest of the operation;
   `compatibility_epoch` is the floor's format epoch. Between Prepare and
   Enable, Initialize is refused with `bad_request`. Mixed-version replicas
   must reject the new variant deterministically (protocol version gate).
2. **Genesis route** `POST /collections/{c}/private-oram/v2/enroll` (write
   access, local Raft leader, V2 active). Body: `{vector_name,
   immutable_manifest, genesis_state}`, both signed by the client owner key
   pinned in the collection's runtime instance. The server verifies both
   signatures, recomputes every digest (consensus trusts the proposer), checks
   the live V1 manifests, epochs (with `Some` write-back digest), layout and the
   absence of session leases, and proposes Initialize through a new
   `Dispatcher::submit_private_oram_mutation_initialize` (an already-equal state
   counts as success).
3. **Owner enrollment ceremony.** The leader walks `layout.owner_peer_ids` one
   owner at a time: it authors Prepared (scope from `aggregate.activation`,
   fresh random enrollment id, store incarnation and operation id, signer = the
   owner's pinned peer-identity key) and proposes it with the current aggregate
   digest. Then it asks the owner over internal gRPC to create its empty owner
   namespace durably and return the signed genesis commitment, and proposes
   Activated. It re-reads the aggregate digest before every proposal.
4. **Client procedure.** Upload V1 index, perform one V1 write-back per index,
   call `enroll`, then open/append. The genesis `client_state_digest` is the
   digest of the client's sealed append checkpoint set
   (`private_oram_append_client_checkpoint_v2_digest`); the client must escrow
   that checkpoint before enrolling.

## Implementation status

- Step 1 is implemented as a new consensus operation,
  `ConsensusOperations::EnrollPrivateOramMutationCollectionV2` (carrying an
  `InitializePrivateOramMutationState`), applied by `apply_enroll_v2` in
  `persistent.rs`: it requires an activation-enabled format floor and no
  pending activation, initializes the genesis state like Initialize, tags the
  raw slot as a legacy authority and activates it with the entry's locator, the
  floor's format epoch and an enrollment request digest. Re-proposing the same
  genesis state is a no-op; a different one is refused. A binary without the
  variant fails to decode the entry and stops instead of diverging. Test:
  `enrollment_after_activation_initializes_and_activates_the_collection_authority`.
- Not implemented yet: the dispatcher submit method, the `enroll` route, the
  owner enrollment ceremony and the client procedure.

## Risks and open questions

- The floor-aware Initialize is new consensus behavior: needs the version gate,
  snapshot acceptance review (`plan_private_oram_mutation_authority_floor_acceptance_v2`)
  and a restart/replay test.
- How the owner's peer-identity key signs genesis commitments locally (key
  custody in the owner store) is not wired yet.
- Enrollment freezes V1 operations: confirm open/append do not depend on the
  refused V1 session-lease CAS.
- Non-empty legacy owner stores: import is undefined; enrollment requires an
  empty owner namespace.
