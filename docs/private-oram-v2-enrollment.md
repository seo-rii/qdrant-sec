# Private ORAM V2 Collection Enrollment (design draft)

Status: steps 1 (enrollment after activation in consensus), 2 (the genesis
route) and 3 (the owner enrollment ceremony) are implemented; the client
procedure is exercised by `tests/consensus_tests/test_private_oram_v2_enrollment.py`. Today no production path creates a
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
2. **Genesis route** `POST /collections/{c}/private-oram/v2/mutation/enroll` (write
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
4. **Client procedure.** Build the V1 index with free headroom
   (`reserve_private_hnsw_oram_physical_slots`), upload it, perform one V1
   write-back per index, read `enrollment-template`, sign the immutable manifest
   and genesis state, call `enroll`, then open/append. The genesis `client_state_digest` is the
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
- Step 2 is implemented as `POST /collections/{c}/private-oram/v2/mutation/enroll`
  (`do_enroll_private_oram_mutation_collection_v2`), proposed through
  `Dispatcher::submit_private_oram_mutation_enroll_v2`. Body: `{client_id,
  vector_name, immutable_manifest, genesis_state}`. The route requires an active V2
  cluster and the local Raft leader, verifies both owner signatures, requires a
  genesis state (sequence 0, no last mutation id) whose indexes are exactly the
  manifest's, builds the consensus genesis state from the consensus epochs (each
  with a `Some` write-back digest equal to the signed one, no V1 session lease)
  and layout, binds the manifest and state to the live V1 indexes with the same
  paired read sessions an open uses, then proposes. Re-enrolling the same genesis
  state succeeds; a different state is refused.
- Open after enrollment: `open` registers its V1 index sessions only in the local
  session registry (`PrivateHnswSessionOwner::PairedMutation`) and never takes the
  consensus V1 session lease that enrolled collections refuse, so enrollment does
  not block it.
- Step 3: after proposing the genesis state (or on a retry of the same one),
  the route runs `run_private_oram_owner_enrollment_v2`. Each step re-reads
  committed state through `ConsensusManager::private_oram_mutation_v2_owner_enrollment_step`:
  - `Prepare { owner }`: the owner creates its empty owner store namespace
    (`PrivateOramOwnerPrestageStoreV2::ensure_lifecycle_state_v2`) and reports
    its signer and lifecycle state (`DescribePrivateOramMutationOwnerStoreV2`,
    or a local call when the owner is the leader). The leader requires the
    genesis lifecycle state and the owner's pinned activation-manifest signer,
    and proposes Prepared with fresh enrollment and operation ids. The
    membership epoch is the layout generation; the authority and owner
    registry digests are the activation manifest digest and the layout digest.
  - `Activate { owner }`: the owner reads its committed prepared record,
    checks its owner store is still exactly the named empty store, and signs
    the genesis commitment with its peer identity
    (`SignPrivateOramMutationOwnerEnrollmentV2`). The leader verifies the
    commitment against the committed prepared record and proposes Activated.
  - `Complete`: every owner in `layout.owner_peer_ids` holds an enrollment
    checkpoint. Owners enroll one at a time, in peer id order.
  Remote owner calls require a TLS internal endpoint, like the other owner RPCs.
- `POST /collections/{c}/private-oram/v2/mutation/enrollment-template`
  (`{vector_name}`) returns the layout generation and digest and each index's
  consensus epoch, root and write-back digest, which the client binds into its
  genesis state, plus whether the collection is already enrolled.

## Findings from the cluster test

- A V1 build counts every empty slot as a dummy node, so every uploaded index
  declares full occupancy. The V2 immutable manifest needs
  `logical_capacity == logical + dummy` and at least one reserved physical slot,
  so such an index can never enroll. Clients that intend to enroll reserve
  headroom before sealing with `reserve_private_hnsw_oram_physical_slots`; the
  sealed bytes are unchanged, only the declared dummy count drops.
- A collection without layout transitions has no consensus layout record. The
  template reports generation 1 of its stable shard layout over the current
  index epochs (`Dispatcher::private_oram_enrollment_layout`), and `enroll`
  records exactly that layout before proposing the genesis state.
- `tests/consensus_tests/test_private_oram_v2_enrollment.py` covers a pinned
  single peer that is both leader and owner (owner RPCs need TLS). A
  multi-owner run needs a TLS test cluster.

## Risks and open questions

- The floor-aware Initialize is new consensus behavior: needs the version gate,
  snapshot acceptance review (`plan_private_oram_mutation_authority_floor_acceptance_v2`)
  and a restart/replay test.
- Non-empty legacy owner stores: import is undefined; enrollment requires an
  empty owner namespace.
