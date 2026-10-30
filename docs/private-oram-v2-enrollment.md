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

- Capability upgrades install a consecutively signed activation-authority
  successor through startup configuration before gathering the new cluster
  proof. If a fully enabled older protocol floor already exists, the authority
  durably retains its exact signed predecessor and the old floor digest.
  Restart before `PrepareTaggedWrites` verifies both signatures, their parent
  link and that exact floor binding; it preserves the old applied floor and
  keeps new-protocol writes fenced. Another authority rotation is refused
  until the floor catches up. The bounded predecessor record remains verifiable
  after activation; missing or invalid evidence never permits a capability
  mismatch. Install the new binary on every peer before completing activation.
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
  single peer that is both leader and owner, and
  `test_private_oram_collection_enrolls_every_owner_over_tls`: three pinned
  peers with internal TLS (a throwaway CA, `https` consensus URIs) and a
  replica each, so the leader enrolls two remote owners over the TLS-only
  owner RPCs. The activation authority pins each peer's consensus URI digest
  including its scheme, so a TLS cluster's bundle must pin `https` (the
  activation fixture takes a per-peer `tls` flag).
- Every V2 index must declare the same `logical_capacity`, and a paired
  collection's V1 HNSW and result manifests must both name the V2 owner signing
  key (the live-binding check compares them), so a paired deployment signs its
  result index with the HNSW owner key. `test_private_oram_v2_append.py`
  enrolls such a paired collection with a genesis state that commits to a real
  sealed client checkpoint.

## Findings from the append test

`test_private_oram_v2_append.py` drives a real paired append: the
`private_oram_v2_append_client` example reads every fixed window of both
indexes through the mutation `read` route, verifies the buckets against the
session roots, finalizes the mutation and posts the owner prepare. Reading
every level-0 node as a candidate is required: linking the new node to a
neighbor whose list is full prunes that list, which needs every current
neighbor's vector, so the read schedule is the rewrites, the insert and one
candidate path per point.

Two server bugs refused every append, and are fixed:

- The runtime job authority was read from the lease slot the append was
  validated against. That slot is the pre-admission one, so it never holds a
  lease and every append was refused when its job was registered. The
  authority is now the lease the admission installs: the coordinator (the
  local leader of the job's freeze token) at the slot's next generation.
- The session's paired V1 read sessions stayed open after the reads. The owner
  pre-stage and the parent materialization take the collection lifecycle
  guard, which refuses while any index session is open, and the coordinator is
  always an owner, so its own read sessions refused every append. They are now
  released when the job is created; later releases find nothing.

With both fixes an append is validated, reserved, pre-staged on the owner and
admitted. Four more gaps stopped it after admission, and are fixed:

- Nothing recorded parent progress. Parent materialization, owner adoption and
  point staging move the coordinator's journal through sequences 1 to 3, but
  admission leaves the consensus cleanup lifecycle `Admitted` with no
  watermark, and every owner's recovery capsule install requires the
  consensus watermark of the staged point. The journal resume only works after
  the decision (it requires an aborted or committed lease) and only advances
  an existing watermark. The journal now has
  `next_private_oram_mutation_parent_progress_before_decision_v2` (valid while
  the admitted lease is preparing over the exact old state, starting at
  sequence 1), and the coordinator, and its restart reconciliation, propose
  one step at a time until consensus holds the journal's watermark.
- Owner adoption deleted the finalized reservation's resolution record as
  residue (`require_no_active_reservation_fence_locked`), but the reservation
  outcome is acknowledged only after point staging and recovery readiness,
  and that acknowledgement re-proves the installed reservation from this
  record. Adoption now only checks that no fence is active; cleanup and the
  next reservation fence still clear the residue.
- Nothing committed. `ApplyPrivateOramMutation` is refused once the collection
  holds V2 authority state, and the V2 `ConsensusCommit` material operation
  had a builder but no caller. After readiness and the outcome
  acknowledgement, the coordinator now proposes the admitted plan's exact new
  state over its exact old state; the lease becomes `ConsensusCommitted` in the
  same apply.
- The supervisor's restart reconciliation re-ran parent materialization and
  owner capsule installs after the commit, which can never succeed (the
  installs require a preparing lease over the old state), so it never reached
  the terminal resume. It now returns early once the recovery-readiness
  certificate is recorded.

With these the append commits: the supervisor's terminal resume records the
decision, the owner terminals and the point resolution, then the cleanup
witness and clear, and a mutation session opens on the appended signed state
while the genesis state is refused.

On three TLS peers with a replica each the same append commits through two
remote owners (`test_private_oram_paired_append_commits_on_every_owner_over_tls`).
Three more gaps showed up once Raft leadership or the coordinator process
changed while an admitted append was in flight, and are fixed:

- The coordinator acknowledged its own reservation outcome only while it led
  Raft (`require_private_oram_activation_coordinator_is_local_leader`), so any
  election after admission failed the live job before its commit. Applying
  the append's material entries (about 300 KB each) can stall a debug build
  long enough for a follower to start one. The acknowledgement carries the
  owners' signed resolution receipts, which consensus validates regardless of
  the proposer, so an admitted mutation's outcome is now acknowledged by its
  lease owner (`PrivateOramReservationAckProposerV3::AdmittedLeaseOwner`);
  pre-admission acknowledgements stay with the leader.
- A live handoff that failed after admission left its job in a pending phase,
  and the supervisor skips collections with a pending job, so nothing ever
  committed. The job now moves to `AdmittedRecovery`, which the supervisor
  takes over and local cleanup accepts.
- Nothing committed after a coordinator restart either: the restart
  reconciliation derived its plan with
  `derive_private_oram_mutation_admitted_recovery_plan_v2`, which accepted
  only a committed lease, and it stopped at the acknowledgement. The
  derivation now also accepts the preparing lease over the exact old state,
  and the lease owner's supervisor
  (`reconcile_private_oram_admitted_to_commit_v2`) re-runs the steps before
  readiness while readiness is not certified, acknowledges the outcome and
  proposes the commit. The commit is idempotent (a second proposal is refused
  in apply and finds the commit applied), and the supervisor leaves a
  preparing lease alone while this process's live job is deciding.

`test_private_oram_paired_append_commits_across_a_leader_change` freezes the
coordinator (SIGSTOP) right after admission until a follower leads, and
`test_private_oram_paired_append_commits_after_the_coordinator_restarts` kills
it at the crash points `mutation_v2_after_admission` and
`mutation_v2_before_consensus_commit` and restarts it; every case commits.
Mutation sessions are coordinated by the current leader, so clients must route
`open` to the leader `GET /cluster` reports; the old leader answers with a
precondition failure.

The decision itself (`decide_private_oram_admitted_mutation_v2`, taken by the
live handoff and by the supervisor alike) proposes a commit only while the
lease consensus holds is valid. It uses a coherent state-and-lease projection
to confirm the exact committed state, receipt and immutable lease identity,
allowing only monotonic renewal evidence. Unexpired admitted mutations can
still finish after a leader change or restart.

Once the lease has expired, the mutation remains `Preparing` and requires
authorized recovery. Expiry alone supplies neither canonical owner abort
intent nor a durable abort policy; production proposal paths continue to
reject `AbortDecided`. Both the old and new state remain closed to new mutation
sessions, and no further generation is admitted. Existing durable abort
decisions remain readable by terminal recovery. This intentionally preserves
the abort-authority contract in [ckks.md](ckks.md), rather than treating a
timeout or expired lease as permission to roll back owner stores.

`test_private_oram_paired_append_stays_fenced_after_its_signed_lease_expired`
shortens the mutation lease with the test-only
`QDRANT_PRIVATE_ORAM_TEST_MUTATION_LEASE_SECS` (crash-point builds only), kills
the coordinator before its decision and restarts it after expiry. It checks
that repeated supervisor scans retain the same old state and preparing lease,
and that neither state can open a new session. An admitted mutation whose
readiness can never be certified also stays blocked.

The live handoff has test-only points (feature `private-oram-crash-points`)
after admission, after the parent materialization, after the owner adoption,
inside readiness after the capsule installs, before the outcome
acknowledgement and before the decision. `QDRANT_PRIVATE_ORAM_CRASH_POINT`
kills the coordinator there; `QDRANT_PRIVATE_ORAM_FAULT_POINT` makes the step
return an error once per process, as a timed-out proposal or a leader change
does. `test_private_oram_paired_append_recovers_a_failed_live_handoff` fails
the handoff at every point and the supervisor commits in the same process each
time. `test_private_oram_paired_append_commits_after_the_coordinator_restarts`
kills the coordinator at every point and restarts it; every point but one
commits. After a restart that follows the parent materialization, the admitted
reconcile's re-validation of the retained owner prepare
(`validate_private_oram_append_owner_prepare_from_durable_recovery_v2`) fails
with a mutation contract error on every supervisor pass, so the append stays
blocked; that case is marked as an expected failure until it is fixed.
`test_private_oram_paired_append_commits_through_repeated_leader_changes`
freezes whichever peer leads four times while the handoff and the recovery run.

The three-peer TLS append also runs on trees of height 4 (both indexes; the
client's `build` takes a `tree_height`, and the HNSW build reserves every slot
but one dummy so both indexes declare the same logical capacity). In the debug
build it completes in about 2-3.5 minutes. At height 5 each material entry of
a few hundred KB takes 2-7 s to apply on every peer, long enough to trip the
election timeout again and again, and the append does not finish within five
minutes. A `perf` profile of the coordinator puts most of the time in base64
decoding, deserializing the owner bucket batches, UTF-8 checks and hashing of
the append material, all unoptimized in a debug build; every Raft state save
also re-validates the whole private ORAM state (about 0.2-0.6 s) and rewrites
a 650 KB state file.

## Risks and open questions

- The floor-aware Initialize is new consensus behavior: needs the version gate,
  snapshot acceptance review (`plan_private_oram_mutation_authority_floor_acceptance_v2`)
  and a restart/replay test.
- Non-empty legacy owner stores: import is undefined; enrollment requires an
  empty owner namespace.
