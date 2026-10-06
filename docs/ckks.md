# qdrant-sec encryption boundary

The `sec` branch adds a small `qdrant-sec` workspace crate for encrypted
payload text and OpenFHE CKKS vector ciphertext envelopes.

Current scope is encrypted storage plus CKKS sidecar search. Payload text
encryption happens before storage. CKKS vector selectors have a server-side
ingest/storage path:
selected dense vectors are encrypted through the configured OpenFHE bridge and
stored as reserved payload sidecar envelopes, while the plaintext vector is
removed from the dense vector write. REST/gRPC nearest-neighbor `search` and
root direct `query` over an encrypted vector name use sidecar scoring that first
asks the OpenFHE bridge to encrypt the query vector, then scores stored
ciphertexts against that encrypted query ciphertext. When `hnsw_ef` is provided
on a raw dense or stored point-id nearest-neighbor request, Qdrant uses an
existing segment-native or persisted experimental ciphertext sidecar candidate
graph and searches it with encrypted query scores; otherwise it uses the exact
brute-force sidecar scan. The same
sidecar scorer also handles root direct `query` and `query/groups` requests
that use a point id as the nearest-neighbor query. Qdrant loads that point's
stored CKKS sidecar envelope
and asks the bridge to score stored ciphertexts against it without reading a
plaintext vector. The same sidecar scorer also handles raw-dense recommend requests
(`average_vector`, `best_score`, and `sum_scores`), legacy discover requests
and universal discover/context requests with raw-dense or point-id
target/context examples.
REST/gRPC universal `query`/`query/groups` and REST/gRPC legacy
`search`/`search/groups` nearest-neighbor requests may also provide a
client-supplied CKKS encrypted query ciphertext envelope. Qdrant
validates the envelope version, scheme, allowlisted profile, context digest, and
slot count against the active vector rule, then sends the ciphertext directly to
`score_encrypted_query_batch` without asking the bridge to encrypt a plaintext
query. Score decryption and reuse of Qdrant's plaintext-vector `HNSWIndex` file
format for CKKS ciphertexts remain out of scope. The experimental sidecar HNSW
path now uses a segment-level CKKS ciphertext vector index primitive; that
primitive can expose and persist its graph as a segment index artifact, while
the serving query path still sources encrypted records from the reserved
payload sidecar.

Unsupported search/index features for CKKS ciphertext vectors in this branch:

- reuse of the plaintext-vector `HNSWIndex` graph file format directly over CKKS ciphertext
- quantization over CKKS ciphertext
- recommend/discover/context flows that require client-supplied encrypted query
  ciphertexts or server-side vector arithmetic over encrypted values
- grouped lookup that requests encrypted vectors from the lookup collection
- payload filtering over encrypted metadata
- shard transfer or snapshot restore without matching runtime keys and OpenFHE
  context material

## Feature support matrix

This branch is intentionally fail-closed for encrypted data paths that are not
fully wired. The table below is the user-facing contract for the current
implementation.

| API/path | Server-side payload AEAD | Client-side payload envelope | CKKS vector envelope |
| --- | --- | --- | --- |
| `upsert` payload/vector | Supported for selected JSON string fields. Values are encrypted before storage and client-supplied `$qdrant_sec` markers are rejected. | Supported for selected fields that already contain a valid `$qdrant_client_aead` marker. Qdrant validates schema, AAD metadata, key policy, and a mandatory Ed25519 signature, but does not decrypt. | Supported for selected dense vectors. Qdrant encrypts through the OpenFHE bridge, stores `$qdrant_sec_vectors` sidecar payload envelopes, and removes plaintext vectors from dense vector storage. Sparse and multi-dense encrypted vectors fail closed. |
| `set_payload` / `overwrite_payload` | Supported for explicit point ids when Qdrant can bind AAD to each point id. Multi-point updates are fanned out into one encrypted operation per point; filter-based and key-path encrypted-field updates fail closed. | Same explicit-point-id limitation as server-side payload writes. Clients must provide one envelope per point/field; filter-based and key-path encrypted-field updates fail closed. | Not applicable. |
| `update_vectors` | Not applicable. | Not applicable. | Supported for point-specific dense vector updates by writing the encrypted sidecar payload and omitting the plaintext vector update. Sparse and multi-dense encrypted vectors fail closed. |
| Payload indexes, filters, facets, ordering, grouping, and formulas | Plaintext indexes, read/update filters, facet keys, order-by keys, group-by keys, and formula payload references over encrypted paths, parent paths, child paths, or `metadata/aes-256-gcm@v1` metadata value paths are rejected. Exact-match search can use a separate client-generated blind-index token field configured through `metadata/blind-index-hmac@v1`; encrypted content itself is not indexed. | Same policy. The opaque ciphertext field is not searchable, orderable, groupable, facetable, or usable in mutation filters as plaintext. Exact-match search requires a separate blind-index token field. | The reserved `$qdrant_sec_vectors` sidecar field is not indexable, filterable, orderable, groupable, facetable, or usable in formulas. Payload filtering/faceting over encrypted metadata is unsupported unless it uses a separate blind-index token field. |
| `retrieve`, `scroll`, `search`, and `query` result payloads | Stored `$qdrant_sec` markers are returned raw by default. REST/gRPC `retrieve`, `scroll`, legacy `search`, batch search, universal `query`, batch query, `recommend`, batch recommend, `discover`, batch discover, and grouped result hits may use `{"encrypted_payload":"decrypted"}` to decrypt server-side payload text and metadata value AEAD fields only when runtime crypto settings are available and the caller has global manage access or collection `payload_decrypt` capability; the same mode fails closed without runtime settings or sufficient privilege. REST payload selectors may use `{"encrypted_payload":"redacted"}` to return payloads while replacing encrypted marker values with redaction sentinels. Group lookup payloads remain raw/redacted only because they may come from a different collection. | Stored `$qdrant_client_aead` markers are returned raw by default for SDK/client decryption, or redacted with the same `encrypted_payload` selector. Qdrant never decrypts client-side envelopes. | Stored vector sidecar payload envelopes are returned raw by default when payloads are requested, or redacted with the same `encrypted_payload` selector. Read/search/query/recommend/discover paths, including grouped variants, reject `with_vector=true` or selectors that request encrypted vector names; clients must request the payload sidecar instead. REST/gRPC nearest-neighbor dense-vector `search`, `search/groups`, REST/gRPC legacy client-encrypted nearest `search`, REST/gRPC legacy client-encrypted nearest `search/groups`, root direct `query`, root direct point-id nearest `query`, root direct REST/gRPC client-encrypted nearest `query`, root direct `query/groups`, root direct point-id nearest `query/groups`, root direct REST/gRPC client-encrypted nearest `query/groups`, root direct `NearestWithMmr` and `NearestWithMmr` query groups, `search/matrix`, raw-dense/point-id `recommend` (`average_vector`, `best_score`, `sum_scores`), legacy `discover` with raw-dense or point-id target/context examples, and universal `discover`/`discover groups`/`context`/`context groups` queries with raw-dense or point-id target/context examples are supported with runtime OpenFHE settings. Batch search/query/recommend/discover may mix encrypted vector names and plaintext vector names; each request is routed independently and output order is preserved. Nearest-neighbor requests may set `hnsw_ef` to use the ciphertext sidecar candidate graph for raw dense query vectors, client-encrypted query ciphertexts, and stored point-id query vectors; exact requests and non-HNSW requests use brute-force sidecar scoring. Matrix requests sample stored sidecars and score pairwise stored ciphertexts. Universal query prefetches over encrypted vector names are supported for RRF/DBSF fusion and as non-fusion candidate filters for encrypted or plaintext root queries. MMR uses query-to-candidate CKKS scores for relevance and candidate-to-candidate CKKS scores for diversity on large-better metrics. Client-encrypted query envelopes fail closed when `cluster.enabled=true` until a consensus-backed query nonce replay ledger exists. Quantization/ACORN/indexed-only search params remain unsupported. |
| Snapshots | Snapshot archives are expected to contain envelopes only; payload sentinel snapshot leakage is covered by integration tests. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings, including missing material, wrong wrapped-RK key, and provider key-id mismatch cases. | Same stored-value behavior as server-side payloads. Qdrant cannot validate client AEAD tags without client keys. | Restore requires matching OpenFHE context/runtime material. Missing runtime instance/material/backend and invalid OpenFHE public-material preflight are covered; valid-but-different context drift is enforced by runtime capability parity and envelope `context_digest` checks when sidecars are opened/scored. |
| Shard transfer / replication | Encrypted collection data-movement operations require matching non-secret crypto runtime capability fingerprints in peer metadata. Operations fail closed if any involved peer has missing or mismatched metadata. Automatic dead-replica recovery only proposes encrypted shard transfers from source peers with matching parity metadata. | Same policy; client-envelope verifier policy must match across nodes before encrypted transfers are allowed. | Same policy; matching OpenFHE context and metadata AEAD material must be enforced before encrypted transfers are allowed. |
| Metadata encryption | `metadata/aes-256-gcm@v1` supports selected JSON string metadata values with `metadata-value/v1`; these values use the same server-side AEAD envelope, fail closed for plaintext indexing/filtering, and participate in `encrypted_payload:"decrypted"` reads under the same `payload_decrypt` access policy. `metadata_keys` selectors also support client-generated exact-match blind-index token fields with `metadata-exact-match-token/v1`. | Client-side metadata value encryption should use `payload/client-aead@v1` on the metadata field plus a separate blind-index token field for exact match. Qdrant stores opaque blind-index tokens and never computes them. | CKKS vector metadata sealing is separate from payload metadata value encryption. |

`vector/private-hnsw-oram@v1` is stricter than the generic encrypted
data-movement policy above. Every peer that owns any fully-active shard replica
holds the same collection-global encrypted ORAM store. Fixed-layout manual
movement and automatic dead-replica recovery move one shard at a time through
`stream_records`, source-side signed full-store preinstall, and a verified
transfer marker. An exact restart of the sole active marked `stream_records`
transfer and an exact reserved single-`Active` replica removal are also
supported.

Typed scale-up and scale-down resharding use the same encrypted-store ownership
contract. Start reserves every configured private HNSW/result index and binds
the expected and next layout to the current epoch/root/writeback state.
Point migration is accepted only as a source-coordinated
`ReplicateShard(resharding_stream_records)` that exactly matches the active
`MigratingPoints` state, shard key, source/destination shards and peers,
replica endpoint states, `sync=true`, no filter, and no independent layout
transition. The coordinator preinstalls every configured encrypted ORAM store
before adding `private_oram_preinstalled`. The marked resharding stream may
submit only its normal `UpsertPoints` migration batch; the fixed-layout
`stream_records` exception remains limited to `SyncPoints`. New sessions and
writebacks remain blocked from start through finish. Finish revalidates the
stable final topology and advances the collection-level layout generation
before applying the final reshard metadata.

`ReplicatePoints`, unmarked or unrelated reshard transfers, mismatched or
method-changing reshard-transfer restart, non-`Active` shard-key creation,
final shard-key deletion, dead or transitional replica removal, batch removal,
final-replica removal, and shard snapshot export/recovery remain fail closed.
Raft snapshot apply accepts an
active private ORAM reshard for an existing local collection only when its
stable crypto identity, configured private index keys, sharding method,
replication factor, consensus epochs, and canonical pre-reshard layout match
the incoming snapshot. The current collection must be either the exact stable
pre-layout or the same reshard key at an equal or earlier stage without
active-replica regression. Scale-up may add exactly one typed target shard;
scale-down keeps the pre-finish shard count. Exact marked reshard transfers are
the only transfer records accepted in this state.

All incoming private ORAM epoch, lease, and layout maps are schema-validated
before collection mutation. The incoming layout must bind the canonical owner
union, shard-layout digest, and configured index epoch/root digest. An existing
local layout must match exactly; only a missing layout for an existing
collection may initialize from incoming generation 1. A peer without the
collection may bootstrap a later active-reshard snapshot in three bounded roles.
A topology-only non-owner must have absent or exactly equal local epoch/layout
entries and must be absent from the pre-layout owner union, all incoming
replicas, and every active transfer endpoint. An exact new scale-up target is
accepted only at `MigratingPoints` when it is absent from the pre-layout owner
union, is the sole `Resharding` replica of the typed target shard, and is the
destination of the sole exact marked incoming transfer from an active source.
An erased redundant pre-layout owner is accepted only at `MigratingPoints`
when it is not an active transfer endpoint and every pre-layout shard it owns
has another `Active` replica. A designated scale-down endpoint is included
only after all reshard transfers are gone, every replica is `Active`, and that
peer owns the shard being removed. The endpoint may own additional pre-layout
shards only when each local shard has another `Active` replica. Before creating
the empty local collection, snapshot apply persists an exact reshard recovery
marker. While the marker exists, normal local-state sync is suppressed and the
restarted peer repeatedly requests abort of only that reshard key. After the
abort is committed it removes the marker and uses normal automatic private
ORAM shard recovery. Each missing shard replica advances its own precommitted
layout generation only when the existing owner union, shard-layout digest, and
index-state digest exactly match that transfer's pre-layout.
Snapshot apply creates collection topology but no private ORAM store and never
starts a transfer task. Sessions remain blocked while the target sends a
rate-bounded internal resume request to the source. The source accepts it only
for the exact current marked transfer whose local task is missing, then reuses
`RestartTransfer` to acquire fresh reservations, reinstall every signed
encrypted store, and restart point migration. A non-redundant pre-layout
owner or transfer source, scale-down endpoint before transfer completion,
already-active target, or target with a missing or ambiguous transfer continues
to fail closed because a Raft snapshot carries neither encrypted ORAM buckets
nor point shard data. A fresh fixed-layout `Partial` target that was not a
pre-layout owner may use the exact full-store resume protocol described below.
A redundant fixed-layout
transfer source or owner can instead force an exact transfer abort before
stable recovery when every local shard has another `Active` replica. Another
reshard key, committed stage, unsupported transfer, or unrelated topology
change also fails closed.
An explicit exact `RestartTransfer` remains an operator fallback. Sessions
remain blocked throughout the active reshard.

### Private ORAM v2 development boundary

The v1 private HNSW and result ORAM providers remain read-only bulk-built
contracts. Dynamic insertion changes signed occupancy, HNSW state, optional
result state, and client recovery state together, so it will use new
`vector/private-hnsw-oram@v2` and `payload/private-result-oram@v2` providers
rather than changing v1 in place. V2 is limited to fixed-capacity append-only
insertion with one logical writer. Update, delete, tree resize, and concurrent
writers remain out of scope.

V2 separates immutable index policy from mutable state. The owner-signed
immutable manifest defines the complete canonical private index set, each
index's HNSW/ORAM parameters, physical bucket layout, logical capacity,
reserved physical slack, client stash bound, and exact padded append
read/write budget. Mutable state is represented by one collection-wide
`PrivateOramSignedStateV2`, not independent HNSW and result manifests. It binds
the immutable manifest digest, stable collection and layout identity,
monotonic state sequence, every index epoch/root and logical/dummy occupancy,
the last writeback digest, the digest of the complete encrypted client
checkpoint set, and the last mutation id.

An append must move the entire configured index set from one signed state to
the next:

- the state sequence and every participating index epoch advance by exactly one
- all participating indexes have the same immutable logical capacity and
  occupancy, so one append cannot omit a configured private vector or result
- every logical occupancy increases by one and every dummy occupancy decreases
  by one, while their sum remains the signed logical capacity
- every root, last-writeback digest, and encrypted client-state-set digest
  changes
- HNSW and optional result state are committed by one collection-wide CAS
- every index records exactly the manifest's fixed append path count and a
  server-observed ordered read-transcript digest; path multiplicity is
  preserved, duplicate paths are not collapsed, and every contiguous request
  window contains exactly the manifest ORAM `path_batch_size`
- each index writeback contains exactly
  `fixed_append_read_path_count * (tree_height + 1)` bucket occurrences,
  framed root-to-leaf in the server-observed leaf order; duplicate bucket ids
  remain in signed frame order, including padded dummy re-encryption

`private-oram-mutation/v1` signs the mutation id and expiry, exact old and new
signed states, the consensus-issued writer lease digest and monotonic fencing
token, a point-operation kind and digest, and the fixed padded HNSW/result
writeback batches. The per-index writeback digest additionally binds the index
identity, old/new epoch and root, fixed read path count, read transcript
digest, bucket ids, ciphertext SHA-256 values, and bucket commitments. The
read transcript is bound to collection, immutable manifest, mutation id,
exact old-state digest, writer lease/fence, manifest `path_batch_size` and
tree height, index identity, contiguous request-window sequence, and every
ordered leaf label. Each leaf must be in `0..2^tree_height`, and the manifest
rejects append path counts that do not divide exactly into fixed-size
windows. This avoids circular signing: each state signature is
verified independently, while the mutation signature binds canonical SHA-256
digests of the state messages and the writeback contents. For
`private_payload_oram_required`, the manifest itself forces
`no_server_point_record`; caller-supplied validation context cannot downgrade
it to a visible point operation. For `ids_visible`, the validator derives the
digest from collection/manifest/mutation identity, canonical point id, and
the SHA-256 of the exact D3 durable staged InsertOnly frame; it does not accept
an arbitrary caller-selected digest. D1 accepts only `f32_le` HNSW vectors.
`docs/qdrant-sec-private-oram-mutation-signature-test-vector.json` freezes the
full paired HNSW/result manifest, old/new state, and append-mutation DTOs plus
canonical bytes for both read transcripts, both writeback digests, and both
point-operation modes. It also freezes message digests, Ed25519 signatures,
lengths, and the deterministic public key.

Canonical encoding is independent of JSON serialization:

- the domain is `u32_be byte_length || raw domain bytes`
- a UTF-8 string is `u64_be byte_length || raw UTF-8 bytes`
- scalar integers are fixed-width big-endian; booleans are one byte (`0` or
  `1`); an optional string is a one-byte presence tag followed by the string
- a vector is `u32_be element_count` followed by its elements; no map encoding
  is used
- index tags are HNSW=`1`, result=`2`; point-operation tags are
  visible-record=`1`, no-server-record=`2`; result-privacy tags are
  ids-visible=`1`, private-payload-ORAM=`2`
- vector encoding tags are f32-le=`1`, i8=`2`, PQ=`3`, binary=`4`; distance
  tags are cosine=`1`, dot=`2`, Euclid=`3`, Manhattan=`4`; Path ORAM is `1`
- index-bearing vectors are strictly sorted by `(kind tag, raw UTF-8 index
  name)`; bucket references retain root-to-leaf frame order and duplicates,
  while read windows and leaf labels retain submitted order and duplicate leaf
  labels

Bucket occurrences are applied in signed frame order. When a bucket id occurs
more than once, its last occurrence supplies the final ciphertext and
commitment used by the sparse Merkle patch and durable bucket write.

The manifest message field order is domain, version, collection id, manifest
nonce, index count and indexes, result privacy, owner signing key id, and
creation time. Each index is kind, name, kind-specific parameters, then
capacity. HNSW parameters are provider, binding, key/rk ids and epoch,
dimension, vector/distance tags, HNSW values, ORAM values, fixed search
budget, and maximum neighbor rewrites. Result parameters omit HNSW-specific
values. Capacity is bucket count, logical capacity, reserved physical slots,
stash bound, fixed append read path count, and fixed append write bucket
count.

The signed-state message field order is domain, version, collection id,
manifest digest, layout generation/digest, state sequence, index states,
client-state digest, optional last mutation id, owner signing key id, and
signed time. Each index state is kind, name, epoch, root, logical/dummy
counts, and last writeback digest.

The mutation message field order is domain, version, mutation id, collection
id, manifest digest, layout generation, writer lease digest/fence,
issued/expiry times, SHA-256 base64url digests of the old/new canonical state
messages, point-operation tag/digest, writebacks, and owner signing key id.
Each writeback is kind, name, read path count/transcript digest, then bucket
references; each bucket reference is id, ciphertext SHA-256, and commitment.
Signatures are Ed25519 over these bytes and use unpadded base64url on the wire.
The read-transcript message order is domain, collection/manifest/mutation/old
state identity, writer lease/fence, paths per window, tree height, index
identity, then ordered windows and ordered leaf labels. The visible point
record digest orders domain, collection, manifest, mutation, point id, and
staged InsertOnly SHA-256; the no-server-record digest omits the final two
visible-record fields. Immediate reuse of the prior mutation id and a new
state signed later than server validation time fail closed. D2 consensus keeps
the exact latest mutation receipt. An exact retry succeeds only while that
resulting collection state is still current, including after its lease is
cleared or while the next mutation is only preparing. Once a later mutation
advances the state, an older retry is stale. Perpetual historical deduplication
would require a separate receipt ledger and is not part of v2.

In this contract, append-only means that one new logical point is added.
Bounded backlink and neighbor-block rewrites required by HNSW insertion are
allowed inside the signed fixed budget. Updating or deleting an existing
point, standalone graph rewiring or compaction, capacity resize, and rebuild
swap remain unsupported.

The activated server implementation uses a dedicated private mutation
point-staging store instead of the ordinary point WAL. The ordinary update path
can enqueue an operation before the collection-wide crypto CAS and does not
provide the required explicit pre-CAS fsync boundary. The coordinator will
therefore prepare all index owners, fsync the exact InsertOnly point operation
in invisible staging, perform one consensus CAS, then finalize remote owners
before the local owner. A live or expired-but-unreconciled mutation lease
fences search, external recovery, snapshots, transfer/resharding, and
collection lifecycle changes.

D3-B1 provides the collection-local parent mutation journal used to recover
that sequence. Its immutable descriptor binds the exact signed mutation,
canonical mutation digest, preparing D2 lease, complete expected old consensus
record, coordinator, and canonical owner/index cross-product. This explicit old
record is required for non-genesis transitions because the signed client state
does not contain the prior consensus receipt. The mutable record permits only
`LeaseAcquired`, `OwnersPrepared`, `PointStageDurable`, `ConsensusCommitted`,
`RemotesFinalized`, `LocalFinalized`, and `Complete`, in that order. It derives
point-operation and consensus receipt/record/transition evidence from the
signed mutation instead of trusting caller-selected digests, and records remote
finalization before local finalization. The point-stage transition now accepts
only an opaque token returned after validating and durably installing the exact
child artifact; callers cannot supply raw point IDs or frame digests as durable
evidence.

D3-B2 implements that child point stage in two layers. The shared canonical
InsertOnly frame is a strict, at-most-64-MiB binary encoding bound to the
collection, mutation, old/new signed state, writer lease/fence, canonical shard
route, point operation, and an empty server-vector set. The collection-local
`private_oram_point_staging/active` directory stores a canonical descriptor,
the exact frame, and a Prepared-only state. Its descriptor binds both the
immutable parent descriptor and the exact `OwnersPrepared` chain-tip digest.
The parent records the child descriptor, frame and canonical point-ID digests
only through the returned durable token. Exact replay is idempotent; another
frame, parent tip, or child digest is rejected.

Point-stage publication writes and fsyncs new owner-only files in a randomized
direct-sibling candidate, fsyncs the candidate, installs it with Linux
`renameat2(RENAME_NOREPLACE)`, fsyncs the pinned root directory descriptor, and
reopens the installed artifact. Files and directories are bounded, no-follow,
same-inode checked, owner-only, and reject hard links, special files, unexpected
entries, nonempty internal temp state, malformed canonical bytes, and any phase
other than Prepared. A candidate stranded before rename is preserved and
ignored rather than adopted; unknown or symlinked candidates fail closed.

This stage is a durability boundary, not an additional confidentiality layer.
Its frame can contain the visible point ID and payload representation, so D4
must apply the collection payload-encryption policy before staging. The host
storage is assumed to be an owner-only local Linux filesystem that provides
durable file and directory fsync plus `RENAME_NOREPLACE`; unsupported platforms
or filesystems fail closed. Private vector bytes are always rejected.

D3-B3-A1 adds an exact reconciliation classifier over the durable parent,
current collection consensus record, and current active mutation lease slot.
It validates generation/max-fence equality, immutable lease identity, monotonic
renewal, parent phase, and any already-recorded committed renewal. Exact new
state with the exact `ConsensusCommitted` lease is finalize authority. Mixed
old/committed or new/preparing state, unrelated records, missing/cleared slots,
ABA generations, and lease-renewal rollback fail closed.

Exact old state with a `Preparing` lease is deliberately returned only as
`ObservedOldNeedsAbortDecision`. It is not abort authority: after a submit
timeout, a delayed Raft entry can still commit the mutation. D3-B3-A2 adds a
consensus-linearized `Preparing -> AbortDecided` lease transition that is valid
only while the collection remains exact old. The decision preserves the exact
lease identity, generation, max writer fence, last-clear receipt, expiry, and
renewal revision. Its idempotent replay revalidates the current state-slot
relationship. Direct `Preparing -> clear`, phase escape, and mutation apply
after the decision fail closed; same-phase renewal remains available while
durable abort cleanup runs. Only exact old plus this phase is returned as
`ExactOldAbortDecided` abort authority.

`AbortDecided` is a new named serde variant in Raft entries, persistent state,
and snapshots. It must not be proposed until every peer advertises support for
both the variant and the strengthened clear transition, and downgrade is not
supported while the phase remains active or appears in retained snapshots.
After proposal timeout, a local state getter is not an apply barrier: recovery
must resubmit the exact CAS through Raft and inspect state plus slot under one
read guard before using the classifier.

The D3-B3-A3 parent-owner recovery slice now makes that read-guard requirement
structural. `ConsensusManager` captures the collection consensus state and
mutation lease slot into an opaque snapshot while holding one persistent read
guard. The parent journal's raw state/slot validator is module-private, and the
restart authority path accepts only this paired snapshot plus an owner peer
identity supplied by a future authenticated local or transport boundary.

The resulting content-manager-only authority binds the parent descriptor,
stable LeaseAcquired and OwnersPrepared records, exact old or committed-new
consensus record, immutable lease identity and phase, selected owner, canonical
per-index requirement and Prepared digest, and signed mutation bundle. Its
domain-separated digest deliberately excludes the mutable parent tip, lease
expiry, and renewal revision after validating renewal monotonicity. Exact replay
therefore remains stable across same-phase lease renewal and later parent phase
progress. Unknown owners and parents that have not reached OwnersPrepared fail
closed, and a known-answer test pins the digest encoding.

This remains parent coordination authority, not child durability evidence.
Parent Prepared digests are still untrusted strings until an owner reopens the
exact child journal under its shared lock and recomputes every per-index
Prepared evidence value. `ObservedOldNeedsAbortDecision` remains observation
only and cannot authorize an abort terminal. The dormant child-rebind foundation
now performs that exact reopen, but no production RPC, store classifier,
terminal recorder, or public route consumes the resulting recovery path yet.

The legacy per-index HNSW/result pending journals also cannot directly supply
V2 parent evidence. Their digest/signature domains use a unique bucket set,
while V2 append signs ordered Path ORAM occurrences and allows repeated bucket
IDs whose last occurrence forms the final image.

D3-B3-B1 now provides a server-safe owner-prepare wire package. It contains the
signed mutation bundle, each manifest-order sequence of encrypted bucket bodies,
and the corresponding sparse Merkle patch proof. It omits the encrypted client
checkpoint, position map, stash, graph delta, result record, recovery marker,
final client state, and any client-claimed read transcript. The owner validator
matches every body to the signed occurrence before duplicate collapse, checks
the fixed ciphertext size, hash, commitment, and inner AEAD version for both
HNSW and result buckets, requires the proof leaves to be the exact sorted unique
updated bucket IDs, and verifies the old-to-new sparse Merkle transition. Its
opaque output retains the signed ordered references and the bucket-ID-sorted
last-occurrence final image; it does not expose the raw prepare request.

Authoritative read evidence is also a non-serializable capability. A server
append session creates an in-memory recorder, records the exact accepted read
windows through it, and passes both that recorder and its evidence to owner
validation. Evidence issued by a different recorder is rejected even when its
transcript bytes are identical. The capability is intentionally not durable:
after a server restart, reads that had not reached durable owner prepare must be
performed again. D4 must connect the recorder to the actual read handler and
session registry before enabling admission; client SDK output cannot mint the
server session capability.

D3-B3-B2 now persists the Prepared portion of a paired V2 owner journal below
the primary HNSW store's existing `temp` snapshot gate. One immutable descriptor
binds the exact parent descriptor and lease-acquired record, owner peer,
mutation/lease/fence identity, all manifest-order signed bucket occurrences and
read transcripts, and the bucket-ID-sorted last-occurrence final references. A
single canonical frame retains the encrypted final HNSW buckets and optional
result buckets. Prepare does not modify canonical bucket, Merkle, epoch, or
point files.

Publication requires an owner-only local Linux filesystem, mounted procfs
fd-relative access, durable file and directory fsync, `RENAME_NOREPLACE`, and
cooperation by all journal writers with the root advisory lock. Candidate and
installed directory identities remain pinned while the files, empty temp
directory, active directory, and root directory are synced. The implementation
then rereads every pinned file for an exact byte match and rechecks all active
and root entries before issuing a crate-private durable token. Exact replay can
return the same token; unknown entries, symlinks, hard links, unsafe modes, and
same-inode content changes fail closed.

Structural inspection deliberately returns only a self-consistent untrusted
snapshot and cannot mint evidence. It takes a shared root advisory lock, so a
terminal publish cannot be misclassified as structural corruption midway
through inspection. Token issuance remains crate-private. D3-B3-B3 now
recomputes and rebinds exact child Prepared evidence to the parent projection,
while canonical-store, manifest, authenticated transport, and terminal
authority remain separate fail-closed gates.

The journal now also supports an append-only sequence-2 `Finalized` or
`AbortedOld` terminal record without replacing the Prepared state. The two
phases use distinct canonical domains and bind the immutable owner descriptor,
Prepared-state digest, parent descriptor, authenticated owner peer, stable
consensus-authority record, reconciliation authority, and one ordered
canonical-state digest for every descriptor index. They do not use the mutable
parent current-record digest as replay identity. Exact replay returns the same
terminal token; phase, authority, owner, index identity, order, or canonical
state substitution is rejected.

Terminal publication writes a randomized candidate below the active temp
directory, fsyncs its record and directory, and installs the candidate across
directories with `RENAME_NOREPLACE`. It then verifies candidate/installed inode
continuity, rereads the exact canonical bytes, and fsyncs the terminal, temp,
active, and root directories before returning. Partial stranded candidates are
preserved but never adopted. Unknown entries, symlinks, hard links, unsafe
modes, oversized records, and terminal tampering fail closed.

The D3-B3-B2 StoreInspector sub-slice now adds phase-specific exact-old and
exact-new verification inside both canonical stores. Under a nonblocking root
exclusive lock it validates the signed store manifest and runtime context,
current epoch, complete Merkle leaf vector/root/count, epoch-directory shape,
target commit, and each mutation-affected bucket's fixed ciphertext size,
commitment, and Merkle leaf. Exact-old additionally requires the new commit to
be absent and accepts only a digest-bound old commit or the signed initial
manifest anchor. Exact-new requires the digest-bound new commit and exact
full-structure equality with every expected final bucket.

Each verifier rereads the protected state before issuing an opaque canonical
state token. The phase-separated digest binds the owner journal descriptor,
Prepared digest, immutable-manifest digest, index kind and name, signed store
manifest message, old and new states, complete Merkle leaf-array digest, commit
kind, final references, and observed affected bucket bodies. Token lifetimes
are tied to the held lock. Raw contexts, lock acquisition, and verifier entry
points remain module-private. Legacy pending state, future or malformed commit
entries, hard links, symlink or inode drift, and oversized reads fail closed.

This token is canonical logical-state and affected-set evidence, not proof that
every unrelated bucket body remains available. Initial upload or restore must
validate the whole store, and every later V2 writer must preserve the full
bucket/Merkle invariant. A malicious storage host can still cause denial of
service by deleting an unrelated body; its eventual read fails closed.

The D3-B3-B2 live-pair StoreAdapter now rebinds a genuine durable Prepared
token to the journal's current exact Prepared snapshot. It independently
validates the immutable-manifest, append-mutation, old-state, and new-state
signatures, then checks every digest, collection and writer identity, canonical
index order, descriptor transition, writeback transcript, and final bucket
reference. The signed V2 immutable index is also mapped semantically to the
physical V1 HNSW or result manifest instead of treating their provider strings
as directly interchangeable.

The adapter acquires the HNSW store, result store, and journal shared locks in
that fixed order. It invokes its callback only while both exact-state tokens and
the live Prepared binding remain valid. A pair token is issued only when both
stores are exact-old or both are exact-new; a mixed physical state issues
neither. Cross-journal or cross-collection path substitution, signed mutation
substitution, and either signed/physical manifest mismatch fail before the
callback. Seven focused tests cover those cases, both successful phases, and
debug redaction.

The D3-B3-B3 child-rebind foundation adds the restart half of this boundary.
The storage-private typed parent authority projects exactly one authenticated
owner's canonical `Hnsw, Result` requirement and parent-recorded Prepared pair.
The projection is intentionally public only as an immutable cross-crate DTO and
is not authority. Collection reopens the exact nonterminal child under its
shared root lock, recomputes every Prepared digest from the full descriptor,
and compares parent/lease, mutation/lease/fence, index order, epoch/root,
writeback, and Prepared evidence before issuing a non-Clone crate-private
callback binding tied to the real lock lifetime. The binding exposes no
capability accessor, so a callback cannot clone either Prepared capability out
of the lock window. HNSW-only, terminal, reordered, foreign-owner, and
substituted parent/mutation/index evidence fails before the callback; a terminal
writer also cannot publish during the callback.

The D3-B3-B3 slice now adds a dormant read-only four-state classifier. A
storage-private wrapper takes `&PrivateOramValidatedOwnerRecoveryAuthorityV1`,
projects its canonical pair, and calls a public-hidden collection facade that
returns only inert `AllOld`, `AllNew`, `PartialNew`, or `ThirdState`. Static
signed input and path validation precedes the fixed HNSW -> result -> child
shared lock order. Store inspection authority is derived only from the exact
child's explicitly untrusted structural view while all three locks remain held.
`Old+Old` is all-old, `New+New` is all-new, and only the canonical HNSW-first
`New+Old` prefix is partial-new. All other combinations are third-state.

`Third` has a narrow meaning: a validated current epoch/root pointer matches
neither expected old nor expected new. If a pointer matches old or new but its
manifest, epoch commit, Merkle tree, or affected bucket evidence fails exact
verification, classification returns an error instead of hiding corruption as
third-state. Tests cover the complete 3x3 pair matrix, both stores' manifest,
commit, Merkle, and bucket corruption, HNSW/result/child-lock contention and
error-path lock release, and debug redaction. No store token, child capability,
or lock guard crosses the facade.

This path remains dormant and has no production caller or terminal call. Every
HNSW and result canonical writer now serializes through its owner-root
exclusive lock, including initial/live install, replica operations, recovery,
abort, manifest, bucket, Merkle, and epoch publication. Common initial uploads
preflight and install the complete bucket set and Merkle image in one owner-lock
window instead of reacquiring it per bucket. Exact-state callbacks revalidate
the root identity before returning. Platforms that cannot provide the required
filesystem lock fail closed before a canonical write.

The parent recovery journal also now pins its root directory and lock file by
directory FD. A non-Clone live authority holds that parent lock while checking
the exact consensus/lease snapshot and parent descriptor/state before and after
its callback. Replacing the parent root during the callback is rejected. This
foundation is read-only: the child/store directories and terminal writes are
still pathname-based and are not yet safe against namespace replacement. They
must move to fd-relative operations before activation. The discarded
child-first bridge is not used because it would invert the store-to-journal
lock order.
The owned parent recovery value is sufficient for a non-authoritative read but
not for mutation. Roll-forward and terminal publication require a separate
live-parent transaction ordered parent -> HNSW -> result -> child exclusive.
They must not upgrade the classifier's child shared lock or consume a returned
disposition as authority. A canonical partial-new prefix must roll forward and
reverify all-new inside that mutating transaction. A real cross-crate authority
to projection to child and pair-classifier integration test remains an
activation gate. The terminal bridge must also bind authenticated transport
identity. No current production caller can mint store or terminal evidence from
raw digest strings.

The dormant D3-C2 parent writer now persists fresh V2 progress as an explicit
format marker, one immutable sequence-numbered record per phase, and a
replaceable current-state pointer. It fsyncs and installs the next record with
no-clobber semantics before advancing the pointer. A crash may therefore leave
exactly one pending successor record. Structural load reports that record but
does not adopt it; only a retry carrying the same phase-specific typed evidence
can advance the pointer. A different successor, a history gap, a pointer ahead
of its immutable record, a missing V2 marker, or a mixed V1/V2 layout fails
closed. Active V1 journals require a separate explicit recovery path and are
never translated to V2 terminal state.

Decision records are created only from a collection-state and lease-slot pair
captured under one consensus read guard. The test-only visible-point validator
additionally requires an exact non-Clone durable token, so structural
`PointStageDurable` bytes alone are insufficient in that dormant path. The
point-stage store now serializes prepare, load, and live reopen through an
owner-only `stage.lock`, pins the root through a directory descriptor on Linux,
and exposes the exact frame and durable token only inside a callback-scoped live
authority. Unsupported platforms fail closed before that authority is created.
The resulting non-Clone decision token binds the parent descriptor and the
actual durable predecessor.
Publishing `DecisionDurable` returns a different token bound to that record,
and publishing `RemotesTerminal` returns another token bound to the immediate
remote-terminal record. Thus no earlier token can skip a phase or authorize a
later writer. Publishing `LocalTerminal` returns a non-Clone token bound to the
exact sequence-6 record. That token can advance a no-server-point mutation to
sequence 7. The visible-point receipt sink and its consuming callback remain
test-only until an authenticated, freshness-bound all-replica publisher can
mint the receipt. An exact sequence-7 retry validates the durable parent
evidence before opening the disposable staged child, so cleanup or a lost
response cannot make the same retry fail; different evidence is still rejected.
Typed paired-owner outcomes remain mandatory, and an empty remote batch derives
its kind from live decision authority rather than decoded disk state.

The dormant V1 staged-point codec rejects `Some({})` and accepts `None` as the
only canonical empty-payload representation because ordinary Qdrant storage
normalizes an empty payload to no payload. This is a same-version narrowing and
is allowed only because the provider and codec have never been production
activated. Any deployment that imported pre-activation fixtures must discard
or explicitly migrate them before activation; silently accepting such an
artifact as current authority is forbidden.

Every immutable record, including an unpointed successor, is structurally
validated. Directory iteration stops after the eighth entry and rejects it,
aggregate V2 history is capped at 256 MiB, and file reads enforce their bound
while reading so concurrent growth cannot force an unbounded allocation.
Generic JSON decoding remains streaming to avoid a second descriptor-sized raw
buffer. An exact pending retry always re-runs immutable record publication,
including destination and source-directory fsync, before moving the pointer.
The V2 parent writer is active only behind the dedicated V2 mutation route and
the cluster mutation-format activation floor. Raw parent/evidence constructors
remain private or test-only; production admission consumes live validated owner
prepare evidence. The parent history watermark is persisted in the activated
consensus aggregate, and every local sequence advance must be reflected by the
next exact watermark CAS before another terminal side effect can run. Parent
`active`, `state_records`, `temp`, cleanup marker, and terminal archive operations
use pinned descriptor-relative namespaces on Linux and fail closed elsewhere.

The activated strict subset supports only
`result_privacy=private_payload_oram_required` with a no-server point record.
`ids_visible` mutation is rejected before admission and again during restart
resume. Therefore the visible-point all-replica publish/abort protocol is not an
activation dependency for this subset and remains unavailable rather than being
approximated through ordinary Qdrant point APIs.

The parent descriptor and current-state digest formats have known-answer
tests. Journal files live below a private non-symlink directory, use bounded
owner-only files and same-file checks, and redact identity and digest values
from errors and debug output. State publication fsyncs the candidate, replaces
the current file atomically, then fsyncs the parent directory. A failure that
leaves the old file is definitive; a changed or unknown target, failed
post-publish readback or root validation, and exhausted post-publish parent
fsync are indeterminate. The same rule applies after publishing an immutable
successor record or the staged-point `active` directory. An exact retry can
reconcile a candidate that was already exposed. The typed point-stage token
proves the Prepared child point artifact, and the paired owner journal can now
prove a structurally and durably installed Prepared artifact to crate-private
callers.
The restart supervisor now consumes exact paired canonical-state authority. It
fetches remote terminals over signer-pinned authenticated peer transport,
reconfirms the exact Raft slot after network I/O, recovers the local HNSW/result
pair, and records sequence 4 through 7 one step at a time. The immutable original
lease owner remains coordinator even when it is a follower; this version does
not take over work when that peer is absent.

Follower confirmation has an explicit local-applied barrier. The forwarded Raft
confirmation returns the entry index applied by the calling node, and the
reconcile snapshot is captured only after that node's persistent `last_applied`
has reached the receipt. Terminal resume and archive/ack work are additionally
serialized by collection key, so independently minted supervisor permits cannot
race the same mutation while unrelated collections continue independently.

Local cleanup is a quiescence claim, not a registry deletion. Claiming the exact
generation blocks new jobs, sessions, and phase mutations, waits for the detached
worker liveness guard to end, releases both paired sessions, and then returns an
opaque quiesced-cleanup permit. A job observed in the same process may not vanish
without a matching cleanup tombstone. Restart absence additionally requires the live
peer identity capability that retains an exclusive storage-root identity-directory
`flock` for the process lifetime. A paused predecessor therefore continues to fence a
replacement process; only process death releases the lock. The permit and tombstone
bind collection, mutation ID, immutable owner, generation, process incarnation, and
the exact descriptor/terminal/witness/evidence cleanup claim. A capability for another
collection or same-numbered generation is not interchangeable.
Session open reservations, session installation, cleanup claims, and final tombstone
installation share one registry linearization point. An outstanding reservation or
active session rejects cleanup; a cleanup claim rejects a later install; and the final
tombstone transition rechecks that no reservation, session, or append job is visible.
The deterministic registration-versus-cleanup regression covers both winning orders.

At sequence 7, storage derives an opaque cleanup expectation from the terminal
watermark, decided lease, consensus state, owner terminal evidence, and point
resolution evidence. The only allowed order is:

```text
Raft cleanup witness
  -> release process-local paired sessions
  -> fsync cleanup_complete_v2.json
  -> Raft clear-pending
  -> exact-generation clear and tombstone
  -> no-replace terminal namespace archive
  -> Raft clear acknowledgement
```

New admission stays blocked through cleared-pending acknowledgement. The
terminal archive is retained for audit and exact replay; owner recovery capsules
are also retained until a separate consensus-backed physical-GC policy is
activated. The generic lease CAS is not cleanup authority and is not used by the
V2 terminal coordinator.

The cleanup marker and archive receipt use immutable no-replace publication:
bounded canonical temp write, file fsync, rename, both affected directory fsyncs,
and exact installed-byte validation. Archive source identity and the complete
generation/tombstone binding are checked before rename, and the archive root is
fsynced before acknowledgement authority is returned. The archive destination is
then reopened and required to have the same device/inode as the pinned pre-rename
source; the old active name must be absent and canonical terminal contents are
revalidated before receipt publication. A failure after rename but before directory
sync is indeterminate; exact retry validates the installed value and completes
durability. Acknowledged recovery and terminal certificates remain
attached until the next admission atomically converts them into a retained GC
obligation; incomplete or non-acknowledged material blocks reservation.

If the immutable coordinator remains absent for 300 seconds while the same foreign
generation is pending, the durable protocol state remains `Pending` and the
operational status becomes `Blocked: ImmutableCoordinatorUnavailable`. This is an
availability condition, not takeover authority, and does not make the whole node
unready. Consensus or reconciliation failures still produce a readiness-failing
blocked state.

V2 D0-D4 are connected for the strict single-writer, fixed-capacity append
subset: signed manifest/state/mutation contracts, fixed-window Path ORAM client
transactions, owner reservation and prestage, collection-wide consensus apply,
dedicated REST/internal transport, restart terminal reconciliation, and cleanup
are all present. Normal Qdrant upsert/update and ordinary search remain rejected.
Production release still requires the V2-E Linux multi-process crash matrix,
leader/supervisor concurrency E2E, complete snapshot/WAL leakage scans,
performance benchmarks, and operational backup/restore drills. Coordinator
takeover, dynamic resize/update/delete, physical evidence GC, and true
multi-writer remain outside V2.

The append contract carries ciphertext hashes and commitments, not raw bucket
bodies. The owner-prepare wire package supplies those encrypted bodies, and the
crypto validator hashes and matches each one to its signed ordered reference.
When the route is activated, the transport layer must additionally enforce a
hard body and total-bucket limit before deserialization.

The first D1 client slice adds a dormant encrypted checkpoint contract.
`PrivateOramAppendClientCheckpointV2` contains collection, immutable manifest,
layout and state-sequence identity plus the complete canonical private index
set. Each HNSW checkpoint carries its optional entry node, position map, stash,
and canonical node-to-point level/generation records. The optional result
checkpoint carries its position map, stash, and payload-to-point generation
records. A collection-wide point ledger preserves point token, optional
visible point id, and optional payload fetch token relationships.

Checkpoint validation requires every HNSW position key to equal that index's
node ledger, every index to cover exactly the collection point ledger, every
result position key to equal the payload-token ledger, and every stash block
to match its recorded node/point/payload identity, level, and generation.
Ledger length must equal signed logical occupancy and stash length must remain
within the immutable manifest bound. In `ids_visible` mode every point has a
visible id and no payload-fetch token. In
`private_payload_oram_required` mode every point has a payload-fetch token and
no visible id, and the HNSW/result mappings must agree.

The checkpoint avoids a circular state commitment with a two-step binding:

1. Seal the checkpoint under the client-only checkpoint key. Its
   domain-separated digest binds collection, manifest, layout generation,
   state sequence, and ciphertext SHA-256.
2. Put that digest in `PrivateOramSignedStateV2.client_state_digest` and sign
   the state.
3. Attach the resulting full signed-state digest as the outer checkpoint
   `state_digest`.

The outer `state_digest` is deliberately excluded from the client-state
digest. Open recomputes both digests and then checks all checkpoint metadata,
index epochs/roots, occupancy, and ledger relationships against the immutable
manifest and signed state. The checkpoint ciphertext remains client-owned and
is not included in Qdrant snapshots. The canonical non-circular digest bytes
are fixed by
`docs/qdrant-sec-private-oram-append-checkpoint-test-vector.json`.

The legacy overwrite-capable position helpers remain for v1 compatibility.
V2 append code uses `insert_position_if_absent` and validated atomic
position-plus-stash insertion. These helpers prevent local key overwrite, but
the encrypted collection-wide ledger remains authoritative for duplicate
node, point, visible-id, and payload-token rejection before the first server
read.

The dormant D0 writeback shape now binds one root-to-leaf writeback frame per
fixed read path, preserves duplicate bucket ids in frame order, and matches
each frame to the server-observed ordered leaf sequence. Its canonical KAT
freezes the ordered occurrence sequence. D1-B additionally converts verified
HNSW or result read proofs into a common sparse proof, checks all overlapping
old-tree nodes against the pinned epoch/root, applies the last occurrence for
each changed bucket, and computes the new root without a full leaf commitment
vector. Small non-power-of-two and single-bucket fixtures compare this result
with full recomputation. These remain client-side dormant primitives: no
append route or executable server mutation is exposed before the remaining
D1-D checkpoint/finalizer work and D2 through D4 are complete.

D1-C now has a fail-closed level-0 graph-delta primitive. It validates the
complete checkpoint and signed state before inspecting candidate blocks,
rejects duplicate identities and stale candidate generations, selects
neighbors deterministically from finite F32 vectors, and preserves immutable
node fields and every upper-layer edge during reciprocal rewrites. The fixed
HNSW append path budget is partitioned into candidate slots,
`max_neighbor_rewrites` rewrite slots, and one insert slot; unused slots are
padding. A valid HNSW v2 manifest therefore reserves at least
`max_neighbor_rewrites + 2` paths. If every reciprocal edge is pruned, the new
node becomes the entry and points to the previous entry so the old graph stays
reachable.

Append-specific HNSW access applies a checked rewrite before Path ORAM
writeback and commits cloned client state only on success. Targetless HNSW and
result eviction places a new stash block or re-encrypts a padding path without
requiring an existing target, which covers empty-index first append.

`PrivateOramAppendHnswTransactionV2` now composes these primitives for one
HNSW index plus at most one paired result index. It owns the exact manifest
window and path budget. Candidate evidence is obtained only from an accepted
window after every response bucket and multiproof has been checked against the
signed state's pinned old epoch, root, and bucket count. The response bucket
sequence must equal the ordered concatenation of every requested root-to-leaf
path, including identical repeated root and ancestor buckets.

Each path starts from the verified old-root image and substitutes the latest
local plaintext overlay for buckets changed by earlier paths. It then reseals
the complete root-to-leaf frame at the new epoch. The transaction retains both
the ordered ciphertext occurrences required by D0 and the last ciphertext per
bucket used by the sparse Merkle patch and final storage image. Tests revisit
the same leaf in a later window, preserve all repeated root occurrences, and
compare the final root with a full commitment-vector recomputation.

Path disclosure has an explicit durable recovery boundary. First,
`prepare_next_read_window` returns only a path-free recovery marker. The SDK
must persist that exact marker before passing it to
`next_read_window(&persisted_marker)`, which then reveals the paths. Any
post-read proof, sequence, planning, rewrite, or stash failure poisons the
attempt. Its `attempt_digest` binds the exact opened checkpoint, append point,
and candidate/remap/padding schedule, so a different plan cannot reuse a
persisted marker with the same mutation metadata. Window changes are adopted
only if the complete window succeeds.

The legacy v2 recovery-marker schema and HNSW v2 attempt/prepared digest
domains remain unchanged and readable. Active HNSW and result append attempts
use a v3 marker that additionally binds index kind and index name, plus
provider-specific v3 attempt domains. The v3 prepared-commit domains remain as
compatibility known answers, while active finalization uses provider-specific
v4 prepared-commit domains that additionally authenticate the canonical source
checkpoint digest. Checkpoint, graph-delta, and next-client-state digests use
explicit canonical framing rather than JSON serialization: the domain has a
4-byte big-endian length, variable byte sequences have 8-byte big-endian
lengths, scalar integers are fixed-width big-endian, and option/enum values
have explicit one-byte tags. Position-map and stash snapshots are normalized
through their keyed client state before encoding, so semantically equal map
orderings have one digest. Known-answer tests preserve the legacy HNSW v2,
compatibility HNSW/result v3, and active HNSW/result v4 values. A persisted
legacy v2 HNSW `window_issued` marker can authorize its exact pending window
once; the returned request carries the v3 marker and every subsequent window
remains on v3.

`finalize` returns a `prepared_commit` marker whose v4 digest binds the
attempt, canonical source checkpoint, graph delta, old/new epochs and roots,
read transcript, ordered writeback, and next client state. Re-encrypting the
same logical attempt therefore produces a distinct marker when the ciphertext
artifact changes, while changing only the public graph delta or source
checkpoint also invalidates the marker. The marker remains durable until both
the server CAS and the new encrypted checkpoint are confirmed.

`PrivateOramAppendResultTransactionV2` provides the paired result-index half
of the same protocol. It accepts exactly one private payload block insertion
plus the manifest-fixed padding schedule, verifies the exact ordered
old-root response including duplicate shared ancestors, applies prior-path
plaintext overlays, reseals every path occurrence at the new epoch, and
computes the final result root with the same sparse Merkle patch. Duplicate
point or payload tokens and oversized payloads fail before the first read.
Within-window duplicate paths fail closed, while a repeated path in a later
window remains valid. `begin` preflights every fixed result window before any
recovery marker or path can be disclosed, so a malformed later window cannot
leak an earlier valid path prefix. Correct-cardinality read responses are also
checked against the manifest's maximum encoded ciphertext length before any
body is decoded. The authenticated verifier then enforces bucket hash,
commitment, proof, and an epoch at or below the pinned current epoch, allowing
unchanged buckets carried forward from older commits.

Result window updates use a complete transaction snapshot. A failure after an
earlier path has already changed the position map, stash, overlay, and ordered
ciphertext frames restores all of them before poisoning the attempt. Its
attempt digest binds the checkpoint, private payload point, and fixed path
schedule. Its prepared digest additionally binds the result ledger record,
canonical source checkpoint, old/new roots and epochs, transcript, ordered
writeback, and next result client state. A canonical working-artifact digest
covers the client state, accepted windows, plaintext overlay, proof set,
ordered refs and ciphertext frames, and final bucket map; rollback tests
require this complete digest to return to its pre-window value. Known-answer
tests pin both HNSW and result recovery digest encodings.

Result finalization revalidates its public prepared output before returning
it. The validator checks fixed ciphertext size, decoded-body SHA-256, bucket
commitment and epoch context for every ordered occurrence; requires each body
to match the corresponding writeback reference; derives every expected bucket
id from the ordered leaf transcript; derives the canonical final bucket set
from the last occurrence of each bucket id; and applies the included old-tree
Merkle patch proof to recompute the new root. It then recomputes the writeback
digest, next-client-state digest, and prepared marker. Tampered bodies, frames,
proofs, roots, final-bucket images, and transcripts therefore fail closed at
this boundary.

The two prepared index outputs are not yet a complete D0 mutation. Paired
checkpoint advancement and resealing are now available as a client-side
dormant primitive. The planner exact-matches the HNSW point record, HNSW
record/new block, and result record point and payload tokens. New records start
at generation one. Existing reciprocal rewrites must preserve node, point,
payload, vector, level, and deletion identity while advancing generation by
exactly one.

The planner inserts the point, HNSW, and result records in canonical raw
32-byte token order. It advances both client states, entry node, epochs, roots,
logical/dummy occupancy, and ordered-writeback digests under one incremented
state sequence, then runs the complete checkpoint validator. Both prepared
outputs carry a canonical `source_checkpoint_digest`, and each provider's v4
prepared-commit digest authenticates that value. Pairing requires the source
digest plus collection, manifest, old-state, mutation, writer lease, and fence
to match. Immediate mutation-id reuse is rejected.

The reseal wrapper does not trust a caller-supplied plaintext checkpoint. It
authenticates and opens the old encrypted checkpoint against the old signed
state, uses that exact plaintext for pairing, validates and seals the advanced
checkpoint, places the exact sealed-ciphertext digest in the next signable
`PrivateOramSignedStateV2`, creates the outer state binding, and reopens the
result to require exact equality. Checkpoint sealing uses a random nonce, so
the returned ciphertext and state payload are one durable pending artifact:
CAS recovery must reuse them rather than reseal the same logical delta.

The D1-D3 paired finalizer completes the dormant client-side artifact. HNSW
output now retains its old-tree Merkle patch proof and passes a public
self-validator before `finalize` returns. The validator checks exact encoded
body size before decoding, AEAD framing, hashes, commitment context, writeback
refs, transcript-derived repeated path frames, the last-occurrence final image,
the sparse patch and new root, graph and rewrite invariants, fixed budgets, and
the manifest-specific next client state. A rewritten level-0 edge may target
only a previous level-0 neighbor or the new node, and every retained target
must exist in the next position map and checkpoint node ledger. Graph and state
tests recompute the v4 prepared digest after tampering to ensure structural
checks do not rely only on a stale marker.

`finalize_private_oram_append_paired_mutation_v1` first verifies the trusted
owner public key, signed manifest, signed old state, pinned collection,
manifest, layout, sequence, state digest, and writer lease/fence. It runs both
provider output validators, performs the randomized D1-D2 reseal exactly once,
signs the new state, derives the `no_server_point_record` digest, preserves
writebacks and observed transcripts in manifest index order, and signs the D0
mutation. It returns only after the complete
`validate_private_oram_append_mutation_v1` check and an exact checkpoint reopen
against the signed new state succeed.

The returned HNSW/result outputs, encrypted checkpoint, and mutation bundle are
one pending aggregate. A CAS retry must persist and reuse that exact aggregate
instead of rerunning randomized finalization. The current self-check uses
transcripts carried by the prepared client outputs; D4 admission must rebuild
the authoritative transcript from the server session record. Storage,
consensus, and public routes remain dormant.

The dormant D2 consensus primitive stores one versioned collection record per
enrolled stable collection identity. The record repeats the immutable manifest
digest, layout generation/digest, state sequence, signed-state and encrypted
client-state digests, and the canonical ordered HNSW/result index set with each
epoch/root/writeback digest and logical/dummy occupancy. Its transition is
explicitly `genesis` at sequence zero or contains the exact latest mutation
receipt. The receipt binds old/new sequences and signed-state digests, point
operation and writer-lease digests, writer fence, lease-slot generation, and a
transition digest recomputed from the complete old record, new record core,
and receipt core. Canonical consensus digest encodings are domain separated,
fixed-width, strict about index order, and pinned by a known-answer test.

Every enrolled collection also has a permanent mutation lease slot. The slot
is never deleted and its generation and maximum writer fence increase together
on each acquire. It contains either an active `preparing` or
`consensus_committed` lease, or an exact typed clear tombstone:
`aborted_before_consensus_commit` or
`finalized_or_reconciled_after_consensus_commit`. Expiry does not authorize
takeover. A delayed acquire against an earlier vacant generation fails, which
closes the optional-lease `None -> lease -> None` ABA case. Preparing binds the
exact base record and transition; apply derives the committed phase rather than
accepting it from the caller.

First apply validates the complete old/new collection transition and active
preparing lease, then advances every configured epoch/root, the collection
record, layout `index_state_digest`, and lease phase in one persistent save.
Every index must advance epoch by one, change root and writeback digest, add one
logical slot, consume one dummy slot, and preserve total capacity. Exact replay
against the still-current new state performs no write and does not recreate or
modify a cleared lease or a later preparing lease. A V2-enrolled collection
rejects standalone v1 epoch/layout mutation and new v1 search-session leases,
because those operations cannot update the collection record atomically.

Raft snapshots include both collection records and lease slots. Legacy
snapshots may omit both top-level maps and decode as non-enrolled; a V2 state
without its exact slot, layout, or index epochs fails closed. Active preparing
and committed slots, including expired ones, are valid Raft snapshot state and
must round-trip. The slot owner must remain in the bound layout. External
collection/data snapshots are a different boundary and require a D4 consensus
lifecycle reservation; command-line snapshot restore already rejects a
persisted active mutation.

D2 is not an activation boundary. D3-A replaces the opaque atomic-write result
with an explicitly classified persistent-image sequence: create a named temp
file in the destination parent, serialize while hashing, fsync the file,
atomically publish it, and fsync the parent directory. Temp creation,
serialization, and temp-file fsync failures are definitive and may roll back
the in-memory transaction. Publish errors are conservatively indeterminate.
If the visible target has the exact candidate SHA-256, parent fsync is retried
up to three total attempts; only a successful parent fsync converts that path
to success.

An unresolved publish or parent-fsync outcome never rolls the in-memory state
back. It sets a serde-skipped process-local poison flag, keeps the state dirty,
and returns a fixed service error. The consensus loop stops before marking the
entry applied, and its next-entry preflight also rejects every save while the
flag is set. On restart, the earlier durable apply-progress queue replays the
same committed entry: an old persistent image applies the transition, while a
new image takes the exact no-op replay path. Fault tests cover definitive
pre-publish rollback, old-disk/new-memory replay, rename-ahead recovery, and
parent-fsync retry and exhaustion. A real power-loss/process crash matrix
remains a D5 release gate.

D3-B1 adds a durable collection-level parent journal for the exact seven-phase
mutation sequence. It binds the signed mutation and old consensus record,
validates derived point and committed-consensus evidence, and classifies parent
record publication outcomes. D3-B2 adds the bounded canonical InsertOnly frame
and a Prepared-only point-stage artifact tied to the exact parent chain tip; the
parent can advance only with its opaque durable token. It intentionally does
not treat structurally valid owner-child digests as proof of owner preparation
or finalization. D3-B3 must inspect those exact child journals and proofs,
finalize exact-new consensus outcomes, and first consensus-fence an observed old
state with `AbortDecided` before any abort. It must then publish or abort the
point stage, replace mutable artifacts with an immutable reconciliation witness,
and clear the mutation lease last. D3/D4 must also add V2-aware search writeback
and consensus lifecycle reservations so search, external snapshots,
delete/restore, transfer, and reshard cannot race mutation acquisition. Runtime
authorization and owner-child evidence are not inferred by D2 or the
point-stage primitive alone.

The external recovery primitive is
`PrivateOramExternalRecoveryCheckpoint`, signed under
`qdrant-sec/private-oram-external-recovery-checkpoint-signature/v1`. It binds:

- stable collection identity and monotonic backup generation
- source peer and canonical sorted local shard ids
- consensus layout generation, canonical owner union, layout digest, and
  private index-state digest
- exact closed collection snapshot byte size and the existing Qdrant
  lowercase-hex SHA-256 checksum
- base64url SHA-256 digest of the complete encrypted client recovery-state set
- owner signing key id and creation time

The crypto crate exposes checked package, canonical message, Ed25519 signing,
shape validation, and exact restore-context verification helpers. The
canonical message uses a 4-byte big-endian domain length, fixed big-endian
numeric values, and 8-byte big-endian UTF-8 string lengths. Shape validation
rejects unknown JSON fields, unsupported versions, zero generation or snapshot
size, empty, duplicated, or unsorted owner/shard sets, a source outside the
owner set, malformed digests, malformed signatures, and owner-key mismatch.
Deterministic message-digest and Ed25519 known-answer tests pin this encoding.

The server now consumes this checkpoint through a distributed, admin-only
external recovery admission protocol:

- `POST /collections/{collection}/private-oram/recovery/begin`
- `POST /collections/{collection}/private-oram/recovery/upload`
- `GET /collections/{collection}/private-oram/recovery/status`
- `POST /collections/{collection}/private-oram/recovery/verify`
- `POST /collections/{collection}/private-oram/recovery/commit`
- `POST /collections/{collection}/private-oram/recovery/abort`

`verify` restores the archive into an isolated pending directory, validates it,
fsyncs it, and promotes it only to an operation-local `verified_collection`
directory. `commit` is the only operation that may replace the live collection
and advance the committed backup generation. It drains and stops the old
collection before hashing it, records an exact old/new durable install marker,
and moves the recovery lease from `Staging` to `Installing` before any rename.

`begin` is accepted only on the same peer identity named as the signed source.
It requires the current stable collection UUID and crypto config, the exact
canonical local shard set, the exact consensus layout and every private index
epoch/root, no private ORAM session lease, no pending generic snapshot recovery
marker, and one identical owner signing public key across all bound private
HNSW and result ORAM rules. The server stages the signed checkpoint before
submitting a collection-wide consensus lease. The lease is one hour, renews
with a bounded sliding window during upload or verification, and fences private
ORAM session, epoch/root, and layout transitions. Consensus stores only a
domain-separated hash of the random 32-byte operation token. The raw token is
returned by `begin` and must be retained by the operator.

Upload is an ordered multipart stream with fixed 8 MiB chunks except for the
final chunk. Every chunk carries a lowercase-hex SHA-256, and the completed
archive must match the checkpoint's exact byte size and SHA-256. Staging uses
private non-symlink directories and regular files, owner/mode checks, exclusive
per-collection file locking, atomic state replacement, fsync ordering, and
crash reconciliation that truncates an uncommitted archive suffix. Duplicate
chunks are idempotent only when their stored bytes hash identically.

Status accepts the operation token only in
`x-qdrant-private-oram-recovery-token`; query-string tokens are ignored.
Handler-generated recovery responses carry `Cache-Control: no-store`, access
logs redact query and unexpected suffix values throughout the recovery
namespace, and metrics accept only the six fixed route shapes. Abort requires
the same owner peer and operation token, but remains available after lease
expiry so an expired operation can be cleared. A later valid begin may take
over an expired lease and best-effort removes superseded local staging.

Verification rechecks the checkpoint signature and current consensus binding,
then restores the closed snapshot in isolation. It requires byte-for-byte
collection config equality and stable identity, the exact source-local shard
set, valid point-shard and payload-index structure, and complete signed HNSW
and result ORAM stores at the checkpointed epochs and roots. A read-only
candidate inspector additionally rejects version migration, runtime recovery
mode, initializing or non-replica shards, missing replica state, non-`Active`
owners, missing local WAL/segment directories, and any shard-directory drift.
It reconstructs the full canonical owner topology and requires the signed
layout digest exactly. The inspector does not replay WAL, repair segments,
write defaults, or start workers. A stale layout, index state, archive,
signature, bucket set, or lease fails closed.

Commit uses a collection-registry tombstone while the live `Collection` is
detached. Ordinary reads return a recovery-install lock instead of `NotFound`;
point/meta writes, collection and shard snapshot recovery, create/delete,
aliases, peer shard changes, and conflicting Raft collection snapshots fail
closed. Cross-collection recommend, discover, group, and query lookup paths
hold the collection lifecycle lock while any install tombstone or live
`Installing` fence exists. Raft snapshot generation merges the cached tombstone
state so a detached collection is never serialized as deleted. Snapshot apply
preserves live `Staging` or restart-loaded `Installing` collections exactly. It
accepts `Installing -> Staging` only when the incoming lease is the exact
rollback image of the same install; a changed lease or dropped install still
fails closed. On the install owner, durable local marker reconciliation must
independently prove the old-tree rollback before the fence can be cleared. A
lagging non-owner has no local install tree and can apply the authoritative
transition directly.

Every prepare writes a fresh 256-bit install-attempt nonce into the durable
marker and install-intent digest. A delayed Prepare or rollback from an earlier
attempt therefore cannot match a later attempt even when both old and new tree
digests are identical. Rollback checks the current on-disk marker before any
rename. Returning to `Staging` discards a leftover `Prepared` marker, so a
later prepare must use a fresh nonce. The marker also pins semantic collection
config and canonical layout digests in addition to exact old/new tree and
private-store digests. Marker version 4 adds `RollbackInProgress` and
`RollbackComplete`, plus old-tree semantic config and private-store digests. It
can therefore resume safely whether a crash left the promoted tree present,
removed it, or already restored the backup. The rollback marker is removed only
after the exact consensus rollback is observed.

After the new tree is promoted and its exact digest is rechecked, Qdrant records
`LoadInProgress` and performs a normal `Collection::load` while consensus still
holds the `Installing` all-operation fence and the old backup remains. It then
requires the stable identity, byte-exact config, exact metadata-derived and
actually loaded local shard sets, semantic config digest, no transfer or
resharding, all-active replica owners and shard keys, canonical layout digest,
and private-store digest before recording `Loaded`. A load or validation
failure in `LoadInProgress` discards the mutated candidate through the durable
rollback phases, restores the exact old tree, and submits the exact
`Installing -> Staging` rollback CAS.

The durable `Loaded` marker is the point of no return because Qdrant submits the
Raft Commit only after it exists. Qdrant never automatically rolls a `Loaded`
tree back: a submitted Commit may still apply after a timeout or process crash.
Restart rolls pre-load install phases forward to `LoadInProgress`, loads the
candidate under the same fence, and preserves a `Loaded` tree for exact Commit
retry. The same operation token can continue from either the live registry or
the matching tombstone, and a delayed Commit that already applied can be
finalized from the durable marker.

Only an exactly observed committed generation allows cleanup. Qdrant first
marks the durable install committed, removes the backup and marker in
crash-reconcilable order, and publishes the already loaded collection. Startup
follows the same load-before-cleanup order and verifies the stable identity and
canonical layout digest before deleting recovery files. Any active
`Staging`/`Installing` consensus recovery or local install marker disables
tolerant collection-load handling and blocks explicit startup snapshot restore.
This prevents load failure from silently removing a recovery fence and prevents
a forced snapshot from replacing either staged authority or a promoted tree.
External verification restores replica snapshots without rewriting archived
peer identity; an archive bound to another peer is rejected unchanged.

A complete external recovery set still consists of the Qdrant collection
snapshot and signed checkpoint plus encrypted client recovery state retained
out of band. Existing client snapshots protect position maps and stashes, but
the complete recovery-state format must additionally protect the HNSW entry
node and the local point-token mapping required by `ids_visible`. Client RK
material, position maps, stashes, entry nodes, token maps, and encrypted
client-state bodies must never be uploaded into Qdrant's collection-local ORAM
store or included in a Qdrant snapshot. Only the complete encrypted set digest
is checkpointed.

Server rollout proceeds in dependency order. A wiped fixed-layout transfer
target with a live source requests source-side fresh full-store preinstall
before restarting the exact marked transfer. External restore now includes the
durable install marker, activation fence, exact Commit and rollback CAS, and
restart reconciliation described above. Unit coverage pins marker-fsync
ambiguity, stale-attempt rollback rejection, private-store substitution,
delayed committed-marker resume, and load-before-cleanup ordering. The
remaining release gate is the hard-crash/RF=1 single- and multi-shard process
matrix plus the first proof-verified private read/writeback after restore.
Finally, the v2 mutable provider will use an immutable capacity manifest plus a
monotonic owner-signed state record and one collection-wide HNSW/result
mutation CAS. Until those process gates pass, operators should treat external
commit as an experimental same-peer recovery path.

Raft persists a separate collection-level private ORAM layout record consumed
by fixed-layout transfer/removal and typed scale-up/down resharding. The record
contains a monotonic generation, a canonical sorted owner-peer union, a
shard-layout digest, and a
digest of the private ORAM index epoch/root set. Collection identity is stored
only through a domain-separated SHA-256 map key, and record debug/log output
redacts collection identity and both digests. Initial creation must use
generation 1; later CAS transitions must advance by exactly one, while exact
replay is idempotent. The map is validated when persistent state or a Raft
snapshot is loaded and is included in newly generated Raft snapshots; legacy
snapshots default it to empty. Supported reshard finish and bounded shard-key
changes advance this record by exactly one generation; unrelated dynamic
layout mutation remains blocked.

Custom-sharded private ORAM collections may create their first shard key while
the collection has no shards and no ORAM ownership record. This bootstrap is
forced to `Active`; initial encrypted-store upload then targets that owner
union. Once an ORAM index exists, shard-key create/drop freezes every configured
HNSW/result index under one consensus reservation and submits an exact
descriptor with the metadata operation. Create may retain the current owner
union or introduce known peers. Before a new owner is named in the submitted
transition, the coordinator installs every configured encrypted ORAM store on
that peer under the same reservation and verifies the exact current
epoch/root/writeback acknowledgement. The descriptor contains the canonical
sorted new-owner difference, and persistent plus topology validation require it
to equal `new.owner_peer_ids - expected.owner_peer_ids`. Partial install failure
does not submit the topology change; already installed encrypted files are
safe to overwrite on retry. Drop is limited to a non-empty post-layout whose
owner union still contains the coordinator. The layout CAS is committed before
metadata apply, and pre/post classification makes replay idempotent. `Partial`
creation and deletion of the final key fail closed. A removed owner may retain
encrypted files locally, but owner-union session checks deny access there.

The canonical shard-layout digest uses domain
`qdrant-sec/private-oram-shard-layout-digest/v1` and binds the stable collection
identity, sharding mode, sorted shard ids, typed shard keys, and the sorted
fully-active owner set of every shard. The canonical index-state digest uses
domain `qdrant-sec/private-oram-index-state-digest/v1` and binds every configured
private HNSW/result index kind and name, epoch, root, and optional writeback
completion digest. Both encodings use fixed big-endian numeric fields and
length-prefixed byte strings. The index-state digest is a checkpoint captured
at a layout transition, not an invariant that changes on every ordinary ORAM
search writeback. A later transition therefore requires the existing record's
topology to match but binds the then-current consensus epoch/root/completion set
into the new generation.

Fixed-layout replica removal freezes every configured private ORAM index with
the same live consensus lease. If no layout record exists, it first bootstraps
generation 1 with the stable pre-removal topology. It then submits one Raft
operation that validates the exact leases and current index-state digest,
advances the layout generation, applies the reserved exact single-replica
removal, and verifies the post-removal topology. Pre-state and already-applied
post-state classification makes exact replay idempotent; mismatched shard,
owner, digest, lease, or index state fails closed without reflecting bound
values.

Fixed-layout `stream_records` shard transfer now consumes the same layout
record. While all configured indexes share one live reservation, the source
captures their exact epoch/root/writeback state and the stable pre/post owner
layouts. A missing record is first bootstrapped at generation 1. The transfer
start Raft operation validates the exact leases and current index states and
persists the expected layout, generation-`+1` layout, and captured index states
inside the marked transfer record. It does not advance membership yet. After
start apply, the reservation is released and the active transfer marker keeps
new sessions and writebacks frozen. Transfer completion uses a dedicated Raft
operation that revalidates the captured index states, advances the layout CAS,
applies target activation and optional source removal, and verifies the exact
post-layout. Pre-state and post-state classification makes start/finish replay
safe across crashes. Exact restart preserves the transition metadata; abort
removes the transfer without advancing the expected layout. Existing layout
records may carry an older index-state checkpoint after ordinary writebacks,
but their topology must match and the new generation always binds the current
index states. An abort may leave the exact transfer target replica `Dead`; an
exact retry excludes only that `(shard, target)` replica from the pre-layout and
must restore it through the same marked transfer. Any other dead or transitional
replica still fails closed. Typed resharding uses a separate layout transition;
unrelated dynamic shard-layout operations remain blocked.

Private ORAM search and result-fetch providers have their own client-led
contract:

| API/path | `vector/private-hnsw-oram@v1` | `payload/private-result-oram@v1` |
| --- | --- | --- |
| Runtime profile | Strict zero-trust compatible. Server materials and backends are forbidden, RK epoch must be pinned, fixed-budget search is required, and signing verifiers are mandatory. | Strict zero-trust compatible. Server materials and backends are forbidden, RK epoch must be pinned, Path ORAM policy is allowlisted, and signing verifiers are mandatory. |
| Collection binding | One vector name per `private-hnsw-oram/v1` rule. It cannot overlap `vector/openfhe-ckks@v1` or `vector/client-ckks@v1` on the same vector name. | One `private-result-oram/v1` payload binding in v1. It is required when a private HNSW manifest uses `result_privacy: private_payload_oram_required`. |
| Normal Qdrant reads/writes | Dense vector upsert/update, point/vector delete, collection peer `SyncPoints`, `with_vector` reads, ordinary search/query/recommend/discover, grouped paths, search matrix, and `lookup_from`/point-id reference-vector resolution fail closed for the private vector; clients must use the private HNSW session APIs. | Point create/replace/delete, full payload replacement/clear, protected-path payload writes, indexes, filters, ordering, grouping, facets, formulas, and raw payload reads fail closed for the private result path; public non-overlapping payload merges remain ordinary. |
| Dedicated APIs | Manifest upload/read, encrypted bucket upload, session open/close, signed `read_paths`, and signed writeback commit are open. Qdrant validates shape, signatures, Merkle proofs, and epoch/root CAS only. | Manifest upload/read, encrypted bucket upload, session open/close, signed `read_buckets`, and signed writeback commit are open. Qdrant validates shape, signatures, Merkle proofs, and epoch/root CAS only. |
| Snapshot/restore | Collection, storage, REST, and CLI/startup recovery preflight validate manifest signatures, current epoch/root, every bucket, Merkle metadata, and paired result ORAM policy before accepting a restored store. | Collection, storage, REST, and CLI/startup recovery preflight validate manifest signatures, current epoch/root, every bucket, Merkle metadata, and configured binding/runtime policy before accepting a restored store. |
| Cluster mode | Initial upload installs the exact signed encrypted bundle on the union of all fully-active shard replica owners before the initial Raft ownership CAS. Session open acquires a hashed Raft lease after recovery; `read_paths` requires that exact live lease; commit renews it, durably prepares every owner peer, applies the digest-bound epoch/root CAS, then finalizes remote replicas before the owner. Close releases the exact lease. Fixed-layout movement/recovery/restart/removal, custom shard-key mutation, and typed scale-up/down resharding use collection-wide reservations; movement and new-owner shard-key create paths also use signed full-store preinstall. Exact point migration and its exact same-method active restart require a marked `resharding_stream_records` transfer matching the active reshard state. A source crash preserves that exact transfer; the target requests automatic resume and the source performs fresh full-store preinstall before same-key restart. Sessions remain blocked throughout active transfer or resharding. Existing-peer active-reshard Raft snapshot topology recovery is accepted only under the consensus-bound pre-layout contract above; restored transfer metadata uses the same target-triggered resume protocol. A genuinely new non-owner may bootstrap remote topology when absent from every owner, replica, and transfer endpoint. A wiped/new exact scale-up target may also bootstrap at `MigratingPoints` only as the sole `Resharding` target of the sole marked incoming transfer; it remains blocked until target-triggered resume reinstalls every configured store and restarts migration. A fresh fixed-layout `Partial` transfer target that was not a pre-layout owner may likewise recover complete collection or complete configured-store loss through a durable exact resume marker and source fresh preinstall; partial store loss remains blocked. A wiped redundant pre-layout owner or fixed-layout transfer source may bootstrap only when every affected shard has another active owner. A designated scale-down endpoint additionally requires zero transfers, all-active replica state, ownership of the removed shard, and another active owner for every local shard. Durable markers force exact transfer or reshard rollback before stable-layout automatic store and shard recovery. Non-redundant owners and sources, already-active targets, transitional removals, and batch removals remain blocked. | Initial upload, session lease, `read_buckets`, replicated writeback, recovery, and close use the same coordinator contract as HNSW. Result ORAM movement and typed resharding follow the same collection-wide ownership and shard-key reservation policy. Paired HNSW/result scale-up/down and custom shard-key process tests verify both encrypted stores, roots, and sessions on every final owner, including preinstalled new shard-key owners. |

The internal Dispatcher writeback coordinator enforces durable local prepare,
awaited Raft epoch/root CAS, then idempotent local finalize. A writeback epoch
may also carry a provider-specific digest: SHA-256 over the canonical HNSW or
result-ORAM commit signature message, which already includes its provider
domain, lineage, old/new epoch and root, and ordered encrypted bucket hashes.
Raft therefore binds the epoch/root transition to one opaque signed writeback
without storing bucket ids or ciphertext. Initial ownership and snapshots from
before this field use no digest. Exact replay includes the optional digest, so
the same epoch/root paired with a different writeback is conflicting stale
state. If Raft rejects the CAS, the coordinator invokes a signed-journal abort
that removes the journal only when the local epoch, Merkle tree, and every
target bucket still match the old view; any partial local mutation preserves
the journal and fails closed. If finalize fails after Raft apply, retrying the
same operation reuses exact-CAS idempotence before running finalize again. The
public REST/gRPC distributed commit routes now use this boundary. Distributed
initial upload couples encrypted bucket replication and ownership to the
initial CAS; session open recovers pending state before acquiring a consensus
lease, and session-bound reads require that exact owner/hash/expiry lease.

Each collection-local HNSW/result store can export a validated replication
batch from its owner-signed durable journal. The batch contains only old/new
epoch state, encrypted buckets, bucket count, and the commit signature; Merkle
state is not transported. A receiving store bounds the writeback by the tree
(the exact per-session budget is enforced on the writer, see below), derives
the canonical writeback digest, requires an
exact match with the proposed consensus transition before creating a journal,
then recomputes the new Merkle tree from its own old tree. The Dispatcher CAS
builder also reads the current Raft record so the previous epoch's optional
digest remains part of the expected state. These are collection/storage
primitives consumed by the internal replication transport and public
distributed session commits.

The internal replicated-writeback coordinator now requires canonical
digest-matching prepare acknowledgements from exactly the caller-supplied
replica peer set before it submits the Raft CAS. Replica prepare failure,
missing/duplicate/extra acknowledgements, digest mismatch, or CAS rejection
attempt remote and local journal aborts. After Raft apply it finalizes remote
replicas before the local owner, preserving the owner's durable journal while a
remote finalize still needs retry. The peer set is not yet derived from a
consensus-backed private-ORAM ownership record. The Dispatcher can now derive a
safe v1 peer set from the collection layout, but only when every shard has the
same non-empty set of fully `Active` replicas, the current peer belongs to that
set, and every remote peer has a known internal address. Any transitional state
or shard membership mismatch fails before fan-out. This is deliberately stricter
than ordinary shard routing because the ORAM store is collection-local rather
than shard-local. Replica finalize and abort also require the exact expected
old/new epoch, root, and canonical writeback digest to match the owner-signed
pending journal; a stale internal request cannot act on a different pending
transition. Internal prepare/finalize/abort RPCs expose these receiver
operations and the owner-side ChannelService fan-out invokes them. Public
session commits stage this validated owner batch under a pinned node-local
session, renew the consensus lease, and invoke the coordinator.

The internal protobuf defines a structured replication wire contract for
HNSW and result ORAM writebacks: collection identity, index kind, exact old/new
transition, encrypted bucket records, owner signature, and canonical digest are
separate typed fields. It does not use an opaque JSON payload. The internal
Qdrant service registers prepare, finalize, and abort methods. Receiver prepare
revalidates stable collection identity, runtime provider policy, manifest and
owner signatures, fixed budget, bucket hashes/commitments, Merkle transition,
and canonical digest before returning an acknowledgement. Finalize and abort
require the exact pending transition. All receiver journal mutations are
serialized by a node-local service lock, and a prepare replay after an already
successful finalize only acknowledges when the current epoch/root, Merkle tree,
and every updated encrypted bucket exactly match the signed batch. Request
bounds and fixed error messages prevent ciphertext, digest, and signing-key
reflection.
The internal service applies the configured gRPC request-size cap before
protobuf decoding as well as the provider-specific bucket and aggregate bounds
inside the handler.

Owner-side transport is available through `ChannelService` and the Dispatcher.
Provider-specific request builders require the encrypted batch and consensus
transition to match before serialization. Dispatcher derives the exact remote
peer set, sends prepare concurrently, waits for every peer call to finish even
when one fails, binds each acknowledgement to its peer and canonical digest,
then uses the existing replicated coordinator for Raft CAS and remote-before-
local finalize. Abort and finalize fan-out likewise attempts every target;
finalize requires `completed=true`, while an abort no-op is idempotent. Peer RPC
errors include only the peer id and never reflect collection identity,
ciphertext, root, or digest. REST and gRPC use this same owner-side coordinator;
a distributed `TableOfContent` without Dispatcher consensus state still fails
closed through the single-node epoch guard.

For initial replica installation, both collection stores can export a complete
signed upload bundle only while the persisted current epoch/root still equals
the manifest epoch/root. Export first validates the manifest's canonical tree
bucket count, enforces a caller-provided aggregate memory budget before
allocating the bucket vector, reads every encrypted bucket, revalidates the full
upload bundle, and requires persisted Merkle leaves to match. Once any writeback
advances the store, it cannot be mislabeled and exported as an initial bundle.
A durable pending writeback also blocks both initial export and exact
idempotent install even while the current epoch still equals the manifest
epoch; transitional state must be reconciled against consensus before the
store can participate in another initial-replication decision.

Shard movement uses a distinct live-replication store contract. HNSW and
result ORAM stores can export the signed manifest as an immutable lineage
anchor together with the current epoch/root, the current consensus writeback
digest when the index has advanced, and the complete encrypted bucket set.
Unchanged buckets may retain epochs older than an optionally refreshed
manifest, but no bucket may be newer than the current epoch and every
commitment is re-derived from its own epoch and manifest key lineage. Export rejects a
pending writeback, a missing digest for advanced state, an incomplete or
non-canonical bucket set, and any persisted Merkle mismatch. The receiver
revalidates the owner manifest signature, requires the bundle's current
epoch/root/digest to exactly match the expected Raft record, recomputes the
Merkle root from all bucket commitments, and writes `current.json` only after
the manifest, encrypted buckets, Merkle state, and digest-bearing completion
record are durable. Installation is idempotent for an exactly matching store
and refuses to replace a different current state. These storage primitives feed
the supported fixed-layout manual and automatic recovery orchestration. Broader
shard layout changes remain fail closed.

The internal Qdrant service exposes this store contract as a separate typed
`InstallPrivateOramLiveReplica` RPC rather than overloading initial install.
The HNSW/result oneof carries current epoch/root, optional writeback digest,
and complete provider bucket records. Before touching the target store, the
receiver checks aggregate wire bounds, reads its local Raft ownership record,
requires an exact epoch/root/digest match, and authorizes a still-live consensus
lease only when the request carries the exact canonical transfer-reservation
hash. It then runs the provider signature and full-state install validation
under the private-ORAM mutation lock. The source helper likewise
exports under the collection write reservation, compares the exported state to
its local Raft record, sends the typed request to the selected peer, and
requires the acknowledgement to repeat the exact epoch/root/digest. Transport
and acknowledgement errors include the peer id only and do not reflect roots,
digests, reservation hashes, signatures, or ciphertext. The receiver
bounded-waits for delayed local Raft application of the exact reservation hash;
it never accepts a missing or different reservation. For supported manual and
automatic fixed-layout shard transfers, the source coordinator acquires the
same hashed consensus reservation for every configured private HNSW/result
index, installs all live bundles on the target, requires exact acknowledgements,
and only then derives a consensus-bound pre/post layout transition and submits a
transfer marked `private_oram_preinstalled`. The marked record carries the exact
captured index states and next layout generation. New private sessions and
writebacks remain frozen from reservation acquisition through the active
transfer marker.

Automatic recovery uses the typed internal
`RequestPrivateOramShardRecovery` RPC. The target schedules that request outside
collection synchronization locks so the source can propose the reservation and
the target can apply it without a Raft/collection-lock cycle. The source
requires the configured shard count to match the fixed actual layout, no
resharding or competing transfer, an `Active` local source, and a `Dead` target.
An exact already-marked retry is idempotently accepted; otherwise the source
runs the same full-store preinstall and marked `ReplicateShard` path with
explicit `stream_records`.

The internal Qdrant service now also accepts a typed, provider-discriminated
initial install RPC using the existing HNSW/result manifest, signature, and
bucket protobuf records. The receiver enforces the same decode and aggregate
bucket bounds, exact provider-kind/oneof/vector-name matching, stable collection
identity, runtime policy, manifest owner signature, full upload validation, and
node-local mutation lock as writeback replication. Installation is idempotent
only for an exactly matching existing bundle. ChannelService sanitizes install
transport errors to peer id only. Dispatcher sends the bundle to every derived
remote replica, waits for all calls even after failures, requires every ACK to
match the expected epoch/root, and only then submits the initial
`expected=None`, digest-free ownership CAS to Raft. A failed CAS leaves the
validated encrypted bundles in place for an exact retry. Public REST and gRPC
manifest routes use a coordinator-local staging path only when consensus is
available. Their complete bucket upload routes then export the validated local
bundle and invoke this all-replica coordinator before returning success. A
distributed `TableOfContent` without a Dispatcher consensus coordinator still
fails closed. Because manifest staging is node-local until the complete bundle
is installed, clients must send the manifest and bucket upload to the same
coordinator node and retry the exact signed bundle after an indeterminate
response.

Distributed recovery classifies local state against the Raft ownership record
before any pending journal may be acted on. A store without a pending journal
must exactly match the consensus epoch/root. A signed pending transition is
aborted only when both local and consensus still match its old epoch/root, and
is finalized only when consensus exactly matches its new epoch/root and
canonical writeback digest. Missing ownership, unrelated state, digest drift,
or a locally finalized transition whose consensus state is still old fails
closed. Session open consumes this classifier through provider journal
validation and remote-first completion before creating a local session.

HNSW and result ORAM now expose validated recovery contexts for that next
step. A context revalidates runtime policy, manifest ownership, current epoch,
and the owner-signed pending replication batch, then holds the existing
upload/session mutation reservation until it is dropped. The internal recovery
orchestrator classifies that snapshot against Raft, re-derives the complete
active replica set, sends exact abort/finalize completion to every remote, and
only then applies the same exact transition locally. Clean initial stores are
covered by route fixtures for both providers. Public distributed session open
runs this orchestrator before lease acquisition. Finalize writes a durable completion
record to the canonical epoch commit file before removing the pending journal.
The record binds index epoch, root, and canonical writeback digest while
`current.json` remains the epoch/root-only API state. A finalize replay without
a pending journal succeeds only when current state, validated Merkle state, and
the completion record all match the exact new epoch/root/digest. Same
epoch/root with a different digest remains fail closed. Legacy digest-less
commit files remain readable and are upgraded only after the signed pending
journal and final bucket/Merkle state have been revalidated. Snapshot source
and restore preflight accept canonical digest-bearing commit files, reject a
digest in `current.json`, and reject malformed digest values without reflecting
them. This makes partial remote-finalize recovery and public commit retries
idempotent.

Raft persistent state now also has a separate per-index private ORAM session
lease map. A lease contains the owner peer, a SHA-256 hash of an opaque lease
id, and bounded issue/expiry times; collection identity and vector name remain
hidden behind the same domain-separated index-key digest used by epoch state.
Lease updates use exact CAS. They support initial acquisition, same-owner
renewal, exact release, and deterministic expired-owner takeover only when the
new issue time is at or after the previous expiry. Early takeover, stale
release, overlong leases, malformed hashes, and capacity overflow fail closed.
Lease state survives process restart and Raft snapshot restore, and debug/log
projections redact the index identity and lease hash. Dispatcher exposes an
awaited Raft apply bridge and current-lease lookup. The qdrant coordinator
derives a domain-separated SHA-256 lease hash from the node-local session id,
acquires or expired-takes-over the lease, verifies owner/hash/expiry before
session work, renews it only after commit authorization and owner-signature
validation, and releases only an exact local lease. Oversized lease ids and
lease errors do not reflect the submitted session id. A commit pins its local
session while network/Raft work is in progress, so read, close, expiry cleanup,
and a second commit cannot interleave with its writeback.

## Payload text

Selected JSON string fields are replaced with a single marker object:

```json
{
  "$qdrant_sec": {
    "kind": "payload_text",
    "envelope": {
      "version": 1,
      "algorithm": "AES-256-GCM",
      "key_id": "tenant-a:payload",
      "material_fingerprint": "...",
      "rk_id": "tenant-a/payload-v1",
      "rk_epoch": 3,
      "nonce": "...",
      "ciphertext": "..."
    },
    "schema_version": 1,
    "encryption_epoch": 0
  }
}
```

The AEAD associated data binds ciphertexts to `collection`, `point_id`, and field
path. Moving a ciphertext to another point or field must fail authentication.
Payload selectors are object dot paths only. Array syntax, wildcards, and
numeric path components such as `items[].name`, `items.*.name`, or
`items.0.name` are rejected instead of being interpreted as array traversal.
Selector components that collide with reserved envelope markers
`$qdrant_sec`, `$qdrant_client_aead`, or `$qdrant_ciphertext` are rejected.

Runtime crypto instances currently accept only these provider IDs:
`payload/aes-256-gcm@v1`, `payload/client-aead@v1`,
`payload/private-result-oram@v1`,
`metadata/aes-256-gcm@v1`, `metadata/blind-index-hmac@v1`,
`vector/openfhe-ckks@v1`, `vector/client-ckks@v1`, and
`vector/private-hnsw-oram@v1`.
Unknown provider IDs fail runtime settings
validation instead of being treated as extension points.
`payload/aes-256-gcm@v1` must bind a `materials.sym_key` resource key and set
an explicit `options.material_fingerprint_id`; it must not configure
`backend_ref`; it is an in-process AEAD provider, not an OpenFHE bridge client.
`metadata/aes-256-gcm@v1` has the same material and fingerprint requirements,
but it must be selected through `metadata_keys` with `metadata-value/v1`.
`vector/openfhe-ckks@v1` must bind `materials.sym_key` for vector envelope
metadata sealing, set `options.material_fingerprint_id`, and configure
`backend_ref` for the OpenFHE bridge.
`metadata/blind-index-hmac@v1` is server-blind: clients compute exact-match
tokens outside Qdrant, and the runtime instance only pins non-secret key lineage
metadata with `key_id`, `expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`.
`vector/client-ckks@v1` is server-blind opaque vector storage: it forbids
server materials/backends and pins client CKKS public material, RK lineage,
`search_mode: opaque_storage_only`, and signing public keys.
`vector/private-hnsw-oram@v1` is server-blind searchable ANN storage: it also
forbids server materials/backends and pins RK lineage, private HNSW/Path
ORAM/fixed-budget policy, integrity requirements, and signing public keys.
Runtime crypto materials currently accept only `symmetric_key_32`,
`wrapping_key_32`, and `wrapped_symmetric_key_32` kinds.

### Client-side encrypted payloads

Zero-trust client-side payload encryption uses a separate provider from
server-side `payload/aes-256-gcm@v1` encryption:

```yaml
crypto:
  instances:
    docs_payload_client_v1:
      provider: payload/client-aead@v1
      materials: {}
      # backend_ref must be omitted. This provider is server-blind:
      # Qdrant stores and verifies client envelopes, but never holds the
      # client data key or runs a bridge/backend for this payload field.
      options:
        key_id: tenant-a/client-rk-2026-04
        key_id_required: true
        expected_rk_id: tenant-a/client-rk-2026-04
        min_rk_epoch: 3
        max_rk_epoch: 3
        signature_public_keys:
          tenant-a/client-signing-v1: base64url-no-pad-ed25519-public-key
          tenant-a/client-signing-v2: base64url-no-pad-ed25519-public-key
    docs_body_blind_v1:
      provider: metadata/blind-index-hmac@v1
      materials: {}
      # backend_ref must be omitted. The HMAC/blind-index key is client-held;
      # Qdrant only stores and indexes the resulting opaque exact-match token.
      options:
        key_id: tenant-a/client-rk-2026-04
        expected_rk_id: tenant-a/client-rk-2026-04
        min_rk_epoch: 3
        max_rk_epoch: 3
params:
  encryption:
    version: 1
    key_id: tenant-a/client-rk-2026-04
    crypto_schema_version: 1
    # For client-envelope bindings, this is the pinned active client RK epoch
    # that the collection guard rechecks before storage.
    encryption_epoch: 3
    migration_state: active
    rules:
      - id: body_client_conf
        selector:
          kind: payload_paths
          paths: [body]
        instance: docs_payload_client_v1
        binding: client-payload-envelope/v1
      - id: body_blind_eq
        selector:
          kind: metadata_keys
          keys: [body__blind_eq]
        instance: docs_body_blind_v1
        binding: metadata-exact-match-token/v1
```

`payload/client-aead@v1` fails runtime validation if `materials` is non-empty,
`backend_ref` is configured, or server-side options such as `retired_materials`
are present. Server-side wrapping keys/RKs belong to `payload/aes-256-gcm@v1`;
client-side payload envelopes must keep client data keys outside the Qdrant
process. Startup validation also fails unless
`key_id` is required and `expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`
are set explicitly. If the instance also sets `options.key_id`, it must match
`expected_rk_id`; at collection binding time `expected_rk_id` must also match
the collection encryption `key_id`. `min_rk_epoch` and `max_rk_epoch` must be
identical; broad epoch ranges are rejected so a client provider pins exactly one
active resource-key epoch.
For collection rules bound to `client-payload-envelope/v1`, `encryption_epoch`
must be non-zero and match that active client RK epoch. The collection write
guard uses it as a second fail-closed check even after the public runtime write
plan has verified the envelope.

This provider does not receive plaintext and does not unwrap a data key. The
client encrypts before insert and Qdrant only validates the envelope schema,
AAD metadata, key policy, nonce/ciphertext encoding, and Ed25519 signature
before storing the opaque ciphertext. By default every write must carry a valid
`signature` object whose `key_id` selects one configured public key from
`signature_public_keys`. Legacy single-key verifier options
`signature_key_id` and `signature_public_key_b64` are rejected; use the
registry form so key rotation and runtime parity checks cover the full verifier
policy.

Unsigned client envelopes are rejected. Qdrant cannot verify the client-side
AES-GCM tag without the client data key, so the Ed25519 signature is the
write-time authenticity check for this zero-trust mode.

Client envelopes must carry `rk_id`, `rk_epoch`, and
`kdf_domain: qdrant-sec/client-payload-text/v1`. Provider instances must pin
`expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch` to a single active epoch
so stale, retired, or wrong client resource-key epochs fail closed during
rotation.
The language-neutral fixture
`docs/qdrant-sec-resource-key-rotation-test-vector.json` fixes the
length-prefixed RK-wrap AAD, old/new local MKs, deterministic test nonces, and
wrapped RK ciphertexts so SDKs can verify MK rewrap compatibility without
learning any production key material.
Envelope `key_id`, `rk_id`, and `signature.key_id` values, plus matching
provider options such as `key_id`, `expected_rk_id`, and signature registry
keys, must use the bounded qdrant-sec crypto identifier syntax
`[A-Za-z0-9._:/@-]`.

For payload writes, the `aad.collection_id` value is the collection's stable
crypto identity. Encrypted collection create/recovery paths must have a
persisted collection UUID; existing encrypted snapshot recovery fails closed if
either side is missing a UUID or if the UUIDs differ. Public encrypted write
paths and the collection write guard fail closed when an encrypted collection
does not have a persisted UUID; collection names are not accepted as the
production crypto identity.

Qdrant rejects duplicate client-side AEAD nonces within a single public write
request, including `update_batch`, and records validated nonces in a
collection-local replay cache keyed by the collection's stable crypto identity
and `(key_id, rk_id, rk_epoch, nonce)`. The cache is persisted under the
collection directory and loaded on collection restart, so replay is caught
across later requests and same-node reloads. On collection load, Qdrant also
scans already stored `$qdrant_client_aead` envelope markers for configured
client-payload paths and backfills missing replay-cache entries; stored duplicate
nonces fail closed. A cluster-wide replay index is not implemented, so
`payload/client-aead@v1` collection runtime validation and public writes fail
closed when `cluster.enabled=true`; clustered zero-trust client envelope ingest
requires a future consensus-backed nonce ledger. SDKs must still generate fresh
96-bit CSPRNG nonces and regenerate envelopes on retry instead of replaying
failed request bodies. Nonces are recorded before shard storage is attempted so
the policy fails secure; if a write returns an error after envelope validation,
clients must build a new envelope with a new nonce before retrying.

```json
{
  "body": {
    "$qdrant_client_aead": {
      "version": 1,
      "kind": "payload_text",
      "algorithm": "AES-256-GCM",
      "key_id": "tenant-a/client-rk-2026-04",
      "rk_id": "tenant-a/client-rk-2026-04",
      "rk_epoch": 3,
      "kdf_domain": "qdrant-sec/client-payload-text/v1",
      "aad": {
        "collection_id": "persisted-collection-uuid",
        "point_id": "1",
        "field_path": "body",
        "schema_version": 1
      },
      "nonce": "base64url-no-pad-96-bit-nonce",
      "ciphertext": "base64url-no-pad-client-ciphertext",
      "signature": {
        "alg": "ed25519",
        "key_id": "tenant-a/client-signing-v1",
        "sig": "base64url-no-pad-signature"
      }
    }
  }
}
```

Client envelopes are not server envelopes. Public writes to a
`payload/aes-256-gcm@v1` rule reject client-supplied `$qdrant_sec` markers, and
`payload/client-aead@v1` rules require `$qdrant_client_aead` markers. Because
Qdrant does not have the client data key in this mode, it cannot verify the
AES-GCM tag or decrypt responses; clients or SDKs must decrypt returned
envelopes. Client envelopes must include `rk_id`, `rk_epoch`, and
`kdf_domain: qdrant-sec/client-payload-text/v1` so resource-key identity is explicit
even though Qdrant cannot unwrap the client key. If the payload also writes
blind-index token fields, the client envelope should include a `blind_indexes`
array of `{ "field_path": "...", "token": "..." }` objects. The Ed25519
signature covers the client envelope header, AAD, sorted blind-index token
manifest, nonce, ciphertext, signature algorithm, and signature key id.
`docs/qdrant-sec-client-payload-signature-test-vector.json` freezes the
canonical length-prefixed signing bytes so external SDKs can verify
interoperability against the server implementation.

Storage does not trust marker shape alone. Public write plans must validate the
client envelope and produce a runtime-verified proof keyed by collection id,
point id, field path, key id, `rk_id`, `rk_epoch`, nonce, ciphertext digest, and
signature digest. The collection write guard recomputes that identity from the
stored marker and accepts the write only when it matches the runtime proof.
Peer replay uses a stricter boundary: target peers do not accept client payload
envelopes on the basis of origin-peer verification alone. Until peer operations
carry verifier policy plus a consensus-backed client nonce ledger, any
`$qdrant_client_aead` marker in a peer replay/update path fails closed instead
of skipping Ed25519 verification on the receiving peer.

Exact-match search over client-side ciphertext uses a separate client-generated
blind-index token field. Qdrant stores and indexes the opaque token, not the
plaintext, and filters must target that token field directly. Range, geo, and
full-text search over client ciphertext remain unsupported.

SDKs that implement this mode must do all cryptographic data-key operations
outside Qdrant:

- Generate a random client RK and derive the payload AEAD key with
  `qdrant-sec/client-payload-text/v1`; do not send the RK to Qdrant.
- Generate a fresh 96-bit CSPRNG nonce for every envelope and regenerate the
  envelope on retry instead of replaying a failed request body.
- Canonicalize AAD with the collection crypto identity, point id, field path,
  schema version, `key_id`, `rk_id`, and `rk_epoch` before signing.
- Sign the envelope with the configured Ed25519 key and rotate signing keys via
  the `signature_public_keys` registry.
- Verify and decrypt raw `$qdrant_client_aead` envelopes on read. Qdrant will
  return the opaque envelope, not plaintext.
- If exact-match filtering is required, generate a separate blind-index token
  with a different client key/HKDF domain and store it in a configured
  `metadata-exact-match-token/v1` field. Plain Qdrant payload indexes remain
  unsupported for encrypted fields themselves.

Collection encryption rules are configured only through the canonical
`params.encryption` section. The old `params.ckks` shape is no longer accepted
on public REST/gRPC create/update paths; use explicit provider bindings instead:

```yaml
params:
  encryption:
    version: 1
    key_id: tenant-a:docs
    crypto_schema_version: 1
    encryption_epoch: 0
    migration_state: active
    rules:
      - id: docs_payload
        selector:
          payload_paths: [body]
        instance: docs_payload_v1
        binding: payload-field/v1
```

Metadata value encryption uses the `metadata_keys` selector with
`metadata-value/v1` and `metadata/aes-256-gcm@v1`. It encrypts selected JSON
string metadata fields through the same server-side AEAD envelope machinery as
payload text, while keeping metadata value rules separate from payload and
blind-index bindings. Plaintext indexes, filters, facets, order-by, group-by,
and formula references over encrypted metadata value paths fail closed. Exact
match over encrypted metadata still requires a separate client-generated token
field using `metadata-exact-match-token/v1` with
`metadata/blind-index-hmac@v1`. Collection config must set a non-empty `key_id`
and non-zero `encryption_epoch` for both metadata value and token fields so
restore, rotation, and runtime parity checks have explicit key-lineage
metadata.

```yaml
crypto:
  instances:
    docs_metadata_value_v1:
      provider: metadata/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/metadata-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/metadata@v1
params:
  encryption:
    version: 1
    key_id: tenant-a:docs
    crypto_schema_version: 1
    encryption_epoch: 3
    migration_state: active
    rules:
      - id: tenant_metadata
        selector:
          metadata_keys: [tenant_id]
        instance: docs_metadata_value_v1
        binding: metadata-value/v1
```

```yaml
params:
  encryption:
    version: 1
    key_id: tenant-a:docs
    crypto_schema_version: 1
    encryption_epoch: 3
    migration_state: active
    rules:
      - id: docs_body
        selector:
          payload_paths: [body]
        instance: docs_payload_client_v1
        binding: client-payload-envelope/v1
      - id: docs_body_blind_eq
        selector:
          metadata_keys: [body__blind_eq]
        instance: docs_body_blind_v1
        binding: metadata-exact-match-token/v1
```

Clients should compute `body__blind_eq` outside Qdrant with a domain-separated
blind-index key such as `qdrant-sec/client-payload-blind-index/v1`, then query
that token field with ordinary exact-match payload filters.
Blind-index tokens deliberately leak equality patterns: the same normalized
plaintext under the same tenant, stable collection crypto id, field path, and
RK epoch produces the same token. Low-cardinality values such as status flags,
booleans, country codes, or small enums can therefore leak frequency
information even though Qdrant never sees the blind-index key. SDKs should
domain-separate the token key by tenant, collection crypto id, field path,
provider id, `rk_id`, and `rk_epoch`, and operators should avoid blind-indexing
fields where equality or frequency leakage is unacceptable.
Token payload values must be base64url-no-padding strings that decode to a
32-byte HMAC-SHA256 output. Qdrant does not hold the blind-index key, but it
does fail closed on missing, non-string, malformed, or wrong-length token
fields before writing them to storage. Key-path payload updates to blind-index
token fields are rejected; write them as full payload objects so the collection
guard can validate the token shape. Payload indexes on blind-index token fields
must target the exact token field and use the `keyword` schema. Filters on blind-index token fields are
also limited to exact-match string tokens, including `match.value`,
`match.any`, and `match.except`; range, geo, full-text, null/empty, or
wrong-length token filters fail closed. Blind-index token fields are not
orderable, groupable, facetable, or usable in score formulas; they are intended
only for exact-match equality filtering over opaque HMAC tokens.
`docs/qdrant-sec-client-blind-index-test-vector.json` freezes one
length-prefixed token-message and HMAC output so external SDKs can verify their
normalization and token generation.

```json
{
  "filter": {
    "must": [
      {
        "key": "body__blind_eq",
        "match": { "value": "base64url-no-pad-client-blind-index-token" }
      }
    ]
  }
}
```

Runtime settings provide key material and providers through the canonical
`crypto` section. The old runtime `ckks` section is no longer part of the
settings schema; `master_key_b64` / `resource_key_b64` direct-key material must
not be used. Define a
`payload/aes-256-gcm@v1` or `payload/client-aead@v1` instance instead:

```yaml
crypto:
  allow_inline_key_material: false
  instances:
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/payload@v1
  materials:
    tenant-a/payload-v1:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk
      wrap_algorithm: AES-256-GCM
      nonce: base64url-no-pad-12-byte-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
      rk_id: tenant-a/payload-rk
      rk_epoch: 3
      state: active
      scope: collection:uuid
    tenant-a/mk:
      kind: wrapping_key_32
      source: env
      env: QDRANT_CRYPTO_MK_B64
```

The generic `crypto` control plane supports a safer MK/RK hierarchy:

- `wrapping_key_32` is an MK/KEK loaded from env/file/`unix_socket`/`vault_kv2`/fd/inline material, or an external AWS KMS / Vault Transit key reference.
- `wrapped_symmetric_key_32` is a random collection or rule RK wrapped by that
  MK using AES-256-GCM, AWS KMS, or Vault Transit.
- Payload text and CKKS vector envelope AEAD keys are still purpose-specific
  HKDF subkeys derived from the unwrapped RK.

Provider `options` are allowlisted per provider. `payload/aes-256-gcm@v1`
accepts only `key_id`, `material_fingerprint_id`, and `retired_materials`;
`payload/client-aead@v1` accepts only its client envelope policy and signature
options; `metadata/aes-256-gcm@v1` accepts the same server-side AEAD options as
payload AEAD; `metadata/blind-index-hmac@v1` accepts only `key_id`,
`expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`; `vector/openfhe-ckks@v1`
accepts only `key_id`, `material_fingerprint_id`, `profile`,
`crypto_context_b64`, `public_key_b64`, `allow_plaintext_queries`,
`plaintext_query_tcb_ack`, `score_plaintext_output_tcb_ack`, and
`signature_public_keys`; `vector/client-ckks@v1` accepts only `key_id`,
`expected_rk_id`, `min_rk_epoch`, `max_rk_epoch`, `search_mode`, `profile`,
`crypto_context_b64`, `public_key_b64`, and `signature_public_keys`;
`vector/private-hnsw-oram@v1` accepts only `key_id`, `expected_rk_id`,
`min_rk_epoch`, `max_rk_epoch`, `search_execution`, `search_mode`,
`result_privacy`, `distance`, `dim`, `hnsw`, `oram`, `fixed_budget`,
`integrity`, and `signature_public_keys`; `payload/private-result-oram@v1`
accepts only `key_id`, `expected_rk_id`, `min_rk_epoch`, `max_rk_epoch`,
`oram`, `integrity`, and `signature_public_keys`; its
`private-result-oram/v1` collection binding validation requires a matching
payload rule backed by that provider, no server materials/backend, pinned RK
epoch, Path ORAM shape policy, integrity policy, and a non-empty signing
verifier registry.
Manifest/bucket upload, session open/close, signed `read_buckets`, and signed
commit REST/gRPC APIs are open, and bucket reads/commits are session-bound with
single-writer epoch/root CAS. Unknown options
fail startup/runtime validation instead of being silently ignored.
Collection-facing private HNSW
ORAM runtime validation errors use fixed descriptions and do not append the
inner setup error detail, so unsupported option names, option values, and reason
strings are not reflected through collection API failures.

Provider `materials` roles are also allowlisted. Server-side payload AEAD and
OpenFHE CKKS vector-envelope providers accept only `materials.sym_key`;
client-side AEAD and blind-index token providers must not configure any server
material or backend. Unexpected material roles fail validation instead of being
silently ignored.

Set `crypto.zero_trust_profile: strict` when the deployment goal is complete
zero trust rather than server-managed encryption. Strict mode is a fail-closed
profile: it rejects server-held crypto materials, OpenFHE bridge backends,
server-side payload/metadata AEAD providers, and the trusted-bridge
`vector/openfhe-ckks@v1` provider. The accepted providers in strict mode are
server-blind `payload/client-aead@v1`, `payload/private-result-oram@v1`,
`metadata/blind-index-hmac@v1`, `vector/client-ckks@v1`, and
`vector/private-hnsw-oram@v1`. Use the non-strict trusted-bridge profile only when
operators explicitly accept that Qdrant/bridge may observe embeddings, scores,
access patterns, and ranking order.

`vector/client-ckks@v1` is a server-blind vector ingest provider. It must not
configure server materials or an OpenFHE backend. Clients submit a signed
`$qdrant_sec_client_ckks_vector` sidecar envelope under
`$qdrant_sec_vectors.<vector_name>`; Qdrant validates schema, stable collection
identity, point id, vector name, `key_id`, `rk_id`, pinned `rk_epoch`,
`context_digest`, ciphertext hash, and Ed25519 signature before storing the
opaque CKKS ciphertext. Plaintext dense vector writes to that vector name are
rejected. The provider must set `search_mode: opaque_storage_only`, which is an
explicit API contract that Qdrant stores the signed opaque vector envelope but
does not score, rank, or index it server-side. Search over these opaque client
vector envelopes fails closed; do not confuse this ingest contract with the
trusted-bridge `vector/openfhe-ckks@v1` search provider.

`vector/openfhe-ckks@v1` remains a trusted-bridge model: Qdrant/bridge may see
plaintext embeddings at ingest and plaintext scores at search. Do not use the
server-side OpenFHE provider as a zero-trust vector insert contract.

`vector/private-hnsw-oram@v1` is the strict zero-trust searchable ANN provider
contract. It uses binding `private-hnsw-oram/v1`, forbids server materials and
OpenFHE backends even outside strict mode, requires pinned RK id/epoch,
configured Ed25519 signing public keys, `search_execution: client_led`,
`search_mode: private_hnsw_oram`, explicit `result_privacy`, and fixed-budget
search in strict mode. Runtime validation also rejects unknown top-level and
nested private HNSW ORAM options instead of silently accepting secret-like policy
drift. Qdrant does not store point-level dense vectors for this provider and
does not score, traverse HNSW, or delete point-level CKKS sidecar vectors
server-side; normal vector writes, `delete_points`, `delete_vectors`, and
server scoring, including legacy search/batch search, ordinary query/fusion/context/MMR,
recommend/discover, `lookup_from` or point-id reference-vector resolution,
grouped search/query, and search matrix paths, fail closed and direct clients
to the private HNSW ORAM session APIs. Ordinary collection peer `SyncPoints`
batches are also rejected for private HNSW ORAM collections. The v1 transfer
exceptions have distinct operation shapes: an exact target shard may receive
`SyncPoints` only from a consensus-recorded, source-preinstalled, unfiltered
fixed-layout `stream_records` transfer, while an exact destination shard may
receive `UpsertPoints` only from an active `MigratingPoints`
`resharding_stream_records` transfer. Both require the
`private_oram_preinstalled` marker and exact transfer/state matching. These
exceptions bypass only the operation-kind blanket guard; they do not permit
point-level private vector or result payload replay. The normal per-field peer
validation still rejects every protected vector name and private result ORAM
payload path. The encrypted ORAM bucket/epoch state is installed and verified
before the marked transfer starts. Phase 11
implements the encrypted bucket store and session read/commit APIs behind this
validated control-plane contract.
Collection config and runtime validation require `vector/private-hnsw-oram@v1`
and `private-hnsw-oram/v1` to be paired exactly, reject multi-vector v1 rules,
and reject overlap with `vector/client-ckks@v1` or `vector/openfhe-ckks@v1`
bindings for the same vector name.
Private HNSW ORAM vector names must also be safe collection-local store path
components, so collection config, manifest, and signed request validation reject
names such as `.`, `..`, names containing `/` or `:`, and names longer than 128
bytes before any bucket-store path is constructed. They also reject names that
normalize to client-owned ORAM state aliases such as `client.state`,
`clientStateSnapshot.json`, `encryptedClientStateSnapshots.json`,
`position.map`, or `stashBackups.json`, including dotted extension forms.
The same private-session guidance is returned even when runtime crypto settings
are absent, so private HNSW ORAM vectors do not fall through to CKKS/OpenFHE
runtime fallback messages on ordinary vector upsert/update, inference-derived
vector writes, point delete, peer `SyncPoints`, `delete_vectors`,
query/search/recommend/discover/group/matrix APIs, `lookup_from` source-vector
resolution, or lower-level collection peer/internal write guards.
Ordinary retrieve/scroll reads that do not request vector output remain allowed,
because they do not ask Qdrant to reveal or score the private vector.
Collection-internal direct query/search/search-matrix entrypoints make the same
binding distinction: `private-hnsw-oram/v1` returns private ORAM session
guidance, while other encrypted vector bindings keep the CKKS sidecar runtime
entrypoint guidance.
Point-level `retrieve`/`scroll` requests that ask for this vector with
`with_vector` also fail closed with the same private HNSW ORAM session guidance;
Qdrant does not expose a CKKS sidecar payload for this provider.
Payload export rejects `with_vector` before applying encrypted payload policy
and points callers at the provider-appropriate vector read or private session
API instead of the ordinary read API.
The gRPC telemetry wrappers attach only the collection label for private HNSW
and private result ORAM calls; vector names, session ids, path labels, bucket
ids, and root hashes are not copied into telemetry extensions.
REST close-session paths route session id shape and length failures through the
same common validator as request bodies, so oversized or malformed session ids
receive the redacted `session_id is invalid` error instead of an early path
validation response.
The private ORAM bucket store is canonical encrypted index data, not an
untrusted acceleration hint: manifests, epoch files, Merkle metadata, and
buckets must live under private non-symlink directories. Directory creation
checks symlink/type before chmod so symlink targets are not hardened by mistake,
and Unix group/world access on bucket directories or files is rejected fail
closed.
Bucket-file read bounds account for base64url expansion of the configured
decoded ciphertext limit plus bounded JSON metadata overhead, so the largest
allowlisted ORAM bucket shapes remain readable without weakening oversized-file
rejection.
Runtime and signed-manifest validation keep fixed path budgets executable:
`oram.path_batch_size` must fit within the Path ORAM leaf count, and
`fixed_budget.paths_per_round` must equal `oram.path_batch_size`. This prevents
SDK/server disagreement and avoids configurations that could only be satisfied
by duplicate `read_paths` labels.
Commit writebacks are budgeted per session rather than per read round: a
session may rewrite one path worth of buckets for every path it read (never
fewer than one fixed round, never more than the tree), and `new_epoch` must be
exactly `old_epoch + 1`. A verified fixed-budget search therefore reads
`upper_layer_steps + base_layer_steps` paths under one pinned root and commits
them in a single writeback; the SDK planners default to that budget and expose
`*_with_read_paths` variants for sessions that read a different number of
paths (for example a result ORAM token fetch spanning several batches).
They also reject `dim`, `hnsw.fixed_neighbor_slots`, and
`oram.block_size_bytes` combinations that cannot hold the fixed-size f32 node
block layout. For example, a 1536-dimensional index with 64 fixed neighbor
slots requires a 16 KiB block-size allowlist entry rather than 8 KiB.
Signed manifests must also match the runtime instance's `hnsw`, `oram`, and
`fixed_budget` policies exactly; upload fails closed if the client signs a
manifest for a different ORAM shape or search budget than the configured
runtime provider.
Signed private HNSW and private result ORAM writebacks persist a validated
pending journal before changing any active bucket. Retrying the same
owner-signed commit revalidates that journal, idempotently rewrites its
encrypted buckets and Merkle tree, applies epoch/root CAS when still needed,
verifies the final state, and removes the journal with a directory fsync. This
resumes crashes before writeback, between bucket/Merkle writes and epoch CAS,
or immediately after epoch CAS. Until retry completes, the current epoch is
either still old or atomically advanced to new, and mixed root/bucket reads
fail closed. A pending journal also keeps snapshot preflight closed because
private ORAM temporary directories must be empty. After a process restart,
opening a replacement session at the signed new epoch detects the journal,
reserves the index write window, verifies and completes the journal, then
atomically converts that reservation into the new session writer lease. Invalid
or tampered journals keep session open fail closed.
Collection snapshots include private HNSW ORAM bucket files as ciphertext-only
JSON artifacts after rejecting non-directory or symlinked private ORAM snapshot
sources, unsupported source file types, client-owned ORAM state files, and
non-empty private ORAM temp write directories. Snapshot source preflight and
archive append also reject non-canonical private ORAM store entries before they
are written to the archive, and validate current epoch plus canonical epoch
commit file contents again at archive time. Client-owned state detection covers
snake_case, camelCase, kebab-case, and dot-separated aliases for client state,
encrypted client state snapshots, position maps, ORAM/token position maps, and
stashes, including `ciphertext_sha256` backup variants and payload fetch token
singular/plural aliases such as `payloadFetchToken`, `payloadFetchTokens`, and
`payload.fetch.token`.
Empty private ORAM temp directories are omitted from the archive;
snapshot tests seal a plaintext sentinel into a client bucket and assert that
the raw snapshot archive and restored bucket file do not contain the sentinel
bytes.
Snapshot restore preflight applies the same fail-closed tree hardening: private
ORAM restore roots, HNSW vector store directories, and nested entries must be
non-symlink regular files or directories, with unsupported file types and
unexpected client-owned state aliases rejected before manifest/epoch/bucket
parity is accepted. Restore also rejects files outside the canonical store
layout: manifest/signature files, encrypted bucket files in the manifest range,
`merkle/nodes.dat`, `epochs/current.json`, and canonical numeric epoch commit
files. Epoch commit files must parse as bounded JSON epoch/root records, carry a
canonical 32-byte base64url root hash, and match the epoch encoded in the
filename.
Collection and full snapshot creation also fail closed while any active private
HNSW ORAM or private result ORAM session exists for the collection, because a
session may be remapping paths and writing back buckets. While a private ORAM
collection/full snapshot guard is active, new session opens and manifest/bucket
uploads fail closed for the same reason. The error is sanitized and does not
include collection-local private ORAM filesystem paths or bucket roots.
Public REST and gRPC collection update/delete paths acquire the same private
ORAM lifecycle guard before submitting the collection meta operation. That keeps
vector/HNSW/quantization config changes and collection deletion from overlapping
active private ORAM sessions or manifest/bucket upload write windows, and it
also keeps collection/full snapshots from overlapping lifecycle operations.
While the lifecycle operation is in flight, new private ORAM sessions/uploads
and new collection/full snapshots fail closed.
REST and gRPC route fixtures cover both directions of this exclusion for private
HNSW ORAM and private result ORAM session/upload APIs, collection/full snapshot
creation with active lifecycle or active session guards, shard snapshot
list/create/stream/download/delete, shard recovery, and partial snapshot
manifest/recover-from routes. REST collection recovery fixtures also cover
active session/snapshot/upload guards.
Snapshot creation also fails closed while a private HNSW ORAM or private result
ORAM manifest/bucket upload write-window guard is active for the collection,
because upload writes canonical manifest, bucket, Merkle, and epoch files.
Snapshot creation also refuses to archive orphan private HNSW ORAM vector stores
whose on-disk store does not match a configured private HNSW ORAM encryption
rule, or configured private HNSW ORAM vector rules whose on-disk store is
missing.
Before writing an archive, collection snapshot creation also runs the same
private HNSW ORAM manifest/current epoch/bucket/Merkle layout parity preflight
used by restore. Missing bucket files or root mismatches fail closed without
reflecting collection-local paths, root hashes, or bucket ciphertexts.
Restore preflight rejects result-private manifests, collection/vector context
mismatches, vector dimension/distance mismatches, manifest signature key-id
mismatches, Path ORAM tree_height/bucket_count mismatches, current epoch/root
mismatches, bucket commitment roots that do not reconstruct the manifest
`root_hash`, and missing encrypted bucket files anywhere in the manifest bucket
range before shard restore proceeds. Symlinked vector directories and bucket
files are rejected by the same restore preflight. If a private HNSW ORAM store
root exists, every on-disk vector store must match a configured private HNSW
ORAM encryption rule, and every configured private HNSW ORAM vector must have a
store. Orphan stores, missing configured stores, and parent store symlinks fail
closed before manifest or bucket data is trusted.
The live REST and gRPC fixtures also exercise adversarial commit handling: a
commit with a non-increasing new epoch is rejected, a validly-shaped but wrong
Ed25519 signature is rejected, and replaying a previous old epoch/root after a
successful commit is rejected against the active session state. The commit path
also preflights the store's current epoch/root against the active session before
bucket or Merkle writeback starts, and the store writeback helper also requires
the stored signed manifest's epoch/root and bucket_count to match the commit old
context before accepting updated buckets. The `read_paths` path performs the
same current epoch/root preflight before returning encrypted buckets, so a
rolled back or mixed current epoch fails closed before bucket ciphertexts are
served.
It now reads buckets through the collection store's batch+proof helper, which
rechecks current epoch/root and fails closed if any returned bucket commitment
does not match the corresponding Merkle proof leaf.
They also reject opening a second session for the same private index while the
first session is active, exercising the MVP single-writer lock at the route
layer. After registering a session, session open rechecks the stored
manifest/signature/current epoch; if a concurrent manifest or epoch update was
observed during open, the new session is closed and the request fails before any
ORAM path reads are served. Session open also requires encrypted bucket/Merkle
metadata for the signed manifest epoch/root, so a manifest-only upload state
does not open a session. Session open requests with `fixed_budget=false` in
strict mode or a non-current desired epoch are rejected before any ORAM path
reads are served. `private_payload_oram_required` is accepted at HNSW
manifest/session policy only when the collection also has a
`private-result-oram/v1` payload binding; otherwise it fails closed. Client id
shape errors are sanitized without echoing the submitted client id; session
clients must use non-empty safe ASCII resource-id characters within the
configured length bound.
Expired sessions are purged from the registry before use and release the
single-writer lock for that private index; using an expired session id for
`read_paths`, `commit`, or `close` fails closed.
Oversized or malformed session ids are rejected before registry lookup without
reflecting the submitted value, while unknown well-shaped session ids still use
the sanitized missing/expired-session error.
`read_paths`, `commit`, and encrypted bucket upload also validate submitted
root hashes as canonical 32-byte base64url values before registry/storage
epoch comparisons, without reflecting malformed values.
`read_paths` and `commit` client signatures are length-checked as fixed
64-byte Ed25519 base64url values before decode/verification.
Runtime `signature_public_keys` verifier entries are likewise treated as fixed
authorizer policy: the registry must be non-empty, key ids must be valid
resource ids, entries must be 32-byte Ed25519 base64url public keys, and
duplicate public keys under multiple ids are rejected before signature
verification.
Signed manifest upload and initial encrypted bucket upload are also rejected
while an active session holds the same private index, so a bulk upload cannot
race a client-led traversal/writeback session. The upload path also holds a
registry write-window guard while manifest or bucket files are being written;
same-index session opens and duplicate uploads fail closed until that guard is
released.
The manifest signs the upload anchor epoch/root and non-secret index policy,
while `epochs/current.json`, Merkle metadata, and CAS are authoritative for the
live epoch/root after writeback commits. A writeback commit that advances
epoch/root does not require Qdrant to receive a freshly signed manifest before a
later session can open at that new epoch. REST and gRPC live fixtures now close
the committed session, verify that the closed session id cannot be reused for
`read_paths`, verify that unknown close-session ids are not reflected in error
responses, and re-open successfully at the committed epoch without manifest
refresh. They also use the reopened session's live epoch/root to perform a
signed `read_paths` call, so post-commit progress is covered past session open.
For initial signed manifest upload, Qdrant writes the manifest/signature before
publishing `epochs/current.json`, so a manifest-store write failure does not
leave a current epoch without a corresponding signed manifest.
If the stored manifest already matches the current epoch/root, repeated
manifest upload is accepted only as a byte-identical no-op. A refreshed signed
manifest is still accepted after commit when `epochs/current.json` has advanced
past the stored manifest and the uploaded manifest matches the new current
epoch/root.
Unknown session id handling for `read_paths`, `commit`, and `close` returns
sanitized errors without echoing the submitted session id.
SDKs may use `refresh_private_hnsw_oram_manifest_for_commit` or
`sign_private_hnsw_oram_manifest_refresh` when a commit plan was built from
the same signed manifest and they want an updated signed manifest body. The
server does not require that refresh for session reopen; clients that continue
from `epochs/current.json` without uploading a refreshed manifest must use
`plan_private_hnsw_oram_commit_for_manifest_context` so bucket commitments
remain bound to the signed manifest lineage while the old epoch/root comes from
the live store state rather than the older upload-anchor manifest.
Before the first signed manifest upload, REST and gRPC manifest read, bucket
upload, and session open calls fail closed with a sanitized `NotFound`
response; they do not surface collection-local private ORAM paths. Corrupt
stored manifest reads are also sanitized without exposing collection-local
`private_hnsw_oram` filesystem paths.
Signed manifest uploads whose collection/vector, key lineage, or vector
metadata context does not match the route and runtime context fail closed
before manifest persistence. Unsupported manifest signature algorithms and
malformed manifest signature errors are sanitized without echoing the submitted
algorithm or signature body. Signature key id lookup failures for manifest
upload, `read_paths`, and `commit` are also sanitized without echoing the
submitted key id. Manifest upload validates the signature algorithm, key-id
shape, and signature body shape before looking up the configured public key, so
malformed signed requests do not reach the verifier registry lookup boundary.
Manifest upload/read, bucket upload, session open, and snapshot restore
preflight also require the stored manifest signature `key_id` to match the
manifest's `owner_signing_key_id` before the verifier public key is looked up,
so non-owner manifest key ids do not reach the registry lookup boundary.
Runtime validation rejects registering the same Ed25519 verifier public key
under multiple key ids. This keeps `owner_signing_key_id` authorization
unambiguous even though the HNSW v1 canonical manifest signature format binds
the owner through the signature header and verifier selection.
The SDK/server manifest signature validators also validate manifest shape before
canonical manifest signature message construction. SDK signing helpers reject
malformed manifests, path-count mismatches, malformed path labels/roots, and
malformed commit hashes, non-advancing commit epochs, and empty commits before
constructing canonical signature messages. Server verification and SDK signing
use the checked `try_private_hnsw_oram_*_signature_message` builders, so
oversized canonical domain, string, path-count, or bucket-count fields fail
closed instead of truncating length prefixes. The older infallible HNSW ORAM
message-builder wrappers are not part of the public contract; callers must use
the checked builders. `docs/qdrant-sec-private-hnsw-oram-signature-test-vector.json`
freezes manifest, `read_paths`, and `commit` canonical messages, SHA-256
digests, and deterministic Ed25519 signatures for SDK interoperability.
The checked `read_paths` and `commit` message builders also reject unsupported
request signature algorithms and malformed signature key ids before canonical
message construction.
The `read_paths` and `commit` client signatures use the same key-id shape check
before verifier lookup; invalid key ids are rejected without echoing the
submitted value. For active sessions, the request key id must match the session
manifest's `owner_signing_key_id` before the verifier public key is looked up,
so non-owner key ids do not reach the registry lookup boundary. The `read_paths`
and `commit` crypto validators also reject malformed collection/vector/key
lineage, `requested_paths`/path-count mismatches, and non-advancing commit
epochs before signature body parsing or canonical message construction.
Unsupported request signature algorithms on these paths are rejected without
echoing the submitted algorithm value.
The REST/gRPC `read_paths` and `commit` handlers run request-shape preflight
for bounded path labels, root hashes, padding, and updated-bucket refs before
bucket access or writeback. Shape-valid requests then verify the client
signature before bucket-path derivation, Merkle preparation, or writeback.
Manifest-store layout failures during upload are sanitized without exposing
collection-local `private_hnsw_oram` filesystem paths.
Path ORAM manifests must also bind `bucket_count` to the canonical full binary
tree size implied by `tree_height`, so malformed layouts are rejected before a
session can reach `read_paths`. The SDK Path ORAM helpers reject `tree_height =
0` as a degenerate tree shape, matching manifest/runtime validation.
Runtime validation currently caps private HNSW and private result ORAM
`tree_height` at 20 because the MVP stores Merkle metadata as bounded JSON;
larger trees require the future compact/proof-oriented Merkle store before they
can be accepted safely.
It also caps the decoded ciphertext bytes in one fixed ORAM read batch, computed
from `path_batch_size * (tree_height + 1)` and the fixed bucket ciphertext size,
so a runtime policy cannot create an oversized `read_paths` or `read_buckets`
response.
Initial bucket upload also rejects incomplete bucket sets, duplicated bucket
ids, malformed bucket ciphertext, and ciphertext hash mismatches before
encrypted bucket files are written. Bucket commitments must also match the
server-verifiable commitment over collection/vector/key lineage, bucket id,
index epoch, and `ciphertext_sha256`. Upload and commit ingress additionally
bound the base64url ciphertext length before decode and then check that decoded
bucket ciphertext length exactly matches the fixed Path ORAM bucket size implied
by `oram.bucket_size` and `oram.block_size_bytes`; a shorter or longer
ciphertext is rejected even when its hash and commitment are self-consistent.
The initial upload ordering and fixed-size ciphertext ingress errors are fixed
messages and do not echo bucket ids, bucket epochs, or bucket ciphertexts.
The malformed ciphertext, fixed-size mismatch, bucket hash/commitment/root hash
shape, bucket commitment context mismatch, and Merkle root mismatch error paths
do not echo the submitted ciphertext or computed Merkle root into REST response bodies or gRPC
status messages, and epoch/root mismatch handling does not echo the submitted
root hash. Bucket-store layout failures during upload are sanitized without
exposing collection-local `private_hnsw_oram` filesystem paths. Corrupt
current-epoch metadata observed during bucket upload or session open is
sanitized the same way.
The collection-local private HNSW ORAM store also avoids reflecting bucket ids
or bucket epochs in bucket read/proof/commit validation errors, and its
current-epoch, Merkle tree context, and bucket-shape errors are fixed messages
without stored/requested epoch, bucket-count, bucket-id, or unsupported-version
values. Its file/directory hardening helpers also use fixed messages instead of
reflecting collection-local paths, temp filenames, symlink targets, or OS error
strings.
Session-open stale epoch errors do not echo the requested or current epoch.
Unsupported runtime `result_privacy` values and collection/runtime vector
dim/distance mismatches are also fixed messages that keep the structured
failure reason without reflecting submitted option values or actual vector
shape values. The `qdrant-sec` private HNSW provider/client and private result
ORAM helper error `Display` implementations keep structured enum fields for
callers while avoiding bucket ids, epochs, versions, ciphertext lengths, leaf
labels, or unsupported algorithm values in rendered strings.
REST and gRPC `read_paths` error handling is checked for non-reflection:
epoch/root mismatches and malformed path labels fail without echoing the
submitted root hash, submitted path label, or any stored bucket ciphertext into
the response body/status message. The path-to-bucket derivation helper also
maps lower-level leaf-label decode failures to the same fixed message. Exact
duplicate path labels are rejected before bucket reads so a larger path batch
cannot satisfy the fixed budget by repeating the same leaf. Missing encrypted
bucket/proof data is
reported as sanitized unavailable bucket data without exposing collection-local
`private_hnsw_oram` filesystem paths.
Before returning a `read_paths` response, Qdrant also checks that each encrypted
bucket commitment matches the same-position Merkle proof leaf. Bucket/proof
mismatches fail closed without echoing bucket ciphertexts or store paths.
For successful fixed-budget reads, the server preserves each requested ORAM
path's full bucket sequence instead of collapsing the response to a unique
bucket set. Shared prefix buckets may therefore appear more than once in the
response, and the SDK Merkle verifier accepts only byte-identical repeated
bucket/proof entries. This keeps the encrypted bucket response length fixed at
`requested_paths * (tree_height + 1)`. SDK proof JSON verification bounds the
proof body before parsing so oversized proof responses fail as malformed proof
JSON rather than reaching the JSON parser.
Active sessions do not keep serving under stale runtime policy. Each `read_paths`
and `commit` call compares the session manifest against the current runtime
context, including collection/vector identity, key lineage, vector metadata,
result privacy, and the `hnsw`/`oram`/`fixed_budget` policy; drift fails closed.
REST and gRPC route fixtures both exercise this by opening a session under one
runtime policy and then rejecting `read_paths` or `commit` through a service
with drifted `fixed_budget` or `oram` options.
The request signing key must also match the session manifest's
`owner_signing_key_id`; merely being present in `signature_public_keys` is not
enough to authorize ORAM read or commit requests for that private index.
For `read_paths`, the server bounds each ORAM leaf label to the canonical
fixed-length base64url form and rejects duplicate path labels without
reflecting malformed labels. After fixed-budget and session epoch/root checks,
shape-valid requests verify the Ed25519 request signature before computing
bucket paths. The SDK/server read-path signature message builder and validator
also shape-check the root hash, path labels, padding metadata, and duplicate
path-label invariant before signature body parsing.
For `commit`, the server bounds `old_root_hash` and `new_root_hash` to
canonical 32-byte base64url strings and rejects empty, oversized, duplicate, or
malformed updated-bucket refs before storage writes. Shape-valid requests
verify the Ed25519 request signature before preparing Merkle/writeback metadata.
The commit signature message builders and validators also reject empty commits,
non-advancing epochs, malformed roots, duplicate
bucket refs, and malformed updated bucket ciphertext hashes before signature
acceptance.
Malformed client signature shape errors for `read_paths` and `commit` are also
sanitized so submitted signature bodies and unsupported algorithm values are not
echoed.
Commit error handling follows the same boundary: malformed updated bucket
ciphertext, malformed new root hashes, and old epoch/root mismatches are
rejected without echoing the submitted ciphertext, new root hash, or old root
hash into the REST body or gRPC status message. Missing commit Merkle metadata
is reported without exposing
collection-local `private_hnsw_oram` filesystem paths. Empty and oversized
`updated_buckets` commits are rejected by fixed writeback request-size
validation before bucket writes are attempted; the SDK/server commit signature
validator also rejects empty commit bucket lists and malformed root hashes
before signature body parsing. Each updated bucket `ciphertext_sha256` is
shape-checked before signature message construction, and each updated bucket
must also carry exactly the manifest-derived fixed ciphertext size.
Commit writebacks also validate every updated bucket commitment against the
bucket ciphertext hash plus collection/vector/key lineage and the proposed
bucket epoch before Merkle metadata is prepared or bucket files are written.
The same live fixtures reject `read_paths` calls whose path count, requested
path count, or dummy padding flag does not match the configured fixed path
budget, before bucket reads are served. Valid `read_paths` calls must carry an
Ed25519 client signature over
collection/vector identity, key lineage, epoch/root, path labels, and padding
metadata before encrypted buckets are returned.
Snapshot restore preflight follows the same result-privacy boundary: private
HNSW ORAM manifests with `private_payload_oram_required` require a configured
private result ORAM payload binding and corresponding result ORAM snapshot store.
It also requires the paired result ORAM snapshot manifest's
`oram.path_batch_size` to divide the private HNSW
`fixed_budget.fixed_result_k`, matching runtime validation and preventing a
restored index from producing partial final `read_buckets` batches. Restore
preflight also checks every
manifest-range bucket for the manifest-derived fixed ciphertext size and verifies
each bucket commitment against collection/vector/key lineage, bucket epoch, and
`ciphertext_sha256` before accepting the Merkle root.
The startup snapshot mapping recovery path runs the same private HNSW ORAM
restore-layout preflight after crypto runtime validation, so CLI recovery
cannot bypass bucket/root consistency checks that are enforced by storage-level
snapshot recovery. Store-originated layout failures in this CLI path are
sanitized before reporting, so collection-local `private_hnsw_oram` paths and
stored bucket bodies are not reflected; CLI layout failures are fixed messages
that also avoid bucket ids and bucket commitment mismatch details.
Private HNSW vector store names must also be safe store path components and
are rejected if they compact to reserved client-owned state aliases such as
`client.state`, `position.map`, `client_state_ciphertext_sha256`,
`client_state_ciphertexts_sha256`, `clientStateCiphertextsSha256`, or `stash`;
snapshot source/archive and restore preflight apply the same checks before
archiving or accepting ORAM store contents.
CLI and REST snapshot recovery also validate stored private HNSW ORAM manifest
and private result ORAM manifest signatures against the runtime
`signature_public_keys` registry after the restore-layout preflight passes, so
tampered manifest signatures fail closed without exposing bucket roots,
ciphertexts, or store paths. Storage-level snapshot recovery also runs private
HNSW ORAM and private result ORAM restore-layout preflight before shard restore
begins and applies the same sanitization before returning layout failures to
callers. Collection-level snapshot manifest and bucket-contract mismatch errors
also avoid reflecting manifest ids, vector names, dimensions, bucket ids, or
bucket ciphertexts.

Current result privacy support has two explicit modes. `result_privacy:
ids_visible` keeps Qdrant blind to vectors, query vectors, visited HNSW nodes,
distances, and client-side top-k during the private session, but a later
ordinary retrieve leaks the retrieved point ids to Qdrant.
`private_payload_oram_required` is accepted only when the same collection also
binds a `payload/private-result-oram@v1` rule through `private-result-oram/v1`,
and result payload fetches must then go through the private result ORAM
session/read/commit path rather than ordinary retrieve. The dedicated result
ORAM REST/gRPC path can upload/read signed manifests plus encrypted bucket
batches, open fixed-budget sessions, return Merkle-proven bucket batches, and
apply signed writeback commits through epoch/root CAS.
Ordinary point upsert, sync, and point delete/delete-by-filter fail closed for a
collection with a `private-result-oram/v1` payload binding because they can
create, replace, or remove payload state outside the private result ORAM epoch
contract. Payload writes also fail closed when they can affect the protected
path: key-less `overwrite_payload` is treated as a full payload replacement,
key-less `set_payload` rejects parent/child path overlap, and `delete_payload`
or payload clear operations that touch the protected path direct callers to the
private result ORAM session APIs instead of falling through to the regular
server/client payload envelope write path. Non-overlapping public payload merges
and explicit sibling paths, such as a `document.title` write beside protected
`document.body`, stay on the ordinary update path.
Ordinary raw payload reads through retrieve, scroll, search, or query also fail
closed when `with_payload` would return a `private-result-oram/v1` payload path.
The public gRPC `GetPoints`, `ScrollPoints`, `SearchPoints`, batch/grouped
search, `RecommendPoints`, batch/grouped recommend, `DiscoverPoints`, batch
discover, `QueryPoints`, and grouped/batch query wrappers follow the same
fail-closed read guard before returning raw protected payload bytes.
Grouped gRPC `with_lookup` payload requests and REST group lookup preflight use
the same guard when the lookup collection is bound to `private-result-oram/v1`.
Callers may omit payloads or request redacted encrypted payload output, so
payload-omitted retrieve/scroll/search requests remain ordinary. Raw or
server-decrypted result payload bytes require the private result ORAM
session/read/commit APIs.
Trusted-bridge CKKS sidecar fallback paths, including point-id query resolution,
grouped search/query, and search matrix sampling, request only the reserved
vector sidecar field and any required group key instead of full raw payloads, so
they do not accidentally read private result ORAM payload paths while resolving
encrypted vector sidecars.
Ordinary server-side selectors that would inspect a private result ORAM payload
path, including filters, order-by, group-by, facets, and formula payload
variables/conditions, fail closed with the same private result ORAM session API
guidance rather than suggesting a blind-index fallback.
The gRPC facet, count filter, scroll filter/order-by, formula query, grouped
search, and grouped query wrappers enforce the same selector guard after
converting their payload paths.
Payload index/schema creation or deletion on a `private-result-oram/v1` payload
path, including gRPC create/delete-field-index wrappers, is also rejected by the
encrypted payload index guard. Public create/delete-field-index requests check
write/extras authorization before this private-result guard, so unauthorized
callers receive the normal forbidden response without provider/session details.
Result ORAM snapshot restore preflight is open for configured
`private-result-oram/v1` bindings and validates manifest/current epoch, buckets,
Merkle metadata, and runtime Ed25519 signatures. The SDK search result now
propagates each node block's `payload_fetch_token`, and a client-side helper
fails closed when `private_payload_oram_required` hits do not all carry payload
fetch tokens. A follow-on SDK helper turns those hit tokens into an exactly
`fixed_result_k` private result ORAM fetch-token batch, padding from a caller
provided distinct dummy-token pool so the eventual result fetch has fixed
logical volume. The helper validates the whole supplied dummy-token pool,
including unused extra tokens, and rejects any duplicate, hit-token collision,
duplicate hit node/point, or non-finite hit distance before it emits a fetch
plan. Collection runtime validation requires a compatible result ORAM binding
whose `oram.path_batch_size` divides the private HNSW
`fixed_budget.fixed_result_k`, so SDKs do not emit a smaller final
`read_buckets` batch. The result ORAM client fetch planner and verified fetch
wrapper also reject token batches that are not an exact multiple of
`oram.path_batch_size` and reject fetched payload blocks with duplicate point
tokens before returning a token-fetch result. The private result ORAM client
contract can now map that fixed token batch through the client-held
token-position map into session
`read_buckets` bucket-id sequences that preserve shared path bucket duplicates,
so ORAM path volume is not reduced by deduplicating overlapping paths. The SDK
ordered planner distributes same-leaf tokens across fixed-size read batches
when the configured batch count can accommodate them, and rejects impossible
leaf-collision schedules before a server request is built. Server read
validation accepts duplicate bucket ids for shared path prefixes but rejects
empty, repeated full-path, non-whole-path-shaped, non-canonical Path ORAM heap
paths, or batches that do not exactly match the configured fixed path budget.
New SDK integrations should use
`plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens` before
signing `read_buckets` requests when token positions may share a leaf. The
crypto crate also
exposes canonical `read_buckets`
message/sign/verify helpers that bind collection/key lineage, index epoch,
root hash, bucket count, and the exact padded bucket-id sequence; REST and gRPC
`read_buckets` handlers now require that signature before encrypted buckets are
read or detailed path-shape errors are returned.
`sign_private_result_oram_read_buckets_for_manifest_context` derives that read
signature context from the signed manifest lineage while taking the live index
epoch/root explicitly. It enforces the fixed `oram.path_batch_size *
(oram.tree_height + 1)` bucket-id volume and canonical Path ORAM heap path shape
before signing. `sign_private_result_oram_read_buckets_for_manifest` is the
convenience wrapper for the first read after upload or after an optional
manifest refresh, when the signed manifest epoch/root is the live read context.
The planner also rejects missing token positions, duplicate fetch tokens,
duplicate token-position entries, and out-of-range leaves before a server
request is built. The crypto crate also has a client-only private result ORAM
payload block/plaintext bucket codec for
fixed-size bucket contents:
payload bytes, payload fetch token, point token, generation, and deletion state
are encoded inside the client-encrypted bucket body and are never server
validated as plaintext. Client AEAD helpers can seal/open those plaintext
buckets into `PrivateResultOramBucket` ciphertexts with collection/key/epoch
AAD, context-bound bucket commitments, ciphertext hash checks, and
Merkle-proof-before-open verification for read batches. The SDK-side result ORAM
state/access helper can now use the client-held token position map and stash to
access a payload fetch token on a Path ORAM path, remap it to a new leaf, and
produce plaintext writeback buckets for the commit path; the plaintext bucket
codec and access helper reject duplicate payload fetch tokens and duplicate
point tokens before decrypted path blocks are absorbed into the stash. A
higher-level verified
token-fetch helper now rebuilds the expected bucket path sequence from the
client position map before opening server batches, consumes only matching
planned encrypted bucket batches, overlays local writebacks between batched Path
ORAM accesses, returns payload blocks, and reseals unique writeback buckets for
the result ORAM commit planner. The server commit guard caps each owner-signed
writeback set to `oram.path_batch_size * (oram.tree_height + 1)` buckets, so
commit volume cannot expand to the full manifest `bucket_count`; it still
rejects empty commits, duplicate bucket ids, malformed bucket hashes, stale
epoch/root, and invalid signatures before storage changes. Multi-batch result
fetches therefore use repeated fixed-size read/commit windows. The HNSW SDK
finalizer maps only real HNSW hits back to fetched payload blocks and validates
the fetched token set, point-token binding, and deleted-payload rejection before
exposing payload bytes to the caller. A canonical plaintext client-state
snapshot shape now round-trips the result ORAM token position map and stash for
client-side backup validation; snapshot export/import rejects duplicate stash
payload tokens, duplicate stash point tokens, and malformed stash payload block
versions, payload lengths, or stash map-key/token mismatches before state
recovery. An encrypted
snapshot helper rejects malformed collection AAD context identifiers and seals
that backup under a client-derived state key with collection/key/epoch/root AAD
plus ciphertext hash checks. Result ORAM read/commit signature contexts also
reject malformed collection and key identifiers before signing. New SDK code should derive
`PrivateResultOramClientKeys` from the signed result manifest rather than the
deprecated legacy domain-only helper; the manifest-bound derivation length-prefixes
collection id, RK id, and RK epoch into the HKDF info context before deriving
bucket and client-state subkeys. Server-side HNSW manifest upload, bucket upload,
session open, and snapshot restore preflight now accept
`private_payload_oram_required` only when the same collection also has a
`private-result-oram/v1` payload rule backed by
`payload/private-result-oram@v1`; without that binding they continue to fail
closed. Normal Qdrant search APIs remain client-led-session-only for private
HNSW vectors.
The crypto crate defines the payload/result ORAM manifest shape through
`PrivateResultOramManifest`, `PrivateResultOramBucket`, and the checked
`try_private_result_oram_*_signature_message` builders. The older infallible
message-builder wrappers are not part of the public contract; production signing
and verification use the checked builders so canonical field-length or
bucket-count overflow fails closed before Ed25519 verification/signing.
`docs/qdrant-sec-private-result-oram-signature-test-vector.json` freezes
manifest, `read_buckets`, and `commit` canonical messages, SHA-256 digests, and
deterministic Ed25519 signatures for SDK interoperability. It can
validate manifest shape, including
canonical Path ORAM tree_height/bucket_count consistency,
logical plus dummy count against ORAM bucket capacity, Ed25519 signatures,
collection/key/epoch context, and root hash pinning;
the commit signature builder defines the signed bucket writeback CAS input used
by commit handlers. `validate_private_result_oram_bucket_shape`
checks bucket version, epoch, range, ciphertext size, ciphertext SHA-256, and
bucket commitment encoding. `private_result_oram_bucket_commitment` binds a
bucket commitment to collection/key lineage, bucket id, index epoch, and
`ciphertext_sha256`, while encoded ciphertext length is bounded before decode
and `private_result_oram_merkle_root_for_commitments`
fixes the root hash calculation over those commitments.
`plan_private_result_oram_commit` prepares signed writeback plans from the live
old epoch/root and current leaf commitments by checking old-root consistency,
bucket epoch/range uniqueness, the next root, and commit signature bucket refs.
`plan_private_result_oram_commit_for_manifest_context` adds manifest lineage,
bucket-count, fixed writeback budget, and context-bound bucket commitment
validation while still taking the live old epoch/root explicitly.
`plan_private_result_oram_commit_for_manifest` is the stricter convenience
variant for the first commit after upload or after an optional signed manifest
refresh: it uses the signed manifest epoch/root/bucket_count as the old commit
context.
`sign_private_result_oram_manifest` and
`sign_private_result_oram_commit` provide the matching SDK-side Ed25519 signing
helpers, while `sign_private_result_oram_read_buckets_for_manifest_context`
signs manifest-lineage-bound fixed-size `read_buckets` requests with a live
epoch/root. `PrivateResultOramUploadBundle` and
`package_private_result_oram_upload_bundle` package a signed manifest with a
complete ordered bucket set whose commitments match the manifest root.
`validate_private_result_oram_upload_bundle` and the bundle's
`validate_initial_upload_contract` method let SDKs and runtime upload handlers
preflight decoded result bundles with one contract: they validate manifest
shape, ordered bucket ids, bucket ciphertext hash/size, context-bound bucket
commitments, and the manifest Merkle root.
`validate_private_result_oram_upload_bundle_with_signature` and the bundle's
`validate_initial_upload_contract_with_signature` method add the owner Ed25519
verification context to that preflight so runtime upload handlers do not have to
stitch shape validation and manifest signature verification together by hand.
The collection-local result ORAM store uses the shape helper for initial bundle
ingest, then applies its runtime ciphertext size cap before writing files. Its
signed ingest entrypoint uses the combined upload-bundle/manifest-signature
helper before creating the private result ORAM layout, so a bad owner Ed25519
signature leaves `epochs/current.json` absent and does not write bucket files.
The separate manifest upload helper publishes the initial epoch only after the
manifest/signature write succeeds, accepts current manifest reupload only when
the stored manifest and signature are byte-identical, and allows a post-commit
manifest refresh when `current.json` has already advanced to the new
epoch/root. REST and gRPC live fixtures also reopen at that committed epoch
without manifest refresh and perform a signed `read_buckets` call using the
live epoch/root.
Manifest upload, manifest read, session open, bucket upload, and snapshot
restore preflight validate the stored manifest signature shape and require the
signature `key_id` to match the manifest's `owner_signing_key_id` before looking
up the runtime `signature_public_keys` entry. A non-owner manifest signature key
therefore fails with the same sanitized owner-mismatch error whether or not the
key id is configured.
`refresh_private_result_oram_manifest_for_commit` and
`sign_private_result_oram_manifest_refresh` mirror the private HNSW helper by
first validating the current result ORAM manifest shape and deriving the next
signed manifest only when a commit plan's old epoch/root matches it. The
collection crate implements
`PrivateResultOramStore` for the payload/result layer. It writes
`private_result_oram/manifest.json`,
`manifest.sig`, encrypted bucket files, Merkle commitment metadata, and
`epochs/current.json` with the same private directory hardening and epoch CAS
contract used by private HNSW ORAM. Its upload bundle preflight validates
manifest signature shape and owner key id before store writes, and the signed
initial upload path verifies the owner Ed25519 signature before layout creation.
Upload bundle,
commit, and stored Merkle-tree root mismatch errors do not reflect computed
Merkle roots; bucket read/proof/commit validation errors also avoid reflecting
bucket ids or bucket epochs. Current-epoch and Merkle tree context errors are
also fixed messages without stored/requested epoch, bucket-count, or
unsupported-version values. Its file/directory hardening helpers also avoid
reflecting collection-local paths, temp filenames, symlink targets, or OS error
strings. The writeback helper preflights stale current epochs, bucket count, and
bucket commitment context before bucket/Merkle writes. It rejects
empty writebacks before storage state changes, and REST/gRPC commit request-size
validation allows at most the manifest `bucket_count` updated buckets so
multi-batch fixed result fetches can be committed without exceeding a
single-read-batch limit. Its signed writeback entrypoint verifies the SDK
Ed25519 commit signature against the stored manifest lineage
before delegating to that helper, so an invalid commit signature leaves the
current epoch, buckets, and Merkle metadata unchanged. The REST/gRPC commit
handlers reject empty, duplicate, and malformed writeback refs before Merkle or
writeback validation runs, and shape-valid invalid signatures fail without
storage changes. SDK commit planning, signing, and verification also reject
empty commit bucket lists and malformed updated bucket ciphertext hashes, and
validate each updated bucket commitment against the bucket ciphertext hash plus
collection/key lineage and the proposed bucket epoch before preparing Merkle
metadata.
For result ORAM `read_buckets` and `commit`, the request signature shape is
preflighted before session access. Once the active session is resolved, the
request signing key must match the session manifest's `owner_signing_key_id`
before the verifier public key is looked up; non-owner key ids therefore do not
reach the registry lookup boundary and are rejected without echoing the
submitted key id. Unsupported request signature algorithms on these two paths
are rejected on the same generic validation path without echoing the submitted
algorithm value.
The `read_buckets` handler verifies the canonical signed bucket-id sequence
before returning detailed path-shape or bucket-range errors, so unauthenticated
malformed read batches stay on the generic signature-failure path. The crypto
read-buckets message builder, signer, and validator also derive the Path ORAM
tree height from the signed `bucket_count` and reject non-canonical tree sizes,
partial paths, and invalid root-to-leaf bucket sequences before signature
acceptance. The `read_buckets` and `commit` message builders also reject
unsupported request signature algorithms and malformed signature key ids before
canonical message construction.
Directory hardening also checks symlink/type before chmod. It also exposes
`read_merkle_path_batch` with the canonical qdrant-sec
`merkle_path_batch/v1` proof DTO; the REST/gRPC `read_buckets` API returns these
server-verifiable bucket commitment proofs without opening ciphertexts. The
store generator rejects empty bucket batches. `read_bucket_batch_with_proof`
preflights the current epoch/root before reading encrypted buckets, returns the
bucket batch with its Merkle proof, and fails closed if any proof leaf does not
match the returned bucket commitment. The SDK-side
`verify_private_result_oram_merkle_proof` and JSON helper validate proof kind,
epoch/root, bucket count, sibling level/position, and bucket commitment matches
against the same DTO emitted by the collection store. They reject empty
proof/bucket sets, preserve fixed-size path-batch semantics by allowing
repeated bucket/proof entries only when the duplicate entries are
byte-identical, reject oversized proof JSON before parsing, and fail closed on
conflicting duplicates.
`write_initial_upload_bundle` validates an SDK-packaged
signed manifest plus complete ordered bucket set, writes the manifest, Merkle
metadata, encrypted buckets, and initial epoch state, and keeps root mismatch
failures fail-closed. Repeated initial epoch writes are idempotent only for the
same epoch/root and leave the stored current epoch untouched on mismatch.
Repeated initial upload bundles with that same epoch/root are accepted as no-op
only when the stored manifest/signature, Merkle tree, and bucket set already
match the incoming bundle.
`commit_writeback` mirrors the private HNSW ORAM commit order by rejecting empty
or non-advancing writebacks, preflighting current epoch/root and stored manifest
context, validating updated bucket ciphertext/hash plus context-bound
commitments, preparing the Merkle update, writing updated encrypted buckets,
writing Merkle metadata, then applying epoch/root CAS. The live private result ORAM
REST/gRPC commit handlers delegate their signed writeback to
`commit_writeback_with_signature`, so the canonical Ed25519 commit signature,
fixed ciphertext size, context-bound bucket commitment, durable pending
journal, Merkle update, and epoch/root CAS share the same storage boundary.
Exact commit retries resume before-write, mid-write, and post-CAS process
failures idempotently; journal signature or shape tampering fails before active
state changes. Invalid signatures, malformed ciphertext, stale roots, and
commitment-context mismatches likewise fail before bucket, Merkle, or epoch
state changes; runtime error mapping preserves only safe failure categories
such as `ciphertext` or `commit signature` without echoing ciphertext bodies,
bucket ids, or root hashes.
Bucket `index_epoch` records the epoch when that encrypted bucket was last
written. After a writeback commit, unchanged buckets may still carry an older
bucket epoch as long as the current Merkle root commits to their existing
bucket commitment; reads reject buckets newer than the requested session epoch.
Collection snapshots include the `private_result_oram/` directory only when
collection encryption has a configured `private-result-oram/v1` binding backed
by `payload/private-result-oram@v1`. Snapshot creation preflights that
configured store before writing the archive, and rejects orphan result ORAM
stores, missing bucket files, unexpected non-canonical store files, and other
layout drift fail closed. Restore preflight applies the same runtime-bound check
before accepting the recovered collection. The preflight verifies the stored
manifest/signature, current epoch/root, encrypted buckets, and Merkle metadata
against runtime policy.
Snapshot creation and restore still reject symlinks inside the result ORAM
source tree without reflecting symlink targets or bucket filenames. Guard
inspection failures are fixed messages and do not reflect collection paths,
reserved directory names, or OS error strings.
The CLI/startup snapshot mapping preflight applies the same runtime-bound
private result ORAM checks before accepting a recovered collection.
Cluster runtime parity uses the existing crypto capability fingerprint for this
provider as well. The fingerprint includes non-secret private HNSW ORAM and
private result ORAM policy such as tree shape, fixed budget, result privacy mode,
and signing verifier digests, while redacting raw verifier public keys. Its JSON
view recursively sorts object keys before hashing, so equivalent runtime policy
loaded by separate processes cannot diverge because of map insertion order. A
peer with a different ORAM shape or signing verifier fails runtime capability parity
before it can be treated as an equivalent private-ORAM-capable node. The mismatch diagnostic
names the peer and fail-closed condition but does not echo the local or peer
fingerprint strings.
Manual shard transfer is supported on a fixed non-empty shard layout, moving one
shard at a time with `MoveShard` or `ReplicateShard` coordinated on the declared
source peer, explicit `stream_records`, and no temporary `to_shard_id`. The
collection-global private ORAM store is replicated to the union of all
fully-active shard replica owners. The coordinator acquires a bounded consensus
lease reservation for every configured private HNSW/result index, installs the
exact current encrypted bucket stores on the target, validates
epoch/root/writeback-digest acknowledgements, captures the exact current index
states and pre/post topology, bootstraps generation 1 when needed, and only then
submits the marked shard transfer. Completion advances the collection layout by
one generation before activating the target and optionally removing the source.
An exact retry after abort may start with its target replica `Dead`; only that
target is excluded from the captured pre-layout, while every other replica must
remain fully active.
Partial preinstalls are idempotent exact-state copies and do not change
membership. The marked target accepts only the transfer's peer
`SyncPoints` operation needed to initialize ordinary shard records, and normal
peer crypto checks still reject protected vector or private result payload
content. Before any initial or live peer install, the source bounds the complete
encoded request to 512 MiB and splits it into deterministic internal gRPC stream
frames no larger than 1 MiB. Every frame carries the protocol version, exact
sequential index/count, total encoded length, and SHA-256 of the complete typed
request. The receiver bounds allocation, rejects missing, reordered, malformed,
or metadata-drifting frames, verifies the final digest, and only then invokes
the existing typed install validation. It admits one chunked full-store stream
at a time, holds that permit through atomic install, and terminates a stream
that is idle between frames for 30 seconds or exceeds the five-minute permit
wait/decode budget. Partial, stalled, or corrupt streams therefore cannot reach
the store mutation lock or filesystem or accumulate multiple aggregate decode
buffers. Two-process tests
advance both private ORAM stores and
run this preinstall/transfer path for both ReplicateShard (RF=1 to RF=2) and
MoveShard, verify the resulting local shard ownership, wait for the target
shard to become active, and reopen both committed sessions on the target.
A three-peer, two-shard RF=1 process test verifies that initial upload and
writeback reach the two disjoint shard owners but not the non-owner, then
replicates one shard to that third peer and reopens both committed sessions from
the newly preinstalled owner.
Another process test injects a malformed target result-ORAM store after the
HNSW live bundle is installed. The request fails before transfer submission,
does not expose roots, signatures, or ciphertext, releases every reservation,
and succeeds on exact retry after the malformed store is removed.
The post-submit abort process test uses the staging transfer delay to keep a
marked transfer active, verifies that source sessions remain frozen, and then
aborts it. The abort removes the transfer marker, leaves the target replica
`Dead`, preserves its preinstalled encrypted stores, and releases source
sessions. An exact ReplicateShard retry then activates the target and reopens
both committed sessions there.
The restart process test keeps the same marked transfer active, removes both
target ORAM stores, and submits an exact same-key `stream_records` restart from
the current source. The coordinator takes a new consensus reservation,
reinstalls both complete encrypted stores, and submits the restart only after
the target acknowledges them. The replacement marker continues to block source
sessions until the target activates, after which both committed sessions reopen
on the target.
The resharding-restart process test similarly keeps a marked scale-up point
migration active, removes both target stores, and submits an exact same-key
`resharding_stream_records` restart from the current source. The coordinator
reinstalls both stores before proposal, while Raft apply stops only the old
transfer task and preserves the `MigratingPoints` reshard state and target shard
identity. The replacement transfer completes, the reshard finishes normally,
and both committed sessions reopen on the final owner union.
A two-peer RF=2 replica-removal process test keeps an HNSW session active and
verifies that reservation acquisition rejects `drop_replica` without reflecting
the session id or root. After close, the same request removes one replica while
retaining the coordinator owner. Both encrypted stores remain on the removed
peer, but HNSW and result-ORAM session open fail there; committed sessions still
open on the remaining owner.
The opt-in large-bundle process benchmark runs with
`QDRANT_RUN_PRIVATE_ORAM_LARGE_BUNDLE_BENCHMARK=1` and exercises the same live
ReplicateShard path with tree-height-5 HNSW and result stores (63 buckets each).
Its fixture carries 10.504 MiB and 5.254 MiB of base64 ciphertext field bytes,
respectively. Three local unoptimized runs observed 5.891-6.924 seconds for
HNSW upload/commit, 4.202-5.036 seconds for result upload/commit,
11.040-14.592 seconds for the preinstall transfer request, and 11.064-15.662
seconds until the replicated shard was active. The benchmark also rejects any
new peer timeout, health-check timeout, or Raft election logged during the
transfer window. These values are regression observations, not a latency
target or SLA.
Full-store initial/live install RPCs use a dedicated five-minute deadline and
one retry. Receiver-side signature verification, full-store hashing, file
writes, and fsync run on Tokio's blocking worker pool so that an install does
not starve peer health checks or Raft heartbeats. `service.max_request_size_mb`
applies to each bounded stream frame rather than the aggregate install request;
the aggregate request still fails closed above the independent 512 MiB limit.
`ReplicatePoints`, snapshot, WAL, unmarked or unrelated resharding transfer
methods, mismatched or method-changing transfer restart, and final shard-key
deletion remain fail closed. Custom shard-key create, including exact
preinstalled new owners, and non-final drop use the consensus-bound layout
transition described above.
Public scale-up/down resharding is routed through typed private-ORAM start and
finish Raft operations. Start requires a fully-active stable topology, reserves
every configured private ORAM index, captures exact epoch/root/writeback state,
and binds the expected and next shard-layout digests. During
`MigratingPoints`, only exact source-coordinated
`ReplicateShard(resharding_stream_records)` transfers are accepted. Each must
match the active reshard key, source/destination shard and peer, shard-key
mapping, endpoint replica states, `sync=true`, no filter, and no separate
layout transition; all encrypted stores are preinstalled before the marker is
submitted. Hash-ring commits and replica promotion retain the existing stage
checks, with only the exact scale-up `Resharding -> Active` or scale-down
`ReshardingScaleDown -> Active` transition allowed. Finish reacquires every
index reservation, requires the committed write hash ring and fully-active
final topology, advances the private ORAM layout generation, and then applies
the final reshard metadata. `AbortResharding` remains available for cleanup.
New private HNSW/result sessions and writebacks fail closed throughout the
active reshard so the captured index-state digest cannot drift.
Shard-key layout changes are blocked for the same reason: `create_sharding_key`
and `drop_sharding_key` would add or remove shard placement without migrating
collection-local private ORAM buckets or transferring epoch/root ownership.
Replica removal is limited to an exact public `drop_replica` of one `Active`
replica from a fully-active fixed layout. The requesting peer must remain in the
post-remove owner union, the target shard must retain another replica, no transfer
or resharding may be active, and every private HNSW/result index must recover and
acquire a consensus lease reservation before layout revalidation. The resulting
Raft update carries an internal reservation marker; unmarked direct replica-set
remove meta-ops fail independently in storage and collection apply. Successful
removal releases the reservation after apply. An uncertain submit retains it
until expiry, and active client sessions prevent acquisition. Ciphertext stores
are not deleted on the removed peer, but coordinated session open requires that
peer to remain an active owner. Dead/transitional replica cleanup, multiple
removals, final-replica removal, and removal during transfer or resharding remain
blocked until a broader ownership protocol exists.
Manual shard snapshot creation, streaming, download, partial snapshot manifests,
and shard snapshot recovery fail closed for the same reason: shard snapshots do
not yet carry the collection-local private ORAM bucket store with epoch/root
parity. Use collection snapshot/restore preflight for private ORAM collections
until shard-level bucket parity is implemented.
Automatic dead-replica recovery is supported only for the same exact
source-preinstalled per-shard `ReplicateShard` shape on a stable configured
layout. As a final guard, only consensus transfer records carrying the verified
`private_oram_preinstalled` marker may start and finish the stream-records path.
Newly coordinated transfers also carry the exact consensus-bound expected/new
layout and index-state checkpoint used by the dedicated start/finish Raft
operations. Legacy marked records remain readable for snapshot/WAL compatibility.
Restart apply is limited to the exact sole active marked transfer with the same
key, endpoints, and method. Fixed-layout restart additionally requires no
temporary shard, no filter, and `stream_records`; resharding restart requires
the same target shard and `resharding_stream_records` under the matching active
`MigratingPoints` state. Raft apply replaces only that transfer task and keeps
the reshard state intact. Unmarked, mismatched, filtered, method-changing, and
other unsupported transfer progress records fail before moving shard data or
replica state. `Abort` remains allowed for cleanup.
A restarted source peer does not run the normal startup abort for that exact
marked active reshard transfer, and missing in-memory task reconciliation
preserves it as well. The target retries a bounded internal resume request. The
source treats a running, finished, or failed task as an idempotent no-op and
restarts only a missing task after revalidating the exact active state and
reinstalling every encrypted store under fresh reservations. Private sessions
stay blocked until reshard finish. Target-peer restart and every transfer shape
that fails the exact marker/state/source check retain the normal abort path.
A three-peer, two-shard RF=2 process test removes a target's collection-global
HNSW ORAM store, restarts the dead replica, and verifies sequential marked
recovery of its shard replicas followed by an epoch-43 session on that target.
Two parametrized two-peer process tests exercise public scale-up and scale-down
in both HNSW-only and paired HNSW/result configurations. They verify that every
configured private session is blocked during resharding, encrypted stores remain
available on the final owner union, every peer persists layout generation 2,
and each committed epoch/root session reopens after finish. The paired cases
verify both encrypted stores and roots; the HNSW-only cases retain ordinary
public point-record retrieval coverage.
A separate two-peer process test kills the source during an exact marked
scale-up migration, removes both target encrypted stores while the source is
offline, and verifies that target-triggered automatic resume performs fresh
re-preinstall and same-key task restart before normal reshard finish.
Consensus snapshot apply uses the same fail-closed stance. Existing-peer active
reshard state is accepted only under the consensus-bound pre-layout, index
epoch/root, exact reshard key, marked-transfer, and monotonic stage/replica
checks described above. Unsupported transfer state and unrelated layout
changes fail before local collection mutation. Snapshot apply itself does not
move encrypted buckets or start tasks; the target-triggered resume protocol
handles an exact restored missing source task afterward.
Fixed-layout active transfer snapshots have a separate preflight for a locally
missing collection. It requires one exact marked `stream_records` transfer,
`Active` source and pre-layout owners, a `Partial` target, ordered configured
index checkpoints, the exact consensus-bound transition, and the pre-layout
with a generation-`+1` post-layout. A topology-only peer outside every owner,
replica, source, and target set may bootstrap topology without local stores. An
exact transfer target may also bootstrap when it is absent from the pre-layout
owner union, owns no other pre-layout shard, and its collection is absent or
every configured HNSW/result ORAM store is absent. Partial store loss, a
non-directory or symlinked store, and stale existing store state fail before
mutation. The historical transfer preinstall marker is not treated as proof
that encrypted stores survived; it only authorizes a new source preinstall.

Remap and padding leaves are chosen by the SDK caller, and the library only range-checks
them. They MUST be independent uniform samples (`sample_private_hnsw_oram_leaf`
and `sample_private_result_oram_leaf` wrap the system CSPRNG with unbiased
rejection sampling). A predictable schedule such as a counter lets the server
link consecutive path accesses and voids the ORAM guarantee; the in-repo recall
tests and benchmarks therefore use random remap leaves as well.

Target recovery writes a durable version-3 recovery marker with an explicit
`resume` action before applying snapshot state. Version-1 and version-2 markers
remain abort-only for compatibility. The fresh target stays `Partial`, and the
peer-restart hook preserves only the sole exact marked transfer with an
`Active` source and its consensus-bound layout transition. The target sends a
bounded background resume request so consensus can apply the new reservation
without waiting on the request itself. The source rechecks the method,
endpoints, sync mode, pre/post layout generations and digests, and index-state
digest. Before stopping the old task or acquiring a reservation, the source
atomically persists the exact full transfer and the domain-separated
reservation lease-id hash in
`private_oram_source_preinstall.json`, fsyncs the file and collection directory,
and restricts the file to mode `0600`. A source restart preserves the fixed
transfer only when this intent still exactly matches the sole active transfer,
the `Active` source, the `Partial` target, and the consensus-bound transition.
The restart handler may then release only source-owned leases whose lease-id
hash and complete lease fields match that recorded reservation and for which no
process-local session exists. Missing index leases are accepted so a crash
during multi-index reservation acquisition can be reconciled, but a newer
reservation is never removed. Before each retry, the source atomically replaces
the recorded hash with the fresh reservation identity. Malformed, insecure, or
mismatched intent files fail closed. The source stops the old transfer task
before installing every configured encrypted store under the fresh reservation
and invoking the same-key
`RestartTransfer(StreamRecords)` path. The task pool and Raft restart operation
both bind the complete expected transfer identity, so a later transfer that
reuses the same shard/source/target key cannot be stopped or restarted by a
stale request. Missing or failed source tasks remain preserved only for this
exact recovery state. Auto sharding requires the configured shard count, while
custom sharding requires the shard-key mapping to cover the exact shard set. The
source intent remains durable for the replacement transfer's full active
lifetime and is removed only by its exact finish or terminal abort. Startup
also removes an idempotent leftover when the exact transfer is already absent;
an intent that conflicts with an active transfer still fails closed.

The replacement source task waits for the target's transfer-initiation
acknowledgement. Before acknowledging, the target requires the exact active
transfer and validates every configured local store against the transition
epoch/root but keeps the resume marker. The local marker blocks both private
session types on the target, while the still-active transfer blocks private
sessions on every owner. Only after the transfer disappears and the target is
`Active` does the marker consumer apply the same validation and durably remove
the marker. A three-peer process test covers both complete collection loss and
complete HNSW/result store-only loss after a compacted Raft snapshot, then
verifies marker-based session rejection, fresh preinstall, transfer completion,
layout generation 2, session reopen, marker cleanup, and all-peer log redaction.
A staging-only six-case process matrix hard-crashes the source immediately
after reservation, after the first store acknowledgement, after all store
acknowledgements, and after restart Raft apply. It also injects a valid-shaped
stale root and a stale result-manifest signature. The matrix pins the expected
per-store durable boundary at each stage, source and target intent retention,
session blocking, exact generation-`+1` recovery after a clean source restart,
both marker removals, and log/error redaction of roots, signatures, and
ciphertexts, including the valid-shaped stale proof values. A separate
three-peer regression leaves the source intent behind through a stale-root
failure and verifies that an exact terminal transfer abort durably removes it
while retaining the pre-layout generation and owner.
A wiped pre-layout owner or source may recover only when every local shard has
another `Active` replica. Snapshot apply writes a durable marker without
starting the captured transfer task, then requests an exact transfer abort.
Normal replica recovery starts only after consensus no longer contains that
transfer. A sole source remains fail closed because the Raft snapshot contains
neither its point shard nor encrypted buckets. The same applies to any
non-redundant pre-layout owner or scale-down endpoint: recovery requires an
external backup containing the point shard, encrypted bucket stores, and
client-held ORAM state; Raft metadata alone is not a backup. An already loaded
owner or endpoint must also have each configured local index at the exact
consensus epoch/root, so retaining collection metadata while deleting an HNSW
or result-ORAM store fails closed.
The same rule applies to a scale-down endpoint that owns multiple pre-layout
shards: the endpoint must own the removed shard and every local shard must have
another `Active` replica. Recovery aborts the whole reshard before restoring
each missing replica; it never reconstructs only the removed shard from
snapshot metadata.
The subsequent fixed-layout recovery may coexist with `Dead` replicas left by
the aborted transfer. Those replicas are excluded from the pre-layout owner
set only when the remaining `Active` owner digest exactly matches the
consensus layout; a dead consensus owner still causes a mismatch and fails
closed. Each recovered replica then advances the layout through the normal
reserved generation-`+1` transfer CAS.
A four-peer RF=2 process test also erases a redundant non-endpoint owner during
scale-up, restores it from an active-reshard snapshot, and verifies exact
rollback, marker cleanup, both encrypted-store reinstalls, precommitted layout
CAS, point-shard recovery, and HNSW/result session reopen on both final owners.
A separate four-peer RF=2 test uses disjoint two-shard replica owners, erases
the designated scale-down endpoint after all migration transfers finish, and
verifies exact rollback, marker cleanup, removed-shard recovery, both encrypted
stores, generation advancement, and session reopen across the restored
pre-layout owner union.
Distributed initial private ORAM upload is coordinator-led: manifest upload
stages only local owner-signed metadata, and complete bucket upload installs the
validated encrypted bundle on the union of fully-active shard replica owners
before applying the initial consensus epoch/root ownership CAS. The coordinator
must itself own at least one active shard replica. A missing consensus
coordinator, incomplete replica set, invalid acknowledgement, or CAS failure
fails the request closed. Session open, session-bound reads, commits, and close
are coordinator-led when consensus state is available. They recover pending
state, enforce a hashed per-index lease, and couple each encrypted writeback to
the replicated epoch/root/writeback-digest transition. A distributed TOC
without that coordinator remains fail closed.

If replica finalization fails after the Raft epoch/root CAS, the owner and any
prepared replicas retain their signed pending-writeback journals. The next
session open classifies the journal against the consensus epoch and digest,
finalizes replicas before the local owner, and only then admits a new session.
Recovery updates an in-process busy session when it still exists. After a
pending recovery has actually completed and the node-local session registry is
empty, recovery may release a consensus lease owned by the current peer
immediately through exact CAS. Clean-state orphan cleanup still requires lease
expiry, so it cannot remove a live transfer reservation, and recovery never
takes over another peer's lease. The same rule applies to private HNSW and
private result ORAM indexes.

The Rust reference SDK helpers in `qdrant-sec` now cover the MVP build/upload
preparation loop. `build_private_hnsw_oram_plaintext_index_from_f32_points`
constructs a deterministic one-layer f32 neighbor graph for fixtures and
reference clients, and
`build_private_hnsw_oram_plaintext_index_from_layered_f32_points` accepts
explicit per-node HNSW levels to populate canonical level masks and
per-neighbor levels for layered fixtures; it also applies an HNSW-style
redundant-neighbor pruning heuristic before sealing the graph.
`build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points` derives
deterministic geometric levels from random opaque node ids via
`private_hnsw_level_from_node_id`, then delegates to the layered builder.
`build_private_hnsw_oram_plaintext_index_from_blocks` packs prebuilt private
HNSW node blocks into Path ORAM plaintext buckets and client position state,
and `seal_private_hnsw_oram_plaintext_index` seals those buckets into
upload-ready encrypted `PrivateHnswOramBucket` records plus a Merkle
`root_hash`. `build_private_hnsw_oram_manifest_from_encrypted_index`
copies the encrypted build metadata into a signed manifest-ready
`PrivateHnswOramManifest`, so clients can build, seal, manifest, sign, and
upload without recomputing server-visible index metadata.
New SDK code should derive `PrivateHnswClientKeys` from the signed HNSW
manifest rather than the deprecated legacy domain-only helper; the manifest-bound
derivation length-prefixes collection id, vector name, RK id, and RK epoch into
the HKDF info context before deriving node, bucket, position-map, payload-token,
and blind-result subkeys.
`package_private_hnsw_oram_upload_bundle` wraps that manifest, its Ed25519
signature, and the sealed buckets into a serde-compatible upload bundle for
REST/gRPC SDK distribution. `validate_private_hnsw_oram_upload_bundle` and the
bundle's `validate_initial_upload_contract` method let SDKs preflight decoded
upload bundles before calling Qdrant: they require a complete bucket set, reject
duplicate or missing bucket ids, verify bucket ciphertext SHA-256 and bucket
commitments against the manifest context, require the manifest signature shape
and owner key id to match the manifest, require each decoded ciphertext to match
the manifest-derived fixed bucket ciphertext size, and recompute the manifest
Merkle root. HNSW ORAM bucket commitments use the
`qdrant-sec/private-hnsw-oram-bucket-commitment/v1` domain with 4-byte
big-endian length-prefixed collection id, vector name, key id, and RK id,
followed by RK epoch, bucket id, index epoch, and the decoded
`ciphertext_sha256`; the manifest Merkle root is computed over the ordered
bucket commitments after padding the leaf level to the next power of two with
zero hashes. `validate_private_hnsw_oram_upload_bundle_with_signature` and the
bundle's `validate_initial_upload_contract_with_signature` method add the
runtime manifest validation context and Ed25519 verification to that preflight.
The collection-local private HNSW ORAM store exposes matching initial upload
bundle entrypoints; the signed variant verifies the owner Ed25519 manifest
signature before creating the private index layout, so a bad signature leaves
`epochs/current.json` absent and does not write bucket files.
For ORAM path reads, `sign_private_hnsw_oram_read_paths_for_manifest_context`
derives the signed read context from the signed manifest lineage plus the live
epoch/root and enforces the manifest's fixed `oram.path_batch_size` and
tree-bounded leaf labels before producing the Ed25519 request signature.
`sign_private_hnsw_oram_read_paths_for_manifest` is the convenience wrapper for
the first read after upload or after an optional manifest refresh, when the
manifest epoch/root is the live read context.
The collection store returns `merkle_path_batch/v1` proofs for the encrypted
bucket sequence served by `read_paths`, including repeated bucket/proof entries
when fixed-size ORAM paths share buckets. The SDK-side Merkle proof verifier and
JSON helper validate kind, epoch/root, bucket count, sibling order, and bucket
commitment matches against that store-emitted DTO. Duplicate entries are allowed
only when the repeated bucket/proof data is byte-identical; conflicting
duplicates, empty proof/bucket sets, oversized proof JSON, or commitment
mismatches fail closed before bucket ciphertext is opened.
Before submitting an ORAM writeback, clients can call
`plan_private_hnsw_oram_commit_for_manifest_context` with the live old
epoch/root, current leaf commitments, and signed manifest to produce signature
bucket refs while validating collection/vector/key lineage, fixed writeback
budget, and updated bucket commitments. When the live old epoch/root is the
same as the signed manifest, `plan_private_hnsw_oram_commit_for_manifest` is a
convenience wrapper for the first commit after upload or after an optional
signed manifest refresh. After the writeback commit succeeds, clients can
optionally call `refresh_private_hnsw_oram_manifest_for_commit` to derive the
next signed manifest body from that manifest-bound plan, or
`sign_private_hnsw_oram_manifest_refresh` to derive and sign it in one step;
both first validate the current manifest shape and reject a plan whose old
epoch/root does not match it. Session open and later commits do not require this
refresh because the live epoch/root is tracked by current epoch CAS and Merkle
metadata; without a refreshed manifest, clients should continue with
`plan_private_hnsw_oram_commit_for_manifest_context` using the current
epoch/root returned by the session/read state.
The server-side private HNSW tests now package a tiny SDK-built encrypted index,
sign its manifest, and verify that the initial
bucket upload bundle satisfies the same manifest epoch/root and Merkle
commitment contract used by REST/gRPC bucket upload. The collection store tests
also exercise a packaged
upload/read_paths/verified-search/writeback-commit round trip against
SDK-sealed buckets. The qdrant route-layer tests reuse that SDK package across
the REST JSON DTOs and gRPC protobuf messages for manifest upload, bucket
upload, session open, ORAM `read_paths`, and commit request/response shapes.
The gRPC fixture also feeds a route-shaped `read_paths` response with encrypted
buckets and a Merkle path batch proof into the SDK verifier, so proof-bearing
wire responses are checked before bucket decryption. Dispatcher-backed REST and
gRPC live route tests now create encrypted collections with stable UUIDs, upload
the SDK manifest and bucket bundle through the private HNSW APIs, open sessions,
sign live `read_paths` requests, verify responses with the SDK Merkle verifier,
commit writeback buckets, close the sessions, and re-open at the new epoch
without refreshing the signed manifest. Initial manifest upload
creates the private epoch layout when no current epoch exists; repeated uploads
still require the current epoch/root to match, and a mismatched upload leaves
the stored current epoch untouched. ORAM commits may carry unchanged
buckets forward from an older bucket epoch; the current Merkle root commits to
each bucket commitment, and clients open each bucket with the epoch recorded in
that bucket while rejecting buckets newer than the requested index epoch. Search
clients should open server `read_paths` responses with
`search_private_hnsw_oram_encrypted_verified`, which preflights the client-pinned
root hash and manifest-derived bucket count before issuing a server read, then
checks the response epoch/root/bucket count and Merkle path batch proof before
decrypting buckets or issuing ORAM writeback. SDKs may keep high-level HNSW
nodes in a local
`PrivateHnswClientNodeCache` and call the `*_with_cache` search helpers. A cache
hit still consumes a padding ORAM access through `padding_node_id`, so fixed-step
request volume remains constant while the client uses its local upper-layer node
copy for traversal and distance calculation. The verified cache helper applies
the same Merkle proof check before bucket decryption, state remap, or writeback.
`PrivateHnswSearchResult::access_metrics` returns
`PrivateHnswSearchAccessMetrics` with path-access count, unique leaf count,
fixed-step budget, and budget-exhaustion status for latency/ORAM-volume
benchmarks without exposing plaintext vectors, distances beyond client-local
hits, or decrypted neighbor lists. The exhausted flag is set only when the path
count, completed step count, and canonical access leaf-label shape all match the
fixed budget. Strict SDK flows should call
`validate_private_hnsw_strict_search_result` before result fetch or commit so a
search that stopped before consuming `fixed_steps` is treated as a failed
fixed-budget search, not a shortened private query. The strict validator also
requires canonical access leaf-label shape, finite hit distances, and unique hit
node/point identifiers. The private result ORAM payload finalizer repeats the
same hit-shape check before returning payload bytes for real hits.
`cargo bench -p qdrant-sec --bench private_hnsw_oram_bench` provides the
initial SDK-side benchmark harness for plaintext reference index build and
fixed-budget plaintext ORAM-HNSW traversal, including an upper-layer client
cache variant, plus client-AEAD encrypted bucket open/reseal traversal. It is
intentionally client-local: the benchmark exercises ORAM path read/writeback
closures, speculative prefetch planning, neighbor-clustered leaf planning, and
directional neighbor filtering, and access metrics, but it does not route
vectors or queries through Qdrant.
`plan_private_hnsw_oram_speculative_prefetch` prepares fixed-count padded
neighbor path labels from the client position map, deduplicating real candidate
leaves and filling the remaining request slots with unique dummy leaves before
the SDK calls `read_paths`. This keeps SDK-generated batches compatible with
the server-side duplicate path-label guard while still preserving a fixed path
count; the leaf-label bucket-path helper also rejects duplicate labels before
producing a request bucket sequence. Runtime and manifest validation reject path
budgets larger than the available unique ORAM leaves. An SDK that reads a padded
prefetch batch must also write back every path of that batch (evict the dummy
paths with `evict_private_hnsw_oram_path`), because the server only bounds the
write-back size: a write-back that covers the real paths alone reveals which of
the prefetched paths were padding. `plan_private_hnsw_oram_neighbor_clustered_leaves` provides a
deterministic graph-order leaf assignment helper for bulk builds, so SDK
experiments can place entry-near neighbor chains on adjacent ORAM leaves before
calling `build_private_hnsw_oram_plaintext_index_from_blocks`; the helper
requires the requested entry node to be present in the build block set and
fails closed instead of silently falling back to the first block.
The plaintext index builder rejects duplicate node ids, point tokens, and
payload fetch tokens before bucket placement so malformed indexes cannot defer
result-token ambiguity to search or private result fetch validation. HNSW node
block codec validation rejects empty/non-contiguous level masks, neighbor levels
outside the node level mask, self-neighbors, and duplicate same-level neighbor
entries while still allowing the same neighbor id on different HNSW levels; it
also rejects malformed, empty, or non-finite `f32_le` vector bytes at codec
decode time. The plaintext bucket codec and client Path ORAM access also reject
duplicate point tokens and duplicate payload fetch tokens before decrypted path
blocks can be absorbed into the stash, leaving the client state unchanged on
that malformed-path boundary.
`plan_private_hnsw_oram_directional_neighbor_filter` is an experimental
client-local helper for Compass-style directional neighbor filtering: given the
current node block, decrypted neighbor blocks, and the query vector, it keeps
only neighbor nodes that move in the query direction and ranks them by
client-side distance before the SDK chooses which padded ORAM paths to request.
`plan_private_hnsw_oram_graph_traversal_path_batch` composes that filter with
the client position map and speculative prefetch padding to produce a fixed-size
`read_paths` label batch for graph-traversal tailored ORAM experiments. The
`*_with_stats` variant keeps the same padded labels while also reporting how
many directional neighbors survived before missing position-map entries were
dropped, so SDK benchmarks can separate graph-filter selectivity from ORAM path
volume.

Client state is mandatory backup material for this provider. Qdrant snapshots
contain encrypted buckets, manifest, and epoch/root metadata, but not the ORAM
position map or stash. SDKs should persist `PrivateHnswOramClientStateSnapshot`
from `PrivateHnswOramClientState::to_snapshot` alongside their RK/signing-key
backup and restore it with `PrivateHnswOramClientState::from_snapshot` before
opening sessions against a pinned epoch/root. For encrypted local backups,
`seal_private_hnsw_oram_client_state_snapshot` uses the RK-derived
position-map subkey, rejects malformed position map/stash snapshots before
producing ciphertext, rejects duplicate position/stash entries, duplicate stash
point/payload fetch tokens, malformed leaf labels, and malformed stash node
blocks, vector bytes, neighbor shapes, level masks, or stash map-key/node-id
mismatches at snapshot export/import, and
binds the ciphertext to collection id,
vector name, RK id/epoch, index epoch, and root hash after rejecting malformed
collection AAD context identifiers, path-like vector names, and client-state
alias vector names. The same vector-name shape is enforced for HNSW bucket AEAD
contexts, manifest-build contexts, read-path signature contexts, and
commit-signature contexts;
`open_private_hnsw_oram_client_state_snapshot` bounds the encoded ciphertext
length and validates the ciphertext hash shape before decode, then rejects hash
tamper or epoch/root context mismatch before returning the snapshot. The
encrypted backup DTO does not serialize plaintext position-map entries, leaf
labels, stash blocks, point tokens, or payload fetch tokens outside the AEAD
ciphertext.
New SDK code should derive `PrivateHnswClientKeys` from the signed manifest
rather than the deprecated legacy domain-only helper. The manifest-bound derivation
length-prefixes collection id, vector name, RK id, and RK epoch into the HKDF
info context before deriving node, bucket, position-map, payload-token, and
blind-result subkeys, so accidental RK reuse across private HNSW indexes does
not produce the same client subkeys. The crypto-crate bucket/search fixtures and
the collection-store and REST/gRPC route fixtures now build their SDK-sealed
private HNSW buckets with the same context-bound derivation path.

The client CKKS vector sidecar signature message is canonical and
length-prefixed for SDK interop. The byte string is:

1. 4-byte big-endian length + ASCII domain
   `qdrant-sec/client-ckks-vector-signature/v1`.
2. 1-byte `version`.
3. For each UTF-8 field below, a 4-byte big-endian length followed by field
   bytes: `scheme`, `security_profile`, `collection_id`, `point_id`,
   `vector_name`, `key_id`, `rk_id`, `context_digest`, `ciphertext_sha256`,
   `ciphertext`, `signature.alg`, `signature.key_id`.
4. 8-byte big-endian `rk_epoch` immediately after `rk_id`.
5. 8-byte big-endian `slots` immediately after `context_digest`.

The `sig` bytes themselves are not included in the signed message. Any change
to the sidecar routing metadata, key lineage, public context digest, slot count,
ciphertext hash, or ciphertext bytes invalidates the Ed25519 signature.
`docs/qdrant-sec-client-ckks-vector-signature-test-vector.json` freezes the
canonical signing bytes for SDK interop, and the server test suite verifies the
helper against that fixture.

For tests and future vector-envelope work, a generic OpenFHE backend is
configured under `crypto.backends` and referenced from a
`vector/openfhe-ckks@v1` instance:

```yaml
crypto:
  backends:
    openfhe_local:
      kind: process
      program: /usr/local/bin/openfhe-bridge
      sha256_b64: base64url-no-pad-sha256-of-bridge
      signature_public_key_b64: base64url-no-pad-ed25519-public-key
      signature_b64: base64url-no-pad-ed25519-signature-over-domain-and-sha256
  instances:
    docs_vector_v1:
      provider: vector/openfhe-ckks@v1
      backend_ref: openfhe_local
      materials:
        sym_key: tenant-a/vector-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/vector@v1
        profile: ckks-128-n16384-d4-scale50
        crypto_context_b64: base64url-no-pad-openfhe-context
        public_key_b64: base64url-no-pad-openfhe-public-key
        # Required for every vector/openfhe-ckks@v1 instance because the bridge
        # returns finite plaintext ranking scores to Qdrant, even when the query
        # vector itself is supplied as an encrypted CKKS envelope.
        score_plaintext_output_tcb_ack: qdrant-sec-ckks-score-output-tcb-v1
        allow_plaintext_queries: false
        signature_public_keys:
          tenant-a/query-signing-v1: base64url-no-pad-ed25519-public-key
        # Required only when allow_plaintext_queries is true.
        # plaintext_query_tcb_ack: qdrant-sec-ckks-plaintext-query-tcb-v1
```

Direct MK/RK materials must set `source` explicitly; qdrant-sec does not infer
`env`, `file`, `unix_socket`, `vault_kv2`, `fd`, or `inline` from whichever
field happens to be present.
When a material uses `source: env`, the `env` name must be non-empty and contain
only ASCII alphanumeric characters or `_`; malformed environment references fail
startup validation instead of being deferred to material load time.
When a material uses `source: file`, the path must be absolute and point to a
regular non-symlink file. On Unix, qdrant-sec rejects group/world-accessible key
files and rejects group/world-writable parent directories. The file and each
parent directory must be owned by root or the qdrant process user so file-backed
MK/RK material is not accidentally exposed or swapped through broad filesystem
permissions.
When a material uses `source: unix_socket`, the same `path` field must point to
an absolute, non-symlink Unix domain socket. On Unix, qdrant-sec rejects sockets
that are group/world-accessible and applies the same parent-directory
owner/mode checks as file-backed material. At startup/material-load time Qdrant
connects to the socket, reads a base64url-no-pad 32-byte material, and closes
the connection. This keeps the raw MK/RK out of config and persistent key files,
but the local socket service becomes part of the key-management TCB and must
preserve cluster runtime parity.
When a material uses `source: vault_kv2`, `path` must be the full Vault KV v2
data endpoint URL, for example `/v1/<mount>/data/<secret>`. Metadata/list
endpoints and bare mount paths are rejected. `env` must name the environment
variable that contains the Vault token, and `vault_field` must name the string
field under `data.data` that contains the base64url-no-pad 32-byte material. The
Vault token value must be non-empty and a valid HTTP header value. The URL must
use HTTPS; loopback HTTP is accepted only for tests/dev. Query strings and
fragments are rejected so Vault tokens or field selectors are not accidentally
placed in config URLs. Username/password URL credentials are also rejected; use
the `env` token source instead. Non-loopback Vault URLs must also set
`expected_host` to the exact configured URL authority, including port when a
non-default port is used. Qdrant rejects the material before loading the Vault
token if `expected_host` is missing or does not match, so a config drift cannot
silently redirect Vault credentials or RK material to an attacker-controlled
host. Vault material fetches do not follow HTTP redirects; redirects must be
resolved in the configured, validated URL.
Vault-backed material keeps the MK/RK out of config files, but the Vault token
source, Vault policy, and Vault availability become part of the key-management
TCB and must be identical across nodes that can write encrypted collections.
Vault KV v2, AWS KMS, and Vault Transit materials may set `timeout_ms` between
`1` and `30000`; when omitted, Qdrant uses a 5000 ms HTTP timeout and never
follows redirects. This keeps resource-key lifecycle endpoints bounded even
when an external key provider is slow.
External key-provider materials may also set non-secret
`provider_key_version` and `provider_attestation_id` identifiers. These values
are not key material and are safe to expose in sanitized config views, but they
are included in the crypto runtime capability fingerprint so mixed KMS/Vault
key versions, attestation policies, or rollout cohorts fail closed before
encrypted writes, shard transfer, or restore use the wrong provider state.
When a wrapping material uses `source: aws_kms`, it must be
`kind: wrapping_key_32`, `path` must be the AWS KMS key id, alias, or ARN, and
`env` must be an environment-variable prefix. Qdrant reads
`${env}_ACCESS_KEY_ID`, `${env}_SECRET_ACCESS_KEY`, `${env}_REGION`, optional
`${env}_SESSION_TOKEN`, and optional `${env}_ENDPOINT_URL`. The endpoint
defaults to `https://kms.${region}.amazonaws.com/`; custom endpoints must use
HTTPS except loopback HTTP for tests/dev and must not include credentials, path,
query, or fragment components. Remote custom endpoints require `expected_host`
and the endpoint authority must match it exactly. If `expected_host` is set for
the default AWS endpoint, the computed `kms.${region}.amazonaws.com` authority
must also match. Qdrant signs AWS KMS `Encrypt`/`Decrypt`
requests with SigV4, sends RK plaintext only inside those KMS calls, records
`wrapped_symmetric_key_32.wrap_algorithm: aws-kms`, and stores the returned KMS
ciphertext blob as `wrapped_key_b64`. AWS KMS material is only valid for
MK/KEK wrapping; it cannot be used as a direct server-side payload/vector RK
source.
When a wrapping material uses `source: vault_transit`, it must be
`kind: wrapping_key_32`, and `path` must be the Vault Transit key metadata URL,
for example `/v1/<mount>/transit/keys/<key>`. qdrant-sec derives the
corresponding `/encrypt/<key>` and `/decrypt/<key>` endpoints and sends the RK
plaintext only to Vault Transit for wrap/unwrap. The config never contains the
MK bytes, and `wrapped_symmetric_key_32.wrap_algorithm` becomes
`vault-transit`. As with Vault KV v2, the URL must use HTTPS except loopback
HTTP for tests/dev, credentials/query/fragment components are rejected, and
`env` must name the Vault token environment variable. Non-loopback Vault
Transit URLs require `expected_host` with the exact URL authority for the same
host-pinning reason as Vault KV v2. Vault Transit material is only valid for
MK/KEK wrapping; it cannot be used as a direct server-side payload/vector RK
source.
When a material uses `source: fd`, the `fd` must reference an already-open Unix
file descriptor containing the base64url-no-pad 32-byte material. Qdrant
marks the descriptor close-on-exec during validation and duplicates it with
close-on-exec before reading, so the original descriptor is not closed by
material loading and secret descriptors are not inherited by bridge child
processes. FD-backed material avoids storing the secret or a secret file path in
config, but operators must still provide the descriptor at the beginning of the
encoded material and keep cluster runtime parity aligned.

Wrapped RK material may declare a lifecycle `state`:

- `active` or omitted: the RK can be unwrapped and used for new encryption.
- `retired`: the RK is read-only and must not be selected for new write plans.
- `disabled`: the RK must not be unwrapped by runtime crypto but may retain
  wrapped material for an explicit future enable/rollback operation.
- `destroyed`: the RK must not retain `wrapped_by`, `nonce`, `wrap_algorithm`,
  or `wrapped_key_b64`; only non-secret identity metadata such as `rk_epoch`,
  `scope`, and `state` remains for audit/preflight.

Runtime validation includes this non-secret state in the cluster capability
fingerprint so nodes disagreeing on RK lifecycle cannot silently accept the same
collection plan.
Provider `materials.sym_key` bindings for new server-side payload/vector writes
must reference an `active` wrapped RK; retired keys are accepted only through the
explicit `retired_materials` read-only rotation list.

Data envelopes record the runtime `key_id`, material fingerprint, and, for
wrapped RK material, the `rk_id` plus `rk_epoch` used for the RK-derived subkey.
They do not reference the MK directly, so MK rotation can rewrap the stored RK
manifest without rewriting payload/vector envelopes. The low-level
`rewrap_resource_key` helper implements that primitive by unwrapping the RK with
the old MK/AAD and immediately wrapping the same RK with the new MK/AAD. The
runtime `rewrap_runtime_resource_key_materials_by_master_key` helper batches
that primitive for every `active` or `retired` wrapped RK that references the
old MK, preserving each RK's epoch, scope, and lifecycle state. `disabled` and
`destroyed` RK records are not implicitly unwrapped during MK rotation.
Operators can generate a fresh random RK for RK rotation through the manage-only
`POST /crypto/resource-keys/generate` endpoint:

```json
{
  "material": "tenant-a/payload-rk-v4",
  "wrapped_by": "tenant-a/mk-v2",
  "rk_epoch": 4,
  "scope": "collection:docs/payload:body"
}
```

The endpoint returns a config patch for one new `wrapped_symmetric_key_32`
material with `state=active`; it does not mutate runtime settings or collection
config. Operators must apply the patch, update the provider's active
`materials.sym_key`, move the old RK into `options.retired_materials`, and then
run the payload/vector migration before disabling or destroying the old RK.

Operators can expose the MK rotation primitive through the manage-only
`POST /crypto/resource-keys/rewrap` endpoint:

```json
{
  "old_wrapped_by": "tenant-a/mk-v1",
  "new_wrapped_by": "tenant-a/mk-v2",
  "dry_run": false
}
```

The endpoint does not mutate in-memory settings or collection config. It returns
a config patch containing only the rewrapped `wrapped_symmetric_key_32` material
records that should be applied to the deployment config or external secret
backend. This keeps MK rotation scoped to O(number of wrapped RKs) and avoids
rewriting payload/vector data envelopes. The `old_wrapped_by` and
`new_wrapped_by` values are validated as crypto material identifiers before any
runtime lookup, and they must reference different `wrapping_key_32` materials.
Set `dry_run: true` to return only the target material count and estimated
external provider call count; dry-run never unwraps or rewraps RK material and
never returns secret-bearing patch fields.
The old and new MK material must both be available in the current runtime during
the rewrap, and operators should roll out the resulting material patch
atomically across nodes so runtime parity fingerprints stay aligned.

Operators can inspect the non-secret collection crypto manifest before and after
rotation:

```text
GET /collections/{collection_name}/crypto/manifest
```

The endpoint is manage-only and first revalidates the collection config against
the current runtime crypto settings. It returns the stable collection crypto id,
schema/epoch/state, each rule's provider and binding, active material references,
retired material references, and client-side RK policy. It does not return
`value_b64`, `wrapped_key_b64`, nonces, signatures, or public material. If a
runtime material referenced by the collection is missing RK epoch metadata or no
longer satisfies the provider policy, manifest generation fails closed instead
of reporting a stale or incomplete key lifecycle view.

After an RK rotation migration has been verified and the runtime provider no
longer references the old RK in either `materials.sym_key` or
`options.retired_materials`, operators can request a non-mutating retirement
patch:

```json
POST /crypto/resource-keys/retire
{
  "materials": ["tenant-a/payload-rk-v3"],
  "target_state": "disabled"
}
```

`target_state` is currently limited to `disabled`. The endpoint rejects active
RKs and any retired RK that is still referenced by a runtime crypto instance. A
`disabled` patch preserves wrapped key material for a future explicit rollback
or enable operation. `destroyed` retirement is intentionally rejected until it is
bound to a persisted, non-dry-run migration completion proof; shredding wrapped
RK material based only on runtime-reference cleanup can permanently orphan old
envelopes.

RK rotation still requires a data re-encryption job and should use the explicit
re-encryption mode rather than normal write-path idempotency. The
`rk_id`/`rk_epoch` fields are included in AEAD AAD for server-generated payload
and vector envelopes, so storage-side edits to resource-key identity fail closed.
During RK rotation, `payload/aes-256-gcm@v1` instances may list old read-only
keys in `options.retired_materials` as objects containing `material` and
`material_fingerprint_id`. Normal public writes still use only `materials.sym_key`
for new encryption, while the admin re-encryption path can decrypt stale
envelopes with the retired keyring entry and re-seal them with the active RK.

Payload AEAD AAD also binds the stable collection crypto identity, point id, and
canonical field path. On public writes Qdrant uses the collection UUID and
rejects encrypted collection configs that are missing that stable identity.
Collection snapshot creation requires encrypted collections to be in
`migration_state=active`; snapshots taken while encryption, rotation, or
decryption migration is in flight are rejected because those archives cannot be
restored without a future verified migration recovery manifest.

Snapshot download and shard snapshot streaming APIs are storage-level exports.
They only support raw encrypted marker export. `encrypted_payload=raw` is accepted
as an explicit no-op, while `encrypted_payload=decrypted` and
`encrypted_payload=redacted` fail during query parsing. Decrypted or redacted data
export must use the audited payload export endpoint instead of snapshot archive
streams:

```text
POST /collections/{collection_name}/points/export?encrypted_payload=raw
POST /collections/{collection_name}/points/export?encrypted_payload=redacted
POST /collections/{collection_name}/points/export?encrypted_payload=decrypted
```

The endpoint accepts the usual scroll body for pagination and filtering, but it
overrides `with_payload` with the explicit encrypted payload policy from the
query string and rejects `with_vector`. `decrypted` export requires the same
collection-scoped `payload_decrypt` capability as decrypted reads and emits a
separate audit method (`export_decrypted_payload`) before the underlying scroll.
Client-side `$qdrant_client_aead` envelopes still cannot be decrypted by
Qdrant; use `raw` or `redacted` for those collections.

The wrapped RK AES-GCM AAD is a length-prefixed tuple of `qdrant-sec`, `v1`,
`resource-key-wrap`, the material reference, `rk_epoch`, `scope`, `wrapped_by`,
and `AES-256-GCM`. Changing the material reference, epoch, scope, or wrapping MK
therefore requires rewrapping the RK.

The generic `crypto` control plane can define reserved
`vector/openfhe-ckks@v1` runtime instances must bind both the OpenFHE process
backend and a `sym_key` metadata key material. The bridge encrypts selected
dense embeddings, while the `sym_key` protects the stored vector envelope
metadata:

```yaml
crypto:
  instances:
    docs_vector_v1:
      provider: vector/openfhe-ckks@v1
      materials:
        sym_key: tenant-a/vector-v1
      backend_ref: openfhe_local
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/vector@v1
        profile: ckks-128-n16384-d4-scale50
        crypto_context_b64: base64url-no-pad-openfhe-context
        public_key_b64: base64url-no-pad-openfhe-public-key
        score_plaintext_output_tcb_ack: qdrant-sec-ckks-score-output-tcb-v1
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/payload@v1
        retired_materials:
          - material: tenant-a/payload-v0
            material_fingerprint_id: tenant-a/payload@v0
  materials:
    tenant-a/mk-v1:
      kind: wrapping_key_32
      source: env
      env: QDRANT_CRYPTO_MK_B64
    tenant-a/payload-v1:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk-v1
      wrap_algorithm: AES-256-GCM
      rk_epoch: 3
      state: active
      scope: collection:uuid-123e4567-e89b-12d3-a456-426614174000
      nonce: base64url-no-pad-96-bit-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
    tenant-a/payload-v0:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk-v1
      wrap_algorithm: AES-256-GCM
      rk_epoch: 2
      state: retired
      scope: collection:uuid-123e4567-e89b-12d3-a456-426614174000
      nonce: base64url-no-pad-96-bit-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
    tenant-a/vector-v1:
      kind: symmetric_key_32
      source: env
      env: QDRANT_VECTOR_METADATA_KEY_B64
  backends:
    openfhe_local:
      kind: process_pool_landlock_strict_netns
      program: /usr/local/bin/openfhe-bridge
      sha256_b64: base64url-no-pad-sha256-of-bridge
      # Only for *_landlock_strict* kinds: extra read-only roots the bridge may
      # open, for example an OpenFHE data directory. Never list storage,
      # snapshot, configuration or key material locations.
      landlock_read_allow_roots:
        - /opt/openfhe/data
```

Generic OpenFHE backends currently accept `process`, `process_pool`, and on
Linux the Landlock-enforcing `process_landlock` / `process_pool_landlock`
variants. Linux also supports
`process_landlock_netns` / `process_pool_landlock_netns`, which add a bridge
child network-namespace split before `exec` for deployments that can run the
bridge without host network access, and the strict variants
`process_landlock_strict` / `process_pool_landlock_strict` /
`process_landlock_strict_netns` / `process_pool_landlock_strict_netns`, which
keep the write-deny rules and additionally handle the Landlock read and execute
access bits: the bridge can read and execute only `/usr`, `/lib`, `/lib64`,
`/bin`, `/sbin` and `/etc`, read `/dev/null`, `/dev/urandom` and `/dev/random`,
read and execute its own program (granted through the validated descriptor, so
the exec path and a shebang interpreter's re-read keep working), and read the
roots listed in `landlock_read_allow_roots` (absolute normalized paths other
than `/`, at most 64, only accepted for the strict kinds; a listed root that
does not exist fails the worker spawn closed). A compromised strict-sandboxed
bridge therefore cannot read the storage directory, configuration or key
material. Any other backend `kind` is rejected during runtime settings
validation.
On Linux, Qdrant sets `no_new_privs`, a parent-death `SIGKILL`, `RLIMIT_CORE=0`,
and, for checked bridge binaries, `RLIMIT_FSIZE=0` immediately before spawning
the configured bridge process. This is not a complete sandbox, but it prevents
privilege gain through setuid binaries or file capabilities, reduces orphaned
plaintext-bearing bridge exposure, disables normal core dumps, and prevents the
checked bridge from writing regular files after bridge path, ownership, mode,
parent directory, and optional SHA-256 pin checks have passed. Treat these
settings as pre-exec process hardening. The Landlock variants additionally
install a write-deny Landlock ruleset in the bridge child before `exec`, blocking
regular file writes, file creation, removal, rename/link, and truncation
operations for kernels that support the configured Landlock ABI. Production
deployments that need Qdrant-managed network egress isolation can select the
`*_landlock_netns` variants; bridge startup then fails closed if the host denies
network namespace creation. These sandbox and egress policy labels are included
in the crypto runtime capability fingerprint, so mixed cluster policies fail
parity checks. Deployments that need broader confinement should still run the
bridge under an external seccomp/AppArmor/container profile. See
[`openfhe-bridge-sandbox.md`](openfhe-bridge-sandbox.md) for a hardened
deployment checklist and starter AppArmor/seccomp examples.

Server-side inference is also a plaintext boundary. If clients submit
`Document`, `Image`, or `Object` vectors for encrypted vector names, Qdrant must
embed that input before CKKS encryption or search scoring. The remote inference
HTTP client does not follow redirects, and request-provided `*-api-key` headers
are forwarded only when their exact header names are listed in
`inference.allowed_api_key_headers`. Remote inference URLs must use HTTPS unless
they target loopback HTTP for local development. Non-loopback endpoints must set
`inference.expected_host` to the exact configured URL authority, including port
when present; Qdrant rejects the endpoint before sending inference input or
forwarding tokens if the URL host drifts. Leave `allowed_api_key_headers` empty
for zero-trust deployments and require clients to submit dense vectors or
client-encrypted CKKS query envelopes produced outside Qdrant.

Collection encryption rules and runtime instances must use the same explicit
provider instance and `key_id`; runtime validation rejects missing instances,
missing material, provider/selector mismatches, and key-id mismatches instead of
falling back to legacy defaults. For server-side payload/vector AEAD envelopes,
`key_id` uses the narrower AEAD key-id syntax `[A-Za-z0-9._:-]`; resource-key
ids, material fingerprint ids, client `rk_id`, and signature key ids may use the
bounded qdrant-sec crypto identifier syntax that also permits `/` and `@`.
The configured 32-byte RK is not used directly
as an AEAD key. Qdrant derives purpose-specific HKDF-SHA256 subkeys for payload text
(`qdrant-sec/payload-text/v1`) and CKKS vector envelopes
(`qdrant-sec/vector-envelope/v1`) before constructing AES-GCM ciphers.
Runtime payload code must use the resource-key constructors so this derivation
is centralized. The `PayloadTextEncryptor::new_with_derived_*_unchecked`
constructors are safe-Rust fixture and compatibility escape hatches for ciphers
or keyrings that have already been domain-separated; `unchecked` is a
cryptographic provenance warning, not a Rust `unsafe` contract.
`crypto.allow_inline_key_material` defaults to `false` so inline key material is
rejected at startup unless explicitly enabled for local development fixtures.
Decrypt paths can be configured with active plus retired AEAD keys; new writes
always use the active key, and
envelopes record the active key id plus material fingerprint.
Server-side public writes reject fields that already contain a
`$qdrant_sec` marker so clients cannot smuggle stale or wrong-key envelopes.
If the matching runtime crypto settings or key material are absent, selected
plaintext fields are not stored as a fallback; the collection write guard rejects
the operation instead.
Rotation/backfill code must use the explicit `ReencryptIfStale` mode so old
schema/epoch/key envelopes are opened and sealed again under the current active
key.
Admin migration plans are intentionally stricter than normal config validation:
`Encrypting -> Active`, `Rotating -> Active`, and `Decrypting -> Disabled`
completion plans require non-empty verified checkpoints with every shard fully
processed. Every migration transition must name a non-zero `target_epoch`.
Initial encryption and rotation plans must also carry syntactically valid
resource-key ids so a migration cannot mark a collection active without a
traceable RK lineage. Rotation plans reject identical active and retired RK ids;
rotation must introduce a distinct active RK before the old RK becomes
read-only. `retired_rk_id` is only valid on rotation transitions. Completion
transitions cannot be marked as `dry_run`, so a dry-run preflight cannot be
reused as the operation that marks encrypted data verified or decrypted.
The REST control plane is split into two admin-only steps:

```text
POST /collections/{collection_name}/crypto/migration/plan
POST /collections/{collection_name}/crypto/migration/run-payloads
```

Use `plan` to start `Disabled -> Encrypting`, `Active -> Rotating`, or
`Active -> Decrypting`. `run-payloads` is the only public payload rewrite entry
point: it combines the server-side payload rewrite/decrypt scan with completion
plan construction and submission. The request must name the active RK id and,
when completing `Rotating -> Active`, the retired RK id:

```json
{
  "active_rk_id": "rk/docs/4",
  "retired_rk_id": "rk/docs/3",
  "dry_run": false
}
```

The endpoint first verifies the current collection state is `Encrypting`,
`Rotating`, or `Decrypting` and preflights the supplied active/retired RK ids
against the current collection config. Invalid completion requests fail before
any payload rewrite/decrypt scan starts. Valid requests then run the appropriate
payload rewrite/decrypt scan, build the completion `CryptoMigrationPlan` from
the returned verified checkpoints, validate it again against the current
collection config, and submit the admin completion operation. If `dry_run` is
`true`, the endpoint still validates runtime material and returns verified
checkpoints plus the completion plan it would submit, but it does not write
payload changes and does not apply the completion transition.
`CryptoMigrationCheckpoint` values represent shard coverage, not only bytes
changed: rerunning a migration over already-current payloads still returns
`rewritten_points == total_points` so the checkpoint can close the migration
safely. The separate `changed_points` counter reports how many payload records
actually changed on that run, so operators can distinguish first-pass rewrites
from idempotent verification reruns. Client-side `$qdrant_client_aead`
envelopes are store-only and cannot be decrypted by Qdrant, so decrypt
migration rejects collections that still bind a client-side payload provider.
This is still a foreground admin operation, not a cluster-wide background
scheduler; interrupted or failed runs should be rerun to produce fresh
checkpoints. The older standalone rewrite/decrypt endpoints were intentionally
removed so operators cannot mutate payload bytes without also validating and
submitting the matching completion plan.
After a verified `Decrypting -> Disabled` completion, the stored encryption
section remains as audit/migration metadata, but it is not treated as effective
encryption for write/read guards. Re-enabling encryption must start a new admin
migration transition rather than relying on ordinary params updates.
Read paths return stored encrypted markers as raw payload values by default.
REST and gRPC clients can request `with_payload: {"encrypted_payload":"redacted"}` to
receive payloads with server-side, client-side, and CKKS vector sidecar marker
values replaced by redaction sentinels. The same redaction policy is applied to
batch search/query/recommend/discover results, grouped result hits, and grouped
lookup payloads.
`encrypted_payload: "decrypted"` is supported for REST/gRPC retrieve, scroll,
legacy search, batch search, universal query, batch query, recommend, batch
recommend, discover, batch discover, and grouped result hits over server-side
`$qdrant_sec` payload fields when the Qdrant node has matching runtime crypto
settings and the caller has global manage access or collection-scoped
`payload_decrypt: true` access. That mode requests raw
encrypted markers from the collection layer,
decrypts only server-side payload text and metadata value AEAD fields in the API
runtime layer, leaves client-side `$qdrant_client_aead` envelopes opaque, and
fails closed if runtime settings are unavailable or invalid. Group lookup
payloads are not decrypted because lookups may target another collection.
When `crypto.zero_trust_profile: strict` is enabled, `decrypted` read mode is
disabled entirely; strict zero-trust deployments must return raw/redacted
envelopes and decrypt in the client SDK.
JWT RBAC claims must grant the decrypt capability explicitly:

```json
{
  "access": [
    {
      "collection": "docs",
      "access": "r",
      "payload_decrypt": true
    }
  ]
}
```

Decrypted snapshot export remains unsupported; REST access logs and denied-auth
audit paths template-redact private ORAM session ids and redact private ORAM
query strings and unexpected private ORAM endpoint tail segments. Slow request
logs and request hashes use redacted request values, including private HNSW ORAM
path/read/access traversal labels, entry and visited node ids, level masks,
neighbor/candidate aliases, query vector/embedding/plaintext aliases,
score/distance aliases, candidate heaps, candidate and node score/distance
aliases, request/commit/read/manifest signatures, private result ORAM bucket
ids, session ids, bucket commitments, leaf commitments, read bucket ids, bucket
id sequences, updated bucket writebacks, access-volume count aliases,
client-state/client-states, ciphertext/hash/sha256 fields, and payload/result
tokens; snake_case and camelCase singular/plural aliases are covered for private
ORAM access-pattern, bucket, commitment, signature, query, candidate,
score/distance, client-state, and token fields.
REST access-log and JSON-validation sanitizers recognize private ORAM markers
only at the route position after `/collections/{collection}`; ordinary
collections named `private-hnsw` or `private-result-oram` keep normal access-log
query strings and validation errors.
Collection telemetry has sentinel coverage so decrypted plaintext is not
intentionally emitted there, and app telemetry serializes only the runtime
capability fingerprint rather than private ORAM key ids, verifier key ids, or
`signature_public_keys` registry entries. Panic telemetry, health-check panic
messages, gRPC status logging, and denied-auth audit errors apply the same
redaction helper before serialization; they redact qdrant-sec envelope markers,
secret-like crypto fields, private ORAM owner/signing key id aliases,
signature-public-key registry aliases, and private ORAM path/root/bucket/node,
query vector/embedding/plaintext, score/distance, candidate/node score,
candidate/node distance, token, client-state ciphertext/hash/sha256, proof, and access-volume
count/length aliases. REST private ORAM wire DTO `Debug` wrappers also redact
upload/read bucket counts alongside roots, ciphertext bodies, commitments, and
signatures, and SDK private ORAM upload bundle debug output redacts upload
bucket counts. SDK private HNSW search access metrics redact path/leaf/fixed
step counts and budget-exhaustion state. Common private ORAM session debug output
redacts bucket counts, tree height, path-batch size, and derived ciphertext byte
budgets, and it does not render the embedded manifest. SDK private HNSW
node/search/build debug output also redacts deleted/generation state,
payload-token presence, build-point vector lengths, build bucket counts, Merkle
proof bucket counts, encrypted bucket-batch bucket counts, and manifest-build
HNSW/ORAM/fixed-budget policy internals. Private result ORAM SDK debug output
applies the same client-state tree-height and bucket-count redaction to client
configs, Merkle proofs, encrypted bucket batches, and read-signature inputs.
Collection-local private ORAM store debug output also redacts Merkle tree/proof
bucket counts.
Private HNSW ORAM commit errors use a fixed writeback-budget message and do not
reflect the concrete max writeback bucket count.
Private result ORAM commit errors follow the same rule for fixed writeback
budget failures.
Private result ORAM bucket validation contexts redact expected epochs, bucket
counts, and ciphertext size limits. Audit events never include request bodies.
Prometheus request metrics may include fixed REST/gRPC endpoint labels and the
collection label for private ORAM manifest, session, read, and commit APIs, but
they do not include path labels, bucket ids, session ids, ciphertext bodies, or
client-state fields, including `*_ciphertext_sha256` client-state aliases. The OpenAPI and gRPC consistency gates pin the private
ORAM REST method/path/operation ids and generated gRPC method paths using exact
route-shape matching. Metrics canonicalization strips query strings only for
otherwise fixed routes and drops malformed/lookalike or extra-tail private ORAM
paths, so these metrics labels cannot silently drift away from the published
API surface. gRPC private HNSW/result ORAM services use the same collection
telemetry wrapper as other collection-scoped services, but the wrapper attaches
only `collection_name` and not vector names, session ids, path labels, bucket
ids, roots, ciphertext, client-state fields, or `*_ciphertext_sha256` aliases.
Client-side-only envelope collections must use `raw` or `redacted`; requesting
`decrypted` fails closed because Qdrant has no client data key.
The REST single-point `GET /collections/{collection}/points/{id}` endpoint has
no request body, so it accepts the same read policy through the
`encrypted_payload=raw|redacted|decrypted` query parameter.
Generic server-side crypto instances require
`options.material_fingerprint_id` to be an opaque deployment-local key version
id. Payload and vector runtime validation rejects missing values so envelopes
do not fall back to key-derived fingerprints. Low-level test helpers may still
construct deterministic fingerprints directly from key material, but production
runtime configuration must provide explicit opaque fingerprint ids.
If the old `ckks` runtime section is configured, settings parsing fails with an
unknown-field error. Migrate to the canonical `crypto` control plane before
enabling encrypted writes.

## Storage path threat model

The intended security boundary is encrypt-before-storage for selected payload
string fields and CKKS vector ciphertext envelopes. This branch does not yet
claim complete end-to-end leakage coverage for every Qdrant storage and cluster
path; the table below is the current contract until integration tests cover each
row.

| Path | Expected protected content | Current status | Required gate before production use |
| --- | --- | --- | --- |
| REST/gRPC ingress | Request payload and plaintext embeddings may exist in process memory until encryption completes. | Trusted Qdrant process boundary. Slow-request log values and request hashes redact payloads, vectors, universal query vectors, and payload filter literals before serialization/hash calculation. | Keep request/body logging disabled or redacted for encrypted fields and embeddings. |
| WAL | Selected payload strings and CKKS vector metadata should be stored only as envelopes after encryption. | Payload sentinel leakage scans cover public server-side/client-side payload ingress and collection directory files, including WAL files. CKKS vector sidecar coverage verifies plaintext vectors are removed before storage and scans collection files for successful encrypted-vector f32/f64 byte patterns. `wal_inspector` redacts collection update operations by default and requires `--raw` to print raw encrypted markers. | Broaden cluster storage scans. |
| Segment and optimizer temp files | Selected payload strings should appear as marker/envelope JSON; CKKS vector plaintext should not be stored by the CKKS envelope path. | Payload sentinel leakage scans cover persisted collection files after graceful stop, and public ingress leakage coverage also scans an explicit optimizer temp directory. `segment_inspector` redacts server payload, client payload, metadata ciphertext, and CKKS vector sidecar markers by default and requires `--raw-payload` for raw marker output. | Broaden optimizer coverage as new temp-file paths are introduced. |
| Payload indexes | AEAD-encrypted fields are not searchable as plaintext. Exact-match search must use separate client-generated blind-index token fields. | Index creation over encrypted payload paths and parent/child overlaps is rejected. `metadata/blind-index-hmac@v1` token fields may be indexed only on the exact token field with `keyword` schema and filtered as opaque HMAC-SHA256 tokens, but parent/child token indexes, non-keyword token indexes, order-by, grouping, facets, and formulas over token fields fail closed. | Keep rejecting plaintext indexes over encrypted content; broaden blind-index SDK and query-mode coverage as new search flows are added. |
| HNSW graph and quantization | CKKS ciphertext vectors are searched through sidecar ciphertext scoring, not through plaintext dense vector storage. | REST/gRPC nearest-neighbor search can score stored CKKS ciphertext envelopes through the OpenFHE bridge using the collection distance metric. `hnsw_ef` uses existing segment-native or persisted CKKS ciphertext graph artifacts; exact and non-HNSW requests use brute force. Query-time foreground graph build is disabled so cache misses fail fast instead of performing O(n²) stored-ciphertext scoring. Segment optimization counts encrypted sidecar bytes, assigns immutable `CkksCiphertextHnsw` segment index artifacts, and persists their private graph files instead of plaintext HNSW, mmap conversion, or quantization. Persisted graphs must be private, owned by root or the Qdrant process user, stored under a trusted parent directory chain, reciprocal, and connected. Raw-dense recommend and raw-dense discover use the same encrypted-query sidecar scoring path but remain brute-force. Quantization remains unsupported for encrypted vectors, and collection validation rejects per-vector or collection-level quantization configs for encrypted vector names. | Broaden distributed rebuild/recovery coverage before treating it as a production-grade segment-native ciphertext index. |
| Snapshots | Snapshot archives should contain encrypted payload/vector envelopes and enough metadata to preflight required keys/context and stable collection identity. | Payload sentinel leakage scan now creates and scans a collection snapshot archive. Collection snapshot creation rejects encrypted configs whose migration state is not `active`. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings for missing instance/material/backend, wrong wrapped-RK key, provider key-id mismatch, missing encrypted collection UUID, UUID mismatch, non-active migration state, and invalid CKKS public material. Valid-but-different CKKS public-material drift is covered by peer runtime parity and sidecar `context_digest` open/score checks. | Broaden restore coverage across cluster paths and add full archive-level sidecar scan coverage if restore starts validating stored sidecars before load. |
| Shard transfer and replication | Sender and receiver must have matching crypto runtime material and CKKS context. | App telemetry, peer metadata, and distributed telemetry expose a non-secret crypto runtime capability fingerprint. Encrypted collection data-movement operations validate involved peer metadata and fail closed on missing or mismatched fingerprints. Automatic dead-replica recovery skips source peers without matching parity metadata. `/readyz` does not mark the node ready for encrypted collections while peer metadata fingerprints are missing or mismatched. | Broaden distributed integration coverage and cluster-wide parity tests. |
| Telemetry, logs, and audit | No plaintext payload bodies, embeddings, ciphertext blobs, signatures, wrapping keys, verifier public-key bodies, or runtime key material should be emitted. | Bridge request bodies and stderr are not included in returned errors. Collection telemetry and slow-request log-value/request-hash smoke tests cover payload/vector/filter/query sentinels, crypto envelope fields, plural batch fields, and camel/kebab-case secret field spellings. Audit events do not include request bodies, and denied audit error strings redact qdrant-sec envelope markers plus secret-like crypto fields. App telemetry exposes only a non-secret crypto runtime capability fingerprint and regression tests assert inline/wrapped key material plus client-envelope/private-ORAM verifier key options are not serialized. | Broaden audit/log capture coverage around any new request logging surfaces. |

## CKKS vectors

`EncryptedCkksVector` stores an AEAD-sealed metadata envelope. The sealed body
contains the OpenFHE CKKS ciphertext plus `key_id`, `vector_name`, `slots`, and
`context_digest`, so storage-side tampering of vector metadata fails closed. The
AEAD key comes from the collection CKKS runtime key material, while the OpenFHE
public material still encrypts the embedding itself:

```json
{
  "version": 1,
  "scheme": "openfhe-ckks",
  "envelope": {
    "version": 1,
    "algorithm": "AES-256-GCM",
    "key_id": "tenant-a:ckks",
    "material_fingerprint": "...",
    "rk_id": "tenant-a/vector-v1",
    "rk_epoch": 3,
    "nonce": "...",
    "ciphertext": "..."
  }
}
```

The vector envelope uses `collection identity`, `point_id`, and `vector_name`
AAD binding. New callers should pass the persisted collection UUID or a stable
crypto collection id as the vector collection identity. Collection-level
encrypted vector write/read/search guards require a persisted UUID and do not
fall back to collection name. Moving an encrypted vector envelope to a different
point, vector name, or collection identity must fail authentication after
unwrap.
Inside the sealed body, `context_digest` is still the SHA-256 digest over the
CKKS parameters, serialized OpenFHE crypto context, and public key. It is
intended to prevent mixing ciphertexts created for incompatible contexts.
CKKS parameters are restricted through the crypto crate's allowlisted profile
registry, which currently contains only `ckks-128-n16384-d4-scale50` in this
branch. Generic
`vector/openfhe-ckks@v1` runtime instances must set this `profile` option plus
`crypto_context_b64`, `public_key_b64`, and
`score_plaintext_output_tcb_ack: qdrant-sec-ckks-score-output-tcb-v1`; a
missing profile, missing public material, missing score-output TCB
acknowledgement, or raw profile name is rejected before collection creation.
`batch_size` may be lower than the profile slot count, but raw
modulus/depth/scale combinations are rejected. OpenFHE bridge encrypt, batch
encrypt, and scoring responses must include `security_profile`; Qdrant verifies
that it matches the requested allowlisted profile. Responses may also include
`security_level_bits` and `noise_budget_bits`; when present, Qdrant rejects
reported security below 128 bits and rejects non-finite or negative noise budget
metadata.

Nearest-neighbor search over an encrypted vector name is implemented for
client-encrypted CKKS query envelopes and root direct point-id nearest `query`
or `query/groups` requests when runtime `crypto` settings are available on the
serving node. Raw dense REST/gRPC query vectors are rejected by default for
`vector/openfhe-ckks@v1`; setting `allow_plaintext_queries: true` also requires
`plaintext_query_tcb_ack: qdrant-sec-ckks-plaintext-query-tcb-v1`. This explicit
acknowledgement opts into a server-side query plaintext TCB for client-supplied
numeric dense vectors. Query vectors produced by Qdrant inference (`document`,
`image`, or `object` inputs) remain rejected for encrypted vector names because
they would send client plaintext to the inference service before CKKS scoring.
In the raw dense opt-in mode, Qdrant scrolls the encrypted sidecar payloads,
validates each CKKS envelope against the active OpenFHE public material/context
digest, sends `encrypt_query` to the bridge, and then sends
`score_encrypted_query_batch` requests over the encrypted query ciphertext plus
stored sidecar ciphertexts. For point-id nearest `query`, Qdrant first retrieves
the referenced point's stored CKKS sidecar envelope and uses its stored
ciphertext as the encrypted query in `score_encrypted_query_batch`; plaintext
vectors are still not stored or read. The same stored-query sidecar scoring is
used before plaintext payload grouping for root direct point-id `query/groups`.
REST universal nearest `query` and `query/groups` may supply a client-side
encrypted query envelope instead of a raw dense vector:

```json
{
  "$qdrant_sec_ckks_query": {
    "version": 1,
    "scheme": "openfhe-ckks",
    "security_profile": "ckks-128-n16384-d4-scale50",
    "collection_id": "collection-stable-crypto-id",
    "vector_name": "text",
    "key_id": "tenant-a:vector",
    "rk_id": "tenant-a/vector-v1",
    "rk_epoch": 3,
    "query_nonce": "base64url-no-pad-96-bit-query-nonce",
    "context_digest": "...",
    "slots": 1536,
    "ciphertext_sha256": "base64url-no-pad-sha256-of-ciphertext",
    "ciphertext": "...",
    "signature": {
      "alg": "ed25519",
      "key_id": "tenant-a/query-signing-v1",
      "sig": "base64url-no-pad-ed25519-signature"
    }
  }
}
```

The `collection_id`, `vector_name`, `key_id`, `rk_id`, and `rk_epoch` fields must
match the active encrypted vector rule's stable collection crypto identity and
resource-key lineage. `query_nonce` is mandatory 96-bit base64url-no-padding
client randomness and is cryptographically bound into the query signature; SDKs
must regenerate it when retrying a request body. Qdrant also records
`collection_id`, `vector_name`, `key_id`, `rk_id`, `rk_epoch`, and
`query_nonce` in a bounded process-local TTL replay cache before bridge scoring,
rejecting recent replays with an error that instructs clients to create a fresh
envelope. The signer key is still validated and included in non-secret warning
metadata, but it is not part of the freshness key; the same CKKS resource-key
lineage cannot reuse a query nonce by switching signers. This is a replay guard,
not a cluster-wide ledger. When `cluster.enabled=true`, client-supplied CKKS
encrypted query envelopes fail closed until a consensus-backed query nonce
ledger exists, so local replay caches are not silently treated as a distributed
freshness guarantee. The
`context_digest` must match the active OpenFHE public material and CKKS parameter profile for that rule,
`slots` must match each stored sidecar envelope being scored,
`ciphertext_sha256` must match the decoded ciphertext bytes, and `ciphertext` is
base64url without padding. The `signature` object is mandatory for
client-supplied encrypted query envelopes: `alg` must be `ed25519`, `key_id`
must select a configured `signature_public_keys` entry on the active
`vector/openfhe-ckks@v1` runtime instance, and `sig` must verify the
domain-separated query metadata, query nonce, and ciphertext under
`qdrant-sec/client-ckks-query-signature/v1`. gRPC carries the same proof through
`query_nonce`, `signature_alg`, `signature_key_id`, and `signature_b64`.
Qdrant does not decrypt or validate the CKKS ciphertext itself; it treats the
validated bytes as the encrypted query input to the OpenFHE bridge scoring API.

The client CKKS query signature message is canonical and length-prefixed so SDKs
can produce interoperable envelopes. The byte string is:

1. ASCII domain `qdrant-sec/client-ckks-query-signature/v1\0`.
2. For each UTF-8 field below, an 8-byte big-endian length followed by the field
   bytes: `version`, `scheme`, `security_profile`, `collection_id`,
   `vector_name`, `key_id`, `rk_id`, `rk_epoch`, `query_nonce`,
   `context_digest`, `slots`, `ciphertext_sha256`, `signature.alg`,
   `signature.key_id`.
3. An 8-byte big-endian length followed by the decoded CKKS query ciphertext
   bytes.

For the current profile the first fields are `version=1`,
`scheme=openfhe-ckks`, and
`security_profile=ckks-128-n16384-d4-scale50`. `ciphertext_sha256` is the
base64url-no-padding SHA-256 digest of the decoded ciphertext bytes and is
signed before the ciphertext bytes themselves are appended. Any field ordering
change, missing field, stale `query_nonce`, wrong `rk_epoch`, or changed
ciphertext bytes invalidates the Ed25519 signature.
`docs/ckks-client-query-signature-test-vector.json` contains a known-answer
fixture for SDKs and is checked by the server unit tests.

Result ordering and
`score_threshold` follow the configured Qdrant distance metric:
`dot`/`cosine` are larger-is-better, while `euclid`/`manhattan` are
smaller-is-better. If `hnsw_ef` is set and `exact=false`, nearest-neighbor
search uses a ciphertext sidecar candidate graph with encrypted-query bridge
scoring for traversal candidates. Query-time foreground graph construction is
disabled: if no segment-native or persisted graph is available for the requested
sidecar set, the request fails fast and callers must retry without `hnsw_ef` or
rebuild the encrypted vector index. Stored point-id nearest `query`/`query/groups`
requests also use the sidecar graph when `hnsw_ef` is provided, scoring
traversal candidates against the referenced point's stored ciphertext. Segment
optimization counts CKKS vector sidecar
ciphertext bytes for encrypted vector thresholds and builds an immutable
`CkksCiphertextHnsw` vector index artifact instead of plaintext HNSW, plain
mmap conversion, or quantization. For unfiltered nearest-neighbor requests,
serving-time CKKS search first loads those segment-native artifacts for
unfiltered requests without an explicit read-consistency override. Indexed
segments are searched through their native CKKS graph, while sidecars that still
live in non-indexed segments are brute-force scored and merged. If a target shard
is not locally inspectable, a filter narrows the candidate set, or the request
requires explicit read consistency, Qdrant falls back to the collection-level
sidecar graph cache/brute-force path. Because segment optimization does not own
the OpenFHE scoring runtime, optimizer-built segment artifacts use a
deterministic connected candidate graph; serving-time CKKS search still scores
visited ciphertext candidates through the runtime bridge.

The collection-level sidecar graph cache is keyed by stable collection crypto
identity, vector name, score direction, graph parameters, and a fingerprint of
the stored ciphertext sidecars, so rename/recreate boundaries and payload/vector
changes do not reuse stale links. The in-memory cache is an acceleration for the
current serving process, and Qdrant may load pre-existing persisted graph hints
under the collection directory. Persisted graph cache files are treated as
untrusted hints:
the cache directory must be a private non-symlink directory owned by root or the
Qdrant process user, every non-sticky parent directory in the path must be
owned by root or the Qdrant process user and not group/world-writable, cache
files and stale temp files must be private regular files owned by root or the
Qdrant process user, oversized files are rejected, and metadata/fingerprint
mismatches or disconnected/non-reciprocal graphs are ignored. Qdrant does not
build a replacement collection-level graph on the read path because that would
require foreground pairwise CKKS scoring. Trusted sticky ancestors such as `/tmp`
are allowed only above the private cache directory so test and temp deployments
can still use standard temporary roots. Query execution does not write new
collection-level persisted graphs or prune cache files. It is still not the
plaintext-vector
`HNSWIndex` file format and should be treated as an experimental ciphertext
candidate index until distributed rebuild and recovery coverage is broader.
`search/groups`, `recommend/groups`, and root direct `query/groups` are
supported when the group field is plaintext payload and runtime OpenFHE settings
are available. `with_lookup` is supported for lookup payloads and plaintext
vectors; lookup payloads use their own `with_payload` encrypted read policy,
and lookup requests that ask for encrypted vectors fail closed. Grouped paths
still use brute-force sidecar scoring.
REST and gRPC search matrix requests over an encrypted vector name sample stored
sidecar envelopes and use stored-ciphertext-to-stored-ciphertext bridge scoring
for pairwise nearests inside the sample; encrypted matrix sampling is
deterministic over the filtered sidecar scan rather than the plaintext random
vector sampler. Universal query prefetches over encrypted vector names may feed
root RRF/DBSF fusion, including mixed plaintext and encrypted prefetch sources.
Non-fusion prefetches are evaluated first and converted to a candidate-id filter
before the encrypted or plaintext root query is rescored. Quantization,
ACORN/indexed-only params remain unsupported. Root direct
`NearestWithMmr` and `NearestWithMmr` query groups over an encrypted vector name
use CKKS sidecar scoring for both query-to-candidate relevance and
candidate-to-candidate diversity; they are limited to large-better metrics
(`dot`/`cosine`). Legacy and
universal recommend queries are supported for `average_vector`, `best_score`,
and `sum_scores` with raw dense examples and point-id examples from the same
encrypted vector sidecar. Single-positive point-id `average_vector` loads that
point's stored sidecar ciphertext as the query, while multi-example point-id
`average_vector` scores every raw dense or stored point-id example independently
and combines the scores as positive and negative averages. Raw-dense
`average_vector` is reduced to one plaintext query vector which is encrypted
through the bridge before scoring; `best_score` and `sum_scores` encrypt each
raw dense example or load each point-id sidecar and score it against the stored
sidecar ciphertexts before combining the scores with the same objective as
Qdrant's plaintext recommend path. Sparse examples fail closed because Qdrant
does not retain sparse encrypted vector sidecars. `best_score` and `sum_scores`
are accepted only for large-better metrics (`dot`/`cosine`) in this sidecar
executor; small-better metrics (`euclid`/`manhattan`) fail closed until the
bridge exposes raw similarity scores for those metrics. Legacy and universal
`discover` support raw dense and point-id target/context examples by loading
stored sidecar ciphertexts for point-id examples. Discover sidecar scoring uses
the same rank plus scaled-sigmoid target objective as Qdrant's plaintext
discover path. Universal `context` queries are supported for raw dense and
point-id context pair examples and use the same pair-rank objective as Qdrant's
plaintext context path.
Discover and context sidecar scoring are accepted only for large-better metrics
(`dot`/`cosine`). Direct collection-internal calls without runtime settings
still fail closed for encrypted vector names. The
`$qdrant_sec_vectors` payload sidecar is an internal ciphertext container:
clients may receive it raw when payloads are requested, but Qdrant rejects
payload indexes, filters, ordering, grouping, facets, and formula references
that target the sidecar field.

## OpenFHE bridge protocol

`CommandOpenFheBackend` invokes an external bridge binary as a long-lived worker.
The bridge reads newline-delimited JSON requests from stdin and writes one
newline-delimited JSON response per request to stdout. The backend reuses the
same child process while the bridge stays healthy and respawns it if the worker
exits between requests.
Single vector encryption requests use `operation: encrypt`; batch vector
encryption requests use `operation: encrypt_batch`; query-vector encryption
requests use `operation: encrypt_query`. Encrypted-query scoring requests use
`operation: score_encrypted_query` for single-point scoring or
`operation: score_encrypted_query_batch` for scroll-batch scoring. Legacy
`score_plaintext_query` operations are kept as a backend compatibility API but
the Qdrant search path uses encrypted-query scoring. All bridge
requests include a deterministic `context_id` and collection/vector routing
metadata. The first successful request for a `context_id` on a bridge worker
also includes the profile parameters plus OpenFHE public material. After that,
Qdrant treats the context as registered on that worker and omits `parameters`,
`crypto_context`, and `public_key` from subsequent requests using the same
`context_id`. If the worker exits or is discarded, the replacement worker must
receive the full material again before it can process cached-context requests.
The `context_id` is the base64url SHA-256 digest Qdrant also stores in CKKS
vector envelopes, so the bridge can cache OpenFHE contexts/public keys by id
while Qdrant avoids sending large public material on every vector operation.
Scoring requests additionally include the collection `distance` metric (`dot`,
`cosine`, `euclid`, or `manhattan`), an encrypted query ciphertext, and stored
CKKS ciphertext bytes. Batch responses must preserve request item order and
return exactly one ciphertext or finite score per item. All encrypt, batch
encrypt, and scoring responses must include
`security_profile`, and it must equal the configured allowlisted CKKS profile.
Responses may include `security_level_bits` and `noise_budget_bits`; Qdrant
validates those optional fields when supplied and fails closed on sub-128-bit
security levels, negative noise budgets, or non-finite noise budgets.
The subprocess backend still enforces a positive `timeout_ms` and caps
stdout/stderr collection so a hung or noisy bridge cannot block Qdrant
indefinitely or force unbounded memory growth. Returned errors do not include
the request body or bridge stderr. Process-pool backends also fail fast when
all configured workers are already busy, rather than queuing additional
plaintext-bearing bridge requests behind a busy worker.

The OpenFHE bridge is part of the trusted computing base because it receives
plaintext embeddings before producing CKKS ciphertext and returns finite
plaintext ranking scores to Qdrant for CKKS sidecar search. Encrypted query
envelopes keep query vectors out of Qdrant's numeric request body, but they do
not make vector ranking server-blind: the bridge and Qdrant still learn score
ordering and returned score values. Runtime configuration
therefore accepts only absolute bridge paths that resolve to executable regular
files, rejects symlinks and group/world-writable binaries or parent directories
on Unix, and requires the binary plus every parent directory to be owned by root
or the Qdrant process user. Generic process backends must set `sha256_b64` to
pin the expected bridge binary digest; generic runtime validation and checked
backend construction both hash the bridge through a no-follow file descriptor
on Unix. Operators can additionally set `signature_public_key_b64` and
`signature_b64` to require an Ed25519 signature over the domain-separated
bridge digest (`qdrant-sec/openfhe-bridge-binary-signature/v1 || sha256`).
The signature fields must be configured together, are included in the runtime
capability fingerprint, and therefore participate in cluster parity checks.
On Linux, checked bridge workers are spawned through a
`/proc/self/fd/<fd>` path backed by the same no-follow validated bridge file
descriptor held open through `spawn`, which narrows the path-swap window between
validation, hashing, and execution.
On non-Linux platforms, checked OpenFHE bridge construction fails closed because
qdrant-sec cannot provide the Linux fd-backed exec mitigation. Deployments that
need the trusted OpenFHE bridge must run that provider on Linux; strict
zero-trust deployments should use the client-led private HNSW ORAM provider
instead of a trusted bridge.
Treat any bridge path change as privileged code execution under the Qdrant
service account. On Linux, the checked bridge spawn path also sets
`no_new_privs`, parent-death `SIGKILL`, `RLIMIT_CORE=0`, and `RLIMIT_FSIZE=0`
so the plaintext-bearing bridge cannot gain extra privileges through
setuid/file-capability execution, is killed if Qdrant exits, does not produce
normal core dumps, and cannot write regular files. Checked bridge workers start
from `/` rather than inheriting Qdrant's working directory, with an empty
inherited environment plus a fixed
`/usr/sbin:/usr/bin:/sbin:/bin` `PATH` for `/usr/bin/env` shebang compatibility,
so env-backed Qdrant settings, crypto material, `LD_PRELOAD`, `PYTHONPATH`, and
other service environment values are not handed to the bridge process by
default. Test-only unchecked bridge workers still remove `QDRANT`/`QDRANT_*`
and explicitly configured sensitive env names.
If the backend kind is `process_landlock_netns`, `process_pool_landlock_netns`,
`process_landlock_strict_netns` or `process_pool_landlock_strict_netns`, Qdrant
also asks Linux to place the bridge child in a fresh network namespace before
`exec`. This is the only Qdrant-managed bridge egress-deny mode; plain
`process_*`, `process_*_landlock` and `process_*_landlock_strict` kinds keep
the host network namespace and rely on external firewall, AppArmor, seccomp, or
container policy for network confinement.

Request fields:

```json
{
  "version": 1,
  "operation": "encrypt",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "point_id": "point-1",
  "vector_name": "embedding",
  "context_id": "base64url-no-pad-context-digest",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "values": [0.125, -42.5, 9.75]
}
```

After the worker has successfully processed one request for the same
`context_id`, later requests omit the public material fields:

```json
{
  "version": 1,
  "operation": "score_encrypted_query_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "distance": "dot",
  "context_id": "base64url-no-pad-context-digest",
  "encrypted_query": "base64url-no-pad-query-ciphertext",
  "items": [
    { "point_id": "point-1", "ciphertext": "base64url-no-pad-ciphertext-1" }
  ]
}
```

Response fields:

```json
{
  "version": 1,
  "security_profile": "ckks-128-n16384-d4-scale50",
  "ciphertext": "base64url-no-pad-openfhe-ciphertext"
}
```

The Rust `CkksVectorBackend` trait also exposes `encrypt_batch` so backends can
amortize vector encryption overhead. `CommandOpenFheBackend` sends one
newline-delimited batch request with shared context and per-point items. The
first request for a worker/context carries the public material shown below;
subsequent requests for the same context omit those public material fields:

```json
{
  "version": 1,
  "operation": "encrypt_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "context_id": "base64url-no-pad-context-digest",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "items": [
    { "point_id": "point-1", "values": [0.125, -42.5] },
    { "point_id": "point-2", "values": [9.75, 3.5] }
  ]
}
```

The bridge response must preserve item order:

```json
{
  "version": 1,
  "security_profile": "ckks-128-n16384-d4-scale50",
  "ciphertexts": [
    "base64url-no-pad-openfhe-ciphertext-1",
    "base64url-no-pad-openfhe-ciphertext-2"
  ]
}
```

`CkksVectorEncryptor` still validates each input vector before the backend call
and seals every returned ciphertext with per-point AAD.

Encrypted-query batch scoring uses the same shared context and query ciphertext,
while each item carries the stored ciphertext for one point:

```json
{
  "version": 1,
  "operation": "score_encrypted_query_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "distance": "dot",
  "context_id": "base64url-no-pad-context-digest",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "encrypted_query": "base64url-no-pad-query-ciphertext",
  "items": [
    { "point_id": "point-1", "ciphertext": "base64url-no-pad-ciphertext-1" },
    { "point_id": "point-2", "ciphertext": "base64url-no-pad-ciphertext-2" }
  ]
}
```

The bridge response must preserve item order and include the expected profile:

```json
{
  "version": 1,
  "security_profile": "ckks-128-n16384-d4-scale50",
  "scores": [9.0, 4.0]
}
```

If the response score count differs from the request item count, or any score
is non-finite, Qdrant discards the bridge response and fails the search.

The Rust side does not include request or bridge stderr in returned errors to
avoid accidentally propagating plaintext embeddings into logs.

## Hardening notes (September 2026 review)

The fixes below change observable behaviour; each is enforced in code and
covered by tests where the affected crate can be tested in isolation.

Crypto and ORAM protocol:

- `ExistingPayloadMode::ReencryptIfStale` compares the resource key lineage
  (`rk_id`/`rk_epoch`) as well as key id, material fingerprint, schema version
  and epoch, so a pure resource-key rotation re-wraps stored envelopes.
- CKKS sidecar markers (`$qdrant_sec_vectors.<name>`) must be the only key of
  their value; sibling keys are rejected instead of ignored.
- Private HNSW/result ORAM commits require `new_epoch == old_epoch + 1` on the
  SDK, in commit planning and signature validation, on the server session, and
  in the collection stores.
- Remap and padding leaves are caller-supplied uniform samples
  (`sample_private_hnsw_oram_leaf`, `sample_private_result_oram_leaf`); the
  prefetch and traversal batch planners take a padding source and emit
  batches in canonical leaf order; result ORAM read planners pad leaf
  collisions with dummy paths recorded in the plan instead of failing.
- Append transactions never read or evict the new block's own initial leaf:
  the HNSW insert consumes the next padding leaf and the result plan carries an
  explicit `insert_eviction_leaf` bound into the attempt digest.
- Commit writebacks are budgeted per session (one path per path read, at least
  one fixed round, at most the tree); see the fixed-budget paragraph above.
- Immutable manifests must leave at least one candidate window
  (`path_batch_size` paths) after `max_neighbor_rewrites + 1` reserved paths.

Server and consensus:

- Raft membership gates use raft's own pending-configuration semantics
  (`pending_conf_index > applied`) instead of comparing the field against zero,
  which had rejected every membership change on a leader with a non-empty log.
  After the private ORAM activation floor is installed, committed configuration
  changes are applied (never halting consensus) and `RemovePeer` is allowed so a
  dead peer can be dropped; `AddPeer` and learner promotion remain blocked until
  the private ORAM roster is re-established, and `--reinit` is still refused.
- Replicated ORAM writebacks classify the epoch CAS outcome: unresolved
  proposals are re-proposed, only a definitive rejection aborts the prepared
  journals, and a still-unresolved outcome is returned as a `Timeout` with the
  prepared state retained for session recovery.
- A crypto migration state of `disabled` (the initial state and the state after
  a completed decrypt run) is inert: write plans use `effective_encryption()`
  like reads, and startup/restore only reject in-flight migrations.
- Encrypted MMR search caps `candidates_limit` by
  `crypto.ckks_grouped_max_candidates`, keeps ciphertexts in memory only for the
  retained MMR candidates, and scores each newly selected point against the
  remaining candidates in batched bridge calls.
- `update_vectors` on one encrypted vector re-verifies and carries forward the
  point's other encrypted sidecar entries; `overwrite_payload` is refused on
  collections with encrypted vector rules (like `clear_payload`) because it
  would discard the reserved sidecar; replicas accept server-blind client CKKS
  sidecar entries on the peer replay path after checking their binding.
- Vault Transit wrapped resource keys (blob version 2) carry a SHA-256 of the
  wrap AAD inside the Transit plaintext, so a blob wrapped for one scope cannot
  be unwrapped under another even for non-derived Transit keys. Version 1 blobs
  still open and log a warning; re-wrap them under the current master key.
- Plan builds that call Vault/KMS or read material files run under
  `block_in_place` when invoked from a multi-thread runtime; `fd` material
  sources are rewound (or memoized for pipes) so a second plan build does not
  read an empty secret.
- The OpenFHE bridge waits up to five seconds for a busy worker before
  failing; the on-disk CKKS sidecar graph cache is only read by tests.
- Optimizer planning sums CKKS ciphertext sizes in place and caches the total
  against the segment version.
- Deleting a collection prunes its private ORAM consensus records (epochs,
  session leases, layouts, external recoveries, mutation state and lease slot).
- Internal replication handlers wait at most 30 seconds for the replication
  lock and 30 seconds for an install-stream slot, returning a retryable
  unavailability instead of parking indefinitely.

### Second pass

Crypto crate:

- Blind-index token bindings are compared in constant time.
- Every `AeadCipher` counts its AES-GCM invocations and refuses to encrypt
  after 2^32 (NIST SP 800-38D random-nonce bound), warning at half; the count
  is per process and resets when the resource key rotates.
- Decrypted buffers, plaintext copies taken from JSON values during
  encryption, and derived-key stack copies are zeroized.
- `validate_client_payload_value` never reports a signature digest for a
  signature it could not verify; a digest now always means "verified against
  the expected key".

Consensus and shard transfer:

- A Raft snapshot rejected by validation no longer arms the indeterminate
  fence; only failures after local side effects started do.
- Private ORAM snapshot recovery markers that cannot be reconciled with the
  consensus state are logged and skipped per collection instead of stopping
  the Raft thread; a corrupt source preinstall intent is quarantined
  (`private_oram_source_preinstall.json.invalid-<unix>`) and ignored.
- A transfer target that lost its preinstalled stores a second time triggers
  another fresh preinstall (the target only re-requests while its stores are
  missing; the source rate-limits restarts to one per minute), and a resume
  target whose transfer was aborted releases its marker so dead-replica
  recovery can run.
- Automatic dead-replica recovery works for custom-sharded ORAM collections
  with several shard keys (the layout check uses the shard key mapping).
- Layout CAS entries apply the collection meta-op before advancing the
  consensus layout, so a deterministic meta-op failure cannot leave the layout
  ahead of the collection state.

Stores, bridge and API layer:

- Epoch commit history behind the current epoch is pruned to 1024 records when
  the epoch advances; owner verification refused directories above 4096
  entries, which made long-lived indexes unrecoverable.
- Bridge requests are written from a helper thread under the request timeout;
  a bridge that stops draining stdin is killed instead of parking a worker
  forever. The response line cap defaults to 64 MiB and is configurable per
  backend as `max_output_bytes`. Workers are spawned outside the pool lock.
- Public gRPC services cap message sizes at `service.max_request_size_mb`
  like REST; internal peer services stay unbounded.
- Mutation v2 read handlers check collection access before touching the
  session registry.
- Staged owner writebacks release the session commit slot when dropped without
  an outcome; standalone reads and commits run store I/O outside the session
  registry mutex on a blocking thread.

### Third pass: fuzz and concurrency tests

`lib/crypto/tests/fuzz_security.rs` drives every untrusted-input surface of
the crypto crate with `proptest`: AEAD envelope and payload envelope
mutations, the control-plane envelope parser and stored-value round trip, the
server-side ingress validators (upload bundles and manifests of both ORAMs
with single-field mutations of an otherwise valid bundle, client CKKS
sidecars), leaf labels, the result ORAM
block/bucket codecs, the HNSW node block/bucket codecs, sealed buckets and
client state snapshots, Merkle path proofs (every field mutation, swapped or
stale buckets, dropped leaves), fetch batch planning under leaf collisions, a
Path ORAM client simulation for both ORAMs (no block is ever lost or
duplicated, failed accesses leave the client state untouched), CKKS parameter
validation, the staged insert frame codec and the owner lifecycle JSON frames.
The invariants are: decoders never panic, encoders and decoders are exact
inverses on the accepted set, every mutation of authenticated data is
rejected, and request shapes do not depend on secret collisions.

`lib/crypto/src/aead_concurrency_tests.rs` and
`lib/crypto/src/openfhe_concurrency_tests.rs` exercise the AES-GCM invocation
budget under thread contention (exactly the remaining budget is spent, nonces
stay unique, decryption consumes nothing) and the bridge worker pool from many
threads against a scripted bridge (`sh` on Unix, PowerShell on Windows): the
pool never exceeds its size, a worker is reserved by one request at a time,
stalled and garbage-emitting bridges are replaced without hanging callers, and
spawn accounting returns to zero.

Fixed while writing them:

- `decode_private_hnsw_node_block` sized two allocations from the untrusted
  `neighbor_count`/`fixed_neighbor_slots` counters before checking that the
  block could hold that many slots; a crafted block claiming four billion
  slots aborted the process on allocation failure. The counters are now bounded
  by the remaining block bytes.
- `access_private_result_oram_path` and `access_private_hnsw_oram_path` loaded
  the served path into the stash before discovering that the target block was
  missing, leaving the other path blocks stashed while the server still stored
  them; the next overlapping read was then rejected as a duplicate and the
  client was wedged. The target is now located before the stash is touched.
- The bridge spawn slot was released after the pool lock was dropped, so a
  concurrent caller could count a freshly pushed worker twice and report the
  pool as exhausted although a slot was free.
- The ordered result ORAM fetch planner filled a batch that could no longer
  avoid a leaf collision from the first leaf with tokens left, piling
  collisions into the last batches; it now takes the leaf with the most tokens
  left, which the planner test checks against the optimal collision count.
- The second pass made the client payload signature digest "verified-only",
  which broke `validate_client_payload_value_after_runtime_verification`
  (every post-runtime check failed with `ExpectedEncryptedEnvelope`, caught by
  the existing payload integration tests that the pass had not run). The
  digest is reported again with an explicit verified flag; a runtime proof is
  minted only from a verified signature, and the post-runtime comparison against
  that proof needs only the digest.
- `apply_private_oram_append_sparse_merkle_patch_v1` gained a property test:
  the patched root equals a full recomputation and every proof or update
  mutation is rejected.
- A private result ORAM token fetch let the server tell real paths from the
  dummy paths that pad a leaf collision, and therefore learn that two fetched
  payloads shared a path: the read batch listed the real paths first and the
  padding paths last, and only the real paths were written back (the server
  enforces an upper bound on the write-back, not its shape). The planner now
  emits each batch in canonical leaf order, and the fetch driver evicts every
  padding path as well, so the write-back is exactly the read set. A property
  test fetches random token sets with collisions and checks both.
- Completing a standalone private ORAM session commit (HNSW and result ORAM
  alike) ran the registry's lease-expiry sweep with the committing session's
  *renewed* lease as the clock, a value one full lease in the future, so every
  other idle session on the node was evicted and its writer slot released
  whenever any client committed. The sweep now uses the real clock and the
  renewed lease is applied to the committing session only; a registry test
  opens two sessions, commits one and checks the other survives. The same
  commit now also resets the session's read-path counter, which only ever
  grew, so a write-back is bounded by the paths read since the last commit
  rather than by everything read since the session opened.
- A collection whose decrypt migration had completed (`migration_state:
  disabled`) could not be restarted or restored: the first pass relaxed the
  in-flight gate of the recovery validators for `Disabled` but they still ran
  the public config rules, which reject every non-active state so that clients
  cannot request one directly, and the shared runtime validator checked the
  disabled rules' instances against the runtime settings. The recovery
  validators now skip those rules for `Disabled` and the runtime validator
  works from `effective_encryption()`, which already treats `Disabled` as no
  encryption, so a decrypted collection whose instances were retired restarts.
  Found by building the server unit-test target for the first time; the test
  that describes the intended behaviour had been failing since that pass, and
  a sibling test still expected the previous error wording.
- The private ORAM bucket and client-state keys had no AES-GCM invocation
  budget although every path write-back seals a whole path with random nonces
  under the same derived key. `PrivateResultOramClientKeys` and
  `PrivateHnswClientKeys` now carry the same per-key 2^32 budget as
  `AeadCipher` (`AeadInvocationBudget`), refuse further seals with
  `KeyUsageExhausted` once it is spent and warn at half; opening never
  consumes budget. Rotating the resource key resets it.

Run them with `cargo test -p qdrant-sec --test fuzz_security` and
`cargo test -p qdrant-sec --lib concurrency_tests`.

The server (`cargo test -p qdrant --bin qdrant`), storage (`cargo test
-p storage --lib`) and collection (`cargo test -p collection --lib`) unit-test
binaries build again as of this pass. Run them on Linux: the private ORAM stores, mutation journal and recovery markers rely on
Unix-only file semantics (directory `flock`, `O_DIRECTORY`/`O_NOFOLLOW`,
mode bits, directory fsync), so on Windows those tests fail with
"unsupported on this platform" or redacted I/O errors, and settings fixtures
that use `/usr/local/bin/...` bridge paths fail the absolute-path check. All
consensus-manager, session-registry and recovered-config tests pass on both.

### Fourth pass: module audits

This pass read the crypto crate's append pipeline, activation/recovery,
mutation and owner-lifecycle modules and the collection crate's owner journal
and store adapter end to end, and re-checked the CKKS sidecar and control-plane
envelopes, the AEAD envelope binding, the payload envelope and blind index, the
HNSW manifest/commit code, the consensus session leases and the REST/gRPC body
limits. Fixed:

- An HNSW append transaction issued one server path per queued action and
  refused a window whose paths repeated, so two candidates whose Path ORAM
  positions coincide, or a rewrite path equal to the insert-eviction or a
  padding leaf of the same window, aborted the attempt and, after the first
  window, poisoned it. The abandoned attempt told the server that two secret
  positions collided. Windows are now built from slots: actions that resolve
  to the same leaf share one path read (every member's block is on that path
  or already stashed, so one load and one eviction serve all of them) and each
  merged action frees a slot that reads the next spare padding leaf of the
  plan. The plan carries one padding leaf per fixed read path, more than the
  schedule consumes, so the substitutes need no plan change; a window is
  refused (`padding_leaves`) only when the spare leaves run out. Every window
  still carries exactly `paths_per_window` distinct paths and repeats across
  windows stay allowed. Tests cover a padding-leaf collision, two candidates
  on one leaf, the insert eviction colliding with a rewrite path and spare-leaf
  exhaustion.
- A wrong window sequence passed to `accept_verified_window` of either append
  transaction consumed nothing but still poisoned the attempt; it now keeps
  waiting for the right response.
- `validate_private_oram_owner_capsule_install_request_signature_v2` hashed
  the package body (up to 128 MiB) before verifying the coordinator signature
  that already commits to the body's length and digest; the signature is now
  checked first.
- Peer recovery requests accepted peer id 0 (Raft's "no peer" sentinel) for
  either party, unlike the adoption and capsule-transport requests.
- The staged insert frame decoder pre-reserved `count * size_of::<Value>()`
  bytes for every JSON array before parsing an element; nested arrays with
  large declared counts reserved tens of bytes per input byte at every level.
  The reservation is capped by what the remaining input could pay for.
- The owner lifecycle and reservation-prepare signer validators accepted any
  `key_id` next to a well-formed public key; like the cleanup and resolution
  validators they now require the id derived from the key.

Checked and left as is: every signature and digest message in the audited
modules is domain-separated and length-prefixed; activation manifests, mixed
version proofs and terminal evidence bind the fields an attacker could swap;
the owner journal's persistence layer (exclusive-create, fsync, no-replace
rename, canonical re-encode, pinned directory descriptors, exact mode and
link counts) and its digest coverage are sound; AEAD, wrapped-key and sidecar
envelopes bind their full context; session leases and lease renewals use the
server clock only.

### Fifth pass: owner lifecycle, mutation and result ORAM audits

This pass re-read the owner cleanup, reservation-resolution and pre-stage
modules, the mutation validator and the result ORAM client end to end and
traced their callers in the collection crate and the server. Fixed:

- The owner-side pre-stage handler parsed the pre-stage package (up to
  480 MiB: a full JSON parse, mutation digest recomputation, read-transcript
  reconstruction and a second canonical re-encode) before checking the
  coordinator's signer pin and signature; the size cap was the only pre-check.
  The package is now decoded after the request signature, which already
  commits to the package length and hash, has been verified.
- The pre-stage attestation statement copied `receipt_digest` and
  `receipt_sha256` from the owner's response unchecked, and the coordinator
  compared only the statement's `receipt_digest` with the receipt. The
  statement constructor now takes the receipt bytes and runs the response
  validator (receipt hash and length), and the coordinator also requires the
  response's `receipt_digest` and the statement's `receipt_sha256` to match
  the receipt it decoded.
- The mutation validator accepted an observed read transcript's
  `transcript_digest` as declared, so a transcript deserialized from storage
  could carry any digest and make the later comparison with
  `writeback.read_transcript_digest` tautological. The digest is now
  recomputed from the ordered leaf labels and the declared window geometry.
  The transcript digest builder also refuses a window that repeats a path,
  matching the transaction and server-side read validators.
- The verified result ORAM fetch base64-decoded every server-returned bucket
  inside the Merkle proof check before any size bound (the 64 MiB cap sat in
  the bucket opener, which runs afterwards). Every bucket's encoded length is
  now compared with the fixed size the geometry implies before the proof is
  touched, as the append-result transaction already did.
- The sealed result ORAM client-state snapshot was the plain JSON of the
  position map and stash, so its ciphertext length revealed stash occupancy
  and the sizes of the stashed blocks to whoever stores it. The plaintext is
  now zero-padded to a length derived from the position count, a
  caller-supplied stash capacity and the block size (the widest JSON a block
  can serialize to), the seal refuses a stash over that capacity, and a test
  checks that the ciphertext length does not change with the stash. The AEAD
  working buffers of the bucket and snapshot openers are zeroized on drop.
- The cleanup authorization ordered the outcome locator after the reservation
  locator by Raft index only; an earlier term now also fails, as it does for
  the resolution receipt. The all-owner cleanup certificate required only a
  lexicographic order of (owner index, peer id), which let one peer appear
  under two indexes or two peers share one index; indexes must now strictly
  increase and peer ids be distinct.
- The pre-stage package, request, roster digest and attestation statement
  accepted peer id 0 (Raft's "no peer" sentinel) where the cleanup, resolution
  and recovery validators refuse it.
- The append client checkpoint (position maps and stashes of every index)
  left its plaintext in the AEAD working buffers after sealing and opening;
  they are zeroized on drop now, like the result ORAM buffers above.
Checked and left as is: every signature and digest message in the audited
modules commits to the fields a receiver later trusts (version, alg, key
epoch, key id, collection, attempt and locator fields, receipt hash and
length) and tags every optional field; the cleanup receipt is re-derived from
the authority-signed target rather than trusted; every self-consistent
validator is followed by signer pinning in production; the result ORAM Merkle
binding, AEAD contexts, fixed read shape and full write-back of padding paths;
the mutation protocol's sequence, epoch and count transitions.

Tests added in this pass. A JSON leaf-mutation fuzzer
(`lib/crypto/src/json_mutation.rs`) serializes a signed message, changes one
scalar field (a digest character, a decimal id, a flag, a number, the
signature or the embedded signer) and requires the validator to reject the
result; it runs, in the module test suites, over the cleanup authorization
and receipt, the resolution receipt, the reservation-prepare record, the
enrollment genesis commitment and status attestation, the peer recovery
response and adoption request, the capsule install request, response and
attestation, the external recovery checkpoint, the pre-stage request,
response and attestation, and (in `tests/private_oram_mutation.rs`) the
signed append mutation bundle. No uncovered field was found. Deterministic
4,000-step load tests for the result and HNSW Path ORAM clients
(`lib/crypto/tests/stress_oram.rs`) mix accesses with random remaps and
evictions on a height-6 tree at 40% load and require the stash to stay under
32 blocks while every block remains on its position path or in the stash.

### Sixth pass: activation, recovery and append pipeline audits

This pass re-read the activation authority, peer activation, mixed-version
activation, peer recovery, external recovery and capsule transport modules and
the whole append pipeline (both transactions, checkpoints, owner prepare,
finalizer, client, point staging), traced their callers, and reproduced the
crypto crate's CI job on Linux. Fixed:

- The OpenFHE bridge asked for `PR_SET_PDEATHSIG`, which Linux delivers when
  the *thread* that spawned the child exits, not the process. Workers were
  spawned on whichever request thread first needed one, and request threads
  come from pools that recycle idle threads, so a live worker was killed
  mid-flight for every other caller as soon as that thread was reaped (the
  crypto crate's Linux CI job failed on exactly this: the second request of
  a busy-pool test hit a worker whose spawning thread had just finished).
  Bridge children are now spawned from one dedicated, process-lifetime
  spawner thread, so the parent-death signal again means "the bridge dies
  with Qdrant". A test spawns a worker from a short-lived thread and checks
  it survives; the busy-pool test now holds the worker past the reservation
  wait it exercises.
- The peer recovery request was the only owner-side RPC without a
  coordinator signature: anyone who could reach an owner's internal endpoint
  could make it take its lifecycle locks, read its journal and sign a fresh
  terminal for a chosen nonce (not an authority bypass, the terminal comes
  from the consensus snapshot and responses are nonce-bound). The coordinator
  now mints the nonce and signs the request with its peer identity, the wire
  message carries the key and signature, and the owner verifies both against
  its authority pin before any recovery work.
- The capsule transport validators accepted resource ids of up to 1024 bytes
  of almost any character; they now use the charset and length the peer
  recovery and external checkpoint validators enforce.
- The peer recovery and external checkpoint base64 decoders re-encode and
  compare like their siblings, so a decoder change cannot reintroduce
  malleable digests.
- The result ORAM append transaction now refuses a plan whose insert eviction
  leaf equals the point's position (the documented invariant was only tested,
  never enforced), its output validator checks the same marker digests as
  the HNSW one, and both transactions' progress reports redact stash
  occupancy and overlay size.

Checked and left as is: every manifest, challenge, ack, proof, recovery,
adoption and install message binds the fields a receiver later trusts and
every production verifier pins the signer from the activation registry;
successor and transition logic is consecutive and append-only; fixed-shape
windows, server response pinning, Merkle sibling consistency, recovery
markers, checkpoint sealing and the live owner-prepare and point-staging
validators hold up.

### Seventh pass: bridge process and HNSW client audits

This pass re-read the OpenFHE bridge module (process validation, sandbox,
request protocol, worker pool) and the HNSW client module end to end, and
cleared the crypto crate's clippy findings on Linux and Windows. Fixed:

- The bridge's stdout reader fed an unbounded channel that nothing drained
  between requests, so a bridge that kept printing grew Qdrant's memory at
  pipe throughput until the process died. The channel now holds one line and
  further output blocks the bridge; before each request the worker is checked
  for unsolicited output and discarded if it spoke unasked, since that stale
  line would have been taken as the answer.
- The bridge now runs in its own session and shutdown kills its whole
  process group, so a forked grandchild cannot keep the pipes and the last
  plaintext request alive past a discard. Every descriptor above stdio is
  marked close-on-exec in the child (except the validated program fd), and
  the script fd's close-on-exec flag is cleared inside `pre_exec` rather than
  in the parent, so concurrent spawns no longer inherit it. A worker also
  shuts its child down on drop, a failed writer-thread spawn no longer
  discards a healthy worker, and parse errors report the serde category and
  position instead of quoting bridge output.
- The unverified HNSW searches (`search_private_hnsw_oram_encrypted` and its
  cached form, benchmark and recall tools) opened whatever the server
  returned under the bucket's own id and epoch, so a replayed older bucket
  could resurrect blocks and make the search abort on a stash collision the
  server can observe. Served buckets must now match the requested path in
  order and carry an epoch below the write-back epoch.
- HNSW Merkle proofs pin every leaf's sibling count to the padded tree depth
  and cap each ciphertext's encoded length before decoding it; a padding
  node without a position, or a node cache without a padding node, is
  rejected before the first read instead of at a query-dependent step; the
  BFS-rank leaf planner is renamed as a benchmark tool and documented as
  revealing the traversal on first access; client-state snapshot and bucket
  AEAD buffers are zeroized.
- The client-side upload bundle validator sized its bucket table from the
  manifest's tree height before comparing it with the bundle's bucket count;
  the count is checked first now, as the server-side validator already did.

Checked and left as is: the checked-bridge path validation (absolute path,
regular non-symlink file, owner and mode along every ancestor, pin hashed
from the opened descriptor, fd-backed exec), the fail-closed `pre_exec`
steps, environment clearing, stderr bounding, reservation and spawn-slot
release on every path, lock ordering, response decoding, one-shot retry
semantics, request zeroization; on the HNSW side the fixed read shape and
full write-back, uniform leaf sampling, atomic path loads, the verified
Merkle chain, decoder bounds, snapshot AEAD binding and Debug redaction.

### Eighth pass: AEAD, control plane, payload and vector audits; strict bridge sandbox

This pass audited the AEAD envelope module, the control-plane envelope types,
the payload encryptor and the CKKS vector module, and closed the Landlock gap
recorded by the seventh pass. Fixed:

- The AES-GCM random-nonce budget lived in the `AeadCipher` instance, and the
  server builds a fresh cipher for every write request, so on the server
  payload and vector paths the counter restarted at zero per request and the
  2^32 limit was never enforced (only the long-lived ORAM and HNSW client
  structs were bounded). Budgets are now process-wide per key: every cipher
  built from the same key bytes shares one counter, keyed by a
  domain-separated SHA-256 of the key, so a rebuilt cipher for an exhausted
  key is refused too. The local master key provider's resource-key wrapping,
  which is also random-nonce AES-GCM, now draws from the same kind of budget.
- Error `Display` no longer echoes unbounded attacker-controlled strings:
  unsupported envelope algorithms and kinds, client algorithms and signature
  algorithms, and control-plane identifiers are rendered through a bounded,
  control-character-escaped 32-character prefix, and the CKKS sidecar marker
  parsers report a fixed message instead of serde's text (which quotes the
  offending value verbatim).
- Server payload decryption checks the schema version and encryption epoch
  before decrypting, so stale envelopes read during a rotation no longer
  materialize plaintext that is then discarded, and the decrypted buffer is
  zeroized on every error path.
- The 1 MiB server payload ciphertext cap is enforced before the generic
  envelope validator, which decodes up to the 16 MiB envelope bound; an
  oversized marker no longer costs sixteen times its rejection.
- Query ciphertexts (client-submitted pre-encrypted queries and bridge-returned
  encrypted queries) are capped at the stored-ciphertext maximum inside the
  crate rather than relying on the caller's request-size cap.
- Client CKKS `context_digest` is length-checked before decoding, matching
  `ciphertext_sha256`; a dead signature-presence check was removed.
- `SecretKey::from_bytes` scrubs its by-value argument after copying it.
- The Linux server binary did not compile since the first pass: the CKKS
  sidecar HNSW cache pruning path called a metadata validator that was gated
  on `cfg(test)`, and neither CI (crypto crate only) nor Windows checks (the
  call site is `cfg(unix)`) exercised it. The validator is built in every
  configuration again.
- New strict bridge sandbox kinds (`process_landlock_strict`,
  `process_pool_landlock_strict` and their `_netns` variants) handle the
  Landlock read and execute bits with an allow-list of the system roots, the
  device files, the validated program descriptor and the configured
  `landlock_read_allow_roots`; the roots are validated at startup, at
  collection runtime validation and at backend construction, keyed into the
  backend cache and the runtime capability fingerprint, and a missing root
  fails the spawn closed.

Tests: shared-budget tests (two ciphers from one key share the counter, a
rebuilt cipher for an exhausted key is refused, the master key wrap observes
the budget, exhausting tests own unique key bytes), bounded-echo rendering,
strict-sandbox rule construction and root validation (unit), Linux bridge
probes proving the strict sandbox denies reads and directory listings outside
the allow-list and file creation everywhere, allows a configured root, and
fails closed for a missing root, plus server kind/root validation, factory
and fingerprint tests.

Checked and left as is: the AAD construction (length-prefixed, tagged,
covers purpose, identifiers, algorithm, key metadata, nonce and suffix), the
v1/v2 resource-key metadata binding, nonce and ciphertext caps before decode,
the HKDF domain separation, blind-index constant-time comparison, the client
payload and CKKS signature messages, signature-verified proof gating, replay
keys, Debug redaction and `deny_unknown_fields` everywhere.

Known remaining limitations:

- The AES-GCM invocation budget is per process: it is not persisted, so a
  restart starts a fresh count for every key. Operators should rotate resource
  keys on a schedule rather than rely on the in-process limit alone.
- The strict Landlock sandbox kinds allow reading and executing everything
  under `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` and `/etc`; a bridge host
  that stores secrets under those roots must move them. The non-namespace
  strict kinds keep network egress, and the write-deny (non-strict) kinds
  still allow reads everywhere.
- `EncryptionContext` encodes an absent optional field and an empty one
  identically; the three constructors never produce an empty field, and
  changing the AAD encoding would invalidate stored envelopes, so this is
  documented rather than changed.
- The `ReencryptIfStale` migration path treats an envelope whose key metadata,
  schema and epoch already match as fresh without decrypting it, so a
  corrupted stored envelope survives migration unnoticed until it is read.
- The client CKKS runtime validation decodes the ciphertext up to three
  times; it is bounded by the request size but is not the cheapest shape.
- `CiphertextEnvelope` (control plane) has no production consumer; its
  `headers` and `capability` fields are not cross-validated and
  `add_vector_rule` overwrites a duplicate vector rule silently.

### Ninth pass: server-side HNSW ORAM, point staging and capsule transport audits

This pass audited the owner/server side of the private HNSW ORAM (manifests,
bucket commitments, Merkle root, commit planning, shape validation), the
point staging codec and the owner capsule install transport. No High or
Medium findings. Fixed:

- The pre-decode ceiling for uploaded and written-back HNSW buckets was the
  heuristic `bucket_size * block_size + 4096`, which falls below the exact
  fixed ciphertext size once `bucket_size` exceeds 4053; such a layout was
  signable and accepted, then every well-formed bucket was rejected as
  oversized. The ceiling is now the fixed size itself, in the crate and in
  the server's duplicate.
- The owner could not detect a replayed capsule install request because the
  challenge nonce is coordinator-issued and the owner kept no record of it;
  a captured signed install could be re-sent to make the owner re-hash,
  re-validate and re-install a package of up to 128 MiB under the
  replication lock (the capsule store is idempotent, so no state changed).
  The owner now keeps a bounded, expiring nonce cache keyed by the signed
  request and signature bytes: an identical retry is answered from the
  cached receipt response before the package is touched, and the same nonce
  with different bytes is refused. The activation acknowledgement cache was
  generalized for this.
- The private HNSW REST and gRPC route tests had not been run since the
  commit rule became `new_epoch == old_epoch + 1` and the writeback budget
  became per-session: a stale error expectation poisoned the shared fixture
  and failed every route test after it. The expectations (and the
  collection store's error wording) now match the checked rule, and the
  oversized-writeback case exceeds the whole tree so it is oversized for
  every session budget. All 167 route and cache tests pass on Linux.

Checked and left as is: the length-prefixed, domain-separated signature
messages (manifest, read paths, commit, install request/response/attestation),
bucket commitments and the Merkle construction (no leaf/inner confusion,
padding cannot collide with a commitment, server rebuilds the root from all
leaves), checked epoch and size arithmetic, base64 pre-decode caps, the
staging codec's symmetric bounds and canonical re-encode, and Debug
redaction throughout.

Known remaining limitations added by this pass:

- The manifest signature still omits `created_at_unix` (and
  `owner_signing_key_id`, which is pinned by the signature header): a copy
  with an altered creation time verifies and then trips the server's
  immutability comparison (availability only). Closing this needs a v2
  signature domain with migration.
- The read-paths signature carries no session or counter binding, so a
  captured signed read is replayable within an epoch by anyone already on
  the transport; commits are not replayable.
- `private_hnsw_oram_fixed_search_read_path_count` counts one path per step
  while the server serves rounds of `path_batch_size` paths; the convenience
  commit planner therefore under-budgets fail-closed relative to the server.
- Write-back is bounded by count, not by membership in the session's served
  paths; the owner signature on every commit keeps this from being an
  escalation.
- The bare capsule attestation validator is self-certifying (it verifies
  with the embedded key); every admission path uses the signer-pinned
  variant, but the bare function remains public as shape validation.
- The install response path hashes the receipt before verifying the
  signature (receipt capped at 64 KiB); empty shard keywords are accepted by
  the staging validator; staged frames are re-encoded up to three times.

### Tenth pass: activation authority, mixed-version activation, peer recovery and reservation audits

This pass audited the signed activation registry and its transitions, the
mixed-version activation proof, the peer recovery request/response/adoption
flows and the owner reservation resolution receipts. No High or Medium
findings. Fixed:

- IPv6 clusters could never pin or activate: the peer URI digest accepted an
  IPv6 literal only in bare form while the production URI parser presents
  it bracketed (`[fd00::11]`), so every activation path failed closed for
  such peers. Bracketed canonical IPv6 literals now hash to the same digest
  as the bare form (other brackets are refused), and the storage caller
  lowercases the configured host so DNS names keep their case-insensitive
  meaning. Existing IPv4 and hostname pins are unchanged.
- The mixed-version activation proof validator now checks explicitly that
  every backing challenge is a V2 challenge and that the wire-protocol floor
  it installs lies within the supported range, instead of relying on the
  log-position equality invariants to exclude a legacy (V1) proof that
  would install floor 0.
- Peer recovery public keys and signatures, and reservation resolution
  fixed-size fields, use the same length-then-decode-then-re-encode rule as
  every other fixed-size field (previously two decoders skipped the
  re-encode check and one decoded before checking the encoded length; both
  fail-closed, aligned for consistency).

Checked and left as is: manifest signature coverage and parent chaining,
registry rollback rules (consecutive generations, immutable identity, peers
never removed or re-keyed), peer pin uniqueness and ordering, challenge
resolver context binding, proof unanimity and per-peer ack verification,
key-id-to-key-bytes binding, role separation and peer id 0 rejection,
terminal evidence and receipt digests covering every field, and the
context comparisons the three receipt consumers perform.

Known remaining limitations added by this pass:

- The activation registry accepts only consecutive generation transitions
  and the anchored check at load is self-referential by design, so a peer
  that falls more than one generation behind must be stepped through each
  generation by the operator.
- The peer recovery terminal-evidence digest hashes its domain string
  without a length prefix (a constant, so unambiguous); changing it is a
  wire-format bump.
- Reservation resolution receipts are checked against their context by
  three callers with hand-written comparisons rather than one shared
  validator.

### Eleventh pass: collection HNSW ORAM store and storage journal writer audits

This pass audited the on-disk private HNSW ORAM store (`lib/collection`)
and the V2 mutation journal writer with its owner recovery capsule module
(`lib/storage`). Fixed:

- Restart resume was permanently stuck in one crash window: when the
  DecisionDurable record had been published but the state pointer had not
  moved, the resume dispatcher matched the pointer phase yet validated
  against the pending record, refused with an invalid transition, and every
  retry failed identically. The decision permit is now built from the
  durable pointer state, a pending record is accepted only when it is the
  DecisionDurable successor carrying the same evidence, and applying the
  permit republishes it. A test drives the crash window end to end.
- Owner capsule installs rejected any lease renewal (exact lease equality),
  so late owners could never install after the coordinator renewed the
  lease and the recovery-capsule certificate could never complete. Installs
  now accept exactly the renewals the reconcile lease validator accepts and
  still require the lease to be in the preparing phase.
- The HNSW store could write records it could never read back: the atomic
  JSON writer had no size cap while every reader enforces one, so a large
  owner-signed commit produced a pending write-back record above the 512 MiB
  read cap that wedged the index until the file was removed by hand. The
  pending record is now refused before any file is created when it exceeds
  the reader's cap, and partial temp files are removed on every write error.
- A post-commit manifest refresh could replace the anchored manifest with
  one whose commitment context differed (for example another `rk_epoch`),
  breaking replication and verification of every stored bucket; the refresh
  now has to preserve every field except epoch, root, node counts and the
  creation time.
- Restored-snapshot verification read one proof per bucket and recomputed
  the whole Merkle tree each time (quadratic in the tree size); buckets are
  now verified in batches of 1024 per proof read.

Checked and left as is: write-then-fsync-then-rename ordering with parent
directory fsyncs in both stores, `RENAME_NOREPLACE` immutable records and
record-before-pointer publication in the journal, `openat2` beneath-root
opens with inode pinning, fixed-size and commitment-context checks on every
served bucket, epoch monotonicity, canonical JSON re-encode checks and Debug
redaction.

Known remaining limitations added by this pass:

- Several server paths still run fsync-heavy store I/O on async runtime
  threads (bucket-set upload, session-open recovery, bundle export, replica
  prepare, and the distributed prepare/abort/finalize closures); moving
  them to blocking tasks is a server-side refactor.
- Proof reads still recompute the Merkle levels of the whole tree per call.
- A same-generation capsule cannot be replaced after an activation-authority
  change while the mutation is live; the stale file must be removed by hand.
- One journal read (`local-cleanup-complete`) is path-based and lock-free
  (fail-closed); stale temp files and staging directories left by crashes
  are never swept in either store; the pending write-back record still
  embeds a full copy of the Merkle tree; the store's test-only public
  mutators bypass the invariants the production paths enforce.
- The storage test `v2_owner_recovery_capsule_store_supersedes_previous_generation`
  is ignored with its reason: `begin_v2` pins the lease generation and writer
  fence to the signed mutation bundle and the immutable manifest, and the
  paired store fixture has no knob to mint a coherent next-generation bundle.
  The supersede rule stays covered by the conflicting-package and exact-replay
  tests; the fixture needs a lease-generation parameter.
- Padding and deleted steps of an HNSW search skip the distance and
  candidate bookkeeping, so per-step latency differs slightly from real
  steps; computing the distance regardless would make the work
  shape-constant.
- A grandchild that calls `setsid` itself escapes the process-group kill;
  only a PID namespace or cgroup would contain it.
- The HNSW client key derivation binds collection, vector name, resource key
  id and epoch but not the key id (the AEAD contexts do), and the manifest
  signature omits `owner_signing_key_id`, `created_at_unix` and the signature
  algorithm and key id; both are pinned by the store and server config, so a
  change needs a versioned domain rather than an in-place fix. The bare
  commit planners skip the fixed-size and commitment-context checks their
  `_for_manifest` wrappers perform and have no production caller.
- The capsule install stream is buffered up to 128 MiB before the coordinator
  signature is verified (the crypto crate verifies before hashing, the
  transport does not); the semaphore, timeouts and TLS bound the exposure.
  Carrying the signed request in the first chunk would remove it.
- `validate_private_oram_owner_capsule_install_attestation_v2` verifies
  against the key embedded in the attestation; every authority-bearing caller
  uses the pinned `_for_signer_v2` form, but the unpinned form stays public.
- HNSW append substitute padding can run out under many collisions and then
  aborts the attempt, which is a slightly secret-correlated abort; a poisoned
  attempt after a rolled-back window costs a fresh plan even for pure
  response errors. Neither path has a production caller yet.
- Decoded HNSW blocks, plaintext buckets and checkpoint structs are ordinary
  heap values that are not zeroized on drop; only the AEAD buffers are.
- The result ORAM bucket key derivation, AEAD and commitment contexts bind
  the resource key epoch but not the layout generation or manifest nonce, so
  a rebuilt ORAM under the same epoch produces ciphertexts that authenticate
  for the same bucket id and index epoch of the previous layout. The verified
  fetch path is protected by the signed-state root; binding the generation
  would change the stored format.
- Decoded result ORAM buckets and payload blocks are ordinary vectors that
  are not zeroized when dropped; only the openers' working buffers are.
- The collection-side paired owner journal
  (`<hnsw store>/temp/private-oram-owner-v2/active`) is never archived or
  removed once its terminal record is written; the storage-level mutation
  journal archives only its own `active/` after clear. A later `prepare` or
  prestage adoption for the same collection compares the new journal against
  the retained one byte for byte, reports `ConcurrentMutation`, and adoption
  then installs an insert-only `Quarantined` terminal marker on the intent. A
  coordinator retry of `adopt_for_parent_v2` after the child reached its
  terminal takes the same path. Retiring the owner journal after the storage
  archive step is the missing lifecycle transition; it needs the same
  durability discipline as the rest of the journal and can only be exercised
  on Linux.
- `prepare_reservation_fence_v1` returns an existing fence for a matching
  challenge before checking whether its cancellation is already durable (the
  fence file is unlinked after the resolution is fsynced), so a crash between
  the two steps lets a cancelled attempt be signed `ReadyExact` once more; and
  preparing a new challenge unlinks an unconsumed Finalized resolution, after
  which `confirm_installed_reservation_resolution_v1` cannot produce the
  completion receipt locally.
- The owner store adapter maps every owner journal error, including
  `Indeterminate` raised after a terminal rename succeeded, to `bad_request`.
- The all-owner cleanup certificate cannot check its own completeness
  (`owner_count` is self-declared and its digest is unkeyed); callers must
  compare it with the roster. The cleanup-authorization flow has no
  production producer yet.
- HNSW append graph planning fails after the candidate windows, poisoning the
  attempt, when a selected neighbor has a level-0 neighbor outside the
  candidate set; the checkpoint carries no adjacency, so SDKs must pass a
  closed candidate set.
- Append checkpoints are sealed with random-nonce AES-GCM under one derived key
  per collection and manifest without an invocation budget (2^32 mutations of
  one collection).
- A private ORAM mutation generation whose owner disappears before the
  recovery capsules are ready cannot be reclaimed; an owner-eviction or early
  abort certificate is still missing.
- Terminal mutation archives, leaked staging directories, external recovery
  uploads and orphaned preinstalled transfer stores are not garbage collected.
- Crypto migration completion is verified by point counts only.
- Standalone private ORAM session `open`/`close` are gated by collection write
  access only, not by an owner-key signature, so a write-scoped key can hold
  the writer slot; read signatures carry no nonce and can be replayed within
  an epoch. Both need a protocol change (signed open/close, per-session
  nonces) on the client side as well.
- Bridge responses carry no request id; a stray stdout line desynchronizes a
  worker until it is killed. Idle bridge stdout is queued without bound.
- The server bounds the size of a private ORAM session write-back but does not
  require it to cover exactly the paths the session read; the client library
  writes back every read path (padding included), a third-party client that
  writes back less reveals which of its reads were padding.
- The internal replication lock is held across outbound peer calls and
  consensus waits during private ORAM recovery requests.
- A mutation activation floor without an activation authority accepts a
  missing pending token (pre-release fixture compatibility).

### Twelfth pass: result ORAM store, mutation journal core and owner store adapter audits

This pass audited the on-disk private result ORAM store (`lib/collection`),
the core of the V1/V2 mutation journal (`lib/storage`) and the owner store
adapter that pairs the HNSW and result stores. The hardening the eleventh
pass applied to the HNSW store had not been carried over to the result
store. Fixed:

- A post-commit result manifest refresh could replace the anchored manifest
  with one whose commitment context differed (another `rk_epoch`, bucket
  count or signer), so every untouched bucket stopped verifying and V2 owner
  store verification failed permanently. The refresh now has to preserve
  every field except epoch, root, result counts and the creation time, as in
  the HNSW store; a test covers the refused fields.
- The result store's atomic JSON writer had no size cap while every reader
  enforces one, so an oversized prepared write-back (or Merkle tree, or
  manifest) was written successfully and then could not be read by commit,
  recover or abort. Each such record is now refused before any file is
  created when it exceeds its reader's cap, and partial temp files are
  removed on every write error instead of only on a failed rename.
- Restored result snapshot verification read one proof per bucket, each
  re-reading and re-hashing the whole Merkle tree (quadratic in the tree
  size); buckets are now verified in batches of 1024 per proof read.
- Journal `begin` disarmed its staging-directory guard before the publishing
  rename, so a refused or failed publish left a full descriptor copy under
  `temp/` that nothing sweeps. The guard now stays armed until the rename
  succeeds.
- Journal JSON reads and writes went through unbuffered files, so serde_json
  issued one system call per byte on every load and transition (descriptors
  are capped at 512 MiB). Reads and writes are now buffered; the size limit
  is still enforced on the underlying reader.

Checked and left as is: bounded, `O_NOFOLLOW`, owner/mode/link-count checked
reads in both modules; canonical re-encode checks on the manifest and
reservation decoders; hashed-and-verified atomic state publication; strictly
sequential phase transitions with checked generation and fence arithmetic;
signature verification before any state use; epoch CAS and replay handling
in the result store; the adapter's validation-before-lock, consistent lock
order, live-binding re-check under the store locks and HNSW-then-result
write order.

Known remaining limitations added by this pass:

- Admitted-mutation recovery rebuilds the lease with `renewal_revision` 0 and
  requires exact equality with the committed lease, so a committed mutation
  whose preparing lease had been renewed could not be recovered. No server
  path proposes a mutation-lease renewal today
  (`private_oram_mutation_v2_renewal_operation` has no caller), so this is
  latent; enabling renewals needs the recovery plan, the parent descriptor
  digest and the exact-manifest lookup to accept the renewed lease together.
- A crash between the manifest and signature renames of a manifest refresh
  (both stores) left the new manifest next to the old signature (fixed in
  the thirteenth pass: an identical re-upload with a verified signature now
  republishes the pair).
- The V1 journal `transition` and `begin` paths read and publish through the
  root path rather than the pinned root descriptor that `acquire_lock`
  validated; only the recovery-authority path re-validates the root identity.
- V1 journal state validation checks the shape of `previous_record_digest`
  but not that it chains to the predecessor record (the digest is unkeyed,
  so this is a consistency check, not authentication).
- Admission recovery manifests verify each owner attestation against the key
  embedded in it; owner identity is bound by the append-reservation
  validator, and whether the consensus admission apply path binds the keys as
  well has not been traced.
- The result manifest refresh may still change `created_at_unix`, which V2
  owner store verification pins; a refresh that changes it fails V2
  verification rather than being refused at upload.

### Thirteenth pass: server-side result ORAM, mutation coordinator, mutation sessions and consensus authority audits

This pass audited the server-side private result ORAM request handling
(`src/common/private_result_oram.rs`), the distributed mutation coordinator
and mutation session lifecycle (`src/common/private_oram_mutation.rs`,
`private_oram_mutation_session.rs`) and the consensus-applied mutation
authority (`lib/storage/.../private_oram_mutation_cleanup/authority.rs`).
Fixed:

- A single-node result ORAM or HNSW ORAM commit whose request future was
  dropped while the store commit ran (client disconnect, gRPC deadline) never
  recorded its outcome: the session stayed `commit_in_progress`, which expiry
  and close skip, so the collection refused every later session, upload,
  snapshot and lifecycle operation until restart. The store commit and the
  registry update now run in one detached task that completes regardless of
  the caller.
- The result ORAM staged owner write-back marked itself settled before its
  abort or finalize store call, so a failed store call skipped both the
  registry update and the drop guard and left the commit slot held. It now
  records the outcome only after the store call, as the HNSW context does.
- A manifest refresh torn between the manifest and signature renames wedged
  both stores (the identical-retry arm refused the matching manifest because
  the signature differed). Both upload paths verify the signature against
  the pinned owner key before the store is called, so an identical manifest
  with a different signature now republishes the pair; tests cover the
  repair in both stores.
- Mutation session read routes (HNSW paths and result buckets) required only
  read access although they move session state (read-in-progress flag and
  path budget), and a missing session answered differently from one of
  another collection. They now require write access like the other session
  routes, and both cases return the same invalid-session error.

Answered from the twelfth pass: admission recovery manifests verify owner
attestations against embedded keys, but every consensus path that accepts a
manifest (append prepared, admission, admission rejected) checks it against
the retained reservation, whose owner signers were pinned to the activation
authority manifest and whose roster equals the layout when it was applied;
Admission additionally pins the manifest bytes to the prepared ones. A
coordinator cannot get self-signed owner attestations accepted.

Checked and left as is: RBAC before store work on every result ORAM route;
manifest, read and commit signatures verified before state changes and
pinned to the owner key; exact old+1 epoch CAS re-checked under the store
lock; request batch caps, duplicate checks and base64 length pre-checks;
registry capped at 1024 sessions with one writer per collection; no registry
guard across `.await`; deterministic consensus apply (no wall clock, local
files or map iteration order), guarded indexing and checked counters on
replicated input, strict aggregate-digest and locator ordering with exact
replay digests, bounded append history and challenge outcomes.

Known remaining limitations added by this pass:

- Commit validation (Ed25519 over the bucket references, ciphertext size
  checks, the current-epoch file read) runs inside the process-wide result
  ORAM registry mutex on an async worker; session open (pending write-back
  recovery and a whole-tree proof read), bucket upload, replica
  prepare/complete and bundle export run store I/O on async workers.
- The staged owner write-back drop guard uses `try_lock` and gives up when
  the registry mutex is busy; a lost release is recovered only by
  coordinated recovery.
- Restored-snapshot verification still re-reads and re-hashes the Merkle
  tree once per 1024-bucket batch, and restore requires the current epoch to
  equal the manifest anchor, so a snapshot of a collection that has committed
  since its manifest upload cannot be restored.
- A failed session open after an upload reservation dropped the registry
  lock before releasing the reservation, so the release could remove a
  reservation taken by another caller in between (fixed in the fourteenth
  pass for both registries).
- Standalone result ORAM sessions are not bound to the principal that opened
  them (the stored client id is unused), and reads need only read access.
- Append prepared, admission and admission-rejected apply arms do not
  re-check the reservation's activation-authority locator against the
  current one; authority rotation has no consensus operation today, so this
  is latent until rotation is enabled.
- The mutation session registry's `seen_job_authorities` and
  `cleanup_tombstones` sets grow by one entry per mutation for the process
  lifetime.
- Consensus apply does not check which peer proposed an abort decision or a
  reserved-attempt rejection, so a Raft member can deny other coordinators'
  appends (liveness only; all Raft peers are trusted, as upstream).

### Fourteenth pass: server HNSW handlers, internal peer RPCs and consensus apply audits

This pass audited the server-side private HNSW request handling
(`src/common/private_hnsw.rs`), the internal peer gRPC service
(`src/tonic/api/qdrant_internal_api.rs`) and the private ORAM apply arms of
the persistent consensus state (`lib/storage/.../consensus/persistent.rs`).
Fixed:

- Two deterministic apply refusals were raised as service errors, which stop
  consensus on every replica at that entry and again on every restart: a
  legacy (pre-tagged) mutation lease, initialize or apply operation meeting
  an upgraded tagged authority slot, and the reservation V3 floor barrier
  meeting non-quiescent reservation history (a reservation can commit
  between the proposer's check and the barrier). Every replica holds the
  same state, so both now reject the entry and advance the apply cursor; the
  legacy reducers stay fenced and the barrier can be re-proposed.
- Replica write-back finalize and abort RPCs carry no coordinator signature
  and acted on the shape of the request alone, so a client reaching the
  internal port could finalize a replica to an epoch consensus never
  accepted, or abort one that consensus had committed. The replica now
  checks its own consensus view: a finalize must name the committed
  epoch/root/write-back digest (waiting up to 10 s for the local apply), and
  an abort must not undo it.
- On an indeterminate epoch CAS the staged owner write-back is meant to stay
  in its commit phase for session recovery, but the context was dropped
  unsettled and its drop guard released the commit slot, after which
  recovery failed with "no commit in progress" once it had already moved
  the store. Both the HNSW and result contexts now mark that branch as left
  pending for recovery.
- A failed session open after an upload reservation released the
  reservation after dropping the registry lock, so another caller's
  reservation could be removed and a session, snapshot or second upload
  could run during that caller's upload. Both registries now keep the
  reservation when the open fails, so only the caller's guard releases it;
  tests cover both.
- Replication bundle export and recovery inspection read and verified the
  manifest with read access before checking the write access they require;
  access is now checked first (HNSW and result ORAM).

Checked and left as is: request caps before allocation, ciphertext length
checks before base64 decoding, checked arithmetic, commit signature
coverage (collection, vector, key metadata, epochs, roots, bucket ids and
digests, algorithm and key id), the detached single-node commit task,
RAII upload/snapshot guards with no await after acquisition, canonical-JSON
size caps before decoding on owner RPCs, signer pins from consensus before
signature verification, bounded nonce caches, deterministic apply (no wall
clock, sorted or order-independent map use), guarded `expect`s, 1M record
caps per replicated map, and validated snapshot and persisted-state loads.

Known remaining limitations added by this pass:

- The internal gRPC port authenticates peers only by CA-chained client
  certificates when p2p TLS is on, and nothing forces TLS on when private
  ORAM is configured; certificates are not bound to peer ids. Handlers
  without a coordinator signature (shard recovery and resharding resume,
  which can restart a fixed-layout transfer every 60 s, and the write-back
  completion RPCs above beyond their consensus check) rely on that.
- The single install-stream slot is shared by capsule install, prestage,
  index install and live-replica install, and a slow sender holds it for the
  5 minute stream timeout; the decoder buffers up to 512 MiB before the
  capsule handler's 128 MiB check.
- Prestage, owner recovery and adoption requests carry nonces without expiry
  and have no replay cache.
- Collection-delete pruning of the replicated private ORAM maps uses each
  node's local collection config, so a node without that config prunes
  nothing and the maps diverge.
- The staged write-back drop guard races on `Arc::strong_count` and gives up
  when the registry mutex is busy (`try_lock`).
- An abort that reaches a replica whose consensus apply lags behind a
  committed CAS still passes the new consensus check.
- `private_hnsw_oram_api_required_message` echoes the requested vector
  name.

### Fifteenth pass: write-back coordinator, peer client and consensus manager audits

This pass audited the coordinator side of the replicated private ORAM
write-back (`lib/storage/src/dispatcher.rs`), the peer client for the
internal private ORAM RPCs (`lib/collection/src/shards/channel_service.rs`)
and the private ORAM parts of the consensus manager
(`lib/storage/src/content_manager/consensus_manager.rs`). Fixed:

- A coordinator whose own apply of a committed epoch CAS failed locally
  (persistence fenced, indeterminate save) read the `Failed` outcome as a
  definite rejection and aborted every prepared journal, although the entry
  had committed and the other replicas had applied it, leaving consensus at
  the new epoch with stores that lack its buckets. A service error from the
  local apply is now an indeterminate outcome (the CAS is re-proposed, and
  the prepared journals are retained if it stays unresolved), and a rejected
  attempt that finds consensus already at the requested state is treated as
  applied on every attempt, not only on retries.
- The activation barrier resolved its base term from the local WAL inside
  apply, so ordinary local WAL compaction made the enable barrier fail with
  a service error on that node (stopping consensus there on every restart)
  and made it impossible for the leader to propose, which left every general
  proposal blocked behind the pending activation. An enable barrier now
  resolves its term from the durable pending activation (whose proof was
  checked against the real base term when the prepare barrier applied), a
  prepare barrier must directly follow its base entry, and every remaining
  miss rejects the entry instead of stopping consensus.
- A deterministic refusal of a private ORAM topology meta-op (layout
  transition, shard transfer finish, resharding start and finish) that left
  the topology pending was converted into a service error, which stops
  consensus on every node (for example a resharding start whose
  crypto-runtime parity check fails after a peer metadata update). Such a
  refusal now rejects the entry; local failures and partially applied
  transitions still stop consensus.

Checked and left as is: the CAS is proposed only after every prepare is
acknowledged by exactly the required peers; unresolved CAS attempts keep the
prepared journals; re-proposal is idempotent; replica sets are computed once
per write-back; peer calls are bounded by timeouts and retries; error texts
from peers are replaced by fixed strings; V2/V3 owner RPCs require TLS, cap
decode sizes and re-check pinned addresses; proposal waits are bounded; no
std lock is held across `.await`; no wall clock in apply.

Known remaining limitations added by this pass:

- Deleting an encrypted collection whose V2 mutation authority has an
  authority floor fails the save after pruning (the floor checkpoint refuses
  a disappearing floor), which stops consensus on every node; after restart
  the replay finds the collection gone and the records stay leaked. Pruning
  also reads node-local collection config (divergence across nodes, records
  leaked when the config lists no ORAM index), and a follower that lags
  across such a prune refuses the leader's snapshot ("would roll back
  committed state") fatally. A deterministic fix needs a replicated
  collection-id to ORAM-key index maintained by the CAS and mutation apply
  paths, and pruning by `collection_id` inside the same atomic patch.
- Shard transfer start applies its layout CAS before the meta-op, so a
  deterministic meta-op refusal there still stops consensus rather than
  leave a partial transition.
- Legacy prepare/finalize/abort/install peer RPCs do not require TLS or
  re-check the pinned address, a replica's prepare acknowledgement only
  echoes the digest the request carried, and their responses are decoded
  without a size cap on the shared peer channel.
- If any replica finalize fails after the CAS committed, the coordinator
  skips its own local finalize until session recovery; recovery completion
  re-derives the replica set and requires every replica to be active; an
  abort timeout is reported as an unresolved CAS.
- Early returns in the activation-barrier and delete-prune apply paths drop
  the proposer's notification (reported as indeterminate), proposal-time
  refusals are only logged (the proposer waits for the full timeout), and
  `await_for_multiple_operations` leaves senders behind on timeout
  (upstream).

### Sixteenth pass: floor checkpoint store and Raft loop audits; CI coverage

This pass audited the local private ORAM floor checkpoint store
(`lib/storage/.../floor_store.rs`) and the private ORAM handling in the Raft
loop (`src/consensus.rs`). It also added the private ORAM store, journal,
consensus and server test filters to the `qdrant-sec CI` workflow: the
workflow compiled those targets but ran none of their private ORAM tests,
including the regression tests added by earlier passes. Their first run
found three stale tests, now aligned: a stale-root CAS test and an owner
store adapter fixture still used epoch gaps that the exact old+1 rule
refuses, and the activation-pending scan test expected the error the fix
below removes. Fixed:

- The leader's activation-pending scan, which gates learner promotion and
  ordinary proposals on every loop iteration, returned a service error for
  an unreadable or undecodable uncommitted WAL entry, and the error stopped
  the consensus thread. A peer can forward such an entry (bytes that are
  not an operation, or a variant from a newer binary), and a newly elected
  leader holding the same entry stopped the same way. The scan now treats
  such an entry as a possible pending activation (blocking promotions and
  ordinary proposals) instead of failing.

Checked and left as is: floor checkpoint writes (temp file in the pinned
directory, fsync, rename, digest re-check, parent fsync with an
indeterminate outcome), bounded reads with `deny_unknown_fields` and
domain-separated digests, strict generation increments, recovery only to the
exact prior or next Raft image, detection of a deleted floor directory or
Raft state file at startup, floor-before-collections ordering on snapshot
install, WAL compaction bounded by the last applied entry, consistent lock
order and no panics in the loop.

Known remaining limitations added by this pass:

- Proposal gates (`ensure_private_oram_topology_proposal_allowed`, the
  general proposal gate while an activation is pending) run only on the
  proposing node; a follower that has not yet applied the activation
  forwards proposals that the leader appends without the gate. A learner
  added this way is only warned about at apply, and while any learner
  exists every peer-recovery signer pin refuses. The leader should check
  forwarded `MsgProp` entries before stepping them, and apply should refuse
  such topology changes deterministically.
- The floor checkpoint's 64 MiB file cap is reached at roughly 65-70k
  authority floors, below the 100k the validator allows; at that size every
  save fails the same way and stops consensus. The two caps should be
  derived from each other and checked at plan time with a `bad_request`.
- Fix design for the collection-delete halt recorded in the fifteenth pass:
  the "no disappearing floor" rule stops a snapshot or state that omits a
  collection from being accepted as a deletion and then replaying the
  collection's older authority from scratch, so it cannot simply be lifted.
  The authority key is derived from the collection name, so a tombstone
  must be ordered by Raft index rather than ban the key: the delete records
  a retired-authority tombstone (final floor digest, maximum ordinal, delete
  entry locator) in Raft state and snapshots; the checkpoint (version 2)
  carries tombstones that never disappear; a floor may leave only with a
  newer matching tombstone; an authority under a retired key is accepted
  only when activated after the delete; snapshot validation requires the
  incoming tombstones to cover the local ones; and the delete is refused
  with a `bad_request` before any side effect when the tombstone cannot be
  formed. The snapshot authority acceptance plan (`wire == None` is
  `InvalidTransition`) needs the same exemption, or a node cannot restart
  after such a delete.

### Seventeenth pass: server crypto runtime audit and consensus follow-ups

This pass audited the server crypto runtime (`src/common/crypto.rs`: backend
and material validation, KMS, Vault Transit and file material sources,
collection crypto validation, fingerprints) and fixed two consensus items
recorded in the sixteenth pass. Local builds were not possible (the WSL
disk image filled the system drive), so these changes were verified by CI.
Fixed:

- High: resource keys wrapped through Vault Transit by this server could
  not be opened, and scope binding was never checked. Wrapping produces a
  version-2 blob whose plaintext is a tag, the SHA-256 of the wrap AAD and
  the key, but stored materials keep no blob version and decoding always
  presented version 1, so a key generated or rewrapped onto Vault failed
  with an invalid key length and every blob that did open skipped the scope
  check. The plaintext shape is unambiguous (65 bytes bound, 32 bytes
  legacy), so a bound plaintext is now always unbound and its scope digest
  checked; a test drives the decode path through a mocked Vault, including
  a refused cross-scope open.
- Collection creation ran the crypto runtime validation, which unwraps
  resource keys through external key services and whose errors name
  materials and other collections' crypto scopes, before checking that the
  caller may create collections; REST and gRPC now check manage access
  first.
- The AWS region read from the environment was spliced into the default
  KMS endpoint host unchecked, so a crafted value could send the signed
  request and session token to another host; it must now be a region
  identifier (lowercase letters, digits and dashes, at most 32 bytes).
- The floor checkpoint file cap (64 MiB) was reached near 65k authority
  floors, below the 100k count cap, so every save failed identically on
  every node; the file cap is now 256 MiB so the count cap binds.
- The leader now re-applies the private ORAM gates to proposals forwarded
  by followers (activation floor for configuration changes, activation
  proposal validation, pending-activation gate) and drops proposals that
  fail or do not decode.

Checked and left as is: redacted Debug and Display for every crypto error
and plan type, URL redaction, HMAC-only key commitments in fingerprints,
TLS verification with redirects disabled, bounded timeouts and response
bodies, sensitive headers, https-only external URLs without credentials,
the strict zero-trust profile rejecting server materials, backends, inline
material and server providers, file and descriptor material checks
(`O_NOFOLLOW`, owner, mode, parent directories), the OpenFHE backend cache
key coverage, checked ORAM sizing arithmetic and domain-separated client
query signatures.

Known remaining limitations added by this pass:

- Vault Transit version-1 (unbound) blobs still open, relying on Transit
  `context`, which ordinary keys ignore; the blob version should be stored
  with the material and version 1 refused for new materials and under the
  strict profile.
- Key commitments for the runtime fingerprint, collection crypto validation
  and create-collection validation unwrap keys through KMS, Vault or local
  sockets with blocking I/O on async workers (telemetry polls included),
  and a transient failure changes the fingerprint; commitments should be
  cached at startup and validation moved to blocking tasks.
- Key service response buffers grow by reallocation and parse into
  non-zeroizing JSON values, and the untrimmed AWS secret access key is
  dropped without zeroization.
- Client CKKS vector instances are not checked against the collection's
  key id and encryption epoch.
